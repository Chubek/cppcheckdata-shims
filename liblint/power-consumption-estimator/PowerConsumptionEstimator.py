#!/usr/bin/env python3
"""
EnergyConsumptionEstimator.py
═════════════════════════════

Cppcheck addon — static estimation of worst-case energy consumption
(WCEC) for C/C++ programs, built on the abstract execution substrate.

Theory
──────
Energy consumption of a program running on a given micro-architecture is
the sum over every executed instruction of its per-instruction energy
cost:

    E_total = Σ_i  n_i · e_i

where  n_i  is the dynamic execution count of instruction class i and
e_i  is the energy weight (in picojoules, nanojoules, or an abstract
unit) of that class.

When the execution count is unknown at analysis time (loops whose bounds
depend on input), we represent  n_i  symbolically via the CostExpr
algebra (imported from StaticCostAnalysis.py) and propagate through the
abstract execution engine.  The result is a *symbolic energy bound*
parameterised by loop-trip variables, call-graph depth, etc.

Architecture Profiles
─────────────────────
We ship several built-in profiles.  Each profile is a dictionary mapping
an *operation class* (OpClass enum) to an energy weight.  Users can
supply custom JSON profiles via the --energy-profile flag.

    ┌──────────────┬─────────────────────────────────────────────────┐
    │  Profile      │  Description                                    │
    ├──────────────┼─────────────────────────────────────────────────┤
    │  ARM_CM0     │  ARM Cortex-M0 (ultra-low-power embedded)       │
    │  ARM_CM4     │  ARM Cortex-M4 (mid-range embedded w/ FPU)      │
    │  ARM_CA53    │  ARM Cortex-A53 (mobile application processor)  │
    │  X86_ATOM    │  Intel Atom (low-power x86)                     │
    │  X86_SKYLAKE │  Intel Skylake (server/desktop x86)             │
    │  RISCV_E31   │  SiFive E31 (RISC-V embedded)                   │
    │  GENERIC     │  Normalised abstract costs (dimensionless)       │
    └──────────────┴─────────────────────────────────────────────────┘

Integration points
──────────────────
  • abstract_exec.py   → AbsExecEngine, AbsExecEvent, AbsExecAnalysis
  • abstract_domains.py → IntervalDomain (for uncertain trip counts)
  • abstract_vm.py      → VM instruction classification
  • StaticCostAnalysis.py → CostExpr algebra for symbolic bounds
  • cppcheckdata.py     → Token, Scope, Function, reportError, parsedump

License: No restrictions — same as cppcheckdata.
"""

from __future__ import annotations

import argparse
import copy
import enum
import json
import math
import os
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from typing import (
    Any,
    Callable,
    ClassVar,
    Dict,
    FrozenSet,
    Iterable,
    List,
    Mapping,
    NamedTuple,
    Optional,
    Sequence,
    Set,
    Tuple,
    Union,
)

# ─── Upstream imports ────────────────────────────────────────────────
import cppcheckdata

# ─── Sibling abstract-execution substrate ────────────────────────────
# These modules live alongside this addon in the cppcheckdata-shims tree.
# We import defensively so the file can be parsed by linters even when
# the substrate is not on sys.path.

try:
    from cppcheckdata_shims.abstract_domains import (
        AbstractDomain,
        IntervalDomain,
        FunctionDomain,
        make_interval_env,
    )
except ImportError:
    # Minimal shims so the file is self-contained for unit-testing.
    AbstractDomain = object  # type: ignore[misc,assignment]

    class IntervalDomain:  # type: ignore[no-redef]
        """Minimal stub — replaced by the real domain at runtime."""
        def __init__(self, lo: float = float('-inf'), hi: float = float('inf')):
            self.lo, self.hi = lo, hi

        @classmethod
        def const(cls, v: float) -> IntervalDomain:
            return cls(v, v)

        @classmethod
        def top(cls) -> IntervalDomain:
            return cls()

        @classmethod
        def bottom(cls) -> IntervalDomain:
            return cls(1.0, -1.0)

        @classmethod
        def range(cls, lo: float, hi: float) -> IntervalDomain:
            return cls(lo, hi)

        def is_bottom(self) -> bool:
            return self.lo > self.hi

        def is_top(self) -> bool:
            return self.lo == float('-inf') and self.hi == float('inf')

        def is_const(self) -> bool:
            return self.lo == self.hi

        def join(self, other: IntervalDomain) -> IntervalDomain:
            if self.is_bottom():
                return other
            if other.is_bottom():
                return self
            return IntervalDomain(min(self.lo, other.lo), max(self.hi, other.hi))

        def meet(self, other: IntervalDomain) -> IntervalDomain:
            lo = max(self.lo, other.lo)
            hi = min(self.hi, other.hi)
            return IntervalDomain(lo, hi)

        def mul(self, other: IntervalDomain) -> IntervalDomain:
            if self.is_bottom() or other.is_bottom():
                return IntervalDomain.bottom()
            prods = [a * b for a in (self.lo, self.hi) for b in (other.lo, other.hi)]
            return IntervalDomain(min(prods), max(prods))

        def add(self, other: IntervalDomain) -> IntervalDomain:
            if self.is_bottom() or other.is_bottom():
                return IntervalDomain.bottom()
            return IntervalDomain(self.lo + other.lo, self.hi + other.hi)

        def __repr__(self) -> str:
            if self.is_bottom():
                return "Interval(⊥)"
            lo_s = "-∞" if self.lo == float('-inf') else str(int(self.lo) if self.lo == int(self.lo) else self.lo)
            hi_s = "+∞" if self.hi == float('inf') else str(int(self.hi) if self.hi == int(self.hi) else self.hi)
            return f"Interval([{lo_s}, {hi_s}])"

    def make_interval_env():  # type: ignore[no-redef]
        return {}


# ═════════════════════════════════════════════════════════════════════
# §1  OPERATION CLASSIFICATION
# ═════════════════════════════════════════════════════════════════════

class OpClass(enum.Enum):
    """
    Instruction-level operation classes that have distinct energy
    fingerprints across micro-architectures.

    The taxonomy is intentionally coarse — mapping every ISA opcode is
    impractical in a source-level tool; instead we classify *C-level
    operations* into categories whose energy ratio is relatively stable
    within an architecture family.
    """

    # ── Arithmetic / logic ───────────────────────────────────────────
    INT_ADD        = "int_add"          # +, -, ++, --
    INT_MUL        = "int_mul"          # *, integer
    INT_DIV        = "int_div"          # /, %, integer
    INT_SHIFT      = "int_shift"        # <<, >>
    INT_BITWISE    = "int_bitwise"      # &, |, ^, ~
    INT_COMPARE    = "int_compare"      # <, >, <=, >=, ==, !=
    INT_LOGIC      = "int_logic"        # &&, ||, !

    # ── Floating point ───────────────────────────────────────────────
    FP_ADD         = "fp_add"
    FP_MUL         = "fp_mul"
    FP_DIV         = "fp_div"
    FP_COMPARE     = "fp_compare"
    FP_CONV        = "fp_conv"          # int↔float conversion

    # ── Memory ───────────────────────────────────────────────────────
    MEM_LOAD       = "mem_load"         # variable read, array index
    MEM_STORE      = "mem_store"        # assignment, array store
    MEM_STACK_PUSH = "mem_stack_push"   # function call frame setup
    MEM_STACK_POP  = "mem_stack_pop"    # function return frame tear-down

    # ── Control flow ─────────────────────────────────────────────────
    BRANCH_UNCOND  = "branch_uncond"    # goto, break, continue
    BRANCH_COND    = "branch_cond"      # if, while, for, switch-case
    CALL           = "call"             # function call overhead
    RETURN         = "return"           # function return

    # ── I/O and system ───────────────────────────────────────────────
    IO_READ        = "io_read"          # scanf, fread, getchar, …
    IO_WRITE       = "io_write"         # printf, fwrite, putchar, …
    SYSCALL        = "syscall"          # generic system call

    # ── Special ──────────────────────────────────────────────────────
    NOP            = "nop"              # empty statement, compiler padding
    CAST           = "cast"             # type cast (often free, sometimes not)
    ALLOC          = "alloc"            # malloc / new
    FREE           = "free"             # free / delete
    UNKNOWN        = "unknown"          # unclassifiable


# ═════════════════════════════════════════════════════════════════════
# §2  ENERGY PROFILES
# ═════════════════════════════════════════════════════════════════════

# All weights are in **abstract energy units** (AEU).  A profile can
# optionally carry a `unit` field ("pJ", "nJ", "µJ", "AEU") and a
# `frequency_mhz` field so that users can convert to real-world energy
# if they know the execution time per operation.

@dataclass(frozen=True)
class EnergyProfile:
    """Immutable description of per-operation energy costs."""

    name: str
    description: str
    unit: str                                   # "pJ" | "nJ" | "µJ" | "AEU"
    frequency_mhz: Optional[float]
    weights: Dict[OpClass, float]               # OpClass → energy-per-op
    cache_miss_penalty: float = 0.0             # extra cost on L1 miss (AEU)
    pipeline_stall_penalty: float = 0.0         # extra cost per stall cycle

    def weight(self, op: OpClass) -> float:
        """Look up the energy weight for *op*, defaulting to UNKNOWN."""
        return self.weights.get(op, self.weights.get(OpClass.UNKNOWN, 1.0))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "unit": self.unit,
            "frequency_mhz": self.frequency_mhz,
            "cache_miss_penalty": self.cache_miss_penalty,
            "pipeline_stall_penalty": self.pipeline_stall_penalty,
            "weights": {k.value: v for k, v in self.weights.items()},
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> EnergyProfile:
        w: Dict[OpClass, float] = {}
        for k, v in d.get("weights", {}).items():
            try:
                w[OpClass(k)] = float(v)
            except (ValueError, KeyError):
                pass
        return cls(
            name=d.get("name", "custom"),
            description=d.get("description", ""),
            unit=d.get("unit", "AEU"),
            frequency_mhz=d.get("frequency_mhz"),
            weights=w,
            cache_miss_penalty=float(d.get("cache_miss_penalty", 0.0)),
            pipeline_stall_penalty=float(d.get("pipeline_stall_penalty", 0.0)),
        )


def _arm_cm0_weights() -> Dict[OpClass, float]:
    """Energy weights for ARM Cortex-M0 @ 48 MHz (values in pJ)."""
    return {
        OpClass.INT_ADD:        3.8,
        OpClass.INT_MUL:       14.5,
        OpClass.INT_DIV:       45.0,
        OpClass.INT_SHIFT:      3.8,
        OpClass.INT_BITWISE:    3.8,
        OpClass.INT_COMPARE:    3.8,
        OpClass.INT_LOGIC:      3.8,
        OpClass.FP_ADD:        85.0,     # software FP on M0
        OpClass.FP_MUL:       120.0,
        OpClass.FP_DIV:       200.0,
        OpClass.FP_COMPARE:    50.0,
        OpClass.FP_CONV:       60.0,
        OpClass.MEM_LOAD:      12.0,
        OpClass.MEM_STORE:     12.0,
        OpClass.MEM_STACK_PUSH: 12.0,
        OpClass.MEM_STACK_POP:  12.0,
        OpClass.BRANCH_UNCOND:  6.0,
        OpClass.BRANCH_COND:    8.0,
        OpClass.CALL:          25.0,
        OpClass.RETURN:        15.0,
        OpClass.IO_READ:      500.0,
        OpClass.IO_WRITE:     500.0,
        OpClass.SYSCALL:      800.0,
        OpClass.NOP:            1.0,
        OpClass.CAST:           2.0,
        OpClass.ALLOC:        300.0,
        OpClass.FREE:         250.0,
        OpClass.UNKNOWN:        5.0,
    }


def _arm_cm4_weights() -> Dict[OpClass, float]:
    """Energy weights for ARM Cortex-M4F @ 168 MHz (values in pJ)."""
    base = _arm_cm0_weights()
    overrides = {
        OpClass.INT_MUL:     6.0,       # single-cycle multiplier
        OpClass.INT_DIV:    18.0,       # hardware divider
        OpClass.FP_ADD:      8.0,       # hardware SP FPU
        OpClass.FP_MUL:     10.0,
        OpClass.FP_DIV:     28.0,
        OpClass.FP_COMPARE:  6.0,
        OpClass.FP_CONV:     7.0,
    }
    base.update(overrides)
    return base


def _arm_ca53_weights() -> Dict[OpClass, float]:
    """Energy weights for ARM Cortex-A53 @ 1.2 GHz (values in pJ)."""
    return {
        OpClass.INT_ADD:         5.0,
        OpClass.INT_MUL:         8.0,
        OpClass.INT_DIV:        25.0,
        OpClass.INT_SHIFT:       5.0,
        OpClass.INT_BITWISE:     5.0,
        OpClass.INT_COMPARE:     5.0,
        OpClass.INT_LOGIC:       5.0,
        OpClass.FP_ADD:         12.0,
        OpClass.FP_MUL:         15.0,
        OpClass.FP_DIV:         40.0,
        OpClass.FP_COMPARE:      8.0,
        OpClass.FP_CONV:        10.0,
        OpClass.MEM_LOAD:       18.0,
        OpClass.MEM_STORE:      18.0,
        OpClass.MEM_STACK_PUSH:  18.0,
        OpClass.MEM_STACK_POP:   18.0,
        OpClass.BRANCH_UNCOND:    4.0,
        OpClass.BRANCH_COND:      8.0,
        OpClass.CALL:            30.0,
        OpClass.RETURN:          18.0,
        OpClass.IO_READ:        800.0,
        OpClass.IO_WRITE:       800.0,
        OpClass.SYSCALL:       1200.0,
        OpClass.NOP:              1.0,
        OpClass.CAST:             3.0,
        OpClass.ALLOC:          400.0,
        OpClass.FREE:           350.0,
        OpClass.UNKNOWN:          6.0,
    }


def _x86_atom_weights() -> Dict[OpClass, float]:
    """Energy weights for Intel Atom N270 @ 1.6 GHz (values in pJ)."""
    return {
        OpClass.INT_ADD:        10.0,
        OpClass.INT_MUL:        18.0,
        OpClass.INT_DIV:        55.0,
        OpClass.INT_SHIFT:      10.0,
        OpClass.INT_BITWISE:    10.0,
        OpClass.INT_COMPARE:    10.0,
        OpClass.INT_LOGIC:      10.0,
        OpClass.FP_ADD:         25.0,
        OpClass.FP_MUL:         30.0,
        OpClass.FP_DIV:         80.0,
        OpClass.FP_COMPARE:     15.0,
        OpClass.FP_CONV:        20.0,
        OpClass.MEM_LOAD:       35.0,
        OpClass.MEM_STORE:      35.0,
        OpClass.MEM_STACK_PUSH:  35.0,
        OpClass.MEM_STACK_POP:   35.0,
        OpClass.BRANCH_UNCOND:   10.0,
        OpClass.BRANCH_COND:     18.0,
        OpClass.CALL:            50.0,
        OpClass.RETURN:          30.0,
        OpClass.IO_READ:       1500.0,
        OpClass.IO_WRITE:      1500.0,
        OpClass.SYSCALL:       3000.0,
        OpClass.NOP:              2.0,
        OpClass.CAST:             5.0,
        OpClass.ALLOC:          600.0,
        OpClass.FREE:           500.0,
        OpClass.UNKNOWN:         12.0,
    }


def _x86_skylake_weights() -> Dict[OpClass, float]:
    """Energy weights for Intel Skylake @ 3.5 GHz (values in pJ)."""
    base = _x86_atom_weights()
    overrides = {
        OpClass.INT_MUL:     12.0,      # faster pipeline
        OpClass.INT_DIV:     35.0,
        OpClass.FP_ADD:      15.0,      # AVX/SSE
        OpClass.FP_MUL:      18.0,
        OpClass.FP_DIV:      50.0,
        OpClass.MEM_LOAD:    45.0,      # higher voltage → more energy per op
        OpClass.MEM_STORE:   45.0,
    }
    base.update(overrides)
    return base


def _riscv_e31_weights() -> Dict[OpClass, float]:
    """Energy weights for SiFive E31 RISC-V @ 150 MHz (values in pJ)."""
    return {
        OpClass.INT_ADD:        3.5,
        OpClass.INT_MUL:       10.0,
        OpClass.INT_DIV:       38.0,
        OpClass.INT_SHIFT:      3.5,
        OpClass.INT_BITWISE:    3.5,
        OpClass.INT_COMPARE:    3.5,
        OpClass.INT_LOGIC:      3.5,
        OpClass.FP_ADD:        70.0,    # software FP
        OpClass.FP_MUL:       100.0,
        OpClass.FP_DIV:       180.0,
        OpClass.FP_COMPARE:    45.0,
        OpClass.FP_CONV:       55.0,
        OpClass.MEM_LOAD:      10.0,
        OpClass.MEM_STORE:     10.0,
        OpClass.MEM_STACK_PUSH: 10.0,
        OpClass.MEM_STACK_POP:  10.0,
        OpClass.BRANCH_UNCOND:   5.0,
        OpClass.BRANCH_COND:     7.0,
        OpClass.CALL:           22.0,
        OpClass.RETURN:         14.0,
        OpClass.IO_READ:       450.0,
        OpClass.IO_WRITE:      450.0,
        OpClass.SYSCALL:       700.0,
        OpClass.NOP:             1.0,
        OpClass.CAST:            2.0,
        OpClass.ALLOC:         280.0,
        OpClass.FREE:          230.0,
        OpClass.UNKNOWN:         4.5,
    }


def _generic_weights() -> Dict[OpClass, float]:
    """Dimensionless normalised weights for architecture-agnostic reasoning."""
    return {
        OpClass.INT_ADD:         1.0,
        OpClass.INT_MUL:         3.0,
        OpClass.INT_DIV:        10.0,
        OpClass.INT_SHIFT:       1.0,
        OpClass.INT_BITWISE:     1.0,
        OpClass.INT_COMPARE:     1.0,
        OpClass.INT_LOGIC:       1.0,
        OpClass.FP_ADD:          4.0,
        OpClass.FP_MUL:          5.0,
        OpClass.FP_DIV:         15.0,
        OpClass.FP_COMPARE:      2.0,
        OpClass.FP_CONV:         3.0,
        OpClass.MEM_LOAD:        4.0,
        OpClass.MEM_STORE:       4.0,
        OpClass.MEM_STACK_PUSH:  4.0,
        OpClass.MEM_STACK_POP:   4.0,
        OpClass.BRANCH_UNCOND:   1.0,
        OpClass.BRANCH_COND:     2.0,
        OpClass.CALL:            8.0,
        OpClass.RETURN:          5.0,
        OpClass.IO_READ:        50.0,
        OpClass.IO_WRITE:       50.0,
        OpClass.SYSCALL:       100.0,
        OpClass.NOP:             0.0,
        OpClass.CAST:            1.0,
        OpClass.ALLOC:          40.0,
        OpClass.FREE:           35.0,
        OpClass.UNKNOWN:         2.0,
    }


# ── Profile registry ─────────────────────────────────────────────────

BUILTIN_PROFILES: Dict[str, EnergyProfile] = {
    "ARM_CM0": EnergyProfile(
        name="ARM_CM0",
        description="ARM Cortex-M0 ultra-low-power embedded core",
        unit="pJ",
        frequency_mhz=48.0,
        weights=_arm_cm0_weights(),
        cache_miss_penalty=0.0,         # no cache on M0
        pipeline_stall_penalty=0.0,
    ),
    "ARM_CM4": EnergyProfile(
        name="ARM_CM4",
        description="ARM Cortex-M4F mid-range embedded with hardware FPU",
        unit="pJ",
        frequency_mhz=168.0,
        weights=_arm_cm4_weights(),
        cache_miss_penalty=20.0,
        pipeline_stall_penalty=5.0,
    ),
    "ARM_CA53": EnergyProfile(
        name="ARM_CA53",
        description="ARM Cortex-A53 mobile application processor",
        unit="pJ",
        frequency_mhz=1200.0,
        weights=_arm_ca53_weights(),
        cache_miss_penalty=80.0,
        pipeline_stall_penalty=12.0,
    ),
    "X86_ATOM": EnergyProfile(
        name="X86_ATOM",
        description="Intel Atom N270 low-power x86",
        unit="pJ",
        frequency_mhz=1600.0,
        weights=_x86_atom_weights(),
        cache_miss_penalty=100.0,
        pipeline_stall_penalty=15.0,
    ),
    "X86_SKYLAKE": EnergyProfile(
        name="X86_SKYLAKE",
        description="Intel Skylake desktop/server x86",
        unit="pJ",
        frequency_mhz=3500.0,
        weights=_x86_skylake_weights(),
        cache_miss_penalty=150.0,
        pipeline_stall_penalty=20.0,
    ),
    "RISCV_E31": EnergyProfile(
        name="RISCV_E31",
        description="SiFive E31 RISC-V embedded core",
        unit="pJ",
        frequency_mhz=150.0,
        weights=_riscv_e31_weights(),
        cache_miss_penalty=15.0,
        pipeline_stall_penalty=4.0,
    ),
    "GENERIC": EnergyProfile(
        name="GENERIC",
        description="Architecture-agnostic normalised weights (dimensionless)",
        unit="AEU",
        frequency_mhz=None,
        weights=_generic_weights(),
        cache_miss_penalty=10.0,
        pipeline_stall_penalty=2.0,
    ),
}

DEFAULT_PROFILE_NAME: str = "GENERIC"


def load_profile(name_or_path: str) -> EnergyProfile:
    """
    Resolve an energy profile by built-in name or JSON file path.

    Parameters
    ----------
    name_or_path : str
        Either a key in BUILTIN_PROFILES (case-insensitive) or a
        filesystem path to a JSON file whose schema matches
        ``EnergyProfile.to_dict()``.

    Returns
    -------
    EnergyProfile
    """
    key = name_or_path.upper().replace("-", "_").replace(" ", "_")
    if key in BUILTIN_PROFILES:
        return BUILTIN_PROFILES[key]
    # Try as file path
    path = os.path.expanduser(name_or_path)
    if os.path.isfile(path):
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return EnergyProfile.from_dict(data)
    raise ValueError(
        f"Unknown energy profile '{name_or_path}'. "
        f"Built-in profiles: {', '.join(sorted(BUILTIN_PROFILES))}. "
        f"Or pass a path to a JSON profile file."
    )


# ═════════════════════════════════════════════════════════════════════
# §3  SYMBOLIC COST EXPRESSIONS  (CostExpr algebra)
# ═════════════════════════════════════════════════════════════════════
#
# We embed a lightweight CostExpr algebra directly so the addon is
# self-contained.  When StaticCostAnalysis.py is on the path, we
# re-export its richer implementation; otherwise the local one suffices.

try:
    from StaticCostAnalysis import (  # type: ignore[import-untyped]
        CostExpr,
        CostConst,
        CostVar,
        CostAdd,
        CostMul,
        CostMax,
        CostMin,
    )
except ImportError:
    # ── Self-contained CostExpr algebra ──────────────────────────────

    class CostExpr:
        """Base class for symbolic cost expressions."""

        def __add__(self, other: CostExpr) -> CostExpr:
            if isinstance(other, CostConst) and other.value == 0:
                return self
            if isinstance(self, CostConst) and self.value == 0:
                return other
            return CostAdd(self, other)

        def __mul__(self, other: CostExpr) -> CostExpr:
            if isinstance(other, CostConst) and other.value == 1:
                return self
            if isinstance(self, CostConst) and self.value == 1:
                return other
            if isinstance(other, CostConst) and other.value == 0:
                return CostConst(0)
            if isinstance(self, CostConst) and self.value == 0:
                return CostConst(0)
            return CostMul(self, other)

        def __radd__(self, other: Any) -> CostExpr:
            if isinstance(other, (int, float)):
                return CostConst(other) + self
            return NotImplemented

        def __rmul__(self, other: Any) -> CostExpr:
            if isinstance(other, (int, float)):
                return CostConst(other) * self
            return NotImplemented

        def evaluate(self, env: Dict[str, float]) -> float:
            raise NotImplementedError

        def free_vars(self) -> Set[str]:
            raise NotImplementedError

        def substitute(self, var: str, expr: CostExpr) -> CostExpr:
            raise NotImplementedError

        def simplify(self) -> CostExpr:
            return self

    class CostConst(CostExpr):
        __slots__ = ("value",)

        def __init__(self, value: float):
            self.value = float(value)

        def evaluate(self, env: Dict[str, float]) -> float:
            return self.value

        def free_vars(self) -> Set[str]:
            return set()

        def substitute(self, var: str, expr: CostExpr) -> CostExpr:
            return self

        def simplify(self) -> CostExpr:
            return self

        def __repr__(self) -> str:
            v = self.value
            return str(int(v)) if v == int(v) else f"{v:.4g}"

    class CostVar(CostExpr):
        __slots__ = ("name",)

        def __init__(self, name: str):
            self.name = name

        def evaluate(self, env: Dict[str, float]) -> float:
            if self.name not in env:
                raise KeyError(f"Unbound cost variable: {self.name}")
            return env[self.name]

        def free_vars(self) -> Set[str]:
            return {self.name}

        def substitute(self, var: str, expr: CostExpr) -> CostExpr:
            return expr if var == self.name else self

        def __repr__(self) -> str:
            return self.name

    class CostAdd(CostExpr):
        __slots__ = ("left", "right")

        def __init__(self, left: CostExpr, right: CostExpr):
            self.left, self.right = left, right

        def evaluate(self, env: Dict[str, float]) -> float:
            return self.left.evaluate(env) + self.right.evaluate(env)

        def free_vars(self) -> Set[str]:
            return self.left.free_vars() | self.right.free_vars()

        def substitute(self, var: str, expr: CostExpr) -> CostExpr:
            return CostAdd(
                self.left.substitute(var, expr),
                self.right.substitute(var, expr),
            )

        def simplify(self) -> CostExpr:
            l, r = self.left.simplify(), self.right.simplify()
            if isinstance(l, CostConst) and isinstance(r, CostConst):
                return CostConst(l.value + r.value)
            if isinstance(l, CostConst) and l.value == 0:
                return r
            if isinstance(r, CostConst) and r.value == 0:
                return l
            return CostAdd(l, r)

        def __repr__(self) -> str:
            return f"({self.left} + {self.right})"

    class CostMul(CostExpr):
        __slots__ = ("left", "right")

        def __init__(self, left: CostExpr, right: CostExpr):
            self.left, self.right = left, right

        def evaluate(self, env: Dict[str, float]) -> float:
            return self.left.evaluate(env) * self.right.evaluate(env)

        def free_vars(self) -> Set[str]:
            return self.left.free_vars() | self.right.free_vars()

        def substitute(self, var: str, expr: CostExpr) -> CostExpr:
            return CostMul(
                self.left.substitute(var, expr),
                self.right.substitute(var, expr),
            )

        def simplify(self) -> CostExpr:
            l, r = self.left.simplify(), self.right.simplify()
            if isinstance(l, CostConst) and isinstance(r, CostConst):
                return CostConst(l.value * r.value)
            if isinstance(l, CostConst) and l.value == 1:
                return r
            if isinstance(r, CostConst) and r.value == 1:
                return l
            if isinstance(l, CostConst) and l.value == 0:
                return CostConst(0)
            if isinstance(r, CostConst) and r.value == 0:
                return CostConst(0)
            return CostMul(l, r)

        def __repr__(self) -> str:
            return f"({self.left} × {self.right})"

    class CostMax(CostExpr):
        __slots__ = ("left", "right")

        def __init__(self, left: CostExpr, right: CostExpr):
            self.left, self.right = left, right

        def evaluate(self, env: Dict[str, float]) -> float:
            return max(self.left.evaluate(env), self.right.evaluate(env))

        def free_vars(self) -> Set[str]:
            return self.left.free_vars() | self.right.free_vars()

        def substitute(self, var: str, expr: CostExpr) -> CostExpr:
            return CostMax(
                self.left.substitute(var, expr),
                self.right.substitute(var, expr),
            )

        def simplify(self) -> CostExpr:
            l, r = self.left.simplify(), self.right.simplify()
            if isinstance(l, CostConst) and isinstance(r, CostConst):
                return CostConst(max(l.value, r.value))
            return CostMax(l, r)

        def __repr__(self) -> str:
            return f"max({self.left}, {self.right})"

    class CostMin(CostExpr):
        __slots__ = ("left", "right")

        def __init__(self, left: CostExpr, right: CostExpr):
            self.left, self.right = left, right

        def evaluate(self, env: Dict[str, float]) -> float:
            return min(self.left.evaluate(env), self.right.evaluate(env))

        def free_vars(self) -> Set[str]:
            return self.left.free_vars() | self.right.free_vars()

        def substitute(self, var: str, expr: CostExpr) -> CostExpr:
            return CostMin(
                self.left.substitute(var, expr),
                self.right.substitute(var, expr),
            )

        def simplify(self) -> CostExpr:
            l, r = self.left.simplify(), self.right.simplify()
            if isinstance(l, CostConst) and isinstance(r, CostConst):
                return CostConst(min(l.value, r.value))
            return CostMin(l, r)

        def __repr__(self) -> str:
            return f"min({self.left}, {self.right})"


# ═════════════════════════════════════════════════════════════════════
# §4  ENERGY EVENTS (Abstract Execution Event Definitions)
# ═════════════════════════════════════════════════════════════════════

@dataclass
class EnergyEvent:
    """
    Base event emitted during abstract execution whenever an energy-
    relevant operation is encountered.

    This mirrors the AbsExecEvent pattern from abstract_exec.py:
    the abstract VM emits events, and the analysis engine consumes
    them to accumulate energy costs.
    """
    kind: str                          # event discriminator
    op_class: OpClass                  # classified operation
    token: Optional[Any] = None        # cppcheckdata.Token or None
    scope_name: Optional[str] = None   # enclosing function/scope name
    file: Optional[str] = None
    line: Optional[int] = None
    column: Optional[int] = None
    energy_weight: float = 0.0         # resolved energy for this event
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class InstructionEnergyEvent(EnergyEvent):
    """
    Event for a single C-level instruction (arithmetic, logic, etc.).
    """
    kind: str = "instruction"
    operand_types: Tuple[str, ...] = ()   # e.g. ("int", "int")


@dataclass
class MemoryEnergyEvent(EnergyEvent):
    """
    Event for a memory operation (load, store, stack push/pop).
    """
    kind: str = "memory"
    access_size_bytes: int = 4             # estimated access width
    is_volatile: bool = False
    array_index_interval: Optional[IntervalDomain] = None


@dataclass
class BranchEnergyEvent(EnergyEvent):
    """
    Event for control-flow operations (branches, calls, returns).
    """
    kind: str = "branch"
    is_loop_back_edge: bool = False
    loop_trip_bound: Optional[IntervalDomain] = None
    callee_name: Optional[str] = None


@dataclass
class IOEnergyEvent(EnergyEvent):
    """
    Event for I/O and system-call operations.
    """
    kind: str = "io"
    io_function: Optional[str] = None      # e.g. "printf", "fread"
    buffer_size_interval: Optional[IntervalDomain] = None


@dataclass
class AllocationEnergyEvent(EnergyEvent):
    """
    Event for heap allocation / deallocation.
    """
    kind: str = "allocation"
    alloc_size_interval: Optional[IntervalDomain] = None
    is_deallocation: bool = False


# ═════════════════════════════════════════════════════════════════════
# §5  TOKEN → OpClass  CLASSIFIER
# ═════════════════════════════════════════════════════════════════════

# Well-known I/O and allocation function names for classification.

_IO_READ_FUNCS: FrozenSet[str] = frozenset({
    "scanf", "fscanf", "sscanf", "vscanf", "vfscanf", "vsscanf",
    "fread", "fgets", "fgetc", "getchar", "getc", "gets", "gets_s",
    "read", "recv", "recvfrom", "recvmsg", "fgetws",
})

_IO_WRITE_FUNCS: FrozenSet[str] = frozenset({
    "printf", "fprintf", "sprintf", "snprintf", "vprintf", "vfprintf",
    "vsprintf", "vsnprintf", "fwrite", "fputs", "fputc", "putchar",
    "putc", "puts", "write", "send", "sendto", "sendmsg", "fputws",
    "wprintf", "fwprintf",
})

_ALLOC_FUNCS: FrozenSet[str] = frozenset({
    "malloc", "calloc", "realloc", "aligned_alloc", "posix_memalign",
    "new", "new[]", "operator new", "operator new[]",
})

_FREE_FUNCS: FrozenSet[str] = frozenset({
    "free", "delete", "delete[]", "operator delete", "operator delete[]",
})

_SYSCALL_FUNCS: FrozenSet[str] = frozenset({
    "system", "exec", "execl", "execle", "execlp", "execv", "execve",
    "execvp", "fork", "vfork", "clone", "wait", "waitpid",
    "open", "close", "ioctl", "mmap", "munmap", "mprotect",
    "socket", "bind", "listen", "accept", "connect",
})


def _is_fp_context(token: Any) -> bool:
    """
    Heuristically determine whether *token* operates in a floating-point
    context by inspecting its valueType and operand types.
    """
    if token is None:
        return False
    vt = getattr(token, "valueType", None)
    if vt is not None:
        if getattr(vt, "type", None) in ("float", "double", "long double"):
            return True
    # Check operands
    for operand in (getattr(token, "astOperand1", None),
                    getattr(token, "astOperand2", None)):
        if operand is not None:
            ovt = getattr(operand, "valueType", None)
            if ovt is not None and getattr(ovt, "type", None) in (
                "float", "double", "long double"
            ):
                return True
    return False


def _get_function_call_name(token: Any) -> Optional[str]:
    """
    If *token* is the name token of a function call ``f(...)``, return
    the fully-qualified name.  Otherwise return None.
    """
    if token is None:
        return None
    if not getattr(token, "isName", False):
        return None
    nxt = getattr(token, "next", None)
    if nxt is None or getattr(nxt, "str", None) != "(":
        return None
    # Build qualified name by walking back through ::
    parts: List[str] = [token.str]
    t = getattr(token, "previous", None)
    while t is not None and getattr(t, "str", None) == "::":
        t = getattr(t, "previous", None)
        if t is not None and getattr(t, "isName", False):
            parts.append(t.str)
            t = getattr(t, "previous", None)
        else:
            break
    parts.reverse()
    return "::".join(parts)


def classify_token(token: Any) -> OpClass:
    """
    Map a cppcheckdata Token to an OpClass.

    This is the central classification dispatch used during abstract
    execution to determine the energy weight of each source-level
    operation.

    The classifier uses token attributes (str, isArithmeticalOp,
    isAssignmentOp, isComparisonOp, isLogicalOp, valueType, …) from
    the cppcheckdata schema.
    """
    if token is None:
        return OpClass.UNKNOWN

    tok_str = getattr(token, "str", "") or ""

    # ── Function calls ───────────────────────────────────────────────
    fname = _get_function_call_name(token)
    if fname is not None:
        base = fname.split("::")[-1]
        if base in _IO_READ_FUNCS:
            return OpClass.IO_READ
        if base in _IO_WRITE_FUNCS:
            return OpClass.IO_WRITE
        if base in _ALLOC_FUNCS:
            return OpClass.ALLOC
        if base in _FREE_FUNCS:
            return OpClass.FREE
        if base in _SYSCALL_FUNCS:
            return OpClass.SYSCALL
        return OpClass.CALL

    # ── Keywords ─────────────────────────────────────────────────────
    if tok_str == "return":
        return OpClass.RETURN
    if tok_str in ("if", "while", "for", "switch", "?"):
        return OpClass.BRANCH_COND
    if tok_str in ("goto", "break", "continue"):
        return OpClass.BRANCH_UNCOND

    # ── Cast expressions ─────────────────────────────────────────────
    if getattr(token, "isCast", False):
        # int↔float casts have measurable cost
        if _is_fp_context(token):
            return OpClass.FP_CONV
        return OpClass.CAST

    # ── Arithmetic operators ─────────────────────────────────────────
    if getattr(token, "isArithmeticalOp", False):
        fp = _is_fp_context(token)
        if tok_str in ("+", "-"):
            return OpClass.FP_ADD if fp else OpClass.INT_ADD
        if tok_str == "*":
            return OpClass.FP_MUL if fp else OpClass.INT_MUL
        if tok_str in ("/", "%"):
            return OpClass.FP_DIV if fp else OpClass.INT_DIV

    # ── Shift operators ──────────────────────────────────────────────
    if tok_str in ("<<", ">>"):
        return OpClass.INT_SHIFT

    # ── Bitwise operators ────────────────────────────────────────────
    if tok_str in ("&", "|", "^", "~"):
        # Distinguish address-of & from bitwise AND via AST arity
        if tok_str == "&" and getattr(token, "astOperand2", None) is None:
            return OpClass.MEM_LOAD   # address-of is essentially a load
        return OpClass.INT_BITWISE

    # ── Comparison operators ─────────────────────────────────────────
    if getattr(token, "isComparisonOp", False):
        if _is_fp_context(token):
            return OpClass.FP_COMPARE
        return OpClass.INT_COMPARE

    # ── Logical operators ────────────────────────────────────────────
    if getattr(token, "isLogicalOp", False) or tok_str == "!":
        return OpClass.INT_LOGIC

    # ── Assignment (store) ───────────────────────────────────────────
    if getattr(token, "isAssignmentOp", False):
        return OpClass.MEM_STORE

    # ── Increment / Decrement ────────────────────────────────────────
    if tok_str in ("++", "--"):
        # load + add + store; we classify as INT_ADD (dominant cost)
        return OpClass.INT_ADD

    # ── Array subscript → memory load ────────────────────────────────
    if tok_str == "[":
        return OpClass.MEM_LOAD

    # ── Variable reference → memory load ─────────────────────────────
    if getattr(token, "isName", False) and getattr(token, "varId", None):
        # Only count as a load if this isn't the LHS of an assignment
        parent = getattr(token, "astParent", None)
        if parent is not None and getattr(parent, "isAssignmentOp", False):
            if getattr(parent, "astOperand1", None) is token:
                return OpClass.MEM_STORE
        return OpClass.MEM_LOAD

    # ── Semicolons, braces, etc. → NOP ───────────────────────────────
    if tok_str in (";", "{", "}", "(", ")", ",", "...", ""):
        return OpClass.NOP

    return OpClass.UNKNOWN


# ═════════════════════════════════════════════════════════════════════
# §6  LOOP BOUND ANALYSIS (simplified)
# ═════════════════════════════════════════════════════════════════════

@dataclass
class LoopBound:
    """Represents a loop's estimated iteration bound."""
    scope_id: Optional[str] = None
    file: Optional[str] = None
    line: Optional[int] = None
    bound_interval: IntervalDomain = field(
        default_factory=lambda: IntervalDomain.top()
    )
    symbolic_bound: Optional[CostExpr] = None
    is_exact: bool = False
    induction_var: Optional[str] = None

    def upper_bound_value(self) -> float:
        """Return the scalar upper bound, or +∞ if unknown."""
        if self.bound_interval.is_top() or self.bound_interval.hi == float('inf'):
            if self.symbolic_bound is not None:
                try:
                    return self.symbolic_bound.evaluate({})
                except (KeyError, TypeError):
                    pass
            return float('inf')
        return self.bound_interval.hi


def _try_extract_loop_bound(scope: Any) -> LoopBound:
    """
    Attempt to extract a loop bound from a Cppcheck Scope object
    representing a for/while/do-while loop.

    Strategy:
      1. For ``for (init; cond; incr)`` — parse the condition to find
         a comparison with a constant, and the init to find the start.
      2. For ``while (cond)`` — similar but without guaranteed init.
      3. Fall back to a configurable default or symbolic variable.

    This is intentionally conservative: we over-approximate (return ⊤)
    rather than under-approximate.
    """
    lb = LoopBound()
    if scope is None:
        return lb

    lb.scope_id = getattr(scope, "Id", None)
    stype = getattr(scope, "type", "")

    # Get the loop's class token (for / while / do)
    class_start = getattr(scope, "classStart", None)
    if class_start is None:
        return lb

    # Walk backwards to find 'for' or 'while' keyword
    tok = getattr(class_start, "previous", None)
    # skip ')'
    if tok is not None and getattr(tok, "str", "") == ")":
        tok = getattr(tok, "link", None)   # jump to matching '('
        if tok is not None:
            tok = getattr(tok, "previous", None)

    keyword = getattr(tok, "str", "") if tok is not None else ""
    lb.file = getattr(tok, "file", None)
    lb.line = getattr(tok, "linenr", None)

    if keyword == "for":
        return _extract_for_bound(tok, lb)
    elif keyword in ("while", "do"):
        return _extract_while_bound(tok, lb)

    # Unknown loop form — return ⊤
    return lb


def _extract_for_bound(for_tok: Any, lb: LoopBound) -> LoopBound:
    """
    Extract bound from ``for (init; cond; incr)``.

    We look for patterns like:
      - ``for (int i = A; i < B; i++)``  → bound = B - A
      - ``for (int i = A; i < B; i += S)``  → bound = ceil((B - A) / S)
    """
    paren = getattr(for_tok, "next", None)
    if paren is None or getattr(paren, "str", "") != "(":
        return lb

    close_paren = getattr(paren, "link", None)
    if close_paren is None:
        return lb

    # Collect tokens between ( and ) and split on ';'
    parts: List[List[Any]] = [[]]
    t = getattr(paren, "next", None)
    while t is not None and t is not close_paren:
        if getattr(t, "str", "") == ";":
            parts.append([])
        else:
            parts[-1].append(t)
        t = getattr(t, "next", None)

    if len(parts) < 3:
        return lb

    init_toks, cond_toks, incr_toks = parts[0], parts[1], parts[2]

    # --- Parse init: look for "VAR = CONST" ---
    init_val: Optional[float] = None
    var_name: Optional[str] = None
    for i, tk in enumerate(init_toks):
        if getattr(tk, "str", "") == "=" and i > 0:
            var_name = getattr(init_toks[i - 1], "str", None)
            if i + 1 < len(init_toks):
                rhs = init_toks[i + 1]
                if getattr(rhs, "isNumber", False):
                    try:
                        init_val = float(rhs.str)
                    except (ValueError, TypeError):
                        pass
            break

    # --- Parse cond: look for "VAR < CONST" or "VAR <= CONST" etc. ---
    bound_val: Optional[float] = None
    cmp_op: Optional[str] = None
    for tk in cond_toks:
        if getattr(tk, "isComparisonOp", False):
            cmp_op = getattr(tk, "str", "")
            rhs = getattr(tk, "astOperand2", None)
            if rhs is not None and getattr(rhs, "isNumber", False):
                try:
                    bound_val = float(rhs.str)
                except (ValueError, TypeError):
                    pass
            elif rhs is not None and getattr(rhs, "isName", False):
                # Symbolic bound
                rhs_name = getattr(rhs, "str", "N")
                lb.symbolic_bound = CostVar(rhs_name)
            break

    # --- Parse incr: look for "VAR++" or "VAR += CONST" ---
    step: float = 1.0
    for tk in incr_toks:
        if getattr(tk, "str", "") in ("++", "--"):
            step = 1.0
            break
        if getattr(tk, "str", "") in ("+=", "-="):
            rhs = getattr(tk, "astOperand2", None)
            if rhs is not None and getattr(rhs, "isNumber", False):
                try:
                    step = float(rhs.str)
                except (ValueError, TypeError):
                    step = 1.0
            break

    # --- Compute bound ---
    lb.induction_var = var_name

    if bound_val is not None and init_val is not None:
        if cmp_op in ("<", "!="):
            trip = max(0.0, math.ceil((bound_val - init_val) / step))
        elif cmp_op == "<=":
            trip = max(0.0, math.ceil((bound_val - init_val + 1) / step))
        elif cmp_op == ">":
            trip = max(0.0, math.ceil((init_val - bound_val) / step))
        elif cmp_op == ">=":
            trip = max(0.0, math.ceil((init_val - bound_val + 1) / step))
        else:
            trip = float('inf')

        if trip != float('inf'):
            lb.bound_interval = IntervalDomain.range(0.0, trip)
            lb.symbolic_bound = CostConst(trip)
            lb.is_exact = True
        return lb

    if bound_val is not None and init_val is None:
        # Upper bound known but start unknown → conservative
        if cmp_op in ("<", "!="):
            lb.bound_interval = IntervalDomain.range(0.0, bound_val)
        elif cmp_op == "<=":
            lb.bound_interval = IntervalDomain.range(0.0, bound_val + 1)
        lb.symbolic_bound = CostConst(bound_val)
        return lb

    if lb.symbolic_bound is not None and init_val is not None:
        # Symbolic upper - concrete lower
        lb.symbolic_bound = lb.symbolic_bound + CostConst(-init_val)
        return lb

    # Generate a fresh symbolic variable for unknowable bounds
    if var_name:
        lb.symbolic_bound = CostVar(f"N_{var_name}")
    else:
        lb.symbolic_bound = CostVar("N_loop")

    return lb


def _extract_while_bound(while_tok: Any, lb: LoopBound) -> LoopBound:
    """
    Extract bound from ``while (cond)`` or ``do { ... } while (cond)``.

    Less information is available than for ``for`` loops, so we try to
    find a comparison and otherwise fall back to a symbolic variable.
    """
    paren = getattr(while_tok, "next", None)
    if paren is None or getattr(paren, "str", "") != "(":
        # do-while: condition is after the body
        lb.symbolic_bound = CostVar("N_while")
        return lb

    close_paren = getattr(paren, "link", None)
    if close_paren is None:
        lb.symbolic_bound = CostVar("N_while")
        return lb

    # Walk tokens in condition looking for a comparison with a constant
    t = getattr(paren, "next", None)
    while t is not None and t is not close_paren:
        if getattr(t, "isComparisonOp", False):
            rhs = getattr(t, "astOperand2", None)
            if rhs is not None and getattr(rhs, "isNumber", False):
                try:
                    bound_val = float(rhs.str)
                    lb.bound_interval = IntervalDomain.range(0.0, bound_val)
                    lb.symbolic_bound = CostConst(bound_val)
                    return lb
                except (ValueError, TypeError):
                    pass
            elif rhs is not None and getattr(rhs, "isName", False):
                lb.symbolic_bound = CostVar(getattr(rhs, "str", "N"))
                return lb
        t = getattr(t, "next", None)

    lb.symbolic_bound = CostVar("N_while")
    return lb


# ═════════════════════════════════════════════════════════════════════
# §7  ENERGY ACCUMULATOR
# ═════════════════════════════════════════════════════════════════════

@dataclass
class EnergySummary:
    """
    Per-function (or per-scope) energy summary, accumulating both a
    concrete interval bound and a symbolic cost expression.
    """
    scope_name: str
    file: Optional[str] = None
    start_line: Optional[int] = None
    end_line: Optional[int] = None

    # Concrete interval: [lo, hi] in the profile's energy unit
    total_interval: IntervalDomain = field(
        default_factory=lambda: IntervalDomain.const(0.0)
    )

    # Symbolic expression parameterised by loop trip variables
    total_symbolic: CostExpr = field(default_factory=lambda: CostConst(0))

    # Breakdown by OpClass
    breakdown: Dict[OpClass, float] = field(default_factory=lambda: defaultdict(float))
    breakdown_symbolic: Dict[OpClass, CostExpr] = field(
        default_factory=lambda: defaultdict(lambda: CostConst(0))
    )

    # Hotspot tracking: (line, energy) pairs
    hotspots: List[Tuple[int, float, OpClass]] = field(default_factory=list)

    # Event count
    event_count: int = 0

    # Nested loop multiplier stack
    _loop_multiplier_stack: List[CostExpr] = field(default_factory=list)
    _loop_interval_stack: List[IntervalDomain] = field(default_factory=list)

    def push_loop(self, bound: LoopBound) -> None:
        """Enter a loop scope — future costs are multiplied by the bound."""
        sym = bound.symbolic_bound if bound.symbolic_bound is not None else CostVar("N")
        self._loop_multiplier_stack.append(sym)
        self._loop_interval_stack.append(bound.bound_interval)

    def pop_loop(self) -> None:
        """Exit a loop scope."""
        if self._loop_multiplier_stack:
            self._loop_multiplier_stack.pop()
        if self._loop_interval_stack:
            self._loop_interval_stack.pop()

    @property
    def current_loop_multiplier(self) -> CostExpr:
        """Product of all enclosing loop bounds (symbolic)."""
        result: CostExpr = CostConst(1)
        for m in self._loop_multiplier_stack:
            result = result * m
        return result

    @property
    def current_loop_interval_multiplier(self) -> IntervalDomain:
        """Product of all enclosing loop bounds (interval)."""
        result = IntervalDomain.const(1.0)
        for iv in self._loop_interval_stack:
            result = result.mul(iv)
        return result

    def add_event(self, event: EnergyEvent) -> None:
        """Incorporate an energy event into this summary."""
        self.event_count += 1
        weight = event.energy_weight

        # Interval accumulation
        w_interval = IntervalDomain.const(weight)
        contribution = self.current_loop_interval_multiplier.mul(w_interval)
        self.total_interval = self.total_interval.add(contribution)

        # Symbolic accumulation
        w_sym = CostConst(weight)
        sym_contribution = self.current_loop_multiplier * w_sym
        self.total_symbolic = self.total_symbolic + sym_contribution

        # Breakdown
        if contribution.is_const():
            self.breakdown[event.op_class] += contribution.lo
        else:
            self.breakdown[event.op_class] += weight  # lower bound
        self.breakdown_symbolic[event.op_class] = (
            self.breakdown_symbolic[event.op_class] + sym_contribution
        )

        # Hotspot
        line = event.line or 0
        self.hotspots.append((line, weight, event.op_class))

    def top_hotspots(self, n: int = 10) -> List[Tuple[int, float, str]]:
        """Return the top *n* hotspot lines by per-occurrence energy."""
        # Aggregate by line
        by_line: Dict[int, float] = defaultdict(float)
        by_line_op: Dict[int, OpClass] = {}
        for line, w, op in self.hotspots:
            by_line[line] += w
            by_line_op[line] = op  # last one wins (approximate)
        ranked = sorted(by_line.items(), key=lambda x: -x[1])[:n]
        return [(line, cost, by_line_op.get(line, OpClass.UNKNOWN).value)
                for line, cost in ranked]

    def dominant_category(self) -> Optional[OpClass]:
        """Return the OpClass that accounts for the most energy."""
        if not self.breakdown:
            return None
        return max(self.breakdown, key=lambda k: self.breakdown[k])

    def simplify(self) -> None:
        """Simplify the symbolic total cost expression."""
        self.total_symbolic = self.total_symbolic.simplify()
        for op in list(self.breakdown_symbolic):
            self.breakdown_symbolic[op] = self.breakdown_symbolic[op].simplify()


# ═════════════════════════════════════════════════════════════════════
# §8  CALL GRAPH ENERGY PROPAGATION
# ═════════════════════════════════════════════════════════════════════

@dataclass
class CallGraphNode:
    """Represents a function in the call graph with its energy summary."""
    name: str
    summary: EnergySummary
    callees: List[str] = field(default_factory=list)
    callers: List[str] = field(default_factory=list)
    call_count: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    propagated: bool = False


class CallGraphEnergyPropagator:
    """
    Bottom-up propagation of energy costs through the call graph.

    Given per-function EnergySummary objects, this class propagates
    callee energy into callers, handling:
      • direct calls with known call counts
      • recursive cycles (conservative: add a CostVar for recursion depth)
      • missing callees (external/library: use a configurable penalty)
    """

    def __init__(
        self,
        nodes: Dict[str, CallGraphNode],
        external_call_penalty: float = 100.0,
        max_recursion_depth_var: str = "R_depth",
    ):
        self.nodes = nodes
        self.external_call_penalty = external_call_penalty
        self.max_recursion_depth_var = max_recursion_depth_var

    def propagate(self) -> None:
        """
        Perform bottom-up propagation.

        We topologically sort the call graph (treating SCCs as single
        nodes with a recursion penalty) and propagate callee energy
        upward.
        """
        # Build adjacency
        visited: Set[str] = set()
        order: List[str] = []

        # Topological sort via DFS post-order
        in_stack: Set[str] = set()
        recursive_edges: Set[Tuple[str, str]] = set()

        def dfs(name: str) -> None:
            if name in visited:
                return
            visited.add(name)
            in_stack.add(name)
            node = self.nodes.get(name)
            if node is None:
                in_stack.discard(name)
                return
            for callee in node.callees:
                if callee in in_stack:
                    recursive_edges.add((name, callee))
                    continue
                dfs(callee)
            in_stack.discard(name)
            order.append(name)

        for name in self.nodes:
            dfs(name)

        # Propagate in reverse post-order (leaves first)
        for name in order:
            node = self.nodes.get(name)
            if node is None:
                continue
            for callee_name in node.callees:
                count = max(1, node.call_count.get(callee_name, 1))
                if (name, callee_name) in recursive_edges:
                    # Recursive: add symbolic penalty
                    rec_cost = CostVar(self.max_recursion_depth_var) * node.summary.total_symbolic
                    node.summary.total_symbolic = node.summary.total_symbolic + rec_cost
                    continue

                callee_node = self.nodes.get(callee_name)
                if callee_node is None:
                    # External function
                    ext_cost = CostConst(self.external_call_penalty * count)
                    node.summary.total_symbolic = node.summary.total_symbolic + ext_cost
                    ext_iv = IntervalDomain.const(self.external_call_penalty * count)
                    node.summary.total_interval = node.summary.total_interval.add(ext_iv)
                else:
                    callee_cost_sym = CostConst(count) * callee_node.summary.total_symbolic
                    node.summary.total_symbolic = node.summary.total_symbolic + callee_cost_sym
                    callee_iv = IntervalDomain.const(count).mul(callee_node.summary.total_interval)
                    node.summary.total_interval = node.summary.total_interval.add(callee_iv)

            node.propagated = True


# ═════════════════════════════════════════════════════════════════════
# §9  ENERGY ANALYSIS ENGINE
# ═════════════════════════════════════════════════════════════════════

@dataclass
class EnergyAnalysisConfig:
    """Configuration for the energy analysis pass."""
    profile_name: str = DEFAULT_PROFILE_NAME
    profile: Optional[EnergyProfile] = None   # resolved at init
    hotspot_threshold_pct: float = 10.0       # report lines > X% of function energy
    max_hotspots_per_function: int = 10
    external_call_penalty: float = 100.0
    report_breakdown: bool = True
    report_symbolic: bool = True
    warn_unbounded_loops: bool = True
    warn_high_energy_functions: float = 0.0   # 0 = disabled
    severity: str = "style"                   # cppcheck severity level

    def resolve_profile(self) -> EnergyProfile:
        if self.profile is not None:
            return self.profile
        self.profile = load_profile(self.profile_name)
        return self.profile


class EnergyAnalysisResult:
    """
    Complete result of the energy analysis over one translation unit.
    """

    def __init__(self, config: EnergyAnalysisConfig, profile: EnergyProfile):
        self.config = config
        self.profile = profile
        self.function_summaries: Dict[str, EnergySummary] = {}
        self.global_summary: EnergySummary = EnergySummary(scope_name="<global>")
        self.call_graph_nodes: Dict[str, CallGraphNode] = {}
        self.loop_bounds: List[LoopBound] = []
        self.events: List[EnergyEvent] = []
        self.warnings: List[Dict[str, Any]] = []

    def total_energy_interval(self) -> IntervalDomain:
        """Aggregate energy across all functions."""
        total = IntervalDomain.const(0.0)
        for s in self.function_summaries.values():
            total = total.add(s.total_interval)
        return total

    def total_energy_symbolic(self) -> CostExpr:
        """Aggregate symbolic energy across all functions."""
        total: CostExpr = CostConst(0)
        for s in self.function_summaries.values():
            total = total + s.total_symbolic
        return total.simplify()

    def ranked_functions(self) -> List[Tuple[str, float]]:
        """Functions ranked by upper-bound energy (descending)."""
        ranked = []
        for name, s in self.function_summaries.items():
            ub = s.total_interval.hi if not s.total_interval.is_top() else float('inf')
            ranked.append((name, ub))
        ranked.sort(key=lambda x: -x[1])
        return ranked

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the result for JSON output."""
        return {
            "profile": self.profile.to_dict(),
            "total_energy": {
                "interval": repr(self.total_energy_interval()),
                "symbolic": repr(self.total_energy_symbolic()),
            },
            "functions": {
                name: {
                    "interval": repr(s.total_interval),
                    "symbolic": repr(s.total_symbolic.simplify()),
                    "event_count": s.event_count,
                    "dominant_category": (s.dominant_category().value
                                         if s.dominant_category() else None),
                    "top_hotspots": s.top_hotspots(self.config.max_hotspots_per_function),
                    "breakdown": {op.value: cost for op, cost in s.breakdown.items() if cost > 0},
                }
                for name, s in self.function_summaries.items()
            },
            "loop_bounds": [
                {
                    "file": lb.file,
                    "line": lb.line,
                    "bound": repr(lb.bound_interval),
                    "symbolic": repr(lb.symbolic_bound) if lb.symbolic_bound else None,
                    "exact": lb.is_exact,
                }
                for lb in self.loop_bounds
            ],
            "warnings_count": len(self.warnings),
        }


class EnergyConsumptionEstimator:
    """
    Main analysis class — the Cppcheck addon entry point.

    This class:
      1. Iterates over all configurations in a parsed dump file.
      2. Builds per-function EnergySummary objects by walking the token
         list and emitting EnergyEvent objects.
      3. Analyses loop scopes to obtain iteration bounds.
      4. Propagates callee energy through the call graph.
      5. Reports hotspots and warnings via cppcheckdata.reportError.

    Usage from Cppcheck (in addon JSON or command-line):
        cppcheck --addon=EnergyConsumptionEstimator source.c

    Or standalone:
        python EnergyConsumptionEstimator.py source.c.dump
    """

    ADDON_NAME: ClassVar[str] = "EnergyConsumptionEstimator"

    def __init__(self, config: Optional[EnergyAnalysisConfig] = None):
        self.config = config or EnergyAnalysisConfig()
        self.profile = self.config.resolve_profile()

    # ── Token-level analysis ─────────────────────────────────────────

    def _emit_event(self, token: Any, op: OpClass, scope_name: str) -> EnergyEvent:
        """Create and return the appropriate EnergyEvent subclass."""
        weight = self.profile.weight(op)
        base_kwargs = dict(
            op_class=op,
            token=token,
            scope_name=scope_name,
            file=getattr(token, "file", None),
            line=getattr(token, "linenr", None),
            column=getattr(token, "column", None),
            energy_weight=weight,
        )

        if op in (OpClass.MEM_LOAD, OpClass.MEM_STORE,
                   OpClass.MEM_STACK_PUSH, OpClass.MEM_STACK_POP):
            # Determine access width from valueType
            access_size = 4  # default: 32-bit
            vt = getattr(token, "valueType", None)
            if vt is not None:
                vtype = getattr(vt, "type", "")
                ptr = getattr(vt, "pointer", 0) or 0
                if ptr > 0:
                    access_size = 8  # pointer
                elif vtype == "char":
                    access_size = 1
                elif vtype == "short":
                    access_size = 2
                elif vtype in ("long", "long long"):
                    access_size = 8
                elif vtype in ("float",):
                    access_size = 4
                elif vtype in ("double", "long double"):
                    access_size = 8
            is_vol = False
            # Check volatile via constness bits or keyword presence
            var = getattr(token, "variable", None)
            if var is not None:
                is_vol = getattr(var, "isVolatile", False)
            return MemoryEnergyEvent(
                **base_kwargs,
                access_size_bytes=access_size,
                is_volatile=is_vol,
            )

        if op in (OpClass.BRANCH_COND, OpClass.BRANCH_UNCOND,
                   OpClass.CALL, OpClass.RETURN):
            callee = None
            if op == OpClass.CALL:
                callee = _get_function_call_name(token)
            return BranchEnergyEvent(
                **base_kwargs,
                callee_name=callee,
            )

        if op in (OpClass.IO_READ, OpClass.IO_WRITE, OpClass.SYSCALL):
            io_fn = _get_function_call_name(token)
            return IOEnergyEvent(
                **base_kwargs,
                io_function=io_fn,
            )

        if op in (OpClass.ALLOC, OpClass.FREE):
            return AllocationEnergyEvent(
                **base_kwargs,
                is_deallocation=(op == OpClass.FREE),
            )

        return InstructionEnergyEvent(**base_kwargs)

    # ── Scope / function iteration ───────────────────────────────────

    def _get_scope_name(self, scope: Any) -> str:
        """Derive a human-readable name for a scope."""
        if scope is None:
            return "<unknown>"
        cls_name = getattr(scope, "className", None)
        stype = getattr(scope, "type", "")
        if cls_name:
            return cls_name
        if stype == "Global":
            return "<global>"
        if stype in ("For", "While", "Do"):
            line = getattr(scope, "bodyStart", None)
            if line:
                line = getattr(line, "linenr", "?")
            return f"<{stype.lower()}_loop@{line}>"
        if stype == "If":
            return "<if>"
        return f"<{stype}>"

    def _is_loop_scope(self, scope: Any) -> bool:
        stype = getattr(scope, "type", "")
        return stype in ("For", "While", "Do")

    def _find_enclosing_function(self, scope: Any) -> Optional[Any]:
        """Walk up scope.nestedIn to find the enclosing Function scope."""
        s = scope
        while s is not None:
            if getattr(s, "type", "") == "Function":
                return s
            s = getattr(s, "nestedIn", None)
        return None

    # ── Main analysis driver ─────────────────────────────────────────

    def analyse_configuration(self, cfg: Any) -> EnergyAnalysisResult:
        """
        Analyse a single Cppcheck configuration (cfg from parsedump).

        Returns an EnergyAnalysisResult populated with per-function
        summaries, loop bounds, events, and warnings.
        """
        result = EnergyAnalysisResult(self.config, self.profile)

        # ── Phase 1: Identify functions and create summaries ─────────
        function_scopes: Dict[str, Any] = {}   # name → scope
        for scope in getattr(cfg, "scopes", []):
            if getattr(scope, "type", "") == "Function":
                name = self._get_scope_name(scope)
                if name not in result.function_summaries:
                    result.function_summaries[name] = EnergySummary(
                        scope_name=name,
                        file=getattr(
                            getattr(scope, "bodyStart", None), "file", None
                        ),
                        start_line=getattr(
                            getattr(scope, "bodyStart", None), "linenr", None
                        ),
                        end_line=getattr(
                            getattr(scope, "bodyEnd", None), "linenr", None
                        ),
                    )
                    function_scopes[name] = scope
                    result.call_graph_nodes[name] = CallGraphNode(
                        name=name,
                        summary=result.function_summaries[name],
                    )

        # ── Phase 2: Identify loop scopes and extract bounds ─────────
        loop_scopes: Dict[str, LoopBound] = {}   # scope.Id → LoopBound
        for scope in getattr(cfg, "scopes", []):
            if self._is_loop_scope(scope):
                lb = _try_extract_loop_bound(scope)
                sid = getattr(scope, "Id", None)
                if sid is not None:
                    loop_scopes[sid] = lb
                    result.loop_bounds.append(lb)
                    if self.config.warn_unbounded_loops and not lb.is_exact:
                        if (lb.bound_interval.is_top() or
                                lb.bound_interval.hi == float('inf')):
                            result.warnings.append({
                                "type": "unbounded_loop",
                                "file": lb.file,
                                "line": lb.line,
                                "message": (
                                    f"Loop has no statically determinable "
                                    f"bound; energy estimate is parameterised "
                                    f"by {lb.symbolic_bound}"
                                ),
                            })

        # ── Phase 3: Walk tokens and emit energy events ──────────────
        # We track which loop scopes we are inside of via a stack.
        active_summaries: Dict[str, EnergySummary] = {}  # function name → summary
        scope_stack: List[Tuple[str, Any]] = []           # (scope_id, scope)

        for token in getattr(cfg, "tokenlist", []):
            # Determine enclosing scope
            token_scope = getattr(token, "scope", None)
            if token_scope is None:
                continue

            # Find the enclosing function
            func_scope = self._find_enclosing_function(token_scope)
            if func_scope is None:
                func_name = "<global>"
            else:
                func_name = self._get_scope_name(func_scope)

            summary = result.function_summaries.get(func_name)
            if summary is None:
                summary = result.global_summary

            # Handle loop scope enter/exit via bodyStart/bodyEnd tokens
            tok_str = getattr(token, "str", "")

            # Check if this token is the bodyStart of a loop scope
            for scope in getattr(cfg, "scopes", []):
                body_start = getattr(scope, "bodyStart", None)
                if body_start is not None and body_start is token:
                    sid = getattr(scope, "Id", None)
                    if sid in loop_scopes:
                        summary.push_loop(loop_scopes[sid])
                        scope_stack.append((sid, scope))

            # Classify and emit event
            op = classify_token(token)
            if op == OpClass.NOP:
                # Still check bodyEnd before skipping
                for scope in getattr(cfg, "scopes", []):
                    body_end = getattr(scope, "bodyEnd", None)
                    if body_end is not None and body_end is token:
                        sid = getattr(scope, "Id", None)
                        if scope_stack and scope_stack[-1][0] == sid:
                            summary.pop_loop()
                            scope_stack.pop()
                continue

            event = self._emit_event(token, op, func_name)
            summary.add_event(event)
            result.events.append(event)

            # Track call graph edges
            if op == OpClass.CALL:
                callee_name = _get_function_call_name(token)
                if callee_name and func_name in result.call_graph_nodes:
                    cg_node = result.call_graph_nodes[func_name]
                    if callee_name not in cg_node.callees:
                        cg_node.callees.append(callee_name)
                    cg_node.call_count[callee_name] += 1

            # Check if this token is the bodyEnd of a loop scope
            for scope in getattr(cfg, "scopes", []):
                body_end = getattr(scope, "bodyEnd", None)
                if body_end is not None and body_end is token:
                    sid = getattr(scope, "Id", None)
                    if scope_stack and scope_stack[-1][0] == sid:
                        summary.pop_loop()
                        scope_stack.pop()

        # ── Phase 4: Propagate call graph energy ─────────────────────
        propagator = CallGraphEnergyPropagator(
            nodes=result.call_graph_nodes,
            external_call_penalty=self.config.external_call_penalty,
        )
        propagator.propagate()

        # ── Phase 5: Simplify symbolic expressions ───────────────────
        for s in result.function_summaries.values():
            s.simplify()
        result.global_summary.simplify()

        # ── Phase 6: Generate hotspot warnings ───────────────────────
        self._generate_warnings(result)

        return result

    def _generate_warnings(self, result: EnergyAnalysisResult) -> None:
        """Generate cppcheck-style warnings from analysis results."""
        for func_name, summary in result.function_summaries.items():
            # Warn if total function energy exceeds threshold
            if (self.config.warn_high_energy_functions > 0 and
                    not summary.total_interval.is_top()):
                if summary.total_interval.hi > self.config.warn_high_energy_functions:
                    result.warnings.append({
                        "type": "high_energy_function",
                        "file": summary.file,
                        "line": summary.start_line,
                        "function": func_name,
                        "energy_upper_bound": summary.total_interval.hi,
                        "message": (
                            f"Function '{func_name}' has estimated worst-case "
                            f"energy {summary.total_interval} {self.profile.unit}"
                        ),
                    })

            # Hotspot warnings: lines that account for a large % of total
            total_concrete = summary.total_interval.hi if (
                not summary.total_interval.is_top() and
                summary.total_interval.hi > 0
            ) else None

            if total_concrete is not None and total_concrete > 0:
                threshold = total_concrete * (self.config.hotspot_threshold_pct / 100.0)
                for line, cost, op_name in summary.top_hotspots(
                    self.config.max_hotspots_per_function
                ):
                    if cost >= threshold and line > 0:
                        pct = (cost / total_concrete) * 100
                        result.warnings.append({
                            "type": "energy_hotspot",
                            "file": summary.file,
                            "line": line,
                            "function": func_name,
                            "energy": cost,
                            "percentage": round(pct, 1),
                            "op_class": op_name,
                            "message": (
                                f"Line {line} in '{func_name}' accounts for "
                                f"{pct:.1f}% of function energy "
                                f"({cost:.1f} {self.profile.unit}, "
                                f"category: {op_name})"
                            ),
                        })

    # ── Reporting ────────────────────────────────────────────────────

    def report(self, result: EnergyAnalysisResult, dumpfile: str = "") -> None:
        """
        Emit warnings through cppcheckdata.reportError and optionally
        print a summary to stderr.
        """
        for w in result.warnings:
            wtype = w.get("type", "")
            msg = w.get("message", "")
            wfile = w.get("file")
            wline = w.get("line", 0)

            if wfile is None:
                continue

            loc = cppcheckdata.Location({
                "file": wfile,
                "line": str(wline),
                "column": "0",
            })

            if wtype == "unbounded_loop":
                error_id = "energyUnboundedLoop"
                severity = "information"
            elif wtype == "high_energy_function":
                error_id = "energyHighFunction"
                severity = self.config.severity
            elif wtype == "energy_hotspot":
                error_id = "energyHotspot"
                severity = self.config.severity
            else:
                error_id = "energyGeneric"
                severity = "information"

            cppcheckdata.reportError(
                loc, severity, msg,
                self.ADDON_NAME, error_id,
            )

        # Summary report to stderr
        if result.function_summaries:
            sys.stderr.write(
                f"\n{'═' * 72}\n"
                f"  Energy Consumption Estimation Summary\n"
                f"  Profile: {self.profile.name} ({self.profile.unit})\n"
                f"{'═' * 72}\n\n"
            )
            for func_name, summary in result.function_summaries.items():
                sys.stderr.write(f"  Function: {func_name}\n")
                sys.stderr.write(f"    Energy interval: {summary.total_interval}\n")
                sys.stderr.write(f"    Symbolic bound:  {summary.total_symbolic}\n")
                sys.stderr.write(f"    Events:          {summary.event_count}\n")
                dom = summary.dominant_category()
                if dom:
                    sys.stderr.write(f"    Dominant class:  {dom.value}\n")
                if self.config.report_breakdown and summary.breakdown:
                    sys.stderr.write("    Breakdown:\n")
                    for op, cost in sorted(
                        summary.breakdown.items(), key=lambda x: -x[1]
                    ):
                        if cost > 0:
                            sys.stderr.write(
                                f"      {op.value:20s}  {cost:>12.1f} {self.profile.unit}\n"
                            )
                top = summary.top_hotspots(5)
                if top:
                    sys.stderr.write("    Top hotspot lines:\n")
                    for line, cost, op_name in top:
                        sys.stderr.write(
                            f"      L{line:<6d}  {cost:>10.1f} {self.profile.unit}  ({op_name})\n"
                        )
                sys.stderr.write("\n")

            total_iv = result.total_energy_interval()
            total_sym = result.total_energy_symbolic()
            sys.stderr.write(f"  Total energy interval: {total_iv}\n")
            sys.stderr.write(f"  Total symbolic bound:  {total_sym}\n")
            sys.stderr.write(f"  Warnings emitted:      {len(result.warnings)}\n")
            sys.stderr.write(f"{'═' * 72}\n\n")


# ═════════════════════════════════════════════════════════════════════
# §10  CPPCHECK ADDON ENTRY POINT
# ═════════════════════════════════════════════════════════════════════

def build_argparser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="EnergyConsumptionEstimator",
        description="Cppcheck addon: static worst-case energy consumption estimation.",
    )
    parser.add_argument(
        "dumpfiles",
        nargs="*",
        help="Cppcheck dump files (.dump) to analyse.",
    )
    parser.add_argument(
        "--energy-profile",
        default=DEFAULT_PROFILE_NAME,
        help=(
            f"Energy profile name or path to a JSON profile file. "
            f"Built-in: {', '.join(sorted(BUILTIN_PROFILES))}. "
            f"Default: {DEFAULT_PROFILE_NAME}"
        ),
    )
    parser.add_argument(
        "--hotspot-threshold",
        type=float,
        default=10.0,
        help="Report hotspot lines that account for more than X%% of function energy (default: 10).",
    )
    parser.add_argument(
        "--max-hotspots",
        type=int,
        default=10,
        help="Maximum number of hotspot lines to report per function (default: 10).",
    )
    parser.add_argument(
        "--external-call-penalty",
        type=float,
        default=100.0,
        help="Energy penalty (in profile units) per call to an external/unknown function (default: 100).",
    )
    parser.add_argument(
        "--warn-high-energy",
        type=float,
        default=0.0,
        help="Emit a warning if a function's WCEC exceeds this value (0 = disabled).",
    )
    parser.add_argument(
        "--no-breakdown",
        action="store_true",
        help="Suppress per-OpClass breakdown in the summary.",
    )
    parser.add_argument(
        "--no-symbolic",
        action="store_true",
        help="Suppress symbolic cost expressions in the output.",
    )
    parser.add_argument(
        "--no-warn-unbounded",
        action="store_true",
        help="Suppress warnings for loops without determinable bounds.",
    )
    parser.add_argument(
        "--json-output",
        type=str,
        default=None,
        help="Path to write a JSON report (in addition to cppcheck-style output).",
    )
    parser.add_argument(
        "--severity",
        default="style",
        choices=["error", "warning", "style", "performance", "portability", "information"],
        help="Cppcheck severity level for energy warnings (default: style).",
    )
    parser.add_argument(
        "--cli",
        action="store_true",
        help="Output in Cppcheck --addon CLI JSON format.",
    )
    parser.add_argument(
        "--list-profiles",
        action="store_true",
        help="List all built-in energy profiles and exit.",
    )
    return parser


def main() -> None:
    parser = build_argparser()
    args = parser.parse_args()

    # Ensure --cli flag propagates to cppcheckdata
    if args.cli and "--cli" not in sys.argv:
        sys.argv.append("--cli")

    # List profiles
    if args.list_profiles:
        sys.stderr.write("\nBuilt-in Energy Profiles:\n")
        sys.stderr.write("─" * 60 + "\n")
        for name, prof in sorted(BUILTIN_PROFILES.items()):
            sys.stderr.write(f"  {name:15s}  {prof.description}\n")
            sys.stderr.write(f"  {'':15s}  unit={prof.unit}  freq={prof.frequency_mhz} MHz\n")
            sys.stderr.write(f"  {'':15s}  cache_miss_penalty={prof.cache_miss_penalty}\n\n")
        sys.stderr.write("─" * 60 + "\n")
        sys.exit(0)

    if not args.dumpfiles:
        parser.print_help()
        sys.exit(1)

    # Build config
    config = EnergyAnalysisConfig(
        profile_name=args.energy_profile,
        hotspot_threshold_pct=args.hotspot_threshold,
        max_hotspots_per_function=args.max_hotspots,
        external_call_penalty=args.external_call_penalty,
        report_breakdown=not args.no_breakdown,
        report_symbolic=not args.no_symbolic,
        warn_unbounded_loops=not args.no_warn_unbounded,
        warn_high_energy_functions=args.warn_high_energy,
        severity=args.severity,
    )

    estimator = EnergyConsumptionEstimator(config)

    all_results: List[Dict[str, Any]] = []

    for dumpfile in args.dumpfiles:
        if not os.path.isfile(dumpfile):
            sys.stderr.write(f"Error: dump file not found: {dumpfile}\n")
            continue

        try:
            data = cppcheckdata.parsedump(dumpfile)
        except Exception as e:
            sys.stderr.write(f"Error parsing dump file {dumpfile}: {e}\n")
            continue

        # Process suppression info
        cppcheckdata.current_dumpfile_suppressions = (
            getattr(data, "suppressions", [])
        )

        for cfg in getattr(data, "configurations", []):
            result = estimator.analyse_configuration(cfg)
            estimator.report(result, dumpfile)

            if args.json_output:
                result_dict = result.to_dict()
                result_dict["dumpfile"] = dumpfile
                result_dict["configuration"] = getattr(cfg, "name", "")
                all_results.append(result_dict)

    # Write JSON report
    if args.json_output and all_results:
        try:
            with open(args.json_output, "w", encoding="utf-8") as fh:
                json.dump(all_results, fh, indent=2, default=str)
            sys.stderr.write(
                f"JSON report written to {args.json_output}\n"
            )
        except Exception as e:
            sys.stderr.write(f"Error writing JSON report: {e}\n")

    sys.exit(cppcheckdata.EXIT_CODE)


if __name__ == "__main__":
    main()
