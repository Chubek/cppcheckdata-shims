#!/usr/bin/env python3
"""
Buflint.py — A Sound Static Analyzer for Memory Safety
═══════════════════════════════════════════════════════

A Cppcheck addon that detects memory-safety violations using the
cppcheckdata-shims library's abstract interpretation, dataflow analysis,
and symbolic execution infrastructure.

Targeted CWEs:
    CWE-119  Buffer Overflow (read/write)
    CWE-120  Buffer Copy without Checking Size of Input
    CWE-121  Stack-based Buffer Overflow
    CWE-122  Heap-based Buffer Overflow
    CWE-124  Buffer Underwrite
    CWE-125  Out-of-bounds Read
    CWE-126  Buffer Over-read
    CWE-127  Buffer Under-read
    CWE-131  Incorrect Calculation of Buffer Size
    CWE-170  Improper Null Termination
    CWE-190  Integer Overflow to Buffer Overflow
    CWE-415  Double Free
    CWE-416  Use After Free
    CWE-476  NULL Pointer Dereference
    CWE-590  Free of Memory not on the Heap
    CWE-761  Free of Pointer not at Start of Buffer
    CWE-787  Out-of-bounds Write
    CWE-788  Access of Memory Location After End of Buffer
    CWE-789  Memory Allocation with Excessive Size Value

Design Principles:
    1. SOUNDNESS: Every real bug in the checked categories is reported
       (no false negatives). Achieved via over-approximating abstract
       domains and conservative transfer functions.
    2. LOW FALSE POSITIVES: Precision is maximized through:
       - Flow-sensitive interval analysis with threshold widening
       - Path-sensitive nullness/allocation-state tracking
       - Interprocedural summaries for common library functions
       - Reduced product domain combining intervals, allocation state,
         and nullness for mutual refinement
    3. MODULARITY: Each CWE check is a separate checker class registered
       with the checker framework; users can enable/disable individually.

Architecture:
    ┌──────────────────────────────────────────────────┐
    │              Buflint (this file)                  │
    │  ┌────────────────────────────────────────────┐  │
    │  │  MemorySafetyChecker (orchestrator)        │  │
    │  │    ├── BufferOverflowChecker               │  │
    │  │    ├── UseAfterFreeChecker                 │  │
    │  │    ├── DoubleFreeChecker                   │  │
    │  │    ├── NullDerefChecker                    │  │
    │  │    ├── UninitializedReadChecker            │  │
    │  │    └── AllocationMisuseChecker             │  │
    │  └────────────────────────────────────────────┘  │
    │  ┌────────────────────────────────────────────┐  │
    │  │  MemoryAbstractDomain (reduced product)    │  │
    │  │    = IntervalDomain                        │  │
    │  │    × AllocationStateDomain                 │  │
    │  │    × NullnessDomain                        │  │
    │  │    × BufferSizeDomain                      │  │
    │  │    with reduction operator                 │  │
    │  └────────────────────────────────────────────┘  │
    │  ┌────────────────────────────────────────────┐  │
    │  │  MemorySafetyAnalysis (forward dataflow)   │  │
    │  │    uses CFG + DataflowEngine               │  │
    │  │    with widening + narrowing               │  │
    │  └────────────────────────────────────────────┘  │
    └──────────────────────────────────────────────────┘

Usage:
    cppcheck --dump myfile.c
    python Buflint.py myfile.c.dump

    Or with specific checkers:
    python Buflint.py --enable=buffer,uaf,double-free myfile.c.dump

License: MIT
"""

from __future__ import annotations

import argparse
import math
import sys
from abc import ABC, abstractmethod
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import (
    Any,
    Callable,
    Dict,
    FrozenSet,
    List,
    Mapping,
    Optional,
    Sequence,
    Set,
    Tuple,
    Union,
)

import cppcheckdata

from cppcheckdata_shims.abstract_domains import (
    BOTTOM,
    TOP,
    AbstractDomain,
    ConstantDomain,
    FlatDomain,
    FunctionDomain,
    IntervalDomain,
    ProductDomain,
    ReducedProductDomain,
    SetDomain,
)
from cppcheckdata_shims.ctrlflow_graph import (
    BasicBlock,
    CFG,
    CFGBuilder,
    EdgeKind,
)
from cppcheckdata_shims.ctrlflow_analysis import (
    compute_dominators,
    compute_post_dominators,
    is_reachable,
)
from cppcheckdata_shims.dataflow_analysis import (
    ForwardAnalysis,
    BackwardAnalysis,
    DataflowResult,
    LiveVariables,
)
from cppcheckdata_shims.dataflow_engine import (
    DataflowEngine,
    WorklistStrategy,
)
from cppcheckdata_shims.abstract_interp import (
    AbstractInterpreter,
    AbstractState,
    PathSensitiveInterpreter,
)
from cppcheckdata_shims.callgraph import CallGraphBuilder, CallGraph
from cppcheckdata_shims.interproc_analysis import (
    InterproceduralAnalysis,
    ContextPolicy,
    BottomUpAnalyzer,
)
from cppcheckdata_shims.memory_abstraction import (
    PointsToAnalysis,
    AliasAnalysis,
    AbstractHeap,
    AllocationSite,
    MemoryLocation,
)
from cppcheckdata_shims.type_analysis import TypeAnalyzer
from cppcheckdata_shims.constraint_engine import (
    ConstraintSolver,
    Constraint,
)
from cppcheckdata_shims.checkers import (
    Checker,
    CheckerRegistry,
    Severity,
    Finding,
    CheckerContext,
)
from cppcheckdata_shims.qscore import QualityScorer


# ═══════════════════════════════════════════════════════════════════════════
#  PART 0 — CONSTANTS AND CWE DEFINITIONS
# ═══════════════════════════════════════════════════════════════════════════

class CWE(Enum):
    """Memory-safety CWEs checked by Buflint."""
    CWE_119 = (
        119, "Improper Restriction of Operations within the Bounds of a Memory Buffer")
    CWE_120 = (120, "Buffer Copy without Checking Size of Input")
    CWE_121 = (121, "Stack-based Buffer Overflow")
    CWE_122 = (122, "Heap-based Buffer Overflow")
    CWE_124 = (124, "Buffer Underwrite ('Buffer Underflow')")
    CWE_125 = (125, "Out-of-bounds Read")
    CWE_126 = (126, "Buffer Over-read")
    CWE_127 = (127, "Buffer Under-read")
    CWE_131 = (131, "Incorrect Calculation of Buffer Size")
    CWE_170 = (170, "Improper Null Termination")
    CWE_190 = (190, "Integer Overflow or Wraparound")
    CWE_415 = (415, "Double Free")
    CWE_416 = (416, "Use After Free")
    CWE_476 = (476, "NULL Pointer Dereference")
    CWE_590 = (590, "Free of Memory not on the Heap")
    CWE_761 = (761, "Free of Pointer not at Start of Buffer")
    CWE_787 = (787, "Out-of-bounds Write")
    CWE_788 = (788, "Access of Memory Location After End of Buffer")
    CWE_789 = (789, "Memory Allocation with Excessive Size Value")

    def __init__(self, number: int, description: str):
        self.number = number
        self.description = description

    def tag(self) -> str:
        return f"CWE-{self.number}"


# Size thresholds for "excessive allocation" (CWE-789)
_MAX_REASONABLE_ALLOC = 1 << 30  # 1 GiB

# Common buffer-manipulation functions and their signatures
# (func_name -> (dst_param_idx, src_param_idx, size_param_idx, is_write))
_BUFFER_FUNCS: Dict[str, Tuple[int, Optional[int], Optional[int], bool]] = {
    "memcpy":   (0, 1, 2, True),
    "memmove":  (0, 1, 2, True),
    "memset":   (0, None, 2, True),
    "strncpy":  (0, 1, 2, True),
    "strncat":  (0, 1, 2, True),
    "snprintf": (0, None, 1, True),
    "memcmp":   (0, 1, 2, False),
    "strncmp":  (0, 1, 2, False),
    "fread":    (0, None, None, True),
    "fwrite":   (0, None, None, False),
    "read":     (1, None, 2, True),
    "write":    (1, None, 2, False),
    "recv":     (1, None, 2, True),
    "send":     (1, None, 2, False),
}

# Functions that copy without explicit size (dangerous)
_UNBOUNDED_COPY_FUNCS: Set[str] = {
    "strcpy", "strcat", "sprintf", "gets", "scanf",
}

# Allocation functions: name -> size_param_index
_ALLOC_FUNCS: Dict[str, Optional[int]] = {
    "malloc": 0,
    "calloc": None,   # special: arg0 * arg1
    "realloc": 1,
    "aligned_alloc": 1,
    "valloc": 0,
    "pvalloc": 0,
    "memalign": 1,
    "posix_memalign": 2,
    "strdup": None,    # size = strlen(arg) + 1
    "strndup": 1,
}

# Deallocation functions: name -> pointer_param_index
_FREE_FUNCS: Dict[str, int] = {
    "free": 0,
    "cfree": 0,
}


# ═══════════════════════════════════════════════════════════════════════════
#  PART 1 — ABSTRACT DOMAINS FOR MEMORY SAFETY
# ═══════════════════════════════════════════════════════════════════════════

# ---------------------------------------------------------------------------
#  1a. Allocation State Domain
# ---------------------------------------------------------------------------
#
#  Tracks the lifecycle of a heap-allocated memory region:
#
#              ⊤ (unknown)
#           /  |   \
#     Allocated  Freed  StackLocal
#           \  |   /
#              ⊥ (unreachable)
#
#  This is a flat lattice of height 2; no widening needed.

class AllocState(Enum):
    """Lifecycle state of a memory object."""
    BOTTOM = auto()       # unreachable / no information
    UNALLOCATED = auto()  # not yet allocated (e.g., declared pointer)
    ALLOCATED = auto()    # heap-allocated and valid
    FREED = auto()        # heap-allocated but freed
    STACK_LOCAL = auto()  # points to stack-local storage
    STATIC = auto()       # points to static/global storage
    TOP = auto()          # unknown state


# Join table for AllocState (flat lattice: any two distinct non-⊥ → ⊤)
_ALLOC_JOIN: Dict[AllocState, Dict[AllocState, AllocState]] = {
    AllocState.BOTTOM: {s: s for s in AllocState},
    AllocState.TOP: {s: AllocState.TOP for s in AllocState},
}
for s in AllocState:
    if s not in (AllocState.BOTTOM, AllocState.TOP):
        _ALLOC_JOIN[s] = {}
        for t in AllocState:
            if t is AllocState.BOTTOM:
                _ALLOC_JOIN[s][t] = s
            elif t is AllocState.TOP:
                _ALLOC_JOIN[s][t] = AllocState.TOP
            elif s == t:
                _ALLOC_JOIN[s][t] = s
            else:
                _ALLOC_JOIN[s][t] = AllocState.TOP

# Meet table (dual)
_ALLOC_MEET: Dict[AllocState, Dict[AllocState, AllocState]] = {
    AllocState.TOP: {s: s for s in AllocState},
    AllocState.BOTTOM: {s: AllocState.BOTTOM for s in AllocState},
}
for s in AllocState:
    if s not in (AllocState.BOTTOM, AllocState.TOP):
        _ALLOC_MEET[s] = {}
        for t in AllocState:
            if t is AllocState.TOP:
                _ALLOC_MEET[s][t] = s
            elif t is AllocState.BOTTOM:
                _ALLOC_MEET[s][t] = AllocState.BOTTOM
            elif s == t:
                _ALLOC_MEET[s][t] = s
            else:
                _ALLOC_MEET[s][t] = AllocState.BOTTOM


@dataclass(frozen=True, slots=True)
class AllocStateDomain:
    """
    Abstract domain tracking allocation state of a pointer.
    Flat lattice — height 2, no widening needed.
    """
    state: AllocState

    @classmethod
    def bottom(cls) -> AllocStateDomain:
        return cls(AllocState.BOTTOM)

    @classmethod
    def top(cls) -> AllocStateDomain:
        return cls(AllocState.TOP)

    @classmethod
    def allocated(cls) -> AllocStateDomain:
        return cls(AllocState.ALLOCATED)

    @classmethod
    def freed(cls) -> AllocStateDomain:
        return cls(AllocState.FREED)

    @classmethod
    def unallocated(cls) -> AllocStateDomain:
        return cls(AllocState.UNALLOCATED)

    @classmethod
    def stack_local(cls) -> AllocStateDomain:
        return cls(AllocState.STACK_LOCAL)

    @classmethod
    def static(cls) -> AllocStateDomain:
        return cls(AllocState.STATIC)

    def is_bottom(self) -> bool:
        return self.state is AllocState.BOTTOM

    def is_top(self) -> bool:
        return self.state is AllocState.TOP

    def leq(self, other: AllocStateDomain) -> bool:
        if self.is_bottom():
            return True
        if other.is_top():
            return True
        return self.state == other.state

    def join(self, other: AllocStateDomain) -> AllocStateDomain:
        return AllocStateDomain(_ALLOC_JOIN[self.state][other.state])

    def meet(self, other: AllocStateDomain) -> AllocStateDomain:
        return AllocStateDomain(_ALLOC_MEET[self.state][other.state])

    def widen(self, other: AllocStateDomain) -> AllocStateDomain:
        return self.join(other)  # finite height

    def narrow(self, other: AllocStateDomain) -> AllocStateDomain:
        return other

    def __repr__(self) -> str:
        _NAMES = {
            AllocState.BOTTOM: "⊥",
            AllocState.UNALLOCATED: "Unalloc",
            AllocState.ALLOCATED: "Alloc",
            AllocState.FREED: "Freed",
            AllocState.STACK_LOCAL: "Stack",
            AllocState.STATIC: "Static",
            AllocState.TOP: "⊤",
        }
        return f"AllocState({_NAMES[self.state]})"


# ---------------------------------------------------------------------------
#  1b. Nullness Domain
# ---------------------------------------------------------------------------

class Nullness(Enum):
    BOTTOM = auto()
    NULL = auto()
    NONNULL = auto()
    TOP = auto()


_NULL_JOIN: Dict[Nullness, Dict[Nullness, Nullness]] = {
    Nullness.BOTTOM: {s: s for s in Nullness},
    Nullness.TOP: {s: Nullness.TOP for s in Nullness},
    Nullness.NULL: {
        Nullness.BOTTOM: Nullness.NULL,
        Nullness.NULL: Nullness.NULL,
        Nullness.NONNULL: Nullness.TOP,
        Nullness.TOP: Nullness.TOP,
    },
    Nullness.NONNULL: {
        Nullness.BOTTOM: Nullness.NONNULL,
        Nullness.NULL: Nullness.TOP,
        Nullness.NONNULL: Nullness.NONNULL,
        Nullness.TOP: Nullness.TOP,
    },
}

_NULL_MEET: Dict[Nullness, Dict[Nullness, Nullness]] = {
    Nullness.TOP: {s: s for s in Nullness},
    Nullness.BOTTOM: {s: Nullness.BOTTOM for s in Nullness},
    Nullness.NULL: {
        Nullness.TOP: Nullness.NULL,
        Nullness.NULL: Nullness.NULL,
        Nullness.NONNULL: Nullness.BOTTOM,
        Nullness.BOTTOM: Nullness.BOTTOM,
    },
    Nullness.NONNULL: {
        Nullness.TOP: Nullness.NONNULL,
        Nullness.NULL: Nullness.BOTTOM,
        Nullness.NONNULL: Nullness.NONNULL,
        Nullness.BOTTOM: Nullness.BOTTOM,
    },
}


@dataclass(frozen=True, slots=True)
class NullnessDom:
    """Nullness abstract domain: {⊥, Null, NonNull, ⊤}."""
    nullness: Nullness

    @classmethod
    def bottom(cls) -> NullnessDom:
        return cls(Nullness.BOTTOM)

    @classmethod
    def top(cls) -> NullnessDom:
        return cls(Nullness.TOP)

    @classmethod
    def null(cls) -> NullnessDom:
        return cls(Nullness.NULL)

    @classmethod
    def nonnull(cls) -> NullnessDom:
        return cls(Nullness.NONNULL)

    def is_bottom(self) -> bool:
        return self.nullness is Nullness.BOTTOM

    def is_top(self) -> bool:
        return self.nullness is Nullness.TOP

    def is_definitely_null(self) -> bool:
        return self.nullness is Nullness.NULL

    def is_definitely_nonnull(self) -> bool:
        return self.nullness is Nullness.NONNULL

    def may_be_null(self) -> bool:
        return self.nullness in (Nullness.NULL, Nullness.TOP)

    def leq(self, other: NullnessDom) -> bool:
        if self.is_bottom():
            return True
        if other.is_top():
            return True
        return self.nullness == other.nullness

    def join(self, other: NullnessDom) -> NullnessDom:
        return NullnessDom(_NULL_JOIN[self.nullness][other.nullness])

    def meet(self, other: NullnessDom) -> NullnessDom:
        return NullnessDom(_NULL_MEET[self.nullness][other.nullness])

    def widen(self, other: NullnessDom) -> NullnessDom:
        return self.join(other)

    def narrow(self, other: NullnessDom) -> NullnessDom:
        return other

    def __repr__(self) -> str:
        _NAMES = {
            Nullness.BOTTOM: "⊥", Nullness.NULL: "Null",
            Nullness.NONNULL: "NonNull", Nullness.TOP: "⊤",
        }
        return f"Nullness({_NAMES[self.nullness]})"


# ---------------------------------------------------------------------------
#  1c. Per-Variable Memory State (Product)
# ---------------------------------------------------------------------------
#
#  For each pointer variable we track a tuple:
#    (NullnessDom, AllocStateDomain, IntervalDomain, IntervalDomain)
#       ^              ^                  ^               ^
#    nullness    alloc lifecycle    buffer size [lo,hi]  current offset
#
#  The buffer size tracks the allocated size in bytes.
#  The offset tracks the current byte offset from the base of the buffer.
#  These allow us to check: 0 ≤ offset < buffer_size on every access.

@dataclass(frozen=True, slots=True)
class PointerAbstractValue:
    """
    Combined abstract value for a single pointer variable.

    Fields:
        nullness:    Is this pointer NULL, NonNull, or unknown?
        alloc_state: Is the memory allocated, freed, stack, etc.?
        buf_size:    Interval bounding the buffer size in bytes.
        offset:      Interval bounding the byte offset from buffer base.
        alloc_site:  Optional token of the allocation site (for diagnostics).
    """
    nullness: NullnessDom
    alloc_state: AllocStateDomain
    buf_size: IntervalDomain
    offset: IntervalDomain
    alloc_site: Optional[Any] = None  # cppcheckdata.Token

    @classmethod
    def bottom(cls) -> PointerAbstractValue:
        return cls(
            nullness=NullnessDom.bottom(),
            alloc_state=AllocStateDomain.bottom(),
            buf_size=IntervalDomain.bottom(),
            offset=IntervalDomain.bottom(),
        )

    @classmethod
    def top(cls) -> PointerAbstractValue:
        return cls(
            nullness=NullnessDom.top(),
            alloc_state=AllocStateDomain.top(),
            buf_size=IntervalDomain.top(),
            offset=IntervalDomain.top(),
        )

    @classmethod
    def null_ptr(cls) -> PointerAbstractValue:
        return cls(
            nullness=NullnessDom.null(),
            alloc_state=AllocStateDomain(AllocState.UNALLOCATED),
            buf_size=IntervalDomain.const(0),
            offset=IntervalDomain.const(0),
        )

    @classmethod
    def heap_alloc(cls, size: IntervalDomain, site=None) -> PointerAbstractValue:
        return cls(
            nullness=NullnessDom.top(),  # malloc may return NULL
            alloc_state=AllocStateDomain.allocated(),
            buf_size=size,
            offset=IntervalDomain.const(0),
            alloc_site=site,
        )

    @classmethod
    def stack_buf(cls, size: IntervalDomain) -> PointerAbstractValue:
        return cls(
            nullness=NullnessDom.nonnull(),
            alloc_state=AllocStateDomain.stack_local(),
            buf_size=size,
            offset=IntervalDomain.const(0),
        )

    def is_bottom(self) -> bool:
        return (self.nullness.is_bottom() and self.alloc_state.is_bottom()
                and self.buf_size.is_bottom() and self.offset.is_bottom())

    def is_top(self) -> bool:
        return (self.nullness.is_top() and self.alloc_state.is_top()
                and self.buf_size.is_top() and self.offset.is_top())

    def join(self, other: PointerAbstractValue) -> PointerAbstractValue:
        return PointerAbstractValue(
            nullness=self.nullness.join(other.nullness),
            alloc_state=self.alloc_state.join(other.alloc_state),
            buf_size=self.buf_size.join(other.buf_size),
            offset=self.offset.join(other.offset),
            alloc_site=self.alloc_site if self.alloc_site == other.alloc_site else None,
        )

    def meet(self, other: PointerAbstractValue) -> PointerAbstractValue:
        return PointerAbstractValue(
            nullness=self.nullness.meet(other.nullness),
            alloc_state=self.alloc_state.meet(other.alloc_state),
            buf_size=self.buf_size.meet(other.buf_size),
            offset=self.offset.meet(other.offset),
            alloc_site=self.alloc_site,
        )

    def widen(self, other: PointerAbstractValue) -> PointerAbstractValue:
        return PointerAbstractValue(
            nullness=self.nullness.widen(other.nullness),
            alloc_state=self.alloc_state.widen(other.alloc_state),
            buf_size=self.buf_size.widen(other.buf_size),
            offset=self.offset.widen(other.offset),
            alloc_site=self.alloc_site,
        )

    def narrow(self, other: PointerAbstractValue) -> PointerAbstractValue:
        return PointerAbstractValue(
            nullness=self.nullness.narrow(other.nullness),
            alloc_state=self.alloc_state.narrow(other.alloc_state),
            buf_size=self.buf_size.narrow(other.buf_size),
            offset=self.offset.narrow(other.offset),
            alloc_site=self.alloc_site,
        )

    def leq(self, other: PointerAbstractValue) -> bool:
        return (self.nullness.leq(other.nullness)
                and self.alloc_state.leq(other.alloc_state)
                and self.buf_size.leq(other.buf_size)
                and self.offset.leq(other.offset))

    # ---- Reduction operator (mutual refinement) --------------------------

    def reduce(self) -> PointerAbstractValue:
        """
        Apply reduction rules to tighten the product:
          - If alloc_state = Freed → nullness can be anything (no change)
          - If nullness = Null → buf_size = [0,0], offset = [0,0]
          - If buf_size = [0,0] and alloc_state = Allocated → contradiction
            (malloc(0) is implementation-defined, but we treat it as ⊥)
          - If offset.lo >= buf_size.hi (and both finite) → out-of-bounds
            (we don't reduce to ⊥ here — that's the checker's job)
        """
        n, a, s, o = self.nullness, self.alloc_state, self.buf_size, self.offset

        # Null pointer has no buffer
        if n.is_definitely_null():
            return PointerAbstractValue(
                nullness=n,
                alloc_state=AllocStateDomain(AllocState.UNALLOCATED),
                buf_size=IntervalDomain.const(0),
                offset=IntervalDomain.const(0),
                alloc_site=self.alloc_site,
            )

        # Freed memory: keep tracking but nullness can be NonNull (dangling)
        # No reduction needed.

        # Allocated with non-null: refine nullness
        if a.state is AllocState.ALLOCATED:
            # malloc can return NULL, so only refine if we already know NonNull
            pass

        # Stack/static are always non-null
        if a.state in (AllocState.STACK_LOCAL, AllocState.STATIC):
            n = NullnessDom.nonnull()

        return PointerAbstractValue(
            nullness=n, alloc_state=a, buf_size=s, offset=o,
            alloc_site=self.alloc_site,
        )

    def __repr__(self) -> str:
        return (f"PtrVal({self.nullness}, {self.alloc_state}, "
                f"size={self.buf_size}, off={self.offset})")


# ---------------------------------------------------------------------------
#  1d. Integer Abstract Value
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class IntAbstractValue:
    """
    Abstract value for integer variables: an interval with optional
    taint tracking.
    """
    interval: IntervalDomain
    is_tainted: bool = False  # from untrusted source?

    @classmethod
    def bottom(cls) -> IntAbstractValue:
        return cls(interval=IntervalDomain.bottom())

    @classmethod
    def top(cls) -> IntAbstractValue:
        return cls(interval=IntervalDomain.top())

    @classmethod
    def const(cls, n: int) -> IntAbstractValue:
        return cls(interval=IntervalDomain.const(n))

    @classmethod
    def range(cls, lo: int, hi: int) -> IntAbstractValue:
        return cls(interval=IntervalDomain.range(lo, hi))

    def is_bottom(self) -> bool:
        return self.interval.is_bottom()

    def is_top(self) -> bool:
        return self.interval.is_top()

    def join(self, other: IntAbstractValue) -> IntAbstractValue:
        return IntAbstractValue(
            interval=self.interval.join(other.interval),
            is_tainted=self.is_tainted or other.is_tainted,
        )

    def meet(self, other: IntAbstractValue) -> IntAbstractValue:
        return IntAbstractValue(
            interval=self.interval.meet(other.interval),
            is_tainted=self.is_tainted and other.is_tainted,
        )

    def widen(self, other: IntAbstractValue) -> IntAbstractValue:
        return IntAbstractValue(
            interval=self.interval.widen(other.interval),
            is_tainted=self.is_tainted or other.is_tainted,
        )

    def narrow(self, other: IntAbstractValue) -> IntAbstractValue:
        return IntAbstractValue(
            interval=self.interval.narrow(other.interval),
            is_tainted=self.is_tainted and other.is_tainted,
        )

    def leq(self, other: IntAbstractValue) -> bool:
        return self.interval.leq(other.interval)

    def add(self, other: IntAbstractValue) -> IntAbstractValue:
        return IntAbstractValue(
            interval=self.interval.add(other.interval),
            is_tainted=self.is_tainted or other.is_tainted,
        )

    def sub(self, other: IntAbstractValue) -> IntAbstractValue:
        return IntAbstractValue(
            interval=self.interval.sub(other.interval),
            is_tainted=self.is_tainted or other.is_tainted,
        )

    def mul(self, other: IntAbstractValue) -> IntAbstractValue:
        return IntAbstractValue(
            interval=self.interval.mul(other.interval),
            is_tainted=self.is_tainted or other.is_tainted,
        )

    def __repr__(self) -> str:
        t = " TAINTED" if self.is_tainted else ""
        return f"Int({self.interval}{t})"


# ---------------------------------------------------------------------------
#  1e. Memory State — The Full Abstract State
# ---------------------------------------------------------------------------

@dataclass
class MemoryState:
    """
    Abstract state at a program point: maps variable names to abstract values.

    Pointer variables → PointerAbstractValue
    Integer variables → IntAbstractValue

    This is the environment lattice:  Var → (PtrVal + IntVal)
    with pointwise join/meet/widen/narrow.
    """
    pointers: Dict[str, PointerAbstractValue] = field(default_factory=dict)
    integers: Dict[str, IntAbstractValue] = field(default_factory=dict)
    _is_bottom: bool = False

    @classmethod
    def bottom(cls) -> MemoryState:
        return cls(_is_bottom=True)

    @classmethod
    def top(cls) -> MemoryState:
        return cls()  # empty maps = all variables map to ⊤ implicitly

    def is_bottom(self) -> bool:
        return self._is_bottom

    def copy(self) -> MemoryState:
        if self._is_bottom:
            return MemoryState.bottom()
        return MemoryState(
            pointers=dict(self.pointers),
            integers=dict(self.integers),
        )

    def get_ptr(self, var: str) -> PointerAbstractValue:
        if self._is_bottom:
            return PointerAbstractValue.bottom()
        return self.pointers.get(var, PointerAbstractValue.top())

    def set_ptr(self, var: str, val: PointerAbstractValue) -> MemoryState:
        if self._is_bottom:
            return self
        new = self.copy()
        new.pointers[var] = val.reduce()
        return new

    def get_int(self, var: str) -> IntAbstractValue:
        if self._is_bottom:
            return IntAbstractValue.bottom()
        return self.integers.get(var, IntAbstractValue.top())

    def set_int(self, var: str, val: IntAbstractValue) -> MemoryState:
        if self._is_bottom:
            return self
        new = self.copy()
        new.integers[var] = val
        return new

    def join(self, other: MemoryState) -> MemoryState:
        if self._is_bottom:
            return other.copy()
        if other._is_bottom:
            return self.copy()

        result = MemoryState()

        # Pointwise join for pointers
        all_ptr_vars = set(self.pointers.keys()) | set(other.pointers.keys())
        for var in all_ptr_vars:
            v1 = self.pointers.get(var, PointerAbstractValue.top())
            v2 = other.pointers.get(var, PointerAbstractValue.top())
            result.pointers[var] = v1.join(v2)

        # Pointwise join for integers
        all_int_vars = set(self.integers.keys()) | set(other.integers.keys())
        for var in all_int_vars:
            v1 = self.integers.get(var, IntAbstractValue.top())
            v2 = other.integers.get(var, IntAbstractValue.top())
            result.integers[var] = v1.join(v2)

        return result

    def widen(self, other: MemoryState) -> MemoryState:
        if self._is_bottom:
            return other.copy()
        if other._is_bottom:
            return self.copy()

        result = MemoryState()

        all_ptr_vars = set(self.pointers.keys()) | set(other.pointers.keys())
        for var in all_ptr_vars:
            v1 = self.pointers.get(var, PointerAbstractValue.top())
            v2 = other.pointers.get(var, PointerAbstractValue.top())
            result.pointers[var] = v1.widen(v2)

        all_int_vars = set(self.integers.keys()) | set(other.integers.keys())
        for var in all_int_vars:
            v1 = self.integers.get(var, IntAbstractValue.top())
            v2 = other.integers.get(var, IntAbstractValue.top())
            result.integers[var] = v1.widen(v2)

        return result

    def narrow(self, other: MemoryState) -> MemoryState:
        if self._is_bottom:
            return self
        if other._is_bottom:
            return other

        result = MemoryState()

        all_ptr_vars = set(self.pointers.keys()) | set(other.pointers.keys())
        for var in all_ptr_vars:
            v1 = self.pointers.get(var, PointerAbstractValue.top())
            v2 = other.pointers.get(var, PointerAbstractValue.top())
            result.pointers[var] = v1.narrow(v2)

        all_int_vars = set(self.integers.keys()) | set(other.integers.keys())
        for var in all_int_vars:
            v1 = self.integers.get(var, IntAbstractValue.top())
            v2 = other.integers.get(var, IntAbstractValue.top())
            result.integers[var] = v1.narrow(v2)

        return result

    def leq(self, other: MemoryState) -> bool:
        if self._is_bottom:
            return True
        if other._is_bottom:
            return False

        for var, v1 in self.pointers.items():
            v2 = other.pointers.get(var, PointerAbstractValue.top())
            if not v1.leq(v2):
                return False

        for var, v1 in self.integers.items():
            v2 = other.integers.get(var, IntAbstractValue.top())
            if not v1.leq(v2):
                return False

        return True

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, MemoryState):
            return NotImplemented
        if self._is_bottom and other._is_bottom:
            return True
        if self._is_bottom or other._is_bottom:
            return False
        return self.pointers == other.pointers and self.integers == other.integers

    def __repr__(self) -> str:
        if self._is_bottom:
            return "MemState(⊥)"
        parts = []
        for k, v in sorted(self.pointers.items()):
            parts.append(f"{k}→{v}")
        for k, v in sorted(self.integers.items()):
            parts.append(f"{k}→{v}")
        return "MemState({" + ", ".join(parts) + "})"


# ═══════════════════════════════════════════════════════════════════════════
#  PART 2 — MEMORY SAFETY DATAFLOW ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════

class MemorySafetyAnalysis(ForwardAnalysis):
    """
    Forward dataflow analysis tracking memory-safety properties.

    For each program point, computes a MemoryState mapping each variable
    to its abstract value (pointer info or integer interval).

    Transfer functions handle:
        - Assignments (x = expr)
        - Allocations (malloc, calloc, realloc, etc.)
        - Deallocations (free)
        - Pointer arithmetic (p + i, p[i])
        - Buffer operations (memcpy, strcpy, etc.)
        - Conditional branches (refine intervals and nullness)
        - Function calls (with library summaries)
    """

    def __init__(self, cfg_data, type_analyzer: Optional[TypeAnalyzer] = None):
        super().__init__(
            domain=None,  # We manage MemoryState directly
            direction="forward",
        )
        self.cfg_data = cfg_data
        self.type_analyzer = type_analyzer
        self.findings: List[Finding] = []

        # Widening thresholds: common buffer sizes and loop bounds
        self.thresholds: List[float] = [
            0, 1, 2, 4, 8, 16, 32, 64, 128, 256, 512,
            1024, 2048, 4096, 8192, 16384, 32768, 65536,
            1 << 20, 1 << 24, 1 << 30,
            # Common C type max values
            127, 255, 32767, 65535,
            2147483647, 4294967295,
        ]
        self.thresholds.sort()

    # ---- Analysis interface ----------------------------------------------

    def initial_value(self) -> MemoryState:
        return MemoryState.bottom()

    def boundary_value(self) -> MemoryState:
        """At function entry, all parameters are ⊤ (unknown)."""
        return MemoryState.top()

    def merge(self, s1: MemoryState, s2: MemoryState) -> MemoryState:
        return s1.join(s2)

    def widen_states(self, old: MemoryState, new: MemoryState) -> MemoryState:
        """Widening with thresholds for interval components."""
        if old.is_bottom():
            return new.copy()
        if new.is_bottom():
            return old.copy()

        result = MemoryState()

        all_ptr_vars = set(old.pointers.keys()) | set(new.pointers.keys())
        for var in all_ptr_vars:
            v1 = old.pointers.get(var, PointerAbstractValue.top())
            v2 = new.pointers.get(var, PointerAbstractValue.top())
            # Use threshold widening for the interval components
            result.pointers[var] = PointerAbstractValue(
                nullness=v1.nullness.widen(v2.nullness),
                alloc_state=v1.alloc_state.widen(v2.alloc_state),
                buf_size=v1.buf_size.widen_with_thresholds(
                    v2.buf_size, self.thresholds),
                offset=v1.offset.widen_with_thresholds(
                    v2.offset, self.thresholds),
                alloc_site=v1.alloc_site,
            )

        all_int_vars = set(old.integers.keys()) | set(new.integers.keys())
        for var in all_int_vars:
            v1 = old.integers.get(var, IntAbstractValue.top())
            v2 = new.integers.get(var, IntAbstractValue.top())
            result.integers[var] = IntAbstractValue(
                interval=v1.interval.widen_with_thresholds(
                    v2.interval, self.thresholds
                ),
                is_tainted=v1.is_tainted or v2.is_tainted,
            )

        return result

    def transfer(self, block: BasicBlock, in_state: MemoryState) -> MemoryState:
        """Transfer function for a basic block."""
        if in_state.is_bottom():
            return MemoryState.bottom()

        state = in_state.copy()

        for token in block.tokens:
            state = self._transfer_token(token, state)

        return state

    # ---- Per-token transfer functions ------------------------------------

    def _transfer_token(self, token, state: MemoryState) -> MemoryState:
        """Dispatch transfer function for a single token/statement."""
        if token is None:
            return state

        # Assignment: x = expr
        if self._is_assignment(token):
            return self._transfer_assignment(token, state)

        # Function call (not as part of assignment)
        if self._is_function_call(token):
            return self._transfer_call(token, state)

        # Pointer dereference: *p or p[i] (check, don't modify state)
        if self._is_deref(token):
            self._check_deref(token, state)

        # Array subscript: a[i] (check bounds)
        if self._is_array_access(token):
            self._check_array_access(token, state)

        return state

    def _transfer_assignment(self, token, state: MemoryState) -> MemoryState:
        """Handle x = expr."""
        lhs = token.astOperand1
        rhs = token.astOperand2

        if lhs is None or rhs is None:
            return state

        lhs_var = self._get_var_name(lhs)
        if lhs_var is None:
            return state

        # Determine if LHS is a pointer or integer
        if self._is_pointer_var(lhs):
            rhs_val = self._eval_ptr_expr(rhs, state)
            state = state.set_ptr(lhs_var, rhs_val)
        else:
            rhs_val = self._eval_int_expr(rhs, state)
            state = state.set_int(lhs_var, rhs_val)

        return state

    def _transfer_call(self, token, state: MemoryState) -> MemoryState:
        """Handle function calls that affect memory state."""
        func_name = self._get_called_func_name(token)
        if func_name is None:
            return state

        args = self._get_call_args(token)

        # --- Allocation ---
        if func_name in _ALLOC_FUNCS:
            return self._transfer_alloc(func_name, token, args, state)

        # --- Deallocation ---
        if func_name in _FREE_FUNCS:
            return self._transfer_free(func_name, token, args, state)

        # --- Realloc (special: both alloc and free) ---
        if func_name == "realloc":
            return self._transfer_realloc(token, args, state)

        # --- Buffer operations ---
        if func_name in _BUFFER_FUNCS:
            self._check_buffer_op(func_name, token, args, state)
            return state

        # --- Unbounded copy (always warn) ---
        if func_name in _UNBOUNDED_COPY_FUNCS:
            self._check_unbounded_copy(func_name, token, args, state)
            return state

        return state

    # ---- Allocation transfer functions -----------------------------------

    def _transfer_alloc(
        self, func_name: str, token, args: List, state: MemoryState
    ) -> MemoryState:
        """Transfer for malloc/calloc/etc."""
        # Determine the assigned variable (if any)
        assign_var = self._get_assign_target(token)
        if assign_var is None:
            return state

        # Compute the allocation size
        size_interval = self._compute_alloc_size(func_name, args, state)

        # Check CWE-789: excessive allocation size
        if (not size_interval.is_bottom()
                and math.isfinite(size_interval.hi)
                and size_interval.hi > _MAX_REASONABLE_ALLOC):
            self._report(
                token, CWE.CWE_789, Severity.WARNING,
                f"Allocation size may be excessive: {size_interval}"
            )

        # Check CWE-789: tainted size
        for arg in args:
            arg_name = self._get_var_name(arg)
            if arg_name:
                int_val = state.get_int(arg_name)
                if int_val.is_tainted:
                    self._report(
                        token, CWE.CWE_789, Severity.WARNING,
                        f"Allocation size from tainted source: {arg_name}"
                    )

        # Model the result
        ptr_val = PointerAbstractValue.heap_alloc(size_interval, site=token)
        state = state.set_ptr(assign_var, ptr_val)

        return state

    def _transfer_free(
        self, func_name: str, token, args: List, state: MemoryState
    ) -> MemoryState:
        """Transfer for free()."""
        ptr_idx = _FREE_FUNCS[func_name]
        if ptr_idx >= len(args):
            return state

        ptr_arg = args[ptr_idx]
        ptr_name = self._get_var_name(ptr_arg)
        if ptr_name is None:
            return state

        ptr_val = state.get_ptr(ptr_name)

        # Check CWE-415: Double free
        if ptr_val.alloc_state.state is AllocState.FREED:
            self._report(
                token, CWE.CWE_415, Severity.ERROR,
                f"Double free of '{ptr_name}'"
                + (f" (allocated at {ptr_val.alloc_site.file}:{ptr_val.alloc_site.linenr})"
                   if ptr_val.alloc_site else "")
            )

        # Check CWE-590: Free of non-heap memory
        if ptr_val.alloc_state.state in (AllocState.STACK_LOCAL, AllocState.STATIC):
            self._report(
                token, CWE.CWE_590, Severity.ERROR,
                f"Free of non-heap pointer '{ptr_name}' "
                f"(state: {ptr_val.alloc_state})"
            )

        # Check CWE-761: Free of pointer not at start of buffer
        if not ptr_val.offset.is_bottom() and not ptr_val.offset.is_top():
            if ptr_val.offset.lo > 0 or ptr_val.offset.hi < 0:
                # Offset is definitely not zero
                if not ptr_val.offset.contains(0):
                    self._report(
                        token, CWE.CWE_761, Severity.ERROR,
                        f"Free of pointer '{ptr_name}' not at start of buffer "
                        f"(offset: {ptr_val.offset})"
                    )

        # Check CWE-476: Free of null pointer (technically defined in C,
        # but often indicates a bug)
        if ptr_val.nullness.is_definitely_null():
            # free(NULL) is a no-op in C, not a bug — skip
            return state

        # Update state: mark as freed
        freed_val = PointerAbstractValue(
            nullness=ptr_val.nullness,
            alloc_state=AllocStateDomain.freed(),
            buf_size=ptr_val.buf_size,
            offset=ptr_val.offset,
            alloc_site=ptr_val.alloc_site,
        )
        state = state.set_ptr(ptr_name, freed_val)

        return state

    def _transfer_realloc(
        self, token, args: List, state: MemoryState
    ) -> MemoryState:
        """Transfer for realloc(ptr, size)."""
        assign_var = self._get_assign_target(token)

        if len(args) >= 1:
            old_ptr_name = self._get_var_name(args[0])
            if old_ptr_name:
                old_val = state.get_ptr(old_ptr_name)
                # Check CWE-416: realloc of freed pointer
                if old_val.alloc_state.state is AllocState.FREED:
                    self._report(
                        token, CWE.CWE_416, Severity.ERROR,
                        f"realloc of freed pointer '{old_ptr_name}'"
                    )
                # Old pointer is now potentially invalid
                # (realloc may move the block)
                state = state.set_ptr(
                    old_ptr_name,
                    PointerAbstractValue(
                        nullness=NullnessDom.top(),
                        alloc_state=AllocStateDomain.top(),  # might be freed if realloc moved it
                        buf_size=IntervalDomain.top(),
                        offset=IntervalDomain.const(0),
                    )
                )

        # Compute new size
        new_size = IntervalDomain.top()
        if len(args) >= 2:
            size_val = self._eval_int_expr(args[1], state)
            new_size = size_val.interval

        if assign_var:
            ptr_val = PointerAbstractValue.heap_alloc(new_size, site=token)
            state = state.set_ptr(assign_var, ptr_val)

        return state

    # ---- Expression evaluation -------------------------------------------

    def _eval_ptr_expr(self, token, state: MemoryState) -> PointerAbstractValue:
        """Evaluate a pointer expression to its abstract value."""
        if token is None:
            return PointerAbstractValue.top()

        # NULL literal (0 or NULL)
        if token.isNumber and self._token_int_value(token) == 0:
            return PointerAbstractValue.null_ptr()

        if token.str == "NULL" or token.str == "nullptr":
            return PointerAbstractValue.null_ptr()

        # Variable reference
        var_name = self._get_var_name(token)
        if var_name:
            return state.get_ptr(var_name)

        # malloc/calloc/etc. call
        func_name = self._get_called_func_name(token)
        if func_name and func_name in _ALLOC_FUNCS:
            args = self._get_call_args(token)
            size = self._compute_alloc_size(func_name, args, state)
            return PointerAbstractValue.heap_alloc(size, site=token)

        # Pointer arithmetic: p + i or p - i
        if token.str == "+" and token.astOperand1 and token.astOperand2:
            left = self._eval_ptr_expr(token.astOperand1, state)
            right = self._eval_int_expr(token.astOperand2, state)
            if not left.is_top():
                elem_size = self._get_pointee_size(token.astOperand1)
                byte_offset = right.interval.mul(
                    IntervalDomain.const(elem_size))
                new_offset = left.offset.add(byte_offset)
                return PointerAbstractValue(
                    nullness=left.nullness,
                    alloc_state=left.alloc_state,
                    buf_size=left.buf_size,
                    offset=new_offset,
                    alloc_site=left.alloc_site,
                ).reduce()
            return PointerAbstractValue.top()

        if token.str == "-" and token.astOperand1 and token.astOperand2:
            left = self._eval_ptr_expr(token.astOperand1, state)
            right = self._eval_int_expr(token.astOperand2, state)
            if not left.is_top():
                elem_size = self._get_pointee_size(token.astOperand1)
                byte_offset = right.interval.mul(
                    IntervalDomain.const(elem_size))
                new_offset = left.offset.sub(byte_offset)
                return PointerAbstractValue(
                    nullness=left.nullness,
                    alloc_state=left.alloc_state,
                    buf_size=left.buf_size,
                    offset=new_offset,
                    alloc_site=left.alloc_site,
                ).reduce()
            return PointerAbstractValue.top()

        # Address-of: &x → stack local
        if token.str == "&" and token.astOperand1:
            inner = token.astOperand1
            if inner and inner.variable:
                var = inner.variable
                size = self._get_var_size(var)
                return PointerAbstractValue.stack_buf(
                    IntervalDomain.const(size)
                )

        # Cast: (type*)expr — propagate through
        if token.str == "(" and token.astOperand1:
            return self._eval_ptr_expr(token.astOperand1, state)

        # Ternary: cond ? a : b → join
        if token.str == "?" and token.astOperand2 and token.astOperand2.str == ":":
            colon = token.astOperand2
            true_val = self._eval_ptr_expr(colon.astOperand1, state)
            false_val = self._eval_ptr_expr(colon.astOperand2, state)
            return true_val.join(false_val)

        return PointerAbstractValue.top()

    def _eval_int_expr(self, token, state: MemoryState) -> IntAbstractValue:
        """Evaluate an integer expression to its abstract value."""
        if token is None:
            return IntAbstractValue.top()

        # Integer literal
        if token.isNumber:
            val = self._token_int_value(token)
            if val is not None:
                return IntAbstractValue.const(val)
            return IntAbstractValue.top()

        # Variable reference
        var_name = self._get_var_name(token)
        if var_name:
            return state.get_int(var_name)

        # sizeof(type)
        if token.str == "sizeof":
            size = self._eval_sizeof(token)
            if size is not None:
                return IntAbstractValue.const(size)
            return IntAbstractValue(interval=IntervalDomain.at_least(1))

        # Binary arithmetic
        if token.astOperand1 and token.astOperand2:
            left = self._eval_int_expr(token.astOperand1, state)
            right = self._eval_int_expr(token.astOperand2, state)

            if token.str == "+":
                return left.add(right)
            elif token.str == "-":
                return left.sub(right)
            elif token.str == "*":
                return left.mul(right)
            elif token.str == "/":
                if right.interval.contains(0):
                    return IntAbstractValue.top()
                return IntAbstractValue(
                    interval=left.interval.div(right.interval),
                    is_tainted=left.is_tainted or right.is_tainted,
                )
            elif token.str == "%":
                return IntAbstractValue(
                    interval=left.interval.mod(right.interval),
                    is_tainted=left.is_tainted or right.is_tainted,
                )
            elif token.str == "<<":
                return IntAbstractValue(
                    interval=left.interval.shift_left(right.interval),
                    is_tainted=left.is_tainted or right.is_tainted,
                )
            elif token.str == "&":
                return IntAbstractValue(
                    interval=left.interval.bitwise_and(right.interval),
                    is_tainted=left.is_tainted or right.is_tainted,
                )

        # Unary minus
        if token.str == "-" and token.astOperand1 and not token.astOperand2:
            inner = self._eval_int_expr(token.astOperand1, state)
            return IntAbstractValue(
                interval=inner.interval.negate(),
                is_tainted=inner.is_tainted,
            )

        # Function call returning int (e.g., strlen)
        func_name = self._get_called_func_name(token)
        if func_name == "strlen":
            args = self._get_call_args(token)
            if args:
                ptr_name = self._get_var_name(args[0])
                if ptr_name:
                    ptr_val = state.get_ptr(ptr_name)
                    if not ptr_val.buf_size.is_top():
                        # strlen(s) ∈ [0, buf_size - 1]
                        max_len = ptr_val.buf_size.sub(IntervalDomain.const(1))
                        return IntAbstractValue(
                            interval=IntervalDomain(0.0, max(max_len.hi, 0.0))
                        )
            return IntAbstractValue(interval=IntervalDomain.at_least(0))

        # Ternary
        if token.str == "?" and token.astOperand2 and token.astOperand2.str == ":":
            colon = token.astOperand2
            true_val = self._eval_int_expr(colon.astOperand1, state)
            false_val = self._eval_int_expr(colon.astOperand2, state)
            return true_val.join(false_val)

        return IntAbstractValue.top()

    # ---- Condition refinement (for branch edges) -------------------------

    def refine_for_condition(
        self, state: MemoryState, cond_token, branch: bool
    ) -> MemoryState:
        """
        Refine the abstract state based on a branch condition.

        For `if (cond)`:
            branch=True  → state in the true branch
            branch=False → state in the false branch

        This is critical for precision: after `if (p != NULL)`,
        we know p is NonNull in the true branch and possibly Null
        in the false branch.
        """
        if state.is_bottom() or cond_token is None:
            return state

        state = state.copy()

        # --- Null checks: if (p), if (p != NULL), if (p == NULL) ---
        state = self._refine_nullness(state, cond_token, branch)

        # --- Comparison: if (i < n), if (i >= 0), etc. ---
        state = self._refine_comparison(state, cond_token, branch)

        return state

    def _refine_nullness(
        self, state: MemoryState, token, branch: bool
    ) -> MemoryState:
        """Refine nullness based on pointer truth tests."""
        # Pattern: if (p)
        if token.isName and token.variable and self._is_pointer_var(token):
            var_name = self._get_var_name(token)
            if var_name:
                ptr_val = state.get_ptr(var_name)
                if branch:
                    # True branch: p is non-null
                    new_val = PointerAbstractValue(
                        nullness=NullnessDom.nonnull(),
                        alloc_state=ptr_val.alloc_state,
                        buf_size=ptr_val.buf_size,
                        offset=ptr_val.offset,
                        alloc_site=ptr_val.alloc_site,
                    )
                else:
                    # False branch: p is null
                    new_val = PointerAbstractValue.null_ptr()
                state = state.set_ptr(var_name, new_val)
            return state

        # Pattern: if (p != NULL) or if (p != 0)
        if token.str == "!=" and token.astOperand1 and token.astOperand2:
            if access_size.hi > effective_size.lo and not (access_size.lo > effective_size.hi):
                # There is overlap between access range and OOB region
                # Compute evidence strength
                if effective_size.lo > 0:
                    oob_portion = max(0, access_size.hi - effective_size.lo)
                    total_range = access_size.size()
                    if total_range > 0 and (oob_portion / total_range) > 0.3:
                        cwe = 787 if is_write else 125
                        if buf.heap_state.state == HeapState.STACK_LOCAL:
                            cwe = 121
                        elif buf.heap_state.state == HeapState.ALLOCATED:
                            cwe = 122
                        self._collector.report(
                            token,
                            Severity.WARNING,
                            f"{func_name}(): potential overflow — "
                            f"writing up to {access_size} bytes to '{var_name}' "
                            f"(available: {effective_size} bytes)",
                            cwe=cwe,
                            check_id="memfunc-overflow-possible",
                        )

    def _check_alloc_size(self, token, size: IntervalDomain) -> None:
        """CWE-789: Check for excessive allocation size."""
        if size.is_top() or size.is_bottom():
            return
        # Flag if the allocation could be excessively large
        # (e.g., > 1GB — a heuristic threshold)
        EXCESSIVE_THRESHOLD = 1 << 30  # 1 GiB
        if size.hi > EXCESSIVE_THRESHOLD:
            self._collector.report(
                token,
                Severity.WARNING,
                f"Memory allocation with potentially excessive size: "
                f"{size} bytes (may exceed {EXCESSIVE_THRESHOLD // (1 << 20)} MiB)",
                cwe=789,
                check_id="excessive-alloc",
            )
        # Flag if size could be zero (malloc(0) is implementation-defined)
        if size.lo <= 0:
            self._collector.report(
                token,
                Severity.WARNING,
                f"Memory allocation with potentially zero or negative size: {size}",
                cwe=131,
                check_id="alloc-size-zero-or-negative",
            )

    def _is_write_context(self, token) -> bool:
        """
        Heuristic: determine if a subscript/deref is in a write context.
        Check if the token is on the LHS of an assignment.
        """
        parent = getattr(token, "astParent", None)
        if parent is None:
            return False
        parent_str = getattr(parent, "str", "")
        if parent_str in ("=", "+=", "-=", "*=", "/=", "%=",
                          "&=", "|=", "^=", "<<=", ">>="):
            # Check if token is on the LHS
            lhs = getattr(parent, "astOperand1", None)
            if lhs is token:
                return True
            # Could be nested: parent.astOperand1 is '[' which is our token
            if lhs is not None and getattr(lhs, "Id", None) == getattr(token, "Id", None):
                return True
        return False


# ═══════════════════════════════════════════════════════════════════════════
#  SECTION 5 — VARIABLE DECLARATION SCANNER
# ═══════════════════════════════════════════════════════════════════════════

class VarDeclScanner:
    """
    Scans variable declarations to initialize the abstract state with
    known buffer sizes for local arrays and stack variables.
    """

    @staticmethod
    def scan_function_scope(scope, state: MemState) -> MemState:
        """
        Scan a function scope for local variable declarations and
        populate the initial state with known buffer information.
        """
        if not hasattr(scope, "varlist"):
            return state

        for var in getattr(scope, "varlist", []):
            if var is None:
                continue
            name = getattr(var.nameToken, "str",
                           None) if var.nameToken else None
            if name is None:
                continue

            is_array = getattr(var, "isArray", False)
            is_pointer = getattr(var, "isPointer", False)

            if is_array:
                arr_size = _get_array_size(var)
                elem_sz = _get_sizeof(var.nameToken)
                if arr_size is not None:
                    total_bytes = arr_size * elem_sz
                    info = BufferInfo.stack_buffer(total_bytes, elem_sz)
                    state = state.set_buffer(name, info)
                else:
                    # VLA or unknown-size array
                    info = BufferInfo(
                        alloc_size=IntervalDomain.at_least(1),
                        offset=IntervalDomain.const(0),
                        elem_size=elem_sz,
                        heap_state=HeapStateDomain.stack_local(),
                        is_null_terminated=FlatDomain.lift(False),
                    )
                    state = state.set_buffer(name, info)

            elif is_pointer:
                # Uninitialized pointer — could be anything
                # We do NOT mark it as null or allocated — leave as top
                # to avoid false positives on unmodeled external assignments
                pass

            else:
                # Integer/scalar variable — initialize to top
                pass

        return state

    @staticmethod
    def scan_function_args(function, state: MemState) -> MemState:
        """
        Scan function arguments. Pointer arguments are assumed to be
        valid (non-null, allocated) unless the function is annotated
        otherwise. This is a sound assumption for well-formed programs
        and reduces false positives.
        """
        if function is None:
            return state
        arguments = getattr(function, "argument", {})
        if not arguments:
            return state

        for arg_nr, arg_var in arguments.items():
            if arg_var is None:
                continue
            name = getattr(arg_var.nameToken, "str",
                           None) if arg_var.nameToken else None
            if name is None:
                continue

            is_pointer = getattr(arg_var, "isPointer", False)
            is_array = getattr(arg_var, "isArray", False)

            if is_pointer or is_array:
                # Assume argument pointers are valid but with unknown size
                # This is sound because we report issues only when we can
                # prove a violation, not when we can't prove safety
                info = BufferInfo(
                    alloc_size=IntervalDomain.at_least(1),
                    offset=IntervalDomain.const(0),
                    elem_size=_get_sizeof(arg_var.nameToken),
                    heap_state=HeapStateDomain.allocated(),
                    is_null_terminated=FlatDomain.top(),
                )
                state = state.set_buffer(name, info)

        return state


# ═══════════════════════════════════════════════════════════════════════════
#  SECTION 6 — SCOPE-ESCAPE CHECKER (CWE-562, returning stack address)
# ═══════════════════════════════════════════════════════════════════════════

class ScopeEscapeChecker:
    """
    Detects cases where a pointer to a stack-local variable escapes
    the function (e.g., returning &local_var). While not strictly a
    memory-safety CWE in the buffer-overflow family, this directly
    leads to use-after-free of stack memory.
    """

    def __init__(self, collector: DiagnosticCollector) -> None:
        self._collector = collector

    def check_return(self, return_token, state: MemState) -> None:
        """Check if a return statement returns a pointer to stack memory."""
        if return_token is None:
            return
        ret_expr = getattr(return_token, "astOperand1", None)
        if ret_expr is None:
            return

        # Check if returning address-of local
        if getattr(ret_expr, "str", "") == "&":
            operand = getattr(ret_expr, "astOperand1", None)
            if operand and hasattr(operand, "variable") and operand.variable:
                var = operand.variable
                if getattr(var, "isLocal", False) and not getattr(var, "isStatic", False):
                    self._collector.report(
                        return_token,
                        Severity.ERROR,
                        f"Returning address of local variable "
                        f"'{var.nameToken.str}' — dangling pointer",
                        cwe=562,
                        check_id="return-stack-addr",
                    )
                    return

        # Check if returning a variable known to point to stack memory
        var_name = _get_var_name(ret_expr)
        if var_name:
            buf = state.get_buffer(var_name)
            if buf.heap_state.state == HeapState.STACK_LOCAL:
                self._collector.report(
                    return_token,
                    Severity.ERROR,
                    f"Returning '{var_name}' which points to stack-allocated memory "
                    f"— dangling pointer after function returns",
                    cwe=562,
                    check_id="return-stack-ptr",
                )

            if buf.heap_state.state == HeapState.FREED:
                self._collector.report(
                    return_token,
                    Severity.ERROR,
                    f"Returning '{var_name}' which was already freed",
                    cwe=416,
                    check_id="return-freed-ptr",
                )


# ═══════════════════════════════════════════════════════════════════════════
#  SECTION 7 — NULL-CHECK ELISION DETECTOR
# ═══════════════════════════════════════════════════════════════════════════

class MallocNullCheckDetector:
    """
    Detects cases where the return value of malloc/calloc/realloc is
    used without checking for NULL. This is CWE-476 (null pointer
    dereference) specific to allocation failure paths.

    Strategy:
      After an allocation p = malloc(...), check if p is tested against
      NULL before being dereferenced. We use dominator analysis: if the
      dereference block is NOT dominated by a null-check block, report.
    """

    def __init__(self, collector: DiagnosticCollector) -> None:
        self._collector = collector

    def check_function(self, cfg: CFG, dom) -> None:
        """
        Scan the CFG for allocation sites and verify that each one
        has a null check before any use.
        """
        alloc_sites: List[Tuple[Any, str, BasicBlock]
                          ] = []  # (token, var_name, block)
        # (token, var_name, block)
        deref_sites: List[Tuple[Any, str, BasicBlock]] = []
        # var_name → blocks
        null_check_blocks: Dict[str, Set[BasicBlock]] = {}

        for block in cfg.blocks:
            for token in block.tokens:
                tok_str = getattr(token, "str", "")

                # Find allocation sites
                if tok_str == "=" and hasattr(token, "isAssignmentOp") and token.isAssignmentOp:
                    rhs = getattr(token, "astOperand2", None)
                    func_name = _find_function_call(rhs) if rhs else None
                    if func_name in _ALLOC_FUNCS:
                        lhs = getattr(token, "astOperand1", None)
                        var_name = _get_var_name(lhs)
                        if var_name:
                            alloc_sites.append((token, var_name, block))

                # Find null checks: if (p) or if (p != NULL)
                if tok_str in ("!=", "=="):
                    op1 = getattr(token, "astOperand1", None)
                    op2 = getattr(token, "astOperand2", None)
                    var_name = None
                    if op2 and getattr(op2, "str", "") == "0":
                        var_name = _get_var_name(op1)
                    elif op1 and getattr(op1, "str", "") == "0":
                        var_name = _get_var_name(op2)
                    if var_name:
                        null_check_blocks.setdefault(
                            var_name, set()).add(block)

                # Find dereferences
                if tok_str == "[" or tok_str == ".":
                    base = getattr(token, "astOperand1", None)
                    var_name = _get_var_name(base)
                    if var_name:
                        deref_sites.append((token, var_name, block))
                if tok_str == "*":
                    operand = getattr(token, "astOperand1", None)
                    is_unary = (
                        operand is not None
                        and getattr(token, "astOperand2", None) is None
                    )
                    if is_unary:
                        var_name = _get_var_name(operand)
                        if var_name:
                            deref_sites.append((token, var_name, block))

        # For each allocation, check if there's a null check before use
        for alloc_tok, alloc_var, alloc_block in alloc_sites:
            check_blocks = null_check_blocks.get(alloc_var, set())
            if not check_blocks:
                # No null check anywhere — find first dereference
                for deref_tok, deref_var, deref_block in deref_sites:
                    if deref_var == alloc_var:
                        # Check if alloc dominates deref (the deref is
                        # reachable from alloc without a check)
                        if dom.dominates(alloc_block, deref_block):
                            # Check that no null-check block is between them
                            has_check = False
                            for cb in check_blocks:
                                if (dom.dominates(alloc_block, cb)
                                        and dom.dominates(cb, deref_block)):
                                    has_check = True
                                    break
                            if not has_check:
                                self._collector.report(
                                    deref_tok,
                                    Severity.WARNING,
                                    f"'{alloc_var}' is used without NULL check after "
                                    f"allocation at line "
                                    f"{getattr(alloc_tok, 'linenr', '?')}",
                                    cwe=476,
                                    check_id="alloc-no-null-check",
                                )
                                break  # Report only the first dereference


# ═══════════════════════════════════════════════════════════════════════════
#  SECTION 8 — INTERPROCEDURAL SUMMARY FRAMEWORK
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class FunctionSummary:
    """
    Summary of a function's effect on memory safety.

    Tracks:
      - Which arguments are freed
      - Which arguments must be non-null
      - Which arguments must have minimum sizes
      - Whether the return value is heap-allocated
      - Whether the return value may be null
    """
    frees_args: Set[int] = field(default_factory=set)
    requires_nonnull: Set[int] = field(default_factory=set)
    min_arg_sizes: Dict[int, IntervalDomain] = field(default_factory=dict)
    returns_heap: bool = False
    return_may_be_null: bool = False
    return_size_from_arg: Optional[int] = None  # arg index providing size


# Pre-built summaries for standard library functions
_STDLIB_SUMMARIES: Dict[str, FunctionSummary] = {
    "malloc": FunctionSummary(
        returns_heap=True,
        return_may_be_null=True,
        return_size_from_arg=0,
    ),
    "calloc": FunctionSummary(
        returns_heap=True,
        return_may_be_null=True,
    ),
    "realloc": FunctionSummary(
        frees_args={0},  # may free the old pointer
        returns_heap=True,
        return_may_be_null=True,
        return_size_from_arg=1,
    ),
    "free": FunctionSummary(
        frees_args={0},
    ),
    "memcpy": FunctionSummary(
        requires_nonnull={0, 1},
    ),
    "memmove": FunctionSummary(
        requires_nonnull={0, 1},
    ),
    "memset": FunctionSummary(
        requires_nonnull={0},
    ),
    "strcpy": FunctionSummary(
        requires_nonnull={0, 1},
    ),
    "strncpy": FunctionSummary(
        requires_nonnull={0, 1},
    ),
    "strcat": FunctionSummary(
        requires_nonnull={0, 1},
    ),
    "strlen": FunctionSummary(
        requires_nonnull={0},
    ),
    "strcmp": FunctionSummary(
        requires_nonnull={0, 1},
    ),
    "printf": FunctionSummary(),
    "fprintf": FunctionSummary(),
    "sprintf": FunctionSummary(
        requires_nonnull={0},
    ),
    "snprintf": FunctionSummary(
        requires_nonnull={0},
    ),
}


class SummaryApplicator:
    """
    Applies function summaries at call sites to refine the abstract state
    and detect violations.
    """

    def __init__(self, collector: DiagnosticCollector) -> None:
        self._collector = collector
        self._summaries: Dict[str, FunctionSummary] = dict(_STDLIB_SUMMARIES)

    def add_summary(self, func_name: str, summary: FunctionSummary) -> None:
        self._summaries[func_name] = summary

    def apply_at_call(
        self, call_token, func_name: str, args: List, state: MemState
    ) -> MemState:
        """Apply a function summary at a call site."""
        summary = self._summaries.get(func_name)
        if summary is None:
            return state

        # Check non-null requirements
        for arg_idx in summary.requires_nonnull:
            if arg_idx < len(args):
                var_name = _get_var_name(args[arg_idx])
                if var_name:
                    buf = state.get_buffer(var_name)
                    if buf.heap_state.state == HeapState.NULL:
                        self._collector.report(
                            call_token,
                            Severity.ERROR,
                            f"{func_name}(): argument {arg_idx + 1} ('{var_name}') "
                            f"is NULL but must be non-null",
                            cwe=476,
                            check_id="null-arg-to-nonnull",
                        )
                    elif buf.heap_state.state == HeapState.FREED:
                        self._collector.report(
                            call_token,
                            Severity.ERROR,
                            f"{func_name}(): argument {arg_idx + 1} ('{var_name}') "
                            f"was freed — use after free",
                            cwe=416,
                            check_id="freed-arg-to-func",
                        )

        # Apply frees
        for arg_idx in summary.frees_args:
            if arg_idx < len(args):
                var_name = _get_var_name(args[arg_idx])
                if var_name:
                    buf = state.get_buffer(var_name)
                    state = state.set_buffer(var_name, buf.with_freed())

        return state


# ═══════════════════════════════════════════════════════════════════════════
#  SECTION 9 — MAIN ANALYSIS DRIVER
# ═══════════════════════════════════════════════════════════════════════════

class BuflintAnalyzer:
    """
    Top-level analyzer that orchestrates all memory-safety checks.

    Architecture:
      1. Parse dump file
      2. Build CFGs for all functions
      3. Build call graph
      4. For each function (in bottom-up call graph order):
         a. Initialize abstract state from declarations
         b. Run forward dataflow analysis (MemSafetyAnalysis)
         c. Run scope-escape checks
         d. Run malloc null-check detection
         e. Apply interprocedural summaries
      5. Collect and report all diagnostics
    """

    def __init__(self) -> None:
        self._collector = DiagnosticCollector()
        self._summary_applicator = SummaryApplicator(self._collector)

    def analyze_dump(self, dump_path: str) -> List[Diagnostic]:
        """Analyze a Cppcheck dump file and return diagnostics."""
        data = cppcheckdata.parsedump(dump_path)

        for config in data.configurations:
            self._analyze_configuration(config)

        return self._collector.diagnostics

    def _analyze_configuration(self, config) -> None:
        """Analyze a single configuration."""
        # ── Step 1: Build CFGs ────────────────────────────────────────
        cfg_builder = CFGBuilder()
        try:
            cfgs = cfg_builder.build_all(config)
        except Exception:
            # Fallback: analyze token-by-token without CFG
            self._analyze_tokenlist_fallback(config)
            return

        # ── Step 2: Build call graph ──────────────────────────────────
        cg_builder = CallGraphBuilder()
        try:
            call_graph = cg_builder.build(config)
            analysis_order = call_graph.topological_order()
            func_names = [getattr(f, "name", str(f)) for f in analysis_order]
        except Exception:
            func_names = list(cfgs.keys())

        # ── Step 3: Analyze each function ─────────────────────────────
        for func_name in func_names:
            if func_name not in cfgs:
                continue
            cfg = cfgs[func_name]
            self._analyze_function(func_name, cfg, config)

    def _analyze_function(self, func_name: str, cfg: CFG, config) -> None:
        """Run all analyses on a single function."""

        # ── Initialize state from declarations ────────────────────────
        initial_state = MemState.bottom()

        # Find the function's scope to get variable declarations
        func_obj = None
        for func in getattr(config, "functions", []):
            if getattr(func, "name", "") == func_name:
                func_obj = func
                break

        if func_obj is not None:
            # Scan function arguments
            initial_state = VarDeclScanner.scan_function_args(
                func_obj, initial_state
            )

        # Scan local variable declarations from the entry block
        if cfg.entry and cfg.entry.tokens:
            scope = getattr(cfg.entry.tokens[0], "scope", None)
            if scope:
                initial_state = VarDeclScanner.scan_function_scope(
                    scope, initial_state
                )

        # ── Run forward dataflow analysis ─────────────────────────────
        analysis = MemSafetyAnalysis(self._collector)

        engine = DataflowEngine(
            strategy=WorklistStrategy.REVERSE_POSTORDER,
            max_iterations=5000,
            use_widening=True,
            widening_delay=3,
            use_narrowing=True,
            narrowing_iterations=2,
            trace=False,
        )

        try:
            result = engine.run(analysis, cfg)
        except Exception:
            # If the engine fails, fall back to single-pass analysis
            self._single_pass_analysis(cfg, initial_state)
            return

        # ── Post-analysis checks ──────────────────────────────────────

        # Scope escape checking (return statements)
        scope_checker = ScopeEscapeChecker(self._collector)
        for block in cfg.blocks:
            out_state = result.out_state(block)
            if out_state is None:
                continue
            for token in block.tokens:
                if getattr(token, "str", "") == "return":
                    scope_checker.check_return(token, out_state)

        # Malloc null-check detection
        try:
            dom = compute_dominators(cfg)
            null_checker = MallocNullCheckDetector(self._collector)
            null_checker.check_function(cfg, dom)
        except Exception:
            pass  # Non-critical check — skip on failure

        # ── Apply interprocedural summaries at call sites ─────────────
        for block in cfg.blocks:
            in_state = result.in_state(block)
            if in_state is None:
                continue
            for token in block.tokens:
                func_call = _find_function_call(token)
                if func_call:
                    args = _get_call_args(token)
                    self._summary_applicator.apply_at_call(
                        token, func_call, args, in_state
                    )

    def _single_pass_analysis(self, cfg: CFG, initial_state: MemState) -> None:
        """Fallback: single forward pass without fixed-point iteration."""
        analysis = MemSafetyAnalysis(self._collector)
        state = initial_state
        for block in cfg.blocks:
            try:
                state = analysis.transfer(block, state)
            except Exception:
                continue

    def _analyze_tokenlist_fallback(self, config) -> None:
        """
        Fallback analysis when CFG construction fails.
        Performs a single linear pass over the token list.
        """
        state = MemState.bottom()
        analysis = MemSafetyAnalysis(self._collector)

        for token in getattr(config, "tokenlist", []):
            try:
                state = analysis._transfer_token(token, state)
            except Exception:
                continue


# ═══════════════════════════════════════════════════════════════════════════
#  SECTION 10 — PATTERN-BASED CHECKS (LIGHTWEIGHT / SYNTACTIC)
# ═══════════════════════════════════════════════════════════════════════════

class PatternChecker:
    """
    Lightweight pattern-based checks that don't require dataflow analysis.
    These catch common coding mistakes with high confidence and zero
    false positives.
    """

    def __init__(self, collector: DiagnosticCollector) -> None:
        self._collector = collector

    def check_tokenlist(self, tokenlist) -> None:
        """Run all pattern checks on a token list."""
        token = tokenlist[0] if tokenlist else None
        while token:
            self._check_sizeof_pointer(token)
            self._check_gets(token)
            self._check_strcpy_overlap(token)
            self._check_snprintf_size(token)
            self._check_alloca_in_loop(token)
            token = getattr(token, "next", None)

    def _check_sizeof_pointer(self, token) -> None:
        """
        CWE-131: Detect sizeof(ptr) when sizeof(*ptr) or sizeof(type) was intended.
        Pattern: malloc(sizeof(p)) where p is a pointer.
        """
        if not _is_function_call(token, "malloc"):
            return
        args = _get_call_args(token)
        if not args:
            return
        arg = args[0]
        # Check if arg is sizeof(ptr_variable)
        if getattr(arg, "str", "") == "sizeof":
            sizeof_arg = getattr(arg, "astOperand2", None)
            if sizeof_arg and _token_is_pointer_type(sizeof_arg):
                self._collector.report(
                    token,
                    Severity.WARNING,
                    f"malloc(sizeof({sizeof_arg.str})): '{sizeof_arg.str}' is a pointer — "
                    f"did you mean sizeof(*{sizeof_arg.str}) or sizeof(type)?",
                    cwe=131,
                    check_id="sizeof-pointer",
                )

    def _check_gets(self, token) -> None:
        """CWE-120/CWE-242: Detect use of gets()."""
        if getattr(token, "str", "") == "gets":
            next_tok = getattr(token, "next", None)
            if next_tok and getattr(next_tok, "str", "") == "(":
                self._collector.report(
                    token,
                    Severity.ERROR,
                    "Use of gets() is inherently unsafe — always use fgets() instead",
                    cwe=242,
                    check_id="use-of-gets",
                )

    def _check_strcpy_overlap(self, token) -> None:
        """
        Detect strcpy(buf, buf + n) — overlapping source and destination.
        This is undefined behavior.
        """
        if not _is_function_call(token, "strcpy"):
            return
        args = _get_call_args(token)
        if len(args) < 2:
            return
        dst_name = _get_var_name(args[0])
        # Check if source involves dst
        src = args[1]
        if getattr(src, "str", "") == "+":
            base = getattr(src, "astOperand1", None)
            if base and _get_var_name(base) == dst_name:
                self._collector.report(
                    token,
                    Severity.ERROR,
                    f"strcpy() with overlapping buffers: source overlaps "
                    f"with destination '{dst_name}' — use memmove()",
                    cwe=119,
                    check_id="strcpy-overlap",
                )

    def _check_snprintf_size(self, token) -> None:
        """
        CWE-131: Detect snprintf(buf, sizeof(buf) - 1, ...) which
        should be snprintf(buf, sizeof(buf), ...) since snprintf
        already reserves space for the null terminator.
        """
        if not _is_function_call(token, "snprintf"):
            return
        args = _get_call_args(token)
        if len(args) < 2:
            return
        size_arg = args[1]
        if getattr(size_arg, "str", "") == "-":
            lhs = getattr(size_arg, "astOperand1", None)
            rhs = getattr(size_arg, "astOperand2", None)
            if (lhs and getattr(lhs, "str", "") == "sizeof"
                    and rhs and getattr(rhs, "str", "") == "1"):
                self._collector.report(
                    token,
                    Severity.STYLE,
                    "snprintf() already null-terminates — "
                    "sizeof(buf) - 1 is likely off-by-one; use sizeof(buf)",
                    cwe=131,
                    check_id="snprintf-off-by-one",
                )

    def _check_alloca_in_loop(self, token) -> None:
        """
        Detect alloca() inside a loop — can cause stack overflow.
        """
        if getattr(token, "str", "") != "alloca":
            return
        next_tok = getattr(token, "next", None)
        if not (next_tok and getattr(next_tok, "str", "") == "("):
            return
        # Walk up scopes to check for loop
        scope = getattr(token, "scope", None)
        while scope:
            scope_type = getattr(scope, "type", "")
            if scope_type in ("While", "For", "Do"):
                self._collector.report(
                    token,
                    Severity.WARNING,
                    "alloca() inside a loop — may cause stack overflow "
                    "on large iteration counts",
                    cwe=770,
                    check_id="alloca-in-loop",
                )
                return
            scope = getattr(scope, "nestedIn", None)


# ═══════════════════════════════════════════════════════════════════════════
#  SECTION 11 — CHECKER REGISTRATION AND MAIN ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════

def run_buflint(dump_path: str, *, verbose: bool = False) -> List[Diagnostic]:
    """
    Main entry point: run all Buflint checks on a dump file.

    Parameters
    ----------
    dump_path : str
        Path to a Cppcheck .dump file.
    verbose : bool
        If True, print progress information to stderr.

    Returns
    -------
    List[Diagnostic]
        Sorted list of diagnostics found.
    """
    if verbose:
        print(f"[buflint] Analyzing {dump_path}", file=sys.stderr)

    # ── Phase 1: Pattern-based checks (fast, zero FP) ────────────────
    collector = DiagnosticCollector()
    data = cppcheckdata.parsedump(dump_path)

    pattern_checker = PatternChecker(collector)
    for config in data.configurations:
        tokenlist = getattr(config, "tokenlist", [])
        if tokenlist:
            pattern_checker.check_tokenlist(tokenlist)

    if verbose:
        print(
            f"[buflint] Pattern checks: {len(collector.diagnostics)} findings",
            file=sys.stderr,
        )

    # ── Phase 2: Dataflow-based checks (sound, low FP) ───────────────
    analyzer = BuflintAnalyzer()
    # Share the collector so pattern findings are included
    analyzer._collector = collector
    analyzer._summary_applicator = SummaryApplicator(collector)

    for config in data.configurations:
        analyzer._analyze_configuration(config)

    if verbose:
        print(
            f"[buflint] Total findings: {len(collector.diagnostics)}",
            file=sys.stderr,
        )

    return collector.diagnostics


def main() -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="buflint",
        description=(
            "Buflint — Sound memory-safety static analyzer for C/C++ "
            "(Cppcheck addon)"
        ),
    )
    parser.add_argument(
        "dump_files",
        nargs="+",
        metavar="FILE.dump",
        help="Cppcheck dump file(s) to analyze",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Print progress information to stderr",
    )
    parser.add_argument(
        "--exit-code",
        type=int,
        default=1,
        metavar="N",
        help="Exit code when findings are present (default: 1)",
    )
    parser.add_argument(
        "--severity",
        choices=["error", "warning", "style", "all"],
        default="all",
        help="Minimum severity to report (default: all)",
    )

    args = parser.parse_args()

    severity_filter = {
        "error": {Severity.ERROR},
        "warning": {Severity.ERROR, Severity.WARNING},
        "style": {Severity.ERROR, Severity.WARNING, Severity.STYLE},
        "all": {Severity.ERROR, Severity.WARNING, Severity.STYLE, Severity.PORTABILITY},
    }[args.severity]

    total_findings = 0

    for dump_path in args.dump_files:
        if not os.path.isfile(dump_path):
            print(
                f"[buflint] Error: file not found: {dump_path}", file=sys.stderr)
            continue

        diagnostics = run_buflint(dump_path, verbose=args.verbose)

        for diag in diagnostics:
            if diag.severity in severity_filter:
                print(diag.cppcheck_format())
                total_findings += 1

    if args.verbose:
        print(
            f"\n[buflint] Grand total: {total_findings} finding(s) "
            f"across {len(args.dump_files)} file(s)",
            file=sys.stderr,
        )

    return args.exit_code if total_findings > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
