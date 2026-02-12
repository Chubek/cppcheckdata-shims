"""
cppcheckdata_shims.abstract_interp
=====================================

Abstract interpretation engine for C programs via Cppcheck dump files.

This module provides a complete abstract interpretation framework that
operates over the CFGs and call graphs built by the sibling modules, using
the fixpoint engine from :mod:`dataflow_engine`.

Theory
------
Abstract interpretation [Cousot & Cousot 1977] approximates concrete program
semantics by computing over *abstract domains* connected to concrete domains
via *Galois connections* ``(α, γ)``:

.. math::

    α(C) ⊑ a  ⟺  C ⊆ γ(a)

The abstract state maps each program variable to an element of an abstract
domain.  Transfer functions lift concrete operations (assignment, arithmetic,
comparison) to abstract counterparts.  Loops are handled by *widening*
operators ``∇`` that guarantee convergence:

.. math::

    ∀ a, a' ∈ A: a, a' ⊑ a ∇ a'

and any ascending chain stabilises in finitely many widening steps.

After the widening fixpoint, a *narrowing* pass ``Δ`` recovers precision.

Architecture
------------
::

    ┌─────────────────────────────────────────────────────────┐
    │                  AbstractInterpreter                     │
    │  ┌─────────────┐  ┌──────────────┐  ┌───────────────┐  │
    │  │ AbstractDomain│  │ CTransfer-   │  │ Condition-    │  │
    │  │ (pluggable)  │  │ Function     │  │ Refiner       │  │
    │  └──────┬───────┘  └──────┬───────┘  └──────┬────────┘  │
    │         │                 │                  │           │
    │  ┌──────▼─────────────────▼──────────────────▼────────┐ │
    │  │          dataflow_engine.IntraproceduralSolver       │ │
    │  │          dataflow_engine.InterproceduralSolver       │ │
    │  └─────────────────────────────────────────────────────┘ │
    └─────────────────────────────────────────────────────────┘

Abstract Domains
~~~~~~~~~~~~~~~~
Each abstract domain implements the :class:`AbstractDomain` interface,
which extends :class:`dataflow_engine.Lattice` with:

- ``abstract_const(value)`` — abstract a concrete constant.
- ``abstract_unary(op, a)`` — abstract unary operations.
- ``abstract_binary(op, a, b)`` — abstract binary operations.
- ``abstract_condition(op, a, b)`` — refine values under branch conditions.
- ``gamma_str(a)`` — human-readable concretization string.

Built-in domains:

- :class:`IntervalDomain` — non-relational interval ``[lo, hi]``
- :class:`SignDomain` — sign abstraction ``{⊥, -, 0, +, ⊤}``
- :class:`CongruenceDomain` — ``a (mod m)`` congruences
- :class:`BitfieldDomain` — three-valued bitwise ``{0, 1, ⊤}`` per bit
- :class:`ReducedProductDomain` — reduced product of multiple domains
- :class:`WrappingIntervalDomain` — machine-integer intervals with wrap-around
- :class:`APRONDomain` — wrapper for APRON library (Octagon, Polka, etc.)

Abstract State
~~~~~~~~~~~~~~
An :class:`AbstractState` is a map ``variable_id → abstract_value`` with
structural operations (join, widen, etc.) delegated to a :class:`MapLattice`.

Transfer Function
~~~~~~~~~~~~~~~~~
:class:`CTransferFunction` walks the token AST within each CFG node,
interpreting assignments, arithmetic, function calls, and pointer
dereferences abstractly.

Condition Refinement
~~~~~~~~~~~~~~~~~~~~
:class:`ConditionRefiner` refines the abstract state along branch edges
(``BRANCH_TRUE`` / ``BRANCH_FALSE``), implementing the abstract
counterpart of conditional tests.

Public API
----------
    AbstractDomain          - base class for abstract domains
    AbstractState           - variable → abstract value mapping
    AbstractInterpreter     - main analysis driver
    IntervalDomain          - interval [lo, hi] domain
    SignDomain              - sign domain {⊥, -, 0, +, ⊤}
    CongruenceDomain        - congruence a (mod m) domain
    BitfieldDomain          - three-valued bit domain
    ReducedProductDomain    - reduced product combinator
    WrappingIntervalDomain  - wrapping machine-integer intervals
    APRONDomain             - APRON library wrapper
    CTransferFunction       - C statement abstract transfer
    ConditionRefiner        - branch condition refinement
    interpret_function      - analyse a single function
    interpret_program       - analyse the whole program

Usage example
-------------
::

    from cppcheckdata_shims.controlflow_graph import build_cfg
    from cppcheckdata_shims.abstract_interp import (
        IntervalDomain, AbstractInterpreter, interpret_function,
    )

    cfg = build_cfg(some_function)
    domain = IntervalDomain(bit_width=32, signed=True)
    result = interpret_function(cfg, domain)

    for node_id, state in result.node_states.items():
        print(f"Node {node_id}:")
        for var, val in state.items():
            print(f"  {var} ∈ {domain.gamma_str(val)}")
"""

from __future__ import annotations

import abc
import copy
import enum
import functools
import itertools
import math
import operator
import sys
import warnings
from collections import OrderedDict, defaultdict
from dataclasses import dataclass, field
from typing import (
    Any,
    Callable,
    Dict,
    FrozenSet,
    Generic,
    Hashable,
    Iterable,
    Iterator,
    List,
    Mapping,
    Optional,
    Protocol,
    Sequence,
    Set,
    Tuple,
    Type,
    TypeVar,
    Union,
)

from . import dataflow_engine as dfe

# ---------------------------------------------------------------------------
# Type aliases
# ---------------------------------------------------------------------------

AbsVal = Any                  # An element of an abstract domain
VarId = str                   # Variable identifier (name or Cppcheck Id)
NodeId = Union[int, str]      # CFG node identifier

# Infinity sentinels (re-export from dataflow_engine for convenience)
NEG_INF = dfe.NEG_INF
POS_INF = dfe.POS_INF


# ===================================================================
# C TYPE INFORMATION
# ===================================================================

class CTypeKind(enum.Enum):
    """Kinds of C types relevant to abstract interpretation."""
    VOID = "void"
    BOOL = "bool"
    CHAR = "char"
    SCHAR = "signed char"
    UCHAR = "unsigned char"
    SHORT = "short"
    USHORT = "unsigned short"
    INT = "int"
    UINT = "unsigned int"
    LONG = "long"
    ULONG = "unsigned long"
    LLONG = "long long"
    ULLONG = "unsigned long long"
    FLOAT = "float"
    DOUBLE = "double"
    LDOUBLE = "long double"
    POINTER = "pointer"
    ARRAY = "array"
    STRUCT = "struct"
    UNION = "union"
    ENUM = "enum"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class CType:
    """Simplified C type descriptor for abstract interpretation.

    Attributes
    ----------
    kind : CTypeKind
        The fundamental kind.
    bit_width : int
        Bit width (e.g. 32 for ``int`` on typical platforms).
    is_signed : bool
        Whether the integer type is signed.
    is_pointer : bool
        Whether the type is a pointer.
    pointed_type : CType or None
        For pointers/arrays, the element type.
    """
    kind: CTypeKind = CTypeKind.INT
    bit_width: int = 32
    is_signed: bool = True
    is_pointer: bool = False
    pointed_type: Optional["CType"] = None

    @property
    def is_integer(self) -> bool:
        return self.kind in (
            CTypeKind.BOOL, CTypeKind.CHAR, CTypeKind.SCHAR,
            CTypeKind.UCHAR, CTypeKind.SHORT, CTypeKind.USHORT,
            CTypeKind.INT, CTypeKind.UINT, CTypeKind.LONG,
            CTypeKind.ULONG, CTypeKind.LLONG, CTypeKind.ULLONG,
            CTypeKind.ENUM,
        )

    @property
    def is_floating(self) -> bool:
        return self.kind in (CTypeKind.FLOAT, CTypeKind.DOUBLE,
                             CTypeKind.LDOUBLE)

    @property
    def min_value(self) -> int:
        """Minimum representable value for integer types."""
        if not self.is_integer:
            return 0
        if self.is_signed:
            return -(1 << (self.bit_width - 1))
        return 0

    @property
    def max_value(self) -> int:
        """Maximum representable value for integer types."""
        if not self.is_integer:
            return 0
        if self.is_signed:
            return (1 << (self.bit_width - 1)) - 1
        return (1 << self.bit_width) - 1


# Common C types (assuming LP64 / typical 64-bit platform)
CTYPE_VOID = CType(CTypeKind.VOID, 0, False)
CTYPE_BOOL = CType(CTypeKind.BOOL, 1, False)
CTYPE_CHAR = CType(CTypeKind.CHAR, 8, True)
CTYPE_UCHAR = CType(CTypeKind.UCHAR, 8, False)
CTYPE_SHORT = CType(CTypeKind.SHORT, 16, True)
CTYPE_USHORT = CType(CTypeKind.USHORT, 16, False)
CTYPE_INT = CType(CTypeKind.INT, 32, True)
CTYPE_UINT = CType(CTypeKind.UINT, 32, False)
CTYPE_LONG = CType(CTypeKind.LONG, 64, True)
CTYPE_ULONG = CType(CTypeKind.ULONG, 64, False)
CTYPE_LLONG = CType(CTypeKind.LLONG, 64, True)
CTYPE_ULLONG = CType(CTypeKind.ULLONG, 64, False)
CTYPE_FLOAT = CType(CTypeKind.FLOAT, 32, True)
CTYPE_DOUBLE = CType(CTypeKind.DOUBLE, 64, True)
CTYPE_PTR = CType(CTypeKind.POINTER, 64, False, is_pointer=True)


def infer_ctype(token) -> CType:
    """Infer a :class:`CType` from a Cppcheck token's type information.

    Uses ``token.valueType`` if available (Cppcheck ≥ 1.73), otherwise
    falls back to heuristics on ``token.variable``.

    Parameters
    ----------
    token : cppcheckdata.Token

    Returns
    -------
    CType
    """
    vt = getattr(token, "valueType", None)
    if vt is not None:
        return _ctype_from_valuetype(vt)

    # Fallback: check variable type string
    var = getattr(token, "variable", None)
    if var is not None:
        type_str = getattr(var, "typeStartToken", None)
        if type_str is not None:
            return _ctype_from_type_string(getattr(type_str, "str", ""))

    return CTYPE_INT  # default assumption


def _ctype_from_valuetype(vt) -> CType:
    """Convert Cppcheck's ValueType to our CType."""
    type_str = getattr(vt, "type", "")
    sign = getattr(vt, "sign", "")
    pointer = getattr(vt, "pointer", 0)

    if pointer and pointer > 0:
        return CType(CTypeKind.POINTER, 64, False, is_pointer=True)

    is_signed = sign != "unsigned"
    is_unsigned = sign == "unsigned"

    type_map = {
        "void": CTYPE_VOID,
        "bool": CTYPE_BOOL,
        "char": CTYPE_CHAR if is_signed else CTYPE_UCHAR,
        "short": CTYPE_SHORT if is_signed else CTYPE_USHORT,
        "int": CTYPE_INT if is_signed else CTYPE_UINT,
        "long": CTYPE_LONG if is_signed else CTYPE_ULONG,
        "long long": CTYPE_LLONG if is_signed else CTYPE_ULLONG,
        "float": CTYPE_FLOAT,
        "double": CTYPE_DOUBLE,
        "long double": CType(CTypeKind.LDOUBLE, 80, True),
    }
    return type_map.get(type_str, CTYPE_INT)


def _ctype_from_type_string(s: str) -> CType:
    """Parse a type token string into CType."""
    s = s.strip().lower()
    if "unsigned" in s:
        if "long long" in s:
            return CTYPE_ULLONG
        if "long" in s:
            return CTYPE_ULONG
        if "short" in s:
            return CTYPE_USHORT
        if "char" in s:
            return CTYPE_UCHAR
        return CTYPE_UINT
    if "long long" in s:
        return CTYPE_LLONG
    if "long" in s:
        return CTYPE_LONG
    if "short" in s:
        return CTYPE_SHORT
    if "char" in s:
        return CTYPE_CHAR
    if "float" in s:
        return CTYPE_FLOAT
    if "double" in s:
        return CTYPE_DOUBLE
    if "void" in s:
        return CTYPE_VOID
    if "bool" in s or "_Bool" in s:
        return CTYPE_BOOL
    return CTYPE_INT


# ===================================================================
# ABSTRACT DOMAIN — BASE CLASS
# ===================================================================

class AbstractDomain(dfe.Lattice, abc.ABC):
    """Base class for abstract domains used in abstract interpretation.

    Extends :class:`dataflow_engine.Lattice` with operations for
    abstracting C language constructs: constants, arithmetic, comparisons,
    casts, and condition refinement.

    Every abstract domain must implement the core lattice operations
    (``bottom``, ``top``, ``join``, ``leq``) plus the abstract
    semantics methods defined here.
    """

    # ---- Abstract constant -------------------------------------------------

    @abc.abstractmethod
    def abstract_const(self, value: Union[int, float]) -> AbsVal:
        """Abstract a concrete constant value.

        Parameters
        ----------
        value : int or float
            The concrete constant.

        Returns
        -------
        AbsVal
            The abstract representation.
        """
        ...

    # ---- Abstract arithmetic -----------------------------------------------

    @abc.abstractmethod
    def abstract_unary(self, op: str, a: AbsVal) -> AbsVal:
        """Abstract a unary operation.

        Parameters
        ----------
        op : str
            The operator token string: ``'-'`` (negation), ``'~'`` (bitwise NOT),
            ``'!'`` (logical NOT), ``'++'``, ``'--'``.
        a : AbsVal
            The operand's abstract value.

        Returns
        -------
        AbsVal
        """
        ...

    @abc.abstractmethod
    def abstract_binary(self, op: str, a: AbsVal, b: AbsVal) -> AbsVal:
        """Abstract a binary operation.

        Parameters
        ----------
        op : str
            The operator: ``'+'``, ``'-'``, ``'*'``, ``'/'``, ``'%'``,
            ``'<<'``, ``'>>'``, ``'&'``, ``'|'``, ``'^'``,
            ``'&&'``, ``'||'``.
        a, b : AbsVal
            The operands' abstract values.

        Returns
        -------
        AbsVal
        """
        ...

    # ---- Abstract conditions -----------------------------------------------

    @abc.abstractmethod
    def abstract_condition(
        self, op: str, a: AbsVal, b: AbsVal, *, true_branch: bool = True
    ) -> Tuple[AbsVal, AbsVal]:
        """Refine abstract values under a comparison condition.

        Given ``a op b`` (e.g. ``x < 5``), return refined abstract values
        for ``a`` and ``b`` under the assumption that the condition is
        true (or false if ``true_branch=False``).

        Parameters
        ----------
        op : str
            Comparison operator: ``'<'``, ``'<='``, ``'>'``, ``'>='``,
            ``'=='``, ``'!='``.
        a, b : AbsVal
            Abstract values of the left and right operands.
        true_branch : bool
            If ``True``, refine assuming the condition holds.
            If ``False``, refine assuming the condition does not hold.

        Returns
        -------
        tuple[AbsVal, AbsVal]
            Refined ``(a', b')``.
        """
        ...

    # ---- Abstract cast -----------------------------------------------------

    def abstract_cast(
        self, a: AbsVal, from_type: CType, to_type: CType
    ) -> AbsVal:
        """Abstract a type cast.

        Default: return ``a`` unchanged (sound for widening casts).
        Override for truncation/wrapping semantics.
        """
        return a

    # ---- Human-readable representation -------------------------------------

    def gamma_str(self, a: AbsVal) -> str:
        """Human-readable representation of the concretisation set.

        Default: ``str(a)``.
        """
        return str(a)

    # ---- Optional: range extraction ----------------------------------------

    def to_interval(self, a: AbsVal) -> Optional[Tuple[float, float]]:
        """Extract a numeric interval ``[lo, hi]`` if the domain supports it.

        Returns ``None`` if the domain cannot provide interval bounds
        or the value is bottom.
        """
        return None

    def may_be_zero(self, a: AbsVal) -> bool:
        """Can this abstract value represent zero?  Conservative: True."""
        return True

    def must_be_zero(self, a: AbsVal) -> bool:
        """Must this abstract value be zero?"""
        return False

    def may_be_negative(self, a: AbsVal) -> bool:
        """Can this abstract value be negative?  Conservative: True."""
        return True

    def may_be_positive(self, a: AbsVal) -> bool:
        """Can this abstract value be positive?  Conservative: True."""
        return True


# ===================================================================
# INTERVAL DOMAIN
# ===================================================================

# Interval values: None = ⊥, (lo, hi) = concrete interval
Interval = Optional[Tuple[float, float]]


class IntervalDomain(AbstractDomain):
    """Non-relational integer interval domain ``[lo, hi]``.

    Sound for signed or unsigned integers of a given bit width.
    Uses widening with configurable thresholds for loop convergence.

    Parameters
    ----------
    bit_width : int
        Width of the integer type (e.g. 32).
    signed : bool
        Whether signed or unsigned.
    thresholds : sequence of int, optional
        Widening thresholds.  Common choices include ``{-1, 0, 1}``
        and powers of 2.
    """

    def __init__(
        self,
        bit_width: int = 32,
        signed: bool = True,
        thresholds: Optional[Sequence[int]] = None,
    ) -> None:
        self.bit_width = bit_width
        self.signed = signed
        if signed:
            self._min = -(1 << (bit_width - 1))
            self._max = (1 << (bit_width - 1)) - 1
        else:
            self._min = 0
            self._max = (1 << bit_width) - 1

        # Default thresholds: common boundary values
        default_thresholds = [
            self._min, -1, 0, 1, self._max,
            -128, 127, 255, -32768, 32767, 65535,
        ]
        if thresholds is not None:
            self._thresholds = sorted(set(thresholds))
        else:
            self._thresholds = sorted(set(
                t for t in default_thresholds if self._min <= t <= self._max
            ))

    # ---- Lattice operations ------------------------------------------------

    def bottom(self) -> Interval:
        return None

    def top(self) -> Interval:
        return (float(self._min), float(self._max))

    def join(self, a: Interval, b: Interval) -> Interval:
        if a is None:
            return b
        if b is None:
            return a
        return (min(a[0], b[0]), max(a[1], b[1]))

    def leq(self, a: Interval, b: Interval) -> bool:
        if a is None:
            return True
        if b is None:
            return False
        return b[0] <= a[0] and a[1] <= b[1]

    def meet(self, a: Interval, b: Interval) -> Interval:
        if a is None or b is None:
            return None
        lo = max(a[0], b[0])
        hi = min(a[1], b[1])
        if lo > hi:
            return None
        return (lo, hi)

    def widen(self, a: Interval, b: Interval) -> Interval:
        if a is None:
            return b
        if b is None:
            return a

        lo = a[0]
        hi = a[1]

        if b[0] < a[0]:
            # Jump lo to nearest threshold below b[0], or type min
            lo = float(self._min)
            for t in self._thresholds:
                if t <= b[0]:
                    lo = float(t)
                else:
                    break

        if b[1] > a[1]:
            # Jump hi to nearest threshold above b[1], or type max
            hi = float(self._max)
            for t in reversed(self._thresholds):
                if t >= b[1]:
                    hi = float(t)
                else:
                    break

        return (lo, hi)

    def narrow(self, a: Interval, b: Interval) -> Interval:
        if a is None:
            return None
        if b is None:
            return a
        lo = b[0] if a[0] == float(self._min) else a[0]
        hi = b[1] if a[1] == float(self._max) else a[1]
        if lo > hi:
            return None
        return (lo, hi)

    def copy_value(self, v: Interval) -> Interval:
        return v  # tuples/None are immutable

    # ---- Abstract semantics ------------------------------------------------

    def abstract_const(self, value: Union[int, float]) -> Interval:
        v = float(int(value))
        v = max(float(self._min), min(v, float(self._max)))
        return (v, v)

    def abstract_unary(self, op: str, a: Interval) -> Interval:
        if a is None:
            return None
        if op == "-":
            return self._clamp((-a[1], -a[0]))
        if op == "+":
            return a
        if op == "~":
            # Bitwise NOT: ~x = -(x+1)
            return self._clamp((-(a[1] + 1), -(a[0] + 1)))
        if op == "!":
            # Logical NOT: 0 if nonzero, 1 if zero
            if a[0] > 0 or a[1] < 0:
                return (0.0, 0.0)
            if a == (0.0, 0.0):
                return (1.0, 1.0)
            return (0.0, 1.0)
        if op == "++":
            return self._clamp((a[0] + 1, a[1] + 1))
        if op == "--":
            return self._clamp((a[0] - 1, a[1] - 1))
        return self.top()

    def abstract_binary(self, op: str, a: Interval, b: Interval) -> Interval:
        if a is None or b is None:
            return None

        if op == "+":
            return self._clamp((a[0] + b[0], a[1] + b[1]))
        if op == "-":
            return self._clamp((a[0] - b[1], a[1] - b[0]))
        if op == "*":
            products = [a[0]*b[0], a[0]*b[1], a[1]*b[0], a[1]*b[1]]
            return self._clamp((min(products), max(products)))
        if op == "/":
            return self._abstract_div(a, b)
        if op == "%":
            return self._abstract_mod(a, b)
        if op == "<<":
            return self._abstract_shl(a, b)
        if op == ">>":
            return self._abstract_shr(a, b)
        if op == "&":
            return self._abstract_bitand(a, b)
        if op == "|":
            return self._abstract_bitor(a, b)
        if op == "^":
            return self._abstract_bitxor(a, b)
        if op == "&&":
            return self._abstract_logand(a, b)
        if op == "||":
            return self._abstract_logor(a, b)

        return self.top()

    def abstract_condition(
        self, op: str, a: Interval, b: Interval, *, true_branch: bool = True
    ) -> Tuple[Interval, Interval]:
        if a is None or b is None:
            return (None, None)

        if not true_branch:
            # Negate the condition
            neg_op = _negate_comparison(op)
            return self.abstract_condition(neg_op, a, b, true_branch=True)

        if op == "<":
            # a < b  →  a ∈ [a.lo, min(a.hi, b.hi - 1)]
            #           b ∈ [max(b.lo, a.lo + 1), b.hi]
            a_hi = min(a[1], b[1] - 1)
            b_lo = max(b[0], a[0] + 1)
            a_new = (a[0], a_hi) if a[0] <= a_hi else None
            b_new = (b_lo, b[1]) if b_lo <= b[1] else None
            return (a_new, b_new)

        if op == "<=":
            a_hi = min(a[1], b[1])
            b_lo = max(b[0], a[0])
            a_new = (a[0], a_hi) if a[0] <= a_hi else None
            b_new = (b_lo, b[1]) if b_lo <= b[1] else None
            return (a_new, b_new)

        if op == ">":
            return self.abstract_condition("<", b, a, true_branch=True)[::-1]

        if op == ">=":
            return self.abstract_condition("<=", b, a, true_branch=True)[::-1]

        if op == "==":
            # a == b  →  intersect
            common = self.meet(a, b)
            return (common, common)

        if op == "!=":
            # a != b: weak refinement — only effective for singletons
            if b[0] == b[1]:
                # b is a constant c
                c = b[0]
                if a[0] == c and a[0] < a[1]:
                    a_new = (a[0] + 1, a[1])
                elif a[1] == c and a[0] < a[1]:
                    a_new = (a[0], a[1] - 1)
                else:
                    a_new = a
            else:
                a_new = a
            if a[0] == a[1]:
                c = a[0]
                if b[0] == c and b[0] < b[1]:
                    b_new = (b[0] + 1, b[1])
                elif b[1] == c and b[0] < b[1]:
                    b_new = (b[0], b[1] - 1)
                else:
                    b_new = b
            else:
                b_new = b
            return (a_new, b_new)

        # Unknown operator — no refinement
        return (a, b)

    def abstract_cast(
        self, a: Interval, from_type: CType, to_type: CType
    ) -> Interval:
        if a is None:
            return None
        if to_type.is_integer:
            tmin = float(to_type.min_value)
            tmax = float(to_type.max_value)
            # If the interval fits, keep it; otherwise widen to full range
            if a[0] >= tmin and a[1] <= tmax:
                return a
            return (tmin, tmax)
        return a

    # ---- Query methods -----------------------------------------------------

    def gamma_str(self, a: Interval) -> str:
        if a is None:
            return "⊥"
        lo, hi = a
        if lo == hi:
            return str(int(lo))
        lo_s = str(int(lo)) if lo != NEG_INF else "-∞"
        hi_s = str(int(hi)) if hi != POS_INF else "+∞"
        return f"[{lo_s}, {hi_s}]"

    def to_interval(self, a: Interval) -> Optional[Tuple[float, float]]:
        return a

    def may_be_zero(self, a: Interval) -> bool:
        if a is None:
            return False
        return a[0] <= 0 <= a[1]

    def must_be_zero(self, a: Interval) -> bool:
        if a is None:
            return False
        return a[0] == 0.0 and a[1] == 0.0

    def may_be_negative(self, a: Interval) -> bool:
        if a is None:
            return False
        return a[0] < 0

    def may_be_positive(self, a: Interval) -> bool:
        if a is None:
            return False
        return a[1] > 0

    # ---- Internal arithmetic -----------------------------------------------

    def _clamp(self, interval: Tuple[float, float]) -> Interval:
        """Clamp to representable range."""
        lo = max(interval[0], float(self._min))
        hi = min(interval[1], float(self._max))
        if lo > hi:
            return None
        return (lo, hi)

    def _abstract_div(self, a: Interval, b: Interval) -> Interval:
        """Abstract integer division.  Division by zero yields ⊤."""
        if b is None:
            return None
        # Exclude zero from divisor
        if b[0] <= 0 <= b[1]:
            # Divisor range includes zero — split
            parts: List[Interval] = []
            if b[0] < 0:
                parts.append(self._div_nonzero(a, (b[0], -1.0)))
            if b[1] > 0:
                parts.append(self._div_nonzero(a, (1.0, b[1])))
            if not parts:
                return None  # divisor is exactly [0, 0] → undefined
            result = parts[0]
            for p in parts[1:]:
                if result is not None and p is not None:
                    result = self.join(result, p)
                elif p is not None:
                    result = p
            return result
        return self._div_nonzero(a, b)

    def _div_nonzero(self, a: Interval, b: Interval) -> Interval:
        if a is None or b is None:
            return None
        quotients = [
            a[0] / b[0], a[0] / b[1],
            a[1] / b[0], a[1] / b[1],
        ]
        # Integer division truncates towards zero
        lo = math.floor(min(quotients))
        hi = math.ceil(max(quotients))
        return self._clamp((float(lo), float(hi)))

    def _abstract_mod(self, a: Interval, b: Interval) -> Interval:
        if a is None or b is None:
            return None
        if b[0] <= 0 <= b[1]:
            # Modulus with possible zero divisor
            max_abs = max(abs(b[0]), abs(b[1]))
            if max_abs == 0:
                return None
            return self._clamp((-(max_abs - 1), max_abs - 1))
        max_abs = max(abs(b[0]), abs(b[1]))
        if a[0] >= 0:
            return self._clamp((0.0, min(a[1], max_abs - 1)))
        if a[1] <= 0:
            return self._clamp((max(a[0], -(max_abs - 1)), 0.0))
        return self._clamp((-(max_abs - 1), max_abs - 1))

    def _abstract_shl(self, a: Interval, b: Interval) -> Interval:
        """Abstract left shift."""
        if a is None or b is None:
            return None
        if b[0] < 0 or b[1] >= self.bit_width:
            return self.top()
        # Conservative: compute extremes
        vals = []
        for av in (a[0], a[1]):
            for bv in (b[0], b[1]):
                if 0 <= bv < self.bit_width:
                    vals.append(av * (2 ** bv))
        if not vals:
            return self.top()
        return self._clamp((min(vals), max(vals)))

    def _abstract_shr(self, a: Interval, b: Interval) -> Interval:
        """Abstract right shift (arithmetic for signed)."""
        if a is None or b is None:
            return None
        if b[0] < 0 or b[1] >= self.bit_width:
            return self.top()
        vals = []
        for av in (a[0], a[1]):
            for bv in (b[0], b[1]):
                if 0 <= bv < self.bit_width:
                    vals.append(int(av) >> int(bv))
        if not vals:
            return self.top()
        return self._clamp((float(min(vals)), float(max(vals))))

    def _abstract_bitand(self, a: Interval, b: Interval) -> Interval:
        """Conservative abstract bitwise AND."""
        if a is None or b is None:
            return None
        # If both non-negative, result in [0, min(a.hi, b.hi)]
        if a[0] >= 0 and b[0] >= 0:
            return (0.0, min(a[1], b[1]))
        return self.top()

    def _abstract_bitor(self, a: Interval, b: Interval) -> Interval:
        """Conservative abstract bitwise OR."""
        if a is None or b is None:
            return None
        if a[0] >= 0 and b[0] >= 0:
            # Upper bound: next power of 2 above max(a.hi, b.hi), minus 1
            m = max(a[1], b[1])
            if m <= 0:
                return (0.0, 0.0)
            upper = 2 ** (int(m).bit_length()) - 1
            return self._clamp((0.0, float(upper)))
        return self.top()

    def _abstract_bitxor(self, a: Interval, b: Interval) -> Interval:
        """Conservative abstract bitwise XOR."""
        return self._abstract_bitor(a, b)  # same bound

    def _abstract_logand(self, a: Interval, b: Interval) -> Interval:
        """Abstract logical AND (``&&``)."""
        if a is None or b is None:
            return None
        a_true = not (a[0] == 0 and a[1] == 0)
        b_true = not (b[0] == 0 and b[1] == 0)
        a_false = (a[0] <= 0 <= a[1])
        b_false = (b[0] <= 0 <= b[1])

        if a_true and b_true and not a_false and not b_false:
            return (1.0, 1.0)
        if not a_true or not b_true:
            return (0.0, 0.0)
        return (0.0, 1.0)

    def _abstract_logor(self, a: Interval, b: Interval) -> Interval:
        """Abstract logical OR (``||``)."""
        if a is None or b is None:
            return None
        a_true = not (a[0] == 0 and a[1] == 0)
        b_true = not (b[0] == 0 and b[1] == 0)
        a_false = (a[0] <= 0 <= a[1])
        b_false = (b[0] <= 0 <= b[1])

        if (a_true and not a_false) or (b_true and not b_false):
            return (1.0, 1.0)
        if not a_true and not b_true:
            return (0.0, 0.0)
        return (0.0, 1.0)


# ===================================================================
# SIGN DOMAIN
# ===================================================================

class SignDomain(AbstractDomain):
    """Abstract sign domain: ``{⊥, -, 0, +, ⊤}``.

    A simple, fast, non-relational domain that tracks the sign of
    integer variables.
    """

    # Re-use the Sign enum from dataflow_engine
    Sign = dfe.Sign

    def bottom(self) -> dfe.Sign:
        return dfe.Sign.BOTTOM

    def top(self) -> dfe.Sign:
        return dfe.Sign.TOP

    def join(self, a: dfe.Sign, b: dfe.Sign) -> dfe.Sign:
        return dfe._SIGN_JOIN[(a, b)]

    def leq(self, a: dfe.Sign, b: dfe.Sign) -> bool:
        if a is dfe.Sign.BOTTOM:
            return True
        if b is dfe.Sign.TOP:
            return True
        return a is b

    def meet(self, a: dfe.Sign, b: dfe.Sign) -> dfe.Sign:
        if a is dfe.Sign.TOP:
            return b
        if b is dfe.Sign.TOP:
            return a
        if a is b:
            return a
        return dfe.Sign.BOTTOM

    def copy_value(self, v: dfe.Sign) -> dfe.Sign:
        return v

    # ---- Abstract semantics ------------------------------------------------

    def abstract_const(self, value: Union[int, float]) -> dfe.Sign:
        if value < 0:
            return dfe.Sign.NEG
        if value > 0:
            return dfe.Sign.POS
        return dfe.Sign.ZERO

    def abstract_unary(self, op: str, a: dfe.Sign) -> dfe.Sign:
        S = dfe.Sign
        if a is S.BOTTOM:
            return S.BOTTOM
        if op == "-":
            return {S.NEG: S.POS, S.POS: S.NEG, S.ZERO: S.ZERO, S.TOP: S.TOP,
                    S.BOTTOM: S.BOTTOM}[a]
        if op == "!":
            return {S.ZERO: S.POS, S.POS: S.ZERO, S.NEG: S.ZERO,
                    S.TOP: S.TOP, S.BOTTOM: S.BOTTOM}[a]
        if op in ("++", ):
            if a is S.POS:
                return S.POS
            if a is S.ZERO:
                return S.POS
            return S.TOP
        if op in ("--", ):
            if a is S.NEG:
                return S.NEG
            if a is S.ZERO:
                return S.NEG
            return S.TOP
        return S.TOP

    def abstract_binary(self, op: str, a: dfe.Sign, b: dfe.Sign) -> dfe.Sign:
        S = dfe.Sign
        if a is S.BOTTOM or b is S.BOTTOM:
            return S.BOTTOM

        if op == "+":
            return _SIGN_ADD.get((a, b), S.TOP)
        if op == "-":
            neg_b = self.abstract_unary("-", b)
            return _SIGN_ADD.get((a, neg_b), S.TOP)
        if op == "*":
            return _SIGN_MUL.get((a, b), S.TOP)
        if op == "/":
            if b is S.ZERO:
                return S.BOTTOM  # division by zero → unreachable
            return _SIGN_MUL.get((a, b), S.TOP)  # same sign rules
        return S.TOP

    def abstract_condition(
        self, op: str, a: dfe.Sign, b: dfe.Sign, *, true_branch: bool = True
    ) -> Tuple[dfe.Sign, dfe.Sign]:
        S = dfe.Sign
        if a is S.BOTTOM or b is S.BOTTOM:
            return (S.BOTTOM, S.BOTTOM)

        if not true_branch:
            neg_op = _negate_comparison(op)
            return self.abstract_condition(neg_op, a, b, true_branch=True)

        if op == "==" and a is S.TOP:
            return (b, b)
        if op == "==" and b is S.TOP:
            return (a, a)
        if op == "==":
            common = self.meet(a, b)
            return (common, common)

        if op == ">" and b is S.ZERO:
            a_new = S.POS if a is S.TOP else (a if a is S.POS else S.BOTTOM)
            return (a_new, b)
        if op == "<" and b is S.ZERO:
            a_new = S.NEG if a is S.TOP else (a if a is S.NEG else S.BOTTOM)
            return (a_new, b)
        if op == ">=" and b is S.ZERO:
            if a is S.TOP:
                a_new = S.TOP  # could be 0 or +
            elif a is S.NEG:
                a_new = S.BOTTOM
            else:
                a_new = a
            return (a_new, b)

        return (a, b)

    def gamma_str(self, a: dfe.Sign) -> str:
        return a.value

    def to_interval(self, a: dfe.Sign) -> Optional[Tuple[float, float]]:
        S = dfe.Sign
        if a is S.BOTTOM:
            return None
        if a is S.ZERO:
            return (0.0, 0.0)
        if a is S.POS:
            return (1.0, POS_INF)
        if a is S.NEG:
            return (NEG_INF, -1.0)
        return (NEG_INF, POS_INF)

    def may_be_zero(self, a: dfe.Sign) -> bool:
        return a in (dfe.Sign.ZERO, dfe.Sign.TOP)

    def must_be_zero(self, a: dfe.Sign) -> bool:
        return a is dfe.Sign.ZERO

    def may_be_negative(self, a: dfe.Sign) -> bool:
        return a in (dfe.Sign.NEG, dfe.Sign.TOP)

    def may_be_positive(self, a: dfe.Sign) -> bool:
        return a in (dfe.Sign.POS, dfe.Sign.TOP)


# Pre-computed sign arithmetic tables
_SIGN_ADD: Dict[Tuple[dfe.Sign, dfe.Sign], dfe.Sign] = {}
_SIGN_MUL: Dict[Tuple[dfe.Sign, dfe.Sign], dfe.Sign] = {}


def _build_sign_arithmetic():
    S = dfe.Sign
    # Addition
    add_table = {
        (S.POS, S.POS): S.POS,
        (S.NEG, S.NEG): S.NEG,
        (S.ZERO, S.ZERO): S.ZERO,
        (S.POS, S.ZERO): S.POS,
        (S.ZERO, S.POS): S.POS,
        (S.NEG, S.ZERO): S.NEG,
        (S.ZERO, S.NEG): S.NEG,
        (S.POS, S.NEG): S.TOP,
        (S.NEG, S.POS): S.TOP,
    }
    for (a, b), r in add_table.items():
        _SIGN_ADD[(a, b)] = r
    for s in S:
        _SIGN_ADD[(S.BOTTOM, s)] = S.BOTTOM
        _SIGN_ADD[(s, S.BOTTOM)] = S.BOTTOM
        if (S.TOP, s) not in _SIGN_ADD:
            _SIGN_ADD[(S.TOP, s)] = S.TOP if s is not S.BOTTOM else S.BOTTOM
        if (s, S.TOP) not in _SIGN_ADD:
            _SIGN_ADD[(s, S.TOP)] = S.TOP if s is not S.BOTTOM else S.BOTTOM

    # Multiplication
    mul_table = {
        (S.POS, S.POS): S.POS,
        (S.NEG, S.NEG): S.POS,
        (S.POS, S.NEG): S.NEG,
        (S.NEG, S.POS): S.NEG,
        (S.ZERO, S.ZERO): S.ZERO,
        (S.POS, S.ZERO): S.ZERO,
        (S.ZERO, S.POS): S.ZERO,
        (S.NEG, S.ZERO): S.ZERO,
        (S.ZERO, S.NEG): S.ZERO,
    }
    for (a, b), r in mul_table.items():
        _SIGN_MUL[(a, b)] = r
    for s in S:
        _SIGN_MUL[(S.BOTTOM, s)] = S.BOTTOM
        _SIGN_MUL[(s, S.BOTTOM)] = S.BOTTOM
        if (S.TOP, s) not in _SIGN_MUL:
            _SIGN_MUL[(S.TOP, s)] = S.ZERO if s is S.ZERO else (
                S.BOTTOM if s is S.BOTTOM else S.TOP)
        if (s, S.TOP) not in _SIGN_MUL:
            _SIGN_MUL[(s, S.TOP)] = S.ZERO if s is S.ZERO else (
                S.BOTTOM if s is S.BOTTOM else S.TOP)

_build_sign_arithmetic()


# ===================================================================
# CONGRUENCE DOMAIN
# ===================================================================

# Congruence values: None = ⊥, ("top",) = ⊤, (a, m) = a (mod m), m > 0
CongruenceValue = Optional[Tuple]


class CongruenceDomain(AbstractDomain):
    """Congruence domain: ``a (mod m)`` where ``m > 0``.

    Abstract values: ``None`` = ⊥, ``("top",)`` = ⊤, ``(a, m)`` = the
    set ``{a + k*m : k ∈ Z}`` (all integers ≡ ``a`` modulo ``m``).
    The special case ``(c, 0)`` represents the singleton ``{c}``.

    This domain is useful for alignment checks, array index analysis,
    and loop counter analysis.
    """

    _TOP = ("top",)

    def bottom(self) -> CongruenceValue:
        return None

    def top(self) -> CongruenceValue:
        return self._TOP

    def join(self, a: CongruenceValue, b: CongruenceValue) -> CongruenceValue:
        if a is None:
            return b
        if b is None:
            return a
        if a == self._TOP or b == self._TOP:
            return self._TOP
        # a = (a_rem, a_mod), b = (b_rem, b_mod)
        a_rem, a_mod = a
        b_rem, b_mod = b
        if a_mod == 0 and b_mod == 0:
            if a_rem == b_rem:
                return a
            return (a_rem % math.gcd(abs(a_rem - b_rem), 1),
                    abs(a_rem - b_rem)) if a_rem != b_rem else a
        new_mod = math.gcd(a_mod, b_mod)
        new_mod = math.gcd(new_mod, abs(a_rem - b_rem))
        if new_mod == 0:
            return self._TOP
        new_rem = a_rem % new_mod
        return (new_rem, new_mod)

    def leq(self, a: CongruenceValue, b: CongruenceValue) -> bool:
        if a is None:
            return True
        if b == self._TOP:
            return True
        if b is None:
            return False
        if a == self._TOP:
            return False
        a_rem, a_mod = a
        b_rem, b_mod = b
        if b_mod == 0:
            return a_mod == 0 and a_rem == b_rem
        if a_mod == 0:
            return a_rem % b_mod == b_rem % b_mod
        # a ⊑ b iff b_mod divides a_mod and a_rem ≡ b_rem (mod b_mod)
        return (a_mod % b_mod == 0) and (a_rem % b_mod == b_rem % b_mod)

    def meet(self, a: CongruenceValue, b: CongruenceValue) -> CongruenceValue:
        if a is None or b is None:
            return None
        if a == self._TOP:
            return b
        if b == self._TOP:
            return a
        a_rem, a_mod = a
        b_rem, b_mod = b
        # Chinese Remainder Theorem
        g = math.gcd(a_mod, b_mod) if (a_mod and b_mod) else max(a_mod, b_mod)
        if g == 0:
            return (a_rem, 0) if a_rem == b_rem else None
        if (a_rem - b_rem) % g != 0:
            return None  # no solution
        new_mod = (a_mod * b_mod // g) if (a_mod and b_mod) else 0
        # Extended GCD to find solution
        if new_mod == 0:
            return (a_rem, 0) if a_rem == b_rem else None
        new_rem = a_rem % new_mod  # simplified
        return (new_rem, new_mod)

    def copy_value(self, v: CongruenceValue) -> CongruenceValue:
        return v

    def abstract_const(self, value: Union[int, float]) -> CongruenceValue:
        return (int(value), 0)  # singleton

    def abstract_unary(self, op: str, a: CongruenceValue) -> CongruenceValue:
        if a is None:
            return None
        if a == self._TOP:
            return self._TOP
        a_rem, a_mod = a
        if op == "-":
            return (-a_rem if a_mod == 0 else (-a_rem % a_mod), a_mod)
        if op in ("++",):
            return ((a_rem + 1) % a_mod if a_mod else a_rem + 1, a_mod)
        if op in ("--",):
            return ((a_rem - 1) % a_mod if a_mod else a_rem - 1, a_mod)
        return self._TOP

    def abstract_binary(
        self, op: str, a: CongruenceValue, b: CongruenceValue
    ) -> CongruenceValue:
        if a is None or b is None:
            return None
        if a == self._TOP or b == self._TOP:
            if op == "*" and (a == (0, 0) or b == (0, 0)):
                return (0, 0)
            return self._TOP
        a_rem, a_mod = a
        b_rem, b_mod = b

        if op == "+":
            new_mod = math.gcd(a_mod, b_mod)
            new_rem = (a_rem + b_rem) % new_mod if new_mod else a_rem + b_rem
            return (new_rem, new_mod)
        if op == "-":
            new_mod = math.gcd(a_mod, b_mod)
            new_rem = (a_rem - b_rem) % new_mod if new_mod else a_rem - b_rem
            return (new_rem, new_mod)
        if op == "*":
            if a_mod == 0 and b_mod == 0:
                return (a_rem * b_rem, 0)
            new_mod = math.gcd(a_rem * b_mod, b_rem * a_mod)
            new_mod = math.gcd(new_mod, a_mod * b_mod)
            new_mod = abs(new_mod)
            new_rem = (a_rem * b_rem) % new_mod if new_mod else a_rem * b_rem
            return (new_rem, new_mod)
        return self._TOP

    def abstract_condition(
        self, op: str, a: CongruenceValue, b: CongruenceValue,
        *, true_branch: bool = True,
    ) -> Tuple[CongruenceValue, CongruenceValue]:
        if a is None or b is None:
            return (None, None)
        if not true_branch:
            neg_op = _negate_comparison(op)
            return self.abstract_condition(neg_op, a, b, true_branch=True)
        if op == "==":
            common = self.meet(a, b)
            return (common, common)
        return (a, b)

    def gamma_str(self, a: CongruenceValue) -> str:
        if a is None:
            return "⊥"
        if a == self._TOP:
            return "⊤"
        r, m = a
        if m == 0:
            return str(r)
        return f"{r} (mod {m})"


# ===================================================================
# BITFIELD DOMAIN
# ===================================================================

@dataclass(frozen=True)
class BitfieldValue:
    """Three-valued bitvector: each bit is ``0``, ``1``, or ``⊤`` (unknown).

    Represented as two bitmasks:
    - ``zeros``: bits known to be 0 (set = known-zero).
    - ``ones``:  bits known to be 1 (set = known-one).
    A bit unknown in both has ``zeros[i] = 0`` and ``ones[i] = 0``.
    A conflict (both set) represents ⊥.

    Parameters
    ----------
    zeros : int
        Bitmask of known-zero bits.
    ones : int
        Bitmask of known-one bits.
    width : int
        Bit width.
    """
    zeros: int
    ones: int
    width: int = 32

    @property
    def mask(self) -> int:
        return (1 << self.width) - 1

    @property
    def is_bottom(self) -> bool:
        return (self.zeros & self.ones) != 0

    @property
    def is_top(self) -> bool:
        return self.zeros == 0 and self.ones == 0

    @property
    def is_constant(self) -> bool:
        return (self.zeros | self.ones) == self.mask and not self.is_bottom

    @property
    def constant_value(self) -> Optional[int]:
        if self.is_constant:
            return self.ones
        return None


class BitfieldDomain(AbstractDomain):
    """Three-valued bitfield abstract domain.

    Tracks per-bit knowledge (``0``, ``1``, ``⊤``).  Excellent for
    bitwise operation analysis, flag checking, and alignment detection.

    Parameters
    ----------
    width : int
        Bit width (default 32).
    """

    def __init__(self, width: int = 32) -> None:
        self.width = width
        self._mask = (1 << width) - 1

    def bottom(self) -> Optional[BitfieldValue]:
        return None

    def top(self) -> BitfieldValue:
        return BitfieldValue(zeros=0, ones=0, width=self.width)

    def join(self, a, b) -> Optional[BitfieldValue]:
        if a is None:
            return b
        if b is None:
            return a
        # Join: a bit is known only if both agree
        known_zero = a.zeros & b.zeros
        known_one = a.ones & b.ones
        return BitfieldValue(known_zero, known_one, self.width)

    def leq(self, a, b) -> bool:
        if a is None:
            return True
        if b is None:
            return False
        # a ⊑ b iff a knows more than b (a's known bits are a superset)
        return ((a.zeros | a.ones) & self._mask) >= ((b.zeros | b.ones) & self._mask) and \
               (a.zeros & b.zeros) == b.zeros and \
               (a.ones & b.ones) == b.ones

    def meet(self, a, b):
        if a is None or b is None:
            return None
        known_zero = a.zeros | b.zeros
        known_one = a.ones | b.ones
        # Check for conflict
        if known_zero & known_one:
            return None
        return BitfieldValue(known_zero, known_one, self.width)

    def copy_value(self, v):
        return v  # frozen dataclass

    def abstract_const(self, value: Union[int, float]) -> BitfieldValue:
        v = int(value) & self._mask
        return BitfieldValue(
            zeros=(~v) & self._mask,
            ones=v & self._mask,
            width=self.width,
        )

    def abstract_unary(self, op: str, a) -> Optional[BitfieldValue]:
        if a is None:
            return None
        if op == "~":
            return BitfieldValue(a.ones, a.zeros, self.width)
        if op == "!":
            cv = a.constant_value
            if cv is not None:
                return self.abstract_const(0 if cv else 1)
            return self.top()
        return self.top()

    def abstract_binary(self, op: str, a, b):
        if a is None or b is None:
            return None
        if op == "&":
            # Known-zero if either is known-zero
            zeros = a.zeros | b.zeros
            # Known-one only if both are known-one
            ones = a.ones & b.ones
            return BitfieldValue(zeros & self._mask, ones & self._mask, self.width)
        if op == "|":
            zeros = a.zeros & b.zeros
            ones = a.ones | b.ones
            return BitfieldValue(zeros & self._mask, ones & self._mask, self.width)
        if op == "^":
            # XOR: known if both bits are known
            both_known = (a.zeros | a.ones) & (b.zeros | b.ones)
            result_ones = ((a.ones & b.zeros) | (a.zeros & b.ones)) & both_known
            result_zeros = ((a.ones & b.ones) | (a.zeros & b.zeros)) & both_known
            return BitfieldValue(
                result_zeros & self._mask,
                result_ones & self._mask,
                self.width,
            )
        # For arithmetic ops, fall back to constant propagation
        cv_a = a.constant_value
        cv_b = b.constant_value
        if cv_a is not None and cv_b is not None:
            if op == "+":
                return self.abstract_const(cv_a + cv_b)
            if op == "-":
                return self.abstract_const(cv_a - cv_b)
            if op == "*":
                return self.abstract_const(cv_a * cv_b)
            if op == "/" and cv_b != 0:
                return self.abstract_const(int(cv_a / cv_b))
            if op == "<<" and 0 <= cv_b < self.width:
                return self.abstract_const(cv_a << cv_b)
            if op == ">>" and 0 <= cv_b < self.width:
                return self.abstract_const(cv_a >> cv_b)
        # Shift with known shift amount
        if op == "<<":
            cv_b = b.constant_value
            if cv_b is not None and 0 <= cv_b < self.width:
                new_zeros = ((a.zeros << cv_b) | ((1 << cv_b) - 1)) & self._mask
                new_ones = (a.ones << cv_b) & self._mask
                return BitfieldValue(new_zeros, new_ones, self.width)
        if op == ">>":
            cv_b = b.constant_value
            if cv_b is not None and 0 <= cv_b < self.width:
                new_zeros = (a.zeros >> cv_b) & self._mask
                new_ones = (a.ones >> cv_b) & self._mask
                return BitfieldValue(new_zeros, new_ones, self.width)
        return self.top()

    def abstract_condition(self, op, a, b, *, true_branch=True):
        if a is None or b is None:
            return (None, None)
        if not true_branch:
            neg_op = _negate_comparison(op)
            return self.abstract_condition(neg_op, a, b, true_branch=True)
        if op == "==":
            common = self.meet(a, b)
            return (common, common)
        return (a, b)

    def gamma_str(self, a) -> str:
        if a is None:
            return "⊥"
        bits = []
        for i in range(self.width - 1, -1, -1):
            if a.ones & (1 << i):
                bits.append("1")
            elif a.zeros & (1 << i):
                bits.append("0")
            else:
                bits.append("?")
        return "".join(bits)

    def to_interval(self, a) -> Optional[Tuple[float, float]]:
        if a is None:
            return None
        cv = a.constant_value
        if cv is not None:
            return (float(cv), float(cv))
        # Conservative bounds
        lo = float(a.ones)
        hi_unknown = self._mask & ~(a.zeros | a.ones)
        hi = float(a.ones | hi_unknown)
        return (lo, hi)

    def may_be_zero(self, a) -> bool:
        if a is None:
            return False
        return a.ones == 0

    def must_be_zero(self, a) -> bool:
        if a is None:
            return False
        return a.ones == 0 and a.zeros == self._mask


# ===================================================================
# WRAPPING INTERVAL DOMAIN
# ===================================================================

@dataclass(frozen=True)
class WrappingInterval:
    """A wrapping interval ``[lo, hi]`` modulo ``2^width``.

    Unlike mathematical intervals, wrapping intervals can represent
    ranges that "wrap around" (e.g., ``[0xFFFFFFF0, 0x0F]`` for a
    near-zero unsigned range).

    Attributes
    ----------
    lo : int
        Lower bound (inclusive).
    hi : int
        Upper bound (inclusive).
    width : int
        Bit width.
    """
    lo: int
    hi: int
    width: int = 32

    @property
    def modulus(self) -> int:
        return 1 << self.width

    @property
    def wraps(self) -> bool:
        """Does this interval wrap around?"""
        return self.lo > self.hi

    @property
    def size(self) -> int:
        """Number of elements in the interval."""
        if self.lo <= self.hi:
            return self.hi - self.lo + 1
        return self.modulus - self.lo + self.hi + 1

    def contains(self, value: int) -> bool:
        v = value % self.modulus
        if self.lo <= self.hi:
            return self.lo <= v <= self.hi
        return v >= self.lo or v <= self.hi


class WrappingIntervalDomain(AbstractDomain):
    """Wrapping machine-integer interval domain.

    Models C unsigned integer arithmetic with modular wrap-around.
    Essential for detecting integer overflow/underflow.

    Parameters
    ----------
    width : int
        Bit width (default 32).
    """

    def __init__(self, width: int = 32) -> None:
        self.width = width
        self._mod = 1 << width
        self._mask = self._mod - 1

    def bottom(self) -> Optional[WrappingInterval]:
        return None

    def top(self) -> WrappingInterval:
        return WrappingInterval(0, self._mask, self.width)

    def join(self, a, b):
        if a is None:
            return b
        if b is None:
            return a
        # If either covers everything, return top
        if a.size + b.size >= self._mod:
            return self.top()
        # Try both possible merged intervals, pick smaller
        lo1 = min(a.lo, b.lo)
        hi1 = max(a.hi, b.hi)
        if lo1 <= hi1:
            size1 = hi1 - lo1 + 1
        else:
            size1 = self._mod - lo1 + hi1 + 1
        # The other direction
        lo2 = min(a.lo, b.lo) if a.wraps or b.wraps else a.lo
        hi2 = max(a.hi, b.hi) if a.wraps or b.wraps else b.hi

        # Simplification: use the hull
        if not a.wraps and not b.wraps:
            return WrappingInterval(
                min(a.lo, b.lo), max(a.hi, b.hi), self.width
            )
        return self.top()

    def leq(self, a, b) -> bool:
        if a is None:
            return True
        if b is None:
            return False
        if b.size >= self._mod:
            return True
        if not b.wraps and not a.wraps:
            return b.lo <= a.lo and a.hi <= b.hi
        if b.wraps and not a.wraps:
            return a.lo >= b.lo or a.hi <= b.hi
        if b.wraps and a.wraps:
            return a.lo >= b.lo and a.hi <= b.hi
        return False

    def meet(self, a, b):
        if a is None or b is None:
            return None
        if not a.wraps and not b.wraps:
            lo = max(a.lo, b.lo)
            hi = min(a.hi, b.hi)
            if lo > hi:
                return None
            return WrappingInterval(lo, hi, self.width)
        return a  # conservative

    def widen(self, a, b):
        if a is None:
            return b
        if b is None:
            return a
        # Simple widening: expand to full range if bounds change
        lo = a.lo if b.lo >= a.lo else 0
        hi = a.hi if b.hi <= a.hi else self._mask
        return WrappingInterval(lo, hi, self.width)

    def copy_value(self, v):
        return v

    def abstract_const(self, value: Union[int, float]) -> WrappingInterval:
        v = int(value) & self._mask
        return WrappingInterval(v, v, self.width)

    def abstract_unary(self, op: str, a):
        if a is None:
            return None
        if op == "-":
            if a.lo == a.hi:
                v = (-a.lo) & self._mask
                return WrappingInterval(v, v, self.width)
            return self.top()
        if op == "~":
            if a.lo == a.hi:
                v = (~a.lo) & self._mask
                return WrappingInterval(v, v, self.width)
            return self.top()
        return self.top()

    def abstract_binary(self, op: str, a, b):
        if a is None or b is None:
            return None
        if not a.wraps and not b.wraps:
            if op == "+":
                lo = (a.lo + b.lo) & self._mask
                hi = (a.hi + b.hi) & self._mask
                # Check for wrap
                if a.hi + b.hi >= self._mod:
                    return self.top()
                return WrappingInterval(lo, hi, self.width)
            if op == "-":
                if a.lo - b.hi >= 0:
                    lo = a.lo - b.hi
                    hi = a.hi - b.lo
                    return WrappingInterval(lo, hi, self.width)
                return self.top()
            if op == "&":
                if a.lo == a.hi and b.lo == b.hi:
                    v = a.lo & b.lo
                    return WrappingInterval(v, v, self.width)
                return WrappingInterval(0, min(a.hi, b.hi), self.width)
            if op == "|":
                if a.lo == a.hi and b.lo == b.hi:
                    v = a.lo | b.lo
                    return WrappingInterval(v, v, self.width)
                return self.top()
        # Constant folding fallback
        if a.lo == a.hi and b.lo == b.hi:
            return self._const_fold(op, a.lo, b.lo)
        return self.top()

    def _const_fold(self, op: str, a: int, b: int) -> WrappingInterval:
        ops = {
            "+": lambda: (a + b) & self._mask,
            "-": lambda: (a - b) & self._mask,
            "*": lambda: (a * b) & self._mask,
            "/": lambda: (a // b) & self._mask if b != 0 else 0,
            "%": lambda: (a % b) & self._mask if b != 0 else 0,
            "&": lambda: a & b,
            "|": lambda: a | b,
            "^": lambda: a ^ b,
            "<<": lambda: (a << b) & self._mask if 0 <= b < self.width else 0,
            ">>": lambda: (a >> b) & self._mask if 0 <= b < self.width else 0,
        }
        fn = ops.get(op)
        if fn:
            try:
                v = fn()
                return WrappingInterval(v, v, self.width)
            except (ZeroDivisionError, OverflowError):
                pass
        return self.top()

    def abstract_condition(self, op, a, b, *, true_branch=True):
        if a is None or b is None:
            return (None, None)
        if not true_branch:
            neg_op = _negate_comparison(op)
            return self.abstract_condition(neg_op, a, b, true_branch=True)
        if op == "==" and not a.wraps and not b.wraps:
            common = self.meet(a, b)
            return (common, common)
        return (a, b)

    def gamma_str(self, a) -> str:
        if a is None:
            return "⊥"
        if a.lo == a.hi:
            return f"0x{a.lo:X}"
        return f"[0x{a.lo:X}, 0x{a.hi:X}]"

    def to_interval(self, a) -> Optional[Tuple[float, float]]:
        if a is None:
            return None
        if a.wraps:
            return (0.0, float(self._mask))
        return (float(a.lo), float(a.hi))


# ===================================================================
# REDUCED PRODUCT DOMAIN
# ===================================================================

class ReducedProductDomain(AbstractDomain):
    """Reduced product of multiple abstract domains.

    Combines ``n`` abstract domains and applies *reduction* to improve
    precision: information from one domain constrains the others.

    For example, combining :class:`IntervalDomain` with
    :class:`CongruenceDomain` yields interval-congruence:
    knowing ``x ∈ [0, 10]`` and ``x ≡ 1 (mod 4)`` gives ``x ∈ {1, 5, 9}``.

    Parameters
    ----------
    *domains : AbstractDomain
        The component domains.
    reduce : bool
        Whether to apply inter-domain reduction after each operation.
    """

    def __init__(self, *domains: AbstractDomain, reduce: bool = True) -> None:
        self.domains: Tuple[AbstractDomain, ...] = domains
        self._reduce = reduce
        self._n = len(domains)

    def bottom(self) -> Optional[Tuple]:
        return None

    def top(self) -> Tuple:
        return tuple(d.top() for d in self.domains)

    def join(self, a, b) -> Optional[Tuple]:
        if a is None:
            return b
        if b is None:
            return a
        result = tuple(
            d.join(av, bv) for d, av, bv in zip(self.domains, a, b)
        )
        return self._apply_reduction(result)

    def leq(self, a, b) -> bool:
        if a is None:
            return True
        if b is None:
            return False
        return all(
            d.leq(av, bv) for d, av, bv in zip(self.domains, a, b)
        )

    def meet(self, a, b):
        if a is None or b is None:
            return None
        result = []
        for d, av, bv in zip(self.domains, a, b):
            m = d.meet(av, bv)
            if d.is_bottom(m) if hasattr(m, '__eq__') else m is None:
                return None
            result.append(m)
        return self._apply_reduction(tuple(result))

    def widen(self, a, b):
        if a is None:
            return b
        if b is None:
            return a
        return tuple(
            d.widen(av, bv) for d, av, bv in zip(self.domains, a, b)
        )

    def narrow(self, a, b):
        if a is None:
            return None
        if b is None:
            return a
        return tuple(
            d.narrow(av, bv) for d, av, bv in zip(self.domains, a, b)
        )

    def copy_value(self, v):
        if v is None:
            return None
        return tuple(d.copy_value(val) for d, val in zip(self.domains, v))

    def abstract_const(self, value):
        result = tuple(d.abstract_const(value) for d in self.domains)
        return self._apply_reduction(result)

    def abstract_unary(self, op, a):
        if a is None:
            return None
        result = tuple(
            d.abstract_unary(op, av) for d, av in zip(self.domains, a)
        )
        return self._apply_reduction(result)

    def abstract_binary(self, op, a, b):
        if a is None or b is None:
            return None
        result = tuple(
            d.abstract_binary(op, av, bv)
            for d, av, bv in zip(self.domains, a, b)
        )
        return self._apply_reduction(result)

    def abstract_condition(self, op, a, b, *, true_branch=True):
        if a is None or b is None:
            return (None, None)
        a_news = []
        b_news = []
        for i, d in enumerate(self.domains):
            a_new, b_new = d.abstract_condition(
                op, a[i], b[i], true_branch=true_branch
            )
            a_news.append(a_new)
            b_news.append(b_new)
        a_result = self._apply_reduction(tuple(a_news))
        b_result = self._apply_reduction(tuple(b_news))
        return (a_result, b_result)

    def abstract_cast(self, a, from_type, to_type):
        if a is None:
            return None
        return tuple(
            d.abstract_cast(av, from_type, to_type)
            for d, av in zip(self.domains, a)
        )

    def gamma_str(self, a) -> str:
        if a is None:
            return "⊥"
        parts = [d.gamma_str(av) for d, av in zip(self.domains, a)]
        return " ∧ ".join(parts)

    def to_interval(self, a):
        if a is None:
            return None
        best = None
        for d, av in zip(self.domains, a):
            iv = d.to_interval(av)
            if iv is not None:
                if best is None:
                    best = iv
                else:
                    best = (max(best[0], iv[0]), min(best[1], iv[1]))
                    if best[0] > best[1]:
                        return None
        return best

    def may_be_zero(self, a) -> bool:
        if a is None:
            return False
        return all(d.may_be_zero(av) for d, av in zip(self.domains, a))

    def must_be_zero(self, a) -> bool:
        if a is None:
            return False
        return any(d.must_be_zero(av) for d, av in zip(self.domains, a))

    def _apply_reduction(self, values: Optional[Tuple]) -> Optional[Tuple]:
        """Apply inter-domain reduction to tighten component values."""
        if values is None or not self._reduce:
            return values

        # Check if any component is bottom
        for d, v in zip(self.domains, values):
            if v is None or (hasattr(d, 'is_bottom') and d.is_bottom(v)):
                return None

        # Interval-Congruence reduction
        result = list(values)
        for i, di in enumerate(self.domains):
            for j, dj in enumerate(self.domains):
                if i == j:
                    continue
                iv = di.to_interval(result[i])
                if iv is None:
                    continue
                # Propagate interval info to other domain
                jv = dj.to_interval(result[j])
                if jv is not None:
                    # Tighten interval via meet
                    common = (max(iv[0], jv[0]), min(iv[1], jv[1]))
                    if common[0] > common[1]:
                        return None

        return tuple(result)


# ===================================================================
# APRON DOMAIN WRAPPER
# ===================================================================

class APRONDomain(AbstractDomain):
    """Wrapper for the APRON numerical abstract domain library.

    APRON provides high-precision relational domains:

    - **Box** (intervals) — same as IntervalDomain but via APRON.
    - **Octagon** — tracks constraints ``±x ± y ≤ c``.
    - **Polka** (convex polyhedra) — tracks ``a₁x₁ + ... + aₙxₙ ≤ c``.
    - **Taylor1+** — linearisation-based floating-point domain.

    Requires the ``pyapron`` package (optional dependency).  Falls back
    to :class:`IntervalDomain` if APRON is not installed.

    Parameters
    ----------
    manager_type : str
        One of ``'box'``, ``'oct'``, ``'polka_strict'``, ``'polka_loose'``,
        ``'polka_equalities'``, ``'taylor1p'``.
    variables : list of str
        Variable names in scope.
    int_dims : int, optional
        Number of integer dimensions (default: all).
    real_dims : int, optional
        Number of real dimensions (default: 0).
    """

    def __init__(
        self,
        manager_type: str = "oct",
        variables: Optional[List[str]] = None,
        int_dims: Optional[int] = None,
        real_dims: int = 0,
    ) -> None:
        self.manager_type = manager_type
        self._variables = variables or []
        self._var_to_dim: Dict[str, int] = {
            v: i for i, v in enumerate(self._variables)
        }
        self._int_dims = int_dims if int_dims is not None else len(self._variables)
        self._real_dims = real_dims
        self._apron = None
        self._manager = None

        try:
            import pyapron  # type: ignore
            self._apron = pyapron
            self._manager = self._create_manager(manager_type)
        except ImportError:
            warnings.warn(
                "pyapron not installed; APRONDomain will use interval fallback",
                stacklevel=2,
            )
            self._fallback = IntervalDomain(bit_width=64, signed=True)

    def _create_manager(self, manager_type: str):
        """Create the APRON manager of the requested type."""
        ap = self._apron
        if manager_type == "box":
            return ap.BoxManager()
        if manager_type == "oct":
            return ap.OctagonManager()
        if manager_type in ("polka_strict", "polka_loose", "polka_equalities"):
            strict = manager_type == "polka_strict"
            return ap.PolkaManager(strict=strict)
        raise ValueError(f"Unknown APRON manager type: {manager_type}")

    @property
    def _has_apron(self) -> bool:
        return self._apron is not None and self._manager is not None

    # ---- Lattice operations ------------------------------------------------

    def bottom(self):
        if self._has_apron:
            ap = self._apron
            return ap.Abstract1.bottom(
                self._manager,
                ap.Environment(
                    [ap.Var(v) for v in self._variables], []
                ),
            )
        return self._fallback.bottom()

    def top(self):
        if self._has_apron:
            ap = self._apron
            return ap.Abstract1.top(
                self._manager,
                ap.Environment(
                    [ap.Var(v) for v in self._variables], []
                ),
            )
        return self._fallback.top()

    def join(self, a, b):
        if self._has_apron:
            return a.join(self._manager, b)
        return self._fallback.join(a, b)

    def leq(self, a, b) -> bool:
        if self._has_apron:
            return a.is_leq(self._manager, b)
        return self._fallback.leq(a, b)

    def meet(self, a, b):
        if self._has_apron:
            return a.meet(self._manager, b)
        return self._fallback.meet(a, b)

    def widen(self, a, b):
        if self._has_apron:
            return a.widening(self._manager, b)
        return self._fallback.widen(a, b)

    def narrow(self, a, b):
        if self._has_apron:
            # APRON doesn't have built-in narrowing; use meet as approximation
            return a.meet(self._manager, b)
        return self._fallback.narrow(a, b)

    def copy_value(self, v):
        if self._has_apron:
            return v.copy(self._manager)
        return self._fallback.copy_value(v)

    # ---- Abstract semantics ------------------------------------------------

    def abstract_const(self, value):
        if not self._has_apron:
            return self._fallback.abstract_const(value)
        # Return a constant as interval [v, v] for all variables — not useful
        # on its own; typically used via assign_variable
        return self.top()

    def abstract_unary(self, op, a):
        if not self._has_apron:
            return self._fallback.abstract_unary(op, a)
        return a  # Conservative

    def abstract_binary(self, op, a, b):
        if not self._has_apron:
            return self._fallback.abstract_binary(op, a, b)
        return self.join(a, b)  # Conservative

    def abstract_condition(self, op, a, b, *, true_branch=True):
        if not self._has_apron:
            return self._fallback.abstract_condition(
                op, a, b, true_branch=true_branch
            )
        return (a, b)

    # ---- APRON-specific helpers --------------------------------------------

    def assign_variable(self, state, var_name: str, expr_str: str):
        """Assign an APRON expression to a variable in the abstract state.

        Parameters
        ----------
        state : APRON Abstract1
        var_name : str
        expr_str : str
            A linear expression string (e.g., ``"2*x + 3"``).

        Returns
        -------
        APRON Abstract1
        """
        if not self._has_apron:
            return state
        ap = self._apron
        var = ap.Var(var_name)
        try:
            expr = ap.Texpr1.from_string(state.environment, expr_str)
            return state.assign(self._manager, var, expr)
        except Exception:
            return state  # Conservative

    def add_constraint(self, state, constraint_str: str):
        """Add a linear constraint to the abstract state.

        Parameters
        ----------
        state : APRON Abstract1
        constraint_str : str
            E.g., ``"x - y >= 0"``.
        """
        if not self._has_apron:
            return state
        ap = self._apron
        try:
            cons = ap.Tcons1.from_string(state.environment, constraint_str)
            array = ap.Tcons1Array([cons])
            return state.meet_tcons_array(self._manager, array)
        except Exception:
            return state

    def get_variable_bounds(
        self, state, var_name: str
    ) -> Optional[Tuple[float, float]]:
        """Extract interval bounds for a variable from the abstract state."""
        if not self._has_apron:
            return self._fallback.to_interval(state)
        ap = self._apron
        try:
            var = ap.Var(var_name)
            interval = state.bound_variable(self._manager, var)
            lo = interval.inf.to_float() if interval.inf.is_finite() else NEG_INF
            hi = interval.sup.to_float() if interval.sup.is_finite() else POS_INF
            return (lo, hi)
        except Exception:
            return None

    def gamma_str(self, a) -> str:
        if not self._has_apron:
            return self._fallback.gamma_str(a)
        try:
            return str(a)
        except Exception:
            return "<?>"

    def to_interval(self, a):
        if not self._has_apron:
            return self._fallback.to_interval(a)
        return None  # relational domain; per-variable bounds via get_variable_bounds


# ===================================================================
# ABSTRACT STATE
# ===================================================================

class AbstractState:
    """Abstract state: a map from variable identifiers to abstract values.

    This is the per-program-point abstract store used during
    abstract interpretation.

    Parameters
    ----------
    domain : AbstractDomain
        The abstract domain for variable values.
    values : dict, optional
        Initial variable → abstract-value mapping.
    """

    __slots__ = ("domain", "_values")

    def __init__(
        self,
        domain: AbstractDomain,
        values: Optional[Dict[VarId, AbsVal]] = None,
    ) -> None:
        self.domain = domain
        self._values: Dict[VarId, AbsVal] = dict(values) if values else {}

    def get(self, var: VarId) -> AbsVal:
        """Get the abstract value of a variable (⊤ if unknown)."""
        return self._values.get(var, self.domain.top())

    def set(self, var: VarId, value: AbsVal) -> "AbstractState":
        """Return a new state with ``var`` mapped to ``value``."""
        new_vals = dict(self._values)
        new_vals[var] = value
        return AbstractState(self.domain, new_vals)

    def remove(self, var: VarId) -> "AbstractState":
        """Return a new state without ``var``."""
        new_vals = dict(self._values)
        new_vals.pop(var, None)
        return AbstractState(self.domain, new_vals)

    def variables(self) -> Set[VarId]:
        """Return the set of variables with non-⊤ values."""
        return set(self._values.keys())

    def items(self) -> Iterable[Tuple[VarId, AbsVal]]:
        return self._values.items()

    def copy(self) -> "AbstractState":
        return AbstractState(
            self.domain,
            {k: self.domain.copy_value(v) for k, v in self._values.items()},
        )

    def __repr__(self) -> str:
        parts = [
            f"{var}: {self.domain.gamma_str(val)}"
            for var, val in sorted(self._values.items())
        ]
        return "{" + ", ".join(parts) + "}"

    def __eq__(self, other) -> bool:
        if not isinstance(other, AbstractState):
            return NotImplemented
        if self.domain is not other.domain:
            return False
        all_vars = self.variables() | other.variables()
        for v in all_vars:
            if not self.domain.eq(self.get(v), other.get(v)):
                return False
        return True


# ===================================================================
# ABSTRACT STATE LATTICE
# ===================================================================

class AbstractStateLattice(dfe.Lattice):
    """Lattice over :class:`AbstractState` values.

    Wraps a :class:`dfe.MapLattice` but returns :class:`AbstractState`
    objects for ergonomic use.
    """

    def __init__(self, domain: AbstractDomain) -> None:
        self.domain = domain

    def bottom(self) -> AbstractState:
        return AbstractState(self.domain)

    def top(self) -> AbstractState:
        # Top state has all variables at ⊤ — represented as empty map
        # (since get() returns ⊤ for missing keys)
        return AbstractState(self.domain)

    def join(self, a: AbstractState, b: AbstractState) -> AbstractState:
        d = self.domain
        all_vars = a.variables() | b.variables()
        new_vals = {}
        for v in all_vars:
            new_vals[v] = d.join(a.get(v), b.get(v))
        return AbstractState(d, new_vals)

    def leq(self, a: AbstractState, b: AbstractState) -> bool:
        d = self.domain
        for v in a.variables():
            if not d.leq(a.get(v), b.get(v)):
                return False
        return True

    def meet(self, a: AbstractState, b: AbstractState) -> AbstractState:
        d = self.domain
        all_vars = a.variables() | b.variables()
        new_vals = {}
        for v in all_vars:
            m = d.meet(a.get(v), b.get(v))
            new_vals[v] = m
        return AbstractState(d, new_vals)

    def widen(self, a: AbstractState, b: AbstractState) -> AbstractState:
        d = self.domain
        all_vars = a.variables() | b.variables()
        new_vals = {}
        for v in all_vars:
            new_vals[v] = d.widen(a.get(v), b.get(v))
        return AbstractState(d, new_vals)

    def narrow(self, a: AbstractState, b: AbstractState) -> AbstractState:
        d = self.domain
        all_vars = a.variables() | b.variables()
        new_vals = {}
        for v in all_vars:
            new_vals[v] = d.narrow(a.get(v), b.get(v))
        return AbstractState(d, new_vals)

    def eq(self, a: AbstractState, b: AbstractState) -> bool:
        return a == b

    def copy_value(self, v: AbstractState) -> AbstractState:
        return v.copy()


# ===================================================================
# C EXPRESSION EVALUATOR
# ===================================================================

class CExpressionEvaluator:
    """Evaluates Cppcheck AST expressions in an abstract domain.

    Recursively walks the token's AST (``astOperand1``, ``astOperand2``)
    and interprets operations abstractly.

    Parameters
    ----------
    domain : AbstractDomain
        The abstract domain.
    state : AbstractState
        The current abstract state (variable → abstract value).
    """

    def __init__(self, domain: AbstractDomain, state: AbstractState) -> None:
        self.domain = domain
        self.state = state

    def evaluate(self, token) -> AbsVal:
        """Evaluate a token expression, returning an abstract value.

        Parameters
        ----------
        token : cppcheckdata.Token

        Returns
        -------
        AbsVal
        """
        if token is None:
            return self.domain.top()

        # Literal integer
        if getattr(token, "isNumber", False):
            try:
                val_str = token.str
                if val_str.startswith("0x") or val_str.startswith("0X"):
                    return self.domain.abstract_const(int(val_str, 16))
                if val_str.startswith("0b") or val_str.startswith("0B"):
                    return self.domain.abstract_const(int(val_str, 2))
                if val_str.startswith("0") and len(val_str) > 1 and val_str.isdigit():
                    return self.domain.abstract_const(int(val_str, 8))
                # Strip suffixes (U, L, LL, etc.)
                cleaned = val_str.rstrip("uUlLfF")
                if "." in cleaned or "e" in cleaned or "E" in cleaned:
                    return self.domain.abstract_const(float(cleaned))
                return self.domain.abstract_const(int(cleaned))
            except (ValueError, OverflowError):
                return self.domain.top()

        # Character literal
        if token.str.startswith("'") and token.str.endswith("'"):
            try:
                if len(token.str) == 3:
                    return self.domain.abstract_const(ord(token.str[1]))
                return self.domain.top()
            except Exception:
                return self.domain.top()

        # Variable reference
        if getattr(token, "isName", False):
            var = getattr(token, "variable", None)
            if var is not None:
                var_id = _variable_id(token)
                return self.state.get(var_id)
            # Enum constant
            enum_val = getattr(token, "values", None)
            if enum_val:
                for v in enum_val:
                    if getattr(v, "valueKind", "") == "known":
                        try:
                            return self.domain.abstract_const(int(v.intvalue))
                        except (ValueError, AttributeError):
                            pass
            # Function name or unknown — return ⊤
            return self.domain.top()

        # Unary operators
        op1 = getattr(token, "astOperand1", None)
        op2 = getattr(token, "astOperand2", None)

        if op1 is not None and op2 is None:
            # Unary
            val = self.evaluate(op1)
            if token.str in ("-", "~", "!", "++", "--"):
                return self.domain.abstract_unary(token.str, val)
            if token.str == "*":
                # Pointer dereference — return ⊤
                return self.domain.top()
            if token.str == "&":
                # Address-of — return ⊤ (pointer value)
                return self.domain.top()
            if token.str == "sizeof":
                # sizeof evaluates to a constant; try Cppcheck values
                values = getattr(token, "values", [])
                for v in (values or []):
                    if hasattr(v, "intvalue"):
                        try:
                            return self.domain.abstract_const(int(v.intvalue))
                        except (ValueError, AttributeError):
                            pass
                return self.domain.top()
            # Cast: (type)expr
            if token.str == "(":
                return self.evaluate(op1)
            return self.domain.top()

        # Binary operators
        if op1 is not None and op2 is not None:
            val1 = self.evaluate(op1)
            val2 = self.evaluate(op2)

            if token.str in ("+", "-", "*", "/", "%",
                             "<<", ">>", "&", "|", "^",
                             "&&", "||"):
                return self.domain.abstract_binary(token.str, val1, val2)

            # Comparison operators → {0, 1}
            if token.str in ("<", "<=", ">", ">=", "==", "!="):
                # Conservative: result is 0 or 1
                return self.domain.join(
                    self.domain.abstract_const(0),
                    self.domain.abstract_const(1),
                )

            # Comma operator
            if token.str == ",":
                return val2

            # Assignment operators (return the assigned value)
            if token.str == "=":
                return val2
            if token.str in ("+=", "-=", "*=", "/=", "%=",
                             "<<=", ">>=", "&=", "|=", "^="):
                base_op = token.str[:-1]
                return self.domain.abstract_binary(base_op, val1, val2)

            # Array subscript
            if token.str == "[":
                return self.domain.top()

            # Member access
            if token.str in (".", "->"):
                return self.domain.top()

            # Ternary (handled via astOperand1 = condition, astOperand2 = ':')
            if token.str == "?":
                # op2 is the ':' operator with true/false branches
                colon = op2
                if colon is not None and getattr(colon, "str", "") == ":":
                    true_val = self.evaluate(getattr(colon, "astOperand1", None))
                    false_val = self.evaluate(getattr(colon, "astOperand2", None))
                    return self.domain.join(true_val, false_val)
                return self.domain.top()

        # Function call — return ⊤
        if token.str == "(" and op1 is not None:
            return self.domain.top()

        # Fallback
        return self.domain.top()


# ===================================================================
# C TRANSFER FUNCTION
# ===================================================================

class CTransferFunction:
    """Abstract transfer function for C statements.

    Interprets the tokens within a CFG basic block, updating the
    abstract state according to the abstract semantics.

    Parameters
    ----------
    domain : AbstractDomain
        The abstract domain.
    function_summaries : dict, optional
        Map from function name to callable ``(AbstractState, args) → AbsVal``,
        providing summaries for called functions.
    handle_pointers : bool
        Whether to attempt simple pointer tracking (default: False).
    """

    def __init__(
        self,
        domain: AbstractDomain,
        function_summaries: Optional[Dict[str, Callable]] = None,
        handle_pointers: bool = False,
    ) -> None:
        self.domain = domain
        self.function_summaries = function_summaries or {}
        self.handle_pointers = handle_pointers

    def __call__(self, node, state_in: AbstractState) -> AbstractState:
        """Apply the transfer function to a CFG node.

        Parameters
        ----------
        node : CFGNode
            The basic block.
        state_in : AbstractState
            The incoming abstract state.

        Returns
        -------
        AbstractState
            The outgoing abstract state.
        """
        state = state_in.copy()

        tokens = getattr(node, "tokens", [])
        for tok in tokens:
            state = self._process_token(tok, state)

        return state

    def _process_token(self, tok, state: AbstractState) -> AbstractState:
        """Process a single token, looking for state-changing operations."""
        # Simple assignment: x = expr
        if tok.str == "=" and not getattr(tok, "isComparisonOp", False):
            return self._process_assignment(tok, state)

        # Compound assignment: x += expr, etc.
        if tok.str in ("+=", "-=", "*=", "/=", "%=",
                        "<<=", ">>=", "&=", "|=", "^="):
            return self._process_compound_assignment(tok, state)

        # Increment/decrement
        if tok.str in ("++", "--"):
            return self._process_incdec(tok, state)

        # Function call at statement level (may have side effects)
        if tok.str == "(" and getattr(tok, "astOperand1", None) is not None:
            return self._process_call(tok, state)

        return state

    def _process_assignment(self, tok, state: AbstractState) -> AbstractState:
        """Handle ``lhs = rhs``."""
        lhs = getattr(tok, "astOperand1", None)
        rhs = getattr(tok, "astOperand2", None)

        if lhs is None or rhs is None:
            return state

        # Evaluate RHS
        evaluator = CExpressionEvaluator(self.domain, state)
        rhs_val = evaluator.evaluate(rhs)

        # Apply type cast if types differ
        lhs_type = infer_ctype(lhs)
        rhs_type = infer_ctype(rhs)
        if lhs_type != rhs_type:
            rhs_val = self.domain.abstract_cast(rhs_val, rhs_type, lhs_type)

        # Determine LHS variable
        if getattr(lhs, "isName", False) and getattr(lhs, "variable", None):
            var_id = _variable_id(lhs)
            state = state.set(var_id, rhs_val)
        elif lhs.str == "*" and self.handle_pointers:
            # Pointer dereference on LHS — conservative: could affect anything
            pass
        elif lhs.str == "[":
            # Array element assignment — conservative
            pass
        elif lhs.str in (".", "->"):
            # Struct member — conservative
            pass

        return state

    def _process_compound_assignment(
        self, tok, state: AbstractState
    ) -> AbstractState:
        """Handle ``lhs op= rhs``."""
        lhs = getattr(tok, "astOperand1", None)
        rhs = getattr(tok, "astOperand2", None)

        if lhs is None or rhs is None:
            return state

        evaluator = CExpressionEvaluator(self.domain, state)
        lhs_val = evaluator.evaluate(lhs)
        rhs_val = evaluator.evaluate(rhs)
        base_op = tok.str[:-1]  # e.g., "+=" → "+"
        result_val = self.domain.abstract_binary(base_op, lhs_val, rhs_val)

        if getattr(lhs, "isName", False) and getattr(lhs, "variable", None):
            var_id = _variable_id(lhs)
            state = state.set(var_id, result_val)

        return state

    def _process_incdec(self, tok, state: AbstractState) -> AbstractState:
        """Handle ``x++``, ``x--``, ``++x``, ``--x``."""
        operand = getattr(tok, "astOperand1", None)
        if operand is None:
            return state

        if getattr(operand, "isName", False) and getattr(operand, "variable", None):
            var_id = _variable_id(operand)
            evaluator = CExpressionEvaluator(self.domain, state)
            old_val = evaluator.evaluate(operand)
            new_val = self.domain.abstract_unary(tok.str, old_val)
            state = state.set(var_id, new_val)

        return state

    def _process_call(self, tok, state: AbstractState) -> AbstractState:
        """Handle function calls (at statement level for side effects)."""
        callee_tok = getattr(tok, "astOperand1", None)
        if callee_tok is None:
            return state

        func_name = getattr(callee_tok, "str", "")

        # Check if we have a summary
        if func_name in self.function_summaries:
            # Collect arguments
            args_tok = getattr(tok, "astOperand2", None)
            args = self._collect_call_args(args_tok, state)
            summary = self.function_summaries[func_name]
            try:
                return summary(state, args)
            except Exception:
                pass

        # Conservative: invalidate all global/pointed-to variables
        # For now, keep state unchanged (optimistic)
        return state

    def _collect_call_args(
        self, tok, state: AbstractState
    ) -> List[AbsVal]:
        """Collect argument abstract values from a call."""
        if tok is None:
            return []
        evaluator = CExpressionEvaluator(self.domain, state)
        args = []
        self._flatten_comma(tok, args)
        return [evaluator.evaluate(a) for a in args]

    def _flatten_comma(self, tok, result: List) -> None:
        """Flatten comma-separated argument tokens."""
        if tok is None:
            return
        if tok.str == ",":
            self._flatten_comma(getattr(tok, "astOperand1", None), result)
            self._flatten_comma(getattr(tok, "astOperand2", None), result)
        else:
            result.append(tok)


# ===================================================================
# CONDITION REFINER
# ===================================================================

class ConditionRefiner:
    """Refines abstract states along branch edges.

    When a CFG edge is a ``BRANCH_TRUE`` or ``BRANCH_FALSE`` edge,
    the condition refiner examines the branch condition and tightens
    the abstract state accordingly.

    Parameters
    ----------
    domain : AbstractDomain
        The abstract domain.
    """

    def __init__(self, domain: AbstractDomain) -> None:
        self.domain = domain

    def refine(
        self,
        edge,
        state: AbstractState,
    ) -> AbstractState:
        """Refine the abstract state along a branch edge.

        Parameters
        ----------
        edge : CFGEdge
            The CFG edge (from :mod:`controlflow_graph`).
        state : AbstractState
            The abstract state at the edge's source node.

        Returns
        -------
        AbstractState
            The refined state at the edge's target node.
        """
        edge_type = getattr(edge, "type", None) or getattr(edge, "edge_type", None)
        if edge_type is None:
            return state

        edge_type_str = str(edge_type)
        if "TRUE" in edge_type_str.upper():
            true_branch = True
        elif "FALSE" in edge_type_str.upper():
            true_branch = False
        else:
            return state

        # Get the condition token
        condition = getattr(edge, "condition", None)
        if condition is None:
            # Try to get from source node
            source = getattr(edge, "source", None) or getattr(edge, "src", None)
            if source is not None:
                condition = getattr(source, "condition", None)

        if condition is None:
            return state

        return self._refine_condition(condition, state, true_branch)

    def _refine_condition(
        self, tok, state: AbstractState, true_branch: bool
    ) -> AbstractState:
        """Refine state based on a condition token."""
        if tok is None:
            return state

        # Comparison: x < 5, x == y, etc.
        if tok.str in ("<", "<=", ">", ">=", "==", "!="):
            return self._refine_comparison(tok, state, true_branch)

        # Logical NOT: !expr
        if tok.str == "!" and getattr(tok, "astOperand2", None) is None:
            op1 = getattr(tok, "astOperand1", None)
            return self._refine_condition(op1, state, not true_branch)

        # Logical AND: a && b
        if tok.str == "&&":
            if true_branch:
                # Both must be true
                op1 = getattr(tok, "astOperand1", None)
                op2 = getattr(tok, "astOperand2", None)
                state = self._refine_condition(op1, state, True)
                state = self._refine_condition(op2, state, True)
                return state
            else:
                # At least one is false — conservative: no refinement
                return state

        # Logical OR: a || b
        if tok.str == "||":
            if true_branch:
                # At least one is true — conservative: no refinement
                return state
            else:
                # Both must be false
                op1 = getattr(tok, "astOperand1", None)
                op2 = getattr(tok, "astOperand2", None)
                state = self._refine_condition(op1, state, False)
                state = self._refine_condition(op2, state, False)
                return state

        # Variable used as truth value: if (x) ≡ if (x != 0)
        if getattr(tok, "isName", False) and getattr(tok, "variable", None):
            var_id = _variable_id(tok)
            var_val = state.get(var_id)
            if true_branch:
                # x != 0
                zero = self.domain.abstract_const(0)
                refined, _ = self.domain.abstract_condition(
                    "!=", var_val, zero, true_branch=True
                )
            else:
                # x == 0
                refined = self.domain.abstract_const(0)
            if refined is not None:
                state = state.set(var_id, refined)

        return state

    def _refine_comparison(
        self, tok, state: AbstractState, true_branch: bool
    ) -> AbstractState:
        """Refine state for a comparison ``lhs op rhs``."""
        lhs = getattr(tok, "astOperand1", None)
        rhs = getattr(tok, "astOperand2", None)
        if lhs is None or rhs is None:
            return state

        evaluator = CExpressionEvaluator(self.domain, state)
        lhs_val = evaluator.evaluate(lhs)
        rhs_val = evaluator.evaluate(rhs)

        # Apply domain's condition refinement
        lhs_refined, rhs_refined = self.domain.abstract_condition(
            tok.str, lhs_val, rhs_val, true_branch=true_branch,
        )

        # Write back refined values to variables
        if getattr(lhs, "isName", False) and getattr(lhs, "variable", None):
            if lhs_refined is not None:
                state = state.set(_variable_id(lhs), lhs_refined)
            else:
                # Bottom — this branch is infeasible
                state = state.set(_variable_id(lhs), self.domain.bottom())

        if getattr(rhs, "isName", False) and getattr(rhs, "variable", None):
            if rhs_refined is not None:
                state = state.set(_variable_id(rhs), rhs_refined)
            else:
                state = state.set(_variable_id(rhs), self.domain.bottom())

        return state


# ===================================================================
# ABSTRACT INTERPRETER — MAIN DRIVER
# ===================================================================

@dataclass
class InterpretationResult:
    """Results of abstract interpretation.

    Attributes
    ----------
    node_states_in : dict
        Map from CFG node → AbstractState before the node.
    node_states_out : dict
        Map from CFG node → AbstractState after the node.
    dataflow_result : DataflowResult
        The underlying dataflow engine result.
    warnings : list
        Analysis warnings (potential bugs found).
    domain : AbstractDomain
        The domain used.
    """
    node_states_in: Dict[Any, AbstractState] = field(default_factory=dict)
    node_states_out: Dict[Any, AbstractState] = field(default_factory=dict)
    dataflow_result: Optional[dfe.DataflowResult] = None
    warnings: List["AnalysisWarning"] = field(default_factory=list)
    domain: Optional[AbstractDomain] = None

    @property
    def node_states(self) -> Dict[Any, AbstractState]:
        """Alias for node_states_out (the state after each node)."""
        return self.node_states_out


@dataclass
class AnalysisWarning:
    """A warning generated by abstract interpretation.

    Attributes
    ----------
    kind : str
        Warning kind (e.g., ``"division_by_zero"``, ``"overflow"``,
        ``"null_deref"``, ``"array_oob"``).
    message : str
        Human-readable message.
    token : any
        The Cppcheck token at the warning location.
    line : int
        Source line number.
    file : str
        Source file.
    state : AbstractState
        The abstract state at the warning point.
    severity : str
        Severity level: ``"error"``, ``"warning"``, ``"style"``.
    """
    kind: str = ""
    message: str = ""
    token: Any = None
    line: int = 0
    file: str = ""
    state: Optional[AbstractState] = None
    severity: str = "warning"


class AbstractInterpreter:
    """Main abstract interpretation driver.

    Orchestrates the analysis of a function or whole program by
    connecting the abstract domain, transfer function, condition
    refiner, and dataflow engine.

    Parameters
    ----------
    domain : AbstractDomain
        The abstract domain.
    cfg : CFG
        The control-flow graph.
    function_summaries : dict, optional
        Summaries for called functions.
    use_widening : bool
        Enable widening at loop heads.
    widening_delay : int
        Iterations before widening.
    use_narrowing : bool
        Perform a narrowing pass after widening fixpoint.
    narrowing_iterations : int
        Maximum narrowing iterations.
    check_division_by_zero : bool
        Report potential division by zero.
    check_overflow : bool
        Report potential integer overflow.
    check_null_deref : bool
        Report potential null pointer dereference.
    max_iterations : int
        Maximum fixpoint iterations.
    handle_pointers : bool
        Enable simple pointer tracking.
    strategy : WorklistStrategy
        Dataflow worklist strategy.
    """

    def __init__(
        self,
        domain: AbstractDomain,
        cfg,
        function_summaries: Optional[Dict[str, Callable]] = None,
        use_widening: bool = True,
        widening_delay: int = 3,
        use_narrowing: bool = True,
        narrowing_iterations: int = 5,
        check_division_by_zero: bool = True,
        check_overflow: bool = False,
        check_null_deref: bool = False,
        max_iterations: int = 100_000,
        handle_pointers: bool = False,
        strategy: dfe.WorklistStrategy = dfe.WorklistStrategy.RPO,
    ) -> None:
        self.domain = domain
        self.cfg = cfg
        self.function_summaries = function_summaries or {}
        self.use_widening = use_widening
        self.widening_delay = widening_delay
        self.use_narrowing = use_narrowing
        self.narrowing_iterations = narrowing_iterations
        self.check_division_by_zero = check_division_by_zero
        self.check_overflow = check_overflow
        self.check_null_deref = check_null_deref
        self.max_iterations = max_iterations
        self.handle_pointers = handle_pointers
        self.strategy = strategy

        # Build components
        self._transfer = CTransferFunction(
            domain, function_summaries, handle_pointers
        )
        self._refiner = ConditionRefiner(domain)
        self._lattice = AbstractStateLattice(domain)
        self._warnings: List[AnalysisWarning] = []

    def run(self) -> InterpretationResult:
        """Run abstract interpretation to fixpoint.

        Returns
        -------
        InterpretationResult
        """
        initial = self._build_initial_state()

        # Edge transfer for branch condition refinement
        def edge_transfer(edge, state: AbstractState) -> AbstractState:
            return self._refiner.refine(edge, state)

        # Run the dataflow engine
        df_result = dfe.run_forward_analysis(
            self.cfg,
            self._lattice,
            self._transfer_with_checks,
            initial_value=initial,
            edge_transfer=edge_transfer,
            strategy=self.strategy,
            use_widening=self.use_widening,
            widening_delay=self.widening_delay,
            max_iterations=self.max_iterations,
            use_narrowing=self.use_narrowing,
            narrowing_iterations=self.narrowing_iterations,
        )

        result = InterpretationResult(
            node_states_in=dict(df_result.facts_in),
            node_states_out=dict(df_result.facts_out),
            dataflow_result=df_result,
            warnings=list(self._warnings),
            domain=self.domain,
        )
        return result

    def _build_initial_state(self) -> AbstractState:
        """Build the initial abstract state at function entry.

        Initialises function parameters to ⊤ (unconstrained).
        """
        func = getattr(self.cfg, "function", None)
        state = AbstractState(self.domain)

        if func is not None:
            # Set parameters to ⊤
            arg_list = getattr(func, "argument", {})
            if isinstance(arg_list, dict):
                for _idx, var in arg_list.items():
                    var_name = getattr(var, "nameToken", None)
                    if var_name:
                        state = state.set(
                            _variable_id_from_var(var),
                            self.domain.top(),
                        )

            # Set local variables to ⊥ (uninitialised)
            # They will be initialised when assigned

        return state

    def _transfer_with_checks(
        self, node, state_in: AbstractState
    ) -> AbstractState:
        """Transfer function wrapper that also performs safety checks."""
        # Run checks before transfer
        if self.check_division_by_zero or self.check_overflow:
            self._check_node(node, state_in)

        # Run the actual transfer
        return self._transfer(node, state_in)

    def _check_node(self, node, state: AbstractState) -> None:
        """Check for potential errors at a CFG node."""
        tokens = getattr(node, "tokens", [])
        for tok in tokens:
            self._check_token(tok, state)

    def _check_token(self, tok, state: AbstractState) -> None:
        """Check a single token for potential errors."""
        if self.check_division_by_zero and tok.str in ("/", "%", "/=", "%="):
            self._check_div_by_zero(tok, state)

        if self.check_overflow and tok.str in ("+", "-", "*", "++", "--",
                                                 "+=", "-=", "*="):
            self._check_integer_overflow(tok, state)

        if self.check_null_deref and tok.str in ("*", "->", "["):
            self._check_null_deref_token(tok, state)

    def _check_div_by_zero(self, tok, state: AbstractState) -> None:
        """Check for potential division by zero."""
        divisor_tok = getattr(tok, "astOperand2", None)
        if divisor_tok is None:
            return

        evaluator = CExpressionEvaluator(self.domain, state)
        divisor_val = evaluator.evaluate(divisor_tok)

        if self.domain.may_be_zero(divisor_val):
            severity = "error" if self.domain.must_be_zero(divisor_val) else "warning"
            msg = (
                f"Division by zero: divisor "
                f"'{getattr(divisor_tok, 'str', '?')}' "
                f"may be zero (value: {self.domain.gamma_str(divisor_val)})"
            )
            self._warnings.append(AnalysisWarning(
                kind="division_by_zero",
                message=msg,
                token=tok,
                line=getattr(tok, "linenr", 0),
                file=getattr(tok, "file", ""),
                state=state,
                severity=severity,
            ))

    def _check_integer_overflow(self, tok, state: AbstractState) -> None:
        """Check for potential integer overflow."""
        evaluator = CExpressionEvaluator(self.domain, state)
        op1 = getattr(tok, "astOperand1", None)
        op2 = getattr(tok, "astOperand2", None)

        if op1 is None:
            return

        val1 = evaluator.evaluate(op1)
        val1_iv = self.domain.to_interval(val1)
        if val1_iv is None:
            return

        tok_type = infer_ctype(tok)
        if not tok_type.is_integer:
            return

        if op2 is not None:
            val2 = evaluator.evaluate(op2)
            result = self.domain.abstract_binary(tok.str.rstrip("="), val1, val2)
        else:
            result = self.domain.abstract_unary(tok.str, val1)

        result_iv = self.domain.to_interval(result)
        if result_iv is None:
            return

        type_min = float(tok_type.min_value)
        type_max = float(tok_type.max_value)

        if result_iv[0] < type_min or result_iv[1] > type_max:
            self._warnings.append(AnalysisWarning(
                kind="integer_overflow",
                message=(
                    f"Potential integer overflow at '{tok.str}': "
                    f"result {self.domain.gamma_str(result)} may exceed "
                    f"[{int(type_min)}, {int(type_max)}]"
                ),
                token=tok,
                line=getattr(tok, "linenr", 0),
                file=getattr(tok, "file", ""),
                state=state,
                severity="warning",
            ))

    def _check_null_deref_token(self, tok, state: AbstractState) -> None:
        """Check for potential null pointer dereference."""
        ptr_tok = getattr(tok, "astOperand1", None)
        if ptr_tok is None:
            return

        if getattr(ptr_tok, "isName", False) and getattr(ptr_tok, "variable", None):
            var_id = _variable_id(ptr_tok)
            val = state.get(var_id)
            if self.domain.may_be_zero(val):
                self._warnings.append(AnalysisWarning(
                    kind="null_dereference",
                    message=(
                        f"Potential null pointer dereference: "
                        f"'{ptr_tok.str}' may be null "
                        f"(value: {self.domain.gamma_str(val)})"
                    ),
                    token=tok,
                    line=getattr(tok, "linenr", 0),
                    file=getattr(tok, "file", ""),
                    state=state,
                    severity="warning",
                ))


# ===================================================================
# INTERPROCEDURAL ABSTRACT INTERPRETER
# ===================================================================

class InterproceduralInterpreter:
    """Whole-program abstract interpreter using the callgraph.

    Analyses functions bottom-up, computing abstract summaries, then
    re-analyses callers with callee summaries incorporated.

    Parameters
    ----------
    domain : AbstractDomain
        The abstract domain.
    callgraph : CallGraph
        From :mod:`callgraph`.
    cfgs : dict
        Map from function → CFG.
    use_widening : bool
        Enable widening.
    widening_delay : int
        Delay before widening.
    use_narrowing : bool
        Enable narrowing pass.
    max_scc_iterations : int
        Max iterations for recursive SCCs.
    max_intra_iterations : int
        Max intraprocedural iterations.
    check_division_by_zero : bool
        Report potential division by zero.
    check_overflow : bool
        Report potential integer overflow.
    """

    def __init__(
        self,
        domain: AbstractDomain,
        callgraph,
        cfgs: Dict,
        use_widening: bool = True,
        widening_delay: int = 3,
        use_narrowing: bool = True,
        max_scc_iterations: int = 50,
        max_intra_iterations: int = 100_000,
        check_division_by_zero: bool = True,
        check_overflow: bool = False,
    ) -> None:
        self.domain = domain
        self.callgraph = callgraph
        self.cfgs = cfgs
        self.use_widening = use_widening
        self.widening_delay = widening_delay
        self.use_narrowing = use_narrowing
        self.max_scc_iterations = max_scc_iterations
        self.max_intra_iterations = max_intra_iterations
        self.check_division_by_zero = check_division_by_zero
        self.check_overflow = check_overflow

        self.results: Dict[str, InterpretationResult] = {}
        self.function_summaries: Dict[str, Callable] = {}

    def run(self) -> Dict[str, InterpretationResult]:
        """Run the interprocedural analysis.

        Returns
        -------
        dict[str, InterpretationResult]
            Map from function id to interpretation result.
        """
        cg = self.callgraph
        sccs = cg.strongly_connected_components()

        for scc in sccs:
            func_nodes = [
                n for n in scc
                if n.function is not None and self._get_cfg(n) is not None
            ]
            if not func_nodes:
                continue

            if len(func_nodes) == 1 and not getattr(func_nodes[0], "is_recursive", False):
                self._analyze_function(func_nodes[0])
            else:
                self._analyze_recursive_scc(func_nodes)

        return self.results

    def _get_cfg(self, cg_node):
        func = cg_node.function
        if func in self.cfgs:
            return self.cfgs[func]
        fid = getattr(func, "Id", None)
        if fid and fid in self.cfgs:
            return self.cfgs[fid]
        fname = getattr(func, "name", None)
        if fname and fname in self.cfgs:
            return self.cfgs[fname]
        return None

    def _analyze_function(self, cg_node) -> Optional[InterpretationResult]:
        fid = cg_node.id
        if fid in self.results:
            return self.results[fid]

        cfg = self._get_cfg(cg_node)
        interpreter = AbstractInterpreter(
            domain=self.domain,
            cfg=cfg,
            function_summaries=self.function_summaries,
            use_widening=self.use_widening,
            widening_delay=self.widening_delay,
            use_narrowing=self.use_narrowing,
            check_division_by_zero=self.check_division_by_zero,
            check_overflow=self.check_overflow,
            max_iterations=self.max_intra_iterations,
        )
        result = interpreter.run()
        self.results[fid] = result

        # Build summary for callers
        func_name = getattr(cg_node.function, "name", fid)
        self._build_summary(func_name, result, cfg)

        return result

    def _build_summary(self, func_name, result, cfg) -> None:
        """Build a callable summary from the analysis result."""
        exit_node = getattr(cfg, "exit", None)
        if exit_node is None:
            return

        exit_state = result.node_states_out.get(exit_node)
        if exit_state is None:
            return

        # Simple summary: applies the exit state's return value
        def summary(caller_state: AbstractState, args: List) -> AbstractState:
            return caller_state  # Conservative: no caller state modification

        self.function_summaries[func_name] = summary

    def _analyze_recursive_scc(self, func_nodes: List) -> None:
        for iteration in range(self.max_scc_iterations):
            changed = False
            for node in func_nodes:
                old_result = self.results.get(node.id)
                new_result = self._analyze_function(node)
                # Simple convergence check
                if old_result is None:
                    changed = True
                    continue
            if not changed:
                break

    def all_warnings(self) -> List[AnalysisWarning]:
        """Collect all warnings from all analysed functions."""
        warnings = []
        for result in self.results.values():
            warnings.extend(result.warnings)
        return warnings


# ===================================================================
# CONVENIENCE FUNCTIONS
# ===================================================================

def interpret_function(
    cfg,
    domain: AbstractDomain,
    *,
    use_widening: bool = True,
    widening_delay: int = 3,
    use_narrowing: bool = True,
    check_division_by_zero: bool = True,
    check_overflow: bool = False,
    check_null_deref: bool = False,
    max_iterations: int = 100_000,
    function_summaries: Optional[Dict[str, Callable]] = None,
) -> InterpretationResult:
    """Analyse a single function with abstract interpretation.

    Parameters
    ----------
    cfg : CFG
        The function's control-flow graph.
    domain : AbstractDomain
        The abstract domain.
    use_widening : bool
        Enable widening.
    widening_delay : int
        Iterations before widening.
    use_narrowing : bool
        Enable narrowing.
    check_division_by_zero : bool
        Report division by zero.
    check_overflow : bool
        Report integer overflow.
    check_null_deref : bool
        Report null dereference.
    max_iterations : int
        Maximum iterations.
    function_summaries : dict, optional
        Called-function summaries.

    Returns
    -------
    InterpretationResult
    """
    interpreter = AbstractInterpreter(
        domain=domain,
        cfg=cfg,
        function_summaries=function_summaries,
        use_widening=use_widening,
        widening_delay=widening_delay,
        use_narrowing=use_narrowing,
        check_division_by_zero=check_division_by_zero,
        check_overflow=check_overflow,
        check_null_deref=check_null_deref,
        max_iterations=max_iterations,
    )
    return interpreter.run()


def interpret_program(
    callgraph,
    cfgs: Dict,
    domain: AbstractDomain,
    *,
    use_widening: bool = True,
    widening_delay: int = 3,
    use_narrowing: bool = True,
    check_division_by_zero: bool = True,
    check_overflow: bool = False,
    max_scc_iterations: int = 50,
    max_intra_iterations: int = 100_000,
) -> Dict[str, InterpretationResult]:
    """Analyse a whole program with interprocedural abstract interpretation.

    Parameters
    ----------
    callgraph : CallGraph
        The program's call graph.
    cfgs : dict
        Map from function → CFG.
    domain : AbstractDomain
        The abstract domain.
    use_widening : bool
        Enable widening.
    widening_delay : int
        Iterations before widening.
    use_narrowing : bool
        Enable narrowing.
    check_division_by_zero : bool
        Report division by zero.
    check_overflow : bool
        Report integer overflow.
    max_scc_iterations : int
        Max iterations for recursive SCCs.
    max_intra_iterations : int
        Max intraprocedural iterations.

    Returns
    -------
    dict[str, InterpretationResult]
    """
    interpreter = InterproceduralInterpreter(
        domain=domain,
        callgraph=callgraph,
        cfgs=cfgs,
        use_widening=use_widening,
        widening_delay=widening_delay,
        use_narrowing=use_narrowing,
        max_scc_iterations=max_scc_iterations,
        max_intra_iterations=max_intra_iterations,
        check_division_by_zero=check_division_by_zero,
        check_overflow=check_overflow,
    )
    return interpreter.run()


# ===================================================================
# UTILITIES
# ===================================================================

def _variable_id(token) -> VarId:
    """Get a stable variable identifier from a token."""
    var = getattr(token, "variable", None)
    if var is not None:
        vid = getattr(var, "Id", None)
        if vid:
            return str(vid)
        name = getattr(var, "nameToken", None)
        if name:
            return getattr(name, "str", token.str)
    return token.str


def _variable_id_from_var(var) -> VarId:
    """Get a stable variable identifier from a Variable object."""
    vid = getattr(var, "Id", None)
    if vid:
        return str(vid)
    name = getattr(var, "nameToken", None)
    if name:
        return getattr(name, "str", "?")
    return "?"


def _negate_comparison(op: str) -> str:
    """Negate a comparison operator."""
    return {
        "<":  ">=",
        "<=": ">",
        ">":  "<=",
        ">=": "<",
        "==": "!=",
        "!=": "==",
    }.get(op, op)


# ===================================================================
# CPPCHECK VALUEFLOW INTEGRATION
# ===================================================================

class ValueFlowIntegrator:
    """Integrates Cppcheck's ValueFlow results into abstract interpretation.

    Cppcheck's ValueFlow engine computes possible values for tokens
    (stored in ``token.values``).  This class converts those values to
    abstract domain elements and uses them to refine the analysis.

    Parameters
    ----------
    domain : AbstractDomain
        The abstract domain.
    trust_known : bool
        If ``True``, treat ValueFlow "known" values as definite constants.
    trust_possible : bool
        If ``True``, incorporate "possible" values via join.
    """

    def __init__(
        self,
        domain: AbstractDomain,
        trust_known: bool = True,
        trust_possible: bool = False,
    ) -> None:
        self.domain = domain
        self.trust_known = trust_known
        self.trust_possible = trust_possible

    def abstract_from_valueflow(self, token) -> Optional[AbsVal]:
        """Extract an abstract value from Cppcheck's ValueFlow for a token.

        Parameters
        ----------
        token : cppcheckdata.Token

        Returns
        -------
        AbsVal or None
            The abstract value, or ``None`` if no useful ValueFlow info.
        """
        values = getattr(token, "values", None)
        if not values:
            return None

        domain = self.domain
        result: Optional[AbsVal] = None

        for v in values:
            kind = getattr(v, "valueKind", "")
            int_val = getattr(v, "intvalue", None)

            if int_val is None:
                continue

            try:
                abs_val = domain.abstract_const(int(int_val))
            except (ValueError, TypeError):
                continue

            if kind == "known" and self.trust_known:
                # Known values are definite
                return abs_val
            elif kind == "possible" and self.trust_possible:
                if result is None:
                    result = abs_val
                else:
                    result = domain.join(result, abs_val)

        return result

    def refine_state(
        self, state: AbstractState, tokens: Iterable
    ) -> AbstractState:
        """Refine an abstract state using ValueFlow information.

        For each variable token with ValueFlow data, intersect (meet)
        the abstract value with the ValueFlow-derived value.

        Parameters
        ----------
        state : AbstractState
        tokens : iterable of cppcheckdata.Token

        Returns
        -------
        AbstractState
        """
        domain = self.domain
        for tok in tokens:
            if not getattr(tok, "isName", False):
                continue
            if getattr(tok, "variable", None) is None:
                continue

            vf_val = self.abstract_from_valueflow(tok)
            if vf_val is None:
                continue

            var_id = _variable_id(tok)
            current = state.get(var_id)
            refined = domain.meet(current, vf_val)
            if refined is not None:
                state = state.set(var_id, refined)

        return state
