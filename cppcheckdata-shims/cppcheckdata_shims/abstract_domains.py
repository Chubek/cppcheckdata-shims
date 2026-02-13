"""
cppcheckdata_shims/abstract_domains.py
═══════════════════════════════════════

Reusable abstract domain library for cppcheckdata-shims addons.

Provides a base ``AbstractDomain`` protocol and concrete implementations
of the most commonly used domains in static analysis:

    ┌─────────────────────────────────────────────────────────────┐
    │  AbstractDomain  (base protocol / ABC)                      │
    │    ├── FlatDomain[T]         — {⊥, t₁, t₂, …, ⊤}          │
    │    ├── SignDomain             — {⊥, ⁻, 0, ⁺, ⊤}            │
    │    ├── ParityDomain           — {⊥, Even, Odd, ⊤}          │
    │    ├── ConstantDomain         — flat lift of integers       │
    │    ├── IntervalDomain         — [lo, hi] ⊆ ℤ               │
    │    ├── CongruenceDomain       — aℤ + b                      │
    │    ├── BitfieldDomain         — (must_one, may_one) masks   │
    │    ├── StridedIntervalDomain  — s[lo, hi]                   │
    │    ├── BoolDomain             — {⊥, True, False, ⊤}        │
    │    ├── SetDomain[T]           — bounded powerset            │
    │    ├── ProductDomain          — direct product D₁ × D₂      │
    │    ├── ReducedProductDomain   — with reduction operator     │
    │    └── FunctionDomain         — Var → D (pointwise lift)    │
    └─────────────────────────────────────────────────────────────┘

Theory (Cousot & Cousot 1977, 1979):
    An abstract domain is a complete lattice (L, ⊑, ⊥, ⊤, ⊔, ⊓)
    connected to the concrete domain by a Galois connection (α, γ):

        C  ←─γ─  A
        C  ──α→  A       α(c) ⊑ a  ⟺  c ⊆ γ(a)

    Every domain below implements the lattice operations; the Galois
    connection is implicit (documented but not enforced at runtime,
    since the concrete domain is ℘(ℤ) or ℘(State) which is too large
    to materialise).

Fixpoint engines in ``dataflow_engine.py`` and ``abstract_interp.py``
depend only on the ``AbstractDomain`` protocol, so any domain defined
here (or by a user addon) plugs in seamlessly.

License: MIT — same as cppcheckdata-shims.
"""

from __future__ import annotations

import math
import operator as op
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum, auto
from functools import reduce
from typing import (
    Any,
    Callable,
    ClassVar,
    Dict,
    Final,
    FrozenSet,
    Generic,
    Hashable,
    Iterator,
    List,
    Mapping,
    Optional,
    Protocol,
    Self,
    Sequence,
    Set,
    Tuple,
    TypeVar,
    Union,
    runtime_checkable,
)


# ═══════════════════════════════════════════════════════════════════════════
#  PART 0 — TYPE VARIABLES AND SENTINELS
# ═══════════════════════════════════════════════════════════════════════════

T = TypeVar("T")
T_co = TypeVar("T_co", covariant=True)
D = TypeVar("D", bound="AbstractDomain")


class _BottomSentinel:
    """Unique sentinel for ⊥ (bottom) in flat domains."""
    _instance: ClassVar[Optional[_BottomSentinel]] = None

    def __new__(cls) -> _BottomSentinel:
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __repr__(self) -> str:
        return "⊥"

    def __hash__(self) -> int:
        return hash("__BOTTOM__")

    def __eq__(self, other: object) -> bool:
        return isinstance(other, _BottomSentinel)


class _TopSentinel:
    """Unique sentinel for ⊤ (top) in flat domains."""
    _instance: ClassVar[Optional[_TopSentinel]] = None

    def __new__(cls) -> _TopSentinel:
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __repr__(self) -> str:
        return "⊤"

    def __hash__(self) -> int:
        return hash("__TOP__")

    def __eq__(self, other: object) -> bool:
        return isinstance(other, _TopSentinel)


BOTTOM: Final = _BottomSentinel()
TOP: Final = _TopSentinel()


# ═══════════════════════════════════════════════════════════════════════════
#  PART 1 — BASE ABSTRACT DOMAIN PROTOCOL
# ═══════════════════════════════════════════════════════════════════════════
#
#  Every domain must implement these operations.  The protocol is
#  deliberately minimal — only lattice structure + widening/narrowing
#  are required.  Arithmetic transfer is domain-specific and provided
#  by subclasses.
#
#  Lattice laws that MUST hold (testable via Hypothesis):
#
#    1. x ⊔ ⊥ = x                          (⊥ is identity for join)
#    2. x ⊓ ⊤ = x                          (⊤ is identity for meet)
#    3. x ⊑ x ⊔ y  and  y ⊑ x ⊔ y         (join is upper bound)
#    4. x ⊓ y ⊑ x  and  x ⊓ y ⊑ y         (meet is lower bound)
#    5. x ⊑ y  ⟺  x ⊔ y = y              (ordering ↔ join)
#    6. x ⊔ y = y ⊔ x                      (commutativity of join)
#    7. x ⊓ y = y ⊓ x                      (commutativity of meet)
#    8. (x ⊔ y) ⊔ z = x ⊔ (y ⊔ z)         (associativity of join)
#    9. x ⊔ x = x                          (idempotence)
#   10. ⊥ ⊑ x ⊑ ⊤                         (extremal elements)
# ═══════════════════════════════════════════════════════════════════════════

@runtime_checkable
class AbstractDomain(Protocol):
    """
    Protocol that every abstract domain element must satisfy.

    This is the universal contract consumed by:
      - ``dataflow_engine.py``  (chaotic iteration / worklist)
      - ``abstract_interp.py``  (widening-based fixpoint)
      - ``ctrlflow_graph.py``   (edge annotations)
      - every addon that performs dataflow analysis
    """

    # ---- Lattice operations ----------------------------------------------

    def join(self, other: Self) -> Self:
        """Least upper bound:  self ⊔ other."""
        ...

    def meet(self, other: Self) -> Self:
        """Greatest lower bound:  self ⊓ other."""
        ...

    def leq(self, other: Self) -> bool:
        """Partial order:  self ⊑ other."""
        ...

    def is_bottom(self) -> bool:
        """Is this the least element ⊥?"""
        ...

    def is_top(self) -> bool:
        """Is this the greatest element ⊤?"""
        ...

    # ---- Widening / narrowing  (for infinite-height lattices) ------------

    def widen(self, other: Self) -> Self:
        """
        Widening operator  self ∇ other.

        Must satisfy:  ∀x, y:  x ⊔ y  ⊑  x ∇ y
        and every ascending chain  x₀ ∇ x₁ ∇ x₂ ∇ …  stabilises in
        finitely many steps.

        Domains with finite height (Sign, Parity, Bool, Constants over a
        bounded set) may implement this as plain ``join``.
        """
        ...

    def narrow(self, other: Self) -> Self:
        """
        Narrowing operator  self Δ other.

        Must satisfy:  other ⊑ self  ⟹  other ⊑ (self Δ other) ⊑ self
        and every descending chain stabilises.

        Default implementation: return other (always safe, may be imprecise).
        """
        ...


# ═══════════════════════════════════════════════════════════════════════════
#  PART 2 — FLAT DOMAIN  (generic)
# ═══════════════════════════════════════════════════════════════════════════
#
#  The flat lattice over a set S is:
#
#            ⊤
#        / | | | \
#       s₁ s₂ s₃ … sₙ
#        \ | | | /
#            ⊥
#
#  Height = 2, so no widening is needed.
#  This subsumes ConstantDomain (S = ℤ), BoolDomain (S = {T,F}), etc.
# ═══════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True, slots=True)
class FlatDomain(Generic[T]):
    """
    Flat lattice over an arbitrary hashable type T.

    Representation:
        value=BOTTOM          →  ⊥
        value=TOP             →  ⊤
        value=<concrete T>    →  the lifted element
    """
    value: Union[T, _BottomSentinel, _TopSentinel]

    # ---- Constructors ----------------------------------------------------

    @classmethod
    def bottom(cls) -> FlatDomain[T]:
        return cls(BOTTOM)

    @classmethod
    def top(cls) -> FlatDomain[T]:
        return cls(TOP)

    @classmethod
    def lift(cls, v: T) -> FlatDomain[T]:
        return cls(v)

    # ---- Lattice operations ----------------------------------------------

    def is_bottom(self) -> bool:
        return self.value is BOTTOM

    def is_top(self) -> bool:
        return self.value is TOP

    def is_concrete(self) -> bool:
        return not self.is_bottom() and not self.is_top()

    def leq(self, other: FlatDomain[T]) -> bool:
        """⊥ ⊑ anything;  x ⊑ ⊤;  x ⊑ x."""
        if self.is_bottom():
            return True
        if other.is_top():
            return True
        return self.value == other.value

    def join(self, other: FlatDomain[T]) -> FlatDomain[T]:
        if self.is_bottom():
            return other
        if other.is_bottom():
            return self
        if self.value == other.value:
            return self
        return FlatDomain.top()

    def meet(self, other: FlatDomain[T]) -> FlatDomain[T]:
        if self.is_top():
            return other
        if other.is_top():
            return self
        if self.value == other.value:
            return self
        return FlatDomain.bottom()

    def widen(self, other: FlatDomain[T]) -> FlatDomain[T]:
        # Height = 2, plain join suffices
        return self.join(other)

    def narrow(self, other: FlatDomain[T]) -> FlatDomain[T]:
        return other

    def __repr__(self) -> str:
        return f"Flat({self.value!r})"


# ═══════════════════════════════════════════════════════════════════════════
#  PART 3 — SIGN DOMAIN
# ═══════════════════════════════════════════════════════════════════════════
#
#  The classic textbook domain (Nielson et al., PPA Ch. 1–2):
#
#            ⊤
#          / | \
#        ⁻   0   ⁺
#          \ | /
#            ⊥
#
#  Concretisation:
#    γ(⊥)  = ∅
#    γ(⁻)  = { z ∈ ℤ | z < 0 }
#    γ(0)  = { 0 }
#    γ(⁺)  = { z ∈ ℤ | z > 0 }
#    γ(⊤)  = ℤ
#
#  Height = 2  ⟹  no widening needed.
# ═══════════════════════════════════════════════════════════════════════════

class Sign(Enum):
    BOTTOM = auto()  # ⊥
    NEG    = auto()  # ⁻
    ZERO   = auto()  # 0
    POS    = auto()  # ⁺
    TOP    = auto()  # ⊤


# Pre-computed join table.  Indexed as _SIGN_JOIN[a][b].
# The table encodes the Hasse diagram above.
_SIGN_JOIN: Dict[Sign, Dict[Sign, Sign]] = {
    Sign.BOTTOM: {s: s for s in Sign},
    Sign.NEG:    {Sign.BOTTOM: Sign.NEG, Sign.NEG: Sign.NEG,
                  Sign.ZERO: Sign.TOP, Sign.POS: Sign.TOP, Sign.TOP: Sign.TOP},
    Sign.ZERO:   {Sign.BOTTOM: Sign.ZERO, Sign.NEG: Sign.TOP,
                  Sign.ZERO: Sign.ZERO, Sign.POS: Sign.TOP, Sign.TOP: Sign.TOP},
    Sign.POS:    {Sign.BOTTOM: Sign.POS, Sign.NEG: Sign.TOP,
                  Sign.ZERO: Sign.TOP, Sign.POS: Sign.POS, Sign.TOP: Sign.TOP},
    Sign.TOP:    {s: Sign.TOP for s in Sign},
}

# Pre-computed meet table.
_SIGN_MEET: Dict[Sign, Dict[Sign, Sign]] = {
    Sign.TOP:    {s: s for s in Sign},
    Sign.NEG:    {Sign.TOP: Sign.NEG, Sign.NEG: Sign.NEG,
                  Sign.ZERO: Sign.BOTTOM, Sign.POS: Sign.BOTTOM, Sign.BOTTOM: Sign.BOTTOM},
    Sign.ZERO:   {Sign.TOP: Sign.ZERO, Sign.NEG: Sign.BOTTOM,
                  Sign.ZERO: Sign.ZERO, Sign.POS: Sign.BOTTOM, Sign.BOTTOM: Sign.BOTTOM},
    Sign.POS:    {Sign.TOP: Sign.POS, Sign.NEG: Sign.BOTTOM,
                  Sign.ZERO: Sign.BOTTOM, Sign.POS: Sign.POS, Sign.BOTTOM: Sign.BOTTOM},
    Sign.BOTTOM: {s: Sign.BOTTOM for s in Sign},
}


@dataclass(frozen=True, slots=True)
class SignDomain:
    """
    The sign abstract domain  {⊥, ⁻, 0, ⁺, ⊤}.

    Supports abstract arithmetic (+, -, *, /) and comparison.

    Examples
    --------
    >>> p = SignDomain.pos()
    >>> n = SignDomain.neg()
    >>> p.add(n)
    SignDomain(sign=Sign.TOP)
    >>> p.mul(p)
    SignDomain(sign=Sign.POS)
    >>> p.mul(n)
    SignDomain(sign=Sign.NEG)
    """
    sign: Sign

    # ---- Constructors ----------------------------------------------------

    @classmethod
    def bottom(cls) -> SignDomain:
        return cls(Sign.BOTTOM)

    @classmethod
    def top(cls) -> SignDomain:
        return cls(Sign.TOP)

    @classmethod
    def neg(cls) -> SignDomain:
        return cls(Sign.NEG)

    @classmethod
    def zero(cls) -> SignDomain:
        return cls(Sign.ZERO)

    @classmethod
    def pos(cls) -> SignDomain:
        return cls(Sign.POS)

    @classmethod
    def abstract(cls, n: int) -> SignDomain:
        """Abstraction function  α: ℤ → Sign."""
        if n < 0:
            return cls(Sign.NEG)
        elif n == 0:
            return cls(Sign.ZERO)
        else:
            return cls(Sign.POS)

    # ---- Lattice operations ----------------------------------------------

    def is_bottom(self) -> bool:
        return self.sign is Sign.BOTTOM

    def is_top(self) -> bool:
        return self.sign is Sign.TOP

    def leq(self, other: SignDomain) -> bool:
        if self.is_bottom():
            return True
        if other.is_top():
            return True
        return self.sign == other.sign

    def join(self, other: SignDomain) -> SignDomain:
        return SignDomain(_SIGN_JOIN[self.sign][other.sign])

    def meet(self, other: SignDomain) -> SignDomain:
        return SignDomain(_SIGN_MEET[self.sign][other.sign])

    def widen(self, other: SignDomain) -> SignDomain:
        return self.join(other)  # finite height

    def narrow(self, other: SignDomain) -> SignDomain:
        return other

    # ---- Abstract arithmetic ---------------------------------------------
    #
    # These transfer functions implement the abstract semantics of
    # arithmetic operations.  Each table entry is the tightest sound
    # abstraction of  { a ⊕ b | a ∈ γ(self), b ∈ γ(other) }.

    def add(self, other: SignDomain) -> SignDomain:
        """Abstract addition."""
        if self.is_bottom() or other.is_bottom():
            return SignDomain.bottom()
        if self.is_top() or other.is_top():
            return SignDomain.top()
        a, b = self.sign, other.sign
        # 0 + x = x
        if a is Sign.ZERO:
            return other
        if b is Sign.ZERO:
            return self
        # same sign: preserved
        if a == b:
            return self
        # opposite signs: could be anything
        return SignDomain.top()

    def sub(self, other: SignDomain) -> SignDomain:
        """Abstract subtraction."""
        return self.add(other.negate())

    def negate(self) -> SignDomain:
        """Abstract unary negation."""
        if self.sign is Sign.NEG:
            return SignDomain.pos()
        if self.sign is Sign.POS:
            return SignDomain.neg()
        return self  # ⊥, 0, ⊤ unchanged

    def mul(self, other: SignDomain) -> SignDomain:
        """Abstract multiplication."""
        if self.is_bottom() or other.is_bottom():
            return SignDomain.bottom()
        a, b = self.sign, other.sign
        # Anything × 0 = 0
        if a is Sign.ZERO or b is Sign.ZERO:
            return SignDomain.zero()
        if a is Sign.TOP or b is Sign.TOP:
            return SignDomain.top()
        # same sign → positive;  different → negative
        if a == b:
            return SignDomain.pos()
        return SignDomain.neg()

    def div(self, other: SignDomain) -> SignDomain:
        """
        Abstract integer division (truncating toward zero).

        Division by an interval containing zero yields ⊤ (could trap),
        but we model the non-trapping case conservatively.
        """
        if self.is_bottom() or other.is_bottom():
            return SignDomain.bottom()
        if other.sign is Sign.ZERO:
            return SignDomain.bottom()  # division by zero → unreachable
        if self.sign is Sign.ZERO:
            return SignDomain.zero()
        if self.is_top() or other.is_top():
            return SignDomain.top()
        if self.sign == other.sign:
            # Result could be 0 or positive (e.g. 1/2 = 0, 4/2 = 2)
            return SignDomain.top()  # sound overapproximation
        # Different signs: could be 0 or negative
        return SignDomain.top()

    def __repr__(self) -> str:
        _NAMES = {
            Sign.BOTTOM: "⊥", Sign.NEG: "⁻", Sign.ZERO: "0",
            Sign.POS: "⁺", Sign.TOP: "⊤",
        }
        return f"SignDomain({_NAMES[self.sign]})"


# ═══════════════════════════════════════════════════════════════════════════
#  PART 4 — PARITY DOMAIN
# ═══════════════════════════════════════════════════════════════════════════
#
#            ⊤
#          /   \
#       Even   Odd
#          \   /
#            ⊥
#
#  Concretisation:
#    γ(Even) = { 2k | k ∈ ℤ }
#    γ(Odd)  = { 2k+1 | k ∈ ℤ }
#
#  Height = 2  ⟹  no widening needed.
# ═══════════════════════════════════════════════════════════════════════════

class Parity(Enum):
    BOTTOM = auto()
    EVEN   = auto()
    ODD    = auto()
    TOP    = auto()


@dataclass(frozen=True, slots=True)
class ParityDomain:
    """
    The parity abstract domain  {⊥, Even, Odd, ⊤}.

    Useful for array alignment checks, bitwise reasoning, and
    detecting off-by-one errors in loop bounds.
    """
    parity: Parity

    @classmethod
    def bottom(cls) -> ParityDomain:
        return cls(Parity.BOTTOM)

    @classmethod
    def top(cls) -> ParityDomain:
        return cls(Parity.TOP)

    @classmethod
    def even(cls) -> ParityDomain:
        return cls(Parity.EVEN)

    @classmethod
    def odd(cls) -> ParityDomain:
        return cls(Parity.ODD)

    @classmethod
    def abstract(cls, n: int) -> ParityDomain:
        return cls(Parity.EVEN if n % 2 == 0 else Parity.ODD)

    def is_bottom(self) -> bool:
        return self.parity is Parity.BOTTOM

    def is_top(self) -> bool:
        return self.parity is Parity.TOP

    def leq(self, other: ParityDomain) -> bool:
        if self.is_bottom():
            return True
        if other.is_top():
            return True
        return self.parity == other.parity

    def join(self, other: ParityDomain) -> ParityDomain:
        if self.is_bottom():
            return other
        if other.is_bottom():
            return self
        if self.parity == other.parity:
            return self
        return ParityDomain.top()

    def meet(self, other: ParityDomain) -> ParityDomain:
        if self.is_top():
            return other
        if other.is_top():
            return self
        if self.parity == other.parity:
            return self
        return ParityDomain.bottom()

    def widen(self, other: ParityDomain) -> ParityDomain:
        return self.join(other)

    def narrow(self, other: ParityDomain) -> ParityDomain:
        return other

    # ---- Abstract arithmetic ---------------------------------------------

    def add(self, other: ParityDomain) -> ParityDomain:
        if self.is_bottom() or other.is_bottom():
            return ParityDomain.bottom()
        if self.is_top() or other.is_top():
            return ParityDomain.top()
        # Even + Even = Even;  Odd + Odd = Even;  else Odd
        if self.parity == other.parity:
            return ParityDomain.even()
        return ParityDomain.odd()

    def sub(self, other: ParityDomain) -> ParityDomain:
        # Subtraction has the same parity rules as addition
        return self.add(other)

    def mul(self, other: ParityDomain) -> ParityDomain:
        if self.is_bottom() or other.is_bottom():
            return ParityDomain.bottom()
        if self.is_top() or other.is_top():
            # If either is ⊤ but the other is Even, result is Even
            if self.parity is Parity.EVEN or other.parity is Parity.EVEN:
                return ParityDomain.even()
            return ParityDomain.top()
        # Even × anything = Even
        if self.parity is Parity.EVEN or other.parity is Parity.EVEN:
            return ParityDomain.even()
        # Odd × Odd = Odd
        return ParityDomain.odd()

    def __repr__(self) -> str:
        _NAMES = {
            Parity.BOTTOM: "⊥", Parity.EVEN: "Even",
            Parity.ODD: "Odd", Parity.TOP: "⊤",
        }
        return f"ParityDomain({_NAMES[self.parity]})"


# ═══════════════════════════════════════════════════════════════════════════
#  PART 5 — CONSTANT PROPAGATION DOMAIN
# ═══════════════════════════════════════════════════════════════════════════
#
#  A specialisation of FlatDomain[int] with concrete arithmetic.
#
#            ⊤
#      / | ... | \
#    …  -1  0  1  2  …
#      \ | ... | /
#            ⊥
# ═══════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True, slots=True)
class ConstantDomain:
    """
    Constant propagation domain — flat lattice over ℤ with arithmetic.

    This is the workhorse domain for intraprocedural constant propagation
    and constant folding optimisations.

    Examples
    --------
    >>> a = ConstantDomain.lift(7)
    >>> b = ConstantDomain.lift(3)
    >>> a.add(b)
    Const(10)
    >>> a.join(b)
    Const(⊤)
    """
    value: Union[int, _BottomSentinel, _TopSentinel]

    @classmethod
    def bottom(cls) -> ConstantDomain:
        return cls(BOTTOM)

    @classmethod
    def top(cls) -> ConstantDomain:
        return cls(TOP)

    @classmethod
    def lift(cls, n: int) -> ConstantDomain:
        return cls(n)

    def is_bottom(self) -> bool:
        return self.value is BOTTOM

    def is_top(self) -> bool:
        return self.value is TOP

    def is_concrete(self) -> bool:
        return isinstance(self.value, int)

    def concrete_value(self) -> Optional[int]:
        return self.value if isinstance(self.value, int) else None

    def leq(self, other: ConstantDomain) -> bool:
        if self.is_bottom():
            return True
        if other.is_top():
            return True
        return self.value == other.value

    def join(self, other: ConstantDomain) -> ConstantDomain:
        if self.is_bottom():
            return other
        if other.is_bottom():
            return self
        if self.value == other.value:
            return self
        return ConstantDomain.top()

    def meet(self, other: ConstantDomain) -> ConstantDomain:
        if self.is_top():
            return other
        if other.is_top():
            return self
        if self.value == other.value:
            return self
        return ConstantDomain.bottom()

    def widen(self, other: ConstantDomain) -> ConstantDomain:
        return self.join(other)  # finite per-variable, but unbounded...
        # In practice, we treat this as finite since any variable only
        # sees finitely many constants during fixpoint iteration.
        # For soundness in pathological cases, callers may impose a
        # threshold and jump to ⊤.

    def narrow(self, other: ConstantDomain) -> ConstantDomain:
        return other

    # ---- Abstract arithmetic (total: ⊥/⊤ propagated) --------------------

    def _binop(
        self, other: ConstantDomain, f: Callable[[int, int], int]
    ) -> ConstantDomain:
        if self.is_bottom() or other.is_bottom():
            return ConstantDomain.bottom()
        if self.is_top() or other.is_top():
            return ConstantDomain.top()
        assert isinstance(self.value, int) and isinstance(other.value, int)
        return ConstantDomain.lift(f(self.value, other.value))

    def add(self, other: ConstantDomain) -> ConstantDomain:
        return self._binop(other, op.add)

    def sub(self, other: ConstantDomain) -> ConstantDomain:
        return self._binop(other, op.sub)

    def mul(self, other: ConstantDomain) -> ConstantDomain:
        return self._binop(other, op.mul)

    def div(self, other: ConstantDomain) -> ConstantDomain:
        if self.is_bottom() or other.is_bottom():
            return ConstantDomain.bottom()
        if other.is_concrete() and other.value == 0:
            return ConstantDomain.bottom()  # division by zero → ⊥
        if self.is_top() or other.is_top():
            return ConstantDomain.top()
        assert isinstance(self.value, int) and isinstance(other.value, int)
        # C-style truncation toward zero
        q = int(self.value / other.value)
        return ConstantDomain.lift(q)

    def mod(self, other: ConstantDomain) -> ConstantDomain:
        if self.is_bottom() or other.is_bottom():
            return ConstantDomain.bottom()
        if other.is_concrete() and other.value == 0:
            return ConstantDomain.bottom()
        if self.is_top() or other.is_top():
            return ConstantDomain.top()
        assert isinstance(self.value, int) and isinstance(other.value, int)
        return ConstantDomain.lift(self.value % other.value)

    def negate(self) -> ConstantDomain:
        if self.is_bottom():
            return self
        if self.is_top():
            return self
        assert isinstance(self.value, int)
        return ConstantDomain.lift(-self.value)

    def __repr__(self) -> str:
        if self.is_bottom():
            return "Const(⊥)"
        if self.is_top():
            return "Const(⊤)"
        return f"Const({self.value})"


# ═══════════════════════════════════════════════════════════════════════════
#  PART 6 — INTERVAL DOMAIN
# ═══════════════════════════════════════════════════════════════════════════
#
#  The interval domain approximates sets of integers by closed intervals:
#
#    γ([a, b]) = { z ∈ ℤ | a ≤ z ≤ b }
#
#  This is the single most important numerical domain in practice
#  (buffer overflow detection, array bounds checking, etc.).
#
#  The lattice has INFINITE height (the chain ⊥ ⊏ [0,0] ⊏ [0,1] ⊏ …
#  never stabilises), so widening is MANDATORY.
#
#  Standard widening (Cousot & Cousot 1977):
#    [a, b] ∇ [c, d] = [ (c < a ? -∞ : a),  (d > b ? +∞ : b) ]
#
#  Standard narrowing:
#    [a, b] Δ [c, d] = [ (a = -∞ ? c : a),  (b = +∞ ? d : b) ]
# ═══════════════════════════════════════════════════════════════════════════

# We use float('inf') / float('-inf') for ±∞ to keep things simple.
# An alternative is a dedicated Infinity sentinel, but float ±inf
# interoperates cleanly with Python's min/max/comparisons.

_NEG_INF: Final[float] = float("-inf")
_POS_INF: Final[float] = float("inf")


@dataclass(frozen=True, slots=True)
class IntervalDomain:
    """
    Interval abstract domain  [lo, hi] ⊆ ℤ ∪ {-∞, +∞}.

    The primary numerical domain for bounds checking, buffer overflow
    detection, and loop iteration counting.

    Representation:
        lo > hi  ⟹  ⊥  (empty interval)
        lo = -∞, hi = +∞  ⟹  ⊤  (all integers)

    Examples
    --------
    >>> a = IntervalDomain(0, 10)
    >>> b = IntervalDomain(5, 20)
    >>> a.join(b)
    Interval([0, 20])
    >>> a.meet(b)
    Interval([5, 10])
    >>> a.add(b)
    Interval([5, 30])
    >>> a.widen(IntervalDomain(0, 100))
    Interval([0, +∞])
    """
    lo: float
    hi: float

    def __post_init__(self) -> None:
        # Normalise: if lo > hi, this is ⊥; we use a canonical form.
        # frozen=True, so we cannot assign; the invariant is checked
        # at usage sites instead.
        pass

    # ---- Constructors ----------------------------------------------------

    @classmethod
    def bottom(cls) -> IntervalDomain:
        """The empty interval ⊥."""
        return cls(1.0, 0.0)  # lo > hi → canonical ⊥

    @classmethod
    def top(cls) -> IntervalDomain:
        """The full interval ⊤ = [-∞, +∞]."""
        return cls(_NEG_INF, _POS_INF)

    @classmethod
    def const(cls, n: int) -> IntervalDomain:
        """Singleton interval [n, n]."""
        return cls(float(n), float(n))

    @classmethod
    def range(cls, lo: int, hi: int) -> IntervalDomain:
        """Closed interval [lo, hi]."""
        return cls(float(lo), float(hi))

    @classmethod
    def at_least(cls, lo: int) -> IntervalDomain:
        """Half-open interval [lo, +∞)."""
        return cls(float(lo), _POS_INF)

    @classmethod
    def at_most(cls, hi: int) -> IntervalDomain:
        """Half-open interval (-∞, hi]."""
        return cls(_NEG_INF, float(hi))

    # ---- Predicates ------------------------------------------------------

    def is_bottom(self) -> bool:
        return self.lo > self.hi

    def is_top(self) -> bool:
        return self.lo == _NEG_INF and self.hi == _POS_INF

    def is_const(self) -> bool:
        """Is this a singleton [n, n]?"""
        return self.lo == self.hi and not self.is_bottom()

    def const_value(self) -> Optional[int]:
        """Return the concrete integer if singleton, else None."""
        if self.is_const() and math.isfinite(self.lo):
            return int(self.lo)
        return None

    def contains(self, n: int) -> bool:
        """Does the interval contain concrete integer n?"""
        if self.is_bottom():
            return False
        return self.lo <= n <= self.hi

    def size(self) -> float:
        """Number of integers in the interval (may be inf)."""
        if self.is_bottom():
            return 0.0
        return self.hi - self.lo + 1.0

    # ---- Lattice operations ----------------------------------------------

    def leq(self, other: IntervalDomain) -> bool:
        """[a,b] ⊑ [c,d]  ⟺  c ≤ a  ∧  b ≤ d  (or self = ⊥)."""
        if self.is_bottom():
            return True
        if other.is_bottom():
            return False
        return other.lo <= self.lo and self.hi <= other.hi

    def join(self, other: IntervalDomain) -> IntervalDomain:
        """[a,b] ⊔ [c,d] = [min(a,c), max(b,d)]."""
        if self.is_bottom():
            return other
        if other.is_bottom():
            return self
        return IntervalDomain(min(self.lo, other.lo), max(self.hi, other.hi))

    def meet(self, other: IntervalDomain) -> IntervalDomain:
        """[a,b] ⊓ [c,d] = [max(a,c), min(b,d)]."""
        if self.is_bottom() or other.is_bottom():
            return IntervalDomain.bottom()
        lo = max(self.lo, other.lo)
        hi = min(self.hi, other.hi)
        if lo > hi:
            return IntervalDomain.bottom()
        return IntervalDomain(lo, hi)

    def widen(self, other: IntervalDomain) -> IntervalDomain:
        """
        Standard widening  [a,b] ∇ [c,d].

        From Cousot & Cousot (1977):
            new_lo = c < a  →  -∞   else  a
            new_hi = d > b  →  +∞   else  b

        This guarantees that any ascending chain stabilises in at most
        2 steps per variable (once each bound is pushed to ±∞).
        """
        if self.is_bottom():
            return other
        if other.is_bottom():
            return self
        new_lo = _NEG_INF if other.lo < self.lo else self.lo
        new_hi = _POS_INF if other.hi > self.hi else self.hi
        return IntervalDomain(new_lo, new_hi)

    def narrow(self, other: IntervalDomain) -> IntervalDomain:
        """
        Standard narrowing  [a,b] Δ [c,d].

            new_lo = a = -∞  →  c   else  a
            new_hi = b = +∞  →  d   else  b
        """
        if self.is_bottom():
            return self
        if other.is_bottom():
            return other
        new_lo = other.lo if self.lo == _NEG_INF else self.lo
        new_hi = other.hi if self.hi == _POS_INF else self.hi
        if new_lo > new_hi:
            return IntervalDomain.bottom()
        return IntervalDomain(new_lo, new_hi)

    # ---- Threshold widening (optional refinement) ------------------------

    def widen_with_thresholds(
        self, other: IntervalDomain, thresholds: Sequence[float]
    ) -> IntervalDomain:
        """
        Widening with thresholds — instead of jumping straight to ±∞,
        jump to the nearest threshold.  This produces tighter invariants
        for common loop bounds (0, 1, array sizes, INT_MAX, etc.).

        The threshold set should be sorted.
        """
        if self.is_bottom():
            return other
        if other.is_bottom():
            return self
        # Lower bound: if shrinking, use largest threshold ≤ other.lo
        if other.lo < self.lo:
            new_lo = _NEG_INF
            for t in thresholds:
                if t <= other.lo:
                    new_lo = t
            # If no threshold found, stays -∞
        else:
            new_lo = self.lo
        # Upper bound: if growing, use smallest threshold ≥ other.hi
        if other.hi > self.hi:
            new_hi = _POS_INF
            for t in reversed(thresholds):
                if t >= other.hi:
                    new_hi = t
            # If no threshold found, stays +∞
        else:
            new_hi = self.hi
        return IntervalDomain(new_lo, new_hi)

    # ---- Abstract arithmetic ---------------------------------------------

    def add(self, other: IntervalDomain) -> IntervalDomain:
        """[a,b] + [c,d] = [a+c, b+d]."""
        if self.is_bottom() or other.is_bottom():
            return IntervalDomain.bottom()
        return IntervalDomain(self.lo + other.lo, self.hi + other.hi)

    def sub(self, other: IntervalDomain) -> IntervalDomain:
        """[a,b] - [c,d] = [a-d, b-c]."""
        if self.is_bottom() or other.is_bottom():
            return IntervalDomain.bottom()
        return IntervalDomain(self.lo - other.hi, self.hi - other.lo)

    def negate(self) -> IntervalDomain:
        """-[a,b] = [-b, -a]."""
        if self.is_bottom():
            return self
        return IntervalDomain(-self.hi, -self.lo)

    def mul(self, other: IntervalDomain) -> IntervalDomain:
        """
        [a,b] × [c,d] = [min(ac,ad,bc,bd), max(ac,ad,bc,bd)].

        We must handle ±∞ carefully; Python's float arithmetic does this
        correctly (inf * 0 = nan is the only trap, handled below).
        """
        if self.is_bottom() or other.is_bottom():
            return IntervalDomain.bottom()
        # Special case: either interval contains only 0
        if self.lo == 0.0 and self.hi == 0.0:
            return IntervalDomain.const(0)
        if other.lo == 0.0 and other.hi == 0.0:
            return IntervalDomain.const(0)
        products = []
        for a in (self.lo, self.hi):
            for b in (other.lo, other.hi):
                p = a * b
                if math.isnan(p):
                    p = 0.0  # inf * 0 = 0 in interval arithmetic
                products.append(p)
        return IntervalDomain(min(products), max(products))

    def div(self, other: IntervalDomain) -> IntervalDomain:
        """
        Integer division [a,b] / [c,d].

        If 0 ∈ [c,d], the result is ⊤ (conservative).
        Otherwise, compute min/max of all endpoint quotients.
        """
        if self.is_bottom() or other.is_bottom():
            return IntervalDomain.bottom()
        if other.contains(0):
            return IntervalDomain.top()  # division by zero possible → ⊤
        quotients = []
        for a in (self.lo, self.hi):
            for b in (other.lo, other.hi):
                if b != 0.0 and math.isfinite(a):
                    quotients.append(a / b)
                elif b != 0.0:
                    # ±∞ / finite
                    quotients.append(a / b)
        if not quotients:
            return IntervalDomain.top()
        lo = math.floor(min(quotients))
        hi = math.floor(max(quotients))
        return IntervalDomain(float(lo), float(hi))

    def mod(self, other: IntervalDomain) -> IntervalDomain:
        """Conservative abstraction of [a,b] % [c,d]."""
        if self.is_bottom() or other.is_bottom():
            return IntervalDomain.bottom()
        if other.contains(0):
            return IntervalDomain.top()
        # |result| < |divisor|, result has sign of dividend
        abs_max = max(abs(other.lo), abs(other.hi))
        if self.lo >= 0:
            return IntervalDomain(0.0, abs_max - 1.0)
        if self.hi <= 0:
            return IntervalDomain(-(abs_max - 1.0), 0.0)
        return IntervalDomain(-(abs_max - 1.0), abs_max - 1.0)

    # ---- Bitwise operations (conservative) -------------------------------

    def bitwise_and(self, other: IntervalDomain) -> IntervalDomain:
        """Conservative abstraction of bitwise AND."""
        if self.is_bottom() or other.is_bottom():
            return IntervalDomain.bottom()
        # If both are non-negative, result is in [0, min(hi_a, hi_b)]
        if self.lo >= 0 and other.lo >= 0:
            return IntervalDomain(0.0, min(self.hi, other.hi))
        return IntervalDomain.top()

    def shift_left(self, other: IntervalDomain) -> IntervalDomain:
        """Conservative abstraction of left shift."""
        if self.is_bottom() or other.is_bottom():
            return IntervalDomain.bottom()
        if other.lo < 0:
            return IntervalDomain.top()  # negative shift is UB in C
        if not math.isfinite(other.hi) or other.hi > 63:
            return IntervalDomain.top()
        # Multiply by [2^lo_shift, 2^hi_shift]
        shift_lo = IntervalDomain.const(1 << int(other.lo))
        shift_hi = IntervalDomain.const(1 << int(other.hi))
        multiplier = IntervalDomain(shift_lo.lo, shift_hi.hi)
        return self.mul(multiplier)

    # ---- Comparison refinement -------------------------------------------
    #
    # These methods refine an interval based on a branch condition.
    # Used by transfer functions for conditional branches:
    #
    #   if (x < 10)  →  refine x to  x ⊓ [-∞, 9]   in true branch
    #                    refine x to  x ⊓ [10, +∞]   in false branch

    def refine_lt(self, bound: float) -> IntervalDomain:
        """Refine self assuming self < bound."""
        return self.meet(IntervalDomain(_NEG_INF, bound - 1.0))

    def refine_le(self, bound: float) -> IntervalDomain:
        """Refine self assuming self ≤ bound."""
        return self.meet(IntervalDomain(_NEG_INF, bound))

    def refine_gt(self, bound: float) -> IntervalDomain:
        """Refine self assuming self > bound."""
        return self.meet(IntervalDomain(bound + 1.0, _POS_INF))

    def refine_ge(self, bound: float) -> IntervalDomain:
        """Refine self assuming self ≥ bound."""
        return self.meet(IntervalDomain(bound, _POS_INF))

    def refine_eq(self, bound: float) -> IntervalDomain:
        """Refine self assuming self == bound."""
        return self.meet(IntervalDomain(bound, bound))

    def refine_ne(self, bound: float) -> IntervalDomain:
        """Refine self assuming self ≠ bound (conservative: no-op unless singleton)."""
        if self.is_const() and self.lo == bound:
            return IntervalDomain.bottom()
        # Cannot tighten in general without splitting the interval
        return self

    def __repr__(self) -> str:
        if self.is_bottom():
            return "Interval(⊥)"
        def _fmt(v: float) -> str:
            if v == _NEG_INF:
                return "-∞"
            if v == _POS_INF:
                return "+∞"
            return str(int(v)) if v == int(v) else str(v)
        return f"Interval([{_fmt(self.lo)}, {_fmt(self.hi)}])"


# ═══════════════════════════════════════════════════════════════════════════
#  PART 7 — CONGRUENCE DOMAIN
# ═══════════════════════════════════════════════════════════════════════════
#
#  Represents sets of the form  { a·k + b | k ∈ ℤ }  =  aℤ + b.
#
#  Concretisation:
#    γ(a, b) = { a·k + b | k ∈ ℤ }    where a ≥ 0
#    γ(0, b) = { b }                    (singleton / constant)
#    γ(1, 0) = ℤ                        (⊤)
#    ⊥ is special
#
#  This subsumes parity (stride=2) and divisibility analysis.
#  Often combined with intervals in a reduced product for precision.
# ═══════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True, slots=True)
class CongruenceDomain:
    """
    Congruence domain  aℤ + b  (integers congruent to b modulo a).

    Representation:
        stride = 0, offset = 0  with _is_bot=True  →  ⊥
        stride = 0, offset = n                       →  {n}  (constant)
        stride = 1, offset = 0                       →  ℤ    (⊤)
        stride > 1, offset = b (0 ≤ b < stride)      →  aℤ + b

    Examples
    --------
    >>> a = CongruenceDomain.from_modular(4, 1)  # 4ℤ + 1 = {1, 5, 9, …}
    >>> b = CongruenceDomain.from_modular(4, 3)  # 4ℤ + 3 = {3, 7, 11, …}
    >>> a.join(b)  # {1,3,5,7,9,11,...} = 2ℤ + 1
    Congruence(2ℤ + 1)
    """
    stride: int  # a ≥ 0
    offset: int  # 0 ≤ b < a  (or b = n when a = 0)
    _is_bot: bool = False

    @classmethod
    def bottom(cls) -> CongruenceDomain:
        return cls(stride=0, offset=0, _is_bot=True)

    @classmethod
    def top(cls) -> CongruenceDomain:
        return cls(stride=1, offset=0)

    @classmethod
    def const(cls, n: int) -> CongruenceDomain:
        return cls(stride=0, offset=n)

    @classmethod
    def from_modular(cls, stride: int, offset: int) -> CongruenceDomain:
        """Create aℤ + b, normalising b into [0, a)."""
        if stride < 0:
            stride = -stride
        if stride == 0:
            return cls(stride=0, offset=offset)
        offset = offset % stride
        return cls(stride=stride, offset=offset)

    def is_bottom(self) -> bool:
        return self._is_bot

    def is_top(self) -> bool:
        return not self._is_bot and self.stride == 1

    def is_const(self) -> bool:
        return not self._is_bot and self.stride == 0

    @staticmethod
    def _gcd(a: int, b: int) -> int:
        a, b = abs(a), abs(b)
        while b:
            a, b = b, a % b
        return a

    def leq(self, other: CongruenceDomain) -> bool:
        """aℤ+b ⊑ cℤ+d  ⟺  c | a  ∧  b ≡ d (mod c)."""
        if self.is_bottom():
            return True
        if other.is_bottom():
            return False
        if other.is_top():
            return True
        if self.stride == 0:
            # self = {offset}, check if offset ∈ γ(other)
            if other.stride == 0:
                return self.offset == other.offset
            return self.offset % other.stride == other.offset
        if other.stride == 0:
            return False  # non-singleton ⊑ singleton only if equal
        # c | a  and  b ≡ d mod c
        return (
            self.stride % other.stride == 0
            and self.offset % other.stride == other.offset
        )

    def join(self, other: CongruenceDomain) -> CongruenceDomain:
        """
        Least upper bound:  gcd(a, c, |b-d|)ℤ + (b mod gcd(…)).

        This is the tightest congruence containing both sets.
        """
        if self.is_bottom():
            return other
        if other.is_bottom():
            return self
        g = self._gcd(self.stride, other.stride)
        g = self._gcd(g, abs(self.offset - other.offset))
        if g == 0:
            # Both are constants; if equal → that constant, else → ⊤
            if self.offset == other.offset:
                return self
            return CongruenceDomain.from_modular(
                abs(self.offset - other.offset), self.offset
            )
        return CongruenceDomain.from_modular(g, self.offset % g if g else 0)

    def meet(self, other: CongruenceDomain) -> CongruenceDomain:
        """
        Greatest lower bound via the Chinese Remainder Theorem.

        If there is no integer in both aℤ+b and cℤ+d, the result is ⊥.
        Otherwise, the result is lcm(a,c)ℤ + r where r is the CRT solution.
        """
        if self.is_bottom() or other.is_bottom():
            return CongruenceDomain.bottom()
        if self.is_top():
            return other
        if other.is_top():
            return self
        # CRT: solve  x ≡ b (mod a)  ∧  x ≡ d (mod c)
        a, b = self.stride, self.offset
        c, d = other.stride, other.offset
        if a == 0 and c == 0:
            return self if b == d else CongruenceDomain.bottom()
        if a == 0:
            return self if b % c == d else CongruenceDomain.bottom()
        if c == 0:
            return other if d % a == b else CongruenceDomain.bottom()
        g = self._gcd(a, c)
        if (b - d) % g != 0:
            return CongruenceDomain.bottom()
        lcm = (a * c) // g
        # Extended GCD to find solution
        # b + a*t ≡ d (mod c)  →  a*t ≡ (d-b) (mod c)
        r = self._crt_solve(a, b, c, d)
        if r is None:
            return CongruenceDomain.bottom()
        return CongruenceDomain.from_modular(lcm, r)

    @staticmethod
    def _crt_solve(a: int, b: int, c: int, d: int) -> Optional[int]:
        """Solve x ≡ b (mod a), x ≡ d (mod c) using extended GCD."""
        def ext_gcd(x: int, y: int) -> Tuple[int, int, int]:
            if y == 0:
                return x, 1, 0
            g, s, t = ext_gcd(y, x % y)
            return g, t, s - (x // y) * t

        g, p, _ = ext_gcd(a, c)
        if (d - b) % g != 0:
            return None
        lcm = (a * c) // g
        r = (b + a * ((d - b) // g) * p) % lcm
        return r

    def widen(self, other: CongruenceDomain) -> CongruenceDomain:
        """Widening: in the congruence domain, join already converges
        (GCD can only decrease), so plain join suffices as widening."""
        return self.join(other)

    def narrow(self, other: CongruenceDomain) -> CongruenceDomain:
        return other

    # ---- Abstract arithmetic ---------------------------------------------

    def add(self, other: CongruenceDomain) -> CongruenceDomain:
        """(aℤ+b) + (cℤ+d) = gcd(a,c)ℤ + (b+d)."""
        if self.is_bottom() or other.is_bottom():
            return CongruenceDomain.bottom()
        g = self._gcd(self.stride, other.stride)
        return CongruenceDomain.from_modular(g, self.offset + other.offset)

    def sub(self, other: CongruenceDomain) -> CongruenceDomain:
        """(aℤ+b) - (cℤ+d) = gcd(a,c)ℤ + (b-d)."""
        if self.is_bottom() or other.is_bottom():
            return CongruenceDomain.bottom()
        g = self._gcd(self.stride, other.stride)
        return CongruenceDomain.from_modular(g, self.offset - other.offset)

    def mul(self, other: CongruenceDomain) -> CongruenceDomain:
        """
        (aℤ+b) × (cℤ+d) = gcd(a·d, b·c, a·c)ℤ + b·d.

        Sound but may lose precision for large strides.
        """
        if self.is_bottom() or other.is_bottom():
            return CongruenceDomain.bottom()
        a, b, c, d = self.stride, self.offset, other.stride, other.offset
        g = self._gcd(a * d, b * c)
        g = self._gcd(g, a * c)
        return CongruenceDomain.from_modular(g, b * d)

    def negate(self) -> CongruenceDomain:
        if self.is_bottom():
            return self
        return CongruenceDomain.from_modular(self.stride, -self.offset)

    def __repr__(self) -> str:
        if self.is_bottom():
            return "Congruence(⊥)"
        if self.stride == 0:
            return f"Congruence({{{self.offset}}})"
        if self.stride == 1 and self.offset == 0:
            return "Congruence(ℤ)"
        return f"Congruence({self.stride}ℤ + {self.offset})"


# ═══════════════════════════════════════════════════════════════════════════
#  PART 8 — BITFIELD DOMAIN
# ═══════════════════════════════════════════════════════════════════════════
#
#  Tracks each bit position independently with a three-valued logic:
#    - Definitely 0
#    - Definitely 1
#    - Unknown (could be 0 or 1)
#
#  Represented as two bitmasks:
#    must_one:  bits that are definitely 1
#    may_one:   bits that might be 1
#
#  Invariant:  must_one ⊆ may_one  (i.e.  must_one & ~may_one == 0)
#
#  γ(must_one, may_one) = { n | must_one ⊆ bits(n) ⊆ may_one }
#
#  This domain is excellent for reasoning about flags, permissions,
#  protocol fields, and bit-manipulation code in embedded C.
# ═══════════════════════════════════════════════════════════════════════════

# We fix the bitwidth to 64 bits (covers C's int, long, long long).
_BITWIDTH: Final[int] = 64
_ALL_BITS: Final[int] = (1 << _BITWIDTH) - 1


@dataclass(frozen=True, slots=True)
class BitfieldDomain:
    """
    Bitfield abstract domain — per-bit three-valued tracking.

    Representation:
        must_one:  int   bits that are definitely 1 in all concrete values
        may_one:   int   bits that are possibly 1 in some concrete value

    ⊥:  must_one = ALL_BITS, may_one = 0   (impossible: must ⊄ may)
    ⊤:  must_one = 0, may_one = ALL_BITS   (every bit is unknown)
    """
    must_one: int
    may_one: int

    def __post_init__(self) -> None:
        # Mask to bitwidth
        object.__setattr__(self, "must_one", self.must_one & _ALL_BITS)
        object.__setattr__(self, "may_one", self.may_one & _ALL_BITS)

    @classmethod
    def bottom(cls) -> BitfieldDomain:
        # Convention: must has bits that may doesn't → empty concretisation
        return cls(must_one=_ALL_BITS, may_one=0)

    @classmethod
    def top(cls) -> BitfieldDomain:
        return cls(must_one=0, may_one=_ALL_BITS)

    @classmethod
    def const(cls, n: int) -> BitfieldDomain:
        n = n & _ALL_BITS
        return cls(must_one=n, may_one=n)

    def is_bottom(self) -> bool:
        # ⊥ when must_one has a bit that may_one doesn't
        return (self.must_one & ~self.may_one) != 0

    def is_top(self) -> bool:
        return self.must_one == 0 and self.may_one == _ALL_BITS

    def is_const(self) -> bool:
        """Exactly one concrete value?"""
        return self.must_one == self.may_one and not self.is_bottom()

    def leq(self, other: BitfieldDomain) -> bool:
        if self.is_bottom():
            return True
        if other.is_bottom():
            return False
        # γ(self) ⊆ γ(other) iff other.must ⊆ self.must and self.may ⊆ other.may
        return (
            (other.must_one & ~self.must_one) == 0
            and (self.may_one & ~other.may_one) == 0
        )

    def join(self, other: BitfieldDomain) -> BitfieldDomain:
        if self.is_bottom():
            return other
        if other.is_bottom():
            return self
        return BitfieldDomain(
            must_one=self.must_one & other.must_one,  # weaken: fewer definite 1s
            may_one=self.may_one | other.may_one,      # weaken: more possible 1s
        )

    def meet(self, other: BitfieldDomain) -> BitfieldDomain:
        if self.is_bottom() or other.is_bottom():
            return BitfieldDomain.bottom()
        return BitfieldDomain(
            must_one=self.must_one | other.must_one,  # strengthen
            may_one=self.may_one & other.may_one,      # strengthen
        )

    def widen(self, other: BitfieldDomain) -> BitfieldDomain:
        # Height = 64 per bit × 2 states = bounded; join suffices.
        return self.join(other)

    def narrow(self, other: BitfieldDomain) -> BitfieldDomain:
        return other

    # ---- Abstract bitwise operations -------------------------------------

    def bitwise_and(self, other: BitfieldDomain) -> BitfieldDomain:
        if self.is_bottom() or other.is_bottom():
            return BitfieldDomain.bottom()
        return BitfieldDomain(
            must_one=self.must_one & other.must_one,
            may_one=self.may_one & other.may_one,
        )

    def bitwise_or(self, other: BitfieldDomain) -> BitfieldDomain:
        if self.is_bottom() or other.is_bottom():
            return BitfieldDomain.bottom()
        return BitfieldDomain(
            must_one=self.must_one | other.must_one,
            may_one=self.may_one | other.may_one,
        )

    def bitwise_xor(self, other: BitfieldDomain) -> BitfieldDomain:
        if self.is_bottom() or other.is_bottom():
            return BitfieldDomain.bottom()
        # For XOR, a bit is definitely 1 only if one is must-1 and
        # the other is must-0 (i.e. not in may_one).
        must0_self = ~self.may_one & _ALL_BITS  # bits definitely 0 in self
        must0_other = ~other.may_one & _ALL_BITS
        return BitfieldDomain(
            must_one=(self.must_one & must0_other) | (other.must_one & must0_self),
            may_one=(self.may_one | other.may_one),  # any bit *could* be 1
        )

    def bitwise_not(self) -> BitfieldDomain:
        if self.is_bottom():
            return self
        return BitfieldDomain(
            must_one=(~self.may_one) & _ALL_BITS,
            may_one=(~self.must_one) & _ALL_BITS,
        )

    def __repr__(self) -> str:
        if self.is_bottom():
            return "Bitfield(⊥)"
        if self.is_const():
            return f"Bitfield(0x{self.must_one:x})"
        return f"Bitfield(must=0x{self.must_one:x}, may=0x{self.may_one:x})"


# ═══════════════════════════════════════════════════════════════════════════
#  PART 9 — STRIDED INTERVAL DOMAIN
# ═══════════════════════════════════════════════════════════════════════════
#
#  Combines interval and congruence: represents  s[lo, hi] = { lo + s·k | k ≥ 0, lo + s·k ≤ hi }.
#
#  This is strictly more precise than the interval domain alone for
#  loop induction variables:  for(i=0; i<n; i+=2)  →  2[0, n-1]
#
#  Reference: Reps, Balakrishnan, Lim (2006), "A Set of New
#  Analyses for Exploiting Value-Sets"
# ═══════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True, slots=True)
class StridedIntervalDomain:
    """
    Strided interval  s[lo, hi].

    Concretisation:
        γ(s, lo, hi) = { lo + s·k | k ∈ ℤ≥0, lo + s·k ≤ hi }

    Special cases:
        s=0, lo=hi      →  {lo}  (singleton)
        s=1              →  classical interval [lo, hi]
        lo > hi          →  ⊥

    Examples
    --------
    >>> a = StridedIntervalDomain(2, 0, 10)   # {0, 2, 4, 6, 8, 10}
    >>> b = StridedIntervalDomain(2, 1, 11)   # {1, 3, 5, 7, 9, 11}
    >>> a.join(b)
    StridedInterval(1[0, 11])
    """
    stride: int
    lo: float
    hi: float

    @classmethod
    def bottom(cls) -> StridedIntervalDomain:
        return cls(stride=0, lo=1.0, hi=0.0)

    @classmethod
    def top(cls) -> StridedIntervalDomain:
        return cls(stride=1, lo=_NEG_INF, hi=_POS_INF)

    @classmethod
    def const(cls, n: int) -> StridedIntervalDomain:
        return cls(stride=0, lo=float(n), hi=float(n))

    @classmethod
    def interval(cls, lo: int, hi: int) -> StridedIntervalDomain:
        """Classical interval [lo, hi] (stride=1)."""
        return cls(stride=1, lo=float(lo), hi=float(hi))

    @classmethod
    def strided(cls, stride: int, lo: int, hi: int) -> StridedIntervalDomain:
        if stride < 0:
            stride = -stride
        if stride == 0 and lo == hi:
            return cls(stride=0, lo=float(lo), hi=float(hi))
        if stride == 0:
            stride = 1  # normalise
        return cls(stride=stride, lo=float(lo), hi=float(hi))

    def is_bottom(self) -> bool:
        return self.lo > self.hi

    def is_top(self) -> bool:
        return self.lo == _NEG_INF and self.hi == _POS_INF and self.stride == 1

    @staticmethod
    def _gcd(a: int, b: int) -> int:
        a, b = abs(a), abs(b)
        while b:
            a, b = b, a % b
        return a

    def leq(self, other: StridedIntervalDomain) -> bool:
        if self.is_bottom():
            return True
        if other.is_bottom():
            return False
        if other.lo > self.lo or self.hi > other.hi:
            return False
        if other.stride == 0:
            return self.stride == 0 and self.lo == other.lo
        if self.stride == 0:
            # singleton; check containment
            n = int(self.lo)
            if other.stride == 0:
                return n == int(other.lo)
            return other.lo <= n <= other.hi and (n - int(other.lo)) % other.stride == 0
        # s1[a,b] ⊑ s2[c,d] if [a,b]⊆[c,d] and s2 | s1 and a ≡ c (mod s2)
        return (
            other.stride != 0
            and self.stride % other.stride == 0
            and (int(self.lo) - int(other.lo)) % other.stride == 0
        )

    def join(self, other: StridedIntervalDomain) -> StridedIntervalDomain:
        if self.is_bottom():
            return other
        if other.is_bottom():
            return self
        g = self._gcd(self.stride, other.stride)
        lo_diff = abs(int(self.lo) - int(other.lo)) if math.isfinite(self.lo) and math.isfinite(other.lo) else 1
        g = self._gcd(g, lo_diff)
        new_stride = max(g, 1)
        return StridedIntervalDomain(
            stride=new_stride,
            lo=min(self.lo, other.lo),
            hi=max(self.hi, other.hi),
        )

    def meet(self, other: StridedIntervalDomain) -> StridedIntervalDomain:
        if self.is_bottom() or other.is_bottom():
            return StridedIntervalDomain.bottom()
        new_lo = max(self.lo, other.lo)
        new_hi = min(self.hi, other.hi)
        if new_lo > new_hi:
            return StridedIntervalDomain.bottom()
        # LCM of strides if both non-zero, CRT for offset
        if self.stride == 0 and other.stride == 0:
            return self if self.lo == other.lo else StridedIntervalDomain.bottom()
        if self.stride == 0:
            # check if self.lo is in other
            n = int(self.lo)
            if other.stride != 0 and (n - int(other.lo)) % other.stride == 0:
                return self
            return StridedIntervalDomain.bottom()
        if other.stride == 0:
            n = int(other.lo)
            if self.stride != 0 and (n - int(self.lo)) % self.stride == 0:
                return other
            return StridedIntervalDomain.bottom()
        g = self._gcd(self.stride, other.stride)
        if (int(self.lo) - int(other.lo)) % g != 0:
            return StridedIntervalDomain.bottom()
        lcm = (self.stride * other.stride) // g
        return StridedIntervalDomain(stride=lcm, lo=new_lo, hi=new_hi)

    def widen(self, other: StridedIntervalDomain) -> StridedIntervalDomain:
        if self.is_bottom():
            return other
        if other.is_bottom():
            return self
        g = self._gcd(self.stride, other.stride)
        new_lo = _NEG_INF if other.lo < self.lo else self.lo
        new_hi = _POS_INF if other.hi > self.hi else self.hi
        return StridedIntervalDomain(stride=max(g, 1), lo=new_lo, hi=new_hi)

    def narrow(self, other: StridedIntervalDomain) -> StridedIntervalDomain:
        if self.is_bottom():
            return self
        if other.is_bottom():
            return other
        new_lo = other.lo if self.lo == _NEG_INF else self.lo
        new_hi = other.hi if self.hi == _POS_INF else self.hi
        g = self._gcd(self.stride, other.stride)
        return StridedIntervalDomain(stride=max(g, 1) if g else 1, lo=new_lo, hi=new_hi)

    def to_interval(self) -> IntervalDomain:
        """Project away stride information."""
        if self.is_bottom():
            return IntervalDomain.bottom()
        return IntervalDomain(self.lo, self.hi)

    def __repr__(self) -> str:
        if self.is_bottom():
            return "StridedInterval(⊥)"
        def _fmt(v: float) -> str:
            if v == _NEG_INF:
                return "-∞"
            if v == _POS_INF:
                return "+∞"
            return str(int(v)) if v == int(v) else str(v)
        return f"StridedInterval({self.stride}[{_fmt(self.lo)}, {_fmt(self.hi)}])"


# ═══════════════════════════════════════════════════════════════════════════
#  PART 10 — BOOLEAN DOMAIN
# ═══════════════════════════════════════════════════════════════════════════
#
#  Specialisation of FlatDomain[bool] with logical operations.
#
#            ⊤
#          /   \
#       True  False
#          \   /
#            ⊥
# ═══════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True, slots=True)
class BoolDomain:
    """
    Three-valued boolean domain  {⊥, True, False, ⊤}.

    Used for boolean flag tracking, reachability, and condition evaluation.
    """
    value: Union[bool, _BottomSentinel, _TopSentinel]

    @classmethod
    def bottom(cls) -> BoolDomain:
        return cls(BOTTOM)

    @classmethod
    def top(cls) -> BoolDomain:
        return cls(TOP)

    @classmethod
    def true_(cls) -> BoolDomain:
        return cls(True)

    @classmethod
    def false_(cls) -> BoolDomain:
        return cls(False)

    @classmethod
    def abstract(cls, b: bool) -> BoolDomain:
        return cls(b)

    def is_bottom(self) -> bool:
        return self.value is BOTTOM

    def is_top(self) -> bool:
        return self.value is TOP

    def is_concrete(self) -> bool:
        return isinstance(self.value, bool)

    def leq(self, other: BoolDomain) -> bool:
        if self.is_bottom():
            return True
        if other.is_top():
            return True
        return self.value == other.value

    def join(self, other: BoolDomain) -> BoolDomain:
        if self.is_bottom():
            return other
        if other.is_bottom():
            return self
        if self.value == other.value:
            return self
        return BoolDomain.top()

    def meet(self, other: BoolDomain) -> BoolDomain:
        if self.is_top():
            return other
        if other.is_top():
            return self
        if self.value == other.value:
            return self
        return BoolDomain.bottom()

    def widen(self, other: BoolDomain) -> BoolDomain:
        return self.join(other)

    def narrow(self, other: BoolDomain) -> BoolDomain:
        return other

    # ---- Abstract logical operations -------------------------------------

    def and_(self, other: BoolDomain) -> BoolDomain:
        if self.is_bottom() or other.is_bottom():
            return BoolDomain.bottom()
        # Short-circuit: False ∧ anything = False
        if self.value is False or other.value is False:
            return BoolDomain.false_()
        if self.value is True and other.value is True:
            return BoolDomain.true_()
        return BoolDomain.top()

    def or_(self, other: BoolDomain) -> BoolDomain:
        if self.is_bottom() or other.is_bottom():
            return BoolDomain.bottom()
        if self.value is True or other.value is True:
            return BoolDomain.true_()
        if self.value is False and other.value is False:
            return BoolDomain.false_()
        return BoolDomain.top()

    def not_(self) -> BoolDomain:
        if self.is_bottom() or self.is_top():
            return self
        return BoolDomain(not self.value)

    def __repr__(self) -> str:
        if self.is_bottom():
            return "Bool(⊥)"
        if self.is_top():
            return "Bool(⊤)"
        return f"Bool({self.value})"


# ═══════════════════════════════════════════════════════════════════════════
#  PART 11 — BOUNDED SET DOMAIN  (powerset with cardinality bound)
# ═══════════════════════════════════════════════════════════════════════════
#
#  Tracks up to k concrete values exactly.  If the set exceeds k, it
#  collapses to ⊤.  This is a practical compromise between the full
#  powerset (exponential) and the flat lattice (too imprecise).
#
#  Used in: string value tracking, enum analysis, small set constants.
# ═══════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class SetDomain(Generic[T]):
    """
    Bounded powerset domain with maximum cardinality k.

    When |set| > k, the domain element collapses to ⊤.

    Concretisation:
        γ(S) = S            if S is a concrete set
        γ(⊥) = ∅
        γ(⊤) = Universe

    Parameters
    ----------
    elements : frozenset or None
        The tracked set.  None = ⊤.
    max_size : int
        Maximum number of elements before collapsing to ⊤.  Default 16.
    """
    elements: Optional[FrozenSet[T]]
    max_size: int = 16
    _is_bot: bool = False

    @classmethod
    def bottom(cls, max_size: int = 16) -> SetDomain[T]:
        return cls(elements=frozenset(), max_size=max_size, _is_bot=True)

    @classmethod
    def top(cls, max_size: int = 16) -> SetDomain[T]:
        return cls(elements=None, max_size=max_size)

    @classmethod
    def singleton(cls, v: T, max_size: int = 16) -> SetDomain[T]:
        return cls(elements=frozenset({v}), max_size=max_size)

    @classmethod
    def from_set(cls, s: FrozenSet[T], max_size: int = 16) -> SetDomain[T]:
        if len(s) > max_size:
            return cls.top(max_size)
        return cls(elements=s, max_size=max_size)

    def is_bottom(self) -> bool:
        return self._is_bot

    def is_top(self) -> bool:
        return self.elements is None and not self._is_bot

    def leq(self, other: SetDomain[T]) -> bool:
        if self.is_bottom():
            return True
        if other.is_top():
            return True
        if other.is_bottom():
            return self.is_bottom()
        if self.is_top():
            return False
        assert self.elements is not None and other.elements is not None
        return self.elements <= other.elements

    def join(self, other: SetDomain[T]) -> SetDomain[T]:
        if self.is_bottom():
            return other
        if other.is_bottom():
            return self
        if self.is_top() or other.is_top():
            return SetDomain.top(self.max_size)
        assert self.elements is not None and other.elements is not None
        union = self.elements | other.elements
        if len(union) > self.max_size:
            return SetDomain.top(self.max_size)
        return SetDomain(elements=union, max_size=self.max_size)

    def meet(self, other: SetDomain[T]) -> SetDomain[T]:
        if self.is_bottom() or other.is_bottom():
            return SetDomain.bottom(self.max_size)
        if self.is_top():
            return other
        if other.is_top():
            return self
        assert self.elements is not None and other.elements is not None
        inter = self.elements & other.elements
        if not inter:
            return SetDomain.bottom(self.max_size)
        return SetDomain(elements=inter, max_size=self.max_size)

    def widen(self, other: SetDomain[T]) -> SetDomain[T]:
        # Bounded set has finite height (at most max_size + 2 levels)
        return self.join(other)

    def narrow(self, other: SetDomain[T]) -> SetDomain[T]:
        return other

    def __repr__(self) -> str:
        if self.is_bottom():
            return "Set(⊥)"
        if self.is_top():
            return "Set(⊤)"
        elems = sorted(str(e) for e in self.elements) if self.elements else []
        return f"Set({{{', '.join(elems)}}})"


# ═══════════════════════════════════════════════════════════════════════════
#  PART 12 — PRODUCT DOMAINS  (direct product and reduced product)
# ═══════════════════════════════════════════════════════════════════════════
#
#  The direct product  D₁ × D₂  applies all operations component-wise.
#  It gains the precision of BOTH domains without any communication.
#
#  The reduced product adds a REDUCTION operator ρ that tightens one
#  component using information from the other.  Example: Interval ×
#  Congruence, where learning x ∈ 2ℤ can tighten [3,10] to [4,10].
# ═══════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class ProductDomain:
    """
    Direct product of two abstract domains.

    All operations applied component-wise.  No inter-component reduction.
    For reduced product, use ``ReducedProductDomain``.
    """
    left: Any   # should satisfy AbstractDomain
    right: Any  # should satisfy AbstractDomain

    def is_bottom(self) -> bool:
        return self.left.is_bottom() or self.right.is_bottom()

    def is_top(self) -> bool:
        return self.left.is_top() and self.right.is_top()

    def leq(self, other: ProductDomain) -> bool:
        return self.left.leq(other.left) and self.right.leq(other.right)

    def join(self, other: ProductDomain) -> ProductDomain:
        return ProductDomain(
            left=self.left.join(other.left),
            right=self.right.join(other.right),
        )

    def meet(self, other: ProductDomain) -> ProductDomain:
        return ProductDomain(
            left=self.left.meet(other.left),
            right=self.right.meet(other.right),
        )

    def widen(self, other: ProductDomain) -> ProductDomain:
        return ProductDomain(
            left=self.left.widen(other.left),
            right=self.right.widen(other.right),
        )

    def narrow(self, other: ProductDomain) -> ProductDomain:
        return ProductDomain(
            left=self.left.narrow(other.left),
            right=self.right.narrow(other.right),
        )

    def __repr__(self) -> str:
        return f"({self.left!r} × {self.right!r})"


@dataclass(frozen=True)
class ReducedProductDomain:
    """
    Reduced product of two abstract domains with a reduction operator.

    The reduction  ρ: D₁ × D₂ → D₁ × D₂  is called after every join/meet/
    widen/narrow to propagate information between components.

    Example reduction for Interval × Congruence:
        ([3, 10], 2ℤ+0) →ρ→ ([4, 10], 2ℤ+0)
        (because the smallest even ≥ 3 is 4)
    """
    left: Any
    right: Any
    _reducer: Callable[[Any, Any], Tuple[Any, Any]] = field(
        default=lambda l, r: (l, r),  # identity (= direct product)
        repr=False,
    )

    def _reduce(self, left: Any, right: Any) -> ReducedProductDomain:
        rl, rr = self._reducer(left, right)
        return ReducedProductDomain(left=rl, right=rr, _reducer=self._reducer)

    def is_bottom(self) -> bool:
        return self.left.is_bottom() or self.right.is_bottom()

    def is_top(self) -> bool:
        return self.left.is_top() and self.right.is_top()

    def leq(self, other: ReducedProductDomain) -> bool:
        return self.left.leq(other.left) and self.right.leq(other.right)

    def join(self, other: ReducedProductDomain) -> ReducedProductDomain:
        return self._reduce(
            self.left.join(other.left),
            self.right.join(other.right),
        )

    def meet(self, other: ReducedProductDomain) -> ReducedProductDomain:
        return self._reduce(
            self.left.meet(other.left),
            self.right.meet(other.right),
        )

    def widen(self, other: ReducedProductDomain) -> ReducedProductDomain:
        return self._reduce(
            self.left.widen(other.left),
            self.right.widen(other.right),
        )

    def narrow(self, other: ReducedProductDomain) -> ReducedProductDomain:
        return self._reduce(
            self.left.narrow(other.left),
            self.right.narrow(other.right),
        )

    def __repr__(self) -> str:
        return f"({self.left!r} ×ρ {self.right!r})"


# ---- Pre-built reduction operators ---------------------------------------

def reduce_interval_congruence(
    interval: IntervalDomain, congruence: CongruenceDomain
) -> Tuple[IntervalDomain, CongruenceDomain]:
    """
    Reduction operator for  Interval × Congruence.

    Tightens the interval bounds to the nearest value satisfying the
    congruence constraint.

    Example:
        ([3, 10], 2ℤ+0) → ([4, 10], 2ℤ+0)
        ([0, 100], 7ℤ+3) → ([3, 94], 7ℤ+3)
    """
    if interval.is_bottom() or congruence.is_bottom():
        return IntervalDomain.bottom(), CongruenceDomain.bottom()
    if interval.is_top() or congruence.is_top():
        return interval, congruence
    if congruence.stride == 0:
        # Congruence says "exactly one value"
        n = congruence.offset
        if interval.contains(n):
            return IntervalDomain.const(n), congruence
        return IntervalDomain.bottom(), CongruenceDomain.bottom()
    s, b = congruence.stride, congruence.offset
    # Tighten lower bound: smallest n ≥ lo such that n ≡ b (mod s)
    if math.isfinite(interval.lo):
        lo_int = int(interval.lo)
        remainder = lo_int % s
        target = b % s
        diff = (target - remainder) % s
        new_lo = float(lo_int + diff)
    else:
        new_lo = interval.lo
    # Tighten upper bound: largest n ≤ hi such that n ≡ b (mod s)
    if math.isfinite(interval.hi):
        hi_int = int(interval.hi)
        remainder = hi_int % s
        target = b % s
        diff = (remainder - target) % s
        new_hi = float(hi_int - diff)
    else:
        new_hi = interval.hi
    if new_lo > new_hi:
        return IntervalDomain.bottom(), CongruenceDomain.bottom()
    return IntervalDomain(new_lo, new_hi), congruence


def reduce_interval_sign(
    interval: IntervalDomain, sign: SignDomain
) -> Tuple[IntervalDomain, SignDomain]:
    """
    Reduction operator for  Interval × Sign.

    Mutual tightening:
      - Sign can narrow interval (e.g. POS → lo = max(lo, 1))
      - Interval can sharpen sign (e.g. [5,10] → POS)
    """
    if interval.is_bottom() or sign.is_bottom():
        return IntervalDomain.bottom(), SignDomain.bottom()

    # Sign → Interval reduction
    new_lo, new_hi = interval.lo, interval.hi
    if sign.sign is Sign.POS:
        new_lo = max(new_lo, 1.0)
    elif sign.sign is Sign.NEG:
        new_hi = min(new_hi, -1.0)
    elif sign.sign is Sign.ZERO:
        new_lo = max(new_lo, 0.0)
        new_hi = min(new_hi, 0.0)

    if new_lo > new_hi:
        return IntervalDomain.bottom(), SignDomain.bottom()

    refined_interval = IntervalDomain(new_lo, new_hi)

    # Interval → Sign reduction
    if refined_interval.hi < 0:
        return refined_interval, SignDomain.neg()
    if refined_interval.lo > 0:
        return refined_interval, SignDomain.pos()
    if refined_interval.lo == 0.0 and refined_interval.hi == 0.0:
        return refined_interval, SignDomain.zero()

    return refined_interval, sign


# ═══════════════════════════════════════════════════════════════════════════
#  PART 13 — FUNCTION DOMAIN  (Var → D, pointwise lift)
# ═══════════════════════════════════════════════════════════════════════════
#
#  Maps variable identifiers (int = cppcheck varId) to abstract domain
#  elements.  All operations are lifted pointwise.
#
#  This is the standard "abstract state" used by the dataflow engine:
#  each program point maps to a FunctionDomain (= abstract environment).
# ═══════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class FunctionDomain(Generic[D]):
    """
    Abstract environment:  VarId → D   (pointwise lift of domain D).

    Unmapped variables are implicitly ⊤ (conservative: anything is possible).

    This is the type plugged into ``dataflow_engine.py``'s worklist
    algorithm as the per-program-point lattice element.

    Type Parameters
    ---------------
    D : AbstractDomain
        The underlying per-variable domain (e.g. IntervalDomain).
    """
    mapping: Dict[int, Any] = field(default_factory=dict)  # varId → D
    _default_factory: Callable[[], Any] = field(
        default=lambda: None, repr=False
    )
    _bottom_factory: Callable[[], Any] = field(
        default=lambda: None, repr=False
    )

    def get(self, var_id: int) -> Any:
        """Look up variable.  Returns _default (⊤) if unmapped."""
        return self.mapping.get(var_id, self._default_factory())

    def set(self, var_id: int, value: Any) -> FunctionDomain[D]:
        """Return new state with var_id mapped to value."""
        new_map = dict(self.mapping)
        new_map[var_id] = value
        return FunctionDomain(
            mapping=new_map,
            _default_factory=self._default_factory,
            _bottom_factory=self._bottom_factory,
        )

    def remove(self, var_id: int) -> FunctionDomain[D]:
        """Return new state with var_id unmapped (= ⊤)."""
        new_map = dict(self.mapping)
        new_map.pop(var_id, None)
        return FunctionDomain(
            mapping=new_map,
            _default_factory=self._default_factory,
            _bottom_factory=self._bottom_factory,
        )

    @property
    def var_ids(self) -> FrozenSet[int]:
        return frozenset(self.mapping.keys())

    def is_bottom(self) -> bool:
        """An environment is ⊥ if ANY variable is ⊥ (unsatisfiable)."""
        return any(v.is_bottom() for v in self.mapping.values())

    def is_top(self) -> bool:
        """An environment is ⊤ if the mapping is empty (everything unknown)."""
        return len(self.mapping) == 0

    def leq(self, other: FunctionDomain[D]) -> bool:
        """Pointwise ⊑."""
        all_vars = self.var_ids | other.var_ids
        for vid in all_vars:
            if not self.get(vid).leq(other.get(vid)):
                return False
        return True

    def join(self, other: FunctionDomain[D]) -> FunctionDomain[D]:
        """Pointwise ⊔."""
        all_vars = self.var_ids | other.var_ids
        new_map: Dict[int, Any] = {}
        for vid in all_vars:
            j = self.get(vid).join(other.get(vid))
            if not j.is_top():  # don't store ⊤ explicitly
                new_map[vid] = j
        return FunctionDomain(
            mapping=new_map,
            _default_factory=self._default_factory,
            _bottom_factory=self._bottom_factory,
        )

    def meet(self, other: FunctionDomain[D]) -> FunctionDomain[D]:
        """Pointwise ⊓."""
        all_vars = self.var_ids | other.var_ids
        new_map: Dict[int, Any] = {}
        for vid in all_vars:
            m = self.get(vid).meet(other.get(vid))
            new_map[vid] = m
        return FunctionDomain(
            mapping=new_map,
            _default_factory=self._default_factory,
            _bottom_factory=self._bottom_factory,
        )

    def widen(self, other: FunctionDomain[D]) -> FunctionDomain[D]:
        """Pointwise ∇."""
        all_vars = self.var_ids | other.var_ids
        new_map: Dict[int, Any] = {}
        for vid in all_vars:
            w = self.get(vid).widen(other.get(vid))
            if not w.is_top():
                new_map[vid] = w
        return FunctionDomain(
            mapping=new_map,
            _default_factory=self._default_factory,
            _bottom_factory=self._bottom_factory,
        )

    def narrow(self, other: FunctionDomain[D]) -> FunctionDomain[D]:
        """Pointwise Δ."""
        all_vars = self.var_ids | other.var_ids
        new_map: Dict[int, Any] = {}
        for vid in all_vars:
            n = self.get(vid).narrow(other.get(vid))
            if not n.is_top():
                new_map[vid] = n
        return FunctionDomain(
            mapping=new_map,
            _default_factory=self._default_factory,
            _bottom_factory=self._bottom_factory,
        )

    def __repr__(self) -> str:
        if not self.mapping:
            return "Env(⊤)"
        entries = ", ".join(f"v{k}: {v!r}" for k, v in sorted(self.mapping.items()))
        return f"Env({{{entries}}})"


# ═══════════════════════════════════════════════════════════════════════════
#  PART 14 — FACTORY FUNCTIONS  (convenient domain construction)
# ═══════════════════════════════════════════════════════════════════════════

def make_interval_env() -> FunctionDomain[IntervalDomain]:
    """Create an empty abstract environment over the interval domain."""
    return FunctionDomain(
        mapping={},
        _default_factory=IntervalDomain.top,
        _bottom_factory=IntervalDomain.bottom,
    )


def make_sign_env() -> FunctionDomain[SignDomain]:
    """Create an empty abstract environment over the sign domain."""
    return FunctionDomain(
        mapping={},
        _default_factory=SignDomain.top,
        _bottom_factory=SignDomain.bottom,
    )


def make_constant_env() -> FunctionDomain[ConstantDomain]:
    """Create an empty abstract environment over the constant domain."""
    return FunctionDomain(
        mapping={},
        _default_factory=ConstantDomain.top,
        _bottom_factory=ConstantDomain.bottom,
    )


def make_congruence_env() -> FunctionDomain[CongruenceDomain]:
    """Create an empty abstract environment over the congruence domain."""
    return FunctionDomain(
        mapping={},
        _default_factory=CongruenceDomain.top,
        _bottom_factory=CongruenceDomain.bottom,
    )


def make_parity_env() -> FunctionDomain[ParityDomain]:
    """Create an empty abstract environment over the parity domain."""
    return FunctionDomain(
        mapping={},
        _default_factory=ParityDomain.top,
        _bottom_factory=ParityDomain.bottom,
    )


def make_bitfield_env() -> FunctionDomain[BitfieldDomain]:
    """Create an empty abstract environment over the bitfield domain."""
    return FunctionDomain(
        mapping={},
        _default_factory=BitfieldDomain.top,
        _bottom_factory=BitfieldDomain.bottom,
    )


def make_interval_congruence_env() -> FunctionDomain[ReducedProductDomain]:
    """
    Create an abstract environment over the reduced product
    Interval × Congruence — the most precise standard numerical
    domain short of polyhedra/octagons.
    """
    def _default() -> ReducedProductDomain:
        return ReducedProductDomain(
            left=IntervalDomain.top(),
            right=CongruenceDomain.top(),
            _reducer=reduce_interval_congruence,
        )

    def _bot() -> ReducedProductDomain:
        return ReducedProductDomain(
            left=IntervalDomain.bottom(),
            right=CongruenceDomain.bottom(),
            _reducer=reduce_interval_congruence,
        )

    return FunctionDomain(
        mapping={},
        _default_factory=_default,
        _bottom_factory=_bot,
    )


# ═══════════════════════════════════════════════════════════════════════════
#  PART 15 — PUBLIC API
# ═══════════════════════════════════════════════════════════════════════════

__all__ = [
    # Sentinels
    "BOTTOM", "TOP",
    # Protocol
    "AbstractDomain",
    # Flat
    "FlatDomain",
    # Numeric
    "SignDomain", "Sign",
    "ParityDomain", "Parity",
    "ConstantDomain",
    "IntervalDomain",
    "CongruenceDomain",
    "StridedIntervalDomain",
    # Bitwise
    "BitfieldDomain",
    # Boolean
    "BoolDomain",
    # Collections
    "SetDomain",
    # Products
    "ProductDomain",
    "ReducedProductDomain",
    "reduce_interval_congruence",
    "reduce_interval_sign",
    # Environments
    "FunctionDomain",
    # Factories
    "make_interval_env",
    "make_sign_env",
    "make_constant_env",
    "make_congruence_env",
    "make_parity_env",
    "make_bitfield_env",
    "make_interval_congruence_env",
]
