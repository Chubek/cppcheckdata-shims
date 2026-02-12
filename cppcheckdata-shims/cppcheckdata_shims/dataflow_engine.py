"""
cppcheckdata_shims.dataflow_engine
====================================

A generic, lattice-based dataflow analysis framework operating over
Cppcheck CFGs and call graphs.

This module provides the foundational fixpoint computation engine used by
all higher-level analyses (:mod:`abstract_interp`, :mod:`symbolic_exec`,
:mod:`constraint_engine`).

Theory
------
A dataflow analysis is defined by:

1.  A **lattice** ``(L, ⊑, ⊥, ⊤, ⊔)`` — a partially-ordered set with a
    least element ``⊥``, greatest element ``⊤``, and a join (least upper
    bound) operator ``⊔``.
2.  A **direction** — *forward* (information flows along control-flow edges)
    or *backward* (information flows against control-flow edges).
3.  A **transfer function** ``f : Node × L → L`` — transforms the dataflow
    fact at a CFG node.
4.  An **initial value** for the entry (forward) or exit (backward) node.
5.  A **merge operator** — ``⊔`` (join) for may-analyses or ``⊓`` (meet)
    for must-analyses.

The engine iterates until a **fixpoint** is reached: no node's dataflow
fact changes upon re-application of its transfer function.

Worklist algorithms
-------------------
The engine implements several worklist strategies:

``FIFO``
    Simple BFS-like iteration.  Correct but not optimal.
``LIFO``
    Simple DFS-like iteration.
``RPO`` (Reverse Post-Order)
    The standard for forward analyses — processes predecessors before
    successors, converging in fewer iterations.
``PO`` (Post-Order)
    The standard for backward analyses.
``SCC``
    Processes strongly-connected components together, applying widening
    at loop heads.  Best for analyses with infinite-height lattices.

Interprocedural analysis
------------------------
The interprocedural engine wraps the intraprocedural one.  It processes
functions in **bottom-up** (callee-first) order from the call graph,
computing **function summaries** that map input facts to output facts.
Recursive SCCs are handled by iterating to a fixpoint with widening.

Public API
----------
    Lattice             - abstract base for lattice definitions
    Direction           - forward / backward enum
    WorklistStrategy    - iteration order enum
    TransferFunction    - callable protocol for transfer functions
    DataflowFacts       - mapping from CFG nodes to lattice values
    IntraproceduralSolver   - single-function fixpoint engine
    InterproceduralSolver   - whole-program fixpoint engine
    DataflowResult      - container for analysis results
    run_forward_analysis    - convenience function
    run_backward_analysis   - convenience function
    run_interprocedural     - convenience function

Built-in lattices
-----------------
    TopBottomLattice    - two-element {⊥, ⊤} lattice
    FlatLattice         - flat lattice over a finite set
    PowersetLattice     - powerset lattice (join = union)
    MapLattice          - lattice of maps (variable → value)
    ProductLattice      - product of multiple lattices
    IntervalLattice     - integer intervals [lo, hi] (with widening)
    SignLattice         - abstract sign domain {⊥, -, 0, +, ⊤}

Usage example
-------------
::

    from cppcheckdata_shims.controlflow_graph import build_cfg
    from cppcheckdata_shims.dataflow_engine import (
        PowersetLattice, Direction, IntraproceduralSolver,
        run_forward_analysis,
    )

    cfg = build_cfg(some_function)

    # Reaching definitions: powerset of (variable, definition-site) pairs
    lattice = PowersetLattice()

    def transfer(node, fact_in):
        # kill definitions of variables redefined here, add new definitions
        gen = set()
        kill = set()
        for tok in node.tokens:
            if is_assignment(tok):
                var = tok.astOperand1
                kill |= {d for d in fact_in if d[0] == var.str}
                gen.add((var.str, tok.linenr))
        return (fact_in - kill) | gen

    result = run_forward_analysis(cfg, lattice, transfer)
    for node, fact in result.items():
        print(f"Block {node.id}: {fact}")
"""

from __future__ import annotations

import abc
import copy
import enum
import math
import sys
import time
from collections import OrderedDict, defaultdict, deque
from dataclasses import dataclass, field
from typing import (
    Any,
    Callable,
    Deque,
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
    runtime_checkable,
)


# ===========================================================================
# TYPE VARIABLES
# ===========================================================================

L = TypeVar("L")          # Lattice value type
K = TypeVar("K")          # Key type (for MapLattice)
V = TypeVar("V")          # Value type (for MapLattice)
T = TypeVar("T")          # Generic type


# ===========================================================================
# DIRECTION
# ===========================================================================

class Direction(enum.Enum):
    """Direction of dataflow propagation."""
    FORWARD = "forward"
    BACKWARD = "backward"


# ===========================================================================
# WORKLIST STRATEGY
# ===========================================================================

class WorklistStrategy(enum.Enum):
    """Strategy for selecting the next worklist node."""
    FIFO = "fifo"
    LIFO = "lifo"
    RPO  = "rpo"        # Reverse post-order (best for forward)
    PO   = "po"         # Post-order (best for backward)
    SCC  = "scc"        # SCC-based (best for loops / widening)


# ===========================================================================
# LATTICE — ABSTRACT BASE
# ===========================================================================

class Lattice(abc.ABC, Generic[L]):
    """Abstract base class for a dataflow lattice.

    A lattice ``(L, ⊑, ⊥, ⊤, ⊔)`` must provide:

    - ``bottom()``  → the least element ⊥.
    - ``top()``     → the greatest element ⊤ (may raise if unbounded).
    - ``join(a, b)`` → the least upper bound ``a ⊔ b``.
    - ``leq(a, b)``  → ``True`` iff ``a ⊑ b``.

    Optionally:
    - ``meet(a, b)`` → the greatest lower bound ``a ⊓ b``.
    - ``widen(a, b)`` → a widening operator for infinite-height lattices.
    - ``narrow(a, b)`` → a narrowing operator (dual of widening).
    """

    @abc.abstractmethod
    def bottom(self) -> L:
        """Return the least element ⊥."""
        ...

    @abc.abstractmethod
    def top(self) -> L:
        """Return the greatest element ⊤."""
        ...

    @abc.abstractmethod
    def join(self, a: L, b: L) -> L:
        """Return the least upper bound ``a ⊔ b``."""
        ...

    @abc.abstractmethod
    def leq(self, a: L, b: L) -> bool:
        """Return ``True`` iff ``a ⊑ b``."""
        ...

    def meet(self, a: L, b: L) -> L:
        """Return the greatest lower bound ``a ⊓ b``.

        Default implementation raises ``NotImplementedError``.
        """
        raise NotImplementedError("meet() not implemented for this lattice")

    def widen(self, a: L, b: L) -> L:
        """Widening operator: return an upper bound of ``a`` and ``b``
        that guarantees convergence for infinite-height lattices.

        Default implementation falls back to ``join``.
        """
        return self.join(a, b)

    def narrow(self, a: L, b: L) -> L:
        """Narrowing operator: refine an over-approximation.

        Default implementation returns ``b`` (no narrowing).
        """
        return b

    def eq(self, a: L, b: L) -> bool:
        """Equality: ``a = b`` iff ``a ⊑ b`` and ``b ⊑ a``."""
        return self.leq(a, b) and self.leq(b, a)

    def is_bottom(self, a: L) -> bool:
        """Is ``a`` the bottom element?"""
        return self.eq(a, self.bottom())

    def is_top(self, a: L) -> bool:
        """Is ``a`` the top element?"""
        try:
            return self.eq(a, self.top())
        except NotImplementedError:
            return False

    def join_all(self, values: Iterable[L]) -> L:
        """Join a sequence of values."""
        result = self.bottom()
        for v in values:
            result = self.join(result, v)
        return result

    def copy_value(self, v: L) -> L:
        """Return a deep copy of a lattice value.

        Default uses ``copy.deepcopy``.  Override for performance.
        """
        return copy.deepcopy(v)


# ===========================================================================
# BUILT-IN LATTICES
# ===========================================================================

# ---------- TopBottomLattice ------------------------------------------------

class _TopBottom(enum.Enum):
    BOTTOM = "⊥"
    TOP = "⊤"


class TopBottomLattice(Lattice[_TopBottom]):
    """The simplest lattice: ``{⊥, ⊤}`` with ``⊥ ⊑ ⊤``."""

    def bottom(self) -> _TopBottom:
        return _TopBottom.BOTTOM

    def top(self) -> _TopBottom:
        return _TopBottom.TOP

    def join(self, a: _TopBottom, b: _TopBottom) -> _TopBottom:
        if a is _TopBottom.TOP or b is _TopBottom.TOP:
            return _TopBottom.TOP
        return _TopBottom.BOTTOM

    def leq(self, a: _TopBottom, b: _TopBottom) -> bool:
        if a is _TopBottom.BOTTOM:
            return True
        return b is _TopBottom.TOP

    def meet(self, a: _TopBottom, b: _TopBottom) -> _TopBottom:
        if a is _TopBottom.BOTTOM or b is _TopBottom.BOTTOM:
            return _TopBottom.BOTTOM
        return _TopBottom.TOP


# ---------- FlatLattice -----------------------------------------------------

_FLAT_BOTTOM = object()
_FLAT_TOP = object()


class FlatLattice(Lattice):
    """A flat lattice over a finite (or conceptually finite) set of values.

    ::

            ⊤
          / | \\
         a  b  c  ...
          \\ | /
            ⊥

    Any two distinct non-bottom, non-top elements are incomparable.
    The join of two different concrete values is ⊤.
    """

    _BOTTOM = _FLAT_BOTTOM
    _TOP = _FLAT_TOP

    def bottom(self):
        return self._BOTTOM

    def top(self):
        return self._TOP

    def join(self, a, b):
        if a is self._BOTTOM:
            return b
        if b is self._BOTTOM:
            return a
        if a is self._TOP or b is self._TOP:
            return self._TOP
        if a == b:
            return a
        return self._TOP

    def leq(self, a, b) -> bool:
        if a is self._BOTTOM:
            return True
        if b is self._TOP:
            return True
        return a == b

    def meet(self, a, b):
        if a is self._TOP:
            return b
        if b is self._TOP:
            return a
        if a is self._BOTTOM or b is self._BOTTOM:
            return self._BOTTOM
        if a == b:
            return a
        return self._BOTTOM

    def copy_value(self, v):
        # Flat values are immutable conceptually
        return v


# ---------- PowersetLattice -------------------------------------------------

class PowersetLattice(Lattice[FrozenSet]):
    """Powerset lattice: ``(2^U, ⊆, ∅, U, ∪)``.

    Since the universe is typically unknown in advance, ``top()`` raises
    ``NotImplementedError`` unless a universe is provided at construction.

    Parameters
    ----------
    universe : frozenset, optional
        If provided, ``top()`` returns this set.
    """

    def __init__(self, universe: Optional[FrozenSet] = None) -> None:
        self._universe = universe

    def bottom(self) -> FrozenSet:
        return frozenset()

    def top(self) -> FrozenSet:
        if self._universe is not None:
            return self._universe
        raise NotImplementedError(
            "PowersetLattice.top() requires a universe"
        )

    def join(self, a: FrozenSet, b: FrozenSet) -> FrozenSet:
        return a | b

    def leq(self, a: FrozenSet, b: FrozenSet) -> bool:
        return a <= b

    def meet(self, a: FrozenSet, b: FrozenSet) -> FrozenSet:
        return a & b

    def copy_value(self, v: FrozenSet) -> FrozenSet:
        return v  # frozensets are immutable


# ---------- MapLattice ------------------------------------------------------

class MapLattice(Lattice[Dict]):
    """Lattice of maps from keys to values in a sub-lattice.

    ``MapLattice(value_lattice)`` represents ``Key → ValueLattice``.
    The join is pointwise join; missing keys are implicitly ``⊥``.

    Parameters
    ----------
    value_lattice : Lattice
        The lattice for individual values.
    """

    def __init__(self, value_lattice: Lattice) -> None:
        self.value_lattice = value_lattice

    def bottom(self) -> Dict:
        return {}

    def top(self) -> Dict:
        raise NotImplementedError(
            "MapLattice.top() is not representable (infinite key domain)"
        )

    def join(self, a: Dict, b: Dict) -> Dict:
        result = dict(a)
        vl = self.value_lattice
        for k, v in b.items():
            if k in result:
                result[k] = vl.join(result[k], v)
            else:
                result[k] = v
        return result

    def leq(self, a: Dict, b: Dict) -> bool:
        vl = self.value_lattice
        for k, va in a.items():
            vb = b.get(k, vl.bottom())
            if not vl.leq(va, vb):
                return False
        return True

    def meet(self, a: Dict, b: Dict) -> Dict:
        result = {}
        vl = self.value_lattice
        for k in set(a.keys()) | set(b.keys()):
            va = a.get(k, vl.bottom())
            vb = b.get(k, vl.bottom())
            result[k] = vl.meet(va, vb)
        return result

    def widen(self, a: Dict, b: Dict) -> Dict:
        result = dict(b)
        vl = self.value_lattice
        for k in set(a.keys()) | set(b.keys()):
            va = a.get(k, vl.bottom())
            vb = b.get(k, vl.bottom())
            result[k] = vl.widen(va, vb)
        return result

    def narrow(self, a: Dict, b: Dict) -> Dict:
        result = {}
        vl = self.value_lattice
        for k in set(a.keys()) | set(b.keys()):
            va = a.get(k, vl.bottom())
            vb = b.get(k, vl.bottom())
            result[k] = vl.narrow(va, vb)
        return result

    def copy_value(self, v: Dict) -> Dict:
        vl = self.value_lattice
        return {k: vl.copy_value(val) for k, val in v.items()}


# ---------- ProductLattice --------------------------------------------------

class ProductLattice(Lattice[Tuple]):
    """Product of ``n`` lattices.  Values are tuples of length ``n``.

    Parameters
    ----------
    *lattices : Lattice
        The component lattices.
    """

    def __init__(self, *lattices: Lattice) -> None:
        self.lattices: Tuple[Lattice, ...] = lattices

    def bottom(self) -> Tuple:
        return tuple(lat.bottom() for lat in self.lattices)

    def top(self) -> Tuple:
        return tuple(lat.top() for lat in self.lattices)

    def join(self, a: Tuple, b: Tuple) -> Tuple:
        return tuple(
            lat.join(av, bv)
            for lat, av, bv in zip(self.lattices, a, b)
        )

    def leq(self, a: Tuple, b: Tuple) -> bool:
        return all(
            lat.leq(av, bv)
            for lat, av, bv in zip(self.lattices, a, b)
        )

    def meet(self, a: Tuple, b: Tuple) -> Tuple:
        return tuple(
            lat.meet(av, bv)
            for lat, av, bv in zip(self.lattices, a, b)
        )

    def widen(self, a: Tuple, b: Tuple) -> Tuple:
        return tuple(
            lat.widen(av, bv)
            for lat, av, bv in zip(self.lattices, a, b)
        )

    def narrow(self, a: Tuple, b: Tuple) -> Tuple:
        return tuple(
            lat.narrow(av, bv)
            for lat, av, bv in zip(self.lattices, a, b)
        )

    def copy_value(self, v: Tuple) -> Tuple:
        return tuple(
            lat.copy_value(val)
            for lat, val in zip(self.lattices, v)
        )


# ---------- IntervalLattice -------------------------------------------------

# We represent intervals as (lo, hi) tuples where lo <= hi.
# Special sentinels for -∞ and +∞.
NEG_INF = float("-inf")
POS_INF = float("inf")

# Interval type: (lo, hi) or None for bottom
IntervalValue = Optional[Tuple[float, float]]


class IntervalLattice(Lattice[IntervalValue]):
    """Integer interval lattice ``[lo, hi]`` with widening.

    Values are ``(lo, hi)`` tuples or ``None`` for ⊥.
    ``(-∞, +∞)`` is ⊤.

    Widening thresholds can be provided to improve precision.

    Parameters
    ----------
    thresholds : sequence of int/float, optional
        Widening thresholds.  When widening, instead of jumping to ±∞,
        the engine jumps to the nearest threshold.
    """

    def __init__(
        self,
        thresholds: Optional[Sequence[float]] = None,
    ) -> None:
        self._thresholds: List[float] = sorted(thresholds or [])

    def bottom(self) -> IntervalValue:
        return None

    def top(self) -> IntervalValue:
        return (NEG_INF, POS_INF)

    def join(self, a: IntervalValue, b: IntervalValue) -> IntervalValue:
        if a is None:
            return b
        if b is None:
            return a
        return (min(a[0], b[0]), max(a[1], b[1]))

    def leq(self, a: IntervalValue, b: IntervalValue) -> bool:
        if a is None:
            return True
        if b is None:
            return False
        return b[0] <= a[0] and a[1] <= b[1]

    def meet(self, a: IntervalValue, b: IntervalValue) -> IntervalValue:
        if a is None or b is None:
            return None
        lo = max(a[0], b[0])
        hi = min(a[1], b[1])
        if lo > hi:
            return None
        return (lo, hi)

    def widen(self, a: IntervalValue, b: IntervalValue) -> IntervalValue:
        """Widening with optional thresholds.

        Standard widening:
        - If ``b.lo < a.lo``, set lower bound to ``-∞`` (or nearest threshold).
        - If ``b.hi > a.hi``, set upper bound to ``+∞`` (or nearest threshold).
        """
        if a is None:
            return b
        if b is None:
            return a

        lo = a[0]
        hi = a[1]

        if b[0] < a[0]:
            # Find the largest threshold ≤ b[0], or -∞
            lo = NEG_INF
            for t in self._thresholds:
                if t <= b[0]:
                    lo = t
                else:
                    break
            if lo == NEG_INF and self._thresholds:
                # Use the smallest threshold if it's ≤ b[0]
                if self._thresholds[0] <= b[0]:
                    lo = self._thresholds[0]
                else:
                    lo = NEG_INF

        if b[1] > a[1]:
            # Find the smallest threshold ≥ b[1], or +∞
            hi = POS_INF
            for t in reversed(self._thresholds):
                if t >= b[1]:
                    hi = t
                else:
                    break
            if hi == POS_INF and self._thresholds:
                if self._thresholds[-1] >= b[1]:
                    hi = self._thresholds[-1]
                else:
                    hi = POS_INF

        return (lo, hi)

    def narrow(self, a: IntervalValue, b: IntervalValue) -> IntervalValue:
        """Narrowing: tighten bounds where a has ±∞."""
        if a is None:
            return None
        if b is None:
            return a
        lo = b[0] if a[0] == NEG_INF else a[0]
        hi = b[1] if a[1] == POS_INF else a[1]
        if lo > hi:
            return None
        return (lo, hi)

    def copy_value(self, v: IntervalValue) -> IntervalValue:
        return v  # tuples are immutable

    # ----- Arithmetic helpers -----------------------------------------------

    @staticmethod
    def add(a: IntervalValue, b: IntervalValue) -> IntervalValue:
        if a is None or b is None:
            return None
        return (a[0] + b[0], a[1] + b[1])

    @staticmethod
    def sub(a: IntervalValue, b: IntervalValue) -> IntervalValue:
        if a is None or b is None:
            return None
        return (a[0] - b[1], a[1] - b[0])

    @staticmethod
    def mul(a: IntervalValue, b: IntervalValue) -> IntervalValue:
        if a is None or b is None:
            return None
        products = [
            a[0] * b[0], a[0] * b[1],
            a[1] * b[0], a[1] * b[1],
        ]
        return (min(products), max(products))

    @staticmethod
    def contains(interval: IntervalValue, value: float) -> bool:
        if interval is None:
            return False
        return interval[0] <= value <= interval[1]

    @staticmethod
    def const(value: float) -> IntervalValue:
        return (value, value)


# ---------- SignLattice -----------------------------------------------------

class Sign(enum.Enum):
    """Abstract sign values."""
    BOTTOM = "⊥"
    NEG    = "-"
    ZERO   = "0"
    POS    = "+"
    TOP    = "⊤"


# Pre-computed join table for the sign lattice
_SIGN_JOIN: Dict[Tuple[Sign, Sign], Sign] = {}

def _build_sign_join():
    for s in Sign:
        _SIGN_JOIN[(Sign.BOTTOM, s)] = s
        _SIGN_JOIN[(s, Sign.BOTTOM)] = s
        _SIGN_JOIN[(Sign.TOP, s)] = Sign.TOP
        _SIGN_JOIN[(s, Sign.TOP)] = Sign.TOP
        _SIGN_JOIN[(s, s)] = s
    # Incomparable pairs
    for a, b in [(Sign.NEG, Sign.ZERO), (Sign.NEG, Sign.POS),
                 (Sign.ZERO, Sign.POS)]:
        _SIGN_JOIN[(a, b)] = Sign.TOP
        _SIGN_JOIN[(b, a)] = Sign.TOP

_build_sign_join()


class SignLattice(Lattice[Sign]):
    """Sign lattice: ``{⊥, -, 0, +, ⊤}``."""

    def bottom(self) -> Sign:
        return Sign.BOTTOM

    def top(self) -> Sign:
        return Sign.TOP

    def join(self, a: Sign, b: Sign) -> Sign:
        return _SIGN_JOIN[(a, b)]

    def leq(self, a: Sign, b: Sign) -> bool:
        if a is Sign.BOTTOM:
            return True
        if b is Sign.TOP:
            return True
        return a is b

    def meet(self, a: Sign, b: Sign) -> Sign:
        if a is Sign.TOP:
            return b
        if b is Sign.TOP:
            return a
        if a is b:
            return a
        return Sign.BOTTOM

    def copy_value(self, v: Sign) -> Sign:
        return v


# ===========================================================================
# TRANSFER FUNCTION PROTOCOL
# ===========================================================================

@runtime_checkable
class TransferFunction(Protocol[L]):
    """Protocol for a transfer function.

    A transfer function takes a CFG node and the incoming dataflow fact,
    and returns the outgoing dataflow fact.

    It may also optionally implement ``edge_transfer`` for edge-specific
    refinements (e.g., branch conditions).
    """

    def __call__(self, node: Any, fact_in: L) -> L:
        """Apply the transfer function.

        Parameters
        ----------
        node : CFGNode
            The basic block / CFG node.
        fact_in : L
            The incoming dataflow fact (after merge of predecessors).

        Returns
        -------
        L
            The outgoing dataflow fact.
        """
        ...


class EdgeTransferFunction(Protocol[L]):
    """Optional edge-sensitive transfer (for branch refinement).

    Parameters
    ----------
    edge : CFGEdge
        The CFG edge.
    fact : L
        The fact at the source of the edge.

    Returns
    -------
    L
        The refined fact along this edge.
    """

    def __call__(self, edge: Any, fact: L) -> L:
        ...


# ===========================================================================
# DATAFLOW RESULT
# ===========================================================================

@dataclass
class DataflowResult(Generic[L]):
    """Container for dataflow analysis results.

    Attributes
    ----------
    facts_in : dict
        Map from CFG node → incoming (pre-node) dataflow fact.
    facts_out : dict
        Map from CFG node → outgoing (post-node) dataflow fact.
    iterations : int
        Number of worklist iterations performed.
    converged : bool
        Whether the analysis reached a fixpoint (vs. hitting the limit).
    elapsed_seconds : float
        Wall-clock time.
    direction : Direction
        Analysis direction.
    widening_applied : int
        Number of times widening was applied.
    """
    facts_in: Dict[Any, L] = field(default_factory=dict)
    facts_out: Dict[Any, L] = field(default_factory=dict)
    iterations: int = 0
    converged: bool = False
    elapsed_seconds: float = 0.0
    direction: Direction = Direction.FORWARD
    widening_applied: int = 0

    def fact_at(self, node, *, before: bool = True) -> L:
        """Return the fact at a node.

        Parameters
        ----------
        node : CFGNode
            The CFG node.
        before : bool
            If ``True``, return the incoming fact (before the node's
            transfer).  If ``False``, return the outgoing fact.
        """
        if before:
            return self.facts_in.get(node)
        return self.facts_out.get(node)

    def items_in(self) -> Iterable[Tuple[Any, L]]:
        """Iterate over ``(node, fact_in)`` pairs."""
        return self.facts_in.items()

    def items_out(self) -> Iterable[Tuple[Any, L]]:
        """Iterate over ``(node, fact_out)`` pairs."""
        return self.facts_out.items()


# ===========================================================================
# INTRAPROCEDURAL SOLVER
# ===========================================================================

class IntraproceduralSolver(Generic[L]):
    """Fixpoint engine for intraprocedural dataflow analysis.

    Parameters
    ----------
    cfg : CFG
        The control-flow graph (from :mod:`controlflow_graph`).
    lattice : Lattice[L]
        The dataflow lattice.
    transfer : callable(node, L) → L
        The transfer function.
    direction : Direction
        Forward or backward.
    strategy : WorklistStrategy
        Worklist iteration order.
    edge_transfer : callable(edge, L) → L, optional
        Edge-sensitive refinement (e.g., branch conditions).
    initial_value : L, optional
        Initial fact for the entry/exit node.  Defaults to ``lattice.bottom()``.
    use_widening : bool
        Whether to apply widening at loop heads.
    widening_delay : int
        Number of iterations before widening kicks in at a node.
    max_iterations : int
        Safety bound on iterations.
    use_narrowing : bool
        Whether to perform a narrowing pass after the widening fixpoint.
    narrowing_iterations : int
        Maximum number of narrowing iterations.
    """

    def __init__(
        self,
        cfg,
        lattice: Lattice[L],
        transfer: Callable,
        direction: Direction = Direction.FORWARD,
        strategy: WorklistStrategy = WorklistStrategy.RPO,
        edge_transfer: Optional[Callable] = None,
        initial_value: Optional[L] = None,
        use_widening: bool = False,
        widening_delay: int = 2,
        max_iterations: int = 1_000_000,
        use_narrowing: bool = False,
        narrowing_iterations: int = 5,
    ) -> None:
        self.cfg = cfg
        self.lattice = lattice
        self.transfer = transfer
        self.direction = direction
        self.strategy = strategy
        self.edge_transfer = edge_transfer
        self.initial_value = (
            initial_value if initial_value is not None
            else lattice.bottom()
        )
        self.use_widening = use_widening
        self.widening_delay = widening_delay
        self.max_iterations = max_iterations
        self.use_narrowing = use_narrowing
        self.narrowing_iterations = narrowing_iterations

        # Pre-compute node orderings and loop heads
        self._nodes: List = list(cfg.nodes.values()) if hasattr(cfg, 'nodes') else list(cfg)
        self._entry = getattr(cfg, 'entry', None)
        self._exit = getattr(cfg, 'exit', None)
        self._loop_heads: Set = set()
        self._node_visit_count: Dict = defaultdict(int)
        self._widening_count: int = 0

    def solve(self) -> DataflowResult[L]:
        """Run the analysis to fixpoint.

        Returns
        -------
        DataflowResult[L]
        """
        t0 = time.monotonic()

        # Determine entry node and direction-specific predecessors/successors
        if self.direction == Direction.FORWARD:
            start_node = self._entry
            predecessors = self._get_predecessors
            successors = self._get_successors
        else:
            start_node = self._exit
            predecessors = self._get_successors
            successors = self._get_predecessors

        # Initialise facts
        facts_in: Dict[Any, L] = {}
        facts_out: Dict[Any, L] = {}
        bot = self.lattice.bottom()
        for node in self._nodes:
            facts_in[node] = self.lattice.copy_value(bot)
            facts_out[node] = self.lattice.copy_value(bot)

        if start_node is not None:
            facts_in[start_node] = self.lattice.copy_value(self.initial_value)

        # Detect loop heads (for widening)
        if self.use_widening:
            self._detect_loop_heads()

        # Build worklist
        worklist = self._build_initial_worklist()
        in_worklist: Set = set(id(n) for n in worklist)

        iterations = 0

        while worklist and iterations < self.max_iterations:
            node = self._pop_worklist(worklist, in_worklist)
            iterations += 1
            self._node_visit_count[id(node)] += 1

            # Merge incoming facts
            preds = predecessors(node)
            if preds:
                merged = self._merge_incoming(
                    node, preds, facts_out if self.direction == Direction.FORWARD else facts_in
                )
            else:
                merged = self.lattice.copy_value(facts_in[node])

            # For non-start nodes, merge with current fact_in in case of
            # initial value at start
            if node is start_node:
                merged = self.lattice.join(
                    merged,
                    self.lattice.copy_value(self.initial_value),
                )

            # Apply widening at loop heads
            if self.use_widening and node in self._loop_heads:
                visit_count = self._node_visit_count[id(node)]
                if visit_count > self.widening_delay:
                    old = facts_in.get(node, self.lattice.bottom())
                    merged = self.lattice.widen(old, merged)
                    self._widening_count += 1

            # Check if input changed
            old_in = facts_in[node]
            if self.lattice.leq(merged, old_in) and self.lattice.leq(old_in, merged):
                # No change — skip
                continue

            facts_in[node] = merged

            # Apply transfer function
            new_out = self.transfer(node, merged)
            facts_out[node] = new_out

            # Propagate to successors
            for succ in successors(node):
                succ_id = id(succ)
                if succ_id not in in_worklist:
                    worklist.append(succ)
                    in_worklist.add(succ_id)

        converged = len(worklist) == 0 or iterations < self.max_iterations

        # Narrowing pass
        if self.use_narrowing and self.use_widening and converged:
            self._narrowing_pass(
                facts_in, facts_out, start_node,
                predecessors, successors,
            )

        elapsed = time.monotonic() - t0

        result = DataflowResult(
            facts_in=facts_in,
            facts_out=facts_out,
            iterations=iterations,
            converged=converged,
            elapsed_seconds=elapsed,
            direction=self.direction,
            widening_applied=self._widening_count,
        )
        return result

    # ----- Internal helpers -------------------------------------------------

    def _get_predecessors(self, node) -> List:
        """Get CFG predecessors of a node."""
        preds = []
        in_edges = getattr(node, "in_edges", None)
        if in_edges:
            for edge in in_edges:
                src = getattr(edge, "source", None) or getattr(edge, "src", None)
                if src is not None:
                    preds.append(src)
        elif hasattr(node, "predecessors"):
            preds = list(node.predecessors)
        return preds

    def _get_successors(self, node) -> List:
        """Get CFG successors of a node."""
        succs = []
        out_edges = getattr(node, "out_edges", None)
        if out_edges:
            for edge in out_edges:
                dst = getattr(edge, "target", None) or getattr(edge, "dst", None)
                if dst is not None:
                    succs.append(dst)
        elif hasattr(node, "successors"):
            succs = list(node.successors)
        return succs

    def _get_edge(self, src, dst):
        """Get the CFG edge from src to dst, if available."""
        out_edges = getattr(src, "out_edges", [])
        for edge in out_edges:
            target = getattr(edge, "target", None) or getattr(edge, "dst", None)
            if target is dst:
                return edge
        return None

    def _merge_incoming(self, node, preds, source_facts: Dict) -> L:
        """Merge facts from predecessors, optionally applying edge transfer."""
        lat = self.lattice
        result = lat.bottom()
        for pred in preds:
            fact = source_facts.get(pred, lat.bottom())
            # Apply edge transfer if available
            if self.edge_transfer is not None:
                edge = self._get_edge(pred, node) if self.direction == Direction.FORWARD else self._get_edge(node, pred)
                if edge is not None:
                    fact = self.edge_transfer(edge, fact)
            result = lat.join(result, fact)
        return result

    def _detect_loop_heads(self) -> None:
        """Detect loop heads in the CFG for widening.

        Uses the CFG's loop information if available; otherwise, detects
        back edges via a DFS.
        """
        # Try to use pre-computed loop info
        cfg = self.cfg
        if hasattr(cfg, "natural_loops"):
            try:
                loops = cfg.natural_loops()
                for header, _body in loops:
                    self._loop_heads.add(header)
                return
            except Exception:
                pass

        # Fallback: DFS to find back edges
        visited: Set = set()
        in_stack: Set = set()

        def dfs(node):
            nid = id(node)
            if nid in visited:
                return
            visited.add(nid)
            in_stack.add(nid)
            for succ in self._get_successors(node):
                sid = id(succ)
                if sid in in_stack:
                    # Back edge: succ is a loop head
                    self._loop_heads.add(succ)
                elif sid not in visited:
                    dfs(succ)
            in_stack.discard(nid)

        if self._entry is not None:
            dfs(self._entry)

    def _build_initial_worklist(self) -> Deque:
        """Build the initial worklist based on the chosen strategy."""
        if self.strategy == WorklistStrategy.RPO and self.direction == Direction.FORWARD:
            order = self._reverse_postorder()
        elif self.strategy == WorklistStrategy.PO and self.direction == Direction.BACKWARD:
            order = self._postorder()
        elif self.strategy == WorklistStrategy.RPO and self.direction == Direction.BACKWARD:
            order = self._postorder()
        elif self.strategy == WorklistStrategy.PO and self.direction == Direction.FORWARD:
            order = self._reverse_postorder()
        elif self.strategy == WorklistStrategy.SCC:
            order = self._scc_order()
        else:
            order = list(self._nodes)

        return deque(order)

    def _pop_worklist(self, worklist: Deque, in_worklist: Set):
        """Pop the next node from the worklist."""
        if self.strategy == WorklistStrategy.LIFO:
            node = worklist.pop()
        else:
            node = worklist.popleft()
        in_worklist.discard(id(node))
        return node

    def _reverse_postorder(self) -> List:
        """Compute reverse post-order of CFG nodes."""
        visited: Set = set()
        order: List = []

        def dfs(node):
            nid = id(node)
            if nid in visited:
                return
            visited.add(nid)
            for succ in self._get_successors(node):
                dfs(succ)
            order.append(node)

        start = self._entry if self.direction == Direction.FORWARD else self._exit
        if start is not None:
            dfs(start)
        # Add any unreachable nodes
        for n in self._nodes:
            if id(n) not in visited:
                dfs(n)

        order.reverse()
        return order

    def _postorder(self) -> List:
        """Compute post-order of CFG nodes."""
        visited: Set = set()
        order: List = []

        def dfs(node):
            nid = id(node)
            if nid in visited:
                return
            visited.add(nid)
            for succ in self._get_successors(node):
                dfs(succ)
            order.append(node)

        start = self._entry if self.direction == Direction.FORWARD else self._exit
        if start is not None:
            dfs(start)
        for n in self._nodes:
            if id(n) not in visited:
                dfs(n)

        return order

    def _scc_order(self) -> List:
        """SCC-based ordering: process inner SCCs first."""
        # Tarjan's SCC
        index_counter = [0]
        stack: List = []
        lowlink: Dict[int, int] = {}
        index: Dict[int, int] = {}
        on_stack: Set[int] = set()
        sccs: List[List] = []

        def strongconnect(v):
            vid = id(v)
            index[vid] = index_counter[0]
            lowlink[vid] = index_counter[0]
            index_counter[0] += 1
            stack.append(v)
            on_stack.add(vid)

            for w in self._get_successors(v):
                wid = id(w)
                if wid not in index:
                    strongconnect(w)
                    lowlink[vid] = min(lowlink[vid], lowlink[wid])
                elif wid in on_stack:
                    lowlink[vid] = min(lowlink[vid], index[wid])

            if lowlink[vid] == index[vid]:
                scc = []
                while True:
                    w = stack.pop()
                    on_stack.discard(id(w))
                    scc.append(w)
                    if id(w) == vid:
                        break
                sccs.append(scc)

        for v in self._nodes:
            if id(v) not in index:
                strongconnect(v)

        # sccs is in reverse topological order (inner first) — flatten
        result = []
        for scc in sccs:
            # Mark all multi-node SCC members as loop heads
            if len(scc) > 1:
                for n in scc:
                    self._loop_heads.add(n)
            result.extend(scc)
        return result

    def _narrowing_pass(
        self,
        facts_in: Dict,
        facts_out: Dict,
        start_node,
        predecessors,
        successors,
    ) -> None:
        """Run a narrowing pass to tighten over-approximations."""
        for _iteration in range(self.narrowing_iterations):
            changed = False
            for node in self._nodes:
                preds = predecessors(node)
                if preds:
                    merged = self._merge_incoming(
                        node, preds,
                        facts_out if self.direction == Direction.FORWARD else facts_in,
                    )
                else:
                    merged = self.lattice.copy_value(facts_in[node])

                if node is start_node:
                    merged = self.lattice.join(merged, self.initial_value)

                # Narrow
                old_in = facts_in[node]
                narrowed = self.lattice.narrow(old_in, merged)

                if not self.lattice.eq(narrowed, old_in):
                    facts_in[node] = narrowed
                    facts_out[node] = self.transfer(node, narrowed)
                    changed = True

            if not changed:
                break


# ===========================================================================
# INTERPROCEDURAL SOLVER
# ===========================================================================

@dataclass
class FunctionSummary(Generic[L]):
    """Summary of a function's effect on the dataflow state.

    Attributes
    ----------
    function : cppcheckdata.Function
        The function.
    input_fact : L
        The dataflow fact at function entry.
    output_fact : L
        The dataflow fact at function exit.
    cfg : CFG
        The function's CFG.
    intra_result : DataflowResult[L]
        The full intraprocedural result.
    """
    function: Any = None
    input_fact: Any = None
    output_fact: Any = None
    cfg: Any = None
    intra_result: Optional[DataflowResult] = None


class InterproceduralSolver(Generic[L]):
    """Interprocedural fixpoint engine.

    Analyses functions bottom-up through the call graph, computing
    function summaries.  For recursive SCCs, iterates to fixpoint
    with widening.

    Parameters
    ----------
    callgraph : CallGraph
        From :mod:`callgraph`.
    cfgs : dict
        Map from ``cppcheckdata.Function`` (or function Id) to ``CFG``.
    lattice : Lattice[L]
        The dataflow lattice.
    transfer_factory : callable(function, cfg) → TransferFunction
        Factory that creates a transfer function for each function.
        The transfer function may consult summaries of callees.
    direction : Direction
        Forward or backward.
    strategy : WorklistStrategy
        Intraprocedural worklist strategy.
    initial_value_factory : callable(function) → L, optional
        Produces the initial value for each function.  Defaults to ⊥.
    use_widening : bool
        Widening for intraprocedural analysis.
    widening_delay : int
        Intraprocedural widening delay.
    max_scc_iterations : int
        Maximum iterations for recursive SCC fixpoints.
    max_intra_iterations : int
        Maximum iterations for each intraprocedural solve.
    summary_join : callable(L, L) → L, optional
        How to join summaries from multiple callers.  Defaults to
        ``lattice.join``.
    call_transfer : callable(call_edge, summary, fact_at_call) → L, optional
        How to apply a callee summary at a call site.  If ``None``,
        the callee's output fact replaces the caller's fact.
    """

    def __init__(
        self,
        callgraph,
        cfgs: Dict,
        lattice: Lattice[L],
        transfer_factory: Callable,
        direction: Direction = Direction.FORWARD,
        strategy: WorklistStrategy = WorklistStrategy.RPO,
        initial_value_factory: Optional[Callable] = None,
        use_widening: bool = False,
        widening_delay: int = 2,
        max_scc_iterations: int = 100,
        max_intra_iterations: int = 100_000,
        summary_join: Optional[Callable] = None,
        call_transfer: Optional[Callable] = None,
        edge_transfer_factory: Optional[Callable] = None,
        use_narrowing: bool = False,
        narrowing_iterations: int = 5,
    ) -> None:
        self.callgraph = callgraph
        self.cfgs = cfgs
        self.lattice = lattice
        self.transfer_factory = transfer_factory
        self.direction = direction
        self.strategy = strategy
        self.initial_value_factory = initial_value_factory or (
            lambda _func: lattice.bottom()
        )
        self.use_widening = use_widening
        self.widening_delay = widening_delay
        self.max_scc_iterations = max_scc_iterations
        self.max_intra_iterations = max_intra_iterations
        self.summary_join = summary_join or lattice.join
        self.call_transfer = call_transfer
        self.edge_transfer_factory = edge_transfer_factory
        self.use_narrowing = use_narrowing
        self.narrowing_iterations = narrowing_iterations

        # Results
        self.summaries: Dict[str, FunctionSummary[L]] = {}
        self.results: Dict[str, DataflowResult[L]] = {}

    def solve(self) -> Dict[str, FunctionSummary[L]]:
        """Run the interprocedural analysis.

        Returns
        -------
        dict[str, FunctionSummary[L]]
            Map from function id to its summary.
        """
        cg = self.callgraph
        sccs = cg.strongly_connected_components()

        # Process SCCs in reverse topological order (callees first)
        for scc in sccs:
            # Filter to real functions with CFGs
            func_nodes = [
                n for n in scc
                if n.function is not None and self._get_cfg(n) is not None
            ]
            if not func_nodes:
                continue

            if len(func_nodes) == 1 and not func_nodes[0].is_recursive:
                # Simple case: non-recursive function
                self._analyze_function(func_nodes[0])
            else:
                # Recursive SCC: iterate to fixpoint
                self._analyze_recursive_scc(func_nodes)

        return self.summaries

    def _get_cfg(self, cg_node):
        """Look up the CFG for a call graph node."""
        func = cg_node.function
        if func is None:
            return None
        # Try by function object
        if func in self.cfgs:
            return self.cfgs[func]
        # Try by function Id
        fid = getattr(func, "Id", None)
        if fid and fid in self.cfgs:
            return self.cfgs[fid]
        # Try by function name
        fname = getattr(func, "name", None)
        if fname and fname in self.cfgs:
            return self.cfgs[fname]
        return None

    def _analyze_function(self, cg_node) -> FunctionSummary[L]:
        """Run intraprocedural analysis on a single function."""
        func = cg_node.function
        cfg = self._get_cfg(cg_node)
        fid = cg_node.id

        # Check if we already have a summary
        if fid in self.summaries:
            return self.summaries[fid]

        initial = self.initial_value_factory(func)

        # Create the transfer function
        transfer = self.transfer_factory(func, cfg)

        # Create edge transfer if factory provided
        edge_xfer = None
        if self.edge_transfer_factory is not None:
            edge_xfer = self.edge_transfer_factory(func, cfg)

        solver = IntraproceduralSolver(
            cfg=cfg,
            lattice=self.lattice,
            transfer=transfer,
            direction=self.direction,
            strategy=self.strategy,
            edge_transfer=edge_xfer,
            initial_value=initial,
            use_widening=self.use_widening,
            widening_delay=self.widening_delay,
            max_iterations=self.max_intra_iterations,
            use_narrowing=self.use_narrowing,
            narrowing_iterations=self.narrowing_iterations,
        )

        result = solver.solve()
        self.results[fid] = result

        # Extract summary: input at entry, output at exit
        cfg_entry = getattr(cfg, "entry", None)
        cfg_exit = getattr(cfg, "exit", None)
        input_fact = result.facts_in.get(cfg_entry, self.lattice.bottom())
        output_fact = result.facts_out.get(cfg_exit, self.lattice.bottom())

        # For backward analysis, swap
        if self.direction == Direction.BACKWARD:
            input_fact, output_fact = output_fact, input_fact

        summary = FunctionSummary(
            function=func,
            input_fact=input_fact,
            output_fact=output_fact,
            cfg=cfg,
            intra_result=result,
        )
        self.summaries[fid] = summary
        return summary

    def _analyze_recursive_scc(self, func_nodes: List) -> None:
        """Analyze a recursive SCC by iterating to fixpoint."""
        lat = self.lattice

        # Initialise summaries with bottom
        prev_summaries: Dict[str, L] = {}
        for node in func_nodes:
            prev_summaries[node.id] = lat.bottom()
            self.summaries[node.id] = FunctionSummary(
                function=node.function,
                input_fact=lat.bottom(),
                output_fact=lat.bottom(),
                cfg=self._get_cfg(node),
            )

        for iteration in range(self.max_scc_iterations):
            changed = False

            for node in func_nodes:
                summary = self._analyze_function_with_existing_summaries(node)
                new_output = summary.output_fact
                old_output = prev_summaries.get(node.id, lat.bottom())

                # Widening for SCC-level convergence
                if iteration > self.widening_delay:
                    new_output = lat.widen(old_output, new_output)

                if not lat.eq(new_output, old_output):
                    changed = True
                    prev_summaries[node.id] = new_output
                    self.summaries[node.id] = FunctionSummary(
                        function=node.function,
                        input_fact=summary.input_fact,
                        output_fact=new_output,
                        cfg=summary.cfg,
                        intra_result=summary.intra_result,
                    )

            if not changed:
                break

    def _analyze_function_with_existing_summaries(
        self, cg_node
    ) -> FunctionSummary[L]:
        """Analyze a function using current (possibly incomplete) summaries."""
        func = cg_node.function
        cfg = self._get_cfg(cg_node)
        fid = cg_node.id

        initial = self.initial_value_factory(func)
        transfer = self.transfer_factory(func, cfg)

        edge_xfer = None
        if self.edge_transfer_factory is not None:
            edge_xfer = self.edge_transfer_factory(func, cfg)

        solver = IntraproceduralSolver(
            cfg=cfg,
            lattice=self.lattice,
            transfer=transfer,
            direction=self.direction,
            strategy=self.strategy,
            edge_transfer=edge_xfer,
            initial_value=initial,
            use_widening=self.use_widening,
            widening_delay=self.widening_delay,
            max_iterations=self.max_intra_iterations,
            use_narrowing=self.use_narrowing,
            narrowing_iterations=self.narrowing_iterations,
        )

        result = solver.solve()
        self.results[fid] = result

        cfg_entry = getattr(cfg, "entry", None)
        cfg_exit = getattr(cfg, "exit", None)
        input_fact = result.facts_in.get(cfg_entry, self.lattice.bottom())
        output_fact = result.facts_out.get(cfg_exit, self.lattice.bottom())

        if self.direction == Direction.BACKWARD:
            input_fact, output_fact = output_fact, input_fact

        return FunctionSummary(
            function=func,
            input_fact=input_fact,
            output_fact=output_fact,
            cfg=cfg,
            intra_result=result,
        )

    def get_summary(self, function_or_id) -> Optional[FunctionSummary[L]]:
        """Look up a function summary.

        Parameters
        ----------
        function_or_id : str or cppcheckdata.Function
            The function's Id or object.
        """
        if isinstance(function_or_id, str):
            return self.summaries.get(function_or_id)
        fid = getattr(function_or_id, "Id", None)
        if fid:
            return self.summaries.get(fid)
        return None

    def get_result(self, function_or_id) -> Optional[DataflowResult[L]]:
        """Look up the intraprocedural result for a function."""
        if isinstance(function_or_id, str):
            return self.results.get(function_or_id)
        fid = getattr(function_or_id, "Id", None)
        if fid:
            return self.results.get(fid)
        return None


# ===========================================================================
# CONVENIENCE FUNCTIONS
# ===========================================================================

def run_forward_analysis(
    cfg,
    lattice: Lattice[L],
    transfer: Callable,
    *,
    initial_value: Optional[L] = None,
    edge_transfer: Optional[Callable] = None,
    strategy: WorklistStrategy = WorklistStrategy.RPO,
    use_widening: bool = False,
    widening_delay: int = 2,
    max_iterations: int = 1_000_000,
    use_narrowing: bool = False,
    narrowing_iterations: int = 5,
) -> DataflowResult[L]:
    """Run a forward dataflow analysis on a single CFG.

    Parameters
    ----------
    cfg : CFG
        The control-flow graph.
    lattice : Lattice[L]
        The dataflow lattice.
    transfer : callable(node, L) → L
        The transfer function.
    initial_value : L, optional
        Initial fact for the entry node.
    edge_transfer : callable(edge, L) → L, optional
        Edge-sensitive refinement.
    strategy : WorklistStrategy
        Worklist order.
    use_widening : bool
        Whether to apply widening at loop heads.
    widening_delay : int
        Iterations before widening.
    max_iterations : int
        Safety bound.
    use_narrowing : bool
        Whether to narrow after widening.
    narrowing_iterations : int
        Max narrowing iterations.

    Returns
    -------
    DataflowResult[L]
    """
    solver = IntraproceduralSolver(
        cfg=cfg,
        lattice=lattice,
        transfer=transfer,
        direction=Direction.FORWARD,
        strategy=strategy,
        edge_transfer=edge_transfer,
        initial_value=initial_value,
        use_widening=use_widening,
        widening_delay=widening_delay,
        max_iterations=max_iterations,
        use_narrowing=use_narrowing,
        narrowing_iterations=narrowing_iterations,
    )
    return solver.solve()


def run_backward_analysis(
    cfg,
    lattice: Lattice[L],
    transfer: Callable,
    *,
    initial_value: Optional[L] = None,
    edge_transfer: Optional[Callable] = None,
    strategy: WorklistStrategy = WorklistStrategy.PO,
    use_widening: bool = False,
    widening_delay: int = 2,
    max_iterations: int = 1_000_000,
    use_narrowing: bool = False,
    narrowing_iterations: int = 5,
) -> DataflowResult[L]:
    """Run a backward dataflow analysis on a single CFG.

    Parameters
    ----------
    cfg : CFG
        The control-flow graph.
    lattice : Lattice[L]
        The dataflow lattice.
    transfer : callable(node, L) → L
        The transfer function (applied in reverse).
    initial_value : L, optional
        Initial fact for the exit node.
    edge_transfer : callable(edge, L) → L, optional
        Edge-sensitive refinement.
    strategy : WorklistStrategy
        Worklist order.
    use_widening : bool
        Whether to apply widening.
    widening_delay : int
        Iterations before widening.
    max_iterations : int
        Safety bound.
    use_narrowing : bool
        Whether to narrow.
    narrowing_iterations : int
        Max narrowing iterations.

    Returns
    -------
    DataflowResult[L]
    """
    solver = IntraproceduralSolver(
        cfg=cfg,
        lattice=lattice,
        transfer=transfer,
        direction=Direction.BACKWARD,
        strategy=strategy,
        edge_transfer=edge_transfer,
        initial_value=initial_value,
        use_widening=use_widening,
        widening_delay=widening_delay,
        max_iterations=max_iterations,
        use_narrowing=use_narrowing,
        narrowing_iterations=narrowing_iterations,
    )
    return solver.solve()


def run_interprocedural(
    callgraph,
    cfgs: Dict,
    lattice: Lattice[L],
    transfer_factory: Callable,
    *,
    direction: Direction = Direction.FORWARD,
    strategy: WorklistStrategy = WorklistStrategy.RPO,
    initial_value_factory: Optional[Callable] = None,
    use_widening: bool = False,
    widening_delay: int = 2,
    max_scc_iterations: int = 100,
    max_intra_iterations: int = 100_000,
    edge_transfer_factory: Optional[Callable] = None,
    use_narrowing: bool = False,
    narrowing_iterations: int = 5,
) -> Dict[str, FunctionSummary[L]]:
    """Run an interprocedural dataflow analysis.

    Parameters
    ----------
    callgraph : CallGraph
        From :mod:`callgraph`.
    cfgs : dict
        Map from function (or function Id/name) to CFG.
    lattice : Lattice[L]
        The dataflow lattice.
    transfer_factory : callable(function, cfg) → callable(node, L) → L
        Factory producing per-function transfer functions.
    direction : Direction
        Forward or backward.
    strategy : WorklistStrategy
        Intraprocedural worklist order.
    initial_value_factory : callable(function) → L, optional
        Produces the initial value per function.
    use_widening : bool
        Enable widening.
    widening_delay : int
        Delay before widening.
    max_scc_iterations : int
        Max iterations for recursive SCCs.
    max_intra_iterations : int
        Max intraprocedural iterations.
    edge_transfer_factory : callable(function, cfg) → callable(edge, L) → L, optional
        Factory for edge-sensitive transfer.
    use_narrowing : bool
        Enable narrowing.
    narrowing_iterations : int
        Max narrowing iterations.

    Returns
    -------
    dict[str, FunctionSummary[L]]
        Map from function id to summary.
    """
    solver = InterproceduralSolver(
        callgraph=callgraph,
        cfgs=cfgs,
        lattice=lattice,
        transfer_factory=transfer_factory,
        direction=direction,
        strategy=strategy,
        initial_value_factory=initial_value_factory,
        use_widening=use_widening,
        widening_delay=widening_delay,
        max_scc_iterations=max_scc_iterations,
        max_intra_iterations=max_intra_iterations,
        edge_transfer_factory=edge_transfer_factory,
        use_narrowing=use_narrowing,
        narrowing_iterations=narrowing_iterations,
    )
    return solver.solve()


# ===========================================================================
# PRE-BUILT ANALYSIS TEMPLATES
# ===========================================================================

class ReachingDefinitionsAnalysis:
    """Ready-to-use reaching definitions analysis.

    A *definition* is a ``(variable_name, token_id)`` pair.
    The lattice is a powerset of such pairs.

    Parameters
    ----------
    cfg : CFG
        The control-flow graph.
    """

    def __init__(self, cfg) -> None:
        self.cfg = cfg
        self.lattice = PowersetLattice()

    def transfer(self, node, fact_in: FrozenSet) -> FrozenSet:
        """Gen/Kill transfer for reaching definitions."""
        gen: Set[Tuple[str, str]] = set()
        kill: Set[Tuple[str, str]] = set()

        tokens = getattr(node, "tokens", [])
        for tok in tokens:
            # Look for assignments: token is '=' and lhs is a variable
            if tok.str == "=" and not getattr(tok, "isComparisonOp", False):
                op1 = getattr(tok, "astOperand1", None)
                if op1 is not None and getattr(op1, "isName", False):
                    var_name = op1.str
                    tok_id = getattr(tok, "Id", str(id(tok)))
                    # Kill all existing defs of this variable
                    kill |= {d for d in fact_in if d[0] == var_name}
                    gen.add((var_name, tok_id))

            # Also handle ++ and --
            if tok.str in ("++", "--"):
                op1 = getattr(tok, "astOperand1", None)
                if op1 is not None and getattr(op1, "isName", False):
                    var_name = op1.str
                    tok_id = getattr(tok, "Id", str(id(tok)))
                    kill |= {d for d in fact_in if d[0] == var_name}
                    gen.add((var_name, tok_id))

        return (fact_in - kill) | frozenset(gen)

    def run(self) -> DataflowResult[FrozenSet]:
        """Execute the analysis."""
        return run_forward_analysis(
            self.cfg, self.lattice, self.transfer,
            initial_value=frozenset(),
        )


class LiveVariablesAnalysis:
    """Ready-to-use live variables analysis (backward).

    A variable is *live* at a point if its current value may be read
    before being overwritten.

    Parameters
    ----------
    cfg : CFG
        The control-flow graph.
    """

    def __init__(self, cfg) -> None:
        self.cfg = cfg
        self.lattice = PowersetLattice()

    def transfer(self, node, fact_out: FrozenSet) -> FrozenSet:
        """Gen/Kill transfer for liveness (backward)."""
        gen: Set[str] = set()
        kill: Set[str] = set()

        tokens = getattr(node, "tokens", [])
        # Process tokens in reverse order for backward analysis
        for tok in reversed(tokens):
            # Definitions (kills)
            if tok.str == "=" and not getattr(tok, "isComparisonOp", False):
                op1 = getattr(tok, "astOperand1", None)
                if op1 is not None and getattr(op1, "isName", False):
                    kill.add(op1.str)
                    # Uses in RHS
                    op2 = getattr(tok, "astOperand2", None)
                    if op2 is not None:
                        self._collect_uses(op2, gen)

            elif tok.str in ("++", "--"):
                op1 = getattr(tok, "astOperand1", None)
                if op1 is not None and getattr(op1, "isName", False):
                    kill.add(op1.str)
                    gen.add(op1.str)  # also a use
            else:
                # Any variable reference is a use
                if getattr(tok, "isName", False) and not getattr(tok, "function", None):
                    var = getattr(tok, "variable", None)
                    if var is not None:
                        gen.add(tok.str)

        return (fact_out - frozenset(kill)) | frozenset(gen)

    def _collect_uses(self, tok, uses: Set[str]) -> None:
        """Recursively collect variable uses in an expression AST."""
        if tok is None:
            return
        if getattr(tok, "isName", False) and getattr(tok, "variable", None):
            uses.add(tok.str)
        self._collect_uses(getattr(tok, "astOperand1", None), uses)
        self._collect_uses(getattr(tok, "astOperand2", None), uses)

    def run(self) -> DataflowResult[FrozenSet]:
        """Execute the analysis."""
        return run_backward_analysis(
            self.cfg, self.lattice, self.transfer,
            initial_value=frozenset(),
        )


class AvailableExpressionsAnalysis:
    """Ready-to-use available expressions analysis (forward, must).

    An expression is *available* at a point if it has been computed on
    every path reaching that point and its operands have not been
    redefined since.

    Uses intersection (meet) as the merge operator — this is a *must*
    analysis.  We implement it over the powerset lattice with meet = ∩.

    Parameters
    ----------
    cfg : CFG
        The control-flow graph.
    """

    def __init__(self, cfg) -> None:
        self.cfg = cfg
        # For must-analysis we use intersection as join
        # We wrap PowersetLattice with inverted join/leq
        self.lattice = _InvertedPowersetLattice()

    def transfer(self, node, fact_in: FrozenSet) -> FrozenSet:
        """Gen/Kill for available expressions."""
        gen: Set[str] = set()
        kill_vars: Set[str] = set()

        tokens = getattr(node, "tokens", [])
        for tok in tokens:
            # Collect expressions
            if tok.str in ("+", "-", "*", "/", "%", "<<", ">>",
                           "&", "|", "^", "&&", "||"):
                expr_str = self._expr_to_string(tok)
                if expr_str:
                    gen.add(expr_str)

            # Collect kills (redefined variables)
            if tok.str == "=" and not getattr(tok, "isComparisonOp", False):
                op1 = getattr(tok, "astOperand1", None)
                if op1 and getattr(op1, "isName", False):
                    kill_vars.add(op1.str)
            if tok.str in ("++", "--"):
                op1 = getattr(tok, "astOperand1", None)
                if op1 and getattr(op1, "isName", False):
                    kill_vars.add(op1.str)

        # Kill any expression that mentions a redefined variable
        killed = frozenset(
            expr for expr in fact_in
            if any(var in expr for var in kill_vars)
        )
        return (fact_in - killed) | frozenset(gen)

    def _expr_to_string(self, tok) -> Optional[str]:
        """Convert an expression AST to a canonical string."""
        if tok is None:
            return None
        op1 = getattr(tok, "astOperand1", None)
        op2 = getattr(tok, "astOperand2", None)
        if op1 is None:
            return tok.str
        s1 = self._expr_to_string(op1)
        s2 = self._expr_to_string(op2)
        if s1 and s2:
            return f"({s1} {tok.str} {s2})"
        if s1:
            return f"({tok.str} {s1})"
        return tok.str

    def run(self) -> DataflowResult[FrozenSet]:
        """Execute the analysis."""
        # For must-analysis: initial value at entry is empty set,
        # and merge is intersection
        return run_forward_analysis(
            self.cfg, self.lattice, self.transfer,
            initial_value=frozenset(),
        )


class _InvertedPowersetLattice(Lattice[FrozenSet]):
    """Powerset lattice with intersection as join (for must-analyses).

    In this lattice:
    - ⊥ = universal set (represented as ``None`` — "all expressions")
    - ⊤ = empty set
    - join = intersection (must hold on all paths)

    We use ``None`` as a sentinel for the universal set since we can't
    enumerate all possible expressions.
    """

    _UNIVERSAL = None  # sentinel for "all expressions"

    def bottom(self) -> FrozenSet:
        return self._UNIVERSAL  # type: ignore

    def top(self) -> FrozenSet:
        return frozenset()

    def join(self, a, b) -> FrozenSet:
        """Intersection."""
        if a is self._UNIVERSAL:
            return b
        if b is self._UNIVERSAL:
            return a
        return a & b

    def leq(self, a, b) -> bool:
        """a ⊑ b means a ⊇ b (inverted subset)."""
        if b is self._UNIVERSAL:
            return True
        if a is self._UNIVERSAL:
            return False
        return b <= a  # b subset of a

    def meet(self, a, b) -> FrozenSet:
        """Union."""
        if a is self._UNIVERSAL or b is self._UNIVERSAL:
            return self._UNIVERSAL  # type: ignore
        return a | b

    def eq(self, a, b) -> bool:
        if a is self._UNIVERSAL and b is self._UNIVERSAL:
            return True
        if a is self._UNIVERSAL or b is self._UNIVERSAL:
            return False
        return a == b

    def copy_value(self, v):
        return v  # frozensets are immutable; None is singleton


class VeryBusyExpressionsAnalysis:
    """Ready-to-use very busy expressions analysis (backward, must).

    An expression is *very busy* at a point if it will definitely be
    evaluated before any of its operands are redefined, regardless of
    which execution path is taken.

    Parameters
    ----------
    cfg : CFG
        The control-flow graph.
    """

    def __init__(self, cfg) -> None:
        self.cfg = cfg
        self.lattice = _InvertedPowersetLattice()

    def transfer(self, node, fact_out: FrozenSet) -> FrozenSet:
        """Gen/Kill for very busy expressions (backward)."""
        gen: Set[str] = set()
        kill_vars: Set[str] = set()

        tokens = getattr(node, "tokens", [])
        for tok in reversed(tokens):
            if tok.str in ("+", "-", "*", "/", "%", "<<", ">>",
                           "&", "|", "^", "&&", "||"):
                expr_str = self._expr_to_string(tok)
                if expr_str:
                    gen.add(expr_str)

            if tok.str == "=" and not getattr(tok, "isComparisonOp", False):
                op1 = getattr(tok, "astOperand1", None)
                if op1 and getattr(op1, "isName", False):
                    kill_vars.add(op1.str)
            if tok.str in ("++", "--"):
                op1 = getattr(tok, "astOperand1", None)
                if op1 and getattr(op1, "isName", False):
                    kill_vars.add(op1.str)

        if fact_out is None:
            remaining = None
        else:
            killed = frozenset(
                expr for expr in fact_out
                if any(var in expr for var in kill_vars)
            )
            remaining = fact_out - killed

        if remaining is None:
            return remaining  # universal set stays universal
        return remaining | frozenset(gen)

    def _expr_to_string(self, tok) -> Optional[str]:
        if tok is None:
            return None
        op1 = getattr(tok, "astOperand1", None)
        op2 = getattr(tok, "astOperand2", None)
        if op1 is None:
            return tok.str
        s1 = self._expr_to_string(op1)
        s2 = self._expr_to_string(op2)
        if s1 and s2:
            return f"({s1} {tok.str} {s2})"
        if s1:
            return f"({tok.str} {s1})"
        return tok.str

    def run(self) -> DataflowResult[FrozenSet]:
        return run_backward_analysis(
            self.cfg, self.lattice, self.transfer,
            initial_value=frozenset(),
        )


# ===========================================================================
# MONOTONICITY CHECKER (development / debugging utility)
# ===========================================================================

def check_monotonicity(
    lattice: Lattice[L],
    transfer: Callable,
    node: Any,
    samples: Sequence[L],
) -> bool:
    """Check that ``transfer(node, ·)`` is monotone on the given samples.

    For every pair ``(a, b)`` in *samples* where ``a ⊑ b``, verifies
    that ``transfer(node, a) ⊑ transfer(node, b)``.

    This is a development/debugging utility — it cannot prove monotonicity
    in general, only detect violations.

    Parameters
    ----------
    lattice : Lattice[L]
    transfer : callable
    node : CFGNode
    samples : sequence of L
        Sample lattice values.

    Returns
    -------
    bool
        ``True`` if no violation found.
    """
    for i, a in enumerate(samples):
        for j, b in enumerate(samples):
            if lattice.leq(a, b):
                fa = transfer(node, a)
                fb = transfer(node, b)
                if not lattice.leq(fa, fb):
                    return False
    return True
