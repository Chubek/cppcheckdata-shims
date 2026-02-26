# cppcheckdata_shims/transition_system.py  (NOT asm.py)
"""
Explicit-state transition system built on top of abstract interpretation.

This module provides:
  - ExplicitStateGraph: explored abstract state space as a labeled digraph
  - TraceReconstructor: given a target state, find a concrete path from entry
  - BoundedExplorer: explore up to depth k, collecting property violations
  - SafetyChecker: verify that an invariant holds at all reachable states

cppcheckdata_shims/transition_system.py

Lightweight explicit-state exploration layer over the abstract interpretation
substrate.  Provides counterexample generation and bounded safety checking
without the full weight of an ASM or model-checking framework.
"""

from __future__ import annotations

import hashlib
import json
from collections import deque
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import (
    Any,
    Callable,
    Deque,
    Dict,
    FrozenSet,
    Generic,
    Iterable,
    List,
    Optional,
    Protocol,
    Sequence,
    Set,
    Tuple,
    TypeVar,
)

# ---------------------------------------------------------------------------
# Imports from the existing substrate
# ---------------------------------------------------------------------------
# These would be real imports in the actual package:
#   from .interval import Interval, IntervalDomain
#   from .abstract_state import AbstractState, AbstractStore
#   from .abstract_executor import AbstractExecutor, StepResult
#   from .cfg import CFG, BasicBlock
#   from .fixpoint import FixpointEngine
#   from .widening import widen, WideningStrategy

# For this standalone design document, we use forward references / protocols.

# ---------------------------------------------------------------------------
# Type variables
# ---------------------------------------------------------------------------

S = TypeVar("S")          # abstract state type
A = TypeVar("A")          # action / transition label type
P = TypeVar("P")          # property type

# ---------------------------------------------------------------------------
# Protocols — structural typing for substrate integration
# ---------------------------------------------------------------------------

class AbstractStateProtocol(Protocol):
    """Minimal interface an abstract state must satisfy."""

    def fingerprint(self) -> str:
        """Return a deterministic hash string for duplicate detection."""
        ...

    def is_bottom(self) -> bool:
        """True if this state is unreachable (⊥)."""
        ...

    def subsumes(self, other: AbstractStateProtocol) -> bool:
        """True if self ⊒ other in the abstract domain's partial order."""
        ...


class TransferProtocol(Protocol[S, A]):
    """Computes successor abstract states."""

    def successors(self, state: S) -> Iterable[Tuple[A, S]]:
        """Yield (action, successor_state) pairs from *state*."""
        ...


class PropertyProtocol(Protocol[S]):
    """A safety property: an invariant that must hold at every reachable state."""

    @property
    def name(self) -> str: ...

    def holds(self, state: S) -> bool:
        """Return True if the property is satisfied in *state*."""
        ...

    def diagnostic(self, state: S) -> str:
        """Human-readable explanation of why the property is violated."""
        ...

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

class ExplorationStatus(Enum):
    """Outcome of a bounded exploration run."""
    SAFE = auto()            # all reachable states satisfy all properties
    VIOLATION_FOUND = auto() # at least one property violated
    DEPTH_EXCEEDED = auto()  # exploration budget exhausted, inconclusive
    STATE_LIMIT = auto()     # too many abstract states, inconclusive


@dataclass(frozen=True)
class Transition(Generic[A]):
    """A single edge in the explicit state graph."""
    source_id: str           # fingerprint of source state
    action: A                # label (e.g., token, CFG edge, function call)
    target_id: str           # fingerprint of target state


@dataclass
class TraceStep(Generic[S, A]):
    """One step in a concrete counterexample trace."""
    state: S
    action: Optional[A]      # None for the initial state
    location: Optional[str]  # source file:line if available

    def __str__(self) -> str:
        act = f" --[{self.action}]--> " if self.action else "[init] "
        loc = f" @ {self.location}" if self.location else ""
        return f"{act}{self.state}{loc}"


@dataclass
class Counterexample(Generic[S, A]):
    """A witness trace demonstrating a property violation."""
    property_name: str
    diagnostic: str
    trace: List[TraceStep[S, A]]
    depth: int

    def pretty(self) -> str:
        lines = [
            f"=== Counterexample for property '{self.property_name}' ===",
            f"Depth: {self.depth}",
            f"Diagnosis: {self.diagnostic}",
            "Trace:",
        ]
        for i, step in enumerate(self.trace):
            lines.append(f"  [{i}] {step}")
        return "\n".join(lines)


@dataclass
class ExplorationResult(Generic[S, A]):
    """Full result of an exploration run."""
    status: ExplorationStatus
    states_explored: int
    transitions_explored: int
    max_depth_reached: int
    counterexamples: List[Counterexample[S, A]] = field(default_factory=list)
    state_count_by_depth: Dict[int, int] = field(default_factory=dict)

    @property
    def is_safe(self) -> bool:
        return self.status == ExplorationStatus.SAFE

    @property
    def is_conclusive(self) -> bool:
        return self.status in (ExplorationStatus.SAFE,
                               ExplorationStatus.VIOLATION_FOUND)

    def summary(self) -> str:
        lines = [
            f"Status: {self.status.name}",
            f"States explored: {self.states_explored}",
            f"Transitions explored: {self.transitions_explored}",
            f"Max depth reached: {self.max_depth_reached}",
        ]
        if self.counterexamples:
            lines.append(f"Counterexamples found: {len(self.counterexamples)}")
            for ce in self.counterexamples:
                lines.append(f"  - {ce.property_name}: {ce.diagnostic}")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Explicit State Graph
# ---------------------------------------------------------------------------

class ExplicitStateGraph(Generic[S, A]):
    """
    The explored portion of the abstract state space, stored as a labeled
    directed graph.

    Nodes are abstract states (identified by fingerprint).
    Edges are transitions labeled with actions.

    This is *not* a full model — it's the reachable fragment discovered
    during bounded exploration.
    """

    def __init__(self) -> None:
        self._states: Dict[str, S] = {}                 # id → state
        self._transitions: List[Transition[A]] = []
        self._successors: Dict[str, List[Tuple[A, str]]] = {}
        self._predecessors: Dict[str, List[Tuple[A, str]]] = {}
        self._depth: Dict[str, int] = {}                # id → discovery depth
        self._initial_id: Optional[str] = None

    # -- Mutation --------------------------------------------------------

    def add_state(self, state: S, fp: str, depth: int) -> bool:
        """Add a state. Returns True if it was genuinely new."""
        if fp in self._states:
            return False
        self._states[fp] = state
        self._depth[fp] = depth
        self._successors.setdefault(fp, [])
        self._predecessors.setdefault(fp, [])
        return True

    def set_initial(self, fp: str) -> None:
        self._initial_id = fp

    def add_transition(self, src_fp: str, action: A, tgt_fp: str) -> None:
        t = Transition(src_fp, action, tgt_fp)
        self._transitions.append(t)
        self._successors.setdefault(src_fp, []).append((action, tgt_fp))
        self._predecessors.setdefault(tgt_fp, []).append((action, src_fp))

    # -- Query -----------------------------------------------------------

    @property
    def num_states(self) -> int:
        return len(self._states)

    @property
    def num_transitions(self) -> int:
        return len(self._transitions)

    def get_state(self, fp: str) -> Optional[S]:
        return self._states.get(fp)

    def reachable_from(self, fp: str) -> Set[str]:
        """BFS forward-reachable state IDs from *fp*."""
        visited: Set[str] = set()
        q: Deque[str] = deque([fp])
        while q:
            cur = q.popleft()
            if cur in visited:
                continue
            visited.add(cur)
            for _, tgt in self._successors.get(cur, []):
                q.append(tgt)
        return visited

    def path_to(self, target_fp: str) -> Optional[List[Tuple[Optional[A], str]]]:
        """BFS shortest path from initial state to *target_fp*.

        Returns a list of (action, state_id) pairs, or None if unreachable.
        """
        if self._initial_id is None:
            return None
        if target_fp == self._initial_id:
            return [(None, self._initial_id)]

        visited: Set[str] = {self._initial_id}
        parent: Dict[str, Tuple[A, str]] = {}
        q: Deque[str] = deque([self._initial_id])

        while q:
            cur = q.popleft()
            for action, tgt in self._successors.get(cur, []):
                if tgt not in visited:
                    visited.add(tgt)
                    parent[tgt] = (action, cur)
                    if tgt == target_fp:
                        # Reconstruct path
                        path: List[Tuple[Optional[A], str]] = []
                        node = tgt
                        while node in parent:
                            act, prev = parent[node]
                            path.append((act, node))
                            node = prev
                        path.append((None, self._initial_id))
                        path.reverse()
                        return path
                    q.append(tgt)
        return None

    def to_dot(self, label_fn: Optional[Callable[[S], str]] = None) -> str:
        """Export the graph in Graphviz DOT format."""
        lines = ["digraph ExplicitStateGraph {", "  rankdir=LR;"]
        for fp, state in self._states.items():
            label = label_fn(state) if label_fn else fp[:12]
            shape = "doublecircle" if fp == self._initial_id else "circle"
            lines.append(f'  "{fp[:12]}" [label="{label}", shape={shape}];')
        for t in self._transitions:
            lines.append(
                f'  "{t.source_id[:12]}" -> "{t.target_id[:12]}" '
                f'[label="{t.action}"];'
            )
        lines.append("}")
        return "\n".join(lines)

    def depth_histogram(self) -> Dict[int, int]:
        hist: Dict[int, int] = {}
        for d in self._depth.values():
            hist[d] = hist.get(d, 0) + 1
        return dict(sorted(hist.items()))


# ---------------------------------------------------------------------------
# Bounded Explorer — the core algorithm
# ---------------------------------------------------------------------------

class BoundedExplorer(Generic[S, A]):
    """
    Explores the abstract state space using BFS up to a configurable depth
    and state count limit, checking safety properties at each visited state.

    This is the counterpart to the FSM-generation algorithm in Grieskamp et al.
    ("Generating Finite State Machines from Abstract State Machines"), adapted
    for abstract interpretation over C programs rather than AsmL specs.

    Key differences from the paper's algorithm:
      - States are *abstract* (intervals, signs, etc.) not concrete
      - Subsumption checking prunes already-covered states
      - No need for grouping functions — the abstract domain IS the grouping
      - Properties are checked inline during exploration
    """

    def __init__(
        self,
        transfer: TransferProtocol[S, A],
        *,
        max_depth: int = 100,
        max_states: int = 10_000,
        use_subsumption: bool = True,
        stop_on_first_violation: bool = False,
    ) -> None:
        self._transfer = transfer
        self._max_depth = max_depth
        self._max_states = max_states
        self._use_subsumption = use_subsumption
        self._stop_on_first = stop_on_first_violation

    def _fingerprint(self, state: S) -> str:
        """Compute a deterministic identifier for an abstract state."""
        if hasattr(state, "fingerprint"):
            return state.fingerprint()  # type: ignore[union-attr]
        # Fallback: repr-based hash (less efficient, but always works)
        return hashlib.sha256(repr(state).encode()).hexdigest()[:32]

    def _is_subsumed(self, state: S, graph: ExplicitStateGraph[S, A]) -> bool:
        """Check if *state* is already covered by an existing state."""
        if not self._use_subsumption:
            return False
        fp = self._fingerprint(state)
        existing = graph.get_state(fp)
        if existing is not None:
            return True
        # Full subsumption check against all visited states
        # (expensive — in production, use a more efficient index)
        if hasattr(state, "subsumes"):
            for _, existing_state in graph._states.items():
                if hasattr(existing_state, "subsumes"):
                    if existing_state.subsumes(state):  # type: ignore
                        return True
        return False

    def explore(
        self,
        initial_state: S,
        properties: Sequence[PropertyProtocol[S]] = (),
        *,
        location_fn: Optional[Callable[[A], str]] = None,
    ) -> ExplorationResult[S, A]:
        """
        Perform bounded BFS exploration from *initial_state*.

        Parameters
        ----------
        initial_state :
            The entry abstract state (e.g., top-of-main with all variables ⊤).
        properties :
            Safety invariants to check at every reachable state.
        location_fn :
            Optional function mapping actions to source locations (file:line).

        Returns
        -------
        ExplorationResult
            Contains status, statistics, and any counterexamples found.
        """
        graph: ExplicitStateGraph[S, A] = ExplicitStateGraph()
        counterexamples: List[Counterexample[S, A]] = []

        init_fp = self._fingerprint(initial_state)
        graph.add_state(initial_state, init_fp, depth=0)
        graph.set_initial(init_fp)

        # BFS queue: (state, fingerprint, depth)
        queue: Deque[Tuple[S, str, int]] = deque()
        queue.append((initial_state, init_fp, 0))

        states_explored = 0
        transitions_explored = 0
        max_depth_seen = 0
        depth_counts: Dict[int, int] = {0: 1}

        # -- Check properties on initial state --
        for prop in properties:
            if not prop.holds(initial_state):
                ce = Counterexample(
                    property_name=prop.name,
                    diagnostic=prop.diagnostic(initial_state),
                    trace=[TraceStep(initial_state, None, None)],
                    depth=0,
                )
                counterexamples.append(ce)
                if self._stop_on_first:
                    return ExplorationResult(
                        status=ExplorationStatus.VIOLATION_FOUND,
                        states_explored=1,
                        transitions_explored=0,
                        max_depth_reached=0,
                        counterexamples=counterexamples,
                        state_count_by_depth=depth_counts,
                    )

        # -- Main BFS loop --
        while queue:
            # Budget checks
            if graph.num_states >= self._max_states:
                return ExplorationResult(
                    status=ExplorationStatus.STATE_LIMIT,
                    states_explored=states_explored,
                    transitions_explored=transitions_explored,
                    max_depth_reached=max_depth_seen,
                    counterexamples=counterexamples,
                    state_count_by_depth=depth_counts,
                )

            current_state, current_fp, depth = queue.popleft()
            states_explored += 1

            if depth >= self._max_depth:
                continue   # don't expand beyond the depth bound

            # Expand successors
            for action, succ_state in self._transfer.successors(current_state):
                transitions_explored += 1

                # Skip unreachable (⊥) successors
                if hasattr(succ_state, "is_bottom") and succ_state.is_bottom():
                    continue

                succ_fp = self._fingerprint(succ_state)
                succ_depth = depth + 1
                max_depth_seen = max(max_depth_seen, succ_depth)

                # Record transition regardless of whether state is new
                graph.add_transition(current_fp, action, succ_fp)

                # Subsumption / duplicate check
                if self._is_subsumed(succ_state, graph):
                    continue

                # New state!
                graph.add_state(succ_state, succ_fp, succ_depth)
                depth_counts[succ_depth] = depth_counts.get(succ_depth, 0) + 1

                # Check properties
                for prop in properties:
                    if not prop.holds(succ_state):
                        # Build counterexample trace
                        path = graph.path_to(succ_fp)
                        trace: List[TraceStep[S, A]] = []
                        if path:
                            for act, sid in path:
                                s = graph.get_state(sid)
                                loc = location_fn(act) if (act and location_fn) else None
                                trace.append(TraceStep(s, act, loc))
                        else:
                            trace.append(TraceStep(succ_state, action, None))

                        ce = Counterexample(
                            property_name=prop.name,
                            diagnostic=prop.diagnostic(succ_state),
                            trace=trace,
                            depth=succ_depth,
                        )
                        counterexamples.append(ce)

                        if self._stop_on_first:
                            return ExplorationResult(
                                status=ExplorationStatus.VIOLATION_FOUND,
                                states_explored=states_explored,
                                transitions_explored=transitions_explored,
                                max_depth_reached=max_depth_seen,
                                counterexamples=counterexamples,
                                state_count_by_depth=depth_counts,
                            )

                queue.append((succ_state, succ_fp, succ_depth))

        # Exhausted the reachable state space within bounds
        status = (
            ExplorationStatus.VIOLATION_FOUND
            if counterexamples
            else ExplorationStatus.SAFE
        )
        return ExplorationResult(
            status=status,
            states_explored=states_explored,
            transitions_explored=transitions_explored,
            max_depth_reached=max_depth_seen,
            counterexamples=counterexamples,
            state_count_by_depth=depth_counts,
        )


# ---------------------------------------------------------------------------
# SafetyChecker — convenience wrapper
# ---------------------------------------------------------------------------

class SafetyChecker(Generic[S, A]):
    """
    High-level API for checking safety properties over abstract C programs.

    This wraps ``BoundedExplorer`` with sensible defaults and provides
    a checker-oriented interface.

    Usage
    -----
    >>> checker = SafetyChecker(transfer_fn)
    >>> checker.add_property(NoNullDeref())
    >>> checker.add_property(NoDivByZero())
    >>> result = checker.check(initial_state)
    >>> if not result.is_safe:
    ...     for ce in result.counterexamples:
    ...         print(ce.pretty())
    """

    def __init__(
        self,
        transfer: TransferProtocol[S, A],
        *,
        max_depth: int = 50,
        max_states: int = 5_000,
    ) -> None:
        self._transfer = transfer
        self._properties: List[PropertyProtocol[S]] = []
        self._max_depth = max_depth
        self._max_states = max_states

    def add_property(self, prop: PropertyProtocol[S]) -> SafetyChecker[S, A]:
        """Fluent API: add a property to check."""
        self._properties.append(prop)
        return self

    def check(
        self,
        initial_state: S,
        *,
        location_fn: Optional[Callable[[A], str]] = None,
    ) -> ExplorationResult[S, A]:
        """Run bounded model checking and return results."""
        explorer = BoundedExplorer(
            self._transfer,
            max_depth=self._max_depth,
            max_states=self._max_states,
            use_subsumption=True,
            stop_on_first_violation=False,
        )
        return explorer.explore(
            initial_state,
            self._properties,
            location_fn=location_fn,
        )


# ---------------------------------------------------------------------------
# TraceReconstructor — standalone utility
# ---------------------------------------------------------------------------

class TraceReconstructor(Generic[S, A]):
    """
    Given a property violation at a specific abstract state, reconstruct
    the shortest trace from the program entry point to that state.

    This is extracted as a standalone utility because addons like
    ``StackDepthAnalyzer`` may want trace reconstruction without
    running the full explorer (e.g., they already found the violating
    state via fixpoint iteration and just need the "how did we get here?").
    """

    def __init__(
        self,
        transfer: TransferProtocol[S, A],
        initial_state: S,
    ) -> None:
        self._transfer = transfer
        self._initial = initial_state

    def reconstruct(
        self,
        target_predicate: Callable[[S], bool],
        *,
        max_depth: int = 200,
    ) -> Optional[List[TraceStep[S, A]]]:
        """
        BFS from initial state until *target_predicate* matches,
        then return the trace.

        Returns None if no matching state is found within the depth bound.
        """
        visited: Dict[str, S] = {}
        parent: Dict[str, Tuple[Optional[A], str]] = {}

        def _fp(s: S) -> str:
            if hasattr(s, "fingerprint"):
                return s.fingerprint()  # type: ignore
            return hashlib.sha256(repr(s).encode()).hexdigest()[:32]

        init_fp = _fp(self._initial)
        visited[init_fp] = self._initial

        if target_predicate(self._initial):
            return [TraceStep(self._initial, None, None)]

        queue: Deque[Tuple[S, str, int]] = deque(
            [(self._initial, init_fp, 0)]
        )

        while queue:
            cur, cur_fp, depth = queue.popleft()
            if depth >= max_depth:
                continue

            for action, succ in self._transfer.successors(cur):
                if hasattr(succ, "is_bottom") and succ.is_bottom():
                    continue
                sfp = _fp(succ)
                if sfp in visited:
                    continue
                visited[sfp] = succ
                parent[sfp] = (action, cur_fp)

                if target_predicate(succ):
                    # Reconstruct
                    trace: List[TraceStep[S, A]] = []
                    node_fp = sfp
                    while node_fp in parent:
                        act, prev_fp = parent[node_fp]
                        trace.append(TraceStep(visited[node_fp], act, None))
                        node_fp = prev_fp
                    trace.append(TraceStep(self._initial, None, None))
                    trace.reverse()
                    return trace

                queue.append((succ, sfp, depth + 1))

        return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

__all__ = [
    # Enums
    "ExplorationStatus",
    # Data classes
    "Transition",
    "TraceStep",
    "Counterexample",
    "ExplorationResult",
    # Core classes
    "ExplicitStateGraph",
    "BoundedExplorer",
    "SafetyChecker",
    "TraceReconstructor",
    # Protocols (for typing)
    "AbstractStateProtocol",
    "TransferProtocol",
    "PropertyProtocol",
]
