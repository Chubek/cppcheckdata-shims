#!/usr/bin/env python3
"""
path_analysis.py  –  General-purpose path analysis for the cppcheckdata_shims substrate.

Provides four layers of functionality:

  Layer 1 – Path Representation
      Immutable, composable path objects that record sequences of abstract
      states and the edges (transitions) between them.  Rich query interface
      for any addon that needs to inspect execution histories.

  Layer 2 – Path Enumeration & Search
      Multiple strategies for discovering paths through a CFG / explicit-state
      graph: DFS, BFS, k-bounded, shortest, longest (pessimal), all-paths up
      to a bound, and demand-driven (goal-directed) search.

  Layer 3 – Path Predicates & Filtering
      A small, composable predicate algebra over paths.  Addons express
      properties like "every node on this path satisfies P" or "some edge
      triggers a call to free()" without writing manual loops.

  Layer 4 – Temporal Logic (LTL / CTL)
      One specific – but important – client of Layers 1-3.  Translates
      temporal-logic formulae into path predicates and evaluation procedures.
      LTL is evaluated over *paths* (Layer 2); CTL over *state graphs*.

Each layer is independently importable and useful.

Dependencies within the substrate
----------------------------------
  - cfg.py            : BasicBlock, CFG
  - interval.py       : IntervalDomain  (optional, for state concretisation)
  - abstract_executor : AbstractState    (optional, states can be opaque)
  - transition_system : ExplicitStateGraph (optional, for CTL / bounded exploration)

All substrate imports are late / guarded so that this module works even if
only cfg.py is available.

Licence: MIT
"""

from __future__ import annotations

import abc
import enum
import heapq
import itertools
import sys
from collections import defaultdict, deque
from dataclasses import dataclass, field, replace
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
    TypeVar,
    Union,
    runtime_checkable,
)

# ─────────────────────────────────────────────────────────────────────
#  Type variables used throughout
# ─────────────────────────────────────────────────────────────────────
S = TypeVar("S")           # Abstract state
L = TypeVar("L")           # Edge label  (action / token / transition kind)
N = TypeVar("N", bound=Hashable)  # Node identity (block id, state id, …)
T = TypeVar("T")           # Generic payload

# ═══════════════════════════════════════════════════════════════════════
#  LAYER 0 — Protocols  (structural typing so addons need not subclass)
# ═══════════════════════════════════════════════════════════════════════

@runtime_checkable
class GraphLike(Protocol[N, L]):
    """
    Anything that looks like a directed labelled graph.
    CFGs, explicit-state graphs, call-graphs – all qualify.
    """

    def successors(self, node: N) -> Iterable[Tuple[N, L]]:
        """Yield (successor_node, edge_label) pairs."""
        ...

    def predecessors(self, node: N) -> Iterable[Tuple[N, L]]:
        """Yield (predecessor_node, edge_label) pairs."""
        ...

    def nodes(self) -> Iterable[N]:
        ...

    def entry(self) -> N:
        ...


@runtime_checkable
class StateLike(Protocol):
    """Anything that can be hashed and compared – i.e. an abstract state."""

    def __hash__(self) -> int: ...
    def __eq__(self, other: object) -> bool: ...


# ═══════════════════════════════════════════════════════════════════════
#  LAYER 1 — Path Representation
# ═══════════════════════════════════════════════════════════════════════

@dataclass(frozen=True, slots=True)
class Edge(Generic[N, L]):
    """A single directed edge in a path."""
    src: N
    dst: N
    label: L                       # Action / token / weight / …
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __repr__(self) -> str:
        lab = f" [{self.label}]" if self.label is not None else ""
        return f"{self.src} →{lab} {self.dst}"


@dataclass(frozen=True)
class Path(Generic[N, L]):
    """
    An immutable, ordered sequence of edges forming a walk through a graph.

    Paths are the *universal exchange type* of this module.  Every search
    strategy produces them; every predicate consumes them; every addon can
    inspect them.

    Construction
    ------------
    >>> p = Path.empty(start_node)
    >>> p = p.append(edge)
    >>> p = Path.from_nodes(graph, [n0, n1, n2])   # convenience

    Paths are *values* — appending returns a new Path.
    """

    edges: Tuple[Edge[N, L], ...]
    _node_seq: Tuple[N, ...] = field(repr=False, compare=False)

    # ── factories ────────────────────────────────────────────────────

    @classmethod
    def empty(cls, start: N) -> "Path[N, L]":
        """A zero-length path sitting at *start*."""
        return cls(edges=(), _node_seq=(start,))

    @classmethod
    def from_edges(cls, edges: Iterable[Edge[N, L]]) -> "Path[N, L]":
        es = tuple(edges)
        if not es:
            raise ValueError("Use Path.empty(node) for a zero-length path")
        nodes: list[N] = [es[0].src]
        for e in es:
            if e.src != nodes[-1]:
                raise ValueError(
                    f"Discontinuous path: expected src={nodes[-1]}, got {e.src}"
                )
            nodes.append(e.dst)
        return cls(edges=es, _node_seq=tuple(nodes))

    @classmethod
    def from_nodes(
        cls,
        graph: GraphLike[N, L],
        node_seq: Sequence[N],
    ) -> "Path[N, L]":
        """
        Build a path by looking up edges between consecutive nodes in *graph*.
        Picks the first matching edge if the graph is a multigraph.
        """
        if len(node_seq) == 0:
            raise ValueError("node_seq must be non-empty")
        if len(node_seq) == 1:
            return cls.empty(node_seq[0])
        edges: list[Edge[N, L]] = []
        for src, dst in zip(node_seq, node_seq[1:]):
            found = False
            for succ, lbl in graph.successors(src):
                if succ == dst:
                    edges.append(Edge(src=src, dst=dst, label=lbl))
                    found = True
                    break
            if not found:
                raise ValueError(f"No edge {src} → {dst} in graph")
        return cls.from_edges(edges)

    # ── core properties ──────────────────────────────────────────────

    @property
    def start(self) -> N:
        return self._node_seq[0]

    @property
    def end(self) -> N:
        return self._node_seq[-1]

    @property
    def nodes(self) -> Tuple[N, ...]:
        """All nodes visited, in order (length = len(edges) + 1)."""
        return self._node_seq

    @property
    def length(self) -> int:
        """Number of edges."""
        return len(self.edges)

    @property
    def is_empty(self) -> bool:
        return self.length == 0

    @property
    def is_cycle(self) -> bool:
        return self.length > 0 and self.start == self.end

    @property
    def is_simple(self) -> bool:
        """No repeated nodes (except possibly start==end for a simple cycle)."""
        ns = self._node_seq
        if self.is_cycle:
            return len(set(ns[:-1])) == len(ns) - 1
        return len(set(ns)) == len(ns)

    # ── node / edge membership ───────────────────────────────────────

    def visits(self, node: N) -> bool:
        return node in self._node_seq

    def visits_any(self, nodes: Iterable[N]) -> bool:
        target = set(nodes)
        return bool(target & set(self._node_seq))

    def contains_edge(self, src: N, dst: N) -> bool:
        return any(e.src == src and e.dst == dst for e in self.edges)

    def edge_labels(self) -> Tuple[L, ...]:
        return tuple(e.label for e in self.edges)

    # ── indexing & slicing ───────────────────────────────────────────

    def node_at(self, idx: int) -> N:
        return self._node_seq[idx]

    def edge_at(self, idx: int) -> Edge[N, L]:
        return self.edges[idx]

    def prefix(self, length: int) -> "Path[N, L]":
        """First *length* edges."""
        if length >= self.length:
            return self
        return Path(
            edges=self.edges[:length],
            _node_seq=self._node_seq[: length + 1],
        )

    def suffix_from(self, edge_idx: int) -> "Path[N, L]":
        """Sub-path starting from edge *edge_idx*."""
        if edge_idx <= 0:
            return self
        return Path(
            edges=self.edges[edge_idx:],
            _node_seq=self._node_seq[edge_idx:],
        )

    def subpath(self, start_edge: int, end_edge: int) -> "Path[N, L]":
        """Edges [start_edge, end_edge)."""
        return Path(
            edges=self.edges[start_edge:end_edge],
            _node_seq=self._node_seq[start_edge: end_edge + 1],
        )

    # ── composition ──────────────────────────────────────────────────

    def append(self, edge: Edge[N, L]) -> "Path[N, L]":
        """Return a new path with *edge* appended."""
        if edge.src != self.end:
            raise ValueError(
                f"Cannot append edge {edge}: src={edge.src} ≠ path end={self.end}"
            )
        return Path(
            edges=self.edges + (edge,),
            _node_seq=self._node_seq + (edge.dst,),
        )

    def extend(self, other: "Path[N, L]") -> "Path[N, L]":
        """Concatenate *other* onto the end (other.start must == self.end)."""
        if other.start != self.end:
            raise ValueError(
                f"Cannot extend: other starts at {other.start}, "
                f"path ends at {self.end}"
            )
        return Path(
            edges=self.edges + other.edges,
            _node_seq=self._node_seq + other._node_seq[1:],
        )

    # ── projection / mapping ─────────────────────────────────────────

    def map_nodes(self, fn: Callable[[N], Any]) -> List[Any]:
        """Apply *fn* to every node; return results in order."""
        return [fn(n) for n in self._node_seq]

    def map_edges(self, fn: Callable[[Edge[N, L]], T]) -> List[T]:
        return [fn(e) for e in self.edges]

    def fold_edges(self, fn: Callable[[T, Edge[N, L]], T], init: T) -> T:
        """Left-fold over edges."""
        acc = init
        for e in self.edges:
            acc = fn(acc, e)
        return acc

    def accumulate(
        self,
        fn: Callable[[T, N, Optional[Edge[N, L]]], T],
        init: T,
    ) -> List[T]:
        """
        Walk the path, calling fn(accumulator, current_node, incoming_edge)
        at every node.  Returns the list of accumulator values (one per node).

        This is the workhorse for *forward dataflow along a specific path*:
        energy accumulation, taint propagation, symbolic state threading, etc.
        """
        acc = init
        results: list[T] = []
        # First node has no incoming edge
        acc = fn(acc, self._node_seq[0], None)
        results.append(acc)
        for i, edge in enumerate(self.edges):
            acc = fn(acc, self._node_seq[i + 1], edge)
            results.append(acc)
        return results

    def reverse_accumulate(
        self,
        fn: Callable[[T, N, Optional[Edge[N, L]]], T],
        init: T,
    ) -> List[T]:
        """Same as accumulate but walks backward from end to start."""
        acc = init
        results: list[T] = []
        acc = fn(acc, self._node_seq[-1], None)
        results.append(acc)
        for i in range(len(self.edges) - 1, -1, -1):
            edge = self.edges[i]
            acc = fn(acc, self._node_seq[i], edge)
            results.append(acc)
        results.reverse()
        return results

    # ── cost / weight helpers ────────────────────────────────────────

    def total_weight(
        self, weight_fn: Callable[[Edge[N, L]], float]
    ) -> float:
        """Sum a numeric weight over all edges."""
        return sum(weight_fn(e) for e in self.edges)

    def max_weight_edge(
        self, weight_fn: Callable[[Edge[N, L]], float]
    ) -> Optional[Edge[N, L]]:
        if not self.edges:
            return None
        return max(self.edges, key=weight_fn)

    # ── display ──────────────────────────────────────────────────────

    def pretty(self, node_str: Callable[[N], str] = str) -> str:
        if self.is_empty:
            return f"[{node_str(self.start)}]"
        parts = [node_str(self.start)]
        for e in self.edges:
            lbl = f" [{e.label}]" if e.label is not None else ""
            parts.append(f" →{lbl} {node_str(e.dst)}")
        return "".join(parts)

    def __repr__(self) -> str:
        return f"Path(len={self.length}, {self.start}→…→{self.end})"

    def __len__(self) -> int:
        return self.length

    def __iter__(self) -> Iterator[Edge[N, L]]:
        return iter(self.edges)

    def __contains__(self, node: N) -> bool:  # type: ignore[override]
        return self.visits(node)


# Convenience alias
PathSet = FrozenSet[Path]


# ═══════════════════════════════════════════════════════════════════════
#  LAYER 2 — Path Enumeration & Search
# ═══════════════════════════════════════════════════════════════════════

class SearchOrder(enum.Enum):
    DFS = "dfs"
    BFS = "bfs"


@dataclass
class SearchConfig:
    """
    Knobs that control path enumeration.

    Addons set these to express very different goals:
      - WCEC addon: max_depth=loop_bound, order=DFS, goal=exit_node,
                    weight_fn=energy, optimise=MAXIMISE
      - Taint addon: goal=sink_node, order=BFS (shortest witness)
      - Model checker: all_paths=True up to max_depth
    """
    max_depth: int = 200
    order: SearchOrder = SearchOrder.DFS
    allow_cycles: bool = False
    max_cycle_unrolls: int = 0          # 0 = no revisits allowed
    max_paths: int = 1_000              # hard cap to avoid explosion
    goal: Optional[Callable[[N], bool]] = None   # stop when reached
    prune: Optional[Callable[[N, int], bool]] = None  # prune(node, depth) → skip?
    weight_fn: Optional[Callable[[Edge], float]] = None
    optimise: Optional[str] = None      # "min" | "max" | None (all paths)


class PathEnumerator(Generic[N, L]):
    """
    Discovers paths through any GraphLike structure.

    This is intentionally *not* specific to CFGs.  It works on call-graphs,
    state-transition graphs, interprocedural super-graphs, etc.
    """

    def __init__(self, graph: GraphLike[N, L]) -> None:
        self.graph = graph

    # ── BFS / DFS bounded enumeration ────────────────────────────────

    def enumerate(
        self,
        start: Optional[N] = None,
        config: Optional[SearchConfig] = None,
    ) -> Iterator[Path[N, L]]:
        """
        Yield paths from *start* according to *config*.

        Paths are yielded lazily.  The caller can stop iteration early.
        """
        cfg = config or SearchConfig()
        origin = start if start is not None else self.graph.entry()
        count = 0

        # visit_counts: how many times each node has been entered on the
        # *current* partial path (for cycle control).
        # We track this per-path via the stack frame.

        if cfg.order is SearchOrder.BFS:
            yield from self._bfs(origin, cfg)
        else:
            yield from self._dfs(origin, cfg)

    # ── DFS core ─────────────────────────────────────────────────────

    def _dfs(
        self, origin: N, cfg: SearchConfig
    ) -> Iterator[Path[N, L]]:
        """Iterative DFS with explicit stack (avoids Python recursion limit)."""
        # Stack frames: (current_path, visit_counts_on_this_path)
        FrameT = Tuple[Path[N, L], Dict[N, int]]
        init_visits: Dict[N, int] = defaultdict(int)
        init_visits[origin] = 1
        stack: List[FrameT] = [(Path.empty(origin), dict(init_visits))]
        count = 0

        while stack:
            path, visits = stack.pop()
            cur = path.end

            # Goal check
            if cfg.goal is not None and cfg.goal(cur):
                yield path
                count += 1
                if count >= cfg.max_paths:
                    return
                continue  # don't expand past goal

            # Depth check
            if path.length >= cfg.max_depth:
                # yield partial path even if goal not reached –
                # caller decides whether partial paths are useful
                if cfg.goal is None:
                    yield path
                    count += 1
                    if count >= cfg.max_paths:
                        return
                continue

            expanded = False
            for succ, lbl in self.graph.successors(cur):
                # Prune hook
                if cfg.prune is not None and cfg.prune(succ, path.length + 1):
                    continue

                succ_count = visits.get(succ, 0)
                if succ_count > 0:
                    # This would create a cycle
                    if not cfg.allow_cycles:
                        continue
                    if succ_count > cfg.max_cycle_unrolls:
                        continue

                edge = Edge(src=cur, dst=succ, label=lbl)
                new_path = path.append(edge)
                new_visits = dict(visits)
                new_visits[succ] = succ_count + 1
                stack.append((new_path, new_visits))
                expanded = True

            if not expanded and cfg.goal is None:
                # Dead-end: yield the path to this leaf
                yield path
                count += 1
                if count >= cfg.max_paths:
                    return

    # ── BFS core ─────────────────────────────────────────────────────

    def _bfs(
        self, origin: N, cfg: SearchConfig
    ) -> Iterator[Path[N, L]]:
        """BFS — finds *shortest* paths first."""
        queue: Deque[Tuple[Path[N, L], Dict[N, int]]] = deque()
        init_visits: Dict[N, int] = defaultdict(int)
        init_visits[origin] = 1
        queue.append((Path.empty(origin), dict(init_visits)))
        count = 0

        while queue:
            path, visits = queue.popleft()
            cur = path.end

            if cfg.goal is not None and cfg.goal(cur):
                yield path
                count += 1
                if count >= cfg.max_paths:
                    return
                continue

            if path.length >= cfg.max_depth:
                if cfg.goal is None:
                    yield path
                    count += 1
                    if count >= cfg.max_paths:
                        return
                continue

            for succ, lbl in self.graph.successors(cur):
                if cfg.prune is not None and cfg.prune(succ, path.length + 1):
                    continue

                succ_count = visits.get(succ, 0)
                if succ_count > 0:
                    if not cfg.allow_cycles:
                        continue
                    if succ_count > cfg.max_cycle_unrolls:
                        continue

                edge = Edge(src=cur, dst=succ, label=lbl)
                new_path = path.append(edge)
                new_visits = dict(visits)
                new_visits[succ] = succ_count + 1
                queue.append((new_path, new_visits))

        # If no goal was set, BFS already yielded leaves above.

    # ── goal-directed (demand-driven) ────────────────────────────────

    def find_path(
        self,
        start: N,
        goal: N,
        *,
        max_depth: int = 200,
        order: SearchOrder = SearchOrder.BFS,
    ) -> Optional[Path[N, L]]:
        """Convenience: find *one* path from start to goal, or None."""
        cfg = SearchConfig(
            max_depth=max_depth,
            order=order,
            goal=lambda n: n == goal,
            max_paths=1,
        )
        return next(self.enumerate(start, cfg), None)

    def find_all_paths(
        self,
        start: N,
        goal: N,
        *,
        max_depth: int = 50,
        max_paths: int = 1_000,
    ) -> List[Path[N, L]]:
        """All simple paths from *start* to *goal* up to *max_depth*."""
        cfg = SearchConfig(
            max_depth=max_depth,
            order=SearchOrder.DFS,
            goal=lambda n: n == goal,
            max_paths=max_paths,
            allow_cycles=False,
        )
        return list(self.enumerate(start, cfg))

    # ── weighted search (Dijkstra / Bellman-Ford-ish) ────────────────

    def shortest_weighted_path(
        self,
        start: N,
        goal: N,
        weight_fn: Callable[[Edge[N, L]], float],
        *,
        max_depth: int = 500,
    ) -> Optional[Path[N, L]]:
        """Dijkstra over the graph.  All weights must be ≥ 0."""
        # Priority queue: (cost, tiebreaker, path)
        counter = itertools.count()
        pq: List[Tuple[float, int, Path[N, L]]] = [
            (0.0, next(counter), Path.empty(start))
        ]
        best: Dict[N, float] = {}
        while pq:
            cost, _, path = heapq.heappop(pq)
            cur = path.end
            if cur == goal:
                return path
            if cur in best and best[cur] <= cost:
                continue
            best[cur] = cost
            if path.length >= max_depth:
                continue
            for succ, lbl in self.graph.successors(cur):
                edge = Edge(src=cur, dst=succ, label=lbl)
                w = weight_fn(edge)
                new_cost = cost + w
                if succ not in best or best[succ] > new_cost:
                    heapq.heappush(
                        pq, (new_cost, next(counter), path.append(edge))
                    )
        return None

    def pessimal_path(
        self,
        start: N,
        goal: N,
        weight_fn: Callable[[Edge[N, L]], float],
        *,
        max_depth: int = 200,
    ) -> Optional[Path[N, L]]:
        """
        Longest (highest-cost) *simple* path from start to goal.

        This is NP-hard in general, so we do bounded DFS with pruning.
        Useful for worst-case analysis (WCEC, WCET).
        """
        best_path: Optional[Path[N, L]] = None
        best_cost = -1.0

        cfg = SearchConfig(
            max_depth=max_depth,
            order=SearchOrder.DFS,
            goal=lambda n: n == goal,
            max_paths=50_000,
            allow_cycles=False,
        )
        for p in self.enumerate(start, cfg):
            c = p.total_weight(weight_fn)
            if c > best_cost:
                best_cost = c
                best_path = p
        return best_path


# ═══════════════════════════════════════════════════════════════════════
#  LAYER 3 — Path Predicates & Filtering
# ═══════════════════════════════════════════════════════════════════════

class PathPredicate(abc.ABC, Generic[N, L]):
    """
    A composable Boolean predicate over paths.

    The algebra:
        p & q           →  And(p, q)
        p | q           →  Or(p, q)
        ~p              →  Not(p)
        p >> q          →  Implies(p, q)

    Addons build predicates, then pass them to PathFilter or to
    the temporal-logic evaluator.
    """

    @abc.abstractmethod
    def __call__(self, path: Path[N, L]) -> bool: ...

    # ── algebra ──────────────────────────────────────────────────────

    def __and__(self, other: "PathPredicate[N, L]") -> "PathPredicate[N, L]":
        return _And(self, other)

    def __or__(self, other: "PathPredicate[N, L]") -> "PathPredicate[N, L]":
        return _Or(self, other)

    def __invert__(self) -> "PathPredicate[N, L]":
        return _Not(self)

    def __rshift__(self, other: "PathPredicate[N, L]") -> "PathPredicate[N, L]":
        return _Or(_Not(self), other)

    def __repr__(self) -> str:
        return f"{type(self).__name__}()"


@dataclass(frozen=True)
class _And(PathPredicate[N, L]):
    left: PathPredicate[N, L]
    right: PathPredicate[N, L]
    def __call__(self, path: Path[N, L]) -> bool:
        return self.left(path) and self.right(path)
    def __repr__(self) -> str:
        return f"({self.left!r} & {self.right!r})"

@dataclass(frozen=True)
class _Or(PathPredicate[N, L]):
    left: PathPredicate[N, L]
    right: PathPredicate[N, L]
    def __call__(self, path: Path[N, L]) -> bool:
        return self.left(path) or self.right(path)
    def __repr__(self) -> str:
        return f"({self.left!r} | {self.right!r})"

@dataclass(frozen=True)
class _Not(PathPredicate[N, L]):
    inner: PathPredicate[N, L]
    def __call__(self, path: Path[N, L]) -> bool:
        return not self.inner(path)
    def __repr__(self) -> str:
        return f"(~{self.inner!r})"


# ── Concrete predicate library ───────────────────────────────────────

class NodeSatisfies(PathPredicate[N, L]):
    """True iff *every* node on the path satisfies *pred*."""
    def __init__(self, pred: Callable[[N], bool], *, name: str = "?"):
        self._pred = pred
        self._name = name
    def __call__(self, path: Path[N, L]) -> bool:
        return all(self._pred(n) for n in path.nodes)
    def __repr__(self) -> str:
        return f"∀node.{self._name}"


class SomeNodeSatisfies(PathPredicate[N, L]):
    """True iff *at least one* node on the path satisfies *pred*."""
    def __init__(self, pred: Callable[[N], bool], *, name: str = "?"):
        self._pred = pred
        self._name = name
    def __call__(self, path: Path[N, L]) -> bool:
        return any(self._pred(n) for n in path.nodes)
    def __repr__(self) -> str:
        return f"∃node.{self._name}"


class EdgeSatisfies(PathPredicate[N, L]):
    """True iff *every* edge satisfies *pred*."""
    def __init__(self, pred: Callable[[Edge[N, L]], bool], *, name: str = "?"):
        self._pred = pred
        self._name = name
    def __call__(self, path: Path[N, L]) -> bool:
        return all(self._pred(e) for e in path.edges)
    def __repr__(self) -> str:
        return f"∀edge.{self._name}"


class SomeEdgeSatisfies(PathPredicate[N, L]):
    """True iff *at least one* edge satisfies *pred*."""
    def __init__(self, pred: Callable[[Edge[N, L]], bool], *, name: str = "?"):
        self._pred = pred
        self._name = name
    def __call__(self, path: Path[N, L]) -> bool:
        return any(self._pred(e) for e in path.edges)
    def __repr__(self) -> str:
        return f"∃edge.{self._name}"


class PathVisits(PathPredicate[N, L]):
    """True iff the path visits a specific node."""
    def __init__(self, node: N):
        self._node = node
    def __call__(self, path: Path[N, L]) -> bool:
        return path.visits(self._node)
    def __repr__(self) -> str:
        return f"visits({self._node})"


class PathAvoids(PathPredicate[N, L]):
    """True iff the path does NOT visit any node in *nodes*."""
    def __init__(self, nodes: Iterable[N]):
        self._bad = frozenset(nodes)
    def __call__(self, path: Path[N, L]) -> bool:
        return not self._bad & frozenset(path.nodes)
    def __repr__(self) -> str:
        return f"avoids({self._bad})"


class ReachesWithin(PathPredicate[N, L]):
    """True iff the path reaches a node satisfying *pred* within *depth* edges."""
    def __init__(self, pred: Callable[[N], bool], depth: int, *, name: str = "?"):
        self._pred = pred
        self._depth = depth
        self._name = name
    def __call__(self, path: Path[N, L]) -> bool:
        for i, n in enumerate(path.nodes):
            if i > self._depth:
                return False
            if self._pred(n):
                return True
        return False
    def __repr__(self) -> str:
        return f"reaches({self._name}, ≤{self._depth})"


class CostBelow(PathPredicate[N, L]):
    """True iff total path cost (per weight_fn) < threshold."""
    def __init__(self, weight_fn: Callable[[Edge[N, L]], float], threshold: float):
        self._wf = weight_fn
        self._thr = threshold
    def __call__(self, path: Path[N, L]) -> bool:
        return path.total_weight(self._wf) < self._thr
    def __repr__(self) -> str:
        return f"cost < {self._thr}"


class CostAbove(PathPredicate[N, L]):
    """True iff total path cost (per weight_fn) > threshold."""
    def __init__(self, weight_fn: Callable[[Edge[N, L]], float], threshold: float):
        self._wf = weight_fn
        self._thr = threshold
    def __call__(self, path: Path[N, L]) -> bool:
        return path.total_weight(self._wf) > self._thr
    def __repr__(self) -> str:
        return f"cost > {self._thr}"


class OrderedVisit(PathPredicate[N, L]):
    """
    True iff the path visits a sequence of nodes in order.
    Useful for "p must be allocated before used before freed" patterns.
    """
    def __init__(self, ordered_preds: Sequence[Callable[[N], bool]]):
        self._preds = list(ordered_preds)
    def __call__(self, path: Path[N, L]) -> bool:
        stage = 0
        for n in path.nodes:
            if stage < len(self._preds) and self._preds[stage](n):
                stage += 1
        return stage == len(self._preds)
    def __repr__(self) -> str:
        return f"ordered_visit({len(self._preds)} stages)"


class MonotonicProperty(PathPredicate[N, L]):
    """
    True iff a numeric property of nodes is monotonically non-decreasing
    (or non-increasing) along the path.  Useful for progress checks.
    """
    def __init__(
        self,
        measure: Callable[[N], float],
        direction: str = "increasing",
    ):
        self._measure = measure
        self._increasing = direction.startswith("inc")
    def __call__(self, path: Path[N, L]) -> bool:
        prev = None
        for n in path.nodes:
            v = self._measure(n)
            if prev is not None:
                if self._increasing and v < prev:
                    return False
                if not self._increasing and v > prev:
                    return False
            prev = v
        return True


# ── Path Filter (applies predicates to path sets) ────────────────────

class PathFilter(Generic[N, L]):
    """Applies one or more predicates to an iterable of paths."""

    def __init__(self, *predicates: PathPredicate[N, L]) -> None:
        self._preds = list(predicates)

    def add(self, pred: PathPredicate[N, L]) -> None:
        self._preds.append(pred)

    def __call__(self, paths: Iterable[Path[N, L]]) -> Iterator[Path[N, L]]:
        """Yield paths that satisfy ALL predicates."""
        for p in paths:
            if all(pred(p) for pred in self._preds):
                yield p

    def any_of(self, paths: Iterable[Path[N, L]]) -> Iterator[Path[N, L]]:
        """Yield paths that satisfy ANY predicate."""
        for p in paths:
            if any(pred(p) for pred in self._preds):
                yield p

    def partition(
        self, paths: Iterable[Path[N, L]]
    ) -> Tuple[List[Path[N, L]], List[Path[N, L]]]:
        """Split into (matching, non_matching)."""
        yes: list[Path[N, L]] = []
        no: list[Path[N, L]] = []
        for p in paths:
            if all(pred(p) for pred in self._preds):
                yes.append(p)
            else:
                no.append(p)
        return yes, no


# ═══════════════════════════════════════════════════════════════════════
#  LAYER 4 — Temporal Logic  (LTL & CTL)
#
#  This is ONE CLIENT of Layers 1-3, not the other way around.
# ═══════════════════════════════════════════════════════════════════════

# ── 4a. Atomic Propositions ─────────────────────────────────────────

class AP(Generic[N]):
    """
    An atomic proposition: a named Boolean function over nodes.
    Building block for temporal formulae.
    """
    def __init__(self, name: str, pred: Callable[[N], bool]) -> None:
        self.name = name
        self.pred = pred

    def __call__(self, node: N) -> bool:
        return self.pred(node)

    def __repr__(self) -> str:
        return self.name

    # Convenience: APs can be combined into temporal formulae directly
    @property
    def formula(self) -> "TLFormula[N]":
        return AtomicFormula(self)


# ── 4b. Temporal Logic Formula AST ──────────────────────────────────

class TLFormula(abc.ABC, Generic[N]):
    """
    Abstract base for temporal-logic formulae.

    Supports both LTL operators (path-based) and CTL operators (state-based).
    The evaluator checks which kind of formula it is and dispatches accordingly.
    """

    @abc.abstractmethod
    def __repr__(self) -> str: ...

    # ── propositional combinators ────────────────────────────────────
    def __and__(self, other: "TLFormula[N]") -> "TLFormula[N]":
        return TLAnd(self, other)

    def __or__(self, other: "TLFormula[N]") -> "TLFormula[N]":
        return TLOr(self, other)

    def __invert__(self) -> "TLFormula[N]":
        return TLNot(self)

    def __rshift__(self, other: "TLFormula[N]") -> "TLFormula[N]":
        """Implication: self >> other  ≡  ¬self ∨ other"""
        return TLOr(TLNot(self), other)


# ── propositional ────────────────────────────────────────────────────

@dataclass(frozen=True)
class AtomicFormula(TLFormula[N]):
    ap: AP[N]
    def __repr__(self) -> str:
        return repr(self.ap)

@dataclass(frozen=True)
class TLTrue(TLFormula[N]):
    def __repr__(self) -> str:
        return "⊤"

@dataclass(frozen=True)
class TLFalse(TLFormula[N]):
    def __repr__(self) -> str:
        return "⊥"

@dataclass(frozen=True)
class TLNot(TLFormula[N]):
    inner: TLFormula[N]
    def __repr__(self) -> str:
        return f"¬{self.inner!r}"

@dataclass(frozen=True)
class TLAnd(TLFormula[N]):
    left: TLFormula[N]
    right: TLFormula[N]
    def __repr__(self) -> str:
        return f"({self.left!r} ∧ {self.right!r})"

@dataclass(frozen=True)
class TLOr(TLFormula[N]):
    left: TLFormula[N]
    right: TLFormula[N]
    def __repr__(self) -> str:
        return f"({self.left!r} ∨ {self.right!r})"

# ── LTL operators (evaluated over paths) ────────────────────────────

@dataclass(frozen=True)
class LTLNext(TLFormula[N]):
    """X φ  — φ holds at the next state."""
    inner: TLFormula[N]
    def __repr__(self) -> str:
        return f"X({self.inner!r})"

@dataclass(frozen=True)
class LTLGlobally(TLFormula[N]):
    """G φ  — φ holds at every state on the path suffix."""
    inner: TLFormula[N]
    def __repr__(self) -> str:
        return f"G({self.inner!r})"

@dataclass(frozen=True)
class LTLFinally(TLFormula[N]):
    """F φ  — φ holds at some state on the path suffix."""
    inner: TLFormula[N]
    def __repr__(self) -> str:
        return f"F({self.inner!r})"

@dataclass(frozen=True)
class LTLUntil(TLFormula[N]):
    """φ U ψ — φ holds until ψ holds (and ψ eventually holds)."""
    left: TLFormula[N]
    right: TLFormula[N]
    def __repr__(self) -> str:
        return f"({self.left!r} U {self.right!r})"

@dataclass(frozen=True)
class LTLRelease(TLFormula[N]):
    """φ R ψ — dual of Until: ψ holds up to and including the first φ (or forever)."""
    left: TLFormula[N]
    right: TLFormula[N]
    def __repr__(self) -> str:
        return f"({self.left!r} R {self.right!r})"

@dataclass(frozen=True)
class LTLWeakUntil(TLFormula[N]):
    """φ W ψ — like Until but φ may hold forever without ψ ever occurring."""
    left: TLFormula[N]
    right: TLFormula[N]
    def __repr__(self) -> str:
        return f"({self.left!r} W {self.right!r})"


# ── CTL operators (evaluated over state graphs) ─────────────────────

@dataclass(frozen=True)
class CTL_EX(TLFormula[N]):
    """EX φ — there exists a successor satisfying φ."""
    inner: TLFormula[N]
    def __repr__(self) -> str:
        return f"EX({self.inner!r})"

@dataclass(frozen=True)
class CTL_AX(TLFormula[N]):
    """AX φ — all successors satisfy φ."""
    inner: TLFormula[N]
    def __repr__(self) -> str:
        return f"AX({self.inner!r})"

@dataclass(frozen=True)
class CTL_EF(TLFormula[N]):
    """EF φ — there exists a path on which φ eventually holds."""
    inner: TLFormula[N]
    def __repr__(self) -> str:
        return f"EF({self.inner!r})"

@dataclass(frozen=True)
class CTL_AF(TLFormula[N]):
    """AF φ — on all paths, φ eventually holds."""
    inner: TLFormula[N]
    def __repr__(self) -> str:
        return f"AF({self.inner!r})"

@dataclass(frozen=True)
class CTL_EG(TLFormula[N]):
    """EG φ — there exists a path on which φ always holds."""
    inner: TLFormula[N]
    def __repr__(self) -> str:
        return f"EG({self.inner!r})"

@dataclass(frozen=True)
class CTL_AG(TLFormula[N]):
    """AG φ — on all paths, φ always holds."""
    inner: TLFormula[N]
    def __repr__(self) -> str:
        return f"AG({self.inner!r})"

@dataclass(frozen=True)
class CTL_EU(TLFormula[N]):
    """E[φ U ψ] — there exists a path on which φ holds until ψ."""
    left: TLFormula[N]
    right: TLFormula[N]
    def __repr__(self) -> str:
        return f"E[{self.left!r} U {self.right!r}]"

@dataclass(frozen=True)
class CTL_AU(TLFormula[N]):
    """A[φ U ψ] — on all paths, φ holds until ψ."""
    left: TLFormula[N]
    right: TLFormula[N]
    def __repr__(self) -> str:
        return f"A[{self.left!r} U {self.right!r}]"


# ── 4c. LTL Evaluator (operates on Paths from Layer 2) ──────────────

class LTLEvaluator(Generic[N, L]):
    """
    Evaluate an LTL formula against a finite path.

    Semantics: standard LTL over finite traces (weak semantics: G φ means
    φ holds at all *existing* positions; F φ means φ holds at some existing
    position).  This is the accepted finite-trace LTL semantics from
    [De Giacomo & Vardi, 2013].
    """

    def check(self, formula: TLFormula[N], path: Path[N, L]) -> bool:
        """Does *formula* hold on *path* starting from position 0?"""
        return self._eval(formula, path.nodes, 0)

    def check_at(self, formula: TLFormula[N], path: Path[N, L], pos: int) -> bool:
        """Does *formula* hold on *path* starting from position *pos*?"""
        return self._eval(formula, path.nodes, pos)

    def find_violation(
        self, formula: TLFormula[N], path: Path[N, L]
    ) -> Optional[int]:
        """
        For G φ-style formulae, find the first position where the formula
        fails.  Returns None if the formula holds everywhere.
        """
        for i in range(len(path.nodes)):
            if not self._eval(formula, path.nodes, i):
                return i
        return None

    def _eval(self, f: TLFormula[N], nodes: Tuple[N, ...], i: int) -> bool:
        n = len(nodes)
        if i >= n:
            # Past the end of the trace — convention for finite LTL:
            # all future obligations trivially hold (weak semantics)
            return True

        # ── propositional ────────────────────────────────────────────
        if isinstance(f, AtomicFormula):
            return f.ap(nodes[i])
        if isinstance(f, TLTrue):
            return True
        if isinstance(f, TLFalse):
            return False
        if isinstance(f, TLNot):
            return not self._eval(f.inner, nodes, i)
        if isinstance(f, TLAnd):
            return self._eval(f.left, nodes, i) and self._eval(f.right, nodes, i)
        if isinstance(f, TLOr):
            return self._eval(f.left, nodes, i) or self._eval(f.right, nodes, i)

        # ── LTL temporal ─────────────────────────────────────────────
        if isinstance(f, LTLNext):
            return self._eval(f.inner, nodes, i + 1)

        if isinstance(f, LTLGlobally):
            # G φ: φ holds at all positions from i to end
            return all(self._eval(f.inner, nodes, j) for j in range(i, n))

        if isinstance(f, LTLFinally):
            # F φ: φ holds at some position from i to end
            return any(self._eval(f.inner, nodes, j) for j in range(i, n))

        if isinstance(f, LTLUntil):
            # φ U ψ: ∃ j ≥ i. ψ@j ∧ ∀ k ∈ [i,j). φ@k
            for j in range(i, n):
                if self._eval(f.right, nodes, j):
                    return True
                if not self._eval(f.left, nodes, j):
                    return False
            return False  # ψ never held — strong Until

        if isinstance(f, LTLRelease):
            # φ R ψ ≡ ¬(¬φ U ¬ψ)
            neg = LTLUntil(TLNot(f.left), TLNot(f.right))
            return not self._eval(neg, nodes, i)

        if isinstance(f, LTLWeakUntil):
            # φ W ψ ≡ (φ U ψ) ∨ G φ
            return self._eval(
                TLOr(LTLUntil(f.left, f.right), LTLGlobally(f.left)),
                nodes,
                i,
            )

        raise TypeError(f"LTLEvaluator cannot handle {type(f).__name__}")

    # ── batch helpers ────────────────────────────────────────────────

    def filter_paths(
        self, formula: TLFormula[N], paths: Iterable[Path[N, L]]
    ) -> Iterator[Path[N, L]]:
        """Yield only those paths satisfying *formula*."""
        for p in paths:
            if self.check(formula, p):
                yield p

    def as_predicate(self, formula: TLFormula[N]) -> PathPredicate[N, L]:
        """
        Wrap an LTL formula as a Layer-3 PathPredicate so it composes
        with all other predicates via &, |, ~.
        """
        return _LTLPredicate(formula, self)


@dataclass(frozen=True)
class _LTLPredicate(PathPredicate[N, L]):
    """Bridge: wraps an LTL formula as a PathPredicate."""
    formula: TLFormula[N]
    evaluator: LTLEvaluator[N, L]

    def __call__(self, path: Path[N, L]) -> bool:
        return self.evaluator.check(self.formula, path)

    def __repr__(self) -> str:
        return f"LTL({self.formula!r})"


# ── 4d. CTL Evaluator (operates on GraphLike structures) ────────────

class CTLEvaluator(Generic[N, L]):
    """
    Evaluate a CTL formula on an explicit state graph.

    Uses fixed-point computation (standard CTL model-checking algorithm):
    - EF φ  = μZ. φ ∨ EX Z
    - AF φ  = μZ. φ ∨ AX Z
    - EG φ  = νZ. φ ∧ EX Z
    - AG φ  = νZ. φ ∧ AX Z
    - E[φ U ψ] = μZ. ψ ∨ (φ ∧ EX Z)
    - A[φ U ψ] = μZ. ψ ∨ (φ ∧ AX Z)

    The result is the *set of nodes* satisfying the formula (the satisfaction
    set).  Checking a specific node is O(1) after the set is computed.
    """

    def __init__(self, graph: GraphLike[N, L]) -> None:
        self.graph = graph
        self._all_nodes: Optional[FrozenSet[N]] = None

    @property
    def all_nodes(self) -> FrozenSet[N]:
        if self._all_nodes is None:
            self._all_nodes = frozenset(self.graph.nodes())
        return self._all_nodes

    def sat(self, formula: TLFormula[N]) -> FrozenSet[N]:
        """
        Compute the satisfaction set: all nodes where *formula* holds.
        This is the core CTL model-checking routine.
        """
        return self._sat(formula)

    def check(self, formula: TLFormula[N], node: N) -> bool:
        """Does *formula* hold at *node*?"""
        return node in self.sat(formula)

    def check_initial(self, formula: TLFormula[N]) -> bool:
        """Does *formula* hold at the graph's entry node?"""
        return self.check(formula, self.graph.entry())

    def witnesses(
        self, formula: TLFormula[N], node: N, max_depth: int = 100
    ) -> Optional[Path[N, L]]:
        """
        For existential formulae (EF, EU, EX), produce a *witness path*
        from *node* demonstrating why the formula holds.
        Returns None if the formula does not hold at *node*.
        """
        if not self.check(formula, node):
            return None
        return self._witness(formula, node, max_depth)

    def counterexample(
        self, formula: TLFormula[N], node: N, max_depth: int = 100
    ) -> Optional[Path[N, L]]:
        """
        For universal formulae (AG, AF, AU, AX), produce a *counterexample*
        path showing why the formula fails at *node*.
        Returns None if the formula holds.
        """
        if self.check(formula, node):
            return None
        return self._counterexample(formula, node, max_depth)

    # ── core sat computation ─────────────────────────────────────────

    def _sat(self, f: TLFormula[N]) -> FrozenSet[N]:
        # ── propositional ────────────────────────────────────────────
        if isinstance(f, AtomicFormula):
            return frozenset(n for n in self.all_nodes if f.ap(n))
        if isinstance(f, TLTrue):
            return self.all_nodes
        if isinstance(f, TLFalse):
            return frozenset()
        if isinstance(f, TLNot):
            return self.all_nodes - self._sat(f.inner)
        if isinstance(f, TLAnd):
            return self._sat(f.left) & self._sat(f.right)
        if isinstance(f, TLOr):
            return self._sat(f.left) | self._sat(f.right)

        # ── CTL ──────────────────────────────────────────────────────
        if isinstance(f, CTL_EX):
            inner_sat = self._sat(f.inner)
            return frozenset(
                n for n in self.all_nodes
                if any(s in inner_sat for s, _ in self.graph.successors(n))
            )

        if isinstance(f, CTL_AX):
            inner_sat = self._sat(f.inner)
            result: set[N] = set()
            for n in self.all_nodes:
                succs = list(self.graph.successors(n))
                if succs and all(s in inner_sat for s, _ in succs):
                    result.add(n)
                elif not succs:
                    # No successors — vacuously true
                    result.add(n)
            return frozenset(result)

        if isinstance(f, CTL_EF):
            # μZ. φ ∨ EX Z   (least fixed point via backward BFS)
            return self._lfp_backward_exists(self._sat(f.inner))

        if isinstance(f, CTL_AF):
            # μZ. φ ∨ AX Z
            return self._lfp_backward_all(self._sat(f.inner))

        if isinstance(f, CTL_EG):
            # νZ. φ ∧ EX Z   (greatest fixed point)
            return self._gfp_backward_exists(self._sat(f.inner))

        if isinstance(f, CTL_AG):
            # AG φ = ¬EF ¬φ
            neg_inner = self._sat(TLNot(f.inner))
            ef_neg = self._lfp_backward_exists(neg_inner)
            return self.all_nodes - ef_neg

        if isinstance(f, CTL_EU):
            # E[φ U ψ] = μZ. ψ ∨ (φ ∧ EX Z)
            phi_sat = self._sat(f.left)
            psi_sat = self._sat(f.right)
            return self._lfp_eu(phi_sat, psi_sat)

        if isinstance(f, CTL_AU):
            # A[φ U ψ] = ¬(E[¬ψ U (¬φ ∧ ¬ψ)] ∨ EG ¬ψ)
            phi_sat = self._sat(f.left)
            psi_sat = self._sat(f.right)
            not_phi = self.all_nodes - phi_sat
            not_psi = self.all_nodes - psi_sat
            eu_part = self._lfp_eu(not_psi, not_phi & not_psi)
            eg_part = self._gfp_backward_exists(not_psi)
            return self.all_nodes - (eu_part | eg_part)

        raise TypeError(f"CTLEvaluator cannot handle {type(f).__name__}")

    # ── fixed-point engines ──────────────────────────────────────────

    def _predecessors_map(self) -> Dict[N, List[Tuple[N, L]]]:
        """Build once, cache on instance."""
        if not hasattr(self, "_pred_cache"):
            m: Dict[N, List[Tuple[N, L]]] = defaultdict(list)
            for n in self.all_nodes:
                for s, lbl in self.graph.successors(n):
                    m[s].append((n, lbl))
            self._pred_cache = m  # type: ignore[attr-defined]
        return self._pred_cache  # type: ignore[attr-defined]

    def _lfp_backward_exists(self, target: FrozenSet[N]) -> FrozenSet[N]:
        """
        EF target:  nodes from which *some* path leads to target.
        Backward BFS from target.
        """
        preds = self._predecessors_map()
        found: Set[N] = set(target)
        queue: Deque[N] = deque(target)
        while queue:
            n = queue.popleft()
            for pred_node, _ in preds.get(n, []):
                if pred_node not in found:
                    found.add(pred_node)
                    queue.append(pred_node)
        return frozenset(found)

    def _lfp_backward_all(self, target: FrozenSet[N]) -> FrozenSet[N]:
        """
        AF target:  nodes from which *all* paths eventually reach target.

        Algorithm: iteratively add nodes whose *all* successors are already
        in the set (starting from target).
        """
        preds = self._predecessors_map()
        found: Set[N] = set(target)

        # Successor counts for each node
        succ_count: Dict[N, int] = {}
        for n in self.all_nodes:
            succ_count[n] = sum(1 for _ in self.graph.successors(n))

        # For each node, how many successors are already in 'found'
        satisfied: Dict[N, int] = defaultdict(int)
        queue: Deque[N] = deque(target)

        while queue:
            n = queue.popleft()
            for pred_node, _ in preds.get(n, []):
                if pred_node in found:
                    continue
                satisfied[pred_node] += 1
                if satisfied[pred_node] >= succ_count.get(pred_node, 0):
                    found.add(pred_node)
                    queue.append(pred_node)

        return frozenset(found)

    def _gfp_backward_exists(self, target: FrozenSet[N]) -> FrozenSet[N]:
        """
        EG target:  nodes from which *some* infinite path stays in target.

        On a finite graph, "infinite" means "hits a cycle within target".
        Algorithm: restrict graph to target, find nodes that have a successor
        in the restriction (SCCs + reachability to them).
        """
        # Restrict to target
        restricted = set(target)

        # Iteratively remove nodes with no successors in restricted
        changed = True
        while changed:
            changed = False
            to_remove: set[N] = set()
            for n in restricted:
                has_succ = any(
                    s in restricted for s, _ in self.graph.successors(n)
                )
                if not has_succ:
                    to_remove.add(n)
            if to_remove:
                restricted -= to_remove
                changed = True

        # Now find all nodes in target that can reach restricted
        if not restricted:
            return frozenset()

        # Backward BFS from restricted within target
        preds = self._predecessors_map()
        found = set(restricted)
        queue: Deque[N] = deque(restricted)
        while queue:
            n = queue.popleft()
            for p, _ in preds.get(n, []):
                if p in target and p not in found:
                    found.add(p)
                    queue.append(p)

        return frozenset(found)

    def _lfp_eu(
        self, phi_sat: FrozenSet[N], psi_sat: FrozenSet[N]
    ) -> FrozenSet[N]:
        """E[φ U ψ]: backward from ψ through φ-nodes."""
        preds = self._predecessors_map()
        found: Set[N] = set(psi_sat)
        queue: Deque[N] = deque(psi_sat)
        while queue:
            n = queue.popleft()
            for p, _ in preds.get(n, []):
                if p not in found and p in phi_sat:
                    found.add(p)
                    queue.append(p)
        return frozenset(found)

    # ── witness / counterexample generation ──────────────────────────

    def _witness(
        self, f: TLFormula[N], node: N, max_depth: int
    ) -> Optional[Path[N, L]]:
        """Forward search for a witness path."""
        enum = PathEnumerator(self.graph)
        sat_set = self.sat(f)

        if isinstance(f, CTL_EF):
            target_set = self._sat(f.inner)
            cfg = SearchConfig(
                max_depth=max_depth,
                order=SearchOrder.BFS,
                goal=lambda n: n in target_set,
                max_paths=1,
            )
            return next(enum.enumerate(node, cfg), None)

        if isinstance(f, CTL_EX):
            target_set = self._sat(f.inner)
            for s, lbl in self.graph.successors(node):
                if s in target_set:
                    return Path.from_edges([Edge(node, s, lbl)])
            return None

        if isinstance(f, CTL_EU):
            phi_sat = self._sat(f.left)
            psi_sat = self._sat(f.right)
            cfg = SearchConfig(
                max_depth=max_depth,
                order=SearchOrder.BFS,
                goal=lambda n: n in psi_sat,
                prune=lambda n, d: n not in phi_sat and n not in psi_sat,
                max_paths=1,
            )
            return next(enum.enumerate(node, cfg), None)

        # Generic fallback: find any path that stays in sat_set
        cfg = SearchConfig(
            max_depth=max_depth,
            order=SearchOrder.BFS,
            max_paths=1,
        )
        for p in enum.enumerate(node, cfg):
            if all(n in sat_set for n in p.nodes):
                return p
        return None

    def _counterexample(
        self, f: TLFormula[N], node: N, max_depth: int
    ) -> Optional[Path[N, L]]:
        """Find a path demonstrating failure of a universal formula."""
        if isinstance(f, CTL_AG):
            # AG φ fails → EF ¬φ holds: witness for ¬φ
            inner_neg = TLNot(f.inner)
            return self._witness(CTL_EF(inner_neg), node, max_depth)

        if isinstance(f, CTL_AF):
            # AF φ fails → EG ¬φ holds: find path that avoids φ
            inner_neg = TLNot(f.inner)
            return self._witness(CTL_EG(inner_neg), node, max_depth)

        if isinstance(f, CTL_AX):
            # AX φ fails → EX ¬φ
            return self._witness(CTL_EX(TLNot(f.inner)), node, max_depth)

        if isinstance(f, CTL_AU):
            # A[φ U ψ] fails → E[¬ψ U (¬φ ∧ ¬ψ)] ∨ EG ¬ψ
            neg_phi = TLNot(f.left)
            neg_psi = TLNot(f.right)
            w = self._witness(CTL_EU(neg_psi, TLAnd(neg_phi, neg_psi)), node, max_depth)
            if w is not None:
                return w
            return self._witness(CTL_EG(neg_psi), node, max_depth)

        return None


# ═══════════════════════════════════════════════════════════════════════
#  CONVENIENCE CONSTRUCTORS — for addons that never touch temporal logic
# ═══════════════════════════════════════════════════════════════════════

def all_simple_paths(
    graph: GraphLike[N, L],
    start: N,
    end: N,
    max_depth: int = 50,
    max_paths: int = 10_000,
) -> List[Path[N, L]]:
    """One-call API: all simple paths between two nodes."""
    return PathEnumerator(graph).find_all_paths(
        start, end, max_depth=max_depth, max_paths=max_paths
    )


def shortest_path(
    graph: GraphLike[N, L], start: N, end: N, max_depth: int = 200
) -> Optional[Path[N, L]]:
    """One-call API: shortest (fewest edges) path."""
    return PathEnumerator(graph).find_path(
        start, end, max_depth=max_depth, order=SearchOrder.BFS
    )


def worst_case_path(
    graph: GraphLike[N, L],
    start: N,
    end: N,
    weight_fn: Callable[[Edge[N, L]], float],
    max_depth: int = 200,
) -> Optional[Path[N, L]]:
    """One-call API: highest-cost simple path (for WCET / WCEC addons)."""
    return PathEnumerator(graph).pessimal_path(
        start, end, weight_fn, max_depth=max_depth
    )


def satisfying_paths(
    graph: GraphLike[N, L],
    start: N,
    predicate: PathPredicate[N, L],
    *,
    max_depth: int = 100,
    max_paths: int = 1_000,
) -> List[Path[N, L]]:
    """One-call API: enumerate paths from *start* that satisfy *predicate*."""
    enum = PathEnumerator(graph)
    cfg = SearchConfig(max_depth=max_depth, max_paths=max_paths * 5)
    filt = PathFilter(predicate)
    return list(itertools.islice(filt(enum.enumerate(start, cfg)), max_paths))


# ═══════════════════════════════════════════════════════════════════════
#  ADAPTERS — bridge substrate types into GraphLike
# ═══════════════════════════════════════════════════════════════════════

class CFGAdapter:
    """
    Wraps a substrate CFG (from cfg.py) as a GraphLike so the path
    analysis machinery works on it directly.

    Usage:
        from cppcheckdata_shims.cfg import build_cfg
        from cppcheckdata_shims.path_analysis import CFGAdapter, PathEnumerator

        cfg = build_cfg(function_scope)
        graph = CFGAdapter(cfg)
        enum = PathEnumerator(graph)
        for path in enum.enumerate():
            ...
    """

    def __init__(self, cfg_obj: Any) -> None:
        """
        *cfg_obj* should have:
          - .blocks  : dict[block_id, BasicBlock]
          - .entry   : block_id
          - .edges   : list of (src_id, dst_id, label) or similar

        We adapt flexibly to handle multiple substrate CFG layouts.
        """
        self._cfg = cfg_obj
        self._succ: Dict[Any, List[Tuple[Any, Any]]] = defaultdict(list)
        self._pred: Dict[Any, List[Tuple[Any, Any]]] = defaultdict(list)
        self._nodes: Set[Any] = set()
        self._entry_node: Any = None
        self._build()

    def _build(self) -> None:
        cfg = self._cfg

        # Detect CFG shape
        if hasattr(cfg, 'blocks') and hasattr(cfg, 'entry_id'):
            # Substrate CFG style
            self._nodes = set(cfg.blocks.keys())
            self._entry_node = cfg.entry_id
            for blk_id, blk in cfg.blocks.items():
                for succ_id in getattr(blk, 'successors', []):
                    label = getattr(blk, 'branch_label', lambda s: "edge")(succ_id) \
                        if callable(getattr(blk, 'branch_label', None)) else "edge"
                    self._succ[blk_id].append((succ_id, label))
                    self._pred[succ_id].append((blk_id, label))
        elif hasattr(cfg, 'entry') and hasattr(cfg, 'nodes'):
            # Generic graph-like CFG
            entry = cfg.entry() if callable(cfg.entry) else cfg.entry
            self._entry_node = entry
            ns = cfg.nodes() if callable(cfg.nodes) else cfg.nodes
            self._nodes = set(ns)
            for n in self._nodes:
                if hasattr(cfg, 'successors'):
                    for s, lbl in cfg.successors(n):
                        self._succ[n].append((s, lbl))
                        self._pred[s].append((n, lbl))
        else:
            raise TypeError(
                f"Cannot adapt {type(cfg).__name__} — expected .blocks/.entry_id "
                f"or .entry()/.nodes()/.successors()"
            )

    def successors(self, node: Any) -> Iterable[Tuple[Any, Any]]:
        return self._succ.get(node, [])

    def predecessors(self, node: Any) -> Iterable[Tuple[Any, Any]]:
        return self._pred.get(node, [])

    def nodes(self) -> Iterable[Any]:
        return self._nodes

    def entry(self) -> Any:
        return self._entry_node


class ExplicitStateGraphAdapter:
    """
    Wraps a transition_system.ExplicitStateGraph as GraphLike.
    """

    def __init__(self, esg: Any) -> None:
        self._esg = esg

    def successors(self, node: Any) -> Iterable[Tuple[Any, Any]]:
        if hasattr(self._esg, 'successors'):
            return self._esg.successors(node)
        # Fallback: edges dict
        return self._esg.edges.get(node, [])

    def predecessors(self, node: Any) -> Iterable[Tuple[Any, Any]]:
        if hasattr(self._esg, 'predecessors'):
            return self._esg.predecessors(node)
        return []

    def nodes(self) -> Iterable[Any]:
        if hasattr(self._esg, 'nodes'):
            ns = self._esg.nodes
            return ns() if callable(ns) else ns
        return self._esg.states

    def entry(self) -> Any:
        if hasattr(self._esg, 'entry'):
            e = self._esg.entry
            return e() if callable(e) else e
        return self._esg.initial_state


# ═══════════════════════════════════════════════════════════════════════
#  CONVENIENCE — Formula Constructors  (less typing for addon authors)
# ═══════════════════════════════════════════════════════════════════════

def atom(name: str, pred: Callable[[Any], bool]) -> TLFormula:
    """Create an atomic proposition formula."""
    return AtomicFormula(AP(name, pred))

# LTL
def X(phi: TLFormula) -> LTLNext:
    return LTLNext(phi)

def G(phi: TLFormula) -> LTLGlobally:
    return LTLGlobally(phi)

def F(phi: TLFormula) -> LTLFinally:
    return LTLFinally(phi)

def U(phi: TLFormula, psi: TLFormula) -> LTLUntil:
    return LTLUntil(phi, psi)

def R(phi: TLFormula, psi: TLFormula) -> LTLRelease:
    return LTLRelease(phi, psi)

def W(phi: TLFormula, psi: TLFormula) -> LTLWeakUntil:
    return LTLWeakUntil(phi, psi)

# CTL
def EX(phi: TLFormula) -> CTL_EX:
    return CTL_EX(phi)

def AX(phi: TLFormula) -> CTL_AX:
    return CTL_AX(phi)

def EF(phi: TLFormula) -> CTL_EF:
    return CTL_EF(phi)

def AF(phi: TLFormula) -> CTL_AF:
    return CTL_AF(phi)

def EG(phi: TLFormula) -> CTL_EG:
    return CTL_EG(phi)

def AG(phi: TLFormula) -> CTL_AG:
    return CTL_AG(phi)

def EU(phi: TLFormula, psi: TLFormula) -> CTL_EU:
    return CTL_EU(phi, psi)

def AU(phi: TLFormula, psi: TLFormula) -> CTL_AU:
    return CTL_AU(phi, psi)


# ═══════════════════════════════════════════════════════════════════════
#  __all__  — public API
# ═══════════════════════════════════════════════════════════════════════

__all__ = [
    # Layer 0 — Protocols
    "GraphLike",
    "StateLike",
    # Layer 1 — Path Representation
    "Edge",
    "Path",
    "PathSet",
    # Layer 2 — Enumeration & Search
    "SearchOrder",
    "SearchConfig",
    "PathEnumerator",
    # Layer 3 — Predicates & Filtering
    "PathPredicate",
    "NodeSatisfies",
    "SomeNodeSatisfies",
    "EdgeSatisfies",
    "SomeEdgeSatisfies",
    "PathVisits",
    "PathAvoids",
    "ReachesWithin",
    "CostBelow",
    "CostAbove",
    "OrderedVisit",
    "MonotonicProperty",
    "PathFilter",
    # Layer 4 — Temporal Logic
    "AP",
    "TLFormula",
    "TLTrue",
    "TLFalse",
    "TLNot",
    "TLAnd",
    "TLOr",
    "AtomicFormula",
    "LTLNext",
    "LTLGlobally",
    "LTLFinally",
    "LTLUntil",
    "LTLRelease",
    "LTLWeakUntil",
    "CTL_EX",
    "CTL_AX",
    "CTL_EF",
    "CTL_AF",
    "CTL_EG",
    "CTL_AG",
    "CTL_EU",
    "CTL_AU",
    "LTLEvaluator",
    "CTLEvaluator",
    # Convenience constructors
    "atom",
    "X", "G", "F", "U", "R", "W",
    "EX", "AX", "EF", "AF", "EG", "AG", "EU", "AU",
    # One-call APIs
    "all_simple_paths",
    "shortest_path",
    "worst_case_path",
    "satisfying_paths",
    # Adapters
    "CFGAdapter",
    "ExplicitStateGraphAdapter",
    "path_analysis",
    "Path",
    "Edge",
    "PathEnumerator",
    "PathPredicate",
    "PathFilter",
    "LTLFormula",
    "CTLFormula",
    "LTLEvaluator",
    "CTLEvaluator",
    "GraphLike",
    "CFGAdapter",
]
