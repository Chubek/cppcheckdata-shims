"""
cppcheckdata_shims/dependency_graph.py
══════════════════════════════════════

Data-dependency and program-dependency graph construction, querying,
and slicing for cppcheckdata-shims addons.

Provides a **Program Dependency Graph (PDG)** that unifies:

    ┌─────────────────────────────────────────────────────────────────┐
    │  Dependency Kinds                                               │
    │    DATA      — def-use chain (definition reaches use)           │
    │    CONTROL   — control dependence (branch governs statement)    │
    │    ANTI      — use before def in same scope (WAR hazard)        │
    │    OUTPUT    — def before def without intervening use (WAW)     │
    │    CALL      — call site → callee entry                         │
    │    PARAM     — actual parameter → formal parameter              │
    │    RETURN    — callee return value → call site                  │
    └─────────────────────────────────────────────────────────────────┘

Theory (Ferrante, Ottenstein & Warren 1987; Horwitz, Reps & Binkley 1990):

    The Program Dependency Graph (PDG) represents a procedure as a
    directed graph where nodes are statements/predicates and edges are
    either:
        (a) data-dependence:  n →_d m  iff  n defines a variable v
            that m uses, and there is a def-clear path n →* m for v.
        (b) control-dependence:  n →_c m  iff  n is a predicate and
            m's execution depends on the outcome of n.

    Slicing (Weiser 1984): Given criterion ⟨p, V⟩ (program point p,
    variable set V), the backward slice is the set of all nodes from
    which there is a path in the PDG to a node at p that defines or
    uses a variable in V.

Integration points:
    - ``ctrlflow_graph.py``   — CFG nodes used for control-dependence
    - ``dataflow_engine.py``  — worklist solver for reaching definitions
    - ``callgraph.py``        — inter-procedural CALL/PARAM/RETURN edges
    - ``ast_helper.py``       — token / AST navigation utilities
    - ``taint_analysis.py``   — taint can propagate along data-dep edges
    - ``checkers.py``         — addons query the graph for dead stores, etc.

Usage example::

    from cppcheckdata_shims.dependency_graph import (
        DependencyGraphBuilder,
        slice_backward,
        DepKind,
    )

    builder = DependencyGraphBuilder()
    pdg = builder.build(cfg)           # cfg from cppcheckdata.parsedump()

    # All data-dependency predecessors of token at line 42
    node = pdg.node_at(line=42, column=5)
    for edge in node.in_edges(DepKind.DATA):
        print(f"defined at line {edge.source.line} var={edge.variable}")

    # Backward slice from variable 'buf' at line 42
    sliced = slice_backward(pdg, line=42, column=5, variables={"buf"})
    for n in sliced:
        print(f"  slice includes line {n.line}")

    # Export to Graphviz DOT
    dot_str = pdg.to_dot()

License: MIT — same as cppcheckdata-shims.
"""

from __future__ import annotations

import itertools
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import (
    Any,
    Callable,
    Deque,
    Dict,
    FrozenSet,
    Iterable,
    Iterator,
    List,
    Mapping,
    Optional,
    Protocol,
    Sequence,
    Set,
    Tuple,
    Union,
)

# ─────────────────────────────────────────────────────────────────────────
#  Sibling imports — follow the same guarded pattern as every other module
# ─────────────────────────────────────────────────────────────────────────

try:
    from . import ast_helper  # token/AST navigation utilities
except ImportError:
    ast_helper = None  # type: ignore[assignment]

try:
    from . import ctrlflow_graph as _cfg_mod  # CFG construction
except ImportError:
    _cfg_mod = None  # type: ignore[assignment]

try:
    from . import callgraph as _cg_mod  # inter-procedural call graph
except ImportError:
    _cg_mod = None  # type: ignore[assignment]


# ═══════════════════════════════════════════════════════════════════════════
#  PART 0 — DEPENDENCY KINDS
# ═══════════════════════════════════════════════════════════════════════════

class DepKind(Enum):
    """
    Classification of dependency edges.

    Following the standard taxonomy from compiler theory:

        DATA      — true dependence (Read After Write / RAW / flow)
                    Definition at source reaches a use at target.
        CONTROL   — target's execution is controlled by source predicate.
        ANTI      — anti-dependence (Write After Read / WAR)
                    Source uses a variable that target redefines.
        OUTPUT    — output dependence (Write After Write / WAW)
                    Source defines a variable that target redefines
                    without an intervening use.
        CALL      — inter-procedural: call site → callee entry node.
        PARAM     — inter-procedural: actual parameter → formal parameter.
        RETURN    — inter-procedural: callee return → call-site result.
    """
    DATA    = auto()
    CONTROL = auto()
    ANTI    = auto()
    OUTPUT  = auto()
    CALL    = auto()
    PARAM   = auto()
    RETURN  = auto()


# ═══════════════════════════════════════════════════════════════════════════
#  PART 1 — NODE AND EDGE DATA STRUCTURES
# ═══════════════════════════════════════════════════════════════════════════


@dataclass(frozen=True, slots=True)
class DepEdge:
    """
    A single dependency edge in the PDG.

    Attributes
    ----------
    source : DepNode
        The origin node (definition / predicate / call site).
    target : DepNode
        The destination node (use / controlled statement / callee).
    kind : DepKind
        The dependency classification.
    variable : str
        The variable name through which the dependence exists.
        Empty string for CONTROL edges.
    var_id : int
        The cppcheck ``varId`` of the variable (0 if not applicable).
    label : str
        Optional human-readable label for DOT export.
    """
    source: DepNode
    target: DepNode
    kind: DepKind
    variable: str = ""
    var_id: int = 0
    label: str = ""

    def __repr__(self) -> str:
        v = f" [{self.variable}]" if self.variable else ""
        return (
            f"DepEdge({self.source.node_id}→{self.target.node_id} "
            f"{self.kind.name}{v})"
        )


@dataclass(slots=True)
class DepNode:
    """
    A node in the dependency graph, wrapping a program point.

    Each node corresponds to a *statement-level* token — typically the
    first significant token of an expression-statement, declaration,
    return, branch predicate, or function call.

    Attributes
    ----------
    node_id : int
        Unique integer identifier within the graph.
    token : object
        The underlying cppcheckdata token (has .str, .linenr, .column,
        .file, .varId, etc.).
    line : int
        Source line number (cached for fast queries).
    column : int
        Source column number.
    file : str
        Source file path.
    scope_id : int
        The cppcheck scope id this node belongs to.
    is_predicate : bool
        True if this node is a branch predicate (if/while/for/switch).
    function_name : str
        Name of the enclosing function (empty at file scope).

    _in_edges : List[DepEdge]
        Edges *into* this node (this node is the target).
    _out_edges : List[DepEdge]
        Edges *out of* this node (this node is the source).
    """
    node_id: int
    token: Any
    line: int = 0
    column: int = 0
    file: str = ""
    scope_id: int = 0
    is_predicate: bool = False
    function_name: str = ""
    _in_edges: List[DepEdge] = field(default_factory=list, repr=False)
    _out_edges: List[DepEdge] = field(default_factory=list, repr=False)

    # ── Definitions and uses at this node ─────────────────────────────
    defs: FrozenSet[int] = field(default_factory=frozenset)   # varIds defined
    uses: FrozenSet[int] = field(default_factory=frozenset)   # varIds used
    def_names: Dict[int, str] = field(default_factory=dict)   # varId → name
    use_names: Dict[int, str] = field(default_factory=dict)   # varId → name

    # ── Query helpers ─────────────────────────────────────────────────

    def in_edges(self, kind: Optional[DepKind] = None) -> List[DepEdge]:
        """Return incoming edges, optionally filtered by kind."""
        if kind is None:
            return list(self._in_edges)
        return [e for e in self._in_edges if e.kind is kind]

    def out_edges(self, kind: Optional[DepKind] = None) -> List[DepEdge]:
        """Return outgoing edges, optionally filtered by kind."""
        if kind is None:
            return list(self._out_edges)
        return [e for e in self._out_edges if e.kind is kind]

    def predecessors(self, kind: Optional[DepKind] = None) -> List[DepNode]:
        """Return source nodes of incoming edges."""
        return [e.source for e in self.in_edges(kind)]

    def successors(self, kind: Optional[DepKind] = None) -> List[DepNode]:
        """Return target nodes of outgoing edges."""
        return [e.target for e in self.out_edges(kind)]

    def data_predecessors(self) -> List[DepNode]:
        """Shorthand: nodes providing data to this node."""
        return self.predecessors(DepKind.DATA)

    def data_successors(self) -> List[DepNode]:
        """Shorthand: nodes consuming data from this node."""
        return self.successors(DepKind.DATA)

    def control_predecessor(self) -> Optional[DepNode]:
        """Return the predicate controlling this node (if any)."""
        preds = self.predecessors(DepKind.CONTROL)
        return preds[0] if preds else None

    def __hash__(self) -> int:
        return self.node_id

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, DepNode):
            return NotImplemented
        return self.node_id == other.node_id

    def __repr__(self) -> str:
        tok_str = getattr(self.token, "str", "?")[:20]
        return (
            f"DepNode(id={self.node_id}, L{self.line}:{self.column}, "
            f"tok='{tok_str}')"
        )


# ═══════════════════════════════════════════════════════════════════════════
#  PART 2 — REACHING DEFINITIONS  (Gen/Kill dataflow)
# ═══════════════════════════════════════════════════════════════════════════
#
#  Classic reaching-definitions analysis (Aho, Sethi, Ullman —
#  "Dragon Book" §9.2):
#
#    A definition  d: v = ...  at program point p  REACHES point q if
#    there is a path p →* q with no other definition of v on that path.
#
#    Domain:    ℘(Definitions)   — powerset of (node_id, var_id) pairs
#    Direction: Forward
#    Meet:      Union (∪)
#    Transfer:  OUT[n] = Gen[n] ∪ (IN[n] \ Kill[n])
#
#  We do NOT use the dataflow_engine here directly because we need the
#  per-node Gen/Kill sets as intermediate artifacts to build data-dep
#  edges.  However, the fixpoint iteration follows the same pattern.
# ═══════════════════════════════════════════════════════════════════════════

# A definition is identified by (node_id, var_id).
Definition = Tuple[int, int]


@dataclass
class ReachingDefinitions:
    """
    Reaching-definitions analysis result.

    Attributes
    ----------
    gen : Dict[int, Set[Definition]]
        gen[node_id] = set of definitions generated at that node.
    kill : Dict[int, Set[Definition]]
        kill[node_id] = set of definitions killed at that node.
    rd_in : Dict[int, Set[Definition]]
        Reaching definitions at entry of each node.
    rd_out : Dict[int, Set[Definition]]
        Reaching definitions at exit of each node.
    all_defs_for_var : Dict[int, Set[Definition]]
        All definitions for each var_id across the entire function.
    """
    gen: Dict[int, Set[Definition]] = field(default_factory=lambda: defaultdict(set))
    kill: Dict[int, Set[Definition]] = field(default_factory=lambda: defaultdict(set))
    rd_in: Dict[int, Set[Definition]] = field(default_factory=lambda: defaultdict(set))
    rd_out: Dict[int, Set[Definition]] = field(default_factory=lambda: defaultdict(set))
    all_defs_for_var: Dict[int, Set[Definition]] = field(
        default_factory=lambda: defaultdict(set)
    )


def _compute_reaching_definitions(
    nodes: Sequence[DepNode],
    cfg_succs: Dict[int, List[int]],
    cfg_preds: Dict[int, List[int]],
) -> ReachingDefinitions:
    """
    Compute reaching definitions via iterative worklist algorithm.

    Parameters
    ----------
    nodes : Sequence[DepNode]
        All nodes in topological (or any) order.
    cfg_succs : Dict[int, List[int]]
        CFG successor map: node_id → [successor node_ids].
    cfg_preds : Dict[int, List[int]]
        CFG predecessor map: node_id → [predecessor node_ids].

    Returns
    -------
    ReachingDefinitions
        The converged analysis result.
    """
    rd = ReachingDefinitions()

    # Phase 1: Compute all_defs_for_var, gen, kill
    for n in nodes:
        for vid in n.defs:
            defn = (n.node_id, vid)
            rd.gen[n.node_id].add(defn)
            rd.all_defs_for_var[vid].add(defn)

    for n in nodes:
        for vid in n.defs:
            # Kill = all other definitions of the same variable
            for d in rd.all_defs_for_var[vid]:
                if d[0] != n.node_id:
                    rd.kill[n.node_id].add(d)

    # Phase 2: Iterative fixpoint  (forward, meet = union)
    node_ids = [n.node_id for n in nodes]
    worklist: Deque[int] = deque(node_ids)
    in_worklist: Set[int] = set(node_ids)

    while worklist:
        nid = worklist.popleft()
        in_worklist.discard(nid)

        # IN[n] = ∪ OUT[p]  for all predecessors p
        new_in: Set[Definition] = set()
        for pid in cfg_preds.get(nid, []):
            new_in |= rd.rd_out.get(pid, set())
        rd.rd_in[nid] = new_in

        # OUT[n] = Gen[n] ∪ (IN[n] \ Kill[n])
        new_out = rd.gen.get(nid, set()) | (new_in - rd.kill.get(nid, set()))

        if new_out != rd.rd_out.get(nid, set()):
            rd.rd_out[nid] = new_out
            for sid in cfg_succs.get(nid, []):
                if sid not in in_worklist:
                    worklist.append(sid)
                    in_worklist.add(sid)

    return rd


# ═══════════════════════════════════════════════════════════════════════════
#  PART 3 — POST-DOMINANCE AND CONTROL DEPENDENCE
# ═══════════════════════════════════════════════════════════════════════════
#
#  Control dependence (Ferrante, Ottenstein & Warren 1987):
#
#    Node m is control-dependent on node n  iff
#      (1) there exists a path from n to m in the CFG such that every
#          node on the path (excluding n) is post-dominated by m, AND
#      (2) n is NOT post-dominated by m.
#
#  Equivalently, we use the post-dominator tree:
#    For each CFG edge (A → B), walk up the post-dominator tree from A
#    (exclusive) to ipdom(B) (inclusive if A ≠ ipdom(B), exclusive if
#    A = ipdom(B)).  Every node encountered on this walk is control-
#    dependent on A.
#
#  We compute the post-dominator tree using the classic iterative
#  algorithm on the reverse CFG (Cooper, Harvey, Kennedy 2001).
# ═══════════════════════════════════════════════════════════════════════════


def _compute_post_dominators(
    node_ids: Sequence[int],
    cfg_succs: Dict[int, List[int]],
    cfg_preds: Dict[int, List[int]],
    exit_id: int,
) -> Dict[int, int]:
    """
    Compute immediate post-dominators via iterative algorithm.

    Parameters
    ----------
    node_ids : Sequence[int]
        All node ids in reverse-postorder of the *forward* CFG.
    cfg_succs : Dict[int, List[int]]
        Forward CFG successor map.
    cfg_preds : Dict[int, List[int]]
        Forward CFG predecessor map.
    exit_id : int
        The unique exit node id.

    Returns
    -------
    Dict[int, int]
        Mapping from node_id → immediate post-dominator node_id.
        The exit node maps to itself.
    """
    # Reverse CFG: preds become succs and vice versa
    rev_succs = cfg_preds  # successors in reverse CFG = predecessors in forward
    rev_preds = cfg_succs  # predecessors in reverse CFG = successors in forward

    # Reverse postorder of reverse CFG ≈ postorder of forward CFG
    # We compute RPO of the reverse CFG starting from exit_id
    rpo = _reverse_postorder(exit_id, rev_succs)
    rpo_number: Dict[int, int] = {nid: i for i, nid in enumerate(rpo)}

    # Initialize ipdom
    ipdom: Dict[int, int] = {}
    ipdom[exit_id] = exit_id

    def intersect(b1: int, b2: int) -> int:
        """Find common dominator using the finger-merge algorithm."""
        while b1 != b2:
            while rpo_number.get(b1, len(rpo)) > rpo_number.get(b2, len(rpo)):
                b1 = ipdom.get(b1, b1)
            while rpo_number.get(b2, len(rpo)) > rpo_number.get(b1, len(rpo)):
                b2 = ipdom.get(b2, b2)
        return b1

    changed = True
    while changed:
        changed = False
        for nid in rpo:
            if nid == exit_id:
                continue
            # Predecessors in reverse CFG = successors in forward CFG
            preds = rev_preds.get(nid, [])
            processed = [p for p in preds if p in ipdom]
            if not processed:
                continue
            new_ipdom = processed[0]
            for p in processed[1:]:
                new_ipdom = intersect(new_ipdom, p)
            if ipdom.get(nid) != new_ipdom:
                ipdom[nid] = new_ipdom
                changed = True

    return ipdom


def _reverse_postorder(start: int, succs: Dict[int, List[int]]) -> List[int]:
    """Compute reverse-postorder traversal from *start*."""
    visited: Set[int] = set()
    post_order: List[int] = []

    def dfs(n: int) -> None:
        if n in visited:
            return
        visited.add(n)
        for s in succs.get(n, []):
            dfs(s)
        post_order.append(n)

    dfs(start)
    post_order.reverse()
    return post_order


def _compute_control_dependence(
    node_ids: Sequence[int],
    cfg_succs: Dict[int, List[int]],
    cfg_preds: Dict[int, List[int]],
    exit_id: int,
    predicates: Set[int],
) -> List[Tuple[int, int]]:
    """
    Compute control-dependence edges.

    Returns a list of (predicate_node_id, dependent_node_id) pairs.
    """
    ipdom = _compute_post_dominators(node_ids, cfg_succs, cfg_preds, exit_id)
    cd_edges: List[Tuple[int, int]] = []

    for a in node_ids:
        for b in cfg_succs.get(a, []):
            # Walk from b up to ipdom(a) in the post-dominator tree
            runner = b
            target = ipdom.get(a, a)
            visited: Set[int] = set()
            while runner != target and runner not in visited:
                visited.add(runner)
                if runner != a:  # a is not control-dependent on itself
                    cd_edges.append((a, runner))
                runner = ipdom.get(runner, runner)
                if runner == runner:  # self-loop in ipdom → root
                    break
            # If a == target, b is also control-dependent on a
            if a == target and b != a:
                cd_edges.append((a, b))

    # Filter: only keep edges where the source is actually a predicate
    cd_edges = [(s, t) for s, t in cd_edges if s in predicates]
    return cd_edges


# ═══════════════════════════════════════════════════════════════════════════
#  PART 4 — THE DEPENDENCY GRAPH
# ═══════════════════════════════════════════════════════════════════════════


class DependencyGraph:
    """
    Program Dependency Graph (PDG) for one function / configuration.

    Combines data-dependence and control-dependence edges into a single
    queryable graph.  Supports:

        - Node lookup by id, line/column, variable
        - Edge filtering by kind
        - Forward/backward reachability
        - Forward/backward program slicing
        - Topological iteration
        - DOT export for visualisation

    Construction is done via ``DependencyGraphBuilder.build(cfg)``.
    """

    def __init__(self) -> None:
        self._nodes: Dict[int, DepNode] = {}          # node_id → DepNode
        self._edges: List[DepEdge] = []
        self._line_index: Dict[int, List[DepNode]] = defaultdict(list)
        self._var_defs: Dict[int, List[DepNode]] = defaultdict(list)  # varId → defining nodes
        self._var_uses: Dict[int, List[DepNode]] = defaultdict(list)  # varId → using nodes
        self._node_counter: int = 0
        self._function_name: str = ""

        # CFG structure (kept for slicing / reachability)
        self._cfg_succs: Dict[int, List[int]] = defaultdict(list)
        self._cfg_preds: Dict[int, List[int]] = defaultdict(list)

    # ── Properties ────────────────────────────────────────────────────

    @property
    def nodes(self) -> List[DepNode]:
        """All nodes in insertion order."""
        return list(self._nodes.values())

    @property
    def edges(self) -> List[DepEdge]:
        """All edges."""
        return list(self._edges)

    @property
    def function_name(self) -> str:
        return self._function_name

    @property
    def node_count(self) -> int:
        return len(self._nodes)

    @property
    def edge_count(self) -> int:
        return len(self._edges)

    # ── Node creation (used by builder) ───────────────────────────────

    def _next_id(self) -> int:
        self._node_counter += 1
        return self._node_counter

    def add_node(self, token: Any, **kwargs: Any) -> DepNode:
        """Create and register a new DepNode."""
        nid = self._next_id()
        node = DepNode(
            node_id=nid,
            token=token,
            line=kwargs.get("line", getattr(token, "linenr", 0)),
            column=kwargs.get("column", getattr(token, "column", 0)),
            file=kwargs.get("file", getattr(token, "file", "")),
            scope_id=kwargs.get("scope_id", 0),
            is_predicate=kwargs.get("is_predicate", False),
            function_name=kwargs.get("function_name", ""),
            defs=frozenset(kwargs.get("defs", frozenset())),
            uses=frozenset(kwargs.get("uses", frozenset())),
            def_names=kwargs.get("def_names", {}),
            use_names=kwargs.get("use_names", {}),
        )
        self._nodes[nid] = node
        self._line_index[node.line].append(node)
        for vid in node.defs:
            self._var_defs[vid].append(node)
        for vid in node.uses:
            self._var_uses[vid].append(node)
        return node

    def add_edge(
        self,
        source: DepNode,
        target: DepNode,
        kind: DepKind,
        variable: str = "",
        var_id: int = 0,
        label: str = "",
    ) -> DepEdge:
        """Create and register a new DepEdge."""
        edge = DepEdge(
            source=source,
            target=target,
            kind=kind,
            variable=variable,
            var_id=var_id,
            label=label or f"{kind.name}",
        )
        self._edges.append(edge)
        source._out_edges.append(edge)
        target._in_edges.append(edge)
        return edge

    # ── Lookup ────────────────────────────────────────────────────────

    def node_by_id(self, node_id: int) -> Optional[DepNode]:
        """Look up a node by its unique id."""
        return self._nodes.get(node_id)

    def nodes_at(self, line: int, column: Optional[int] = None) -> List[DepNode]:
        """Return all nodes at a given source line (and optionally column)."""
        candidates = self._line_index.get(line, [])
        if column is not None:
            candidates = [n for n in candidates if n.column == column]
        return candidates

    def node_at(self, line: int, column: int) -> Optional[DepNode]:
        """Return the first node at (line, column), or None."""
        nodes = self.nodes_at(line, column)
        return nodes[0] if nodes else None

    def definitions_of(self, var_id: int) -> List[DepNode]:
        """All nodes that define the given variable."""
        return list(self._var_defs.get(var_id, []))

    def uses_of(self, var_id: int) -> List[DepNode]:
        """All nodes that use the given variable."""
        return list(self._var_uses.get(var_id, []))

    def edges_of_kind(self, kind: DepKind) -> List[DepEdge]:
        """All edges of a particular dependency kind."""
        return [e for e in self._edges if e.kind is kind]

    # ── Reachability ──────────────────────────────────────────────────

    def reachable_forward(
        self,
        start: DepNode,
        kinds: Optional[Set[DepKind]] = None,
    ) -> Set[DepNode]:
        """
        All nodes reachable from *start* via outgoing edges.

        Parameters
        ----------
        start : DepNode
        kinds : Optional[Set[DepKind]]
            If provided, only traverse edges of these kinds.
        """
        visited: Set[DepNode] = set()
        queue: Deque[DepNode] = deque([start])
        while queue:
            node = queue.popleft()
            if node in visited:
                continue
            visited.add(node)
            for edge in node.out_edges():
                if kinds is None or edge.kind in kinds:
                    queue.append(edge.target)
        return visited

    def reachable_backward(
        self,
        start: DepNode,
        kinds: Optional[Set[DepKind]] = None,
    ) -> Set[DepNode]:
        """
        All nodes from which *start* is reachable via incoming edges.
        """
        visited: Set[DepNode] = set()
        queue: Deque[DepNode] = deque([start])
        while queue:
            node = queue.popleft()
            if node in visited:
                continue
            visited.add(node)
            for edge in node.in_edges():
                if kinds is None or edge.kind in kinds:
                    queue.append(edge.source)
        return visited

    # ── Dead-store detection ──────────────────────────────────────────

    def dead_stores(self) -> List[DepNode]:
        """
        Return nodes that define a variable but have no outgoing
        DATA edge — i.e., the definition is never used.
        """
        dead: List[DepNode] = []
        for node in self._nodes.values():
            if node.defs and not node.out_edges(DepKind.DATA):
                dead.append(node)
        return dead

    # ── Topological ordering ──────────────────────────────────────────

    def topological_order(
        self,
        kinds: Optional[Set[DepKind]] = None,
    ) -> List[DepNode]:
        """
        Kahn's algorithm for topological sort over edges of given kinds.

        If the graph has cycles (possible with loops), the result is a
        best-effort ordering (nodes in cycles are appended at the end).
        """
        in_degree: Dict[int, int] = defaultdict(int)
        adj: Dict[int, List[int]] = defaultdict(list)

        for edge in self._edges:
            if kinds is not None and edge.kind not in kinds:
                continue
            adj[edge.source.node_id].append(edge.target.node_id)
            in_degree[edge.target.node_id] += 1

        for nid in self._nodes:
            in_degree.setdefault(nid, 0)

        queue: Deque[int] = deque(
            nid for nid, deg in in_degree.items() if deg == 0
        )
        result: List[DepNode] = []
        while queue:
            nid = queue.popleft()
            node = self._nodes.get(nid)
            if node is not None:
                result.append(node)
            for tid in adj.get(nid, []):
                in_degree[tid] -= 1
                if in_degree[tid] == 0:
                    queue.append(tid)

        # Append remaining (cycle members) in id order
        seen = {n.node_id for n in result}
        for nid in sorted(self._nodes.keys()):
            if nid not in seen:
                result.append(self._nodes[nid])

        return result

    # ── DOT export ────────────────────────────────────────────────────

    def to_dot(
        self,
        title: Optional[str] = None,
        kinds: Optional[Set[DepKind]] = None,
        highlight_nodes: Optional[Set[int]] = None,
    ) -> str:
        """
        Export the graph in Graphviz DOT format.

        Parameters
        ----------
        title : Optional[str]
            Graph title.
        kinds : Optional[Set[DepKind]]
            Only include edges of these kinds.  None = all.
        highlight_nodes : Optional[Set[int]]
            Node ids to highlight (filled yellow).

        Returns
        -------
        str
            DOT source text.
        """
        if title is None:
            title = f"PDG: {self._function_name}" if self._function_name else "PDG"
        highlight = highlight_nodes or set()

        lines: List[str] = [
            f'digraph "{title}" {{',
            '  rankdir=TB;',
            '  node [shape=box, fontname="Courier", fontsize=10];',
            '  edge [fontname="Courier", fontsize=8];',
        ]

        _KIND_STYLE: Dict[DepKind, str] = {
            DepKind.DATA:    'color="blue"',
            DepKind.CONTROL: 'color="red", style="dashed"',
            DepKind.ANTI:    'color="orange", style="dotted"',
            DepKind.OUTPUT:  'color="purple", style="dotted"',
            DepKind.CALL:    'color="darkgreen", style="bold"',
            DepKind.PARAM:   'color="darkgreen"',
            DepKind.RETURN:  'color="darkgreen", style="dashed"',
        }

        for node in self._nodes.values():
            tok_str = getattr(node.token, "str", "?")[:30]
            lbl = f"L{node.line}: {tok_str}"
            if node.defs:
                def_names = ", ".join(node.def_names.get(v, f"v{v}") for v in node.defs)
                lbl += f"\\ndef: {def_names}"
            if node.uses:
                use_names = ", ".join(node.use_names.get(v, f"v{v}") for v in node.uses)
                lbl += f"\\nuse: {use_names}"
            style = ', style="filled", fillcolor="yellow"' if node.node_id in highlight else ""
            pred = ', shape="diamond"' if node.is_predicate else ""
            lines.append(f'  n{node.node_id} [label="{lbl}"{style}{pred}];')

        for edge in self._edges:
            if kinds is not None and edge.kind not in kinds:
                continue
            style = _KIND_STYLE.get(edge.kind, "")
            elbl = edge.variable if edge.variable else edge.kind.name
            lines.append(
                f'  n{edge.source.node_id} -> n{edge.target.node_id} '
                f'[label="{elbl}", {style}];'
            )

        lines.append("}")
        return "\n".join(lines)

    # ── Summary ───────────────────────────────────────────────────────

    def summary(self) -> Dict[str, Any]:
        """Return a dictionary summarising graph statistics."""
        kind_counts = defaultdict(int)
        for e in self._edges:
            kind_counts[e.kind.name] += 1
        return {
            "function": self._function_name,
            "nodes": self.node_count,
            "edges": self.edge_count,
            "edges_by_kind": dict(kind_counts),
            "predicates": sum(1 for n in self._nodes.values() if n.is_predicate),
            "dead_stores": len(self.dead_stores()),
        }

    def __repr__(self) -> str:
        return (
            f"DependencyGraph(fn='{self._function_name}', "
            f"nodes={self.node_count}, edges={self.edge_count})"
        )


# ═══════════════════════════════════════════════════════════════════════════
#  PART 5 — PROGRAM SLICING
# ═══════════════════════════════════════════════════════════════════════════
#
#  Program slicing (Weiser 1984; Tip 1995 survey):
#
#    Slicing criterion:  C = ⟨p, V⟩  — a program point p and a set of
#    variables V.
#
#    Backward slice:  all statements that could affect the values of V
#    at point p.  Computed as backward reachability in the PDG from
#    nodes at p that define/use variables in V.
#
#    Forward slice:  all statements that could be affected by changes
#    at point p.  Computed as forward reachability in the PDG.
# ═══════════════════════════════════════════════════════════════════════════


def slice_backward(
    graph: DependencyGraph,
    line: int,
    column: Optional[int] = None,
    variables: Optional[Set[str]] = None,
    kinds: Optional[Set[DepKind]] = None,
) -> Set[DepNode]:
    """
    Compute a backward program slice.

    Parameters
    ----------
    graph : DependencyGraph
    line : int
        Source line of the slicing criterion.
    column : Optional[int]
        Source column (None = any column at that line).
    variables : Optional[Set[str]]
        Variable names in the criterion.  None = all variables at that point.
    kinds : Optional[Set[DepKind]]
        Edge kinds to follow.  None = DATA + CONTROL (standard slice).

    Returns
    -------
    Set[DepNode]
        The set of nodes in the backward slice.
    """
    if kinds is None:
        kinds = {DepKind.DATA, DepKind.CONTROL}

    # Find seed nodes
    candidates = graph.nodes_at(line, column)
    seeds: List[DepNode] = []
    for n in candidates:
        if variables is None:
            seeds.append(n)
        else:
            # Check if node defines or uses any of the named variables
            all_names = set(n.def_names.values()) | set(n.use_names.values())
            if all_names & variables:
                seeds.append(n)

    if not seeds:
        return set()

    result: Set[DepNode] = set()
    for seed in seeds:
        result |= graph.reachable_backward(seed, kinds)
    return result


def slice_forward(
    graph: DependencyGraph,
    line: int,
    column: Optional[int] = None,
    variables: Optional[Set[str]] = None,
    kinds: Optional[Set[DepKind]] = None,
) -> Set[DepNode]:
    """
    Compute a forward program slice.

    Parameters
    ----------
    graph : DependencyGraph
    line : int
        Source line of the slicing criterion.
    column : Optional[int]
        Source column.
    variables : Optional[Set[str]]
        Variable names in the criterion.
    kinds : Optional[Set[DepKind]]
        Edge kinds to follow.  None = DATA + CONTROL.

    Returns
    -------
    Set[DepNode]
        The set of nodes in the forward slice.
    """
    if kinds is None:
        kinds = {DepKind.DATA, DepKind.CONTROL}

    candidates = graph.nodes_at(line, column)
    seeds: List[DepNode] = []
    for n in candidates:
        if variables is None:
            seeds.append(n)
        else:
            all_names = set(n.def_names.values()) | set(n.use_names.values())
            if all_names & variables:
                seeds.append(n)

    if not seeds:
        return set()

    result: Set[DepNode] = set()
    for seed in seeds:
        result |= graph.reachable_forward(seed, kinds)
    return result


def chop(
    graph: DependencyGraph,
    source_line: int,
    sink_line: int,
    kinds: Optional[Set[DepKind]] = None,
) -> Set[DepNode]:
    """
    Compute a program chop:  forward slice from source ∩ backward slice
    from sink.

    This isolates the statements through which information flows from
    the source point to the sink point — highly useful for taint analysis
    and understanding data provenance.
    """
    fwd = slice_forward(graph, source_line, kinds=kinds)
    bwd = slice_backward(graph, sink_line, kinds=kinds)
    return fwd & bwd


# ═══════════════════════════════════════════════════════════════════════════
#  PART 6 — TOKEN / AST HELPERS FOR THE BUILDER
# ═══════════════════════════════════════════════════════════════════════════


def _get_var_id(token: Any) -> int:
    """Extract varId from a cppcheck token, or 0."""
    return getattr(token, "varId", 0) or 0


def _get_var_name(token: Any) -> str:
    """Extract the string name from a cppcheck token."""
    return getattr(token, "str", "")


def _is_assignment(token: Any) -> bool:
    """Check if a token is an assignment operator."""
    return getattr(token, "isAssignmentOp", False)


def _is_comparison(token: Any) -> bool:
    """Check if a token is a comparison operator."""
    return getattr(token, "isComparisonOp", False)


def _collect_var_ids_in_subtree(token: Any) -> Dict[int, str]:
    """
    Walk the AST subtree rooted at *token* and collect all
    (varId → name) pairs found in leaf nodes.
    """
    result: Dict[int, str] = {}
    if token is None:
        return result
    stack: List[Any] = [token]
    while stack:
        t = stack.pop()
        if t is None:
            continue
        vid = _get_var_id(t)
        if vid:
            result[vid] = _get_var_name(t)
        op1 = getattr(t, "astOperand1", None)
        op2 = getattr(t, "astOperand2", None)
        if op1 is not None:
            stack.append(op1)
        if op2 is not None:
            stack.append(op2)
    return result


def _is_predicate_keyword(token: Any) -> bool:
    """Check if a token is a control-flow keyword (if/while/for/switch)."""
    s = getattr(token, "str", "")
    return s in ("if", "while", "for", "switch", "case")


# ═══════════════════════════════════════════════════════════════════════════
#  PART 7 — DEPENDENCY GRAPH BUILDER
# ═══════════════════════════════════════════════════════════════════════════


class DependencyGraphBuilder:
    """
    Constructs a ``DependencyGraph`` from a Cppcheck dump configuration.

    The builder performs these passes:

    1.  **Statement identification** — walk the token stream and identify
        statement-level tokens (assignments, calls, declarations, returns,
        predicates).

    2.  **Def/Use extraction** — for each statement, determine which
        variables are defined (written) and which are used (read).

    3.  **CFG edge construction** — build intra-procedural control-flow
        edges between consecutive statements, respecting branches.

    4.  **Reaching definitions** — run the iterative fixpoint to compute
        which definitions reach each use.

    5.  **Data-dependence edges** — for each use at a node, add a DATA
        edge from every reaching definition of that variable.

    6.  **Anti/Output dependence edges** — WAR and WAW hazards.

    7.  **Control-dependence edges** — using post-dominator tree.

    8.  **Inter-procedural edges** (optional) — CALL, PARAM, RETURN
        if a ``callgraph`` is provided.

    Usage::

        builder = DependencyGraphBuilder()
        pdg = builder.build(cfg)
    """

    def __init__(
        self,
        include_anti: bool = False,
        include_output: bool = False,
        include_control: bool = True,
        max_tokens: int = 50_000,
    ) -> None:
        """
        Parameters
        ----------
        include_anti : bool
            Include ANTI (WAR) dependence edges.  Off by default as they
            significantly increase graph size and are not needed for
            standard slicing.
        include_output : bool
            Include OUTPUT (WAW) dependence edges.
        include_control : bool
            Include CONTROL dependence edges (requires post-dominator
            computation).
        max_tokens : int
            Safety limit — skip analysis for functions with more tokens.
        """
        self.include_anti = include_anti
        self.include_output = include_output
        self.include_control = include_control
        self.max_tokens = max_tokens

    def build(self, cfg: Any) -> DependencyGraph:
        """
        Build a DependencyGraph from a cppcheckdata configuration.

        Parameters
        ----------
        cfg : cppcheckdata Configuration
            One configuration from ``parsedump().configurations``.

        Returns
        -------
        DependencyGraph
        """
        graph = DependencyGraph()
        tokens = getattr(cfg, "tokenlist", [])
        if not tokens or len(tokens) > self.max_tokens:
            return graph

        # ── Pass 1: identify statement-level nodes ────────────────────
        stmt_nodes, token_to_node = self._identify_statements(graph, tokens)

        if not stmt_nodes:
            return graph

        # ── Pass 2: build CFG edges ──────────────────────────────────
        cfg_succs, cfg_preds = self._build_cfg_edges(graph, stmt_nodes, tokens)

        # ── Pass 3: reaching definitions ─────────────────────────────
        rd = _compute_reaching_definitions(stmt_nodes, cfg_succs, cfg_preds)

        # ── Pass 4: DATA dependence edges ────────────────────────────
        self._add_data_edges(graph, stmt_nodes, rd)

        # ── Pass 5: ANTI / OUTPUT dependence edges ───────────────────
        if self.include_anti or self.include_output:
            self._add_anti_output_edges(graph, stmt_nodes, rd)

        # ── Pass 6: CONTROL dependence edges ─────────────────────────
        if self.include_control and len(stmt_nodes) >= 2:
            self._add_control_edges(graph, stmt_nodes, cfg_succs, cfg_preds)

        return graph

    # ── Pass 1 ────────────────────────────────────────────────────────

    def _identify_statements(
        self,
        graph: DependencyGraph,
        tokens: Sequence[Any],
    ) -> Tuple[List[DepNode], Dict[int, DepNode]]:
        """
        Walk the token stream and create a DepNode for each
        statement-level construct.

        Heuristic for "statement boundary":
          - Token whose previous token is ';' or '{' or '}' or
            is the first token, AND which itself is not ';' / '{' / '}'.
          - Tokens that are assignment LHS (via astParent check).
          - Predicate keywords (if/while/for/switch).
          - Return statements.
          - Function call names.

        For each statement node, we extract defs and uses by walking
        tokens until the next ';' (or '{' / '}').
        """
        stmt_nodes: List[DepNode] = []
        token_to_node: Dict[int, DepNode] = {}  # token.Id → DepNode

        # Group tokens into statement-level chunks separated by ';' / '{' / '}'
        chunks: List[List[Any]] = []
        current_chunk: List[Any] = []

        for tok in tokens:
            s = getattr(tok, "str", "")
            if s in (";", "{", "}"):
                if current_chunk:
                    chunks.append(current_chunk)
                    current_chunk = []
            else:
                current_chunk.append(tok)

        if current_chunk:
            chunks.append(current_chunk)

        # Determine enclosing function name (best-effort)
        func_name = ""
        for scope in getattr(graph, "_cfg_scopes", []):
            pass  # handled below

        for chunk in chunks:
            if not chunk:
                continue
            first = chunk[0]

            # Collect defs and uses for this statement
            defs: Set[int] = set()
            uses: Set[int] = set()
            def_names: Dict[int, str] = {}
            use_names: Dict[int, str] = {}
            is_pred = False

            for tok in chunk:
                s = getattr(tok, "str", "")
                vid = _get_var_id(tok)

                if _is_predicate_keyword(tok):
                    is_pred = True

                if vid == 0:
                    continue

                # Determine if this variable occurrence is a def or use
                # by examining its AST parent
                parent = getattr(tok, "astParent", None)
                is_def = False
                if parent is not None:
                    if _is_assignment(parent):
                        lhs = getattr(parent, "astOperand1", None)
                        if lhs is not None and _get_var_id(lhs) == vid:
                            is_def = True
                    # Increment/decrement (++/--)
                    pstr = getattr(parent, "str", "")
                    if pstr in ("++", "--"):
                        is_def = True
                        uses.add(vid)
                        use_names[vid] = _get_var_name(tok)

                if is_def:
                    defs.add(vid)
                    def_names[vid] = _get_var_name(tok)
                else:
                    uses.add(vid)
                    use_names[vid] = _get_var_name(tok)

            # Also detect declarations with initializers:
            #   "int x = expr;"  → first token might be a type keyword
            # The assignment detection above handles this if the AST is correct.

            # Detect function name context
            scope = getattr(first, "scope", None)
            if scope is not None:
                stype = getattr(scope, "type", "")
                if stype == "Function":
                    func_name = getattr(scope, "className", func_name)
                    graph._function_name = func_name

            node = graph.add_node(
                first,
                is_predicate=is_pred,
                function_name=func_name,
                defs=defs,
                uses=uses,
                def_names=def_names,
                use_names=use_names,
            )
            stmt_nodes.append(node)

            # Map each token in the chunk to this node
            for tok in chunk:
                tid = id(tok)
                token_to_node[tid] = node

        return stmt_nodes, token_to_node

    # ── Pass 2 ────────────────────────────────────────────────────────

    def _build_cfg_edges(
        self,
        graph: DependencyGraph,
        stmt_nodes: List[DepNode],
        tokens: Sequence[Any],
    ) -> Tuple[Dict[int, List[int]], Dict[int, List[int]]]:
        """
        Build control-flow edges between statement nodes.

        This is a simplified CFG construction that handles:
          - Sequential flow (fall-through)
          - if/else branching
          - while/for loop back-edges

        A full CFG is available from ``ctrlflow_graph.py``; here we build
        a lightweight version sufficient for reaching-definitions.
        """
        cfg_succs: Dict[int, List[int]] = defaultdict(list)
        cfg_preds: Dict[int, List[int]] = defaultdict(list)

        if not stmt_nodes:
            return cfg_succs, cfg_preds

        # Default: sequential flow
        for i in range(len(stmt_nodes) - 1):
            src = stmt_nodes[i].node_id
            tgt = stmt_nodes[i + 1].node_id
            cfg_succs[src].append(tgt)
            cfg_preds[tgt].append(src)

        # Identify branch targets and back-edges from predicates
        # We use a scope-depth stack to track matching if/while/for blocks
        pred_stack: List[DepNode] = []
        for node in stmt_nodes:
            if node.is_predicate:
                pred_stack.append(node)
            tok_str = getattr(node.token, "str", "")

            # Look for back-edges: if this node is in a loop scope
            # and is the last node before the scope closes, add a
            # back-edge to the loop predicate
            scope = getattr(node.token, "scope", None)
            if scope is not None:
                stype = getattr(scope, "type", "")
                if stype in ("While", "For") and pred_stack:
                    # Find the predicate for this loop scope
                    for ps in reversed(pred_stack):
                        ps_scope = getattr(ps.token, "scope", None)
                        if ps_scope is not None and id(ps_scope) == id(scope):
                            # Back-edge from node to predicate
                            if ps.node_id not in cfg_succs.get(node.node_id, []):
                                cfg_succs[node.node_id].append(ps.node_id)
                                cfg_preds[ps.node_id].append(node.node_id)
                            break

        # Store on graph for later use
        graph._cfg_succs = cfg_succs
        graph._cfg_preds = cfg_preds

        return cfg_succs, cfg_preds

    # ── Pass 4 ────────────────────────────────────────────────────────

    def _add_data_edges(
        self,
        graph: DependencyGraph,
        stmt_nodes: List[DepNode],
        rd: ReachingDefinitions,
    ) -> None:
        """
        Add DATA dependence edges:  for each use of variable v at node n,
        add a DATA edge from every definition d of v that reaches n.
        """
        node_map: Dict[int, DepNode] = {n.node_id: n for n in stmt_nodes}

        for node in stmt_nodes:
            for vid in node.uses:
                # Which definitions of vid reach this node?
                for def_id, def_vid in rd.rd_in.get(node.node_id, set()):
                    if def_vid != vid:
                        continue
                    def_node = node_map.get(def_id)
                    if def_node is None or def_node is node:
                        continue
                    var_name = node.use_names.get(vid, def_node.def_names.get(vid, f"v{vid}"))
                    graph.add_edge(
                        source=def_node,
                        target=node,
                        kind=DepKind.DATA,
                        variable=var_name,
                        var_id=vid,
                        label=f"data:{var_name}",
                    )

    # ── Pass 5 ────────────────────────────────────────────────────────

    def _add_anti_output_edges(
        self,
        graph: DependencyGraph,
        stmt_nodes: List[DepNode],
        rd: ReachingDefinitions,
    ) -> None:
        """
        Add ANTI (WAR) and OUTPUT (WAW) dependence edges.

        ANTI:   use at A, def at B (A before B), no intervening def of v.
        OUTPUT: def at A, def at B (A before B), no intervening use of v.
        """
        node_map: Dict[int, DepNode] = {n.node_id: n for n in stmt_nodes}
        node_order: Dict[int, int] = {n.node_id: i for i, n in enumerate(stmt_nodes)}

        if self.include_anti:
            # For each def at node B, find prior uses that are not
            # separated by another def of the same variable
            for bnode in stmt_nodes:
                for vid in bnode.defs:
                    # Which definitions of vid reach B?
                    # The uses that B kills are anti-dependent on B
                    for anode in stmt_nodes:
                        if anode is bnode:
                            continue
                        if node_order.get(anode.node_id, 0) >= node_order.get(bnode.node_id, 0):
                            continue
                        if vid not in anode.uses:
                            continue
                        # Check that no def of vid between A and B
                        intervening = False
                        for mid in range(
                            node_order[anode.node_id] + 1,
                            node_order[bnode.node_id],
                        ):
                            mnode = stmt_nodes[mid]
                            if vid in mnode.defs:
                                intervening = True
                                break
                        if not intervening:
                            var_name = anode.use_names.get(vid, f"v{vid}")
                            graph.add_edge(
                                source=anode,
                                target=bnode,
                                kind=DepKind.ANTI,
                                variable=var_name,
                                var_id=vid,
                                label=f"anti:{var_name}",
                            )

        if self.include_output:
            for bnode in stmt_nodes:
                for vid in bnode.defs:
                    for anode in stmt_nodes:
                        if anode is bnode:
                            continue
                        if node_order.get(anode.node_id, 0) >= node_order.get(bnode.node_id, 0):
                            continue
                        if vid not in anode.defs:
                            continue
                        intervening_use = False
                        for mid in range(
                            node_order[anode.node_id] + 1,
                            node_order[bnode.node_id],
                        ):
                            mnode = stmt_nodes[mid]
                            if vid in mnode.uses:
                                intervening_use = True
                                break
                        if not intervening_use:
                            var_name = anode.def_names.get(vid, f"v{vid}")
                            graph.add_edge(
                                source=anode,
                                target=bnode,
                                kind=DepKind.OUTPUT,
                                variable=var_name,
                                var_id=vid,
                                label=f"output:{var_name}",
                            )

    # ── Pass 6 ────────────────────────────────────────────────────────

    def _add_control_edges(
        self,
        graph: DependencyGraph,
        stmt_nodes: List[DepNode],
        cfg_succs: Dict[int, List[int]],
        cfg_preds: Dict[int, List[int]],
    ) -> None:
        """Add CONTROL dependence edges using post-dominance."""
        node_ids = [n.node_id for n in stmt_nodes]
        if not node_ids:
            return

        # Create a synthetic exit node
        exit_id = max(node_ids) + 1
        # The last node leads to exit
        last_id = node_ids[-1]
        cfg_succs_ext = dict(cfg_succs)
        cfg_preds_ext = dict(cfg_preds)
        cfg_succs_ext.setdefault(last_id, []).append(exit_id)
        cfg_preds_ext[exit_id] = [last_id]

        # Also connect return statements to exit
        for node in stmt_nodes:
            tok_str = getattr(node.token, "str", "")
            if tok_str == "return":
                if exit_id not in cfg_succs_ext.get(node.node_id, []):
                    cfg_succs_ext.setdefault(node.node_id, []).append(exit_id)
                    cfg_preds_ext.setdefault(exit_id, []).append(node.node_id)

        predicates = {n.node_id for n in stmt_nodes if n.is_predicate}

        try:
            cd_edges = _compute_control_dependence(
                node_ids + [exit_id],
                cfg_succs_ext,
                cfg_preds_ext,
                exit_id,
                predicates,
            )
        except (RecursionError, KeyError):
            # Gracefully degrade if the CFG is too complex
            return

        node_map = {n.node_id: n for n in stmt_nodes}
        seen: Set[Tuple[int, int]] = set()
        for src_id, tgt_id in cd_edges:
            if (src_id, tgt_id) in seen:
                continue
            seen.add((src_id, tgt_id))
            src_node = node_map.get(src_id)
            tgt_node = node_map.get(tgt_id)
            if src_node is not None and tgt_node is not None:
                graph.add_edge(
                    source=src_node,
                    target=tgt_node,
                    kind=DepKind.CONTROL,
                    label="ctrl",
                )


# ═══════════════════════════════════════════════════════════════════════════
#  PART 8 — INTER-PROCEDURAL EXTENSION
# ═══════════════════════════════════════════════════════════════════════════


def add_interprocedural_edges(
    caller_graph: DependencyGraph,
    callee_graph: DependencyGraph,
    call_node: DepNode,
    callee_entry: Optional[DepNode] = None,
    callee_exit: Optional[DepNode] = None,
    param_mapping: Optional[List[Tuple[int, int]]] = None,
) -> None:
    """
    Add CALL, PARAM, and RETURN edges connecting two function-level PDGs.

    This is used when building a System Dependence Graph (SDG) from
    individual procedure PDGs (Horwitz, Reps & Binkley 1990).

    Parameters
    ----------
    caller_graph : DependencyGraph
        The calling function's PDG.
    callee_graph : DependencyGraph
        The called function's PDG.
    call_node : DepNode
        The call-site node in the caller.
    callee_entry : Optional[DepNode]
        The entry node of the callee.  If None, uses the first node.
    callee_exit : Optional[DepNode]
        The exit node of the callee.  If None, uses the last node.
    param_mapping : Optional[List[Tuple[int, int]]]
        List of (actual_var_id, formal_var_id) pairs mapping actual
        arguments in the caller to formal parameters in the callee.
    """
    if callee_entry is None and callee_graph.nodes:
        callee_entry = callee_graph.nodes[0]
    if callee_exit is None and callee_graph.nodes:
        callee_exit = callee_graph.nodes[-1]

    if callee_entry is not None:
        caller_graph.add_edge(
            source=call_node,
            target=callee_entry,
            kind=DepKind.CALL,
            label="call",
        )

    if callee_exit is not None:
        caller_graph.add_edge(
            source=callee_exit,
            target=call_node,
            kind=DepKind.RETURN,
            label="return",
        )

    if param_mapping:
        for actual_vid, formal_vid in param_mapping:
            # Find the actual argument node in the caller
            actual_nodes = caller_graph.definitions_of(actual_vid) + caller_graph.uses_of(actual_vid)
            formal_nodes = callee_graph.uses_of(formal_vid) + callee_graph.definitions_of(formal_vid)
            if actual_nodes and formal_nodes:
                caller_graph.add_edge(
                    source=actual_nodes[-1],  # most recent definition/use
                    target=formal_nodes[0],   # first use in callee
                    kind=DepKind.PARAM,
                    variable=formal_nodes[0].use_names.get(
                        formal_vid, f"v{formal_vid}"
                    ),
                    var_id=formal_vid,
                    label="param",
                )


# ═══════════════════════════════════════════════════════════════════════════
#  PART 9 — CONVENIENCE FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════


def build_from_dump(cfg: Any, **builder_kwargs: Any) -> DependencyGraph:
    """
    One-liner convenience: build a PDG from a cppcheckdata configuration.

    Parameters
    ----------
    cfg : cppcheckdata configuration
    **builder_kwargs
        Forwarded to ``DependencyGraphBuilder.__init__``.

    Returns
    -------
    DependencyGraph
    """
    builder = DependencyGraphBuilder(**builder_kwargs)
    return builder.build(cfg)


def def_use_chains(graph: DependencyGraph) -> Dict[int, List[Tuple[DepNode, DepNode]]]:
    """
    Extract all def-use chains from the PDG, grouped by variable id.

    Returns
    -------
    Dict[int, List[Tuple[DepNode, DepNode]]]
        var_id → [(definition_node, use_node), …]
    """
    chains: Dict[int, List[Tuple[DepNode, DepNode]]] = defaultdict(list)
    for edge in graph.edges_of_kind(DepKind.DATA):
        if edge.var_id:
            chains[edge.var_id].append((edge.source, edge.target))
    return chains


def use_def_chains(graph: DependencyGraph) -> Dict[int, List[Tuple[DepNode, DepNode]]]:
    """
    Extract all use-def chains (reverse of def-use).

    Returns
    -------
    Dict[int, List[Tuple[DepNode, DepNode]]]
        var_id → [(use_node, definition_node), …]
    """
    chains: Dict[int, List[Tuple[DepNode, DepNode]]] = defaultdict(list)
    for edge in graph.edges_of_kind(DepKind.DATA):
        if edge.var_id:
            chains[edge.var_id].append((edge.target, edge.source))
    return chains


def find_unused_definitions(graph: DependencyGraph) -> List[DepNode]:
    """
    Find all definitions that have no reaching use — dead stores.

    This is a wrapper around ``DependencyGraph.dead_stores()`` for
    discoverability.
    """
    return graph.dead_stores()


def dependency_distance(
    graph: DependencyGraph,
    source: DepNode,
    target: DepNode,
    kinds: Optional[Set[DepKind]] = None,
) -> int:
    """
    Compute shortest dependency-edge path length from *source* to *target*.

    Returns -1 if unreachable.
    """
    if source is target:
        return 0
    if kinds is None:
        kinds = {DepKind.DATA, DepKind.CONTROL}

    visited: Set[int] = set()
    queue: Deque[Tuple[DepNode, int]] = deque([(source, 0)])
    while queue:
        node, dist = queue.popleft()
        if node is target:
            return dist
        if node.node_id in visited:
            continue
        visited.add(node.node_id)
        for edge in node.out_edges():
            if edge.kind in kinds:
                queue.append((edge.target, dist + 1))
    return -1


# ═══════════════════════════════════════════════════════════════════════════
#  PART 10 — MODULE-LEVEL EXPORTS
# ═══════════════════════════════════════════════════════════════════════════

__all__ = [
    # Enums
    "DepKind",
    # Data structures
    "DepEdge",
    "DepNode",
    "DependencyGraph",
    "ReachingDefinitions",
    # Builder
    "DependencyGraphBuilder",
    # Slicing
    "slice_backward",
    "slice_forward",
    "chop",
    # Inter-procedural
    "add_interprocedural_edges",
    # Convenience
    "build_from_dump",
    "def_use_chains",
    "use_def_chains",
    "find_unused_definitions",
    "dependency_distance",
]
