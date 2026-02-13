"""
cppcheckdata_shims/distrib_analysis.py
=======================================

Distributive Analysis Framework — IFDS and IDE implementations
for interprocedural, context-sensitive, distributive dataflow analysis.

Theoretical basis:
    - Reps, Horwitz, Sagiv. "Precise Interprocedural Dataflow Analysis
      via Graph Reachability." POPL 1995.  (IFDS)
    - Sagiv, Reps, Horwitz. "Precise Interprocedural Dataflow Analysis
      with Applications to Constant Propagation." TCS 1996.  (IDE)
    - Møller & Schwartzbach, "Static Program Analysis", Chapter 9.

Key property exploited:
    For distributive transfer functions f,
        f(x ⊔ y) = f(x) ⊔ f(y)
    which guarantees MOP = MFP (the fixed-point solution equals
    the ideal merge-over-all-paths solution).

This module does NOT reimplement what already exists:
    - CFGs come from ctrlflow_graph
    - Call graphs come from callgraph
    - Abstract domains come from abstract_domains
    - The intraprocedural worklist engine comes from dataflow_engine
    - Base analysis classes come from dataflow_analyses
"""

from __future__ import annotations

import itertools
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import (
    Any,
    Callable,
    Dict,
    FrozenSet,
    Generic,
    Hashable,
    Iterable,
    List,
    Optional,
    Set,
    Tuple,
    TypeVar,
)

# ── Imports from existing shim modules (NO duplication) ──────────────
from cppcheckdata_shims.ctrlflow_graph import BasicBlock, CFG, build_cfg_for_function, build_all_cfgs
from cppcheckdata_shims.callgraph import CallGraph, CallSite, build_call_graph
from cppcheckdata_shims.dataflow_analyses import ForwardAnalysis
from cppcheckdata_shims.dataflow_engine import WorklistSolver
from cppcheckdata_shims.abstract_domains import PowersetDomain

# =====================================================================
#  Part I: Representation of Distributive Functions
# =====================================================================

# The domain element type
D = TypeVar("D", bound=Hashable)

# A special "zero" element representing Λ (the universal source in
# the IFDS representation graph).  Distinguished from all real facts.
_ZERO = "__IFDS_ZERO__"


@dataclass(frozen=True)
class FlowEdge:
    """
    A single edge in the representation graph of a distributive
    function f : 2^D → 2^D.

    An edge (src, tgt) means:
        - If src is _ZERO ("0-node"):  tgt ∈ f(∅)          (generation)
        - If src is a domain element d: tgt ∈ f({d})        (propagation)

    The full set of edges compactly encodes f.  Given input set S ⊆ D:
        f(S) = { tgt | (ZERO, tgt) ∈ edges }
             ∪ { tgt | ∃ d ∈ S : (d, tgt) ∈ edges }

    This is the representation from Reps–Horwitz–Sagiv (POPL '95),
    as explained in Møller & Schwartzbach §9.3.
    """
    src: Any   # _ZERO or a domain element
    tgt: Any   # a domain element


class DistributiveFunction(Generic[D]):
    """
    Compact representation of a distributive function f : 2^D → 2^D
    as a bipartite graph on (D ∪ {0}) nodes.

    From Møller & Schwartzbach §9.3:
        "Every distributive function f : 2^D → 2^D where D is finite
        can be represented uniquely by such a graph with at most
        (|D| + 1)^2 edges."

    Composition and join of distributive functions reduce to graph
    operations, enabling the IFDS/IDE tabulation algorithms.
    """

    __slots__ = ("_edges", "_domain")

    def __init__(self, domain: FrozenSet[D], edges: Iterable[FlowEdge] = ()):
        self._domain: FrozenSet[D] = domain
        self._edges: Set[FlowEdge] = set(edges)

    # ── Construction helpers ──────────────────────────────────────

    @classmethod
    def identity(cls, domain: FrozenSet[D]) -> "DistributiveFunction[D]":
        """
        The identity function id(S) = S.
        Represented by edges {(d, d) | d ∈ D}.
        """
        edges = {FlowEdge(d, d) for d in domain}
        return cls(domain, edges)

    @classmethod
    def constant(cls, domain: FrozenSet[D], value: FrozenSet[D]) -> "DistributiveFunction[D]":
        """
        The constant function f(S) = value for all S.
        Represented by edges {(0, d) | d ∈ value}.
        """
        edges = {FlowEdge(_ZERO, d) for d in value}
        return cls(domain, edges)

    @classmethod
    def gen_kill(cls, domain: FrozenSet[D],
                 gen: FrozenSet[D], kill: FrozenSet[D]) -> "DistributiveFunction[D]":
        """
        Standard gen/kill function: f(S) = gen ∪ (S - kill).

        Edges:
            {(0, d) | d ∈ gen} ∪ {(d, d) | d ∈ D - kill}
        """
        edges: Set[FlowEdge] = set()
        for d in gen:
            edges.add(FlowEdge(_ZERO, d))
        for d in domain - kill:
            edges.add(FlowEdge(d, d))
        return cls(domain, edges)

    @classmethod
    def from_mapping(cls, domain: FrozenSet[D],
                     mapping: Dict[Any, Set[D]]) -> "DistributiveFunction[D]":
        """
        Build from explicit mapping: src → {tgt₁, tgt₂, ...}.
        Keys may be _ZERO or domain elements.
        """
        edges = set()
        for src, tgts in mapping.items():
            for tgt in tgts:
                edges.add(FlowEdge(src, tgt))
        return cls(domain, edges)

    # ── Application ───────────────────────────────────────────────

    def apply(self, input_set: FrozenSet[D]) -> FrozenSet[D]:
        """
        Evaluate f(S).

        f(S) = { tgt | (0, tgt) ∈ edges }
             ∪ { tgt | ∃ d ∈ S : (d, tgt) ∈ edges }
        """
        result: Set[D] = set()
        for e in self._edges:
            if e.src is _ZERO or e.src in input_set:
                result.add(e.tgt)
        return frozenset(result)

    # ── Algebra: composition, join ────────────────────────────────

    def compose(self, other: "DistributiveFunction[D]") -> "DistributiveFunction[D]":
        """
        Compute (self ∘ other), i.e. f(g(x)) where self=f, other=g.

        Edge rule (Møller & Schwartzbach §9.3):
            (a, c) ∈ compose  ⟺  ∃ b : (a,b) ∈ other ∧ (b,c) ∈ self
          plus
            (0, c) ∈ compose  ⟺  (0,c) ∈ self  (f's unconditional gens)

        This is essentially graph matrix multiplication on the
        (D ∪ {0}) node set.
        """
        # Build adjacency: other.src → {other.tgt, ...}
        other_adj: Dict[Any, Set[Any]] = defaultdict(set)
        for e in other._edges:
            other_adj[e.src].add(e.tgt)

        # Build adjacency: self.src → {self.tgt, ...}
        self_adj: Dict[Any, Set[Any]] = defaultdict(set)
        for e in self._edges:
            self_adj[e.src].add(e.tgt)

        new_edges: Set[FlowEdge] = set()

        # (0, c) from self's own 0-edges (these always propagate)
        for c in self_adj.get(_ZERO, set()):
            new_edges.add(FlowEdge(_ZERO, c))

        # For each edge (a, b) in other, follow b in self to get (a, c)
        for a, bs in other_adj.items():
            for b in bs:
                for c in self_adj.get(b, set()):
                    new_edges.add(FlowEdge(a, c))

        return DistributiveFunction(self._domain, new_edges)

    def join(self, other: "DistributiveFunction[D]") -> "DistributiveFunction[D]":
        """
        Pointwise join: (f ⊔ g)(S) = f(S) ∪ g(S) for all S.
        Represented by the union of edge sets.
        """
        return DistributiveFunction(self._domain, self._edges | other._edges)

    # ── Inspection ────────────────────────────────────────────────

    @property
    def edges(self) -> FrozenSet[FlowEdge]:
        return frozenset(self._edges)

    @property
    def domain(self) -> FrozenSet[D]:
        return self._domain

    def generates(self) -> FrozenSet[D]:
        """Elements unconditionally generated: f(∅)."""
        return frozenset(e.tgt for e in self._edges if e.src is _ZERO)

    def propagates(self, d: D) -> FrozenSet[D]:
        """Given a single fact d, what does f({d}) produce (excluding gens)?"""
        return frozenset(e.tgt for e in self._edges if e.src == d)

    def is_identity(self) -> bool:
        id_edges = {FlowEdge(d, d) for d in self._domain}
        return self._edges == id_edges

    def __eq__(self, other):
        if not isinstance(other, DistributiveFunction):
            return NotImplemented
        return self._edges == other._edges and self._domain == other._domain

    def __hash__(self):
        return hash((self._domain, frozenset(self._edges)))

    def __repr__(self):
        gen = sorted(str(e.tgt) for e in self._edges if e.src is _ZERO)
        prop = sorted(f"{e.src}→{e.tgt}" for e in self._edges if e.src is not _ZERO)
        return f"DistFunc(gen={gen}, prop={prop})"


# =====================================================================
#  Part II: The Supergraph (Exploded Interprocedural CFG)
# =====================================================================

class EdgeKind(Enum):
    """Classification of edges in the interprocedural supergraph."""
    INTRAPROCEDURAL = auto()   # Normal edge within a function
    CALL_TO_START = auto()     # From call site to callee entry
    EXIT_TO_RETURN = auto()    # From callee exit to return site
    CALL_TO_RETURN = auto()    # Summary edge bypassing the callee


@dataclass(frozen=True)
class SuperNode:
    """
    A node in the interprocedural supergraph.

    Combines a CFG basic block with the function it belongs to.
    """
    function_id: Any          # Function.Id
    block_id: int             # BasicBlock.id
    function_name: str = ""   # For debugging

    def __repr__(self):
        name = self.function_name or str(self.function_id)
        return f"SN({name}:B{self.block_id})"


@dataclass(frozen=True)
class SuperEdge:
    """
    An edge in the interprocedural supergraph, annotated with its
    kind and the distributive flow function it carries.
    """
    src: SuperNode
    tgt: SuperNode
    kind: EdgeKind
    flow_function: Optional[DistributiveFunction] = None
    call_site: Optional[Any] = None  # CallSite if applicable


class Supergraph:
    """
    The interprocedural supergraph G* combining all per-function CFGs
    with call/return edges.

    From Møller & Schwartzbach §9.4 / Reps–Horwitz–Sagiv:
        G* = (N*, E*)  where
        N* = ⋃_p N_p   (union of all intra-procedural nodes)
        E* = E_intra ∪ E_call ∪ E_ret ∪ E_call-to-return

    This class builds the supergraph from existing CFGs (ctrlflow_graph)
    and the call graph (callgraph), avoiding reimplementation.
    """

    def __init__(self, configuration, call_graph: CallGraph = None):
        self._config = configuration
        self._call_graph = call_graph or build_call_graph(configuration)
        self._cfgs: Dict[Any, CFG] = {}        # func_id → CFG
        self._nodes: Dict[Any, SuperNode] = {}  # (func_id, block_id) → SuperNode
        self._edges: List[SuperEdge] = []
        self._succ: Dict[SuperNode, List[SuperEdge]] = defaultdict(list)
        self._pred: Dict[SuperNode, List[SuperEdge]] = defaultdict(list)
        self._func_entries: Dict[Any, SuperNode] = {}  # func_id → entry SuperNode
        self._func_exits: Dict[Any, SuperNode] = {}    # func_id → exit SuperNode

        # Call-site bookkeeping for the tabulation algorithm
        self._call_to_return_site: Dict[SuperNode, SuperNode] = {}
        self._call_to_callee_entry: Dict[SuperNode, List[SuperNode]] = defaultdict(list)
        self._exit_to_return_sites: Dict[SuperNode, List[Tuple[SuperNode, SuperNode]]] = defaultdict(list)
        #                           callee_exit → [(call_node, return_node), ...]

        self._build()

    def _build(self):
        """Construct the supergraph from CFGs and call graph."""
        # Step 1: Build CFGs (reuse ctrlflow_graph module)
        all_cfgs = build_all_cfgs(self._config)
        for func, cfg in all_cfgs.items():
            self._cfgs[func.Id] = cfg
            # Register all nodes
            for block in cfg.blocks:
                sn = SuperNode(func.Id, block.id, func.name)
                self._nodes[(func.Id, block.id)] = sn
            # Register entry/exit
            entry_sn = self._nodes[(func.Id, cfg.entry.id)]
            exit_sn = self._nodes[(func.Id, cfg.exit.id)]
            self._func_entries[func.Id] = entry_sn
            self._func_exits[func.Id] = exit_sn

        # Step 2: Add intraprocedural edges
        for func, cfg in all_cfgs.items():
            for block in cfg.blocks:
                src = self._nodes[(func.Id, block.id)]
                for succ in block.successors:
                    tgt = self._nodes[(func.Id, succ.id)]
                    edge = SuperEdge(src, tgt, EdgeKind.INTRAPROCEDURAL)
                    self._edges.append(edge)
                    self._succ[src].append(edge)
                    self._pred[tgt].append(edge)

        # Step 3: Add interprocedural edges from call graph
        for func in self._config.functions:
            if func.Id not in self._cfgs:
                continue
            cfg = self._cfgs[func.Id]
            call_sites = self._call_graph.call_sites_in(func)

            for cs in call_sites:
                call_block = self._find_block_containing_token(cfg, cs.token)
                if call_block is None:
                    continue

                call_sn = self._nodes.get((func.Id, call_block.id))
                if call_sn is None:
                    continue

                # Return site: the block(s) that are successors of the call block
                # In most CFGs the call block falls through to the return-site block.
                return_blocks = call_block.successors
                for ret_block in return_blocks:
                    ret_sn = self._nodes.get((func.Id, ret_block.id))
                    if ret_sn is None:
                        continue

                    # Call-to-return (summary) edge
                    c2r_edge = SuperEdge(call_sn, ret_sn, EdgeKind.CALL_TO_RETURN,
                                         call_site=cs)
                    self._edges.append(c2r_edge)
                    self._succ[call_sn].append(c2r_edge)
                    self._pred[ret_sn].append(c2r_edge)
                    self._call_to_return_site[call_sn] = ret_sn

                    # If callee is resolved, add call→entry and exit→return
                    if cs.callee and cs.callee.Id in self._cfgs:
                        callee_entry = self._func_entries.get(cs.callee.Id)
                        callee_exit = self._func_exits.get(cs.callee.Id)

                        if callee_entry:
                            c2s_edge = SuperEdge(call_sn, callee_entry,
                                                 EdgeKind.CALL_TO_START, call_site=cs)
                            self._edges.append(c2s_edge)
                            self._succ[call_sn].append(c2s_edge)
                            self._pred[callee_entry].append(c2s_edge)
                            self._call_to_callee_entry[call_sn].append(callee_entry)

                        if callee_exit and callee_entry:
                            e2r_edge = SuperEdge(callee_exit, ret_sn,
                                                 EdgeKind.EXIT_TO_RETURN, call_site=cs)
                            self._edges.append(e2r_edge)
                            self._succ[callee_exit].append(e2r_edge)
                            self._pred[ret_sn].append(e2r_edge)
                            self._exit_to_return_sites[callee_exit].append(
                                (call_sn, ret_sn))

    def _find_block_containing_token(self, cfg: CFG, token) -> Optional[BasicBlock]:
        """Find the basic block that contains the given token."""
        if token is None:
            return None
        for block in cfg.blocks:
            if block.is_entry or block.is_exit:
                continue
            for tok in block.tokens:
                if tok.Id == token.Id:
                    return block
        return None

    # ── Accessors ─────────────────────────────────────────────────

    def successors(self, node: SuperNode) -> List[SuperEdge]:
        return self._succ.get(node, [])

    def predecessors(self, node: SuperNode) -> List[SuperEdge]:
        return self._pred.get(node, [])

    def entry_of(self, function_id) -> Optional[SuperNode]:
        return self._func_entries.get(function_id)

    def exit_of(self, function_id) -> Optional[SuperNode]:
        return self._func_exits.get(function_id)

    def return_site_of(self, call_node: SuperNode) -> Optional[SuperNode]:
        return self._call_to_return_site.get(call_node)

    def callee_entries_of(self, call_node: SuperNode) -> List[SuperNode]:
        return self._call_to_callee_entry.get(call_node, [])

    def callers_of_exit(self, exit_node: SuperNode) -> List[Tuple[SuperNode, SuperNode]]:
        """Return [(call_node, return_node), ...] for a callee exit."""
        return self._exit_to_return_sites.get(exit_node, [])

    @property
    def all_nodes(self) -> Iterable[SuperNode]:
        return self._nodes.values()

    @property
    def all_edges(self) -> List[SuperEdge]:
        return self._edges

    @property
    def cfg_of(self) -> Dict[Any, CFG]:
        return self._cfgs

    @property
    def call_graph(self) -> CallGraph:
        return self._call_graph


# =====================================================================
#  Part III: The IFDS Tabulation Algorithm
# =====================================================================


@dataclass(frozen=True)
class ExplodedNode:
    """
    A node in the exploded supergraph G# (Reps–Horwitz–Sagiv).

    Pairs a supergraph node n with a domain fact d (or _ZERO).
    Reachability in G# from (entry, 0) to (n, d) means that d holds
    at n on some valid interprocedural path.
    """
    super_node: SuperNode
    fact: Any   # _ZERO or a domain element D

    def __repr__(self):
        f = "Λ" if self.fact is _ZERO else str(self.fact)
        return f"({self.super_node}, {f})"


class IFDSProblem(Generic[D]):
    """
    Abstract specification of an IFDS problem.

    Subclass this and implement the flow-function factories.
    The algorithm (IFDSSolver) handles the tabulation.

    From Reps–Horwitz–Sagiv / Møller & Schwartzbach §9.4:
        An IFDS problem is a tuple (G*, D, F, M_Θ, ⊔) where:
        - G* is the supergraph
        - D is a finite set of dataflow facts
        - F ⊆ (2^D → 2^D) is the set of distributive flow functions
        - M_Θ ⊆ F maps each edge in G* to a flow function
        - ⊔ is union (for may-analysis) or intersection (for must-analysis)
    """

    def __init__(self, supergraph: Supergraph, domain: FrozenSet[D],
                 entry_function_id: Any):
        self.supergraph = supergraph
        self.domain = domain
        self.entry_function_id = entry_function_id

    # ── Flow function factories (to be overridden) ────────────────

    def normal_flow(self, src: SuperNode, tgt: SuperNode,
                    edge: SuperEdge) -> DistributiveFunction:
        """
        Flow function for an intraprocedural edge (not at call/return sites).
        Default: identity.
        """
        return DistributiveFunction.identity(self.domain)

    def call_flow(self, call_node: SuperNode, callee_entry: SuperNode,
                  edge: SuperEdge) -> DistributiveFunction:
        """
        Flow function for a call-to-start edge.
        Maps caller facts to callee-entry facts (parameter binding).
        Default: identity.
        """
        return DistributiveFunction.identity(self.domain)

    def return_flow(self, callee_exit: SuperNode, return_site: SuperNode,
                    call_node: SuperNode,
                    edge: SuperEdge) -> DistributiveFunction:
        """
        Flow function for an exit-to-return-site edge.
        Maps callee-exit facts back to caller return-site facts.
        Default: identity.
        """
        return DistributiveFunction.identity(self.domain)

    def call_to_return_flow(self, call_node: SuperNode, return_site: SuperNode,
                            edge: SuperEdge) -> DistributiveFunction:
        """
        Flow function for the call-to-return (summary) edge.
        Models facts that bypass the callee (e.g., locals not
        passed as arguments).
        Default: identity.
        """
        return DistributiveFunction.identity(self.domain)

    def initial_seeds(self) -> Set[D]:
        """
        Initial dataflow facts at the entry of the analysis entry function.
        Default: empty set (only _ZERO reachable initially).
        """
        return set()


class IFDSSolver(Generic[D]):
    """
    The IFDS tabulation algorithm from Reps–Horwitz–Sagiv (1995).

    Computes the merge-over-all-valid-paths solution for an IFDS problem
    in O(|E*| · |D|³) time.

    Algorithm outline (Møller & Schwartzbach §9.4):
        1. Build the exploded supergraph G# where nodes are (n, d) pairs.
        2. Propagate reachability from (s_main, 0) using a worklist.
        3. At call sites, compute summary edges to avoid re-analyzing
           callees for each calling context (context sensitivity via
           the call-stack matching of valid paths).

    The result is, for each supergraph node n:
        result(n) = { d ∈ D | (n, d) is reachable in G# }
    """

    def __init__(self, problem: IFDSProblem[D]):
        self.problem = problem
        self._sg = problem.supergraph

        # Path edges: (s_p, d₁) → (n, d₂)
        # Represented as: for each entry fact (sp, d1), the set of
        # reachable (n, d2) pairs.
        # But for efficiency, we track per-node: which facts are reachable.
        self._path_edge: Dict[SuperNode, Set[Any]] = defaultdict(set)

        # Summary edges at call sites: (call_node, d₁) → (return_site, d₂)
        self._summary_edge: Dict[Tuple[SuperNode, Any], Set[Tuple[SuperNode, Any]]] = defaultdict(set)

        # End-summary: for each callee, (exit_node, d₃) reached from (entry, d₁)
        self._end_summary: Dict[Tuple[SuperNode, Any], Set[Any]] = defaultdict(set)
        #                       (callee_entry, d1) → {d3 at callee_exit}

        # Incoming: for each callee entry, the set of (call_node, d_caller)
        self._incoming: Dict[Tuple[SuperNode, Any], Set[Tuple[SuperNode, Any]]] = defaultdict(set)

        # Results: node → set of facts
        self._results: Dict[SuperNode, Set[D]] = defaultdict(set)

    def solve(self) -> Dict[SuperNode, FrozenSet[D]]:
        """
        Run the IFDS tabulation algorithm.

        Returns:
            Mapping from SuperNode → frozenset of dataflow facts
            that hold at that node (the MOP solution).
        """
        entry_sn = self._sg.entry_of(self.problem.entry_function_id)
        if entry_sn is None:
            return {}

        # Worklist of (source_entry_node, source_fact, current_node, current_fact)
        # We simplify by tracking path-edges as (node, fact) and propagating.
        worklist: deque[Tuple[SuperNode, Any, SuperNode, Any]] = deque()

        # Seed: (entry, 0) → (entry, 0)
        self._propagate(entry_sn, _ZERO, entry_sn, _ZERO, worklist)

        # Additional seeds from initial_seeds()
        for seed_fact in self.problem.initial_seeds():
            self._propagate(entry_sn, _ZERO, entry_sn, seed_fact, worklist)

        # Main loop
        while worklist:
            sp, d1, n, d2 = worklist.popleft()
            self._process_node(sp, d1, n, d2, worklist)

        # Collect results
        result: Dict[SuperNode, FrozenSet[D]] = {}
        for node in self._sg.all_nodes:
            facts = self._path_edge.get(node, set())
            # Filter out _ZERO — it's internal bookkeeping
            real_facts = frozenset(f for f in facts if f is not _ZERO)
            result[node] = real_facts

        return result

    def _propagate(self, sp: SuperNode, d1: Any,
                   n: SuperNode, d2: Any,
                   worklist: deque):
        """Add a path edge and enqueue if new."""
        fact_set = self._path_edge[n]
        if d2 not in fact_set:
            fact_set.add(d2)
            worklist.append((sp, d1, n, d2))

    def _process_node(self, sp: SuperNode, d1: Any,
                      n: SuperNode, d2: Any,
                      worklist: deque):
        """Process a path edge from (sp, d1) to (n, d2)."""
        edges = self._sg.successors(n)

        for edge in edges:
            m = edge.tgt

            if edge.kind == EdgeKind.INTRAPROCEDURAL:
                # ── Normal (non-call, non-return) edge ────────────
                # Check if n is also a call site (then this edge is
                # handled by CALL_TO_RETURN instead)
                if self._is_call_site(n) and edge.kind == EdgeKind.INTRAPROCEDURAL:
                    # Intraprocedural edges from call blocks are the
                    # fall-through within the function; the CALL_TO_RETURN
                    # edge handles the callee bypass.  Skip to avoid
                    # double-processing.  (Only if a CALL_TO_RETURN exists.)
                    has_c2r = any(e.kind == EdgeKind.CALL_TO_RETURN
                                 for e in self._sg.successors(n))
                    if has_c2r:
                        continue

                ff = self.problem.normal_flow(n, m, edge)
                for d3 in self._apply_flow_to_fact(ff, d2):
                    self._propagate(sp, d1, m, d3, worklist)

            elif edge.kind == EdgeKind.CALL_TO_START:
                # ── Call edge: propagate into callee ──────────────
                callee_entry = m
                ff = self.problem.call_flow(n, callee_entry, edge)
                for d3 in self._apply_flow_to_fact(ff, d2):
                    # Record incoming
                    self._incoming[(callee_entry, d3)].add((n, d2))
                    # Propagate into callee
                    self._propagate(callee_entry, d3, callee_entry, d3, worklist)
                    # Check if we already have end-summaries for this callee
                    callee_exit = self._sg.exit_of(callee_entry.function_id)
                    if callee_exit:
                        for d_exit in self._end_summary.get((callee_entry, d3), set()):
                            # Apply return flow
                            ret_site = self._sg.return_site_of(n)
                            if ret_site:
                                ret_edge = self._find_edge(callee_exit, ret_site,
                                                           EdgeKind.EXIT_TO_RETURN)
                                rff = self.problem.return_flow(
                                    callee_exit, ret_site, n,
                                    ret_edge or edge)
                                for d4 in self._apply_flow_to_fact(rff, d_exit):
                                    self._propagate(sp, d1, ret_site, d4, worklist)

            elif edge.kind == EdgeKind.CALL_TO_RETURN:
                # ── Call-to-return edge: bypass callee ────────────
                ff = self.problem.call_to_return_flow(n, m, edge)
                for d3 in self._apply_flow_to_fact(ff, d2):
                    self._propagate(sp, d1, m, d3, worklist)

                # Also apply any already-computed summary edges
                for (sum_ret, sum_d) in self._summary_edge.get((n, d2), set()):
                    self._propagate(sp, d1, sum_ret, sum_d, worklist)

            elif edge.kind == EdgeKind.EXIT_TO_RETURN:
                # ── Exit node of callee: propagate back to callers ─
                callee_exit = n
                callee_entry = self._sg.entry_of(n.function_id)
                if callee_entry is None:
                    continue

                # Record end-summary
                self._end_summary[(callee_entry, d1)].add(d2)

                # For all callers that entered this callee with fact d1
                for (call_sn, d_caller) in self._incoming.get((callee_entry, d1), set()):
                    ret_site = self._sg.return_site_of(call_sn)
                    if ret_site is None:
                        continue
                    rff = self.problem.return_flow(callee_exit, ret_site,
                                                   call_sn, edge)
                    for d4 in self._apply_flow_to_fact(rff, d2):
                        # Record summary edge
                        self._summary_edge[(call_sn, d_caller)].add((ret_site, d4))
                        # Propagate at return site using the caller's
                        # entry-point context
                        # We need to propagate for every path edge that
                        # reached (call_sn, d_caller)
                        self._propagate(
                            self._sg.entry_of(call_sn.function_id) or call_sn,
                            _ZERO, ret_site, d4, worklist)

    def _apply_flow_to_fact(self, ff: DistributiveFunction, d: Any) -> Set[Any]:
        """
        Apply a distributive flow function to a single fact.
        Returns the set of output facts.

        If d is _ZERO → return ff.generates() (the 0-row)
        If d is a domain fact → return ff.propagates(d) ∪ ff.generates()

        Note: _ZERO always generates; a real fact also picks up
        _ZERO-sourced edges (unconditional gens).
        """
        result = set()
        for e in ff.edges:
            if e.src is _ZERO:
                result.add(e.tgt)
            elif e.src == d:
                result.add(e.tgt)
        return result

    def _is_call_site(self, node: SuperNode) -> bool:
        """Check if any outgoing edge is a CALL_TO_START."""
        return any(e.kind == EdgeKind.CALL_TO_START
                   for e in self._sg.successors(node))

    def _find_edge(self, src: SuperNode, tgt: SuperNode,
                   kind: EdgeKind) -> Optional[SuperEdge]:
        """Find a specific edge."""
        for e in self._sg.successors(src):
            if e.tgt == tgt and e.kind == kind:
                return e
        return None

    # ── Query interface ───────────────────────────────────────────

    def results_at(self, node: SuperNode) -> FrozenSet[D]:
        """Return the set of dataflow facts holding at a supergraph node."""
        facts = self._path_edge.get(node, set())
        return frozenset(f for f in facts if f is not _ZERO)

    def all_results(self) -> Dict[SuperNode, FrozenSet[D]]:
        """Return results for all nodes."""
        return {n: frozenset(f for f in fs if f is not _ZERO)
                for n, fs in self._path_edge.items()}


# =====================================================================
#  Part IV: The IDE Framework (Extension for Value Domains)
# =====================================================================

# Value lattice element type
V = TypeVar("V")

# IDE uses "environment transformers" — functions Env → Env where
# Env = D → V (mapping from dataflow facts to a value lattice).
# Each edge in the exploded supergraph carries a "micro function" V → V.


@dataclass(frozen=True)
class MicroFunction:
    """
    An edge function (micro function) in the IDE framework.
    Maps a single lattice value V → V.

    Concrete implementations provided as subclasses for common patterns.
    """

    def apply(self, val: Any) -> Any:
        raise NotImplementedError

    def compose(self, other: "MicroFunction") -> "MicroFunction":
        """self ∘ other, i.e., self(other(x))."""
        raise NotImplementedError

    def join(self, other: "MicroFunction") -> "MicroFunction":
        """Pointwise join: (f ⊔ g)(x) = f(x) ⊔ g(x)."""
        raise NotImplementedError


class IdentityMicro(MicroFunction):
    """id(v) = v."""

    def apply(self, val):
        return val

    def compose(self, other):
        return other

    def join(self, other):
        if isinstance(other, IdentityMicro):
            return self
        return other.join(self)

    def __eq__(self, other):
        return isinstance(other, IdentityMicro)

    def __hash__(self):
        return hash("__identity__")

    def __repr__(self):
        return "id"


class ConstantMicro(MicroFunction):
    """f(v) = c for all v.  Used for assigning constants."""

    def __init__(self, constant):
        object.__setattr__(self, '_constant', constant)

    @property
    def constant(self):
        return self._constant

    def apply(self, val):
        return self._constant

    def compose(self, other):
        # self(other(x)) = c regardless of other
        return self

    def join(self, other):
        if isinstance(other, ConstantMicro) and other._constant == self._constant:
            return self
        # Different constants → Top (represented by TopMicro)
        return TopMicro()

    def __eq__(self, other):
        return isinstance(other, ConstantMicro) and other._constant == self._constant

    def __hash__(self):
        return hash(("__const__", self._constant))

    def __repr__(self):
        return f"const({self._constant})"


class TopMicro(MicroFunction):
    """
    f(v) = ⊤ (top of the value lattice).
    Used when multiple incompatible values are joined.
    """

    def apply(self, val):
        return None  # Caller interprets None as ⊤

    def compose(self, other):
        return self

    def join(self, other):
        return self

    def __eq__(self, other):
        return isinstance(other, TopMicro)

    def __hash__(self):
        return hash("__top__")

    def __repr__(self):
        return "⊤"


class LinearMicro(MicroFunction):
    """
    f(v) = a * v + b (over integers/numeric lattice).
    Useful for induction variable and linear propagation analyses.

    Composition: (a₁·(a₂·v + b₂) + b₁) = (a₁·a₂)·v + (a₁·b₂ + b₁)
    """

    def __init__(self, a: int, b: int):
        object.__setattr__(self, '_a', a)
        object.__setattr__(self, '_b', b)

    @property
    def a(self):
        return self._a

    @property
    def b(self):
        return self._b

    def apply(self, val):
        if val is None:
            return None  # ⊤ propagates
        return self._a * val + self._b

    def compose(self, other):
        if isinstance(other, IdentityMicro):
            return self
        if isinstance(other, ConstantMicro):
            return ConstantMicro(self.apply(other._constant))
        if isinstance(other, TopMicro):
            return TopMicro()
        if isinstance(other, LinearMicro):
            # (a1 * (a2*v + b2) + b1) = (a1*a2)*v + (a1*b2 + b1)
            new_a = self._a * other._a
            new_b = self._a * other._b + self._b
            return LinearMicro(new_a, new_b)
        return ComposedMicro(self, other)

    def join(self, other):
        if isinstance(other, LinearMicro):
            if self._a == other._a and self._b == other._b:
                return self
        if self == other:
            return self
        return TopMicro()

    def __eq__(self, other):
        return (isinstance(other, LinearMicro) and
                self._a == other._a and self._b == other._b)

    def __hash__(self):
        return hash(("__linear__", self._a, self._b))

    def __repr__(self):
        return f"({self._a}·v + {self._b})"


class ComposedMicro(MicroFunction):
    """Fallback composition: f(g(x)) where f and g are arbitrary."""

    def __init__(self, outer: MicroFunction, inner: MicroFunction):
        object.__setattr__(self, '_outer', outer)
        object.__setattr__(self, '_inner', inner)

    def apply(self, val):
        return self._outer.apply(self._inner.apply(val))

    def compose(self, other):
        return ComposedMicro(self, other)

    def join(self, other):
        if self == other:
            return self
        return TopMicro()

    def __eq__(self, other):
        return (isinstance(other, ComposedMicro) and
                self._outer == other._outer and self._inner == other._inner)

    def __hash__(self):
        return hash(("__composed__", self._outer, self._inner))


class IDEProblem(IFDSProblem[D], Generic[D, V]):
    """
    Abstract specification of an IDE problem.

    Extends IFDS with micro-functions (edge functions) on the
    value lattice V.  Subclass and override the edge-function factories.

    From Sagiv–Reps–Horwitz / Møller & Schwartzbach §9.6:
        An IDE problem adds to IFDS:
        - A value lattice (L, ⊔) with finite height
        - Edge functions ℓ : V → V for each edge in G#
    """

    def __init__(self, supergraph: Supergraph, domain: FrozenSet[D],
                 entry_function_id: Any, top_value: V, bottom_value: V):
        super().__init__(supergraph, domain, entry_function_id)
        self.top_value = top_value
        self.bottom_value = bottom_value

    def value_join(self, a: V, b: V) -> V:
        """Join operation on the value lattice. Override for your lattice."""
        raise NotImplementedError

    # ── Edge function factories ───────────────────────────────────

    def normal_edge_function(self, src: SuperNode, tgt: SuperNode,
                             src_fact: Any, tgt_fact: Any,
                             edge: SuperEdge) -> MicroFunction:
        """Edge function for intraprocedural edges in G#."""
        return IdentityMicro()

    def call_edge_function(self, call_node: SuperNode, callee_entry: SuperNode,
                           src_fact: Any, tgt_fact: Any,
                           edge: SuperEdge) -> MicroFunction:
        return IdentityMicro()

    def return_edge_function(self, callee_exit: SuperNode, return_site: SuperNode,
                             call_node: SuperNode,
                             src_fact: Any, tgt_fact: Any,
                             edge: SuperEdge) -> MicroFunction:
        return IdentityMicro()

    def call_to_return_edge_function(self, call_node: SuperNode,
                                     return_site: SuperNode,
                                     src_fact: Any, tgt_fact: Any,
                                     edge: SuperEdge) -> MicroFunction:
        return IdentityMicro()


class IDESolver(Generic[D, V]):
    """
    The IDE tabulation algorithm (Sagiv–Reps–Horwitz 1996).

    Extends IFDS with a second phase that propagates values along
    the exploded supergraph edges using micro-functions.

    Phase I:  Standard IFDS tabulation → reachable (n, d) pairs.
    Phase II: Propagate values V along the path edges using the
              micro-functions, computing for each (n, d) the
              join-over-all-paths value.

    Result: for each node n and fact d, the value v ∈ V.
    """

    def __init__(self, problem: IDEProblem[D, V]):
        self.problem = problem
        self._sg = problem.supergraph

        # Phase I: IFDS reachability
        self._ifds_solver = IFDSSolver(problem)

        # Phase II: value propagation
        # (node, fact) → current value
        self._values: Dict[Tuple[SuperNode, Any], Any] = {}

    def solve(self) -> Dict[SuperNode, Dict[D, V]]:
        """
        Run the full IDE algorithm.

        Returns:
            {SuperNode: {fact: value}} for all reachable (node, fact) pairs.
        """
        # Phase I: compute reachability (which (n, d) pairs are reachable)
        ifds_results = self._ifds_solver.solve()

        # Phase II: propagate values
        self._propagate_values(ifds_results)

        # Collect results
        result: Dict[SuperNode, Dict[D, V]] = defaultdict(dict)
        for (node, fact), val in self._values.items():
            if fact is not _ZERO:
                result[node][fact] = val
        return dict(result)

    def _propagate_values(self, ifds_results: Dict[SuperNode, FrozenSet[D]]):
        """
        Phase II of IDE: propagate values along the reachable path edges.

        Uses a worklist over (node, fact) pairs.
        """
        entry_sn = self._sg.entry_of(self.problem.entry_function_id)
        if entry_sn is None:
            return

        top = self.problem.top_value

        # Initialize all reachable (node, fact) to ⊤
        for node, facts in ifds_results.items():
            for fact in facts:
                self._values[(node, fact)] = top
            self._values[(node, _ZERO)] = top

        # Seed: entry node gets bottom value for _ZERO
        self._values[(entry_sn, _ZERO)] = self.problem.bottom_value
        for seed_fact in self.problem.initial_seeds():
            self._values[(entry_sn, seed_fact)] = self.problem.bottom_value

        # Worklist
        worklist: deque[Tuple[SuperNode, Any]] = deque()
        worklist.append((entry_sn, _ZERO))
        for sf in self.problem.initial_seeds():
            worklist.append((entry_sn, sf))

        visited_edges: Set[Tuple[SuperNode, Any, SuperNode, Any]] = set()

        iterations = 0
        max_iterations = len(ifds_results) * (len(self.problem.domain) + 1) * 10

        while worklist and iterations < max_iterations:
            iterations += 1
            n, d2 = worklist.popleft()
            current_val = self._values.get((n, d2), top)

            if current_val is top or current_val is None:
                continue

            for edge in self._sg.successors(n):
                m = edge.tgt

                if edge.kind == EdgeKind.INTRAPROCEDURAL:
                    ff = self.problem.normal_flow(n, m, edge)
                    for d3 in self._ifds_solver._apply_flow_to_fact(ff, d2):
                        ef = self.problem.normal_edge_function(
                            n, m, d2, d3, edge)
                        new_val = ef.apply(current_val)
                        if self._update_value(m, d3, new_val):
                            worklist.append((m, d3))

                elif edge.kind == EdgeKind.CALL_TO_START:
                    callee_entry = m
                    ff = self.problem.call_flow(n, callee_entry, edge)
                    for d3 in self._ifds_solver._apply_flow_to_fact(ff, d2):
                        ef = self.problem.call_edge_function(
                            n, callee_entry, d2, d3, edge)
                        new_val = ef.apply(current_val)
                        if self._update_value(callee_entry, d3, new_val):
                            worklist.append((callee_entry, d3))

                elif edge.kind == EdgeKind.CALL_TO_RETURN:
                    ff = self.problem.call_to_return_flow(n, m, edge)
                    for d3 in self._ifds_solver._apply_flow_to_fact(ff, d2):
                        ef = self.problem.call_to_return_edge_function(
                            n, m, d2, d3, edge)
                        new_val = ef.apply(current_val)
                        if self._update_value(m, d3, new_val):
                            worklist.append((m, d3))

                elif edge.kind == EdgeKind.EXIT_TO_RETURN:
                    for call_sn, ret_sn in self._sg.callers_of_exit(n):
                        ff = self.problem.return_flow(n, ret_sn, call_sn, edge)
                        for d3 in self._ifds_solver._apply_flow_to_fact(ff, d2):
                            ef = self.problem.return_edge_function(
                                n, ret_sn, call_sn, d2, d3, edge)
                            new_val = ef.apply(current_val)
                            if self._update_value(ret_sn, d3, new_val):
                                worklist.append((ret_sn, d3))

    def _update_value(self, node: SuperNode, fact: Any, new_val: Any) -> bool:
        """
        Join new_val into the current value for (node, fact).
        Returns True if the value changed (need to re-propagate).
        """
        key = (node, fact)
        old_val = self._values.get(key, self.problem.top_value)

        if new_val is None or new_val == self.problem.top_value:
            return False

        if old_val is None or old_val == self.problem.top_value:
            self._values[key] = new_val
            return True

        joined = self.problem.value_join(old_val, new_val)
        if joined != old_val:
            self._values[key] = joined
            return True
        return False

    # ── Query interface ───────────────────────────────────────────

    def value_at(self, node: SuperNode, fact: D) -> V:
        return self._values.get((node, fact), self.problem.top_value)

    def env_at(self, node: SuperNode) -> Dict[D, V]:
        result = {}
        for (n, f), v in self._values.items():
            if n == node and f is not _ZERO:
                result[f] = v
        return result


# =====================================================================
#  Part V: Concrete IFDS Problem Instances
# =====================================================================

# These are ready-to-use IFDS problems built on the framework above,
# instantiating the abstract flow-function factories for common analyses.


@dataclass(frozen=True)
class UninitFact:
    """
    Domain element for possibly-uninitialized-variables analysis.
    Each fact represents "variable V may be uninitialized."

    This is the motivating example from Møller & Schwartzbach §9.1.
    """
    var_id: Any
    var_name: str = ""

    def __repr__(self):
        return f"uninit({self.var_name or self.var_id})"


class PossiblyUninitializedIFDS(IFDSProblem[UninitFact]):
    """
    IFDS instance: Possibly-Uninitialized Variables.

    From Møller & Schwartzbach §9.1:
        "A variable x is possibly uninitialized at a program point p
        if there exists a path from the function entry to p on which
        x has not been assigned a value."

    Domain D = {uninit(v) | v is a local variable}.
    Fact uninit(v) ∈ result(n) means v may be uninitialized at n.

    Transfer:
        - At function entry: GEN all local variables (they start uninitialized).
        - At assignment `v = ...`: KILL uninit(v).
        - At call: map uninit facts for parameters appropriately.
    """

    def __init__(self, supergraph: Supergraph, configuration,
                 entry_function_id: Any):
        # Build domain: one UninitFact per local variable per function
        self._config = configuration
        domain_facts = set()
        self._var_to_func: Dict[Any, Any] = {}  # var_id → function_id

        for func in configuration.functions:
            for var in configuration.variables:
                if (var.isLocal and not var.isArgument and
                        var.nameToken and var.nameToken.scope and
                        hasattr(var.nameToken.scope, 'function') and
                        var.nameToken.scope.function == func):
                    fact = UninitFact(var.Id, getattr(var, 'name', str(var.Id)))
                    domain_facts.add(fact)
                    self._var_to_func[var.Id] = func.Id

        super().__init__(supergraph, frozenset(domain_facts), entry_function_id)

        # Precompute: for each function, which UninitFacts are its locals
        self._func_locals: Dict[Any, Set[UninitFact]] = defaultdict(set)
        for fact in domain_facts:
            fid = self._var_to_func.get(fact.var_id)
            if fid:
                self._func_locals[fid].add(fact)

        # Precompute: var_id → UninitFact
        self._var_fact: Dict[Any, UninitFact] = {f.var_id: f for f in domain_facts}

        # Precompute: for each block, which variables it assigns
        self._block_kills: Dict[Tuple[Any, int], Set[UninitFact]] = {}
        self._precompute_kills(supergraph, configuration)

    def _precompute_kills(self, sg: Supergraph, config):
        """Scan all blocks to find variable assignments."""
        for func in config.functions:
            cfg = sg.cfg_of.get(func.Id)
            if cfg is None:
                continue
            for block in cfg.blocks:
                kills = set()
                for tok in block.tokens:
                    if (tok.isAssignmentOp and tok.astOperand1 and
                            tok.astOperand1.varId):
                        fact = self._var_fact.get(tok.astOperand1.varId)
                        if fact:
                            kills.add(fact)
                self._block_kills[(func.Id, block.id)] = kills

    def normal_flow(self, src, tgt, edge):
        func_id = src.function_id
        kills = self._block_kills.get((func_id, src.block_id), set())
        if not kills:
            return DistributiveFunction.identity(self.domain)
        return DistributiveFunction.gen_kill(
            self.domain,
            gen=frozenset(),
            kill=frozenset(kills)
        )

    def call_flow(self, call_node, callee_entry, edge):
        # At call: propagate non-argument facts; for arguments, if
        # the actual is uninitialized, the formal is too.
        # Simplified: pass through all facts (conservative).
        return DistributiveFunction.identity(self.domain)

    def return_flow(self, callee_exit, return_site, call_node, edge):
        return DistributiveFunction.identity(self.domain)

    def call_to_return_flow(self, call_node, return_site, edge):
        # Locals survive across the call
        return DistributiveFunction.identity(self.domain)

    def initial_seeds(self):
        """All locals of the entry function start uninitialized."""
        return self._func_locals.get(self.entry_function_id, set())


@dataclass(frozen=True)
class TaintFact:
    """
    Domain element for taint analysis via IFDS.
    Represents "variable V holds tainted data."
    """
    var_id: Any
    var_name: str = ""

    def __repr__(self):
        return f"tainted({self.var_name or self.var_id})"


class TaintIFDS(IFDSProblem[TaintFact]):
    """
    IFDS instance: Interprocedural Taint Analysis.

    Domain D = {tainted(v) | v is a variable}.
    Fact tainted(v) ∈ result(n) means v may hold user-controlled data at n.

    This is a *distributive* reformulation of the set-based taint analysis
    from dataflow_analyses.py, now interprocedural and context-sensitive
    via the IFDS framework.
    """

    DEFAULT_SOURCES = frozenset({
        'scanf', 'gets', 'fgets', 'recv', 'read', 'getenv',
        'getchar', 'fgetc', 'fread',
    })
    DEFAULT_SINKS = frozenset({
        'system', 'exec', 'execl', 'execlp', 'execvp', 'popen',
        'sprintf', 'strcpy', 'strcat', 'printf', 'fprintf',
    })

    def __init__(self, supergraph: Supergraph, configuration,
                 entry_function_id: Any,
                 sources: FrozenSet[str] = None,
                 sinks: FrozenSet[str] = None):
        self._config = configuration
        self._sources = sources or self.DEFAULT_SOURCES
        self._sinks = sinks or self.DEFAULT_SINKS

        # Build domain: one TaintFact per variable
        domain_facts = set()
        self._var_fact: Dict[Any, TaintFact] = {}
        for var in configuration.variables:
            name = getattr(var, 'name', str(var.Id))
            fact = TaintFact(var.Id, name)
            domain_facts.add(fact)
            self._var_fact[var.Id] = fact

        super().__init__(supergraph, frozenset(domain_facts), entry_function_id)

        # Precompute per-block gen/kill for taint
        self._block_gen: Dict[Tuple[Any, int], Set[TaintFact]] = {}
        self._block_kill: Dict[Tuple[Any, int], Set[TaintFact]] = {}
        self._block_propagate: Dict[Tuple[Any, int], Dict[TaintFact, Set[TaintFact]]] = {}
        self._sink_locations: List[Tuple[SuperNode, Any]] = []
        self._precompute(supergraph, configuration)

    def _precompute(self, sg: Supergraph, config):
        """Scan blocks for taint sources, sinks, propagation."""
        for func in config.functions:
            cfg = sg.cfg_of.get(func.Id)
            if cfg is None:
                continue
            for block in cfg.blocks:
                gen = set()
                kill = set()
                prop = defaultdict(set)  # src_fact → {tgt_facts}

                for tok in block.tokens:
                    # Source: x = source_func(...)
                    if (tok.isName and hasattr(tok, 'function') and
                            tok.function and tok.function.name in self._sources):
                        # Find assignment target
                        parent = tok.astParent
                        if (parent and parent.isAssignmentOp and
                                parent.astOperand1 and parent.astOperand1.varId):
                            fact = self._var_fact.get(parent.astOperand1.varId)
                            if fact:
                                gen.add(fact)

                    # Propagation: y = expr involving tainted x
                    elif tok.isAssignmentOp:
                        lhs = tok.astOperand1
                        if lhs and lhs.varId:
                            lhs_fact = self._var_fact.get(lhs.varId)
                            if lhs_fact:
                                rhs_vars = self._collect_var_ids(tok.astOperand2)
                                rhs_facts = {self._var_fact[v] for v in rhs_vars
                                             if v in self._var_fact}
                                if rhs_facts:
                                    for rf in rhs_facts:
                                        prop[rf].add(lhs_fact)
                                else:
                                    # Assigned from non-tainted source → kill
                                    kill.add(lhs_fact)

                    # Sink detection
                    if (tok.isName and hasattr(tok, 'function') and
                            tok.function and tok.function.name in self._sinks):
                        sn = SuperNode(func.Id, block.id, func.name)
                        self._sink_locations.append((sn, tok))

                self._block_gen[(func.Id, block.id)] = gen
                self._block_kill[(func.Id, block.id)] = kill
                self._block_propagate[(func.Id, block.id)] = dict(prop)

    def _collect_var_ids(self, token) -> Set[Any]:
        """Recursively collect varIds from an expression AST."""
        if token is None:
            return set()
        result = set()
        if token.varId:
            result.add(token.varId)
        result |= self._collect_var_ids(getattr(token, 'astOperand1', None))
        result |= self._collect_var_ids(getattr(token, 'astOperand2', None))
        return result

    def normal_flow(self, src, tgt, edge):
        key = (src.function_id, src.block_id)
        gen = self._block_gen.get(key, set())
        kill = self._block_kill.get(key, set())
        prop = self._block_propagate.get(key, {})

        # Build the distributive function with gen/kill + propagation
        mapping: Dict[Any, Set[TaintFact]] = defaultdict(set)

        # 0-edges: unconditional generation
        for g in gen:
            mapping[_ZERO].add(g)

        # Identity for non-killed, non-propagated facts
        for fact in self.domain:
            if fact not in kill:
                mapping[fact].add(fact)

        # Propagation edges: if fact x is present, generate fact y
        for src_fact, tgt_facts in prop.items():
            for tf in tgt_facts:
                mapping[src_fact].add(tf)

        return DistributiveFunction.from_mapping(self.domain, dict(mapping))

    def call_flow(self, call_node, callee_entry, edge):
        # Map caller taint facts to callee parameters
        # Conservative: pass all facts through (refined in real usage)
        return DistributiveFunction.identity(self.domain)

    def return_flow(self, callee_exit, return_site, call_node, edge):
        return DistributiveFunction.identity(self.domain)

    def call_to_return_flow(self, call_node, return_site, edge):
        return DistributiveFunction.identity(self.domain)

    def initial_seeds(self):
        return set()  # No initial taint; sources introduce it

    @property
    def sink_locations(self):
        """Return all detected sink locations for post-analysis checking."""
        return self._sink_locations


# ── IDE instance: Copy-Constant Propagation ──────────────────────────

@dataclass(frozen=True)
class VarFact:
    """Domain element for copy-constant propagation: represents a variable."""
    var_id: Any
    var_name: str = ""

    def __repr__(self):
        return self.var_name or str(self.var_id)


# Constant propagation lattice value:
#   None = ⊤ (unknown)
#   int  = known constant
#   NAC  = not-a-constant (⊥ in the const-prop lattice)
NAC = "__NAC__"


class CopyConstantPropagationIDE(IDEProblem[VarFact, Any]):
    """
    IDE instance: Interprocedural Copy-Constant Propagation.

    From Møller & Schwartzbach §9.5–9.6:
        "Copy-constant propagation analysis determines for each variable
        at each program point whether it holds a constant value that
        can be determined at compile time."

    Domain D = {var(v) | v is a variable}.
    Value lattice V: ⊤ (unknown) > c₁, c₂, ... > NAC (not constant).
    Transfer: assignment x = c yields edge function const(c).
              assignment x = y yields edge function id (copy).
              other assignments yield ⊤ (kill).
    """

    def __init__(self, supergraph: Supergraph, configuration,
                 entry_function_id: Any):
        self._config = configuration

        domain_facts = set()
        self._var_fact: Dict[Any, VarFact] = {}
        for var in configuration.variables:
            name = getattr(var, 'name', str(var.Id))
            fact = VarFact(var.Id, name)
            domain_facts.add(fact)
            self._var_fact[var.Id] = fact

        super().__init__(
            supergraph, frozenset(domain_facts), entry_function_id,
            top_value=None,    # ⊤: unknown
            bottom_value=NAC   # ⊥: not-a-constant (starting assumption)
        )

        # Precompute assignment info per block
        self._block_assignments: Dict[Tuple[Any, int], list] = {}
        self._precompute(supergraph, configuration)

    def _precompute(self, sg, config):
        for func in config.functions:
            cfg = sg.cfg_of.get(func.Id)
            if cfg is None:
                continue
            for block in cfg.blocks:
                assignments = []
                for tok in block.tokens:
                    if tok.isAssignmentOp and tok.str == '=':
                        lhs = tok.astOperand1
                        rhs = tok.astOperand2
                        if lhs and lhs.varId:
                            lhs_fact = self._var_fact.get(lhs.varId)
                            if lhs_fact is None:
                                continue
                            if rhs and rhs.isNumber:
                                # x = constant
                                try:
                                    val = int(rhs.str)
                                except (ValueError, TypeError):
                                    try:
                                        val = float(rhs.str)
                                    except (ValueError, TypeError):
                                        val = NAC
                                assignments.append(('const', lhs_fact, val))
                            elif rhs and rhs.varId:
                                # x = y (copy)
                                rhs_fact = self._var_fact.get(rhs.varId)
                                if rhs_fact:
                                    assignments.append(('copy', lhs_fact, rhs_fact))
                                else:
                                    assignments.append(('kill', lhs_fact, None))
                            else:
                                # x = complex_expr → kill
                                assignments.append(('kill', lhs_fact, None))
                self._block_assignments[(func.Id, block.id)] = assignments

    def value_join(self, a, b):
        """Join on the constant-propagation lattice."""
        if a is None:
            return b  # ⊤ ⊔ x = x
        if b is None:
            return a
        if a == NAC or b == NAC:
            return NAC
        if a == b:
            return a
        return NAC  # Different constants → NAC

    def normal_flow(self, src, tgt, edge):
        key = (src.function_id, src.block_id)
        assignments = self._block_assignments.get(key, [])
        if not assignments:
            return DistributiveFunction.identity(self.domain)

        # Build flow function considering all assignments in the block
        killed = set()
        generated = set()
        for kind, lhs_fact, _ in assignments:
            killed.add(lhs_fact)
            if kind == 'const':
                generated.add(lhs_fact)
            elif kind == 'copy':
                generated.add(lhs_fact)

        return DistributiveFunction.gen_kill(
            self.domain,
            gen=frozenset(generated),
            kill=frozenset(killed - generated)
        )

    def normal_edge_function(self, src, tgt, src_fact, tgt_fact, edge):
        key = (src.function_id, src.block_id)
        assignments = self._block_assignments.get(key, [])

        for kind, lhs_fact, rhs in assignments:
            if lhs_fact == tgt_fact:
                if kind == 'const':
                    return ConstantMicro(rhs)
                elif kind == 'copy' and rhs == src_fact:
                    return IdentityMicro()
                elif kind == 'kill':
                    return TopMicro()

        # No assignment to tgt_fact in this block → identity
        if src_fact == tgt_fact:
            return IdentityMicro()

        return TopMicro()

    def call_flow(self, call_node, callee_entry, edge):
        return DistributiveFunction.identity(self.domain)

    def return_flow(self, callee_exit, return_site, call_node, edge):
        return DistributiveFunction.identity(self.domain)

    def call_to_return_flow(self, call_node, return_site, edge):
        return DistributiveFunction.identity(self.domain)

    def initial_seeds(self):
        return set()


# =====================================================================
#  Part VI: Convenience — Intraprocedural Distributive Analysis Wrapper
# =====================================================================

class IntraproceduralDistributiveAnalysis(Generic[D]):
    """
    Simplified wrapper for intraprocedural distributive analysis
    on a single CFG.

    Uses the compact function representation and the existing
    WorklistSolver from dataflow_engine.py for the fixed-point
    computation, but with the guarantee that MOP = MFP.

    This is useful when you don't need interprocedural (IFDS) power
    but want the precision guarantee of distributive transfer functions.
    """

    def __init__(self, cfg: CFG, domain: FrozenSet[D],
                 flow_functions: Dict[int, DistributiveFunction],
                 initial: FrozenSet[D] = frozenset()):
        """
        Args:
            cfg: The control flow graph.
            domain: The finite set of dataflow facts.
            flow_functions: {block_id: DistributiveFunction} — one per block.
            initial: Initial facts at ENTRY.
        """
        self.cfg = cfg
        self.domain = domain
        self._flow_funcs = flow_functions
        self._initial = initial

    def solve(self) -> Dict[int, Tuple[FrozenSet[D], FrozenSet[D]]]:
        """
        Compute the MOP (= MFP for distributive functions) solution.

        Returns {block_id: (IN, OUT)} where IN/OUT are frozensets of facts.
        """
        IN: Dict[int, FrozenSet[D]] = {}
        OUT: Dict[int, FrozenSet[D]] = {}

        entry = self.cfg.entry
        IN[entry.id] = self._initial
        for block in self.cfg.blocks:
            if block != entry:
                IN[block.id] = frozenset()
            ff = self._flow_funcs.get(block.id,
                                       DistributiveFunction.identity(self.domain))
            OUT[block.id] = ff.apply(IN[block.id])

        # Worklist iteration (reuses the RPO ordering from ctrlflow_graph)
        rpo = self.cfg.reverse_postorder()
        worklist = deque(rpo)
        in_worklist = {b.id for b in rpo}

        while worklist:
            block = worklist.popleft()
            in_worklist.discard(block.id)

            # Join predecessors
            if block == entry:
                new_in = self._initial
            else:
                pred_outs = [OUT[p.id] for p in block.predecessors
                             if p.id in OUT]
                new_in = frozenset().union(*pred_outs) if pred_outs else frozenset()

            IN[block.id] = new_in

            ff = self._flow_funcs.get(block.id,
                                       DistributiveFunction.identity(self.domain))
            new_out = ff.apply(new_in)

            if new_out != OUT.get(block.id, frozenset()):
                OUT[block.id] = new_out
                for succ in block.successors:
                    if succ.id not in in_worklist:
                        worklist.append(succ)
                        in_worklist.add(succ.id)

        return {b.id: (IN.get(b.id, frozenset()), OUT.get(b.id, frozenset()))
                for b in self.cfg.blocks}


# =====================================================================
#  Part VII: Distributivity Checker (Development Aid)
# =====================================================================

def check_distributivity(f: DistributiveFunction, sample_size: int = None) -> bool:
    """
    Verify that a DistributiveFunction is truly distributive by
    exhaustive or sampled testing:

        f(A ∪ B) == f(A) ∪ f(B)   for all A, B ⊆ D

    For small domains (|D| ≤ 12), tests all pairs.
    For larger domains, samples randomly.

    This is a development/debugging aid — in production, the
    compact representation guarantees distributivity by construction.
    """
    domain = f.domain
    if len(domain) > 12 and sample_size is None:
        sample_size = 1000

    elements = sorted(domain, key=str)

    if sample_size is None:
        # Exhaustive: test all 2^|D| × 2^|D| pairs
        from itertools import combinations
        all_subsets = []
        for r in range(len(elements) + 1):
            for combo in combinations(elements, r):
                all_subsets.append(frozenset(combo))

        for A in all_subsets:
            for B in all_subsets:
                union = A | B
                lhs = f.apply(union)
                rhs = f.apply(A) | f.apply(B)
                if lhs != rhs:
                    return False
        return True
    else:
        import random
        for _ in range(sample_size):
            k_a = random.randint(0, len(elements))
            k_b = random.randint(0, len(elements))
            A = frozenset(random.sample(elements, min(k_a, len(elements))))
            B = frozenset(random.sample(elements, min(k_b, len(elements))))
            lhs = f.apply(A | B)
            rhs = f.apply(A) | f.apply(B)
            if lhs != rhs:
                return False
        return True


# =====================================================================
#  Part VIII: Integration Helpers for ShimsBridge
# =====================================================================

def run_ifds_uninit(configuration, entry_function_id: Any) -> Dict[SuperNode, FrozenSet[UninitFact]]:
    """
    Convenience: run the possibly-uninitialized IFDS analysis.

    Args:
        configuration: cppcheckdata.Configuration
        entry_function_id: Function.Id for the analysis entry (e.g., main)

    Returns:
        {SuperNode: frozenset of UninitFact} — facts holding at each node.
    """
    sg = Supergraph(configuration)
    problem = PossiblyUninitializedIFDS(sg, configuration, entry_function_id)
    solver = IFDSSolver(problem)
    return solver.solve()


def run_ifds_taint(configuration, entry_function_id: Any,
                   sources=None, sinks=None) -> Tuple[Dict[SuperNode, FrozenSet[TaintFact]], list]:
    """
    Convenience: run the IFDS-based taint analysis.

    Returns:
        (results, sink_violations) where:
        - results: {SuperNode: frozenset of TaintFact}
        - sink_violations: [(SuperNode, token, TaintFact), ...] detected violations
    """
    sg = Supergraph(configuration)
    problem = TaintIFDS(sg, configuration, entry_function_id, sources, sinks)
    solver = IFDSSolver(problem)
    results = solver.solve()

    # Check sinks
    violations = []
    for sn, tok in problem.sink_locations:
        facts_at_sink = results.get(sn, frozenset())
        # Check if any argument to the sink is tainted
        if facts_at_sink:
            for fact in facts_at_sink:
                violations.append((sn, tok, fact))

    return results, violations


def run_ide_constants(configuration, entry_function_id: Any) -> Dict[SuperNode, Dict[VarFact, Any]]:
    """
    Convenience: run the IDE copy-constant propagation.

    Returns:
        {SuperNode: {VarFact: value}} where value is int/float or NAC.
    """
    sg = Supergraph(configuration)
    problem = CopyConstantPropagationIDE(sg, configuration, entry_function_id)
    solver = IDESolver(problem)
    return solver.solve()
