# cppcheckdata_shims/ctrlflow_analysis.py
"""
Control-flow analysis for cppcheckdata-shims.

This module provides analyses that reason about the *structure* of control
flow—loops, paths, dominance, reachability—rather than propagating abstract
data values (which is the job of dataflow_analysis.py).

All analyses consume the CFG representation from ctrlflow_graph.py and
optionally exploit cppcheckdata.Configuration.ValueFlow for path-condition
pruning, loop-bound estimation, and invariant detection.

Principal analyses
------------------
- DominatorTree / PostDominatorTree
- NaturalLoopDetector
- LoopInvariantAnalysis        ← the main user-facing "loop-invariant code motion" checker
- InductionVariableAnalysis
- LoopBoundAnalysis
- PathSensitiveAnalysis
- PathFeasibilityChecker
- BranchCorrelationAnalysis
- UnreachableCodeDetector
- ControlDependenceGraph       ← NEW: CDG (Ferrante–Ottenstein–Warren 1987)
- IntervalAnalysis             ← NEW: T1/T2 intervals (Allen–Cocke)
- StructuralAnalysis           ← NEW: region-based structural analysis
- CyclomaticComplexityAnalyzer ← NEW: McCabe V(G) = E − N + 2P
- StronglyConnectedComponents  ← NEW: Tarjan's SCC
- CriticalEdgeDetector         ← NEW: critical-edge identification
- LoopNestingForest            ← NEW: Ramalingam's loop-nesting forest
- DefUseChainBuilder           ← NEW: per-variable def-use chains on CFG

Usage example (loop-invariant warning)
--------------------------------------
    from cppcheckdata_shims.ctrlflow_graph import build_cfg
    from cppcheckdata_shims.ctrlflow_analysis import (
        NaturalLoopDetector, LoopInvariantAnalysis,
    )

    cfg = build_cfg(configuration)
    loops = NaturalLoopDetector(cfg).detect()
    lia = LoopInvariantAnalysis(cfg, loops, configuration)
    lia.run()
    for inv in lia.invariants():
        print(f"{inv.file}:{inv.line}: style: expression '{inv.text}' "
              f"is loop-invariant and can be hoisted [loopInvariant]")

References
----------
[1] Cooper, Harvey, Kennedy – "A Simple, Fast Dominance Algorithm", 2001.
[2] Lengauer, Tarjan – "A Fast Algorithm for Finding Dominators …", 1979.
[3] Aho, Lam, Sethi, Ullman – "Compilers: Principles, Techniques, &
    Tools", 2e, §9.6 (natural loops), §9.7 (dominators).
[4] Ferrante, Ottenstein, Warren – "The Program Dependence Graph …", 1987.
[5] Allen, Cocke – "A Catalog of Optimizing Transformations", 1972.
[6] Sharir – "Structural Analysis of Programs", 1980.
[7] McCabe – "A Complexity Measure", IEEE TSE, 1976.
[8] Tarjan – "Depth-First Search and Linear Graph Algorithms", 1972.
[9] Ramalingam – "On Loops, Dominators, and Dominance Frontiers", 2002.
[10] Cytron et al. – "Efficiently Computing SSA Form …", 1991.
"""

from __future__ import annotations

import sys
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import (
    Any, Callable, Deque, Dict, FrozenSet, Iterable, Iterator, List,
    Mapping, Optional, Sequence, Set, Tuple, Union,
)

# ---------------------------------------------------------------------------
# Type aliases for the CFG representation from ctrlflow_graph.py
# ---------------------------------------------------------------------------
# We program against a structural protocol so the module works with
# both real ctrlflow_graph objects and lightweight mocks in tests.
#
# A "CfgNode" must expose:
#   .id            : int | str          — unique identifier
#   .successors    : Sequence[CfgNode | CfgEdge]
#   .predecessors  : Sequence[CfgNode | CfgEdge]
#   .tokens        : Sequence[Token]    — cppcheckdata tokens in this block
#   .is_entry      : bool               (optional)
#   .is_exit       : bool               (optional)
#
# A "Cfg" must expose:
#   .entry         : CfgNode
#   .exit          : CfgNode
#   .nodes         : Sequence[CfgNode]  — all nodes (blocks)
#   .edges         : Sequence[CfgEdge]  (optional – for some new analyses)

CfgNode = Any
Cfg = Any
Token = Any
Configuration = Any

_SENTINEL = object()

# ===================================================================
#  Utility: node id extraction
# ===================================================================


def _nid(node: CfgNode) -> Any:
    """Return a hashable id for a CFG node."""
    if hasattr(node, "id"):
        return node.id
    return id(node)


def _node_tokens(node: CfgNode) -> List[Token]:
    """Return the token list inside a CFG block, tolerating missing attr."""
    return list(getattr(node, "tokens", []) or [])


def _successors(node: CfgNode) -> List[CfgNode]:
    """Get successor *nodes*, handling both edge objects and direct node refs.

    ctrlflow_graph.CFGNode stores edges in .successors; each edge has .dst.
    But lightweight test mocks may store nodes directly.
    """
    succs = getattr(node, "successors", []) or []
    result: List[CfgNode] = []
    for s in succs:
        if hasattr(s, "dst"):
            result.append(s.dst)
        elif hasattr(s, "target"):
            result.append(s.target)
        else:
            result.append(s)
    return result


def _predecessors(node: CfgNode) -> List[CfgNode]:
    """Get predecessor *nodes*, handling both edge objects and direct node refs."""
    preds = getattr(node, "predecessors", []) or []
    result: List[CfgNode] = []
    for p in preds:
        if hasattr(p, "src"):
            result.append(p.src)
        elif hasattr(p, "source"):
            result.append(p.source)
        else:
            result.append(p)
    return result


def _all_nodes(cfg: Cfg) -> List[CfgNode]:
    return list(getattr(cfg, "nodes", []) or [])


def _all_edges_raw(cfg: Cfg) -> List[Any]:
    """Return the raw edge list from the CFG, or [] if not available."""
    return list(getattr(cfg, "edges", []) or [])


# ===================================================================
# Helper: token id extraction
# ===================================================================

def _get_tok_id(tok: Any) -> Any:
    """Extract a hashable id from a cppcheckdata token."""
    if tok is None:
        return None
    if hasattr(tok, "Id"):
        return tok.Id
    return id(tok)


# ===================================================================
#  1. Dominator Tree
# ===================================================================

class DominatorTree:
    """
    Lengauer–Tarjan-style dominator tree computation.

    For a CFG with *n* nodes this runs in O(n · α(n)) time, where
    α is the inverse Ackermann function (effectively linear).

    The implementation uses the Cooper–Harvey–Kennedy iterative
    algorithm [1], which is simple, correct, and fast enough for the
    CFGs that cppcheck produces.

    Attributes after .compute():
        idom              : Dict[node_id, node_id]  — immediate dominator
        dom_frontier      : Dict[node_id, Set[node_id]]  — dominance frontier
        dom_tree_children : Dict[node_id, List[node_id]]
        depth             : Dict[node_id, int]  — depth in the dominator tree

    IMPORTANT — root convention
    ---------------------------
    The entry node's immediate dominator is set to *itself*
    (``self.idom[entry_id] == entry_id``).  Every walk up the idom
    chain **must** check for this self-loop to avoid infinite loops.
    """

    def __init__(self, cfg: Cfg):
        self.cfg = cfg
        self._nodes: List[CfgNode] = _all_nodes(cfg)
        self._node_map: Dict[Any, CfgNode] = {_nid(n): n for n in self._nodes}
        self.idom: Dict[Any, Any] = {}
        self.dom_frontier: Dict[Any, Set[Any]] = defaultdict(set)
        self.dom_tree_children: Dict[Any, List[Any]] = defaultdict(list)
        self.depth: Dict[Any, int] = {}
        self._computed = False

    # ---- public API --------------------------------------------------

    def compute(self) -> "DominatorTree":
        """Compute immediate dominators and dominance frontiers."""
        if self._computed:
            return self
        self._compute_idom()
        self._build_dom_tree()
        self._compute_dom_frontier()
        self._compute_depth()
        self._computed = True
        return self

    def dominates(self, a_id: Any, b_id: Any) -> bool:
        """Return True if *a* dominates *b* (a dom b).

        A node dominates itself.  The entry node dominates every node.
        We walk up the immediate-dominator chain from *b*; the walk
        terminates when we either find *a* or reach the root (a node
        whose idom is itself).
        """
        self.compute()
        if a_id == b_id:
            return True
        cur = b_id
        visited: Set[Any] = set()
        while cur is not None:
            if cur == a_id:
                return True
            if cur in visited:
                return False          # cycle – defensive
            visited.add(cur)
            idom_of_cur = self.idom.get(cur)
            if idom_of_cur == cur:    # root of the dominator tree
                return False
            cur = idom_of_cur
        return False

    def strictly_dominates(self, a_id: Any, b_id: Any) -> bool:
        """Return True if *a* strictly dominates *b*: a dom b and a ≠ b."""
        return a_id != b_id and self.dominates(a_id, b_id)

    def common_dominator(self, a_id: Any, b_id: Any) -> Optional[Any]:
        """Lowest common ancestor in the dominator tree."""
        self.compute()
        # Collect ancestors of a
        a_anc: Set[Any] = set()
        cur = a_id
        visited: Set[Any] = set()
        while cur is not None and cur not in visited:
            a_anc.add(cur)
            visited.add(cur)
            idom_of_cur = self.idom.get(cur)
            if idom_of_cur == cur:
                break
            cur = idom_of_cur
        # Walk from b and find first hit
        cur = b_id
        visited2: Set[Any] = set()
        while cur is not None and cur not in visited2:
            if cur in a_anc:
                return cur
            visited2.add(cur)
            idom_of_cur = self.idom.get(cur)
            if idom_of_cur == cur:
                if cur in a_anc:
                    return cur
                break
            cur = idom_of_cur
        return None

    def all_dominators(self, node_id: Any) -> Set[Any]:
        """Return the set of all nodes that dominate *node_id* (including itself)."""
        self.compute()
        result: Set[Any] = set()
        cur = node_id
        visited: Set[Any] = set()
        while cur is not None and cur not in visited:
            result.add(cur)
            visited.add(cur)
            idom_of_cur = self.idom.get(cur)
            if idom_of_cur == cur:
                break
            cur = idom_of_cur
        return result

    def subtree(self, root_id: Any) -> Set[Any]:
        """Return all node ids in the dominator sub-tree rooted at *root_id*."""
        self.compute()
        result: Set[Any] = set()
        q: Deque[Any] = deque([root_id])
        while q:
            nid = q.popleft()
            if nid in result:
                continue
            result.add(nid)
            for child in self.dom_tree_children.get(nid, []):
                q.append(child)
        return result

    # ---- internals: Cooper–Harvey–Kennedy iterative algorithm --------

    def _compute_idom(self):
        entry = self.cfg.entry
        entry_id = _nid(entry)
        nodes = self._nodes

        # RPO numbering via iterative DFS
        finish_stack: List[Any] = []
        vis: Set[Any] = set()

        def _dfs(start: CfgNode):
            s: List[Tuple[CfgNode, int]] = [(start, 0)]
            while s:
                node, idx = s[-1]
                nid = _nid(node)
                if nid not in vis:
                    vis.add(nid)
                succs = _successors(node)
                if idx < len(succs):
                    s[-1] = (node, idx + 1)
                    child = succs[idx]
                    if _nid(child) not in vis:
                        s.append((child, 0))
                else:
                    s.pop()
                    finish_stack.append(nid)

        _dfs(entry)
        rpo_order = list(reversed(finish_stack))
        rpo_num: Dict[Any, int] = {nid: i for i, nid in enumerate(rpo_order)}

        # Initialise idom: entry's idom is itself (sentinel for root)
        self.idom = {nid: None for nid in rpo_num}
        self.idom[entry_id] = entry_id

        n_nodes = len(rpo_order)

        def _intersect(b1: Any, b2: Any) -> Any:
            """Walk two fingers up the idom tree until they meet."""
            finger1, finger2 = b1, b2
            max_steps = n_nodes + 10
            steps = 0
            while finger1 != finger2 and steps < max_steps:
                steps += 1
                while (rpo_num.get(finger1, n_nodes)
                       > rpo_num.get(finger2, n_nodes)):
                    nxt = self.idom.get(finger1)
                    if nxt is None or nxt == finger1:
                        break
                    finger1 = nxt
                while (rpo_num.get(finger2, n_nodes)
                       > rpo_num.get(finger1, n_nodes)):
                    nxt = self.idom.get(finger2)
                    if nxt is None or nxt == finger2:
                        break
                    finger2 = nxt
                # Both at root?
                if (self.idom.get(finger1) == finger1
                        and self.idom.get(finger2) == finger2):
                    break
            return finger1

        # Iterative refinement until fixed point
        changed = True
        max_outer = n_nodes * 3 + 10
        outer = 0
        while changed and outer < max_outer:
            changed = False
            outer += 1
            for nid in rpo_order:
                if nid == entry_id:
                    continue
                node = self._node_map.get(nid)
                if node is None:
                    continue
                preds = [_nid(p) for p in _predecessors(node)
                         if self.idom.get(_nid(p)) is not None]
                if not preds:
                    continue
                new_idom = preds[0]
                for p in preds[1:]:
                    if self.idom.get(p) is not None:
                        new_idom = _intersect(new_idom, p)
                if self.idom.get(nid) != new_idom:
                    self.idom[nid] = new_idom
                    changed = True

    def _build_dom_tree(self):
        self.dom_tree_children = defaultdict(list)
        for nid, idom_id in self.idom.items():
            if idom_id is not None and idom_id != nid:
                self.dom_tree_children[idom_id].append(nid)

    def _compute_dom_frontier(self):
        """Compute dominance frontiers (Cytron et al. 1991, §4.2)."""
        self.dom_frontier = defaultdict(set)
        for node in self._nodes:
            nid = _nid(node)
            preds = [_nid(p) for p in _predecessors(node)]
            if len(preds) < 2:
                continue
            for p in preds:
                runner = p
                visited: Set[Any] = set()
                idom_of_nid = self.idom.get(nid)
                while runner is not None and runner != idom_of_nid:
                    if runner in visited:
                        break
                    visited.add(runner)
                    self.dom_frontier[runner].add(nid)
                    nxt = self.idom.get(runner)
                    if nxt == runner:    # root
                        break
                    runner = nxt

    def _compute_depth(self):
        entry_id = _nid(self.cfg.entry)
        self.depth = {entry_id: 0}
        queue: Deque[Any] = deque([entry_id])
        while queue:
            nid = queue.popleft()
            d = self.depth[nid]
            for child in self.dom_tree_children.get(nid, []):
                if child not in self.depth:
                    self.depth[child] = d + 1
                    queue.append(child)


# ===================================================================
#  2. Post-Dominator Tree
# ===================================================================

class PostDominatorTree:
    """
    Post-dominator tree: the dominator tree of the *reverse* CFG.

    Node A post-dominates B iff every path from B to the exit
    passes through A.

    Uses the same (now-fixed) DominatorTree algorithm on a reversed graph.
    """

    def __init__(self, cfg: Cfg):
        self.cfg = cfg
        self._reverse_cfg = _ReversedCfg(cfg)
        self._dom = DominatorTree(self._reverse_cfg)
        self.ipdom: Dict[Any, Any] = {}
        self.pdom_frontier: Dict[Any, Set[Any]] = defaultdict(set)
        self._computed = False

    def compute(self) -> "PostDominatorTree":
        """Compute immediate post-dominators."""
        if self._computed:
            return self
        self._dom.compute()
        self.ipdom = dict(self._dom.idom)
        self.pdom_frontier = dict(self._dom.dom_frontier)
        self._computed = True
        return self

    def post_dominates(self, a_id: Any, b_id: Any) -> bool:
        """Return True if *a* post-dominates *b*."""
        self.compute()
        return self._dom.dominates(a_id, b_id)

    def strictly_post_dominates(self, a_id: Any, b_id: Any) -> bool:
        return a_id != b_id and self.post_dominates(a_id, b_id)

    def common_post_dominator(self, a_id: Any, b_id: Any) -> Optional[Any]:
        self.compute()
        return self._dom.common_dominator(a_id, b_id)

    def all_post_dominators(self, node_id: Any) -> Set[Any]:
        self.compute()
        return self._dom.all_dominators(node_id)


class _ReversedCfg:
    """Lightweight reversed view of a Cfg for post-dominator computation."""

    def __init__(self, cfg: Cfg):
        self._cfg = cfg
        real_exit = cfg.exit
        real_entry = cfg.entry
        originals = _all_nodes(cfg)
        self._map: Dict[Any, _ReversedNode] = {}
        for n in originals:
            rn = _ReversedNode(n)
            self._map[_nid(n)] = rn
        # In the reversed graph entry↔exit are swapped.
        exit_id = _nid(real_exit)
        entry_id = _nid(real_entry)
        if exit_id not in self._map:
            self._map[exit_id] = _ReversedNode(real_exit)
        if entry_id not in self._map:
            self._map[entry_id] = _ReversedNode(real_entry)
        self.entry = self._map[exit_id]
        self.exit = self._map[entry_id]
        # Assign reversed successors/predecessors
        for n in originals:
            rn = self._map[_nid(n)]
            rn._successors = [self._map[_nid(p)]
                              for p in _predecessors(n)
                              if _nid(p) in self._map]
            rn._predecessors = [self._map[_nid(s)]
                                for s in _successors(n)
                                if _nid(s) in self._map]
        self.nodes = list(self._map.values())


class _ReversedNode:
    """Thin wrapper that swaps successors/predecessors."""

    def __init__(self, original: CfgNode):
        self._original = original
        self.id = _nid(original)
        self.tokens = _node_tokens(original)
        self._successors: List["_ReversedNode"] = []
        self._predecessors: List["_ReversedNode"] = []
        self.is_entry = getattr(original, "is_exit", False)
        self.is_exit = getattr(original, "is_entry", False)

    @property
    def successors(self) -> List["_ReversedNode"]:
        return self._successors

    @property
    def predecessors(self) -> List["_ReversedNode"]:
        return self._predecessors


# ===================================================================
#  3. Natural Loop Detection
# ===================================================================

@dataclass
class NaturalLoop:
    """
    Representation of a natural loop in the CFG.

    Attributes
    ----------
    header       : node id of the loop header (dominates all body nodes)
    body         : frozenset of node ids constituting the loop body
    back_edges   : list of (tail, header) back-edge pairs
    exit_edges   : list of (body_node, outside_node) edges leaving the loop
    preheader    : optional node id that is the unique predecessor of header
                   outside the loop (if one exists)
    depth        : nesting depth (1 = outermost)
    parent       : header id of the enclosing loop, or None
    children     : header ids of immediately nested loops
    """
    header: Any
    body: FrozenSet[Any]
    back_edges: List[Tuple[Any, Any]]
    exit_edges: List[Tuple[Any, Any]] = field(default_factory=list)
    preheader: Optional[Any] = None
    depth: int = 1
    parent: Optional[Any] = None
    children: List[Any] = field(default_factory=list)

    @property
    def size(self) -> int:
        return len(self.body)


class NaturalLoopDetector:
    """
    Detect all natural loops in a CFG.

    Algorithm (Aho et al. §9.6):
    1. Compute dominator tree.
    2. Identify back-edges (edges n→h where h dominates n).
    3. For each back-edge, compute the natural loop body via
       reverse reachability from n to h.
    4. Merge loops with the same header.
    5. Compute nesting and exit edges.
    """

    def __init__(self, cfg: Cfg, domtree: Optional[DominatorTree] = None):
        self.cfg = cfg
        self.domtree = domtree or DominatorTree(cfg)
        self._loops: List[NaturalLoop] = []
        self._detected = False

    def detect(self) -> List[NaturalLoop]:
        """Return all natural loops, outermost first."""
        if self._detected:
            return list(self._loops)

        self.domtree.compute()
        nodes = _all_nodes(self.cfg)
        node_map = {_nid(n): n for n in nodes}

        # Step 1: find back-edges (uses the fixed dominates())
        back_edges: List[Tuple[Any, Any]] = []
        for node in nodes:
            nid = _nid(node)
            for succ in _successors(node):
                sid = _nid(succ)
                if self.domtree.dominates(sid, nid):
                    back_edges.append((nid, sid))

        # Step 2: group by header, compute body
        header_to_tails: Dict[Any, List[Any]] = defaultdict(list)
        for tail, header in back_edges:
            header_to_tails[header].append(tail)

        raw_loops: Dict[Any, Set[Any]] = {}
        raw_back: Dict[Any, List[Tuple[Any, Any]]] = {}

        for header, tails in header_to_tails.items():
            body: Set[Any] = {header}
            worklist: Deque[Any] = deque()
            for tail in tails:
                if tail not in body:
                    body.add(tail)
                    worklist.append(tail)
            while worklist:
                nid = worklist.popleft()
                n = node_map.get(nid)
                if n is None:
                    continue
                for pred in _predecessors(n):
                    pid = _nid(pred)
                    if pid not in body:
                        body.add(pid)
                        worklist.append(pid)
            raw_loops[header] = body
            raw_back[header] = [(t, header) for t in tails]

        # Step 3: exit edges
        loop_objects: Dict[Any, NaturalLoop] = {}
        for header, body in raw_loops.items():
            exits: List[Tuple[Any, Any]] = []
            for nid in body:
                n = node_map.get(nid)
                if n is None:
                    continue
                for succ in _successors(n):
                    sid = _nid(succ)
                    if sid not in body:
                        exits.append((nid, sid))

            preheader = None
            h_node = node_map.get(header)
            if h_node is not None:
                outer_preds = [_nid(p) for p in _predecessors(h_node)
                               if _nid(p) not in body]
                if len(outer_preds) == 1:
                    preheader = outer_preds[0]

            loop_objects[header] = NaturalLoop(
                header=header,
                body=frozenset(body),
                back_edges=raw_back[header],
                exit_edges=exits,
                preheader=preheader,
            )

        # Step 4: nesting — A nested in B if A.body ⊂ B.body
        headers_by_size = sorted(loop_objects.keys(),
                                 key=lambda h: len(loop_objects[h].body))
        for i, h1 in enumerate(headers_by_size):
            loop_a = loop_objects[h1]
            for h2 in headers_by_size[i + 1:]:
                loop_b = loop_objects[h2]
                if loop_a.body < loop_b.body:
                    loop_a.parent = h2
                    if h1 not in loop_b.children:
                        loop_b.children.append(h1)
                    break

        # Compute depth (cycle-safe)
        def _depth(h: Any, seen: Optional[Set[Any]] = None) -> int:
            if seen is None:
                seen = set()
            if h in seen:
                return 1
            seen.add(h)
            p = loop_objects[h].parent
            if p is None:
                return 1
            return _depth(p, seen) + 1

        for h in loop_objects:
            loop_objects[h].depth = _depth(h)

        self._loops = sorted(loop_objects.values(), key=lambda l: l.depth)
        self._detected = True
        return list(self._loops)

    def loop_for_node(self, node_id: Any) -> Optional[NaturalLoop]:
        """Return the innermost loop containing *node_id*, or None."""
        self.detect()
        best: Optional[NaturalLoop] = None
        for loop in self._loops:
            if node_id in loop.body:
                if best is None or loop.depth > best.depth:
                    best = loop
        return best

    def nesting_depth(self, node_id: Any) -> int:
        """Return the loop nesting depth of *node_id* (0 if not in any loop)."""
        loop = self.loop_for_node(node_id)
        return loop.depth if loop else 0


# ===================================================================
#  4. Loop-Invariant Analysis
# ===================================================================

@dataclass
class LoopInvariantExpr:
    """An expression inside a loop body that is loop-invariant."""
    token: Any
    token_id: Any
    loop_header: Any
    text: str = ""
    file: str = ""
    line: int = 0
    column: int = 0
    reason: str = ""


class LoopInvariantAnalysis:
    """
    Identify loop-invariant computations.

    An expression E inside a loop L is *loop-invariant* if **all** operands
    of E satisfy one of:
      (a) the operand is a constant (literal / constexpr),
      (b) the operand is defined outside L,
      (c) the operand has exactly one reaching definition, and that
          definition is itself loop-invariant.
    """

    def __init__(self, cfg: Cfg, loops: List[NaturalLoop],
                 configuration: Optional[Configuration] = None):
        self.cfg = cfg
        self.loops = loops
        self.configuration = configuration
        self._invariants: List[LoopInvariantExpr] = []
        self._computed = False

        # Pre-index: token id → CFG node id
        self._tok_to_node: Dict[Any, Any] = {}
        for node in _all_nodes(cfg):
            nid = _nid(node)
            for tok in _node_tokens(node):
                self._tok_to_node[_get_tok_id(tok)] = nid

    def run(self) -> "LoopInvariantAnalysis":
        """Run the analysis.  Idempotent."""
        if self._computed:
            return self
        for loop in self.loops:
            self._analyse_loop(loop)
        self._computed = True
        return self

    def invariants(self) -> List[LoopInvariantExpr]:
        """Return all detected loop-invariant expressions."""
        self.run()
        return list(self._invariants)

    def invariants_for_loop(self, header: Any) -> List[LoopInvariantExpr]:
        """Return invariants for a specific loop (by header node id)."""
        return [inv for inv in self.invariants() if inv.loop_header == header]

    # ---- internals ---------------------------------------------------

    def _analyse_loop(self, loop: NaturalLoop):
        """Find invariant expressions within a single loop."""
        body_tokens: List[Token] = []
        node_map = {_nid(n): n for n in _all_nodes(self.cfg)}
        for nid in loop.body:
            n = node_map.get(nid)
            if n is None:
                continue
            body_tokens.extend(_node_tokens(n))

        # Sets of variables *defined* (written to) inside the loop
        defs_in_loop: Set[int] = set()
        var_defs: Dict[int, List[Token]] = defaultdict(list)

        for tok in body_tokens:
            vid = getattr(tok, "varId", None)
            if vid is None or vid == 0:
                continue
            if self._is_definition(tok):
                defs_in_loop.add(vid)
                var_defs[vid].append(tok)

        # Iterative invariant detection (worklist)
        invariant_tids: Set[Any] = set()
        changed = True
        while changed:
            changed = False
            for tok in body_tokens:
                tid = _get_tok_id(tok)
                if tid in invariant_tids:
                    continue
                if not self._is_computation(tok):
                    continue
                if self._expr_is_invariant(tok, loop, defs_in_loop,
                                           invariant_tids):
                    invariant_tids.add(tid)
                    changed = True

        # Build result objects
        for tok in body_tokens:
            tid = _get_tok_id(tok)
            if tid not in invariant_tids:
                continue
            if self._is_trivial_constant(tok):
                continue
            self._invariants.append(LoopInvariantExpr(
                token=tok,
                token_id=tid,
                loop_header=loop.header,
                text=self._expr_text(tok),
                file=getattr(tok, "file", ""),
                line=getattr(tok, "linenr", 0),
                column=getattr(tok, "column", 0),
                reason=self._invariance_reason(tok, loop, defs_in_loop,
                                               invariant_tids),
            ))

    def _is_definition(self, tok: Token) -> bool:
        """Heuristic: token is an assignment target."""
        parent = getattr(tok, "astParent", None)
        if parent is None:
            return False
        pstr = getattr(parent, "str", "")
        if pstr in ("=", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=",
                    "<<=", ">>=", "++", "--"):
            op1 = getattr(parent, "astOperand1", None)
            if op1 is tok:
                return True
        if getattr(tok, "str", "") in ("++", "--"):
            return True
        return False

    def _is_computation(self, tok: Token) -> bool:
        """Is this token the root of a non-trivial computation subtree?"""
        s = getattr(tok, "str", "")
        if s in ("+", "-", "*", "/", "%", "<<", ">>", "&", "|", "^",
                 "<", ">", "<=", ">=", "==", "!=", "&&", "||"):
            return True
        if s in ("!", "~") and getattr(tok, "astOperand1", None) is not None:
            return True
        if s == "." or s == "->":
            return True
        if s == "[":
            return True
        return False

    def _expr_is_invariant(self, tok: Token, loop: NaturalLoop,
                           defs_in_loop: Set[int],
                           already_invariant: Set[Any]) -> bool:
        """Check if the expression rooted at *tok* is loop-invariant."""
        operands: List[Token] = []
        op1 = getattr(tok, "astOperand1", None)
        op2 = getattr(tok, "astOperand2", None)
        if op1 is not None:
            operands.append(op1)
        if op2 is not None:
            operands.append(op2)
        for operand in operands:
            if not self._operand_is_invariant(operand, loop, defs_in_loop,
                                              already_invariant):
                return False
        return True

    def _operand_is_invariant(self, tok: Token, loop: NaturalLoop,
                              defs_in_loop: Set[int],
                              already_invariant: Set[Any]) -> bool:
        """Check if a single operand is invariant w.r.t. a loop."""
        tid = _get_tok_id(tok)

        # (a) Constant literal
        if self._is_trivial_constant(tok):
            return True

        # (b) Variable not defined inside the loop
        vid = getattr(tok, "varId", None)
        if vid and vid not in defs_in_loop:
            return True

        # (c) Already proven invariant in a previous iteration
        if tid in already_invariant:
            return True

        # (d) ValueFlow: all known values are the same → effectively constant
        if self._valueflow_proves_invariant(tok, loop):
            return True

        # (e) Sub-expression: recurse
        if self._is_computation(tok):
            return self._expr_is_invariant(tok, loop, defs_in_loop,
                                           already_invariant)
        return False

    def _valueflow_proves_invariant(self, tok: Token,
                                    loop: NaturalLoop) -> bool:
        """Use ValueFlow to check if token value is known-constant across iterations."""
        values = getattr(tok, "values", None)
        if not values:
            return False
        known_vals = [v for v in values
                      if getattr(v, "valueKind", "") == "known"
                      or getattr(v, "isKnown", False)]
        if not known_vals:
            return False
        first_int = getattr(known_vals[0], "intvalue", _SENTINEL)
        if first_int is _SENTINEL:
            return False
        return all(getattr(v, "intvalue", _SENTINEL) == first_int
                   for v in known_vals)

    def _is_trivial_constant(self, tok: Token) -> bool:
        """Is the token a numeric / string literal?"""
        return bool(
            getattr(tok, "isNumber", False)
            or getattr(tok, "isInt", False)
            or getattr(tok, "isFloat", False)
            or getattr(tok, "isString", False)
            or getattr(tok, "isChar", False)
        )

    def _expr_text(self, tok: Token) -> str:
        """Best-effort textual rendering of the expression tree at *tok*."""
        s = getattr(tok, "str", "?")
        op1 = getattr(tok, "astOperand1", None)
        op2 = getattr(tok, "astOperand2", None)
        if op1 and op2:
            return f"{self._expr_text(op1)} {s} {self._expr_text(op2)}"
        if op1:
            return f"{s}{self._expr_text(op1)}"
        return s

    def _invariance_reason(self, tok: Token, loop: NaturalLoop,
                           defs_in_loop: Set[int],
                           invariant_tids: Set[Any]) -> str:
        operands: List[Token] = []
        op1 = getattr(tok, "astOperand1", None)
        op2 = getattr(tok, "astOperand2", None)
        if op1:
            operands.append(op1)
        if op2:
            operands.append(op2)
        reasons = []
        for operand in operands:
            vid = getattr(operand, "varId", None)
            opname = getattr(operand, "str", "?")
            if self._is_trivial_constant(operand):
                reasons.append(f"'{opname}' is a constant")
            elif vid and vid not in defs_in_loop:
                reasons.append(f"'{opname}' is not modified inside the loop")
            elif _get_tok_id(operand) in invariant_tids:
                reasons.append(f"'{opname}' is itself loop-invariant")
            elif self._valueflow_proves_invariant(operand, loop):
                reasons.append(f"'{opname}' has constant ValueFlow")
        return "; ".join(reasons) if reasons else "all operands are invariant"


# ===================================================================
#  5. Induction Variable Analysis
# ===================================================================

class InductionVariableKind(Enum):
    BASIC = auto()      # i = i + c  (or i = i - c, i++, i--)
    DERIVED = auto()    # j = a * i + b  where i is basic IV


@dataclass
class InductionVariable:
    """
    Represents a basic or derived induction variable.

    For a basic IV:  var_id incremented by ``step`` each iteration.
    For a derived IV: value = coeff * basic_iv + offset.
    """
    var_id: int
    kind: InductionVariableKind
    loop_header: Any
    step: Optional[int] = None
    basic_iv: Optional[int] = None
    coeff: int = 1
    offset: int = 0
    init_token: Optional[Any] = None
    update_token: Optional[Any] = None


class InductionVariableAnalysis:
    """
    Identify basic and derived induction variables within natural loops.

    Reference: Aho, Lam, Sethi, Ullman — "Compilers", §9.7.
    """

    def __init__(self, cfg: Cfg, loops: List[NaturalLoop],
                 invariant_analysis: Optional[LoopInvariantAnalysis] = None,
                 configuration: Optional[Configuration] = None):
        self.cfg = cfg
        self.loops = loops
        self.inv_analysis = invariant_analysis
        self.configuration = configuration
        self._ivs: List[InductionVariable] = []
        self._computed = False

    def run(self) -> "InductionVariableAnalysis":
        if self._computed:
            return self
        for loop in self.loops:
            self._find_ivs(loop)
        self._computed = True
        return self

    def induction_variables(self) -> List[InductionVariable]:
        self.run()
        return list(self._ivs)

    def basic_ivs(self, header: Optional[Any] = None) -> List[InductionVariable]:
        return [iv for iv in self.induction_variables()
                if iv.kind == InductionVariableKind.BASIC
                and (header is None or iv.loop_header == header)]

    def derived_ivs(self, header: Optional[Any] = None) -> List[InductionVariable]:
        return [iv for iv in self.induction_variables()
                if iv.kind == InductionVariableKind.DERIVED
                and (header is None or iv.loop_header == header)]

    # ------------------------------------------------------------------ #

    def _find_ivs(self, loop: NaturalLoop):
        body_tokens = self._collect_body_tokens(loop)

        var_defs: Dict[int, List[Token]] = defaultdict(list)
        for tok in body_tokens:
            vid = getattr(tok, "varId", None)
            if not vid:
                continue
            parent = getattr(tok, "astParent", None)
            if parent is None:
                continue
            pstr = getattr(parent, "str", "")
            op1 = getattr(parent, "astOperand1", None)
            if pstr in ("=", "+=", "-=") and op1 is tok:
                var_defs[vid].append(parent)
            elif pstr in ("++", "--"):
                var_defs[vid].append(parent)

        invariant_tids: Set[Any] = set()
        if self.inv_analysis:
            self.inv_analysis.run()
            invariant_tids = {inv.token_id
                              for inv in self.inv_analysis.invariants_for_loop(loop.header)}

        biv_ids: Set[int] = set()
        for vid, defs in var_defs.items():
            if self._is_basic_iv(vid, defs, loop, invariant_tids, body_tokens):
                step = self._extract_step(defs)
                self._ivs.append(InductionVariable(
                    var_id=vid,
                    kind=InductionVariableKind.BASIC,
                    loop_header=loop.header,
                    step=step,
                    update_token=defs[0] if defs else None,
                ))
                biv_ids.add(vid)

        for vid, defs in var_defs.items():
            if vid in biv_ids:
                continue
            div_info = self._check_derived(vid, defs, biv_ids, loop,
                                           invariant_tids, body_tokens)
            if div_info is not None:
                self._ivs.append(InductionVariable(
                    var_id=vid,
                    kind=InductionVariableKind.DERIVED,
                    loop_header=loop.header,
                    basic_iv=div_info[0],
                    coeff=div_info[1],
                    offset=div_info[2],
                    update_token=defs[0] if defs else None,
                ))

    def _is_basic_iv(self, vid: int, defs: List[Token],
                     loop: NaturalLoop, invariant_tids: Set[Any],
                     body_tokens: List[Token]) -> bool:
        if not defs:
            return False
        for d in defs:
            dstr = getattr(d, "str", "")
            if dstr in ("++", "--"):
                continue
            if dstr in ("+=", "-="):
                rhs = getattr(d, "astOperand2", None)
                if rhs is None:
                    return False
                if not self._is_invariant_operand(rhs, loop, invariant_tids):
                    return False
                continue
            if dstr == "=":
                rhs = getattr(d, "astOperand2", None)
                if rhs is None:
                    return False
                rhs_str = getattr(rhs, "str", "")
                if rhs_str not in ("+", "-"):
                    return False
                r_op1 = getattr(rhs, "astOperand1", None)
                r_op2 = getattr(rhs, "astOperand2", None)
                if r_op1 is None or r_op2 is None:
                    return False
                vid1 = getattr(r_op1, "varId", None)
                vid2 = getattr(r_op2, "varId", None)
                if vid1 == vid:
                    if not self._is_invariant_operand(r_op2, loop, invariant_tids):
                        return False
                elif vid2 == vid:
                    if not self._is_invariant_operand(r_op1, loop, invariant_tids):
                        return False
                else:
                    return False
                continue
            return False
        return True

    def _extract_step(self, defs: List[Token]) -> Optional[int]:
        for d in defs:
            dstr = getattr(d, "str", "")
            if dstr == "++":
                return 1
            if dstr == "--":
                return -1
            op2 = getattr(d, "astOperand2", None)
            if op2 is None:
                continue
            if dstr == "+=":
                v = self._const_value(op2)
                if v is not None:
                    return v
            elif dstr == "-=":
                v = self._const_value(op2)
                if v is not None:
                    return -v
            elif dstr == "=":
                rhs = op2
                rhs_str = getattr(rhs, "str", "")
                c_op = getattr(rhs, "astOperand2", None)
                if c_op is None:
                    c_op = getattr(rhs, "astOperand1", None)
                if c_op is not None:
                    v = self._const_value(c_op)
                    if v is not None:
                        return v if rhs_str == "+" else -v
        return None

    def _check_derived(self, vid: int, defs: List[Token],
                       biv_ids: Set[int], loop: NaturalLoop,
                       invariant_tids: Set[Any],
                       body_tokens: List[Token]) -> Optional[Tuple[int, int, int]]:
        if len(defs) != 1:
            return None
        d = defs[0]
        if getattr(d, "str", "") != "=":
            return None
        rhs = getattr(d, "astOperand2", None)
        return self._match_affine(rhs, biv_ids, loop, invariant_tids)

    def _match_affine(self, tok: Optional[Token], biv_ids: Set[int],
                      loop: NaturalLoop,
                      invariant_tids: Set[Any]) -> Optional[Tuple[int, int, int]]:
        if tok is None:
            return None
        s = getattr(tok, "str", "")
        vid = getattr(tok, "varId", None)
        if vid and vid in biv_ids:
            return (vid, 1, 0)
        op1 = getattr(tok, "astOperand1", None)
        op2 = getattr(tok, "astOperand2", None)
        if s == "*" and op1 and op2:
            v1 = getattr(op1, "varId", None)
            v2 = getattr(op2, "varId", None)
            c1 = self._const_value(op1)
            c2 = self._const_value(op2)
            if v1 in biv_ids and c2 is not None:
                return (v1, c2, 0)
            if v2 in biv_ids and c1 is not None:
                return (v2, c1, 0)
        if s in ("+", "-") and op1 and op2:
            sub1 = self._match_affine(op1, biv_ids, loop, invariant_tids)
            sub2 = self._match_affine(op2, biv_ids, loop, invariant_tids)
            c1 = self._const_value(op1)
            c2 = self._const_value(op2)
            if sub1 and c2 is not None:
                biv, coeff, off = sub1
                return (biv, coeff, off + c2 if s == "+" else off - c2)
            if sub2 and c1 is not None and s == "+":
                biv, coeff, off = sub2
                return (biv, coeff, off + c1)
        return None

    def _is_invariant_operand(self, tok: Token, loop: NaturalLoop,
                              invariant_tids: Set[Any]) -> bool:
        if getattr(tok, "isNumber", False):
            return True
        if _get_tok_id(tok) in invariant_tids:
            return True
        vid = getattr(tok, "varId", None)
        if vid:
            node_map = {_nid(n): n for n in _all_nodes(self.cfg)}
            for nid in loop.body:
                n = node_map.get(nid)
                if n is None:
                    continue
                for t in _node_tokens(n):
                    tvid = getattr(t, "varId", None)
                    if tvid == vid:
                        parent = getattr(t, "astParent", None)
                        if parent and getattr(parent, "str", "") in \
                                ("=", "+=", "-=", "*=", "/=", "++", "--"):
                            op1 = getattr(parent, "astOperand1", None)
                            if op1 is t:
                                return False
            return True
        return False

    def _const_value(self, tok: Optional[Token]) -> Optional[int]:
        if tok is None:
            return None
        if getattr(tok, "isNumber", False) or getattr(tok, "isInt", False):
            try:
                return int(getattr(tok, "str", "0"))
            except (ValueError, TypeError):
                return None
        values = getattr(tok, "values", None)
        if values:
            known = [v for v in values
                     if getattr(v, "valueKind", "") == "known"
                     or getattr(v, "isKnown", False)]
            if len(known) == 1:
                iv = getattr(known[0], "intvalue", None)
                if iv is not None:
                    return int(iv)
        return None

    def _collect_body_tokens(self, loop: NaturalLoop) -> List[Token]:
        tokens: List[Token] = []
        node_map = {_nid(n): n for n in _all_nodes(self.cfg)}
        for nid in loop.body:
            n = node_map.get(nid)
            if n:
                tokens.extend(_node_tokens(n))
        return tokens


# ===================================================================
#  6. Loop Bound Analysis
# ===================================================================

@dataclass
class LoopBound:
    """Estimated iteration bound for a loop."""
    loop_header: Any
    lower: Optional[int] = None
    upper: Optional[int] = None
    exact: Optional[int] = None
    confidence: str = "possible"   # "certain" | "probable" | "possible"
    description: str = ""


class LoopBoundAnalysis:
    """
    Estimate loop iteration bounds using induction variables,
    loop conditions, and ValueFlow data.
    """

    def __init__(self, cfg: Cfg, loops: List[NaturalLoop],
                 iv_analysis: Optional[InductionVariableAnalysis] = None,
                 configuration: Optional[Configuration] = None):
        self.cfg = cfg
        self.loops = loops
        self.iv_analysis = iv_analysis
        self.configuration = configuration
        self._bounds: List[LoopBound] = []
        self._computed = False

    def run(self) -> "LoopBoundAnalysis":
        if self._computed:
            return self
        if self.iv_analysis:
            self.iv_analysis.run()
        for loop in self.loops:
            self._analyse_loop(loop)
        self._computed = True
        return self

    def bounds(self) -> List[LoopBound]:
        self.run()
        return list(self._bounds)

    def bound_for_loop(self, header: Any) -> Optional[LoopBound]:
        for b in self.bounds():
            if b.loop_header == header:
                return b
        return None

    # ------------------------------------------------------------------ #

    def _analyse_loop(self, loop: NaturalLoop):
        bivs = []
        if self.iv_analysis:
            bivs = self.iv_analysis.basic_ivs(loop.header)

        node_map = {_nid(n): n for n in _all_nodes(self.cfg)}
        header_node = node_map.get(loop.header)
        if header_node is None:
            return

        cond_tok = self._find_condition_token(header_node, loop, node_map)
        if cond_tok is None:
            self._valueflow_bound(loop, node_map)
            return

        for biv in bivs:
            bound = self._bound_from_condition(biv, cond_tok, loop)
            if bound is not None:
                self._bounds.append(bound)
                return

        self._valueflow_bound(loop, node_map)

    def _find_condition_token(self, header_node: CfgNode,
                              loop: NaturalLoop,
                              node_map: Dict) -> Optional[Token]:
        for tok in reversed(_node_tokens(header_node)):
            s = getattr(tok, "str", "")
            if s in ("<", ">", "<=", ">=", "!=", "=="):
                return tok
        for src_id, _ in loop.exit_edges:
            src = node_map.get(src_id)
            if src is None:
                continue
            for tok in reversed(_node_tokens(src)):
                s = getattr(tok, "str", "")
                if s in ("<", ">", "<=", ">=", "!=", "=="):
                    return tok
        return None

    def _bound_from_condition(self, biv: InductionVariable,
                              cond: Token,
                              loop: NaturalLoop) -> Optional[LoopBound]:
        op1 = getattr(cond, "astOperand1", None)
        op2 = getattr(cond, "astOperand2", None)
        if op1 is None or op2 is None:
            return None

        vid1 = getattr(op1, "varId", None)
        vid2 = getattr(op2, "varId", None)
        cmp = getattr(cond, "str", "")

        bound_tok: Optional[Token] = None
        if vid1 == biv.var_id:
            bound_tok = op2
        elif vid2 == biv.var_id:
            bound_tok = op1
        else:
            return None

        bound_val = self._token_int_value(bound_tok)
        if bound_val is None:
            return None

        init_val = self._find_init_value(biv, loop)
        step = biv.step
        if step is None or step == 0:
            return None

        diff = bound_val - (init_val if init_val is not None else 0)
        if step > 0 and cmp in ("<", "!="):
            iters = max(0, (diff + step - 1) // step)
        elif step > 0 and cmp == "<=":
            iters = max(0, (diff + step) // step)
        elif step < 0 and cmp in (">", "!="):
            iters = max(0, (-diff - step - 1) // (-step))
        elif step < 0 and cmp == ">=":
            iters = max(0, (-diff - step) // (-step))
        else:
            return None

        return LoopBound(
            loop_header=loop.header,
            lower=iters,
            upper=iters,
            exact=iters,
            confidence="probable",
            description=(
                f"BIV v{biv.var_id}: init={init_val}, "
                f"step={step}, bound {cmp} {bound_val} → ~{iters} iterations"
            ),
        )

    def _find_init_value(self, biv: InductionVariable,
                         loop: NaturalLoop) -> Optional[int]:
        if loop.preheader is not None:
            node_map = {_nid(n): n for n in _all_nodes(self.cfg)}
            pre = node_map.get(loop.preheader)
            if pre is not None:
                for tok in _node_tokens(pre):
                    vid = getattr(tok, "varId", None)
                    parent = getattr(tok, "astParent", None)
                    if vid == biv.var_id and parent:
                        pstr = getattr(parent, "str", "")
                        if pstr == "=":
                            op2 = getattr(parent, "astOperand2", None)
                            v = self._token_int_value(op2)
                            if v is not None:
                                return v
        return 0

    def _token_int_value(self, tok: Optional[Token]) -> Optional[int]:
        if tok is None:
            return None
        if getattr(tok, "isNumber", False) or getattr(tok, "isInt", False):
            try:
                return int(getattr(tok, "str", "0"))
            except (ValueError, TypeError):
                pass
        values = getattr(tok, "values", None)
        if values:
            known = [v for v in values
                     if getattr(v, "valueKind", "") == "known"
                     or getattr(v, "isKnown", False)]
            if known:
                iv = getattr(known[0], "intvalue", None)
                if iv is not None:
                    return int(iv)
        return None

    def _valueflow_bound(self, loop: NaturalLoop, node_map: Dict):
        """Fallback: use ValueFlow conditions on exit-edge tokens."""
        for src_id, _ in loop.exit_edges:
            src = node_map.get(src_id)
            if src is None:
                continue
            for tok in _node_tokens(src):
                values = getattr(tok, "values", None)
                if not values:
                    continue
                for v in values:
                    cond = getattr(v, "condition", None)
                    if cond is not None:
                        ival = getattr(v, "intvalue", None)
                        if ival is not None:
                            self._bounds.append(LoopBound(
                                loop_header=loop.header,
                                upper=int(ival) if int(ival) > 0 else None,
                                confidence="possible",
                                description=(
                                    f"ValueFlow conditional value {ival} "
                                    f"at exit edge from node {src_id}"
                                ),
                            ))
                            return


# ===================================================================
#  7. Path-Sensitive Analysis Framework
# ===================================================================

@dataclass(frozen=True)
class PathCondition:
    """A single branch condition along a path."""
    condition_token_id: Any
    branch_taken: bool
    text: str = ""


@dataclass
class PathState:
    """Abstract state along a specific execution path."""
    conditions: Tuple[PathCondition, ...] = ()
    var_state: Dict[int, Any] = field(default_factory=dict)
    feasible: bool = True

    @property
    def path_id(self) -> int:
        return hash(self.conditions)

    def with_condition(self, cond: PathCondition) -> "PathState":
        return PathState(
            conditions=self.conditions + (cond,),
            var_state=dict(self.var_state),
            feasible=self.feasible,
        )

    def with_var(self, var_id: int, value: Any) -> "PathState":
        new_state = dict(self.var_state)
        new_state[var_id] = value
        return PathState(
            conditions=self.conditions,
            var_state=new_state,
            feasible=self.feasible,
        )


class PathSensitiveAnalysis:
    """
    Path-sensitive analysis engine.

    Instead of merging abstract states at join points, this tracks
    **separate** states per path.  Enforces:
      - **k-limiting**: at most *k* paths per CFG node (default 32).
      - **loop unrolling budget**: each back-edge followed at most
        *max_unroll* times per path (default 2).
      - **path merging heuristic**: paths with identical variable
        states are merged even if conditions differ.
    """

    def __init__(self, cfg: Cfg,
                 configuration: Optional[Configuration] = None,
                 domtree: Optional[DominatorTree] = None,
                 k_limit: int = 32,
                 max_unroll: int = 2):
        self.cfg = cfg
        self.configuration = configuration
        self.domtree = domtree or DominatorTree(cfg)
        self.k_limit = k_limit
        self.max_unroll = max_unroll
        self._states: Dict[Any, List[PathState]] = defaultdict(list)
        self._computed = False

    def run(self) -> "PathSensitiveAnalysis":
        if self._computed:
            return self
        self.domtree.compute()
        self._propagate()
        self._computed = True
        return self

    def states_at(self, node_id: Any) -> List[PathState]:
        self.run()
        return list(self._states.get(node_id, []))

    def feasible_states_at(self, node_id: Any) -> List[PathState]:
        return [s for s in self.states_at(node_id) if s.feasible]

    def all_paths(self) -> Dict[Any, List[PathState]]:
        self.run()
        return dict(self._states)

    # ---- internal propagation ----------------------------------------

    def _propagate(self):
        entry_id = _nid(self.cfg.entry)
        initial = PathState()
        self._states[entry_id] = [initial]
        node_map = {_nid(n): n for n in _all_nodes(self.cfg)}

        back_count: Dict[Tuple[int, Any], int] = defaultdict(int)
        worklist: Deque[Any] = deque([entry_id])
        visited_iterations: Dict[Any, int] = defaultdict(int)
        max_iterations = len(node_map) * self.k_limit * 4

        iteration = 0
        while worklist and iteration < max_iterations:
            iteration += 1
            nid = worklist.popleft()
            node = node_map.get(nid)
            if node is None:
                continue

            current_states = list(self._states.get(nid, []))
            if not current_states:
                continue

            succs = _successors(node)
            is_branch = len(succs) == 2

            for si, succ in enumerate(succs):
                sid = _nid(succ)
                new_states: List[PathState] = []

                for ps in current_states:
                    if is_branch:
                        cond_tok = self._branch_condition(node)
                        branch_taken = (si == 0)
                        cond = PathCondition(
                            condition_token_id=(_get_tok_id(cond_tok)
                                                if cond_tok else nid),
                            branch_taken=branch_taken,
                            text=getattr(cond_tok, "str",
                                         "") if cond_tok else "",
                        )
                        new_ps = ps.with_condition(cond)
                        new_ps = self._check_feasibility(new_ps, cond_tok,
                                                         branch_taken)
                    else:
                        new_ps = ps

                    # Back-edge budget (uses fixed dominates)
                    if self.domtree.dominates(sid, nid):
                        key = (new_ps.path_id, sid)
                        if back_count[key] >= self.max_unroll:
                            continue
                        back_count[key] += 1

                    new_ps = self._apply_node_effects(new_ps, node)
                    new_states.append(new_ps)

                existing = self._states.get(sid, [])
                merged = self._merge_states(existing, new_states)
                if merged != existing:
                    self._states[sid] = merged[:self.k_limit]
                    visited_iterations[sid] += 1
                    if visited_iterations[sid] < self.k_limit * 2:
                        worklist.append(sid)

    def _branch_condition(self, node: CfgNode) -> Optional[Token]:
        tokens = _node_tokens(node)
        for tok in reversed(tokens):
            s = getattr(tok, "str", "")
            if s in ("<", ">", "<=", ">=", "==", "!=", "&&", "||", "!"):
                return tok
            if getattr(tok, "isName", False) and not getattr(tok, "isOp", False):
                parent = getattr(tok, "astParent", None)
                if parent and getattr(parent, "str", "") in ("if", "while", "?"):
                    return tok
        return None

    def _check_feasibility(self, ps: PathState, cond_tok: Optional[Token],
                           branch_taken: bool) -> PathState:
        if cond_tok is None:
            return ps
        values = getattr(cond_tok, "values", None)
        if not values:
            return ps
        for v in values:
            if not (getattr(v, "valueKind", "") == "known"
                    or getattr(v, "isKnown", False)):
                continue
            iv = getattr(v, "intvalue", None)
            if iv is not None:
                cond_true = (int(iv) != 0)
                if cond_true != branch_taken:
                    return PathState(
                        conditions=ps.conditions,
                        var_state=ps.var_state,
                        feasible=False,
                    )
        return ps

    def _apply_node_effects(self, ps: PathState,
                            node: CfgNode) -> PathState:
        for tok in _node_tokens(node):
            parent = getattr(tok, "astParent", None)
            if parent is None:
                continue
            pstr = getattr(parent, "str", "")
            if pstr == "=" and getattr(parent, "astOperand1", None) is tok:
                vid = getattr(tok, "varId", None)
                if vid:
                    rhs = getattr(parent, "astOperand2", None)
                    val = self._evaluate(rhs, ps)
                    ps = ps.with_var(vid, val)
        return ps

    def _evaluate(self, tok: Optional[Token], ps: PathState) -> Any:
        if tok is None:
            return None
        if getattr(tok, "isNumber", False):
            try:
                return int(getattr(tok, "str", "0"))
            except (ValueError, TypeError):
                return None
        vid = getattr(tok, "varId", None)
        if vid and vid in ps.var_state:
            return ps.var_state[vid]
        values = getattr(tok, "values", None)
        if values:
            known = [v for v in values
                     if getattr(v, "valueKind", "") == "known"
                     or getattr(v, "isKnown", False)]
            if len(known) == 1:
                return getattr(known[0], "intvalue", None)
        return None

    def _merge_states(self, existing: List[PathState],
                      incoming: List[PathState]) -> List[PathState]:
        seen: Dict[int, PathState] = {}
        for ps in existing:
            key = hash(frozenset(ps.var_state.items()))
            seen[key] = ps
        for ps in incoming:
            key = hash(frozenset(ps.var_state.items()))
            if key not in seen:
                seen[key] = ps
        return list(seen.values())


# ===================================================================
#  8. Path Feasibility Checker
# ===================================================================

class PathFeasibilityChecker:
    """
    Determine whether a specific path is feasible by checking that all
    branch conditions along the path are mutually satisfiable.

    Uses lightweight interval reasoning (no SMT).
    """

    def __init__(self, cfg: Cfg,
                 configuration: Optional[Configuration] = None):
        self.cfg = cfg
        self.configuration = configuration

    def is_feasible(self, path_state: PathState) -> bool:
        if not path_state.feasible:
            return False
        constraints = self._extract_constraints(path_state)
        return self._check_constraints(constraints)

    def infeasible_reason(self, path_state: PathState) -> Optional[str]:
        if path_state.feasible:
            constraints = self._extract_constraints(path_state)
            if self._check_constraints(constraints):
                return None
        for i, c1 in enumerate(path_state.conditions):
            for c2 in path_state.conditions[i + 1:]:
                if (c1.condition_token_id == c2.condition_token_id
                        and c1.branch_taken != c2.branch_taken):
                    return (
                        f"Contradictory branches on condition "
                        f"'{c1.text}': taken={c1.branch_taken} "
                        f"vs taken={c2.branch_taken}"
                    )
        return "Path marked infeasible"

    def _extract_constraints(self, ps: PathState) -> List[Tuple[int, str, int]]:
        constraints: List[Tuple[int, str, int]] = []
        node_map = {_nid(n): n for n in _all_nodes(self.cfg)}
        for cond in ps.conditions:
            tok = self._find_token_by_id(cond.condition_token_id, node_map)
            if tok is None:
                continue
            op = getattr(tok, "str", "")
            op1 = getattr(tok, "astOperand1", None)
            op2 = getattr(tok, "astOperand2", None)
            if op1 is None or op2 is None:
                continue
            vid = getattr(op1, "varId", None)
            val = self._token_int_value(op2)
            if vid is None or val is None:
                continue
            effective_op = op
            if not cond.branch_taken:
                effective_op = self._negate_op(op)
            if effective_op:
                constraints.append((vid, effective_op, val))
        return constraints

    def _check_constraints(self, constraints: List[Tuple[int, str, int]]) -> bool:
        intervals: Dict[int, Tuple[float, float]] = {}
        for vid, op, val in constraints:
            lo, hi = intervals.get(vid, (float('-inf'), float('inf')))
            if op == "<":
                hi = min(hi, val - 1)
            elif op == "<=":
                hi = min(hi, val)
            elif op == ">":
                lo = max(lo, val + 1)
            elif op == ">=":
                lo = max(lo, val)
            elif op == "==":
                lo = max(lo, val)
                hi = min(hi, val)
            intervals[vid] = (lo, hi)
        for vid, (lo, hi) in intervals.items():
            if lo > hi:
                return False
        return True

    def _negate_op(self, op: str) -> Optional[str]:
        neg = {"<": ">=", "<=": ">", ">": "<=", ">=": "<",
               "==": "!=", "!=": "=="}
        return neg.get(op)

    def _find_token_by_id(self, tid: Any, node_map: Dict) -> Optional[Token]:
        for nid, node in node_map.items():
            for tok in _node_tokens(node):
                if _get_tok_id(tok) == tid:
                    return tok
        return None

    def _token_int_value(self, tok: Optional[Token]) -> Optional[int]:
        if tok is None:
            return None
        if getattr(tok, "isNumber", False):
            try:
                return int(getattr(tok, "str", "0"))
            except (ValueError, TypeError):
                pass
        values = getattr(tok, "values", None)
        if values:
            known = [v for v in values
                     if getattr(v, "valueKind", "") == "known"
                     or getattr(v, "isKnown", False)]
            if known:
                iv = getattr(known[0], "intvalue", None)
                if iv is not None:
                    return int(iv)
        return None


# ===================================================================
#  9. Branch Correlation Analysis
# ===================================================================

@dataclass
class CorrelationGroup:
    """A set of branch points controlled by the same condition."""
    condition_var_id: int
    branch_node_ids: List[Any]
    description: str = ""


class BranchCorrelationAnalysis:
    """
    Detect correlated branches: multiple branch points that test the
    same variable (or the same condition expression).
    """

    def __init__(self, cfg: Cfg):
        self.cfg = cfg
        self._groups: List[CorrelationGroup] = []
        self._computed = False

    def run(self) -> "BranchCorrelationAnalysis":
        if self._computed:
            return self
        cond_map: Dict[int, List[Any]] = defaultdict(list)
        for node in _all_nodes(self.cfg):
            succs = _successors(node)
            if len(succs) != 2:
                continue
            for tok in reversed(_node_tokens(node)):
                s = getattr(tok, "str", "")
                if s in ("<", ">", "<=", ">=", "==", "!="):
                    op1 = getattr(tok, "astOperand1", None)
                    vid = getattr(op1, "varId", None) if op1 else None
                    if vid:
                        cond_map[vid].append(_nid(node))
                    break
                vid = getattr(tok, "varId", None)
                if vid and getattr(tok, "isName", False):
                    cond_map[vid].append(_nid(node))
                    break
        for vid, nodes in cond_map.items():
            if len(nodes) >= 2:
                self._groups.append(CorrelationGroup(
                    condition_var_id=vid,
                    branch_node_ids=nodes,
                    description=f"Variable v{vid} tested at {len(nodes)} branch points",
                ))
        self._computed = True
        return self

    def groups(self) -> List[CorrelationGroup]:
        self.run()
        return list(self._groups)

    def correlated_with(self, node_id: Any) -> List[Any]:
        self.run()
        result: List[Any] = []
        for g in self._groups:
            if node_id in g.branch_node_ids:
                result.extend(n for n in g.branch_node_ids if n != node_id)
        return result


# ===================================================================
# 10. Unreachable Code Detector
# ===================================================================

@dataclass
class UnreachableRegion:
    """A region of code that is unreachable under all feasible paths."""
    node_ids: FrozenSet[Any]
    reason: str
    tokens: List[Any] = field(default_factory=list)

    @property
    def file(self) -> str:
        if self.tokens:
            return getattr(self.tokens[0], "file", "")
        return ""

    @property
    def line(self) -> int:
        if self.tokens:
            return getattr(self.tokens[0], "linenr", 0)
        return 0


class UnreachableCodeDetector:
    """
    Detect unreachable code using multiple strategies:
    1. Structural: nodes not reachable from entry via forward DFS.
    2. Path-condition pruning via PathSensitiveAnalysis.
    3. ValueFlow dead branches.
    """

    def __init__(self, cfg: Cfg,
                 configuration: Optional[Configuration] = None,
                 path_analysis: Optional[PathSensitiveAnalysis] = None,
                 feasibility: Optional[PathFeasibilityChecker] = None):
        self.cfg = cfg
        self.configuration = configuration
        self.path_analysis = path_analysis
        self.feasibility = feasibility
        self._regions: List[UnreachableRegion] = []
        self._computed = False

    def run(self) -> "UnreachableCodeDetector":
        if self._computed:
            return self
        self._structural_unreachable()
        self._valueflow_dead_branches()
        if self.path_analysis and self.feasibility:
            self._path_infeasible_unreachable()
        self._computed = True
        return self

    def regions(self) -> List[UnreachableRegion]:
        self.run()
        return list(self._regions)

    def unreachable_node_ids(self) -> Set[Any]:
        ids: Set[Any] = set()
        for r in self.regions():
            ids |= r.node_ids
        return ids

    def _structural_unreachable(self):
        all_ids = {_nid(n) for n in _all_nodes(self.cfg)}
        reachable: Set[Any] = set()
        worklist: Deque[CfgNode] = deque([self.cfg.entry])
        while worklist:
            node = worklist.popleft()
            nid = _nid(node)
            if nid in reachable:
                continue
            reachable.add(nid)
            for succ in _successors(node):
                if _nid(succ) not in reachable:
                    worklist.append(succ)
        unreachable = all_ids - reachable
        if unreachable:
            node_map = {_nid(n): n for n in _all_nodes(self.cfg)}
            toks = []
            for uid in unreachable:
                n = node_map.get(uid)
                if n:
                    toks.extend(_node_tokens(n))
            self._regions.append(UnreachableRegion(
                node_ids=frozenset(unreachable),
                reason="structurally unreachable from entry",
                tokens=toks[:5],
            ))

    def _valueflow_dead_branches(self):
        node_map = {_nid(n): n for n in _all_nodes(self.cfg)}
        for node in _all_nodes(self.cfg):
            succs = _successors(node)
            if len(succs) != 2:
                continue
            cond_tok = self._find_branch_condition(node)
            if cond_tok is None:
                continue
            values = getattr(cond_tok, "values", None)
            if not values:
                continue
            known = [v for v in values
                     if getattr(v, "valueKind", "") == "known"
                     or getattr(v, "isKnown", False)]
            if not known:
                continue
            int_vals = set()
            for v in known:
                iv = getattr(v, "intvalue", None)
                if iv is not None:
                    int_vals.add(int(iv) != 0)
            if len(int_vals) != 1:
                continue
            always_true = int_vals.pop()
            dead_index = 1 if always_true else 0
            dead_succ = succs[dead_index]
            dead_id = _nid(dead_succ)
            dead_toks = _node_tokens(node_map.get(dead_id, dead_succ))
            self._regions.append(UnreachableRegion(
                node_ids=frozenset({dead_id}),
                reason=(f"branch condition "
                        f"'{getattr(cond_tok, 'str', '?')}' is always "
                        f"{'true' if always_true else 'false'}"),
                tokens=dead_toks[:3],
            ))

    def _path_infeasible_unreachable(self):
        if not self.path_analysis or not self.feasibility:
            return
        self.path_analysis.run()
        all_ids = {_nid(n) for n in _all_nodes(self.cfg)}
        already_reported = self.unreachable_node_ids()
        node_map = {_nid(n): n for n in _all_nodes(self.cfg)}
        for nid in all_ids:
            if nid in already_reported:
                continue
            states = self.path_analysis.states_at(nid)
            if not states:
                continue
            all_infeasible = all(
                not self.feasibility.is_feasible(ps) for ps in states
            )
            if all_infeasible and states:
                toks = _node_tokens(node_map.get(nid))
                self._regions.append(UnreachableRegion(
                    node_ids=frozenset({nid}),
                    reason="all paths to this node are infeasible",
                    tokens=list(toks)[:3],
                ))

    def _find_branch_condition(self, node: CfgNode) -> Optional[Token]:
        for tok in reversed(_node_tokens(node)):
            s = getattr(tok, "str", "")
            if s in ("<", ">", "<=", ">=", "==", "!=", "&&", "||", "!"):
                return tok
            if getattr(tok, "isName", False):
                return tok
        return None


# ===================================================================
# Helper: token id extraction  (kept at module level as before)
# ===================================================================

def _get_tok_id(tok: Any) -> Any:
    """Extract a hashable id from a cppcheckdata token."""
    if tok is None:
        return None
    if hasattr(tok, "Id"):
        return tok.Id
    return id(tok)


# ###################################################################
#  NEW ANALYSES (11–18) — informed by control-flow graph literature
# ###################################################################


# ===================================================================
# 11. Control Dependence Graph (CDG)
# ===================================================================

class ControlDependenceGraph:
    """
    Control-dependence graph as defined by Ferrante, Ottenstein & Warren
    (1987): "The Program Dependence Graph and Its Use in Optimization."

    Node B is control-dependent on node A iff:
      1. There exists a path from A to B such that B post-dominates
         every node on the path (exclusive of A).
      2. A is not post-dominated by B.

    Equivalently, B ∈ CDF(A) where CDF is the *control dependence
    frontier* — the dominance frontier of the **reverse** CFG's
    dominator tree.

    This implementation leverages PostDominatorTree and its pdom_frontier.

    Usage::

        cdg = ControlDependenceGraph(cfg).compute()
        for dep in cdg.dependences_of(node_id):
            ...
    """

    def __init__(self, cfg: Cfg,
                 pdom: Optional[PostDominatorTree] = None):
        self.cfg = cfg
        self.pdom = pdom or PostDominatorTree(cfg)
        # cd_map[A] = set of node ids that are control-dependent on A
        self.cd_map: Dict[Any, Set[Any]] = defaultdict(set)
        # rev_cd_map[B] = set of node ids that B is control-dependent on
        self.rev_cd_map: Dict[Any, Set[Any]] = defaultdict(set)
        self._computed = False

    def compute(self) -> "ControlDependenceGraph":
        if self._computed:
            return self
        self.pdom.compute()
        # For every CFG edge (A → B) where B does NOT post-dominate A,
        # walk up B's post-dominator chain until we reach ipdom(A).
        # Every node on that walk (including B) is control-dependent on A.
        node_map = {_nid(n): n for n in _all_nodes(self.cfg)}
        for node in _all_nodes(self.cfg):
            a_id = _nid(node)
            ipdom_a = self.pdom.ipdom.get(a_id)
            for succ in _successors(node):
                b_id = _nid(succ)
                runner = b_id
                visited: Set[Any] = set()
                while runner is not None and runner != ipdom_a:
                    if runner in visited:
                        break
                    visited.add(runner)
                    self.cd_map[a_id].add(runner)
                    self.rev_cd_map[runner].add(a_id)
                    nxt = self.pdom.ipdom.get(runner)
                    if nxt == runner:  # root of post-dom tree
                        break
                    runner = nxt
        self._computed = True
        return self

    def dependences_of(self, node_id: Any) -> Set[Any]:
        """Return nodes that are control-dependent on *node_id*."""
        self.compute()
        return set(self.cd_map.get(node_id, set()))

    def controllers_of(self, node_id: Any) -> Set[Any]:
        """Return nodes that *node_id* is control-dependent on."""
        self.compute()
        return set(self.rev_cd_map.get(node_id, set()))

    def all_dependences(self) -> Dict[Any, Set[Any]]:
        self.compute()
        return dict(self.cd_map)


# ===================================================================
# 12. Interval Analysis (Allen & Cocke)
# ===================================================================

@dataclass
class Interval:
    """An interval in the derived graph (Allen–Cocke T1/T2 reduction)."""
    header: Any
    nodes: FrozenSet[Any]
    level: int = 0   # reduction level (0 = original graph)


class IntervalAnalysis:
    """
    Compute T1/T2 interval structure of a CFG (Allen & Cocke, 1972).

    An *interval* I(h) with header h is the maximal subgraph such that:
      - h is in I(h).
      - Any node n ≠ h in I(h) has all its predecessors in I(h).
      - I(h) is a connected sub-graph.

    The analysis iteratively partitions the graph into intervals,
    then collapses each interval into a single node to form the
    *derived graph*, and repeats until the graph is a single node
    (reducible) or no more collapsing is possible (irreducible).
    """

    def __init__(self, cfg: Cfg):
        self.cfg = cfg
        self._intervals: List[List[Interval]] = []  # per level
        self._reducible: Optional[bool] = None
        self._computed = False

    def compute(self) -> "IntervalAnalysis":
        if self._computed:
            return self
        self._compute_intervals()
        self._computed = True
        return self

    def intervals(self, level: int = 0) -> List[Interval]:
        """Return intervals at a given reduction level."""
        self.compute()
        if level < len(self._intervals):
            return list(self._intervals[level])
        return []

    def is_reducible(self) -> bool:
        """Return True if the CFG is reducible (T1/T2 reducible)."""
        self.compute()
        return bool(self._reducible)

    def all_levels(self) -> List[List[Interval]]:
        self.compute()
        return [list(lvl) for lvl in self._intervals]

    def _compute_intervals(self):
        # Build adjacency from CFG
        all_ids = [_nid(n) for n in _all_nodes(self.cfg)]
        succ_map: Dict[Any, List[Any]] = defaultdict(list)
        pred_map: Dict[Any, List[Any]] = defaultdict(list)
        for n in _all_nodes(self.cfg):
            nid = _nid(n)
            for s in _successors(n):
                sid = _nid(s)
                succ_map[nid].append(sid)
                pred_map[sid].append(nid)

        entry_id = _nid(self.cfg.entry)
        level = 0

        while True:
            intervals = self._find_intervals(all_ids, succ_map, pred_map,
                                             entry_id, level)
            self._intervals.append(intervals)

            if len(intervals) <= 1:
                self._reducible = True
                break

            if len(intervals) == len(all_ids):
                # No collapsing happened → irreducible
                self._reducible = False
                break

            # Build derived graph
            node_to_interval: Dict[Any, Any] = {}
            for intv in intervals:
                for nid in intv.nodes:
                    node_to_interval[nid] = intv.header

            new_ids = [intv.header for intv in intervals]
            new_succ: Dict[Any, List[Any]] = defaultdict(list)
            new_pred: Dict[Any, List[Any]] = defaultdict(list)

            for intv in intervals:
                h = intv.header
                for nid in intv.nodes:
                    for sid in succ_map.get(nid, []):
                        target = node_to_interval.get(sid)
                        if target is not None and target != h:
                            if target not in new_succ[h]:
                                new_succ[h].append(target)
                                new_pred[target].append(h)

            all_ids = new_ids
            succ_map = new_succ
            pred_map = new_pred
            entry_id = node_to_interval.get(entry_id, entry_id)
            level += 1

    @staticmethod
    def _find_intervals(all_ids: List[Any],
                        succ_map: Dict[Any, List[Any]],
                        pred_map: Dict[Any, List[Any]],
                        entry_id: Any,
                        level: int) -> List[Interval]:
        assigned: Set[Any] = set()
        intervals: List[Interval] = []
        headers: Deque[Any] = deque([entry_id])

        while headers:
            h = headers.popleft()
            if h in assigned:
                continue
            body: Set[Any] = {h}
            assigned.add(h)
            changed = True
            while changed:
                changed = False
                for nid in list(all_ids):
                    if nid in body or nid in assigned:
                        continue
                    preds_of_n = pred_map.get(nid, [])
                    if preds_of_n and all(p in body for p in preds_of_n):
                        body.add(nid)
                        assigned.add(nid)
                        changed = True
            # New headers: successors of body nodes not yet assigned
            for nid in body:
                for sid in succ_map.get(nid, []):
                    if sid not in assigned:
                        headers.append(sid)
            intervals.append(Interval(header=h, nodes=frozenset(body),
                                      level=level))
        return intervals


# ===================================================================
# 13. Structural Analysis (Sharir, 1980)
# ===================================================================

class RegionType(Enum):
    BLOCK = auto()
    IF_THEN = auto()
    IF_THEN_ELSE = auto()
    SELF_LOOP = auto()
    WHILE_LOOP = auto()
    NATURAL_LOOP = auto()
    SEQUENCE = auto()
    SWITCH = auto()
    PROPER = auto()
    IMPROPER = auto()


@dataclass
class StructuralRegion:
    """A region identified by structural analysis."""
    region_type: RegionType
    node_ids: FrozenSet[Any]
    entry_id: Any
    children: List["StructuralRegion"] = field(default_factory=list)
    parent: Optional["StructuralRegion"] = None


class StructuralAnalysis:
    """
    Region-based structural analysis (Sharir, 1980).

    Identifies high-level control structures (if-then-else, while,
    sequences) by pattern matching on the CFG.
    """

    def __init__(self, cfg: Cfg,
                 domtree: Optional[DominatorTree] = None):
        self.cfg = cfg
        self.domtree = domtree or DominatorTree(cfg)
        self._regions: List[StructuralRegion] = []
        self._computed = False

    def compute(self) -> "StructuralAnalysis":
        if self._computed:
            return self
        self.domtree.compute()
        self._identify_regions()
        self._computed = True
        return self

    def regions(self) -> List[StructuralRegion]:
        self.compute()
        return list(self._regions)

    def region_for_node(self, node_id: Any) -> Optional[StructuralRegion]:
        """Return the innermost region containing *node_id*."""
        self.compute()
        best: Optional[StructuralRegion] = None
        for r in self._regions:
            if node_id in r.node_ids:
                if best is None or len(r.node_ids) < len(best.node_ids):
                    best = r
        return best

    def _identify_regions(self):
        node_map = {_nid(n): n for n in _all_nodes(self.cfg)}

        for node in _all_nodes(self.cfg):
            nid = _nid(node)
            succs = [_nid(s) for s in _successors(node)]

            # Self-loop
            if nid in succs:
                self._regions.append(StructuralRegion(
                    region_type=RegionType.SELF_LOOP,
                    node_ids=frozenset({nid}),
                    entry_id=nid,
                ))
                continue

            if len(succs) == 2:
                t_id, f_id = succs[0], succs[1]
                t_node = node_map.get(t_id)
                f_node = node_map.get(f_id)

                # If-then: one successor immediately reaches the other
                if t_node is not None:
                    t_succs = [_nid(s) for s in _successors(t_node)]
                    if len(t_succs) == 1 and t_succs[0] == f_id:
                        self._regions.append(StructuralRegion(
                            region_type=RegionType.IF_THEN,
                            node_ids=frozenset({nid, t_id, f_id}),
                            entry_id=nid,
                        ))
                        continue

                # If-then-else: both branches converge
                if t_node is not None and f_node is not None:
                    t_succs = set(_nid(s) for s in _successors(t_node))
                    f_succs = set(_nid(s) for s in _successors(f_node))
                    common = t_succs & f_succs
                    if common:
                        join = next(iter(common))
                        self._regions.append(StructuralRegion(
                            region_type=RegionType.IF_THEN_ELSE,
                            node_ids=frozenset({nid, t_id, f_id, join}),
                            entry_id=nid,
                        ))
                        continue

            # Sequence: single-entry, single-exit chain
            if len(succs) == 1:
                chain = [nid]
                cur = succs[0]
                while cur is not None:
                    c_node = node_map.get(cur)
                    if c_node is None:
                        break
                    preds = [_nid(p) for p in _predecessors(c_node)]
                    c_succs = [_nid(s) for s in _successors(c_node)]
                    if len(preds) != 1 or preds[0] != chain[-1]:
                        break
                    chain.append(cur)
                    if len(c_succs) != 1:
                        break
                    cur = c_succs[0]
                if len(chain) >= 3:
                    self._regions.append(StructuralRegion(
                        region_type=RegionType.SEQUENCE,
                        node_ids=frozenset(chain),
                        entry_id=nid,
                    ))


# ===================================================================
# 14. Cyclomatic Complexity Analyzer
# ===================================================================

@dataclass
class CyclomaticResult:
    """Cyclomatic complexity result."""
    complexity: int
    num_edges: int
    num_nodes: int
    num_connected: int = 1
    description: str = ""


class CyclomaticComplexityAnalyzer:
    """
    Compute McCabe's cyclomatic complexity: $V(G) = E - N + 2P$
    where $E$ = edges, $N$ = nodes, $P$ = connected components.

    Reference: McCabe, "A Complexity Measure", IEEE TSE, 1976.
    """

    def __init__(self, cfg: Cfg):
        self.cfg = cfg
        self._result: Optional[CyclomaticResult] = None

    def compute(self) -> CyclomaticResult:
        if self._result is not None:
            return self._result

        nodes = _all_nodes(self.cfg)
        n = len(nodes)
        e = 0
        for node in nodes:
            e += len(_successors(node))

        # Connected components via BFS
        all_ids = {_nid(nd) for nd in nodes}
        node_map = {_nid(nd): nd for nd in nodes}
        visited: Set[Any] = set()
        p = 0
        for nid in all_ids:
            if nid in visited:
                continue
            p += 1
            q: Deque[Any] = deque([nid])
            while q:
                cur = q.popleft()
                if cur in visited:
                    continue
                visited.add(cur)
                nd = node_map.get(cur)
                if nd is None:
                    continue
                for s in _successors(nd):
                    if _nid(s) not in visited:
                        q.append(_nid(s))
                for pr in _predecessors(nd):
                    if _nid(pr) not in visited:
                        q.append(_nid(pr))

        v = e - n + 2 * p
        self._result = CyclomaticResult(
            complexity=v,
            num_edges=e,
            num_nodes=n,
            num_connected=p,
            description=f"V(G) = {e} - {n} + 2×{p} = {v}",
        )
        return self._result

    @property
    def complexity(self) -> int:
        return self.compute().complexity


# ===================================================================
# 15. Strongly Connected Components (Tarjan)
# ===================================================================

@dataclass
class SCC:
    """A single strongly-connected component."""
    nodes: FrozenSet[Any]
    is_trivial: bool = False   # single node with no self-loop


class StronglyConnectedComponents:
    """
    Tarjan's algorithm for finding all SCCs in a directed graph.

    Reference: Tarjan, "Depth-First Search and Linear Graph
    Algorithms", SIAM J. Comput. 1(2), 1972.
    """

    def __init__(self, cfg: Cfg):
        self.cfg = cfg
        self._sccs: List[SCC] = []
        self._computed = False

    def compute(self) -> "StronglyConnectedComponents":
        if self._computed:
            return self
        self._tarjan()
        self._computed = True
        return self

    def sccs(self) -> List[SCC]:
        self.compute()
        return list(self._sccs)

    def non_trivial_sccs(self) -> List[SCC]:
        """Return only SCCs with more than one node or a self-loop."""
        return [s for s in self.sccs() if not s.is_trivial]

    def scc_for_node(self, node_id: Any) -> Optional[SCC]:
        self.compute()
        for s in self._sccs:
            if node_id in s.nodes:
                return s
        return None

    def _tarjan(self):
        all_nodes_list = _all_nodes(self.cfg)
        node_map = {_nid(n): n for n in all_nodes_list}
        index_counter = [0]
        stack: List[Any] = []
        on_stack: Set[Any] = set()
        index: Dict[Any, int] = {}
        lowlink: Dict[Any, int] = {}

        def strongconnect(nid: Any):
            index[nid] = index_counter[0]
            lowlink[nid] = index_counter[0]
            index_counter[0] += 1
            stack.append(nid)
            on_stack.add(nid)

            nd = node_map.get(nid)
            if nd is not None:
                for s in _successors(nd):
                    sid = _nid(s)
                    if sid not in index:
                        strongconnect(sid)
                        lowlink[nid] = min(lowlink[nid], lowlink[sid])
                    elif sid in on_stack:
                        lowlink[nid] = min(lowlink[nid], index[sid])

            if lowlink[nid] == index[nid]:
                component: Set[Any] = set()
                while True:
                    w = stack.pop()
                    on_stack.discard(w)
                    component.add(w)
                    if w == nid:
                        break
                fs = frozenset(component)
                # Trivial if single node without self-loop
                trivial = (len(component) == 1)
                if trivial:
                    the_id = next(iter(component))
                    nd2 = node_map.get(the_id)
                    if nd2 is not None:
                        for s in _successors(nd2):
                            if _nid(s) == the_id:
                                trivial = False
                                break
                self._sccs.append(SCC(nodes=fs, is_trivial=trivial))

        # Use iterative version to avoid stack overflow on large graphs
        # (We keep the recursive version for clarity but guard with
        # sys.setrecursionlimit if needed.)
        sys_limit = sys.getrecursionlimit()
        needed = len(all_nodes_list) + 100
        if needed > sys_limit:
            sys.setrecursionlimit(needed)
        try:
            for nid in [_nid(n) for n in all_nodes_list]:
                if nid not in index:
                    strongconnect(nid)
        finally:
            sys.setrecursionlimit(sys_limit)


# ===================================================================
# 16. Critical Edge Detector
# ===================================================================

@dataclass
class CriticalEdge:
    """An edge (src, dst) where src has multiple successors and
    dst has multiple predecessors."""
    src: Any
    dst: Any


class CriticalEdgeDetector:
    """
    Identify critical edges in the CFG.

    A *critical edge* is an edge from a node with ≥2 successors to a
    node with ≥2 predecessors.  Such edges are problematic for SSA
    construction and many optimisations because inserting code "on
    the edge" requires splitting it.
    """

    def __init__(self, cfg: Cfg):
        self.cfg = cfg
        self._edges: List[CriticalEdge] = []
        self._computed = False

    def compute(self) -> "CriticalEdgeDetector":
        if self._computed:
            return self
        for node in _all_nodes(self.cfg):
            succs = _successors(node)
            if len(succs) < 2:
                continue
            nid = _nid(node)
            for s in succs:
                sid = _nid(s)
                preds = _predecessors(s)
                if len(preds) >= 2:
                    self._edges.append(CriticalEdge(src=nid, dst=sid))
        self._computed = True
        return self

    def critical_edges(self) -> List[CriticalEdge]:
        self.compute()
        return list(self._edges)

    def has_critical_edges(self) -> bool:
        self.compute()
        return len(self._edges) > 0

    def count(self) -> int:
        self.compute()
        return len(self._edges)


# ===================================================================
# 17. Loop Nesting Forest (Ramalingam, 2002)
# ===================================================================

@dataclass
class LoopNestingNode:
    """A node in the loop-nesting forest."""
    node_id: Any
    loop_header: Optional[Any] = None   # None = not a loop header
    parent: Optional["LoopNestingNode"] = None
    children: List["LoopNestingNode"] = field(default_factory=list)
    depth: int = 0


class LoopNestingForest:
    """
    Build Ramalingam's loop-nesting forest from the dominator tree
    and back-edge information.

    The forest has one tree per top-level loop; each tree node
    corresponds to a loop header, with children being immediately
    nested headers.  Non-loop nodes are leaves.

    Reference: Ramalingam, "On Loops, Dominators, and Dominance
    Frontiers", ACM TOPLAS 24(5), 2002.
    """

    def __init__(self, cfg: Cfg,
                 domtree: Optional[DominatorTree] = None,
                 loops: Optional[List[NaturalLoop]] = None):
        self.cfg = cfg
        self.domtree = domtree or DominatorTree(cfg)
        self._loops = loops
        self._forest: Dict[Any, LoopNestingNode] = {}
        self._roots: List[LoopNestingNode] = []
        self._computed = False

    def compute(self) -> "LoopNestingForest":
        if self._computed:
            return self
        self.domtree.compute()
        if self._loops is None:
            detector = NaturalLoopDetector(self.cfg, self.domtree)
            self._loops = detector.detect()

        # Create a nesting node for every CFG node
        for node in _all_nodes(self.cfg):
            nid = _nid(node)
            self._forest[nid] = LoopNestingNode(node_id=nid)

        # Mark loop headers
        loop_headers: Set[Any] = set()
        for loop in self._loops:
            loop_headers.add(loop.header)
            fn = self._forest.get(loop.header)
            if fn:
                fn.loop_header = loop.header

        # Parent assignment: each node's parent in the nesting forest
        # is the header of the innermost loop containing it (if any).
        for loop in sorted(self._loops, key=lambda l: -l.depth):
            for nid in loop.body:
                if nid == loop.header:
                    continue
                fn = self._forest.get(nid)
                if fn and fn.parent is None:
                    parent_fn = self._forest.get(loop.header)
                    if parent_fn:
                        fn.parent = parent_fn
                        parent_fn.children.append(fn)

        # Loop header nesting: header's parent = enclosing loop's header
        for loop in self._loops:
            fn = self._forest.get(loop.header)
            if fn and fn.parent is None and loop.parent is not None:
                parent_fn = self._forest.get(loop.parent)
                if parent_fn:
                    fn.parent = parent_fn
                    parent_fn.children.append(fn)

        # Roots = nodes without parent
        for fn in self._forest.values():
            if fn.parent is None:
                self._roots.append(fn)

        # Compute depths
        def _set_depth(node: LoopNestingNode, d: int):
            node.depth = d
            for ch in node.children:
                _set_depth(ch, d + 1)

        for root in self._roots:
            _set_depth(root, 0)

        self._computed = True
        return self

    def roots(self) -> List[LoopNestingNode]:
        self.compute()
        return list(self._roots)

    def node(self, node_id: Any) -> Optional[LoopNestingNode]:
        self.compute()
        return self._forest.get(node_id)

    def nesting_depth(self, node_id: Any) -> int:
        fn = self.node(node_id)
        return fn.depth if fn else 0


# ===================================================================
# 18. Def-Use Chain Builder
# ===================================================================

@dataclass
class DefUseInfo:
    """Def-use information for a single variable at a CFG node."""
    var_id: int
    defs: List[Any] = field(default_factory=list)   # token ids of definitions
    uses: List[Any] = field(default_factory=list)    # token ids of uses


class DefUseChainBuilder:
    """
    Build per-variable def-use and use-def chains over the CFG.

    For each variable, identifies:
      - Which CFG nodes define it.
      - Which CFG nodes use it.
      - The mapping from each definition to the set of uses it reaches.

    This is a lightweight reaching-definitions analysis (Aho et al. §9.2)
    that works directly on cppcheckdata tokens.
    """

    def __init__(self, cfg: Cfg):
        self.cfg = cfg
        # def_sites[var_id] = set of node ids that define the variable
        self.def_sites: Dict[int, Set[Any]] = defaultdict(set)
        # use_sites[var_id] = set of node ids that use the variable
        self.use_sites: Dict[int, Set[Any]] = defaultdict(set)
        # du_chains[var_id][(def_node_id, def_tok_id)] = set of (use_node_id, use_tok_id)
        self.du_chains: Dict[int, Dict[Tuple[Any, Any], Set[Tuple[Any, Any]]]] = defaultdict(
            lambda: defaultdict(set)
        )
        self._computed = False

    def compute(self) -> "DefUseChainBuilder":
        if self._computed:
            return self
        self._collect_defs_uses()
        self._propagate_reaching_defs()
        self._computed = True
        return self

    def defs_for(self, var_id: int) -> Set[Any]:
        """Return node ids that define *var_id*."""
        self.compute()
        return set(self.def_sites.get(var_id, set()))

    def uses_for(self, var_id: int) -> Set[Any]:
        """Return node ids that use *var_id*."""
        self.compute()
        return set(self.use_sites.get(var_id, set()))

    def uses_of_def(self, var_id: int, def_node_id: Any,
                    def_tok_id: Any) -> Set[Tuple[Any, Any]]:
        """Return (node_id, tok_id) pairs that use the definition."""
        self.compute()
        return set(self.du_chains.get(var_id, {}).get(
            (def_node_id, def_tok_id), set()))

    def _collect_defs_uses(self):
        for node in _all_nodes(self.cfg):
            nid = _nid(node)
            for tok in _node_tokens(node):
                vid = getattr(tok, "varId", None)
                if not vid:
                    continue
                parent = getattr(tok, "astParent", None)
                is_def = False
                if parent:
                    pstr = getattr(parent, "str", "")
                    if pstr in ("=", "+=", "-=", "*=", "/=", "%=",
                                "&=", "|=", "^=", "<<=", ">>="):
                        if getattr(parent, "astOperand1", None) is tok:
                            is_def = True
                    elif pstr in ("++", "--"):
                        is_def = True
                if getattr(tok, "str", "") in ("++", "--"):
                    is_def = True

                if is_def:
                    self.def_sites[vid].add(nid)
                else:
                    self.use_sites[vid].add(nid)

    def _propagate_reaching_defs(self):
        """Simple reaching-definitions propagation (gen/kill per block)."""
        all_vars = set(self.def_sites.keys()) | set(self.use_sites.keys())
        node_list = _all_nodes(self.cfg)
        node_map = {_nid(n): n for n in node_list}
        all_ids = [_nid(n) for n in node_list]

        for vid in all_vars:
            # gen[nid] = set of (nid, tok_id) for defs of vid in nid
            gen: Dict[Any, Set[Tuple[Any, Any]]] = defaultdict(set)
            for nid in self.def_sites.get(vid, set()):
                nd = node_map.get(nid)
                if nd is None:
                    continue
                for tok in _node_tokens(nd):
                    if getattr(tok, "varId", None) == vid:
                        parent = getattr(tok, "astParent", None)
                        is_d = False
                        if parent:
                            pstr = getattr(parent, "str", "")
                            if pstr in ("=", "+=", "-=", "*=", "/=",
                                        "%=", "&=", "|=", "^=",
                                        "<<=", ">>="):
                                if getattr(parent, "astOperand1", None) is tok:
                                    is_d = True
                            elif pstr in ("++", "--"):
                                is_d = True
                        if getattr(tok, "str", "") in ("++", "--"):
                            is_d = True
                        if is_d:
                            gen[nid].add((nid, _get_tok_id(tok)))

            # Reaching defs: in[n] = ∪ out[p] for p in pred(n)
            #                out[n] = gen[n] ∪ (in[n] - kill[n])
            # For simplicity: kill[n] = gen[n] (strong update assumption)
            rd_in: Dict[Any, Set[Tuple[Any, Any]]] = defaultdict(set)
            rd_out: Dict[Any, Set[Tuple[Any, Any]]] = defaultdict(set)

            changed = True
            max_iter = len(all_ids) * 3 + 10
            it = 0
            while changed and it < max_iter:
                changed = False
                it += 1
                for nid in all_ids:
                    nd = node_map.get(nid)
                    if nd is None:
                        continue
                    new_in: Set[Tuple[Any, Any]] = set()
                    for p in _predecessors(nd):
                        pid = _nid(p)
                        new_in |= rd_out.get(pid, set())
                    old_out = rd_out.get(nid, set())
                    g = gen.get(nid, set())
                    new_out = g | (new_in - g)  # gen ∪ (in - kill)
                    if new_out != old_out:
                        rd_out[nid] = new_out
                        rd_in[nid] = new_in
                        changed = True

            # Build du-chains: for each use site, link reaching defs
            for use_nid in self.use_sites.get(vid, set()):
                nd = node_map.get(use_nid)
                if nd is None:
                    continue
                reaching = rd_in.get(use_nid, set())
                for tok in _node_tokens(nd):
                    if getattr(tok, "varId", None) == vid:
                        parent = getattr(tok, "astParent", None)
                        is_d = False
                        if parent:
                            pstr = getattr(parent, "str", "")
                            if pstr in ("=", "+=", "-=", "*=", "/=",
                                        "%=", "&=", "|=", "^=",
                                        "<<=", ">>="):
                                if getattr(parent, "astOperand1", None) is tok:
                                    is_d = True
                            elif pstr in ("++", "--"):
                                is_d = True
                        if is_d:
                            continue  # this is a def, not a use
                        use_tid = _get_tok_id(tok)
                        for def_key in reaching:
                            self.du_chains[vid][def_key].add(
                                (use_nid, use_tid))


# ===================================================================
# Convenience orchestrator
# ===================================================================

def run_all_ctrlflow_analysis(
    cfg: Cfg,
    configuration: Optional[Configuration] = None,
    *,
    analysis: Optional[Set[str]] = None,
    k_limit: int = 32,
    max_unroll: int = 2,
) -> Dict[str, Any]:
    """
    Run all (or selected) control-flow analyses on a CFG.

    Parameters
    ----------
    cfg            : control-flow graph from ctrlflow_graph.py
    configuration  : cppcheckdata.Configuration
    analysis       : set of analysis names to run, or None for all.
                     Valid names: "dominators", "post_dominators", "loops",
                     "loop_invariants", "induction_vars", "loop_bounds",
                     "path_sensitive", "path_feasibility", "correlations",
                     "unreachable", "cdg", "intervals", "structural",
                     "cyclomatic", "scc", "critical_edges",
                     "loop_nesting", "def_use"
    k_limit        : path-sensitive k-limit
    max_unroll     : path-sensitive loop unroll budget

    Returns
    -------
    Dict mapping analysis name → result object.
    """
    ALL = {
        "dominators", "post_dominators", "loops", "loop_invariants",
        "induction_vars", "loop_bounds", "path_sensitive",
        "path_feasibility", "correlations", "unreachable",
        "cdg", "intervals", "structural", "cyclomatic", "scc",
        "critical_edges", "loop_nesting", "def_use",
    }
    wanted = analysis if analysis is not None else ALL
    results: Dict[str, Any] = {}

    # ---- core analyses (used by many others) ----
    domtree: Optional[DominatorTree] = None
    if wanted & {"dominators", "loops", "loop_invariants", "induction_vars",
                 "loop_bounds", "path_sensitive", "unreachable",
                 "structural", "loop_nesting", "cdg"}:
        domtree = DominatorTree(cfg).compute()
        if "dominators" in wanted:
            results["dominators"] = domtree

    pdom: Optional[PostDominatorTree] = None
    if wanted & {"post_dominators", "cdg"}:
        pdom = PostDominatorTree(cfg).compute()
        if "post_dominators" in wanted:
            results["post_dominators"] = pdom

    loops: Optional[List[NaturalLoop]] = None
    if wanted & {"loops", "loop_invariants", "induction_vars",
                 "loop_bounds", "loop_nesting"}:
        detector = NaturalLoopDetector(cfg, domtree)
        loops = detector.detect()
        if "loops" in wanted:
            results["loops"] = loops

    # ---- loop-based analyses ----
    inv_analysis: Optional[LoopInvariantAnalysis] = None
    if "loop_invariants" in wanted and loops is not None:
        inv_analysis = LoopInvariantAnalysis(cfg, loops, configuration)
        inv_analysis.run()
        results["loop_invariants"] = inv_analysis

    iv_analysis: Optional[InductionVariableAnalysis] = None
    if "induction_vars" in wanted and loops is not None:
        iv_analysis = InductionVariableAnalysis(cfg, loops, inv_analysis,
                                                configuration)
        iv_analysis.run()
        results["induction_vars"] = iv_analysis

    if "loop_bounds" in wanted and loops is not None:
        lb = LoopBoundAnalysis(cfg, loops, iv_analysis, configuration)
        lb.run()
        results["loop_bounds"] = lb

    # ---- path-sensitive analyses ----
    path_analysis: Optional[PathSensitiveAnalysis] = None
    if "path_sensitive" in wanted:
        path_analysis = PathSensitiveAnalysis(cfg, configuration, domtree,
                                              k_limit, max_unroll)
        path_analysis.run()
        results["path_sensitive"] = path_analysis

    feasibility: Optional[PathFeasibilityChecker] = None
    if "path_feasibility" in wanted:
        feasibility = PathFeasibilityChecker(cfg, configuration)
        results["path_feasibility"] = feasibility

    if "correlations" in wanted:
        bca = BranchCorrelationAnalysis(cfg)
        bca.run()
        results["correlations"] = bca

    if "unreachable" in wanted:
        ucd = UnreachableCodeDetector(cfg, configuration, path_analysis,
                                      feasibility)
        ucd.run()
        results["unreachable"] = ucd

    # ---- new analyses (11–18) ----
    if "cdg" in wanted:
        cdg = ControlDependenceGraph(cfg, pdom)
        cdg.compute()
        results["cdg"] = cdg

    if "intervals" in wanted:
        ia = IntervalAnalysis(cfg)
        ia.compute()
        results["intervals"] = ia

    if "structural" in wanted:
        sa = StructuralAnalysis(cfg, domtree)
        sa.compute()
        results["structural"] = sa

    if "cyclomatic" in wanted:
        cc = CyclomaticComplexityAnalyzer(cfg)
        results["cyclomatic"] = cc.compute()

    if "scc" in wanted:
        scc_obj = StronglyConnectedComponents(cfg)
        scc_obj.compute()
        results["scc"] = scc_obj

    if "critical_edges" in wanted:
        ce = CriticalEdgeDetector(cfg)
        ce.compute()
        results["critical_edges"] = ce

    if "loop_nesting" in wanted:
        lnf = LoopNestingForest(cfg, domtree, loops)
        lnf.compute()
        results["loop_nesting"] = lnf

    if "def_use" in wanted:
        du = DefUseChainBuilder(cfg)
        du.compute()
        results["def_use"] = du

    return results
