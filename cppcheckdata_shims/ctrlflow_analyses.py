# cppcheckdata_shims/ctrlflow_analyses.py
"""
Control-flow analyses for cppcheckdata-shims.

This module provides analyses that reason about the *structure* of control
flow—loops, paths, dominance, reachability—rather than propagating abstract
data values (which is the job of dataflow_analyses.py).

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

Usage example (loop-invariant warning)
--------------------------------------
    from cppcheckdata_shims.ctrlflow_graph import build_cfg
    from cppcheckdata_shims.ctrlflow_analyses import (
        NaturalLoopDetector, LoopInvariantAnalysis,
    )

    cfg = build_cfg(configuration)
    loops = NaturalLoopDetector(cfg).detect()
    lia = LoopInvariantAnalysis(cfg, loops, configuration)
    lia.run()
    for inv in lia.invariants():
        print(f"{inv.file}:{inv.line}: style: expression '{inv.text}' "
              f"is loop-invariant and can be hoisted [loopInvariant]")
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
#   .successors    : Sequence[CfgNode]
#   .predecessors  : Sequence[CfgNode]
#   .tokens        : Sequence[Token]    — cppcheckdata tokens in this block
#   .is_entry      : bool
#   .is_exit       : bool
#
# A "Cfg" must expose:
#   .entry         : CfgNode
#   .exit          : CfgNode
#   .nodes         : Sequence[CfgNode]  — all nodes (blocks)

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
    return list(getattr(node, "successors", []) or [])


def _predecessors(node: CfgNode) -> List[CfgNode]:
    return list(getattr(node, "predecessors", []) or [])


def _all_nodes(cfg: Cfg) -> List[CfgNode]:
    return list(getattr(cfg, "nodes", []) or [])


# ===================================================================
#  1. Dominator Tree
# ===================================================================

class DominatorTree:
    """
    Lengauer–Tarjan-style dominator tree computation.

    For a CFG with *n* nodes this runs in O(n · α(n)) time, where
    α is the inverse Ackermann function (effectively linear).

    Attributes after .compute():
        idom            : Dict[node_id, node_id]  — immediate dominator
        dom_frontier    : Dict[node_id, Set[node_id]]  — dominance frontier
        dom_tree_children : Dict[node_id, List[node_id]]
        depth           : Dict[node_id, int]  — depth in the dominator tree
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
        """Return True if *a* dominates *b* (a dom b)."""
        self.compute()
        cur = b_id
        while cur is not None:
            if cur == a_id:
                return True
            cur = self.idom.get(cur)
        return False

    def strictly_dominates(self, a_id: Any, b_id: Any) -> bool:
        return a_id != b_id and self.dominates(a_id, b_id)

    def common_dominator(self, a_id: Any, b_id: Any) -> Optional[Any]:
        """Lowest common ancestor in the dominator tree."""
        self.compute()
        a_anc: Set[Any] = set()
        cur = a_id
        while cur is not None:
            a_anc.add(cur)
            cur = self.idom.get(cur)
        cur = b_id
        while cur is not None:
            if cur in a_anc:
                return cur
            cur = self.idom.get(cur)
        return None

    # ---- internals: Cooper–Harvey–Kennedy iterative algorithm --------
    # Simple, correct, and fast enough for the CFGs cppcheck produces.

    def _compute_idom(self):
        entry = self.cfg.entry
        entry_id = _nid(entry)
        nodes = self._nodes

        # RPO numbering
        rpo_order: List[Any] = []
        visited: Set[Any] = set()
        stack: List[CfgNode] = [entry]
        # iterative DFS for RPO
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

        # initialise idom
        self.idom = {nid: None for nid in rpo_num}
        self.idom[entry_id] = entry_id

        def _intersect(b1: Any, b2: Any) -> Any:
            finger1, finger2 = b1, b2
            while finger1 != finger2:
                while rpo_num.get(finger1, len(rpo_order)) > rpo_num.get(finger2, len(rpo_order)):
                    finger1 = self.idom.get(finger1, finger1)
                while rpo_num.get(finger2, len(rpo_order)) > rpo_num.get(finger1, len(rpo_order)):
                    finger2 = self.idom.get(finger2, finger2)
            return finger1

        changed = True
        while changed:
            changed = False
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
        entry_id = _nid(self.cfg.entry)
        self.dom_tree_children = defaultdict(list)
        for nid, idom_id in self.idom.items():
            if idom_id is not None and idom_id != nid:
                self.dom_tree_children[idom_id].append(nid)

    def _compute_dom_frontier(self):
        self.dom_frontier = defaultdict(set)
        for node in self._nodes:
            nid = _nid(node)
            preds = [_nid(p) for p in _predecessors(node)]
            if len(preds) < 2:
                continue
            for p in preds:
                runner = p
                while runner is not None and runner != self.idom.get(nid):
                    self.dom_frontier[runner].add(nid)
                    if runner == self.idom.get(runner):
                        break
                    runner = self.idom.get(runner)

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

    Uses the same algorithm as DominatorTree but on a reversed graph.
    """

    def __init__(self, cfg: Cfg):
        self.cfg = cfg
        self._reverse_cfg = _ReversedCfg(cfg)
        self._dom = DominatorTree(self._reverse_cfg)
        self.ipdom: Dict[Any, Any] = {}
        self.pdom_frontier: Dict[Any, Set[Any]] = defaultdict(set)
        self._computed = False

    def compute(self) -> "PostDominatorTree":
        if self._computed:
            return self
        self._dom.compute()
        self.ipdom = dict(self._dom.idom)
        self.pdom_frontier = dict(self._dom.dom_frontier)
        self._computed = True
        return self

    def post_dominates(self, a_id: Any, b_id: Any) -> bool:
        self.compute()
        return self._dom.dominates(a_id, b_id)


class _ReversedCfg:
    """Lightweight reversed view of a Cfg for post-dominator computation."""

    def __init__(self, cfg: Cfg):
        self._cfg = cfg
        real_exit = cfg.exit
        real_entry = cfg.entry
        # In the reversed graph entry↔exit are swapped.
        self.entry = _ReversedNode(real_exit, reverse=True)
        self.exit = _ReversedNode(real_entry, reverse=True)
        # Build reversed node map
        originals = _all_nodes(cfg)
        self._map: Dict[Any, _ReversedNode] = {}
        for n in originals:
            rn = _ReversedNode(n, reverse=True)
            self._map[_nid(n)] = rn
        # Fix up entry/exit
        self._map[_nid(real_exit)] = self.entry
        self._map[_nid(real_entry)] = self.exit
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

    def __init__(self, original: CfgNode, reverse: bool = False):
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

    Algorithm:
    1. Compute dominator tree.
    2. Identify back-edges (edges n→h where h dominates n).
    3. For each back-edge, compute the natural loop body via
       reverse reachability from n to h (staying within dominated
       nodes).
    4. Merge loops with the same header.
    5. Compute nesting and exit edges.

    Reference: Aho, Lam, Sethi, Ullman — "Compilers: Principles,
    Techniques, & Tools", §9.6 (Natural Loops).
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

        # Step 1: find back-edges
        back_edges: List[Tuple[Any, Any]] = []
        for node in nodes:
            nid = _nid(node)
            for succ in _successors(node):
                sid = _nid(succ)
                if self.domtree.dominates(sid, nid):
                    back_edges.append((nid, sid))

        # Step 2: compute loop body for each back-edge
        # Group by header
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

        # Step 3: compute exit edges
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

            # Find preheader: unique predecessor of header not in body
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

        # Step 4: compute nesting
        # Loop A is nested in loop B if A.body ⊂ B.body
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

        # Compute depth
        def _depth(h: Any) -> int:
            p = loop_objects[h].parent
            if p is None:
                return 1
            return _depth(p) + 1

        for h in loop_objects:
            loop_objects[h].depth = _depth(h)

        self._loops = sorted(loop_objects.values(), key=lambda l: l.depth)
        self._detected = True
        return list(self._loops)

    def loop_for_node(self, node_id: Any) -> Optional[NaturalLoop]:
        """Return the innermost loop containing *node_id*, or None."""
        self.detect()
        # innermost = highest depth
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
    """
    An expression inside a loop body that does *not* change across
    iterations and can therefore be hoisted to the loop preheader.

    Attributes
    ----------
    token       : the cppcheckdata Token object of the root of the expression
    token_id    : token Id
    loop_header : header node id of the containing loop
    text        : textual representation of the expression
    file        : source file
    line        : source line number
    column      : source column
    reason      : human-readable explanation of why this is invariant
    """
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
      (b) the operand is defined outside L (all reaching definitions
          come from outside L),
      (c) the operand has exactly one reaching definition, and that
          definition is itself loop-invariant.

    The analysis uses ValueFlow values attached to tokens to improve
    precision: a variable whose ValueFlow value is ``isKnown`` and does
    not change inside the loop is invariant regardless of reaching-def
    information.

    Parameters
    ----------
    cfg            : the control-flow graph
    loops          : list of NaturalLoop objects (from NaturalLoopDetector)
    configuration  : cppcheckdata.Configuration — provides tokenlist, variables,
                     and ValueFlow data
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
        """Run the analysis. Idempotent."""
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
        # Collect all tokens inside the loop body
        body_tokens: List[Token] = []
        node_map = {_nid(n): n for n in _all_nodes(self.cfg)}
        for nid in loop.body:
            n = node_map.get(nid)
            if n is None:
                continue
            body_tokens.extend(_node_tokens(n))

        # Sets of variables *defined* (written to) inside the loop
        defs_in_loop: Set[int] = set()
        # Map: varId → list of definition tokens inside loop
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
            # Only report "interesting" invariants — skip trivial constants
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
        # Assignment: the token is the LHS operand of '='
        parent = getattr(tok, "astParent", None)
        if parent is None:
            return False
        pstr = getattr(parent, "str", "")
        if pstr in ("=", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=",
                     "<<=", ">>=", "++", "--"):
            op1 = getattr(parent, "astOperand1", None)
            if op1 is tok:
                return True
            # Also catch ++ and -- applied directly
        if getattr(tok, "str", "") in ("++", "--"):
            return True
        return False

    def _is_computation(self, tok: Token) -> bool:
        """Is this token the root of a non-trivial computation subtree?"""
        # We look for binary/unary operators and function calls that
        # produce values used elsewhere.
        s = getattr(tok, "str", "")
        # Binary arithmetic / comparison operators
        if s in ("+", "-", "*", "/", "%", "<<", ">>", "&", "|", "^",
                 "<", ">", "<=", ">=", "==", "!=", "&&", "||"):
            return True
        # Unary operators
        if s in ("!", "~") and getattr(tok, "astOperand1", None) is not None:
            return True
        # Member access that computes something
        if s == "." or s == "->":
            return True
        # Function calls are NOT invariant unless we can prove purity
        # (we're conservative: skip them)
        # A variable read that is invariant is interesting only if
        # it appears as an operand inside an operator expression,
        # not standalone. We handle that at the operand level.
        # Also: subscript operator
        if s == "[":
            return True
        return False

    def _expr_is_invariant(self, tok: Token, loop: NaturalLoop,
                           defs_in_loop: Set[int],
                           already_invariant: Set[Any]) -> bool:
        """
        Check if the expression rooted at *tok* is loop-invariant.
        """
        s = getattr(tok, "str", "")

        # Check all operands
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
        """
        Use ValueFlow to check if a token's value is known-constant
        throughout loop iterations.
        """
        values = getattr(tok, "values", None)
        if not values:
            return False
        # If all values are "known" (not conditional / possible)
        # and they all agree on the same intvalue, the token is invariant.
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

    For a basic IV:  var_id incremented by `step` each iteration.
    For a derived IV: value = coeff * basic_iv + offset.
    """
    var_id: int
    kind: InductionVariableKind
    loop_header: Any
    step: Optional[int] = None          # basic: increment per iteration
    basic_iv: Optional[int] = None      # derived: var_id of the basic IV
    coeff: int = 1                      # derived: multiplicative coefficient
    offset: int = 0                     # derived: additive offset
    init_token: Optional[Any] = None    # token where IV is initialised
    update_token: Optional[Any] = None  # token where IV is updated


class InductionVariableAnalysis:
    """
    Identify basic and derived induction variables within natural loops.

    A *basic induction variable* (BIV) is a variable whose only
    definitions inside the loop are of the form  i = i ± c  where c
    is loop-invariant.

    A *derived induction variable* (DIV) is computed as  j = a * i + b
    where i is a BIV and a, b are loop-invariant.

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

    def _find_ivs(self, loop: NaturalLoop):
        body_tokens = self._collect_body_tokens(loop)

        # Map: varId → list of definitions inside loop body
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

        # Identify BIVs
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

        # Identify DIVs: j = a * i + b where i is BIV
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
        """
        Variable vid is a BIV if every definition inside the loop
        has the form  vid = vid ± c  (or vid++/vid--) where c is invariant.
        """
        if not defs:
            return False
        for d in defs:
            dstr = getattr(d, "str", "")
            if dstr in ("++", "--"):
                continue
            if dstr == "+=" or dstr == "-=":
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
                # rhs must be: vid + c or vid - c
                rhs_str = getattr(rhs, "str", "")
                if rhs_str not in ("+", "-"):
                    return False
                r_op1 = getattr(rhs, "astOperand1", None)
                r_op2 = getattr(rhs, "astOperand2", None)
                if r_op1 is None or r_op2 is None:
                    return False
                # One of the operands must be vid, the other invariant
                vid1 = getattr(r_op1, "varId", None)
                vid2 = getattr(r_op2, "varId", None)
                if vid1 == vid:
                    if not self._is_invariant_operand(r_op2, loop,
                                                      invariant_tids):
                        return False
                elif vid2 == vid:
                    if not self._is_invariant_operand(r_op1, loop,
                                                      invariant_tids):
                        return False
                else:
                    return False
                continue
            return False
        return True

    def _extract_step(self, defs: List[Token]) -> Optional[int]:
        """Try to extract the constant step from BIV definitions."""
        for d in defs:
            dstr = getattr(d, "str", "")
            if dstr == "++":
                return 1
            if dstr == "--":
                return -1
            op2 = getattr(d, "astOperand2", None)
            if op2 is None:
                continue
            # For += / -=
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
        """
        Check if vid is a derived IV of the form j = a * i + b.
        Returns (basic_iv_id, coeff, offset) or None.
        """
        if len(defs) != 1:
            return None
        d = defs[0]
        dstr = getattr(d, "str", "")
        if dstr != "=":
            return None
        rhs = getattr(d, "astOperand2", None)
        return self._match_affine(rhs, biv_ids, loop, invariant_tids)

    def _match_affine(self, tok: Optional[Token], biv_ids: Set[int],
                      loop: NaturalLoop,
                      invariant_tids: Set[Any]) -> Optional[Tuple[int, int, int]]:
        """Try to match tok as  a*biv+b  or  biv*a+b  etc."""
        if tok is None:
            return None
        s = getattr(tok, "str", "")
        vid = getattr(tok, "varId", None)

        # Direct BIV reference: j = i  →  coeff=1, offset=0
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
        # Variable not defined in loop
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
        """Extract a compile-time integer constant from tok or its ValueFlow."""
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
    lower: Optional[int] = None   # minimum iterations (None = unknown)
    upper: Optional[int] = None   # maximum iterations (None = unknown)
    exact: Optional[int] = None   # exact count if deterministic
    confidence: str = "possible"  # "certain" | "probable" | "possible"
    description: str = ""


class LoopBoundAnalysis:
    """
    Estimate loop iteration bounds using induction variables,
    loop conditions, and ValueFlow data.

    Strategy:
    1. For each loop with a BIV:
       - Find the loop exit condition (comparison involving the BIV).
       - Extract the bound from the comparison operand.
       - Compute iterations = (bound - init) / step.
    2. Fall back to ValueFlow on the condition token.
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

    def _analyse_loop(self, loop: NaturalLoop):
        bivs = []
        if self.iv_analysis:
            bivs = self.iv_analysis.basic_ivs(loop.header)

        node_map = {_nid(n): n for n in _all_nodes(self.cfg)}
        header_node = node_map.get(loop.header)
        if header_node is None:
            return

        # The loop condition is typically the last comparison in
        # the header block or the first exit edge's source block.
        cond_tok = self._find_condition_token(header_node, loop, node_map)
        if cond_tok is None:
            # Try ValueFlow fallback
            self._valueflow_bound(loop, node_map)
            return

        for biv in bivs:
            bound = self._bound_from_condition(biv, cond_tok, loop)
            if bound is not None:
                self._bounds.append(bound)
                return

        # Fallback
        self._valueflow_bound(loop, node_map)

    def _find_condition_token(self, header_node: CfgNode,
                              loop: NaturalLoop,
                              node_map: Dict) -> Optional[Token]:
        """Find the comparison token that controls loop exit."""
        # Check header tokens
        for tok in reversed(_node_tokens(header_node)):
            s = getattr(tok, "str", "")
            if s in ("<", ">", "<=", ">=", "!=", "=="):
                return tok
        # Check exit edge sources
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
        """
        Given BIV and condition like  i < N, compute iterations.
        """
        op1 = getattr(cond, "astOperand1", None)
        op2 = getattr(cond, "astOperand2", None)
        if op1 is None or op2 is None:
            return None

        vid1 = getattr(op1, "varId", None)
        vid2 = getattr(op2, "varId", None)
        cmp = getattr(cond, "str", "")

        # Determine which operand is the BIV and which is the bound
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

        # Compute iterations based on comparison operator
        # for i = init; i < bound; i += step → iters = (bound - init) / step
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
        """Find the initial value of a BIV from the preheader or ValueFlow."""
        # Check preheader tokens
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
        return 0  # Common default

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

    def _valueflow_bound(self, loop: NaturalLoop,
                         node_map: Dict):
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
    """
    A single branch condition along a path.
    Represented as (token_id_of_condition, branch_taken: bool).
    """
    condition_token_id: Any
    branch_taken: bool
    text: str = ""


@dataclass
class PathState:
    """
    Abstract state along a specific execution path.

    Combines path conditions (which branches were taken) with
    a variable state map (variable valuations / abstract values).
    """
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

    Instead of merging abstract states at join points (like classical
    dataflow analysis), this tracks **separate** states per path
    through the CFG.  Each distinct path is characterised by the
    sequence of branch decisions taken.

    To prevent exponential blow-up, the analysis enforces:
      - **k-limiting**: at most *k* paths per CFG node (default 32).
      - **loop unrolling budget**: each loop back-edge is followed
        at most *max_unroll* times per path (default 2).
      - **path merging heuristic**: paths with identical variable
        states are merged even if their conditions differ.

    Parameters
    ----------
    cfg             : the control-flow graph
    configuration   : cppcheckdata.Configuration (for ValueFlow)
    k_limit         : maximum number of path states per node
    max_unroll      : maximum loop back-edge traversals per path

    After .run():
        .states_at(node_id) → List[PathState]
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

        # back-edge counter per (path_id, node_id)
        back_count: Dict[Tuple[int, Any], int] = defaultdict(int)

        # BFS worklist
        worklist: Deque[Any] = deque([entry_id])
        visited_iterations: Dict[Any, int] = defaultdict(int)
        max_iterations = len(node_map) * self.k_limit * 4  # safety bound
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
                        # Determine branch condition
                        cond_tok = self._branch_condition(node)
                        branch_taken = (si == 0)  # Convention: 0=true, 1=false
                        cond = PathCondition(
                            condition_token_id=_get_tok_id(cond_tok) if cond_tok else nid,
                            branch_taken=branch_taken,
                            text=getattr(cond_tok, "str", "") if cond_tok else "",
                        )
                        new_ps = ps.with_condition(cond)
                        # Check feasibility
                        new_ps = self._check_feasibility(new_ps, cond_tok,
                                                         branch_taken)
                    else:
                        new_ps = ps

                    # Check back-edge budget
                    if self.domtree.dominates(sid, nid):
                        key = (new_ps.path_id, sid)
                        if back_count[key] >= self.max_unroll:
                            continue
                        back_count[key] += 1

                    # Update variable state from tokens in current node
                    new_ps = self._apply_node_effects(new_ps, node)
                    new_states.append(new_ps)

                # Merge with existing states at successor, enforce k-limit
                existing = self._states.get(sid, [])
                merged = self._merge_states(existing, new_states)
                if merged != existing:
                    self._states[sid] = merged[:self.k_limit]
                    visited_iterations[sid] += 1
                    if visited_iterations[sid] < self.k_limit * 2:
                        worklist.append(sid)

    def _branch_condition(self, node: CfgNode) -> Optional[Token]:
        """Find the condition token for a branch node."""
        tokens = _node_tokens(node)
        for tok in reversed(tokens):
            s = getattr(tok, "str", "")
            if s in ("<", ">", "<=", ">=", "==", "!=", "&&", "||", "!"):
                return tok
            if getattr(tok, "isName", False) and not getattr(tok, "isOp", False):
                # Could be a boolean variable as condition
                parent = getattr(tok, "astParent", None)
                if parent and getattr(parent, "str", "") in ("if", "while", "?"):
                    return tok
        return None

    def _check_feasibility(self, ps: PathState, cond_tok: Optional[Token],
                           branch_taken: bool) -> PathState:
        """Use ValueFlow to check if this branch is feasible."""
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
                    # This path is infeasible
                    return PathState(
                        conditions=ps.conditions,
                        var_state=ps.var_state,
                        feasible=False,
                    )
        return ps

    def _apply_node_effects(self, ps: PathState,
                            node: CfgNode) -> PathState:
        """Update path state based on assignments in the node."""
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

    def _evaluate(self, tok: Optional[Token],
                  ps: PathState) -> Any:
        """Best-effort evaluation of a token in the context of a path state."""
        if tok is None:
            return None
        # Constant
        if getattr(tok, "isNumber", False):
            try:
                return int(getattr(tok, "str", "0"))
            except (ValueError, TypeError):
                return None
        # Variable with known value
        vid = getattr(tok, "varId", None)
        if vid and vid in ps.var_state:
            return ps.var_state[vid]
        # ValueFlow
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
        """Merge incoming states with existing, deduplicating by var_state."""
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
    Determine whether a specific path through the CFG is feasible
    by checking that all branch conditions along the path are
    mutually satisfiable.

    This uses a lightweight constraint-based approach:
    - Each branch condition contributes a constraint on variables.
    - Constraints are checked pairwise and via simple interval reasoning
      (no SMT solver, just ValueFlow + interval propagation).
    """

    def __init__(self, cfg: Cfg,
                 configuration: Optional[Configuration] = None):
        self.cfg = cfg
        self.configuration = configuration

    def is_feasible(self, path_state: PathState) -> bool:
        """Check if the conditions in a PathState are satisfiable."""
        if not path_state.feasible:
            return False
        constraints = self._extract_constraints(path_state)
        return self._check_constraints(constraints)

    def infeasible_reason(self, path_state: PathState) -> Optional[str]:
        """If infeasible, return a human-readable reason."""
        if path_state.feasible:
            constraints = self._extract_constraints(path_state)
            if self._check_constraints(constraints):
                return None
        # Find conflicting conditions
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
        """
        Extract (var_id, op, value) constraints from path conditions.
        E.g. condition x < 5 with branch_taken=True → (var_x, "<", 5).
        """
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
        """Lightweight interval-based constraint checking."""
        # Per-variable: track interval [lo, hi]
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
            elif op == "!=":
                # Weak: can't represent != as interval, skip
                pass
            intervals[vid] = (lo, hi)

        # Check feasibility: lo ≤ hi for all variables
        for vid, (lo, hi) in intervals.items():
            if lo > hi:
                return False
        return True

    def _negate_op(self, op: str) -> Optional[str]:
        neg = {"<": ">=", "<=": ">", ">": "<=", ">=": "<",
               "==": "!=", "!=": "=="}
        return neg.get(op)

    def _find_token_by_id(self, tid: Any,
                          node_map: Dict) -> Optional[Token]:
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
    """A set of branch points that are controlled by the same condition."""
    condition_var_id: int
    branch_node_ids: List[Any]
    description: str = ""


class BranchCorrelationAnalysis:
    """
    Detect correlated branches: multiple branch points in the CFG
    that test the same variable (or the same condition expression).

    Knowing that two branches are correlated allows path-sensitive
    analysis to prune more infeasible paths (e.g., after checking
    ``p != NULL`` on one branch, the other branch testing ``p``
    cannot take the null path).
    """

    def __init__(self, cfg: Cfg):
        self.cfg = cfg
        self._groups: List[CorrelationGroup] = []
        self._computed = False

    def run(self) -> "BranchCorrelationAnalysis":
        if self._computed:
            return self
        cond_map: Dict[int, List[Any]] = defaultdict(list)  # varId → node ids

        for node in _all_nodes(self.cfg):
            succs = _successors(node)
            if len(succs) != 2:
                continue
            # Find condition variable
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
        """Return other branch nodes correlated with *node_id*."""
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
    tokens: List[Any] = field(default_factory=list)  # representative tokens

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

    1. **Structural**: nodes not reachable from entry via forward DFS.
    2. **Path-condition pruning**: nodes reachable only via infeasible
       paths (using PathSensitiveAnalysis + PathFeasibilityChecker).
    3. **Post-dominator**: nodes that unconditionally follow a return/
       exit statement.
    4. **ValueFlow dead branches**: branches whose condition is known
       to always be true or false.

    Returns a list of UnreachableRegion objects.
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
        """Find nodes not reachable from entry."""
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
        """Find branches where the condition is always true or false."""
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
            # If ALL known values agree, one branch is dead
            int_vals = set()
            for v in known:
                iv = getattr(v, "intvalue", None)
                if iv is not None:
                    int_vals.add(int(iv) != 0)
            if len(int_vals) != 1:
                continue
            always_true = int_vals.pop()
            dead_index = 1 if always_true else 0  # dead = not-taken branch
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
        """Find nodes reachable only via infeasible paths."""
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
            # If ALL paths to this node are infeasible, the node is unreachable
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
# Convenience orchestrator
# ===================================================================

def run_all_ctrlflow_analyses(
    cfg: Cfg,
    configuration: Optional[Configuration] = None,
    *,
    analyses: Optional[Set[str]] = None,
    k_limit: int = 32,
    max_unroll: int = 2,
) -> Dict[str, Any]:
    """
    Run all (or selected) control-flow analyses on a CFG.

    Parameters
    ----------
    cfg            : control-flow graph from ctrlflow_graph.py
    configuration  : cppcheckdata.Configuration
    analyses       : set of analysis names to run, or None for all.
                     Valid names: "dominators", "post_dominators", "loops",
                     "loop_invariants", "induction_vars", "loop_bounds",
                     "path_sensitive", "path_feasibility", "correlations",
                     "unreachable"
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
    }
    wanted = analyses if analyses is not None else ALL
    results: Dict[str, Any] = {}

    # Dominators (many others depend on this)
    domtree = None
    if wanted & {"dominators", "loops", "loop_invariants", "induction_vars",
                 "loop_bounds", "path_sensitive", "unreachable"}:
        domtree = DominatorTree(cfg).compute()
        if "dominators" in wanted:
            results["dominators"] = domtree

    # Post-dominators
    if "post_dominators" in wanted:
        pdt = PostDominatorTree(cfg).compute()
        results["post_dominators"] = pdt

    # Loops
    loops: List[NaturalLoop] = []
    if wanted & {"loops", "loop_invariants", "induction_vars", "loop_bounds"}:
        detector = NaturalLoopDetector(cfg, domtree)
        loops = detector.detect()
        if "loops" in wanted:
            results["loops"] = loops

    # Loop invariants
    inv_analysis = None
    if wanted & {"loop_invariants", "induction_vars"}:
        inv_analysis = LoopInvariantAnalysis(cfg, loops, configuration).run()
        if "loop_invariants" in wanted:
            results["loop_invariants"] = inv_analysis

    # Induction variables
    iv_analysis = None
    if wanted & {"induction_vars", "loop_bounds"}:
        iv_analysis = InductionVariableAnalysis(
            cfg, loops, inv_analysis, configuration,
        ).run()
        if "induction_vars" in wanted:
            results["induction_vars"] = iv_analysis

    # Loop bounds
    if "loop_bounds" in wanted:
        lb = LoopBoundAnalysis(cfg, loops, iv_analysis, configuration).run()
        results["loop_bounds"] = lb

    # Path-sensitive
    psa = None
    if wanted & {"path_sensitive", "unreachable"}:
        psa = PathSensitiveAnalysis(
            cfg, configuration, domtree, k_limit, max_unroll,
        ).run()
        if "path_sensitive" in wanted:
            results["path_sensitive"] = psa

    # Path feasibility
    pfc = None
    if wanted & {"path_feasibility", "unreachable"}:
        pfc = PathFeasibilityChecker(cfg, configuration)
        if "path_feasibility" in wanted:
            results["path_feasibility"] = pfc

    # Branch correlations
    if "correlations" in wanted:
        bca = BranchCorrelationAnalysis(cfg).run()
        results["correlations"] = bca

    # Unreachable code
    if "unreachable" in wanted:
        ucd = UnreachableCodeDetector(cfg, configuration, psa, pfc).run()
        results["unreachable"] = ucd

    return results
