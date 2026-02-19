"""
cppcheckdata_shims.controlflow_graph
=====================================

Builds intraprocedural Control Flow Graphs (CFGs) from Cppcheck dump data.

Each function in a Configuration yields one CFG.  A CFG is a directed graph
whose nodes are *basic blocks* (straight-line sequences of tokens) and whose
edges carry control-flow semantics (fall-through, branch-true, branch-false,
back-edge, switch-case, etc.).

Public API
----------
    CFGNode          - a single basic block
    CFGEdge          - a directed edge between two CFGNodes
    CFG              - the control flow graph for one function
    build_cfg        - build a CFG from a cppcheckdata.Function + Configuration
    build_all_cfgs   - build CFGs for every function in a Configuration

Typical usage::

    import cppcheckdata
    from cppcheckdata_shims.controlflow_graph import build_all_cfgs

    data = cppcheckdata.parsedump("foo.c.dump")
    for cfg_config in data.configurations:
        for func, cfg in build_all_cfgs(cfg_config).items():
            print(f"Function {func.name}: {len(cfg.nodes)} blocks, "
                  f"{len(cfg.edges)} edges")
            for node in cfg.nodes:
                print(f"  BB{node.id}: {node.label()}")

Implementation notes
--------------------
* We iterate over the *token stream* inside a function scope (from
  ``scope.bodyStart`` to ``scope.bodyEnd``) and partition it into basic
  blocks.  A new block starts after every branch target and at every
  control-flow merge point.
* The AST attached to each token is **not** restructured; we merely
  reference the existing Token objects from cppcheckdata.
* ``goto`` support is best-effort: we resolve labels that appear inside
  the same function scope.
"""

from __future__ import annotations

import enum
import itertools
from collections import defaultdict, OrderedDict
from dataclasses import dataclass, field
from typing import (
    Dict,
    Iterable,
    Iterator,
    List,
    Optional,
    Sequence,
    Set,
    Tuple,
    Union,
)

# ---------------------------------------------------------------------------
# Edge kinds
# ---------------------------------------------------------------------------


class EdgeKind(enum.Enum):
    """Classification of a CFG edge."""

    FALL_THROUGH = "fall-through"
    BRANCH_TRUE = "branch-true"
    BRANCH_FALSE = "branch-false"
    BACK_EDGE = "back-edge"
    BREAK = "break"
    CONTINUE = "continue"
    RETURN = "return"
    GOTO = "goto"
    SWITCH_CASE = "switch-case"
    SWITCH_DEFAULT = "switch-default"
    EXCEPTION = "exception"
    CALL = "call"            # interprocedural (placeholder)
    CALL_RETURN = "call-return"     # interprocedural (placeholder)


# ---------------------------------------------------------------------------
# CFGNode  –  a basic block
# ---------------------------------------------------------------------------

_next_node_id: int = 0


def _fresh_node_id() -> int:
    global _next_node_id
    nid = _next_node_id
    _next_node_id += 1
    return nid


def reset_node_counter() -> None:
    """Reset the global node-id counter (useful for deterministic tests)."""
    global _next_node_id
    _next_node_id = 0


class CFGNode:
    """A basic block in the CFG.

    Attributes
    ----------
    id : int
        Unique (per-process) numeric identifier.
    tokens : list
        Ordered list of ``cppcheckdata.Token`` objects that belong to this
        block.  May be empty for synthetic entry/exit nodes.
    scope : object or None
        The ``cppcheckdata.Scope`` that *directly* contains this block.
    kind : str
        Human-readable tag: ``"entry"``, ``"exit"``, ``"if-cond"``,
        ``"loop-cond"``, ``"switch-dispatch"``, ``"body"``, …
    successors : list[CFGEdge]
        Outgoing edges.
    predecessors : list[CFGEdge]
        Incoming edges.
    """

    __slots__ = (
        "id",
        "tokens",
        "scope",
        "kind",
        "successors",
        "predecessors",
        "_label_cache",
    )

    def __init__(
        self,
        tokens: Optional[List] = None,
        scope=None,
        kind: str = "body",
    ) -> None:
        self.id: int = _fresh_node_id()
        self.tokens: List = tokens if tokens is not None else []
        self.scope = scope
        self.kind: str = kind
        self.successors: List[CFGEdge] = []
        self.predecessors: List[CFGEdge] = []
        self._label_cache: Optional[str] = None

    # ----- helpers ----------------------------------------------------------

    def label(self) -> str:
        """Return a compact, human-readable label for this block."""
        if self._label_cache is not None:
            return self._label_cache
        if not self.tokens:
            lbl = f"[{self.kind}]"
        else:
            parts = []
            for t in self.tokens[:6]:
                parts.append(t.str)
            s = " ".join(parts)
            if len(self.tokens) > 6:
                s += " …"
            loc = ""
            first = self.tokens[0]
            if first.file and first.linenr:
                loc = f"{first.file}:{first.linenr} "
            lbl = f"{loc}{s}"
        self._label_cache = lbl
        return lbl

    @property
    def first_token(self):
        """First token in the block, or ``None``."""
        return self.tokens[0] if self.tokens else None

    @property
    def last_token(self):
        """Last token in the block, or ``None``."""
        return self.tokens[-1] if self.tokens else None

    @property
    def file(self) -> Optional[str]:
        ft = self.first_token
        return ft.file if ft else None

    @property
    def linenr(self) -> Optional[int]:
        ft = self.first_token
        return ft.linenr if ft else None

    def __repr__(self) -> str:
        return f"CFGNode(id={self.id}, kind={self.kind!r}, ntokens={len(self.tokens)})"

    def __hash__(self) -> int:
        return self.id

    def __eq__(self, other) -> bool:
        if isinstance(other, CFGNode):
            return self.id == other.id
        return NotImplemented


# ---------------------------------------------------------------------------
# CFGEdge
# ---------------------------------------------------------------------------

class CFGEdge:
    """A directed edge in the CFG.

    Attributes
    ----------
    src : CFGNode
    dst : CFGNode
    kind : EdgeKind
    label : str or None
        Optional auxiliary label (e.g. the case constant for SWITCH_CASE).
    """

    __slots__ = ("src", "dst", "kind", "label")

    def __init__(
        self,
        src: CFGNode,
        dst: CFGNode,
        kind: EdgeKind = EdgeKind.FALL_THROUGH,
        label: Optional[str] = None,
    ) -> None:
        self.src = src
        self.dst = dst
        self.kind = kind
        self.label = label

    def __repr__(self) -> str:
        return (
            f"CFGEdge(BB{self.src.id} -> BB{self.dst.id}, "
            f"kind={self.kind.value!r})"
        )

    def __hash__(self) -> int:
        return hash((self.src.id, self.dst.id, self.kind))

    def __eq__(self, other) -> bool:
        if isinstance(other, CFGEdge):
            return (
                self.src.id == other.src.id
                and self.dst.id == other.dst.id
                and self.kind == other.kind
            )
        return NotImplemented


# ---------------------------------------------------------------------------
# CFG
# ---------------------------------------------------------------------------

class CFG:
    """Intraprocedural control flow graph for a single function.

    Attributes
    ----------
    function : cppcheckdata.Function
        The function this CFG represents.
    entry : CFGNode
        Synthetic entry block (no tokens).
    exit : CFGNode
        Synthetic exit block (no tokens).
    nodes : list[CFGNode]
        All basic blocks (including entry and exit).
    edges : list[CFGEdge]
        All edges.
    """

    def __init__(self, function) -> None:
        self.function = function
        self.entry = CFGNode(kind="entry")
        self.exit = CFGNode(kind="exit")
        self.nodes: List[CFGNode] = [self.entry, self.exit]
        self.edges: List[CFGEdge] = []
        # fast lookup helpers
        self._token_to_node: Dict[int, CFGNode] = {}  # token.Id -> node

    # ----- graph mutation ---------------------------------------------------

    def add_node(self, node: CFGNode) -> CFGNode:
        """Register *node* in this CFG and return it."""
        self.nodes.append(node)
        for tok in node.tokens:
            if tok.Id is not None:
                self._token_to_node[tok.Id] = node
        return node

    def add_edge(
        self,
        src: CFGNode,
        dst: CFGNode,
        kind: EdgeKind = EdgeKind.FALL_THROUGH,
        label: Optional[str] = None,
    ) -> CFGEdge:
        """Create an edge, register it, and wire up predecessor/successor lists."""
        e = CFGEdge(src, dst, kind=kind, label=label)
        self.edges.append(e)
        src.successors.append(e)
        dst.predecessors.append(e)
        return e

    # ----- queries ----------------------------------------------------------

    def node_for_token(self, token) -> Optional[CFGNode]:
        """Return the basic block that contains *token*, or ``None``."""
        return self._token_to_node.get(token.Id if hasattr(token, "Id") else token)

    def successors_of(self, node: CFGNode) -> List[CFGNode]:
        return [e.dst for e in node.successors]

    def predecessors_of(self, node: CFGNode) -> List[CFGNode]:
        return [e.src for e in node.predecessors]

    def reachable_from(self, start: CFGNode) -> Set[CFGNode]:
        """Return the set of nodes reachable from *start* (BFS)."""
        visited: Set[CFGNode] = set()
        worklist = [start]
        while worklist:
            n = worklist.pop()
            if n in visited:
                continue
            visited.add(n)
            for e in n.successors:
                worklist.append(e.dst)
        return visited

    def all_paths(
        self,
        src: CFGNode,
        dst: CFGNode,
        max_depth: int = 200,
    ) -> Iterator[List[CFGNode]]:
        """Yield all simple paths from *src* to *dst* (DFS, bounded)."""
        stack: List[Tuple[CFGNode, List[CFGNode], Set[int]]] = [
            (src, [src], {src.id})
        ]
        while stack:
            current, path, visited = stack.pop()
            if current is dst:
                yield list(path)
                continue
            if len(path) >= max_depth:
                continue
            for e in current.successors:
                nxt = e.dst
                if nxt.id not in visited:
                    stack.append((nxt, path + [nxt], visited | {nxt.id}))

    def dominators(self) -> Dict[CFGNode, Set[CFGNode]]:
        """Compute the dominator sets using the iterative algorithm.

        Returns a dict mapping each node to its set of dominators.
        """
        dom: Dict[CFGNode, Set[CFGNode]] = {}
        all_nodes = set(self.nodes)
        dom[self.entry] = {self.entry}
        for n in self.nodes:
            if n is not self.entry:
                dom[n] = set(all_nodes)
        changed = True
        while changed:
            changed = False
            for n in self.nodes:
                if n is self.entry:
                    continue
                preds = self.predecessors_of(n)
                if not preds:
                    new_dom = {n}
                else:
                    new_dom = set.intersection(*(dom[p] for p in preds))
                    new_dom = new_dom | {n}
                if new_dom != dom[n]:
                    dom[n] = new_dom
                    changed = True
        return dom

    def post_dominators(self) -> Dict[CFGNode, Set[CFGNode]]:
        """Compute post-dominator sets (dominators on the reverse graph)."""
        pdom: Dict[CFGNode, Set[CFGNode]] = {}
        all_nodes = set(self.nodes)
        pdom[self.exit] = {self.exit}
        for n in self.nodes:
            if n is not self.exit:
                pdom[n] = set(all_nodes)
        changed = True
        while changed:
            changed = False
            for n in self.nodes:
                if n is self.exit:
                    continue
                succs = self.successors_of(n)
                if not succs:
                    new_pdom = {n}
                else:
                    new_pdom = set.intersection(*(pdom[s] for s in succs))
                    new_pdom = new_pdom | {n}
                if new_pdom != pdom[n]:
                    pdom[n] = new_pdom
                    changed = True
        return pdom

    def back_edges(self) -> List[CFGEdge]:
        """Return edges whose destination dominates their source (loop back-edges)."""
        dom = self.dominators()
        return [e for e in self.edges if e.dst in dom.get(e.src, set())]

    def natural_loops(self) -> Dict[CFGEdge, Set[CFGNode]]:
        """Return a mapping from each back-edge to the set of nodes in
        its natural loop."""
        result: Dict[CFGEdge, Set[CFGNode]] = {}
        for be in self.back_edges():
            loop_nodes: Set[CFGNode] = {be.dst}
            stack = [be.src]
            while stack:
                m = stack.pop()
                if m not in loop_nodes:
                    loop_nodes.add(m)
                    for e in m.predecessors:
                        stack.append(e.src)
            result[be] = loop_nodes
        return result

    # ----- serialisation helpers --------------------------------------------

    def to_dot(self, title: Optional[str] = None) -> str:
        """Return a Graphviz DOT representation of this CFG."""
        lines = ["digraph CFG {"]
        if title:
            lines.append(f'  label="{title}";')
        lines.append("  node [shape=box, fontname=monospace, fontsize=10];")
        for n in self.nodes:
            lbl = n.label().replace('"', '\\"').replace("\n", "\\n")
            color = ""
            if n.kind == "entry":
                color = ', style=filled, fillcolor="#ccffcc"'
            elif n.kind == "exit":
                color = ', style=filled, fillcolor="#ffcccc"'
            lines.append(f'  BB{n.id} [label="BB{n.id}\\n{lbl}"{color}];')
        for e in self.edges:
            style = ""
            elabel = e.kind.value
            if e.label:
                elabel += f": {e.label}"
            if e.kind == EdgeKind.BRANCH_TRUE:
                style = ', color=green, fontcolor=green'
            elif e.kind == EdgeKind.BRANCH_FALSE:
                style = ', color=red, fontcolor=red'
            elif e.kind == EdgeKind.BACK_EDGE:
                style = ', style=dashed, color=blue, fontcolor=blue'
            elif e.kind in (EdgeKind.BREAK, EdgeKind.CONTINUE):
                style = ', style=dotted'
            lines.append(
                f'  BB{e.src.id} -> BB{e.dst.id} '
                f'[label="{elabel}"{style}];'
            )
        lines.append("}")
        return "\n".join(lines)

    def __repr__(self) -> str:
        fname = self.function.name if self.function else "<unknown>"
        return (
            f"CFG(function={fname!r}, nodes={len(self.nodes)}, "
            f"edges={len(self.edges)})"
        )


# ===========================================================================
# CFG BUILDER
# ===========================================================================

class _TokenStream:
    """Thin wrapper giving indexed + peek access over a token range."""

    def __init__(self, start_tok, end_tok) -> None:
        self._tokens: List = []
        tok = start_tok
        while tok and tok != end_tok:
            self._tokens.append(tok)
            tok = tok.next
        if end_tok is not None:
            self._tokens.append(end_tok)
        self._pos: int = 0

    def at_end(self) -> bool:
        return self._pos >= len(self._tokens)

    def current(self):
        if self._pos < len(self._tokens):
            return self._tokens[self._pos]
        return None

    def peek(self, offset: int = 1):
        idx = self._pos + offset
        if 0 <= idx < len(self._tokens):
            return self._tokens[idx]
        return None

    def advance(self, n: int = 1):
        self._pos += n

    def position(self) -> int:
        return self._pos

    def set_position(self, pos: int) -> None:
        self._pos = pos

    def remaining(self) -> List:
        return self._tokens[self._pos:]

    def __len__(self) -> int:
        return len(self._tokens)


def _tok_str(tok) -> str:
    """Safely get the string of a token."""
    if tok is None:
        return ""
    return tok.str if tok.str else ""


def _find_matching_brace(tok):
    """Given a '{' token, return its matching '}' via the .link attribute."""
    if tok and tok.str == "{" and tok.link:
        return tok.link
    return None


class _CFGBuilder:
    """Internal builder that constructs a CFG for a single function.

    The algorithm is a single forward pass over the token stream inside
    the function body.  We maintain a *current block* and cut it whenever
    we encounter a control-flow keyword.  We use an explicit context stack
    to handle nesting (``if``/``else``, ``while``, ``for``, ``do``,
    ``switch``/``case``).
    """

    def __init__(self, function, scope, cfg_config) -> None:
        self.function = function
        self.scope = scope        # the Function scope
        self.cfg_config = cfg_config
        self.cfg = CFG(function)
        # label -> CFGNode (for goto)
        self._labels: Dict[str, CFGNode] = {}
        # deferred goto -> label name
        self._pending_gotos: List[Tuple[CFGNode, str]] = []

    # ----- helpers ----------------------------------------------------------

    def _new_block(self, kind: str = "body", scope=None) -> CFGNode:
        node = CFGNode(kind=kind, scope=scope or self.scope)
        self.cfg.add_node(node)
        return node

    def _edge(self, src, dst, kind=EdgeKind.FALL_THROUGH, label=None):
        return self.cfg.add_edge(src, dst, kind=kind, label=label)

    # ----- token scanning helpers -------------------------------------------

    @staticmethod
    def _skip_to_token(tok, target_str: str, limit_tok=None):
        """Advance *tok* until tok.str == target_str or limit_tok is reached."""
        while tok and tok != limit_tok:
            if tok.str == target_str:
                return tok
            tok = tok.next
        return None

    @staticmethod
    def _collect_tokens_until(tok, stop_strs: Set[str], limit_tok=None) -> Tuple[List, Optional]:
        """Collect tokens from *tok* until one of *stop_strs* is found.
        Returns (collected, stop_token_or_None)."""
        collected = []
        while tok and tok != limit_tok:
            if tok.str in stop_strs:
                return collected, tok
            collected.append(tok)
            tok = tok.next
        return collected, None

    @staticmethod
    def _skip_past_semicolon(tok, limit_tok=None):
        """Advance past the next ';'. Returns the token *after* the ';'."""
        while tok and tok != limit_tok:
            if tok.str == ";":
                return tok.next
            # Skip nested braces etc. via link
            if tok.str in ("(", "[", "{") and tok.link:
                tok = tok.link
            tok = tok.next
        return None

    @staticmethod
    def _skip_parenthesised(tok):
        """If *tok* is '(', return the token after the matching ')'.
        Otherwise return *tok* unchanged."""
        if tok and tok.str == "(" and tok.link:
            return tok.link.next
        return tok

    # ----- main build -------------------------------------------------------

    def build(self) -> CFG:
        """Build and return the CFG."""
        body_start = self.scope.bodyStart   # the '{' token
        body_end = self.scope.bodyEnd       # the '}' token

        if body_start is None or body_end is None:
            # Forward declaration or something odd – return trivial CFG
            self._edge(self.cfg.entry, self.cfg.exit)
            return self.cfg

        # First real block
        first_block = self._new_block(kind="body")
        self._edge(self.cfg.entry, first_block)

        # Recursively process the compound statement
        after_block = self._process_compound(
            body_start.next,   # first token inside '{'
            body_end,          # limit: the '}'
            first_block,
            break_target=None,
            continue_target=None,
        )

        # Connect whatever remains to exit
        if after_block is not None:
            self._edge(after_block, self.cfg.exit, EdgeKind.FALL_THROUGH)

        # Resolve pending gotos
        for goto_block, lbl_name in self._pending_gotos:
            target = self._labels.get(lbl_name)
            if target:
                self._edge(goto_block, target, EdgeKind.GOTO)
            else:
                # Unresolved – connect to exit as a safe fallback
                self._edge(goto_block, self.cfg.exit, EdgeKind.GOTO)

        return self.cfg

    def _process_compound(
        self,
        tok,
        limit_tok,
        current_block: CFGNode,
        break_target: Optional[CFGNode],
        continue_target: Optional[CFGNode],
    ) -> Optional[CFGNode]:
        """Process a sequence of statements between *tok* and *limit_tok*.

        Returns the block that is "live" after this compound, or ``None``
        if all paths explicitly left (return/goto/break/continue).
        """
        while tok and tok != limit_tok:
            s = _tok_str(tok)

            # ---- labels (goto targets) ------------------------------------
            if (
                tok.isName
                and tok.next
                and tok.next.str == ":"
                and not (tok.next.next and tok.next.next.str == ":")  # not ::
                and s not in ("case", "default")
            ):
                # This is a label like "label_name:"
                label_block = self._new_block(
                    kind="label", scope=tok.scope if hasattr(tok, 'scope') else None)
                if current_block is not None:
                    self._edge(current_block, label_block)
                self._labels[s] = label_block
                current_block = label_block
                tok = tok.next.next  # skip "label" ":"
                continue

            # ---- return ----------------------------------------------------
            if s == "return":
                # Collect tokens until ';'
                ret_toks, semi = self._collect_tokens_until(
                    tok, {";"}, limit_tok)
                if current_block is not None:
                    current_block.tokens.extend(ret_toks)
                    if semi:
                        current_block.tokens.append(semi)
                    current_block.kind = "return"
                    self._edge(current_block, self.cfg.exit, EdgeKind.RETURN)
                tok = semi.next if semi else None
                current_block = None  # dead code until next label / merge
                continue

            # ---- break -----------------------------------------------------
            if s == "break":
                if current_block is not None:
                    current_block.tokens.append(tok)
                    if break_target:
                        self._edge(current_block, break_target, EdgeKind.BREAK)
                    else:
                        # No break target? Shouldn't happen, but be safe
                        self._edge(current_block, self.cfg.exit,
                                   EdgeKind.BREAK)
                tok = self._skip_past_semicolon(tok.next, limit_tok)
                current_block = None
                continue

            # ---- continue --------------------------------------------------
            if s == "continue":
                if current_block is not None:
                    current_block.tokens.append(tok)
                    if continue_target:
                        self._edge(current_block, continue_target,
                                   EdgeKind.CONTINUE)
                    else:
                        self._edge(current_block, self.cfg.exit,
                                   EdgeKind.CONTINUE)
                tok = self._skip_past_semicolon(tok.next, limit_tok)
                current_block = None
                continue

            # ---- goto ------------------------------------------------------
            if s == "goto":
                label_tok = tok.next
                if current_block is not None:
                    current_block.tokens.append(tok)
                    if label_tok:
                        current_block.tokens.append(label_tok)
                    lbl_name = _tok_str(label_tok)
                    self._pending_gotos.append((current_block, lbl_name))
                tok = self._skip_past_semicolon(
                    tok.next, limit_tok) if tok.next else None
                current_block = None
                continue

            # ---- if / else -------------------------------------------------
            if s == "if":
                tok, current_block = self._process_if(
                    tok, limit_tok, current_block, break_target, continue_target
                )
                continue

            # ---- while -----------------------------------------------------
            if s == "while":
                tok, current_block = self._process_while(
                    tok, limit_tok, current_block, break_target, continue_target
                )
                continue

            # ---- for -------------------------------------------------------
            if s == "for":
                tok, current_block = self._process_for(
                    tok, limit_tok, current_block, break_target, continue_target
                )
                continue

            # ---- do ... while ----------------------------------------------
            if s == "do":
                tok, current_block = self._process_do_while(
                    tok, limit_tok, current_block, break_target, continue_target
                )
                continue

            # ---- switch ----------------------------------------------------
            if s == "switch":
                tok, current_block = self._process_switch(
                    tok, limit_tok, current_block, break_target, continue_target
                )
                continue

            # ---- nested brace block '{' ... '}' ----------------------------
            if s == "{":
                inner_end = _find_matching_brace(tok)
                if inner_end:
                    current_block = self._process_compound(
                        tok.next, inner_end, current_block,
                        break_target, continue_target,
                    )
                    tok = inner_end.next
                    continue
                # Fallthrough if link not found (shouldn't happen)

            # ---- ordinary statement token ----------------------------------
            if current_block is None:
                # Dead code after return/break/etc., but a new statement
                # starts (unreachable).  Create a block anyway for completeness.
                current_block = self._new_block(kind="unreachable")

            current_block.tokens.append(tok)

            # If we just consumed a ';', the *next* statement could start a
            # new leader.  We don't forcibly cut here to keep straight-line
            # sequences in a single block, but we *do* cut before control-flow
            # keywords (handled at the top of the loop).

            tok = tok.next

        return current_block

    # -----------------------------------------------------------------------
    # if / else
    # -----------------------------------------------------------------------

    def _process_if(self, tok, limit_tok, current_block, break_target, continue_target):
        """Handle ``if (...) { ... } [else { ... }]``.

        Returns (next_tok, live_block_or_None).
        """
        # tok is 'if'
        if_tok = tok
        tok = tok.next  # should be '('

        # --- condition -------------------------------------------------------
        cond_block = self._new_block(kind="if-cond")
        if current_block is not None:
            self._edge(current_block, cond_block)

        # Collect condition tokens inside '(' ... ')'
        if tok and tok.str == "(":
            rparen = tok.link
            cond_inner = tok.next
            while cond_inner and cond_inner != rparen:
                cond_block.tokens.append(cond_inner)
                cond_inner = cond_inner.next
            tok = rparen.next if rparen else tok.next
        # If there was no paren (malformed), just skip
        if tok is None:
            return None, None

        # --- true branch -----------------------------------------------------
        true_block = self._new_block(kind="if-true")
        self._edge(cond_block, true_block, EdgeKind.BRANCH_TRUE)

        if tok.str == "{":
            inner_end = _find_matching_brace(tok)
            if inner_end:
                true_exit = self._process_compound(
                    tok.next, inner_end, true_block, break_target, continue_target,
                )
                tok = inner_end.next
            else:
                true_exit = true_block
                tok = tok.next
        else:
            # Single-statement body (no braces)
            true_exit = self._process_compound(
                tok, limit_tok, true_block, break_target, continue_target,
            )
            # We consumed until ';' inside _process_compound – we need the
            # token after the semicolon.  Because _process_compound advances
            # past it, we rely on the returned block and walk from the last
            # token.
            if true_exit and true_exit.tokens:
                last = true_exit.tokens[-1]
                tok = last.next
                # If the last token was ';', we're fine. Otherwise try to
                # advance past ';'.
                if last.str != ";":
                    tok = self._skip_past_semicolon(last, limit_tok)
            else:
                tok = None

        # --- else branch? ----------------------------------------------------
        false_block: Optional[CFGNode] = None
        false_exit: Optional[CFGNode] = None

        if tok and _tok_str(tok) == "else":
            tok = tok.next  # skip 'else'
            false_block = self._new_block(kind="if-false")
            self._edge(cond_block, false_block, EdgeKind.BRANCH_FALSE)

            # Check for 'else if'
            if tok and _tok_str(tok) == "if":
                # Recurse — this will handle the nested if-else chain
                tok, false_exit = self._process_if(
                    tok, limit_tok, false_block, break_target, continue_target
                )
            elif tok and tok.str == "{":
                inner_end = _find_matching_brace(tok)
                if inner_end:
                    false_exit = self._process_compound(
                        tok.next, inner_end, false_block, break_target, continue_target,
                    )
                    tok = inner_end.next
                else:
                    false_exit = false_block
                    tok = tok.next
            else:
                # Single statement else
                false_exit = self._process_compound(
                    tok, limit_tok, false_block, break_target, continue_target,
                )
                if false_exit and false_exit.tokens:
                    last = false_exit.tokens[-1]
                    tok = last.next
                    if last.str != ";":
                        tok = self._skip_past_semicolon(last, limit_tok)
                else:
                    tok = None
        else:
            # No else — the false edge goes straight to the merge point
            pass

        # --- merge -----------------------------------------------------------
        merge = self._new_block(kind="if-merge")

        if false_block is None:
            # No else: false edge from condition to merge
            self._edge(cond_block, merge, EdgeKind.BRANCH_FALSE)

        if true_exit is not None:
            self._edge(true_exit, merge)
        if false_exit is not None:
            self._edge(false_exit, merge)

        # If both branches terminated (return/break/…), the merge block is
        # unreachable, but we still create it for structural completeness.
        if true_exit is None and false_exit is None:
            return tok, None
        return tok, merge

    # -----------------------------------------------------------------------
    # while
    # -----------------------------------------------------------------------

    def _process_while(self, tok, limit_tok, current_block, break_target, continue_target):
        """Handle ``while (...) { ... }``."""
        tok = tok.next  # skip 'while', now at '('

        cond_block = self._new_block(kind="loop-cond")
        if current_block is not None:
            self._edge(current_block, cond_block)

        # Condition
        if tok and tok.str == "(":
            rparen = tok.link
            inner = tok.next
            while inner and inner != rparen:
                cond_block.tokens.append(inner)
                inner = inner.next
            tok = rparen.next if rparen else tok.next

        after_loop = self._new_block(kind="while-after")

        # Body
        body_block = self._new_block(kind="loop-body")
        self._edge(cond_block, body_block, EdgeKind.BRANCH_TRUE)
        self._edge(cond_block, after_loop, EdgeKind.BRANCH_FALSE)

        if tok and tok.str == "{":
            inner_end = _find_matching_brace(tok)
            if inner_end:
                body_exit = self._process_compound(
                    tok.next, inner_end, body_block,
                    break_target=after_loop,
                    continue_target=cond_block,
                )
                tok = inner_end.next
            else:
                body_exit = body_block
                tok = tok.next
        else:
            body_exit = self._process_compound(
                tok, limit_tok, body_block,
                break_target=after_loop,
                continue_target=cond_block,
            )
            if body_exit and body_exit.tokens:
                last = body_exit.tokens[-1]
                tok = last.next
                if last.str != ";":
                    tok = self._skip_past_semicolon(last, limit_tok)
            else:
                tok = None

        if body_exit is not None:
            self._edge(body_exit, cond_block, EdgeKind.BACK_EDGE)

        return tok, after_loop

    # -----------------------------------------------------------------------
    # for
    # -----------------------------------------------------------------------

    def _process_for(self, tok, limit_tok, current_block, break_target, continue_target):
        """Handle ``for (init; cond; incr) { ... }``."""
        tok = tok.next  # skip 'for', now at '('

        if not tok or tok.str != "(":
            return tok, current_block

        rparen = tok.link
        tok = tok.next  # first token inside '('

        # --- init ------------------------------------------------------------
        init_block = self._new_block(kind="for-init")
        if current_block is not None:
            self._edge(current_block, init_block)

        while tok and tok != rparen and tok.str != ";":
            init_block.tokens.append(tok)
            tok = tok.next
        if tok and tok.str == ";":
            tok = tok.next  # skip ';'

        # --- cond ------------------------------------------------------------
        cond_block = self._new_block(kind="loop-cond")
        self._edge(init_block, cond_block)

        while tok and tok != rparen and tok.str != ";":
            cond_block.tokens.append(tok)
            tok = tok.next
        if tok and tok.str == ";":
            tok = tok.next  # skip ';'

        # --- incr (collect but don't attach yet) ----------------------------
        incr_tokens = []
        while tok and tok != rparen:
            incr_tokens.append(tok)
            tok = tok.next
        # skip past ')'
        if rparen:
            tok = rparen.next

        after_loop = self._new_block(kind="for-after")
        incr_block = self._new_block(kind="for-incr")
        incr_block.tokens = incr_tokens

        self._edge(cond_block, after_loop, EdgeKind.BRANCH_FALSE)

        # --- body ------------------------------------------------------------
        body_block = self._new_block(kind="loop-body")
        self._edge(cond_block, body_block, EdgeKind.BRANCH_TRUE)

        if tok and tok.str == "{":
            inner_end = _find_matching_brace(tok)
            if inner_end:
                body_exit = self._process_compound(
                    tok.next, inner_end, body_block,
                    break_target=after_loop,
                    continue_target=incr_block,
                )
                tok = inner_end.next
            else:
                body_exit = body_block
                tok = tok.next
        else:
            body_exit = self._process_compound(
                tok, limit_tok, body_block,
                break_target=after_loop,
                continue_target=incr_block,
            )
            if body_exit and body_exit.tokens:
                last = body_exit.tokens[-1]
                tok = last.next
                if last.str != ";":
                    tok = self._skip_past_semicolon(last, limit_tok)
            else:
                tok = None

        if body_exit is not None:
            self._edge(body_exit, incr_block)
        self._edge(incr_block, cond_block, EdgeKind.BACK_EDGE)

        return tok, after_loop

    # -----------------------------------------------------------------------
    # do ... while
    # -----------------------------------------------------------------------

    def _process_do_while(self, tok, limit_tok, current_block, break_target, continue_target):
        """Handle ``do { ... } while (...);``."""
        tok = tok.next  # skip 'do'

        body_block = self._new_block(kind="loop-body")
        if current_block is not None:
            self._edge(current_block, body_block)

        cond_block = self._new_block(kind="loop-cond")
        after_loop = self._new_block(kind="do-while-after")

        if tok and tok.str == "{":
            inner_end = _find_matching_brace(tok)
            if inner_end:
                body_exit = self._process_compound(
                    tok.next, inner_end, body_block,
                    break_target=after_loop,
                    continue_target=cond_block,
                )
                tok = inner_end.next
            else:
                body_exit = body_block
                tok = tok.next
        else:
            body_exit = self._process_compound(
                tok, limit_tok, body_block,
                break_target=after_loop,
                continue_target=cond_block,
            )
            if body_exit and body_exit.tokens:
                last = body_exit.tokens[-1]
                tok = last.next
            else:
                tok = None

        if body_exit is not None:
            self._edge(body_exit, cond_block)

        # Now expect "while" "(" ... ")" ";"
        if tok and tok.str == "while":
            tok = tok.next
            if tok and tok.str == "(":
                rparen = tok.link
                inner = tok.next
                while inner and inner != rparen:
                    cond_block.tokens.append(inner)
                    inner = inner.next
                tok = rparen.next if rparen else tok.next
            # skip ';'
            if tok and tok.str == ";":
                tok = tok.next

        self._edge(cond_block, body_block, EdgeKind.BACK_EDGE)
        self._edge(cond_block, after_loop, EdgeKind.BRANCH_FALSE)
        # The "true" branch of a do-while condition is the back-edge we already added.
        # Mark it explicitly:
        for e in cond_block.successors:
            if e.dst is body_block:
                e.kind = EdgeKind.BRANCH_TRUE

        return tok, after_loop

    # -----------------------------------------------------------------------
    # switch
    # -----------------------------------------------------------------------

    def _process_switch(self, tok, limit_tok, current_block, break_target, continue_target):
        """Handle ``switch (...) { case ...: ... }``."""
        tok = tok.next  # skip 'switch', now at '('

        dispatch_block = self._new_block(kind="switch-dispatch")
        if current_block is not None:
            self._edge(current_block, dispatch_block)

        # Condition
        if tok and tok.str == "(":
            rparen = tok.link
            inner = tok.next
            while inner and inner != rparen:
                dispatch_block.tokens.append(inner)
                inner = inner.next
            tok = rparen.next if rparen else tok.next

        after_switch = self._new_block(kind="switch-after")

        # Body of switch must be '{' ... '}'
        if not tok or tok.str != "{":
            return tok, after_switch

        switch_body_end = _find_matching_brace(tok)
        tok = tok.next  # first token inside '{'

        # We walk through the switch body, recognizing 'case' and 'default'.
        case_block: Optional[CFGNode] = None
        has_default = False
        prev_case_exit: Optional[CFGNode] = None

        while tok and tok != switch_body_end:
            s = _tok_str(tok)

            if s == "case":
                # New case block
                new_case = self._new_block(kind="case")
                # Collect case label tokens up to ':'
                case_label_parts = []
                tok = tok.next
                while tok and tok.str != ":" and tok != switch_body_end:
                    case_label_parts.append(tok.str)
                    tok = tok.next
                case_label = " ".join(case_label_parts)
                self._edge(dispatch_block, new_case,
                           EdgeKind.SWITCH_CASE, label=case_label)

                # Fall-through from previous case
                if prev_case_exit is not None:
                    self._edge(prev_case_exit, new_case, EdgeKind.FALL_THROUGH)

                case_block = new_case
                if tok and tok.str == ":":
                    tok = tok.next
                continue

            if s == "default":
                new_case = self._new_block(kind="default")
                self._edge(dispatch_block, new_case, EdgeKind.SWITCH_DEFAULT)
                has_default = True
                if prev_case_exit is not None:
                    self._edge(prev_case_exit, new_case, EdgeKind.FALL_THROUGH)
                case_block = new_case
                tok = tok.next  # skip 'default'
                if tok and tok.str == ":":
                    tok = tok.next
                continue

            # Regular statement inside a case
            if case_block is None:
                # Tokens before first case/default (shouldn't happen, but be safe)
                case_block = self._new_block(kind="switch-pre")

            # Check for control-flow keywords
            if s == "break":
                case_block.tokens.append(tok)
                self._edge(case_block, after_switch, EdgeKind.BREAK)
                tok = self._skip_past_semicolon(tok.next, switch_body_end)
                prev_case_exit = None
                case_block = None
                continue

            if s == "return":
                ret_toks, semi = self._collect_tokens_until(
                    tok, {";"}, switch_body_end)
                case_block.tokens.extend(ret_toks)
                if semi:
                    case_block.tokens.append(semi)
                case_block.kind = "return"
                self._edge(case_block, self.cfg.exit, EdgeKind.RETURN)
                tok = semi.next if semi else None
                prev_case_exit = None
                case_block = None
                continue

            if s in ("if", "while", "for", "do", "switch", "{"):
                # Delegate to compound processing
                remaining_exit = self._process_compound(
                    tok, switch_body_end, case_block,
                    break_target=after_switch,
                    continue_target=continue_target,
                )
                # We need to figure out where tok advanced to.
                # The safest way: find the last token added and advance from there.
                if remaining_exit and remaining_exit.tokens:
                    tok = remaining_exit.tokens[-1].next
                else:
                    tok = None
                prev_case_exit = remaining_exit
                case_block = remaining_exit
                continue

            # Ordinary token
            case_block.tokens.append(tok)
            prev_case_exit = case_block
            tok = tok.next

        # If the last case didn't end with break/return, fall through to after
        if prev_case_exit is not None:
            self._edge(prev_case_exit, after_switch)
        if case_block is not None and case_block is not prev_case_exit:
            self._edge(case_block, after_switch)

        # If there's no default, dispatch can fall through to after
        if not has_default:
            self._edge(dispatch_block, after_switch, EdgeKind.FALL_THROUGH)

        tok = switch_body_end.next if switch_body_end else None
        return tok, after_switch


# ===========================================================================
# PUBLIC API
# ===========================================================================

def build_cfg(function, cfg_config) -> Optional[CFG]:
    """Build a :class:`CFG` for a single function.

    Parameters
    ----------
    function : cppcheckdata.Function
        The function object from the dump file.
    cfg_config : cppcheckdata.Configuration
        The configuration that contains *function*.

    Returns
    -------
    CFG or None
        The control flow graph, or ``None`` if the function has no body
        (forward declaration, etc.).
    """
    # Find the Function scope
    scope = None
    for s in cfg_config.scopes:
        if s.type == "Function" and s.function is function:
            scope = s
            break
    # Fallback: try matching through the className
    if scope is None:
        for s in cfg_config.scopes:
            if s.type == "Function" and s.className == function.name:
                if s.functionId == function.Id or s.function is function:
                    scope = s
                    break
    if scope is None:
        return None
    if scope.bodyStart is None or scope.bodyEnd is None:
        return None

    builder = _CFGBuilder(function, scope, cfg_config)
    return builder.build()


def build_all_cfgs(cfg_config) -> OrderedDict:
    """Build CFGs for every function that has a body in *cfg_config*.

    Parameters
    ----------
    cfg_config : cppcheckdata.Configuration
        A configuration from a Cppcheck dump file.

    Returns
    -------
    OrderedDict[cppcheckdata.Function, CFG]
        Mapping from function objects to their CFGs, in the order they
        appear in the dump file.
    """
    result: OrderedDict = OrderedDict()
    for func in cfg_config.functions:
        cfg = build_cfg(func, cfg_config)
        if cfg is not None:
            result[func] = cfg
    return result


# ---------------------------------------------------------------------------
# Convenience: print a summary
# ---------------------------------------------------------------------------

def cfg_summary(cfg: CFG) -> str:
    """Return a multi-line human-readable summary of *cfg*."""
    lines = [repr(cfg)]
    for node in cfg.nodes:
        succ_ids = ", ".join(
            f"BB{e.dst.id}({e.kind.value})" for e in node.successors)
        pred_ids = ", ".join(f"BB{e.src.id}" for e in node.predecessors)
        lines.append(
            f"  BB{node.id} [{node.kind}] "
            f"tokens={len(node.tokens)}  "
            f"succ=[{succ_ids}]  "
            f"pred=[{pred_ids}]"
        )
    return "\n".join(lines)
