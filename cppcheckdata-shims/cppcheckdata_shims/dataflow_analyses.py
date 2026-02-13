"""
cppcheckdata_shims/dataflow_analyses.py
═══════════════════════════════════════

Ready-made dataflow analyses built on ``dataflow_engine.py``.

Provided analyses
─────────────────
  1. ReachingDefinitions     — forward, may (gen/kill)
  2. AvailableExpressions    — forward, must
  3. VeryBusyExpressions     — backward, must
  4. LiveVariables           — backward, may
  5. DefiniteAssignment      — forward, must
  6. DominatorAnalysis       — forward, must (block-level)
  7. ConstantPropagation     — forward, must (flat lattice)
  8. CopyPropagation         — forward, must
  9. PointerAnalysis         — flow-sensitive, Andersen-style points-to
  10. AliasAnalysis          — built on PointerAnalysis + ValueFlow
  11. TaintAnalysis          — forward, may (source/sink/sanitiser)
  12. IntervalAnalysis        — forward, widening-based (numeric bounds)
  13. SignAnalysis            — forward (sign lattice)
  14. NullPointerAnalysis     — forward, tracks null/non-null/unknown

Each analysis consumes a ``cppcheckdata.Configuration`` object (from
``parsedump()``), constructs a simplified CFG internally, and exposes
a clean query API after ``run()``.

Integration with cppcheck's ValueFlow
──────────────────────────────────────
Where possible, analyses consult ``token.values`` (the ``ValueFlow``
list attached to each Token by cppcheck) to:
  - seed initial abstract values (IntervalAnalysis, ConstantPropagation)
  - resolve pointer targets (PointerAnalysis)
  - prune infeasible branches (all forward analyses)

This avoids re-deriving information that cppcheck's C++ engine already
computed, while still allowing the Python-side analysis to go further
(inter-procedural, relational, taint, alias, …).

License: MIT — same as cppcheckdata-shims.
"""

from __future__ import annotations

import math
import itertools
from abc import ABC, abstractmethod
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import (
    Any,
    Callable,
    ClassVar,
    Dict,
    FrozenSet,
    Generic,
    Iterable,
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
)

# ── cppcheckdata types (from deps/cppcheckdata.py) ──────────────────────
# We import these at runtime; type stubs used for annotation.
try:
    from cppcheckdata import (  # type: ignore[import-untyped]
        CppcheckData,
        Configuration,
        Token,
        Scope,
        Variable,
        Function,
        ValueFlow,
    )
except ImportError:
    # Fallback: allow module to load even without cppcheckdata on sys.path
    CppcheckData = Any  # type: ignore[assignment,misc]
    Configuration = Any  # type: ignore[assignment,misc]
    Token = Any  # type: ignore[assignment,misc]
    Scope = Any  # type: ignore[assignment,misc]
    Variable = Any  # type: ignore[assignment,misc]
    Function = Any  # type: ignore[assignment,misc]
    ValueFlow = Any  # type: ignore[assignment,misc]

# ── Our own library imports ──────────────────────────────────────────────
from cppcheckdata_shims.abstract_domains import (
    IntervalDomain,
    SignDomain,
    Sign,
    ConstantDomain,
    FlatDomain,
    BoolDomain,
    FunctionDomain,
    SetDomain,
    make_interval_env,
    make_sign_env,
    make_constant_env,
)


# ═════════════════════════════════════════════════════════════════════════
#  PART 0 — SIMPLIFIED CFG CONSTRUCTION
# ═════════════════════════════════════════════════════════════════════════
#
#  We build a lightweight CFG from cppcheckdata's Scope/Token structure.
#  Each "basic block" is a maximal straight-line sequence of tokens.
#  Edges encode control flow (fall-through, branches, loops, returns).
#
#  This is intentionally simpler than the full ``ctrlflow_graph.py``
#  module (which handles irreducible graphs, exceptions, longjmp, etc.)
#  — the analyses below need only a standard reducible CFG.
# ═════════════════════════════════════════════════════════════════════════

BlockId = int


@dataclass
class BasicBlock:
    """A maximal straight-line sequence of tokens."""

    id: BlockId
    tokens: List[Any]  # List[Token]
    successors: List[BlockId] = field(default_factory=list)
    predecessors: List[BlockId] = field(default_factory=list)
    is_entry: bool = False
    is_exit: bool = False

    @property
    def first_token(self) -> Optional[Any]:
        return self.tokens[0] if self.tokens else None

    @property
    def last_token(self) -> Optional[Any]:
        return self.tokens[-1] if self.tokens else None

    def __repr__(self) -> str:
        loc = ""
        if self.tokens:
            t = self.tokens[0]
            loc = f" @{getattr(t, 'file', '?')}:{getattr(t, 'linenr', '?')}"
        return f"BB{self.id}({len(self.tokens)} tok{loc})"


@dataclass
class SimpleCFG:
    """
    Simplified control-flow graph over a single function scope.

    Attributes
    ----------
    blocks : dict mapping BlockId → BasicBlock
    entry  : BlockId of the function entry block
    exits  : set of BlockIds that are function exit points
    token_to_block : dict mapping Token.Id → BlockId
    """

    blocks: Dict[BlockId, BasicBlock] = field(default_factory=dict)
    entry: BlockId = 0
    exits: Set[BlockId] = field(default_factory=set)
    token_to_block: Dict[str, BlockId] = field(default_factory=dict)

    @property
    def reverse_postorder(self) -> List[BlockId]:
        """Compute reverse post-order traversal (good for forward analyses)."""
        visited: Set[BlockId] = set()
        order: List[BlockId] = []

        def _dfs(bid: BlockId) -> None:
            if bid in visited:
                return
            visited.add(bid)
            for succ in self.blocks[bid].successors:
                _dfs(succ)
            order.append(bid)

        _dfs(self.entry)
        order.reverse()
        return order

    @property
    def postorder(self) -> List[BlockId]:
        """Post-order traversal (good for backward analyses)."""
        visited: Set[BlockId] = set()
        order: List[BlockId] = []

        def _dfs(bid: BlockId) -> None:
            if bid in visited:
                return
            visited.add(bid)
            for succ in self.blocks[bid].successors:
                _dfs(succ)
            order.append(bid)

        _dfs(self.entry)
        return order


def _is_branch_token(tok: Any) -> bool:
    """Check if a token is a control-flow branching construct."""
    s = getattr(tok, "str", "")
    return s in {"if", "while", "for", "do", "switch", "goto", "?"}


def _is_return_token(tok: Any) -> bool:
    s = getattr(tok, "str", "")
    return s in {"return", "throw"}


def build_cfg(cfg: Any, scope: Optional[Any] = None) -> SimpleCFG:
    """
    Build a SimpleCFG from a cppcheckdata Configuration.

    Parameters
    ----------
    cfg : cppcheckdata.Configuration
        The dump configuration to analyse.
    scope : cppcheckdata.Scope, optional
        If given, build CFG only for this scope (function body).
        If None, use the first function scope found.

    Returns
    -------
    SimpleCFG
    """
    # ── Locate the target scope ──────────────────────────────────────
    if scope is None:
        for s in getattr(cfg, "scopes", []):
            if getattr(s, "type", "") == "Function":
                scope = s
                break
    if scope is None:
        # Fallback: treat the entire tokenlist as one block
        result = SimpleCFG()
        bb = BasicBlock(id=0, tokens=list(getattr(cfg, "tokenlist", [])),
                        is_entry=True, is_exit=True)
        result.blocks[0] = bb
        result.entry = 0
        result.exits = {0}
        for tok in bb.tokens:
            tid = getattr(tok, "Id", id(tok))
            result.token_to_block[tid] = 0
        return result

    # ── Collect tokens belonging to this scope ───────────────────────
    scope_tokens: List[Any] = []
    body_start = getattr(scope, "bodyStart", None)
    body_end = getattr(scope, "bodyEnd", None)
    if body_start and body_end:
        tok = getattr(body_start, "next", None)
        while tok and tok != body_end:
            scope_tokens.append(tok)
            tok = getattr(tok, "next", None)
    else:
        # Fallback to tokenlist filtered by scope
        for tok in getattr(cfg, "tokenlist", []):
            if getattr(tok, "scope", None) == scope:
                scope_tokens.append(tok)

    if not scope_tokens:
        result = SimpleCFG()
        bb = BasicBlock(id=0, tokens=[], is_entry=True, is_exit=True)
        result.blocks[0] = bb
        result.entry = 0
        result.exits = {0}
        return result

    # ── Partition into basic blocks ──────────────────────────────────
    # We split at: (1) branch tokens, (2) targets of branches (labels),
    # (3) ';' after return/throw, (4) '{' / '}' scope boundaries.
    result = SimpleCFG()
    current_id = 0
    current_tokens: List[Any] = []

    def _flush(is_exit: bool = False) -> None:
        nonlocal current_id, current_tokens
        if current_tokens:
            bb = BasicBlock(
                id=current_id,
                tokens=list(current_tokens),
                is_entry=(current_id == 0),
                is_exit=is_exit,
            )
            result.blocks[current_id] = bb
            for t in current_tokens:
                tid = getattr(t, "Id", id(t))
                result.token_to_block[tid] = current_id
            current_id += 1
            current_tokens = []

    for tok in scope_tokens:
        s = getattr(tok, "str", "")

        # Split BEFORE branch keywords (they start a new block)
        if _is_branch_token(tok) and current_tokens:
            _flush()

        current_tokens.append(tok)

        # Split AFTER: semicolons, '{', '}', returns
        if s == ";":
            is_ret = any(
                _is_return_token(t) for t in current_tokens
            )
            _flush(is_exit=is_ret)
        elif s in {"{", "}"}:
            _flush()

    _flush(is_exit=True)  # last block is an exit

    # ── Wire edges (conservative: sequential fall-through) ───────────
    # For a more precise CFG, we'd parse if/else/while structure.
    # Here we do sequential + branch-target edges.
    block_ids = sorted(result.blocks.keys())
    for i, bid in enumerate(block_ids):
        bb = result.blocks[bid]

        # Check if this block ends with a return/throw → no fall-through
        has_return = any(_is_return_token(t) for t in bb.tokens)
        has_branch = any(_is_branch_token(t) for t in bb.tokens)

        if has_return:
            bb.is_exit = True
            # No successor (function exits)
        elif i + 1 < len(block_ids):
            next_bid = block_ids[i + 1]
            bb.successors.append(next_bid)
            result.blocks[next_bid].predecessors.append(bid)

        # For branches (if/while/for), also add an edge to the block
        # after the matching '}' (the false/exit branch).  We use
        # token linking to find it.
        if has_branch:
            for tok in bb.tokens:
                if _is_branch_token(tok):
                    # The linked '(' has a link to ')'; the next token
                    # after ')' starts the true-branch body.
                    # The false branch starts after the matching '}'.
                    _add_branch_edges(result, bid, tok, block_ids)

    result.entry = block_ids[0] if block_ids else 0
    result.exits = {bid for bid, bb in result.blocks.items() if bb.is_exit}

    return result


def _add_branch_edges(
    cfg_graph: SimpleCFG, bid: BlockId, branch_tok: Any, block_ids: List[BlockId]
) -> None:
    """
    Attempt to add branch edges for if/while/for tokens.

    Uses cppcheckdata's token.link to find matching braces.
    """
    # Find the '(' following the branch keyword
    next_tok = getattr(branch_tok, "next", None)
    if next_tok is None or getattr(next_tok, "str", "") != "(":
        return
    # Find matching ')'
    close_paren = getattr(next_tok, "link", None)
    if close_paren is None:
        return
    # The token after ')' should be '{' (true branch body)
    true_start = getattr(close_paren, "next", None)
    if true_start is None:
        return
    # Find the block containing the true-branch start
    true_tid = getattr(true_start, "Id", id(true_start))
    if true_tid in cfg_graph.token_to_block:
        true_bid = cfg_graph.token_to_block[true_tid]
        bb = cfg_graph.blocks[bid]
        if true_bid not in bb.successors:
            bb.successors.append(true_bid)
            cfg_graph.blocks[true_bid].predecessors.append(bid)
    # If true_start is '{', find its matching '}' for the false branch
    if getattr(true_start, "str", "") == "{":
        close_brace = getattr(true_start, "link", None)
        if close_brace:
            false_start = getattr(close_brace, "next", None)
            if false_start:
                false_tid = getattr(false_start, "Id", id(false_start))
                if false_tid in cfg_graph.token_to_block:
                    false_bid = cfg_graph.token_to_block[false_tid]
                    bb = cfg_graph.blocks[bid]
                    if false_bid not in bb.successors:
                        bb.successors.append(false_bid)
                        cfg_graph.blocks[false_bid].predecessors.append(bid)


# ═════════════════════════════════════════════════════════════════════════
#  PART 1 — VALUEFLOW INTEGRATION UTILITIES
# ═════════════════════════════════════════════════════════════════════════
#
#  cppcheck's ValueFlow annotates tokens with possible runtime values.
#  Each token.values is a list of ValueFlow objects with attributes:
#
#    intvalue     : int     — known integer value
#    tokvalue     : Token   — value is same as another token
#    floatValue   : str     — floating point value
#    condition     : Token   — value is conditional on this token
#    valueKind    : str     — "known" or "possible"
#    inconclusive : bool
#    lifetimeKind : str     — "Object", "SubObject", "Lambda", "Iterator"
#    lifetimeScope: str     — "Local", "Argument", "SubFunction"
#    path         : int     — execution path id
#
#  We mine this aggressively to seed our abstract domains.
# ═════════════════════════════════════════════════════════════════════════

def _valueflow_int_range(tok: Any) -> Optional[IntervalDomain]:
    """
    Extract an interval from a token's ValueFlow annotations.

    Combines all known/possible integer values into a single interval.
    Returns None if no integer ValueFlow data is available.
    """
    values = getattr(tok, "values", None)
    if not values:
        return None
    lo = math.inf
    hi = -math.inf
    found = False
    for v in values:
        iv = getattr(v, "intvalue", None)
        if iv is not None:
            lo = min(lo, iv)
            hi = max(hi, iv)
            found = True
    if not found:
        return None
    return IntervalDomain(float(lo), float(hi))


def _valueflow_known_int(tok: Any) -> Optional[int]:
    """
    Extract a single known integer value from ValueFlow.

    Returns the value only if there is exactly one 'known' value.
    """
    values = getattr(tok, "values", None)
    if not values:
        return None
    known = [
        v for v in values
        if getattr(v, "valueKind", "") == "known"
        and getattr(v, "intvalue", None) is not None
    ]
    if len(known) == 1:
        return known[0].intvalue
    return None


def _valueflow_is_null_possible(tok: Any) -> Optional[bool]:
    """Check if ValueFlow says this pointer could be null."""
    values = getattr(tok, "values", None)
    if not values:
        return None
    for v in values:
        iv = getattr(v, "intvalue", None)
        if iv is not None and iv == 0:
            return True
    return False


def _valueflow_lifetime_targets(tok: Any) -> List[Any]:
    """
    Extract tokens that this token's lifetime points to.

    Uses ValueFlow's tokvalue (alias/pointer tracking).
    """
    values = getattr(tok, "values", None)
    if not values:
        return []
    targets = []
    for v in values:
        tv = getattr(v, "tokvalue", None)
        if tv is not None:
            targets.append(tv)
    return targets


# ═════════════════════════════════════════════════════════════════════════
#  PART 2 — ABSTRACT ANALYSIS BASE CLASS
# ═════════════════════════════════════════════════════════════════════════

class Direction(Enum):
    FORWARD = auto()
    BACKWARD = auto()


class MeetOrJoin(Enum):
    JOIN = auto()  # may analysis: ⊔ (union-like)
    MEET = auto()  # must analysis: ⊓ (intersection-like)


L = TypeVar("L")  # Lattice element type


class DataflowAnalysis(ABC, Generic[L]):
    """
    Abstract base for all dataflow analyses.

    Subclasses implement:
      - ``direction``      — FORWARD or BACKWARD
      - ``confluence``      — JOIN (may) or MEET (must)
      - ``init_entry()``    — lattice value at entry/exit boundary
      - ``init_interior()`` — lattice value at all other points
      - ``transfer(block, in_val)`` — block transfer function
      - ``leq(a, b)``      — partial order on lattice

    The base class provides:
      - ``run()``           — chaotic iteration to fixpoint
      - ``in_state(bid)``   — lattice value at block entry
      - ``out_state(bid)``  — lattice value at block exit
    """

    def __init__(self, configuration: Any, scope: Optional[Any] = None) -> None:
        self.configuration = configuration
        self.scope = scope
        self.cfg: SimpleCFG = build_cfg(configuration, scope)
        self._in: Dict[BlockId, L] = {}
        self._out: Dict[BlockId, L] = {}
        self._converged = False

    # ── Subclass contract ────────────────────────────────────────────

    @property
    @abstractmethod
    def direction(self) -> Direction:
        ...

    @property
    @abstractmethod
    def confluence(self) -> MeetOrJoin:
        ...

    @abstractmethod
    def init_entry(self) -> L:
        """Initial lattice value at the entry (forward) or exit (backward)."""
        ...

    @abstractmethod
    def init_interior(self) -> L:
        """Initial lattice value at all non-boundary blocks."""
        ...

    @abstractmethod
    def transfer(self, block: BasicBlock, in_val: L) -> L:
        """Transfer function:  out = f(in)  for a single block."""
        ...

    @abstractmethod
    def lattice_leq(self, a: L, b: L) -> bool:
        """Partial order:  a ⊑ b."""
        ...

    @abstractmethod
    def lattice_combine(self, a: L, b: L) -> L:
        """Combine two lattice values (join for may, meet for must)."""
        ...

    # ── Fixpoint engine ──────────────────────────────────────────────

    def run(self, max_iterations: int = 1000) -> int:
        """
        Run chaotic iteration to fixpoint.

        Returns the number of iterations taken.

        Raises RuntimeError if max_iterations exceeded.
        """
        blocks = self.cfg.blocks

        # Initialise
        if self.direction == Direction.FORWARD:
            for bid in blocks:
                bb = blocks[bid]
                if bb.is_entry:
                    self._in[bid] = self.init_entry()
                else:
                    self._in[bid] = self.init_interior()
                self._out[bid] = self.transfer(bb, self._in[bid])
            worklist = deque(self.cfg.reverse_postorder)
        else:
            for bid in blocks:
                bb = blocks[bid]
                if bb.is_exit:
                    self._out[bid] = self.init_entry()
                else:
                    self._out[bid] = self.init_interior()
                self._in[bid] = self.transfer(bb, self._out[bid])
            worklist = deque(self.cfg.postorder)

        seen: Set[BlockId] = set(worklist)
        iteration = 0

        while worklist and iteration < max_iterations:
            iteration += 1
            bid = worklist.popleft()
            seen.discard(bid)
            bb = blocks[bid]

            if self.direction == Direction.FORWARD:
                # Combine from predecessors
                preds = bb.predecessors
                if preds:
                    combined = self._out[preds[0]]
                    for p in preds[1:]:
                        combined = self.lattice_combine(combined, self._out[p])
                    if bb.is_entry:
                        combined = self.lattice_combine(
                            combined, self.init_entry()
                        )
                    new_in = combined
                else:
                    new_in = self.init_entry() if bb.is_entry else self.init_interior()

                new_out = self.transfer(bb, new_in)
                self._in[bid] = new_in

                if not self.lattice_leq(new_out, self._out[bid]):
                    self._out[bid] = new_out
                    for succ in bb.successors:
                        if succ not in seen:
                            worklist.append(succ)
                            seen.add(succ)
                else:
                    self._out[bid] = new_out

            else:  # BACKWARD
                succs = bb.successors
                if succs:
                    combined = self._in[succs[0]]
                    for s in succs[1:]:
                        combined = self.lattice_combine(combined, self._in[s])
                    if bb.is_exit:
                        combined = self.lattice_combine(
                            combined, self.init_entry()
                        )
                    new_out = combined
                else:
                    new_out = self.init_entry() if bb.is_exit else self.init_interior()

                new_in = self.transfer(bb, new_out)
                self._out[bid] = new_out

                if not self.lattice_leq(new_in, self._in[bid]):
                    self._in[bid] = new_in
                    for pred in bb.predecessors:
                        if pred not in seen:
                            worklist.append(pred)
                            seen.add(pred)
                else:
                    self._in[bid] = new_in

        if iteration >= max_iterations and worklist:
            raise RuntimeError(
                f"Dataflow analysis did not converge in {max_iterations} iterations"
            )

        self._converged = True
        return iteration

    # ── Query API ────────────────────────────────────────────────────

    def in_state(self, bid: BlockId) -> L:
        """Lattice value at the entry of block ``bid``."""
        return self._in[bid]

    def out_state(self, bid: BlockId) -> L:
        """Lattice value at the exit of block ``bid``."""
        return self._out[bid]

    def state_at_token(self, tok: Any) -> L:
        """
        Compute the lattice value just BEFORE the given token.

        Walks the block's tokens from the beginning, applying transfers
        one token at a time, to get the precise intra-block state.
        """
        tid = getattr(tok, "Id", id(tok))
        if tid not in self.cfg.token_to_block:
            raise ValueError(f"Token {tok} not found in CFG")
        bid = self.cfg.token_to_block[tid]
        bb = self.cfg.blocks[bid]
        state = self._in[bid]
        for t in bb.tokens:
            if getattr(t, "Id", id(t)) == tid:
                return state
            state = self._transfer_single_token(t, state)
        return state  # token was last in block

    def _transfer_single_token(self, tok: Any, state: L) -> L:
        """
        Single-token micro-transfer.  Default: return state unchanged.
        Subclasses override for token-level precision.
        """
        return state


# ═════════════════════════════════════════════════════════════════════════
#  PART 3 — DEFINITION / EXPRESSION IDENTIFIERS
# ═════════════════════════════════════════════════════════════════════════
#
#  Common data structures used by multiple analyses.
# ═════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class Definition:
    """
    A program point where a variable is defined (assigned).

    Attributes
    ----------
    var_id   : int   — cppcheck varId
    var_name : str   — human-readable name
    token_id : str   — Id of the assignment token
    file     : str
    line     : int
    column   : int
    block_id : BlockId
    """
    var_id: int
    var_name: str
    token_id: str
    file: str = ""
    line: int = 0
    column: int = 0
    block_id: BlockId = -1

    def __repr__(self) -> str:
        return f"Def({self.var_name}@{self.file}:{self.line})"


@dataclass(frozen=True)
class Expression:
    """
    An AST expression identified by cppcheck's exprId.

    For Available/Very-Busy expression analyses.
    """
    expr_id: int
    text: str  # reconstructed expression text
    token_id: str  # Id of the root AST token
    used_var_ids: FrozenSet[int] = frozenset()

    def __repr__(self) -> str:
        return f"Expr({self.text})"


def _reconstruct_expr_text(tok: Any) -> str:
    """Reconstruct expression text from AST node (simplified)."""
    if tok is None:
        return ""
    op1 = getattr(tok, "astOperand1", None)
    op2 = getattr(tok, "astOperand2", None)
    s = getattr(tok, "str", "?")
    if op1 is None and op2 is None:
        return s
    left = _reconstruct_expr_text(op1)
    right = _reconstruct_expr_text(op2)
    if op1 and op2:
        return f"({left} {s} {right})"
    if op1:
        return f"({s} {left})"
    return f"({s} {right})"


def _collect_var_ids_in_expr(tok: Any) -> FrozenSet[int]:
    """Collect all varIds referenced in an expression subtree."""
    result: Set[int] = set()

    def _walk(t: Any) -> None:
        if t is None:
            return
        vid = getattr(t, "varId", None)
        if vid and vid != 0:
            result.add(vid)
        _walk(getattr(t, "astOperand1", None))
        _walk(getattr(t, "astOperand2", None))

    _walk(tok)
    return frozenset(result)


# ═════════════════════════════════════════════════════════════════════════
#  PART 4 — SCANNING HELPERS
# ═════════════════════════════════════════════════════════════════════════
#
#  Scan a block for definitions, uses, expressions.
# ═════════════════════════════════════════════════════════════════════════

def _scan_definitions_in_block(
    block: BasicBlock,
) -> Tuple[Set[Definition], Set[int]]:
    """
    Scan a block for variable definitions (assignments).

    Returns (gen_set, kill_var_ids).
    """
    gen: Set[Definition] = set()
    kill_var_ids: Set[int] = set()

    for tok in block.tokens:
        # Assignment: tok.isAssignmentOp and has astOperand1 with varId
        if getattr(tok, "isAssignmentOp", False):
            lhs = getattr(tok, "astOperand1", None)
            if lhs is not None:
                vid = getattr(lhs, "varId", None)
                if vid and vid != 0:
                    d = Definition(
                        var_id=vid,
                        var_name=getattr(lhs, "str", f"v{vid}"),
                        token_id=getattr(tok, "Id", ""),
                        file=getattr(tok, "file", ""),
                        line=getattr(tok, "linenr", 0),
                        column=getattr(tok, "column", 0),
                        block_id=block.id,
                    )
                    gen.add(d)
                    kill_var_ids.add(vid)

        # Variable declaration with initialiser:  int x = ...;
        # In cppcheck dumps, this appears as an '=' with isSplittedVarDeclEq
        if getattr(tok, "isSplittedVarDeclEq", False) or (
            getattr(tok, "str", "") == "=" and getattr(tok, "variable", None)
        ):
            lhs = getattr(tok, "astOperand1", None)
            if lhs is not None:
                vid = getattr(lhs, "varId", None)
                if vid and vid != 0:
                    d = Definition(
                        var_id=vid,
                        var_name=getattr(lhs, "str", f"v{vid}"),
                        token_id=getattr(tok, "Id", ""),
                        file=getattr(tok, "file", ""),
                        line=getattr(tok, "linenr", 0),
                        column=getattr(tok, "column", 0),
                        block_id=block.id,
                    )
                    gen.add(d)
                    kill_var_ids.add(vid)

    return gen, kill_var_ids


def _scan_uses_in_block(block: BasicBlock) -> Set[int]:
    """Scan a block for variable uses (varIds that are read)."""
    uses: Set[int] = set()
    for tok in block.tokens:
        vid = getattr(tok, "varId", None)
        if vid and vid != 0 and getattr(tok, "isName", False):
            # Exclude pure LHS of assignments
            parent = getattr(tok, "astParent", None)
            if parent and getattr(parent, "isAssignmentOp", False):
                lhs = getattr(parent, "astOperand1", None)
                if lhs is tok:
                    continue  # this is a def, not a use
            uses.add(vid)
    return uses


def _scan_expressions_in_block(
    block: BasicBlock,
) -> Tuple[Set[Expression], Set[int]]:
    """
    Scan for non-trivial expressions and killed variable ids.

    An expression is "generated" if it is computed in this block.
    An expression is "killed" if any of its operand variables is
    redefined in this block.
    """
    gen: Set[Expression] = set()
    killed_var_ids: Set[int] = set()

    for tok in block.tokens:
        # Assignment kills
        if getattr(tok, "isAssignmentOp", False):
            lhs = getattr(tok, "astOperand1", None)
            if lhs:
                vid = getattr(lhs, "varId", None)
                if vid and vid != 0:
                    killed_var_ids.add(vid)

        # Arithmetic / comparison expressions
        if getattr(tok, "isArithmeticalOp", False) or getattr(
            tok, "isComparisonOp", False
        ):
            eid = getattr(tok, "exprId", None)
            if eid and eid != 0:
                text = _reconstruct_expr_text(tok)
                var_ids = _collect_var_ids_in_expr(tok)
                expr = Expression(
                    expr_id=eid,
                    text=text,
                    token_id=getattr(tok, "Id", ""),
                    used_var_ids=var_ids,
                )
                gen.add(expr)

    return gen, killed_var_ids


# ═════════════════════════════════════════════════════════════════════════
#  PART 5 — REACHING DEFINITIONS ANALYSIS
# ═════════════════════════════════════════════════════════════════════════
#
#  Direction:   FORWARD
#  Confluence:  JOIN (may / union)
#  Lattice:     ℘(Definition)  — sets of definitions
#  Transfer:    out(B) = gen(B) ∪ (in(B) \ kill(B))
#
#  "Which definitions of variable x can reach program point p?"
# ═════════════════════════════════════════════════════════════════════════

class ReachingDefinitions(DataflowAnalysis[FrozenSet[Definition]]):
    """
    Classic reaching definitions analysis.

    After ``run()``, use:
      - ``reaching_at(token)`` → set of Definition reaching that point
      - ``reaching_var(var_id, token)`` → defs of that specific variable
    """

    def __init__(self, configuration: Any, scope: Optional[Any] = None) -> None:
        super().__init__(configuration, scope)
        # Pre-compute gen/kill per block
        self._gen: Dict[BlockId, Set[Definition]] = {}
        self._kill_vars: Dict[BlockId, Set[int]] = {}
        self._all_defs: Set[Definition] = set()
        for bid, bb in self.cfg.blocks.items():
            g, k = _scan_definitions_in_block(bb)
            self._gen[bid] = g
            self._kill_vars[bid] = k
            self._all_defs |= g

    @property
    def direction(self) -> Direction:
        return Direction.FORWARD

    @property
    def confluence(self) -> MeetOrJoin:
        return MeetOrJoin.JOIN

    def init_entry(self) -> FrozenSet[Definition]:
        return frozenset()

    def init_interior(self) -> FrozenSet[Definition]:
        return frozenset()

    def transfer(
        self, block: BasicBlock, in_val: FrozenSet[Definition]
    ) -> FrozenSet[Definition]:
        bid = block.id
        gen = self._gen.get(bid, set())
        kill_vars = self._kill_vars.get(bid, set())
        # Kill: remove all defs whose var_id is redefined in this block
        surviving = frozenset(d for d in in_val if d.var_id not in kill_vars)
        return surviving | frozenset(gen)

    def lattice_leq(
        self, a: FrozenSet[Definition], b: FrozenSet[Definition]
    ) -> bool:
        return a <= b

    def lattice_combine(
        self, a: FrozenSet[Definition], b: FrozenSet[Definition]
    ) -> FrozenSet[Definition]:
        return a | b

    # ── Query API ────────────────────────────────────────────────────

    def reaching_at(self, tok: Any) -> FrozenSet[Definition]:
        """All definitions reaching just before ``tok``."""
        return self.state_at_token(tok)

    def reaching_var(self, var_id: int, tok: Any) -> FrozenSet[Definition]:
        """Definitions of ``var_id`` reaching just before ``tok``."""
        return frozenset(d for d in self.reaching_at(tok) if d.var_id == var_id)

    def _transfer_single_token(
        self, tok: Any, state: FrozenSet[Definition]
    ) -> FrozenSet[Definition]:
        """Intra-block: process one assignment token."""
        if getattr(tok, "isAssignmentOp", False):
            lhs = getattr(tok, "astOperand1", None)
            if lhs:
                vid = getattr(lhs, "varId", None)
                if vid and vid != 0:
                    new_def = Definition(
                        var_id=vid,
                        var_name=getattr(lhs, "str", f"v{vid}"),
                        token_id=getattr(tok, "Id", ""),
                        file=getattr(tok, "file", ""),
                        line=getattr(tok, "linenr", 0),
                        column=getattr(tok, "column", 0),
                        block_id=self.cfg.token_to_block.get(
                            getattr(tok, "Id", ""), -1
                        ),
                    )
                    state = frozenset(
                        d for d in state if d.var_id != vid
                    ) | frozenset({new_def})
        return state

    @property
    def all_definitions(self) -> FrozenSet[Definition]:
        return frozenset(self._all_defs)


# ═════════════════════════════════════════════════════════════════════════
#  PART 6 — AVAILABLE EXPRESSIONS ANALYSIS
# ═════════════════════════════════════════════════════════════════════════
#
#  Direction:   FORWARD
#  Confluence:  MEET (must / intersection)
#  Lattice:     ℘(Expression)  — sets of expressions
#  Transfer:    out(B) = gen(B) ∪ (in(B) \ kill(B))
#
#  "Which expressions are guaranteed to have been computed (and not
#   invalidated) on every path reaching program point p?"
#
#  Application: common subexpression elimination (CSE).
# ═════════════════════════════════════════════════════════════════════════

class AvailableExpressions(DataflowAnalysis[FrozenSet[Expression]]):
    """
    Available expressions analysis for common subexpression elimination.

    After ``run()``, use:
      - ``available_at(token)`` → set of Expression available at that point
    """

    def __init__(self, configuration: Any, scope: Optional[Any] = None) -> None:
        super().__init__(configuration, scope)
        self._gen: Dict[BlockId, Set[Expression]] = {}
        self._kill_vars: Dict[BlockId, Set[int]] = {}
        self._universe: Set[Expression] = set()
        for bid, bb in self.cfg.blocks.items():
            g, k = _scan_expressions_in_block(bb)
            self._gen[bid] = g
            self._kill_vars[bid] = k
            self._universe |= g

    @property
    def direction(self) -> Direction:
        return Direction.FORWARD

    @property
    def confluence(self) -> MeetOrJoin:
        return MeetOrJoin.MEET

    def init_entry(self) -> FrozenSet[Expression]:
        return frozenset()  # No expressions available at entry

    def init_interior(self) -> FrozenSet[Expression]:
        return frozenset(self._universe)  # Must analysis: start with ⊤ = all

    def transfer(
        self, block: BasicBlock, in_val: FrozenSet[Expression]
    ) -> FrozenSet[Expression]:
        bid = block.id
        gen = self._gen.get(bid, set())
        kill_vars = self._kill_vars.get(bid, set())
        # Kill expressions that use any redefined variable
        surviving = frozenset(
            e for e in in_val if not (e.used_var_ids & kill_vars)
        )
        return surviving | frozenset(gen)

    def lattice_leq(
        self, a: FrozenSet[Expression], b: FrozenSet[Expression]
    ) -> bool:
        # Must analysis with intersection: a ⊑ b iff b ⊆ a
        # (more expressions available = lower in lattice)
        return b <= a

    def lattice_combine(
        self, a: FrozenSet[Expression], b: FrozenSet[Expression]
    ) -> FrozenSet[Expression]:
        return a & b  # intersection (must)

    def available_at(self, tok: Any) -> FrozenSet[Expression]:
        return self.state_at_token(tok)


# ═════════════════════════════════════════════════════════════════════════
#  PART 7 — VERY BUSY EXPRESSIONS ANALYSIS
# ═════════════════════════════════════════════════════════════════════════
#
#  Direction:   BACKWARD
#  Confluence:  MEET (must / intersection)
#  Lattice:     ℘(Expression)
#  Transfer:    in(B) = gen(B) ∪ (out(B) \ kill(B))
#
#  "Which expressions will definitely be evaluated on every path from
#   program point p before any of their operands are redefined?"
#
#  Application: code hoisting.
# ═════════════════════════════════════════════════════════════════════════

class VeryBusyExpressions(DataflowAnalysis[FrozenSet[Expression]]):
    """
    Very busy expressions analysis for code hoisting.
    """

    def __init__(self, configuration: Any, scope: Optional[Any] = None) -> None:
        super().__init__(configuration, scope)
        self._gen: Dict[BlockId, Set[Expression]] = {}
        self._kill_vars: Dict[BlockId, Set[int]] = {}
        self._universe: Set[Expression] = set()
        for bid, bb in self.cfg.blocks.items():
            g, k = _scan_expressions_in_block(bb)
            self._gen[bid] = g
            self._kill_vars[bid] = k
            self._universe |= g

    @property
    def direction(self) -> Direction:
        return Direction.BACKWARD

    @property
    def confluence(self) -> MeetOrJoin:
        return MeetOrJoin.MEET

    def init_entry(self) -> FrozenSet[Expression]:
        return frozenset()  # Nothing busy at program exit

    def init_interior(self) -> FrozenSet[Expression]:
        return frozenset(self._universe)  # Must analysis: ⊤ = all

    def transfer(
        self, block: BasicBlock, in_val: FrozenSet[Expression]
    ) -> FrozenSet[Expression]:
        """For backward: in_val is actually the out-value of the block."""
        bid = block.id
        gen = self._gen.get(bid, set())
        kill_vars = self._kill_vars.get(bid, set())
        surviving = frozenset(
            e for e in in_val if not (e.used_var_ids & kill_vars)
        )
        return surviving | frozenset(gen)

    def lattice_leq(
        self, a: FrozenSet[Expression], b: FrozenSet[Expression]
    ) -> bool:
        return b <= a  # must: more is lower

    def lattice_combine(
        self, a: FrozenSet[Expression], b: FrozenSet[Expression]
    ) -> FrozenSet[Expression]:
        return a & b

    def very_busy_at(self, tok: Any) -> FrozenSet[Expression]:
        return self.state_at_token(tok)


# ═════════════════════════════════════════════════════════════════════════
#  PART 8 — LIVE VARIABLES ANALYSIS
# ═════════════════════════════════════════════════════════════════════════
#
#  Direction:   BACKWARD
#  Confluence:  JOIN (may / union)
#  Lattice:     ℘(VarId)
#  Transfer:    in(B) = use(B) ∪ (out(B) \ def(B))
#
#  "Is variable x potentially read along some path from point p
#   before being redefined?"
#
#  Application: dead code elimination, register allocation.
# ═════════════════════════════════════════════════════════════════════════

class LiveVariables(DataflowAnalysis[FrozenSet[int]]):
    """
    Live variable analysis.

    After ``run()``, use:
      - ``live_at(token)`` → set of var_ids live at that point
      - ``is_live(var_id, token)`` → bool
      - ``dead_definitions()`` → definitions whose LHS is never live
    """

    def __init__(self, configuration: Any, scope: Optional[Any] = None) -> None:
        super().__init__(configuration, scope)
        self._use: Dict[BlockId, Set[int]] = {}
        self._def: Dict[BlockId, Set[int]] = {}
        for bid, bb in self.cfg.blocks.items():
            self._use[bid] = _scan_uses_in_block(bb)
            defs, _ = _scan_definitions_in_block(bb)
            self._def[bid] = {d.var_id for d in defs}

    @property
    def direction(self) -> Direction:
        return Direction.BACKWARD

    @property
    def confluence(self) -> MeetOrJoin:
        return MeetOrJoin.JOIN

    def init_entry(self) -> FrozenSet[int]:
        return frozenset()

    def init_interior(self) -> FrozenSet[int]:
        return frozenset()

    def transfer(
        self, block: BasicBlock, in_val: FrozenSet[int]
    ) -> FrozenSet[int]:
        """in_val here is the out-value (backward analysis)."""
        bid = block.id
        use = self._use.get(bid, set())
        defs = self._def.get(bid, set())
        return frozenset(use) | (in_val - frozenset(defs))

    def lattice_leq(
        self, a: FrozenSet[int], b: FrozenSet[int]
    ) -> bool:
        return a <= b

    def lattice_combine(
        self, a: FrozenSet[int], b: FrozenSet[int]
    ) -> FrozenSet[int]:
        return a | b

    def live_at(self, tok: Any) -> FrozenSet[int]:
        return self.state_at_token(tok)

    def is_live(self, var_id: int, tok: Any) -> bool:
        return var_id in self.live_at(tok)

    def dead_definitions(self) -> List[Definition]:
        """
        Find definitions where the assigned variable is not live
        immediately after the assignment.  These are dead stores.
        """
        dead: List[Definition] = []
        for bid, bb in self.cfg.blocks.items():
            out_live = self._out.get(bid, frozenset())
            defs, _ = _scan_definitions_in_block(bb)
            for d in defs:
                if d.var_id not in out_live:
                    dead.append(d)
        return dead


# ═════════════════════════════════════════════════════════════════════════
#  PART 9 — DEFINITE ASSIGNMENT ANALYSIS
# ═════════════════════════════════════════════════════════════════════════
#
#  Direction:   FORWARD
#  Confluence:  MEET (must / intersection)
#  Lattice:     ℘(VarId)  — variables definitely assigned
#  Transfer:    out(B) = def(B) ∪ in(B)
#
#  "Is variable x guaranteed to have been assigned a value on every
#   path from program entry to point p?"
#
#  Application: detecting use of uninitialised variables.
# ═════════════════════════════════════════════════════════════════════════

class DefiniteAssignment(DataflowAnalysis[FrozenSet[int]]):
    """
    Definite assignment analysis.

    After ``run()``, use:
      - ``is_definitely_assigned(var_id, token)`` → bool
      - ``uninitialised_uses()`` → list of (var_id, token) pairs
    """

    def __init__(self, configuration: Any, scope: Optional[Any] = None) -> None:
        super().__init__(configuration, scope)
        self._def: Dict[BlockId, Set[int]] = {}
        self._all_vars: Set[int] = set()
        for bid, bb in self.cfg.blocks.items():
            defs, _ = _scan_definitions_in_block(bb)
            self._def[bid] = {d.var_id for d in defs}
            self._all_vars |= self._def[bid]
            self._all_vars |= _scan_uses_in_block(bb)

    @property
    def direction(self) -> Direction:
        return Direction.FORWARD

    @property
    def confluence(self) -> MeetOrJoin:
        return MeetOrJoin.MEET

    def init_entry(self) -> FrozenSet[int]:
        # At function entry, parameters are considered assigned.
        assigned: Set[int] = set()
        if self.scope:
            func = getattr(self.scope, "function", None)
            if func:
                for arg in getattr(func, "argument", {}).values():
                    vid = getattr(arg, "Id", None)
                    if vid:
                        assigned.add(int(vid))
        return frozenset(assigned)

    def init_interior(self) -> FrozenSet[int]:
        return frozenset(self._all_vars)  # Must: ⊤ = all vars

    def transfer(
        self, block: BasicBlock, in_val: FrozenSet[int]
    ) -> FrozenSet[int]:
        bid = block.id
        return in_val | frozenset(self._def.get(bid, set()))

    def lattice_leq(
        self, a: FrozenSet[int], b: FrozenSet[int]
    ) -> bool:
        return b <= a  # must: more assigned = lower

    def lattice_combine(
        self, a: FrozenSet[int], b: FrozenSet[int]
    ) -> FrozenSet[int]:
        return a & b

    def is_definitely_assigned(self, var_id: int, tok: Any) -> bool:
        return var_id in self.state_at_token(tok)

    def uninitialised_uses(self) -> List[Tuple[int, Any]]:
        """Find uses of variables that may not have been assigned."""
        results: List[Tuple[int, Any]] = []
        for bid, bb in self.cfg.blocks.items():
            state = self._in.get(bid, frozenset())
            for tok in bb.tokens:
                vid = getattr(tok, "varId", None)
                if vid and vid != 0 and getattr(tok, "isName", False):
                    # Check it's a read, not a write
                    parent = getattr(tok, "astParent", None)
                    is_lhs = (
                        parent
                        and getattr(parent, "isAssignmentOp", False)
                        and getattr(parent, "astOperand1", None) is tok
                    )
                    if not is_lhs and vid not in state:
                        results.append((vid, tok))
                # Update state for this token
                if getattr(tok, "isAssignmentOp", False):
                    lhs = getattr(tok, "astOperand1", None)
                    if lhs:
                        lhs_vid = getattr(lhs, "varId", None)
                        if lhs_vid and lhs_vid != 0:
                            state = state | frozenset({lhs_vid})
        return results


# ═════════════════════════════════════════════════════════════════════════
#  PART 10 — DOMINATOR ANALYSIS
# ═════════════════════════════════════════════════════════════════════════
#
#  Direction:   FORWARD
#  Confluence:  MEET (must / intersection)
#  Lattice:     ℘(BlockId)  — set of dominating blocks
#  Transfer:    out(B) = {B} ∪ in(B)
#
#  Block D dominates block B if every path from entry to B goes through D.
#  Used for: loop detection, SSA construction, code motion legality.
# ═════════════════════════════════════════════════════════════════════════

class DominatorAnalysis(DataflowAnalysis[FrozenSet[BlockId]]):
    """
    Block-level dominator analysis.

    After ``run()``, use:
      - ``dominators(bid)`` → set of BlockIds that dominate bid
      - ``immediate_dominator(bid)`` → the closest dominator
      - ``dominance_frontier(bid)`` → dominance frontier set
    """

    @property
    def direction(self) -> Direction:
        return Direction.FORWARD

    @property
    def confluence(self) -> MeetOrJoin:
        return MeetOrJoin.MEET

    def init_entry(self) -> FrozenSet[BlockId]:
        return frozenset({self.cfg.entry})

    def init_interior(self) -> FrozenSet[BlockId]:
        return frozenset(self.cfg.blocks.keys())  # ⊤ = all blocks

    def transfer(
        self, block: BasicBlock, in_val: FrozenSet[BlockId]
    ) -> FrozenSet[BlockId]:
        return in_val | frozenset({block.id})

    def lattice_leq(
        self, a: FrozenSet[BlockId], b: FrozenSet[BlockId]
    ) -> bool:
        return b <= a  # must: more dominators = lower

    def lattice_combine(
        self, a: FrozenSet[BlockId], b: FrozenSet[BlockId]
    ) -> FrozenSet[BlockId]:
        return a & b

    def dominators(self, bid: BlockId) -> FrozenSet[BlockId]:
        """Set of blocks that dominate ``bid``."""
        return self._out.get(bid, frozenset())

    def immediate_dominator(self, bid: BlockId) -> Optional[BlockId]:
        """
        The immediate dominator of ``bid`` (closest strict dominator).
        Returns None for the entry block.
        """
        doms = self.dominators(bid) - {bid}
        if not doms:
            return None
        # idom is the dominator that is dominated by all other dominators
        for candidate in doms:
            candidate_doms = self.dominators(candidate) - {candidate}
            if doms - {candidate} == candidate_doms & doms:
                return candidate
        # Fallback: pick the one with the most dominators (closest to bid)
        return max(doms, key=lambda d: len(self.dominators(d)))

    def dominance_frontier(self, bid: BlockId) -> Set[BlockId]:
        """
        Dominance frontier of block ``bid``:
        blocks where ``bid``'s dominance stops.
        """
        frontier: Set[BlockId] = set()
        for y, bb in self.cfg.blocks.items():
            if y == bid:
                continue
            for pred in bb.predecessors:
                runner = pred
                while runner != self.immediate_dominator(y) and runner is not None:
                    if runner == bid:
                        frontier.add(y)
                        break
                    runner = self.immediate_dominator(runner)
        return frontier


# ═════════════════════════════════════════════════════════════════════════
#  PART 11 — CONSTANT PROPAGATION ANALYSIS
# ═════════════════════════════════════════════════════════════════════════
#
#  Direction:   FORWARD
#  Confluence:  MEET (must — flat lattice meet)
#  Lattice:     VarId → ConstantDomain  (FunctionDomain[ConstantDomain])
#  Transfer:    Process assignments; use ValueFlow to seed known values.
#
#  Application: constant folding, dead branch elimination.
# ═════════════════════════════════════════════════════════════════════════

# Type alias for readability
ConstEnv = FunctionDomain  # FunctionDomain[ConstantDomain]


class ConstantPropagation(DataflowAnalysis[ConstEnv]):
    """
    Intraprocedural constant propagation using the flat (constant) lattice.

    Leverages cppcheck's ValueFlow: if a token has a known integer value,
    we use it directly rather than re-deriving.

    After ``run()``, use:
      - ``constant_at(var_id, token)`` → Optional[int]
      - ``all_constants_at(token)`` → dict var_id → int
    """

    def __init__(self, configuration: Any, scope: Optional[Any] = None) -> None:
        super().__init__(configuration, scope)

    @property
    def direction(self) -> Direction:
        return Direction.FORWARD

    @property
    def confluence(self) -> MeetOrJoin:
        return MeetOrJoin.MEET

    def _make_top_env(self) -> ConstEnv:
        return make_constant_env()

    def init_entry(self) -> ConstEnv:
        # All variables are ⊤ (unknown) at entry
        return self._make_top_env()

    def init_interior(self) -> ConstEnv:
        return self._make_top_env()

    def transfer(self, block: BasicBlock, in_val: ConstEnv) -> ConstEnv:
        state = in_val
        for tok in block.tokens:
            state = self._transfer_single_token(tok, state)
        return state

    def _transfer_single_token(self, tok: Any, state: ConstEnv) -> ConstEnv:
        if getattr(tok, "isAssignmentOp", False):
            lhs = getattr(tok, "astOperand1", None)
            rhs = getattr(tok, "astOperand2", None)
            if lhs:
                vid = getattr(lhs, "varId", None)
                if vid and vid != 0:
                    rhs_val = self._eval_expr(rhs, state)
                    state = state.set(vid, rhs_val)
        return state

    def _eval_expr(self, tok: Any, state: ConstEnv) -> ConstantDomain:
        """Evaluate an expression to a ConstantDomain value."""
        if tok is None:
            return ConstantDomain.top()

        # ── Use ValueFlow first ──────────────────────────────────────
        known = _valueflow_known_int(tok)
        if known is not None:
            return ConstantDomain.lift(known)

        # ── Literal number ───────────────────────────────────────────
        if getattr(tok, "isNumber", False) and getattr(tok, "isInt", False):
            try:
                n = int(getattr(tok, "str", "0"), 0)
                return ConstantDomain.lift(n)
            except (ValueError, TypeError):
                return ConstantDomain.top()

        # ── Variable reference ───────────────────────────────────────
        vid = getattr(tok, "varId", None)
        if vid and vid != 0:
            return state.get(vid)

        # ── Binary arithmetic ────────────────────────────────────────
        if getattr(tok, "isArithmeticalOp", False):
            op1 = getattr(tok, "astOperand1", None)
            op2 = getattr(tok, "astOperand2", None)
            left = self._eval_expr(op1, state)
            right = self._eval_expr(op2, state)
            s = getattr(tok, "str", "")
            if s == "+":
                return left.add(right)
            if s == "-":
                return left.sub(right)
            if s == "*":
                return left.mul(right)
            if s == "/":
                return left.div(right)
            if s == "%":
                return left.mod(right)

        # ── Unary minus ──────────────────────────────────────────────
        s = getattr(tok, "str", "")
        if s == "-" and getattr(tok, "astOperand1", None) and not getattr(
            tok, "astOperand2", None
        ):
            operand = self._eval_expr(getattr(tok, "astOperand1", None), state)
            return operand.negate()

        return ConstantDomain.top()

    def lattice_leq(self, a: ConstEnv, b: ConstEnv) -> bool:
        return a.leq(b)

    def lattice_combine(self, a: ConstEnv, b: ConstEnv) -> ConstEnv:
        return a.meet(b)

    def constant_at(self, var_id: int, tok: Any) -> Optional[int]:
        """Return the constant value of ``var_id`` at ``tok``, or None."""
        state = self.state_at_token(tok)
        val = state.get(var_id)
        return val.concrete_value()

    def all_constants_at(self, tok: Any) -> Dict[int, int]:
        """Return all variables with known constant values at ``tok``."""
        state = self.state_at_token(tok)
        result: Dict[int, int] = {}
        for vid in state.var_ids:
            v = state.get(vid)
            c = v.concrete_value()
            if c is not None:
                result[vid] = c
        return result


# ═════════════════════════════════════════════════════════════════════════
#  PART 12 — COPY PROPAGATION ANALYSIS
# ═════════════════════════════════════════════════════════════════════════
#
#  Direction:   FORWARD
#  Confluence:  MEET (must / intersection)
#  Lattice:     ℘(Copy)  — set of valid copy relationships (x := y)
#  Transfer:    gen(B) = new copies in B
#               kill(B) = copies invalidated by assignments to x or y
#
#  Application: replacing uses of x with y after x := y.
# ═════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class CopyRel:
    """A copy relationship:  dest := src  (both by varId)."""
    dest: int   # varId of LHS
    src: int    # varId of RHS
    token_id: str = ""

    def __repr__(self) -> str:
        return f"Copy(v{self.dest} := v{self.src})"


class CopyPropagation(DataflowAnalysis[FrozenSet[CopyRel]]):
    """
    Copy propagation analysis.

    After ``run()``, use:
      - ``copies_at(token)`` → set of valid CopyRel at that point
      - ``source_of(var_id, token)`` → the original source varId, or None
    """

    def __init__(self, configuration: Any, scope: Optional[Any] = None) -> None:
        super().__init__(configuration, scope)
        self._gen: Dict[BlockId, Set[CopyRel]] = {}
        self._kill_vars: Dict[BlockId, Set[int]] = {}
        self._universe: Set[CopyRel] = set()
        for bid, bb in self.cfg.blocks.items():
            gen, kill = self._scan_copies(bb)
            self._gen[bid] = gen
            self._kill_vars[bid] = kill
            self._universe |= gen

    def _scan_copies(
        self, block: BasicBlock
    ) -> Tuple[Set[CopyRel], Set[int]]:
        gen: Set[CopyRel] = set()
        kill: Set[int] = set()
        for tok in block.tokens:
            if getattr(tok, "isAssignmentOp", False):
                lhs = getattr(tok, "astOperand1", None)
                rhs = getattr(tok, "astOperand2", None)
                if lhs:
                    lhs_vid = getattr(lhs, "varId", None)
                    if lhs_vid and lhs_vid != 0:
                        kill.add(lhs_vid)
                        # Check if RHS is a simple variable (copy)
                        if (
                            rhs
                            and getattr(rhs, "varId", None)
                            and getattr(rhs, "varId", 0) != 0
                            and not getattr(rhs, "astOperand1", None)
                        ):
                            rhs_vid = rhs.varId
                            copy = CopyRel(
                                dest=lhs_vid,
                                src=rhs_vid,
                                token_id=getattr(tok, "Id", ""),
                            )
                            gen.add(copy)
        return gen, kill

    @property
    def direction(self) -> Direction:
        return Direction.FORWARD

    @property
    def confluence(self) -> MeetOrJoin:
        return MeetOrJoin.MEET

    def init_entry(self) -> FrozenSet[CopyRel]:
        return frozenset()

    def init_interior(self) -> FrozenSet[CopyRel]:
        return frozenset(self._universe)  # must: ⊤ = all

    def transfer(
        self, block: BasicBlock, in_val: FrozenSet[CopyRel]
    ) -> FrozenSet[CopyRel]:
        bid = block.id
        kill = self._kill_vars.get(bid, set())
        gen = self._gen.get(bid, set())
        # Kill copies where either dest or src is redefined
        surviving = frozenset(
            c for c in in_val if c.dest not in kill and c.src not in kill
        )
        return surviving | frozenset(gen)

    def lattice_leq(
        self, a: FrozenSet[CopyRel], b: FrozenSet[CopyRel]
    ) -> bool:
        return b <= a  # must: more copies = lower

    def lattice_combine(
        self, a: FrozenSet[CopyRel], b: FrozenSet[CopyRel]
    ) -> FrozenSet[CopyRel]:
        return a & b

    def copies_at(self, tok: Any) -> FrozenSet[CopyRel]:
        return self.state_at_token(tok)

    def source_of(self, var_id: int, tok: Any) -> Optional[int]:
        """Transitively follow copy chain to find the original source."""
        copies = self.copies_at(tok)
        visited: Set[int] = set()
        current = var_id
        while current not in visited:
            visited.add(current)
            src = next((c.src for c in copies if c.dest == current), None)
            if src is None:
                break
            current = src
        return current if current != var_id else None


# ═════════════════════════════════════════════════════════════════════════
#  PART 13 — POINTER / POINTS-TO ANALYSIS
# ═════════════════════════════════════════════════════════════════════════
#
#  A flow-sensitive Andersen-style points-to analysis.
#
#  Direction:   FORWARD
#  Confluence:  JOIN (may / union)
#  Lattice:     VarId → ℘(PointsToTarget)   (function domain of sets)
#
#  Tracks for each pointer variable which objects (represented by
#  allocation site or variable address) it can point to.
#
#  Leverages ValueFlow:
#    - token.values with tokvalue → pointer aliasing
#    - lifetimeKind / lifetimeScope → stack vs heap objects
#
#  Handles:
#    - p = &x          →  pts(p) = {addr(x)}
#    - p = q           →  pts(p) = pts(q)
#    - p = malloc(…)   →  pts(p) = {heap_N}
#    - *p = …          →  weak update to all targets of p
#    - p = NULL        →  pts(p) = {null}
# ═════════════════════════════════════════════════════════════════════════

class TargetKind(Enum):
    STACK_VAR = auto()    # &x  — address of a stack variable
    HEAP_ALLOC = auto()   # malloc/calloc/new
    GLOBAL_VAR = auto()   # address of a global
    NULL = auto()         # null pointer
    UNKNOWN = auto()      # escaped, external, etc.
    STRING_LIT = auto()   # string literal


@dataclass(frozen=True)
class PointsToTarget:
    """
    An abstract location that a pointer can point to.

    Attributes
    ----------
    kind     : TargetKind
    var_id   : optional varId (for STACK_VAR, GLOBAL_VAR)
    alloc_id : optional token Id of the allocation site (HEAP_ALLOC)
    label    : human-readable label
    """
    kind: TargetKind
    var_id: int = 0
    alloc_id: str = ""
    label: str = ""

    def __repr__(self) -> str:
        if self.kind == TargetKind.NULL:
            return "NULL"
        if self.kind == TargetKind.UNKNOWN:
            return "UNKNOWN"
        if self.kind == TargetKind.STACK_VAR:
            return f"&v{self.var_id}"
        if self.kind == TargetKind.HEAP_ALLOC:
            return f"heap@{self.alloc_id[:8]}"
        if self.kind == TargetKind.GLOBAL_VAR:
            return f"&global_v{self.var_id}"
        return self.label or f"target({self.kind.name})"


NULL_TARGET = PointsToTarget(kind=TargetKind.NULL, label="NULL")
UNKNOWN_TARGET = PointsToTarget(kind=TargetKind.UNKNOWN, label="UNKNOWN")

# Points-to state: maps pointer varId → set of targets
PtsState = Dict[int, FrozenSet[PointsToTarget]]


def _pts_join(a: PtsState, b: PtsState) -> PtsState:
    """Pointwise union of two points-to states."""
    result: PtsState = dict(a)
    for vid, targets in b.items():
        if vid in result:
            result[vid] = result[vid] | targets
        else:
            result[vid] = targets
    return result


def _pts_leq(a: PtsState, b: PtsState) -> bool:
    """a ⊑ b iff for all vars, a[v] ⊆ b[v]."""
    for vid, targets in a.items():
        if vid not in b:
            if targets:
                return False
        elif not (targets <= b[vid]):
            return False
    return True


def _freeze_pts(state: PtsState) -> FrozenSet[Tuple[int, FrozenSet[PointsToTarget]]]:
    """Make a PtsState hashable for convergence checking."""
    return frozenset((vid, targets) for vid, targets in state.items())


_ALLOC_FUNCTIONS = frozenset({
    "malloc", "calloc", "realloc", "strdup", "strndup",
    "new", "operator new", "operator new[]",
    "g_malloc", "g_new", "g_strdup",  # GLib
    "xmalloc", "xcalloc",  # common wrappers
})


class PointerAnalysis(DataflowAnalysis[PtsState]):
    """
    Flow-sensitive Andersen-style points-to analysis.

    After ``run()``, use:
      - ``points_to(var_id, token)`` → set of PointsToTarget
      - ``may_alias(var_id_a, var_id_b, token)`` → bool
      - ``is_null_possible(var_id, token)`` → bool
      - ``heap_allocations()`` → list of allocation sites
    """

    def __init__(self, configuration: Any, scope: Optional[Any] = None) -> None:
        super().__init__(configuration, scope)
        self._alloc_sites: List[Tuple[str, Any]] = []  # (alloc_id, token)

    @property
    def direction(self) -> Direction:
        return Direction.FORWARD

    @property
    def confluence(self) -> MeetOrJoin:
        return MeetOrJoin.JOIN

    def init_entry(self) -> PtsState:
        # At entry, pointer parameters might point to anything
        state: PtsState = {}
        if self.scope:
            func = getattr(self.scope, "function", None)
            if func:
                for arg in getattr(func, "argument", {}).values():
                    var = getattr(arg, "variable", arg)
                    vid = getattr(var, "Id", None) or getattr(var, "varId", None)
                    vtype = getattr(var, "valueType", None) or getattr(
                        var, "typeStartToken", None
                    )
                    is_ptr = False
                    if vtype:
                        is_ptr = getattr(vtype, "pointer", 0) > 0
                    if not is_ptr:
                        # Check type token for '*'
                        type_tok = getattr(var, "typeStartToken", None)
                        while type_tok:
                            if getattr(type_tok, "str", "") == "*":
                                is_ptr = True
                                break
                            if type_tok == getattr(var, "typeEndToken", None):
                                break
                            type_tok = getattr(type_tok, "next", None)
                    if vid and is_ptr:
                        state[int(vid)] = frozenset({UNKNOWN_TARGET})
        return state

    def init_interior(self) -> PtsState:
        return {}

    def transfer(self, block: BasicBlock, in_val: PtsState) -> PtsState:
        state = dict(in_val)
        for tok in block.tokens:
            state = self._transfer_token(tok, state)
        return state

    def _transfer_token(self, tok: Any, state: PtsState) -> PtsState:
        """Process a single token for pointer assignments."""
        s = getattr(tok, "str", "")

        # ── Assignment: p = ... ──────────────────────────────────────
        if getattr(tok, "isAssignmentOp", False):
            lhs = getattr(tok, "astOperand1", None)
            rhs = getattr(tok, "astOperand2", None)
            if lhs is None:
                return state
            lhs_vid = getattr(lhs, "varId", None)
            if not lhs_vid or lhs_vid == 0:
                return state

            # Check if LHS is a pointer type
            vtype = getattr(lhs, "valueType", None)
            is_ptr = vtype and getattr(vtype, "pointer", 0) > 0
            # Also check if variable is pointer
            var = getattr(lhs, "variable", None)
            if var and not is_ptr:
                vt2 = getattr(var, "valueType", None)
                if vt2 and getattr(vt2, "pointer", 0) > 0:
                    is_ptr = True

            if not is_ptr:
                return state

            targets = self._eval_ptr_rhs(rhs, state)

            # ── ValueFlow augmentation ───────────────────────────────
            vf_targets = _valueflow_lifetime_targets(rhs or tok)
            for vf_tok in vf_targets:
                vf_vid = getattr(vf_tok, "varId", None)
                if vf_vid and vf_vid != 0:
                    targets = targets | frozenset({
                        PointsToTarget(
                            kind=TargetKind.STACK_VAR,
                            var_id=vf_vid,
                            label=getattr(vf_tok, "str", ""),
                        )
                    })

            # Check ValueFlow for null
            if _valueflow_is_null_possible(rhs or tok):
                targets = targets | frozenset({NULL_TARGET})

            state = dict(state)
            if s == "=":
                state[lhs_vid] = targets if targets else frozenset({UNKNOWN_TARGET})
            else:
                # Compound assignment (+=, etc.) — doesn't change pointer target
                pass

        # ── Dereference write: *p = … ────────────────────────────────
        elif s == "*" and getattr(tok, "astParent", None):
            parent = tok.astParent
            if getattr(parent, "isAssignmentOp", False):
                lhs_of_assign = getattr(parent, "astOperand1", None)
                if lhs_of_assign is tok:
                    # *p = ... → weak update to all targets of p
                    inner = getattr(tok, "astOperand1", None)
                    if inner:
                        inner_vid = getattr(inner, "varId", None)
                        # targets of p each get a potential new value
                        # (not modelling values through pointers, just tracking
                        #  that the pointee is modified)
                        pass  # Points-to set of p doesn't change

        return state

    def _eval_ptr_rhs(self, tok: Any, state: PtsState) -> FrozenSet[PointsToTarget]:
        """Evaluate an RHS expression to a set of pointer targets."""
        if tok is None:
            return frozenset({UNKNOWN_TARGET})

        s = getattr(tok, "str", "")

        # ── NULL literal ─────────────────────────────────────────────
        if getattr(tok, "isNumber", False) and s == "0":
            return frozenset({NULL_TARGET})
        if s.upper() in {"NULL", "NULLPTR", "0"}:
            return frozenset({NULL_TARGET})

        # ── Address-of: &x ───────────────────────────────────────────
        if s == "&":
            operand = getattr(tok, "astOperand1", None)
            if operand:
                vid = getattr(operand, "varId", None)
                if vid and vid != 0:
                    var = getattr(operand, "variable", None)
                    is_global = False
                    if var:
                        is_global = getattr(var, "isGlobal", False)
                    kind = TargetKind.GLOBAL_VAR if is_global else TargetKind.STACK_VAR
                    return frozenset({
                        PointsToTarget(
                            kind=kind,
                            var_id=vid,
                            label=getattr(operand, "str", ""),
                        )
                    })

        # ── Allocation: malloc/calloc/new ────────────────────────────
        if getattr(tok, "function", None) or (
            getattr(tok, "str", "") in _ALLOC_FUNCTIONS
        ):
            func_name = getattr(tok, "str", "")
            if func_name in _ALLOC_FUNCTIONS:
                alloc_id = getattr(tok, "Id", str(id(tok)))
                target = PointsToTarget(
                    kind=TargetKind.HEAP_ALLOC,
                    alloc_id=alloc_id,
                    label=f"{func_name}()",
                )
                self._alloc_sites.append((alloc_id, tok))
                return frozenset({target})

        # Check if the next token is '(' and the function name is an alloc
        next_tok = getattr(tok, "next", None)
        if next_tok and getattr(next_tok, "str", "") == "(":
            func_name = getattr(tok, "str", "")
            if func_name in _ALLOC_FUNCTIONS:
                alloc_id = getattr(tok, "Id", str(id(tok)))
                target = PointsToTarget(
                    kind=TargetKind.HEAP_ALLOC,
                    alloc_id=alloc_id,
                    label=f"{func_name}()",
                )
                self._alloc_sites.append((alloc_id, tok))
                return frozenset({target})

        # ── String literal ───────────────────────────────────────────
        if getattr(tok, "isString", False):
            return frozenset({
                PointsToTarget(
                    kind=TargetKind.STRING_LIT,
                    label=getattr(tok, "str", ""),
                )
            })

        # ── Simple pointer copy: p = q ───────────────────────────────
        vid = getattr(tok, "varId", None)
        if vid and vid != 0:
            return state.get(vid, frozenset({UNKNOWN_TARGET}))

        # ── Cast expression ──────────────────────────────────────────
        if getattr(tok, "isCast", False):
            inner = getattr(tok, "astOperand1", None) or getattr(
                tok, "astOperand2", None
            )
            return self._eval_ptr_rhs(inner, state)

        # ── Ternary: cond ? a : b ───────────────────────────────────
        if s == "?":
            op2 = getattr(tok, "astOperand2", None)
            if op2 and getattr(op2, "str", "") == ":":
                true_val = self._eval_ptr_rhs(
                    getattr(op2, "astOperand1", None), state
                )
                false_val = self._eval_ptr_rhs(
                    getattr(op2, "astOperand2", None), state
                )
                return true_val | false_val

        return frozenset({UNKNOWN_TARGET})

    def lattice_leq(self, a: PtsState, b: PtsState) -> bool:
        return _pts_leq(a, b)

    def lattice_combine(self, a: PtsState, b: PtsState) -> PtsState:
        return _pts_join(a, b)

    # ── Query API ────────────────────────────────────────────────────

    def points_to(self, var_id: int, tok: Optional[Any] = None) -> FrozenSet[PointsToTarget]:
        """
        What does pointer ``var_id`` point to at ``tok``?
        If tok is None, returns the union across all program points.
        """
        if tok is not None:
            state = self.state_at_token(tok)
            return state.get(var_id, frozenset())
        # Union across all blocks
        result: FrozenSet[PointsToTarget] = frozenset()
        for bid in self.cfg.blocks:
            state = self._out[bid]
            result = result | state.get(var_id, frozenset())
        return result

    def may_alias(self, var_a: int, var_b: int, tok: Any) -> bool:
        """
        Can ``var_a`` and ``var_b`` point to the same object at ``tok``?
        """
        pts_a = self.points_to(var_a, tok)
        pts_b = self.points_to(var_b, tok)
        # UNKNOWN aliases with everything
        if UNKNOWN_TARGET in pts_a or UNKNOWN_TARGET in pts_b:
            return True
        return bool(pts_a & pts_b)

    def is_null_possible(self, var_id: int, tok: Any) -> bool:
        """Can ``var_id`` be NULL at ``tok``?"""
        return NULL_TARGET in self.points_to(var_id, tok)

    def heap_allocations(self) -> List[Tuple[str, Any]]:
        """Return all detected heap allocation sites."""
        return list(self._alloc_sites)

    def _transfer_single_token(self, tok: Any, state: PtsState) -> PtsState:
        return self._transfer_token(tok, state)


# ═════════════════════════════════════════════════════════════════════════
#  PART 14 — ALIAS ANALYSIS  (built on PointerAnalysis + ValueFlow)
# ═════════════════════════════════════════════════════════════════════════
#
#  Higher-level alias queries that combine pointer analysis with
#  cppcheck's ValueFlow lifetime information.
# ═════════════════════════════════════════════════════════════════════════

class AliasAnalysis:
    """
    Combined alias analysis leveraging PointerAnalysis and ValueFlow.

    This is NOT a DataflowAnalysis subclass — it's a query facade
    that wraps PointerAnalysis and adds ValueFlow-based refinements.

    Usage
    -----
    >>> aa = AliasAnalysis(cfg)
    >>> aa.run()
    >>> aa.may_alias(var_p, var_q, at_token)    # bool
    >>> aa.must_alias(var_p, var_q, at_token)   # bool
    >>> aa.alias_set(var_p, at_token)           # set of varIds
    """

    def __init__(self, configuration: Any, scope: Optional[Any] = None) -> None:
        self.configuration = configuration
        self.scope = scope
        self._pa = PointerAnalysis(configuration, scope)
        self._converged = False

    def run(self) -> int:
        """Run the underlying pointer analysis."""
        iters = self._pa.run()
        self._converged = True
        return iters

    def may_alias(self, var_a: int, var_b: int, tok: Any) -> bool:
        """
        Can ``var_a`` and ``var_b`` refer to the same memory at ``tok``?

        Uses both points-to sets and ValueFlow tokvalue information.
        """
        # ── Points-to based ──────────────────────────────────────────
        if self._pa.may_alias(var_a, var_b, tok):
            return True

        # ── ValueFlow based: check if either variable's ValueFlow
        #    points to the other ──────────────────────────────────────
        for bid, bb in self._pa.cfg.blocks.items():
            for t in bb.tokens:
                vid = getattr(t, "varId", None)
                if vid not in (var_a, var_b):
                    continue
                targets = _valueflow_lifetime_targets(t)
                for target_tok in targets:
                    target_vid = getattr(target_tok, "varId", None)
                    if (vid == var_a and target_vid == var_b) or (
                        vid == var_b and target_vid == var_a
                    ):
                        return True

        return False

    def must_alias(self, var_a: int, var_b: int, tok: Any) -> bool:
        """
        Must ``var_a`` and ``var_b`` definitely refer to the same
        memory at ``tok``?

        This requires both to point to exactly one (identical) target.
        """
        pts_a = self._pa.points_to(var_a, tok)
        pts_b = self._pa.points_to(var_b, tok)
        if len(pts_a) != 1 or len(pts_b) != 1:
            return False
        if UNKNOWN_TARGET in pts_a or UNKNOWN_TARGET in pts_b:
            return False
        return pts_a == pts_b

    def alias_set(self, var_id: int, tok: Any) -> Set[int]:
        """
        Find all variable ids that may alias with ``var_id`` at ``tok``.
        """
        result: Set[int] = set()
        pts_target = self._pa.points_to(var_id, tok)
        if not pts_target:
            return result
        state = self._pa.state_at_token(tok)
        for vid, targets in state.items():
            if vid == var_id:
                continue
            if UNKNOWN_TARGET in pts_target or UNKNOWN_TARGET in targets:
                result.add(vid)
            elif pts_target & targets:
                result.add(vid)
        return result

    def points_to(self, var_id: int, tok: Any) -> FrozenSet[PointsToTarget]:
        """Delegate to underlying PointerAnalysis."""
        return self._pa.points_to(var_id, tok)

    def is_null_possible(self, var_id: int, tok: Any) -> bool:
        return self._pa.is_null_possible(var_id, tok)


# ═════════════════════════════════════════════════════════════════════════
#  PART 15 — TAINT ANALYSIS
# ═════════════════════════════════════════════════════════════════════════
#
#  Direction:   FORWARD
#  Confluence:  JOIN (may / union)
#  Lattice:     VarId → {UNTAINTED, TAINTED, SANITISED}
#
#  Tracks flow of untrusted data from sources to sinks.
#  Configurable: users provide source/sink/sanitiser predicates.
# ═════════════════════════════════════════════════════════════════════════

class TaintLevel(Enum):
    UNTAINTED = auto()
    TAINTED = auto()
    SANITISED = auto()


TaintState = Dict[int, TaintLevel]


def _taint_join(a: TaintState, b: TaintState) -> TaintState:
    """Join: TAINTED dominates SANITISED dominates UNTAINTED."""
    result: TaintState = dict(a)
    for vid, level in b.items():
        if vid not in result:
            result[vid] = level
        else:
            # TAINTED > SANITISED > UNTAINTED
            if level == TaintLevel.TAINTED or result[vid] == TaintLevel.TAINTED:
                result[vid] = TaintLevel.TAINTED
            elif level == TaintLevel.SANITISED or result[vid] == TaintLevel.SANITISED:
                result[vid] = TaintLevel.SANITISED
    return result


def _taint_leq(a: TaintState, b: TaintState) -> bool:
    """a ⊑ b if for all vars, a[v] ≤ b[v] in the taint ordering."""
    _ORDER = {TaintLevel.UNTAINTED: 0, TaintLevel.SANITISED: 1, TaintLevel.TAINTED: 2}
    for vid, level in a.items():
        b_level = b.get(vid, TaintLevel.UNTAINTED)
        if _ORDER[level] > _ORDER[b_level]:
            return False
    return True


# Default predicates — users can override these
def _default_is_source(tok: Any) -> bool:
    """Default source predicate: scanf, gets, getenv, read, recv, etc."""
    func = getattr(tok, "function", None)
    if func:
        name = getattr(func, "name", "")
    else:
        name = getattr(tok, "str", "")
    return name in {
        "scanf", "fscanf", "sscanf", "gets", "fgets", "getenv",
        "read", "recv", "recvfrom", "recvmsg", "fread",
        "getc", "getchar", "fgetc",
        "gets_s", "fgets_s",  # C11 bounds-checking
        "readline",  # POSIX
        "argv",  # main parameter
    }


def _default_is_sink(tok: Any) -> bool:
    """Default sink predicate: printf format, exec, system, SQL, etc."""
    func = getattr(tok, "function", None)
    if func:
        name = getattr(func, "name", "")
    else:
        name = getattr(tok, "str", "")
    return name in {
        "printf", "fprintf", "sprintf", "snprintf",
        "system", "exec", "execl", "execle", "execlp",
        "execv", "execve", "execvp", "popen",
        "strcpy", "strcat", "memcpy", "memmove",
        "write", "send", "sendto", "sendmsg",
        "mysql_query", "sqlite3_exec",  # SQL injection
    }


def _default_is_sanitiser(tok: Any) -> bool:
    """Default sanitiser predicate: strlen check, bounds check, etc."""
    func = getattr(tok, "function", None)
    if func:
        name = getattr(func, "name", "")
    else:
        name = getattr(tok, "str", "")
    return name in {
        "sanitize", "validate", "check_bounds",
        "strlcpy", "strlcat",  # safe string functions
        "snprintf",  # bounded output
        "escape", "html_escape", "url_encode",
    }


@dataclass
class TaintWarning:
    """A taint-related vulnerability finding."""
    var_id: int
    var_name: str
    source_token: Optional[Any]
    sink_token: Any
    taint_level: TaintLevel
    file: str = ""
    line: int = 0

    def __repr__(self) -> str:
        return (
            f"TaintWarning(v{self.var_id}={self.var_name}, "
            f"{self.taint_level.name} @ {self.file}:{self.line})"
        )


class TaintAnalysis(DataflowAnalysis[TaintState]):
    """
    Forward taint tracking analysis.

    After ``run()``, use:
      - ``is_tainted(var_id, token)`` → bool
      - ``taint_warnings()`` → list of TaintWarning
    """

    def __init__(
        self,
        configuration: Any,
        scope: Optional[Any] = None,
        is_source: Optional[Callable[[Any], bool]] = None,
        is_sink: Optional[Callable[[Any], bool]] = None,
        is_sanitiser: Optional[Callable[[Any], bool]] = None,
    ) -> None:
        super().__init__(configuration, scope)
        self._is_source = is_source or _default_is_source
        self._is_sink = is_sink or _default_is_sink
        self._is_sanitiser = is_sanitiser or _default_is_sanitiser
        self._warnings: List[TaintWarning] = []

    @property
    def direction(self) -> Direction:
        return Direction.FORWARD

    @property
    def confluence(self) -> MeetOrJoin:
        return MeetOrJoin.JOIN

    def init_entry(self) -> TaintState:
        return {}

    def init_interior(self) -> TaintState:
        return {}

    def transfer(self, block: BasicBlock, in_val: TaintState) -> TaintState:
        state = dict(in_val)
        for tok in block.tokens:
            state = self._transfer_taint_token(tok, state)
        return state

    def _transfer_taint_token(self, tok: Any, state: TaintState) -> TaintState:
        s = getattr(tok, "str", "")

        # ── Source: function call that returns tainted data ──────────
        if self._is_source(tok):
            # The LHS of the enclosing assignment gets tainted
            parent = getattr(tok, "astParent", None)
            if parent and getattr(parent, "isAssignmentOp", False):
                lhs = getattr(parent, "astOperand1", None)
                if lhs:
                    vid = getattr(lhs, "varId", None)
                    if vid and vid != 0:
                        state = dict(state)
                        state[vid] = TaintLevel.TAINTED
            # Also check if it's the RHS of the parent's parent
            # (for cases like: x = scanf(...) where scanf is deeper in AST)

        # ── Sanitiser ────────────────────────────────────────────────
        if self._is_sanitiser(tok):
            parent = getattr(tok, "astParent", None)
            if parent and getattr(parent, "isAssignmentOp", False):
                lhs = getattr(parent, "astOperand1", None)
                if lhs:
                    vid = getattr(lhs, "varId", None)
                    if vid and vid != 0:
                        state = dict(state)
                        state[vid] = TaintLevel.SANITISED

        # ── Assignment propagation: x = y → taint(x) = taint(y) ────
        if getattr(tok, "isAssignmentOp", False):
            lhs = getattr(tok, "astOperand1", None)
            rhs = getattr(tok, "astOperand2", None)
            if lhs and rhs:
                lhs_vid = getattr(lhs, "varId", None)
                rhs_vid = getattr(rhs, "varId", None)
                if lhs_vid and lhs_vid != 0:
                    # Check if RHS is tainted
                    rhs_taint = self._eval_taint_expr(rhs, state)
                    if rhs_taint != TaintLevel.UNTAINTED:
                        state = dict(state)
                        state[lhs_vid] = rhs_taint
                    elif lhs_vid in state:
                        # Clean assignment overwrites taint
                        state = dict(state)
                        state[lhs_vid] = TaintLevel.UNTAINTED

        # ── Sink detection ───────────────────────────────────────────
        if self._is_sink(tok):
            self._check_sink(tok, state)

        return state

    def _eval_taint_expr(self, tok: Any, state: TaintState) -> TaintLevel:
        """Evaluate the taint level of an expression."""
        if tok is None:
            return TaintLevel.UNTAINTED

        vid = getattr(tok, "varId", None)
        if vid and vid != 0:
            return state.get(vid, TaintLevel.UNTAINTED)

        # Binary ops: taint if either operand is tainted
        op1 = getattr(tok, "astOperand1", None)
        op2 = getattr(tok, "astOperand2", None)
        if op1 or op2:
            t1 = self._eval_taint_expr(op1, state) if op1 else TaintLevel.UNTAINTED
            t2 = self._eval_taint_expr(op2, state) if op2 else TaintLevel.UNTAINTED
            if t1 == TaintLevel.TAINTED or t2 == TaintLevel.TAINTED:
                return TaintLevel.TAINTED
            if t1 == TaintLevel.SANITISED or t2 == TaintLevel.SANITISED:
                return TaintLevel.SANITISED

        return TaintLevel.UNTAINTED

    def _check_sink(self, tok: Any, state: TaintState) -> None:
        """Check if any argument to a sink function is tainted."""
        # Walk the AST children looking for tainted variables
        def _walk(t: Any) -> None:
            if t is None:
                return
            vid = getattr(t, "varId", None)
            if vid and vid != 0 and state.get(vid) == TaintLevel.TAINTED:
                self._warnings.append(
                    TaintWarning(
                        var_id=vid,
                        var_name=getattr(t, "str", f"v{vid}"),
                        source_token=None,  # Could track provenance
                        sink_token=tok,
                        taint_level=TaintLevel.TAINTED,
                        file=getattr(tok, "file", ""),
                        line=getattr(tok, "linenr", 0),
                    )
                )
            _walk(getattr(t, "astOperand1", None))
            _walk(getattr(t, "astOperand2", None))

        # Walk the arguments (children of the function call in AST)
        parent = getattr(tok, "astParent", None)
        if parent:
            _walk(parent)
        else:
            _walk(tok)

    def lattice_leq(self, a: TaintState, b: TaintState) -> bool:
        return _taint_leq(a, b)

    def lattice_combine(self, a: TaintState, b: TaintState) -> TaintState:
        return _taint_join(a, b)

    # ── Query API ────────────────────────────────────────────────────

    def is_tainted(self, var_id: int, tok: Any) -> bool:
        state = self.state_at_token(tok)
        return state.get(var_id, TaintLevel.UNTAINTED) == TaintLevel.TAINTED

    def taint_level(self, var_id: int, tok: Any) -> TaintLevel:
        state = self.state_at_token(tok)
        return state.get(var_id, TaintLevel.UNTAINTED)

    def taint_warnings(self) -> List[TaintWarning]:
        return list(self._warnings)

    def _transfer_single_token(self, tok: Any, state: TaintState) -> TaintState:
        return self._transfer_taint_token(tok, state)


# ═════════════════════════════════════════════════════════════════════════
#  PART 16 — INTERVAL ANALYSIS  (numeric bounds)
# ═════════════════════════════════════════════════════════════════════════
#
#  Direction:   FORWARD
#  Confluence:  JOIN (may)
#  Lattice:     VarId → IntervalDomain
#  Transfer:    Abstract interpretation of arithmetic + comparisons
#  Widening:    Standard interval widening at loop heads
#
#  Application: buffer overflow detection, array bounds checking.
# ═════════════════════════════════════════════════════════════════════════

IntervalEnv = FunctionDomain  # FunctionDomain[IntervalDomain]


class IntervalAnalysis(DataflowAnalysis[IntervalEnv]):
    """
    Forward interval analysis with widening at loop heads.

    Seeds initial values from ValueFlow where available.

    After ``run()``, use:
      - ``interval_at(var_id, token)`` → IntervalDomain
      - ``is_in_bounds(var_id, lo, hi, token)`` → bool/None
    """

    # Widening thresholds: common loop bounds and sizes
    THRESHOLDS: ClassVar[List[float]] = [
        -1.0, 0.0, 1.0, 2.0, 7.0, 8.0, 10.0, 15.0, 16.0,
        31.0, 32.0, 63.0, 64.0, 100.0, 127.0, 128.0,
        255.0, 256.0, 511.0, 512.0, 1023.0, 1024.0,
        4095.0, 4096.0, 32767.0, 32768.0,
        65535.0, 65536.0,
        2147483647.0,  # INT_MAX
        4294967295.0,  # UINT_MAX
    ]

    def __init__(self, configuration: Any, scope: Optional[Any] = None) -> None:
        super().__init__(configuration, scope)
        self._loop_heads: Set[BlockId] = self._detect_loop_heads()
        self._widen_count: Dict[BlockId, int] = defaultdict(int)
        self._widen_limit: int = 3  # widen after this many iterations

    def _detect_loop_heads(self) -> Set[BlockId]:
        """Detect loop header blocks (targets of back-edges)."""
        heads: Set[BlockId] = set()
        visited: Set[BlockId] = set()
        in_stack: Set[BlockId] = set()

        def _dfs(bid: BlockId) -> None:
            visited.add(bid)
            in_stack.add(bid)
            for succ in self.cfg.blocks[bid].successors:
                if succ in in_stack:
                    heads.add(succ)  # back-edge → succ is a loop head
                elif succ not in visited:
                    _dfs(succ)
            in_stack.discard(bid)

        if self.cfg.entry in self.cfg.blocks:
            _dfs(self.cfg.entry)

        # Also check for 'while'/'for' tokens in blocks
        for bid, bb in self.cfg.blocks.items():
            for tok in bb.tokens:
                if getattr(tok, "str", "") in {"while", "for", "do"}:
                    heads.add(bid)

        return heads

    @property
    def direction(self) -> Direction:
        return Direction.FORWARD

    @property
    def confluence(self) -> MeetOrJoin:
        return MeetOrJoin.JOIN

    def init_entry(self) -> IntervalEnv:
        env = make_interval_env()
        # ── Seed from ValueFlow ──────────────────────────────────────
        if self.scope:
            func = getattr(self.scope, "function", None)
            if func:
                for arg in getattr(func, "argument", {}).values():
                    vid = getattr(arg, "Id", None) or getattr(arg, "varId", None)
                    if vid:
                        env = env.set(int(vid), IntervalDomain.top())
        return env

    def init_interior(self) -> IntervalEnv:
        return make_interval_env()

    def transfer(self, block: BasicBlock, in_val: IntervalEnv) -> IntervalEnv:
        state = in_val
        for tok in block.tokens:
            state = self._transfer_interval_token(tok, state)
        return state

    def _transfer_interval_token(
        self, tok: Any, state: IntervalEnv
    ) -> IntervalEnv:
        # ── Assignment ───────────────────────────────────────────────
        if getattr(tok, "isAssignmentOp", False):
            lhs = getattr(tok, "astOperand1", None)
            rhs = getattr(tok, "astOperand2", None)
            if lhs:
                vid = getattr(lhs, "varId", None)
                if vid and vid != 0:
                    s = getattr(tok, "str", "=")
                    if s == "=":
                        rhs_val = self._eval_interval(rhs, state)
                        state = state.set(vid, rhs_val)
                    elif s == "+=":
                        old = state.get(vid)
                        rhs_val = self._eval_interval(rhs, state)
                        state = state.set(vid, old.add(rhs_val))
                    elif s == "-=":
                        old = state.get(vid)
                        rhs_val = self._eval_interval(rhs, state)
                        state = state.set(vid, old.sub(rhs_val))
                    elif s == "*=":
                        old = state.get(vid)
                        rhs_val = self._eval_interval(rhs, state)
                        state = state.set(vid, old.mul(rhs_val))

        # ── Increment / decrement (i++, ++i, i--, --i) ──────────────
        s = getattr(tok, "str", "")
        if s in {"++", "--"}:
            operand = getattr(tok, "astOperand1", None)
            if operand:
                vid = getattr(operand, "varId", None)
                if vid and vid != 0:
                    old = state.get(vid)
                    one = IntervalDomain.const(1)
                    if s == "++":
                        state = state.set(vid, old.add(one))
                    else:
                        state = state.set(vid, old.sub(one))

        return state

    def _eval_interval(self, tok: Any, state: IntervalEnv) -> IntervalDomain:
        """Evaluate an expression to an IntervalDomain value."""
        if tok is None:
            return IntervalDomain.top()

        # ── ValueFlow first ──────────────────────────────────────────
        vf_range = _valueflow_int_range(tok)
        if vf_range is not None:
            return vf_range

        # ── Literal ──────────────────────────────────────────────────
        if getattr(tok, "isNumber", False) and getattr(tok, "isInt", False):
            try:
                n = int(getattr(tok, "str", "0"), 0)
                return IntervalDomain.const(n)
            except (ValueError, TypeError):
                return IntervalDomain.top()

        # ── Variable ─────────────────────────────────────────────────
        vid = getattr(tok, "varId", None)
        if vid and vid != 0:
            return state.get(vid)

        # ── Binary ops ───────────────────────────────────────────────
        s = getattr(tok, "str", "")
        op1 = getattr(tok, "astOperand1", None)
        op2 = getattr(tok, "astOperand2", None)
        if op1 and op2:
            left = self._eval_interval(op1, state)
            right = self._eval_interval(op2, state)
            if s == "+":
                return left.add(right)
            if s == "-":
                return left.sub(right)
            if s == "*":
                return left.mul(right)
            if s == "/":
                return left.div(right)
            if s == "%":
                return left.mod(right)
            if s == "&":
                return left.bitwise_and(right)
            if s == "<<":
                return left.shift_left(right)

        # ── Unary minus ──────────────────────────────────────────────
        if s == "-" and op1 and not op2:
            return self._eval_interval(op1, state).negate()

        # ── sizeof ───────────────────────────────────────────────────
        if s == "sizeof":
            # cppcheck often resolves sizeof to a known value
            known = _valueflow_known_int(tok)
            if known is not None:
                return IntervalDomain.const(known)

        return IntervalDomain.top()

    def lattice_leq(self, a: IntervalEnv, b: IntervalEnv) -> bool:
        return a.leq(b)

    def lattice_combine(self, a: IntervalEnv, b: IntervalEnv) -> IntervalEnv:
        return a.join(b)

    def run(self, max_iterations: int = 1000) -> int:
        """
        Overridden to add widening at loop heads.
        """
        blocks = self.cfg.blocks

        # Initialise
        for bid in blocks:
            bb = blocks[bid]
            if bb.is_entry:
                self._in[bid] = self.init_entry()
            else:
                self._in[bid] = self.init_interior()
            self._out[bid] = self.transfer(bb, self._in[bid])

        worklist = deque(self.cfg.reverse_postorder)
        seen: Set[BlockId] = set(worklist)
        iteration = 0

        while worklist and iteration < max_iterations:
            iteration += 1
            bid = worklist.popleft()
            seen.discard(bid)
            bb = blocks[bid]

            # Combine from predecessors
            preds = bb.predecessors
            if preds:
                combined = self._out[preds[0]]
                for p in preds[1:]:
                    combined = combined.join(self._out[p])
                if bb.is_entry:
                    combined = combined.join(self.init_entry())
                new_in = combined
            else:
                new_in = self.init_entry() if bb.is_entry else self.init_interior()

            # ── Widening at loop heads ───────────────────────────────
            if bid in self._loop_heads:
                self._widen_count[bid] += 1
                if self._widen_count[bid] > self._widen_limit:
                    # Apply threshold widening
                    old_in = self._in[bid]
                    widened_map: Dict[int, Any] = {}
                    all_vars = old_in.var_ids | new_in.var_ids
                    for vid in all_vars:
                        old_v = old_in.get(vid)
                        new_v = new_in.get(vid)
                        widened_map[vid] = old_v.widen_with_thresholds(
                            new_v, self.THRESHOLDS
                        )
                    new_in = FunctionDomain(
                        mapping=widened_map,
                        _default_factory=IntervalDomain.top,
                        _bottom_factory=IntervalDomain.bottom,
                    )

            new_out = self.transfer(bb, new_in)
            self._in[bid] = new_in

            if not new_out.leq(self._out[bid]):
                self._out[bid] = new_out
                for succ in bb.successors:
                    if succ not in seen:
                        worklist.append(succ)
                        seen.add(succ)
            else:
                self._out[bid] = new_out

        # ── Narrowing pass ───────────────────────────────────────────
        for _ in range(3):  # bounded narrowing iterations
            changed = False
            for bid in self.cfg.reverse_postorder:
                bb = blocks[bid]
                preds = bb.predecessors
                if preds:
                    combined = self._out[preds[0]]
                    for p in preds[1:]:
                        combined = combined.join(self._out[p])
                    new_in = self._in[bid].narrow(combined)
                else:
                    new_in = self._in[bid]
                new_out = self.transfer(bb, new_in)
                if not new_out.leq(self._out[bid]) or not self._out[bid].leq(new_out):
                    changed = True
                self._in[bid] = new_in
                self._out[bid] = new_out
            if not changed:
                break

        self._converged = True
        return iteration

    # ── Query API ────────────────────────────────────────────────────

    def interval_at(self, var_id: int, tok: Any) -> IntervalDomain:
        """The interval of ``var_id`` at ``tok``."""
        state = self.state_at_token(tok)
        return state.get(var_id)

    def is_in_bounds(
        self, var_id: int, lo: int, hi: int, tok: Any
    ) -> Optional[bool]:
        """
        Is ``var_id`` guaranteed to be in [lo, hi] at ``tok``?

        Returns:
          True  — definitely in bounds
          False — definitely out of bounds (at least partially)
          None  — cannot determine
        """
        interval = self.interval_at(var_id, tok)
        if interval.is_bottom():
            return True  # unreachable
        if interval.is_top():
            return None
        bound = IntervalDomain.range(lo, hi)
        if interval.leq(bound):
            return True
        meet = interval.meet(bound)
        if meet.is_bottom():
            return False
        return None

    def _transfer_single_token(
        self, tok: Any, state: IntervalEnv
    ) -> IntervalEnv:
        return self._transfer_interval_token(tok, state)


# ═════════════════════════════════════════════════════════════════════════
#  PART 17 — SIGN ANALYSIS
# ═════════════════════════════════════════════════════════════════════════
#
#  Direction:   FORWARD
#  Confluence:  JOIN (may)
#  Lattice:     VarId → SignDomain
# ═════════════════════════════════════════════════════════════════════════

SignEnv = FunctionDomain  # FunctionDomain[SignDomain]


class SignAnalysis(DataflowAnalysis[SignEnv]):
    """
    Forward sign analysis.

    After ``run()``, use:
      - ``sign_at(var_id, token)`` → SignDomain
      - ``is_negative(var_id, token)`` → bool
      - ``is_non_negative(var_id, token)`` → bool
    """

    @property
    def direction(self) -> Direction:
        return Direction.FORWARD

    @property
    def confluence(self) -> MeetOrJoin:
        return MeetOrJoin.JOIN

    def init_entry(self) -> SignEnv:
        return make_sign_env()

    def init_interior(self) -> SignEnv:
        return make_sign_env()

    def transfer(self, block: BasicBlock, in_val: SignEnv) -> SignEnv:
        state = in_val
        for tok in block.tokens:
            state = self._transfer_sign_token(tok, state)
        return state

    def _transfer_sign_token(self, tok: Any, state: SignEnv) -> SignEnv:
        if getattr(tok, "isAssignmentOp", False) and getattr(tok, "str", "") == "=":
            lhs = getattr(tok, "astOperand1", None)
            rhs = getattr(tok, "astOperand2", None)
            if lhs:
                vid = getattr(lhs, "varId", None)
                if vid and vid != 0:
                    rhs_sign = self._eval_sign(rhs, state)
                    state = state.set(vid, rhs_sign)
        return state

    def _eval_sign(self, tok: Any, state: SignEnv) -> SignDomain:
        if tok is None:
            return SignDomain.top()

        # ValueFlow
        known = _valueflow_known_int(tok)
        if known is not None:
            return SignDomain.abstract(known)

        # Literal
        if getattr(tok, "isNumber", False):
            try:
                n = int(getattr(tok, "str", "0"), 0)
                return SignDomain.abstract(n)
            except (ValueError, TypeError):
                return SignDomain.top()

        # Variable
        vid = getattr(tok, "varId", None)
        if vid and vid != 0:
            return state.get(vid)

        # Unsigned type → non-negative
        vtype = getattr(tok, "valueType", None)
        if vtype and getattr(vtype, "sign", "") == "unsigned":
            return SignDomain.pos().join(SignDomain.zero())  # = ⊤, but semantically ≥ 0
            # We'd need a non-negative element; for now, return ⊤

        # Binary ops
        s = getattr(tok, "str", "")
        op1 = getattr(tok, "astOperand1", None)
        op2 = getattr(tok, "astOperand2", None)
        if op1 and op2:
            left = self._eval_sign(op1, state)
            right = self._eval_sign(op2, state)
            if s == "+":
                return left.add(right)
            if s == "-":
                return left.sub(right)
            if s == "*":
                return left.mul(right)
            if s == "/":
                return left.div(right)

        return SignDomain.top()

    def lattice_leq(self, a: SignEnv, b: SignEnv) -> bool:
        return a.leq(b)

    def lattice_combine(self, a: SignEnv, b: SignEnv) -> SignEnv:
        return a.join(b)

    def sign_at(self, var_id: int, tok: Any) -> SignDomain:
        return self.state_at_token(tok).get(var_id)

    def is_negative(self, var_id: int, tok: Any) -> bool:
        s = self.sign_at(var_id, tok)
        return s.sign == Sign.NEG

    def is_non_negative(self, var_id: int, tok: Any) -> bool:
        s = self.sign_at(var_id, tok)
        return s.sign in {Sign.ZERO, Sign.POS}

    def _transfer_single_token(self, tok: Any, state: SignEnv) -> SignEnv:
        return self._transfer_sign_token(tok, state)


# ═════════════════════════════════════════════════════════════════════════
#  PART 18 — NULL POINTER ANALYSIS
# ═════════════════════════════════════════════════════════════════════════
#
#  Direction:   FORWARD
#  Confluence:  JOIN (may)
#  Lattice:     VarId → {BOTTOM, NULL, NON_NULL, TOP}  (flat-ish)
#
#  Tracks whether pointer variables are definitely null, definitely
#  non-null, or unknown.  Used for null-dereference detection.
#
#  Leverages ValueFlow: if cppcheck says a value is known to be 0,
#  we mark it NULL.
# ═════════════════════════════════════════════════════════════════════════

class NullState(Enum):
    BOTTOM = auto()
    NULL = auto()
    NON_NULL = auto()
    TOP = auto()


@dataclass(frozen=True)
class NullDomain:
    """Three-valued null tracking domain."""
    state: NullState

    @classmethod
    def bottom(cls) -> NullDomain:
        return cls(NullState.BOTTOM)

    @classmethod
    def top(cls) -> NullDomain:
        return cls(NullState.TOP)

    @classmethod
    def null(cls) -> NullDomain:
        return cls(NullState.NULL)

    @classmethod
    def non_null(cls) -> NullDomain:
        return cls(NullState.NON_NULL)

    def is_bottom(self) -> bool:
        return self.state == NullState.BOTTOM

    def is_top(self) -> bool:
        return self.state == NullState.TOP

    def join(self, other: NullDomain) -> NullDomain:
        if self.is_bottom():
            return other
        if other.is_bottom():
            return self
        if self.state == other.state:
            return self
        return NullDomain.top()

    def meet(self, other: NullDomain) -> NullDomain:
        if self.is_top():
            return other
        if other.is_top():
            return self
        if self.state == other.state:
            return self
        return NullDomain.bottom()

    def leq(self, other: NullDomain) -> bool:
        if self.is_bottom():
            return True
        if other.is_top():
            return True
        return self.state == other.state

    def widen(self, other: NullDomain) -> NullDomain:
        return self.join(other)

    def narrow(self, other: NullDomain) -> NullDomain:
        return other

    def __repr__(self) -> str:
        return f"Null({self.state.name})"


NullEnv = FunctionDomain  # FunctionDomain[NullDomain]


def _make_null_env() -> NullEnv:
    return FunctionDomain(
        mapping={},
        _default_factory=NullDomain.top,
        _bottom_factory=NullDomain.bottom,
    )


@dataclass
class NullDerefWarning:
    """A potential null-pointer dereference."""
    var_id: int
    var_name: str
    token: Any
    null_state: NullState
    file: str = ""
    line: int = 0
    severity: str = "warning"  # "error" if definite

    def __repr__(self) -> str:
        return (
            f"NullDeref(v{self.var_id}={self.var_name}, "
            f"{self.null_state.name} @ {self.file}:{self.line})"
        )


class NullPointerAnalysis(DataflowAnalysis[NullEnv]):
    """
    Null pointer analysis.

    Tracks whether each pointer variable is NULL, NON_NULL, or UNKNOWN.

    After ``run()``, use:
      - ``null_state_at(var_id, token)`` → NullDomain
      - ``null_deref_warnings()`` → list of potential dereferences
    """

    def __init__(self, configuration: Any, scope: Optional[Any] = None) -> None:
        super().__init__(configuration, scope)
        self._warnings: List[NullDerefWarning] = []

    @property
    def direction(self) -> Direction:
        return Direction.FORWARD

    @property
    def confluence(self) -> MeetOrJoin:
        return MeetOrJoin.JOIN

    def init_entry(self) -> NullEnv:
        env = _make_null_env()
        # Pointer parameters: could be null unless annotated
        if self.scope:
            func = getattr(self.scope, "function", None)
            if func:
                for arg in getattr(func, "argument", {}).values():
                    var = getattr(arg, "variable", arg)
                    vid = getattr(var, "Id", None) or getattr(var, "varId", None)
                    if vid:
                        vtype = getattr(var, "valueType", None)
                        if vtype and getattr(vtype, "pointer", 0) > 0:
                            env = env.set(int(vid), NullDomain.top())
        return env

    def init_interior(self) -> NullEnv:
        return _make_null_env()

    def transfer(self, block: BasicBlock, in_val: NullEnv) -> NullEnv:
        state = in_val
        for tok in block.tokens:
            state = self._transfer_null_token(tok, state)
        return state

    def _transfer_null_token(self, tok: Any, state: NullEnv) -> NullEnv:
        s = getattr(tok, "str", "")

        # ── Assignment ───────────────────────────────────────────────
        if getattr(tok, "isAssignmentOp", False) and s == "=":
            lhs = getattr(tok, "astOperand1", None)
            rhs = getattr(tok, "astOperand2", None)
            if lhs:
                vid = getattr(lhs, "varId", None)
                if vid and vid != 0:
                    rhs_null = self._eval_null(rhs, state)
                    state = state.set(vid, rhs_null)

        # ── Null check: if (p) or if (p != NULL) ────────────────────
        # We detect comparison tokens and refine in successors.
        # (Block-level: we note the comparison but refinement happens
        #  at the confluence point with branch-specific edges.)
        if getattr(tok, "isComparisonOp", False):
            self._note_null_check(tok, state)

        # ── Dereference detection: *p or p->member ──────────────────
        if s == "*":
            operand = getattr(tok, "astOperand1", None)
            if operand:
                vid = getattr(operand, "varId", None)
                if vid and vid != 0:
                    nstate = state.get(vid)
                    if nstate.state in {NullState.NULL, NullState.TOP}:
                        severity = "error" if nstate.state == NullState.NULL else "warning"
                        self._warnings.append(
                            NullDerefWarning(
                                var_id=vid,
                                var_name=getattr(operand, "str", f"v{vid}"),
                                token=tok,
                                null_state=nstate.state,
                                file=getattr(tok, "file", ""),
                                line=getattr(tok, "linenr", 0),
                                severity=severity,
                            )
                        )
                    # After dereference, assume non-null (or crash)
                    state = state.set(vid, NullDomain.non_null())

        if s == "." and getattr(tok, "originalName", "") == "->":
            lhs_tok = getattr(tok, "astOperand1", None)
            if lhs_tok:
                vid = getattr(lhs_tok, "varId", None)
                if vid and vid != 0:
                    nstate = state.get(vid)
                    if nstate.state in {NullState.NULL, NullState.TOP}:
                        severity = "error" if nstate.state == NullState.NULL else "warning"
                        self._warnings.append(
                            NullDerefWarning(
                                var_id=vid,
                                var_name=getattr(lhs_tok, "str", f"v{vid}"),
                                token=tok,
                                null_state=nstate.state,
                                file=getattr(tok, "file", ""),
                                line=getattr(tok, "linenr", 0),
                                severity=severity,
                            )
                        )
                    state = state.set(vid, NullDomain.non_null())

        return state

    def _eval_null(self, tok: Any, state: NullEnv) -> NullDomain:
        """Evaluate an expression's null-ness."""
        if tok is None:
            return NullDomain.top()

        s = getattr(tok, "str", "")

        # NULL / nullptr / 0
        if s.upper() in {"NULL", "NULLPTR"} or (
            getattr(tok, "isNumber", False) and s == "0"
        ):
            return NullDomain.null()

        # ── ValueFlow check ──────────────────────────────────────────
        if _valueflow_is_null_possible(tok):
            known = _valueflow_known_int(tok)
            if known == 0:
                return NullDomain.null()
            return NullDomain.top()

        # ── malloc/calloc can return NULL ────────────────────────────
        func_name = getattr(tok, "str", "")
        if func_name in _ALLOC_FUNCTIONS:
            return NullDomain.top()  # might return NULL

        # ── &x is never null ─────────────────────────────────────────
        if s == "&":
            return NullDomain.non_null()

        # ── Variable ─────────────────────────────────────────────────
        vid = getattr(tok, "varId", None)
        if vid and vid != 0:
            return state.get(vid)

        # ── Non-zero constant ────────────────────────────────────────
        if getattr(tok, "isNumber", False):
            return NullDomain.non_null()

        # ── String literal ───────────────────────────────────────────
        if getattr(tok, "isString", False):
            return NullDomain.non_null()

        return NullDomain.top()

    def _note_null_check(self, tok: Any, state: NullEnv) -> None:
        """Record null check for potential branch refinement."""
        # This is noted but branch-sensitive refinement requires
        # splitting at the CFG edge level, which our simplified
        # CFG doesn't fully support.  The information is available
        # for future enhancement.
        pass

    def lattice_leq(self, a: NullEnv, b: NullEnv) -> bool:
        return a.leq(b)

    def lattice_combine(self, a: NullEnv, b: NullEnv) -> NullEnv:
        return a.join(b)

    def null_state_at(self, var_id: int, tok: Any) -> NullDomain:
        return self.state_at_token(tok).get(var_id)

    def null_deref_warnings(self) -> List[NullDerefWarning]:
        return list(self._warnings)

    def _transfer_single_token(self, tok: Any, state: NullEnv) -> NullEnv:
        return self._transfer_null_token(tok, state)


# ═════════════════════════════════════════════════════════════════════════
#  PART 19 — COMBINED ANALYSIS RUNNER
# ═════════════════════════════════════════════════════════════════════════
#
#  Convenience: run multiple analyses in one call.
# ═════════════════════════════════════════════════════════════════════════

@dataclass
class AnalysisResults:
    """Collected results from running multiple analyses."""
    reaching_defs: Optional[ReachingDefinitions] = None
    available_exprs: Optional[AvailableExpressions] = None
    very_busy_exprs: Optional[VeryBusyExpressions] = None
    live_vars: Optional[LiveVariables] = None
    definite_assign: Optional[DefiniteAssignment] = None
    dominators: Optional[DominatorAnalysis] = None
    constants: Optional[ConstantPropagation] = None
    copies: Optional[CopyPropagation] = None
    pointers: Optional[PointerAnalysis] = None
    aliases: Optional[AliasAnalysis] = None
    taint: Optional[TaintAnalysis] = None
    intervals: Optional[IntervalAnalysis] = None
    signs: Optional[SignAnalysis] = None
    null_ptrs: Optional[NullPointerAnalysis] = None

    @property
    def all_analyses(self) -> List[Tuple[str, Any]]:
        result = []
        for name in (
            "reaching_defs", "available_exprs", "very_busy_exprs",
            "live_vars", "definite_assign", "dominators",
            "constants", "copies", "pointers", "aliases",
            "taint", "intervals", "signs", "null_ptrs",
        ):
            val = getattr(self, name)
            if val is not None:
                result.append((name, val))
        return result


def run_all_analyses(
    configuration: Any,
    scope: Optional[Any] = None,
    analyses: Optional[Set[str]] = None,
    taint_config: Optional[Dict[str, Callable]] = None,
) -> AnalysisResults:
    """
    Run a suite of dataflow analyses on a configuration.

    Parameters
    ----------
    configuration : cppcheckdata.Configuration
    scope : optional Scope to analyse (defaults to first function)
    analyses : optional set of analysis names to run (default: all).
        Valid names: "reaching_defs", "available_exprs", "very_busy_exprs",
        "live_vars", "definite_assign", "dominators", "constants",
        "copies", "pointers", "aliases", "taint", "intervals", "signs",
        "null_ptrs"
    taint_config : optional dict with keys "is_source", "is_sink",
        "is_sanitiser" mapping to callables

    Returns
    -------
    AnalysisResults with populated fields for requested analyses.
    """
    ALL = {
        "reaching_defs", "available_exprs", "very_busy_exprs",
        "live_vars", "definite_assign", "dominators",
        "constants", "copies", "pointers", "aliases",
        "taint", "intervals", "signs", "null_ptrs",
    }
    if analyses is None:
        analyses = ALL
    else:
        analyses = analyses & ALL

    results = AnalysisResults()

    if "reaching_defs" in analyses:
        rd = ReachingDefinitions(configuration, scope)
        rd.run()
        results.reaching_defs = rd

    if "available_exprs" in analyses:
        ae = AvailableExpressions(configuration, scope)
        ae.run()
        results.available_exprs = ae

    if "very_busy_exprs" in analyses:
        vbe = VeryBusyExpressions(configuration, scope)
        vbe.run()
        results.very_busy_exprs = vbe

    if "live_vars" in analyses:
        lv = LiveVariables(configuration, scope)
        lv.run()
        results.live_vars = lv

    if "definite_assign" in analyses:
        da = DefiniteAssignment(configuration, scope)
        da.run()
        results.definite_assign = da

    if "dominators" in analyses:
        dom = DominatorAnalysis(configuration, scope)
        dom.run()
        results.dominators = dom

    if "constants" in analyses:
        cp = ConstantPropagation(configuration, scope)
        cp.run()
        results.constants = cp

    if "copies" in analyses:
        copy = CopyPropagation(configuration, scope)
        copy.run()
        results.copies = copy

    if "pointers" in analyses:
        pa = PointerAnalysis(configuration, scope)
        pa.run()
        results.pointers = pa

    if "aliases" in analyses:
        aa = AliasAnalysis(configuration, scope)
        aa.run()
        results.aliases = aa

    if "taint" in analyses:
        tc = taint_config or {}
        ta = TaintAnalysis(
            configuration, scope,
            is_source=tc.get("is_source"),
            is_sink=tc.get("is_sink"),
            is_sanitiser=tc.get("is_sanitiser"),
        )
        ta.run()
        results.taint = ta

    if "intervals" in analyses:
        ia = IntervalAnalysis(configuration, scope)
        ia.run()
        results.intervals = ia

    if "signs" in analyses:
        sa = SignAnalysis(configuration, scope)
        sa.run()
        results.signs = sa

    if "null_ptrs" in analyses:
        npa = NullPointerAnalysis(configuration, scope)
        npa.run()
        results.null_ptrs = npa

    return results


# ═════════════════════════════════════════════════════════════════════════
#  PART 20 — PUBLIC API
# ═════════════════════════════════════════════════════════════════════════

__all__ = [
    # CFG
    "BasicBlock",
    "SimpleCFG",
    "build_cfg",
    # Base
    "Direction",
    "MeetOrJoin",
    "DataflowAnalysis",
    # Data structures
    "Definition",
    "Expression",
    "CopyRel",
    "PointsToTarget",
    "TargetKind",
    "NULL_TARGET",
    "UNKNOWN_TARGET",
    "TaintLevel",
    "TaintWarning",
    "NullState",
    "NullDomain",
    "NullDerefWarning",
    # Analyses
    "ReachingDefinitions",
    "AvailableExpressions",
    "VeryBusyExpressions",
    "LiveVariables",
    "DefiniteAssignment",
    "DominatorAnalysis",
    "ConstantPropagation",
    "CopyPropagation",
    "PointerAnalysis",
    "AliasAnalysis",
    "TaintAnalysis",
    "IntervalAnalysis",
    "SignAnalysis",
    "NullPointerAnalysis",
    # Combined
    "AnalysisResults",
    "run_all_analyses",
]
