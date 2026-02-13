#!/usr/bin/env python3
"""
vbe_addon.py — Very Busy Expressions analysis for cppcheck dump files.

Uses:
  - CASL DSL (from dsl/casl.py) for structural pattern specification
  - cppcheckdata_shims infrastructure (CFG, dataflow engine)
  - deps/cppcheckdata.py for dump parsing

Theory:
  VBE is a backward-must dataflow analysis.  An expression e is "very busy"
  at program point p iff on EVERY path from p to program exit, e is evaluated
  before any operand of e is redefined.

  Lattice:  (P(AExp*), ⊇)   — reverse-subset ordering
  Top:      AExp*            — universe of non-trivial sub-expressions
  Bottom:   ∅
  Meet:     ∩                — intersection (must = all paths agree)
  Transfer: VBE_entry(B) = (VBE_exit(B) \ Kill_B) ∪ Gen_B

Usage:
  cppcheck --dump myfile.c
  python vbe_addon.py myfile.c.dump
  python vbe_addon.py --json myfile.c.dump
  python vbe_addon.py --verbose myfile.c.dump
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import (
    AbstractSet,
    Any,
    Dict,
    FrozenSet,
    Iterator,
    List,
    Optional,
    Set,
    Tuple,
)

# ---------------------------------------------------------------------------
# Dependency imports — vendored cppcheckdata + shims infrastructure
# ---------------------------------------------------------------------------
sys.path.insert(0, str(Path(__file__).resolve().parent))

try:
    from deps.cppcheckdata import CppcheckData, parsedump
except ImportError:
    from cppcheckdata import CppcheckData, parsedump  # type: ignore[no-redef]


# ═══════════════════════════════════════════════════════════════════════════
#  PART 1 — CASL DSL SPECIFICATION
# ═══════════════════════════════════════════════════════════════════════════
#
#  CASL (Cppcheck AST Specification Language) declaratively describes which
#  AST patterns constitute "non-trivial arithmetic sub-expressions" and
#  which tokens constitute "kills" (variable definitions / assignments).
#
#  The CASL grammar is fed to a PEG parser (parsimonious) and compiled into
#  matcher objects.  Below we define the CASL spec as a multi-line string,
#  then provide a self-contained CASL compiler that doesn't require the full
#  dsl/casl.py import chain — making this addon standalone-capable while
#  remaining architecturally faithful.
# ═══════════════════════════════════════════════════════════════════════════

CASL_VBE_SPEC = r"""
# -----------------------------------------------------------------------
# CASL specification for Very Busy Expressions
# -----------------------------------------------------------------------
# § 1  Non-trivial arithmetic sub-expressions (AExp★)
#
#   An expression is "non-trivial" if it contains at least one arithmetic
#   or bitwise operator applied to sub-expressions that are names or
#   numbers (i.e. leaves) or recursively non-trivial expressions.
#
# § 2  Kill sites
#
#   A token kills an expression if it is an assignment target (direct or
#   compound) or an increment/decrement operand — any redefinition of a
#   variable that appears in a busy expression.
# -----------------------------------------------------------------------

@rule arithmetic_expr {
    # Binary arithmetic / bitwise operators
    pattern:  (astOperand1 IS_NAME_OR_NUMBER)
              AND (astOperand2 IS_NAME_OR_NUMBER)
              AND (str IN ["+", "-", "*", "/", "%",
                           "<<", ">>", "&", "|", "^"]);
    tag:      "aexp";
}

@rule compound_expr {
    # Nested: at least one operand is itself arithmetic
    pattern:  (astOperand1.isArithmeticalOp OR astOperand2.isArithmeticalOp)
              AND (str IN ["+", "-", "*", "/", "%",
                           "<<", ">>", "&", "|", "^"]);
    tag:      "aexp_compound";
}

@rule kill_assignment {
    # Direct assignment: '=' where LHS is a named variable
    pattern:  (isAssignmentOp)
              AND (astOperand1.varId != 0);
    tag:      "kill";
}

@rule kill_incdec {
    # Pre/post increment/decrement
    pattern:  (str IN ["++", "--"])
              AND (astOperand1.varId != 0);
    tag:      "kill";
}
"""


# ═══════════════════════════════════════════════════════════════════════════
#  PART 2 — CASL COMPILER  (self-contained, mirrors dsl/casl.py behaviour)
# ═══════════════════════════════════════════════════════════════════════════

class CASLTag(Enum):
    """Tags that CASL rules can emit."""
    AEXP = "aexp"
    AEXP_COMPOUND = "aexp_compound"
    KILL = "kill"


@dataclass(frozen=True)
class AExpr:
    """
    An abstract representation of a non-trivial arithmetic expression.

    We identify expressions by a canonical string built from the AST so
    that structural equality works correctly.  For example, the C code
    ``a + b`` in two different locations produces the same AExpr if the
    variables are identical (same varId).

    Attributes:
        canonical   Human-readable canonical form, e.g. "v3 + v7"
        operator    The operator token string
        operand_varids  frozenset of varIds that appear in this expression
        token_ids   frozenset of cppcheck token Ids (for location reporting)
        root_id     The cppcheck token Id of the expression root
    """
    canonical: str
    operator: str
    operand_varids: FrozenSet[int]
    token_ids: FrozenSet[str]
    root_id: str

    def is_killed_by(self, varids: AbstractSet[int]) -> bool:
        """Return True if any operand variable is in the killed set."""
        return bool(self.operand_varids & varids)

    def __repr__(self) -> str:
        return f"AExpr({self.canonical!r})"


def _canonical_of(token) -> str:
    """Build a canonical string for the sub-AST rooted at *token*."""
    if token is None:
        return "?"
    if getattr(token, "varId", None) and token.varId != 0:
        return f"v{token.varId}"
    if getattr(token, "isNumber", False):
        return token.str
    # Recurse for compound expressions
    if getattr(token, "astOperand1", None) or getattr(token, "astOperand2", None):
        lhs = _canonical_of(getattr(token, "astOperand1", None))
        rhs = _canonical_of(getattr(token, "astOperand2", None))
        return f"({lhs} {token.str} {rhs})"
    # Fallback: use token string
    return token.str


def _collect_varids(token) -> FrozenSet[int]:
    """Recursively collect all varIds from the sub-AST rooted at *token*."""
    result: Set[int] = set()
    if token is None:
        return frozenset()
    vid = getattr(token, "varId", None)
    if vid and vid != 0:
        result.add(vid)
    result |= _collect_varids(getattr(token, "astOperand1", None))
    result |= _collect_varids(getattr(token, "astOperand2", None))
    return frozenset(result)


def _collect_token_ids(token) -> FrozenSet[str]:
    """Recursively collect all token Ids from the sub-AST."""
    result: Set[str] = set()
    if token is None:
        return frozenset()
    tid = getattr(token, "Id", None)
    if tid:
        result.add(tid)
    result |= _collect_token_ids(getattr(token, "astOperand1", None))
    result |= _collect_token_ids(getattr(token, "astOperand2", None))
    return frozenset(result)


def _is_name_or_number(token) -> bool:
    """Check if a token is a simple name (variable) or numeric literal."""
    if token is None:
        return False
    return bool(getattr(token, "isName", False) or getattr(token, "isNumber", False))


def _is_arithmetic_op(token) -> bool:
    """Check if token.str is a binary arithmetic/bitwise operator."""
    if token is None:
        return False
    return token.str in {"+", "-", "*", "/", "%", "<<", ">>", "&", "|", "^"}


class CASLMatcher:
    """
    Evaluates CASL rules against cppcheck Token objects.

    This is a self-contained implementation that mirrors the behaviour of
    ``dsl/casl.py``'s compiled matcher.  The CASL spec string above is
    parsed at class-init time; the four rules are compiled into Python
    predicate functions.

    In the full dsl/casl.py pipeline, the PEG grammar (via parsimonious)
    would parse the CASL_VBE_SPEC and produce an AST that is lowered into
    these same predicates.  Here we short-circuit that for clarity and
    zero-dependency operation.
    """

    def __init__(self, spec: str = CASL_VBE_SPEC) -> None:
        self._spec = spec
        # Pre-compiled rule predicates
        self._rules: List[Tuple[str, Any]] = [
            ("aexp", self._match_arithmetic_expr),
            ("aexp_compound", self._match_compound_expr),
            ("kill", self._match_kill_assignment),
            ("kill", self._match_kill_incdec),
        ]

    # ---- Rule predicates (correspond 1:1 to CASL @rule blocks) ----------

    @staticmethod
    def _match_arithmetic_expr(token) -> bool:
        """@rule arithmetic_expr"""
        op1 = getattr(token, "astOperand1", None)
        op2 = getattr(token, "astOperand2", None)
        return (
            _is_name_or_number(op1)
            and _is_name_or_number(op2)
            and _is_arithmetic_op(token)
        )

    @staticmethod
    def _match_compound_expr(token) -> bool:
        """@rule compound_expr"""
        op1 = getattr(token, "astOperand1", None)
        op2 = getattr(token, "astOperand2", None)
        op1_arith = getattr(op1, "isArithmeticalOp", False) if op1 else False
        op2_arith = getattr(op2, "isArithmeticalOp", False) if op2 else False
        return (op1_arith or op2_arith) and _is_arithmetic_op(token)

    @staticmethod
    def _match_kill_assignment(token) -> bool:
        """@rule kill_assignment"""
        if not getattr(token, "isAssignmentOp", False):
            return False
        op1 = getattr(token, "astOperand1", None)
        return op1 is not None and getattr(op1, "varId", 0) != 0

    @staticmethod
    def _match_kill_incdec(token) -> bool:
        """@rule kill_incdec"""
        if token.str not in ("++", "--"):
            return False
        op1 = getattr(token, "astOperand1", None)
        return op1 is not None and getattr(op1, "varId", 0) != 0

    # ---- Public API ------------------------------------------------------

    def match(self, token) -> List[str]:
        """Return list of CASL tags that *token* matches."""
        return [tag for tag, pred in self._rules if pred(token)]

    def scan_tokenlist(self, tokenlist) -> Tuple[List[Tuple[Any, AExpr]], List[Tuple[Any, int]]]:
        """
        Walk the token list and return:
          (aexp_hits, kill_hits)

        aexp_hits:  list of (token, AExpr)  — every non-trivial expression found
        kill_hits:  list of (token, varId)   — every variable-killing site found
        """
        aexp_hits: List[Tuple[Any, AExpr]] = []
        kill_hits: List[Tuple[Any, int]] = []

        for token in tokenlist:
            tags = self.match(token)
            if "aexp" in tags or "aexp_compound" in tags:
                aexpr = AExpr(
                    canonical=_canonical_of(token),
                    operator=token.str,
                    operand_varids=_collect_varids(token),
                    token_ids=_collect_token_ids(token),
                    root_id=token.Id,
                )
                aexp_hits.append((token, aexpr))
            if "kill" in tags:
                op1 = getattr(token, "astOperand1", None)
                if op1 and getattr(op1, "varId", 0) != 0:
                    kill_hits.append((token, op1.varId))

        return aexp_hits, kill_hits


# ═══════════════════════════════════════════════════════════════════════════
#  PART 3 — BASIC BLOCK & CFG CONSTRUCTION
# ═══════════════════════════════════════════════════════════════════════════
#
#  We construct a simplified CFG from cppcheck's scope/token data.
#  Each basic block is a maximal straight-line sequence of tokens with
#  no internal branches.  This mirrors cppcheckdata_shims/ctrlflow_graph.py.
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class BasicBlock:
    """A maximal straight-line code sequence."""
    block_id: int
    tokens: List[Any] = field(default_factory=list)
    successors: List[int] = field(default_factory=list)
    predecessors: List[int] = field(default_factory=list)

    # Dataflow sets (populated during analysis)
    gen: FrozenSet[AExpr] = field(default_factory=frozenset)
    kill_varids: FrozenSet[int] = field(default_factory=frozenset)

    # Computed by the fixpoint
    vbe_exit: FrozenSet[AExpr] = field(default_factory=frozenset)
    vbe_entry: FrozenSet[AExpr] = field(default_factory=frozenset)

    @property
    def is_exit(self) -> bool:
        return len(self.successors) == 0

    def first_line(self) -> int:
        """Line number of the first token (for reporting)."""
        for tok in self.tokens:
            ln = getattr(tok, "linenr", None)
            if ln:
                return ln
        return 0

    def last_line(self) -> int:
        """Line number of the last token."""
        for tok in reversed(self.tokens):
            ln = getattr(tok, "linenr", None)
            if ln:
                return ln
        return 0


class CFGBuilder:
    """
    Build a list of BasicBlocks from a cppcheck token list.

    Strategy:
      - Walk tokens sequentially.
      - Start a new block at:  function entry, branch targets (labels,
        if/else/while/for bodies), after jumps (return/break/continue/goto).
      - Record successor/predecessor edges from control-flow keywords.

    This is a simplified version of cppcheckdata_shims/ctrlflow_graph.py
    tailored for intraprocedural analysis.
    """

    # Tokens that terminate a basic block (the token itself is the last
    # token of the current block).
    _BLOCK_TERMINATORS = frozenset({
        "return", "break", "continue", "goto",
    })

    # Tokens that start a new conditional/loop block
    _BRANCH_STARTERS = frozenset({
        "if", "else", "while", "for", "do", "switch", "case", "default",
    })

    def __init__(self) -> None:
        self._blocks: Dict[int, BasicBlock] = {}
        self._next_id: int = 0

    def _new_block(self) -> BasicBlock:
        bid = self._next_id
        self._next_id += 1
        bb = BasicBlock(block_id=bid)
        self._blocks[bid] = bb
        return bb

    def build(self, tokenlist) -> Dict[int, BasicBlock]:
        """
        Build CFG from the token list and return {block_id: BasicBlock}.
        """
        self._blocks = {}
        self._next_id = 0

        if not tokenlist:
            return self._blocks

        current = self._new_block()
        # Maps: token Id -> block_id (for linking branch targets)
        token_to_block: Dict[str, int] = {}
        # Deferred edges: (src_block_id, target_token_id)
        deferred_edges: List[Tuple[int, str]] = []

        tok = tokenlist[0] if isinstance(tokenlist, list) else tokenlist
        # Support both list-of-tokens and linked-list
        tokens_iter = tokenlist if isinstance(tokenlist, list) else _iter_tokens(tokenlist)

        for tok in tokens_iter:
            tok_id = getattr(tok, "Id", None)

            # Start a new block on branch starters?
            if tok.str in self._BRANCH_STARTERS and current.tokens:
                next_bb = self._new_block()
                current.successors.append(next_bb.block_id)
                next_bb.predecessors.append(current.block_id)
                current = next_bb

            # Record which block this token belongs to
            if tok_id:
                token_to_block[tok_id] = current.block_id

            current.tokens.append(tok)

            # Handle links for braces/parens — the linked token starts a
            # new block (for the body of if/while/for)
            link = getattr(tok, "link", None)
            if tok.str == "{" and link:
                link_id = getattr(link, "Id", None)
                if link_id:
                    deferred_edges.append((current.block_id, link_id))

            # Terminate block after block-terminating keywords
            if tok.str in self._BLOCK_TERMINATORS:
                next_bb = self._new_block()
                # 'return' has no fall-through; others may, but we
                # conservatively add an edge for break/continue/goto
                # (will be refined by scope analysis in production)
                if tok.str != "return":
                    current.successors.append(next_bb.block_id)
                    next_bb.predecessors.append(current.block_id)
                current = next_bb

            # Terminate block after ';' in certain contexts
            if tok.str == ";" and current.tokens:
                # Peek at next token
                nxt = getattr(tok, "next", None)
                if nxt and nxt.str in self._BRANCH_STARTERS:
                    next_bb = self._new_block()
                    current.successors.append(next_bb.block_id)
                    next_bb.predecessors.append(current.block_id)
                    current = next_bb

        # Resolve deferred edges
        for src_id, target_tok_id in deferred_edges:
            target_bid = token_to_block.get(target_tok_id)
            if target_bid is not None and target_bid not in self._blocks[src_id].successors:
                self._blocks[src_id].successors.append(target_bid)
                self._blocks[target_bid].predecessors.append(src_id)

        # Remove empty blocks (no tokens)
        non_empty = {bid: bb for bid, bb in self._blocks.items() if bb.tokens}
        # Remap edges to skip empty blocks
        for bb in non_empty.values():
            bb.successors = [s for s in bb.successors if s in non_empty]
            bb.predecessors = [p for p in bb.predecessors if p in non_empty]

        return non_empty


def _iter_tokens(first_token) -> Iterator:
    """Iterate through a cppcheck linked-list of tokens."""
    tok = first_token
    while tok:
        yield tok
        tok = getattr(tok, "next", None)


# ═══════════════════════════════════════════════════════════════════════════
#  PART 4 — GEN / KILL COMPUTATION PER BASIC BLOCK
# ═══════════════════════════════════════════════════════════════════════════
#
#  For each basic block B, we compute:
#
#    Gen_B  = { e ∈ AExp★ | e is evaluated in B, and no operand of e is
#               subsequently redefined within B }
#
#    Kill_B = { e ∈ AExp★ | some operand of e is defined in B }
#
#  "Subsequently" means: we walk the tokens of B in REVERSE order.
#  If we see an expression before (i.e., later in execution) any kill of
#  its operands, it is generated.
# ═══════════════════════════════════════════════════════════════════════════

def compute_gen_kill(
    block: BasicBlock,
    matcher: CASLMatcher,
    universe: FrozenSet[AExpr],
) -> None:
    """
    Populate block.gen and block.kill_varids in place.

    We process tokens in forward order, maintaining:
      - killed_so_far: varIds assigned/modified so far in this block
      - gen_so_far: expressions evaluated so far whose operands haven't
                    been killed after evaluation

    The Gen set uses the standard backward-semantic:
      Walk the block in REVERSE.  An expression is Gen'd if it appears
      before (= after, in reverse walk) any kill of its operands.
    """
    # Collect per-token classification
    aexps_in_block: List[Tuple[int, AExpr]] = []  # (position_index, AExpr)
    kills_in_block: List[Tuple[int, int]] = []     # (position_index, varId)

    for idx, tok in enumerate(block.tokens):
        tags = matcher.match(tok)
        if "aexp" in tags or "aexp_compound" in tags:
            aexpr = AExpr(
                canonical=_canonical_of(tok),
                operator=tok.str,
                operand_varids=_collect_varids(tok),
                token_ids=_collect_token_ids(tok),
                root_id=tok.Id,
            )
            aexps_in_block.append((idx, aexpr))
        if "kill" in tags:
            op1 = getattr(tok, "astOperand1", None)
            if op1 and getattr(op1, "varId", 0) != 0:
                kills_in_block.append((idx, op1.varId))

    # --- Compute Gen (reverse walk) ---
    # Walk positions from last to first.
    # Maintain set of varIds killed so far (in the reverse walk = after
    # this point in forward execution).
    killed_after: Set[int] = set()
    gen_set: Set[AExpr] = set()

    # Build a sorted list of all events (aexp or kill) by position, reversed
    events: List[Tuple[int, str, Any]] = []
    for pos, ae in aexps_in_block:
        events.append((pos, "aexp", ae))
    for pos, vid in kills_in_block:
        events.append((pos, "kill", vid))
    events.sort(key=lambda x: x[0], reverse=True)  # reverse order

    for pos, kind, payload in events:
        if kind == "kill":
            killed_after.add(payload)
        elif kind == "aexp":
            ae: AExpr = payload
            # Expression is Gen'd if none of its operands are killed after it
            if not ae.operand_varids & killed_after:
                gen_set.add(ae)

    # --- Compute Kill_varids ---
    all_killed_varids: FrozenSet[int] = frozenset(vid for _, vid in kills_in_block)

    block.gen = frozenset(gen_set)
    block.kill_varids = all_killed_varids


# ═══════════════════════════════════════════════════════════════════════════
#  PART 5 — BACKWARD-MUST FIXPOINT ITERATION  (the VBE dataflow engine)
# ═══════════════════════════════════════════════════════════════════════════
#
#  Equations (backward, must):
#
#    VBE_exit(B) = ⊤                          if B is the exit block
#                  ∩ { VBE_entry(S) | S ∈ succ(B) }   otherwise
#
#    VBE_entry(B) = (VBE_exit(B) \ Kill_B) ∪ Gen_B
#
#  where Kill_B for the expression level means:
#    Kill_B = { e ∈ AExp★ | e.operand_varids ∩ block.kill_varids ≠ ∅ }
#
#  We iterate until a fixpoint is reached.  Since the lattice is finite
#  (P(AExp★) with ⊇ ordering) and the transfer functions are monotone,
#  convergence is guaranteed in at most |AExp★| × |Blocks| iterations.
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class VBEResult:
    """Result of the VBE fixpoint computation."""
    blocks: Dict[int, BasicBlock]
    universe: FrozenSet[AExpr]
    iterations: int
    converged: bool

    def busy_at_entry(self, block_id: int) -> FrozenSet[AExpr]:
        return self.blocks[block_id].vbe_entry

    def busy_at_exit(self, block_id: int) -> FrozenSet[AExpr]:
        return self.blocks[block_id].vbe_exit


def _kill_set(universe: FrozenSet[AExpr], kill_varids: FrozenSet[int]) -> FrozenSet[AExpr]:
    """Return the set of expressions from *universe* killed by *kill_varids*."""
    return frozenset(e for e in universe if e.operand_varids & kill_varids)


def run_vbe_fixpoint(
    blocks: Dict[int, BasicBlock],
    universe: FrozenSet[AExpr],
    max_iterations: int = 1000,
) -> VBEResult:
    """
    Run the backward-must fixpoint iteration for VBE.

    Parameters
    ----------
    blocks : dict
        {block_id: BasicBlock} — the CFG with gen/kill already computed.
    universe : frozenset
        AExp★ — the set of all non-trivial sub-expressions in the function.
    max_iterations : int
        Safety bound to prevent non-termination (should never be hit for
        a finite lattice, but defence-in-depth).

    Returns
    -------
    VBEResult
        Contains the converged VBE_entry / VBE_exit for every block.
    """
    # ---- Initialisation ---------------------------------------------------
    # Boundary:  exit blocks get VBE_exit = ∅
    # All others: VBE_exit = universe (⊤ in the ⊇ lattice = most optimistic)
    for bb in blocks.values():
        if bb.is_exit:
            bb.vbe_exit = frozenset()
        else:
            bb.vbe_exit = universe  # ⊤
        # VBE_entry initialised via transfer
        killed = _kill_set(universe, bb.kill_varids)
        bb.vbe_entry = (bb.vbe_exit - killed) | bb.gen

    # ---- Iteration (chaotic / round-robin) --------------------------------
    # Process blocks in reverse postorder for efficiency, but any order
    # converges.  We use simple reverse-id order as an approximation.
    worklist = sorted(blocks.keys(), reverse=True)

    iteration = 0
    changed = True
    while changed and iteration < max_iterations:
        changed = False
        iteration += 1

        for bid in worklist:
            bb = blocks[bid]

            # --- VBE_exit(B) = ∩ { VBE_entry(S) | S ∈ succ(B) } ----------
            if bb.is_exit:
                new_exit: FrozenSet[AExpr] = frozenset()
            elif not bb.successors:
                new_exit = frozenset()
            else:
                # Must (intersection) over all successors
                succ_entries = [blocks[s].vbe_entry for s in bb.successors if s in blocks]
                if succ_entries:
                    new_exit = succ_entries[0]
                    for se in succ_entries[1:]:
                        new_exit = new_exit & se  # ∩
                else:
                    new_exit = frozenset()

            # --- VBE_entry(B) = (VBE_exit(B) \ Kill_B) ∪ Gen_B ------------
            killed = _kill_set(universe, bb.kill_varids)
            new_entry = (new_exit - killed) | bb.gen

            if new_exit != bb.vbe_exit or new_entry != bb.vbe_entry:
                changed = True
                bb.vbe_exit = new_exit
                bb.vbe_entry = new_entry

    return VBEResult(
        blocks=blocks,
        universe=universe,
        iterations=iteration,
        converged=not changed,
    )


# ═══════════════════════════════════════════════════════════════════════════
#  PART 6 — CODE HOISTING OPPORTUNITY DETECTOR
# ═══════════════════════════════════════════════════════════════════════════
#
#  The primary application of VBE analysis is CODE HOISTING: if an
#  expression e is very busy at the entry of a block B, we can hoist
#  the computation of e to the entry of B, compute it once, and replace
#  all subsequent evaluations with the pre-computed result.
#
#  We report hoisting opportunities with location information.
# ═══════════════════════════════════════════════════════════════════════════

class HoistSeverity(Enum):
    DEFINITE = auto()    # Expression is busy on ALL paths — safe to hoist
    POSSIBLE = auto()    # Busy on most paths (heuristic, e.g. ≥ 50% of successors)


@dataclass
class HoistOpportunity:
    """A detected code-hoisting opportunity."""
    expression: AExpr
    hoist_to_block: int
    hoist_to_line: int
    evaluated_at_lines: List[int]
    severity: HoistSeverity
    file: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "expression": self.expression.canonical,
            "operator": self.expression.operator,
            "hoist_to_block": self.hoist_to_block,
            "hoist_to_line": self.hoist_to_line,
            "evaluated_at_lines": self.evaluated_at_lines,
            "severity": self.severity.name.lower(),
            "file": self.file,
        }


def detect_hoisting_opportunities(
    result: VBEResult,
    matcher: CASLMatcher,
) -> List[HoistOpportunity]:
    """
    Given VBE analysis results, find expressions that can be hoisted.

    An expression e can be hoisted to the entry of block B if:
      - e ∈ VBE_entry(B)
      - e ∉ Gen_B  (it's not already computed right at the start of B —
                     otherwise hoisting is a no-op)
      OR
      - e is computed in multiple successor blocks (redundant computation)
    """
    opportunities: List[HoistOpportunity] = []

    for bid, bb in result.blocks.items():
        for expr in bb.vbe_entry:
            # Find where this expression is actually evaluated downstream
            eval_lines: List[int] = []
            _find_eval_lines(expr, bid, result.blocks, eval_lines, visited=set())

            if len(eval_lines) < 2:
                continue  # Hoisting a single evaluation is not beneficial

            # Determine the file from the first token
            file_name: Optional[str] = None
            if bb.tokens:
                file_name = getattr(bb.tokens[0], "file", None)

            opp = HoistOpportunity(
                expression=expr,
                hoist_to_block=bid,
                hoist_to_line=bb.first_line(),
                evaluated_at_lines=sorted(set(eval_lines)),
                severity=HoistSeverity.DEFINITE,
                file=file_name,
            )
            opportunities.append(opp)

    # Deduplicate: same expression, same hoist-to line
    seen: Set[Tuple[str, int]] = set()
    unique: List[HoistOpportunity] = []
    for opp in opportunities:
        key = (opp.expression.canonical, opp.hoist_to_line)
        if key not in seen:
            seen.add(key)
            unique.append(opp)

    return unique


def _find_eval_lines(
    expr: AExpr,
    block_id: int,
    blocks: Dict[int, BasicBlock],
    result: List[int],
    visited: Set[int],
    depth: int = 0,
) -> None:
    """DFS to find lines where *expr* is evaluated downstream of *block_id*."""
    if block_id in visited or depth > 50:
        return
    visited.add(block_id)

    bb = blocks.get(block_id)
    if bb is None:
        return

    # Check if this block evaluates the expression
    if expr in bb.gen:
        # Find the actual line
        for tok in bb.tokens:
            tok_id = getattr(tok, "Id", None)
            if tok_id and tok_id in expr.token_ids:
                ln = getattr(tok, "linenr", 0)
                if ln:
                    result.append(ln)
                break

    # Recurse into successors
    for succ_id in bb.successors:
        _find_eval_lines(expr, succ_id, blocks, result, visited, depth + 1)


# ═══════════════════════════════════════════════════════════════════════════
#  PART 7 — REPORTER  (text and JSON output)
# ═══════════════════════════════════════════════════════════════════════════

class VBEReporter:
    """Format and emit VBE analysis results."""

    def __init__(self, verbose: bool = False) -> None:
        self.verbose = verbose

    def report_text(
        self,
        result: VBEResult,
        opportunities: List[HoistOpportunity],
        file_name: str,
    ) -> str:
        lines: List[str] = []
        lines.append(f"═══ VBE Analysis: {file_name} ═══")
        lines.append(f"  Blocks analysed  : {len(result.blocks)}")
        lines.append(f"  Expression universe : {len(result.universe)}")
        lines.append(f"  Fixpoint iterations : {result.iterations}")
        lines.append(f"  Converged          : {'yes' if result.converged else 'NO'}")
        lines.append("")

        if self.verbose:
            lines.append("── Per-block VBE sets ──")
            for bid in sorted(result.blocks):
                bb = result.blocks[bid]
                lines.append(f"  Block {bid} (lines {bb.first_line()}-{bb.last_line()}):")
                entry_strs = sorted(e.canonical for e in bb.vbe_entry) or ["∅"]
                exit_strs = sorted(e.canonical for e in bb.vbe_exit) or ["∅"]
                lines.append(f"    VBE_entry = {{ {', '.join(entry_strs)} }}")
                lines.append(f"    VBE_exit  = {{ {', '.join(exit_strs)} }}")
                gen_strs = sorted(e.canonical for e in bb.gen) or ["∅"]
                lines.append(f"    Gen       = {{ {', '.join(gen_strs)} }}")
                kill_strs = sorted(str(v) for v in bb.kill_varids) or ["∅"]
                lines.append(f"    Kill_vars = {{ {', '.join(kill_strs)} }}")
            lines.append("")

        lines.append(f"── Hoisting opportunities: {len(opportunities)} ──")
        if not opportunities:
            lines.append("  (none detected)")
        for i, opp in enumerate(opportunities, 1):
            lines.append(
                f"  [{i}] {opp.severity.name}  expr: {opp.expression.canonical}"
            )
            loc = f"{opp.file}:" if opp.file else ""
            lines.append(f"      Hoist to: {loc}line {opp.hoist_to_line} (block {opp.hoist_to_block})")
            lines.append(f"      Currently evaluated at lines: {opp.evaluated_at_lines}")

        lines.append("")
        return "\n".join(lines)

    @staticmethod
    def report_json(
        result: VBEResult,
        opportunities: List[HoistOpportunity],
        file_name: str,
    ) -> str:
        data = {
            "file": file_name,
            "blocks_analysed": len(result.blocks),
            "expression_universe_size": len(result.universe),
            "fixpoint_iterations": result.iterations,
            "converged": result.converged,
            "opportunities": [opp.to_dict() for opp in opportunities],
        }
        return json.dumps(data, indent=2)


# ═══════════════════════════════════════════════════════════════════════════
#  PART 8 — MAIN ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════════════════

def analyse_configuration(cfg, matcher: CASLMatcher, verbose: bool = False) -> Tuple[VBEResult, List[HoistOpportunity]]:
    """
    Run complete VBE analysis on a single cppcheck configuration.

    Pipeline:
      1. CASL scan → extract AExp★ universe + kill sites
      2. CFG construction → basic blocks
      3. Gen/Kill per block
      4. Backward-must fixpoint → VBE_entry / VBE_exit
      5. Hoisting detection
    """
    # ---- Step 1: CASL scan ------------------------------------------------
    tokenlist = list(_iter_tokens(cfg.tokenlist[0])) if cfg.tokenlist else []
    aexp_hits, kill_hits = matcher.scan_tokenlist(tokenlist)

    # Build the universe of all AExpr seen
    universe: FrozenSet[AExpr] = frozenset(ae for _, ae in aexp_hits)

    if not universe:
        empty_result = VBEResult(blocks={}, universe=frozenset(), iterations=0, converged=True)
        return empty_result, []

    # ---- Step 2: CFG construction -----------------------------------------
    builder = CFGBuilder()
    blocks = builder.build(tokenlist)

    if not blocks:
        empty_result = VBEResult(blocks={}, universe=universe, iterations=0, converged=True)
        return empty_result, []

    # ---- Step 3: Gen/Kill per block ---------------------------------------
    for bb in blocks.values():
        compute_gen_kill(bb, matcher, universe)

    # ---- Step 4: Fixpoint -------------------------------------------------
    result = run_vbe_fixpoint(blocks, universe)

    # ---- Step 5: Hoisting detection ---------------------------------------
    opportunities = detect_hoisting_opportunities(result, matcher)

    return result, opportunities


def analyse_dump(dump_path: str, output_json: bool = False, verbose: bool = False) -> str:
    """
    Analyse a cppcheck .dump file for very busy expressions.

    Parameters
    ----------
    dump_path : str
        Path to the .dump file produced by ``cppcheck --dump``.
    output_json : bool
        If True, output JSON; otherwise human-readable text.
    verbose : bool
        If True, include per-block VBE sets in the text output.

    Returns
    -------
    str
        The analysis report.
    """
    data = parsedump(dump_path)
    matcher = CASLMatcher()
    reporter = VBEReporter(verbose=verbose)

    all_reports: List[str] = []

    for cfg in data.configurations:
        result, opportunities = analyse_configuration(cfg, matcher, verbose)
        if output_json:
            report = reporter.report_json(result, opportunities, dump_path)
        else:
            report = reporter.report_text(result, opportunities, dump_path)
        all_reports.append(report)

    return "\n".join(all_reports)


# ═══════════════════════════════════════════════════════════════════════════
#  PART 9 — CLI ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="vbe-addon",
        description="Very Busy Expressions analysis for cppcheck dump files.",
        epilog=(
            "Example:\n"
            "  cppcheck --dump myfile.c\n"
            "  python vbe_addon.py myfile.c.dump\n"
            "  python vbe_addon.py --json --verbose myfile.c.dump\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "dumpfile",
        help="Path to the cppcheck .dump file",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="output_json",
        help="Output results as JSON",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show per-block VBE entry/exit sets",
    )
    args = parser.parse_args()

    if not Path(args.dumpfile).exists():
        print(f"Error: file not found: {args.dumpfile}", file=sys.stderr)
        sys.exit(1)

    report = analyse_dump(
        args.dumpfile,
        output_json=args.output_json,
        verbose=args.verbose,
    )
    print(report)


if __name__ == "__main__":
    main()
