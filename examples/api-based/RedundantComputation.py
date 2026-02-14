#!/usr/bin/env python3
"""
RedundantComputation.py — A Cppcheck addon that detects redundant computations
using the cppcheckdata-shims library for CFG construction, data-flow analysis,
abstract interpretation, and symbolic execution.

Usage:
    python RedundantComputation.py [--verbose] [--json] [--severity=all|perf|style]
          <file1.dump> [<file2.dump> ...]

Detected patterns:
    RC01  Fully redundant subexpression (available-expressions analysis)
    RC02  Redundant conditional test (dominated by identical guard)
    RC03  Redundant assignment (same LHS = same RHS, no intervening modification)
    RC04  Loop-invariant computation (expression with loop-invariant operands)
    RC05  Redundant pure function call (same args, callee has no side-effects)
    RC06  Dead store followed by identical recomputation

Architecture:
    Phase 1 — Token walk: collect expression sites, assignments, conditions
    Phase 2 — CFG construction + dominance analysis
    Phase 3 — Available-expressions data-flow (forward, must-analysis)
    Phase 4 — Loop-invariant detection (natural-loop identification + reaching-defs)
    Phase 5 — Pure-function modelling + redundant-call detection
    Phase 6 — Report consolidation and emission
"""

from __future__ import annotations

import sys
import os
import argparse
import json
import time
import hashlib
from typing import (
    Dict, List, Set, Tuple, Optional, FrozenSet, NamedTuple, Sequence,
    Iterator, Any, DefaultDict,
)
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path

# ---------------------------------------------------------------------------
# Lazy import of cppcheckdata and shims
# ---------------------------------------------------------------------------

def _import_cppcheckdata():
    """Import cppcheckdata, adjusting sys.path if needed."""
    try:
        import cppcheckdata
        return cppcheckdata
    except ImportError:
        # Try Cppcheck's default addon directory
        for candidate in (
            Path("/usr/share/cppcheck/addons"),
            Path("/usr/local/share/cppcheck/addons"),
            Path.home() / ".local" / "share" / "cppcheck" / "addons",
        ):
            if (candidate / "cppcheckdata.py").exists():
                sys.path.insert(0, str(candidate))
                import cppcheckdata
                return cppcheckdata
        raise SystemExit(
            "error: cannot locate cppcheckdata.py; "
            "install Cppcheck or set PYTHONPATH"
        )


def _import_shims():
    """Import all cppcheckdata-shims modules."""
    # We import lazily so --help is fast
    from cppcheckdata_shims import ctrlflow_graph as cfg_mod
    from cppcheckdata_shims import ctrlflow_analysis as cfa_mod
    from cppcheckdata_shims import dataflow_analysis as dfa_mod
    from cppcheckdata_shims import dataflow_engine as dfe_mod
    from cppcheckdata_shims import abstract_domains as ad_mod
    from cppcheckdata_shims import abstract_interp as ai_mod
    from cppcheckdata_shims import callgraph as cg_mod
    from cppcheckdata_shims import memory_abstraction as ma_mod
    from cppcheckdata_shims import type_analysis as ta_mod
    from cppcheckdata_shims import symbolic_exec as se_mod
    from cppcheckdata_shims import constraint_engine as ce_mod
    from cppcheckdata_shims import checkers as chk_mod

    return SimpleNamespace(
        cfg=cfg_mod,
        cfa=cfa_mod,
        dfa=dfa_mod,
        dfe=dfe_mod,
        ad=ad_mod,
        ai=ai_mod,
        cg=cg_mod,
        ma=ma_mod,
        ta=ta_mod,
        se=se_mod,
        ce=ce_mod,
        chk=chk_mod,
    )


class SimpleNamespace:
    """Minimal namespace to bundle shim modules."""
    def __init__(self, **kw):
        self.__dict__.update(kw)


# ═══════════════════════════════════════════════════════════════════════════
# Data Structures
# ═══════════════════════════════════════════════════════════════════════════

class Severity(Enum):
    ERROR = "error"
    WARNING = "warning"
    STYLE = "style"
    PERFORMANCE = "performance"
    INFORMATION = "information"


@dataclass(frozen=True)
class ExprFingerprint:
    """
    A canonical, structure-preserving fingerprint of an expression.

    We normalise by:
    - Sorting commutative operands lexicographically
    - Stripping whitespace
    - Recording operand variable IDs rather than names (handles renaming)

    The fingerprint is a string suitable for hashing and equality testing.
    """
    canonical: str            # e.g. "var:3 + var:7"
    operand_var_ids: FrozenSet[int]  # set of cppcheckdata Variable.Id values
    original_text: str        # pretty-printed source text
    is_pure_call: bool = False
    callee_name: str = ""

    def __hash__(self):
        return hash(self.canonical)

    def __eq__(self, other):
        if not isinstance(other, ExprFingerprint):
            return NotImplemented
        return self.canonical == other.canonical


@dataclass
class ExprSite:
    """A concrete occurrence of an expression in the source."""
    fingerprint: ExprFingerprint
    token: Any              # cppcheckdata Token
    file: str
    line: int
    column: int
    scope_id: int           # enclosing function/scope
    cfg_block_id: Optional[int] = None
    in_loop: bool = False
    loop_header_block: Optional[int] = None


@dataclass
class Assignment:
    """An assignment statement x = expr."""
    lhs_var_id: int
    lhs_name: str
    rhs_fingerprint: ExprFingerprint
    token: Any
    file: str
    line: int
    column: int
    cfg_block_id: Optional[int] = None


@dataclass
class Condition:
    """A branch condition."""
    fingerprint: ExprFingerprint
    token: Any
    file: str
    line: int
    column: int
    cfg_block_id: Optional[int] = None
    is_loop_condition: bool = False


class RuleID(Enum):
    RC01 = "RC01"
    RC02 = "RC02"
    RC03 = "RC03"
    RC04 = "RC04"
    RC05 = "RC05"
    RC06 = "RC06"


@dataclass
class Diagnostic:
    """A single diagnostic message."""
    rule: RuleID
    severity: Severity
    file: str
    line: int
    column: int
    message: str
    first_occurrence_line: Optional[int] = None
    first_occurrence_file: Optional[str] = None
    expression_text: str = ""
    cwe: Optional[int] = None

    def to_cppcheck_json(self) -> dict:
        result = {
            "errorId": f"redundantComputation.{self.rule.value}",
            "severity": self.severity.value,
            "message": self.message,
            "location": [
                {"file": self.file, "linenr": self.line, "column": self.column},
            ],
        }
        if self.first_occurrence_line is not None:
            result["location"].append({
                "file": self.first_occurrence_file or self.file,
                "linenr": self.first_occurrence_line,
                "column": 0,
                "info": "expression first computed here",
            })
        if self.cwe is not None:
            result["cwe"] = self.cwe
        return result

    def to_gcc_string(self) -> str:
        sev = self.severity.value
        loc = f"{self.file}:{self.line}:{self.column}"
        tag = f"[{self.rule.value}]"
        first = ""
        if self.first_occurrence_line is not None:
            first_file = self.first_occurrence_file or self.file
            first = f"\n{first_file}:{self.first_occurrence_line}: note: expression first computed here"
        return f"{loc}: {sev}: {self.message} {tag}{first}"


# ═══════════════════════════════════════════════════════════════════════════
# Phase 1 — Expression & Event Collection (Token Walk)
# ═══════════════════════════════════════════════════════════════════════════

# Set of operators known to be commutative for normalisation
_COMMUTATIVE_OPS = frozenset({"+", "*", "&", "|", "^", "==", "!=", "&&", "||"})

# Set of functions known to be pure (no side effects, deterministic)
_KNOWN_PURE_FUNCTIONS = frozenset({
    "strlen", "strcmp", "strncmp", "memcmp",
    "abs", "fabs", "labs", "llabs",
    "sqrt", "cbrt", "pow", "exp", "log", "log2", "log10",
    "sin", "cos", "tan", "asin", "acos", "atan", "atan2",
    "ceil", "floor", "round", "trunc",
    "isdigit", "isalpha", "isalnum", "isspace", "isupper", "islower",
    "toupper", "tolower",
    "min", "max",
    "sizeof",
    "offsetof",
    "htons", "htonl", "ntohs", "ntohl",
})


def _token_str(tok) -> str:
    """Get the string value of a token."""
    return tok.str if hasattr(tok, 'str') else str(tok)


def _token_var_id(tok) -> Optional[int]:
    """Get the variable ID from a token, or None."""
    vid = getattr(tok, 'varId', None) or getattr(tok, 'variableId', None)
    if vid and int(vid) != 0:
        return int(vid)
    return None


def _token_scope_id(tok) -> int:
    """Get the enclosing scope's ID."""
    scope = getattr(tok, 'scope', None)
    if scope is not None:
        return int(getattr(scope, 'Id', 0) or 0)
    return 0


def _is_assignment_op(tok) -> bool:
    s = _token_str(tok)
    return s in ("=", "+=", "-=", "*=", "/=", "%=", "<<=", ">>=", "&=", "|=", "^=")


def _is_binary_arith_or_cmp(tok) -> bool:
    s = _token_str(tok)
    return s in (
        "+", "-", "*", "/", "%",
        "==", "!=", "<", "<=", ">", ">=",
        "&&", "||", "&", "|", "^",
        "<<", ">>",
    )


class ExpressionCollector:
    """
    Walk all tokens in a translation unit and extract:
    - Non-trivial expressions (binary ops, function calls)
    - Assignments
    - Conditions (if / while / for / ternary)

    Builds ExprFingerprints that canonicalise commutative operands.
    """

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.expr_sites: List[ExprSite] = []
        self.assignments: List[Assignment] = []
        self.conditions: List[Condition] = []
        self._var_name_cache: Dict[int, str] = {}

    # --- fingerprinting ------------------------------------------------

    def _fingerprint_token_tree(self, tok) -> Tuple[str, Set[int]]:
        """
        Recursively fingerprint the AST rooted at `tok`.
        Returns (canonical_string, set_of_var_ids).
        """
        if tok is None:
            return ("", set())

        s = _token_str(tok)
        vid = _token_var_id(tok)

        # Leaf: variable
        if vid is not None:
            self._var_name_cache[vid] = s
            return (f"var:{vid}", {vid})

        # Leaf: literal
        ast_op = getattr(tok, 'astOperand1', None)
        ast_op2 = getattr(tok, 'astOperand2', None)
        if ast_op is None and ast_op2 is None:
            # number or string literal
            return (f"lit:{s}", set())

        # Function call: name(args)
        if s == "(" and ast_op is not None:
            callee_str = _token_str(ast_op)
            callee_vid = _token_var_id(ast_op)
            if callee_vid is None and callee_str not in ("(", "[", ".", "->"):
                # It's a named function call
                args_fp, args_vars = self._fingerprint_token_tree(ast_op2)
                return (f"call:{callee_str}({args_fp})", args_vars)

        # Comma in argument lists
        if s == ",":
            left_fp, left_vars = self._fingerprint_token_tree(ast_op)
            right_fp, right_vars = self._fingerprint_token_tree(ast_op2)
            return (f"{left_fp},{right_fp}", left_vars | right_vars)

        # Binary operator
        if ast_op is not None and ast_op2 is not None:
            left_fp, left_vars = self._fingerprint_token_tree(ast_op)
            right_fp, right_vars = self._fingerprint_token_tree(ast_op2)
            all_vars = left_vars | right_vars

            # Normalise commutative ops by sorting operands
            if s in _COMMUTATIVE_OPS:
                parts = sorted([left_fp, right_fp])
                return (f"({parts[0]} {s} {parts[1]})", all_vars)
            else:
                return (f"({left_fp} {s} {right_fp})", all_vars)

        # Unary operator
        if ast_op is not None and ast_op2 is None:
            child_fp, child_vars = self._fingerprint_token_tree(ast_op)
            return (f"(u{s} {child_fp})", child_vars)
        if ast_op is None and ast_op2 is not None:
            child_fp, child_vars = self._fingerprint_token_tree(ast_op2)
            return (f"({s}u {child_fp})", child_vars)

        return (f"?{s}?", set())

    def _make_fingerprint(self, tok) -> ExprFingerprint:
        canonical, var_ids = self._fingerprint_token_tree(tok)
        # Reconstruct original text (approximate)
        original = self._reconstruct_text(tok)
        # Check if it's a pure call
        s = _token_str(tok)
        is_pure = False
        callee = ""
        if s == "(":
            op1 = getattr(tok, 'astOperand1', None)
            if op1 is not None:
                callee = _token_str(op1)
                if callee in _KNOWN_PURE_FUNCTIONS:
                    is_pure = True
        return ExprFingerprint(
            canonical=canonical,
            operand_var_ids=frozenset(var_ids),
            original_text=original,
            is_pure_call=is_pure,
            callee_name=callee,
        )

    def _reconstruct_text(self, tok, depth: int = 0) -> str:
        """Best-effort reconstruction of source text from AST."""
        if tok is None or depth > 20:
            return ""
        s = _token_str(tok)
        op1 = getattr(tok, 'astOperand1', None)
        op2 = getattr(tok, 'astOperand2', None)
        if op1 is None and op2 is None:
            return s
        if s == "(":
            callee = self._reconstruct_text(op1, depth + 1) if op1 else ""
            args = self._reconstruct_text(op2, depth + 1) if op2 else ""
            return f"{callee}({args})"
        if s == ",":
            left = self._reconstruct_text(op1, depth + 1)
            right = self._reconstruct_text(op2, depth + 1)
            return f"{left}, {right}"
        if op1 and op2:
            left = self._reconstruct_text(op1, depth + 1)
            right = self._reconstruct_text(op2, depth + 1)
            return f"{left} {s} {right}"
        if op1:
            child = self._reconstruct_text(op1, depth + 1)
            return f"{s}{child}"
        if op2:
            child = self._reconstruct_text(op2, depth + 1)
            return f"{s}{child}"
        return s

    # --- token walk ----------------------------------------------------

    def collect(self, cfg_data) -> None:
        """
        Walk all tokens in `cfg_data` (a CppcheckData configuration).
        """
        tok = cfg_data.tokenlist[0] if cfg_data.tokenlist else None

        while tok is not None:
            self._visit_token(tok, cfg_data)
            tok = tok.next

    def _visit_token(self, tok, cfg_data) -> None:
        s = _token_str(tok)
        file_ = getattr(tok, 'file', '<unknown>')
        line = int(getattr(tok, 'linenr', 0) or 0)
        col = int(getattr(tok, 'column', 0) or 0)
        scope_id = _token_scope_id(tok)

        # --- Binary expression (not assignment) ---
        op1 = getattr(tok, 'astOperand1', None)
        op2 = getattr(tok, 'astOperand2', None)

        if _is_binary_arith_or_cmp(tok) and op1 is not None and op2 is not None:
            fp = self._make_fingerprint(tok)
            # Only record non-trivial expressions
            if len(fp.operand_var_ids) > 0 or fp.is_pure_call:
                self.expr_sites.append(ExprSite(
                    fingerprint=fp,
                    token=tok,
                    file=file_,
                    line=line,
                    column=col,
                    scope_id=scope_id,
                ))

        # --- Function calls ---
        if s == "(" and op1 is not None:
            callee = _token_str(op1)
            callee_vid = _token_var_id(op1)
            if callee_vid is None and callee not in ("(", "[", ".", "->", ""):
                fp = self._make_fingerprint(tok)
                if fp.is_pure_call:
                    self.expr_sites.append(ExprSite(
                        fingerprint=fp,
                        token=tok,
                        file=file_,
                        line=line,
                        column=col,
                        scope_id=scope_id,
                    ))

        # --- Assignments ---
        if _is_assignment_op(tok) and op1 is not None and op2 is not None:
            lhs_vid = _token_var_id(op1)
            if lhs_vid is not None:
                rhs_fp = self._make_fingerprint(op2)
                self.assignments.append(Assignment(
                    lhs_var_id=lhs_vid,
                    lhs_name=_token_str(op1),
                    rhs_fingerprint=rhs_fp,
                    token=tok,
                    file=file_,
                    line=line,
                    column=col,
                ))

        # --- Conditions ---
        parent = getattr(tok, 'astParent', None)
        if parent is not None:
            ps = _token_str(parent)
            if ps in ("if", "while", "for", "?"):
                # tok is the condition expression of a control structure
                parent_op1 = getattr(parent, 'astOperand1', None)
                if parent_op1 is tok or (
                    ps == "for" and getattr(parent, 'astOperand2', None) is tok
                ):
                    fp = self._make_fingerprint(tok)
                    if len(fp.operand_var_ids) > 0:
                        is_loop = ps in ("while", "for")
                        self.conditions.append(Condition(
                            fingerprint=fp,
                            token=tok,
                            file=file_,
                            line=line,
                            column=col,
                            is_loop_condition=is_loop,
                        ))

    def summary(self) -> str:
        return (
            f"Collected: {len(self.expr_sites)} expression sites, "
            f"{len(self.assignments)} assignments, "
            f"{len(self.conditions)} conditions"
        )


# ═══════════════════════════════════════════════════════════════════════════
# Phase 2 — CFG + Dominance Construction
# ═══════════════════════════════════════════════════════════════════════════

class CFGManager:
    """
    Build and cache CFGs for each function scope.
    Computes dominance trees and natural loops.
    """

    def __init__(self, shims, verbose: bool = False):
        self.shims = shims
        self.verbose = verbose
        self._cfg_cache: Dict[int, Any] = {}       # scope_id -> CFG
        self._dom_cache: Dict[int, Any] = {}        # scope_id -> dominator tree
        self._loops_cache: Dict[int, List] = {}     # scope_id -> list of natural loops
        self._block_map_cache: Dict[int, Dict] = {} # scope_id -> {token_id: block_id}

    def get_cfg(self, scope) -> Optional[Any]:
        sid = int(getattr(scope, 'Id', 0) or 0)
        if sid in self._cfg_cache:
            return self._cfg_cache[sid]
        try:
            g = self.shims.cfg.build_cfg(scope)
            self._cfg_cache[sid] = g
            if self.verbose:
                n_blocks = len(g.blocks) if hasattr(g, 'blocks') else '?'
                print(f"  [CFG] scope {sid}: {n_blocks} blocks", file=sys.stderr)
            return g
        except Exception as exc:
            if self.verbose:
                print(f"  [CFG] scope {sid}: failed ({exc})", file=sys.stderr)
            self._cfg_cache[sid] = None
            return None

    def get_dominators(self, scope) -> Optional[Any]:
        sid = int(getattr(scope, 'Id', 0) or 0)
        if sid in self._dom_cache:
            return self._dom_cache[sid]
        g = self.get_cfg(scope)
        if g is None:
            self._dom_cache[sid] = None
            return None
        try:
            dom = self.shims.cfa.compute_dominators(g)
            self._dom_cache[sid] = dom
            return dom
        except Exception as exc:
            if self.verbose:
                print(f"  [DOM] scope {sid}: failed ({exc})", file=sys.stderr)
            self._dom_cache[sid] = None
            return None

    def get_natural_loops(self, scope) -> List:
        sid = int(getattr(scope, 'Id', 0) or 0)
        if sid in self._loops_cache:
            return self._loops_cache[sid]
        g = self.get_cfg(scope)
        dom = self.get_dominators(scope)
        if g is None or dom is None:
            self._loops_cache[sid] = []
            return []
        try:
            loops = self.shims.cfa.find_natural_loops(g, dom)
            self._loops_cache[sid] = loops
            if self.verbose:
                print(f"  [LOOPS] scope {sid}: {len(loops)} natural loops",
                      file=sys.stderr)
            return loops
        except Exception as exc:
            if self.verbose:
                print(f"  [LOOPS] scope {sid}: failed ({exc})", file=sys.stderr)
            self._loops_cache[sid] = []
            return []

    def get_block_for_token(self, scope, tok) -> Optional[int]:
        """Map a token to its CFG basic-block ID."""
        sid = int(getattr(scope, 'Id', 0) or 0)
        if sid not in self._block_map_cache:
            g = self.get_cfg(scope)
            if g is None:
                self._block_map_cache[sid] = {}
            else:
                mapping = {}
                for blk in (g.blocks if hasattr(g, 'blocks') else []):
                    blk_id = getattr(blk, 'id', None) or id(blk)
                    for t in (getattr(blk, 'tokens', None) or []):
                        tid = getattr(t, 'Id', None) or id(t)
                        mapping[tid] = blk_id
                self._block_map_cache[sid] = mapping
        tid = getattr(tok, 'Id', None) or id(tok)
        return self._block_map_cache[sid].get(tid)


# ═══════════════════════════════════════════════════════════════════════════
# Phase 3 — Available Expressions Analysis (RC01, RC05)
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class AvailableExprLattice:
    """
    Lattice for Available Expressions:
    - ⊤ = all expressions available (intersection identity)
    - ⊥ = no expressions available
    - Meet = set intersection
    - Direction: forward

    Element: frozenset of ExprFingerprint
    """
    universe: FrozenSet[ExprFingerprint]

    @property
    def top(self) -> FrozenSet[ExprFingerprint]:
        return self.universe

    @property
    def bottom(self) -> FrozenSet[ExprFingerprint]:
        return frozenset()

    def meet(self, a: FrozenSet[ExprFingerprint],
             b: FrozenSet[ExprFingerprint]) -> FrozenSet[ExprFingerprint]:
        return a & b

    def leq(self, a: FrozenSet[ExprFingerprint],
            b: FrozenSet[ExprFingerprint]) -> bool:
        """a ⊑ b  iff  a ⊆ b  (more available = higher)."""
        return a <= b


class AvailableExprAnalysis:
    """
    Classical forward must-analysis for available expressions.

    Gen(B)  = set of expressions computed in B whose operands are not
              subsequently killed in B
    Kill(B) = set of expressions containing a variable defined in B

    Transfer: out(B) = Gen(B) ∪ (in(B) − Kill(B))

    At confluence (meet): intersection (must be available on ALL paths).
    """

    def __init__(
        self,
        shims,
        cfg_manager: CFGManager,
        expr_sites: List[ExprSite],
        assignments: List[Assignment],
        scope,
        verbose: bool = False,
    ):
        self.shims = shims
        self.cfg_mgr = cfg_manager
        self.scope = scope
        self.verbose = verbose

        # Group expr_sites and assignments by block
        self.block_exprs: DefaultDict[int, List[ExprSite]] = defaultdict(list)
        self.block_assigns: DefaultDict[int, List[Assignment]] = defaultdict(list)
        self.all_fingerprints: Set[ExprFingerprint] = set()

        sid = int(getattr(scope, 'Id', 0) or 0)
        for es in expr_sites:
            if es.scope_id == sid:
                blk = cfg_manager.get_block_for_token(scope, es.token)
                if blk is not None:
                    es.cfg_block_id = blk
                    self.block_exprs[blk].append(es)
                    self.all_fingerprints.add(es.fingerprint)

        for asn in assignments:
            scope_of_asn = _token_scope_id(asn.token)
            if scope_of_asn == sid:
                blk = cfg_manager.get_block_for_token(scope, asn.token)
                if blk is not None:
                    asn.cfg_block_id = blk
                    self.block_assigns[blk].append(asn)

        self.universe = frozenset(self.all_fingerprints)
        self.lattice = AvailableExprLattice(self.universe)

    def _gen_kill(self, block_id: int) -> Tuple[FrozenSet[ExprFingerprint],
                                                  FrozenSet[ExprFingerprint]]:
        """Compute Gen and Kill sets for a basic block."""
        # Variables defined in this block
        defined_vars: Set[int] = set()
        for asn in self.block_assigns[block_id]:
            defined_vars.add(asn.lhs_var_id)

        # Kill: any expression that mentions a variable defined here
        kill: Set[ExprFingerprint] = set()
        for fp in self.universe:
            if fp.operand_var_ids & defined_vars:
                kill.add(fp)

        # Gen: expressions computed here whose operands are not killed
        # after the computation (within the same block)
        # Simplified: we treat the block atomically — if an expr is
        # computed AND its operands are defined, it's still generated
        # (the definition may come before the use).
        # For precision, we'd need intra-block ordering.
        gen: Set[ExprFingerprint] = set()
        for es in self.block_exprs[block_id]:
            fp = es.fingerprint
            # If no operand of this expression is defined AFTER this
            # expression within the block, it is generated.
            # Approximation: if operand is defined at all in block, be conservative
            if not (fp.operand_var_ids & defined_vars):
                gen.add(fp)

        return frozenset(gen), frozenset(kill)

    def solve(self) -> Dict[int, FrozenSet[ExprFingerprint]]:
        """
        Run the Available Expressions fixed-point iteration.
        Returns: {block_id: set of available expressions at block entry}
        """
        g = self.cfg_mgr.get_cfg(self.scope)
        if g is None or not self.universe:
            return {}

        blocks = list(g.blocks) if hasattr(g, 'blocks') else []
        if not blocks:
            return {}

        block_ids = [getattr(b, 'id', None) or id(b) for b in blocks]
        entry_id = block_ids[0] if block_ids else None

        # Predecessor map
        preds: DefaultDict[int, List[int]] = defaultdict(list)
        succs: DefaultDict[int, List[int]] = defaultdict(list)
        for b in blocks:
            bid = getattr(b, 'id', None) or id(b)
            for s in (getattr(b, 'successors', None) or []):
                sid_ = getattr(s, 'id', None) or id(s)
                succs[bid].append(sid_)
                preds[sid_].append(bid)

        # Pre-compute gen/kill
        gen_kill: Dict[int, Tuple[FrozenSet, FrozenSet]] = {}
        for bid in block_ids:
            gen_kill[bid] = self._gen_kill(bid)

        # Initialise: entry → ⊥, all others → ⊤
        avail_in: Dict[int, FrozenSet[ExprFingerprint]] = {}
        avail_out: Dict[int, FrozenSet[ExprFingerprint]] = {}
        for bid in block_ids:
            if bid == entry_id:
                avail_in[bid] = self.lattice.bottom
            else:
                avail_in[bid] = self.lattice.top
            gen_b, kill_b = gen_kill[bid]
            avail_out[bid] = gen_b | (avail_in[bid] - kill_b)

        # Worklist (RPO for efficiency)
        worklist = deque(block_ids)
        in_worklist = set(block_ids)
        iterations = 0
        max_iters = len(block_ids) * len(self.universe) + 100

        while worklist and iterations < max_iters:
            iterations += 1
            bid = worklist.popleft()
            in_worklist.discard(bid)

            # Meet over predecessors
            if bid == entry_id:
                new_in = self.lattice.bottom
            else:
                pred_outs = [avail_out[p] for p in preds[bid] if p in avail_out]
                if not pred_outs:
                    new_in = self.lattice.bottom
                else:
                    new_in = pred_outs[0]
                    for po in pred_outs[1:]:
                        new_in = self.lattice.meet(new_in, po)

            if new_in != avail_in[bid]:
                avail_in[bid] = new_in
                gen_b, kill_b = gen_kill[bid]
                new_out = gen_b | (new_in - kill_b)
                if new_out != avail_out[bid]:
                    avail_out[bid] = new_out
                    for s in succs[bid]:
                        if s not in in_worklist:
                            worklist.append(s)
                            in_worklist.add(s)

        if self.verbose:
            sid = int(getattr(self.scope, 'Id', 0) or 0)
            print(f"  [AE] scope {sid}: converged in {iterations} iterations",
                  file=sys.stderr)

        return avail_in

    def find_redundant(self) -> List[Diagnostic]:
        """
        After solving, find expressions that are computed at a point where
        they are already available.
        """
        avail_in = self.solve()
        if not avail_in:
            return []

        diagnostics: List[Diagnostic] = []
        # Track first occurrence of each fingerprint for the note
        first_seen: Dict[ExprFingerprint, ExprSite] = {}
        for es in sorted(
            [e for elist in self.block_exprs.values() for e in elist],
            key=lambda e: (e.file, e.line, e.column),
        ):
            if es.fingerprint not in first_seen:
                first_seen[es.fingerprint] = es

        for block_id, avail_set in avail_in.items():
            for es in self.block_exprs.get(block_id, []):
                if es.fingerprint in avail_set:
                    first = first_seen.get(es.fingerprint)
                    if first is not None and (first.line != es.line or first.file != es.file):
                        rule = RuleID.RC05 if es.fingerprint.is_pure_call else RuleID.RC01
                        sev = Severity.PERFORMANCE
                        if es.fingerprint.is_pure_call:
                            msg = (
                                f"redundant call to pure function "
                                f"'{es.fingerprint.callee_name}' — result already "
                                f"available from line {first.line}"
                            )
                        else:
                            msg = (
                                f"redundant computation of '{es.fingerprint.original_text}'"
                                f" — value already available from line {first.line}"
                            )
                        diagnostics.append(Diagnostic(
                            rule=rule,
                            severity=sev,
                            file=es.file,
                            line=es.line,
                            column=es.column,
                            message=msg,
                            first_occurrence_line=first.line,
                            first_occurrence_file=first.file,
                            expression_text=es.fingerprint.original_text,
                        ))

        return diagnostics


# ═══════════════════════════════════════════════════════════════════════════
# Phase 4 — Redundant Condition Detection (RC02)
# ═══════════════════════════════════════════════════════════════════════════

class RedundantConditionDetector:
    """
    Detect conditions that are redundant because:
    1. An identical condition dominates the current one (nested if-if), OR
    2. The condition was already tested and the result is known on this path.

    Uses the dominator tree: if condition C is at block B, and an identical
    condition C' is at a dominator block D, and no operand of C is modified
    between D and B, then C is redundant.
    """

    def __init__(
        self,
        shims,
        cfg_manager: CFGManager,
        conditions: List[Condition],
        assignments: List[Assignment],
        scope,
        verbose: bool = False,
    ):
        self.shims = shims
        self.cfg_mgr = cfg_manager
        self.scope = scope
        self.verbose = verbose
        self.conditions = [
            c for c in conditions
            if _token_scope_id(c.token) == int(getattr(scope, 'Id', 0) or 0)
        ]
        self.assignments = assignments

    def find_redundant(self) -> List[Diagnostic]:
        diagnostics: List[Diagnostic] = []
        dom = self.cfg_mgr.get_dominators(self.scope)
        if dom is None:
            return diagnostics

        # Assign blocks to conditions
        for cond in self.conditions:
            blk = self.cfg_mgr.get_block_for_token(self.scope, cond.token)
            cond.cfg_block_id = blk

        # For each pair of conditions with same fingerprint
        by_fp: DefaultDict[ExprFingerprint, List[Condition]] = defaultdict(list)
        for c in self.conditions:
            by_fp[c.fingerprint].append(c)

        # Get variables defined per block
        sid = int(getattr(self.scope, 'Id', 0) or 0)
        defs_per_block: DefaultDict[int, Set[int]] = defaultdict(set)
        for asn in self.assignments:
            asn_sid = _token_scope_id(asn.token)
            if asn_sid == sid and asn.cfg_block_id is not None:
                defs_per_block[asn.cfg_block_id].add(asn.lhs_var_id)

        for fp, conds in by_fp.items():
            if len(conds) < 2:
                continue
            # Sort by line
            conds.sort(key=lambda c: (c.file, c.line))
            for i, c2 in enumerate(conds):
                if c2.cfg_block_id is None:
                    continue
                for c1 in conds[:i]:
                    if c1.cfg_block_id is None:
                        continue
                    # Check if c1's block dominates c2's block
                    if self._dominates(dom, c1.cfg_block_id, c2.cfg_block_id):
                        # Check no operand killed between c1 and c2
                        if not self._operand_killed_on_path(
                            dom, c1.cfg_block_id, c2.cfg_block_id,
                            fp.operand_var_ids, defs_per_block
                        ):
                            diagnostics.append(Diagnostic(
                                rule=RuleID.RC02,
                                severity=Severity.WARNING,
                                file=c2.file,
                                line=c2.line,
                                column=c2.column,
                                message=(
                                    f"redundant condition "
                                    f"'{fp.original_text}' — "
                                    f"already tested at line {c1.line} "
                                    f"which dominates this point"
                                ),
                                first_occurrence_line=c1.line,
                                first_occurrence_file=c1.file,
                                expression_text=fp.original_text,
                            ))
                            break  # Only report once per dominated condition

        return diagnostics

    def _dominates(self, dom, a: int, b: int) -> bool:
        """Check if block a dominates block b using the dominator tree."""
        try:
            return self.shims.cfa.dominates(dom, a, b)
        except (AttributeError, TypeError):
            # Fallback: walk idom chain
            idom = getattr(dom, 'idom', {})
            if isinstance(idom, dict):
                cur = b
                visited = set()
                while cur is not None and cur not in visited:
                    if cur == a:
                        return True
                    visited.add(cur)
                    cur = idom.get(cur)
            return False

    def _operand_killed_on_path(
        self, dom, src_block: int, dst_block: int,
        operand_vars: FrozenSet[int],
        defs_per_block: DefaultDict[int, Set[int]],
    ) -> bool:
        """
        Conservative check: walk the dominator chain from dst up to src
        and see if any block on the path defines an operand variable.
        """
        idom = getattr(dom, 'idom', {})
        if not isinstance(idom, dict):
            return True  # conservative
        cur = dst_block
        visited = set()
        while cur is not None and cur != src_block and cur not in visited:
            visited.add(cur)
            if defs_per_block[cur] & operand_vars:
                return True
            cur = idom.get(cur)
        return False


# ═══════════════════════════════════════════════════════════════════════════
# Phase 5 — Redundant Assignment Detection (RC03, RC06)
# ═══════════════════════════════════════════════════════════════════════════

class RedundantAssignmentDetector:
    """
    Detect:
    RC03 — Same variable assigned the exact same expression twice with no
           intervening modification of the variable or its RHS operands,
           and no intervening use of the variable.
    RC06 — Dead store: variable assigned, never used before being reassigned
           with the same expression (the first store was wasted).
    """

    def __init__(
        self,
        shims,
        cfg_manager: CFGManager,
        assignments: List[Assignment],
        expr_sites: List[ExprSite],
        scope,
        verbose: bool = False,
    ):
        self.shims = shims
        self.cfg_mgr = cfg_manager
        self.scope = scope
        self.verbose = verbose
        sid = int(getattr(scope, 'Id', 0) or 0)
        self.assignments = [
            a for a in assignments
            if _token_scope_id(a.token) == sid
        ]
        self.expr_sites = [
            e for e in expr_sites
            if e.scope_id == sid
        ]

    def find_redundant(self) -> List[Diagnostic]:
        diagnostics: List[Diagnostic] = []

        # Group assignments by (lhs_var_id, rhs_fingerprint)
        by_key: DefaultDict[
            Tuple[int, ExprFingerprint], List[Assignment]
        ] = defaultdict(list)
        for asn in self.assignments:
            by_key[(asn.lhs_var_id, asn.rhs_fingerprint)].append(asn)

        for (var_id, rhs_fp), asns in by_key.items():
            if len(asns) < 2:
                continue
            asns.sort(key=lambda a: (a.file, a.line))

            for i in range(1, len(asns)):
                prev = asns[i - 1]
                curr = asns[i]

                # Check if any operand (including the LHS var itself)
                # is modified between prev and curr
                if self._var_or_operand_modified_between(
                    prev, curr, var_id, rhs_fp.operand_var_ids
                ):
                    continue

                # Check if the variable is used between the two assignments
                var_used = self._var_used_between(prev, curr, var_id)

                if var_used:
                    # RC03: redundant assignment (value was used, but
                    # reassigned the same thing)
                    diagnostics.append(Diagnostic(
                        rule=RuleID.RC03,
                        severity=Severity.STYLE,
                        file=curr.file,
                        line=curr.line,
                        column=curr.column,
                        message=(
                            f"redundant assignment: '{curr.lhs_name} = "
                            f"{rhs_fp.original_text}' — identical assignment "
                            f"at line {prev.line} with no intervening modification"
                        ),
                        first_occurrence_line=prev.line,
                        first_occurrence_file=prev.file,
                        expression_text=f"{curr.lhs_name} = {rhs_fp.original_text}",
                    ))
                else:
                    # RC06: dead store — first assignment never used
                    diagnostics.append(Diagnostic(
                        rule=RuleID.RC06,
                        severity=Severity.WARNING,
                        file=prev.file,
                        line=prev.line,
                        column=prev.column,
                        message=(
                            f"dead store: '{prev.lhs_name} = "
                            f"{rhs_fp.original_text}' at line {prev.line} is "
                            f"never used before being reassigned at line {curr.line}"
                        ),
                        first_occurrence_line=curr.line,
                        first_occurrence_file=curr.file,
                        expression_text=f"{prev.lhs_name} = {rhs_fp.original_text}",
                    ))

        return diagnostics

    def _var_or_operand_modified_between(
        self, prev: Assignment, curr: Assignment,
        var_id: int, operand_vars: FrozenSet[int],
    ) -> bool:
        """
        Walk tokens between prev and curr to see if var_id or any
        operand variable is assigned.
        """
        check_vars = {var_id} | set(operand_vars)
        tok = prev.token.next if hasattr(prev.token, 'next') else None
        curr_id = getattr(curr.token, 'Id', None) or id(curr.token)
        limit = 5000  # safety bound
        count = 0
        while tok is not None and count < limit:
            tid = getattr(tok, 'Id', None) or id(tok)
            if tid == curr_id:
                break
            # Check if this token is an assignment to a watched variable
            if _is_assignment_op(tok):
                op1 = getattr(tok, 'astOperand1', None)
                if op1 is not None:
                    vid = _token_var_id(op1)
                    if vid in check_vars:
                        return True
            # Also check ++ / --
            s = _token_str(tok)
            if s in ("++", "--"):
                op1 = getattr(tok, 'astOperand1', None)
                if op1 is not None:
                    vid = _token_var_id(op1)
                    if vid in check_vars:
                        return True
            tok = tok.next
            count += 1
        return False

    def _var_used_between(
        self, prev: Assignment, curr: Assignment, var_id: int
    ) -> bool:
        """Check if var_id is read between prev and curr assignments."""
        tok = prev.token.next if hasattr(prev.token, 'next') else None
        curr_id = getattr(curr.token, 'Id', None) or id(curr.token)
        limit = 5000
        count = 0
        while tok is not None and count < limit:
            tid = getattr(tok, 'Id', None) or id(tok)
            if tid == curr_id:
                break
            vid = _token_var_id(tok)
            if vid == var_id:
                # Check it's not the LHS of an assignment
                parent = getattr(tok, 'astParent', None)
                if parent is not None and _is_assignment_op(parent):
                    p_op1 = getattr(parent, 'astOperand1', None)
                    p_op1_id = getattr(p_op1, 'Id', None) or id(p_op1) if p_op1 else None
                    tok_id_here = getattr(tok, 'Id', None) or id(tok)
                    if p_op1_id == tok_id_here:
                        tok = tok.next
                        count += 1
                        continue
                return True
            tok = tok.next
            count += 1
        return False


# ═══════════════════════════════════════════════════════════════════════════
# Phase 6 — Loop-Invariant Computation Detection (RC04)
# ═══════════════════════════════════════════════════════════════════════════

class LoopInvariantDetector:
    """
    Detect computations inside loops where all operands are loop-invariant.

    An expression e inside loop L is loop-invariant if:
    - All variable operands of e have reaching definitions only from
      outside L, OR
    - All variable operands are themselves defined by loop-invariant
      computations (transitive closure).

    We use the natural-loop identification from Phase 2 and a simple
    reaching-definitions approximation.
    """

    def __init__(
        self,
        shims,
        cfg_manager: CFGManager,
        expr_sites: List[ExprSite],
        assignments: List[Assignment],
        scope,
        verbose: bool = False,
    ):
        self.shims = shims
        self.cfg_mgr = cfg_manager
        self.scope = scope
        self.verbose = verbose
        sid = int(getattr(scope, 'Id', 0) or 0)
        self.expr_sites = [e for e in expr_sites if e.scope_id == sid]
        self.assignments = [
            a for a in assignments
            if _token_scope_id(a.token) == sid
        ]

    def find_loop_invariant(self) -> List[Diagnostic]:
        diagnostics: List[Diagnostic] = []
        loops = self.cfg_mgr.get_natural_loops(self.scope)
        if not loops:
            return diagnostics

        for loop in loops:
            loop_blocks = set()
            header = None
            if hasattr(loop, 'header'):
                header = getattr(loop.header, 'id', None) or id(loop.header)
            if hasattr(loop, 'body_blocks'):
                for b in loop.body_blocks:
                    loop_blocks.add(getattr(b, 'id', None) or id(b))
            elif hasattr(loop, 'blocks'):
                for b in loop.blocks:
                    loop_blocks.add(getattr(b, 'id', None) or id(b))
            if header is not None:
                loop_blocks.add(header)

            if not loop_blocks:
                continue

            # Variables defined inside the loop
            vars_defined_in_loop: Set[int] = set()
            for asn in self.assignments:
                if asn.cfg_block_id in loop_blocks:
                    vars_defined_in_loop.add(asn.lhs_var_id)

            # Find expressions in the loop whose operands are NOT
            # defined inside the loop
            for es in self.expr_sites:
                if es.cfg_block_id not in loop_blocks:
                    continue
                if not es.fingerprint.operand_var_ids:
                    continue
                # All operands must be loop-invariant (not modified in loop)
                if not (es.fingerprint.operand_var_ids & vars_defined_in_loop):
                    # This expression is loop-invariant!
                    msg = (
                        f"loop-invariant computation: "
                        f"'{es.fingerprint.original_text}' — all operands are "
                        f"unchanged within the loop; consider hoisting"
                    )
                    diagnostics.append(Diagnostic(
                        rule=RuleID.RC04,
                        severity=Severity.PERFORMANCE,
                        file=es.file,
                        line=es.line,
                        column=es.column,
                        message=msg,
                        expression_text=es.fingerprint.original_text,
                    ))

        return diagnostics


# ═══════════════════════════════════════════════════════════════════════════
# Main Checker — Orchestrator
# ═══════════════════════════════════════════════════════════════════════════

class RedundantComputationChecker:
    """
    Top-level orchestrator that runs all six detection passes
    and consolidates results.
    """

    RULE_DESCRIPTIONS = {
        RuleID.RC01: "Fully redundant subexpression",
        RuleID.RC02: "Redundant conditional test",
        RuleID.RC03: "Redundant assignment",
        RuleID.RC04: "Loop-invariant computation",
        RuleID.RC05: "Redundant pure function call",
        RuleID.RC06: "Dead store followed by identical recomputation",
    }

    def __init__(
        self,
        verbose: bool = False,
        json_output: bool = False,
        severity_filter: str = "all",
        enabled_rules: Optional[Set[str]] = None,
    ):
        self.verbose = verbose
        self.json_output = json_output
        self.severity_filter = severity_filter
        self.enabled_rules = enabled_rules  # None means all
        self.diagnostics: List[Diagnostic] = []
        self.stats: Dict[str, Any] = {
            "files_analyzed": 0,
            "functions_analyzed": 0,
            "expressions_collected": 0,
            "diagnostics_total": 0,
            "by_rule": defaultdict(int),
            "time_seconds": 0.0,
        }

    def run(self, dump_files: List[str]) -> int:
        """Analyze all dump files. Returns exit code (0 = clean, 1 = findings)."""
        t0 = time.monotonic()

        cppcheckdata = _import_cppcheckdata()

        # Try to import shims; fall back to lightweight mode
        try:
            shims = _import_shims()
            have_shims = True
        except ImportError as exc:
            if self.verbose:
                print(f"[warn] cppcheckdata-shims not available ({exc}); "
                      f"using lightweight token-walk-only mode",
                      file=sys.stderr)
            shims = None
            have_shims = False

        for dump_path in dump_files:
            if not os.path.isfile(dump_path):
                print(f"error: {dump_path}: file not found", file=sys.stderr)
                continue
            self._analyze_dump(dump_path, cppcheckdata, shims, have_shims)

        # De-duplicate diagnostics
        self._deduplicate()

        # Apply severity filter
        if self.severity_filter != "all":
            allowed = set()
            if "perf" in self.severity_filter:
                allowed.add(Severity.PERFORMANCE)
            if "style" in self.severity_filter:
                allowed.add(Severity.STYLE)
            if "warn" in self.severity_filter:
                allowed.add(Severity.WARNING)
            if "error" in self.severity_filter:
                allowed.add(Severity.ERROR)
            if allowed:
                self.diagnostics = [d for d in self.diagnostics if d.severity in allowed]

        # Apply rule filter
        if self.enabled_rules is not None:
            rule_set = {RuleID(r) for r in self.enabled_rules if r in RuleID.__members__}
            self.diagnostics = [d for d in self.diagnostics if d.rule in rule_set]

        # Sort diagnostics
        self.diagnostics.sort(key=lambda d: (d.file, d.line, d.column, d.rule.value))

        # Update stats
        self.stats["diagnostics_total"] = len(self.diagnostics)
        for d in self.diagnostics:
            self.stats["by_rule"][d.rule.value] += 1
        self.stats["time_seconds"] = time.monotonic() - t0

        # Emit output
        self._emit()

        return 1 if self.diagnostics else 0

    def _analyze_dump(self, dump_path: str, cppcheckdata, shims, have_shims: bool):
        """Analyze a single .dump file."""
        self.stats["files_analyzed"] += 1
        if self.verbose:
            print(f"\n{'='*60}", file=sys.stderr)
            print(f"Analyzing: {dump_path}", file=sys.stderr)
            print(f"{'='*60}", file=sys.stderr)

        try:
            data = cppcheckdata.CppcheckData(dump_path)
        except Exception as exc:
            print(f"error: {dump_path}: failed to parse ({exc})", file=sys.stderr)
            return

        for cfg in data.configurations:
            if self.verbose:
                cfg_name = getattr(cfg, 'name', '<default>')
                print(f"\n--- Configuration: {cfg_name} ---", file=sys.stderr)

            # Phase 1: Collect
            collector = ExpressionCollector(verbose=self.verbose)
            collector.collect(cfg)
            if self.verbose:
                print(f"  {collector.summary()}", file=sys.stderr)
            self.stats["expressions_collected"] += len(collector.expr_sites)

            if not have_shims:
                # Lightweight mode: only token-walk-based checks
                self._lightweight_checks(collector)
                continue

            # Build CFG manager
            cfg_mgr = CFGManager(shims, verbose=self.verbose)

            # Iterate over function scopes
            for scope in (cfg.scopes or []):
                scope_type = getattr(scope, 'type', '')
                if scope_type not in ('Function', 'function'):
                    continue
                self.stats["functions_analyzed"] += 1

                # Assign blocks to all collected items for this scope
                sid = int(getattr(scope, 'Id', 0) or 0)
                for es in collector.expr_sites:
                    if es.scope_id == sid:
                        blk = cfg_mgr.get_block_for_token(scope, es.token)
                        es.cfg_block_id = blk
                for asn in collector.assignments:
                    if _token_scope_id(asn.token) == sid:
                        blk = cfg_mgr.get_block_for_token(scope, asn.token)
                        asn.cfg_block_id = blk

                # Phase 3: Available Expressions (RC01, RC05)
                if self._rule_enabled(RuleID.RC01) or self._rule_enabled(RuleID.RC05):
                    ae = AvailableExprAnalysis(
                        shims, cfg_mgr,
                        collector.expr_sites, collector.assignments,
                        scope, verbose=self.verbose,
                    )
                    self.diagnostics.extend(ae.find_redundant())

                # Phase 4: Redundant Conditions (RC02)
                if self._rule_enabled(RuleID.RC02):
                    rcd = RedundantConditionDetector(
                        shims, cfg_mgr,
                        collector.conditions, collector.assignments,
                        scope, verbose=self.verbose,
                    )
                    self.diagnostics.extend(rcd.find_redundant())

                # Phase 5: Redundant Assignments (RC03, RC06)
                if self._rule_enabled(RuleID.RC03) or self._rule_enabled(RuleID.RC06):
                    rad = RedundantAssignmentDetector(
                        shims, cfg_mgr,
                        collector.assignments, collector.expr_sites,
                        scope, verbose=self.verbose,
                    )
                    self.diagnostics.extend(rad.find_redundant())

                # Phase 6: Loop-Invariant (RC04)
                if self._rule_enabled(RuleID.RC04):
                    lid = LoopInvariantDetector(
                        shims, cfg_mgr,
                        collector.expr_sites, collector.assignments,
                        scope, verbose=self.verbose,
                    )
                    self.diagnostics.extend(lid.find_loop_invariant())

    def _lightweight_checks(self, collector: ExpressionCollector):
        """
        Fallback checks when shims are not available.
        Uses simple token-order heuristics.
        """
        # Simple RC03: consecutive identical assignments
        prev_asn: Dict[Tuple[int, str], Assignment] = {}
        for asn in sorted(collector.assignments, key=lambda a: (a.file, a.line)):
            key = (asn.lhs_var_id, asn.rhs_fingerprint.canonical)
            if key in prev_asn:
                prev = prev_asn[key]
                if prev.file == asn.file and (asn.line - prev.line) <= 10:
                    self.diagnostics.append(Diagnostic(
                        rule=RuleID.RC03,
                        severity=Severity.STYLE,
                        file=asn.file,
                        line=asn.line,
                        column=asn.column,
                        message=(
                            f"possibly redundant assignment: "
                            f"'{asn.lhs_name} = {asn.rhs_fingerprint.original_text}' "
                            f"— same assignment at line {prev.line}"
                        ),
                        first_occurrence_line=prev.line,
                        first_occurrence_file=prev.file,
                        expression_text=f"{asn.lhs_name} = {asn.rhs_fingerprint.original_text}",
                    ))
            prev_asn[key] = asn

        # Simple RC01: repeated expression in same scope within N lines
        prev_expr: Dict[Tuple[int, str], ExprSite] = {}
        for es in sorted(collector.expr_sites, key=lambda e: (e.file, e.line)):
            key = (es.scope_id, es.fingerprint.canonical)
            if key in prev_expr:
                prev = prev_expr[key]
                if prev.file == es.file and (es.line - prev.line) <= 20:
                    self.diagnostics.append(Diagnostic(
                        rule=RuleID.RC01,
                        severity=Severity.PERFORMANCE,
                        file=es.file,
                        line=es.line,
                        column=es.column,
                        message=(
                            f"possibly redundant expression: "
                            f"'{es.fingerprint.original_text}' "
                            f"— same expression at line {prev.line} "
                            f"(token-walk heuristic; use shims for CFG precision)"
                        ),
                        first_occurrence_line=prev.line,
                        first_occurrence_file=prev.file,
                        expression_text=es.fingerprint.original_text,
                    ))
            prev_expr[key] = es

    def _rule_enabled(self, rule: RuleID) -> bool:
        if self.enabled_rules is None:
            return True
        return rule.value in self.enabled_rules

    def _deduplicate(self):
        """Remove duplicate diagnostics (same rule, file, line)."""
        seen: Set[Tuple[str, str, int, int]] = set()
        unique: List[Diagnostic] = []
        for d in self.diagnostics:
            key = (d.rule.value, d.file, d.line, d.column)
            if key not in seen:
                seen.add(key)
                unique.append(d)
        self.diagnostics = unique

    def _emit(self):
        """Emit diagnostics to stdout."""
        if self.json_output:
            output = {
                "version": 1,
                "checker": "RedundantComputation",
                "stats": {
                    "files": self.stats["files_analyzed"],
                    "functions": self.stats["functions_analyzed"],
                    "expressions": self.stats["expressions_collected"],
                    "diagnostics": self.stats["diagnostics_total"],
                    "by_rule": dict(self.stats["by_rule"]),
                    "time_seconds": round(self.stats["time_seconds"], 3),
                },
                "diagnostics": [d.to_cppcheck_json() for d in self.diagnostics],
            }
            print(json.dumps(output, indent=2))
        else:
            for d in self.diagnostics:
                print(d.to_gcc_string())

            if self.verbose:
                print(f"\n--- Summary ---", file=sys.stderr)
                print(f"Files analyzed:       {self.stats['files_analyzed']}",
                      file=sys.stderr)
                print(f"Functions analyzed:   {self.stats['functions_analyzed']}",
                      file=sys.stderr)
                print(f"Expressions collected: {self.stats['expressions_collected']}",
                      file=sys.stderr)
                print(f"Diagnostics:          {self.stats['diagnostics_total']}",
                      file=sys.stderr)
                for rule, count in sorted(self.stats["by_rule"].items()):
                    desc = self.RULE_DESCRIPTIONS.get(RuleID(rule), "")
                    print(f"  {rule}: {count}  ({desc})", file=sys.stderr)
                print(f"Time:                 {self.stats['time_seconds']:.3f}s",
                      file=sys.stderr)


# ═══════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="RedundantComputation",
        description=(
            "Cppcheck addon: detect redundant computations using "
            "available-expression analysis, dominance, and loop-invariant detection."
        ),
        epilog=(
            "Rules:\n"
            "  RC01  Fully redundant subexpression\n"
            "  RC02  Redundant conditional test\n"
            "  RC03  Redundant assignment (same LHS = same RHS)\n"
            "  RC04  Loop-invariant computation\n"
            "  RC05  Redundant pure function call\n"
            "  RC06  Dead store followed by identical recomputation\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "dump_files", nargs="+", metavar="FILE.dump",
        help="Cppcheck dump file(s) to analyze",
    )
    p.add_argument(
        "--verbose", "-v", action="store_true",
        help="Print progress and debug info to stderr",
    )
    p.add_argument(
        "--json", dest="json_output", action="store_true",
        help="Emit JSON output instead of GCC-style diagnostics",
    )
    p.add_argument(
        "--severity", default="all",
        choices=["all", "perf", "style", "warn", "error"],
        help="Filter diagnostics by severity (default: all)",
    )
    p.add_argument(
        "--enable", dest="enable_rules", default=None,
        help="Comma-separated list of rules to enable (e.g., RC01,RC04)",
    )
    p.add_argument(
        "--disable", dest="disable_rules", default=None,
        help="Comma-separated list of rules to disable",
    )
    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # Compute enabled rules
    all_rules = {r.value for r in RuleID}
    enabled: Optional[Set[str]] = None

    if args.enable_rules:
        enabled = set(args.enable_rules.upper().split(",")) & all_rules
    if args.disable_rules:
        disabled = set(args.disable_rules.upper().split(","))
        if enabled is None:
            enabled = all_rules - disabled
        else:
            enabled -= disabled

    checker = RedundantComputationChecker(
        verbose=args.verbose,
        json_output=args.json_output,
        severity_filter=args.severity,
        enabled_rules=enabled,
    )
    return checker.run(args.dump_files)


if __name__ == "__main__":
    sys.exit(main())
