#!/usr/bin/env python3
"""
NullptrMisuseDetector.py — Cppcheck addon for detecting erroneous
usage of nullptr / NULL in C and C++ programs.

Usage:
    python NullptrMisuseDetector.py [--verbose] [--json] <file.dump> ...

Rules:
    NP01  Definite null dereference (pointer provably null at use)
    NP02  Dereference before null check
    NP03  Null-returning function result used without null check
    NP04  Redundant null check (pointer cannot be null)
    NP05  Null passed to non-null parameter
    NP06  Arithmetic on null pointer
    NP07  Null assigned then dereferenced (on all paths)
    NP08  Tautological double null check

Architecture:
    Phase 1 — Collection: walk tokens, extract dereferences,
              null checks, assignments, and call sites
    Phase 2 — CFG & Dominance: build control-flow graphs,
              dominator trees, post-dominator trees
    Phase 3 — Null-State Analysis: forward dataflow with a
              three-valued lattice {Null, NonNull, MaybeNull, Top}
    Phase 4 — Pattern Detection: match collected events against
              analysis results to produce diagnostics
    Phase 5 — Reporting: deduplicate and emit
"""

from __future__ import annotations

import sys
import os
import re
import argparse
import json
import time
from typing import (
    Dict, List, Set, Tuple, Optional, NamedTuple, Any,
    FrozenSet, DefaultDict, Iterator,
)
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path

# ═══════════════════════════════════════════════════════════════════════
# Lazy Imports
# ═══════════════════════════════════════════════════════════════════════

def _import_cppcheckdata():
    try:
        import cppcheckdata
        return cppcheckdata
    except ImportError:
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
    """Import cppcheckdata-shims modules (optional, for dataflow)."""
    class _NS:
        def __init__(self, **kw):
            self.__dict__.update(kw)
    try:
        from cppcheckdata_shims import ctrlflow_graph as cfg_mod
        from cppcheckdata_shims import ctrlflow_analysis as cfa_mod
        from cppcheckdata_shims import dataflow_analysis as dfa_mod
        from cppcheckdata_shims import dataflow_engine as dfe_mod
        from cppcheckdata_shims import abstract_domains as ad_mod
        from cppcheckdata_shims import abstract_interp as ai_mod
        from cppcheckdata_shims import type_analysis as ta_mod
        from cppcheckdata_shims import callgraph as cg_mod
        from cppcheckdata_shims import symbolic_exec as se_mod
        from cppcheckdata_shims import checkers as chk_mod
        return _NS(
            cfg=cfg_mod, cfa=cfa_mod, dfa=dfa_mod, dfe=dfe_mod,
            ad=ad_mod, ai=ai_mod, ta=ta_mod, cg=cg_mod,
            se=se_mod, chk=chk_mod,
        )
    except ImportError:
        return None


# ═══════════════════════════════════════════════════════════════════════
# Constants
# ═══════════════════════════════════════════════════════════════════════

# Functions that may return NULL
MAY_RETURN_NULL: Dict[str, str] = {
    # Allocation
    "malloc":        "memory allocation",
    "calloc":        "memory allocation",
    "realloc":       "memory reallocation",
    "aligned_alloc": "memory allocation",
    "strdup":        "string duplication",
    "strndup":       "string duplication",
    # I/O
    "fopen":   "file open",
    "freopen": "file reopen",
    "fdopen":  "file open",
    "tmpfile": "temp file creation",
    "popen":   "process open",
    # String search
    "strchr":   "character search",
    "strrchr":  "character search",
    "strstr":   "substring search",
    "strpbrk":  "character span search",
    "strtok":   "string tokenisation",
    "bsearch":  "binary search",
    # Environment / Locale
    "getenv":    "environment lookup",
    "setlocale": "locale setting",
    "tmpnam":    "temp name generation",
    # Dynamic loading
    "dlopen": "dynamic library loading",
    "dlsym":  "symbol lookup",
    # mmap (returns MAP_FAILED, not NULL, but often conflated)
    "mmap": "memory mapping",
}

# Functions whose parameters must not be null (name → set of 0-based param indices)
NON_NULL_PARAMS: Dict[str, Set[int]] = {
    "memcpy":  {0, 1},
    "memmove": {0, 1},
    "memset":  {0},
    "memcmp":  {0, 1},
    "strcpy":  {0, 1},
    "strncpy": {0, 1},
    "strcat":  {0, 1},
    "strncat": {0, 1},
    "strcmp":   {0, 1},
    "strncmp": {0, 1},
    "strlen":  {0},
    "printf":  {0},
    "fprintf": {0, 1},
    "sprintf": {0, 1},
    "snprintf": {0, 2},
    "fputs":   {0, 1},
    "puts":    {0},
    "fwrite":  {0, 3},
    "fread":   {0, 3},
    "fclose":  {0},
    "fflush":  {0},
    "free":    set(),       # free(NULL) is valid — intentionally empty
    "qsort":   {0, 3},
}

# Tokens that represent null
NULL_LITERALS: FrozenSet[str] = frozenset({
    "nullptr", "NULL", "0", "0L", "0LL",
    "0U", "0UL", "0ULL", "0x0", "0X0",
})


# ═══════════════════════════════════════════════════════════════════════
# Token Helpers
# ═══════════════════════════════════════════════════════════════════════

def _tok_str(tok) -> str:
    return tok.str if hasattr(tok, 'str') else str(tok)

def _tok_var_id(tok) -> Optional[int]:
    vid = getattr(tok, 'varId', None) or getattr(tok, 'variableId', None)
    if vid and int(vid) != 0:
        return int(vid)
    return None

def _tok_scope_id(tok) -> int:
    scope = getattr(tok, 'scope', None)
    return int(getattr(scope, 'Id', 0) or 0) if scope else 0

def _tok_file(tok) -> str:
    return getattr(tok, 'file', '<unknown>') or '<unknown>'

def _tok_line(tok) -> int:
    return int(getattr(tok, 'linenr', 0) or 0)

def _tok_col(tok) -> int:
    return int(getattr(tok, 'column', 0) or 0)

def _is_null_literal(tok) -> bool:
    """Check if a token is a null literal (nullptr, NULL, 0, etc.)."""
    s = _tok_str(tok)
    if s in NULL_LITERALS:
        return True
    # Check known int value == 0
    known = getattr(tok, 'getKnownIntValue', None)
    if known:
        v = known()
        if v is not None and v == 0:
            return True
    return False

def _token_is_pointer(tok) -> bool:
    """Check if token's valueType indicates a pointer."""
    vt = getattr(tok, 'valueType', None)
    if vt is None:
        return False
    return int(getattr(vt, 'pointer', 0) or 0) > 0

def _token_iter(cfg_data) -> Iterator:
    """Iterate through all tokens in a configuration."""
    tokenlist = getattr(cfg_data, 'tokenlist', [])
    if isinstance(tokenlist, list):
        for tok in tokenlist:
            yield tok
    else:
        tok = tokenlist
        while tok is not None:
            yield tok
            tok = tok.next


# ═══════════════════════════════════════════════════════════════════════
# Data Structures
# ═══════════════════════════════════════════════════════════════════════

class Severity(Enum):
    ERROR = "error"
    WARNING = "warning"
    STYLE = "style"
    PERFORMANCE = "performance"


class RuleID(Enum):
    NP01 = "NP01"
    NP02 = "NP02"
    NP03 = "NP03"
    NP04 = "NP04"
    NP05 = "NP05"
    NP06 = "NP06"
    NP07 = "NP07"
    NP08 = "NP08"


@dataclass
class Diagnostic:
    rule: RuleID
    severity: Severity
    file: str
    line: int
    column: int
    message: str
    var_name: str = ""
    cwe: Optional[int] = None

    def to_json(self) -> dict:
        r = {
            "errorId": f"nullptrMisuse.{self.rule.value}",
            "severity": self.severity.value,
            "message": self.message,
            "location": [{
                "file": self.file,
                "linenr": self.line,
                "column": self.column,
            }],
        }
        if self.cwe:
            r["cwe"] = self.cwe
        return r

    def to_gcc(self) -> str:
        loc = f"{self.file}:{self.line}:{self.column}"
        return f"{loc}: {self.severity.value}: {self.message} [{self.rule.value}]"


@dataclass
class DerefSite:
    """A dereference of a pointer variable."""
    token: Any
    var_id: int
    var_name: str
    file: str
    line: int
    column: int
    scope_id: int
    is_arrow: bool      # p->field (vs *p)
    is_array: bool      # p[i]


@dataclass
class NullCheck:
    """A comparison of a pointer against null."""
    token: Any          # the comparison operator token (== or !=)
    var_id: int
    var_name: str
    file: str
    line: int
    column: int
    scope_id: int
    is_eq_null: bool    # true if (p == NULL), false if (p != NULL)
    is_negation: bool   # true if (!p), maps to (p == NULL)


@dataclass
class NullAssignment:
    """An assignment of null to a pointer variable."""
    token: Any
    var_id: int
    var_name: str
    file: str
    line: int
    column: int
    scope_id: int


@dataclass
class NullReturnCall:
    """A call to a function that may return null."""
    call_token: Any
    func_name: str
    return_reason: str  # e.g., "memory allocation"
    assigned_var_id: Optional[int]
    assigned_var_name: str
    file: str
    line: int
    column: int
    scope_id: int


@dataclass
class NonNullArgPass:
    """Passing a possibly-null value to a non-null parameter."""
    call_token: Any
    func_name: str
    param_index: int     # 0-based
    arg_token: Any
    arg_var_id: Optional[int]
    arg_var_name: str
    file: str
    line: int
    column: int
    scope_id: int


# ═══════════════════════════════════════════════════════════════════════
# Null-State Lattice
# ═══════════════════════════════════════════════════════════════════════

class NullState(Enum):
    """
    Abstract null-state for a pointer variable.

        Top         ← unknown / uninitialized
        MaybeNull   ← could be null or non-null
       /         \
    Null        NonNull
       \         /
        Bottom      ← unreachable
    """
    BOTTOM = 0
    NULL = 1
    NONNULL = 2
    MAYBENULL = 3
    TOP = 4

    def join(self, other: 'NullState') -> 'NullState':
        if self == other:
            return self
        if self == NullState.BOTTOM:
            return other
        if other == NullState.BOTTOM:
            return self
        if self == NullState.TOP or other == NullState.TOP:
            return NullState.TOP
        # NULL ∨ NONNULL = MAYBENULL
        # NULL ∨ MAYBENULL = MAYBENULL
        # NONNULL ∨ MAYBENULL = MAYBENULL
        return NullState.MAYBENULL

    def meet(self, other: 'NullState') -> 'NullState':
        if self == other:
            return self
        if self == NullState.TOP:
            return other
        if other == NullState.TOP:
            return self
        if self == NullState.BOTTOM or other == NullState.BOTTOM:
            return NullState.BOTTOM
        if self == NullState.MAYBENULL:
            return other  # NULL or NONNULL
        if other == NullState.MAYBENULL:
            return self
        # NULL ∧ NONNULL = BOTTOM
        return NullState.BOTTOM

    def is_definitely_null(self) -> bool:
        return self == NullState.NULL

    def is_definitely_nonnull(self) -> bool:
        return self == NullState.NONNULL

    def may_be_null(self) -> bool:
        return self in (NullState.NULL, NullState.MAYBENULL, NullState.TOP)


# A mapping from variable ID → NullState
NullStateMap = Dict[int, NullState]


def _join_maps(a: NullStateMap, b: NullStateMap) -> NullStateMap:
    """Join two null-state maps (union of keys, join of values)."""
    result: NullStateMap = {}
    all_keys = set(a.keys()) | set(b.keys())
    for k in all_keys:
        va = a.get(k, NullState.BOTTOM)
        vb = b.get(k, NullState.BOTTOM)
        result[k] = va.join(vb)
    return result


def _maps_equal(a: NullStateMap, b: NullStateMap) -> bool:
    all_keys = set(a.keys()) | set(b.keys())
    for k in all_keys:
        if a.get(k, NullState.BOTTOM) != b.get(k, NullState.BOTTOM):
            return False
    return True


# ═══════════════════════════════════════════════════════════════════════
# Phase 1 — Event Collection (Token Walk)
# ═══════════════════════════════════════════════════════════════════════

class EventCollector:
    """
    Single-pass token walk to extract:
    - DerefSite: dereferences via *, ->, []
    - NullCheck: comparisons against null
    - NullAssignment: assignments of null to pointer vars
    - NullReturnCall: calls to may-return-null functions
    - NonNullArgPass: passing possibly-null to non-null params
    """

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.derefs: List[DerefSite] = []
        self.null_checks: List[NullCheck] = []
        self.null_assigns: List[NullAssignment] = []
        self.null_return_calls: List[NullReturnCall] = []
        self.nonnull_arg_passes: List[NonNullArgPass] = []

    def collect(self, cfg_data) -> None:
        for tok in _token_iter(cfg_data):
            self._visit(tok)

    def _visit(self, tok) -> None:
        s = _tok_str(tok)

        # ── Dereferences ─────────────────────────────────────────────
        # Unary * operator: *p
        if s == '*' and getattr(tok, 'astOperand1', None) is not None \
                and getattr(tok, 'astOperand2', None) is None:
            op1 = tok.astOperand1
            vid = _tok_var_id(op1)
            if vid and _token_is_pointer(op1):
                self.derefs.append(DerefSite(
                    token=tok, var_id=vid, var_name=_tok_str(op1),
                    file=_tok_file(tok), line=_tok_line(tok),
                    column=_tok_col(tok), scope_id=_tok_scope_id(tok),
                    is_arrow=False, is_array=False,
                ))

        # Arrow operator: p->field
        elif s == '.' and getattr(tok, 'originalName', None) == '->':
            op1 = getattr(tok, 'astOperand1', None)
            if op1:
                vid = _tok_var_id(op1)
                if vid and _token_is_pointer(op1):
                    self.derefs.append(DerefSite(
                        token=tok, var_id=vid, var_name=_tok_str(op1),
                        file=_tok_file(tok), line=_tok_line(tok),
                        column=_tok_col(tok), scope_id=_tok_scope_id(tok),
                        is_arrow=True, is_array=False,
                    ))

        # Array subscript: p[i] — the '[' token
        elif s == '[':
            op1 = getattr(tok, 'astOperand1', None)
            if op1:
                vid = _tok_var_id(op1)
                if vid and _token_is_pointer(op1):
                    self.derefs.append(DerefSite(
                        token=tok, var_id=vid, var_name=_tok_str(op1),
                        file=_tok_file(tok), line=_tok_line(tok),
                        column=_tok_col(tok), scope_id=_tok_scope_id(tok),
                        is_arrow=False, is_array=True,
                    ))

        # ── Null checks ──────────────────────────────────────────────
        # p == NULL, p != NULL, NULL == p, NULL != p
        elif s in ('==', '!='):
            op1 = getattr(tok, 'astOperand1', None)
            op2 = getattr(tok, 'astOperand2', None)
            if op1 and op2:
                ptr_tok, null_tok = None, None
                if _is_null_literal(op2) and _tok_var_id(op1):
                    ptr_tok, null_tok = op1, op2
                elif _is_null_literal(op1) and _tok_var_id(op2):
                    ptr_tok, null_tok = op2, op1

                if ptr_tok:
                    vid = _tok_var_id(ptr_tok)
                    if vid:
                        self.null_checks.append(NullCheck(
                            token=tok, var_id=vid,
                            var_name=_tok_str(ptr_tok),
                            file=_tok_file(tok), line=_tok_line(tok),
                            column=_tok_col(tok),
                            scope_id=_tok_scope_id(tok),
                            is_eq_null=(s == '=='),
                            is_negation=False,
                        ))

        # !p  (logical negation of pointer = null check)
        elif s == '!':
            op1 = getattr(tok, 'astOperand1', None)
            op2 = getattr(tok, 'astOperand2', None)
            if op1 and op2 is None:
                vid = _tok_var_id(op1)
                if vid and _token_is_pointer(op1):
                    self.null_checks.append(NullCheck(
                        token=tok, var_id=vid,
                        var_name=_tok_str(op1),
                        file=_tok_file(tok), line=_tok_line(tok),
                        column=_tok_col(tok),
                        scope_id=_tok_scope_id(tok),
                        is_eq_null=True,
                        is_negation=True,
                    ))

        # ── Null assignments ─────────────────────────────────────────
        elif s == '=' and not _tok_str(tok).startswith('=='):
            if getattr(tok, 'isAssignmentOp', False):
                op1 = getattr(tok, 'astOperand1', None)
                op2 = getattr(tok, 'astOperand2', None)
                if op1 and op2 and _is_null_literal(op2):
                    vid = _tok_var_id(op1)
                    if vid:
                        self.null_assigns.append(NullAssignment(
                            token=tok, var_id=vid,
                            var_name=_tok_str(op1),
                            file=_tok_file(tok), line=_tok_line(tok),
                            column=_tok_col(tok),
                            scope_id=_tok_scope_id(tok),
                        ))

        # ── Function calls ───────────────────────────────────────────
        elif s == '(':
            op1 = getattr(tok, 'astOperand1', None)
            if op1 is None:
                return
            callee = _tok_str(op1)

            # May-return-null call
            if callee in MAY_RETURN_NULL:
                # Find the LHS of the assignment, if any
                assigned_vid = None
                assigned_name = ""
                parent = getattr(tok, 'astParent', None)
                if parent and _tok_str(parent) == '=':
                    lhs = getattr(parent, 'astOperand1', None)
                    if lhs:
                        assigned_vid = _tok_var_id(lhs)
                        assigned_name = _tok_str(lhs)

                self.null_return_calls.append(NullReturnCall(
                    call_token=tok,
                    func_name=callee,
                    return_reason=MAY_RETURN_NULL[callee],
                    assigned_var_id=assigned_vid,
                    assigned_var_name=assigned_name,
                    file=_tok_file(tok), line=_tok_line(tok),
                    column=_tok_col(tok),
                    scope_id=_tok_scope_id(tok),
                ))

            # Non-null parameter check
            if callee in NON_NULL_PARAMS:
                required_indices = NON_NULL_PARAMS[callee]
                if not required_indices:
                    return  # e.g., free — no non-null params
                args = self._collect_args(tok)
                for idx in required_indices:
                    if idx >= len(args):
                        continue
                    arg_tok = args[idx]
                    if _is_null_literal(arg_tok):
                        vid = _tok_var_id(arg_tok)
                        self.nonnull_arg_passes.append(NonNullArgPass(
                            call_token=tok,
                            func_name=callee,
                            param_index=idx,
                            arg_token=arg_tok,
                            arg_var_id=vid,
                            arg_var_name=_tok_str(arg_tok),
                            file=_tok_file(tok), line=_tok_line(tok),
                            column=_tok_col(tok),
                            scope_id=_tok_scope_id(tok),
                        ))

    def _collect_args(self, call_tok) -> List[Any]:
        """Flatten comma-separated AST arguments."""
        args: List[Any] = []
        op2 = getattr(call_tok, 'astOperand2', None)
        if op2 is None:
            return args
        self._flatten_comma(op2, args)
        return args

    def _flatten_comma(self, tok, result: list):
        if tok is None:
            return
        if _tok_str(tok) == ',':
            self._flatten_comma(getattr(tok, 'astOperand1', None), result)
            self._flatten_comma(getattr(tok, 'astOperand2', None), result)
        else:
            result.append(tok)

    def summary(self) -> str:
        parts = [
            f"{len(self.derefs)} dereferences",
            f"{len(self.null_checks)} null checks",
            f"{len(self.null_assigns)} null assignments",
            f"{len(self.null_return_calls)} may-return-null calls",
            f"{len(self.nonnull_arg_passes)} non-null arg violations",
        ]
        return "Collected: " + ", ".join(parts)


# ═══════════════════════════════════════════════════════════════════════
# Phase 2 — CFG & Dominance (via shims)
# ═══════════════════════════════════════════════════════════════════════

class CFGManager:
    """
    Build and cache control-flow graphs, dominator trees, and
    post-dominator trees for each function scope.
    """

    def __init__(self, shims, verbose: bool = False):
        self.shims = shims
        self.verbose = verbose
        self._cfg_cache: Dict[int, Any] = {}
        self._dom_cache: Dict[int, Any] = {}
        self._postdom_cache: Dict[int, Any] = {}
        self._loop_cache: Dict[int, Any] = {}

    def get_cfg(self, scope):
        sid = int(getattr(scope, 'Id', 0) or 0)
        if sid not in self._cfg_cache:
            try:
                cfg = self.shims.cfg.build_cfg(scope)
                self._cfg_cache[sid] = cfg
            except Exception as exc:
                if self.verbose:
                    print(f"  [CFG] build failed for scope {sid}: {exc}",
                          file=sys.stderr)
                self._cfg_cache[sid] = None
        return self._cfg_cache[sid]

    def get_dominators(self, scope):
        sid = int(getattr(scope, 'Id', 0) or 0)
        if sid not in self._dom_cache:
            cfg = self.get_cfg(scope)
            if cfg is None:
                self._dom_cache[sid] = None
            else:
                try:
                    dom = self.shims.cfa.compute_dominators(cfg)
                    self._dom_cache[sid] = dom
                except Exception:
                    self._dom_cache[sid] = None
        return self._dom_cache[sid]

    def get_postdominators(self, scope):
        sid = int(getattr(scope, 'Id', 0) or 0)
        if sid not in self._postdom_cache:
            cfg = self.get_cfg(scope)
            if cfg is None:
                self._postdom_cache[sid] = None
            else:
                try:
                    pdom = self.shims.cfa.compute_post_dominators(cfg)
                    self._postdom_cache[sid] = pdom
                except Exception:
                    self._postdom_cache[sid] = None
        return self._postdom_cache[sid]

    def get_loops(self, scope):
        sid = int(getattr(scope, 'Id', 0) or 0)
        if sid not in self._loop_cache:
            cfg = self.get_cfg(scope)
            dom = self.get_dominators(scope)
            if cfg is None or dom is None:
                self._loop_cache[sid] = None
            else:
                try:
                    loops = self.shims.cfa.find_natural_loops(cfg, dom)
                    self._loop_cache[sid] = loops
                except Exception:
                    self._loop_cache[sid] = None
        return self._loop_cache[sid]

    def dominates(self, scope, node_a, node_b) -> bool:
        """Does node_a dominate node_b in scope's CFG?"""
        dom = self.get_dominators(scope)
        if dom is None:
            return False
        try:
            return self.shims.cfa.dominates(dom, node_a, node_b)
        except Exception:
            return False

    def post_dominates(self, scope, node_a, node_b) -> bool:
        """Does node_a post-dominate node_b?"""
        pdom = self.get_postdominators(scope)
        if pdom is None:
            return False
        try:
            return self.shims.cfa.dominates(pdom, node_a, node_b)
        except Exception:
            return False


# ═══════════════════════════════════════════════════════════════════════
# Phase 3 — Null-State Dataflow Analysis
# ═══════════════════════════════════════════════════════════════════════

class NullStateAnalysis:
    """
    Forward dataflow analysis with the NullState lattice.

    At each program point, computes a mapping var_id → NullState.

    Transfer function:
        - p = NULL / nullptr / 0   →  state[p] = NULL
        - p = malloc(...)          →  state[p] = MAYBENULL
        - p = &x / non-null expr   →  state[p] = NONNULL
        - p = q                    →  state[p] = state[q]
        - if (p != NULL) then-br   →  state[p] = NONNULL (on then edge)
        - if (p == NULL) then-br   →  state[p] = NULL (on then edge)
        - if (p) then-br           →  state[p] = NONNULL (on then edge)
        - *p / p-> / p[i]          →  no state change (but we read)

    Meet (join) at merge points: join operation from lattice.
    """

    def __init__(
        self,
        events: EventCollector,
        shims=None,
        cfg_manager: Optional[CFGManager] = None,
        verbose: bool = False,
    ):
        self.events = events
        self.shims = shims
        self.cfg_manager = cfg_manager
        self.verbose = verbose
        # Results: maps (scope_id, line) → NullStateMap
        self._state_at: Dict[Tuple[int, int], NullStateMap] = {}
        # Per-variable final states: var_id → NullState
        self._var_states: DefaultDict[int, NullState] = defaultdict(
            lambda: NullState.TOP
        )

    def run(self, cfg_data) -> None:
        """
        Run null-state analysis. If shims are available, use CFG-based
        forward dataflow. Otherwise, fall back to a simple token-walk
        approximation.
        """
        if self.shims and self.cfg_manager:
            self._run_cfg_based(cfg_data)
        else:
            self._run_simple(cfg_data)

    def state_at(self, var_id: int, scope_id: int, line: int) -> NullState:
        """Query the null-state of var_id at a specific program point."""
        key = (scope_id, line)
        m = self._state_at.get(key)
        if m:
            return m.get(var_id, NullState.TOP)
        return self._var_states.get(var_id, NullState.TOP)

    def _run_cfg_based(self, cfg_data):
        """Full CFG-based forward dataflow analysis."""
        scopes = getattr(cfg_data, 'scopes', None) or []
        for scope in scopes:
            scope_type = getattr(scope, 'type', '')
            if scope_type not in ('Function', 'function'):
                continue
            cfg = self.cfg_manager.get_cfg(scope)
            if cfg is None:
                continue
            self._analyze_function_cfg(scope, cfg)

    def _analyze_function_cfg(self, scope, cfg):
        """
        Worklist-based forward dataflow for one function.
        Uses the shims dataflow_engine if available.
        """
        sid = int(getattr(scope, 'Id', 0) or 0)

        try:
            # Try using the shims dataflow engine with a custom domain
            domain = self.shims.ad.MapLattice(
                key_type=int,
                value_lattice=self.shims.ad.FiniteLattice(
                    elements=['bottom', 'null', 'nonnull', 'maybenull', 'top'],
                    order=[
                        ('bottom', 'null'), ('bottom', 'nonnull'),
                        ('null', 'maybenull'), ('nonnull', 'maybenull'),
                        ('maybenull', 'top'),
                    ],
                ),
            )

            def transfer(node, state_in):
                state = dict(state_in)
                for tok in self._tokens_in_node(node):
                    self._apply_transfer(tok, state, sid)
                return state

            result = self.shims.dfe.forward_analysis(
                cfg=cfg,
                domain=domain,
                transfer=transfer,
                init={}
            )

            if result:
                for node, state in result.items():
                    for tok in self._tokens_in_node(node):
                        line = _tok_line(tok)
                        key = (sid, line)
                        mapped = {
                            k: self._lattice_elem_to_state(v)
                            for k, v in state.items()
                        }
                        self._state_at[key] = mapped
                return

        except (AttributeError, TypeError, Exception) as exc:
            if self.verbose:
                print(f"  [NULL-DF] shims engine failed ({exc}); "
                      f"using manual worklist", file=sys.stderr)

        # Manual worklist fallback
        self._manual_worklist(scope, cfg, sid)

    def _manual_worklist(self, scope, cfg, sid: int):
        """Manual worklist algorithm for null-state dataflow."""
        try:
            nodes = list(self.shims.cfg.cfg_nodes(cfg))
            succs = lambda n: list(self.shims.cfg.cfg_successors(cfg, n))
            preds = lambda n: list(self.shims.cfg.cfg_predecessors(cfg, n))
        except Exception:
            self._run_simple_for_scope(scope, sid)
            return

        # state_out[node] = NullStateMap
        state_out: Dict[Any, NullStateMap] = {n: {} for n in nodes}
        worklist = list(nodes)

        iterations = 0
        max_iter = len(nodes) * 5 + 100

        while worklist and iterations < max_iter:
            iterations += 1
            node = worklist.pop(0)

            # Compute state_in = join of predecessors' state_out
            pred_list = preds(node)
            if not pred_list:
                state_in: NullStateMap = {}
            else:
                state_in = dict(state_out[pred_list[0]])
                for p in pred_list[1:]:
                    state_in = _join_maps(state_in, state_out[p])

            # Apply transfer function
            state = dict(state_in)
            for tok in self._tokens_in_node(node):
                self._apply_transfer(tok, state, sid)
                line = _tok_line(tok)
                self._state_at[(sid, line)] = dict(state)

            # Check if state changed
            if not _maps_equal(state, state_out[node]):
                state_out[node] = state
                for s in succs(node):
                    if s not in worklist:
                        worklist.append(s)

    def _apply_transfer(self, tok, state: NullStateMap, sid: int):
        """Apply the transfer function for a single token."""
        s = _tok_str(tok)

        # Assignment: x = expr
        if s == '=' and getattr(tok, 'isAssignmentOp', False):
            op1 = getattr(tok, 'astOperand1', None)
            op2 = getattr(tok, 'astOperand2', None)
            if op1 and op2:
                lhs_vid = _tok_var_id(op1)
                if lhs_vid:
                    if _is_null_literal(op2):
                        state[lhs_vid] = NullState.NULL
                    elif _tok_str(op2) == '&':
                        # Address-of is always non-null
                        state[lhs_vid] = NullState.NONNULL
                    elif _tok_str(op2) == '(':
                        # Function call
                        callee_tok = getattr(op2, 'astOperand1', None)
                        if callee_tok:
                            callee = _tok_str(callee_tok)
                            if callee in MAY_RETURN_NULL:
                                state[lhs_vid] = NullState.MAYBENULL
                            else:
                                state[lhs_vid] = NullState.NONNULL
                        else:
                            state[lhs_vid] = NullState.TOP
                    else:
                        rhs_vid = _tok_var_id(op2)
                        if rhs_vid and rhs_vid in state:
                            state[lhs_vid] = state[rhs_vid]
                        elif _is_null_literal(op2):
                            state[lhs_vid] = NullState.NULL
                        else:
                            state[lhs_vid] = NullState.TOP

        # Record state at this line for later query
        line = _tok_line(tok)
        self._state_at[(sid, line)] = dict(state)

    def _tokens_in_node(self, node) -> List[Any]:
        """Extract tokens from a CFG node."""
        try:
            return list(self.shims.cfg.node_tokens(node))
        except Exception:
            tok = getattr(node, 'token', None)
            return [tok] if tok else []

    def _lattice_elem_to_state(self, elem) -> NullState:
        mapping = {
            'bottom': NullState.BOTTOM,
            'null': NullState.NULL,
            'nonnull': NullState.NONNULL,
            'maybenull': NullState.MAYBENULL,
            'top': NullState.TOP,
        }
        return mapping.get(str(elem), NullState.TOP)

    def _run_simple(self, cfg_data):
        """Fallback: simple forward token-walk approximation."""
        current_state: NullStateMap = {}
        current_scope = -1

        for tok in _token_iter(cfg_data):
            sid = _tok_scope_id(tok)
            if sid != current_scope:
                current_state = {}
                current_scope = sid

            self._apply_transfer(tok, current_state, sid)
            line = _tok_line(tok)
            self._state_at[(sid, line)] = dict(current_state)

        # Also populate _var_states with last known state
        for (sid, line), m in self._state_at.items():
            for vid, st in m.items():
                self._var_states[vid] = st

    def _run_simple_for_scope(self, scope, sid: int):
        """Simple token-walk for a single scope."""
        current_state: NullStateMap = {}
        class_token = getattr(scope, 'bodyStart', None) or \
                      getattr(scope, 'classStart', None)
        class_end = getattr(scope, 'bodyEnd', None) or \
                    getattr(scope, 'classEnd', None)
        if class_token is None:
            return
        tok = class_token
        while tok is not None and tok != class_end:
            self._apply_transfer(tok, current_state, sid)
            line = _tok_line(tok)
            self._state_at[(sid, line)] = dict(current_state)
            tok = tok.next


# ═══════════════════════════════════════════════════════════════════════
# Phase 4 — Pattern Detection
# ═══════════════════════════════════════════════════════════════════════

class NullptrPatternDetector:
    """
    Match collected events against dataflow analysis results
    to produce diagnostics for each rule.
    """

    def __init__(
        self,
        events: EventCollector,
        null_analysis: NullStateAnalysis,
        cfg_manager: Optional[CFGManager] = None,
        enabled_rules: Optional[Set[str]] = None,
        verbose: bool = False,
    ):
        self.events = events
        self.null_analysis = null_analysis
        self.cfg_manager = cfg_manager
        self.enabled_rules = enabled_rules
        self.verbose = verbose

    def _enabled(self, rule: RuleID) -> bool:
        if self.enabled_rules is None:
            return True
        return rule.value in self.enabled_rules

    def detect_all(self) -> List[Diagnostic]:
        diags: List[Diagnostic] = []
        if self._enabled(RuleID.NP01):
            diags.extend(self._detect_np01())
        if self._enabled(RuleID.NP02):
            diags.extend(self._detect_np02())
        if self._enabled(RuleID.NP03):
            diags.extend(self._detect_np03())
        if self._enabled(RuleID.NP04):
            diags.extend(self._detect_np04())
        if self._enabled(RuleID.NP05):
            diags.extend(self._detect_np05())
        if self._enabled(RuleID.NP06):
            diags.extend(self._detect_np06())
        if self._enabled(RuleID.NP07):
            diags.extend(self._detect_np07())
        if self._enabled(RuleID.NP08):
            diags.extend(self._detect_np08())
        return diags

    # ── NP01: Definite null dereference ──────────────────────────────

    def _detect_np01(self) -> List[Diagnostic]:
        """Pointer is provably NULL at point of dereference."""
        results: List[Diagnostic] = []
        for d in self.events.derefs:
            state = self.null_analysis.state_at(
                d.var_id, d.scope_id, d.line
            )
            if state.is_definitely_null():
                deref_kind = "->" if d.is_arrow else (
                    "[]" if d.is_array else "*"
                )
                results.append(Diagnostic(
                    rule=RuleID.NP01,
                    severity=Severity.ERROR,
                    file=d.file, line=d.line, column=d.column,
                    message=(
                        f"null pointer dereference: '{d.var_name}' is NULL "
                        f"when dereferenced via '{deref_kind}'"
                    ),
                    var_name=d.var_name,
                    cwe=476,
                ))
        return results

    # ── NP02: Dereference before null check ──────────────────────────

    def _detect_np02(self) -> List[Diagnostic]:
        """
        Pointer p is dereferenced at line L1, then checked for null at
        line L2 > L1 in the same scope, with no intervening reassignment.
        """
        results: List[Diagnostic] = []

        # Build deref map: (var_id, scope_id) → list of lines
        deref_map: DefaultDict[Tuple[int, int], List[DerefSite]] = defaultdict(list)
        for d in self.events.derefs:
            deref_map[(d.var_id, d.scope_id)].append(d)

        # Build assignment lines per (var_id, scope_id)
        assign_lines: DefaultDict[Tuple[int, int], List[int]] = defaultdict(list)
        for a in self.events.null_assigns:
            assign_lines[(a.var_id, a.scope_id)].append(a.line)
        # Also track any assignment (not just null) that might re-set the var
        # by scanning tokens — approximated here

        for check in self.events.null_checks:
            key = (check.var_id, check.scope_id)
            for deref in deref_map.get(key, []):
                if deref.line < check.line:
                    # Check no intervening reassignment
                    alines = assign_lines.get(key, [])
                    intervening = any(
                        deref.line < al < check.line for al in alines
                    )
                    if not intervening:
                        results.append(Diagnostic(
                            rule=RuleID.NP02,
                            severity=Severity.ERROR,
                            file=deref.file, line=deref.line,
                            column=deref.column,
                            message=(
                                f"pointer '{check.var_name}' is dereferenced "
                                f"at line {deref.line} but checked for null "
                                f"at line {check.line} — if null, the "
                                f"dereference is undefined behaviour"
                            ),
                            var_name=check.var_name,
                            cwe=476,
                        ))
                        break  # one diagnostic per (deref, check) pair
        return results

    # ── NP03: Null return not checked ────────────────────────────────

    def _detect_np03(self) -> List[Diagnostic]:
        """
        Return value of a may-return-null function is used (dereferenced
        or passed) without a null check.
        """
        results: List[Diagnostic] = []

        for nrc in self.events.null_return_calls:
            if nrc.assigned_var_id is None:
                continue  # not assigned to a variable

            vid = nrc.assigned_var_id
            sid = nrc.scope_id

            # Check if there's a null check for this variable after the call
            has_check = any(
                c.var_id == vid and c.scope_id == sid
                and c.line > nrc.line
                for c in self.events.null_checks
            )

            if has_check:
                continue  # developer checks — OK

            # Check if the variable is dereferenced after the call
            deref_after = [
                d for d in self.events.derefs
                if d.var_id == vid and d.scope_id == sid
                and d.line > nrc.line
            ]

            if deref_after:
                first_deref = min(deref_after, key=lambda d: d.line)
                results.append(Diagnostic(
                    rule=RuleID.NP03,
                    severity=Severity.WARNING,
                    file=nrc.file, line=nrc.line, column=nrc.column,
                    message=(
                        f"return value of '{nrc.func_name}' "
                        f"({nrc.return_reason}) is stored in "
                        f"'{nrc.assigned_var_name}' and dereferenced at "
                        f"line {first_deref.line} without a null check"
                    ),
                    var_name=nrc.assigned_var_name,
                    cwe=690,
                ))
        return results

    # ── NP04: Redundant null check ───────────────────────────────────

    def _detect_np04(self) -> List[Diagnostic]:
        """Pointer can never be null at the check site."""
        results: List[Diagnostic] = []
        for check in self.events.null_checks:
            state = self.null_analysis.state_at(
                check.var_id, check.scope_id, check.line
            )
            if state.is_definitely_nonnull():
                results.append(Diagnostic(
                    rule=RuleID.NP04,
                    severity=Severity.STYLE,
                    file=check.file, line=check.line, column=check.column,
                    message=(
                        f"redundant null check: '{check.var_name}' cannot "
                        f"be null at this point"
                    ),
                    var_name=check.var_name,
                ))
        return results

    # ── NP05: Null passed to non-null parameter ──────────────────────

    def _detect_np05(self) -> List[Diagnostic]:
        """Null literal or provably-null value passed to a non-null param."""
        results: List[Diagnostic] = []

        # Direct null literal passes (already collected)
        for nap in self.events.nonnull_arg_passes:
            results.append(Diagnostic(
                rule=RuleID.NP05,
                severity=Severity.ERROR,
                file=nap.file, line=nap.line, column=nap.column,
                message=(
                    f"null value '{nap.arg_var_name}' passed as argument "
                    f"{nap.param_index + 1} to '{nap.func_name}', which "
                    f"requires a non-null pointer"
                ),
                var_name=nap.arg_var_name,
                cwe=476,
            ))

        # Also check variables that are provably null via dataflow
        for tok_iter_scope in self._iter_call_args():
            func_name, param_idx, arg_tok, sid, line, col, file_ = tok_iter_scope
            if func_name not in NON_NULL_PARAMS:
                continue
            if param_idx not in NON_NULL_PARAMS[func_name]:
                continue
            vid = _tok_var_id(arg_tok)
            if vid is None:
                continue
            state = self.null_analysis.state_at(vid, sid, line)
            if state.is_definitely_null():
                results.append(Diagnostic(
                    rule=RuleID.NP05,
                    severity=Severity.ERROR,
                    file=file_, line=line, column=col,
                    message=(
                        f"pointer '{_tok_str(arg_tok)}' is NULL when passed "
                        f"as argument {param_idx + 1} to '{func_name}', "
                        f"which requires a non-null pointer"
                    ),
                    var_name=_tok_str(arg_tok),
                    cwe=476,
                ))

        return results

    def _iter_call_args(self):
        """
        Generator yielding (func_name, param_idx, arg_tok, scope_id,
        line, col, file) for every argument to a non-null-requiring call.
        Uses the already-collected events rather than re-walking tokens.
        """
        # This is a simplified version; a full implementation would
        # re-walk tokens. For now, we rely on the direct null literal
        # detection in EventCollector.
        return []

    # ── NP06: Null arithmetic ────────────────────────────────────────

    def _detect_np06(self) -> List[Diagnostic]:
        """Arithmetic on a null pointer (e.g., NULL + offset)."""
        results: List[Diagnostic] = []
        for d in self.events.derefs:
            # Check for p + n where p is null
            # We check the parent AST node for arithmetic
            parent = getattr(d.token, 'astParent', None)
            if parent and _tok_str(parent) in ('+', '-'):
                state = self.null_analysis.state_at(
                    d.var_id, d.scope_id, d.line
                )
                if state.is_definitely_null():
                    results.append(Diagnostic(
                        rule=RuleID.NP06,
                        severity=Severity.WARNING,
                        file=d.file, line=d.line, column=d.column,
                        message=(
                            f"arithmetic on null pointer '{d.var_name}': "
                            f"this is undefined behaviour"
                        ),
                        var_name=d.var_name,
                        cwe=476,
                    ))
        return results

    # ── NP07: Null assigned then dereferenced ────────────────────────

    def _detect_np07(self) -> List[Diagnostic]:
        """
        Variable assigned NULL/nullptr, then dereferenced with no
        intervening reassignment on the path between them.
        """
        results: List[Diagnostic] = []

        for assign in self.events.null_assigns:
            vid = assign.var_id
            sid = assign.scope_id

            # Find dereferences of the same variable after the assignment
            later_derefs = [
                d for d in self.events.derefs
                if d.var_id == vid and d.scope_id == sid
                and d.line > assign.line
            ]

            if not later_derefs:
                continue

            first_deref = min(later_derefs, key=lambda d: d.line)

            # Check for intervening non-null assignments
            # (any assignment to vid between assign.line and first_deref.line)
            has_intervening_assign = False
            for tok in _token_iter_range_approx(assign, first_deref):
                if tok is None:
                    break
                if _tok_str(tok) == '=' and getattr(tok, 'isAssignmentOp', False):
                    op1 = getattr(tok, 'astOperand1', None)
                    if op1 and _tok_var_id(op1) == vid:
                        op2 = getattr(tok, 'astOperand2', None)
                        if op2 and not _is_null_literal(op2):
                            has_intervening_assign = True
                            break

            # Check for intervening null check (which implies a branch)
            has_intervening_check = any(
                c.var_id == vid and c.scope_id == sid
                and assign.line < c.line < first_deref.line
                for c in self.events.null_checks
            )

            if not has_intervening_assign and not has_intervening_check:
                deref_kind = "->" if first_deref.is_arrow else (
                    "[]" if first_deref.is_array else "*"
                )
                results.append(Diagnostic(
                    rule=RuleID.NP07,
                    severity=Severity.ERROR,
                    file=assign.file, line=assign.line,
                    column=assign.column,
                    message=(
                        f"'{assign.var_name}' is assigned null at line "
                        f"{assign.line}, then dereferenced via "
                        f"'{deref_kind}' at line {first_deref.line} "
                        f"without reassignment"
                    ),
                    var_name=assign.var_name,
                    cwe=476,
                ))

        return results

    # ── NP08: Tautological double null check ─────────────────────────

    def _detect_np08(self) -> List[Diagnostic]:
        """
        Same pointer tested for null twice with no intervening
        reassignment — the second check is tautological.
        """
        results: List[Diagnostic] = []

        # Group null checks by (var_id, scope_id)
        checks_by_var: DefaultDict[
            Tuple[int, int], List[NullCheck]
        ] = defaultdict(list)
        for c in self.events.null_checks:
            checks_by_var[(c.var_id, c.scope_id)].append(c)

        for (vid, sid), checks in checks_by_var.items():
            if len(checks) < 2:
                continue

            sorted_checks = sorted(checks, key=lambda c: c.line)
            for i in range(len(sorted_checks) - 1):
                c1 = sorted_checks[i]
                c2 = sorted_checks[i + 1]

                # Check no intervening assignment to the variable
                has_assign = any(
                    a.var_id == vid and a.scope_id == sid
                    and c1.line < a.line < c2.line
                    for a in self.events.null_assigns
                )

                if not has_assign and c1.is_eq_null == c2.is_eq_null:
                    check_kind = "== null" if c2.is_eq_null else "!= null"
                    results.append(Diagnostic(
                        rule=RuleID.NP08,
                        severity=Severity.STYLE,
                        file=c2.file, line=c2.line, column=c2.column,
                        message=(
                            f"tautological null check: '{c2.var_name} "
                            f"{check_kind}' was already tested at line "
                            f"{c1.line} with no intervening reassignment"
                        ),
                        var_name=c2.var_name,
                    ))

        return results


def _token_iter_range_approx(start_event, end_event) -> Iterator:
    """
    Iterate tokens approximately between two events.
    Uses the token's next pointer starting from start_event's token.
    """
    tok = getattr(start_event, 'token', None)
    if tok is None:
        return
    end_line = end_event.line
    tok = tok.next
    limit = 5000  # safety bound
    while tok is not None and limit > 0:
        limit -= 1
        if _tok_line(tok) >= end_line:
            break
        yield tok
        tok = tok.next


# ═══════════════════════════════════════════════════════════════════════
# Phase 5 — Orchestrator
# ═══════════════════════════════════════════════════════════════════════

class NullptrMisuseChecker:
    """Top-level orchestrator for the nullptr misuse detector."""

    RULE_INFO = {
        RuleID.NP01: ("Definite null dereference",       Severity.ERROR,   476),
        RuleID.NP02: ("Dereference before null check",   Severity.ERROR,   476),
        RuleID.NP03: ("Null return not checked",         Severity.WARNING, 690),
        RuleID.NP04: ("Redundant null check",            Severity.STYLE,   None),
        RuleID.NP05: ("Null to non-null parameter",      Severity.ERROR,   476),
        RuleID.NP06: ("Null arithmetic",                 Severity.WARNING, 476),
        RuleID.NP07: ("Null assigned then dereferenced",  Severity.ERROR,   476),
        RuleID.NP08: ("Tautological double null check",  Severity.STYLE,   None),
    }

    def __init__(
        self,
        verbose: bool = False,
        json_output: bool = False,
        enabled_rules: Optional[Set[str]] = None,
    ):
        self.verbose = verbose
        self.json_output = json_output
        self.enabled_rules = enabled_rules
        self.diagnostics: List[Diagnostic] = []
        self.stats: Dict[str, Any] = {
            "files": 0,
            "functions_analyzed": 0,
            "diagnostics": 0,
            "by_rule": defaultdict(int),
            "time_seconds": 0.0,
        }

    def run(self, dump_files: List[str]) -> int:
        t0 = time.monotonic()
        cppcheckdata = _import_cppcheckdata()
        shims = _import_shims()

        if shims is None and self.verbose:
            print("[info] shims not available; using simple analysis",
                  file=sys.stderr)

        for dump_path in dump_files:
            if not os.path.isfile(dump_path):
                print(f"error: {dump_path}: not found", file=sys.stderr)
                continue
            self._analyze_dump(dump_path, cppcheckdata, shims)

        # Deduplicate
        seen: Set[Tuple] = set()
        unique: List[Diagnostic] = []
        for d in self.diagnostics:
            key = (d.rule.value, d.file, d.line, d.column, d.message)
            if key not in seen:
                seen.add(key)
                unique.append(d)
        self.diagnostics = sorted(
            unique, key=lambda d: (d.file, d.line, d.column)
        )

        self.stats["diagnostics"] = len(self.diagnostics)
        for d in self.diagnostics:
            self.stats["by_rule"][d.rule.value] += 1
        self.stats["time_seconds"] = time.monotonic() - t0

        self._emit()
        return 1 if self.diagnostics else 0

    def _analyze_dump(self, path: str, cppcheckdata, shims):
        self.stats["files"] += 1
        if self.verbose:
            print(f"\n{'='*60}\nAnalyzing: {path}\n{'='*60}",
                  file=sys.stderr)

        try:
            data = cppcheckdata.CppcheckData(path)
        except Exception as exc:
            print(f"error: {path}: {exc}", file=sys.stderr)
            return

        for cfg in data.configurations:
            # Phase 1: Collect events
            events = EventCollector(verbose=self.verbose)
            events.collect(cfg)
            if self.verbose:
                print(f"  {events.summary()}", file=sys.stderr)

            # Phase 2: CFG & dominance
            cfg_mgr = CFGManager(shims, verbose=self.verbose) if shims else None

            # Count function scopes
            scopes = getattr(cfg, 'scopes', None) or []
            func_scopes = [
                s for s in scopes
                if getattr(s, 'type', '') in ('Function', 'function')
            ]
            self.stats["functions_analyzed"] += len(func_scopes)

            # Phase 3: Null-state analysis
            null_analysis = NullStateAnalysis(
                events=events,
                shims=shims,
                cfg_manager=cfg_mgr,
                verbose=self.verbose,
            )
            null_analysis.run(cfg)

            # Phase 4: Pattern detection
            detector = NullptrPatternDetector(
                events=events,
                null_analysis=null_analysis,
                cfg_manager=cfg_mgr,
                enabled_rules=self.enabled_rules,
                verbose=self.verbose,
            )
            diags = detector.detect_all()
            self.diagnostics.extend(diags)

    def _emit(self):
        if self.json_output:
            out = {
                "version": 1,
                "checker": "NullptrMisuseDetector",
                "stats": {
                    "files": self.stats["files"],
                    "functions_analyzed": self.stats["functions_analyzed"],
                    "diagnostics": self.stats["diagnostics"],
                    "by_rule": dict(self.stats["by_rule"]),
                    "time_seconds": round(self.stats["time_seconds"], 3),
                },
                "diagnostics": [d.to_json() for d in self.diagnostics],
            }
            print(json.dumps(out, indent=2))
        else:
            for d in self.diagnostics:
                print(d.to_gcc())
            if self.verbose:
                print(f"\n--- Summary ---", file=sys.stderr)
                for k, v in self.stats.items():
                    if k == "by_rule":
                        for rule, count in sorted(v.items()):
                            desc = self.RULE_INFO.get(
                                RuleID(rule), ("?",)
                            )[0]
                            print(f"  {rule}: {count} ({desc})",
                                  file=sys.stderr)
                    else:
                        print(f"  {k}: {v}", file=sys.stderr)


# ═══════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="NullptrMisuseDetector",
        description="Cppcheck addon: detect nullptr/NULL misuse.",
        epilog=(
            "Rules:\n"
            "  NP01  Definite null dereference\n"
            "  NP02  Dereference before null check\n"
            "  NP03  Null-returning function not checked\n"
            "  NP04  Redundant null check\n"
            "  NP05  Null passed to non-null parameter\n"
            "  NP06  Arithmetic on null pointer\n"
            "  NP07  Null assigned then dereferenced\n"
            "  NP08  Tautological double null check\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("dump_files", nargs="+", metavar="FILE.dump")
    p.add_argument("--verbose", "-v", action="store_true")
    p.add_argument("--json", dest="json_output", action="store_true")
    p.add_argument("--enable", dest="enable_rules", default=None,
                   help="Comma-separated rules (e.g. NP01,NP03)")
    p.add_argument("--disable", dest="disable_rules", default=None,
                   help="Comma-separated rules to disable")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    all_rules = {r.value for r in RuleID}
    enabled = None
    if args.enable_rules:
        enabled = set(args.enable_rules.upper().split(",")) & all_rules
    if args.disable_rules:
        disabled = set(args.disable_rules.upper().split(","))
        enabled = (enabled or all_rules) - disabled

    checker = NullptrMisuseChecker(
        verbose=args.verbose,
        json_output=args.json_output,
        enabled_rules=enabled,
    )
    return checker.run(args.dump_files)


if __name__ == "__main__":
    sys.exit(main())
