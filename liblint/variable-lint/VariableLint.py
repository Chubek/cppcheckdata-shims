#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
VariableLint.py
═══════════════

A cppcheck addon that detects variable-related weaknesses in C/C++ code.

Every diagnostic is mapped to one or more MITRE CWE entries (v4.19).

╔═══════════════════════════════════════════════════════════════════════════╗
║  CHECK ID                  │ CWE(s)             │ SEVERITY             ║
╠═══════════════════════════════════════════════════════════════════════════╣
║  uninitVar                 │ CWE-457             │ error                ║
║  unusedVariable            │ CWE-563             │ style                ║
║  shadowVariable            │ CWE-398 / CWE-710  │ warning              ║
║  deadStore                 │ CWE-563             │ warning              ║
║  constVariable             │ CWE-398 / CWE-710  │ style                ║
║  reusedVariable            │ CWE-1335            │ style                ║
║  narrowingConversion       │ CWE-197 / CWE-681  │ warning              ║
║  signConversion            │ CWE-195 / CWE-196  │ warning              ║
║  intOverflowAssign         │ CWE-190             │ warning              ║
║  selfAssignment            │ CWE-480 / CWE-682  │ warning              ║
║  redundantAssignment       │ CWE-563             │ warning              ║
║  uninitialisedStructMember │ CWE-908             │ warning              ║
║  volatileMisuse            │ CWE-667             │ warning              ║
║  pointerArithOverflow      │ CWE-119 / CWE-787  │ error                ║
║  nullDerefAfterCheck       │ CWE-476             │ error                ║
║  toctou                    │ CWE-367             │ warning              ║
║  uninitArrayRead           │ CWE-908             │ warning              ║
║  danglingPointer           │ CWE-825             │ error                ║
╚═══════════════════════════════════════════════════════════════════════════╝

Usage
─────

    # Dump file first
    cppcheck --dump myfile.c

    # Run addon
    python VariableLint.py myfile.c.dump

    # With SARIF output
    REPORT_GENERATE_SARIF=variablelint.sarif python VariableLint.py myfile.c.dump

    # With HTML output
    REPORT_GENERATE_HTML=variablelint.html python VariableLint.py myfile.c.dump

    # Run built-in self-tests (no dump file needed)
    python VariableLint.py --self-test

Architecture
────────────

    ┌───────────────┐     ┌──────────────────┐     ┌──────────────┐
    │  cppcheck     │────▶│  cppcheckdata /   │────▶│ VariableLint │
    │  --dump       │     │  cppcheckdata     │     │  (this file) │
    │               │     │  _shims           │     │              │
    └───────────────┘     └──────────────────┘     └──────┬───────┘
                                                          │
                                                          ▼
                                                   ┌──────────────┐
                                                   │plus_reporter │
                                                   │  .py         │
                                                   │ (diagnostics)│
                                                   └──────────────┘

License: MIT
"""

from __future__ import annotations

import argparse
import copy
import os
import re
import sys
import textwrap
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import (
    Any, Callable, Dict, FrozenSet, Iterator, List, Mapping,
    Optional, Protocol, Sequence, Set, Tuple, Union,
)

# ─────────────────────────────────────────────────────────────────────────────
#  IMPORTS – graceful degradation
# ─────────────────────────────────────────────────────────────────────────────

# Try importing the real cppcheckdata module; fall back to shims if absent.
try:
    import cppcheckdata  # type: ignore[import-untyped]
except ImportError:
    try:
        from cppcheckdata_shims import cppcheckdata  # type: ignore
    except ImportError:
        cppcheckdata = None  # Will be handled at runtime

# Try importing plus_reporter; degrade to plain print if absent.
try:
    from plus_reporter import Reporter, Diagnostic  # type: ignore[import-untyped]
    _HAS_REPORTER = True
except ImportError:
    _HAS_REPORTER = False


# ═══════════════════════════════════════════════════════════════════════════════
#  FALLBACK REPORTER (when plus_reporter.py is not available)
# ═══════════════════════════════════════════════════════════════════════════════

class _FallbackDiagnostic:
    """Minimal diagnostic builder that prints cppcheck-style one-liners."""

    def __init__(self, severity: str, check_id: str, message: str):
        self._severity = severity
        self._id = check_id
        self._msg = message
        self._file: str = ""
        self._line: int = 0
        self._col: int = 0
        self._notes: List[str] = []
        self._cwe: Optional[int] = None

    # Builder methods ─────────────────────────────────────────────────────

    def at(self, file: str, line: int, col: int = 0) -> "_FallbackDiagnostic":
        self._file = file
        self._line = line
        self._col = col
        return self

    def span(self, *_a: Any, **_k: Any) -> "_FallbackDiagnostic":
        return self

    def note(self, *_a: Any, text: str = "", **_k: Any) -> "_FallbackDiagnostic":
        if text:
            self._notes.append(text)
        elif _a:
            self._notes.append(str(_a[-1]))
        return self

    def help(self, text: str) -> "_FallbackDiagnostic":
        self._notes.append(f"help: {text}")
        return self

    def cwe(self, cwe_id: int) -> "_FallbackDiagnostic":
        self._cwe = cwe_id
        return self

    def emit(self) -> None:
        loc = f"{self._file}:{self._line}"
        if self._col:
            loc += f":{self._col}"
        cwe_str = f" [CWE-{self._cwe}]" if self._cwe else ""
        print(
            f"[{loc}]: ({self._severity}) {self._msg} [{self._id}]{cwe_str}",
            file=sys.stderr,
        )
        for n in self._notes:
            print(f"  note: {n}", file=sys.stderr)


class _FallbackReporter:
    """Minimal reporter that wraps _FallbackDiagnostic."""

    _counter: Dict[str, int] = defaultdict(int)

    @classmethod
    def error(cls, check_id: str, msg: str) -> _FallbackDiagnostic:
        cls._counter["error"] += 1
        return _FallbackDiagnostic("error", check_id, msg)

    @classmethod
    def warning(cls, check_id: str, msg: str) -> _FallbackDiagnostic:
        cls._counter["warning"] += 1
        return _FallbackDiagnostic("warning", check_id, msg)

    @classmethod
    def style(cls, check_id: str, msg: str) -> _FallbackDiagnostic:
        cls._counter["style"] += 1
        return _FallbackDiagnostic("style", check_id, msg)

    @classmethod
    def perf(cls, check_id: str, msg: str) -> _FallbackDiagnostic:
        cls._counter["performance"] += 1
        return _FallbackDiagnostic("performance", check_id, msg)

    @classmethod
    def info(cls, check_id: str, msg: str) -> _FallbackDiagnostic:
        cls._counter["information"] += 1
        return _FallbackDiagnostic("information", check_id, msg)


# Choose the reporter to use for all diagnostics
if _HAS_REPORTER:
    R = Reporter
else:
    R = _FallbackReporter  # type: ignore[assignment,misc]


# ═══════════════════════════════════════════════════════════════════════════════
#  TOKEN / VARIABLE / SCOPE HELPERS (work with both cppcheckdata & shims)
# ═══════════════════════════════════════════════════════════════════════════════

def _tok_str(tok: Any) -> str:
    """Return the string representation of a token."""
    return getattr(tok, "str", "") or ""


def _tok_file(tok: Any) -> str:
    return getattr(tok, "file", "") or ""


def _tok_line(tok: Any) -> int:
    return int(getattr(tok, "linenr", 0) or 0)


def _tok_col(tok: Any) -> int:
    return int(getattr(tok, "column", 0) or 0)


def _tok_next(tok: Any) -> Any:
    return getattr(tok, "next", None)


def _tok_prev(tok: Any) -> Any:
    return getattr(tok, "previous", None)


def _tok_astop1(tok: Any) -> Any:
    return getattr(tok, "astOperand1", None)


def _tok_astop2(tok: Any) -> Any:
    return getattr(tok, "astOperand2", None)


def _tok_astparent(tok: Any) -> Any:
    return getattr(tok, "astParent", None)


def _tok_variable(tok: Any) -> Any:
    return getattr(tok, "variable", None)


def _tok_var_id(tok: Any) -> int:
    return int(getattr(tok, "varId", 0) or 0)


def _tok_scope(tok: Any) -> Any:
    return getattr(tok, "scope", None)


def _tok_type(tok: Any) -> str:
    return getattr(tok, "valueType", None) and getattr(tok.valueType, "type", "") or ""


def _tok_values(tok: Any) -> list:
    return getattr(tok, "values", None) or []


def _tok_is_op(tok: Any) -> bool:
    return getattr(tok, "isOp", False)


def _tok_is_assign(tok: Any) -> bool:
    return getattr(tok, "isAssignmentOp", False)


def _tok_is_comparison(tok: Any) -> bool:
    return getattr(tok, "isComparisonOp", False)


def _tok_is_name(tok: Any) -> bool:
    return getattr(tok, "isName", False)


def _tok_is_number(tok: Any) -> bool:
    return getattr(tok, "isNumber", False)


def _var_name(var: Any) -> str:
    return getattr(var, "nameToken", None) and _tok_str(var.nameToken) or ""


def _var_is_local(var: Any) -> bool:
    return getattr(var, "isLocal", False)


def _var_is_arg(var: Any) -> bool:
    return getattr(var, "isArgument", False)


def _var_is_pointer(var: Any) -> bool:
    return getattr(var, "isPointer", False)


def _var_is_array(var: Any) -> bool:
    return getattr(var, "isArray", False)


def _var_is_reference(var: Any) -> bool:
    return getattr(var, "isReference", False)


def _var_is_const(var: Any) -> bool:
    return getattr(var, "isConst", False)


def _var_is_volatile(var: Any) -> bool:
    return getattr(var, "isVolatile", False)


def _var_is_static(var: Any) -> bool:
    return getattr(var, "isStatic", False)


def _var_is_global(var: Any) -> bool:
    return getattr(var, "isGlobal", False)


def _var_type_start_tok(var: Any) -> Any:
    return getattr(var, "typeStartToken", None)


def _var_type_end_tok(var: Any) -> Any:
    return getattr(var, "typeEndToken", None)


def _var_name_tok(var: Any) -> Any:
    return getattr(var, "nameToken", None)


def _scope_type(scope: Any) -> str:
    return getattr(scope, "type", "") or ""


def _scope_classname(scope: Any) -> str:
    return getattr(scope, "className", "") or ""


def _scope_bodystart(scope: Any) -> Any:
    return getattr(scope, "bodyStart", None)


def _scope_bodyend(scope: Any) -> Any:
    return getattr(scope, "bodyEnd", None)


def _scope_nested_in(scope: Any) -> Any:
    return getattr(scope, "nestedIn", None)


def _iter_tokens(start: Any, end: Any) -> Iterator:
    """Iterate tokens from *start* (exclusive) to *end* (exclusive)."""
    tok = _tok_next(start)
    while tok is not None and tok is not end:
        yield tok
        tok = _tok_next(tok)


def _iter_tokens_inclusive(start: Any, end: Any) -> Iterator:
    """Iterate tokens from *start* (inclusive) to *end* (inclusive)."""
    tok = start
    while tok is not None:
        yield tok
        if tok is end:
            break
        tok = _tok_next(tok)


def _collect_var_type_str(var: Any) -> str:
    """Reconstruct the type string of a variable from its type tokens."""
    ts = _var_type_start_tok(var)
    te = _var_type_end_tok(var)
    if ts is None:
        return ""
    parts: List[str] = []
    for t in _iter_tokens_inclusive(ts, te):
        parts.append(_tok_str(t))
    return " ".join(parts)


def _value_type_sign(tok: Any) -> str:
    """Return 'signed' / 'unsigned' / '' for a token's valueType."""
    vt = getattr(tok, "valueType", None)
    if vt is None:
        return ""
    return getattr(vt, "sign", "") or ""


def _value_type_bits(tok: Any) -> int:
    """Best-effort bit-width of a token's valueType.  0 = unknown."""
    vt = getattr(tok, "valueType", None)
    if vt is None:
        return 0
    t = getattr(vt, "type", "") or ""
    _MAP = {
        "char": 8, "short": 16, "int": 32, "long": 64,
        "long long": 64, "float": 32, "double": 64,
    }
    return _MAP.get(t, 0)


# ═══════════════════════════════════════════════════════════════════════════════
#  CWE MAP
# ═══════════════════════════════════════════════════════════════════════════════

class CWE:
    """Central mapping of check-id → CWE number."""
    UNINIT_VAR              = 457   # CWE-457  Use of Uninitialized Variable
    UNUSED_VAR              = 563   # CWE-563  Assignment to Variable without Use
    SHADOW_VAR_398          = 398   # CWE-398  7PK – Code Quality
    SHADOW_VAR_710          = 710   # CWE-710  Improper Adherence to Coding Standards
    DEAD_STORE              = 563   # CWE-563  (same as unused)
    CONST_VAR               = 398   # CWE-398  7PK – Code Quality
    REUSED_VAR              = 1335  # CWE-1335 Incorrect Bitwise Shift (nearest)  [placeholder]
    NARROW_CONV             = 197   # CWE-197  Numeric Truncation Error
    NARROW_CONV_681         = 681   # CWE-681  Incorrect Conversion between Numeric Types
    SIGN_CONV_195           = 195   # CWE-195  Signed to Unsigned Conversion Error
    SIGN_CONV_196           = 196   # CWE-196  Unsigned to Signed Conversion Error
    INT_OVERFLOW            = 190   # CWE-190  Integer Overflow or Wraparound
    SELF_ASSIGN_480         = 480   # CWE-480  Use of Incorrect Operator
    SELF_ASSIGN_682         = 682   # CWE-682  Incorrect Calculation
    REDUNDANT_ASSIGN        = 563   # CWE-563
    UNINIT_STRUCT           = 908   # CWE-908  Use of Uninitialized Resource
    VOLATILE_MISUSE         = 667   # CWE-667  Improper Locking
    PTR_ARITH_OOB           = 787   # CWE-787  Out-of-bounds Write
    PTR_ARITH_119           = 119   # CWE-119  Improper Restriction of Buffer Bounds
    NULL_DEREF              = 476   # CWE-476  NULL Pointer Dereference
    TOCTOU                  = 367   # CWE-367  TOCTOU Race Condition
    UNINIT_ARRAY            = 908   # CWE-908
    DANGLING_PTR            = 825   # CWE-825  Expired Pointer Dereference


# ═══════════════════════════════════════════════════════════════════════════════
#  ANALYSIS CONTEXT
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class VarInfo:
    """Per-variable tracking information accumulated during analysis."""
    var: Any                           # cppcheckdata Variable object
    name: str = ""
    var_id: int = 0
    file: str = ""
    line: int = 0
    col: int = 0
    type_str: str = ""
    is_written: bool = False           # Was ever assigned after declaration
    is_read: bool = False              # Was ever used in an expression
    is_initialised: bool = False       # Was initialised at declaration
    write_count: int = 0
    read_count: int = 0
    last_write_tok: Any = None         # token of the most recent write
    last_read_tok: Any = None
    scope: Any = None


@dataclass
class AnalysisContext:
    """Shared state across all checkers for one configuration."""
    cfg: Any  # cppcheckdata Configuration
    vars: Dict[int, VarInfo] = field(default_factory=dict)  # varId → VarInfo
    diag_count: Dict[str, int] = field(default_factory=lambda: defaultdict(int))


# ═══════════════════════════════════════════════════════════════════════════════
#  VARIABLE INFO COLLECTOR
# ═══════════════════════════════════════════════════════════════════════════════

def _collect_var_info(ctx: AnalysisContext) -> None:
    """
    First pass: populate ``ctx.vars`` with declaration-level info and scan
    every token to record reads / writes.
    """
    cfg = ctx.cfg

    # 1. Register every variable declared in the configuration.
    for var in getattr(cfg, "variables", []):
        vid = int(getattr(var, "Id", 0) or 0)
        if vid == 0:
            continue
        name_tok = _var_name_tok(var)
        info = VarInfo(
            var=var,
            name=_var_name(var),
            var_id=vid,
            file=_tok_file(name_tok) if name_tok else "",
            line=_tok_line(name_tok) if name_tok else 0,
            col=_tok_col(name_tok) if name_tok else 0,
            type_str=_collect_var_type_str(var),
            scope=getattr(var, "scope", None),
        )
        # Check if initialised at declaration:
        #   If the nameToken's next is '=' or '(' or '{', it is initialised.
        if name_tok:
            nxt = _tok_next(name_tok)
            if nxt and _tok_str(nxt) in ("=", "(", "{"):
                info.is_initialised = True
        # Function parameters are always initialised by the caller.
        if _var_is_arg(var):
            info.is_initialised = True
        ctx.vars[vid] = info

    # 2. Walk every token to mark reads and writes.
    tokenlist = getattr(cfg, "tokenlist", [])
    # cppcheckdata may expose tokenlist as the first token; walk via .next
    first_tok = tokenlist[0] if isinstance(tokenlist, list) and tokenlist else tokenlist
    if first_tok is None:
        return

    tok: Any = first_tok
    while tok is not None:
        vid = _tok_var_id(tok)
        if vid and vid in ctx.vars:
            parent = _tok_astparent(tok)
            # Heuristic: if the token is the LHS of an assignment, it is a write.
            if parent and _tok_is_assign(parent) and _tok_astop1(parent) is tok:
                ctx.vars[vid].is_written = True
                ctx.vars[vid].write_count += 1
                ctx.vars[vid].last_write_tok = tok
            else:
                ctx.vars[vid].is_read = True
                ctx.vars[vid].read_count += 1
                ctx.vars[vid].last_read_tok = tok
        tok = _tok_next(tok)


# ═══════════════════════════════════════════════════════════════════════════════
#  INDIVIDUAL CHECKERS
# ═══════════════════════════════════════════════════════════════════════════════

# --------------------------------------------------------------------------- #
# 1. uninitVar  (CWE-457)
# --------------------------------------------------------------------------- #

def check_uninit_var(ctx: AnalysisContext) -> None:
    """
    Detect local variables that are read before being initialised.

    Approach (simplified, linear scan):
    For each function scope, walk tokens; track which local variables have
    been assigned.  If a variable is read and has never been assigned or
    initialised, report.
    """
    cfg = ctx.cfg

    for scope in getattr(cfg, "scopes", []):
        if _scope_type(scope) != "Function":
            continue

        body_start = _scope_bodystart(scope)
        body_end = _scope_bodyend(scope)
        if body_start is None or body_end is None:
            continue

        # Set of varIds that have been definitely written inside this scope
        written: Set[int] = set()

        for tok in _iter_tokens(body_start, body_end):
            vid = _tok_var_id(tok)
            if vid == 0 or vid not in ctx.vars:
                continue
            info = ctx.vars[vid]
            # Only check locals declared in *this* scope
            if not _var_is_local(info.var):
                continue
            if getattr(info.var, "scope", None) is not scope:
                continue

            parent = _tok_astparent(tok)

            # Is this a write (LHS of assignment)?
            if parent and _tok_is_assign(parent) and _tok_astop1(parent) is tok:
                written.add(vid)
                continue

            # Is this a read while not yet written and not initialised?
            if vid not in written and not info.is_initialised:
                R.error(
                    "uninitVar",
                    f"variable '{info.name}' is used without being initialised",
                ).at(
                    _tok_file(tok), _tok_line(tok), _tok_col(tok),
                ).note(
                    info.file, info.line,
                    f"'{info.name}' declared here without initialiser",
                ).help(
                    "initialise the variable at declaration or ensure all paths assign before use",
                ).cwe(CWE.UNINIT_VAR).emit()
                ctx.diag_count["uninitVar"] += 1
                # Suppress duplicate reports for same var in same scope
                written.add(vid)


# --------------------------------------------------------------------------- #
# 2. unusedVariable  (CWE-563)
# --------------------------------------------------------------------------- #

def check_unused_variable(ctx: AnalysisContext) -> None:
    """
    Detect local variables that are declared but never read.
    """
    for vid, info in ctx.vars.items():
        if not _var_is_local(info.var):
            continue
        if _var_is_arg(info.var):
            continue
        if info.is_read:
            continue
        # Ignore variables whose names start with '_' (conventional discard)
        if info.name.startswith("_"):
            continue
        # Ignore variables named 'unused' or 'dummy'
        if info.name.lower() in ("unused", "dummy", "ignore", "void_"):
            continue

        R.style(
            "unusedVariable",
            f"local variable '{info.name}' is never read",
        ).at(
            info.file, info.line, info.col,
        ).help(
            "remove the variable or prefix with '_' if intentionally unused",
        ).cwe(CWE.UNUSED_VAR).emit()
        ctx.diag_count["unusedVariable"] += 1


# --------------------------------------------------------------------------- #
# 3. shadowVariable  (CWE-398, CWE-710)
# --------------------------------------------------------------------------- #

def check_shadow_variable(ctx: AnalysisContext) -> None:
    """
    Detect inner-scope variables that shadow an outer-scope variable.
    """
    # Build name → list[(scope_depth, VarInfo)]
    name_map: Dict[str, List[VarInfo]] = defaultdict(list)
    for vid, info in ctx.vars.items():
        if info.name:
            name_map[info.name].append(info)

    for name, infos in name_map.items():
        if len(infos) < 2:
            continue
        # Check each pair for nesting
        for i, inner in enumerate(infos):
            for outer in infos[i + 1 :]:
                inner_scope = getattr(inner.var, "scope", None)
                outer_scope = getattr(outer.var, "scope", None)
                if inner_scope is None or outer_scope is None:
                    continue
                # Walk nestedIn chain from inner_scope to see if outer_scope
                # is an ancestor.
                s = _scope_nested_in(inner_scope)
                depth = 0
                found = False
                while s is not None and depth < 50:
                    if s is outer_scope:
                        found = True
                        break
                    s = _scope_nested_in(s)
                    depth += 1
                if found:
                    R.warning(
                        "shadowVariable",
                        f"variable '{name}' shadows outer variable",
                    ).at(
                        inner.file, inner.line, inner.col,
                    ).note(
                        outer.file, outer.line,
                        f"outer variable '{name}' declared here",
                    ).help(
                        "rename the inner variable to avoid confusion",
                    ).cwe(CWE.SHADOW_VAR_398).emit()
                    ctx.diag_count["shadowVariable"] += 1


# --------------------------------------------------------------------------- #
# 4. deadStore  (CWE-563)
# --------------------------------------------------------------------------- #

def check_dead_store(ctx: AnalysisContext) -> None:
    """
    Detect writes to variables that are never subsequently read before the
    next write or end of scope (dead stores).

    Strategy: for each function scope, scan backwards.  When we see a write
    and the variable has not been read since the last write, it is dead.
    """
    cfg = ctx.cfg
    for scope in getattr(cfg, "scopes", []):
        if _scope_type(scope) != "Function":
            continue
        body_start = _scope_bodystart(scope)
        body_end = _scope_bodyend(scope)
        if body_start is None or body_end is None:
            continue

        # Collect tokens in order
        tokens: List[Any] = list(_iter_tokens(body_start, body_end))

        # For each local variable, track "read since last write"
        read_since_write: Dict[int, bool] = {}
        last_write_tok: Dict[int, Any] = {}

        # Forward scan: for each write, check if the *previous* write was dead
        for tok in tokens:
            vid = _tok_var_id(tok)
            if vid == 0 or vid not in ctx.vars:
                continue
            info = ctx.vars[vid]
            if not _var_is_local(info.var):
                continue

            parent = _tok_astparent(tok)
            is_write = parent and _tok_is_assign(parent) and _tok_astop1(parent) is tok

            if is_write:
                # If there was a previous write and no read since, dead store!
                if vid in last_write_tok and not read_since_write.get(vid, True):
                    prev = last_write_tok[vid]
                    R.warning(
                        "deadStore",
                        f"value assigned to '{info.name}' is never read",
                    ).at(
                        _tok_file(prev), _tok_line(prev), _tok_col(prev),
                    ).note(
                        _tok_file(tok), _tok_line(tok),
                        "overwritten here without reading the previous value",
                    ).help(
                        "remove the first assignment or use the value before overwriting",
                    ).cwe(CWE.DEAD_STORE).emit()
                    ctx.diag_count["deadStore"] += 1
                last_write_tok[vid] = tok
                read_since_write[vid] = False
            else:
                # This is a read
                read_since_write[vid] = True


# --------------------------------------------------------------------------- #
# 5. constVariable  (CWE-398)
# --------------------------------------------------------------------------- #

def check_const_variable(ctx: AnalysisContext) -> None:
    """
    Detect local variables that are assigned exactly once (at declaration)
    and could be declared ``const``.
    """
    for vid, info in ctx.vars.items():
        if not _var_is_local(info.var):
            continue
        if _var_is_arg(info.var):
            continue
        if _var_is_const(info.var):
            continue
        if _var_is_pointer(info.var) or _var_is_reference(info.var):
            continue  # pointer constness is more nuanced
        if _var_is_volatile(info.var):
            continue
        if not info.is_initialised:
            continue
        if info.write_count > 0:
            continue  # was assigned after declaration
        if not info.is_read:
            continue  # would be caught by unusedVariable

        R.style(
            "constVariable",
            f"variable '{info.name}' could be declared 'const'",
        ).at(
            info.file, info.line, info.col,
        ).help(
            f"declare as: const {info.type_str} {info.name}",
        ).cwe(CWE.CONST_VAR).emit()
        ctx.diag_count["constVariable"] += 1


# --------------------------------------------------------------------------- #
# 6. selfAssignment  (CWE-480, CWE-682)
# --------------------------------------------------------------------------- #

def check_self_assignment(ctx: AnalysisContext) -> None:
    """
    Detect ``x = x;`` patterns.
    """
    cfg = ctx.cfg
    for scope in getattr(cfg, "scopes", []):
        if _scope_type(scope) != "Function":
            continue
        body_start = _scope_bodystart(scope)
        body_end = _scope_bodyend(scope)
        if body_start is None or body_end is None:
            continue
        for tok in _iter_tokens(body_start, body_end):
            if not _tok_is_assign(tok):
                continue
            if _tok_str(tok) != "=":
                continue
            lhs = _tok_astop1(tok)
            rhs = _tok_astop2(tok)
            if lhs is None or rhs is None:
                continue
            l_vid = _tok_var_id(lhs)
            r_vid = _tok_var_id(rhs)
            if l_vid and l_vid == r_vid:
                info = ctx.vars.get(l_vid)
                name = info.name if info else _tok_str(lhs)
                R.warning(
                    "selfAssignment",
                    f"variable '{name}' is assigned to itself",
                ).at(
                    _tok_file(tok), _tok_line(tok), _tok_col(tok),
                ).help(
                    "did you mean to assign a different variable?",
                ).cwe(CWE.SELF_ASSIGN_480).emit()
                ctx.diag_count["selfAssignment"] += 1


# --------------------------------------------------------------------------- #
# 7. redundantAssignment  (CWE-563)
# --------------------------------------------------------------------------- #

def check_redundant_assignment(ctx: AnalysisContext) -> None:
    """
    Detect ``x = value; x = other_value;`` with no read of x in between.

    Reuses the dead-store infrastructure but emits a different check id
    when both assignments are to the *same literal*.
    """
    cfg = ctx.cfg
    for scope in getattr(cfg, "scopes", []):
        if _scope_type(scope) != "Function":
            continue
        body_start = _scope_bodystart(scope)
        body_end = _scope_bodyend(scope)
        if body_start is None or body_end is None:
            continue

        last_assign_tok: Dict[int, Any] = {}  # vid → assignment tok (the '=')
        read_since: Dict[int, bool] = {}

        for tok in _iter_tokens(body_start, body_end):
            vid = _tok_var_id(tok)
            if vid == 0 or vid not in ctx.vars:
                continue
            info = ctx.vars[vid]
            if not _var_is_local(info.var):
                continue

            parent = _tok_astparent(tok)
            is_write = parent and _tok_is_assign(parent) and _tok_astop1(parent) is tok

            if is_write:
                # Check whether previous write had an identical RHS literal
                if vid in last_assign_tok and not read_since.get(vid, True):
                    prev_assign = last_assign_tok[vid]
                    prev_rhs = _tok_astop2(prev_assign)
                    cur_rhs = _tok_astop2(parent)
                    if (prev_rhs and cur_rhs
                            and _tok_is_number(prev_rhs) and _tok_is_number(cur_rhs)
                            and _tok_str(prev_rhs) == _tok_str(cur_rhs)):
                        R.warning(
                            "redundantAssignment",
                            f"'{info.name}' assigned the same value {_tok_str(cur_rhs)} twice",
                        ).at(
                            _tok_file(tok), _tok_line(tok), _tok_col(tok),
                        ).note(
                            _tok_file(prev_assign), _tok_line(prev_assign),
                            "first assignment was here",
                        ).cwe(CWE.REDUNDANT_ASSIGN).emit()
                        ctx.diag_count["redundantAssignment"] += 1

                last_assign_tok[vid] = parent  # The '=' token
                read_since[vid] = False
            else:
                read_since[vid] = True


# --------------------------------------------------------------------------- #
# 8. narrowingConversion  (CWE-197, CWE-681)
# --------------------------------------------------------------------------- #

def check_narrowing_conversion(ctx: AnalysisContext) -> None:
    """
    Detect assignments where the RHS type is wider than the LHS type,
    e.g. ``int x = some_long;`` or ``short s = some_int;``.
    """
    cfg = ctx.cfg
    for scope in getattr(cfg, "scopes", []):
        if _scope_type(scope) != "Function":
            continue
        body_start = _scope_bodystart(scope)
        body_end = _scope_bodyend(scope)
        if body_start is None or body_end is None:
            continue
        for tok in _iter_tokens(body_start, body_end):
            if not _tok_is_assign(tok):
                continue
            if _tok_str(tok) != "=":
                continue
            lhs = _tok_astop1(tok)
            rhs = _tok_astop2(tok)
            if lhs is None or rhs is None:
                continue

            lhs_bits = _value_type_bits(lhs)
            rhs_bits = _value_type_bits(rhs)

            if lhs_bits == 0 or rhs_bits == 0:
                continue
            if rhs_bits > lhs_bits:
                info = ctx.vars.get(_tok_var_id(lhs))
                name = info.name if info else _tok_str(lhs)
                R.warning(
                    "narrowingConversion",
                    f"assignment to '{name}' narrows from {rhs_bits}-bit to {lhs_bits}-bit",
                ).at(
                    _tok_file(tok), _tok_line(tok), _tok_col(tok),
                ).help(
                    "add an explicit cast to silence if intentional",
                ).cwe(CWE.NARROW_CONV).emit()
                ctx.diag_count["narrowingConversion"] += 1


# --------------------------------------------------------------------------- #
# 9. signConversion  (CWE-195, CWE-196)
# --------------------------------------------------------------------------- #

def check_sign_conversion(ctx: AnalysisContext) -> None:
    """
    Detect assignments between signed and unsigned types of the same width.
    """
    cfg = ctx.cfg
    for scope in getattr(cfg, "scopes", []):
        if _scope_type(scope) != "Function":
            continue
        body_start = _scope_bodystart(scope)
        body_end = _scope_bodyend(scope)
        if body_start is None or body_end is None:
            continue
        for tok in _iter_tokens(body_start, body_end):
            if not _tok_is_assign(tok):
                continue
            if _tok_str(tok) != "=":
                continue
            lhs = _tok_astop1(tok)
            rhs = _tok_astop2(tok)
            if lhs is None or rhs is None:
                continue

            l_sign = _value_type_sign(lhs)
            r_sign = _value_type_sign(rhs)

            if not l_sign or not r_sign:
                continue
            if l_sign == r_sign:
                continue

            info = ctx.vars.get(_tok_var_id(lhs))
            name = info.name if info else _tok_str(lhs)
            if l_sign == "unsigned":
                cwe = CWE.SIGN_CONV_195  # signed → unsigned
                direction = "signed-to-unsigned"
            else:
                cwe = CWE.SIGN_CONV_196  # unsigned → signed
                direction = "unsigned-to-signed"

            R.warning(
                "signConversion",
                f"implicit {direction} conversion in assignment to '{name}'",
            ).at(
                _tok_file(tok), _tok_line(tok), _tok_col(tok),
            ).help(
                "add an explicit cast or change the variable type",
            ).cwe(cwe).emit()
            ctx.diag_count["signConversion"] += 1


# --------------------------------------------------------------------------- #
# 10. uninitialisedStructMember  (CWE-908)
# --------------------------------------------------------------------------- #

def check_uninit_struct_member(ctx: AnalysisContext) -> None:
    """
    Detect struct/class variables that are declared without initialiser and
    then used via member access (`.` or `->`).

    Simplified: only fires if there is no `=`, `{`, or `(` after the
    declaration name-token and a member-access read occurs later.
    """
    cfg = ctx.cfg
    for scope in getattr(cfg, "scopes", []):
        if _scope_type(scope) != "Function":
            continue
        body_start = _scope_bodystart(scope)
        body_end = _scope_bodyend(scope)
        if body_start is None or body_end is None:
            continue

        # Find local struct-like variables without initialiser
        uninit_structs: Set[int] = set()
        for vid, info in ctx.vars.items():
            if not _var_is_local(info.var):
                continue
            if getattr(info.var, "scope", None) is not scope:
                continue
            vt = getattr(info.var, "valueType", None)
            if vt is None:
                continue
            # "record" type in cppcheckdata means struct/class/union
            if getattr(vt, "type", "") not in ("record",):
                continue
            if info.is_initialised:
                continue
            uninit_structs.add(vid)

        if not uninit_structs:
            continue

        assigned: Set[int] = set()
        for tok in _iter_tokens(body_start, body_end):
            vid = _tok_var_id(tok)
            if vid == 0:
                continue

            # Track any assignment to the struct variable itself
            parent = _tok_astparent(tok)
            if parent and _tok_is_assign(parent) and _tok_astop1(parent) is tok:
                assigned.add(vid)
                continue

            # Check for member access read on uninitialised struct
            if vid in uninit_structs and vid not in assigned:
                if parent and _tok_str(parent) in (".", "->"):
                    info = ctx.vars.get(vid)
                    name = info.name if info else _tok_str(tok)
                    R.warning(
                        "uninitialisedStructMember",
                        f"member of uninitialised struct '{name}' is read",
                    ).at(
                        _tok_file(tok), _tok_line(tok), _tok_col(tok),
                    ).help(
                        "initialise the struct: use = {0} or memset",
                    ).cwe(CWE.UNINIT_STRUCT).emit()
                    ctx.diag_count["uninitialisedStructMember"] += 1
                    # suppress further reports for same var
                    assigned.add(vid)


# --------------------------------------------------------------------------- #
# 11. nullDerefAfterCheck  (CWE-476)
# --------------------------------------------------------------------------- #

def check_null_deref_after_check(ctx: AnalysisContext) -> None:
    """
    Detect the pattern:

        if (ptr == NULL) {
            ...             // no return / break / continue
        }
        *ptr = ...;         // deref outside the if → possible null deref

    Simplified heuristic: look for ``==`` or ``!=`` with ``NULL`` / ``0``,
    then see if the same pointer is dereferenced after the if-block.
    """
    cfg = ctx.cfg
    for scope in getattr(cfg, "scopes", []):
        if _scope_type(scope) != "Function":
            continue
        body_start = _scope_bodystart(scope)
        body_end = _scope_bodyend(scope)
        if body_start is None or body_end is None:
            continue

        # Collect pointers compared to NULL
        null_checked: Dict[int, Any] = {}  # vid → comparison token

        for tok in _iter_tokens(body_start, body_end):
            s = _tok_str(tok)
            if s not in ("==", "!="):
                continue
            lhs = _tok_astop1(tok)
            rhs = _tok_astop2(tok)
            if lhs is None or rhs is None:
                continue

            # Determine which side is the pointer and which is NULL/0
            ptr_side = None
            if _tok_str(rhs) in ("NULL", "nullptr", "0"):
                ptr_side = lhs
            elif _tok_str(lhs) in ("NULL", "nullptr", "0"):
                ptr_side = rhs

            if ptr_side is None:
                continue
            vid = _tok_var_id(ptr_side)
            if vid and vid in ctx.vars and _var_is_pointer(ctx.vars[vid].var):
                null_checked[vid] = tok

        # Now scan for dereferences of those pointers
        for tok in _iter_tokens(body_start, body_end):
            if _tok_str(tok) != "*":
                continue
            op = _tok_astop1(tok)
            if op is None:
                continue
            vid = _tok_var_id(op)
            if vid and vid in null_checked:
                info = ctx.vars.get(vid)
                name = info.name if info else _tok_str(op)
                cmp_tok = null_checked[vid]
                R.error(
                    "nullDerefAfterCheck",
                    f"pointer '{name}' is dereferenced after being compared to NULL",
                ).at(
                    _tok_file(tok), _tok_line(tok), _tok_col(tok),
                ).note(
                    _tok_file(cmp_tok), _tok_line(cmp_tok),
                    f"'{name}' was compared to NULL here",
                ).help(
                    "ensure the dereference is inside the non-NULL branch",
                ).cwe(CWE.NULL_DEREF).emit()
                ctx.diag_count["nullDerefAfterCheck"] += 1
                # Only report once per variable per function
                del null_checked[vid]


# --------------------------------------------------------------------------- #
# 12. danglingPointer  (CWE-825)
# --------------------------------------------------------------------------- #

def check_dangling_pointer(ctx: AnalysisContext) -> None:
    """
    Detect use of a pointer after ``free()`` without reassignment.
    """
    cfg = ctx.cfg
    for scope in getattr(cfg, "scopes", []):
        if _scope_type(scope) != "Function":
            continue
        body_start = _scope_bodystart(scope)
        body_end = _scope_bodyend(scope)
        if body_start is None or body_end is None:
            continue

        freed: Dict[int, Any] = {}  # vid → free-call token

        for tok in _iter_tokens(body_start, body_end):
            s = _tok_str(tok)

            # Detect free(ptr) / delete ptr
            if s in ("free", "g_free", "cfree"):
                nxt = _tok_next(tok)
                if nxt and _tok_str(nxt) == "(":
                    arg = _tok_next(nxt)
                    if arg:
                        vid = _tok_var_id(arg)
                        if vid:
                            freed[vid] = tok
                continue

            if s == "delete":
                nxt = _tok_next(tok)
                if nxt:
                    vid = _tok_var_id(nxt)
                    if vid:
                        freed[vid] = tok
                continue

            vid = _tok_var_id(tok)
            if vid == 0:
                continue

            # If this variable is assigned, remove from freed set
            parent = _tok_astparent(tok)
            if parent and _tok_is_assign(parent) and _tok_astop1(parent) is tok:
                freed.pop(vid, None)
                continue

            # If used after free
            if vid in freed:
                info = ctx.vars.get(vid)
                name = info.name if info else _tok_str(tok)
                free_tok = freed[vid]
                R.error(
                    "danglingPointer",
                    f"pointer '{name}' used after free",
                ).at(
                    _tok_file(tok), _tok_line(tok), _tok_col(tok),
                ).note(
                    _tok_file(free_tok), _tok_line(free_tok),
                    f"'{name}' was freed here",
                ).help(
                    "set pointer to NULL after free, or restructure ownership",
                ).cwe(CWE.DANGLING_PTR).emit()
                ctx.diag_count["danglingPointer"] += 1
                del freed[vid]


# --------------------------------------------------------------------------- #
# 13. volatileMisuse  (CWE-667)
# --------------------------------------------------------------------------- #

def check_volatile_misuse(ctx: AnalysisContext) -> None:
    """
    Detect suspicious patterns involving volatile-qualified variables:
    - Multiple reads of a volatile in a single expression (value may change
      between reads).
    """
    cfg = ctx.cfg
    for scope in getattr(cfg, "scopes", []):
        if _scope_type(scope) != "Function":
            continue
        body_start = _scope_bodystart(scope)
        body_end = _scope_bodyend(scope)
        if body_start is None or body_end is None:
            continue

        # Walk AST roots — expressions that appear as statement-level
        for tok in _iter_tokens(body_start, body_end):
            parent = _tok_astparent(tok)
            if parent is not None:
                continue
            # This is an AST root; count volatile variable reads
            vol_reads: Dict[int, int] = defaultdict(int)
            _count_volatile_reads(tok, vol_reads, ctx)
            for vid, count in vol_reads.items():
                if count >= 2:
                    info = ctx.vars.get(vid)
                    name = info.name if info else f"var#{vid}"
                    R.warning(
                        "volatileMisuse",
                        f"volatile variable '{name}' read {count} times in one expression",
                    ).at(
                        _tok_file(tok), _tok_line(tok), _tok_col(tok),
                    ).help(
                        "cache the volatile read in a local variable if both reads must see the same value",
                    ).cwe(CWE.VOLATILE_MISUSE).emit()
                    ctx.diag_count["volatileMisuse"] += 1


def _count_volatile_reads(tok: Any, acc: Dict[int, int], ctx: AnalysisContext) -> None:
    if tok is None:
        return
    vid = _tok_var_id(tok)
    if vid and vid in ctx.vars and _var_is_volatile(ctx.vars[vid].var):
        acc[vid] += 1
    _count_volatile_reads(_tok_astop1(tok), acc, ctx)
    _count_volatile_reads(_tok_astop2(tok), acc, ctx)


# --------------------------------------------------------------------------- #
# 14. toctou  (CWE-367) — Time-of-Check Time-of-Use
# --------------------------------------------------------------------------- #

_CHECK_FUNCS = frozenset({"access", "stat", "lstat", "fstat"})
_USE_FUNCS = frozenset({
    "open", "fopen", "creat", "mkdir", "rmdir", "unlink",
    "remove", "rename", "chmod", "chown", "chdir", "chroot",
    "link", "symlink", "truncate",
})


def check_toctou(ctx: AnalysisContext) -> None:
    """
    Detect check-then-use patterns on file paths:

        if (access(path, R_OK) == 0)
            fopen(path, "r");        // TOCTOU window!

    Heuristic: within the same function, if a variable appears as an
    argument to a check function and later to a use function, flag it.
    """
    cfg = ctx.cfg
    for scope in getattr(cfg, "scopes", []):
        if _scope_type(scope) != "Function":
            continue
        body_start = _scope_bodystart(scope)
        body_end = _scope_bodyend(scope)
        if body_start is None or body_end is None:
            continue

        checked_vars: Dict[int, Any] = {}  # vid → check-call token

        for tok in _iter_tokens(body_start, body_end):
            s = _tok_str(tok)

            if s in _CHECK_FUNCS:
                nxt = _tok_next(tok)
                if nxt and _tok_str(nxt) == "(":
                    arg = _tok_next(nxt)
                    if arg:
                        vid = _tok_var_id(arg)
                        if vid:
                            checked_vars[vid] = tok
                continue

            if s in _USE_FUNCS:
                nxt = _tok_next(tok)
                if nxt and _tok_str(nxt) == "(":
                    arg = _tok_next(nxt)
                    if arg:
                        vid = _tok_var_id(arg)
                        if vid and vid in checked_vars:
                            info = ctx.vars.get(vid)
                            name = info.name if info else _tok_str(arg)
                            check_tok = checked_vars[vid]
                            R.warning(
                                "toctou",
                                f"TOCTOU race condition on '{name}'",
                            ).at(
                                _tok_file(tok), _tok_line(tok), _tok_col(tok),
                            ).note(
                                _tok_file(check_tok), _tok_line(check_tok),
                                f"'{_tok_str(check_tok)}({name}, ...)' check here",
                            ).help(
                                "use file-descriptor-based operations (fstat+fdopen) "
                                "to avoid the race window",
                            ).cwe(CWE.TOCTOU).emit()
                            ctx.diag_count["toctou"] += 1


# --------------------------------------------------------------------------- #
# 15. pointerArithOverflow  (CWE-119, CWE-787)
# --------------------------------------------------------------------------- #

def check_pointer_arith_overflow(ctx: AnalysisContext) -> None:
    """
    Heuristic: detect ``ptr + expr`` or ``ptr[expr]`` where *expr* has a
    known-possible negative value (from cppcheck value-flow) — suggests
    out-of-bounds access.
    """
    cfg = ctx.cfg
    for scope in getattr(cfg, "scopes", []):
        if _scope_type(scope) != "Function":
            continue
        body_start = _scope_bodystart(scope)
        body_end = _scope_bodyend(scope)
        if body_start is None or body_end is None:
            continue
        for tok in _iter_tokens(body_start, body_end):
            s = _tok_str(tok)
            if s not in ("+", "-", "["):
                continue
            lhs = _tok_astop1(tok)
            rhs = _tok_astop2(tok)
            if lhs is None or rhs is None:
                continue

            # One side must be a pointer
            ptr_side = None
            idx_side = None
            if _var_is_pointer(ctx.vars[_tok_var_id(lhs)].var) if _tok_var_id(lhs) in ctx.vars else False:
                ptr_side, idx_side = lhs, rhs
            elif _var_is_pointer(ctx.vars[_tok_var_id(rhs)].var) if _tok_var_id(rhs) in ctx.vars else False:
                ptr_side, idx_side = rhs, lhs

            if ptr_side is None or idx_side is None:
                continue

            # Check value-flow for negative values
            for val in _tok_values(idx_side):
                int_val = getattr(val, "intvalue", None)
                if int_val is not None and int_val < 0:
                    info = ctx.vars.get(_tok_var_id(ptr_side))
                    name = info.name if info else _tok_str(ptr_side)
                    R.error(
                        "pointerArithOverflow",
                        f"pointer arithmetic on '{name}' may go out of bounds "
                        f"(index could be {int_val})",
                    ).at(
                        _tok_file(tok), _tok_line(tok), _tok_col(tok),
                    ).help(
                        "validate the index is non-negative and within bounds",
                    ).cwe(CWE.PTR_ARITH_OOB).emit()
                    ctx.diag_count["pointerArithOverflow"] += 1
                    break  # one report per site


# ═══════════════════════════════════════════════════════════════════════════════
#  MASTER RUNNER
# ═══════════════════════════════════════════════════════════════════════════════

_ALL_CHECKS: List[Callable[[AnalysisContext], None]] = [
    check_uninit_var,
    check_unused_variable,
    check_shadow_variable,
    check_dead_store,
    check_const_variable,
    check_self_assignment,
    check_redundant_assignment,
    check_narrowing_conversion,
    check_sign_conversion,
    check_uninit_struct_member,
    check_null_deref_after_check,
    check_dangling_pointer,
    check_volatile_misuse,
    check_toctou,
    check_pointer_arith_overflow,
]


def run_variable_lint(data: Any) -> Dict[str, int]:
    """
    Run all VariableLint checks on a cppcheckdata dump.

    Args:
        data: A ``cppcheckdata.CppcheckData`` object (from parsedump).

    Returns:
        Dictionary mapping check-id → count of diagnostics emitted.
    """
    total_counts: Dict[str, int] = defaultdict(int)

    for cfg in getattr(data, "configurations", []):
        ctx = AnalysisContext(cfg=cfg)
        _collect_var_info(ctx)

        for checker in _ALL_CHECKS:
            try:
                checker(ctx)
            except Exception as exc:  # noqa: BLE001
                print(
                    f"[VariableLint] internal error in {checker.__name__}: {exc}",
                    file=sys.stderr,
                )

        for k, v in ctx.diag_count.items():
            total_counts[k] += v

    return dict(total_counts)


# ═══════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

def main() -> int:
    parser = argparse.ArgumentParser(
        prog="VariableLint",
        description="cppcheck addon: detect variable-related weaknesses "
                    "(CWE-mapped, Rust-style diagnostics via plus_reporter)",
    )
    parser.add_argument(
        "dumpfiles",
        nargs="*",
        help="one or more .dump files produced by cppcheck --dump",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="emit built-in test cases and exit",
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="suppress summary at end",
    )

    args = parser.parse_args()

    # ── Self-test mode ────────────────────────────────────────────────────
    if not args.dumpfiles:
        parser.print_help(sys.stderr)
        return 1

    # ── Ensure cppcheckdata is available ─────────────────────────────────
    if cppcheckdata is None:
        print(
            "[VariableLint] FATAL: cannot import cppcheckdata or "
            "cppcheckdata_shims.  Install cppcheck or provide the shims.",
            file=sys.stderr,
        )
        return 2

    # ── Process each dump file ───────────────────────────────────────────
    grand_total: Dict[str, int] = defaultdict(int)

    for dumpfile in args.dumpfiles:
        if not os.path.isfile(dumpfile):
            print(f"[VariableLint] WARNING: file not found: {dumpfile}",
                  file=sys.stderr)
            continue

        try:
            data = cppcheckdata.parsedump(dumpfile)
        except Exception as exc:
            print(f"[VariableLint] ERROR: cannot parse {dumpfile}: {exc}",
                  file=sys.stderr)
            continue

        counts = run_variable_lint(data)
        for k, v in counts.items():
            grand_total[k] += v

    # ── Summary ──────────────────────────────────────────────────────────
    total = sum(grand_total.values())
    if not args.quiet:
        print(f"\nVariableLint: {total} diagnostic(s) emitted.", file=sys.stderr)
        if grand_total:
            for check_id in sorted(grand_total):
                print(f"  {check_id}: {grand_total[check_id]}", file=sys.stderr)

    return 1 if total > 0 else 0


if __name__ == "__main__":
    raise SystemExit(main())
