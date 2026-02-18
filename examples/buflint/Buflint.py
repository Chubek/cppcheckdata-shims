#!/usr/bin/env python3
"""
buflint.py  —  Cppcheck addon for buffer & memory-safety CWEs.

Detected CWEs
──────────────
  CWE-120  Classic buffer overflow (gets / scanf %s)
  CWE-121  Stack-based buffer overflow
  CWE-122  Heap-based buffer overflow
  CWE-124  Buffer underwrite
  CWE-126  Buffer over-read
  CWE-127  Buffer under-read (negative index read)
  CWE-131  Incorrect calculation of buffer size
  CWE-135  Incorrect calculation of multi-byte string length
  CWE-170  Improper null termination
  CWE-401  Missing release of memory after effective lifetime (leak)
  CWE-415  Double free
  CWE-416  Use after free
  CWE-476  NULL pointer dereference
  CWE-590  Free of memory not on the heap
  CWE-761  Free of pointer not at start of buffer
  CWE-787  Out-of-bounds write
  CWE-805  Buffer access with incorrect length value

Architecture  (four passes, token-list + AST only, NO CFG import)
──────────────
  Pass 1 — MemSafetyAnalysis   : forward token-walk typestate tracking
  Pass 2 — PatternChecks        : syntactic pattern detection
  Pass 3 — BoundsAnalysis       : buffer-size / index checking
  Pass 4 — NullCheckAnalysis    : missing NULL check after malloc

Usage
─────
    cppcheck --dump myfile.c
    python buflint.py myfile.c.dump

Or integrated:
    cppcheck --addon=buflint.py myfile.c
"""

from __future__ import annotations

import sys
import re
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import (
    Any,
    Dict,
    List,
    Optional,
    Set,
    Tuple,
)

import cppcheckdata

# ═══════════════════════════════════════════════════════════════════
#  OPTIONAL: IntervalDomain from cppcheckdata_shims
# ═══════════════════════════════════════════════════════════════════

try:
    from cppcheckdata_shims.abstract_domains import IntervalDomain
    _HAS_INTERVAL = True
except ImportError:
    _HAS_INTERVAL = False

if not _HAS_INTERVAL:
    _INF = float("inf")

    class IntervalDomain:
        """Minimal [lo, hi] integer interval (fallback)."""

        def __init__(self, lo: float = _INF, hi: float = -_INF):
            self.lo = lo
            self.hi = hi

        @classmethod
        def const(cls, v: int) -> "IntervalDomain":
            return cls(float(v), float(v))

        @classmethod
        def range(cls, lo: int, hi: int) -> "IntervalDomain":
            return cls(float(lo), float(hi))

        def is_bottom(self) -> bool:
            return self.lo > self.hi

        def contains(self, v: int) -> bool:
            if self.is_bottom():
                return False
            return self.lo <= v <= self.hi


# ═══════════════════════════════════════════════════════════════════
#  REPORTING
# ═══════════════════════════════════════════════════════════════════

@dataclass
class Finding:
    file: str
    line: int
    column: int
    severity: str
    message: str
    cwe: int
    check_id: str

    def format_cli(self) -> str:
        return (
            f"[{self.file}:{self.line}:{self.column}] "
            f"({self.severity}) "
            f"buflint/{self.check_id}: {self.message} "
            f"[CWE-{self.cwe}]"
        )


class Reporter:
    def __init__(self) -> None:
        self.findings: List[Finding] = []
        self._seen: Set[Tuple[str, int, int, str]] = set()

    def report(self, token: Any, severity: str, message: str,
               cwe: int, check_id: str) -> None:
        f_file = getattr(token, "file", "<unknown>")
        f_line = int(getattr(token, "linenr", 0))
        f_col  = int(getattr(token, "column", 0))

        key = (f_file, f_line, cwe, check_id)
        if key in self._seen:
            return
        self._seen.add(key)

        self.findings.append(Finding(
            file=f_file, line=f_line, column=f_col,
            severity=severity, message=message,
            cwe=cwe, check_id=check_id,
        ))

    def dump(self) -> None:
        for f in sorted(self.findings, key=lambda x: (x.file, x.line, x.column)):
            print(f.format_cli())


# ═══════════════════════════════════════════════════════════════════
#  HELPER UTILITIES
# ═══════════════════════════════════════════════════════════════════

def _s(tok: Any) -> str:
    """Safe token string."""
    if tok is None:
        return ""
    return getattr(tok, "str", "") or ""


def _var_id(tok: Any) -> int:
    """Variable ID or 0."""
    if tok is None:
        return 0
    vid = getattr(tok, "varId", 0)
    return vid if vid else 0


def _is_alloc(tok: Any) -> bool:
    """Is token an allocation function name (immediately before '(')?"""
    return _s(tok) in ("malloc", "calloc", "realloc", "strdup",
                        "strndup", "aligned_alloc")


def _is_free(tok: Any) -> bool:
    return _s(tok) == "free"


def _try_eval(tok: Any) -> Optional[int]:
    """Evaluate a constant expression in the AST.  Returns None on failure."""
    if tok is None:
        return None

    s = _s(tok)

    # Integer literal
    if getattr(tok, "isNumber", False):
        try:
            if s.startswith(("0x", "0X")):
                return int(s, 16)
            if s.startswith("0") and len(s) > 1 and s.isdigit():
                return int(s, 8)
            return int(s)
        except (ValueError, OverflowError):
            return None

    # Check value-flow for known values (most reliable)
    values = getattr(tok, "values", None) or []
    for v in values:
        if getattr(v, "valueKind", "") == "known":
            iv = getattr(v, "intvalue", None)
            if iv is not None:
                return int(iv)

    # sizeof — Cppcheck resolves sizeof into values
    if s == "sizeof":
        for v in values:
            iv = getattr(v, "intvalue", None)
            if iv is not None:
                return int(iv)
        return None

    # Binary operators
    op1 = getattr(tok, "astOperand1", None)
    op2 = getattr(tok, "astOperand2", None)

    if s == "*" and op1 and op2:
        a, b = _try_eval(op1), _try_eval(op2)
        if a is not None and b is not None:
            return a * b
    if s == "+" and op1 and op2:
        a, b = _try_eval(op1), _try_eval(op2)
        if a is not None and b is not None:
            return a + b
    if s == "-" and op1 and op2:
        a, b = _try_eval(op1), _try_eval(op2)
        if a is not None and b is not None:
            return a - b
    if s == "/" and op1 and op2:
        a, b = _try_eval(op1), _try_eval(op2)
        if a is not None and b is not None and b != 0:
            return a // b
    if s == "<<" and op1 and op2:
        a, b = _try_eval(op1), _try_eval(op2)
        if a is not None and b is not None:
            return a << b

    # Fallback: first known value
    for v in values:
        iv = getattr(v, "intvalue", None)
        if iv is not None:
            return int(iv)

    return None


def _get_func_name_from_call(call_paren_tok: Any) -> str:
    """
    Given the '(' token of a function call, return the function name.
    In cppcheckdata AST:  '(' has astOperand1 = function-name,
                                   astOperand2 = first-arg (or comma tree).
    """
    op1 = getattr(call_paren_tok, "astOperand1", None)
    if op1:
        return _s(op1)
    prev = getattr(call_paren_tok, "previous", None)
    if prev and getattr(prev, "isName", False):
        return _s(prev)
    return ""


def _get_call_args_from_paren(paren_tok: Any) -> List[Any]:
    """
    Given the '(' token, collect AST argument nodes.
    astOperand2 of '(' is the arg tree.  If it's a ',' node, flatten it.
    """
    result: List[Any] = []
    root = getattr(paren_tok, "astOperand2", None)
    if root is None:
        return result
    _flatten_comma(root, result)
    return result


def _flatten_comma(tok: Any, out: List[Any]) -> None:
    if tok is None:
        return
    if _s(tok) == ",":
        _flatten_comma(getattr(tok, "astOperand1", None), out)
        _flatten_comma(getattr(tok, "astOperand2", None), out)
    else:
        out.append(tok)


def _get_alloc_size(func_name_tok: Any) -> Optional[int]:
    """
    For malloc(N) or calloc(N,M), compute the allocation size.
    func_name_tok is the name token (e.g. 'malloc'), next should be '('.
    """
    name = _s(func_name_tok)
    nxt = getattr(func_name_tok, "next", None)
    if nxt is None or _s(nxt) != "(":
        return None

    args = _get_call_args_from_paren(nxt)

    if name == "malloc" and len(args) >= 1:
        return _try_eval(args[0])
    if name == "calloc" and len(args) >= 2:
        a = _try_eval(args[0])
        b = _try_eval(args[1])
        if a is not None and b is not None:
            return a * b
    return None


def _get_array_dimension(var: Any) -> Optional[int]:
    """
    Get the first dimension of an array variable from its declaration.
    Uses the variable's nameToken and walks the declaration tokens.
    """
    if var is None:
        return None
    if not getattr(var, "isArray", False):
        return None

    name_tok = getattr(var, "nameToken", None)
    if name_tok is None:
        return None

    # Walk from nameToken looking for [ N ]
    t = name_tok.next
    if t and _s(t) == "[":
        # Try AST of the bracket expression
        # In the AST, the '[' in declaration context may have the
        # dimension as astOperand2
        dim = getattr(t, "astOperand2", None)
        if dim:
            v = _try_eval(dim)
            if v is not None:
                return v

        # Fallback: look at the token between [ and ]
        link = getattr(t, "link", None)
        if link:
            inner = t.next
            if inner and inner != link:
                v = _try_eval(inner)
                if v is not None:
                    return v
    return None


def _get_element_size_from_var(var: Any) -> int:
    """Get element size from variable type.  Default 1."""
    if var is None:
        return 1
    name_tok = getattr(var, "nameToken", None)
    tok_to_check = name_tok if name_tok else None
    if tok_to_check is None:
        return 1

    vt = getattr(tok_to_check, "valueType", None)
    if vt is None:
        return 1

    type_name = getattr(vt, "type", "")
    size_map = {
        "char": 1, "short": 2, "int": 4, "long": 8,
        "float": 4, "double": 8,
    }
    return size_map.get(type_name, 1)


# ═══════════════════════════════════════════════════════════════════
#  POINTER STATE FOR PASS 1
# ═══════════════════════════════════════════════════════════════════

class AllocState(Enum):
    UNKNOWN     = auto()
    ALLOCATED   = auto()
    FREED       = auto()
    NULL        = auto()
    NON_HEAP    = auto()


@dataclass
class PtrInfo:
    state: AllocState = AllocState.UNKNOWN
    alloc_tok: Optional[Any] = None
    free_tok: Optional[Any] = None
    is_offset: bool = False
    alloc_size: Optional[int] = None


# ═══════════════════════════════════════════════════════════════════
#  PASS 1 — MEMORY SAFETY (typestate, forward token walk)
# ═══════════════════════════════════════════════════════════════════

class MemSafetyAnalysis:
    """
    CWE-415 (double free), CWE-416 (use-after-free),
    CWE-401 (leak), CWE-476 (null deref),
    CWE-590 (free non-heap), CWE-761 (free offset ptr).
    """

    def __init__(self, reporter: Reporter) -> None:
        self.reporter = reporter
        self.env: Dict[int, PtrInfo] = {}

    def run(self, cfg_data: Any) -> None:
        """Iterate over the full token list for each configuration."""
        self.env.clear()

        # Walk the ENTIRE token list — this is the reliable way
        for tok in cfg_data.tokenlist:
            self._visit(tok)

        # Leak check at end of each function scope
        for scope in getattr(cfg_data, "scopes", []):
            stype = getattr(scope, "type", "")
            if stype in ("Function",):
                self._check_leaks(scope)

    def _visit(self, tok: Any) -> None:
        s = _s(tok)

        # ── p = malloc(...) / p = NULL / p = &x / p = q ──
        if s == "=":
            self._on_assign(tok)
            return

        # ── free(p) — detected via the '(' whose func-name is 'free' ──
        if s == "(" and _is_free(getattr(tok, "astOperand1", None)):
            self._on_free(tok)
            return

        # ── dereferences: *p  p[i]  p->m ──
        if s == "*" and getattr(tok, "astOperand1", None) and not getattr(tok, "astOperand2", None):
            # Unary dereference: * has only astOperand1
            self._check_deref(tok, getattr(tok, "astOperand1", None))
        elif s == "[":
            self._check_deref(tok, getattr(tok, "astOperand1", None))
        elif s == "->":
            self._check_deref(tok, getattr(tok, "astOperand1", None))

        # ── Pointer arithmetic: p++  p+=N ──
        if s in ("++", "--"):
            target = getattr(tok, "astOperand1", None)
            vid = _var_id(target)
            if vid and vid in self.env:
                self.env[vid].is_offset = True

    def _on_assign(self, tok: Any) -> None:
        """Handle lhs = rhs."""
        lhs = getattr(tok, "astOperand1", None)
        rhs = getattr(tok, "astOperand2", None)
        if lhs is None or rhs is None:
            return

        vid = _var_id(lhs)
        if not vid:
            return

        # Before assigning, check if old value leaks
        old = self.env.get(vid)
        if old and old.state == AllocState.ALLOCATED:
            self.reporter.report(
                tok, "warning",
                f"Pointer '{_s(lhs)}' reassigned without free "
                f"(allocated at line {getattr(old.alloc_tok, 'linenr', '?')})",
                cwe=401, check_id="memoryLeak",
            )

        rhs_s = _s(rhs)

        # p = NULL / 0 / nullptr
        if rhs_s in ("NULL", "nullptr") or (rhs_s == "0" and not getattr(rhs, "astOperand1", None)):
            self.env[vid] = PtrInfo(state=AllocState.NULL)
            return

        # p = malloc(...)  — rhs is the '(' of the call, astOperand1 = func name
        if rhs_s == "(":
            fname = _s(getattr(rhs, "astOperand1", None))
            if fname in ("malloc", "calloc", "strdup", "strndup",
                         "aligned_alloc", "realloc"):
                func_tok = getattr(rhs, "astOperand1", None)
                sz = _get_alloc_size(func_tok) if func_tok else None

                # Check realloc(p, size) — self-assignment leak
                if fname == "realloc":
                    args = _get_call_args_from_paren(rhs)
                    if args:
                        old_vid = _var_id(args[0])
                        if old_vid and old_vid == vid:
                            self.reporter.report(
                                tok, "warning",
                                f"p = realloc(p, n) leaks if realloc fails. "
                                f"Use a temporary.",
                                cwe=401, check_id="reallocLeak",
                            )

                self.env[vid] = PtrInfo(
                    state=AllocState.ALLOCATED,
                    alloc_tok=tok,
                    alloc_size=sz,
                )
                return

        # p = &local / p = array_name / p = "literal"
        if rhs_s == "&":
            self.env[vid] = PtrInfo(state=AllocState.NON_HEAP)
            return
        if getattr(rhs, "isString", False):
            self.env[vid] = PtrInfo(state=AllocState.NON_HEAP)
            return
        rhs_var = getattr(rhs, "variable", None)
        if rhs_var and getattr(rhs_var, "isArray", False):
            self.env[vid] = PtrInfo(state=AllocState.NON_HEAP)
            return

        # p = q  (alias copy)
        rhs_vid = _var_id(rhs)
        if rhs_vid and rhs_vid in self.env:
            src = self.env[rhs_vid]
            self.env[vid] = PtrInfo(
                state=src.state, alloc_tok=src.alloc_tok,
                free_tok=src.free_tok, is_offset=src.is_offset,
                alloc_size=src.alloc_size,
            )
            return

        # p = q + N  (offset)
        if rhs_s in ("+", "-"):
            base = getattr(rhs, "astOperand1", None)
            bvid = _var_id(base)
            if bvid and bvid in self.env:
                src = self.env[bvid]
                self.env[vid] = PtrInfo(
                    state=src.state, alloc_tok=src.alloc_tok,
                    free_tok=src.free_tok, is_offset=True,
                    alloc_size=src.alloc_size,
                )
                return

        # Unknown
        self.env[vid] = PtrInfo(state=AllocState.UNKNOWN)

    def _on_free(self, paren_tok: Any) -> None:
        """
        Handle free(p).
        paren_tok is the '(' token.
        AST:  '(' → astOperand1='free', astOperand2='p'
        """
        args = _get_call_args_from_paren(paren_tok)
        if not args:
            return
        arg = args[0]
        arg_vid = _var_id(arg)

        # free(stack_array) → CWE-590
        arg_var = getattr(arg, "variable", None)
        if arg_var:
            if getattr(arg_var, "isArray", False) and getattr(arg_var, "isLocal", False):
                self.reporter.report(
                    paren_tok, "error",
                    f"Freeing stack-allocated array '{_s(arg)}'",
                    cwe=590, check_id="freeNonHeap",
                )
                return
            if getattr(arg_var, "isGlobal", False):
                self.reporter.report(
                    paren_tok, "error",
                    f"Freeing global variable '{_s(arg)}'",
                    cwe=590, check_id="freeNonHeap",
                )
                return

        if not arg_vid:
            return

        info = self.env.get(arg_vid)
        if info is None:
            # First encounter — just record as freed
            self.env[arg_vid] = PtrInfo(state=AllocState.FREED, free_tok=paren_tok)
            return

        if info.state == AllocState.NON_HEAP:
            self.reporter.report(
                paren_tok, "error",
                f"Freeing non-heap pointer '{_s(arg)}'",
                cwe=590, check_id="freeNonHeap",
            )
            return

        if info.state == AllocState.FREED:
            prev = getattr(info.free_tok, "linenr", "?")
            self.reporter.report(
                paren_tok, "error",
                f"Double free of '{_s(arg)}' (previously freed at line {prev})",
                cwe=415, check_id="doubleFree",
            )
            return

        if info.is_offset:
            self.reporter.report(
                paren_tok, "error",
                f"Freeing offset pointer '{_s(arg)}' "
                f"(not at start of allocation)",
                cwe=761, check_id="freeOffsetPointer",
            )

        if info.state == AllocState.NULL:
            return  # free(NULL) is valid

        info.state = AllocState.FREED
        info.free_tok = paren_tok

    def _check_deref(self, tok: Any, target: Any) -> None:
        """Check if target pointer is freed or null."""
        if target is None:
            return
        vid = _var_id(target)
        if not vid:
            return
        info = self.env.get(vid)
        if info is None:
            return

        if info.state == AllocState.FREED:
            fl = getattr(info.free_tok, "linenr", "?")
            self.reporter.report(
                tok, "error",
                f"Use after free: '{_s(target)}' freed at line {fl}",
                cwe=416, check_id="useAfterFree",
            )
        elif info.state == AllocState.NULL:
            self.reporter.report(
                tok, "error",
                f"NULL pointer dereference: '{_s(target)}'",
                cwe=476, check_id="nullDeref",
            )

    def _check_leaks(self, scope: Any) -> None:
        """At function exit, check for allocated-but-not-freed pointers."""
        body_end = getattr(scope, "bodyEnd", None)
        if body_end is None:
            return
        for vid, info in self.env.items():
            if info.state == AllocState.ALLOCATED:
                al = getattr(info.alloc_tok, "linenr", "?")
                self.reporter.report(
                    body_end, "warning",
                    f"Memory leak: allocation at line {al} not freed",
                    cwe=401, check_id="memoryLeak",
                )


# ═══════════════════════════════════════════════════════════════════
#  PASS 2 — PATTERN CHECKS (AST + token patterns)
# ═══════════════════════════════════════════════════════════════════

class PatternChecks:
    """CWE-120, CWE-131, CWE-135, CWE-170."""

    def __init__(self, reporter: Reporter) -> None:
        self.reporter = reporter

    def run(self, cfg_data: Any) -> None:
        for tok in cfg_data.tokenlist:
            s = _s(tok)

            # ── CWE-120: gets() ──
            if s == "gets" and _s(getattr(tok, "next", None)) == "(":
                self.reporter.report(
                    tok, "error",
                    "Use of gets() is always unsafe — use fgets()",
                    cwe=120, check_id="dangerousGets",
                )

            # ── CWE-120: scanf %s without width ──
            if s in ("scanf", "fscanf", "sscanf"):
                self._check_scanf(tok)

            # ── CWE-131 / CWE-135 / CWE-170: alloc + string patterns ──
            # Detect via the '(' of malloc/calloc call
            if s == "(" and _s(getattr(tok, "astOperand1", None)) in ("malloc", "calloc"):
                self._check_alloc_size_patterns(tok)

            # ── CWE-170: strncpy without null termination ──
            if s == "strncpy" and _s(getattr(tok, "next", None)) == "(":
                self._check_strncpy(tok)

    def _check_scanf(self, tok: Any) -> None:
        nxt = getattr(tok, "next", None)
        if nxt is None or _s(nxt) != "(":
            return

        # Find the format string token
        args = _get_call_args_from_paren(nxt)
        # For scanf: first arg is fmt; for fscanf/sscanf: second arg
        fmt_idx = 0 if _s(tok) == "scanf" else 1
        if fmt_idx >= len(args):
            return

        fmt_tok = args[fmt_idx]
        if not getattr(fmt_tok, "isString", False):
            return

        fmt_str = _s(fmt_tok).strip('"')
        # Find %s without width limiter (i.e. %s not %20s, not %*s)
        if re.search(r'%(?!\d)(?!\*)s', fmt_str):
            self.reporter.report(
                tok, "warning",
                f"'{_s(tok)}' with '%s' without width limit",
                cwe=120, check_id="scanfNoWidth",
            )

    def _check_alloc_size_patterns(self, paren_tok: Any) -> None:
        """
        paren_tok is '(' of malloc/calloc call.
        Check if the size argument is strlen(s) without +1.
        """
        arg_root = getattr(paren_tok, "astOperand2", None)
        if arg_root is None:
            return

        func_name = _s(getattr(paren_tok, "astOperand1", None))

        # For calloc, the size expression is the product — check both args
        # For malloc, arg_root is the single argument
        if self._has_strlen_without_plus1(arg_root):
            self.reporter.report(
                paren_tok, "warning",
                "Allocation uses strlen() without +1 for null terminator",
                cwe=131, check_id="strlenNoPlusOne",
            )

        if self._has_wcslen_without_sizeof_wchar(arg_root):
            self.reporter.report(
                paren_tok, "warning",
                "Wide-string allocation uses wcslen() without "
                "sizeof(wchar_t)",
                cwe=135, check_id="wcslenSizeof",
            )

    def _has_strlen_without_plus1(self, tok: Any) -> bool:
        """Check if AST contains strlen() not wrapped in strlen()+1."""
        if tok is None:
            return False
        s = _s(tok)

        # If this node is '+' with one side being strlen and other being 1 → OK
        if s == "+":
            op1 = getattr(tok, "astOperand1", None)
            op2 = getattr(tok, "astOperand2", None)
            if self._is_strlen_expr(op1) and _try_eval(op2) == 1:
                return False
            if self._is_strlen_expr(op2) and _try_eval(op1) == 1:
                return False
            # Both strlen → missing +1 for concatenation
            if self._is_strlen_expr(op1) and self._is_strlen_expr(op2):
                return True
            # One is strlen, other is not 1
            if self._is_strlen_expr(op1) or self._is_strlen_expr(op2):
                return True

        # Direct strlen call as entire argument
        if self._is_strlen_expr(tok):
            return True

        # strlen * sizeof(char) — still missing +1
        if s == "*":
            op1 = getattr(tok, "astOperand1", None)
            op2 = getattr(tok, "astOperand2", None)
            if self._is_strlen_expr(op1) or self._is_strlen_expr(op2):
                return True

        return False

    def _is_strlen_expr(self, tok: Any) -> bool:
        """Is this tok a call to strlen (possibly wrapped in '(')?"""
        if tok is None:
            return False
        s = _s(tok)
        if s == "strlen":
            return True
        # AST: '(' with astOperand1 = 'strlen'
        if s == "(":
            return _s(getattr(tok, "astOperand1", None)) == "strlen"
        return False

    def _has_wcslen_without_sizeof_wchar(self, tok: Any) -> bool:
        if tok is None:
            return False
        s = _s(tok)

        is_wcslen = self._is_wcslen_expr(tok)
        if is_wcslen:
            return True  # bare wcslen with no multiplication

        if s == "*":
            op1 = getattr(tok, "astOperand1", None)
            op2 = getattr(tok, "astOperand2", None)
            has_wcs = self._is_wcslen_expr(op1) or self._is_wcslen_expr(op2)
            if not has_wcs:
                return False
            other = op2 if self._is_wcslen_expr(op1) else op1
            # Check if other is sizeof(wchar_t) — value should be 4 usually
            v = _try_eval(other)
            if v is not None and v >= 4:
                return False  # probably sizeof(wchar_t)
            return True

        return False

    def _is_wcslen_expr(self, tok: Any) -> bool:
        if tok is None:
            return False
        if _s(tok) == "wcslen":
            return True
        if _s(tok) == "(":
            return _s(getattr(tok, "astOperand1", None)) == "wcslen"
        return False

    def _check_strncpy(self, tok: Any) -> None:
        """Detect strncpy without subsequent null termination."""
        nxt = getattr(tok, "next", None)
        if not nxt:
            return
        args = _get_call_args_from_paren(nxt)
        if not args:
            return

        dst_tok = args[0]
        dst_name = _s(dst_tok)
        if not dst_name:
            return

        # Look ahead up to 30 tokens for  dst[...] = '\0' / 0
        t = tok
        found = False
        for _ in range(40):
            t = getattr(t, "next", None)
            if t is None:
                break
            ts = _s(t)
            if ts == "}" or ts == "return":
                break
            # dst [ ... ] = 0 / '\0'
            if ts == dst_name:
                n1 = getattr(t, "next", None)
                if n1 and _s(n1) == "[":
                    link = getattr(n1, "link", None)
                    if link:
                        eq = getattr(link, "next", None)
                        if eq and _s(eq) == "=":
                            val = getattr(eq, "next", None)
                            if val and _s(val) in ("0", "'\\0'"):
                                found = True
                                break

        if not found:
            self.reporter.report(
                tok, "warning",
                f"strncpy to '{dst_name}' without explicit null "
                f"termination — may not be null-terminated",
                cwe=170, check_id="strncpyNoNullTerm",
            )


# ═══════════════════════════════════════════════════════════════════
#  PASS 3 — BOUNDS ANALYSIS
# ═══════════════════════════════════════════════════════════════════

class BoundsAnalysis:
    """CWE-121/122/124/126/127/787/805."""

    WRITE_FUNCS: Dict[str, Tuple[int, int]] = {
        # func_name: (dst_arg_idx, size_arg_idx)
        "memcpy":  (0, 2),
        "memmove": (0, 2),
        "memset":  (0, 2),
        "strncpy": (0, 2),
        "strncat": (0, 2),
    }

    def __init__(self, reporter: Reporter,
                 mem_env: Dict[int, PtrInfo]) -> None:
        self.reporter = reporter
        self.mem_env = mem_env

    def run(self, cfg_data: Any) -> None:
        for tok in cfg_data.tokenlist:
            s = _s(tok)

            # Array subscript  a[i]
            if s == "[" and getattr(tok, "astOperand1", None):
                self._check_subscript(tok)

            # Memory write functions
            if s == "(" and _s(getattr(tok, "astOperand1", None)) in self.WRITE_FUNCS:
                self._check_memfunc(tok)

    def _check_subscript(self, tok: Any) -> None:
        arr = getattr(tok, "astOperand1", None)
        idx_tok = getattr(tok, "astOperand2", None)
        if arr is None or idx_tok is None:
            return

        buf_size = self._buf_size(arr)
        if buf_size is None:
            return

        # Collect possible index values
        indices: List[int] = []
        v = _try_eval(idx_tok)
        if v is not None:
            indices.append(v)
        else:
            for val in (getattr(idx_tok, "values", None) or []):
                iv = getattr(val, "intvalue", None)
                if iv is not None:
                    indices.append(int(iv))

        if not indices:
            return

        is_write = self._is_write(tok)
        is_heap = self._is_heap(arr)

        for idx in indices:
            if idx < 0:
                cwe = 124 if is_write else 127
                tag = "Underwrite" if is_write else "Underread"
                self.reporter.report(
                    tok, "error",
                    f"Buffer {tag.lower()}: '{_s(arr)}[{idx}]' "
                    f"— negative index",
                    cwe=cwe, check_id=f"buffer{tag}",
                )
            elif idx >= buf_size:
                if is_write:
                    cwe = 122 if is_heap else 121
                    kind = "Heap" if is_heap else "Stack"
                    self.reporter.report(
                        tok, "error",
                        f"{kind} buffer overflow: '{_s(arr)}[{idx}]' "
                        f"exceeds size {buf_size}",
                        cwe=cwe, check_id="bufferOverflow",
                    )
                else:
                    self.reporter.report(
                        tok, "warning",
                        f"Buffer over-read: '{_s(arr)}[{idx}]' "
                        f"exceeds size {buf_size}",
                        cwe=126, check_id="bufferOverread",
                    )

    def _check_memfunc(self, paren_tok: Any) -> None:
        fname = _s(getattr(paren_tok, "astOperand1", None))
        info = self.WRITE_FUNCS.get(fname)
        if info is None:
            return

        dst_idx, size_idx = info
        args = _get_call_args_from_paren(paren_tok)
        if dst_idx >= len(args) or size_idx >= len(args):
            return

        dst = args[dst_idx]
        size_tok = args[size_idx]

        dst_bytes = self._buf_size_bytes(dst)
        copy_size = _try_eval(size_tok)

        if dst_bytes is not None and copy_size is not None and copy_size > dst_bytes:
            self.reporter.report(
                paren_tok, "error",
                f"'{fname}' writes {copy_size} bytes into "
                f"'{_s(dst)}' of {dst_bytes} bytes",
                cwe=805, check_id="bufferAccessIncorrectLength",
            )

    # -- helpers --

    def _buf_size(self, tok: Any) -> Optional[int]:
        """Size in elements."""
        var = getattr(tok, "variable", None)
        dim = _get_array_dimension(var)
        if dim is not None:
            return dim

        vid = _var_id(tok)
        if vid and vid in self.mem_env:
            info = self.mem_env[vid]
            if info.alloc_size is not None:
                esz = _get_element_size_from_var(var) if var else 1
                return info.alloc_size // max(esz, 1)

        return None

    def _buf_size_bytes(self, tok: Any) -> Optional[int]:
        var = getattr(tok, "variable", None)
        dim = _get_array_dimension(var)
        if dim is not None:
            esz = _get_element_size_from_var(var) if var else 1
            return dim * esz

        vid = _var_id(tok)
        if vid and vid in self.mem_env:
            info = self.mem_env[vid]
            return info.alloc_size

        return None

    def _is_heap(self, tok: Any) -> bool:
        vid = _var_id(tok)
        if vid and vid in self.mem_env:
            return self.mem_env[vid].state in (AllocState.ALLOCATED,
                                                AllocState.FREED)
        var = getattr(tok, "variable", None)
        if var:
            return getattr(var, "isPointer", False) and not getattr(var, "isArray", False)
        return False

    def _is_write(self, bracket_tok: Any) -> bool:
        """Is this subscript on the LHS of an assignment?"""
        parent = getattr(bracket_tok, "astParent", None)
        if parent is None:
            return False
        ps = _s(parent)
        if ps in ("=", "+=", "-=", "*=", "/=", "%=",
                   "|=", "&=", "^=", "<<=", ">>="):
            return getattr(parent, "astOperand1", None) is bracket_tok
        return False


# ═══════════════════════════════════════════════════════════════════
#  PASS 4 — NULL CHECK AFTER ALLOCATION
# ═══════════════════════════════════════════════════════════════════

class NullCheckAnalysis:
    """CWE-476: dereference of pointer from malloc without NULL check."""

    def __init__(self, reporter: Reporter) -> None:
        self.reporter = reporter

    def run(self, cfg_data: Any) -> None:
        unchecked: Dict[int, Any] = {}  # var_id → alloc_token

        for tok in cfg_data.tokenlist:
            s = _s(tok)

            # ── Assignment from allocator ──
            if s == "=":
                lhs = getattr(tok, "astOperand1", None)
                rhs = getattr(tok, "astOperand2", None)
                if lhs and rhs:
                    vid = _var_id(lhs)
                    if vid and _s(rhs) == "(":
                        fname = _s(getattr(rhs, "astOperand1", None))
                        if fname in ("malloc", "calloc", "realloc"):
                            unchecked[vid] = tok

            # ── NULL-check patterns ──
            if s in ("!", "==", "!=", "if"):
                self._absorb_check(tok, unchecked)

            # ── Dereference ──
            if s in ("*", "->"):
                target = getattr(tok, "astOperand1", None)
                vid = _var_id(target)
                if vid and vid in unchecked:
                    self.reporter.report(
                        tok, "warning",
                        f"Pointer '{_s(target)}' dereferenced without "
                        f"NULL check after allocation",
                        cwe=476, check_id="nullDerefAlloc",
                    )
                    del unchecked[vid]
            if s == "[":
                target = getattr(tok, "astOperand1", None)
                vid = _var_id(target)
                if vid and vid in unchecked:
                    self.reporter.report(
                        tok, "warning",
                        f"Pointer '{_s(target)}' used without NULL check "
                        f"after allocation",
                        cwe=476, check_id="nullDerefAlloc",
                    )
                    del unchecked[vid]

    def _absorb_check(self, tok: Any, unchecked: Dict[int, Any]) -> None:
        """Remove from unchecked if the variable appears in a condition."""
        for attr in ("astOperand1", "astOperand2"):
            child = getattr(tok, attr, None)
            if child:
                vid = _var_id(child)
                if vid and vid in unchecked:
                    del unchecked[vid]
                # One level deeper for patterns like if(p == NULL)
                for attr2 in ("astOperand1", "astOperand2"):
                    gc = getattr(child, attr2, None)
                    if gc:
                        vid2 = _var_id(gc)
                        if vid2 and vid2 in unchecked:
                            del unchecked[vid2]


# ═══════════════════════════════════════════════════════════════════
#  ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════════

class BuflintChecker:
    def __init__(self) -> None:
        self.reporter = Reporter()

    def check(self, data: Any) -> None:
        for cfg_data in data.configurations:
            mem = MemSafetyAnalysis(self.reporter)
            mem.run(cfg_data)

            PatternChecks(self.reporter).run(cfg_data)
            BoundsAnalysis(self.reporter, mem.env).run(cfg_data)
            NullCheckAnalysis(self.reporter).run(cfg_data)

    def report(self) -> int:
        self.reporter.dump()
        return len(self.reporter.findings)


# ═══════════════════════════════════════════════════════════════════
#  ENTRY POINTS
# ═══════════════════════════════════════════════════════════════════

def check(data: Any) -> None:
    """Cppcheck addon entry point."""
    checker = BuflintChecker()
    checker.check(data)
    count = checker.report()
    if count > 0:
        sys.exit(1)


def main() -> None:
    """CLI entry point."""
    if len(sys.argv) < 2:
        print("Usage: python buflint.py <dumpfile> [...]", file=sys.stderr)
        sys.exit(2)

    total = 0
    for path in sys.argv[1:]:
        if path.startswith("-"):
            continue
        try:
            data = cppcheckdata.parsedump(path)
        except Exception as e:
            print(f"Error loading {path}: {e}", file=sys.stderr)
            continue
        checker = BuflintChecker()
        checker.check(data)
        total += checker.report()

    if total:
        print(f"\nbuflint: {total} finding(s).", file=sys.stderr)
        sys.exit(1)
    else:
        print("buflint: no findings.", file=sys.stderr)
        sys.exit(0)


if __name__ == "__main__":
    main()
