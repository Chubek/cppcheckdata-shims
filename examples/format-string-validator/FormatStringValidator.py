#!/usr/bin/env python3
"""
FormatStringValidator.py  —  Cppcheck addon for format-string CWEs.

Detected CWEs
──────────────
  CWE-134   Use of Externally-Controlled Format String
  CWE-120   Buffer Copy without Checking Size of Input (sprintf)
  CWE-126   Buffer Over-read (missing arguments → stack read)
  CWE-193   Off-by-One Error (snprintf size)
  CWE-685   Function Call With Incorrect Number of Arguments
  CWE-686   Function Call With Incorrect Argument Type
  CWE-787   Out-of-bounds Write (sprintf overflow)

Architecture  (four passes, token-list + AST only, NO private shim APIs)
──────────────
  Pass 1 — FormatCallFinder     : locates all printf/scanf-family calls
  Pass 2 — UncontrolledFmtCheck : CWE-134 (format string from variable)
  Pass 3 — ArgCountTypeCheck    : CWE-685, CWE-686, CWE-126 (count/type)
  Pass 4 — SprintfBufferCheck   : CWE-120, CWE-787, CWE-193 (overflow)

Usage
─────
    cppcheck --dump myfile.c
    python FormatStringValidator.py myfile.c.dump

Or integrated:
    cppcheck --addon=FormatStringValidator.py myfile.c

License: MIT
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

        def upper(self) -> float:
            return self.hi

        def lower(self) -> float:
            return self.lo


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
            f"fmtcheck/{self.check_id}: {self.message} "
            f"[CWE-{self.cwe}]"
        )


class Reporter:
    """Deduplicating finding reporter."""

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
        for f in sorted(self.findings,
                        key=lambda x: (x.file, x.line, x.column)):
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


def _try_eval(tok: Any) -> Optional[int]:
    """Evaluate a constant-expression AST node.  Returns None on failure."""
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

    # Known values from Cppcheck value-flow
    values = getattr(tok, "values", None) or []
    for v in values:
        if getattr(v, "valueKind", "") == "known":
            iv = getattr(v, "intvalue", None)
            if iv is not None:
                return int(iv)

    if s == "sizeof":
        for v in values:
            iv = getattr(v, "intvalue", None)
            if iv is not None:
                return int(iv)
        return None

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

    # Fallback: first known intvalue
    for v in values:
        iv = getattr(v, "intvalue", None)
        if iv is not None:
            return int(iv)

    return None


def _get_call_args_from_paren(paren_tok: Any) -> List[Any]:
    """
    Given the '(' token of a function call, collect AST argument nodes.
    AST layout:  '(' → astOperand1 = function-name
                      → astOperand2 = arg tree (flattened via commas)
    """
    result: List[Any] = []
    root = getattr(paren_tok, "astOperand2", None)
    if root is None:
        return result
    _flatten_comma(root, result)
    return result


def _flatten_comma(tok: Any, out: List[Any]) -> None:
    """Recursively flatten a comma-separated AST into a list."""
    if tok is None:
        return
    if _s(tok) == ",":
        _flatten_comma(getattr(tok, "astOperand1", None), out)
        _flatten_comma(getattr(tok, "astOperand2", None), out)
    else:
        out.append(tok)


def _get_array_dimension(var: Any) -> Optional[int]:
    """Get the first dimension of an array variable from its declaration."""
    if var is None:
        return None
    if not getattr(var, "isArray", False):
        return None

    name_tok = getattr(var, "nameToken", None)
    if name_tok is None:
        return None

    t = name_tok.next
    if t and _s(t) == "[":
        dim = getattr(t, "astOperand2", None)
        if dim:
            v = _try_eval(dim)
            if v is not None:
                return v
        link = getattr(t, "link", None)
        if link:
            inner = t.next
            if inner and inner != link:
                v = _try_eval(inner)
                if v is not None:
                    return v
    return None


# ═══════════════════════════════════════════════════════════════════
#  FORMAT SPECIFIER PARSER
# ═══════════════════════════════════════════════════════════════════

class ConversionType(Enum):
    """The conversion character at the end of a %-specifier."""
    SIGNED_INT   = auto()   # d, i
    UNSIGNED_INT = auto()   # u, o, x, X
    FLOAT        = auto()   # f, F, e, E, g, G, a, A
    CHAR         = auto()   # c
    STRING       = auto()   # s
    POINTER      = auto()   # p
    COUNT        = auto()   # n  (writes to memory!)
    PERCENT      = auto()   # %%  (literal %, consumes no arg)
    UNKNOWN      = auto()


class LengthModifier(Enum):
    """Length sub-specifier (hh, h, l, ll, j, z, t, L)."""
    NONE = auto()
    HH   = auto()
    H    = auto()
    L    = auto()   # l
    LL   = auto()   # ll
    J    = auto()
    Z    = auto()
    T    = auto()
    BIG_L = auto()  # L (long double)


@dataclass
class FormatSpecifier:
    """Parsed representation of one %-directive in a format string."""
    raw: str                           # e.g. "%-10.5ld"
    position: int                      # char offset in the format string
    flags: str = ""                    # subset of "-+ 0#"
    field_width: Optional[int] = None  # None if '*' or absent
    width_is_star: bool = False        # True if width = '*'
    precision: Optional[int] = None    # None if '*' or absent
    precision_is_star: bool = False
    length: LengthModifier = LengthModifier.NONE
    conversion: ConversionType = ConversionType.UNKNOWN
    conversion_char: str = ""          # the actual character
    consumes_arg: bool = True          # False for %%
    is_scanf: bool = False             # True when used in scanf family
    suppress_assignment: bool = False  # scanf's '*' flag


# Regex for a single printf/scanf conversion specifier.
# Reference: C11 §7.21.6.1 (fprintf) / §7.21.6.2 (fscanf)
#
# Pattern explanation:
#   %                   — literal percent
#   (\*?)               — scanf assignment suppression (group 1)
#   ([-+ 0#]*)          — flags (group 2)
#   (\*|\d*)            — field width or '*' (group 3)
#   (?:\.(\*|\d*))?     — precision (group 4, optional)
#   (hh|h|ll|l|j|z|t|L)?  — length modifier (group 5, optional)
#   ([diouxXeEfFgGaAcspn%]) — conversion character (group 6)
#
_FMT_SPEC_RE = re.compile(
    r'%'
    r'(\*?)'                            # 1: scanf suppress
    r'([-+ 0#]*)'                       # 2: flags
    r'(\*|\d*)'                         # 3: width
    r'(?:\.(\*|\d*))?'                  # 4: precision
    r'(hh|h|ll|l|j|z|t|L)?'            # 5: length
    r'([diouxXeEfFgGaAcspn%])'         # 6: conversion
)

# Scanf also supports character classes like %[abc], %[^abc]
_SCANF_CHARCLASS_RE = re.compile(
    r'%'
    r'(\*?)'                            # suppress
    r'(\d*)'                            # width
    r'\[([^\]]*)\]'                     # character class
)

_CONV_MAP: Dict[str, ConversionType] = {
    "d": ConversionType.SIGNED_INT,
    "i": ConversionType.SIGNED_INT,
    "u": ConversionType.UNSIGNED_INT,
    "o": ConversionType.UNSIGNED_INT,
    "x": ConversionType.UNSIGNED_INT,
    "X": ConversionType.UNSIGNED_INT,
    "e": ConversionType.FLOAT,
    "E": ConversionType.FLOAT,
    "f": ConversionType.FLOAT,
    "F": ConversionType.FLOAT,
    "g": ConversionType.FLOAT,
    "G": ConversionType.FLOAT,
    "a": ConversionType.FLOAT,
    "A": ConversionType.FLOAT,
    "c": ConversionType.CHAR,
    "s": ConversionType.STRING,
    "p": ConversionType.POINTER,
    "n": ConversionType.COUNT,
    "%": ConversionType.PERCENT,
}

_LEN_MAP: Dict[str, LengthModifier] = {
    "hh": LengthModifier.HH,
    "h":  LengthModifier.H,
    "l":  LengthModifier.L,
    "ll": LengthModifier.LL,
    "j":  LengthModifier.J,
    "z":  LengthModifier.Z,
    "t":  LengthModifier.T,
    "L":  LengthModifier.BIG_L,
}


def parse_format_string(fmt: str,
                        is_scanf: bool = False) -> List[FormatSpecifier]:
    """
    Parse a C format string into a list of ``FormatSpecifier`` objects.

    Parameters
    ----------
    fmt : str
        The format string content (without surrounding quotes).
    is_scanf : bool
        If True, interpret '*' as assignment suppression (scanf).

    Returns
    -------
    list[FormatSpecifier]
        Ordered list of specifiers found.  Literal text between them
        is ignored.
    """
    specs: List[FormatSpecifier] = []

    # Handle scanf character classes first
    if is_scanf:
        for m in _SCANF_CHARCLASS_RE.finditer(fmt):
            suppress = bool(m.group(1))
            width_str = m.group(2)
            spec = FormatSpecifier(
                raw=m.group(0),
                position=m.start(),
                field_width=int(width_str) if width_str else None,
                conversion=ConversionType.STRING,
                conversion_char="[",
                consumes_arg=not suppress,
                is_scanf=True,
                suppress_assignment=suppress,
            )
            specs.append(spec)

    for m in _FMT_SPEC_RE.finditer(fmt):
        suppress_str = m.group(1)
        flags_str    = m.group(2)
        width_str    = m.group(3)
        prec_str     = m.group(4)
        len_str      = m.group(5)
        conv_char    = m.group(6)

        conv = _CONV_MAP.get(conv_char, ConversionType.UNKNOWN)
        length = _LEN_MAP.get(len_str or "", LengthModifier.NONE)

        # Width
        width_is_star = (width_str == "*")
        field_width: Optional[int] = None
        if not width_is_star and width_str:
            try:
                field_width = int(width_str)
            except ValueError:
                pass

        # Precision
        prec_is_star = (prec_str == "*") if prec_str is not None else False
        precision: Optional[int] = None
        if prec_str is not None and not prec_is_star and prec_str:
            try:
                precision = int(prec_str)
            except ValueError:
                pass

        # scanf suppression
        suppress = bool(suppress_str) and is_scanf

        consumes = True
        if conv == ConversionType.PERCENT:
            consumes = False
        if suppress:
            consumes = False

        # Count extra args consumed by '*' width/precision (printf only)
        extra_args = 0
        if not is_scanf:
            if width_is_star:
                extra_args += 1
            if prec_is_star:
                extra_args += 1

        spec = FormatSpecifier(
            raw=m.group(0),
            position=m.start(),
            flags=flags_str,
            field_width=field_width,
            width_is_star=width_is_star,
            precision=precision,
            precision_is_star=prec_is_star,
            length=length,
            conversion=conv,
            conversion_char=conv_char,
            consumes_arg=consumes,
            is_scanf=is_scanf,
            suppress_assignment=suppress,
        )
        specs.append(spec)

        # If width or precision is '*', add synthetic "int" specifiers
        # for the extra arguments they consume
        for _ in range(extra_args):
            star_spec = FormatSpecifier(
                raw="*",
                position=m.start(),
                conversion=ConversionType.SIGNED_INT,
                conversion_char="*",
                consumes_arg=True,
                is_scanf=False,
            )
            # Insert BEFORE the current spec in the list (stars come first)
            specs.insert(len(specs) - 1, star_spec)

    # Deduplicate: scanf charclass matches might overlap with %[
    # Remove by position
    seen_pos: Set[int] = set()
    unique: List[FormatSpecifier] = []
    for sp in specs:
        if sp.position not in seen_pos:
            seen_pos.add(sp.position)
            unique.append(sp)
    specs = unique

    # Sort by position
    specs.sort(key=lambda sp: sp.position)

    return specs


# ═══════════════════════════════════════════════════════════════════
#  FORMAT FUNCTION DATABASE
# ═══════════════════════════════════════════════════════════════════

@dataclass
class FmtFuncInfo:
    """Metadata about a printf/scanf-family function."""
    name: str
    is_scanf: bool = False          # scanf family
    fmt_arg_index: int = 0          # 0-based index of format arg
    has_dest_buffer: bool = False   # sprintf, snprintf, sscanf
    dest_arg_index: int = -1        # index of destination buffer arg
    has_size_arg: bool = False      # snprintf
    size_arg_index: int = -1        # index of the size argument
    is_wide: bool = False           # wprintf, wscanf family
    returns_count: bool = False     # snprintf returns needed length


# ── printf family ──
_PRINTF_FUNCS: Dict[str, FmtFuncInfo] = {
    "printf": FmtFuncInfo(
        name="printf", fmt_arg_index=0),
    "fprintf": FmtFuncInfo(
        name="fprintf", fmt_arg_index=1),
    "dprintf": FmtFuncInfo(
        name="dprintf", fmt_arg_index=1),
    "sprintf": FmtFuncInfo(
        name="sprintf", fmt_arg_index=1,
        has_dest_buffer=True, dest_arg_index=0),
    "snprintf": FmtFuncInfo(
        name="snprintf", fmt_arg_index=2,
        has_dest_buffer=True, dest_arg_index=0,
        has_size_arg=True, size_arg_index=1,
        returns_count=True),
    "wprintf": FmtFuncInfo(
        name="wprintf", fmt_arg_index=0, is_wide=True),
    "fwprintf": FmtFuncInfo(
        name="fwprintf", fmt_arg_index=1, is_wide=True),
    "swprintf": FmtFuncInfo(
        name="swprintf", fmt_arg_index=2,
        has_dest_buffer=True, dest_arg_index=0,
        has_size_arg=True, size_arg_index=1,
        is_wide=True),
    "syslog": FmtFuncInfo(
        name="syslog", fmt_arg_index=1),
}

# ── scanf family ──
_SCANF_FUNCS: Dict[str, FmtFuncInfo] = {
    "scanf": FmtFuncInfo(
        name="scanf", is_scanf=True, fmt_arg_index=0),
    "fscanf": FmtFuncInfo(
        name="fscanf", is_scanf=True, fmt_arg_index=1),
    "sscanf": FmtFuncInfo(
        name="sscanf", is_scanf=True, fmt_arg_index=1,
        has_dest_buffer=False),
    "wscanf": FmtFuncInfo(
        name="wscanf", is_scanf=True, fmt_arg_index=0,
        is_wide=True),
    "fwscanf": FmtFuncInfo(
        name="fwscanf", is_scanf=True, fmt_arg_index=1,
        is_wide=True),
    "swscanf": FmtFuncInfo(
        name="swscanf", is_scanf=True, fmt_arg_index=1,
        is_wide=True),
}

ALL_FMT_FUNCS: Dict[str, FmtFuncInfo] = {**_PRINTF_FUNCS, **_SCANF_FUNCS}


# ═══════════════════════════════════════════════════════════════════
#  FORMAT CALL DESCRIPTOR
# ═══════════════════════════════════════════════════════════════════

@dataclass
class FormatCall:
    """A single invocation of a format-string function found in the code."""
    func_info: FmtFuncInfo
    func_name_tok: Any            # token of the function name
    paren_tok: Any                # the '(' token
    all_args: List[Any]           # all AST argument nodes
    fmt_arg_tok: Optional[Any]    # the format-string argument token
    fmt_string: Optional[str]     # the literal string if available
    specs: List[FormatSpecifier]  # parsed specifiers (empty if non-literal)
    variadic_args: List[Any]      # args after the format string
    dest_arg_tok: Optional[Any] = None
    size_arg_tok: Optional[Any] = None


# ═══════════════════════════════════════════════════════════════════
#  PASS 1 — FIND ALL FORMAT FUNCTION CALLS
# ═══════════════════════════════════════════════════════════════════

class FormatCallFinder:
    """
    Walk the token list and locate every printf/scanf-family call.
    For each, parse the format string (if it is a literal) into
    specifiers and produce a ``FormatCall`` descriptor.
    """

    def find(self, cfg_data: Any) -> List[FormatCall]:
        calls: List[FormatCall] = []

        for tok in cfg_data.tokenlist:
            s = _s(tok)

            # We detect calls via the '(' token whose astOperand1 is
            # a known format function name.
            if s != "(":
                continue

            op1 = getattr(tok, "astOperand1", None)
            if op1 is None:
                continue
            fname = _s(op1)
            if fname not in ALL_FMT_FUNCS:
                continue

            func_info = ALL_FMT_FUNCS[fname]
            args = _get_call_args_from_paren(tok)

            # Validate minimum arg count
            min_args = func_info.fmt_arg_index + 1
            if len(args) < min_args:
                continue  # malformed — Cppcheck will catch separately

            fmt_tok = args[func_info.fmt_arg_index]
            fmt_str: Optional[str] = None
            specs: List[FormatSpecifier] = []

            # Extract the literal string if present
            if getattr(fmt_tok, "isString", False):
                # Token str is like '"hello %d\n"' — strip outer quotes
                raw = _s(fmt_tok)
                if raw.startswith('"') and raw.endswith('"'):
                    fmt_str = raw[1:-1]
                elif raw.startswith('L"') and raw.endswith('"'):
                    fmt_str = raw[2:-1]

                if fmt_str is not None:
                    specs = parse_format_string(
                        fmt_str, is_scanf=func_info.is_scanf)

            # Variadic args: everything after the format string
            variadic_start = func_info.fmt_arg_index + 1
            variadic_args = args[variadic_start:]

            dest_tok = None
            size_tok = None
            if func_info.has_dest_buffer and func_info.dest_arg_index < len(args):
                dest_tok = args[func_info.dest_arg_index]
            if func_info.has_size_arg and func_info.size_arg_index < len(args):
                size_tok = args[func_info.size_arg_index]

            calls.append(FormatCall(
                func_info=func_info,
                func_name_tok=op1,
                paren_tok=tok,
                all_args=args,
                fmt_arg_tok=fmt_tok,
                fmt_string=fmt_str,
                specs=specs,
                variadic_args=variadic_args,
                dest_arg_tok=dest_tok,
                size_arg_tok=size_tok,
            ))

        return calls


# ═══════════════════════════════════════════════════════════════════
#  TAINT TRACKING (simplified, for CWE-134)
# ═══════════════════════════════════════════════════════════════════

class TaintState(Enum):
    """Simple taint lattice: untainted < tainted."""
    UNTAINTED = auto()
    TAINTED   = auto()
    UNKNOWN   = auto()


class SimpleTaintTracker:
    """
    Lightweight forward taint analysis over the token list.

    Tainted sources:
      - Parameters of non-main functions (may be attacker-controlled)
      - Return values of getenv, fgets, gets, read, recv, getline,
        fread, scanf-family output args

    We track taint per variable ID.  This is deliberately simple —
    a full taint analysis would use the dataflow engine, but we avoid
    private shim APIs.
    """

    TAINT_SOURCES: Set[str] = {
        "getenv", "fgets", "gets", "read", "recv",
        "getline", "fread", "readline",
    }

    def __init__(self) -> None:
        self.taint: Dict[int, TaintState] = {}

    def run(self, cfg_data: Any) -> None:
        self.taint.clear()

        # Mark function parameters as tainted (conservative)
        for scope in getattr(cfg_data, "scopes", []):
            stype = getattr(scope, "type", "")
            if stype == "Function":
                func = getattr(scope, "function", None)
                if func:
                    fname = getattr(func, "name", "")
                    if fname == "main":
                        # argv is tainted, argc is not
                        for arg in getattr(func, "argument", {}).values():
                            tok = getattr(arg, "nameToken", None)
                            vid = _var_id(tok)
                            if vid:
                                vname = _s(tok)
                                if vname == "argv":
                                    self.taint[vid] = TaintState.TAINTED
                    else:
                        # All parameters of non-main functions
                        for arg in getattr(func, "argument", {}).values():
                            tok = getattr(arg, "nameToken", None)
                            vid = _var_id(tok)
                            if vid:
                                self.taint[vid] = TaintState.TAINTED

        # Walk tokens for taint propagation
        for tok in cfg_data.tokenlist:
            s = _s(tok)

            if s == "=":
                lhs = getattr(tok, "astOperand1", None)
                rhs = getattr(tok, "astOperand2", None)
                if lhs and rhs:
                    lhs_vid = _var_id(lhs)
                    if lhs_vid:
                        rhs_taint = self._eval_taint(rhs)
                        self.taint[lhs_vid] = rhs_taint

    def _eval_taint(self, tok: Any) -> TaintState:
        """Evaluate the taint status of an expression."""
        if tok is None:
            return TaintState.UNKNOWN

        s = _s(tok)

        # Direct variable reference
        vid = _var_id(tok)
        if vid and vid in self.taint:
            return self.taint[vid]

        # Function call returning tainted data
        if s == "(":
            fname = _s(getattr(tok, "astOperand1", None))
            if fname in self.TAINT_SOURCES:
                return TaintState.TAINTED
            # scanf family: the output args become tainted, but
            # the return value is the count — handled elsewhere
            return TaintState.UNKNOWN

        # Taint propagates through arithmetic/concatenation
        op1 = getattr(tok, "astOperand1", None)
        op2 = getattr(tok, "astOperand2", None)
        t1 = self._eval_taint(op1) if op1 else TaintState.UNTAINTED
        t2 = self._eval_taint(op2) if op2 else TaintState.UNTAINTED

        if t1 == TaintState.TAINTED or t2 == TaintState.TAINTED:
            return TaintState.TAINTED
        if t1 == TaintState.UNKNOWN or t2 == TaintState.UNKNOWN:
            return TaintState.UNKNOWN
        return TaintState.UNTAINTED

    def is_tainted(self, tok: Any) -> bool:
        """Is the expression rooted at ``tok`` tainted?"""
        return self._eval_taint(tok) == TaintState.TAINTED

    def is_maybe_tainted(self, tok: Any) -> bool:
        t = self._eval_taint(tok)
        return t in (TaintState.TAINTED, TaintState.UNKNOWN)


# ═══════════════════════════════════════════════════════════════════
#  PASS 2 — UNCONTROLLED FORMAT STRING  (CWE-134)
# ═══════════════════════════════════════════════════════════════════

class UncontrolledFmtCheck:
    """
    Detect ``printf(user_var)`` where the format string is not a
    compile-time literal — CWE-134.

    Also flags the dangerous ``%n`` specifier which writes to memory.
    """

    def __init__(self, reporter: Reporter,
                 taint: SimpleTaintTracker) -> None:
        self.reporter = reporter
        self.taint = taint

    def run(self, calls: List[FormatCall]) -> None:
        for call in calls:
            self._check_uncontrolled(call)
            self._check_percent_n(call)

    def _check_uncontrolled(self, call: FormatCall) -> None:
        """Flag non-literal format strings in printf family."""
        if call.func_info.is_scanf:
            return  # scanf format is usually a literal; even if not,
                    # it's a different risk profile (CWE-119/120)

        fmt_tok = call.fmt_arg_tok
        if fmt_tok is None:
            return

        # If the format string IS a literal, it's fine
        if getattr(fmt_tok, "isString", False):
            return

        # Non-literal format.  Check if it's tainted.
        vid = _var_id(fmt_tok)
        severity = "warning"
        msg_suffix = ""

        if vid and self.taint.is_tainted(fmt_tok):
            severity = "error"
            msg_suffix = " (tainted by external input)"
        elif vid and self.taint.is_maybe_tainted(fmt_tok):
            severity = "warning"
            msg_suffix = " (may be externally controlled)"
        else:
            # Even a non-literal format from a local variable is risky
            severity = "warning"
            msg_suffix = ""

        self.reporter.report(
            call.func_name_tok, severity,
            f"Format string for '{call.func_info.name}' is not a "
            f"string literal — potential format string attack"
            f"{msg_suffix}",
            cwe=134, check_id="uncontrolledFormatString",
        )

    def _check_percent_n(self, call: FormatCall) -> None:
        """Flag %n which writes to memory through format string."""
        for spec in call.specs:
            if spec.conversion == ConversionType.COUNT:
                self.reporter.report(
                    call.func_name_tok, "warning",
                    f"'{call.func_info.name}' uses '%n' specifier "
                    f"which writes to memory — dangerous if format "
                    f"string is attacker-controlled",
                    cwe=134, check_id="formatStringPercentN",
                )
                break  # One report per call


# ═══════════════════════════════════════════════════════════════════
#  PASS 3 — ARGUMENT COUNT AND TYPE CHECKING  (CWE-685, 686, 126)
# ═══════════════════════════════════════════════════════════════════

class ArgCountTypeCheck:
    """
    For each format call with a literal format string, verify:

    1. The number of variadic arguments matches the number of
       consuming specifiers (CWE-685 / CWE-126).
    2. Each argument's type is compatible with its specifier (CWE-686).
    """

    def __init__(self, reporter: Reporter) -> None:
        self.reporter = reporter

    def run(self, calls: List[FormatCall]) -> None:
        for call in calls:
            if call.fmt_string is None:
                continue  # non-literal format — can't check
            self._check_arg_count(call)
            self._check_arg_types(call)

    def _check_arg_count(self, call: FormatCall) -> None:
        consuming = [s for s in call.specs if s.consumes_arg]
        expected = len(consuming)
        actual = len(call.variadic_args)

        if actual < expected:
            missing = expected - actual
            self.reporter.report(
                call.func_name_tok, "error",
                f"'{call.func_info.name}' format expects {expected} "
                f"argument(s) but only {actual} provided — "
                f"{missing} missing (undefined behavior: reads garbage "
                f"from stack)",
                cwe=685, check_id="fmtArgCountMismatch",
            )
        elif actual > expected:
            extra = actual - expected
            self.reporter.report(
                call.func_name_tok, "warning",
                f"'{call.func_info.name}' format expects {expected} "
                f"argument(s) but {actual} provided — "
                f"{extra} extra argument(s) ignored",
                cwe=685, check_id="fmtArgCountExtra",
            )

    def _check_arg_types(self, call: FormatCall) -> None:
        consuming = [s for s in call.specs if s.consumes_arg]

        for i, spec in enumerate(consuming):
            if i >= len(call.variadic_args):
                break  # already reported by count check
            arg = call.variadic_args[i]
            self._check_one_type(call, spec, arg, i)

    def _check_one_type(self, call: FormatCall, spec: FormatSpecifier,
                        arg: Any, idx: int) -> None:
        """Check one specifier against one argument."""
        # Get the argument's value type from Cppcheck
        vt = getattr(arg, "valueType", None)
        if vt is None:
            return  # can't determine type — skip

        vt_type = getattr(vt, "type", "")       # "int", "char", "float", etc.
        vt_sign = getattr(vt, "sign", "")       # "signed", "unsigned"
        vt_pointer = getattr(vt, "pointer", 0)  # pointer depth
        is_pointer = (vt_pointer and int(vt_pointer) > 0)

        conv = spec.conversion
        conv_char = spec.conversion_char

        # ── %s expects char* (or wchar_t* for wide) ──
        if conv == ConversionType.STRING:
            if not is_pointer:
                self.reporter.report(
                    arg, "error",
                    f"Argument {idx + 1} of '{call.func_info.name}' "
                    f"for '%{conv_char}' should be a string (pointer) "
                    f"but has type '{vt_type}'",
                    cwe=686, check_id="fmtArgTypeMismatch",
                )
            return

        # ── %d / %i / %u / %o / %x expect integer ──
        if conv in (ConversionType.SIGNED_INT, ConversionType.UNSIGNED_INT):
            if is_pointer:
                self.reporter.report(
                    arg, "warning",
                    f"Argument {idx + 1} of '{call.func_info.name}' "
                    f"for '%{conv_char}' expects integer but got "
                    f"pointer type",
                    cwe=686, check_id="fmtArgTypeMismatch",
                )
            elif vt_type in ("float", "double"):
                self.reporter.report(
                    arg, "warning",
                    f"Argument {idx + 1} of '{call.func_info.name}' "
                    f"for '%{conv_char}' expects integer but got "
                    f"'{vt_type}'",
                    cwe=686, check_id="fmtArgTypeMismatch",
                )
            # Check signed/unsigned mismatch with length
            if conv == ConversionType.SIGNED_INT and vt_sign == "unsigned":
                if spec.length == LengthModifier.NONE and vt_type not in ("char",):
                    self.reporter.report(
                        arg, "style",
                        f"Argument {idx + 1} of '{call.func_info.name}' "
                        f"for '%{conv_char}' is unsigned but specifier "
                        f"expects signed",
                        cwe=686, check_id="fmtSignMismatch",
                    )
            # Check length modifier vs actual size
            self._check_length_modifier(call, spec, arg, vt_type, idx)
            return

        # ── %f / %e / %g expect float/double ──
        if conv == ConversionType.FLOAT:
            if is_pointer:
                self.reporter.report(
                    arg, "warning",
                    f"Argument {idx + 1} of '{call.func_info.name}' "
                    f"for '%{conv_char}' expects float/double but got "
                    f"pointer type",
                    cwe=686, check_id="fmtArgTypeMismatch",
                )
            elif vt_type in ("int", "short", "char", "long"):
                self.reporter.report(
                    arg, "warning",
                    f"Argument {idx + 1} of '{call.func_info.name}' "
                    f"for '%{conv_char}' expects float/double but got "
                    f"'{vt_type}'",
                    cwe=686, check_id="fmtArgTypeMismatch",
                )
            return

        # ── %p expects pointer ──
        if conv == ConversionType.POINTER:
            if not is_pointer:
                self.reporter.report(
                    arg, "warning",
                    f"Argument {idx + 1} of '{call.func_info.name}' "
                    f"for '%p' expects a pointer but got '{vt_type}'",
                    cwe=686, check_id="fmtArgTypeMismatch",
                )
            return

        # ── %c expects char/int ──
        if conv == ConversionType.CHAR:
            if is_pointer:
                self.reporter.report(
                    arg, "warning",
                    f"Argument {idx + 1} of '{call.func_info.name}' "
                    f"for '%c' expects char/int but got pointer type",
                    cwe=686, check_id="fmtArgTypeMismatch",
                )
            return

        # ── %n expects int* ──
        if conv == ConversionType.COUNT:
            if not is_pointer:
                self.reporter.report(
                    arg, "error",
                    f"Argument {idx + 1} of '{call.func_info.name}' "
                    f"for '%n' must be a pointer to int",
                    cwe=686, check_id="fmtArgTypeMismatch",
                )
            return

    def _check_length_modifier(self, call: FormatCall,
                                spec: FormatSpecifier, arg: Any,
                                vt_type: str, idx: int) -> None:
        """
        Warn about length-modifier / actual-type mismatches.
        E.g. %ld with an int argument, or %d with a long argument.
        """
        length = spec.length
        conv_char = spec.conversion_char

        # Size mapping (approximate, platform-dependent)
        expected_type: Optional[str] = None
        if length == LengthModifier.NONE:
            expected_type = "int"
        elif length == LengthModifier.L:
            expected_type = "long"
        elif length == LengthModifier.LL:
            expected_type = "long long"
        elif length == LengthModifier.H:
            expected_type = "short"
        elif length == LengthModifier.HH:
            expected_type = "char"
        elif length == LengthModifier.Z:
            expected_type = "size_t"

        if expected_type is None:
            return

        # Simple mismatch detection
        type_rank = {"char": 1, "short": 2, "int": 3, "long": 4}
        actual_rank = type_rank.get(vt_type, 0)
        expected_rank = type_rank.get(expected_type, 0)

        if actual_rank and expected_rank and actual_rank != expected_rank:
            # Only report if the size definitely differs
            if (expected_rank >= 4 and actual_rank <= 3) or \
               (expected_rank <= 2 and actual_rank >= 3):
                self.reporter.report(
                    arg, "warning",
                    f"Argument {idx + 1} of '{call.func_info.name}': "
                    f"'%{spec.raw.lstrip('%')}' expects "
                    f"'{expected_type}' but argument is '{vt_type}'",
                    cwe=686, check_id="fmtLengthMismatch",
                )


# ═══════════════════════════════════════════════════════════════════
#  PASS 4 — SPRINTF BUFFER OVERFLOW  (CWE-120, CWE-787, CWE-193)
# ═══════════════════════════════════════════════════════════════════

class SprintfBufferCheck:
    """
    For sprintf / snprintf calls, estimate the maximum output length
    and compare against the destination buffer size.

    Also recommends replacing sprintf with snprintf.
    """

    def __init__(self, reporter: Reporter) -> None:
        self.reporter = reporter

    def run(self, calls: List[FormatCall]) -> None:
        for call in calls:
            fname = call.func_info.name
            if fname == "sprintf":
                self._check_sprintf(call)
            elif fname in ("snprintf", "swprintf"):
                self._check_snprintf(call)

    def _check_sprintf(self, call: FormatCall) -> None:
        """
        sprintf(dst, fmt, ...) — always warn because there is no
        bounds parameter.  If we can compute a minimum output length
        and buffer size, check for definite overflow.
        """
        # Always recommend snprintf over sprintf
        self.reporter.report(
            call.func_name_tok, "warning",
            f"'sprintf' has no bounds checking — use 'snprintf' instead",
            cwe=120, check_id="sprintfNoBoundsCheck",
        )

        # Try to estimate output and buffer sizes
        min_output = self._estimate_min_output(call)
        buf_size = self._get_dest_size(call)

        if min_output is not None and buf_size is not None:
            if min_output > buf_size:
                self.reporter.report(
                    call.func_name_tok, "error",
                    f"'sprintf' minimum output ({min_output} bytes) "
                    f"exceeds destination buffer ({buf_size} bytes)",
                    cwe=787, check_id="sprintfOverflow",
                )

    def _check_snprintf(self, call: FormatCall) -> None:
        """Check snprintf(dst, size, fmt, ...) for issues."""
        size_tok = call.size_arg_tok
        if size_tok is None:
            return

        size_val = _try_eval(size_tok)
        buf_size = self._get_dest_size(call)

        # ── CWE-193: size argument > buffer size ──
        if size_val is not None and buf_size is not None:
            if size_val > buf_size:
                self.reporter.report(
                    call.func_name_tok, "error",
                    f"'snprintf' size argument ({size_val}) exceeds "
                    f"destination buffer size ({buf_size})",
                    cwe=787, check_id="snprintfSizeExceedsBuffer",
                )

        # ── CWE-193: off-by-one — common mistake sizeof(buf) + 1 ──
        if size_val is not None and buf_size is not None:
            if size_val == buf_size + 1:
                self.reporter.report(
                    call.func_name_tok, "warning",
                    f"'snprintf' size ({size_val}) is one more than "
                    f"buffer size ({buf_size}) — off-by-one error",
                    cwe=193, check_id="snprintfOffByOne",
                )

        # ── Check for size = 0 (no-op, likely a bug) ──
        if size_val is not None and size_val == 0:
            self.reporter.report(
                call.func_name_tok, "warning",
                f"'snprintf' called with size 0 — writes nothing, "
                f"likely a bug",
                cwe=685, check_id="snprintfZeroSize",
            )

        # ── Check minimum output vs size ──
        min_output = self._estimate_min_output(call)
        if min_output is not None and size_val is not None:
            if min_output > size_val:
                self.reporter.report(
                    call.func_name_tok, "warning",
                    f"'snprintf' minimum output ({min_output} bytes) "
                    f"exceeds size argument ({size_val}) — output "
                    f"will be truncated",
                    cwe=787, check_id="snprintfTruncation",
                )

    def _estimate_min_output(self, call: FormatCall) -> Optional[int]:
        """
        Conservative MINIMUM output byte count from the format string.

        We sum up:
          - literal characters (exact count)
          - %d / %i: at least 1 byte (could be "0")
          - %s: 0 bytes minimum (empty string possible)
          - %c: 1 byte
          - etc.

        Plus 1 for the null terminator.

        Returns None if the format string is unknown or contains
        unpredictable specifiers.
        """
        if call.fmt_string is None:
            return None

        fmt = call.fmt_string
        total = 0
        last_end = 0

        for spec in call.specs:
            # Count literal characters before this specifier
            start = spec.position
            if start > last_end:
                literal_chunk = fmt[last_end:start]
                total += self._count_literal_bytes(literal_chunk)
            last_end = start + len(spec.raw)

            if spec.conversion == ConversionType.PERCENT:
                total += 1  # literal '%'
                continue

            # Minimum output per conversion type
            if spec.conversion == ConversionType.CHAR:
                total += 1
            elif spec.conversion == ConversionType.SIGNED_INT:
                total += 1  # at least "0"
            elif spec.conversion == ConversionType.UNSIGNED_INT:
                total += 1
            elif spec.conversion == ConversionType.FLOAT:
                total += 1  # at least "0"
            elif spec.conversion == ConversionType.STRING:
                # If precision is set, max output is precision
                # Minimum is 0 (empty string) unless we know the arg
                if spec.precision is not None:
                    pass  # could be 0
                # Try to evaluate the argument for string literals
                consuming = [s for s in call.specs if s.consumes_arg]
                spec_idx = -1
                for ci, cs in enumerate(consuming):
                    if cs is spec:
                        spec_idx = ci
                        break
                if spec_idx >= 0 and spec_idx < len(call.variadic_args):
                    str_arg = call.variadic_args[spec_idx]
                    if getattr(str_arg, "isString", False):
                        sval = _s(str_arg)
                        if sval.startswith('"') and sval.endswith('"'):
                            # Length of the string content
                            content = sval[1:-1]
                            # Count escape sequences as 1 byte each
                            decoded_len = self._decode_escapes_len(content)
                            total += decoded_len
                            continue
                total += 0  # conservative minimum
            elif spec.conversion == ConversionType.POINTER:
                total += 1  # at least "0" or "(nil)"
            elif spec.conversion == ConversionType.COUNT:
                pass  # %n doesn't produce output

            # If field_width is set and > current minimum, use it
            if spec.field_width is not None:
                # The field width is a minimum output width
                pass  # already counting minimum without padding

        # Trailing literal characters
        if last_end < len(fmt):
            total += self._count_literal_bytes(fmt[last_end:])

        # +1 for null terminator (sprintf always writes it)
        total += 1

        return total

    def _count_literal_bytes(self, s: str) -> int:
        """Count bytes in a literal string chunk, handling escape sequences."""
        return self._decode_escapes_len(s)

    def _decode_escapes_len(self, s: str) -> int:
        """Count the number of actual bytes when C escape sequences are decoded."""
        count = 0
        i = 0
        while i < len(s):
            if s[i] == '\\' and i + 1 < len(s):
                next_c = s[i + 1]
                if next_c in ('n', 't', 'r', '0', '\\', '"', "'",
                              'a', 'b', 'f', 'v', '?'):
                    count += 1
                    i += 2
                elif next_c == 'x':
                    # \xHH — hex escape
                    count += 1
                    i += 2
                    while i < len(s) and s[i] in '0123456789abcdefABCDEF':
                        i += 1
                elif next_c in '01234567':
                    # Octal escape
                    count += 1
                    i += 2
                    limit = 0
                    while i < len(s) and s[i] in '01234567' and limit < 2:
                        i += 1
                        limit += 1
                else:
                    count += 1  # unknown escape, count as 1
                    i += 2
            else:
                count += 1
                i += 1
        return count

    def _get_dest_size(self, call: FormatCall) -> Optional[int]:
        """Get the destination buffer size in bytes."""
        dst = call.dest_arg_tok
        if dst is None:
            return None

        var = getattr(dst, "variable", None)
        if var is None:
            return None

        # Array variable — get dimension
        dim = _get_array_dimension(var)
        if dim is not None:
            # Element size
            esz = self._element_size(var)
            return dim * esz

        return None

    def _element_size(self, var: Any) -> int:
        """Get element size from variable type.  Default 1 (char)."""
        name_tok = getattr(var, "nameToken", None)
        if name_tok is None:
            return 1
        vt = getattr(name_tok, "valueType", None)
        if vt is None:
            return 1
        type_name = getattr(vt, "type", "")
        size_map = {"char": 1, "short": 2, "int": 4, "long": 8,
                    "float": 4, "double": 8}
        return size_map.get(type_name, 1)


# ═══════════════════════════════════════════════════════════════════
#  PASS 5 — SCANF-SPECIFIC CHECKS
# ═══════════════════════════════════════════════════════════════════

class ScanfCheck:
    """
    Additional checks specific to scanf-family functions:

    - %s without width limiter (CWE-120)
    - Missing & on non-pointer arguments
    - Buffer overflow via scanf into undersized buffer
    """

    def __init__(self, reporter: Reporter) -> None:
        self.reporter = reporter

    def run(self, calls: List[FormatCall]) -> None:
        for call in calls:
            if not call.func_info.is_scanf:
                continue
            self._check_scanf_s_width(call)
            self._check_scanf_buffer_size(call)

    def _check_scanf_s_width(self, call: FormatCall) -> None:
        """Flag %s and %[ without width limiter in scanf."""
        for spec in call.specs:
            if not spec.consumes_arg:
                continue
            if spec.conversion == ConversionType.STRING:
                if spec.field_width is None:
                    char_used = spec.conversion_char
                    if char_used == "[":
                        char_used = "%[...]"
                    else:
                        char_used = f"%{char_used}"
                    self.reporter.report(
                        call.func_name_tok, "warning",
                        f"'{call.func_info.name}' uses '{char_used}' "
                        f"without width limit — buffer overflow risk",
                        cwe=120, check_id="scanfNoWidthLimit",
                    )

    def _check_scanf_buffer_size(self, call: FormatCall) -> None:
        """Check if scanf width limiter exceeds destination buffer."""
        consuming = [s for s in call.specs if s.consumes_arg]

        for i, spec in enumerate(consuming):
            if i >= len(call.variadic_args):
                break

            if spec.conversion != ConversionType.STRING:
                continue
            if spec.field_width is None:
                continue  # no width — already warned above

            arg = call.variadic_args[i]

            # For scanf, string args are pointers to buffers
            # Try to get the buffer size
            var = getattr(arg, "variable", None)
            if var is None:
                # Could be &buf or buf (array decays to pointer)
                # Check if arg is unary & operator
                if _s(arg) == "&":
                    inner = getattr(arg, "astOperand1", None)
                    if inner:
                        var = getattr(inner, "variable", None)

            if var is None:
                continue

            dim = _get_array_dimension(var)
            if dim is None:
                continue

            # scanf %Ns reads at most N chars + null terminator
            # So buffer must be at least field_width + 1
            needed = spec.field_width + 1
            if needed > dim:
                self.reporter.report(
                    call.func_name_tok, "error",
                    f"'{call.func_info.name}' with width {spec.field_width} "
                    f"needs {needed} bytes but '{_s(arg)}' is only "
                    f"{dim} bytes — buffer overflow",
                    cwe=787, check_id="scanfWidthExceedsBuffer",
                )


# ═══════════════════════════════════════════════════════════════════
#  ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════════

class FormatStringChecker:
    """Run all format-string checks on parsed dump data."""

    def __init__(self) -> None:
        self.reporter = Reporter()

    def check(self, data: Any) -> None:
        for cfg_data in data.configurations:
            # Pre-analysis: taint tracking
            taint = SimpleTaintTracker()
            taint.run(cfg_data)

            # Pass 1: find all format function calls
            finder = FormatCallFinder()
            calls = finder.find(cfg_data)

            # Pass 2: uncontrolled format string (CWE-134)
            UncontrolledFmtCheck(self.reporter, taint).run(calls)

            # Pass 3: argument count and type checking (CWE-685, 686, 126)
            ArgCountTypeCheck(self.reporter).run(calls)

            # Pass 4: sprintf buffer overflow (CWE-120, 787, 193)
            SprintfBufferCheck(self.reporter).run(calls)

            # Pass 5: scanf-specific checks (CWE-120)
            ScanfCheck(self.reporter).run(calls)

    def report(self) -> int:
        self.reporter.dump()
        return len(self.reporter.findings)


# ═══════════════════════════════════════════════════════════════════
#  ENTRY POINTS
# ═══════════════════════════════════════════════════════════════════

def check(data: Any) -> None:
    """Cppcheck addon entry point (called when used with --addon)."""
    checker = FormatStringChecker()
    checker.check(data)
    count = checker.report()
    if count > 0:
        sys.exit(1)


def main() -> None:
    """CLI entry point for standalone usage."""
    if len(sys.argv) < 2:
        print("Usage: python FormatStringValidator.py <dumpfile> [...]",
              file=sys.stderr)
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
        checker = FormatStringChecker()
        checker.check(data)
        total += checker.report()

    if total:
        print(f"\nfmtcheck: {total} finding(s).", file=sys.stderr)
        sys.exit(1)
    else:
        print("fmtcheck: no findings.", file=sys.stderr)
        sys.exit(0)


if __name__ == "__main__":
    main()
