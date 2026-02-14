#!/usr/bin/env python3
"""
FormatStringValidator.py — Cppcheck addon for detecting format-string
vulnerabilities and argument mismatches.

Usage:
    python FormatStringValidator.py [--verbose] [--json] <file.dump> ...

Rules:
    FS01  Missing arguments (fewer args than specifiers)
    FS02  Extra arguments (more args than specifiers)
    FS03  Type mismatch (arg type incompatible with specifier)
    FS04  Tainted format string (non-literal, potential CWE-134)
    FS05  Invalid/unknown conversion specifier
    FS06  %n usage (writes to memory)
    FS07  Width/precision * with non-int argument
    FS08  scanf argument not a pointer

Architecture:
    Phase 1 — Token walk: locate format-function calls, extract format
              strings and argument tokens
    Phase 2 — Format-string parsing: lex the format string into a
              sequence of FormatDirective objects
    Phase 3 — Type analysis: resolve argument types via cppcheckdata
              ValueType and shims type_analysis
    Phase 4 — Matching: pair each directive with its corresponding
              argument and check compatibility
    Phase 5 — Taint check: trace format-string arguments back to
              non-literal origins (FS04)
    Phase 6 — Report consolidation
"""

from __future__ import annotations

import sys
import os
import re
import argparse
import json
import time
from typing import (
    Dict, List, Set, Tuple, Optional, NamedTuple, Sequence, Any,
    DefaultDict,
)
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path

# ═══════════════════════════════════════════════════════════════════════
# Lazy imports
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
    """Import cppcheckdata-shims modules (optional, for taint analysis)."""
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
# Constants — Format Function Database
# ═══════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class FormatFuncInfo:
    """Metadata about a format-string function."""
    name: str
    family: str                # "printf" or "scanf"
    format_arg_index: int      # 0-based index of the format-string parameter
    first_vararg_index: int    # 0-based index of the first variadic argument
    is_variadic: bool = True   # vprintf-family take va_list, not checked
    has_dest: bool = False     # sprintf/snprintf have a dest buffer
    has_count: bool = False    # snprintf has a count parameter

# Printf family
_PRINTF_FUNCS: Dict[str, FormatFuncInfo] = {}
for _name, _fmt_idx, _va_idx, _dest, _cnt in [
    ("printf",     0, 1, False, False),
    ("fprintf",    1, 2, False, False),
    ("sprintf",    1, 2, True,  False),
    ("snprintf",   2, 3, True,  True),
    ("dprintf",    1, 2, False, False),
    ("syslog",     1, 2, False, False),
    ("wprintf",    0, 1, False, False),
    ("fwprintf",   1, 2, False, False),
    ("swprintf",   2, 3, True,  True),
]:
    _PRINTF_FUNCS[_name] = FormatFuncInfo(
        name=_name, family="printf",
        format_arg_index=_fmt_idx, first_vararg_index=_va_idx,
        has_dest=_dest, has_count=_cnt,
    )

# Variadic va_list versions — we check the format string but NOT args
for _name, _fmt_idx in [
    ("vprintf", 0), ("vfprintf", 1), ("vsprintf", 1),
    ("vsnprintf", 2), ("vdprintf", 1),
]:
    _PRINTF_FUNCS[_name] = FormatFuncInfo(
        name=_name, family="printf",
        format_arg_index=_fmt_idx, first_vararg_index=-1,
        is_variadic=False,
    )

# Scanf family
_SCANF_FUNCS: Dict[str, FormatFuncInfo] = {}
for _name, _fmt_idx, _va_idx in [
    ("scanf",    0, 1),
    ("fscanf",   1, 2),
    ("sscanf",   1, 2),
    ("wscanf",   0, 1),
    ("fwscanf",  1, 2),
    ("swscanf",  1, 2),
]:
    _SCANF_FUNCS[_name] = FormatFuncInfo(
        name=_name, family="scanf",
        format_arg_index=_fmt_idx, first_vararg_index=_va_idx,
    )

for _name, _fmt_idx in [
    ("vscanf", 0), ("vfscanf", 1), ("vsscanf", 1),
]:
    _SCANF_FUNCS[_name] = FormatFuncInfo(
        name=_name, family="scanf",
        format_arg_index=_fmt_idx, first_vararg_index=-1,
        is_variadic=False,
    )

ALL_FORMAT_FUNCS: Dict[str, FormatFuncInfo] = {**_PRINTF_FUNCS, **_SCANF_FUNCS}


# ═══════════════════════════════════════════════════════════════════════
# Format String Parser
# ═══════════════════════════════════════════════════════════════════════

class ConversionType(Enum):
    """Categories of format conversion specifiers."""
    SIGNED_INT = auto()     # d, i
    UNSIGNED_INT = auto()   # u, o, x, X
    FLOAT = auto()          # f, F, e, E, g, G, a, A
    CHAR = auto()           # c
    STRING = auto()         # s
    POINTER = auto()        # p
    WRITE_COUNT = auto()    # n (dangerous!)
    PERCENT = auto()        # %% (literal, no argument consumed)
    INVALID = auto()        # unrecognised


@dataclass
class FormatDirective:
    """
    A single parsed format directive from a format string.

    A printf directive has the form:
        %[flags][width][.precision][length]specifier

    Where each component is optional.
    """
    raw: str                          # e.g. "%-10.5ld"
    position: int                     # character offset in format string
    flags: str = ""                   # subset of "-+ #0"
    width: Optional[str] = None       # number, "*", or None
    precision: Optional[str] = None   # number, "*", or None
    length_modifier: str = ""         # "", "h", "hh", "l", "ll", "L", "z", "j", "t"
    specifier: str = ""               # "d", "s", "p", etc.
    conversion_type: ConversionType = ConversionType.INVALID
    args_consumed: int = 0            # how many arguments this consumes
    star_width: bool = False          # True if width is "*"
    star_precision: bool = False      # True if precision is "*"
    is_suppressed: bool = False       # scanf %*d suppresses assignment


# The master regex for a printf/scanf format specifier.
# Matches: % [flags] [width] [.precision] [length] specifier
#
# Flags:    [-+ #0']  (POSIX also allows ')
# Width:    [0-9]+ | *
# Prec:     . followed by [0-9]+ | *
# Length:   hh | h | ll | l | L | z | j | t | q | I | I32 | I64 (MSVC)
# Spec:     [diouxXeEfFgGaAcspnCS%]

_FMT_SPEC_RE = re.compile(
    r'%'
    r'(?P<flags>[-+ #0\']*)'
    r'(?P<width>\*|\d+)?'
    r'(?:\.(?P<precision>\*|\d+))?'
    r'(?P<length>hh|h|ll|l|L|z|j|t|q|I64|I32|I)?'
    r'(?P<specifier>[diouxXeEfFgGaAcCsSpnm%])'
)

# Scanf-specific: the * flag suppresses assignment
_SCANF_SUPPRESS_RE = re.compile(
    r'%'
    r'(?P<suppress>\*)?'
    r'(?P<width>\d+)?'
    r'(?P<length>hh|h|ll|l|L|z|j|t|q|I64|I32|I)?'
    r'(?P<specifier>[diouxXeEfFgGaAcCsSpn\[%])'
)

# Map specifier character → ConversionType
_SPEC_TO_TYPE: Dict[str, ConversionType] = {
    'd': ConversionType.SIGNED_INT,
    'i': ConversionType.SIGNED_INT,
    'u': ConversionType.UNSIGNED_INT,
    'o': ConversionType.UNSIGNED_INT,
    'x': ConversionType.UNSIGNED_INT,
    'X': ConversionType.UNSIGNED_INT,
    'f': ConversionType.FLOAT,
    'F': ConversionType.FLOAT,
    'e': ConversionType.FLOAT,
    'E': ConversionType.FLOAT,
    'g': ConversionType.FLOAT,
    'G': ConversionType.FLOAT,
    'a': ConversionType.FLOAT,
    'A': ConversionType.FLOAT,
    'c': ConversionType.CHAR,
    'C': ConversionType.CHAR,
    's': ConversionType.STRING,
    'S': ConversionType.STRING,
    'p': ConversionType.POINTER,
    'n': ConversionType.WRITE_COUNT,
    '%': ConversionType.PERCENT,
    'm': ConversionType.STRING,  # glibc extension (no argument)
}


def parse_format_string(
    fmt: str,
    family: str = "printf",
) -> Tuple[List[FormatDirective], List[str]]:
    """
    Parse a C format string into a list of FormatDirective objects.

    Returns:
        (directives, errors) where errors are strings describing
        malformed specifiers.
    """
    directives: List[FormatDirective] = []
    errors: List[str] = []

    if family == "scanf":
        return _parse_scanf_format(fmt)

    pos = 0
    while pos < len(fmt):
        idx = fmt.find('%', pos)
        if idx == -1:
            break
        pos = idx

        m = _FMT_SPEC_RE.match(fmt, pos)
        if m is None:
            # Try to find the end of this malformed specifier
            # Look for the next alphabetic character or end of string
            end = pos + 1
            while end < len(fmt) and not fmt[end].isalpha() and fmt[end] != '%':
                end += 1
            if end < len(fmt):
                end += 1
            raw = fmt[pos:end]
            errors.append(f"invalid format specifier '{raw}' at position {pos}")
            directives.append(FormatDirective(
                raw=raw, position=pos,
                conversion_type=ConversionType.INVALID,
                args_consumed=1,  # assume it would consume one
            ))
            pos = end
            continue

        raw = m.group(0)
        flags = m.group('flags') or ""
        width = m.group('width')
        precision = m.group('precision')
        length = m.group('length') or ""
        spec = m.group('specifier')

        conv = _SPEC_TO_TYPE.get(spec, ConversionType.INVALID)
        if conv == ConversionType.INVALID:
            errors.append(f"unknown specifier '{spec}' at position {pos}")

        star_w = (width == "*")
        star_p = (precision == "*")

        # Count arguments consumed
        args = 0
        if conv != ConversionType.PERCENT and spec != 'm':
            args = 1
        if star_w:
            args += 1
        if star_p:
            args += 1

        directives.append(FormatDirective(
            raw=raw,
            position=pos,
            flags=flags,
            width=width,
            precision=precision,
            length_modifier=length,
            specifier=spec,
            conversion_type=conv,
            args_consumed=args,
            star_width=star_w,
            star_precision=star_p,
        ))
        pos = m.end()

    return directives, errors


def _parse_scanf_format(fmt: str) -> Tuple[List[FormatDirective], List[str]]:
    """Parse a scanf-family format string."""
    directives: List[FormatDirective] = []
    errors: List[str] = []
    pos = 0

    while pos < len(fmt):
        idx = fmt.find('%', pos)
        if idx == -1:
            break
        pos = idx

        m = _SCANF_SUPPRESS_RE.match(fmt, pos)
        if m is None:
            # Handle %[ scansets
            bracket = re.match(r'%(\*)?(\d+)?\[([^\]]*)\]', fmt[pos:])
            if bracket:
                raw = bracket.group(0)
                suppressed = bracket.group(1) is not None
                directives.append(FormatDirective(
                    raw=raw, position=pos,
                    specifier='[',
                    conversion_type=ConversionType.STRING,
                    args_consumed=0 if suppressed else 1,
                    is_suppressed=suppressed,
                ))
                pos += len(raw)
                continue

            end = pos + 1
            while end < len(fmt) and not fmt[end].isalpha() and fmt[end] != '%':
                end += 1
            if end < len(fmt):
                end += 1
            raw = fmt[pos:end]
            errors.append(f"invalid scanf specifier '{raw}' at position {pos}")
            directives.append(FormatDirective(
                raw=raw, position=pos,
                conversion_type=ConversionType.INVALID,
                args_consumed=1,
            ))
            pos = end
            continue

        raw = m.group(0)
        suppressed = m.group('suppress') is not None
        length = m.group('length') or ""
        spec = m.group('specifier')

        conv = _SPEC_TO_TYPE.get(spec, ConversionType.INVALID)
        if conv == ConversionType.INVALID and spec != '[':
            errors.append(f"unknown scanf specifier '{spec}' at position {pos}")

        args = 0 if (conv == ConversionType.PERCENT or suppressed) else 1

        directives.append(FormatDirective(
            raw=raw,
            position=pos,
            width=m.group('width'),
            length_modifier=length,
            specifier=spec,
            conversion_type=conv,
            args_consumed=args,
            is_suppressed=suppressed,
        ))
        pos = m.end()

    return directives, errors


# ═══════════════════════════════════════════════════════════════════════
# Type Compatibility Matrix
# ═══════════════════════════════════════════════════════════════════════

class CTypeKind(Enum):
    """Simplified C type categories for matching against format specs."""
    BOOL = "bool"
    CHAR = "char"
    SCHAR = "signed char"
    UCHAR = "unsigned char"
    SHORT = "short"
    USHORT = "unsigned short"
    INT = "int"
    UINT = "unsigned int"
    LONG = "long"
    ULONG = "unsigned long"
    LLONG = "long long"
    ULLONG = "unsigned long long"
    FLOAT = "float"
    DOUBLE = "double"
    LDOUBLE = "long double"
    CHAR_PTR = "char *"
    WCHAR_PTR = "wchar_t *"
    VOID_PTR = "void *"
    INT_PTR = "int *"           # for %n
    SIZE_T = "size_t"
    SSIZE_T = "ssize_t"
    PTRDIFF_T = "ptrdiff_t"
    INTMAX_T = "intmax_t"
    UINTMAX_T = "uintmax_t"
    POINTER = "pointer"         # generic pointer
    UNKNOWN = "unknown"


def _expected_type_printf(d: FormatDirective) -> List[CTypeKind]:
    """
    Given a printf directive, return the list of acceptable C types
    for the corresponding argument.
    """
    spec = d.specifier
    length = d.length_modifier

    if d.conversion_type == ConversionType.PERCENT:
        return []  # no argument

    if d.conversion_type == ConversionType.SIGNED_INT:
        if length == "hh":
            return [CTypeKind.CHAR, CTypeKind.SCHAR, CTypeKind.INT]
        if length == "h":
            return [CTypeKind.SHORT, CTypeKind.INT]
        if length == "l":
            return [CTypeKind.LONG, CTypeKind.INT]
        if length == "ll" or length == "q":
            return [CTypeKind.LLONG]
        if length == "z":
            return [CTypeKind.SIZE_T, CTypeKind.SSIZE_T, CTypeKind.ULONG, CTypeKind.LONG]
        if length == "j":
            return [CTypeKind.INTMAX_T, CTypeKind.LLONG]
        if length == "t":
            return [CTypeKind.PTRDIFF_T, CTypeKind.LONG, CTypeKind.INT]
        # Default (no length modifier)
        return [CTypeKind.INT, CTypeKind.UINT, CTypeKind.BOOL,
                CTypeKind.CHAR, CTypeKind.SHORT]

    if d.conversion_type == ConversionType.UNSIGNED_INT:
        if length == "hh":
            return [CTypeKind.UCHAR, CTypeKind.CHAR, CTypeKind.INT, CTypeKind.UINT]
        if length == "h":
            return [CTypeKind.USHORT, CTypeKind.INT, CTypeKind.UINT]
        if length == "l":
            return [CTypeKind.ULONG, CTypeKind.LONG]
        if length == "ll" or length == "q":
            return [CTypeKind.ULLONG, CTypeKind.LLONG]
        if length == "z":
            return [CTypeKind.SIZE_T, CTypeKind.ULONG]
        if length == "j":
            return [CTypeKind.UINTMAX_T, CTypeKind.ULLONG]
        return [CTypeKind.UINT, CTypeKind.INT, CTypeKind.BOOL,
                CTypeKind.CHAR, CTypeKind.USHORT]

    if d.conversion_type == ConversionType.FLOAT:
        if length == "L":
            return [CTypeKind.LDOUBLE]
        # float is promoted to double in varargs
        return [CTypeKind.DOUBLE, CTypeKind.FLOAT]

    if d.conversion_type == ConversionType.CHAR:
        if length == "l":
            return [CTypeKind.INT, CTypeKind.UINT]  # wint_t
        return [CTypeKind.INT, CTypeKind.CHAR, CTypeKind.UCHAR, CTypeKind.UINT]

    if d.conversion_type == ConversionType.STRING:
        if length == "l":
            return [CTypeKind.WCHAR_PTR]
        return [CTypeKind.CHAR_PTR, CTypeKind.VOID_PTR]

    if d.conversion_type == ConversionType.POINTER:
        return [CTypeKind.VOID_PTR, CTypeKind.POINTER, CTypeKind.CHAR_PTR]

    if d.conversion_type == ConversionType.WRITE_COUNT:
        if length == "hh":
            return [CTypeKind.POINTER]  # signed char *
        if length == "h":
            return [CTypeKind.POINTER]  # short *
        if length == "l":
            return [CTypeKind.POINTER]  # long *
        if length == "ll":
            return [CTypeKind.POINTER]  # long long *
        return [CTypeKind.INT_PTR, CTypeKind.POINTER]

    return [CTypeKind.UNKNOWN]


def _expected_type_scanf(d: FormatDirective) -> List[CTypeKind]:
    """For scanf, all arguments must be pointers to the appropriate type."""
    if d.is_suppressed or d.conversion_type == ConversionType.PERCENT:
        return []
    # All scanf args must be pointers
    return [CTypeKind.POINTER, CTypeKind.VOID_PTR, CTypeKind.CHAR_PTR,
            CTypeKind.INT_PTR]


# ═══════════════════════════════════════════════════════════════════════
# Data Structures
# ═══════════════════════════════════════════════════════════════════════

class Severity(Enum):
    ERROR = "error"
    WARNING = "warning"
    STYLE = "style"
    PERFORMANCE = "performance"


class RuleID(Enum):
    FS01 = "FS01"
    FS02 = "FS02"
    FS03 = "FS03"
    FS04 = "FS04"
    FS05 = "FS05"
    FS06 = "FS06"
    FS07 = "FS07"
    FS08 = "FS08"


@dataclass
class Diagnostic:
    rule: RuleID
    severity: Severity
    file: str
    line: int
    column: int
    message: str
    function_name: str = ""
    format_string: str = ""
    cwe: Optional[int] = None

    def to_json(self) -> dict:
        r = {
            "errorId": f"formatString.{self.rule.value}",
            "severity": self.severity.value,
            "message": self.message,
            "location": [{"file": self.file, "linenr": self.line, "column": self.column}],
        }
        if self.cwe:
            r["cwe"] = self.cwe
        return r

    def to_gcc(self) -> str:
        loc = f"{self.file}:{self.line}:{self.column}"
        return f"{loc}: {self.severity.value}: {self.message} [{self.rule.value}]"


@dataclass
class FormatCallSite:
    """A call to a format-string function."""
    func_info: FormatFuncInfo
    call_token: Any                   # the '(' token of the call
    callee_name: str
    file: str
    line: int
    column: int
    format_arg_token: Optional[Any]   # token of format string argument
    format_string: Optional[str]      # extracted literal string, or None
    format_is_literal: bool
    arg_tokens: List[Any]             # tokens for variadic arguments
    scope_id: int


# ═══════════════════════════════════════════════════════════════════════
# Phase 1 — Call-Site Collection (Token Walk)
# ═══════════════════════════════════════════════════════════════════════

def _token_str(tok) -> str:
    return tok.str if hasattr(tok, 'str') else str(tok)

def _token_var_id(tok) -> Optional[int]:
    vid = getattr(tok, 'varId', None) or getattr(tok, 'variableId', None)
    if vid and int(vid) != 0:
        return int(vid)
    return None

def _token_scope_id(tok) -> int:
    scope = getattr(tok, 'scope', None)
    return int(getattr(scope, 'Id', 0) or 0) if scope else 0


def _extract_string_literal(tok) -> Optional[str]:
    """
    If tok is a string literal token, extract its content (without quotes).
    Handles simple cases; does not resolve string concatenation or macros.
    """
    s = _token_str(tok)
    if s.startswith('"') and s.endswith('"') and len(s) >= 2:
        # Unescape basic C escape sequences
        content = s[1:-1]
        return content
    # Wide string
    if s.startswith('L"') and s.endswith('"'):
        return s[2:-1]
    return None


def _collect_call_arguments(call_tok) -> List[Any]:
    """
    Given the '(' token of a function call (with AST), collect
    argument tokens by walking the comma tree in astOperand2.
    """
    args = []
    op2 = getattr(call_tok, 'astOperand2', None)
    if op2 is None:
        return args
    _flatten_comma(op2, args)
    return args


def _flatten_comma(tok, result: list):
    """Recursively flatten a comma-separated AST into a list of argument roots."""
    if tok is None:
        return
    if _token_str(tok) == ',':
        _flatten_comma(getattr(tok, 'astOperand1', None), result)
        _flatten_comma(getattr(tok, 'astOperand2', None), result)
    else:
        result.append(tok)


def _is_string_literal_token(tok) -> bool:
    s = _token_str(tok)
    return (s.startswith('"') and s.endswith('"')) or \
           (s.startswith('L"') and s.endswith('"'))


def _trace_to_literal(tok, depth: int = 0) -> Optional[str]:
    """
    Try to trace a token back to a string literal, following simple
    variable assignments and string concatenation.
    """
    if tok is None or depth > 10:
        return None

    # Direct literal
    lit = _extract_string_literal(tok)
    if lit is not None:
        return lit

    # If it's a variable, try to find its initialisation
    vid = _token_var_id(tok)
    if vid is not None:
        var = getattr(tok, 'variable', None)
        if var is not None:
            name_tok = getattr(var, 'nameToken', None)
            if name_tok is not None:
                # Look at the next token after the variable name for '='
                assign_tok = getattr(name_tok, 'next', None)
                if assign_tok and _token_str(assign_tok) == '=':
                    rhs = getattr(assign_tok, 'next', None)
                    if rhs:
                        return _trace_to_literal(rhs, depth + 1)
    return None


class CallSiteCollector:
    """Walk tokens and find calls to format-string functions."""

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.call_sites: List[FormatCallSite] = []

    def collect(self, cfg_data) -> None:
        tokenlist = cfg_data.tokenlist if hasattr(cfg_data, 'tokenlist') else []
        if not tokenlist:
            return

        tok = tokenlist[0] if isinstance(tokenlist, list) else tokenlist
        while tok is not None:
            self._visit(tok)
            tok = tok.next

    def _visit(self, tok) -> None:
        s = _token_str(tok)

        # We're looking for the '(' token whose astOperand1 is the callee
        if s != '(':
            return

        op1 = getattr(tok, 'astOperand1', None)
        if op1 is None:
            return

        callee_name = _token_str(op1)
        callee_vid = _token_var_id(op1)

        # Skip if callee is a variable (function pointer — can't resolve)
        if callee_vid is not None and callee_name not in ALL_FORMAT_FUNCS:
            return

        func_info = ALL_FORMAT_FUNCS.get(callee_name)
        if func_info is None:
            return

        # Collect arguments
        args = _collect_call_arguments(tok)

        # Extract the format string argument
        fmt_idx = func_info.format_arg_index
        fmt_tok = args[fmt_idx] if fmt_idx < len(args) else None
        fmt_str = None
        fmt_is_literal = False

        if fmt_tok is not None:
            # Try direct extraction
            fmt_str = _extract_string_literal(fmt_tok)
            if fmt_str is not None:
                fmt_is_literal = True
            else:
                # Try tracing through variables
                fmt_str = _trace_to_literal(fmt_tok)
                if fmt_str is not None:
                    fmt_is_literal = False  # resolved but not directly literal

        # Get variadic arguments (those after the format string)
        va_start = func_info.first_vararg_index
        va_args = args[va_start:] if va_start >= 0 and va_start < len(args) else []

        file_ = getattr(tok, 'file', '<unknown>')
        line = int(getattr(tok, 'linenr', 0) or 0)
        col = int(getattr(tok, 'column', 0) or 0)

        self.call_sites.append(FormatCallSite(
            func_info=func_info,
            call_token=tok,
            callee_name=callee_name,
            file=file_,
            line=line,
            column=col,
            format_arg_token=fmt_tok,
            format_string=fmt_str,
            format_is_literal=fmt_is_literal,
            arg_tokens=va_args,
            scope_id=_token_scope_id(tok),
        ))

    def summary(self) -> str:
        return f"Found {len(self.call_sites)} format-function call sites"


# ═══════════════════════════════════════════════════════════════════════
# Phase 2–3 — Type Resolution
# ═══════════════════════════════════════════════════════════════════════

def _resolve_type(tok, shims=None) -> CTypeKind:
    """
    Resolve the C type of the expression rooted at `tok`.
    Uses cppcheckdata ValueType if available, with shims type_analysis
    as a fallback.
    """
    # Try cppcheckdata's built-in ValueType
    vt = getattr(tok, 'valueType', None)
    if vt is not None:
        return _valuetype_to_kind(vt)

    # Try shims type_analysis
    if shims is not None and hasattr(shims, 'ta'):
        try:
            resolved = shims.ta.resolve_type(tok)
            if resolved is not None:
                return _shims_type_to_kind(resolved)
        except Exception:
            pass

    # Heuristic: if the token is a string literal, it's char*
    s = _token_str(tok)
    if _is_string_literal_token(tok):
        return CTypeKind.CHAR_PTR
    if s.startswith('L"'):
        return CTypeKind.WCHAR_PTR

    # Check for & (address-of) — means it's a pointer
    if s == '&':
        return CTypeKind.POINTER

    return CTypeKind.UNKNOWN


def _valuetype_to_kind(vt) -> CTypeKind:
    """Map cppcheckdata ValueType to our CTypeKind."""
    type_str = getattr(vt, 'type', '') or ''
    sign = getattr(vt, 'sign', '') or ''
    pointer = int(getattr(vt, 'pointer', 0) or 0)

    if pointer > 0:
        if 'char' in type_str:
            return CTypeKind.CHAR_PTR
        if 'void' in type_str:
            return CTypeKind.VOID_PTR
        if 'int' in type_str:
            return CTypeKind.INT_PTR
        return CTypeKind.POINTER

    type_lower = type_str.lower()

    if type_lower == 'bool':
        return CTypeKind.BOOL
    if type_lower == 'char':
        return CTypeKind.SCHAR if sign == 'signed' else (
            CTypeKind.UCHAR if sign == 'unsigned' else CTypeKind.CHAR
        )
    if type_lower == 'short':
        return CTypeKind.USHORT if sign == 'unsigned' else CTypeKind.SHORT
    if type_lower == 'int':
        return CTypeKind.UINT if sign == 'unsigned' else CTypeKind.INT
    if type_lower == 'long':
        return CTypeKind.ULONG if sign == 'unsigned' else CTypeKind.LONG
    if type_lower in ('long long', 'longlong'):
        return CTypeKind.ULLONG if sign == 'unsigned' else CTypeKind.LLONG
    if type_lower == 'float':
        return CTypeKind.FLOAT
    if type_lower == 'double':
        return CTypeKind.DOUBLE
    if type_lower in ('long double', 'longdouble'):
        return CTypeKind.LDOUBLE

    return CTypeKind.UNKNOWN


def _shims_type_to_kind(resolved) -> CTypeKind:
    """Convert a shims type_analysis result to CTypeKind."""
    name = str(resolved).lower() if resolved else ""
    if 'char *' in name or 'char*' in name:
        return CTypeKind.CHAR_PTR
    if '*' in name or 'pointer' in name:
        return CTypeKind.POINTER
    if 'double' in name:
        if 'long' in name:
            return CTypeKind.LDOUBLE
        return CTypeKind.DOUBLE
    if 'float' in name:
        return CTypeKind.FLOAT
    if 'long long' in name or 'int64' in name:
        return CTypeKind.LLONG
    if 'unsigned long' in name:
        return CTypeKind.ULONG
    if 'long' in name:
        return CTypeKind.LONG
    if 'unsigned' in name and 'int' in name:
        return CTypeKind.UINT
    if 'int' in name:
        return CTypeKind.INT
    if 'char' in name:
        return CTypeKind.CHAR
    if 'size_t' in name:
        return CTypeKind.SIZE_T
    return CTypeKind.UNKNOWN


def _is_pointer_type(kind: CTypeKind) -> bool:
    return kind in (
        CTypeKind.POINTER, CTypeKind.VOID_PTR,
        CTypeKind.CHAR_PTR, CTypeKind.WCHAR_PTR,
        CTypeKind.INT_PTR,
    )


def _type_compatible(actual: CTypeKind, expected: List[CTypeKind]) -> bool:
    """Check if actual type is in the expected list, with some leniency."""
    if actual == CTypeKind.UNKNOWN:
        return True  # can't check, assume OK
    if actual in expected:
        return True
    # Integer promotions: small types promote to int in varargs
    int_types = {
        CTypeKind.BOOL, CTypeKind.CHAR, CTypeKind.SCHAR,
        CTypeKind.UCHAR, CTypeKind.SHORT, CTypeKind.USHORT,
    }
    if actual in int_types and CTypeKind.INT in expected:
        return True
    # float promotes to double in varargs
    if actual == CTypeKind.FLOAT and CTypeKind.DOUBLE in expected:
        return True
    # Any pointer type matches POINTER or VOID_PTR
    if _is_pointer_type(actual) and (
        CTypeKind.POINTER in expected or CTypeKind.VOID_PTR in expected
    ):
        return True
    return False


# ═══════════════════════════════════════════════════════════════════════
# Phase 4 — Matching & Validation
# ═══════════════════════════════════════════════════════════════════════

class FormatStringValidator:
    """
    The main validation engine. For each call site:
    1. Parse the format string
    2. Count expected arguments
    3. Type-check each argument against its specifier
    4. Check for dangerous patterns (%n, non-literal format)
    """

    def __init__(
        self,
        shims=None,
        verbose: bool = False,
        enabled_rules: Optional[Set[str]] = None,
    ):
        self.shims = shims
        self.verbose = verbose
        self.enabled_rules = enabled_rules
        self.diagnostics: List[Diagnostic] = []

    def _enabled(self, rule: RuleID) -> bool:
        if self.enabled_rules is None:
            return True
        return rule.value in self.enabled_rules

    def validate_call_site(self, site: FormatCallSite) -> List[Diagnostic]:
        """Validate a single format-function call site."""
        diags: List[Diagnostic] = []
        family = site.func_info.family

        # ── FS04: Non-literal format string ──────────────────────────
        if self._enabled(RuleID.FS04):
            if site.format_string is None:
                diags.append(Diagnostic(
                    rule=RuleID.FS04,
                    severity=Severity.ERROR,
                    file=site.file,
                    line=site.line,
                    column=site.column,
                    message=(
                        f"format string argument to '{site.callee_name}' is not "
                        f"a string literal — potential format string vulnerability"
                    ),
                    function_name=site.callee_name,
                    cwe=134,
                ))
                return diags  # can't check further without the string
            elif not site.format_is_literal:
                diags.append(Diagnostic(
                    rule=RuleID.FS04,
                    severity=Severity.WARNING,
                    file=site.file,
                    line=site.line,
                    column=site.column,
                    message=(
                        f"format string argument to '{site.callee_name}' is not "
                        f"a direct literal (resolved through variable); "
                        f"verify it cannot be attacker-controlled"
                    ),
                    function_name=site.callee_name,
                    format_string=site.format_string,
                    cwe=134,
                ))

        if site.format_string is None:
            return diags

        # ── Parse the format string ──────────────────────────────────
        directives, parse_errors = parse_format_string(
            site.format_string, family
        )

        # ── FS05: Invalid specifiers ─────────────────────────────────
        if self._enabled(RuleID.FS05):
            for err in parse_errors:
                diags.append(Diagnostic(
                    rule=RuleID.FS05,
                    severity=Severity.ERROR,
                    file=site.file,
                    line=site.line,
                    column=site.column,
                    message=(
                        f"in call to '{site.callee_name}': {err} "
                        f"in format string \"{site.format_string}\""
                    ),
                    function_name=site.callee_name,
                    format_string=site.format_string,
                ))

            for d in directives:
                if d.conversion_type == ConversionType.INVALID:
                    diags.append(Diagnostic(
                        rule=RuleID.FS05,
                        severity=Severity.ERROR,
                        file=site.file,
                        line=site.line,
                        column=site.column,
                        message=(
                            f"invalid format specifier '{d.raw}' in call to "
                            f"'{site.callee_name}'"
                        ),
                        function_name=site.callee_name,
                        format_string=site.format_string,
                    ))

        # ── FS06: %n usage ───────────────────────────────────────────
        if self._enabled(RuleID.FS06):
            for d in directives:
                if d.conversion_type == ConversionType.WRITE_COUNT:
                    diags.append(Diagnostic(
                        rule=RuleID.FS06,
                        severity=Severity.WARNING,
                        file=site.file,
                        line=site.line,
                        column=site.column,
                        message=(
                            f"use of '%n' in call to '{site.callee_name}' — "
                            f"'%n' writes to memory and is a common attack vector"
                        ),
                        function_name=site.callee_name,
                        format_string=site.format_string,
                        cwe=134,
                    ))

        # ── Skip argument-count/type checks for va_list versions ─────
        if not site.func_info.is_variadic:
            return diags

        # ── Count expected arguments ─────────────────────────────────
        total_expected = sum(d.args_consumed for d in directives)
        total_supplied = len(site.arg_tokens)

        # ── FS01: Missing arguments ──────────────────────────────────
        if self._enabled(RuleID.FS01) and total_supplied < total_expected:
            diags.append(Diagnostic(
                rule=RuleID.FS01,
                severity=Severity.ERROR,
                file=site.file,
                line=site.line,
                column=site.column,
                message=(
                    f"'{site.callee_name}' format string \"{site.format_string}\" "
                    f"requires {total_expected} argument(s) but only "
                    f"{total_supplied} supplied — undefined behaviour"
                ),
                function_name=site.callee_name,
                format_string=site.format_string,
            ))

        # ── FS02: Extra arguments ────────────────────────────────────
        if self._enabled(RuleID.FS02) and total_supplied > total_expected:
            diags.append(Diagnostic(
                rule=RuleID.FS02,
                severity=Severity.WARNING,
                file=site.file,
                line=site.line,
                column=site.column,
                message=(
                    f"'{site.callee_name}' format string \"{site.format_string}\" "
                    f"expects {total_expected} argument(s) but "
                    f"{total_supplied} supplied — extra arguments ignored"
                ),
                function_name=site.callee_name,
                format_string=site.format_string,
            ))

        # ── FS03 / FS07 / FS08: Type checking ───────────────────────
        arg_idx = 0  # index into site.arg_tokens
        for d in directives:
            if d.conversion_type == ConversionType.PERCENT:
                continue  # %% consumes no args

            # Handle * width
            if d.star_width:
                if arg_idx < total_supplied:
                    if self._enabled(RuleID.FS07):
                        wtype = _resolve_type(site.arg_tokens[arg_idx], self.shims)
                        if wtype != CTypeKind.UNKNOWN and wtype != CTypeKind.INT:
                            diags.append(Diagnostic(
                                rule=RuleID.FS07,
                                severity=Severity.STYLE,
                                file=site.file,
                                line=site.line,
                                column=site.column,
                                message=(
                                    f"'*' width in '{d.raw}' expects 'int' argument "
                                    f"but got '{wtype.value}'"
                                ),
                                function_name=site.callee_name,
                                format_string=site.format_string,
                            ))
                    arg_idx += 1

            # Handle * precision
            if d.star_precision:
                if arg_idx < total_supplied:
                    if self._enabled(RuleID.FS07):
                        ptype = _resolve_type(site.arg_tokens[arg_idx], self.shims)
                        if ptype != CTypeKind.UNKNOWN and ptype != CTypeKind.INT:
                            diags.append(Diagnostic(
                                rule=RuleID.FS07,
                                severity=Severity.STYLE,
                                file=site.file,
                                line=site.line,
                                column=site.column,
                                message=(
                                    f"'*' precision in '{d.raw}' expects 'int' "
                                    f"argument but got '{ptype.value}'"
                                ),
                                function_name=site.callee_name,
                                format_string=site.format_string,
                            ))
                    arg_idx += 1

            # The main value argument
            if d.args_consumed > 0 and not d.is_suppressed:
                consumed_for_value = d.args_consumed - (
                    (1 if d.star_width else 0) + (1 if d.star_precision else 0)
                )
                if consumed_for_value > 0 and arg_idx < total_supplied:
                    arg_tok = site.arg_tokens[arg_idx]
                    actual_type = _resolve_type(arg_tok, self.shims)

                    # FS03: type mismatch
                    if self._enabled(RuleID.FS03):
                        if family == "printf":
                            expected = _expected_type_printf(d)
                        else:
                            expected = _expected_type_scanf(d)

                        if expected and not _type_compatible(actual_type, expected):
                            expected_str = " or ".join(
                                f"'{e.value}'" for e in expected[:3]
                            )
                            diags.append(Diagnostic(
                                rule=RuleID.FS03,
                                severity=Severity.ERROR,
                                file=site.file,
                                line=site.line,
                                column=site.column,
                                message=(
                                    f"argument {arg_idx + 1} to "
                                    f"'{site.callee_name}' has type "
                                    f"'{actual_type.value}' but format "
                                    f"specifier '{d.raw}' expects "
                                    f"{expected_str}"
                                ),
                                function_name=site.callee_name,
                                format_string=site.format_string,
                            ))

                    # FS08: scanf arg not a pointer
                    if self._enabled(RuleID.FS08) and family == "scanf":
                        if actual_type != CTypeKind.UNKNOWN and \
                           not _is_pointer_type(actual_type):
                            diags.append(Diagnostic(
                                rule=RuleID.FS08,
                                severity=Severity.ERROR,
                                file=site.file,
                                line=site.line,
                                column=site.column,
                                message=(
                                    f"argument {arg_idx + 1} to "
                                    f"'{site.callee_name}' for specifier "
                                    f"'{d.raw}' should be a pointer but "
                                    f"has type '{actual_type.value}'"
                                ),
                                function_name=site.callee_name,
                                format_string=site.format_string,
                            ))

                    arg_idx += 1

        return diags


# ═══════════════════════════════════════════════════════════════════════
# Phase 5 — Taint Analysis for FS04 (optional, requires shims)
# ═══════════════════════════════════════════════════════════════════════

class FormatTaintAnalyzer:
    """
    Uses the shims abstract_domains Taint lattice and dataflow_engine
    to trace whether a format-string argument can be influenced by
    external input (argv, getenv, fgets, recv, etc.).
    """

    TAINT_SOURCES = frozenset({
        "argv",       # main(argc, argv)
        "getenv",     # environment variables
        "fgets",      # file/stdin input
        "gets",       # deprecated stdin
        "read",       # POSIX read
        "recv",       # socket receive
        "recvfrom",
        "recvmsg",
        "fread",
        "scanf",      # standard input
        "fscanf",
        "getline",
        "getdelim",
    })

    def __init__(self, shims, cfg_data, verbose: bool = False):
        self.shims = shims
        self.cfg_data = cfg_data
        self.verbose = verbose
        self._tainted_vars: Optional[Set[int]] = None

    def is_tainted(self, tok) -> bool:
        """Check if the expression at tok is tainted by external input."""
        if self.shims is None:
            return False  # can't check without shims

        if self._tainted_vars is None:
            self._compute_tainted_vars()

        vid = _token_var_id(tok)
        if vid is not None and vid in self._tainted_vars:
            return True

        # Check if any sub-expression is tainted
        op1 = getattr(tok, 'astOperand1', None)
        op2 = getattr(tok, 'astOperand2', None)
        if op1 and self.is_tainted(op1):
            return True
        if op2 and self.is_tainted(op2):
            return True

        return False

    def _compute_tainted_vars(self):
        """
        Compute the set of variable IDs that are tainted.
        Uses a simple forward taint propagation.
        """
        self._tainted_vars = set()

        try:
            taint_domain = self.shims.ad.TaintLattice()
        except (AttributeError, TypeError):
            # Fallback: simple token-walk taint propagation
            self._simple_taint_walk()
            return

        # Try full dataflow-based taint analysis
        try:
            for scope in (self.cfg_data.scopes or []):
                scope_type = getattr(scope, 'type', '')
                if scope_type not in ('Function', 'function'):
                    continue
                cfg = self.shims.cfg.build_cfg(scope)
                if cfg is None:
                    continue

                # Run taint analysis
                result = self.shims.dfa.run_taint_analysis(
                    cfg, taint_domain,
                    sources=self.TAINT_SOURCES,
                )
                if result:
                    for var_id in result.tainted_variables():
                        self._tainted_vars.add(var_id)
        except Exception as exc:
            if self.verbose:
                print(f"  [TAINT] dataflow taint failed ({exc}); "
                      f"falling back to token walk", file=sys.stderr)
            self._simple_taint_walk()

    def _simple_taint_walk(self):
        """Fallback: walk tokens looking for assignments from taint sources."""
        tokenlist = self.cfg_data.tokenlist if hasattr(self.cfg_data, 'tokenlist') else []
        if not tokenlist:
            return
        tok = tokenlist[0] if isinstance(tokenlist, list) else tokenlist

        # First pass: find directly tainted variables
        while tok is not None:
            s = _token_str(tok)
            # Check for call to a taint source
            if s == '(':
                op1 = getattr(tok, 'astOperand1', None)
                if op1 and _token_str(op1) in self.TAINT_SOURCES:
                    # Find the LHS of the assignment
                    parent = getattr(tok, 'astParent', None)
                    if parent and _token_str(parent) == '=':
                        lhs = getattr(parent, 'astOperand1', None)
                        if lhs:
                            vid = _token_var_id(lhs)
                            if vid:
                                self._tainted_vars.add(vid)

            # Check for argv parameter in main
            vid = _token_var_id(tok)
            if vid and s == 'argv':
                self._tainted_vars.add(vid)

            tok = tok.next

        # Second pass: simple propagation (x = tainted_var → x is tainted)
        changed = True
        iterations = 0
        while changed and iterations < 20:
            changed = False
            iterations += 1
            tok = tokenlist[0] if isinstance(tokenlist, list) else tokenlist
            while tok is not None:
                s = _token_str(tok)
                if s == '=' and not s.startswith('=='):
                    op1 = getattr(tok, 'astOperand1', None)
                    op2 = getattr(tok, 'astOperand2', None)
                    if op1 and op2:
                        lhs_vid = _token_var_id(op1)
                        rhs_vid = _token_var_id(op2)
                        if lhs_vid and rhs_vid and rhs_vid in self._tainted_vars:
                            if lhs_vid not in self._tainted_vars:
                                self._tainted_vars.add(lhs_vid)
                                changed = True
                tok = tok.next


# ═══════════════════════════════════════════════════════════════════════
# Orchestrator
# ═══════════════════════════════════════════════════════════════════════

class FormatStringChecker:
    """Top-level orchestrator for the format-string validation addon."""

    RULE_INFO = {
        RuleID.FS01: ("Missing format arguments", Severity.ERROR, None),
        RuleID.FS02: ("Extra format arguments", Severity.WARNING, None),
        RuleID.FS03: ("Format type mismatch", Severity.ERROR, None),
        RuleID.FS04: ("Non-literal format string", Severity.ERROR, 134),
        RuleID.FS05: ("Invalid format specifier", Severity.ERROR, None),
        RuleID.FS06: ("%n usage", Severity.WARNING, 134),
        RuleID.FS07: ("Width/precision * type mismatch", Severity.STYLE, None),
        RuleID.FS08: ("Scanf arg not a pointer", Severity.ERROR, None),
    }

    def __init__(
        self,
        verbose: bool = False,
        json_output: bool = False,
        enabled_rules: Optional[Set[str]] = None,
        taint_check: bool = True,
    ):
        self.verbose = verbose
        self.json_output = json_output
        self.enabled_rules = enabled_rules
        self.taint_check = taint_check
        self.diagnostics: List[Diagnostic] = []
        self.stats: Dict[str, Any] = {
            "files": 0,
            "call_sites": 0,
            "diagnostics": 0,
            "by_rule": defaultdict(int),
            "time_seconds": 0.0,
        }

    def run(self, dump_files: List[str]) -> int:
        t0 = time.monotonic()
        cppcheckdata = _import_cppcheckdata()
        shims = _import_shims() if self.taint_check else None

        if shims is None and self.verbose:
            print("[info] shims not available; taint analysis disabled",
                  file=sys.stderr)

        for dump_path in dump_files:
            if not os.path.isfile(dump_path):
                print(f"error: {dump_path}: not found", file=sys.stderr)
                continue
            self._analyze_dump(dump_path, cppcheckdata, shims)

        # Deduplicate
        seen = set()
        unique = []
        for d in self.diagnostics:
            key = (d.rule.value, d.file, d.line, d.column, d.message)
            if key not in seen:
                seen.add(key)
                unique.append(d)
        self.diagnostics = sorted(unique, key=lambda d: (d.file, d.line, d.column))

        self.stats["diagnostics"] = len(self.diagnostics)
        for d in self.diagnostics:
            self.stats["by_rule"][d.rule.value] += 1
        self.stats["time_seconds"] = time.monotonic() - t0

        self._emit()
        return 1 if self.diagnostics else 0

    def _analyze_dump(self, path: str, cppcheckdata, shims):
        self.stats["files"] += 1
        if self.verbose:
            print(f"\n{'='*60}\nAnalyzing: {path}\n{'='*60}", file=sys.stderr)

        try:
            data = cppcheckdata.CppcheckData(path)
        except Exception as exc:
            print(f"error: {path}: {exc}", file=sys.stderr)
            return

        for cfg in data.configurations:
            # Phase 1: Collect call sites
            collector = CallSiteCollector(verbose=self.verbose)
            collector.collect(cfg)
            if self.verbose:
                print(f"  {collector.summary()}", file=sys.stderr)
            self.stats["call_sites"] += len(collector.call_sites)

            # Phase 5: Taint analysis (if enabled)
            taint = None
            if shims and self.taint_check and \
               self.enabled_rules is None or \
               (self.enabled_rules and "FS04" in self.enabled_rules):
                taint = FormatTaintAnalyzer(shims, cfg, verbose=self.verbose)

            # Phase 2–4: Validate each call site
            validator = FormatStringValidator(
                shims=shims,
                verbose=self.verbose,
                enabled_rules=self.enabled_rules,
            )

            for site in collector.call_sites:
                diags = validator.validate_call_site(site)
                self.diagnostics.extend(diags)

                # Enhanced FS04: taint-based check
                if taint and site.format_arg_token and not site.format_is_literal:
                    if taint.is_tainted(site.format_arg_token):
                        # Upgrade the FS04 warning to error with taint info
                        already = any(
                            d.rule == RuleID.FS04 and d.line == site.line
                            for d in diags
                        )
                        if not already:
                            self.diagnostics.append(Diagnostic(
                                rule=RuleID.FS04,
                                severity=Severity.ERROR,
                                file=site.file,
                                line=site.line,
                                column=site.column,
                                message=(
                                    f"TAINTED format string passed to "
                                    f"'{site.callee_name}' — the format argument "
                                    f"may be influenced by external input "
                                    f"(CWE-134)"
                                ),
                                function_name=site.callee_name,
                                cwe=134,
                            ))

    def _emit(self):
        if self.json_output:
            out = {
                "version": 1,
                "checker": "FormatStringValidator",
                "stats": {
                    "files": self.stats["files"],
                    "call_sites": self.stats["call_sites"],
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
        prog="FormatStringValidator",
        description="Cppcheck addon: validate printf/scanf format strings.",
        epilog=(
            "Rules:\n"
            "  FS01  Missing format arguments (UB)\n"
            "  FS02  Extra format arguments (ignored)\n"
            "  FS03  Argument type incompatible with specifier\n"
            "  FS04  Non-literal / tainted format string (CWE-134)\n"
            "  FS05  Invalid or unknown conversion specifier\n"
            "  FS06  Use of %n (writes to memory)\n"
            "  FS07  * width/precision with non-int argument\n"
            "  FS08  scanf argument not a pointer\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("dump_files", nargs="+", metavar="FILE.dump")
    p.add_argument("--verbose", "-v", action="store_true")
    p.add_argument("--json", dest="json_output", action="store_true")
    p.add_argument("--enable", dest="enable_rules", default=None,
                   help="Comma-separated rules to enable (e.g. FS01,FS03)")
    p.add_argument("--disable", dest="disable_rules", default=None,
                   help="Comma-separated rules to disable")
    p.add_argument("--no-taint", dest="no_taint", action="store_true",
                   help="Disable taint analysis for FS04")
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

    checker = FormatStringChecker(
        verbose=args.verbose,
        json_output=args.json_output,
        enabled_rules=enabled,
        taint_check=not args.no_taint,
    )
    return checker.run(args.dump_files)


if __name__ == "__main__":
    sys.exit(main())
