#!/usr/bin/env python3
"""
VarargsSafetyChecker.py
════════════════════════════════════════════════════════════════════════

Cppcheck addon: varargs-safety-checker
Tier 1 | CWE-134, CWE-686, CWE-687, CWE-688, CWE-252, CWE-825

Detects incorrect use of variadic functions and format strings in C.

Background
──────────
C's variadic calling convention transfers zero type-safety to the
callee.  The compiler cannot verify:
  - that the format string matches the argument list in type or count,
  - that va_arg() is called in the correct lifecycle order,
  - that a tainted (externally-sourced) format string is not used as
    the fmt argument of printf-family functions,
  - that the return value of scanf-family functions is checked.

Checkers
────────
  VSC-01  nonLiteralFormat        CWE-134   Non-literal string used as
                                            printf/syslog format argument
  VSC-02  formatSpecArgCountLow   CWE-687   Fewer arguments supplied than
                                            format specifiers demand
  VSC-03  formatSpecArgCountHigh  CWE-688   More arguments supplied than
                                            format specifiers consume
  VSC-04  formatSpecTypeMismatch  CWE-686   Argument type incompatible
                                            with the corresponding format
                                            specifier
  VSC-05  vaStartWrongParam       CWE-695   va_start() called with a
                                            parameter that is not the last
                                            named parameter of the function
  VSC-06  vaArgBeforeStart        CWE-825   va_arg() called before
                                            va_start() in the same scope
  VSC-07  vaArgAfterEnd           CWE-825   va_arg() or va_copy() called
                                            after va_end() without
                                            intervening va_start()
  VSC-08  vaListDoubleFree        CWE-415   va_end() called twice on the
                                            same va_list without
                                            intervening va_start()
  VSC-09  taintedFormatString     CWE-134   Format string derived from
                                            user-controlled input (argv,
                                            getenv, fgets, scanf) passed
                                            to a format sink
  VSC-10  uncheckedScanfReturn    CWE-252   Return value of scanf-family
                                            function not checked

CONTRACT — Safe Variable-ID Access
───────────────────────────────────
ALL variable-ID access MUST use _safe_vid() or _safe_vid_tok().
Direct int(tok.varId) calls are FORBIDDEN.

Rationale: cppcheckdata returns varId as decimal strings, hex address
strings ("560e31248150" — ValueError), None, or sentinel 0 (meaning
"no variable").  _safe_vid() normalises all cases to Optional[int],
returning None for the sentinel and non-decimal strings.

Usage
─────
    cppcheck --dump myfile.c
    python VarargsSafetyChecker.py myfile.c.dump

License: MIT
"""

from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import dataclass, field
from typing import (
    Any,
    Dict,
    FrozenSet,
    List,
    Optional,
    Set,
    Tuple,
)

try:
    import cppcheckdata
except ImportError:
    sys.stderr.write("ERROR: cppcheckdata module not found.\n")
    sys.exit(1)


# ═══════════════════════════════════════════════════════════════════════════
#  PART 1 — SAFE VARIABLE-ID HELPERS  (hardening mandate)
# ═══════════════════════════════════════════════════════════════════════════

def _safe_vid(vid: Any) -> Optional[int]:
    """
    Safely convert a raw varId value to int.

    Returns None for:
      - None input
      - non-decimal strings (hex address strings like '560e31248150')
      - cppcheck sentinel value 0  ("no variable")

    NEVER call int(tok.varId) directly anywhere in this addon.
    """
    if vid is None:
        return None
    try:
        v = int(vid)
        return v if v != 0 else None
    except (ValueError, TypeError):
        return None


def _safe_vid_tok(tok: Any) -> Optional[int]:
    """Return the safe variable-ID for a token, or None."""
    return _safe_vid(getattr(tok, "varId", None))


# ═══════════════════════════════════════════════════════════════════════════
#  PART 2 — TOKEN UTILITIES
# ═══════════════════════════════════════════════════════════════════════════

def _tok_str(tok: Any) -> str:
    return getattr(tok, "str", "") or ""

def _tok_file(tok: Any) -> str:
    return getattr(tok, "file", "") or ""

def _tok_line(tok: Any) -> int:
    return int(getattr(tok, "linenr", 0) or 0)

def _tok_col(tok: Any) -> int:
    return int(getattr(tok, "column", 0) or 0)

def _tok_next(tok: Any) -> Optional[Any]:
    return getattr(tok, "next", None)

def _tok_prev(tok: Any) -> Optional[Any]:
    return getattr(tok, "previous", None)

def _tok_scope(tok: Any) -> Optional[Any]:
    return getattr(tok, "scope", None)

def _scope_type(scope: Any) -> str:
    return getattr(scope, "type", "") or ""

def _is_function_call(tok: Any) -> bool:
    if not getattr(tok, "isName", False):
        return False
    nxt = _tok_next(tok)
    return nxt is not None and _tok_str(nxt) == "("

def _is_string_literal(tok: Any) -> bool:
    return getattr(tok, "isString", False)

def _vf_int_values(tok: Any) -> List[int]:
    result: List[int] = []
    for v in getattr(tok, "values", None) or []:
        iv = getattr(v, "intvalue", None)
        if iv is not None:
            try:
                result.append(int(iv))
            except (ValueError, TypeError):
                pass
    return result

def _tok_is_inside_loop(tok: Any) -> bool:
    s = _tok_scope(tok)
    while s is not None:
        if _scope_type(s) in ("For", "While", "Do"):
            return True
        if _scope_type(s) == "Function":
            break
        s = getattr(s, "nestedIn", None)
    return False

def _token_order_key(tok: Any) -> Tuple[str, int, int]:
    return (_tok_file(tok), _tok_line(tok), _tok_col(tok))

def _tok_comes_before(a: Any, b: Any) -> bool:
    return _token_order_key(a) < _token_order_key(b)

def _same_function_scope(a: Any, b: Any) -> bool:
    """Return True if two tokens are in the same function body."""
    def _fn_scope(tok: Any) -> Optional[Any]:
        s = _tok_scope(tok)
        while s is not None:
            if _scope_type(s) == "Function":
                return s
            s = getattr(s, "nestedIn", None)
        return None
    sa = _fn_scope(a)
    sb = _fn_scope(b)
    return sa is not None and sa is sb


def _call_arg_tokens(call_name_tok: Any) -> List[Any]:
    """
    Return positional argument tokens for a function call in order.

    In cppcheck's AST the open-paren token's astOperand2 is the
    first argument (or a comma node for multiple arguments).
    """
    nxt = _tok_next(call_name_tok)
    if nxt is None or _tok_str(nxt) != "(":
        return []
    first = getattr(nxt, "astOperand2", None)
    if first is None:
        return []

    args: List[Any] = []

    def _collect(node: Any) -> None:
        if node is None:
            return
        if _tok_str(node) == ",":
            _collect(getattr(node, "astOperand1", None))
            _collect(getattr(node, "astOperand2", None))
        else:
            args.append(node)

    _collect(first)
    return args


def _variable_of(tok: Any) -> Optional[Any]:
    return getattr(tok, "variable", None)

def _is_local_variable(var: Any) -> bool:
    if var is None:
        return False
    return (
        getattr(var, "isLocal", False)
        and not getattr(var, "isStatic", False)
        and not getattr(var, "isGlobal", False)
    )

def _is_assignment_lhs(tok: Any) -> bool:
    parent = getattr(tok, "astParent", None)
    if parent is None:
        return False
    if not getattr(parent, "isAssignmentOp", False):
        return False
    return getattr(parent, "astOperand1", None) is tok


# ═══════════════════════════════════════════════════════════════════════════
#  PART 3 — DOMAIN CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════

# ── Printf-family sinks: (function_name → 0-based index of format arg) ──
# Index -1 means "no format arg, count args only" (not used here).
_PRINTF_SINKS: Dict[str, int] = {
    # Standard
    "printf":       0,
    "vprintf":      0,
    "fprintf":      1,
    "vfprintf":     1,
    "sprintf":      1,
    "vsprintf":     1,
    "snprintf":     2,
    "vsnprintf":    2,
    "dprintf":      1,
    "vdprintf":     1,
    # POSIX / BSD
    "asprintf":     1,
    "vasprintf":    1,
    # Syslog
    "syslog":       1,
    "vsyslog":      1,
    # BSD err(3)
    "err":          1,
    "errx":         1,
    "warn":         0,
    "warnx":        0,
    # Wide-char
    "wprintf":      0,
    "fwprintf":     1,
    "swprintf":     2,
}

# ── Scanf-family sinks: (function_name → 0-based index of format arg) ──
_SCANF_SINKS: Dict[str, int] = {
    "scanf":        0,
    "fscanf":       1,
    "sscanf":       1,
    "vscanf":       0,
    "vfscanf":      1,
    "vsscanf":      1,
}

# ── Sources of user-controlled / tainted data ───────────────────────────
_TAINT_SOURCES: FrozenSet[str] = frozenset({
    # Environment
    "getenv", "secure_getenv",
    # stdio
    "fgets", "fgetws", "gets", "fread",
    # scanf family (return value can be used as format)
    "scanf", "fscanf", "sscanf",
    # network / IPC
    "recv", "recvfrom", "recvmsg", "read",
    # special
    "readline", "getline", "getdelim",
})

# argv is the canonical taint source — handled separately by checking
# the second parameter of main().

# ── va_list lifecycle functions ─────────────────────────────────────────
_VA_START   = "va_start"
_VA_END     = "va_end"
_VA_ARG     = "va_arg"
_VA_COPY    = "va_copy"

_VA_LIFECYCLE: FrozenSet[str] = frozenset({
    _VA_START, _VA_END, _VA_ARG, _VA_COPY,
})

# ── Format specifier → compatible C type families ───────────────────────
# We map each printf conversion specifier to a set of "type class" tags.
# Argument tokens are classified by inspecting their cppcheck type info.
_FMT_TYPE_MAP: Dict[str, FrozenSet[str]] = {
    "d":  frozenset({"int", "signed"}),
    "i":  frozenset({"int", "signed"}),
    "u":  frozenset({"uint", "unsigned"}),
    "o":  frozenset({"uint", "unsigned"}),
    "x":  frozenset({"uint", "unsigned"}),
    "X":  frozenset({"uint", "unsigned"}),
    "e":  frozenset({"float", "double"}),
    "E":  frozenset({"float", "double"}),
    "f":  frozenset({"float", "double"}),
    "F":  frozenset({"float", "double"}),
    "g":  frozenset({"float", "double"}),
    "G":  frozenset({"float", "double"}),
    "a":  frozenset({"float", "double"}),
    "A":  frozenset({"float", "double"}),
    "c":  frozenset({"int", "char"}),
    "s":  frozenset({"ptr", "char_ptr"}),
    "p":  frozenset({"ptr", "any_ptr"}),
    "n":  frozenset({"int_ptr"}),
    "ld": frozenset({"long", "int"}),
    "li": frozenset({"long", "int"}),
    "lu": frozenset({"ulong", "unsigned"}),
    "lf": frozenset({"double"}),
    "zu": frozenset({"size_t", "uint"}),
    "zd": frozenset({"ssize_t", "int"}),
    "lld": frozenset({"longlong", "int"}),
    "llu": frozenset({"ulonglong", "unsigned"}),
}


# ═══════════════════════════════════════════════════════════════════════════
#  PART 4 — FORMAT STRING PARSER
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class _FmtSpec:
    """Represents one parsed format specifier from a format string."""
    index:      int          # position in argument list (0-based after fmt)
    raw:        str          # the full specifier, e.g. "%-10.5ld"
    conversion: str          # the conversion char(s), e.g. "ld"
    is_star_w:  bool = False # True if width is '*' (consumes an arg)
    is_star_p:  bool = False # True if precision is '*' (consumes an arg)


# Regex: matches a single printf-style format specifier.
#   %[flags][width][.precision][length]conversion
_FMT_RE = re.compile(
    r"%"
    r"(?P<flags>[-+ #0]*)?"
    r"(?P<width>\*|\d*)?"
    r"(?:\.(?P<prec>\*|\d*))?"
    r"(?P<length>hh|ll|[hlLqjzt])?"
    r"(?P<conv>[diouxXeEfFgGaAcspn%])"
)


def _parse_format_string(fmt: str) -> List[_FmtSpec]:
    """
    Parse a C printf format string and return a list of _FmtSpec objects.

    Each specifier that consumes a variadic argument produces one entry.
    %% (escaped percent) is ignored.
    Width/precision '*' each produce an extra implicit int argument.

    The returned list is ordered by argument consumption position.
    """
    specs: List[_FmtSpec] = []
    arg_index = 0

    for m in _FMT_RE.finditer(fmt):
        conv    = m.group("conv")
        width   = m.group("width")  or ""
        prec    = m.group("prec")   or ""
        length  = m.group("length") or ""
        raw     = m.group(0)

        if conv == "%":
            continue  # escaped percent, no argument consumed

        star_w = (width == "*")
        star_p = (prec  == "*")

        # Each '*' in width or precision consumes an implicit int arg
        if star_w:
            specs.append(_FmtSpec(arg_index, "*", "d",
                                  is_star_w=True))
            arg_index += 1
        if star_p:
            specs.append(_FmtSpec(arg_index, "*", "d",
                                  is_star_p=True))
            arg_index += 1

        # Build the canonical conversion key: length modifier + conv char
        conv_key = (length + conv) if (length + conv) in _FMT_TYPE_MAP else conv

        specs.append(_FmtSpec(arg_index, raw, conv_key,
                              is_star_w=False, is_star_p=False))
        arg_index += 1

    return specs


def _extract_string_literal(tok: Any) -> Optional[str]:
    """
    Extract the C string value from a string-literal token.

    cppcheck stores the token str with surrounding double quotes.
    We strip the quotes and handle simple escape sequences.
    Returns None if the token is not a string literal.
    """
    if not _is_string_literal(tok):
        return None
    s = _tok_str(tok)
    if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
        # Remove surrounding quotes; decode simple C escapes
        inner = s[1:-1]
        # Replace common escape sequences for regex purposes
        inner = inner.replace("\\n", "\n").replace("\\t", "\t")
        inner = inner.replace("\\\\", "\\").replace('\\"', '"')
        return inner
    return None


def _resolve_format_tok(arg_tok: Any) -> Optional[str]:
    """
    Try to resolve a format-argument token to its literal string value.

    Handles:
      - Direct string literals: printf("hello %d", ...)
      - Const char* variables with a known ValueFlow string value
        (cppcheck may propagate literal string values into variables)
    Returns None if the format string cannot be determined statically.
    """
    if arg_tok is None:
        return None

    # Direct string literal
    s = _extract_string_literal(arg_tok)
    if s is not None:
        return s

    # ValueFlow: check if any value is a known string
    for v in getattr(arg_tok, "values", None) or []:
        tv = getattr(v, "tokvalue", None)
        if tv is not None and _is_string_literal(tv):
            return _extract_string_literal(tv)

    return None


# ═══════════════════════════════════════════════════════════════════════════
#  PART 5 — ARGUMENT TYPE CLASSIFIER
# ═══════════════════════════════════════════════════════════════════════════

def _classify_arg(tok: Any) -> Optional[str]:
    """
    Classify an argument token into a type-class tag for format mismatch
    detection.

    Returns one of: "int", "uint", "long", "ulong", "longlong",
    "ulonglong", "float", "double", "char", "char_ptr", "ptr",
    "any_ptr", "int_ptr", "size_t", or None if unknown.

    We use the cppcheck Type object attached to the token where available,
    falling back to lexical inspection of the token string.
    """
    if tok is None:
        return None

    # Try cppcheck's type information first
    var = _variable_of(tok)
    if var is not None:
        vtype = getattr(var, "type", None)
        if vtype is not None:
            tn = (getattr(vtype, "str", None) or "").lower()
            return _type_name_to_class(tn)

    # Inspect the token's valueType attribute
    vt = getattr(tok, "valueType", None)
    if vt is not None:
        tn = (getattr(vt, "originalTypeName", None) or
              getattr(vt, "type", None) or "")
        if tn:
            return _type_name_to_class(tn.lower())
        # pointer?
        ptr = getattr(vt, "pointer", 0) or 0
        if ptr > 0:
            return "ptr"

    # Lexical fallbacks for integer literals
    ts = _tok_str(tok)
    if ts.isdigit():
        return "int"
    if ts.endswith(("u", "U")) and ts[:-1].isdigit():
        return "uint"
    if ts.endswith(("l", "L")) and ts[:-1].isdigit():
        return "long"
    if ts.endswith(("ul", "UL", "lu", "LU")):
        return "ulong"
    if ts.endswith(("ll", "LL")):
        return "longlong"
    if ts.endswith(("ull", "ULL")):
        return "ulonglong"
    # Float/double literals
    if re.match(r'^[0-9]*\.[0-9]+([eE][+-]?[0-9]+)?[fF]?$', ts):
        return "float" if ts.endswith(("f", "F")) else "double"
    # String literals
    if _is_string_literal(tok):
        return "char_ptr"
    # Character literals
    if ts.startswith("'"):
        return "char"
    # NULL
    if ts in {"NULL", "nullptr", "0"}:
        return "ptr"

    return None


def _type_name_to_class(tn: str) -> Optional[str]:
    """Map a C type name string to a type-class tag."""
    tn = tn.strip()
    if "unsigned long long" in tn or "uint64" in tn:
        return "ulonglong"
    if "long long" in tn or "int64" in tn:
        return "longlong"
    if "unsigned long" in tn or "ulong" in tn:
        return "ulong"
    if "unsigned int" in tn or "uint" in tn or "uint32" in tn:
        return "uint"
    if "unsigned short" in tn or "ushort" in tn:
        return "uint"
    if "unsigned char" in tn:
        return "uint"
    if "long" in tn and "unsigned" not in tn:
        return "long"
    if "int" in tn and "unsigned" not in tn:
        return "int"
    if "short" in tn:
        return "int"
    if "char" in tn and "*" in tn:
        return "char_ptr"
    if "char" in tn:
        return "char"
    if "double" in tn or "long double" in tn:
        return "double"
    if "float" in tn:
        return "float"
    if "size_t" in tn:
        return "size_t"
    if "ssize_t" in tn:
        return "int"
    if "*" in tn:
        return "ptr"
    return None


def _types_compatible(spec_conv: str, arg_class: Optional[str]) -> bool:
    """
    Return True if arg_class is compatible with the format specifier.

    We use a permissive model: if we cannot classify the argument,
    we do NOT flag (to minimise false positives).
    """
    if arg_class is None:
        return True  # unknown → assume compatible

    expected = _FMT_TYPE_MAP.get(spec_conv)
    if expected is None:
        return True  # unknown specifier → assume compatible

    # Direct membership
    if arg_class in expected:
        return True

    # Promotion rules: char and short promote to int for %d
    if spec_conv in ("d", "i", "c") and arg_class in ("char", "short", "int"):
        return True

    # Pointer compatibility: %p accepts any pointer
    if spec_conv == "p" and arg_class in ("ptr", "char_ptr", "any_ptr",
                                           "int_ptr"):
        return True

    # %s accepts char*
    if spec_conv == "s" and arg_class in ("char_ptr", "ptr"):
        return True

    # Integer ↔ unsigned of same width
    _INT_UNSIGNED_PAIRS = {
        ("int", "uint"),
        ("long", "ulong"),
        ("longlong", "ulonglong"),
        ("size_t", "uint"),
        ("size_t", "ulong"),
        ("size_t", "ulonglong"),
    }
    for a, b in _INT_UNSIGNED_PAIRS:
        if (arg_class == a and b in expected) or \
           (arg_class == b and a in expected):
            return True

    return False


# ═══════════════════════════════════════════════════════════════════════════
#  PART 6 — FINDING MODEL
# ═══════════════════════════════════════════════════════════════════════════

ADDON_NAME = "VarargsSafetyChecker"


@dataclass(frozen=True)
class _Finding:
    error_id: str
    message:  str
    cwe:      int
    file:     str
    line:     int
    column:   int = 0
    severity: str = "warning"
    extra:    str = ""

    def emit(self) -> None:
        obj = {
            "file":     self.file,
            "linenr":   self.line,
            "column":   self.column,
            "severity": self.severity,
            "message":  self.message,
            "addon":    ADDON_NAME,
            "errorId":  self.error_id,
            "cwe":      self.cwe,
            "extra":    self.extra,
        }
        sys.stdout.write(json.dumps(obj) + "\n")


# ═══════════════════════════════════════════════════════════════════════════
#  PART 7 — BASE CHECKER
# ═══════════════════════════════════════════════════════════════════════════

class _BaseChecker:
    """Abstract base. All varId access via _safe_vid / _safe_vid_tok."""
    error_id: str = ""
    cwe:      int = 0
    severity: str = "warning"

    def __init__(self) -> None:
        self._findings: List[_Finding] = []

    def check(self, cfg: Any) -> None:
        raise NotImplementedError

    def _emit(
        self,
        tok: Any,
        message: str,
        error_id: Optional[str] = None,
        cwe:      Optional[int] = None,
        severity: Optional[str] = None,
        extra:    str = "",
    ) -> None:
        self._findings.append(_Finding(
            error_id = error_id  or self.error_id,
            message  = message,
            cwe      = cwe       or self.cwe,
            file     = _tok_file(tok),
            line     = _tok_line(tok),
            column   = _tok_col(tok),
            severity = severity  or self.severity,
            extra    = extra,
        ))

    @property
    def findings(self) -> List[_Finding]:
        return list(self._findings)


# ═══════════════════════════════════════════════════════════════════════════
#  PART 8 — INDIVIDUAL CHECKERS
# ═══════════════════════════════════════════════════════════════════════════

# ─────────────────────────────────────────────────────────────────────────
#  VSC-01  nonLiteralFormat  (CWE-134)
#
#  A printf-family function is called with a format argument that is NOT
#  a string literal — it is a variable, function return value, or any
#  non-constant expression.
#
#  Detection:
#    1. Find calls to functions in _PRINTF_SINKS.
#    2. Retrieve the format argument token by its 0-based index.
#    3. Try to resolve it to a literal via _resolve_format_tok().
#    4. If resolution fails → the format is non-literal → flag.
#
#  False-positive guards:
#    - If the token's ValueFlow value resolves to a known string literal
#      (e.g., a const char* variable initialised with a literal),
#      we do NOT flag.
#    - %2$s POSIX-style positional specifiers: treated as non-literal
#      only if the base format cannot be resolved.
#    - vprintf/vfprintf by design receive a va_list; the format itself
#      is still expected to be a literal — we check only the fmt arg,
#      not the va_list arg.
# ─────────────────────────────────────────────────────────────────────────

class _VSC01_NonLiteralFormat(_BaseChecker):
    error_id = "nonLiteralFormat"
    cwe      = 134
    severity = "warning"

    def check(self, cfg: Any) -> None:
        seen: Set[Tuple[str, int]] = set()
        for tok in getattr(cfg, "tokenlist", []):
            func = _tok_str(tok)
            if func not in _PRINTF_SINKS and func not in _SCANF_SINKS:
                continue
            if not _is_function_call(tok):
                continue

            fmt_idx = (
                _PRINTF_SINKS.get(func)
                if func in _PRINTF_SINKS
                else _SCANF_SINKS.get(func)
            )
            if fmt_idx is None:
                continue

            args = _call_arg_tokens(tok)
            if len(args) <= fmt_idx:
                continue  # too few args — VSC-02 covers this

            fmt_arg = args[fmt_idx]
            resolved = _resolve_format_tok(fmt_arg)
            if resolved is not None:
                continue  # literal format — ok

            key = (_tok_file(tok), _tok_line(tok))
            if key in seen:
                continue
            seen.add(key)

            self._emit(
                tok,
                f"'{func}()' called with a non-literal format string; "
                f"if the format string is externally controlled, this is "
                f"a format-string injection vulnerability (CWE-134).  "
                f"Use a literal format string or suppress with "
                f"'printf(\"%s\", str)'.",
                severity="warning",
            )


# ─────────────────────────────────────────────────────────────────────────
#  VSC-02  formatSpecArgCountLow  (CWE-687)
#
#  The format string contains more conversion specifiers than there are
#  arguments supplied to the variadic function.
#
#  Detection:
#    1. Resolve the format argument to a literal string.
#    2. Parse the format string → count required arguments.
#    3. Count the actual arguments after the format argument.
#    4. Flag if required > actual.
#
#  Star-width/precision arguments are included in required count.
# ─────────────────────────────────────────────────────────────────────────

class _VSC02_FormatArgCountLow(_BaseChecker):
    error_id = "formatSpecArgCountLow"
    cwe      = 687
    severity = "error"

    def check(self, cfg: Any) -> None:
        seen: Set[Tuple[str, int]] = set()
        for tok in getattr(cfg, "tokenlist", []):
            func = _tok_str(tok)
            if func not in _PRINTF_SINKS:
                continue
            if not _is_function_call(tok):
                continue

            fmt_idx = _PRINTF_SINKS[func]
            args = _call_arg_tokens(tok)
            if len(args) <= fmt_idx:
                continue

            fmt_str = _resolve_format_tok(args[fmt_idx])
            if fmt_str is None:
                continue  # can't analyse non-literal

            specs = _parse_format_string(fmt_str)
            required = len(specs)
            # Arguments actually supplied after the format string
            supplied = len(args) - fmt_idx - 1

            if required > supplied:
                key = (_tok_file(tok), _tok_line(tok))
                if key in seen:
                    continue
                seen.add(key)
                self._emit(
                    tok,
                    f"'{func}()': format string requires {required} "
                    f"argument(s) but only {supplied} "
                    f"{'was' if supplied == 1 else 'were'} supplied; "
                    f"reading uninitialised stack memory (CWE-687).",
                    severity="error",
                )


# ─────────────────────────────────────────────────────────────────────────
#  VSC-03  formatSpecArgCountHigh  (CWE-688)
#
#  More arguments are supplied than the format string can consume.
#  While not immediately exploitable, it indicates a logic error —
#  often a missing specifier or a copy-paste mistake where sensitive
#  data is being silently ignored.
# ─────────────────────────────────────────────────────────────────────────

class _VSC03_FormatArgCountHigh(_BaseChecker):
    error_id = "formatSpecArgCountHigh"
    cwe      = 688
    severity = "style"

    def check(self, cfg: Any) -> None:
        seen: Set[Tuple[str, int]] = set()
        for tok in getattr(cfg, "tokenlist", []):
            func = _tok_str(tok)
            if func not in _PRINTF_SINKS:
                continue
            if not _is_function_call(tok):
                continue

            fmt_idx = _PRINTF_SINKS[func]
            args = _call_arg_tokens(tok)
            if len(args) <= fmt_idx:
                continue

            fmt_str = _resolve_format_tok(args[fmt_idx])
            if fmt_str is None:
                continue

            specs    = _parse_format_string(fmt_str)
            required = len(specs)
            supplied = len(args) - fmt_idx - 1

            if supplied > required:
                key = (_tok_file(tok), _tok_line(tok))
                if key in seen:
                    continue
                seen.add(key)
                self._emit(
                    tok,
                    f"'{func}()': format string consumes {required} "
                    f"argument(s) but {supplied} were supplied; "
                    f"{supplied - required} excess "
                    f"{'argument is' if supplied - required == 1 else 'arguments are'} "
                    f"silently ignored — possible logic error (CWE-688).",
                    severity="style",
                )


# ─────────────────────────────────────────────────────────────────────────
#  VSC-04  formatSpecTypeMismatch  (CWE-686)
#
#  An argument's type is incompatible with the corresponding format
#  specifier.  Classic examples:
#    printf("%d", 3.14f)   → float passed for %d
#    printf("%s", 42)      → int passed for %s
#    printf("%p", "str")   → string literal for %p (char* vs void*)
#
#  Detection:
#    1. Resolve format string.
#    2. Parse specifiers.
#    3. For each specifier, classify the corresponding argument.
#    4. Test compatibility via _types_compatible().
#
#  Conservative: only flag when we have positive evidence of mismatch.
#  Unknown argument types are not flagged.
# ─────────────────────────────────────────────────────────────────────────

class _VSC04_FormatTypeMismatch(_BaseChecker):
    error_id = "formatSpecTypeMismatch"
    cwe      = 686
    severity = "warning"

    def check(self, cfg: Any) -> None:
        seen: Set[Tuple[str, int, int]] = set()   # (file, line, specIdx)
        for tok in getattr(cfg, "tokenlist", []):
            func = _tok_str(tok)
            if func not in _PRINTF_SINKS:
                continue
            if not _is_function_call(tok):
                continue

            fmt_idx = _PRINTF_SINKS[func]
            args = _call_arg_tokens(tok)
            if len(args) <= fmt_idx:
                continue

            fmt_str = _resolve_format_tok(args[fmt_idx])
            if fmt_str is None:
                continue

            specs    = _parse_format_string(fmt_str)
            var_args = args[fmt_idx + 1:]  # args after the format

            for spec in specs:
                if spec.index >= len(var_args):
                    break  # VSC-02 covers count mismatch

                arg_tok   = var_args[spec.index]
                arg_class = _classify_arg(arg_tok)

                if _types_compatible(spec.conversion, arg_class):
                    continue

                key = (_tok_file(tok), _tok_line(tok), spec.index)
                if key in seen:
                    continue
                seen.add(key)

                self._emit(
                    tok,
                    f"'{func}()': argument {spec.index + 1} has type-class "
                    f"'{arg_class}' but format specifier '{spec.raw}' "
                    f"expects a type compatible with '{spec.conversion}'; "
                    f"type mismatch in variadic call (CWE-686).",
                )


# ─────────────────────────────────────────────────────────────────────────
#  VSC-05  vaStartWrongParam  (CWE-695)
#
#  va_start(ap, param) is called with a 'param' that is NOT the last
#  named parameter of the enclosing function.
#
#  Background: the C standard (C99 §7.15.1.4) requires that the second
#  argument to va_start be the last named parameter before the '...'
#  ellipsis.  Passing any other parameter is undefined behaviour on some
#  calling conventions (notably those that pass arguments in registers).
#
#  Detection:
#    1. Find calls to va_start().
#    2. Get the second argument token.
#    3. Find the enclosing Function scope's parameter list.
#    4. Determine the last named (non-ellipsis) parameter.
#    5. Compare the second arg's varId to the last parameter's varId.
# ─────────────────────────────────────────────────────────────────────────

class _VSC05_VaStartWrongParam(_BaseChecker):
    error_id = "vaStartWrongParam"
    cwe      = 695
    severity = "warning"

    def check(self, cfg: Any) -> None:
        seen: Set[Tuple[str, int]] = set()
        for tok in getattr(cfg, "tokenlist", []):
            if _tok_str(tok) != _VA_START:
                continue
            if not _is_function_call(tok):
                continue

            args = _call_arg_tokens(tok)
            if len(args) < 2:
                continue  # malformed — ignore

            param_tok = args[1]
            param_vid = _safe_vid_tok(param_tok)
            if param_vid is None:
                continue

            # Find enclosing function scope and its parameter list
            last_param_vid = self._last_named_param_vid(tok, cfg)
            if last_param_vid is None:
                continue  # cannot determine → conservative, no flag

            if param_vid == last_param_vid:
                continue  # correct usage

            key = (_tok_file(tok), _tok_line(tok))
            if key in seen:
                continue
            seen.add(key)

            self._emit(
                tok,
                f"'va_start()' called with '{_tok_str(param_tok)}' as the "
                f"second argument, which is not the last named parameter of "
                f"the enclosing variadic function; this is undefined "
                f"behaviour per C99 §7.15.1.4 (CWE-695).",
            )

    @staticmethod
    def _last_named_param_vid(call_tok: Any, cfg: Any) -> Optional[int]:
        """
        Return the varId of the last named parameter of the function
        that contains call_tok, or None if it cannot be determined.
        """
        # Walk up the scope chain to find the enclosing Function scope
        fn_scope = None
        s = _tok_scope(call_tok)
        while s is not None:
            if _scope_type(s) == "Function":
                fn_scope = s
                break
            s = getattr(s, "nestedIn", None)
        if fn_scope is None:
            return None

        # The Function scope has a 'function' attribute pointing to the
        # Function object, which has an 'argumentList'.
        fn_obj = getattr(fn_scope, "function", None)
        if fn_obj is None:
            return None

        arg_list = getattr(fn_obj, "argumentList", None) or []
        last_vid: Optional[int] = None
        for arg in arg_list:
            # Skip the ellipsis pseudo-parameter
            if getattr(arg, "isEllipsis", False):
                continue
            vid = _safe_vid(getattr(arg, "nameToken", None) and
                            getattr(getattr(arg, "nameToken", None),
                                    "varId", None))
            if vid is not None:
                last_vid = vid
        return last_vid


# ─────────────────────────────────────────────────────────────────────────
#  VSC-06  vaArgBeforeStart  (CWE-825)
#
#  va_arg() is called before va_start() has been called in the same
#  function scope.
#
#  Detection:
#    1. For each function scope, collect va_start() call sites (by
#       va_list varId) and va_arg() call sites.
#    2. If a va_arg() call precedes the va_start() for the same va_list,
#       flag the va_arg() call.
# ─────────────────────────────────────────────────────────────────────────

class _VSC06_VaArgBeforeStart(_BaseChecker):
    error_id = "vaArgBeforeStart"
    cwe      = 825
    severity = "error"

    def check(self, cfg: Any) -> None:
        seen: Set[Tuple[str, int]] = set()
        tlist = getattr(cfg, "tokenlist", [])

        # Collect va_start and va_arg sites per va_list varId
        va_start_sites: Dict[int, List[Any]] = {}
        va_arg_sites:   Dict[int, List[Any]] = {}

        for tok in tlist:
            ts = _tok_str(tok)
            if ts not in (_VA_START, _VA_ARG, _VA_COPY):
                continue
            if not _is_function_call(tok):
                continue

            args = _call_arg_tokens(tok)
            if not args:
                continue

            ap_vid = _safe_vid_tok(args[0])
            if ap_vid is None:
                continue

            if ts == _VA_START:
                va_start_sites.setdefault(ap_vid, []).append(tok)
            elif ts in (_VA_ARG, _VA_COPY):
                va_arg_sites.setdefault(ap_vid, []).append(tok)

        for ap_vid, arg_sites in va_arg_sites.items():
            start_sites = va_start_sites.get(ap_vid, [])

            for arg_tok in arg_sites:
                # Is there a va_start for this ap before this va_arg?
                has_prior_start = any(
                    _tok_comes_before(st, arg_tok)
                    and _same_function_scope(st, arg_tok)
                    for st in start_sites
                )
                if has_prior_start:
                    continue

                key = (_tok_file(arg_tok), _tok_line(arg_tok))
                if key in seen:
                    continue
                seen.add(key)

                self._emit(
                    arg_tok,
                    f"'{_tok_str(arg_tok)}()' called on va_list "
                    f"(varId={ap_vid}) before 'va_start()'; "
                    f"the va_list is uninitialised — undefined behaviour "
                    f"(CWE-825).",
                    severity="error",
                )


# ─────────────────────────────────────────────────────────────────────────
#  VSC-07  vaArgAfterEnd  (CWE-825)
#
#  va_arg() or va_copy() is called after va_end() has been called on the
#  same va_list, without an intervening va_start().
#
#  Detection:
#    For each va_list varId, collect va_end() and subsequent va_arg()/
#    va_copy() call sites.  If a va_arg()/va_copy() follows a va_end()
#    with no va_start() in between, flag.
# ─────────────────────────────────────────────────────────────────────────

class _VSC07_VaArgAfterEnd(_BaseChecker):
    error_id = "vaArgAfterEnd"
    cwe      = 825
    severity = "error"

    def check(self, cfg: Any) -> None:
        seen: Set[Tuple[str, int]] = set()
        tlist = getattr(cfg, "tokenlist", [])

        # Collect lifecycle events per va_list varId in source order
        events: Dict[int, List[Tuple[str, Any]]] = {}  # vid → [(kind, tok)]

        for tok in tlist:
            ts = _tok_str(tok)
            if ts not in _VA_LIFECYCLE:
                continue
            if not _is_function_call(tok):
                continue
            args = _call_arg_tokens(tok)
            if not args:
                continue
            ap_vid = _safe_vid_tok(args[0])
            if ap_vid is None:
                continue
            events.setdefault(ap_vid, []).append((ts, tok))

        for ap_vid, ev_list in events.items():
            # Sort by source position
            ev_list.sort(key=lambda x: _token_order_key(x[1]))

            after_end = False
            end_tok: Optional[Any] = None

            for kind, tok in ev_list:
                if kind == _VA_START:
                    after_end = False
                    end_tok = None
                elif kind == _VA_END:
                    after_end = True
                    end_tok = tok
                elif kind in (_VA_ARG, _VA_COPY) and after_end:
                    key = (_tok_file(tok), _tok_line(tok))
                    if key in seen:
                        continue
                    seen.add(key)
                    end_line = _tok_line(end_tok) if end_tok else "?"
                    self._emit(
                        tok,
                        f"'{kind}()' called on va_list (varId={ap_vid}) "
                        f"after 'va_end()' at line {end_line} without "
                        f"an intervening 'va_start()'; the va_list object "
                        f"is invalid (CWE-825).",
                        severity="error",
                    )


# ─────────────────────────────────────────────────────────────────────────
#  VSC-08  vaListDoubleFree  (CWE-415)
#
#  va_end() is called twice on the same va_list object without an
#  intervening va_start().  This mirrors the double-free pattern for
#  va_list objects (which may be heap-backed on some platforms).
# ─────────────────────────────────────────────────────────────────────────

class _VSC08_VaListDoubleFree(_BaseChecker):
    error_id = "vaListDoubleFree"
    cwe      = 415
    severity = "error"

    def check(self, cfg: Any) -> None:
        seen: Set[Tuple[str, int]] = set()
        tlist = getattr(cfg, "tokenlist", [])

        events: Dict[int, List[Tuple[str, Any]]] = {}

        for tok in tlist:
            ts = _tok_str(tok)
            if ts not in _VA_LIFECYCLE:
                continue
            if not _is_function_call(tok):
                continue
            args = _call_arg_tokens(tok)
            if not args:
                continue
            ap_vid = _safe_vid_tok(args[0])
            if ap_vid is None:
                continue
            events.setdefault(ap_vid, []).append((ts, tok))

        for ap_vid, ev_list in events.items():
            ev_list.sort(key=lambda x: _token_order_key(x[1]))

            pending_end: Optional[Any] = None

            for kind, tok in ev_list:
                if kind == _VA_START:
                    pending_end = None
                elif kind == _VA_END:
                    if pending_end is not None:
                        # Second va_end() without va_start() in between
                        key = (_tok_file(tok), _tok_line(tok))
                        if key not in seen:
                            seen.add(key)
                            first_line = _tok_line(pending_end)
                            self._emit(
                                tok,
                                f"'va_end()' called twice on the same "
                                f"va_list (varId={ap_vid}); first call at "
                                f"line {first_line}, no 'va_start()' "
                                f"between them — double-end of va_list "
                                f"(CWE-415).",
                                severity="error",
                            )
                    else:
                        pending_end = tok


# ─────────────────────────────────────────────────────────────────────────
#  VSC-09  taintedFormatString  (CWE-134)
#
#  A format string passed to a printf/syslog sink is derived from a
#  user-controlled source: argv[], getenv(), fgets(), recv(), etc.
#
#  Detection (two-pass taint propagation):
#    Pass 1 — Mark tainted varIds:
#      a. Any variable assigned from a function in _TAINT_SOURCES.
#      b. argv parameters: identify the second parameter of main().
#      c. Any variable assigned from another tainted variable
#         (single-level propagation through assignments).
#
#    Pass 2 — Find printf-family calls where the format argument's
#      varId is in the tainted set.
#
#  This is a conservative, single-level propagation model.  It will
#  not track taint through struct fields, pointer arithmetic, or
#  function calls.  That scope is intentional for an addon (deep
#  taint analysis belongs in a dedicated SAST engine).
#
#  False-positive guards:
#    - If the format argument is a direct string literal, no flag.
#    - If the tainted variable is used as a %s ARGUMENT (not the format
#      string itself), no flag — that is safe.
# ─────────────────────────────────────────────────────────────────────────

class _VSC09_TaintedFormatString(_BaseChecker):
    error_id = "taintedFormatString"
    cwe      = 134
    severity = "warning"

    def check(self, cfg: Any) -> None:
        seen: Set[Tuple[str, int]] = set()
        tlist = getattr(cfg, "tokenlist", [])

        tainted: Set[int] = self._collect_tainted_vids(cfg, tlist)
        if not tainted:
            return

        for tok in tlist:
            func = _tok_str(tok)
            if func not in _PRINTF_SINKS and func not in _SCANF_SINKS:
                continue
            if not _is_function_call(tok):
                continue

            fmt_idx = (
                _PRINTF_SINKS.get(func)
                if func in _PRINTF_SINKS
                else _SCANF_SINKS.get(func)
            )
            if fmt_idx is None:
                continue

            args = _call_arg_tokens(tok)
            if len(args) <= fmt_idx:
                continue

            fmt_arg = args[fmt_idx]

            # Direct literal — safe
            if _resolve_format_tok(fmt_arg) is not None:
                continue

            # Check if the format argument's varId is tainted
            fmt_vid = _safe_vid_tok(fmt_arg)
            if fmt_vid is None or fmt_vid not in tainted:
                continue

            key = (_tok_file(tok), _tok_line(tok))
            if key in seen:
                continue
            seen.add(key)

            self._emit(
                tok,
                f"'{func}()': format string argument (varId={fmt_vid}) "
                f"is derived from a user-controlled source; an attacker "
                f"can supply format specifiers to read/write arbitrary "
                f"memory (CWE-134).",
                severity="warning",
            )

    @staticmethod
    def _collect_tainted_vids(cfg: Any, tlist: List[Any]) -> Set[int]:
        """
        Compute the set of variable IDs that carry tainted data.

        Taint sources:
          1. Variables assigned from functions in _TAINT_SOURCES.
          2. argv (second parameter of main()).
          3. Variables assigned from other tainted variables (propagation).
        """
        tainted: Set[int] = set()

        # ── Source 1: function-return taint ────────────────────────────
        for tok in tlist:
            if not getattr(tok, "isAssignmentOp", False):
                continue
            rhs = getattr(tok, "astOperand2", None)
            if rhs is None:
                continue

            # Identify a function call on the RHS
            callee_name: Optional[str] = None
            if _tok_str(rhs) == "(":
                op1 = getattr(rhs, "astOperand1", None)
                if op1 and _tok_str(op1) in _TAINT_SOURCES:
                    callee_name = _tok_str(op1)
            elif (
                getattr(rhs, "isName", False)
                and _tok_str(rhs) in _TAINT_SOURCES
                and _tok_str(_tok_next(rhs) or object()) == "("
            ):
                callee_name = _tok_str(rhs)

            if callee_name is None:
                continue

            lhs = getattr(tok, "astOperand1", None)
            if lhs is None:
                continue
            vid = _safe_vid_tok(lhs)
            if vid is not None:
                tainted.add(vid)

        # ── Source 2: argv taint ────────────────────────────────────────
        for fn in getattr(cfg, "functions", []) or []:
            if getattr(fn, "name", "") != "main":
                continue
            arg_list = getattr(fn, "argumentList", None) or []
            if len(arg_list) >= 2:
                argv_param = arg_list[1]
                argv_tok = getattr(argv_param, "nameToken", None)
                if argv_tok:
                    vid = _safe_vid_tok(argv_tok)
                    if vid is not None:
                        tainted.add(vid)

        # ── Source 3: single-level propagation ─────────────────────────
        changed = True
        while changed:
            changed = False
            for tok in tlist:
                if not getattr(tok, "isAssignmentOp", False):
                    continue
                lhs = getattr(tok, "astOperand1", None)
                rhs = getattr(tok, "astOperand2", None)
                if lhs is None or rhs is None:
                    continue
                rhs_vid = _safe_vid_tok(rhs)
                if rhs_vid not in tainted:
                    continue
                lhs_vid = _safe_vid_tok(lhs)
                if lhs_vid is not None and lhs_vid not in tainted:
                    tainted.add(lhs_vid)
                    changed = True

        return tainted


# ─────────────────────────────────────────────────────────────────────────
#  VSC-10  uncheckedScanfReturn  (CWE-252)
#
#  The return value of a scanf-family function (which reports the number
#  of successfully matched items, or EOF on error) is not checked.
#
#  Unchecked scanf return values mean that subsequent uses of the output
#  variables may operate on uninitialised or stale data.
#
#  Detection:
#    1. Find calls to functions in _SCANF_SINKS.
#    2. Check whether the call appears as:
#       a. The RHS of an assignment whose LHS is checked (good), OR
#       b. A condition in if/while (good), OR
#       c. A bare statement (bad — return value discarded).
#
#  False-positive guard:
#    - (void) casts: if the call is explicitly cast to void, we suppress.
#      cppcheck represents this as the call being the operand of a cast.
# ─────────────────────────────────────────────────────────────────────────

class _VSC10_UncheckedScanfReturn(_BaseChecker):
    error_id = "uncheckedScanfReturn"
    cwe      = 252
    severity = "warning"

    def check(self, cfg: Any) -> None:
        seen: Set[Tuple[str, int]] = set()
        tlist = getattr(cfg, "tokenlist", [])

        for tok in tlist:
            func = _tok_str(tok)
            if func not in _SCANF_SINKS:
                continue
            if not _is_function_call(tok):
                continue

            if self._return_value_checked(tok):
                continue

            key = (_tok_file(tok), _tok_line(tok))
            if key in seen:
                continue
            seen.add(key)

            self._emit(
                tok,
                f"Return value of '{func}()' is not checked; '{func}()' "
                f"returns the number of successfully matched items (or EOF "
                f"on error).  Ignoring it means subsequent variables may "
                f"hold uninitialised data if input was malformed (CWE-252).",
            )

    @staticmethod
    def _return_value_checked(call_tok: Any) -> bool:
        """
        Return True if the call's return value is used in any way
        that indicates it has been checked.

        Patterns accepted as "checked":
          - Assigned to a variable:  n = scanf(...)
          - Used as a condition:     if (scanf(...) == 1)
          - Used in a comparison:    while (scanf(...) != EOF)
          - Passed to another call:  assert(scanf(...) == 1)
        """
        # The call site is the '(' node in cppcheck's AST.
        # Its astParent reveals the usage context.
        open_paren = _tok_next(call_tok)
        if open_paren is None or _tok_str(open_paren) != "(":
            return False

        parent = getattr(open_paren, "astParent", None)
        if parent is None:
            # Also check the name-token's parent
            parent = getattr(call_tok, "astParent", None)

        if parent is None:
            return False  # bare call statement

        ps = _tok_str(parent)

        # Assignment: n = scanf(...)
        if getattr(parent, "isAssignmentOp", False):
            return True

        # Comparison: scanf(...) == 1, scanf(...) != EOF
        if ps in {"==", "!=", "<", ">", "<=", ">="}:
            return True

        # if/while condition contains the call
        if ps in {"if", "while", "for"}:
            return True

        # Explicit (void) cast — the programmer intentionally discards
        if ps == "(":
            # Check if the parent's parent is a void cast
            grandparent = getattr(parent, "astParent", None)
            if grandparent and _tok_str(grandparent) == "(void)":
                return True

        # Used as argument to another function (e.g., assert)
        if ps == ",":
            return True

        return False


# ═══════════════════════════════════════════════════════════════════════════
#  PART 9 — ADDON ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════

_ALL_CHECKERS: List[type] = [
    _VSC01_NonLiteralFormat,
    _VSC02_FormatArgCountLow,
    _VSC03_FormatArgCountHigh,
    _VSC04_FormatTypeMismatch,
    _VSC05_VaStartWrongParam,
    _VSC06_VaArgBeforeStart,
    _VSC07_VaArgAfterEnd,
    _VSC08_VaListDoubleFree,
    _VSC09_TaintedFormatString,
    _VSC10_UncheckedScanfReturn,
]


def _run_on_dump(dump_file: str) -> int:
    data  = cppcheckdata.parsedump(dump_file)
    total = 0

    for cfg in data.configurations:
        for checker_cls in _ALL_CHECKERS:
            checker = checker_cls()
            try:
                checker.check(cfg)
            except Exception as exc:
                sys.stderr.write(
                    f"[VSC] {checker_cls.__name__} raised "
                    f"{type(exc).__name__}: {exc}\n"
                )
                continue
            for finding in checker.findings:
                finding.emit()
                total += 1

    return 1 if total > 0 else 0


def main() -> None:
    if len(sys.argv) < 2:
        sys.stderr.write(
            "Usage: python VarargsSafetyChecker.py <file.c.dump>\n"
        )
        sys.exit(1)
    dump_file = sys.argv[1]
    if not os.path.isfile(dump_file):
        sys.stderr.write(f"ERROR: dump file not found: {dump_file}\n")
        sys.exit(1)
    sys.exit(_run_on_dump(dump_file))


if __name__ == "__main__":
    main()
