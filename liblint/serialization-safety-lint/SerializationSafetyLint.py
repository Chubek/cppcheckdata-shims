#!/usr/bin/env python3
"""
SerializationSafetyLint.py
══════════════════════════════════════════════════════════════════════════
Cppcheck addon: detects unsafe serialization/deserialization patterns in
C/C++ code, covering tainted wire data flowing into dangerous operations.

Output format (plain text, cppcheck-addon compatible):
    [filename:line]: (severity) message [errorId]

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CHECKER INVENTORY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  SSL-01  UntrustedDeserializeChecker   CWE-502  error
  SSL-02  TaintedFormatStringChecker    CWE-134  error
  SSL-03  TaintedMemopSizeChecker       CWE-119  warning
  SSL-04  MissingLengthValidation       CWE-20   warning
  SSL-05  WireLengthOverflowChecker     CWE-190  warning
  SSL-06  FixedBufferNetworkRead        CWE-787  error
  SSL-07  TaintedHeapAlloc              CWE-122  warning

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CONTRACT — READ BEFORE MODIFYING
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
1.  NEVER call int(tok.varId) directly. Always use _safe_vid(raw)
    or _safe_vid_tok(tok).  varId values from .dump files may be
    hex addresses, "0", or None — all of which int() will crash on.

2.  NEVER assume tok.astOperand1 / astOperand2 / astParent are
    populated. Always use getattr(tok, "astOperandN", None) and
    guard with `if x is not None`.

3.  All checker classes must inherit _BaseChecker and implement
    check(cfg) -> List[_Finding].

4.  Text output is the sole output format. Do not add JSON paths.

5.  Taint sources are defined in _WIRE_SOURCES. Add new sources
    there — do not scatter them across checker logic.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Usage:
    cppcheck --dump target.c
    python SerializationSafetyLint.py target.c.dump
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

import cppcheckdata

# ══════════════════════════════════════════════════════════════════════════
#  §1  CONSTANTS — WIRE / NETWORK TAINT SOURCES
# ══════════════════════════════════════════════════════════════════════════

# Functions whose RETURN VALUE is considered wire-tainted.
_WIRE_SOURCES_RETURN: FrozenSet[str] = frozenset({
    # POSIX network / socket
    "recv", "recvfrom", "recvmsg",
    # POSIX file I/O (used for pipe / socket fd)
    "read", "fread",
    # Standard input
    "fgets", "gets", "getchar", "scanf", "fscanf",
    # Environment (can be attacker-controlled in some models)
    "getenv",
    # String-to-int conversions applied to wire data
    "atoi", "atol", "atoll", "strtol", "strtoul", "strtoll", "strtoull",
    # Explicit deserialize / unmarshal patterns
    "ntohl", "ntohs", "ntohll",
    "be32toh", "be16toh", "be64toh",
    "le32toh", "le16toh", "le64toh",
})

# Functions that write tainted data INTO a buffer argument.
# Tuple: (function_name, zero-based output_arg_index)
_WIRE_SOURCES_OUTPARAM: Tuple[Tuple[str, int], ...] = (
    ("recv",      1),
    ("recvfrom",  1),
    ("read",      1),
    ("fread",     0),
    ("fgets",     0),
    ("gets",      0),
    ("scanf",     -1),   # -1 = all pointer args
    ("fscanf",    -1),
)

# Functions that perform unsafe deserialization / object instantiation.
_UNSAFE_DESERIALIZE: FrozenSet[str] = frozenset({
    "pickle_loads",       # Python C-ext pattern
    "yaml_load",
    "json_decode",        # some C libs
    "msgpack_unpack",
    "thrift_deserialize",
    "protobuf_parse",
    "avro_value_read",
    "cbor_decode",
    "ber_decode",
    "asn1_decode",
    "xmlParseDoc",        # libxml2
    "xmlReadMemory",
    "xmlParseMemory",
    "curl_easy_perform",  # not deserialize but triggers SSL-01 if fed wire buf
})

# Format-string functions — first arg is format.
_FORMAT_FUNCS_ARG0: FrozenSet[str] = frozenset({
    "printf", "fprintf", "sprintf", "snprintf",
    "vprintf", "vfprintf", "vsprintf", "vsnprintf",
    "wprintf", "fwprintf", "swprintf",
    "syslog",
})

# memop functions and which arg is the size.
# (function, size_arg_index)
_MEMOP_SIZE_ARG: Tuple[Tuple[str, int], ...] = (
    ("memcpy",  2),
    ("memmove", 2),
    ("memset",  2),
    ("bcopy",   2),
    ("strncpy", 2),
    ("strncat", 2),
    ("stpncpy", 2),
    ("memcmp",  2),
)

# Heap allocation functions — size is first argument.
_HEAP_ALLOC: FrozenSet[str] = frozenset({
    "malloc", "calloc", "realloc",
    "g_malloc", "g_malloc0",
    "kmalloc", "vmalloc",
    "operator new",
})

# Network read functions that write directly into a buffer
# with an explicit size: (func, buf_arg, size_arg)
_NETWORK_READ_INTO_BUF: Tuple[Tuple[str, int, int], ...] = (
    ("recv",     1, 2),
    ("recvfrom", 1, 2),
    ("read",     1, 2),
    ("fread",    0, 2),
)

# Validated / sanitized calls — if a varId passes through one of these
# before use, we consider it sanitized.
_SANITIZERS: FrozenSet[str] = frozenset({
    # Length/range checks
    "assert",
    # Explicit validators in common frameworks
    "validate_length",
    "check_size",
    "sanitize",
    "bounds_check",
})


# ══════════════════════════════════════════════════════════════════════════
#  §2  SAFE varId HELPER  (see CONTRACT §1)
# ══════════════════════════════════════════════════════════════════════════

def _safe_vid(raw: Any) -> Optional[int]:
    """
    Convert a raw varId value to a positive int, or return None.

    Handles:
      - None              → None
      - 0 / "0"           → None   (cppcheck sentinel for "no variable")
      - hex address str   → None   (e.g. "560e31248150")
      - valid decimal str → int
      - already an int    → int (if > 0)
    """
    if raw is None:
        return None
    try:
        v = int(raw)
        return v if v > 0 else None
    except (ValueError, TypeError):
        return None


def _safe_vid_tok(tok: Any) -> Optional[int]:
    """Return the safe varId for a token, or None."""
    return _safe_vid(getattr(tok, "varId", None))


# ══════════════════════════════════════════════════════════════════════════
#  §3  TOKEN TRAVERSAL HELPERS
# ══════════════════════════════════════════════════════════════════════════

def _tok_str(tok: Any) -> str:
    return getattr(tok, "str", "") or ""

def _tok_file(tok: Any) -> str:
    return getattr(tok, "file", "") or ""

def _tok_line(tok: Any) -> int:
    return int(getattr(tok, "linenr", 0) or 0)

def _tok_op1(tok: Any) -> Any:
    return getattr(tok, "astOperand1", None)

def _tok_op2(tok: Any) -> Any:
    return getattr(tok, "astOperand2", None)

def _tok_parent(tok: Any) -> Any:
    return getattr(tok, "astParent", None)

def _iter_tokens(cfg: Any):
    """Yield every token in the configuration."""
    yield from getattr(cfg, "tokenlist", [])

def _iter_scopes(cfg: Any):
    yield from getattr(cfg, "scopes", [])

def _iter_variables(cfg: Any):
    yield from getattr(cfg, "variables", [])


def _called_name(tok: Any) -> Optional[str]:
    """
    If `tok` is the '(' of a function call, return the callee name.
    Returns None if this is a cast or non-call paren.
    """
    if _tok_str(tok) != "(":
        return None
    if getattr(tok, "isCast", False):
        return None
    op1 = _tok_op1(tok)
    if op1 is None:
        return None
    s = _tok_str(op1)
    # Member calls: obj->method, obj.method — take right side
    if s in {"->", "."}:
        right = _tok_op2(op1)
        if right is not None:
            return _tok_str(right)
        return None
    return s if s else None


def _get_call_args(call_paren: Any) -> List[Any]:
    """
    Return a list of AST tokens representing arguments to a call.
    `call_paren` is the '(' token of the call.

    Arguments are chained via ',' nodes in the AST under astOperand2.
    """
    op2 = _tok_op2(call_paren)
    if op2 is None:
        return []
    args: List[Any] = []
    _flatten_comma(op2, args)
    return args


def _flatten_comma(tok: Any, out: List[Any]) -> None:
    """Recursively flatten comma-separated argument AST nodes."""
    if tok is None:
        return
    if _tok_str(tok) == ",":
        _flatten_comma(_tok_op1(tok), out)
        _flatten_comma(_tok_op2(tok), out)
    else:
        out.append(tok)


def _is_in_loop(tok: Any) -> bool:
    """Return True if tok lives inside any loop scope."""
    scope = getattr(tok, "scope", None)
    while scope is not None:
        if getattr(scope, "type", "") in {"While", "For", "Do"}:
            return True
        scope = getattr(scope, "nestedIn", None)
    return False


def _scope_fn_name(tok: Any) -> Optional[str]:
    """Return the function name that contains tok, or None."""
    scope = getattr(tok, "scope", None)
    while scope is not None:
        if getattr(scope, "type", "") == "Function":
            return getattr(scope, "className", None)
        scope = getattr(scope, "nestedIn", None)
    return None


# ══════════════════════════════════════════════════════════════════════════
#  §4  TAINT COLLECTION
# ══════════════════════════════════════════════════════════════════════════

def _collect_wire_tainted_vids(cfg: Any) -> Set[int]:
    """
    Single-pass taint collection.

    Marks a varId as wire-tainted when:
      (a) It is the LHS of `var = wire_source_call(…)`
      (b) It is an output-parameter argument to a wire-source function
      (c) It is assigned from another already-tainted varId

    Returns a set of positive integer varIds.
    """
    tainted: Set[int] = set()

    # ── Pass 1: direct sources ────────────────────────────────────────
    for tok in _iter_tokens(cfg):
        if _tok_str(tok) != "(":
            continue
        name = _called_name(tok)
        if name is None:
            continue

        # (a) Return-value sources: var = source_fn(...)
        if name in _WIRE_SOURCES_RETURN:
            parent = _tok_parent(tok)
            if parent is not None and getattr(parent, "isAssignmentOp", False):
                lhs = _tok_op1(parent)
                vid = _safe_vid_tok(lhs)
                if vid is not None:
                    tainted.add(vid)
            # Also handle: if the call is the RHS of an assign one level up
            gp = _tok_parent(parent) if parent is not None else None
            if gp is not None and getattr(gp, "isAssignmentOp", False):
                lhs = _tok_op1(gp)
                vid = _safe_vid_tok(lhs)
                if vid is not None:
                    tainted.add(vid)

        # (b) Output-parameter sources
        for (src_name, out_idx) in _WIRE_SOURCES_OUTPARAM:
            if name != src_name:
                continue
            args = _get_call_args(tok)
            if out_idx == -1:
                # All pointer args become tainted
                for arg in args:
                    vid = _safe_vid_tok(arg)
                    if vid is not None:
                        tainted.add(vid)
            elif 0 <= out_idx < len(args):
                arg = args[out_idx]
                # Buffer passed as &buf or as buf
                inner = _tok_op1(arg) if _tok_str(arg) == "&" else arg
                vid = _safe_vid_tok(inner)
                if vid is not None:
                    tainted.add(vid)

    # ── Pass 2: one-hop propagation (var = tainted_var) ──────────────
    changed = True
    while changed:
        changed = False
        for tok in _iter_tokens(cfg):
            if not getattr(tok, "isAssignmentOp", False):
                continue
            if _tok_str(tok) != "=":
                continue
            lhs = _tok_op1(tok)
            rhs = _tok_op2(tok)
            lhs_vid = _safe_vid_tok(lhs)
            rhs_vid = _safe_vid_tok(rhs)
            if lhs_vid is None or rhs_vid is None:
                continue
            if rhs_vid in tainted and lhs_vid not in tainted:
                tainted.add(lhs_vid)
                changed = True

    return tainted


def _collect_sanitized_vids(cfg: Any, tainted: Set[int]) -> Set[int]:
    """
    Return the subset of tainted varIds that have passed through a
    known sanitizer before their use site.

    This is a conservative approximation: if ANY call to a sanitizer
    with that varId appears in the token list, we mark it sanitized.
    A full path-sensitive analysis is out of scope for an addon.
    """
    sanitized: Set[int] = set()
    for tok in _iter_tokens(cfg):
        if _tok_str(tok) != "(":
            continue
        name = _called_name(tok)
        if name not in _SANITIZERS:
            continue
        for arg in _get_call_args(tok):
            vid = _safe_vid_tok(arg)
            if vid is not None and vid in tainted:
                sanitized.add(vid)
    return sanitized


# ══════════════════════════════════════════════════════════════════════════
#  §5  FINDING MODEL
# ══════════════════════════════════════════════════════════════════════════

@dataclass
class _Finding:
    """One diagnostic finding."""
    filename: str
    line: int
    severity: str           # "error" | "warning" | "style" | "performance"
    message: str
    error_id: str
    # Optional secondary location (e.g., where taint was introduced)
    secondary_file: str = ""
    secondary_line: int = 0

    def format(self) -> str:
        """
        Emit the plain-text format cppcheck addons use:
            [file:line]: (severity) message [errorId]

        If a secondary location is attached, append it on the same line
        as context:
            [file:line]: (severity) message [errorId] -> [sec_file:sec_line]
        """
        base = (
            f"[{self.filename}:{self.line}]: "
            f"({self.severity}) "
            f"{self.message} "
            f"[{self.error_id}]"
        )
        if self.secondary_file and self.secondary_line:
            base += f" -> [{self.secondary_file}:{self.secondary_line}]"
        return base


# ══════════════════════════════════════════════════════════════════════════
#  §6  BASE CHECKER
# ══════════════════════════════════════════════════════════════════════════

class _BaseChecker:
    """
    Minimal base for all SSL checkers.

    Subclasses implement:
        check(cfg, tainted, sanitized) -> List[_Finding]
    """

    name: str = "base"

    def check(
        self,
        cfg: Any,
        tainted: Set[int],
        sanitized: Set[int],
    ) -> List[_Finding]:
        raise NotImplementedError

    @staticmethod
    def _finding(
        tok: Any,
        severity: str,
        message: str,
        error_id: str,
        sec_tok: Any = None,
    ) -> _Finding:
        sec_f = _tok_file(sec_tok) if sec_tok is not None else ""
        sec_l = _tok_line(sec_tok) if sec_tok is not None else 0
        return _Finding(
            filename=_tok_file(tok),
            line=_tok_line(tok),
            severity=severity,
            message=message,
            error_id=error_id,
            secondary_file=sec_f,
            secondary_line=sec_l,
        )


# ══════════════════════════════════════════════════════════════════════════
#  §7  CHECKER IMPLEMENTATIONS
# ══════════════════════════════════════════════════════════════════════════

# ──────────────────────────────────────────────────────────────────────────
#  SSL-01  UntrustedDeserializeChecker  (CWE-502)
# ──────────────────────────────────────────────────────────────────────────

class UntrustedDeserializeChecker(_BaseChecker):
    """
    Flags calls to known deserialization functions when any argument
    carries a wire-tainted varId or is a tainted buffer.

    CWE-502: Deserialization of Untrusted Data.
    """

    name = "SSL-01"

    def check(
        self,
        cfg: Any,
        tainted: Set[int],
        sanitized: Set[int],
    ) -> List[_Finding]:
        findings: List[_Finding] = []
        seen: Set[Tuple[str, int]] = set()

        for tok in _iter_tokens(cfg):
            if _tok_str(tok) != "(":
                continue
            name = _called_name(tok)
            if name not in _UNSAFE_DESERIALIZE:
                continue

            args = _get_call_args(tok)
            for arg in args:
                vid = _safe_vid_tok(arg)
                if vid is None:
                    continue
                if vid not in tainted or vid in sanitized:
                    continue
                key = (_tok_file(tok), _tok_line(tok))
                if key in seen:
                    break
                seen.add(key)
                findings.append(self._finding(
                    tok,
                    "error",
                    f"Deserialization of wire-tainted data passed to "
                    f"'{name}()' without validation (CWE-502)",
                    "untrustedDeserialize",
                ))
                break  # one finding per call site

        return findings


# ──────────────────────────────────────────────────────────────────────────
#  SSL-02  TaintedFormatStringChecker  (CWE-134)
# ──────────────────────────────────────────────────────────────────────────

class TaintedFormatStringChecker(_BaseChecker):
    """
    Flags calls to printf-family functions when the format-string
    argument (arg 0) is wire-tainted.

    CWE-134: Use of Externally-Controlled Format String.
    """

    name = "SSL-02"

    def check(
        self,
        cfg: Any,
        tainted: Set[int],
        sanitized: Set[int],
    ) -> List[_Finding]:
        findings: List[_Finding] = []
        seen: Set[Tuple[str, int]] = set()

        for tok in _iter_tokens(cfg):
            if _tok_str(tok) != "(":
                continue
            name = _called_name(tok)
            if name not in _FORMAT_FUNCS_ARG0:
                continue

            args = _get_call_args(tok)
            # fprintf / fscanf: format is arg index 1
            fmt_idx = 1 if name in {"fprintf", "fscanf", "fwprintf"} else 0
            if fmt_idx >= len(args):
                continue

            fmt_arg = args[fmt_idx]
            vid = _safe_vid_tok(fmt_arg)
            if vid is None:
                continue
            if vid not in tainted or vid in sanitized:
                continue

            key = (_tok_file(tok), _tok_line(tok))
            if key in seen:
                continue
            seen.add(key)

            findings.append(self._finding(
                tok,
                "error",
                f"Format string argument to '{name}()' is wire-tainted "
                f"(CWE-134). Use a literal format string.",
                "taintedFormatString",
            ))

        return findings


# ──────────────────────────────────────────────────────────────────────────
#  SSL-03  TaintedMemopSizeChecker  (CWE-119)
# ──────────────────────────────────────────────────────────────────────────

class TaintedMemopSizeChecker(_BaseChecker):
    """
    Flags memcpy/memset/strncpy etc. when the size argument is
    wire-tainted and has not been sanitized.

    CWE-119: Improper Restriction of Operations within Buffer Bounds.
    """

    name = "SSL-03"

    def check(
        self,
        cfg: Any,
        tainted: Set[int],
        sanitized: Set[int],
    ) -> List[_Finding]:
        findings: List[_Finding] = []
        seen: Set[Tuple[str, int]] = set()

        for tok in _iter_tokens(cfg):
            if _tok_str(tok) != "(":
                continue
            name = _called_name(tok)
            if name is None:
                continue

            size_idx: Optional[int] = None
            for (fn, si) in _MEMOP_SIZE_ARG:
                if fn == name:
                    size_idx = si
                    break
            if size_idx is None:
                continue

            args = _get_call_args(tok)
            if size_idx >= len(args):
                continue

            size_arg = args[size_idx]
            vid = _safe_vid_tok(size_arg)
            if vid is None:
                continue
            if vid not in tainted or vid in sanitized:
                continue

            key = (_tok_file(tok), _tok_line(tok))
            if key in seen:
                continue
            seen.add(key)

            findings.append(self._finding(
                tok,
                "warning",
                f"Size argument (arg {size_idx}) to '{name}()' is "
                f"wire-tainted without bounds validation (CWE-119)",
                "taintedMemopSize",
            ))

        return findings


# ──────────────────────────────────────────────────────────────────────────
#  SSL-04  MissingLengthValidationChecker  (CWE-20)
# ──────────────────────────────────────────────────────────────────────────

class MissingLengthValidationChecker(_BaseChecker):
    """
    Flags deserialization loops (for/while) that iterate over a length
    field derived from wire data with no visible upper-bound guard.

    Pattern:
        n = recv(...)  / ntohl(...)
        for (i = 0; i < n; i++) { ... }    ← n is tainted, no guard before loop

    CWE-20: Improper Input Validation.
    """

    name = "SSL-04"

    # Loop-header comparison operators.
    _COMPARE_OPS: FrozenSet[str] = frozenset({"<", "<=", ">", ">="})

    def check(
        self,
        cfg: Any,
        tainted: Set[int],
        sanitized: Set[int],
    ) -> List[_Finding]:
        findings: List[_Finding] = []

        for scope in _iter_scopes(cfg):
            if getattr(scope, "type", "") not in {"For", "While"}:
                continue

            body_start = getattr(scope, "bodyStart", None)
            if body_start is None:
                continue

            # Find comparison token in the loop condition.
            # For a "for" scope, condition is between the 1st and 2nd ';'
            # For "while", condition is between '(' and ')'.
            # Simplification: scan back from bodyStart for a comparison op
            # that uses a tainted variable.
            cond_tok = self._find_loop_condition_tok(body_start)
            if cond_tok is None:
                continue

            # Walk the comparison subtree for tainted varIds.
            tainted_bound_vid = self._find_tainted_bound(
                cond_tok, tainted, sanitized
            )
            if tainted_bound_vid is None:
                continue

            # Check: is there a guard (if / assert) before the loop
            # within the same function that bounds this varId?
            if self._has_prior_guard(body_start, tainted_bound_vid):
                continue

            findings.append(_Finding(
                filename=_tok_file(body_start),
                line=_tok_line(body_start),
                severity="warning",
                message=(
                    f"Loop bound uses wire-tainted length (varId "
                    f"{tainted_bound_vid}) without prior upper-bound "
                    f"validation (CWE-20)"
                ),
                error_id="missingLengthValidation",
            ))

        return findings

    # ── helpers ──────────────────────────────────────────────────────

    def _find_loop_condition_tok(self, body_start: Any) -> Any:
        """Scan back up to 30 tokens from bodyStart for a comparison."""
        tok = getattr(body_start, "previous", None)
        steps = 0
        while tok is not None and steps < 30:
            if _tok_str(tok) in self._COMPARE_OPS:
                return tok
            tok = getattr(tok, "previous", None)
            steps += 1
        return None

    def _find_tainted_bound(
        self,
        cmp_tok: Any,
        tainted: Set[int],
        sanitized: Set[int],
    ) -> Optional[int]:
        """
        Walk the comparison operator's operands for a tainted varId.
        Returns the first tainted (unsanitized) varId found, or None.
        """
        for op in (_tok_op1(cmp_tok), _tok_op2(cmp_tok)):
            if op is None:
                continue
            vid = _safe_vid_tok(op)
            if vid is not None and vid in tainted and vid not in sanitized:
                return vid
        return None

    def _has_prior_guard(self, body_start: Any, vid: int) -> bool:
        """
        Scan backwards from body_start (up to 60 tokens) for an `if`
        or `assert` call that references the same varId.
        This is a heuristic — not path-sensitive.
        """
        tok = getattr(body_start, "previous", None)
        steps = 0
        while tok is not None and steps < 60:
            s = _tok_str(tok)
            if s in {"if", "assert"}:
                # Check nearby tokens for the same varId
                t2 = tok
                for _ in range(15):
                    t2 = getattr(t2, "next", None)
                    if t2 is None:
                        break
                    if _safe_vid_tok(t2) == vid:
                        return True
            tok = getattr(tok, "previous", None)
            steps += 1
        return False


# ──────────────────────────────────────────────────────────────────────────
#  SSL-05  WireLengthOverflowChecker  (CWE-190)
# ──────────────────────────────────────────────────────────────────────────

class WireLengthOverflowChecker(_BaseChecker):
    """
    Flags wire-tainted integers used in arithmetic expressions that
    feed into allocation or memop sizes without an overflow guard.

    Pattern:
        n = ntohl(buf)          // tainted
        size = n * sizeof(T)    // potential integer overflow
        malloc(size)            // overflow → undersized allocation

    CWE-190: Integer Overflow or Wraparound.
    """

    name = "SSL-05"

    _OVERFLOW_OPS: FrozenSet[str] = frozenset({"*", "+", "<<", "*=", "+="})

    def check(
        self,
        cfg: Any,
        tainted: Set[int],
        sanitized: Set[int],
    ) -> List[_Finding]:
        findings: List[_Finding] = []
        seen: Set[Tuple[str, int]] = set()

        for tok in _iter_tokens(cfg):
            if _tok_str(tok) not in self._OVERFLOW_OPS:
                continue

            op1 = _tok_op1(tok)
            op2 = _tok_op2(tok)

            tainted_operand_vid: Optional[int] = None
            for op in (op1, op2):
                if op is None:
                    continue
                vid = _safe_vid_tok(op)
                if vid is not None and vid in tainted and vid not in sanitized:
                    tainted_operand_vid = vid
                    break

            if tainted_operand_vid is None:
                continue

            # Only flag if this expression eventually feeds an alloc / memop.
            if not self._feeds_alloc_or_memop(tok):
                continue

            key = (_tok_file(tok), _tok_line(tok))
            if key in seen:
                continue
            seen.add(key)

            findings.append(self._finding(
                tok,
                "warning",
                f"Wire-tainted integer (varId {tainted_operand_vid}) used in "
                f"'{_tok_str(tok)}' without overflow check before "
                f"allocation/copy (CWE-190)",
                "wireLengthOverflow",
            ))

        return findings

    def _feeds_alloc_or_memop(self, arith_tok: Any) -> bool:
        """
        Walk upward in the AST up to 4 levels to see if this arithmetic
        result is used as a size argument to an alloc or memop.
        """
        tok = _tok_parent(arith_tok)
        depth = 0
        while tok is not None and depth < 4:
            s = _tok_str(tok)
            if s == "(":
                name = _called_name(tok)
                if name in _HEAP_ALLOC:
                    return True
                for (fn, _si) in _MEMOP_SIZE_ARG:
                    if fn == name:
                        return True
            tok = _tok_parent(tok)
            depth += 1
        return False


# ──────────────────────────────────────────────────────────────────────────
#  SSL-06  FixedBufferNetworkReadChecker  (CWE-787)
# ──────────────────────────────────────────────────────────────────────────

class FixedBufferNetworkReadChecker(_BaseChecker):
    """
    Flags calls to recv/read/fread where the caller-supplied size
    argument is larger than the receiving buffer's declared dimension,
    or where the size is wire-tainted.

    CWE-787: Out-of-bounds Write.
    """

    name = "SSL-06"

    def check(
        self,
        cfg: Any,
        tainted: Set[int],
        sanitized: Set[int],
    ) -> List[_Finding]:
        findings: List[_Finding] = []

        # Build varId → declared array dimension map
        dim_map: Dict[int, int] = {}
        for var in _iter_variables(cfg):
            raw_id = getattr(var, "Id", None)
            vid = _safe_vid(raw_id)
            if vid is None:
                continue
            dims = getattr(var, "dimensions", None)
            if not dims:
                continue
            for dim in dims:
                sz = getattr(dim, "size", None)
                if sz is not None:
                    try:
                        dim_map[vid] = int(sz)
                    except (ValueError, TypeError):
                        pass
                    break

        seen: Set[Tuple[str, int]] = set()

        for tok in _iter_tokens(cfg):
            if _tok_str(tok) != "(":
                continue
            name = _called_name(tok)
            if name is None:
                continue

            entry: Optional[Tuple[str, int, int]] = None
            for (fn, buf_idx, sz_idx) in _NETWORK_READ_INTO_BUF:
                if fn == name:
                    entry = (fn, buf_idx, sz_idx)
                    break
            if entry is None:
                continue

            _fn, buf_idx, sz_idx = entry
            args = _get_call_args(tok)
            if len(args) <= max(buf_idx, sz_idx):
                continue

            buf_arg  = args[buf_idx]
            size_arg = args[sz_idx]

            buf_vid  = _safe_vid_tok(buf_arg)
            size_vid = _safe_vid_tok(size_arg)

            key = (_tok_file(tok), _tok_line(tok))
            if key in seen:
                continue

            # Case A: size argument is wire-tainted
            if (size_vid is not None
                    and size_vid in tainted
                    and size_vid not in sanitized):
                seen.add(key)
                findings.append(self._finding(
                    tok,
                    "error",
                    f"Network read '{name}()': size argument is "
                    f"wire-tainted — attacker controls read length (CWE-787)",
                    "fixedBufferNetworkRead",
                ))
                continue

            # Case B: declared buffer size < size argument (ValueFlow)
            if buf_vid is not None and buf_vid in dim_map:
                declared = dim_map[buf_vid]
                for v in getattr(size_arg, "values", None) or []:
                    iv = getattr(v, "intvalue", None)
                    if iv is None:
                        continue
                    try:
                        req = int(iv)
                    except (ValueError, TypeError):
                        continue
                    if req > declared:
                        seen.add(key)
                        findings.append(self._finding(
                            tok,
                            "error",
                            f"Network read '{name}()': requested size {req} "
                            f"exceeds declared buffer size {declared} (CWE-787)",
                            "fixedBufferNetworkRead",
                        ))
                        break

        return findings


# ──────────────────────────────────────────────────────────────────────────
#  SSL-07  TaintedHeapAllocChecker  (CWE-122)
# ──────────────────────────────────────────────────────────────────────────

class TaintedHeapAllocChecker(_BaseChecker):
    """
    Flags malloc/calloc/realloc calls where the size is directly
    or indirectly derived from wire-tainted data without validation.

    CWE-122: Heap-based Buffer Overflow (undersized allocation vector).
    """

    name = "SSL-07"

    def check(
        self,
        cfg: Any,
        tainted: Set[int],
        sanitized: Set[int],
    ) -> List[_Finding]:
        findings: List[_Finding] = []
        seen: Set[Tuple[str, int]] = set()

        for tok in _iter_tokens(cfg):
            if _tok_str(tok) != "(":
                continue
            name = _called_name(tok)
            if name not in _HEAP_ALLOC:
                continue

            args = _get_call_args(tok)
            if not args:
                continue

            # malloc(n): size is arg 0
            # calloc(n, sz): both args matter
            # realloc(ptr, n): size is arg 1
            size_indices = [0]
            if name == "realloc" and len(args) >= 2:
                size_indices = [1]
            elif name == "calloc" and len(args) >= 2:
                size_indices = [0, 1]

            for si in size_indices:
                if si >= len(args):
                    continue
                arg = args[si]
                vid = _safe_vid_tok(arg)
                if vid is None:
                    continue
                if vid not in tainted or vid in sanitized:
                    continue

                key = (_tok_file(tok), _tok_line(tok))
                if key in seen:
                    break
                seen.add(key)

                findings.append(self._finding(
                    tok,
                    "warning",
                    f"Heap allocation '{name}()': size argument "
                    f"(arg {si}) is wire-tainted without validation "
                    f"(CWE-122)",
                    "taintedHeapAlloc",
                ))
                break

        return findings


# ══════════════════════════════════════════════════════════════════════════
#  §8  RUNNER
# ══════════════════════════════════════════════════════════════════════════

_ALL_CHECKERS: List[_BaseChecker] = [
    UntrustedDeserializeChecker(),
    TaintedFormatStringChecker(),
    TaintedMemopSizeChecker(),
    MissingLengthValidationChecker(),
    WireLengthOverflowChecker(),
    FixedBufferNetworkReadChecker(),
    TaintedHeapAllocChecker(),
]


def _run_on_dump(dump_path: str) -> None:
    """Load a .dump file and run all checkers against every configuration."""
    try:
        data = cppcheckdata.CppcheckData(dump_path)
    except Exception as exc:
        sys.stderr.write(
            f"SerializationSafetyLint: failed to load '{dump_path}': {exc}\n"
        )
        sys.exit(1)

    for cfg in data.configurations:
        tainted   = _collect_wire_tainted_vids(cfg)
        sanitized = _collect_sanitized_vids(cfg, tainted)

        all_findings: List[_Finding] = []
        for checker in _ALL_CHECKERS:
            try:
                found = checker.check(cfg, tainted, sanitized)
                all_findings.extend(found)
            except Exception as exc:
                sys.stderr.write(
                    f"SerializationSafetyLint: checker {checker.name} "
                    f"failed on '{dump_path}': {exc}\n"
                )

        # Sort by filename then line for deterministic output.
        all_findings.sort(key=lambda f: (f.filename, f.line))

        for finding in all_findings:
            print(finding.format())


def main() -> None:
    if len(sys.argv) < 2:
        sys.stderr.write(
            "Usage: python SerializationSafetyLint.py <file.c.dump> "
            "[file2.c.dump ...]\n"
        )
        sys.exit(1)

    for dump_path in sys.argv[1:]:
        _run_on_dump(dump_path)


if __name__ == "__main__":
    main()
