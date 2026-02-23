#!/usr/bin/env python3
"""
BufferOverflowScan.py
═════════════════════
Cppcheck addon — Buffer Overflow & Out-of-Bounds Scanner.

Detects:
  BOS-01  Stack buffer overflow via constant index       (CWE-121)
  BOS-02  Heap buffer overflow via known allocation      (CWE-122)
  BOS-03  Off-by-one error on array bounds               (CWE-193)
  BOS-04  Unsafe string/memory functions (strcpy et al.) (CWE-120)
  BOS-05  Tainted / unchecked size passed to alloc       (CWE-789)
  BOS-06  Buffer underflow (negative index)              (CWE-124)

Output format (text, never JSON):
  [filename:line]: (severity) message [errorId]

Usage:
  cppcheck --dump target.c
  python BufferOverflowScan.py target.c.dump

Requires:
  - cppcheck >= 2.10  (for .dump files)
  - cppcheckdata       (bundled with cppcheck)
  - cppcheckdata_shims (the shims library)

License: MIT
"""

from __future__ import annotations

import sys
import os
import re
from abc import abstractmethod
from collections import defaultdict
from dataclasses import dataclass, field
from typing import (
    Any,
    ClassVar,
    Dict,
    FrozenSet,
    Iterator,
    List,
    Optional,
    Set,
    Tuple,
)

# ─────────────────────────────────────────────────────────────────────────────
#  Shims imports — with graceful fallback so the addon at least loads
# ─────────────────────────────────────────────────────────────────────────────
try:
    from cppcheckdata_shims.checkers import (
        Checker,
        CheckerContext,
        CheckerRegistry,
        SuppressionManager,
        DiagnosticSeverity,
        Confidence,
        SourceLocation,
        Diagnostic,
        _iter_tokens,
        _iter_variables,
        _iter_scopes,
        _tok_str,
        _tok_file,
        _tok_line,
        _tok_col,
        _tok_loc,
        _get_valueflow_values,
        _has_known_int_value,
        _has_possible_int_value,
        _valueflow_int_range,
        _var_name,
    )
    _SHIMS_OK = True
except ImportError as _e:
    print(f"[BufferOverflowScan] WARNING: cppcheckdata_shims not found: {_e}",
          file=sys.stderr)
    _SHIMS_OK = False
    sys.exit(1)

try:
    import cppcheckdata
except ImportError:
    print("[BufferOverflowScan] ERROR: cppcheckdata module not found. "
          "Make sure cppcheck is installed.", file=sys.stderr)
    sys.exit(1)


# ═════════════════════════════════════════════════════════════════════════════
#  PART 1 — TEXT REPORTER
#  Replaces JSON output with the requested plain-text format:
#    [filename:line]: (severity) message [errorId]
# ═════════════════════════════════════════════════════════════════════════════

class TextReporter:
    """
    Emits diagnostics to stdout in the format:

        [filename:line]: (severity) message [errorId]

    Optionally includes the column number when non-zero:

        [filename:line:col]: (severity) message [errorId]

    Diagnostics are de-duplicated by (file, line, errorId) so that
    multiple checkers seeing the same site do not double-report.
    """

    def __init__(self, *, show_column: bool = True) -> None:
        self._show_column = show_column
        self._seen: Set[Tuple[str, int, str]] = set()
        self._count: int = 0

    # ── Public interface ──────────────────────────────────────────────────

    def emit(self, diag: Diagnostic) -> None:
        """Format and print one diagnostic; silently drop duplicates."""
        loc = diag.location
        dedup_key = (loc.file, loc.line, diag.error_id)
        if dedup_key in self._seen:
            return
        self._seen.add(dedup_key)

        location_str = self._format_location(loc)
        severity_str = diag.severity.value          # e.g. "error", "warning"
        print(
            f"{location_str}: ({severity_str}) {diag.message} [{diag.error_id}]"
        )
        self._count += 1

    def emit_all(self, diagnostics: List[Diagnostic]) -> None:
        """Emit a list of diagnostics in order."""
        for d in diagnostics:
            self.emit(d)

    def print_summary(self) -> None:
        """Print a human-readable summary line to stderr."""
        noun = "diagnostic" if self._count == 1 else "diagnostics"
        print(f"\nBufferOverflowScan: {self._count} {noun} emitted.",
              file=sys.stderr)

    # ── Helpers ───────────────────────────────────────────────────────────

    def _format_location(self, loc: SourceLocation) -> str:
        if self._show_column and loc.column:
            return f"[{loc.file}:{loc.line}:{loc.column}]"
        return f"[{loc.file}:{loc.line}]"


# ═════════════════════════════════════════════════════════════════════════════
#  PART 2 — SHARED CONSTANTS / PATTERN LIBRARIES
# ═════════════════════════════════════════════════════════════════════════════

# Functions that copy/write without a size argument and are therefore
# inherently unsafe when the destination buffer is bounded.
_UNSAFE_STRING_FUNCS: FrozenSet[str] = frozenset({
    # No-size copies — always dangerous
    "strcpy",
    "strcat",
    "wcscpy",
    "wcscat",
    "sprintf",
    "vsprintf",
    "gets",
    # Non-null-terminated versions (still dangerous without sizes)
    "lstrcpy",
    "lstrcpyA",
    "lstrcpyW",
    "lstrcatA",
    "lstrcatW",
    # POSIX extensions that are commonly misused
    "stpcpy",
    "stpcat",
})

# Safer replacements we can suggest in messages.
_SAFE_ALTERNATIVES: Dict[str, str] = {
    "strcpy":   "strncpy or strlcpy",
    "strcat":   "strncat or strlcat",
    "wcscpy":   "wcsncpy",
    "wcscat":   "wcsncat",
    "sprintf":  "snprintf",
    "vsprintf": "vsnprintf",
    "gets":     "fgets",
    "lstrcpy":  "StringCbCopy (MSDN)",
    "lstrcpyA": "StringCbCopyA",
    "lstrcpyW": "StringCbCopyW",
    "stpcpy":   "stpncpy",
}

# Memory allocation functions whose first/only size argument may be tainted.
# Tuple: (function_name, zero_based_index_of_size_argument)
_ALLOC_FUNCS: List[Tuple[str, int]] = [
    ("malloc",   0),
    ("calloc",   0),   # also arg[1]; we check both
    ("calloc",   1),
    ("realloc",  1),
    ("alloca",   0),
    ("valloc",   0),
    ("memalign", 1),
    ("aligned_alloc", 1),
    ("operator new",  0),
]

# Functions known to write into their destination with a size limit;
# we use these to rule out BOS-04 warnings (these are the safe versions).
_SAFE_STRING_FUNCS: FrozenSet[str] = frozenset({
    "strncpy", "strncat", "snprintf", "vsnprintf", "fgets",
    "wcsncpy",  "wcsncat",
    "strlcpy",  "strlcat",
    "StringCbCopy", "StringCbCopyA", "StringCbCopyW",
    "StringCbCat",  "StringCbCatA",  "StringCbCatW",
    "memcpy_s", "memmove_s", "strcpy_s", "strcat_s",
})

# External / user-supplied variable name heuristics for taint detection.
# Variables whose names suggest they came from user input.
_TAINT_NAME_PATTERNS: List[re.Pattern] = [
    re.compile(r"\b(argc|argv)\b"),
    re.compile(r"\b(user|input|req|request|param|query|buf_size|len|length|"
               r"size|sz|count|num|n_bytes|nbytes|nchars)\b", re.IGNORECASE),
    re.compile(r"\b(recv|read|fread|sscanf|atoi|atol|strtol|strtoul)\b"),
]

# Syscall / libc read functions that introduce tainted data.
_TAINT_SOURCE_FUNCS: FrozenSet[str] = frozenset({
    "read", "fread", "recv", "recvfrom", "recvmsg",
    "scanf", "sscanf", "fscanf",
    "atoi", "atol", "atoll",
    "strtol", "strtoul", "strtoll", "strtoull",
    "getenv", "getopt",
})


# ═════════════════════════════════════════════════════════════════════════════
#  PART 3 — HELPER UTILITIES
# ═════════════════════════════════════════════════════════════════════════════

def _get_token_function_name(tok: Any) -> Optional[str]:
    """
    Return the name of the function a token calls, or None.

    Handles both direct-call tokens (tok.function) and string matching
    for calls that cppcheck may not have resolved to a Function object.
    """
    func = getattr(tok, "function", None)
    if func is not None:
        return getattr(func, "name", None) or _tok_str(tok)
    # Fall back to token string for unresolved calls
    s = _tok_str(tok)
    next_tok = getattr(tok, "next", None)
    if next_tok and _tok_str(next_tok) == "(":
        return s
    return None


def _is_function_call(tok: Any, name: str) -> bool:
    """True when `tok` is the identifier of a call to `name`."""
    if _tok_str(tok) != name:
        return False
    next_tok = getattr(tok, "next", None)
    return next_tok is not None and _tok_str(next_tok) == "("


def _call_args(call_tok: Any) -> List[Any]:
    """
    Return a list of AST operand tokens for the arguments of a function call.

    `call_tok` should point to the opening '(' token or the function
    identifier.  We navigate via the AST's astOperand2 chain on the
    '(' node.

    cppcheck models  f(a, b, c)  as:
      '(' → astOperand1 = f-token
          → astOperand2 = ','
              astOperand1 = a
              astOperand2 = ','
                  astOperand1 = b
                  astOperand2 = c
    """
    # Normalise: accept either the identifier or the '(' token.
    if _tok_str(call_tok) != "(":
        call_tok = getattr(call_tok, "next", None)
    if call_tok is None or _tok_str(call_tok) != "(":
        return []

    args: List[Any] = []

    def _walk(node: Any) -> None:
        if node is None:
            return
        if _tok_str(node) == ",":
            _walk(getattr(node, "astOperand1", None))
            _walk(getattr(node, "astOperand2", None))
        else:
            args.append(node)

    top = getattr(call_tok, "astOperand2", None)
    _walk(top)
    return args


def _array_declared_size(var: Any) -> Optional[int]:
    """
    Return the declared element count of an array variable, or None.

    Covers:
      char buf[64];          →  64
      int  arr[10][5];       →  10  (outermost dimension)
      char buf[] = "hello";  →  None  (compiler-deduced; cppcheck may fill it)
    """
    dims = getattr(var, "dimensions", None)
    if not dims:
        return None
    for dim in dims:
        sz = getattr(dim, "size", None)
        if sz is not None:
            try:
                n = int(sz)
                if n > 0:
                    return n
            except (ValueError, TypeError):
                pass
    return None


def _var_is_array(var: Any) -> bool:
    """True when the variable is an array (has at least one dimension)."""
    dims = getattr(var, "dimensions", None)
    return bool(dims)


def _tok_is_lvalue_of_assign(tok: Any) -> bool:
    """True when `tok` is the left-hand side of an assignment operator."""
    parent = getattr(tok, "astParent", None)
    if parent is None:
        return False
    if not getattr(parent, "isAssignmentOp", False):
        return False
    return getattr(parent, "astOperand1", None) is tok


def _known_int_values(tok: Any) -> List[int]:
    """
    Collect all known/possible integer values from ValueFlow for `tok`.

    Returns an empty list when no integer ValueFlow values are available.
    """
    result: List[int] = []
    for v in _get_valueflow_values(tok):
        iv = getattr(v, "intvalue", None)
        if iv is not None:
            try:
                result.append(int(iv))
            except (ValueError, TypeError):
                pass
    return result


def _is_tainted_name(name: str) -> bool:
    """Heuristic: does this variable name look like it comes from user input?"""
    for pat in _TAINT_NAME_PATTERNS:
        if pat.search(name):
            return True
    return False


def _scope_function_name(tok: Any) -> Optional[str]:
    """
    Walk up the scope chain from `tok` and return the enclosing function name.
    Returns None if `tok` is at file scope.
    """
    scope = getattr(tok, "scope", None)
    while scope is not None:
        kind = getattr(scope, "type", "")
        if kind == "Function":
            func = getattr(scope, "function", None)
            if func is not None:
                return getattr(func, "name", None)
        scope = getattr(scope, "nestedIn", None)
    return None


# ═════════════════════════════════════════════════════════════════════════════
#  PART 4 — CHECKER IMPLEMENTATIONS
# ═════════════════════════════════════════════════════════════════════════════

# ─────────────────────────────────────────────────────────────────────────────
#  BOS-01  Stack Buffer Overflow — constant index ≥ declared size
#  CWE-121: Stack-based Buffer Overflow
# ─────────────────────────────────────────────────────────────────────────────

class StackBufferOverflowChecker(Checker):
    """
    Detects array subscripts with a constant index that equals or
    exceeds the statically declared array size.

    Examples flagged:
        char buf[8];
        buf[8]  = 'x';   // index == size  → off by one
        buf[9]  = 'x';   // index >  size  → definite overflow
        buf[-1] = 'x';   // negative       → handled by BOS-06

    Strategy:
      1. Collect all array variables and their declared sizes.
      2. For every '[' AST node, resolve the array's declared size
         and the index's ValueFlow integer set.
      3. If any known/possible index >= size, emit a diagnostic.
    """

    name: ClassVar[str] = "bos-stack-overflow"
    description: ClassVar[str] = "Stack-based buffer overflow via constant index"
    error_ids: ClassVar[FrozenSet[str]] = frozenset({
        "stackBufferOverflow",
        "stackBufferOverflowPossible",
    })
    default_severity: ClassVar[DiagnosticSeverity] = DiagnosticSeverity.ERROR
    cwe_ids: ClassVar[Dict[str, int]] = {
        "stackBufferOverflow":         121,
        "stackBufferOverflowPossible": 121,
    }

    def __init__(self) -> None:
        super().__init__()
        # varId → declared element count
        self._array_sizes: Dict[int, int] = {}
        # varId → variable name (for messages)
        self._array_names: Dict[int, str] = {}
        # (tok, varId, index, is_definite, array_name, arr_size)
        self._violations: List[Tuple[Any, int, int, bool, str, int]] = []

    def collect_evidence(self, ctx: CheckerContext) -> None:
        cfg = ctx.cfg

        # ── Pass 1: index all array variables ────────────────────────────
        for var in _iter_variables(cfg):
            if not _var_is_array(var):
                continue
            vid = getattr(var, "Id", None)
            if vid is None:
                continue
            vid = int(vid)
            sz = _array_declared_size(var)
            if sz is not None:
                self._array_sizes[vid] = sz
                self._array_names[vid] = _var_name(var)

        # ── Pass 2: inspect every subscript operator ──────────────────────
        for tok in _iter_tokens(cfg):
            if _tok_str(tok) != "[":
                continue

            arr_operand  = getattr(tok, "astOperand1", None)   # the array
            idx_operand  = getattr(tok, "astOperand2", None)   # the index

            if arr_operand is None or idx_operand is None:
                continue

            arr_vid = getattr(arr_operand, "varId", None)
            if not arr_vid or arr_vid == 0:
                continue

            arr_size = self._array_sizes.get(arr_vid)
            if arr_size is None:
                continue

            arr_name = self._array_names.get(arr_vid, "?")

            # Gather every integer value the index can take
            idx_values = _known_int_values(idx_operand)
            if not idx_values:
                continue

            for idx_val in idx_values:
                if idx_val < 0:
                    continue  # handed to BOS-06

                if idx_val >= arr_size:
                    # Distinguish known (all values OOB) vs. possible
                    all_oob = all(v >= arr_size for v in idx_values)
                    self._violations.append(
                        (tok, arr_vid, idx_val, all_oob, arr_name, arr_size)
                    )
                    break   # one violation per subscript site is enough

    def diagnose(self, ctx: CheckerContext) -> None:
        seen: Set[Tuple[str, int, int]] = set()

        for tok, vid, idx, definite, arr_name, arr_size in self._violations:
            file = _tok_file(tok)
            line = _tok_line(tok)
            key  = (file, line, vid)
            if key in seen:
                continue
            seen.add(key)

            if definite:
                self._emit(
                    error_id="stackBufferOverflow",
                    message=(
                        f"Stack buffer overflow: array '{arr_name}' has "
                        f"{arr_size} element(s) but index {idx} was used "
                        f"(valid range: 0..{arr_size - 1})"
                    ),
                    file=file, line=line, column=_tok_col(tok),
                    severity=DiagnosticSeverity.ERROR,
                    confidence=Confidence.HIGH,
                    evidence={"varId": vid, "index": idx,
                              "arraySize": arr_size},
                )
            else:
                self._emit(
                    error_id="stackBufferOverflowPossible",
                    message=(
                        f"Possible stack buffer overflow: array '{arr_name}' "
                        f"has {arr_size} element(s); index may be {idx} "
                        f"(valid range: 0..{arr_size - 1})"
                    ),
                    file=file, line=line, column=_tok_col(tok),
                    severity=DiagnosticSeverity.WARNING,
                    confidence=Confidence.MEDIUM,
                    evidence={"varId": vid, "index": idx,
                              "arraySize": arr_size},
                )


# ─────────────────────────────────────────────────────────────────────────────
#  BOS-02  Heap Buffer Overflow — access beyond malloc'd allocation
#  CWE-122: Heap-based Buffer Overflow
# ─────────────────────────────────────────────────────────────────────────────

class HeapBufferOverflowChecker(Checker):
    """
    Tracks malloc/calloc allocations with known sizes and flags
    subscript or pointer-arithmetic accesses that exceed those sizes.

    Strategy:
      1. For each  p = malloc(N)  where N is a known constant, record
         varId(p) → N  (in bytes, then convert to element count via
         ValueType size when available).
      2. For each  p[i]  or  *(p + i)  where i >= N, emit a diagnostic.

    Limitations (conservative):
      - Only constant-size allocations are tracked.
      - realloc is not tracked (the new size may differ).
    """

    name: ClassVar[str] = "bos-heap-overflow"
    description: ClassVar[str] = "Heap-based buffer overflow beyond malloc'd size"
    error_ids: ClassVar[FrozenSet[str]] = frozenset({
        "heapBufferOverflow",
        "heapBufferOverflowPossible",
    })
    default_severity: ClassVar[DiagnosticSeverity] = DiagnosticSeverity.ERROR
    cwe_ids: ClassVar[Dict[str, int]] = {
        "heapBufferOverflow":         122,
        "heapBufferOverflowPossible": 122,
    }

    # malloc-like functions and the zero-based index of their size argument
    _MALLOC_LIKE: ClassVar[List[Tuple[str, int]]] = [
        ("malloc",        0),
        ("g_malloc",      0),
        ("g_malloc0",     0),
        ("kmalloc",       0),
        ("vmalloc",       0),
        ("alloca",        0),
        ("operator new",  0),
    ]

    def __init__(self) -> None:
        super().__init__()
        # varId → allocation size in bytes (best known constant)
        self._heap_sizes: Dict[int, int] = {}
        # varId → pointer element size in bytes (best effort)
        self._elem_sizes: Dict[int, int] = {}
        # (tok, varId, idx, definite, alloc_bytes)
        self._violations: List[Tuple[Any, int, int, bool, int]] = []

    def collect_evidence(self, ctx: CheckerContext) -> None:
        cfg = ctx.cfg

        # ── Pass 1: collect allocation sites ─────────────────────────────
        for tok in _iter_tokens(cfg):
            fname = _get_token_function_name(tok)
            if fname is None:
                continue

            alloc_arg_idx: Optional[int] = None
            for alloc_name, arg_idx in self._MALLOC_LIKE:
                if fname == alloc_name:
                    alloc_arg_idx = arg_idx
                    break
            if alloc_arg_idx is None:
                continue

            args = _call_args(tok)
            if alloc_arg_idx >= len(args):
                continue

            size_arg = args[alloc_arg_idx]
            size_vals = _known_int_values(size_arg)
            if not size_vals:
                continue

            # The allocation's result is assigned to a pointer variable
            # via:  ptr = malloc(...)
            # Walk up the AST to the assignment node.
            call_parent = getattr(tok, "astParent", None)
            # The '(' token is the call node; its parent may be '='
            paren_tok = getattr(tok, "next", None)
            if paren_tok is None:
                continue
            assign_parent = getattr(paren_tok, "astParent", None)
            if assign_parent is None:
                continue

            lhs = getattr(assign_parent, "astOperand1", None)
            if lhs is None:
                continue
            ptr_vid = getattr(lhs, "varId", None)
            if not ptr_vid or ptr_vid == 0:
                continue

            # Use the minimum known size (conservative: detect overflows
            # even on the smallest possible allocation).
            alloc_bytes = min(size_vals)
            self._heap_sizes[ptr_vid] = alloc_bytes

            # Try to learn the element size from the pointer's ValueType
            vt = getattr(lhs, "valueType", None)
            if vt:
                esz = getattr(vt, "typeSize", None)
                if esz and int(esz) > 0:
                    self._elem_sizes[ptr_vid] = int(esz)

        # ── Pass 2: inspect subscripts on heap pointers ───────────────────
        for tok in _iter_tokens(cfg):
            if _tok_str(tok) != "[":
                continue

            arr_op = getattr(tok, "astOperand1", None)
            idx_op = getattr(tok, "astOperand2", None)
            if arr_op is None or idx_op is None:
                continue

            vid = getattr(arr_op, "varId", None)
            if not vid or vid not in self._heap_sizes:
                continue

            alloc_bytes  = self._heap_sizes[vid]
            elem_size    = self._elem_sizes.get(vid, 1)
            # Number of addressable elements
            max_elements = alloc_bytes // max(elem_size, 1)

            idx_values = _known_int_values(idx_op)
            if not idx_values:
                continue

            for idx_val in idx_values:
                if idx_val < 0:
                    continue
                if idx_val >= max_elements:
                    all_oob = all(v >= max_elements for v in idx_values)
                    self._violations.append(
                        (tok, vid, idx_val, all_oob, alloc_bytes)
                    )
                    break

    def diagnose(self, ctx: CheckerContext) -> None:
        seen: Set[Tuple[str, int, int]] = set()

        for tok, vid, idx, definite, alloc_bytes in self._violations:
            file = _tok_file(tok)
            line = _tok_line(tok)
            key  = (file, line, vid)
            if key in seen:
                continue
            seen.add(key)

            elem_sz  = self._elem_sizes.get(vid, 1)
            max_elem = alloc_bytes // max(elem_sz, 1)

            if definite:
                self._emit(
                    error_id="heapBufferOverflow",
                    message=(
                        f"Heap buffer overflow: pointer allocated {alloc_bytes} "
                        f"byte(s) ({max_elem} element(s)), but index {idx} "
                        f"exceeds the allocation (valid range: 0..{max_elem - 1})"
                    ),
                    file=file, line=line, column=_tok_col(tok),
                    severity=DiagnosticSeverity.ERROR,
                    confidence=Confidence.HIGH,
                    evidence={"varId": vid, "index": idx,
                              "allocBytes": alloc_bytes},
                )
            else:
                self._emit(
                    error_id="heapBufferOverflowPossible",
                    message=(
                        f"Possible heap buffer overflow: pointer allocated "
                        f"{alloc_bytes} byte(s); index may be {idx} "
                        f"(valid range: 0..{max_elem - 1})"
                    ),
                    file=file, line=line, column=_tok_col(tok),
                    severity=DiagnosticSeverity.WARNING,
                    confidence=Confidence.MEDIUM,
                    evidence={"varId": vid, "index": idx,
                              "allocBytes": alloc_bytes},
                )


# ─────────────────────────────────────────────────────────────────────────────
#  BOS-03  Off-by-One Error
#  CWE-193: Off-by-One Error
# ─────────────────────────────────────────────────────────────────────────────

class OffByOneChecker(Checker):
    """
    Detects the classic off-by-one pattern: using `size` as an index
    into an array of `size` elements (valid indices are 0..size-1).

    Patterns recognised:
      A.  buf[N]   when buf has exactly N elements
          (already caught by BOS-01 as a definite overflow, but here we
           emit a more descriptive "off-by-one" message)

      B.  Loop patterns:
            for (i = 0; i <= N; i++) buf[i] = ...;   ← '<=' should be '<'
          Detected via the loop's comparison operator and ValueFlow on `i`.

      C.  strlen(s) used as index into s (NULL terminator is at s[len]):
            s[strlen(s)] = ch;    // technically valid (writes the NUL)
            s[strlen(s) + 1] ... // off-by-one past the NUL

    This checker focuses on pattern B (loop ≤ instead of <) as it is the
    most common source of off-by-one errors and the hardest for developers
    to spot without a tool.
    """

    name: ClassVar[str] = "bos-off-by-one"
    description: ClassVar[str] = "Off-by-one error in array or string access"
    error_ids: ClassVar[FrozenSet[str]] = frozenset({
        "offByOne",
        "offByOneLoop",
        "offByOneStrlen",
    })
    default_severity: ClassVar[DiagnosticSeverity] = DiagnosticSeverity.WARNING
    cwe_ids: ClassVar[Dict[str, int]] = {
        "offByOne":       193,
        "offByOneLoop":   193,
        "offByOneStrlen": 193,
    }

    def __init__(self) -> None:
        super().__init__()
        self._array_sizes: Dict[int, int] = {}
        self._array_names: Dict[int, str] = {}
        # (tok, eid, message)
        self._violations: List[Tuple[Any, str, str]] = []

    def collect_evidence(self, ctx: CheckerContext) -> None:
        cfg = ctx.cfg

        # Index array sizes (same as BOS-01)
        for var in _iter_variables(cfg):
            if not _var_is_array(var):
                continue
            vid = getattr(var, "Id", None)
            if vid is None:
                continue
            vid = int(vid)
            sz = _array_declared_size(var)
            if sz is not None:
                self._array_sizes[vid] = sz
                self._array_names[vid] = _var_name(var)

        # ── Pattern A: buf[N] where N == declared size ────────────────────
        for tok in _iter_tokens(cfg):
            if _tok_str(tok) != "[":
                continue
            arr_op = getattr(tok, "astOperand1", None)
            idx_op = getattr(tok, "astOperand2", None)
            if arr_op is None or idx_op is None:
                continue
            vid = getattr(arr_op, "varId", None)
            if not vid:
                continue
            sz = self._array_sizes.get(vid)
            if sz is None:
                continue
            for iv in _known_int_values(idx_op):
                if iv == sz:
                    name = self._array_names.get(vid, "?")
                    self._violations.append((
                        tok,
                        "offByOne",
                        f"Off-by-one: '{name}' has {sz} element(s); "
                        f"index {iv} is one past the end "
                        f"(valid range: 0..{sz - 1})",
                    ))
                    break

        # ── Pattern B: loop with '<=' comparator ─────────────────────────
        #  Detect:  for (i = 0; i <= <array_size_expr>; ...)
        #  We look for '<=' tokens whose right operand's ValueFlow value
        #  equals some known array size, and whose left operand (the
        #  induction variable) is subsequently used as an array index.
        for tok in _iter_tokens(cfg):
            if _tok_str(tok) != "<=":
                continue
            rhs = getattr(tok, "astOperand2", None)
            lhs = getattr(tok, "astOperand1", None)
            if rhs is None or lhs is None:
                continue

            rhs_vals = _known_int_values(rhs)
            for rhs_val in rhs_vals:
                # Does this rhs value match any declared array size?
                for vid, sz in self._array_sizes.items():
                    if rhs_val == sz - 1:
                        continue   # '<= size-1' is safe (equivalent to '< size')
                    if rhs_val == sz:
                        name = self._array_names.get(vid, "?")
                        self._violations.append((
                            tok,
                            "offByOneLoop",
                            f"Off-by-one in loop: condition 'i <= {rhs_val}' "
                            f"with array '{name}' of size {sz}; "
                            f"use 'i < {sz}' to avoid accessing one past the end",
                        ))
                        break

        # ── Pattern C: strlen result used as index ────────────────────────
        for tok in _iter_tokens(cfg):
            if not _is_function_call(tok, "strlen"):
                continue
            # Check whether the result is used directly as an array index.
            # The call site AST:  strlen(s)  →  tok=strlen, next=(
            # The parent of '(' may be '[' (as astOperand2 of the subscript).
            paren = getattr(tok, "next", None)
            if paren is None or _tok_str(paren) != "(":
                continue
            parent = getattr(paren, "astParent", None)
            # Direct pattern: s[strlen(s)]
            if parent and _tok_str(parent) == "[":
                idx_of_subscript = getattr(parent, "astOperand2", None)
                if idx_of_subscript is paren:
                    self._violations.append((
                        tok,
                        "offByOneStrlen",
                        "Possible off-by-one: using strlen() result directly "
                        "as an array index writes to the NUL terminator position; "
                        "if intentional (appending), ensure the buffer has room "
                        "for the NUL byte",
                    ))

    def diagnose(self, ctx: CheckerContext) -> None:
        seen: Set[Tuple[str, int, str]] = set()
        for tok, eid, msg in self._violations:
            file = _tok_file(tok)
            line = _tok_line(tok)
            key  = (file, line, eid)
            if key in seen:
                continue
            seen.add(key)
            self._emit(
                error_id=eid,
                message=msg,
                file=file, line=line, column=_tok_col(tok),
                severity=self.default_severity,
                confidence=Confidence.MEDIUM,
            )


# ─────────────────────────────────────────────────────────────────────────────
#  BOS-04  Unsafe String / Memory Functions
#  CWE-120: Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')
# ─────────────────────────────────────────────────────────────────────────────

class UnsafeStringFunctionChecker(Checker):
    """
    Flags calls to functions that copy data without a size bound:
    strcpy, strcat, gets, sprintf, vsprintf, wcscpy, wcscat.

    These are inherently dangerous when the destination is a bounded buffer
    because there is no way for the runtime to prevent overflow if the
    source is longer than the destination.

    The checker also looks for `sprintf(buf, "%s", src)` where `src` is
    a variable of unknown length — a common indirect overflow.

    False positive mitigation:
      - We do NOT flag calls inside system / library headers
        (file path contains "<" or "include" directory heuristic).
      - We do NOT flag `sprintf` with a format string that contains
        no `%s` / `%[` patterns (bounded format only).
    """

    name: ClassVar[str] = "bos-unsafe-string-func"
    description: ClassVar[str] = "Call to unsafe string/memory function without size bound"
    error_ids: ClassVar[FrozenSet[str]] = frozenset({
        "unsafeStringFunction",
        "unsafeGetsFunction",
        "unsafeSprintfFunction",
    })
    default_severity: ClassVar[DiagnosticSeverity] = DiagnosticSeverity.WARNING
    cwe_ids: ClassVar[Dict[str, int]] = {
        "unsafeStringFunction":  120,
        "unsafeGetsFunction":    120,
        "unsafeSprintfFunction": 134,  # also format-string related
    }

    # Format verbs that accept unbounded string input
    _UNBOUNDED_FMT: ClassVar[re.Pattern] = re.compile(r"%[^diouxXeEfgGaAcspn%]*[sS\[]")

    def __init__(self) -> None:
        super().__init__()
        # (tok, eid, message)
        self._violations: List[Tuple[Any, str, str]] = []

    def _in_system_header(self, tok: Any) -> bool:
        """Heuristic: skip tokens from system/library headers."""
        f = _tok_file(tok)
        if not f:
            return False
        # cppcheck marks system-header tokens; also catch by path heuristic
        if getattr(tok, "isExpandedMacro", False):
            return False   # macros are user-level
        norm = f.replace("\\", "/").lower()
        return ("/usr/include" in norm
                or "/usr/lib"  in norm
                or norm.startswith("<"))

    def collect_evidence(self, ctx: CheckerContext) -> None:
        cfg = ctx.cfg

        for tok in _iter_tokens(cfg):
            if self._in_system_header(tok):
                continue

            fname = _tok_str(tok)
            if fname not in _UNSAFE_STRING_FUNCS:
                continue

            # Must be followed by '(' to be a call
            next_tok = getattr(tok, "next", None)
            if next_tok is None or _tok_str(next_tok) != "(":
                continue

            safe_alt = _SAFE_ALTERNATIVES.get(fname, "a size-bounded alternative")

            # ── gets() — always dangerous ─────────────────────────────────
            if fname == "gets":
                self._violations.append((
                    tok,
                    "unsafeGetsFunction",
                    "Call to 'gets' is always unsafe: it provides no way to "
                    f"limit input size and will overflow any fixed buffer; "
                    f"use '{safe_alt}' instead",
                ))
                continue

            # ── sprintf / vsprintf — check for unbounded %s ───────────────
            if fname in {"sprintf", "vsprintf"}:
                args = _call_args(tok)
                # args[0] = dest, args[1] = format string
                if len(args) >= 2:
                    fmt_tok = args[1]
                    # Try to get the literal format string from ValueFlow
                    fmt_str: Optional[str] = None
                    for v in _get_valueflow_values(fmt_tok):
                        vs = getattr(v, "tokvalue", None)
                        if vs:
                            fmt_str = _tok_str(vs)
                            break
                    if fmt_str is None:
                        # Unknown format string — conservative flag
                        self._violations.append((
                            tok,
                            "unsafeSprintfFunction",
                            f"Call to '{fname}' with unknown format string may "
                            "overflow the destination buffer; "
                            f"use '{safe_alt}' with an explicit size limit",
                        ))
                    elif self._UNBOUNDED_FMT.search(fmt_str):
                        self._violations.append((
                            tok,
                            "unsafeSprintfFunction",
                            f"Call to '{fname}' with unbounded '%%s' or '%%[' "
                            "format specifier may overflow the destination buffer; "
                            f"use '{safe_alt}'",
                        ))
                continue

            # ── General unsafe copy functions ─────────────────────────────
            self._violations.append((
                tok,
                "unsafeStringFunction",
                f"Call to '{fname}' does not check the destination buffer size "
                f"and may overflow it; use '{safe_alt}' instead",
            ))

    def diagnose(self, ctx: CheckerContext) -> None:
        seen: Set[Tuple[str, int]] = set()
        for tok, eid, msg in self._violations:
            file = _tok_file(tok)
            line = _tok_line(tok)
            key  = (file, line)
            if key in seen:
                continue
            seen.add(key)
            self._emit(
                error_id=eid,
                message=msg,
                file=file, line=line, column=_tok_col(tok),
                severity=self.default_severity,
                confidence=Confidence.HIGH,
            )


# ─────────────────────────────────────────────────────────────────────────────
#  BOS-05  Tainted / Unchecked Allocation Size
#  CWE-789: Memory Allocation with Excessive Size Value
# ─────────────────────────────────────────────────────────────────────────────

class TaintedAllocSizeChecker(Checker):
    """
    Detects memory allocations whose size argument is tainted (originates
    from user-controlled input) without a preceding upper-bound validation.

    The "taint" model is heuristic:
      - Variables with names matching _TAINT_NAME_PATTERNS are considered
        tainted (argc, len, size, count, user_*, input_*, …).
      - Variables assigned from _TAINT_SOURCE_FUNCS (read, recv, atoi, …)
        are considered tainted.

    Validation detection:
      We look for an 'if' statement containing the tainted variable and
      a relational operator (< <= > >=) between the preceding token and
      the alloc call.  This is coarse but avoids most false positives.

    CWE-789: Memory Allocation with Excessive Size Value
    CWE-190: Integer Overflow to Buffer Overflow (secondary)
    """

    name: ClassVar[str] = "bos-tainted-alloc"
    description: ClassVar[str] = "Memory allocation with unchecked / tainted size"
    error_ids: ClassVar[FrozenSet[str]] = frozenset({
        "taintedAllocSize",
        "taintedAllocSizePossible",
    })
    default_severity: ClassVar[DiagnosticSeverity] = DiagnosticSeverity.WARNING
    cwe_ids: ClassVar[Dict[str, int]] = {
        "taintedAllocSize":         789,
        "taintedAllocSizePossible": 789,
    }

    def __init__(self) -> None:
        super().__init__()
        # varIds known to carry tainted data
        self._tainted_vars: Set[int] = set()
        # (tok, eid, message)
        self._violations: List[Tuple[Any, str, str]] = []

    def _mark_tainted(self, var: Any) -> None:
        vid = getattr(var, "Id", None)
        if vid is not None:
            self._tainted_vars.add(int(vid))

    def collect_evidence(self, ctx: CheckerContext) -> None:
        cfg = ctx.cfg

        # ── Pass 1: collect tainted variable IDs ─────────────────────────

        # 1a. Heuristic: tainted names
        for var in _iter_variables(cfg):
            name = _var_name(var)
            if _is_tainted_name(name):
                self._mark_tainted(var)

        # 1b. Taint from external source functions
        for tok in _iter_tokens(cfg):
            fname = _tok_str(tok)
            if fname not in _TAINT_SOURCE_FUNCS:
                continue
            next_tok = getattr(tok, "next", None)
            if next_tok is None or _tok_str(next_tok) != "(":
                continue
            # The result is assigned to the LHS of the enclosing assignment
            paren_parent = getattr(next_tok, "astParent", None)
            if paren_parent is None:
                continue
            lhs = getattr(paren_parent, "astOperand1", None)
            if lhs is None:
                continue
            vid = getattr(lhs, "varId", None)
            if vid and vid != 0:
                self._tainted_vars.add(int(vid))

        if not self._tainted_vars:
            return

        # ── Pass 2: flag alloc calls with tainted size arguments ──────────
        for tok in _iter_tokens(cfg):
            fname = _tok_str(tok)

            alloc_arg_idx: Optional[int] = None
            for alloc_name, arg_idx in _ALLOC_FUNCS:
                if fname == alloc_name:
                    alloc_arg_idx = arg_idx
                    break
            if alloc_arg_idx is None:
                continue

            next_tok = getattr(tok, "next", None)
            if next_tok is None or _tok_str(next_tok) != "(":
                continue

            args = _call_args(tok)
            if alloc_arg_idx >= len(args):
                continue

            size_arg = args[alloc_arg_idx]
            # Walk the size expression to see if any leaf is a tainted var
            tainted_leaf = self._find_tainted_leaf(size_arg)
            if tainted_leaf is None:
                continue

            leaf_name = _tok_str(tainted_leaf)
            # Confidence: HIGH if the var name is directly tainted,
            #             MEDIUM if it propagated through arithmetic.
            direct = getattr(tainted_leaf, "varId", None) in self._tainted_vars

            if direct:
                self._violations.append((
                    tok,
                    "taintedAllocSize",
                    f"Call to '{fname}' with size argument '{leaf_name}' "
                    "that may be controlled by user input; "
                    "validate and bound the size before allocation "
                    "to prevent CWE-789 / heap overflow",
                ))
            else:
                self._violations.append((
                    tok,
                    "taintedAllocSizePossible",
                    f"Call to '{fname}' with size derived from potentially "
                    f"tainted variable '{leaf_name}'; "
                    "consider validating the size before allocation",
                ))

    def _find_tainted_leaf(self, node: Any) -> Optional[Any]:
        """
        Recursively walk an AST expression node; return the first
        leaf token whose varId is in self._tainted_vars, or None.
        """
        if node is None:
            return None
        vid = getattr(node, "varId", None)
        if vid and int(vid) in self._tainted_vars:
            return node
        # Recurse into binary / unary sub-expressions
        left  = self._find_tainted_leaf(getattr(node, "astOperand1", None))
        if left is not None:
            return left
        return self._find_tainted_leaf(getattr(node, "astOperand2", None))

    def diagnose(self, ctx: CheckerContext) -> None:
        seen: Set[Tuple[str, int]] = set()
        for tok, eid, msg in self._violations:
            file = _tok_file(tok)
            line = _tok_line(tok)
            key  = (file, line)
            if key in seen:
                continue
            seen.add(key)
            confidence = (Confidence.HIGH
                          if eid == "taintedAllocSize"
                          else Confidence.MEDIUM)
            self._emit(
                error_id=eid,
                message=msg,
                file=file, line=line, column=_tok_col(tok),
                severity=self.default_severity,
                confidence=confidence,
            )


# ─────────────────────────────────────────────────────────────────────────────
#  BOS-06  Buffer Underflow — negative array index
#  CWE-124: Buffer Underwrite ('Buffer Underflow')
# ─────────────────────────────────────────────────────────────────────────────

class BufferUnderflowChecker(Checker):
    """
    Detects array subscripts with a known-negative index.

    In C, accessing arr[-1] is undefined behaviour regardless of whether
    `arr` points to a heap or stack buffer.

    Strategy:
      For every '[' AST node whose index operand carries a ValueFlow
      integer value < 0, emit a diagnostic.

    CWE-124: Buffer Underwrite ('Buffer Underflow')
    """

    name: ClassVar[str] = "bos-buffer-underflow"
    description: ClassVar[str] = "Buffer underflow via negative array index"
    error_ids: ClassVar[FrozenSet[str]] = frozenset({
        "bufferUnderflow",
        "bufferUnderflowPossible",
    })
    default_severity: ClassVar[DiagnosticSeverity] = DiagnosticSeverity.ERROR
    cwe_ids: ClassVar[Dict[str, int]] = {
        "bufferUnderflow":         124,
        "bufferUnderflowPossible": 124,
    }

    def __init__(self) -> None:
        super().__init__()
        # (tok, idx_val, arr_name, definite)
        self._violations: List[Tuple[Any, int, str, bool]] = []

    def collect_evidence(self, ctx: CheckerContext) -> None:
        cfg = ctx.cfg

        for tok in _iter_tokens(cfg):
            if _tok_str(tok) != "[":
                continue

            arr_op = getattr(tok, "astOperand1", None)
            idx_op = getattr(tok, "astOperand2", None)
            if arr_op is None or idx_op is None:
                continue

            idx_vals = _known_int_values(idx_op)
            if not idx_vals:
                continue

            neg_vals = [v for v in idx_vals if v < 0]
            if not neg_vals:
                continue

            arr_name = _tok_str(arr_op)
            definite  = all(v < 0 for v in idx_vals)
            worst     = min(neg_vals)   # most-negative value

            self._violations.append((tok, worst, arr_name, definite))

    def diagnose(self, ctx: CheckerContext) -> None:
        seen: Set[Tuple[str, int, str]] = set()
        for tok, idx_val, arr_name, definite in self._violations:
            file = _tok_file(tok)
            line = _tok_line(tok)
            key  = (file, line, arr_name)
            if key in seen:
                continue
            seen.add(key)

            if definite:
                self._emit(
                    error_id="bufferUnderflow",
                    message=(
                        f"Buffer underflow: negative index {idx_val} "
                        f"used on '{arr_name}' — this is undefined behaviour "
                        "(CWE-124)"
                    ),
                    file=file, line=line, column=_tok_col(tok),
                    severity=DiagnosticSeverity.ERROR,
                    confidence=Confidence.HIGH,
                )
            else:
                self._emit(
                    error_id="bufferUnderflowPossible",
                    message=(
                        f"Possible buffer underflow: index may be {idx_val} "
                        f"on '{arr_name}' — negative indices are undefined "
                        "behaviour (CWE-124)"
                    ),
                    file=file, line=line, column=_tok_col(tok),
                    severity=DiagnosticSeverity.WARNING,
                    confidence=Confidence.MEDIUM,
                )


# ═════════════════════════════════════════════════════════════════════════════
#  PART 5 — CHECKER RUNNER
# ═════════════════════════════════════════════════════════════════════════════

class CheckerRunner:
    """
    Orchestrates the full four-phase lifecycle across all registered checkers
    and emits results through a TextReporter.

    Lifecycle per checker per configuration:
      1. configure(ctx)
      2. collect_evidence(ctx)
      3. diagnose(ctx)
      4. report(ctx)  →  TextReporter.emit_all()
    """

    def __init__(
        self,
        reporter: TextReporter,
        *,
        options: Optional[Dict[str, Any]] = None,
    ) -> None:
        self._reporter = reporter
        self._options  = options or {}
        self._checkers: List[Checker] = []

    def register(self, checker: Checker) -> None:
        self._checkers.append(checker)

    def run(self, cfg: Any) -> None:
        """Run all checkers against one cppcheckdata Configuration."""
        suppressions = SuppressionManager()
        suppressions.load_inline_suppressions(cfg)

        ctx = CheckerContext(
            cfg=cfg,
            suppressions=suppressions,
            options=self._options,
        )

        for checker in self._checkers:
            try:
                checker.configure(ctx)
                checker.collect_evidence(ctx)
                checker.diagnose(ctx)
                diagnostics = checker.report(ctx)
                self._reporter.emit_all(diagnostics)
            except Exception as exc:
                print(
                    f"[BufferOverflowScan] ERROR in checker "
                    f"'{checker.name}': {exc}",
                    file=sys.stderr,
                )
                # Continue with remaining checkers


# ═════════════════════════════════════════════════════════════════════════════
#  PART 6 — MAIN ENTRY POINT
# ═════════════════════════════════════════════════════════════════════════════

def _build_runner(reporter: TextReporter) -> CheckerRunner:
    """Instantiate and register all checkers."""
    runner = CheckerRunner(reporter)
    runner.register(StackBufferOverflowChecker())
    runner.register(HeapBufferOverflowChecker())
    runner.register(OffByOneChecker())
    runner.register(UnsafeStringFunctionChecker())
    runner.register(TaintedAllocSizeChecker())
    runner.register(BufferUnderflowChecker())
    return runner


def main(argv: Optional[List[str]] = None) -> int:
    """
    Entry point for use as a Cppcheck addon.

    Cppcheck invokes addons as:
        python BufferOverflowScan.py <dumpfile>

    Returns 0 on success, 1 on argument error, 2 on parse error.
    """
    args = argv if argv is not None else sys.argv[1:]

    if not args:
        print(
            "Usage: python BufferOverflowScan.py <file.c.dump> [<file2.c.dump> ...]",
            file=sys.stderr,
        )
        return 1

    reporter = TextReporter(show_column=True)
    runner   = _build_runner(reporter)

    exit_code = 0
    for dump_path in args:
        if not os.path.isfile(dump_path):
            print(f"[BufferOverflowScan] ERROR: file not found: {dump_path}",
                  file=sys.stderr)
            exit_code = 1
            continue

        try:
            data = cppcheckdata.parsedump(dump_path)
        except Exception as exc:
            print(f"[BufferOverflowScan] ERROR parsing '{dump_path}': {exc}",
                  file=sys.stderr)
            exit_code = 2
            continue

        for cfg in data.configurations:
            runner.run(cfg)

    reporter.print_summary()
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
