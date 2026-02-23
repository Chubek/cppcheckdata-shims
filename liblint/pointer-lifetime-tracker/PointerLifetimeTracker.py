#!/usr/bin/env python3
"""
PointerLifetimeTracker.py  —  Cppcheck addon (cppcheckdata-shims compatible)

Checks for pointer lifetime, memory management, and ownership violations:

  PLT-01  Memory leak: allocated memory never freed            (CWE-401)
  PLT-02  Mismatched allocator/deallocator (new/delete,
          malloc/free, new[]/delete[])                         (CWE-762)
  PLT-03  Reference count not decremented on all exit paths    (CWE-401)
  PLT-04  Class without destructor holds raw-owning pointer    (CWE-401)
  PLT-05  Rule of Three violated: copy constructor or copy-
          assignment operator missing when destructor present  (CWE-401)
  PLT-06  Rule of Five violated: move operations missing when
          Rule-of-Three members are user-defined  (C++11)      (CWE-401)
  PLT-07  RAII opportunity: raw malloc/free pair inside a
          C++ function (prefer std::unique_ptr / RAII guard)   (CWE-401)

Error-ID namespace: PLT-xx  (reuses the "PLT" prefix from PathLint context;
rename to PLLx or PTLx if deploying both addons together).

NOTE on scope
─────────────
Token-level analysis cannot replicate a full data-flow engine.  The
heuristics here are deliberately conservative (low false-positive rate)
at the cost of missing some cases.  They are most useful as a first
pass that surfaces obvious structural defects.

Usage:
  cppcheck --dump source.cpp
  python3 PointerLifetimeTracker.py source.cpp.dump [--cli]
"""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, Iterator, List, Optional, Set, Tuple

# ── shims import ──────────────────────────────────────────────────────────────
try:
    import cppcheckdata
except ImportError:
    sys.stderr.write(
        "PointerLifetimeTracker: 'cppcheckdata' not found. "
        "Add the shims directory to PYTHONPATH.\n"
    )
    sys.exit(1)

_CLI_MODE: bool = "--cli" in sys.argv


# ══════════════════════════════════════════════════════════════════════════════
# § 1 — Token type predicates
#       All type checks go through these helpers so a future shims change
#       requires editing exactly one place.  DO NOT use tok.isIdentifier etc.
# ══════════════════════════════════════════════════════════════════════════════

def _is_name(tok) -> bool:
    try:
        return tok.type == "name"
    except AttributeError:
        return False


def _is_number(tok) -> bool:
    try:
        return tok.type == "number"
    except AttributeError:
        return False


def _is_string(tok) -> bool:
    try:
        return tok.type == "string"
    except AttributeError:
        return False


def _is_op(tok) -> bool:
    try:
        return tok.type == "op"
    except AttributeError:
        return False


# ══════════════════════════════════════════════════════════════════════════════
# § 2 — Token navigation helpers
# ══════════════════════════════════════════════════════════════════════════════

def _tok_linenr(tok) -> int:
    try:
        return int(tok.linenr)
    except (AttributeError, TypeError, ValueError):
        return 0


def _tok_col(tok) -> int:
    try:
        return int(tok.col)
    except (AttributeError, TypeError, ValueError):
        return 0


def _tok_file(tok, fallback: str) -> str:
    try:
        f = tok.file
        return f if f else fallback
    except AttributeError:
        return fallback


def _next_tok(tok):
    return tok.next if tok is not None else None


def _prev_tok(tok):
    return tok.previous if tok is not None else None


def _open_paren_after(tok):
    """Return the '(' that directly follows *tok*, or None."""
    nxt = _next_tok(tok)
    if nxt is not None and nxt.str == "(":
        return nxt
    return None


def _walk_args(open_paren_tok) -> Iterator:
    """
    Yield every token inside a balanced parenthesis group.
    Uses tok.link when available, otherwise counts depth manually.
    """
    if open_paren_tok is None or open_paren_tok.str != "(":
        return
    close = getattr(open_paren_tok, "link", None)
    if close is not None:
        t = open_paren_tok.next
        while t is not None and t is not close:
            yield t
            t = t.next
    else:
        depth = 0
        t = open_paren_tok
        while t is not None:
            if t.str == "(":
                depth += 1
            elif t.str == ")":
                depth -= 1
                if depth == 0:
                    return
            if depth > 0 and t is not open_paren_tok:
                yield t
            t = t.next


def _first_arg(open_paren_tok):
    nxt = _next_tok(open_paren_tok)
    if nxt is not None and nxt.str != ")":
        return nxt
    return None


def _nth_arg(open_paren_tok, n: int):
    """Return the n-th argument token (0-based).  Returns None if absent."""
    depth = 0
    idx   = -1
    t     = open_paren_tok
    while t is not None:
        if t.str == "(":
            depth += 1
            t = t.next
            continue
        if t.str == ")":
            depth -= 1
            if depth <= 0:
                break
            t = t.next
            continue
        if depth == 1:
            if t.str == ",":
                t = t.next
                continue
            idx += 1
            if idx == n:
                return t
        t = t.next
    return None


def _scope_lines(scope) -> Tuple[int, int]:
    """Return (first_line, last_line) for a scope's body."""
    try:
        return int(scope.bodyStart.linenr), int(scope.bodyEnd.linenr)
    except (AttributeError, TypeError, ValueError):
        return 0, 0


def _tokens_in_scope(scope, tokenlist: list) -> Iterator:
    """Yield tokens whose linenr falls within scope.bodyStart…bodyEnd."""
    lo, hi = _scope_lines(scope)
    if lo == 0:
        return
    for tok in tokenlist:
        try:
            ln = int(tok.linenr)
        except (AttributeError, TypeError, ValueError):
            continue
        if lo <= ln <= hi:
            yield tok


def _scope_contains_line(scope, line: int) -> bool:
    lo, hi = _scope_lines(scope)
    return lo <= line <= hi


# ══════════════════════════════════════════════════════════════════════════════
# § 3 — Vocabulary tables
# ══════════════════════════════════════════════════════════════════════════════

# ── 3.1 Heap-allocation functions and their expected deallocator ──────────────
#
# Each entry:  allocator_name → (family, expected_deallocator_name)
#
# "family" is used to cross-check mismatches (PLT-02).

_ALLOC_TO_FREE: Dict[str, Tuple[str, str]] = {
    # C heap
    "malloc":          ("c_heap",   "free"),
    "calloc":          ("c_heap",   "free"),
    "realloc":         ("c_heap",   "free"),
    "aligned_alloc":   ("c_heap",   "free"),
    "memalign":        ("c_heap",   "free"),
    "valloc":          ("c_heap",   "free"),
    "pvalloc":         ("c_heap",   "free"),
    "strdup":          ("c_heap",   "free"),
    "strndup":         ("c_heap",   "free"),
    "wcsdup":          ("c_heap",   "free"),
    # POSIX / system
    "mmap":            ("mmap",     "munmap"),
    # C++ scalar new
    "new":             ("cpp_new",  "delete"),
    # C++ array new — detected by "new" followed by '['
    "new[]":           ("cpp_new_arr", "delete[]"),
    # Windows heap
    "HeapAlloc":       ("win_heap", "HeapFree"),
    "LocalAlloc":      ("win_heap", "LocalFree"),
    "GlobalAlloc":     ("win_heap", "GlobalFree"),
    "CoTaskMemAlloc":  ("com_heap", "CoTaskMemFree"),
    "SysAllocString":  ("bstr",     "SysFreeString"),
}

# Inverse: deallocator → expected family
_FREE_FAMILIES: Dict[str, str] = {
    "free":           "c_heap",
    "munmap":         "mmap",
    "delete":         "cpp_new",
    "delete[]":       "cpp_new_arr",
    "HeapFree":       "win_heap",
    "LocalFree":      "win_heap",
    "GlobalFree":     "win_heap",
    "CoTaskMemFree":  "com_heap",
    "SysFreeString":  "bstr",
}

# ── 3.2 Reference-count manipulation patterns ─────────────────────────────────

_REFCOUNT_INC_RE = re.compile(
    r"^(?:"
    r"g_object_ref|Py_INCREF|CFRetain|AddRef"
    r"|intrusive_ptr_add_ref|boost_intrusive_ptr_add_ref"
    r"|refcount_inc|ref_inc|retain"
    r")$",
)

_REFCOUNT_DEC_RE = re.compile(
    r"^(?:"
    r"g_object_unref|Py_DECREF|CFRelease|Release"
    r"|intrusive_ptr_release|boost_intrusive_ptr_release"
    r"|refcount_dec|ref_dec|release"
    r")$",
)

# ── 3.3 RAII / smart-pointer identifiers ─────────────────────────────────────

_SMART_PTR_RE = re.compile(
    r"^(?:"
    r"unique_ptr|shared_ptr|weak_ptr|auto_ptr"
    r"|scoped_ptr|intrusive_ptr"           # Boost
    r"|CComPtr|CComQIPtr"                  # ATL
    r"|winrt::com_ptr"
    r"|std::unique_ptr|std::shared_ptr|std::weak_ptr"
    r")$",
)

# ── 3.4 Special member function name patterns ─────────────────────────────────

# Recognized patterns for destructor, copy ctor, copy assign, move ctor,
# move assign — detected syntactically from token sequences.

# Name prefixes that strongly suggest "this is a destructor"
_DESTRUCTOR_RE = re.compile(r"^~")

# Operator names for copy/move assignment
_COPY_ASSIGN_RE = re.compile(r"^operator=$")
_MOVE_ASSIGN_RE = re.compile(r"^operator=$")   # same name; context differs

# ── 3.5 Raw-pointer member variable name heuristic ────────────────────────────

_OWNING_PTR_NAME_RE = re.compile(
    r"(?:ptr|pointer|buf|buffer|data|mem|array|heap|alloc|obj|resource)",
    re.IGNORECASE,
)

# ── 3.6 C++ source file extensions ───────────────────────────────────────────

_CPP_EXTS: FrozenSet[str] = frozenset({
    ".cpp", ".cxx", ".cc", ".C", ".c++", ".hpp", ".hxx", ".hh", ".H",
})


def _is_cpp_file(path: str) -> bool:
    import os
    _, ext = os.path.splitext(path)
    return ext in _CPP_EXTS


# ══════════════════════════════════════════════════════════════════════════════
# § 4 — Diagnostic data class and emitter
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class Diagnostic:
    filename: str
    line:     int
    col:      int
    severity: str
    message:  str
    error_id: str
    cwe:      int


def _emit(diag: Diagnostic) -> None:
    if _CLI_MODE:
        sys.stdout.write(
            json.dumps({
                "file":     diag.filename,
                "line":     diag.line,
                "column":   diag.col,
                "severity": diag.severity,
                "message":  diag.message,
                "id":       diag.error_id,
                "cwe":      diag.cwe,
            }) + "\n"
        )
        sys.stdout.flush()
    else:
        sys.stderr.write(
            f"[{diag.filename}:{diag.line}]: "
            f"({diag.severity}) {diag.message} [{diag.error_id}]\n"
        )


# ══════════════════════════════════════════════════════════════════════════════
# § 5 — Base checker
# ══════════════════════════════════════════════════════════════════════════════

class _BaseChecker:
    def __init__(self) -> None:
        self._seen: Set[Tuple[str, int, str]] = set()

    def _report(
        self,
        tok,
        fallback: str,
        severity: str,
        message: str,
        error_id: str,
        cwe: int,
    ) -> Optional[Diagnostic]:
        key = (_tok_file(tok, fallback), _tok_linenr(tok), error_id)
        if key in self._seen:
            return None
        self._seen.add(key)
        return Diagnostic(
            filename=_tok_file(tok, fallback),
            line=_tok_linenr(tok),
            col=_tok_col(tok),
            severity=severity,
            message=message,
            error_id=error_id,
            cwe=cwe,
        )

    def check(self, cfg, fallback_file: str) -> Iterator[Diagnostic]:
        raise NotImplementedError


# ══════════════════════════════════════════════════════════════════════════════
# § 6 — Allocation event data structures
#
#  These are populated by a shared pre-pass over each function scope and
#  consumed by the individual checkers.  Keeping the pre-pass separate means
#  we scan each function's token list exactly once.
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class AllocEvent:
    """One call to an allocation function."""
    var_name:   str            # LHS variable name (empty if result discarded)
    allocator:  str            # e.g. "malloc", "new", "new[]"
    family:     str            # e.g. "c_heap", "cpp_new"
    tok:        object         # the allocation token (for location)


@dataclass
class FreeEvent:
    """One call to a deallocation function."""
    var_name:   str            # argument variable name
    deallocator: str           # e.g. "free", "delete"
    family:     str            # e.g. "c_heap"
    tok:        object


@dataclass
class ScopeAllocs:
    """All allocation / deallocation events in one function scope."""
    allocs: List[AllocEvent] = field(default_factory=list)
    frees:  List[FreeEvent]  = field(default_factory=list)


def _collect_alloc_events(scope, tokenlist: list) -> ScopeAllocs:
    """
    Single-pass collection of AllocEvent and FreeEvent within *scope*.

    Allocation patterns recognised:
      • T *p = malloc(…)          → var_name = "p"
      • T *p = new T(…)           → var_name = "p"
      • T *p = new T[…]           → var_name = "p"  (new[])
      • p = calloc(…)             → var_name = "p"
      • (result discarded)        → var_name = ""

    Deallocation patterns recognised:
      • free(p)                   → var_name = "p"
      • delete p                  → var_name = "p"
      • delete[] p                → var_name = "p"
      • munmap(p, …)              → var_name = "p"
      • HeapFree(heap, 0, p)      → var_name = "p"  (3rd arg)
    """
    result = ScopeAllocs()
    tl     = list(_tokens_in_scope(scope, tokenlist))

    i = 0
    while i < len(tl):
        tok = tl[i]

        # ── Detect allocation calls ────────────────────────────────────────

        if _is_name(tok):

            # ── C-style allocators: malloc / calloc / realloc / strdup … ──
            if tok.str in _ALLOC_TO_FREE and tok.str not in ("new", "new[]"):
                family, _ = _ALLOC_TO_FREE[tok.str]
                paren = _open_paren_after(tok)
                if paren is not None:
                    var = _lhs_of_assignment(tok)
                    result.allocs.append(
                        AllocEvent(
                            var_name=var,
                            allocator=tok.str,
                            family=family,
                            tok=tok,
                        )
                    )

            # ── C++ new / new[] ───────────────────────────────────────────
            elif tok.str == "new":
                # new[]  →  "new" followed by optional type then '['
                # We peek two tokens ahead to decide scalar vs array
                is_array = _peek_new_is_array(tok)
                allocator = "new[]" if is_array else "new"
                family    = _ALLOC_TO_FREE[allocator][0]
                var       = _lhs_of_assignment(tok)
                result.allocs.append(
                    AllocEvent(
                        var_name=var,
                        allocator=allocator,
                        family=family,
                        tok=tok,
                    )
                )

            # ── C-style free ──────────────────────────────────────────────
            elif tok.str == "free":
                paren = _open_paren_after(tok)
                if paren is not None:
                    arg = _first_arg(paren)
                    var = arg.str if (arg is not None and _is_name(arg)) else ""
                    result.frees.append(
                        FreeEvent(
                            var_name=var,
                            deallocator="free",
                            family="c_heap",
                            tok=tok,
                        )
                    )

            # ── munmap ────────────────────────────────────────────────────
            elif tok.str == "munmap":
                paren = _open_paren_after(tok)
                if paren is not None:
                    arg = _first_arg(paren)
                    var = arg.str if (arg is not None and _is_name(arg)) else ""
                    result.frees.append(
                        FreeEvent(
                            var_name=var,
                            deallocator="munmap",
                            family="mmap",
                            tok=tok,
                        )
                    )

            # ── Windows HeapFree(heap, flags, ptr) ───────────────────────
            elif tok.str in ("HeapFree", "LocalFree", "GlobalFree", "CoTaskMemFree"):
                paren = _open_paren_after(tok)
                if paren is not None:
                    # ptr is 3rd arg for HeapFree, 1st for the others
                    pos = 2 if tok.str == "HeapFree" else 0
                    arg = _nth_arg(paren, pos)
                    var = arg.str if (arg is not None and _is_name(arg)) else ""
                    fam = _FREE_FAMILIES.get(tok.str, "win_heap")
                    result.frees.append(
                        FreeEvent(
                            var_name=var,
                            deallocator=tok.str,
                            family=fam,
                            tok=tok,
                        )
                    )

            # ── SysFreeString ─────────────────────────────────────────────
            elif tok.str == "SysFreeString":
                paren = _open_paren_after(tok)
                if paren is not None:
                    arg = _first_arg(paren)
                    var = arg.str if (arg is not None and _is_name(arg)) else ""
                    result.frees.append(
                        FreeEvent(
                            var_name=var,
                            deallocator="SysFreeString",
                            family="bstr",
                            tok=tok,
                        )
                    )

        # ── delete / delete[] — keyword tokens ────────────────────────────
        if _is_name(tok) and tok.str == "delete":
            nxt = _next_tok(tok)
            is_array_delete = False
            if nxt is not None and nxt.str == "[":
                close = _next_tok(nxt)
                if close is not None and close.str == "]":
                    is_array_delete = True
                    nxt = _next_tok(close)   # skip past ']'

            # nxt should now be the pointer being deleted
            if nxt is not None and _is_name(nxt):
                result.frees.append(
                    FreeEvent(
                        var_name=nxt.str,
                        deallocator="delete[]" if is_array_delete else "delete",
                        family="cpp_new_arr" if is_array_delete else "cpp_new",
                        tok=tok,
                    )
                )

        i += 1

    return result


def _lhs_of_assignment(alloc_tok) -> str:
    """
    Given the token of an allocator call, walk backwards over
    '= <type-tokens>*' to find the variable name on the left-hand side.

    Returns the name string, or "" if none is found.
    """
    # Walk backwards: alloc_tok ← '(' ← alloc_name ← '=' ← var_name
    prev = _prev_tok(alloc_tok)
    if prev is None:
        return ""
    # Skip over '(' if we're actually at the alloc name with paren already matched
    if prev.str == "=":
        lhs = _prev_tok(prev)
        if lhs is not None and _is_name(lhs):
            return lhs.str
    # Maybe: T *var = new …  → walk left past any type qualifiers
    # We look two hops back for '='
    if prev is not None:
        prev2 = _prev_tok(prev)
        if prev2 is not None and prev2.str == "=":
            lhs = _prev_tok(prev2)
            if lhs is not None and _is_name(lhs):
                return lhs.str
        # Handle: T *var = malloc — prev is the identifier, prev2 is '='
        if _is_name(prev):
            prev3 = _prev_tok(prev)
            if prev3 is not None and prev3.str == "=":
                return prev.str
    return ""


def _peek_new_is_array(new_tok) -> bool:
    """
    Return True if this 'new' expression is 'new T[…]' (array form).
    Heuristic: within the next 6 tokens, does '[' appear before '(' or ';'?
    """
    t   = _next_tok(new_tok)
    hop = 0
    while t is not None and hop < 8:
        if t.str == "[":
            return True
        if t.str in ("(", ";", ")", ","):
            return False
        t   = _next_tok(t)
        hop += 1
    return False


# ══════════════════════════════════════════════════════════════════════════════
# § 7 — PLT-01 : Memory leak — allocated but never freed  (CWE-401)
# ══════════════════════════════════════════════════════════════════════════════

class MemoryLeakChecker(_BaseChecker):
    """
    Within each function scope, every named allocation must have at least
    one corresponding deallocation of the same variable name.

    Known limitations:
      • If a variable is freed in a called helper function we cannot see
        that; this would be a false positive.  The checker therefore
        suppresses the warning when any free() / delete appears in the
        same scope at all AND the variable name is a common generic name
        ("p", "ptr", "buf", "data") — reducing but not eliminating FPs.
      • Conditional / early-return paths are not modelled.
    """

    _GENERIC_NAMES: FrozenSet[str] = frozenset({
        "p", "ptr", "buf", "data", "mem", "block",
        "addr", "tmp", "temp", "result", "ret",
    })

    def check(self, cfg, fallback_file: str) -> Iterator[Diagnostic]:
        for scope in cfg.scopes:
            if scope.type != "Function":
                continue
            try:
                yield from self._check_scope(scope, cfg.tokenlist, fallback_file)
            except Exception as exc:
                sys.stderr.write(
                    f"MemoryLeakChecker: error in scope: {exc}\n"
                )

    def _check_scope(self, scope, tokenlist, fallback_file: str) -> Iterator[Diagnostic]:
        sa = _collect_alloc_events(scope, tokenlist)

        # Map var_name → list[AllocEvent]
        alloc_map: Dict[str, List[AllocEvent]] = {}
        for ev in sa.allocs:
            if ev.var_name:
                alloc_map.setdefault(ev.var_name, []).append(ev)

        if not alloc_map:
            return

        # Set of freed variable names
        freed_names: Set[str] = {ev.var_name for ev in sa.frees if ev.var_name}

        # If the scope contains any smart-pointer usage we reduce sensitivity:
        # RAII objects may own the memory.
        has_smart_ptr = _scope_has_smart_ptr(scope, tokenlist)

        for var, evs in alloc_map.items():
            if var in freed_names:
                continue    # at least one deallocation found
            if has_smart_ptr and var in self._GENERIC_NAMES:
                continue    # too risky to flag with RAII in play
            # Flag the first allocation site
            ev = evs[0]
            diag = self._report(
                ev.tok, fallback_file,
                severity="warning",
                message=(
                    f"Memory allocated with '{ev.allocator}' into '{var}' "
                    f"has no corresponding deallocation in this function — "
                    f"possible memory leak (CWE-401)"
                ),
                error_id="PLT-01",
                cwe=401,
            )
            if diag:
                yield diag


def _scope_has_smart_ptr(scope, tokenlist: list) -> bool:
    """Return True if any smart-pointer type name appears in this scope."""
    for tok in _tokens_in_scope(scope, tokenlist):
        if _is_name(tok) and _SMART_PTR_RE.match(tok.str):
            return True
    return False


# ══════════════════════════════════════════════════════════════════════════════
# § 8 — PLT-02 : Mismatched allocator/deallocator  (CWE-762)
# ══════════════════════════════════════════════════════════════════════════════

class MismatchedAllocFreeChecker(_BaseChecker):
    """
    Detects when a variable is allocated with one family and freed with a
    different family within the same function scope.

    Examples of mismatches:
      • malloc … delete          (c_heap  vs cpp_new)
      • new    … free            (cpp_new vs c_heap)
      • new[]  … delete          (cpp_new_arr vs cpp_new)
      • new    … delete[]        (cpp_new vs cpp_new_arr)
      • mmap   … free            (mmap vs c_heap)
    """

    def check(self, cfg, fallback_file: str) -> Iterator[Diagnostic]:
        for scope in cfg.scopes:
            if scope.type != "Function":
                continue
            try:
                yield from self._check_scope(scope, cfg.tokenlist, fallback_file)
            except Exception as exc:
                sys.stderr.write(
                    f"MismatchedAllocFreeChecker: error in scope: {exc}\n"
                )

    def _check_scope(self, scope, tokenlist, fallback_file: str) -> Iterator[Diagnostic]:
        sa = _collect_alloc_events(scope, tokenlist)

        # Build: var_name → last AllocEvent (most recent wins for the var)
        last_alloc: Dict[str, AllocEvent] = {}
        for ev in sa.allocs:
            if ev.var_name:
                last_alloc[ev.var_name] = ev

        for free_ev in sa.frees:
            vname = free_ev.var_name
            if not vname or vname not in last_alloc:
                continue
            alloc_ev = last_alloc[vname]
            if alloc_ev.family == free_ev.family:
                continue   # correct pair
            diag = self._report(
                free_ev.tok, fallback_file,
                severity="error",
                message=(
                    f"Variable '{vname}' allocated with "
                    f"'{alloc_ev.allocator}' (family '{alloc_ev.family}') "
                    f"but deallocated with '{free_ev.deallocator}' "
                    f"(family '{free_ev.family}') — "
                    f"mismatched allocator/deallocator (CWE-762)"
                ),
                error_id="PLT-02",
                cwe=762,
            )
            if diag:
                yield diag


# ══════════════════════════════════════════════════════════════════════════════
# § 9 — PLT-03 : Reference count not decremented on all paths  (CWE-401)
# ══════════════════════════════════════════════════════════════════════════════

class RefCountChecker(_BaseChecker):
    """
    Within a function scope, if a reference-count increment is found but NO
    corresponding decrement appears anywhere in the same scope, flag it.

    Rationale:
      A function that increments a reference count is almost always responsible
      for decrementing it either directly or by handing ownership to a data
      structure that owns the decrement.  When neither pattern is visible in
      the same scope, it is a strong signal of a ref-count leak.

    Conservative suppression:
      • If the incremented object is returned from the function, ownership
        is transferred; we suppress the warning (single 'return' token after
        the inc call involving the same variable name).
    """

    def check(self, cfg, fallback_file: str) -> Iterator[Diagnostic]:
        for scope in cfg.scopes:
            if scope.type != "Function":
                continue
            try:
                yield from self._check_scope(scope, cfg.tokenlist, fallback_file)
            except Exception as exc:
                sys.stderr.write(
                    f"RefCountChecker: error in scope: {exc}\n"
                )

    def _check_scope(self, scope, tokenlist, fallback_file: str) -> Iterator[Diagnostic]:
        tl = list(_tokens_in_scope(scope, tokenlist))

        # Collect increments: function(obj) → obj name
        increments: List[Tuple[str, object]] = []  # (var_name, tok)
        decrements: Set[str] = set()
        returns:    Set[str] = set()

        i = 0
        while i < len(tl):
            tok = tl[i]

            if _is_name(tok):
                # ── increment call ────────────────────────────────────────
                if _REFCOUNT_INC_RE.match(tok.str):
                    paren = _open_paren_after(tok)
                    if paren is not None:
                        arg = _first_arg(paren)
                        if arg is not None and _is_name(arg):
                            increments.append((arg.str, tok))

                # ── decrement call ────────────────────────────────────────
                elif _REFCOUNT_DEC_RE.match(tok.str):
                    paren = _open_paren_after(tok)
                    if paren is not None:
                        arg = _first_arg(paren)
                        if arg is not None and _is_name(arg):
                            decrements.add(arg.str)

                # ── return <var> ──────────────────────────────────────────
                elif tok.str == "return":
                    ret_val = _next_tok(tok)
                    if ret_val is not None and _is_name(ret_val):
                        returns.add(ret_val.str)

            i += 1

        for var, inc_tok in increments:
            if var in decrements:
                continue   # balanced
            if var in returns:
                continue   # ownership transferred via return
            diag = self._report(
                inc_tok, fallback_file,
                severity="warning",
                message=(
                    f"Reference count for '{var}' is incremented but "
                    f"never decremented in this function — "
                    f"possible reference-count leak (CWE-401)"
                ),
                error_id="PLT-03",
                cwe=401,
            )
            if diag:
                yield diag


# ══════════════════════════════════════════════════════════════════════════════
# § 10 — Class-level analysis helpers
#
#  Checks PLT-04 through PLT-06 all operate on a Class/Struct scope.
#  We extract a ClassInfo summary once per class scope.
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class ClassInfo:
    """Structural summary of a class scope."""
    name:              str
    scope:             object           # the Scope object
    has_destructor:    bool = False
    has_copy_ctor:     bool = False
    has_copy_assign:   bool = False
    has_move_ctor:     bool = False
    has_move_assign:   bool = False
    has_raw_ptr_member: bool = False    # pointer member matching heuristic
    has_smart_ptr_member: bool = False
    destructor_tok:    Optional[object] = None  # token to anchor reports


def _extract_class_info(scope, tokenlist: list) -> Optional[ClassInfo]:
    """
    Parse the token stream within a Class or Struct scope to extract
    the ClassInfo summary.

    We only scan the *direct* tokens of the class body (not nested classes).
    Nested function bodies are identified by tracking brace depth.
    """
    if scope.type not in ("Class", "Struct"):
        return None

    try:
        class_name = scope.className if scope.className else "<anonymous>"
    except AttributeError:
        class_name = "<anonymous>"

    info = ClassInfo(name=class_name, scope=scope)

    tl = list(_tokens_in_scope(scope, tokenlist))

    # We need to suppress tokens that belong to nested scopes (method bodies).
    # Strategy: track brace depth; only examine tokens at depth 0 or 1.
    # (depth 0 = class scope itself; depth 1 = single method signature level)
    brace_depth = 0

    i = 0
    while i < len(tl):
        tok = tl[i]

        if tok.str == "{":
            brace_depth += 1
            i += 1
            continue
        if tok.str == "}":
            brace_depth -= 1
            i += 1
            continue

        # Only examine at outer class level (depth <= 1 to catch signatures)
        if brace_depth > 1:
            i += 1
            continue

        # ── Detect destructor ──────────────────────────────────────────────
        if _is_op(tok) and tok.str == "~":
            nxt = _next_tok(tok)
            if nxt is not None and _is_name(nxt) and nxt.str == class_name:
                info.has_destructor = True
                info.destructor_tok = tok

        # ── Detect copy constructor: ClassName(const ClassName &…) ────────
        if _is_name(tok) and tok.str == class_name:
            # Look for: ClassName ( const ClassName &
            # or:       ClassName ( ClassName const &
            p1 = _next_tok(tok)
            if p1 is not None and p1.str == "(":
                # Scan the first few tokens of the parameter list
                inner = _scan_ctor_params(p1)
                if inner == "copy":
                    info.has_copy_ctor = True
                elif inner == "move":
                    info.has_move_ctor = True

        # ── Detect copy/move assignment: operator=(const ClassName &) ─────
        if _is_name(tok) and tok.str == "operator":
            nxt = _next_tok(tok)
            if nxt is not None and nxt.str == "=":
                paren = _next_tok(nxt)
                if paren is not None and paren.str == "(":
                    inner = _scan_assign_params(paren, class_name)
                    if inner == "copy":
                        info.has_copy_assign = True
                    elif inner == "move":
                        info.has_move_assign = True

        # ── Detect raw pointer member variable declarations ────────────────
        # Heuristic: '*' at class body depth (0-1) preceded by a type name
        # and followed by an identifier matching _OWNING_PTR_NAME_RE.
        if _is_op(tok) and tok.str == "*" and brace_depth <= 1:
            nxt = _next_tok(tok)
            if (
                nxt is not None
                and _is_name(nxt)
                and _OWNING_PTR_NAME_RE.search(nxt.str)
            ):
                info.has_raw_ptr_member = True

        # ── Detect smart pointer member declarations ───────────────────────
        if _is_name(tok) and _SMART_PTR_RE.match(tok.str):
            info.has_smart_ptr_member = True

        i += 1

    return info


def _scan_ctor_params(open_paren_tok) -> str:
    """
    Examine the first few tokens of a constructor parameter list and return:
      "copy"  if it looks like ClassName(const ClassName &…)
      "move"  if it looks like ClassName(ClassName &&…)
      ""      otherwise
    """
    args = list(_walk_args(open_paren_tok))
    if not args:
        return ""

    tokens = [a.str for a in args[:8]]   # first 8 tokens of the param list

    # Move: T ( T && )  or  T ( T &&name )
    if "&&" in tokens:
        return "move"
    # Copy: T ( const T & )  or  T ( T const & )
    if "&" in tokens:
        return "copy"
    return ""


def _scan_assign_params(open_paren_tok, class_name: str) -> str:
    """
    Return "copy" or "move" for an operator=() parameter list.
    """
    args = list(_walk_args(open_paren_tok))
    if not args:
        return ""
    tokens = [a.str for a in args[:8]]
    if "&&" in tokens:
        return "move"
    if "&" in tokens:
        return "copy"
    return ""


# ══════════════════════════════════════════════════════════════════════════════
# § 11 — PLT-04 : Class without destructor holds raw-owning pointer  (CWE-401)
# ══════════════════════════════════════════════════════════════════════════════

class MissingDestructorChecker(_BaseChecker):
    """
    If a class/struct has a raw-pointer member (heuristic: '*identifier'
    where the identifier name suggests ownership) and NO user-defined
    destructor, the class will leak that memory.

    Suppressed when:
      • A smart-pointer member is also present (likely manages the resource).
      • The class name starts with '_' (internal/implementation detail).
    """

    def check(self, cfg, fallback_file: str) -> Iterator[Diagnostic]:
        for scope in cfg.scopes:
            if scope.type not in ("Class", "Struct"):
                continue
            try:
                yield from self._check_class(scope, cfg.tokenlist, fallback_file)
            except Exception as exc:
                sys.stderr.write(
                    f"MissingDestructorChecker: error in class scope: {exc}\n"
                )

    def _check_class(self, scope, tokenlist, fallback_file: str) -> Iterator[Diagnostic]:
        info = _extract_class_info(scope, tokenlist)
        if info is None:
            return
        if info.name.startswith("_"):
            return   # skip internal/private types
        if not info.has_raw_ptr_member:
            return
        if info.has_smart_ptr_member:
            return   # RAII already in use
        if info.has_destructor:
            return   # destructor present

        # Anchor the diagnostic on bodyStart of the class scope
        tok = scope.bodyStart
        diag = self._report(
            tok, fallback_file,
            severity="warning",
            message=(
                f"Class '{info.name}' has a raw-pointer member that "
                f"appears to own heap memory but no user-defined destructor "
                f"— the allocated memory will not be freed when the object "
                f"is destroyed (CWE-401)"
            ),
            error_id="PLT-04",
            cwe=401,
        )
        if diag:
            yield diag


# ══════════════════════════════════════════════════════════════════════════════
# § 12 — PLT-05 : Rule of Three violated  (CWE-401)
#
# "If a class defines any of: destructor, copy constructor, copy assignment
#  operator, it should explicitly define all three."
#                                                    — Effective C++, Item 6
# ══════════════════════════════════════════════════════════════════════════════

class RuleOfThreeChecker(_BaseChecker):
    """
    Checks that whenever a class defines a destructor, it also defines both
    the copy constructor and copy assignment operator — and vice versa.

    Suppressed when smart-pointer members are present (compiler-generated
    copy operations are usually safe in that case).
    """

    def check(self, cfg, fallback_file: str) -> Iterator[Diagnostic]:
        for scope in cfg.scopes:
            if scope.type not in ("Class", "Struct"):
                continue
            try:
                yield from self._check_class(scope, cfg.tokenlist, fallback_file)
            except Exception as exc:
                sys.stderr.write(
                    f"RuleOfThreeChecker: error in class scope: {exc}\n"
                )

    def _check_class(self, scope, tokenlist, fallback_file: str) -> Iterator[Diagnostic]:
        info = _extract_class_info(scope, tokenlist)
        if info is None:
            return
        if info.name.startswith("_"):
            return
        if info.has_smart_ptr_member:
            return

        rule_of_three_members = [
            info.has_destructor,
            info.has_copy_ctor,
            info.has_copy_assign,
        ]

        # Only fire when at least one is present but not all three
        count = sum(rule_of_three_members)
        if count == 0 or count == 3:
            return

        tok = info.destructor_tok or scope.bodyStart
        missing = []
        if not info.has_destructor:
            missing.append("destructor")
        if not info.has_copy_ctor:
            missing.append("copy constructor")
        if not info.has_copy_assign:
            missing.append("copy assignment operator")

        diag = self._report(
            tok, fallback_file,
            severity="warning",
            message=(
                f"Class '{info.name}' defines some but not all Rule-of-Three "
                f"special members; missing: {', '.join(missing)} — "
                f"compiler-generated copies may cause double-free or "
                f"shallow-copy bugs (CWE-401)"
            ),
            error_id="PLT-05",
            cwe=401,
        )
        if diag:
            yield diag


# ══════════════════════════════════════════════════════════════════════════════
# § 13 — PLT-06 : Rule of Five violated  (C++11, CWE-401)
#
# "If a class defines any of the five special members (destructor, copy ctor,
#  copy assign, move ctor, move assign), it should define all five."
#                                           — C++ Core Guidelines C.21
# ══════════════════════════════════════════════════════════════════════════════

class RuleOfFiveChecker(_BaseChecker):
    """
    Checks that when Rule-of-Three members are present, the move constructor
    and move assignment operator are also defined.

    Move-only types (only move ctor / move assign, no copy) are excluded.
    We only fire when:
      • At least one of {destructor, copy ctor, copy assign} is present, AND
      • move constructor or move assignment operator is absent.

    Restricted to C++ files.
    """

    def check(self, cfg, fallback_file: str) -> Iterator[Diagnostic]:
        if not _is_cpp_file(fallback_file):
            return   # Rule of Five is a C++ concern only
        for scope in cfg.scopes:
            if scope.type not in ("Class", "Struct"):
                continue
            try:
                yield from self._check_class(scope, cfg.tokenlist, fallback_file)
            except Exception as exc:
                sys.stderr.write(
                    f"RuleOfFiveChecker: error in class scope: {exc}\n"
                )

    def _check_class(self, scope, tokenlist, fallback_file: str) -> Iterator[Diagnostic]:
        info = _extract_class_info(scope, tokenlist)
        if info is None:
            return
        if info.name.startswith("_"):
            return

        has_rule3 = any([info.has_destructor, info.has_copy_ctor, info.has_copy_assign])
        if not has_rule3:
            return

        missing_move = []
        if not info.has_move_ctor:
            missing_move.append("move constructor")
        if not info.has_move_assign:
            missing_move.append("move assignment operator")

        if not missing_move:
            return   # all five present

        tok = info.destructor_tok or scope.bodyStart
        diag = self._report(
            tok, fallback_file,
            severity="style",
            message=(
                f"Class '{info.name}' defines Rule-of-Three members but is "
                f"missing: {', '.join(missing_move)} — "
                f"without move operations the compiler may generate "
                f"inefficient or incorrect moves in C++11 and later "
                f"(C++ Core Guideline C.21, CWE-401)"
            ),
            error_id="PLT-06",
            cwe=401,
        )
        if diag:
            yield diag


# ══════════════════════════════════════════════════════════════════════════════
# § 14 — PLT-07 : RAII opportunity — raw malloc/free in C++ function  (CWE-401)
# ══════════════════════════════════════════════════════════════════════════════

class RAIIOpportunityChecker(_BaseChecker):
    """
    In a C++ source file, whenever a function-scope uses malloc/calloc/realloc
    (C allocators) and a matching free(), suggest replacing with
    std::unique_ptr or a RAII guard.

    This is a style/best-practice check; we emit severity "style".

    We only flag when:
      • The file is C++ (determined from extension).
      • The function has at least one C-heap alloc AND at least one free.
      • No smart-pointer type appears in the same scope (already RAII).
    """

    _C_ALLOCATORS: FrozenSet[str] = frozenset({
        "malloc", "calloc", "realloc",
        "aligned_alloc", "memalign", "strdup", "strndup",
    })

    def check(self, cfg, fallback_file: str) -> Iterator[Diagnostic]:
        if not _is_cpp_file(fallback_file):
            return
        for scope in cfg.scopes:
            if scope.type != "Function":
                continue
            try:
                yield from self._check_scope(scope, cfg.tokenlist, fallback_file)
            except Exception as exc:
                sys.stderr.write(
                    f"RAIIOpportunityChecker: error in scope: {exc}\n"
                )

    def _check_scope(self, scope, tokenlist, fallback_file: str) -> Iterator[Diagnostic]:
        if _scope_has_smart_ptr(scope, tokenlist):
            return   # already using RAII

        sa = _collect_alloc_events(scope, tokenlist)

        c_allocs = [
            ev for ev in sa.allocs
            if ev.allocator in self._C_ALLOCATORS
        ]
        if not c_allocs:
            return

        c_frees = [ev for ev in sa.frees if ev.family == "c_heap"]
        if not c_frees:
            return

        # Emit one diagnostic per unique allocator call site
        for ev in c_allocs:
            diag = self._report(
                ev.tok, fallback_file,
                severity="style",
                message=(
                    f"C-style '{ev.allocator}()' used in C++ function — "
                    f"consider replacing with std::unique_ptr<> or a RAII "
                    f"wrapper to guarantee deallocation on all exit paths "
                    f"(CWE-401)"
                ),
                error_id="PLT-07",
                cwe=401,
            )
            if diag:
                yield diag


# ══════════════════════════════════════════════════════════════════════════════
# § 15 — Entry point
# ══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    if len(sys.argv) < 2:
        sys.stderr.write(
            "Usage: PointerLifetimeTracker.py <file.dump> [--cli]\n"
        )
        sys.exit(1)

    dump_file = sys.argv[1]

    try:
        data = cppcheckdata.parsedump(dump_file)
    except Exception as exc:
        sys.stderr.write(
            f"PointerLifetimeTracker: failed to parse '{dump_file}': {exc}\n"
        )
        sys.exit(1)

    checkers: List[_BaseChecker] = [
        MemoryLeakChecker(),            # PLT-01  CWE-401
        MismatchedAllocFreeChecker(),   # PLT-02  CWE-762
        RefCountChecker(),              # PLT-03  CWE-401
        MissingDestructorChecker(),     # PLT-04  CWE-401
        RuleOfThreeChecker(),           # PLT-05  CWE-401
        RuleOfFiveChecker(),            # PLT-06  CWE-401
        RAIIOpportunityChecker(),       # PLT-07  CWE-401
    ]

    for cfg in data.configurations:
        fallback_file = cfg.tokenlist[0].file if cfg.tokenlist else dump_file

        for checker in checkers:
            try:
                for diag in checker.check(cfg, fallback_file):
                    _emit(diag)
            except Exception as exc:
                sys.stderr.write(
                    f"PointerLifetimeTracker: {checker.__class__.__name__} "
                    f"raised an unexpected error: {exc}\n"
                )


if __name__ == "__main__":
    main()
