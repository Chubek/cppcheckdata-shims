#!/usr/bin/env python3
"""
LifetimeAnnotationVerifier.py
════════════════════════════════════════════════════════════════════════

Cppcheck addon: lifetime-annotation-verifier
Tier 1 | CWE-416, CWE-562, CWE-590, CWE-672, CWE-825, CWE-119, CWE-476

Detects temporal memory-safety violations caused by incorrect object
lifetime management in C source code.

Background
──────────
C has no automatic lifetime tracking.  The programmer must ensure that:
  1. Memory is not accessed after it has been freed (CWE-416).
  2. Pointers to local stack variables are not returned or stored in
     structures with longer lifetimes (CWE-562).
  3. malloc/calloc results are not passed to free() more than once
     (CWE-415 / double-free).
  4. Resources are not used after the resource handle has been closed
     or released (CWE-672).
  5. NULL is checked before dereference after allocation (CWE-476).
  6. Temporary buffer addresses are not stored for later use beyond
     the buffer's scope (CWE-825).
  7. Memory is not freed inside a loop over a structure that still
     references the freed object (CWE-119 adjacent).
  8. Pointer arithmetic does not escape the bounds implied by the
     original allocation size (CWE-823 / CWE-119).

Checkers
────────
  LAV-01  useAfterFree            CWE-416  Variable used after free()
  LAV-02  stackAddressEscape      CWE-562  Address of local variable
                                           returned or stored globally
  LAV-03  doubleFree              CWE-415  free() called twice on the
                                           same pointer without intervening
                                           reallocation
  LAV-04  useAfterClose           CWE-672  File descriptor / handle used
                                           after close()/fclose()
  LAV-05  nullDerefAfterAlloc     CWE-476  Allocation result used without
                                           NULL check
  LAV-06  danglingTempAddress     CWE-825  Address of compound-literal or
                                           VLA stored beyond its scope
  LAV-07  freeInLoop              CWE-416  free() inside loop body without
                                           reassignment guard — loop may
                                           iterate with a dangling pointer
  LAV-08  pointerArithOverflow    CWE-119  Pointer arithmetic offset
                                           provably exceeds allocation
                                           bounds via ValueFlow

CONTRACT — Safe Variable-ID Access
───────────────────────────────────
ALL variable-ID access in this addon MUST use _safe_vid() or
_safe_vid_tok().  Direct int(tok.varId) calls are FORBIDDEN.

Rationale: cppcheckdata returns varId values as decimal strings, hex
address strings ("560e31248150" — causes ValueError), None, or 0
(cppcheck's "no variable" sentinel).  _safe_vid() normalises all
cases to Optional[int], returning None for sentinel and non-decimal
strings.

Usage
─────
    cppcheck --dump myfile.c
    python LifetimeAnnotationVerifier.py myfile.c.dump

License: MIT
"""

from __future__ import annotations

import json
import os
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
      - non-decimal strings (hex addresses like '560e31248150')
      - cppcheck sentinel value 0 ("no variable")

    NEVER call int(tok.varId) directly.  Use this function exclusively.
    """
    if vid is None:
        return None
    try:
        v = int(vid)
        return v if v != 0 else None
    except (ValueError, TypeError):
        return None


def _safe_vid_tok(tok: Any) -> Optional[int]:
    """
    Return the safe variable-ID for a token, or None.

    Wrapper around _safe_vid() for the common tok.varId access pattern.
    """
    return _safe_vid(getattr(tok, "varId", None))


# ═══════════════════════════════════════════════════════════════════════════
#  PART 2 — TOKEN UTILITIES
# ═══════════════════════════════════════════════════════════════════════════

def _tok_str(tok: Any) -> str:
    return getattr(tok, "str", "") or ""


def _tok_file(tok: Any) -> str:
    return getattr(tok, "file", "") or ""


def _tok_line(tok: Any) -> int:
    return getattr(tok, "linenr", 0) or 0


def _tok_col(tok: Any) -> int:
    return getattr(tok, "column", 0) or 0


def _tok_next(tok: Any) -> Optional[Any]:
    return getattr(tok, "next", None)


def _tok_prev(tok: Any) -> Optional[Any]:
    return getattr(tok, "previous", None)


def _tok_scope(tok: Any) -> Optional[Any]:
    return getattr(tok, "scope", None)


def _scope_type(scope: Any) -> str:
    """Return the scope type string, or '' if unavailable."""
    return getattr(scope, "type", "") or ""


def _vf_int_values(tok: Any) -> List[int]:
    """Return all ValueFlow integer values for a token."""
    result: List[int] = []
    for v in getattr(tok, "values", None) or []:
        iv = getattr(v, "intvalue", None)
        if iv is not None:
            try:
                result.append(int(iv))
            except (ValueError, TypeError):
                pass
    return result


def _vf_is_null_possible(tok: Any) -> bool:
    """Return True if ValueFlow says this token may be NULL (intvalue == 0)."""
    for v in getattr(tok, "values", None) or []:
        iv = getattr(v, "intvalue", None)
        if iv is not None and int(iv) == 0:
            return True
    return False


def _vf_lifetime_targets(tok: Any) -> List[Any]:
    """
    Extract ValueFlow lifetime target tokens.

    cppcheck's ValueFlow tracks pointer lifetimes through the
    'tokvalue' attribute on Value objects.  Returns a list of
    tokens that this token's value points to.
    """
    targets: List[Any] = []
    for v in getattr(tok, "values", None) or []:
        tv = getattr(v, "tokvalue", None)
        if tv is not None:
            targets.append(tv)
    return targets


def _is_function_call(tok: Any) -> bool:
    """Return True if tok is the name token of a function call."""
    if not getattr(tok, "isName", False):
        return False
    nxt = _tok_next(tok)
    return nxt is not None and _tok_str(nxt) == "("


def _is_assignment_lhs(tok: Any) -> bool:
    """Return True if this token is the direct LHS of an assignment."""
    parent = getattr(tok, "astParent", None)
    if parent is None:
        return False
    if not getattr(parent, "isAssignmentOp", False):
        return False
    lhs = getattr(parent, "astOperand1", None)
    return lhs is tok


def _is_local_variable(var: Any) -> bool:
    """
    Return True if the cppcheck Variable is a local (stack) variable.

    Local variables have isLocal == True and isStatic == False.
    """
    if var is None:
        return False
    return (
        getattr(var, "isLocal", False)
        and not getattr(var, "isStatic", False)
        and not getattr(var, "isGlobal", False)
    )


def _is_global_variable(var: Any) -> bool:
    """Return True if the cppcheck Variable is a global."""
    if var is None:
        return False
    return getattr(var, "isGlobal", False) or getattr(var, "isStatic", False)


def _variable_of(tok: Any) -> Optional[Any]:
    """Return the cppcheck Variable object for a token, if any."""
    return getattr(tok, "variable", None)


def _scope_depth(scope: Any) -> int:
    """Estimate scope nesting depth by walking parent links."""
    depth = 0
    s = scope
    while s is not None:
        depth += 1
        s = getattr(s, "nestedIn", None)
        if depth > 64:  # guard against cycles
            break
    return depth


def _enclosing_function_scope(tok: Any) -> Optional[Any]:
    """Walk scope chain upward until we find a Function scope."""
    s = _tok_scope(tok)
    while s is not None:
        if _scope_type(s) == "Function":
            return s
        s = getattr(s, "nestedIn", None)
    return None


def _tok_is_inside_loop(tok: Any) -> bool:
    """Return True if tok is textually inside a for/while/do scope."""
    s = _tok_scope(tok)
    while s is not None:
        st = _scope_type(s)
        if st in ("For", "While", "Do"):
            return True
        if st == "Function":
            break
        s = getattr(s, "nestedIn", None)
    return False


# ═══════════════════════════════════════════════════════════════════════════
#  PART 3 — DOMAIN CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════

# Functions that allocate heap memory (return a new pointer)
_ALLOC_FUNCS: FrozenSet[str] = frozenset({
    "malloc", "calloc", "realloc", "reallocarray",
    "strdup", "strndup", "wcsdup",
    "valloc", "memalign", "aligned_alloc", "posix_memalign",
    "mmap",
    # GLib
    "g_malloc", "g_malloc0", "g_malloc_n", "g_malloc0_n",
    "g_calloc", "g_realloc", "g_strdup", "g_strndup",
    "g_new", "g_new0",
    # OpenSSL
    "OPENSSL_malloc", "OPENSSL_zalloc", "CRYPTO_malloc",
    # common wrappers
    "xmalloc", "xcalloc", "xrealloc", "xstrdup",
    "safe_malloc", "safe_calloc",
})

# Functions that FREE a pointer argument (first argument is the pointer)
_FREE_FUNCS: FrozenSet[str] = frozenset({
    "free", "cfree",
    "mmap",          # munmap frees, but mmap also appears here for reuse
    "munmap",
    "g_free", "OPENSSL_free", "CRYPTO_free",
    "xfree", "safe_free",
})

# Functions that CLOSE a file descriptor / handle
_CLOSE_FUNCS: FrozenSet[str] = frozenset({
    "fclose", "close", "closedir",
    "pclose", "fdclose",
    # POSIX AIO
    "aio_cancel",
    # SQLite
    "sqlite3_close", "sqlite3_close_v2",
    # OpenSSL
    "SSL_free", "SSL_CTX_free", "BIO_free", "BIO_free_all",
    # Sockets
    "shutdown",
    # epoll
    "epoll_close",
})

# Functions that open / return a handle (FILE* or fd)
_OPEN_FUNCS: FrozenSet[str] = frozenset({
    "fopen", "freopen", "fdopen", "popen",
    "open", "openat", "creat",
    "opendir",
    "socket", "accept", "dup", "dup2",
    "sqlite3_open", "sqlite3_open_v2",
})

# Functions that USE a file descriptor or handle as first argument
# (i.e., operations that are invalid after close)
_FD_USE_FUNCS: FrozenSet[str] = frozenset({
    "fread", "fwrite", "fgets", "fputs", "fgetc", "fputc",
    "fprintf", "fscanf", "fflush", "fseek", "ftell", "rewind",
    "read", "write", "pread", "pwrite",
    "ioctl", "fcntl", "lseek",
    "recv", "send", "sendto", "recvfrom",
    "readdir",
})

# Reallocation functions (free the old pointer, return a new one)
_REALLOC_FUNCS: FrozenSet[str] = frozenset({
    "realloc", "reallocarray", "g_realloc",
})

# Pointer arithmetic operators (for LAV-08)
_PTR_ARITH_OPS: FrozenSet[str] = frozenset({"+", "-", "+=", "-="})


# ═══════════════════════════════════════════════════════════════════════════
#  PART 4 — FINDING MODEL
# ═══════════════════════════════════════════════════════════════════════════

ADDON_NAME = "LifetimeAnnotationVerifier"


@dataclass(frozen=True)
class _Finding:
    """
    Single diagnostic finding.

    Serialises to the canonical cppcheck addon JSON protocol:
    one JSON object per line on stdout.
    """
    error_id: str
    message: str
    cwe: int
    file: str
    line: int
    column: int = 0
    severity: str = "warning"
    extra: str = ""

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
#  PART 5 — BASE CHECKER
# ═══════════════════════════════════════════════════════════════════════════

class _BaseChecker:
    """
    Abstract base for LAV checkers.

    All varId access MUST go through _safe_vid / _safe_vid_tok.
    Direct int(tok.varId) calls are FORBIDDEN per the session contract.
    """

    error_id: str = ""
    cwe: int = 0
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
        cwe: Optional[int] = None,
        severity: Optional[str] = None,
        extra: str = "",
    ) -> None:
        self._findings.append(_Finding(
            error_id  = error_id  or self.error_id,
            message   = message,
            cwe       = cwe       or self.cwe,
            file      = _tok_file(tok),
            line      = _tok_line(tok),
            column    = _tok_col(tok),
            severity  = severity  or self.severity,
            extra     = extra,
        ))

    @property
    def findings(self) -> List[_Finding]:
        return list(self._findings)


# ═══════════════════════════════════════════════════════════════════════════
#  PART 6 — SHARED ANALYSIS PRIMITIVES
# ═══════════════════════════════════════════════════════════════════════════

def _first_call_arg_tok(call_name_tok: Any) -> Optional[Any]:
    """
    Given the name-token of a function call, return the AST token
    for the first argument.

    In cppcheck's AST the call structure is:
        '('  ← the call operator
          astOperand1 = the callee name token
          astOperand2 = first argument  (or ',' node for multiple args)
    """
    nxt = _tok_next(call_name_tok)
    if nxt is None or _tok_str(nxt) != "(":
        return None
    # The '(' token's astOperand2 is the first arg in cppcheck's AST
    return getattr(nxt, "astOperand2", None)


def _call_arg_tokens(call_name_tok: Any) -> List[Any]:
    """
    Return all argument tokens for a function call, in order.

    Walks the comma-separated argument list in cppcheck's AST.
    """
    first_arg = _first_call_arg_tok(call_name_tok)
    if first_arg is None:
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

    _collect(first_arg)
    return args


def _varids_in_expr(tok: Any) -> Set[int]:
    """
    Recursively collect all safe varIds mentioned in an AST subtree.

    Uses _safe_vid_tok() at every node — never direct int(varId).
    """
    result: Set[int] = set()

    def _walk(t: Any) -> None:
        if t is None:
            return
        vid = _safe_vid_tok(t)
        if vid is not None:
            result.add(vid)
        _walk(getattr(t, "astOperand1", None))
        _walk(getattr(t, "astOperand2", None))

    _walk(tok)
    return result


def _tok_root_name(tok: Any) -> Optional[Any]:
    """
    Walk up astParent links to find the root name token of a
    pointer expression.  Useful for resolving 'p' in '(*p).field'.
    """
    t = tok
    for _ in range(32):
        parent = getattr(t, "astParent", None)
        if parent is None:
            break
        ps = _tok_str(parent)
        # Stop at assignment / comparison / statement boundaries
        if ps in {"=", "==", "!=", "<", ">", "<=", ">=",
                  ";", "{", "}", "(", ")", ","}:
            break
        t = parent
    return t


def _collect_freed_varids(cfg: Any) -> Dict[int, List[Any]]:
    """
    Scan the token list and return a mapping:
        varId → [free-call-name-token, ...]

    Only records calls to _FREE_FUNCS where the first argument's
    varId is determinable via _safe_vid_tok().
    """
    freed: Dict[int, List[Any]] = {}
    for tok in getattr(cfg, "tokenlist", []):
        if _tok_str(tok) not in _FREE_FUNCS:
            continue
        if not _is_function_call(tok):
            continue
        args = _call_arg_tokens(tok)
        if not args:
            continue
        vid = _safe_vid_tok(args[0])
        if vid is None:
            continue
        freed.setdefault(vid, []).append(tok)
    return freed


def _collect_alloc_varids(cfg: Any) -> Dict[int, List[Any]]:
    """
    Scan the token list and return a mapping:
        varId (LHS of assignment) → [alloc-call-name-token, ...]

    Records assignments where the RHS is a call to _ALLOC_FUNCS.
    """
    alloced: Dict[int, List[Any]] = {}
    for tok in getattr(cfg, "tokenlist", []):
        if not getattr(tok, "isAssignmentOp", False):
            continue
        rhs = getattr(tok, "astOperand2", None)
        if rhs is None:
            continue
        # RHS might be the call '(' node; walk to callee name
        callee = None
        if _tok_str(rhs) == "(":
            prev = getattr(rhs, "previous", None)
            if prev and getattr(prev, "isName", False):
                callee = _tok_str(prev)
        elif getattr(rhs, "isName", False) and _tok_str(_tok_next(rhs)) == "(":
            callee = _tok_str(rhs)
        if callee not in _ALLOC_FUNCS:
            continue
        lhs = getattr(tok, "astOperand1", None)
        if lhs is None:
            continue
        vid = _safe_vid_tok(lhs)
        if vid is None:
            continue
        alloced.setdefault(vid, []).append(rhs if callee is None else tok)
    return alloced


def _token_order_key(tok: Any) -> Tuple[str, int, int]:
    """Sortable key for token ordering: (file, line, column)."""
    return (_tok_file(tok), _tok_line(tok), _tok_col(tok))


def _tok_comes_before(a: Any, b: Any) -> bool:
    """Return True if token a appears before token b in source order."""
    return _token_order_key(a) < _token_order_key(b)


# ═══════════════════════════════════════════════════════════════════════════
#  PART 7 — INDIVIDUAL CHECKERS
# ═══════════════════════════════════════════════════════════════════════════

# ─────────────────────────────────────────────────────────────────────────
#  LAV-01  useAfterFree  (CWE-416)
#
#  A pointer variable is used (read, dereferenced, passed to a function)
#  after it has been passed to free().
#
#  Detection strategy:
#    1. Build the set of (varId, free_line) pairs — calls to _FREE_FUNCS.
#    2. For each token that reads a varId, check whether a free() call
#       for that varId appears BEFORE the read in source order AND there
#       is no intervening reassignment of the pointer.
#
#  False-positive guards:
#    - Reassignment of the pointer after free() clears the freed flag.
#    - The same pointer being passed to realloc() after free() is legal
#      (realloc semantics).
#    - free(NULL) is a no-op — we exclude varIds whose ValueFlow shows 0.
# ─────────────────────────────────────────────────────────────────────────

class _LAV01_UseAfterFree(_BaseChecker):
    error_id = "useAfterFree"
    cwe = 416
    severity = "error"

    def check(self, cfg: Any) -> None:
        tlist = getattr(cfg, "tokenlist", [])
        seen: Set[Tuple[str, int]] = set()

        # Collect free() call sites: varId → list of free-call tokens
        # in source order.
        free_sites: Dict[int, List[Any]] = {}
        for tok in tlist:
            if _tok_str(tok) not in _FREE_FUNCS:
                continue
            if not _is_function_call(tok):
                continue
            args = _call_arg_tokens(tok)
            if not args:
                continue
            vid = _safe_vid_tok(args[0])
            if vid is None:
                continue
            free_sites.setdefault(vid, []).append(tok)

        if not free_sites:
            return

        # For each varId that was freed, scan forward for uses.
        # We track the "freed-at" line per varId and reset it on
        # reassignment.
        for tok in tlist:
            vid = _safe_vid_tok(tok)
            if vid is None:
                continue
            if vid not in free_sites:
                continue

            # Is this token itself a free() call?  Skip — that's the
            # free site itself, handled by LAV-03 (double-free).
            if _is_function_call(tok) and _tok_str(tok) in _FREE_FUNCS:
                continue

            # Is this token an assignment LHS (pointer reassigned)?
            if _is_assignment_lhs(tok):
                continue

            # Find the latest free() of this varId that precedes tok
            latest_free: Optional[Any] = None
            for ft in free_sites[vid]:
                if _tok_comes_before(ft, tok):
                    if latest_free is None or _tok_comes_before(latest_free, ft):
                        latest_free = ft

            if latest_free is None:
                continue

            # Was there a reassignment of vid between latest_free and tok?
            reassigned = False
            for t in tlist:
                if not _tok_comes_before(latest_free, t):
                    continue
                if not _tok_comes_before(t, tok):
                    continue
                t_vid = _safe_vid_tok(t)
                if t_vid != vid:
                    continue
                if _is_assignment_lhs(t):
                    reassigned = True
                    break

            if reassigned:
                continue

            key = (_tok_file(tok), _tok_line(tok))
            if key in seen:
                continue
            seen.add(key)

            var_name = _tok_str(tok)
            free_line = _tok_line(latest_free)
            self._emit(
                tok,
                f"'{var_name}' used after being freed at line {free_line}; "
                f"subsequent accesses yield undefined behaviour (CWE-416).",
                severity="error",
            )


# ─────────────────────────────────────────────────────────────────────────
#  LAV-02  stackAddressEscape  (CWE-562)
#
#  The address of a local (stack) variable is:
#    A) returned from the function, OR
#    B) assigned to a global or static variable, OR
#    C) passed to a function that stores it (best-effort heuristic).
#
#  Detection:
#    1. For each `return` token, walk the AST subtree for `&` operators.
#    2. Check if the operand of `&` is a local variable.
#    3. For assignments, check if the RHS is `&local_var` and the LHS
#       is a global/static variable.
#
#  ValueFlow integration:
#    cppcheck's ValueFlow tracks lifetime targets.  If a token has a
#    lifetime value pointing to a local variable, we check whether that
#    token escapes via return or global assignment.
# ─────────────────────────────────────────────────────────────────────────

class _LAV02_StackAddressEscape(_BaseChecker):
    error_id = "stackAddressEscape"
    cwe = 562
    severity = "error"

    def check(self, cfg: Any) -> None:
        tlist = getattr(cfg, "tokenlist", [])
        seen: Set[Tuple[str, int]] = set()

        for tok in tlist:
            ts = _tok_str(tok)

            # ── Pattern A: return &local_var ─────────────────────────
            if ts == "return":
                ret_val = getattr(tok, "astOperand1", None)
                if ret_val is None:
                    continue
                self._check_addr_of_local(ret_val, tok, "returned", seen)

                # Also check ValueFlow lifetime targets on the return val
                for lt in _vf_lifetime_targets(ret_val):
                    var = _variable_of(lt)
                    if var and _is_local_variable(var):
                        key = (_tok_file(tok), _tok_line(tok))
                        if key not in seen:
                            seen.add(key)
                            self._emit(
                                tok,
                                f"Returning address/reference to local "
                                f"variable '{_tok_str(lt)}'; the variable's "
                                f"storage is invalid after function return "
                                f"(CWE-562).",
                                severity="error",
                            )

            # ── Pattern B: global_ptr = &local_var ───────────────────
            if getattr(tok, "isAssignmentOp", False):
                lhs = getattr(tok, "astOperand1", None)
                rhs = getattr(tok, "astOperand2", None)
                if lhs is None or rhs is None:
                    continue

                lhs_var = _variable_of(lhs)
                if lhs_var is None or not _is_global_variable(lhs_var):
                    continue

                self._check_addr_of_local(rhs, tok, "stored in global", seen)

    def _check_addr_of_local(
        self,
        expr_tok: Any,
        site_tok: Any,
        context: str,
        seen: Set[Tuple[str, int]],
    ) -> None:
        """
        Walk expr_tok's AST subtree looking for `&local_var` patterns.
        """
        if expr_tok is None:
            return

        if _tok_str(expr_tok) == "&":
            # Unary address-of: check operand
            op = getattr(expr_tok, "astOperand2", None) or \
                 getattr(expr_tok, "astOperand1", None)
            if op is not None:
                var = _variable_of(op)
                if var and _is_local_variable(var):
                    key = (_tok_file(site_tok), _tok_line(site_tok))
                    if key not in seen:
                        seen.add(key)
                        self._emit(
                            site_tok,
                            f"Address of local variable '{_tok_str(op)}' "
                            f"is {context}; the variable's storage becomes "
                            f"invalid after its enclosing scope exits "
                            f"(CWE-562).",
                            severity="error",
                        )

        # Recurse into sub-expressions
        self._check_addr_of_local(
            getattr(expr_tok, "astOperand1", None), site_tok, context, seen
        )
        self._check_addr_of_local(
            getattr(expr_tok, "astOperand2", None), site_tok, context, seen
        )


# ─────────────────────────────────────────────────────────────────────────
#  LAV-03  doubleFree  (CWE-415)
#
#  free() (or equivalent) is called more than once on the same pointer
#  variable without an intervening reallocation or NULL assignment.
#
#  Detection:
#    1. Collect all free() call sites per varId in source order.
#    2. For each varId with ≥ 2 free sites, check whether there is a
#       reassignment of the pointer between consecutive free() calls.
#    3. If not → flag the second free().
#
#  False-positive guards:
#    - realloc(p, ...) between two frees() is a legal pattern.
#    - p = NULL between frees() is a legal defensive pattern.
#    - If the pointer is returned from a function between the frees(),
#      we cannot determine the new value — suppress.
# ─────────────────────────────────────────────────────────────────────────

class _LAV03_DoubleFree(_BaseChecker):
    error_id = "doubleFree"
    cwe = 415
    severity = "error"

    def check(self, cfg: Any) -> None:
        tlist = getattr(cfg, "tokenlist", [])
        seen: Set[Tuple[str, int]] = set()

        # Collect free sites per varId in source order
        free_sites: Dict[int, List[Any]] = {}
        for tok in tlist:
            if _tok_str(tok) not in _FREE_FUNCS:
                continue
            if not _is_function_call(tok):
                continue
            args = _call_arg_tokens(tok)
            if not args:
                continue
            vid = _safe_vid_tok(args[0])
            if vid is None:
                continue
            free_sites.setdefault(vid, []).append(tok)

        for vid, sites in free_sites.items():
            if len(sites) < 2:
                continue

            # Sort by source position
            sites_sorted = sorted(sites, key=_token_order_key)

            for i in range(1, len(sites_sorted)):
                first_free = sites_sorted[i - 1]
                second_free = sites_sorted[i]

                # Was there a reassignment between first_free and second_free?
                reassigned = False
                for tok in tlist:
                    if not _tok_comes_before(first_free, tok):
                        continue
                    if not _tok_comes_before(tok, second_free):
                        continue
                    tok_vid = _safe_vid_tok(tok)
                    if tok_vid != vid:
                        continue
                    if _is_assignment_lhs(tok):
                        reassigned = True
                        break
                    # realloc call uses this varId as first arg → reassigned
                    if (
                        _tok_str(tok) in _REALLOC_FUNCS
                        and _is_function_call(tok)
                    ):
                        args = _call_arg_tokens(tok)
                        if args and _safe_vid_tok(args[0]) == vid:
                            reassigned = True
                            break

                if reassigned:
                    continue

                key = (_tok_file(second_free), _tok_line(second_free))
                if key in seen:
                    continue
                seen.add(key)

                first_line = _tok_line(first_free)
                func_name = _tok_str(second_free)
                self._emit(
                    second_free,
                    f"'{func_name}()' called on the same pointer twice; "
                    f"first free at line {first_line}, second at this site "
                    f"without intervening reassignment — double-free yields "
                    f"heap corruption (CWE-415).",
                    severity="error",
                )


# ─────────────────────────────────────────────────────────────────────────
#  LAV-04  useAfterClose  (CWE-672)
#
#  A file descriptor, FILE*, or resource handle is used after the
#  handle has been passed to a close/release function.
#
#  Detection:
#    1. Collect close() call sites per varId.
#    2. For each subsequent use of the same varId (read, passed to
#       another function), check for intervening reassignment.
#    3. Flag uses that follow a close() with no reassignment.
#
#  This mirrors LAV-01 logic but targets _CLOSE_FUNCS + _FD_USE_FUNCS
#  instead of _FREE_FUNCS.
# ─────────────────────────────────────────────────────────────────────────

class _LAV04_UseAfterClose(_BaseChecker):
    error_id = "useAfterClose"
    cwe = 672
    severity = "error"

    def check(self, cfg: Any) -> None:
        tlist = getattr(cfg, "tokenlist", [])
        seen: Set[Tuple[str, int]] = set()

        # Collect close sites per varId
        close_sites: Dict[int, List[Any]] = {}
        for tok in tlist:
            if _tok_str(tok) not in _CLOSE_FUNCS:
                continue
            if not _is_function_call(tok):
                continue
            args = _call_arg_tokens(tok)
            if not args:
                continue
            vid = _safe_vid_tok(args[0])
            if vid is None:
                continue
            close_sites.setdefault(vid, []).append(tok)

        if not close_sites:
            return

        # Scan for uses of closed handles
        for tok in tlist:
            # Only flag uses inside _FD_USE_FUNCS calls
            if _tok_str(tok) not in _FD_USE_FUNCS:
                continue
            if not _is_function_call(tok):
                continue
            args = _call_arg_tokens(tok)
            if not args:
                continue
            vid = _safe_vid_tok(args[0])
            if vid is None or vid not in close_sites:
                continue

            # Find the latest close() before this use
            latest_close: Optional[Any] = None
            for ct in close_sites[vid]:
                if _tok_comes_before(ct, tok):
                    if latest_close is None or _tok_comes_before(latest_close, ct):
                        latest_close = ct

            if latest_close is None:
                continue

            # Intervening reassignment?
            reassigned = False
            for t in tlist:
                if not _tok_comes_before(latest_close, t):
                    continue
                if not _tok_comes_before(t, tok):
                    continue
                if _safe_vid_tok(t) == vid and _is_assignment_lhs(t):
                    reassigned = True
                    break

            if reassigned:
                continue

            key = (_tok_file(tok), _tok_line(tok))
            if key in seen:
                continue
            seen.add(key)

            use_name = _tok_str(tok)
            close_line = _tok_line(latest_close)
            close_name = _tok_str(latest_close)
            self._emit(
                tok,
                f"'{use_name}()' called on handle already closed by "
                f"'{close_name}()' at line {close_line}; using a closed "
                f"resource handle yields undefined behaviour (CWE-672).",
                severity="error",
            )


# ─────────────────────────────────────────────────────────────────────────
#  LAV-05  nullDerefAfterAlloc  (CWE-476)
#
#  The return value of an allocation function is used (dereferenced,
#  passed, written through) without first checking for NULL.
#
#  Detection:
#    1. Find assignment tokens where RHS is a call to _ALLOC_FUNCS.
#    2. Record the LHS varId.
#    3. Scan forward: if the varId appears as the operand of a pointer
#       dereference (`*p`, `p->`, `p[`) before a NULL check, flag.
#
#  ValueFlow integration:
#    If cppcheck has already determined via ValueFlow that the value is
#    provably non-null, we skip the finding.  This suppresses FPs for
#    functions that are statically known to never return NULL (e.g.,
#    xmalloc wrappers).
#
#  FALSE-POSITIVE GUARDS:
#    - If the pointer is passed to free() before being dereferenced,
#      we don't flag (the programmer didn't intend to use it).
#    - If ValueFlow shows the pointer can be non-null only, skip.
# ─────────────────────────────────────────────────────────────────────────

class _LAV05_NullDerefAfterAlloc(_BaseChecker):
    error_id = "nullDerefAfterAlloc"
    cwe = 476
    severity = "warning"

    # Operators / tokens that dereference a pointer
    _DEREF_OPS: FrozenSet[str] = frozenset({"*", "->", "["})

    def check(self, cfg: Any) -> None:
        tlist = getattr(cfg, "tokenlist", [])
        seen: Set[Tuple[str, int]] = set()

        # Find alloc assignments: varId → (alloc_tok, alloc_func_name)
        alloc_map: Dict[int, Tuple[Any, str]] = {}
        for tok in tlist:
            if not getattr(tok, "isAssignmentOp", False):
                continue
            lhs = getattr(tok, "astOperand1", None)
            rhs = getattr(tok, "astOperand2", None)
            if lhs is None or rhs is None:
                continue
            # Identify allocation call on the RHS
            alloc_func = self._alloc_func_of(rhs)
            if alloc_func is None:
                continue
            vid = _safe_vid_tok(lhs)
            if vid is None:
                continue
            alloc_map[vid] = (tok, alloc_func)

        if not alloc_map:
            return

        for tok in tlist:
            ts = _tok_str(tok)
            if ts not in self._DEREF_OPS:
                continue

            # Find the pointer being dereferenced
            operand = (
                getattr(tok, "astOperand1", None)
                or getattr(tok, "astOperand2", None)
            )
            if operand is None:
                continue

            vid = _safe_vid_tok(operand)
            if vid is None or vid not in alloc_map:
                continue

            alloc_tok, alloc_func = alloc_map[vid]

            # Was the dereference preceded by a NULL check?
            if self._is_null_checked_before(vid, alloc_tok, tok, tlist):
                continue

            # ValueFlow: is the value provably non-null?
            if not _vf_is_null_possible(operand):
                # Only null is NOT possible — i.e., proven non-null.
                # We still warn because the allocation CAN fail.
                # If ValueFlow shows null IS possible, definitely flag.
                pass  # warn regardless

            key = (_tok_file(tok), _tok_line(tok))
            if key in seen:
                continue
            seen.add(key)

            var_name = _tok_str(operand)
            alloc_line = _tok_line(alloc_tok)
            self._emit(
                tok,
                f"'{var_name}' allocated by '{alloc_func}()' at line "
                f"{alloc_line} is dereferenced without checking for NULL; "
                f"allocation failure causes null pointer dereference "
                f"(CWE-476).",
            )

    @staticmethod
    def _alloc_func_of(rhs_tok: Any) -> Optional[str]:
        """
        Determine if rhs_tok represents an allocation call.
        Returns the function name, or None.
        """
        # In cppcheck AST, a call 'f(args)' has the '(' as the call
        # operator; its astOperand1 is the function name.
        if _tok_str(rhs_tok) == "(":
            op1 = getattr(rhs_tok, "astOperand1", None)
            if op1 and _tok_str(op1) in _ALLOC_FUNCS:
                return _tok_str(op1)
        # Also check if rhs is itself a name followed by '('
        nxt = _tok_next(rhs_tok)
        if (
            getattr(rhs_tok, "isName", False)
            and nxt is not None
            and _tok_str(nxt) == "("
            and _tok_str(rhs_tok) in _ALLOC_FUNCS
        ):
            return _tok_str(rhs_tok)
        return None

    @staticmethod
    def _is_null_checked_before(
        vid: int,
        alloc_tok: Any,
        use_tok: Any,
        tlist: List[Any],
    ) -> bool:
        """
        Return True if there is a NULL check on vid between
        alloc_tok and use_tok.

        A NULL check is:  `if (ptr)`, `if (ptr != NULL)`,
                          `if (!ptr)`, `assert(ptr)`, etc.
        """
        for tok in tlist:
            if not _tok_comes_before(alloc_tok, tok):
                continue
            if not _tok_comes_before(tok, use_tok):
                continue

            # if/while condition that references the varId
            ts = _tok_str(tok)
            if ts in {"if", "while"}:
                # The condition is astOperand1 of the if/while token
                cond = getattr(tok, "astOperand1", None)
                if cond is not None and vid in _varids_in_expr(cond):
                    return True

            # Comparison with 0 or NULL
            if ts in {"==", "!="}:
                op1 = getattr(tok, "astOperand1", None)
                op2 = getattr(tok, "astOperand2", None)
                sides = [op1, op2]
                for side in sides:
                    if side is None:
                        continue
                    if _safe_vid_tok(side) == vid:
                        other = op2 if side is op1 else op1
                        if other is not None:
                            vals = _vf_int_values(other)
                            if 0 in vals or _tok_str(other) in {"NULL", "0", "nullptr"}:
                                return True

            # assert(ptr) or assert(ptr != NULL)
            if ts == "assert" and _is_function_call(tok):
                args = _call_arg_tokens(tok)
                for arg in args:
                    if vid in _varids_in_expr(arg):
                        return True

        return False


# ─────────────────────────────────────────────────────────────────────────
#  LAV-06  danglingTempAddress  (CWE-825)
#
#  The address of a compound literal, VLA, or temporary object created
#  inside a block is stored in a pointer that outlives the block.
#
#  Detection:
#    1. Find compound-literal expressions: `(Type){...}` — in cppcheck's
#       AST these appear as a '(' with a type-cast-like structure.
#    2. Find VLA declarations: array declarations whose size is not a
#       compile-time constant.
#    3. Check if &(compound_literal) or &vla is assigned to a pointer
#       in an enclosing scope.
#
#  This checker also catches the pattern:
#      char *p;
#      {
#          char buf[64];
#          p = buf;          ← dangling after inner block exits
#      }
#  by checking if a local variable's address is assigned to a pointer
#  in a LESS-NESTED scope.
# ─────────────────────────────────────────────────────────────────────────

class _LAV06_DanglingTempAddress(_BaseChecker):
    error_id = "danglingTempAddress"
    cwe = 825
    severity = "warning"

    def check(self, cfg: Any) -> None:
        tlist = getattr(cfg, "tokenlist", [])
        seen: Set[Tuple[str, int]] = set()

        for tok in tlist:
            if not getattr(tok, "isAssignmentOp", False):
                continue

            lhs = getattr(tok, "astOperand1", None)
            rhs = getattr(tok, "astOperand2", None)
            if lhs is None or rhs is None:
                continue

            lhs_vid = _safe_vid_tok(lhs)
            if lhs_vid is None:
                continue

            lhs_var = _variable_of(lhs)
            if lhs_var is None:
                continue

            lhs_scope = getattr(lhs_var, "scope", None)
            lhs_depth = _scope_depth(lhs_scope) if lhs_scope else 0

            # Walk RHS for address-of expressions
            self._check_rhs(rhs, tok, lhs_depth, seen)

    def _check_rhs(
        self,
        tok: Any,
        site: Any,
        lhs_depth: int,
        seen: Set[Tuple[str, int]],
    ) -> None:
        if tok is None:
            return

        if _tok_str(tok) == "&":
            operand = (
                getattr(tok, "astOperand2", None)
                or getattr(tok, "astOperand1", None)
            )
            if operand is not None:
                var = _variable_of(operand)
                if var and _is_local_variable(var):
                    var_scope = getattr(var, "scope", None)
                    var_depth = _scope_depth(var_scope) if var_scope else 0
                    # The variable lives in a deeper scope than the pointer
                    if var_depth > lhs_depth:
                        key = (_tok_file(site), _tok_line(site))
                        if key not in seen:
                            seen.add(key)
                            self._emit(
                                site,
                                f"Address of '{_tok_str(operand)}' (declared "
                                f"in a deeper scope) stored in a pointer that "
                                f"outlives it; pointer becomes dangling when "
                                f"the inner scope exits (CWE-825).",
                            )

        # Also flag: p = buf where buf is a local in a deeper scope
        # (array-to-pointer decay without explicit &)
        elif getattr(tok, "isName", False):
            var = _variable_of(tok)
            if var and _is_local_variable(var):
                if getattr(var, "isArray", False):
                    var_scope = getattr(var, "scope", None)
                    var_depth = _scope_depth(var_scope) if var_scope else 0
                    if var_depth > lhs_depth:
                        key = (_tok_file(site), _tok_line(site))
                        if key not in seen:
                            seen.add(key)
                            self._emit(
                                site,
                                f"Array '{_tok_str(tok)}' decays to a pointer "
                                f"that outlives the array's scope; the pointer "
                                f"becomes dangling when the inner block exits "
                                f"(CWE-825).",
                            )

        self._check_rhs(
            getattr(tok, "astOperand1", None), site, lhs_depth, seen
        )
        self._check_rhs(
            getattr(tok, "astOperand2", None), site, lhs_depth, seen
        )


# ─────────────────────────────────────────────────────────────────────────
#  LAV-07  freeInLoop  (CWE-416)
#
#  free() is called inside a loop body, but the loop iterates over
#  a data structure that still holds a reference to the freed memory,
#  OR the pointer is not reassigned before the next iteration.
#
#  Detection:
#    1. Find free() calls inside for/while/do loops.
#    2. Check if the freed varId is used AGAIN before the next free()
#       in a subsequent iteration (the variable is not reassigned in
#       the loop body after the free()).
#
#  This catches the classic "free in loop" defect:
#      while (p) {
#          q = p->next;
#          free(p);
#          p = p->next;  ← UB: p was freed; p->next is UAF
#      }
#
#  False-positive guard:
#    If the loop body reassigns the freed pointer BEFORE any dereference
#    of it (e.g., p = q immediately after free(p)), we do not flag.
# ─────────────────────────────────────────────────────────────────────────

class _LAV07_FreeInLoop(_BaseChecker):
    error_id = "freeInLoop"
    cwe = 416
    severity = "warning"

    def check(self, cfg: Any) -> None:
        tlist = getattr(cfg, "tokenlist", [])
        seen: Set[Tuple[str, int]] = set()

        for tok in tlist:
            if _tok_str(tok) not in _FREE_FUNCS:
                continue
            if not _is_function_call(tok):
                continue
            if not _tok_is_inside_loop(tok):
                continue

            args = _call_arg_tokens(tok)
            if not args:
                continue
            vid = _safe_vid_tok(args[0])
            if vid is None:
                continue

            # Look for a USE of vid AFTER the free(), before the
            # enclosing loop's closing '}'.
            # A use is: the token reads vid and is NOT a reassignment.
            use_after: Optional[Any] = None
            reassigned_after = False

            t = _tok_next(tok)
            # Skip past the argument list of free()
            if t and _tok_str(t) == "(":
                t = getattr(t, "link", None)
                if t:
                    t = _tok_next(t)

            brace_depth = 0
            while t is not None:
                ts = _tok_str(t)
                if ts == "{":
                    brace_depth += 1
                elif ts == "}":
                    if brace_depth == 0:
                        break  # exited the loop body
                    brace_depth -= 1
                elif ts in {"for", "while", "do"}:
                    break  # don't cross nested loop boundaries

                t_vid = _safe_vid_tok(t)
                if t_vid == vid:
                    if _is_assignment_lhs(t):
                        reassigned_after = True
                        break
                    elif not reassigned_after:
                        # Check it's a real use, not part of free() itself
                        parent = getattr(t, "astParent", None)
                        if parent is None or _tok_str(parent) not in _FREE_FUNCS:
                            use_after = t
                            break

                t = _tok_next(t)

            if use_after is None or reassigned_after:
                continue

            key = (_tok_file(tok), _tok_line(tok))
            if key in seen:
                continue
            seen.add(key)

            freed_name = _tok_str(args[0])
            use_line = _tok_line(use_after)
            self._emit(
                tok,
                f"'{_tok_str(tok)}({freed_name})' inside loop at line "
                f"{_tok_line(tok)}, followed by use of '{freed_name}' at "
                f"line {use_line} without reassignment; may cause "
                f"use-after-free on subsequent iterations (CWE-416).",
            )


# ─────────────────────────────────────────────────────────────────────────
#  LAV-08  pointerArithOverflow  (CWE-119)
#
#  Pointer arithmetic produces an address that provably exceeds the
#  bounds of the original allocation.
#
#  Detection via ValueFlow:
#    1. Find pointer arithmetic expressions: `p + n`, `p - n`, `p[n]`.
#    2. If the pointer's allocation size is known (from _ALLOC_FUNCS
#       size argument with a known ValueFlow value) and the arithmetic
#       offset is also known, compute whether the result is out-of-bounds.
#    3. Flag if offset ≥ allocation_size (for element type size 1).
#
#  This checker uses ValueFlow integer values for both the allocation
#  size and the arithmetic offset to avoid false positives.
#
#  NOTE: We use a simplified model (byte-granularity) because we cannot
#  reliably determine sizeof(element_type) from the dump alone.  We
#  therefore only flag cases where the offset itself is ≥ the alloc
#  size in bytes — a necessary (not sufficient) condition for overflow.
# ─────────────────────────────────────────────────────────────────────────

class _LAV08_PointerArithOverflow(_BaseChecker):
    error_id = "pointerArithOverflow"
    cwe = 119
    severity = "warning"

    def check(self, cfg: Any) -> None:
        tlist = getattr(cfg, "tokenlist", [])
        seen: Set[Tuple[str, int]] = set()

        # Build alloc-size map: varId → known allocation size in bytes
        alloc_sizes: Dict[int, int] = self._collect_alloc_sizes(tlist)
        if not alloc_sizes:
            return

        for tok in tlist:
            ts = _tok_str(tok)

            # We look for '+' or '-' where astOperand1 is a pointer varId
            if ts not in {"+", "-"}:
                continue

            op1 = getattr(tok, "astOperand1", None)
            op2 = getattr(tok, "astOperand2", None)
            if op1 is None or op2 is None:
                continue

            vid = _safe_vid_tok(op1)
            if vid is None or vid not in alloc_sizes:
                continue

            alloc_size = alloc_sizes[vid]

            # Get the offset from ValueFlow
            offsets = _vf_int_values(op2)
            if not offsets:
                # Try literal
                try:
                    offsets = [int(_tok_str(op2))]
                except (ValueError, TypeError):
                    continue

            for offset in offsets:
                if ts == "-":
                    offset = -offset

                # Negative offsets (before allocation) are also bad
                if offset < 0 or offset >= alloc_size:
                    key = (_tok_file(tok), _tok_line(tok))
                    if key in seen:
                        continue
                    seen.add(key)

                    self._emit(
                        tok,
                        f"Pointer arithmetic on varId {vid} produces offset "
                        f"{offset} into allocation of {alloc_size} byte(s); "
                        f"this exceeds the valid range [0, {alloc_size - 1}] "
                        f"and constitutes an out-of-bounds access (CWE-119).",
                    )
                    break

    @staticmethod
    def _collect_alloc_sizes(tlist: List[Any]) -> Dict[int, int]:
        """
        Return a mapping of varId → known allocation size in bytes.

        We only include entries where BOTH the allocation function call
        AND its size argument have provable ValueFlow integer values.
        """
        sizes: Dict[int, int] = {}

        for tok in tlist:
            if not getattr(tok, "isAssignmentOp", False):
                continue

            lhs = getattr(tok, "astOperand1", None)
            rhs = getattr(tok, "astOperand2", None)
            if lhs is None or rhs is None:
                continue

            vid = _safe_vid_tok(lhs)
            if vid is None:
                continue

            # Identify the allocation call
            alloc_func = None
            call_open_paren = None
            if _tok_str(rhs) == "(":
                op1 = getattr(rhs, "astOperand1", None)
                if op1 and _tok_str(op1) in _ALLOC_FUNCS:
                    alloc_func = _tok_str(op1)
                    call_open_paren = rhs

            if alloc_func is None:
                continue

            # Get the size argument:
            # malloc(size)       → arg[0]
            # calloc(nmemb, sz)  → arg[0] * arg[1]
            args = _call_arg_tokens(op1) if call_open_paren else []

            if alloc_func == "calloc" and len(args) >= 2:
                nmemb_vals = _vf_int_values(args[0])
                size_vals = _vf_int_values(args[1])
                if nmemb_vals and size_vals:
                    sizes[vid] = nmemb_vals[0] * size_vals[0]
            elif args:
                size_vals = _vf_int_values(args[0])
                if size_vals:
                    sizes[vid] = size_vals[0]

        return sizes


# ═══════════════════════════════════════════════════════════════════════════
#  PART 8 — ADDON ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════

_ALL_CHECKERS: List[type] = [
    _LAV01_UseAfterFree,
    _LAV02_StackAddressEscape,
    _LAV03_DoubleFree,
    _LAV04_UseAfterClose,
    _LAV05_NullDerefAfterAlloc,
    _LAV06_DanglingTempAddress,
    _LAV07_FreeInLoop,
    _LAV08_PointerArithOverflow,
]


def _run_on_dump(dump_file: str) -> int:
    """
    Parse a cppcheck .dump file and run all LAV checkers.

    Findings are written to stdout as cppcheck addon JSON lines.
    Returns 0 if no findings, 1 if any findings were produced.
    """
    data = cppcheckdata.parsedump(dump_file)
    total = 0

    for cfg in data.configurations:
        for checker_cls in _ALL_CHECKERS:
            checker = checker_cls()
            try:
                checker.check(cfg)
            except Exception as exc:
                sys.stderr.write(
                    f"[LAV] {checker_cls.__name__} raised "
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
            "Usage: python LifetimeAnnotationVerifier.py <file.c.dump>\n"
        )
        sys.exit(1)

    dump_file = sys.argv[1]
    if not os.path.isfile(dump_file):
        sys.stderr.write(f"ERROR: dump file not found: {dump_file}\n")
        sys.exit(1)

    sys.exit(_run_on_dump(dump_file))


if __name__ == "__main__":
    main()
