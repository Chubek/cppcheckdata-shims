#!/usr/bin/env python3
"""
ErrnoUsageChecker.py
════════════════════════════════════════════════════════════════════════

Cppcheck addon: errno-usage-checker
Tier 1 | CWE-252, 253, 272, 390, 391, 676, 687, 703

Detects incorrect, dangerous, or unreliable uses of the POSIX errno
facility in C source code.

The errno mechanism is one of the most misused APIs in C:
  - errno is only meaningful immediately after a failing syscall
  - Many callers check errno before checking the return value
  - errno is set to zero at program start but NOT cleared between calls
  - Some functions (strtol, strtod) signal errors ONLY through errno
  - Thread-safety requires errno to be the thread-local macro, not a
    global variable
  - Setting errno to zero manually has legitimate uses (strtol pattern)
    but is often confused with error checking

Checkers
────────
  EUC-01  errnoReadBeforeCheck        CWE-252  errno read before testing
                                               syscall return value
  EUC-02  errnoNotCheckedAfterCall    CWE-391  error-returning function
                                               called without checking
                                               errno OR return value
  EUC-03  errnoAfterStrtolMissing     CWE-253  strtol/strtod family
                                               called without errno check
  EUC-04  errnoOverwrite              CWE-390  errno overwritten by
                                               intervening call before use
  EUC-05  errnoComparedToNegative     CWE-687  errno compared to
                                               negative value (always false)
  EUC-06  errnoUsedAsBoolean          CWE-253  if(errno) used as boolean
                                               — non-portable, misleading
  EUC-07  strerrorNotThreadSafe       CWE-676  strerror() used instead
                                               of strerror_r/strerror_s
  EUC-08  errnoGlobalVariableAccess   CWE-703  direct access of global
                                               `errno` variable instead
                                               of the thread-local macro
                                               (pre-C11 style)

CONTRACT — Safe Variable-ID Access
───────────────────────────────────
ALL variable-ID access in this addon MUST use _safe_vid() or
_safe_vid_tok().  Direct int(tok.varId) calls are FORBIDDEN.

Rationale: cppcheckdata may return varId values as:
  - decimal strings  ("42")
  - hex address strings  ("560e31248150")  ← causes ValueError
  - None
  - 0  (cppcheck's "no variable" sentinel)

_safe_vid() normalises all cases to Optional[int], returning None
for the sentinel and for non-decimal strings.

Usage
─────
    cppcheck --dump myfile.c
    python ErrnoUsageChecker.py myfile.c.dump

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

# ── cppcheckdata import ──────────────────────────────────────────────────
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
      - non-decimal strings (e.g. hex addresses like '560e31248150')
      - cppcheck's sentinel value 0 ("no variable")

    NEVER call int(tok.varId) directly.  Always use this function.
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

    Wrapper around _safe_vid() for the common token access pattern.
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


def _tok_next_str(tok: Any) -> str:
    """Return the string of the next token, or ''."""
    nxt = getattr(tok, "next", None)
    return _tok_str(nxt) if nxt else ""


def _is_assignment_target(tok: Any) -> bool:
    """Return True if this token is the LHS of an assignment."""
    parent = getattr(tok, "astParent", None)
    if parent is None:
        return False
    if not getattr(parent, "isAssignmentOp", False):
        return False
    lhs = getattr(parent, "astOperand1", None)
    return lhs is tok


def _scope_of(tok: Any) -> Any:
    return getattr(tok, "scope", None)


def _tokens_forward(start_tok: Any):
    """Generator: yield tokens starting from start_tok, following .next."""
    t = start_tok
    while t is not None:
        yield t
        t = getattr(t, "next", None)


def _tokens_between(start_tok: Any, end_tok: Any):
    """
    Yield tokens from start_tok up to (but not including) end_tok.
    Both tokens must be linked by .next chains.
    """
    t = start_tok
    while t is not None and t is not end_tok:
        yield t
        t = getattr(t, "next", None)


# ═══════════════════════════════════════════════════════════════════════════
#  PART 3 — DOMAIN CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════

# Functions that SET errno and have a meaningful return value that must
# be checked FIRST before consulting errno.
# Format: name → (return_type_hint, description)
_ERRNO_SETTING_SYSCALLS: FrozenSet[str] = frozenset({
    # POSIX file I/O
    "open", "openat", "creat",
    "read", "write", "pread", "pwrite",
    "close", "lseek", "lseek64",
    "ftruncate", "truncate",
    "stat", "fstat", "lstat",
    "chmod", "fchmod", "chown", "fchown", "lchown",
    "rename", "unlink", "rmdir", "mkdir", "mkdirat",
    "symlink", "readlink", "link",
    "access", "faccessat",
    "getcwd",
    # Memory
    "mmap", "munmap", "mprotect", "mremap",
    "mlock", "munlock",
    # Process
    "fork", "waitpid", "wait", "waitid",
    "kill", "signal", "sigaction",
    "execve", "execvp", "execl", "execlp",
    "getpid", "getppid", "getuid", "geteuid",
    "setuid", "seteuid", "setgid", "setegid",
    "getpwnam", "getpwuid", "getgrnam", "getgrgid",
    # Network
    "socket", "bind", "listen", "accept", "connect",
    "send", "recv", "sendto", "recvfrom",
    "gethostbyname", "getaddrinfo", "freeaddrinfo",
    "setsockopt", "getsockopt",
    "shutdown",
    # stdio (set errno on error, but return EOF / NULL / negative)
    "fopen", "fclose", "fread", "fwrite",
    "fseek", "ftell", "rewind",
    "fputs", "fgets", "fputc", "fgetc",
    "fprintf", "fscanf",
    "remove", "fflush",
    # Memory allocation (set errno = ENOMEM on failure)
    "malloc", "calloc", "realloc", "posix_memalign",
    # Directory
    "opendir", "readdir", "closedir",
    # Time
    "clock_gettime", "clock_settime", "gettimeofday",
    # Misc POSIX
    "dup", "dup2", "pipe", "pipe2",
    "select", "poll", "epoll_wait", "epoll_ctl",
    "ioctl", "fcntl",
    "pthread_create", "pthread_join", "pthread_mutex_lock",
    "pthread_mutex_unlock", "pthread_mutex_trylock",
    "sem_wait", "sem_post", "sem_trywait",
    "nanosleep", "usleep",
    "dlopen", "dlclose", "dlsym",
    "regcomp", "regexec",
})

# Functions that signal errors ONLY through errno — no useful return
# value to check first.  The caller MUST set errno=0 before calling,
# then check errno afterward.
_ERRNO_ONLY_FUNCS: FrozenSet[str] = frozenset({
    "strtol", "strtoll", "strtoul", "strtoull",
    "strtof", "strtod", "strtold",
    "strtoimax", "strtoumax",
    # getenv technically does not set errno but is often confused
    # with the above; we exclude it to avoid FPs.
})

# strerror() is not thread-safe; preferred alternatives follow.
_STRERROR_UNSAFE: FrozenSet[str] = frozenset({"strerror"})
_STRERROR_SAFE: FrozenSet[str] = frozenset({"strerror_r", "strerror_s"})

# Any call that can clobber errno between a syscall and its errno check.
# This is a superset — we include anything that might call into libc.
# We track ALL function calls (any identifier followed by '(') as
# potential errno-clobbering, which is the conservative-correct policy.

# Comparison operators (for EUC-05 / EUC-06 pattern detection)
_CMP_OPS: FrozenSet[str] = frozenset({"==", "!=", "<", ">", "<=", ">="})


# ═══════════════════════════════════════════════════════════════════════════
#  PART 4 — FINDING MODEL
# ═══════════════════════════════════════════════════════════════════════════

ADDON_NAME = "ErrnoUsageChecker"


@dataclass(frozen=True)
class _Finding:
    """
    Single diagnostic finding — serialises to cppcheck addon JSON format.

    Cppcheck addon stdout protocol (one JSON object per line):
    {"file":"...","linenr":N,"column":N,"severity":"...","message":"...",
     "addon":"...","errorId":"...","cwe":N,"extra":""}
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
        """Write a single cppcheck-compatible JSON line to stdout."""
        obj: Dict[str, Any] = {
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
    Minimal abstract base for EUC checkers.

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

def _collect_errno_read_sites(cfg: Any) -> List[Any]:
    """
    Return every token where `errno` is READ (not written).

    A read site is any token with str=="errno" that is NOT the
    LHS of an assignment, and is NOT a direct address-of (&errno).
    """
    sites: List[Any] = []
    for tok in getattr(cfg, "tokenlist", []):
        if _tok_str(tok) != "errno":
            continue
        # Skip writes: errno = ...
        if _is_assignment_target(tok):
            continue
        # Skip &errno (address-of — implementation detail, not a read)
        parent = getattr(tok, "astParent", None)
        if parent and _tok_str(parent) == "&":
            op2 = getattr(parent, "astOperand2", None)
            if op2 is None:  # unary &
                continue
        sites.append(tok)
    return sites


def _collect_errno_write_sites(cfg: Any) -> List[Any]:
    """
    Return every token where `errno` is WRITTEN.

    This includes both `errno = 0` (legitimate pre-strtol pattern)
    and any other assignment.
    """
    sites: List[Any] = []
    for tok in getattr(cfg, "tokenlist", []):
        if _tok_str(tok) != "errno":
            continue
        if _is_assignment_target(tok):
            sites.append(tok)
    return sites


def _is_function_call(tok: Any) -> bool:
    """
    Return True if tok is the name token of a function call.

    Heuristic: tok.str is an identifier, followed by '('
    that is flagged as a function call by cppcheck, OR
    tok has a .function attribute.
    """
    if not getattr(tok, "isName", False):
        return False
    nxt = getattr(tok, "next", None)
    if nxt is None:
        return False
    return _tok_str(nxt) == "("


def _call_name(tok: Any) -> str:
    """
    If tok is the '(' of a call expression, return the callee name.
    If tok is the name token, return its string directly.
    """
    if _tok_str(tok) == "(":
        prev = getattr(tok, "previous", None)
        if prev and getattr(prev, "isName", False):
            return _tok_str(prev)
    if getattr(tok, "isName", False) and _tok_next_str(tok) == "(":
        return _tok_str(tok)
    return ""


def _is_return_value_checked(call_name_tok: Any) -> bool:
    """
    Heuristic: the return value of a call is 'checked' if the call
    appears as:
      - the RHS of an assignment  (ret = call(...))
      - an if/while condition     (if (call(...) < 0))
      - a comparison expression   (call(...) != -1)
      - directly inside if(...)   (if (!call(...)))

    We do NOT flag calls that are passed directly as arguments to
    another function (that would be a separate concern).
    """
    # Walk up the AST from the call's '(' token or the name token
    tok = call_name_tok
    # Advance to the '(' if we're on the name
    if getattr(tok, "isName", False):
        tok = getattr(tok, "next", None)
    if tok is None:
        return False

    # The call expression in cppcheck's AST: the '(' is the root,
    # its astParent is what the result feeds into.
    parent = getattr(tok, "astParent", None)
    if parent is None:
        # Top-level statement — result discarded
        return False

    ps = _tok_str(parent)

    # Assignment: result stored somewhere
    if getattr(parent, "isAssignmentOp", False):
        return True

    # Comparison: result compared to something
    if ps in _CMP_OPS:
        return True

    # Unary ! or ~ (e.g. if (!open(...)))
    if ps in {"!", "~"}:
        return True

    # Ternary ?
    if ps == "?":
        return True

    # Direct operand of if/while condition (parent of parent is if/while)
    grandparent = getattr(parent, "astParent", None)
    if grandparent is not None:
        gps = _tok_str(grandparent)
        if gps in {"if", "while", "for", "do"}:
            return True

    # Part of a boolean expression feeding into if
    if ps in {"&&", "||"}:
        return True

    return False


def _intervening_calls_between(
    start_tok: Any,
    end_tok: Any,
) -> List[str]:
    """
    Return names of function calls between start_tok and end_tok
    (exclusive) that could clobber errno.

    We skip:
      - The call that SET errno (start_tok itself)
      - Pure macro expansions that expand to no syscall
      - errno = 0  (that is an intentional reset, not a clobber)

    We conservatively include ALL identifier-followed-by-'(' sequences
    as potential errno-clobbering calls.
    """
    calls: List[str] = []
    tok = getattr(start_tok, "next", None)
    while tok is not None and tok is not end_tok:
        if _is_function_call(tok):
            name = _tok_str(tok)
            # strerror clobbers errno on some platforms
            # errno = 0 is NOT a function call, skip
            if name and name != "errno":
                calls.append(name)
        tok = getattr(tok, "next", None)
    return calls


# ═══════════════════════════════════════════════════════════════════════════
#  PART 7 — INDIVIDUAL CHECKERS
# ═══════════════════════════════════════════════════════════════════════════

# ─────────────────────────────────────────────────────────────────────────
#  EUC-01  errnoReadBeforeCheck  (CWE-252)
#
#  errno is accessed before the return value of the preceding syscall
#  is tested.  Classic pattern:
#
#    n = read(fd, buf, sz);
#    if (errno == EAGAIN) { ... }    // BUG: should check n first
#
#  Detection:
#    1. Find every errno READ site.
#    2. Walk BACKWARDS from the errno read to find the nearest
#       preceding call to an _ERRNO_SETTING_SYSCALLS member.
#    3. Check whether that call's return value was tested BEFORE
#       the errno read.
#    4. If not → flag.
#
#  False-positive guard:
#    If the return value IS stored/tested, we don't flag even if the
#    test comes AFTER the errno read, because the programmer may be
#    doing a combined check (unusual but legal).
# ─────────────────────────────────────────────────────────────────────────

class _EUC01_ErrnoReadBeforeCheck(_BaseChecker):
    error_id = "errnoReadBeforeCheck"
    cwe = 252
    severity = "warning"

    def check(self, cfg: Any) -> None:
        seen: Set[Tuple[str, int]] = set()

        for tok in getattr(cfg, "tokenlist", []):
            if _tok_str(tok) != "errno":
                continue
            if _is_assignment_target(tok):
                continue  # write, not read

            # Walk backwards to find the nearest preceding syscall
            preceding_call: Optional[Any] = None
            t = getattr(tok, "previous", None)
            depth = 0
            while t is not None:
                s = _tok_str(t)

                # Don't walk across statement/scope boundaries too far
                if s == "{":
                    break

                # Function call name token?
                if _is_function_call(t) and _tok_str(t) in _ERRNO_SETTING_SYSCALLS:
                    preceding_call = t
                    break

                t = getattr(t, "previous", None)

            if preceding_call is None:
                continue

            # Was the return value checked before we hit the errno read?
            if not _is_return_value_checked(preceding_call):
                key = (_tok_file(tok), _tok_line(tok))
                if key in seen:
                    continue
                seen.add(key)

                call_name = _tok_str(preceding_call)
                self._emit(
                    tok,
                    f"errno read after '{call_name}()' without first "
                    f"checking its return value; errno is only meaningful "
                    f"when the call has failed (CWE-252).",
                )


# ─────────────────────────────────────────────────────────────────────────
#  EUC-02  errnoNotCheckedAfterCall  (CWE-391)
#
#  A function that sets errno is called, its return value is discarded
#  (expression statement), and errno is never checked in the same
#  statement sequence before the next call.
#
#  Pattern:
#    close(fd);            // return value AND errno both ignored
#    write(fd2, buf, n);
#
#  We only flag when:
#    - return value not stored/tested
#    - AND no subsequent errno read before the next modifying call
#    - AND not inside a logging/cleanup-only context (best-effort)
# ─────────────────────────────────────────────────────────────────────────

class _EUC02_ErrnoNotCheckedAfterCall(_BaseChecker):
    error_id = "errnoNotCheckedAfterCall"
    cwe = 391
    severity = "style"   # style: not every unchecked call is dangerous

    def check(self, cfg: Any) -> None:
        seen: Set[Tuple[str, int]] = set()

        for tok in getattr(cfg, "tokenlist", []):
            if not _is_function_call(tok):
                continue
            if _tok_str(tok) not in _ERRNO_SETTING_SYSCALLS:
                continue

            # Is the return value used?
            if _is_return_value_checked(tok):
                continue

            # Is errno read between this call and the next modifying call?
            errno_checked_later = False
            next_syscall_tok: Optional[Any] = None

            t = getattr(tok, "next", None)
            # Skip past the argument list
            paren = t
            if paren and _tok_str(paren) == "(":
                paren = getattr(paren, "link", None)
                if paren:
                    t = getattr(paren, "next", None)

            while t is not None:
                ts = _tok_str(t)
                if ts == "errno" and not _is_assignment_target(t):
                    errno_checked_later = True
                    break
                if _is_function_call(t) and _tok_str(t) in _ERRNO_SETTING_SYSCALLS:
                    next_syscall_tok = t
                    break
                if ts == "}":
                    break
                t = getattr(t, "next", None)

            if errno_checked_later:
                continue  # programmer checks errno — OK

            key = (_tok_file(tok), _tok_line(tok))
            if key in seen:
                continue
            seen.add(key)

            self._emit(
                tok,
                f"Return value of '{_tok_str(tok)}()' is not checked and "
                f"errno is not consulted; errors will be silently ignored "
                f"(CWE-391).",
                severity="style",
            )


# ─────────────────────────────────────────────────────────────────────────
#  EUC-03  errnoAfterStrtolMissing  (CWE-253)
#
#  strtol / strtod / strtoul family: the ONLY correct usage is:
#
#    errno = 0;
#    long v = strtol(str, &end, 10);
#    if (errno != 0 || end == str) { /* error */ }
#
#  We flag if:
#    A) errno is not set to 0 before the call, OR
#    B) errno is not read after the call before another call.
# ─────────────────────────────────────────────────────────────────────────

class _EUC03_ErrnoAfterStrtolMissing(_BaseChecker):
    error_id = "errnoAfterStrtolMissing"
    cwe = 253
    severity = "warning"

    def check(self, cfg: Any) -> None:
        seen: Set[Tuple[str, int]] = set()

        for tok in getattr(cfg, "tokenlist", []):
            if _tok_str(tok) not in _ERRNO_ONLY_FUNCS:
                continue
            if not _is_function_call(tok):
                continue

            call_line = _tok_line(tok)
            call_file = _tok_file(tok)

            # ── Check A: was errno = 0 set before this call? ─────────
            errno_cleared = False
            t = getattr(tok, "previous", None)
            while t is not None:
                ts = _tok_str(t)
                if ts == "{":
                    break  # reached start of block without clearing
                if ts == "errno" and _is_assignment_target(t):
                    # Check the RHS is 0
                    parent = getattr(t, "astParent", None)
                    if parent is not None:
                        rhs = getattr(parent, "astOperand2", None)
                        if rhs is not None and _vf_int_values(rhs) == [0]:
                            errno_cleared = True
                            break
                        # Even if we can't ValueFlow-prove it's 0,
                        # any errno assignment before the call is
                        # accepted as an attempt at clearing.
                        if rhs is not None and _tok_str(rhs) == "0":
                            errno_cleared = True
                            break
                t = getattr(t, "previous", None)

            # ── Check B: is errno read after the call? ────────────────
            errno_read_after = False
            t = getattr(tok, "next", None)
            # Skip past arg list
            if t and _tok_str(t) == "(":
                t = getattr(t, "link", None)
                if t:
                    t = getattr(t, "next", None)
            while t is not None:
                ts = _tok_str(t)
                if ts == "errno" and not _is_assignment_target(t):
                    errno_read_after = True
                    break
                # Another call clobbers errno before we check it
                if _is_function_call(t) and _tok_str(t) not in _ERRNO_ONLY_FUNCS:
                    # Some innocent functions (printf, etc.) may clobber
                    # errno; we stop here.
                    break
                if ts == "}":
                    break
                t = getattr(t, "next", None)

            func_name = _tok_str(tok)
            key = (_tok_file(tok), _tok_line(tok))
            if key in seen:
                continue

            if not errno_cleared and not errno_read_after:
                seen.add(key)
                self._emit(
                    tok,
                    f"'{func_name}()' signals errors only through errno; "
                    f"errno was neither cleared to 0 before the call nor "
                    f"checked afterward — conversion errors will be "
                    f"silently missed (CWE-253).",
                )
            elif not errno_cleared:
                seen.add(key)
                self._emit(
                    tok,
                    f"'{func_name}()' requires errno=0 before the call; "
                    f"stale errno from a previous failure may be "
                    f"misinterpreted as a conversion error (CWE-253).",
                )
            elif not errno_read_after:
                seen.add(key)
                self._emit(
                    tok,
                    f"errno is not checked after '{func_name}()'; "
                    f"integer overflow and invalid-input errors will be "
                    f"silently ignored (CWE-253).",
                )


# ─────────────────────────────────────────────────────────────────────────
#  EUC-04  errnoOverwrite  (CWE-390)
#
#  errno is set by a syscall but one or more function calls intervene
#  before the programmer reads errno, potentially overwriting its value.
#
#  Pattern:
#    n = read(fd, buf, sz);
#    if (n < 0) {
#        log_message("read failed");   // ← clobbers errno!
#        fprintf(stderr, "%d", errno); // errno may now reflect log_message
#    }
#
#  Detection:
#    1. Find each errno READ site.
#    2. Walk BACKWARDS to the nearest errno-setting syscall.
#    3. Count function calls between the syscall and the errno read.
#    4. If any intervening call exists → flag.
#
#  False-positive guards:
#    - Allow strerror_r / strerror_s (they save errno or use separate buf)
#    - Allow pure errno reads themselves (not calls)
#    - Do not flag if the errno read is in a compound expression with
#      the return-value check (e.g. n<0 && errno==EINTR on one line)
# ─────────────────────────────────────────────────────────────────────────

class _EUC04_ErrnoOverwrite(_BaseChecker):
    error_id = "errnoOverwrite"
    cwe = 390
    severity = "warning"

    # These calls are guaranteed not to modify errno
    _SAFE_CALLS: FrozenSet[str] = frozenset({
        "strerror_r", "strerror_s",
        # Compiler intrinsics / macros that don't call libc
        "__builtin_expect", "__likely", "__unlikely",
    })

    def check(self, cfg: Any) -> None:
        seen: Set[Tuple[str, int]] = set()

        for errno_tok in _collect_errno_read_sites(cfg):
            # Walk backwards to find the nearest errno-setting syscall
            syscall_tok: Optional[Any] = None
            t = getattr(errno_tok, "previous", None)
            while t is not None:
                ts = _tok_str(t)
                if ts == "{":
                    break
                if _is_function_call(t) and ts in _ERRNO_SETTING_SYSCALLS:
                    syscall_tok = t
                    break
                t = getattr(t, "previous", None)

            if syscall_tok is None:
                continue

            # Are they on the SAME line?  If so, no clobber possible.
            if _tok_line(syscall_tok) == _tok_line(errno_tok):
                continue

            # Collect intervening calls
            clobbers: List[str] = []
            t = getattr(syscall_tok, "next", None)
            # Skip past the syscall's argument list
            if t and _tok_str(t) == "(":
                t = getattr(t, "link", None)
                if t:
                    t = getattr(t, "next", None)

            while t is not None and t is not errno_tok:
                if _is_function_call(t):
                    name = _tok_str(t)
                    if name and name not in self._SAFE_CALLS:
                        clobbers.append(name)
                t = getattr(t, "next", None)

            if not clobbers:
                continue

            key = (_tok_file(errno_tok), _tok_line(errno_tok))
            if key in seen:
                continue
            seen.add(key)

            clobber_list = ", ".join(f"'{c}()'" for c in clobbers[:3])
            if len(clobbers) > 3:
                clobber_list += f" (and {len(clobbers) - 3} more)"

            self._emit(
                errno_tok,
                f"errno may have been overwritten before this read; "
                f"intervening call(s) {clobber_list} can modify errno "
                f"after '{_tok_str(syscall_tok)}()' set it (CWE-390).",
            )


# ─────────────────────────────────────────────────────────────────────────
#  EUC-05  errnoComparedToNegative  (CWE-687)
#
#  errno is an unsigned-or-positive integer in all POSIX implementations.
#  Error values (EAGAIN, ENOMEM, etc.) are all positive.
#  Comparing errno to a negative number is always false.
#
#  Patterns flagged:
#    if (errno < 0)   — always false
#    if (errno == -1) — always false
#    if (errno < -1)  — always false
#
#  This often arises from confusion with syscall return values:
#    if (errno == -1) { ... }   // should be:  if (ret == -1) { ... }
# ─────────────────────────────────────────────────────────────────────────

class _EUC05_ErrnoComparedToNegative(_BaseChecker):
    error_id = "errnoComparedToNegative"
    cwe = 687
    severity = "warning"

    def check(self, cfg: Any) -> None:
        seen: Set[Tuple[str, int]] = set()

        for tok in getattr(cfg, "tokenlist", []):
            if _tok_str(tok) not in _CMP_OPS:
                continue

            op1 = getattr(tok, "astOperand1", None)
            op2 = getattr(tok, "astOperand2", None)
            if op1 is None or op2 is None:
                continue

            # Identify which side is errno and which is the constant
            errno_side: Optional[Any] = None
            const_side: Optional[Any] = None

            if _tok_str(op1) == "errno":
                errno_side = op1
                const_side = op2
            elif _tok_str(op2) == "errno":
                errno_side = op2
                const_side = op1

            if errno_side is None:
                continue

            # Is the constant side provably negative?
            const_vals = _vf_int_values(const_side)
            if not const_vals:
                # Try direct literal check
                s = _tok_str(const_side)
                try:
                    v = int(s)
                    const_vals = [v]
                except (ValueError, TypeError):
                    pass

            neg_vals = [v for v in const_vals if v < 0]
            if not neg_vals:
                continue

            key = (_tok_file(tok), _tok_line(tok))
            if key in seen:
                continue
            seen.add(key)

            op_str = _tok_str(tok)
            example_val = neg_vals[0]
            self._emit(
                tok,
                f"errno compared to negative value {example_val} with "
                f"'{op_str}': errno is always non-negative (POSIX error "
                f"codes are positive integers); this comparison is always "
                f"false (CWE-687).",
            )


# ─────────────────────────────────────────────────────────────────────────
#  EUC-06  errnoUsedAsBoolean  (CWE-253)
#
#  Using errno directly as a boolean condition is non-portable and
#  misleading because:
#    - errno may be non-zero from a PREVIOUS successful call
#    - errno == 0 does NOT mean success (return value must be checked)
#    - Some implementations define errno as (*__errno_location()) which
#      is truthy even when there is no current error
#
#  Flagged patterns:
#    if (errno)          — implicit boolean test
#    while (errno)       — loop on errno
#    return errno;       — returning errno as error indicator
#    assert(!errno)      — asserting errno is zero
# ─────────────────────────────────────────────────────────────────────────

class _EUC06_ErrnoUsedAsBoolean(_BaseChecker):
    error_id = "errnoUsedAsBoolean"
    cwe = 253
    severity = "warning"

    def check(self, cfg: Any) -> None:
        seen: Set[Tuple[str, int]] = set()

        for tok in getattr(cfg, "tokenlist", []):
            if _tok_str(tok) != "errno":
                continue
            if _is_assignment_target(tok):
                continue

            parent = getattr(tok, "astParent", None)
            if parent is None:
                continue

            ps = _tok_str(parent)

            flagged = False
            context = ""

            # Pattern A: if/while/for/do uses errno as the condition directly
            # In cppcheck's AST, `if (errno)` has `if` as parent of `errno`
            if ps in {"if", "while", "for"}:
                cond = getattr(parent, "astOperand1", None)
                if cond is tok:
                    flagged = True
                    context = f"'{ps}' condition"

            # Pattern B: logical NOT: if (!errno) — also misleading
            if ps == "!":
                gp = getattr(parent, "astParent", None)
                if gp and _tok_str(gp) in {"if", "while", "for"}:
                    flagged = True
                    context = "boolean negation in condition"

            # Pattern C: return errno (used as exit code without mapping)
            if ps == "return":
                flagged = True
                context = "return statement"

            if not flagged:
                continue

            key = (_tok_file(tok), _tok_line(tok))
            if key in seen:
                continue
            seen.add(key)

            self._emit(
                tok,
                f"errno used as boolean in {context}: errno may be "
                f"non-zero from a previous call and does not reliably "
                f"indicate the current operation failed; always check "
                f"the function's return value first (CWE-253).",
            )


# ─────────────────────────────────────────────────────────────────────────
#  EUC-07  strerrorNotThreadSafe  (CWE-676)
#
#  strerror() is not thread-safe: it returns a pointer to a static
#  buffer that may be overwritten by another thread's strerror() call.
#
#  Prefer:
#    - strerror_r (POSIX)
#    - strerror_s (C11 Annex K)
#    - perror (writes directly, no shared buffer exposed)
#
#  We also flag strerror() in contexts where thread safety matters
#  (i.e., when pthread_create has been seen in the same file).
#  For simplicity, we flag ALL uses unconditionally with a
#  portability severity, consistent with CERT C MSC24-C.
# ─────────────────────────────────────────────────────────────────────────

class _EUC07_StrerrorNotThreadSafe(_BaseChecker):
    error_id = "strerrorNotThreadSafe"
    cwe = 676
    severity = "portability"

    def check(self, cfg: Any) -> None:
        seen: Set[Tuple[str, int]] = set()

        for tok in getattr(cfg, "tokenlist", []):
            if _tok_str(tok) != "strerror":
                continue
            if not _is_function_call(tok):
                continue

            key = (_tok_file(tok), _tok_line(tok))
            if key in seen:
                continue
            seen.add(key)

            self._emit(
                tok,
                "strerror() returns a pointer to a static buffer that is "
                "not thread-safe; use strerror_r() (POSIX) or strerror_s() "
                "(C11 Annex K) instead (CWE-676).",
                severity="portability",
            )


# ─────────────────────────────────────────────────────────────────────────
#  EUC-08  errnoGlobalVariableAccess  (CWE-703)
#
#  Before C99/POSIX, some implementations exposed errno as a global int:
#    extern int errno;
#  rather than as a thread-local macro.  Direct use of the extern
#  declaration (instead of including <errno.h> and relying on the macro)
#  is non-portable and not thread-safe in multi-threaded programs.
#
#  Detection: look for `extern int errno` or `extern volatile int errno`
#  declaration tokens.
#
#  We also flag code that takes the address of errno: &errno
#  The address is stable for the thread-local macro only on platforms
#  where it expands to (*__errno_location()), but relying on this is
#  non-portable.
# ─────────────────────────────────────────────────────────────────────────

class _EUC08_ErrnoGlobalVariableAccess(_BaseChecker):
    error_id = "errnoGlobalVariableAccess"
    cwe = 703
    severity = "portability"

    def check(self, cfg: Any) -> None:
        seen: Set[Tuple[str, int]] = set()

        for tok in getattr(cfg, "tokenlist", []):
            ts = _tok_str(tok)

            # ── Pattern A: extern int errno declaration ───────────────
            if ts == "extern":
                # Walk forward: extern [volatile] int errno
                t = getattr(tok, "next", None)
                if t and _tok_str(t) == "volatile":
                    t = getattr(t, "next", None)
                if t and _tok_str(t) in {"int", "long"}:
                    t = getattr(t, "next", None)
                    if t and _tok_str(t) == "errno":
                        key = (_tok_file(tok), _tok_line(tok))
                        if key not in seen:
                            seen.add(key)
                            self._emit(
                                tok,
                                "Direct 'extern int errno' declaration is "
                                "non-portable and not thread-safe; include "
                                "<errno.h> and use the errno macro instead "
                                "(CWE-703).",
                                severity="portability",
                            )

            # ── Pattern B: &errno (taking address of errno) ───────────
            if ts == "&":
                # Unary & — operand is the next AST child with no op2
                op1 = getattr(tok, "astOperand1", None)
                op2 = getattr(tok, "astOperand2", None)
                # unary & has op1 = None and op2 = operand in some
                # cppcheck AST layouts; check both
                operand = op2 if op1 is None else None
                if operand is None:
                    # Alternative layout: & is parent of errno
                    # Check if errno is a direct child
                    pass

                # Also check: the previous token was & and current is errno
                prev = getattr(tok, "previous", None)
                if prev and _tok_str(prev) == "&" and ts == "errno":
                    key = (_tok_file(tok), _tok_line(tok))
                    if key not in seen:
                        seen.add(key)
                        self._emit(
                            tok,
                            "Taking the address of errno (&errno) is "
                            "non-portable; errno may be a macro that "
                            "expands to a function call (CWE-703).",
                            severity="portability",
                        )

            # ── Pattern B (AST-based): unary & applied to errno ───────
            if ts == "errno":
                parent = getattr(tok, "astParent", None)
                if parent and _tok_str(parent) == "&":
                    # Confirm unary (no op2 sibling, OR tok is op2 of &)
                    op1_of_amp = getattr(parent, "astOperand1", None)
                    op2_of_amp = getattr(parent, "astOperand2", None)
                    is_unary = (op1_of_amp is None or op2_of_amp is None)
                    if is_unary:
                        key = (_tok_file(tok), _tok_line(tok))
                        if key not in seen:
                            seen.add(key)
                            self._emit(
                                tok,
                                "Taking the address of errno (&errno) is "
                                "non-portable; errno may be a macro that "
                                "expands to a function call (CWE-703).",
                                severity="portability",
                            )


# ═══════════════════════════════════════════════════════════════════════════
#  PART 8 — ADDON ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════

_ALL_CHECKERS: List[type] = [
    _EUC01_ErrnoReadBeforeCheck,
    _EUC02_ErrnoNotCheckedAfterCall,
    _EUC03_ErrnoAfterStrtolMissing,
    _EUC04_ErrnoOverwrite,
    _EUC05_ErrnoComparedToNegative,
    _EUC06_ErrnoUsedAsBoolean,
    _EUC07_StrerrorNotThreadSafe,
    _EUC08_ErrnoGlobalVariableAccess,
]


def _run_on_dump(dump_file: str) -> int:
    """
    Parse a cppcheck .dump file and run all EUC checkers.

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
                # Graceful degradation — never crash cppcheck's pipeline
                sys.stderr.write(
                    f"[EUC] {checker_cls.__name__} raised "
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
            "Usage: python ErrnoUsageChecker.py <file.c.dump>\n"
        )
        sys.exit(1)

    dump_file = sys.argv[1]
    if not os.path.isfile(dump_file):
        sys.stderr.write(f"ERROR: dump file not found: {dump_file}\n")
        sys.exit(1)

    sys.exit(_run_on_dump(dump_file))


if __name__ == "__main__":
    main()
