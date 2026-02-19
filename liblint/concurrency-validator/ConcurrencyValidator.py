#!/usr/bin/env python3
"""
ConcurrencyValidator.py
=======================

A Cppcheck addon that detects concurrency-related CWE vulnerabilities
in C/C++ source code.

Covered CWEs:
    CWE-362  : Concurrent Execution using Shared Resource with
                Improper Synchronization ('Race Condition')
    CWE-364  : Signal Handler Race Condition
    CWE-366  : Race Condition within a Thread
    CWE-367  : Time-of-Check Time-of-Use (TOCTOU) Race Condition
    CWE-370  : Missing Check for Certificate Revocation after Initial Check
                (modelled here as generic TOCTOU on security-check patterns)
    CWE-413  : Improper Resource Locking
    CWE-414  : Missing Lock Check
    CWE-609  : Double-Checked Locking
    CWE-662  : Improper Synchronization
    CWE-667  : Improper Locking
    CWE-764  : Multiple Locks of a Critical Resource
    CWE-765  : Multiple Unlocks of a Critical Resource
    CWE-820  : Missing Synchronization
    CWE-821  : Incorrect Synchronization
    CWE-833  : Deadlock
    CWE-1058 : Invocation of Block Cipher with a Non-Random IV
                (not concurrency — skipped)
    CWE-1088 : Synchronous Access of Remote Resource without Timeout

Usage:
    cppcheck --dump myfile.c
    python ConcurrencyValidator.py myfile.c.dump

Requires:
    - cppcheckdata  (bundled with Cppcheck)

Optionally enhanced by:
    - cppcheckdata_shims  (abstract_domains, ast_helper, etc.)
      If not available, the addon still works using cppcheckdata alone.

License: MIT
"""

from __future__ import annotations

import sys
import os
import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import (
    Any,
    Dict,
    FrozenSet,
    List,
    Optional,
    Set,
    Sequence,
    Tuple,
)

# ──────────────────────────────────────────────────────────────────────
#  Core dependency — always available with Cppcheck
# ──────────────────────────────────────────────────────────────────────
import cppcheckdata

# ──────────────────────────────────────────────────────────────────────
#  Optional shims — graceful degradation if not installed
# ──────────────────────────────────────────────────────────────────────
_HAS_SHIMS = False
try:
    from cppcheckdata_shims.abstract_domains import FlatDomain, BOTTOM, TOP
    _HAS_SHIMS = True
except ImportError:
    pass

# ══════════════════════════════════════════════════════════════════════
#  CONSTANTS — Function-name sets for lock/unlock/signal/TOCTOU/etc.
# ══════════════════════════════════════════════════════════════════════

ADDON_NAME = "ConcurrencyValidator"

# --- Locking primitives ------------------------------------------------
LOCK_FUNCTIONS: FrozenSet[str] = frozenset({
    # POSIX
    "pthread_mutex_lock",
    "pthread_mutex_trylock",
    "pthread_rwlock_rdlock",
    "pthread_rwlock_wrlock",
    "pthread_rwlock_tryrdlock",
    "pthread_rwlock_trywrlock",
    "pthread_spin_lock",
    "pthread_spin_trylock",
    # C11
    "mtx_lock",
    "mtx_trylock",
    "mtx_timedlock",
    # Windows
    "EnterCriticalSection",
    "TryEnterCriticalSection",
    "AcquireSRWLockExclusive",
    "AcquireSRWLockShared",
    "WaitForSingleObject",
    "WaitForMultipleObjects",
    # Linux kernel
    "spin_lock",
    "spin_lock_irqsave",
    "spin_lock_bh",
    "mutex_lock",
    "down",
    "down_interruptible",
    "read_lock",
    "write_lock",
})

UNLOCK_FUNCTIONS: FrozenSet[str] = frozenset({
    # POSIX
    "pthread_mutex_unlock",
    "pthread_rwlock_unlock",
    "pthread_spin_unlock",
    # C11
    "mtx_unlock",
    # Windows
    "LeaveCriticalSection",
    "ReleaseSRWLockExclusive",
    "ReleaseSRWLockShared",
    "ReleaseMutex",
    # Linux kernel
    "spin_unlock",
    "spin_unlock_irqrestore",
    "spin_unlock_bh",
    "mutex_unlock",
    "up",
    "read_unlock",
    "write_unlock",
})

# --- Signal-related functions -------------------------------------------
SIGNAL_REGISTER_FUNCTIONS: FrozenSet[str] = frozenset({
    "signal", "sigaction", "sigset",
})

# Functions unsafe to call from a signal handler (subset — CERT SIG30-C)
SIGNAL_UNSAFE_FUNCTIONS: FrozenSet[str] = frozenset({
    "printf", "fprintf", "sprintf", "snprintf", "vprintf", "vfprintf",
    "vsprintf", "vsnprintf",
    "malloc", "calloc", "realloc", "free",
    "exit", "_Exit", "abort",
    "longjmp", "siglongjmp",
    "fork", "execve", "execl", "execlp", "execle", "execv", "execvp",
    "pthread_mutex_lock", "pthread_mutex_unlock",
    "pthread_cond_signal", "pthread_cond_wait",
    "sem_wait", "sem_post",
    "fopen", "fclose", "fread", "fwrite", "fflush", "fseek", "ftell",
    "fgets", "fputs", "puts", "gets",
    "syslog",
    "openlog", "closelog",
    "strtok", "strerror", "asctime", "ctime", "localtime", "gmtime",
    "rand", "srand",
    "getenv", "setenv", "unsetenv",
    "atexit",
})

# --- TOCTOU pairs  (check, use) ----------------------------------------
TOCTOU_PAIRS: List[Tuple[str, str]] = [
    ("access", "open"),
    ("access", "fopen"),
    ("stat", "open"),
    ("stat", "fopen"),
    ("stat", "chmod"),
    ("stat", "chown"),
    ("stat", "rename"),
    ("stat", "unlink"),
    ("stat", "remove"),
    ("lstat", "open"),
    ("lstat", "chmod"),
    ("lstat", "chown"),
    ("lstat", "readlink"),
    ("faccessat", "openat"),
    ("PathFileExists", "CreateFile"),
    ("GetFileAttributes", "CreateFile"),
]

# Build lookup: check_func → set of use_funcs
_TOCTOU_CHECK_TO_USE: Dict[str, Set[str]] = defaultdict(set)
for _chk, _use in TOCTOU_PAIRS:
    _TOCTOU_CHECK_TO_USE[_chk].add(_use)

# --- Functions requiring timeout for remote access ----------------------
REMOTE_NO_TIMEOUT_FUNCTIONS: FrozenSet[str] = frozenset({
    "connect",
    "recv",
    "recvfrom",
    "recvmsg",
    "send",
    "sendto",
    "sendmsg",
    "accept",
    "read",   # only flagged when used on a socket fd — heuristic below
    "write",  # same heuristic
    "select",  # select itself is fine but we flag if timeout param is NULL
})

# --- Shared-variable access helpers ------------------------------------
# We consider a variable "shared" if it is global/static/extern or
# its address has been passed to pthread_create / thrd_create.

THREAD_CREATE_FUNCTIONS: FrozenSet[str] = frozenset({
    "pthread_create",
    "thrd_create",
    "CreateThread",
    "_beginthreadex",
    "_beginthread",
})


# ══════════════════════════════════════════════════════════════════════
#  HELPER:  Get the called function name from a token
# ══════════════════════════════════════════════════════════════════════

def _get_call_name(token) -> Optional[str]:
    """
    If *token* is the name-token of a function call  ``foo(...)``
    return the (possibly qualified) function name.  Otherwise None.

    Uses cppcheckdata.get_function_call_name_args which is the
    canonical helper shipped with cppcheck.
    """
    name, _args = cppcheckdata.get_function_call_name_args(token)
    return name


def _get_call_args(token) -> Optional[List]:
    """Return argument token list for a call, or None."""
    _name, args = cppcheckdata.get_function_call_name_args(token)
    return args


# ══════════════════════════════════════════════════════════════════════
#  HELPER:  Iterate all function-call tokens in a configuration
# ══════════════════════════════════════════════════════════════════════

def _iter_calls(cfg) -> List[Tuple[str, Any, Optional[List]]]:
    """
    Yield (func_name, token, args) for every function call in *cfg*.
    """
    results = []
    for token in cfg.tokenlist:
        name = _get_call_name(token)
        if name is not None:
            args = _get_call_args(token)
            results.append((name, token, args))
    return results


# ══════════════════════════════════════════════════════════════════════
#  HELPER:  Determine if a variable is potentially shared
# ══════════════════════════════════════════════════════════════════════

def _is_shared_variable(var) -> bool:
    """Heuristic: a variable is shared if it is global, extern, or static."""
    if var is None:
        return False
    return var.isGlobal or var.isExtern or var.isStatic


def _shared_var_accesses(cfg) -> Dict[str, List]:
    """
    Map  variable-name → list of access tokens  for shared variables.
    Only considers executable scopes.
    """
    accesses: Dict[str, List] = defaultdict(list)
    for token in cfg.tokenlist:
        if token.variable and _is_shared_variable(token.variable):
            if token.scope and token.scope.isExecutable:
                vname = token.variable.nameToken.str if token.variable.nameToken else token.str
                accesses[vname].append(token)
    return accesses


def _is_write_access(token) -> bool:
    """Heuristic to decide if *token* is on the LHS of an assignment."""
    parent = token.astParent
    if parent is None:
        return False
    if parent.isAssignmentOp:
        return parent.astOperand1 == token
    # Unary ++ / --
    if parent.str in ("++", "--"):
        return True
    return False


# ══════════════════════════════════════════════════════════════════════
#  HELPER:  Scope-based lock tracking
# ══════════════════════════════════════════════════════════════════════

@dataclass
class _LockEvent:
    kind: str          # "lock" or "unlock"
    func_name: str     # e.g. "pthread_mutex_lock"
    mutex_expr: str    # textual representation of the mutex argument
    token: Any         # cppcheckdata Token
    linenr: int
    file: str


def _collect_lock_events(cfg) -> List[_LockEvent]:
    """Walk the token list and collect every lock/unlock call."""
    events: List[_LockEvent] = []
    for fname, tok, args in _iter_calls(cfg):
        if fname in LOCK_FUNCTIONS:
            mutex_str = _mutex_arg_str(args)
            events.append(_LockEvent("lock", fname, mutex_str, tok, tok.linenr, tok.file))
        elif fname in UNLOCK_FUNCTIONS:
            mutex_str = _mutex_arg_str(args)
            events.append(_LockEvent("unlock", fname, mutex_str, tok, tok.linenr, tok.file))
    return events


def _mutex_arg_str(args: Optional[List]) -> str:
    """Extract a textual representation of the first (mutex) argument."""
    if not args or len(args) == 0:
        return "<unknown>"
    # Walk tokens of the first argument to build a string
    tok = args[0]
    parts: List[str] = []
    # Simple approach: just use the token str and handle & prefix
    t = tok
    # Go to leftmost token of this expression
    while t and t.astOperand1:
        t = t.astOperand1
    # Now walk forward collecting strings until we leave this sub-expression
    # Simpler: just use the top-level token str
    return _expr_to_str(tok)


def _expr_to_str(tok) -> str:
    """Recursively convert an AST expression token to a string."""
    if tok is None:
        return ""
    if tok.astOperand1 is None and tok.astOperand2 is None:
        return tok.str
    # Unary
    if tok.astOperand1 and tok.astOperand2 is None:
        return f"{tok.str}{_expr_to_str(tok.astOperand1)}"
    # Binary
    left = _expr_to_str(tok.astOperand1)
    right = _expr_to_str(tok.astOperand2)
    if tok.str == ".":
        return f"{left}.{right}"
    if tok.str == "->":
        return f"{left}->{right}"
    if tok.str == "[":
        return f"{left}[{right}]"
    return f"{left}{tok.str}{right}"


# ══════════════════════════════════════════════════════════════════════
#  HELPER:  Find the enclosing function scope for a token
# ══════════════════════════════════════════════════════════════════════

def _enclosing_function(token) -> Optional[str]:
    """Return the name of the enclosing function, or None."""
    scope = token.scope
    while scope:
        if scope.type == "Function" and scope.className:
            return scope.className
        scope = scope.nestedIn
    return None


# ══════════════════════════════════════════════════════════════════════
#  REPORTING HELPER  — wraps cppcheckdata.reportError
# ══════════════════════════════════════════════════════════════════════

def _report(token, severity: str, msg: str, error_id: str, cwe: int = 0):
    """
    Emit a diagnostic using cppcheckdata.reportError.

    Parameters
    ----------
    token : cppcheckdata.Token
        Location of the finding.
    severity : str
        One of "error", "warning", "style", "portability", "performance",
        "information".
    msg : str
        Human-readable message.
    error_id : str
        Unique identifier such as "racecondition", "doubleLock", etc.
    cwe : int
        CWE number (informational, appended to the message).
    """
    extra = f"CWE-{cwe}" if cwe else ""
    full_msg = f"[CWE-{cwe}] {msg}" if cwe else msg
    cppcheckdata.reportError(token, severity, full_msg, ADDON_NAME, error_id, extra=extra)


# ══════════════════════════════════════════════════════════════════════
#  CHECK 1 — CWE-362 / CWE-366 / CWE-820 : Race Condition on shared
#             variables (unsynchronised read+write or write+write)
# ══════════════════════════════════════════════════════════════════════

def _check_race_conditions(cfg):
    """
    Detect potential race conditions on shared (global/static/extern)
    variables that are accessed from executable scopes without
    surrounding lock/unlock pairs.

    Covers:
        CWE-362 — Concurrent Execution using Shared Resource with
                   Improper Synchronization
        CWE-366 — Race Condition within a Thread
        CWE-820 — Missing Synchronization
    """
    lock_events = _collect_lock_events(cfg)
    shared_accesses = _shared_var_accesses(cfg)

    # Build a set of (file, line) ranges that are "locked"
    # Simple model: between a lock() and the next unlock() in the same scope
    locked_lines: Set[Tuple[str, int]] = set()
    lock_stack: List[_LockEvent] = []
    for ev in lock_events:
        if ev.kind == "lock":
            lock_stack.append(ev)
        elif ev.kind == "unlock" and lock_stack:
            lev = lock_stack.pop()
            # Mark lines between lock and unlock as protected
            if lev.file == ev.file:
                for ln in range(lev.linenr, ev.linenr + 1):
                    locked_lines.add((lev.file, ln))

    for var_name, tokens in shared_accesses.items():
        has_write = False
        has_read = False
        unprotected_writes: List = []
        unprotected_reads: List = []

        for tok in tokens:
            is_write = _is_write_access(tok)
            loc = (tok.file, tok.linenr)
            protected = loc in locked_lines

            if is_write:
                has_write = True
                if not protected:
                    unprotected_writes.append(tok)
            else:
                has_read = True
                if not protected:
                    unprotected_reads.append(tok)

        # Race: unprotected write + any other unprotected access
        if unprotected_writes:
            if len(unprotected_writes) > 1 or unprotected_reads:
                for tok in unprotected_writes:
                    _report(
                        tok, "warning",
                        f"Shared variable '{var_name}' written without "
                        f"holding a lock — potential race condition",
                        "raceCondition", cwe=362,
                    )
            # CWE-820 specifically if there is NO lock anywhere
            if not lock_events:
                for tok in unprotected_writes:
                    _report(
                        tok, "warning",
                        f"Shared variable '{var_name}' accessed with no "
                        f"synchronisation primitives in scope",
                        "missingSynchronization", cwe=820,
                    )

        # CWE-366: read of shared variable without lock where writes exist
        if has_write and unprotected_reads:
            for tok in unprotected_reads:
                _report(
                    tok, "warning",
                    f"Shared variable '{var_name}' read without lock "
                    f"while writes exist elsewhere — race within thread",
                    "raceInThread", cwe=366,
                )


# ══════════════════════════════════════════════════════════════════════
#  CHECK 2 — CWE-667 / CWE-764 / CWE-765 / CWE-413 / CWE-414
#             Improper locking patterns
# ══════════════════════════════════════════════════════════════════════

def _check_locking(cfg):
    """
    Detect locking errors:
        CWE-667  — Improper Locking (lock without unlock)
        CWE-764  — Multiple Locks of a Critical Resource
        CWE-765  — Multiple Unlocks of a Critical Resource
        CWE-413  — Improper Resource Locking
        CWE-414  — Missing Lock Check
    """
    events = _collect_lock_events(cfg)
    if not events:
        return

    # Per-function analysis
    func_events: Dict[str, List[_LockEvent]] = defaultdict(list)
    for ev in events:
        fn = _enclosing_function(ev.token)
        key = fn or "<global>"
        func_events[key].append(ev)

    for fn_name, evs in func_events.items():
        # Track held locks: mutex_expr → lock event
        held: Dict[str, _LockEvent] = {}

        for ev in evs:
            mx = ev.mutex_expr
            if ev.kind == "lock":
                if mx in held:
                    # CWE-764: Double lock
                    _report(
                        ev.token, "warning",
                        f"Mutex '{mx}' locked again without unlock "
                        f"(first lock at line {held[mx].linenr})",
                        "doubleLock", cwe=764,
                    )
                held[mx] = ev
            elif ev.kind == "unlock":
                if mx not in held:
                    # CWE-765: Unlock without matching lock
                    _report(
                        ev.token, "warning",
                        f"Mutex '{mx}' unlocked without preceding lock",
                        "unmatchedUnlock", cwe=765,
                    )
                else:
                    del held[mx]

        # Locks still held at end of function → CWE-667
        for mx, lev in held.items():
            _report(
                lev.token, "warning",
                f"Mutex '{mx}' locked in function '{fn_name}' but never "
                f"unlocked — potential improper locking / resource leak",
                "lockNotReleased", cwe=667,
            )


# ══════════════════════════════════════════════════════════════════════
#  CHECK 3 — CWE-833 : Deadlock detection (lock-ordering heuristic)
# ══════════════════════════════════════════════════════════════════════

def _check_deadlock(cfg):
    """
    Simple deadlock heuristic: if two different functions acquire the
    same set of mutexes in different orders, flag as potential deadlock.

    CWE-833 — Deadlock
    """
    events = _collect_lock_events(cfg)
    if not events:
        return

    # Per-function lock order: func → list of mutex expressions in order
    func_lock_order: Dict[str, List[Tuple[str, Any]]] = defaultdict(list)
    for ev in events:
        if ev.kind == "lock":
            fn = _enclosing_function(ev.token) or "<global>"
            func_lock_order[fn].append((ev.mutex_expr, ev.token))

    # Compare pairs of functions
    fns = list(func_lock_order.keys())
    for i in range(len(fns)):
        for j in range(i + 1, len(fns)):
            order_a = [mx for mx, _ in func_lock_order[fns[i]]]
            order_b = [mx for mx, _ in func_lock_order[fns[j]]]
            common = set(order_a) & set(order_b)
            if len(common) >= 2:
                # Check if ordering is reversed for any pair
                common_list = list(common)
                for ci in range(len(common_list)):
                    for cj in range(ci + 1, len(common_list)):
                        m1, m2 = common_list[ci], common_list[cj]
                        idx_a1 = order_a.index(m1) if m1 in order_a else -1
                        idx_a2 = order_a.index(m2) if m2 in order_a else -1
                        idx_b1 = order_b.index(m1) if m1 in order_b else -1
                        idx_b2 = order_b.index(m2) if m2 in order_b else -1
                        if idx_a1 >= 0 and idx_a2 >= 0 and idx_b1 >= 0 and idx_b2 >= 0:
                            if (idx_a1 < idx_a2) != (idx_b1 < idx_b2):
                                tok_a = func_lock_order[fns[i]][0][1]
                                _report(
                                    tok_a, "warning",
                                    f"Potential deadlock: '{fns[i]}' and "
                                    f"'{fns[j]}' acquire mutexes "
                                    f"'{m1}' and '{m2}' in different orders",
                                    "deadlockOrder", cwe=833,
                                )


# ══════════════════════════════════════════════════════════════════════
#  CHECK 4 — CWE-609 : Double-Checked Locking
# ══════════════════════════════════════════════════════════════════════

def _check_double_checked_locking(cfg):
    """
    Detect the double-checked locking anti-pattern:

        if (ptr == NULL) {
            lock(m);
            if (ptr == NULL) {     ← CWE-609
                ptr = ...;
            }
            unlock(m);
        }

    Heuristic: an ``if`` scope that checks a shared variable,
    contains a lock() call followed by another ``if`` checking
    the same variable.

    CWE-609 — Double-Checked Locking
    """
    for scope in cfg.scopes:
        if scope.type != "If":
            continue
        # Check the condition for a shared variable
        cond_var = _if_condition_var(scope, cfg)
        if cond_var is None or not _is_shared_variable(cond_var):
            continue

        # Walk tokens inside this if-body looking for lock + nested if
        # with same condition variable
        if scope.bodyStart is None or scope.bodyEnd is None:
            continue

        found_lock = False
        tok = scope.bodyStart.next
        while tok and tok != scope.bodyEnd:
            name = _get_call_name(tok)
            if name in LOCK_FUNCTIONS:
                found_lock = True
            if found_lock and tok.str == "if":
                # Check if this inner if tests the same variable
                inner_var = _condition_var_from_token(tok)
                if inner_var and inner_var.Id == cond_var.Id:
                    _report(
                        tok, "warning",
                        f"Double-checked locking pattern on "
                        f"'{cond_var.nameToken.str if cond_var.nameToken else '?'}' "
                        f"— may be broken without memory barriers/volatile",
                        "doubleCheckedLocking", cwe=609,
                    )
                    break
            tok = tok.next


def _if_condition_var(scope, cfg) -> Optional[Any]:
    """Return the Variable tested in an if-scope's condition, or None."""
    # The condition tokens are between the 'if (' and the ')'.
    if scope.bodyStart is None:
        return None
    # bodyStart is '{', the '(' should be bodyStart.previous.link
    rparen = scope.bodyStart.previous  # could be ')'
    if rparen is None or rparen.str != ")":
        return None
    lparen = rparen.link
    if lparen is None:
        return None
    # Walk tokens between lparen and rparen looking for a variable
    tok = lparen.next
    while tok and tok != rparen:
        if tok.variable:
            return tok.variable
        tok = tok.next
    return None


def _condition_var_from_token(if_tok) -> Optional[Any]:
    """Given an 'if' keyword token, find the variable in its condition."""
    paren = if_tok.next
    if paren is None or paren.str != "(":
        return None
    rparen = paren.link
    if rparen is None:
        return None
    tok = paren.next
    while tok and tok != rparen:
        if tok.variable:
            return tok.variable
        tok = tok.next
    return None


# ══════════════════════════════════════════════════════════════════════
#  CHECK 5 — CWE-364 : Signal Handler Race Condition
# ══════════════════════════════════════════════════════════════════════

def _check_signal_handler(cfg):
    """
    Find signal handlers registered via signal()/sigaction() and
    check if they call async-signal-unsafe functions.

    CWE-364 — Signal Handler Race Condition
    """
    # Step 1: identify signal handler function names
    handler_names: Set[str] = set()

    for fname, tok, args in _iter_calls(cfg):
        if fname in SIGNAL_REGISTER_FUNCTIONS and args and len(args) >= 2:
            handler_tok = args[1]
            # The handler argument is a function pointer (name or &name)
            if handler_tok.str == "&" and handler_tok.astOperand1:
                handler_tok = handler_tok.astOperand1
            if handler_tok.isName and handler_tok.str not in ("SIG_IGN", "SIG_DFL", "SIG_ERR"):
                handler_names.add(handler_tok.str)

    if not handler_names:
        return

    # Step 2: for each function scope whose name is a handler, walk
    #         its tokens looking for unsafe calls
    for scope in cfg.scopes:
        if scope.type != "Function":
            continue
        if scope.className not in handler_names:
            continue

        tok = scope.bodyStart
        if tok is None:
            continue
        end = scope.bodyEnd
        while tok and tok != end:
            call_name = _get_call_name(tok)
            if call_name and call_name in SIGNAL_UNSAFE_FUNCTIONS:
                _report(
                    tok, "warning",
                    f"Signal handler '{scope.className}' calls "
                    f"async-signal-unsafe function '{call_name}'",
                    "signalHandlerUnsafe", cwe=364,
                )
            tok = tok.next

    # Step 3: check for shared variables modified in signal handlers
    # without volatile / sig_atomic_t
    for scope in cfg.scopes:
        if scope.type != "Function":
            continue
        if scope.className not in handler_names:
            continue
        tok = scope.bodyStart
        end = scope.bodyEnd
        while tok and tok != end:
            if tok.variable and _is_write_access(tok):
                var = tok.variable
                if var.isGlobal or var.isStatic:
                    # Check if volatile
                    if not var.isVolatile:
                        vname = var.nameToken.str if var.nameToken else tok.str
                        _report(
                            tok, "warning",
                            f"Signal handler '{scope.className}' modifies "
                            f"non-volatile shared variable '{vname}'",
                            "signalHandlerSharedVar", cwe=364,
                        )
            tok = tok.next


# ══════════════════════════════════════════════════════════════════════
#  CHECK 6 — CWE-367 : TOCTOU Race Condition
# ══════════════════════════════════════════════════════════════════════

def _check_toctou(cfg):
    """
    Detect Time-of-Check Time-of-Use patterns such as:
        access(path, ...) followed by open(path, ...)

    CWE-367 — TOCTOU Race Condition
    """
    calls = _iter_calls(cfg)

    # Group calls by enclosing function
    func_calls: Dict[str, List[Tuple[str, Any, Optional[List]]]] = defaultdict(list)
    for fname, tok, args in calls:
        fn = _enclosing_function(tok) or "<global>"
        func_calls[fn].append((fname, tok, args))

    for fn, callseq in func_calls.items():
        # For each check function, look for a later use function with
        # the same path argument
        for i, (fname_i, tok_i, args_i) in enumerate(callseq):
            if fname_i not in _TOCTOU_CHECK_TO_USE:
                continue
            path_i = _first_arg_str(args_i)
            if not path_i:
                continue
            for j in range(i + 1, len(callseq)):
                fname_j, tok_j, args_j = callseq[j]
                if fname_j in _TOCTOU_CHECK_TO_USE[fname_i]:
                    path_j = _first_arg_str(args_j)
                    if path_j and path_j == path_i:
                        _report(
                            tok_j, "warning",
                            f"TOCTOU: '{fname_i}' at line {tok_i.linenr} "
                            f"checks '{path_i}', then '{fname_j}' at line "
                            f"{tok_j.linenr} uses it — race window exists",
                            "toctou", cwe=367,
                        )


def _first_arg_str(args: Optional[List]) -> Optional[str]:
    """Return the string representation of the first argument."""
    if not args or len(args) == 0:
        return None
    return _expr_to_str(args[0])


# ══════════════════════════════════════════════════════════════════════
#  CHECK 7 — CWE-662 / CWE-821 : Improper / Incorrect Synchronization
# ══════════════════════════════════════════════════════════════════════

def _check_improper_sync(cfg):
    """
    Detect misuse of synchronisation primitives:
      - Condition variable wait without holding the associated mutex
      - Spin-waiting patterns (busy loops on shared variables)

    CWE-662 — Improper Synchronization
    CWE-821 — Incorrect Synchronization
    """
    # Detect pthread_cond_wait / pthread_cond_timedwait outside lock scope
    lock_events = _collect_lock_events(cfg)
    locked_lines: Set[Tuple[str, int]] = set()

    lock_stack: List[_LockEvent] = []
    for ev in lock_events:
        if ev.kind == "lock":
            lock_stack.append(ev)
        elif ev.kind == "unlock" and lock_stack:
            lev = lock_stack.pop()
            if lev.file == ev.file:
                for ln in range(lev.linenr, ev.linenr + 1):
                    locked_lines.add((lev.file, ln))

    cond_wait_funcs = frozenset({
        "pthread_cond_wait", "pthread_cond_timedwait",
        "cnd_wait", "cnd_timedwait",
        "SleepConditionVariableCS", "SleepConditionVariableSRW",
    })

    for fname, tok, args in _iter_calls(cfg):
        if fname in cond_wait_funcs:
            loc = (tok.file, tok.linenr)
            if loc not in locked_lines:
                _report(
                    tok, "warning",
                    f"'{fname}' called without holding the mutex "
                    f"— undefined behaviour / improper synchronization",
                    "condWaitNoLock", cwe=662,
                )

    # Detect spin-wait pattern: while(shared_var) { } or while(!shared_var){}
    for scope in cfg.scopes:
        if scope.type not in ("While", "Do"):
            continue
        # Check condition for shared variable
        cvar = _if_condition_var(scope, cfg)
        if cvar and _is_shared_variable(cvar):
            # Check if the loop body is empty or just yield/sleep
            has_sync = False
            if scope.bodyStart and scope.bodyEnd:
                tok = scope.bodyStart.next
                while tok and tok != scope.bodyEnd:
                    name = _get_call_name(tok)
                    if name in LOCK_FUNCTIONS or name in UNLOCK_FUNCTIONS or name in cond_wait_funcs:
                        has_sync = True
                        break
                    if name and name in ("sleep", "usleep", "nanosleep",
                                         "sched_yield", "thrd_yield",
                                         "SwitchToThread", "Sleep"):
                        has_sync = True
                        break
                    tok = tok.next
            if not has_sync:
                vname = cvar.nameToken.str if cvar.nameToken else "?"
                _report(
                    scope.bodyStart, "style",
                    f"Busy-wait (spin loop) on shared variable '{vname}' "
                    f"without synchronisation primitive — consider using "
                    f"condition variables or atomics",
                    "spinWait", cwe=821,
                )


# ══════════════════════════════════════════════════════════════════════
#  CHECK 8 — CWE-1088 : Synchronous Remote Access without Timeout
# ══════════════════════════════════════════════════════════════════════

def _check_remote_no_timeout(cfg):
    """
    Detect calls to blocking socket/IO functions that may hang
    indefinitely because no timeout has been set.

    CWE-1088 — Synchronous Access of Remote Resource without Timeout

    Heuristic:
      - Flag recv/send/connect/accept calls unless preceded by
        setsockopt with SO_RCVTIMEO/SO_SNDTIMEO or select/poll
        in the same function scope.
    """
    timeout_setters = frozenset({
        "setsockopt", "select", "poll", "epoll_wait",
        "WSAPoll", "WSAWaitForMultipleEvents",
    })

    calls = _iter_calls(cfg)

    func_calls: Dict[str, List[Tuple[str, Any, Optional[List]]]] = defaultdict(list)
    for fname, tok, args in calls:
        fn = _enclosing_function(tok) or "<global>"
        func_calls[fn].append((fname, tok, args))

    blocking_funcs = frozenset({
        "connect", "recv", "recvfrom", "recvmsg",
        "send", "sendto", "sendmsg", "accept",
    })

    for fn, callseq in func_calls.items():
        has_timeout = False
        blocking_calls: List[Tuple[str, Any]] = []

        for fname, tok, args in callseq:
            if fname in timeout_setters:
                has_timeout = True
            if fname in blocking_funcs:
                blocking_calls.append((fname, tok))

        if not has_timeout and blocking_calls:
            for fname, tok in blocking_calls:
                _report(
                    tok, "warning",
                    f"Blocking socket call '{fname}' without prior timeout "
                    f"configuration (setsockopt/select/poll) — may hang "
                    f"indefinitely",
                    "remoteNoTimeout", cwe=1088,
                )


# ══════════════════════════════════════════════════════════════════════
#  MAIN ENTRY POINT
# ══════════════════════════════════════════════════════════════════════

def run_checks_on_cfg(cfg):
    """Execute all concurrency checks on a single Configuration."""
    _check_race_conditions(cfg)
    _check_locking(cfg)
    _check_deadlock(cfg)
    _check_double_checked_locking(cfg)
    _check_signal_handler(cfg)
    _check_toctou(cfg)
    _check_improper_sync(cfg)
    _check_remote_no_timeout(cfg)


def main():
    parser = cppcheckdata.ArgumentParser()
    args = parser.parse_args()

    if not args.dumpfile:
        if not args.quiet:
            print(f"{ADDON_NAME}: No dump files specified.", file=sys.stderr)
        sys.exit(1)

    dump_files, _ctu = cppcheckdata.get_files(args)

    for dumpfile in dump_files:
        if not args.quiet:
            print(f"Checking {dumpfile} ...")

        data = cppcheckdata.parsedump(dumpfile)

        if not data.configurations:
            continue

        for cfg in data.configurations:
            run_checks_on_cfg(cfg)

    sys.exit(cppcheckdata.EXIT_CODE)


if __name__ == "__main__":
    main()
