#!/usr/bin/env python3
"""
SharedResourceValidator.py
══════════════════════════════════════════════════════════════════════════════

Cppcheck addon — Shared Resource Discipline Validator.

Checks performed
────────────────
  SRV-01  Race conditions on shared variables          (CWE-362)
  SRV-02  TOCTOU on shared file / state               (CWE-367)
  SRV-03  Mutex misuse (double-lock, spurious unlock)  (CWE-667)
  SRV-04  Deadlock via lock-order inversion            (CWE-833)
  SRV-05  Lock-order hierarchy violation               (CWE-833)
  SRV-06  Shared variables written without protection  (CWE-362)
  SRV-07  Non-atomic RMW on shared variable            (CWE-366)
  SRV-08  Data races (cross-function conflicting acc.) (CWE-362)
  SRV-09  Unsafe call inside signal handler            (CWE-828)

Framework used
──────────────
  cppcheckdata_shims.checkers — Checker, CheckerContext, CheckerRegistry,
      CheckerRunner, CheckerRunResults, SuppressionManager, Diagnostic,
      DiagnosticSeverity, Confidence, SourceLocation,
      _iter_tokens, _iter_scopes, _iter_functions, _iter_variables,
      _tok_str, _tok_file, _tok_line, _tok_col, _tok_loc,
      _has_known_int_value, _get_valueflow_values, _is_deref, _is_in_loop

Usage
─────
  cppcheck --dump myfile.c
  python3 SharedResourceValidator.py myfile.c.dump

License: MIT
"""

from __future__ import annotations

import re
import sys
from abc import ABC
from collections import defaultdict
from dataclasses import dataclass, field
from typing import (
    Any, ClassVar, Dict, FrozenSet, Iterator,
    List, Optional, Set, Tuple,
)

# ══════════════════════════════════════════════════════════════════════════════
#  FRAMEWORK IMPORT
# ══════════════════════════════════════════════════════════════════════════════

try:
    from cppcheckdata_shims.checkers import (
        Checker,
        CheckerContext,
        CheckerRegistry,
        CheckerRunner,
        CheckerRunResults,
        SuppressionManager,
        Diagnostic,
        DiagnosticSeverity,
        Confidence,
        SourceLocation,
        _iter_tokens,
        _iter_scopes,
        _iter_functions,
        _iter_variables,
        _tok_str,
        _tok_file,
        _tok_line,
        _tok_col,
        _tok_loc,
        _has_known_int_value,
        _get_valueflow_values,
        _is_deref,
        _is_in_loop,
    )
    _SHIMS_OK = True
except ImportError:
    _SHIMS_OK = False

    # ── Minimal stubs so the file is importable without the shims package ──
    class DiagnosticSeverity:                          # type: ignore[no-redef]
        ERROR       = "error"
        WARNING     = "warning"
        STYLE       = "style"
        INFORMATION = "information"

    class Confidence:                                  # type: ignore[no-redef]
        HIGH   = "high"
        MEDIUM = "medium"
        LOW    = "low"

    class Checker(ABC):                                # type: ignore[no-redef]
        pass

    class CheckerContext:                              # type: ignore[no-redef]
        pass

    class CheckerRegistry:                             # type: ignore[no-redef]
        def register(self, _): pass

    class SuppressionManager:                          # type: ignore[no-redef]
        pass

    class CheckerRunner:                               # type: ignore[no-redef]
        pass


# ══════════════════════════════════════════════════════════════════════════════
#  PART 0 — SHARED PATTERN TABLES
# ══════════════════════════════════════════════════════════════════════════════

# ── Mutex types ───────────────────────────────────────────────────────────────
_MUTEX_TYPES: FrozenSet[str] = frozenset({
    "pthread_mutex_t", "pthread_rwlock_t", "pthread_spinlock_t",
    "std::mutex", "std::recursive_mutex", "std::timed_mutex",
    "std::shared_mutex", "std::shared_timed_mutex",
    "CRITICAL_SECTION", "SRWLOCK", "GMutex",
    "omp_lock_t", "omp_nest_lock_t",
})

# ── Lock acquisition → family ─────────────────────────────────────────────────
_LOCK_FUNCS: Dict[str, str] = {
    "pthread_mutex_lock":           "posix_mutex",
    "pthread_mutex_trylock":        "posix_mutex",
    "pthread_rwlock_rdlock":        "posix_rwlock",
    "pthread_rwlock_wrlock":        "posix_rwlock",
    "pthread_rwlock_tryrdlock":     "posix_rwlock",
    "pthread_rwlock_trywrlock":     "posix_rwlock",
    "pthread_spin_lock":            "posix_spin",
    "pthread_spin_trylock":         "posix_spin",
    "EnterCriticalSection":         "win_cs",
    "TryEnterCriticalSection":      "win_cs",
    "AcquireSRWLockExclusive":      "win_srw",
    "AcquireSRWLockShared":         "win_srw",
    "g_mutex_lock":                 "glib_mutex",
    "omp_set_lock":                 "omp_lock",
    "omp_set_nest_lock":            "omp_lock",
}

# ── Lock release ──────────────────────────────────────────────────────────────
_UNLOCK_FUNCS: Dict[str, str] = {
    "pthread_mutex_unlock":         "posix_mutex",
    "pthread_rwlock_unlock":        "posix_rwlock",
    "pthread_spin_unlock":          "posix_spin",
    "LeaveCriticalSection":         "win_cs",
    "ReleaseSRWLockExclusive":      "win_srw",
    "ReleaseSRWLockShared":         "win_srw",
    "g_mutex_unlock":               "glib_mutex",
    "omp_unset_lock":               "omp_lock",
    "omp_unset_nest_lock":          "omp_lock",
}

# ── Reader-writer lock subsets ────────────────────────────────────────────────
_RW_READ_LOCK: FrozenSet[str] = frozenset({
    "pthread_rwlock_rdlock", "pthread_rwlock_tryrdlock",
})
_RW_WRITE_LOCK: FrozenSet[str] = frozenset({
    "pthread_rwlock_wrlock", "pthread_rwlock_trywrlock",
})
_RW_UNLOCK: FrozenSet[str] = frozenset({
    "pthread_rwlock_unlock",
})

# ── Condition-variable operations ─────────────────────────────────────────────
_CONDVAR_WAIT_FUNCS: FrozenSet[str] = frozenset({
    "pthread_cond_wait",
    "pthread_cond_timedwait",
    "pthread_cond_timedwait_monotonic_np",
})
_CONDVAR_SIGNAL_FUNCS: FrozenSet[str] = frozenset({
    "pthread_cond_signal",
    "pthread_cond_broadcast",
})

# ── TOCTOU check → use sets ───────────────────────────────────────────────────
_TOCTOU_CHECK_FUNCS: FrozenSet[str] = frozenset({
    "access", "stat", "lstat", "fstat", "faccessat",
    "access64", "stat64", "lstat64",
})
_TOCTOU_USE_FUNCS: FrozenSet[str] = frozenset({
    "open", "fopen", "openat", "creat",
    "unlink", "unlinkat", "rename", "renameat",
    "chmod", "chown", "mkdir", "rmdir",
    "execve", "execl", "execle",
})

# ── Atomic operations ─────────────────────────────────────────────────────────
_ATOMIC_OPS: FrozenSet[str] = frozenset({
    "__atomic_load", "__atomic_store", "__atomic_exchange",
    "__atomic_compare_exchange", "__atomic_fetch_add",
    "__atomic_fetch_sub", "__atomic_fetch_and",
    "__atomic_fetch_or",  "__atomic_fetch_xor",
    "__sync_fetch_and_add", "__sync_fetch_and_sub",
    "__sync_fetch_and_or",  "__sync_fetch_and_and",
    "__sync_fetch_and_xor", "__sync_bool_compare_and_swap",
    "__sync_val_compare_and_swap", "__sync_lock_test_and_set",
    "__sync_lock_release",
    "atomic_load", "atomic_store", "atomic_exchange",
    "atomic_compare_exchange_strong", "atomic_compare_exchange_weak",
    "atomic_fetch_add", "atomic_fetch_sub",
    "atomic_fetch_and", "atomic_fetch_or", "atomic_fetch_xor",
    "InterlockedIncrement", "InterlockedDecrement",
    "InterlockedExchange", "InterlockedCompareExchange",
    "InterlockedAdd", "InterlockedOr", "InterlockedAnd",
})

_ATOMIC_TYPE_RE = re.compile(
    r"\b(_Atomic|atomic_int|atomic_long|atomic_uint|atomic_ulong"
    r"|atomic_bool|atomic_flag|std::atomic)\b"
)

# ── Signal-handler safety ─────────────────────────────────────────────────────
_SIGNAL_UNSAFE_FUNCS: FrozenSet[str] = frozenset({
    "printf", "fprintf", "sprintf", "snprintf", "vprintf", "vfprintf",
    "puts", "fputs", "fwrite", "fread", "fopen", "fclose", "fflush",
    "malloc", "calloc", "realloc", "free",
    "exit", "atexit",
    "pthread_mutex_lock", "pthread_mutex_unlock",
    "pthread_cond_wait", "pthread_cond_signal",
    "longjmp", "setjmp",
    "syslog", "openlog", "closelog",
    "sleep", "usleep", "nanosleep",
    "getenv", "setenv", "putenv",
    "strtok",
})

# ── Shared-variable name heuristics ──────────────────────────────────────────
_SHARED_VAR_RE = re.compile(
    r"^(g_|s_|global_|shared_|tls_|gbl_|srv_|rsc_|res_|pool_)",
    re.IGNORECASE,
)
_COUNTER_RE = re.compile(
    r"\b(count|counter|total|sum|hits|misses|ref_?count|refcount)\b",
    re.IGNORECASE,
)

# ── Read-modify-write operators ───────────────────────────────────────────────
_RMW_OPS: FrozenSet[str] = frozenset({
    "++", "--", "+=", "-=", "*=", "/=", "%=",
    "&=", "|=", "^=", "<<=", ">>=",
})


# ══════════════════════════════════════════════════════════════════════════════
#  PART 1 — BASE CLASS
# ══════════════════════════════════════════════════════════════════════════════

class _SRVChecker(Checker):
    """
    Abstract base for every SharedResourceValidator checker.

    Provides:
      - Token navigation helpers (_call_name, _first_arg_*)
      - Scope-name resolution (_scope_name)
      - Storage-class query   (_is_global_or_static)
      - Per-function lock-state simulation (_build_func_token_map,
        _held_locks_before)
    """

    addon_name: ClassVar[str] = "SharedResourceValidator"

    # ── lifecycle stubs (concrete checkers override both) ─────────────────────

    def collect_evidence(self, ctx: CheckerContext) -> None:  # type: ignore[override]
        raise NotImplementedError

    def diagnose(self, ctx: CheckerContext) -> None:           # type: ignore[override]
        raise NotImplementedError

    # ── token helpers ─────────────────────────────────────────────────────────

    @staticmethod
    def _tok_is_call(tok: Any) -> bool:
        """True when *tok* is the identifier of a direct function call."""
        if tok.type != "name":
            return False
        nxt = getattr(tok, "next", None)
        return nxt is not None and _tok_str(nxt) == "("

    @staticmethod
    def _first_arg_name(call_tok: Any) -> Optional[str]:
        """
        Return the string of the first argument token in a call.

        Prefers the AST's astOperand2 of the '(' node (left-most leaf);
        falls back to linear token scan inside the parentheses.
        """
        nxt = getattr(call_tok, "next", None)
        if nxt is None or _tok_str(nxt) != "(":
            return None

        # AST path
        arg_root = getattr(nxt, "astOperand2", None)
        if arg_root is not None:
            t = arg_root
            while True:
                left = getattr(t, "astOperand1", None)
                if left is None:
                    break
                t = left
            if t.type == "name":
                return _tok_str(t)

        # Linear fallback
        inner = getattr(nxt, "next", None)
        if inner and inner.type == "name":
            return _tok_str(inner)
        return None

    @staticmethod
    def _first_arg_varid(call_tok: Any) -> int:
        """Return varId (int) of the first argument, or 0."""
        nxt = getattr(call_tok, "next", None)
        if nxt is None or _tok_str(nxt) != "(":
            return 0

        arg_root = getattr(nxt, "astOperand2", None)
        if arg_root is not None:
            t = arg_root
            while True:
                left = getattr(t, "astOperand1", None)
                if left is None:
                    break
                t = left
            return int(getattr(t, "varId", 0) or 0)

        inner = getattr(nxt, "next", None)
        return int(getattr(inner, "varId", 0) or 0) if inner else 0

    @staticmethod
    def _nth_arg_name(call_tok: Any, n: int) -> Optional[str]:
        """
        Return the name-string of the n-th argument (0-based)
        by walking the token stream inside the parentheses.
        """
        nxt = getattr(call_tok, "next", None)
        if nxt is None or _tok_str(nxt) != "(":
            return None
        inner = getattr(nxt, "next", None)
        depth, idx = 1, 0
        while inner and depth > 0:
            s = _tok_str(inner)
            if s == "(":
                depth += 1
            elif s == ")":
                depth -= 1
                if depth == 0:
                    break
            elif s == "," and depth == 1:
                idx += 1
            elif depth == 1 and inner.type == "name" and idx == n:
                return s
            inner = getattr(inner, "next", None)
        return None

    # ── scope helpers ─────────────────────────────────────────────────────────

    @staticmethod
    def _scope_name(tok: Any) -> str:
        """Walk the scope chain to find the enclosing function name."""
        scope = getattr(tok, "scope", None)
        while scope:
            func = getattr(scope, "function", None)
            if func is not None:
                td = getattr(func, "tokenDef", None)
                return _tok_str(td) if td else _tok_str(func)
            scope = getattr(scope, "nestedIn", None)
        return "<global>"

    @staticmethod
    def _is_global_or_static(var: Any) -> bool:
        """True for variables at global or static storage duration."""
        if getattr(var, "isGlobal", False):
            return True
        if getattr(var, "isStatic", False):
            return True
        if (
            not getattr(var, "isLocal", False)
            and not getattr(var, "isArgument", False)
        ):
            return True
        return False

    # ── lock-state simulation ─────────────────────────────────────────────────

    @staticmethod
    def _build_func_token_map(cfg: Any) -> Dict[str, List[Any]]:
        """Group every token by its enclosing function name."""
        result: Dict[str, List[Any]] = defaultdict(list)
        for tok in _iter_tokens(cfg):
            fname = _SRVChecker._scope_name(tok)
            result[fname].append(tok)
        return result

    def _simulate_locks(
        self,
        tokens: List[Any],
        stop_before: Optional[Any] = None,
    ) -> Tuple[Set[int], Dict[int, int]]:
        """
        Simulate lock acquisitions / releases over *tokens*.

        Returns
        -------
        held : set of mutex varIds currently held
        count : map of mutex varId → nested lock count
        """
        held: Set[int] = set()
        count: Dict[int, int] = defaultdict(int)
        for tok in tokens:
            if stop_before is not None and tok is stop_before:
                break
            if tok.type != "name":
                continue
            s = _tok_str(tok)
            if s in _LOCK_FUNCS:
                mid = self._first_arg_varid(tok)
                count[mid] += 1
                held.add(mid)
            elif s in _UNLOCK_FUNCS:
                mid = self._first_arg_varid(tok)
                if count[mid] > 0:
                    count[mid] -= 1
                    if count[mid] == 0:
                        held.discard(mid)
        return held, count

    # ── shared variable discovery ─────────────────────────────────────────────

    @staticmethod
    def _find_shared_var_ids(cfg: Any) -> Tuple[Set[int], Dict[int, str]]:
        """
        Return (set_of_varIds, varId→name) for global/static variables
        that look like shared state.
        """
        ids: Set[int] = set()
        names: Dict[int, str] = {}
        for var in _iter_variables(cfg):
            if not _SRVChecker._is_global_or_static(var):
                continue
            name_tok = getattr(var, "nameToken", None)
            if name_tok is None:
                continue
            vname = _tok_str(name_tok)
            vid = int(getattr(var, "Id", 0) or 0)
            if vid:
                ids.add(vid)
                names[vid] = vname
        return ids, names

    # ── deduplication helper ──────────────────────────────────────────────────

    @staticmethod
    def _seen_key(tok: Any) -> Tuple[str, int]:
        return (_tok_file(tok), _tok_line(tok))


# ══════════════════════════════════════════════════════════════════════════════
#  PART 2 — INDIVIDUAL CHECKERS
# ══════════════════════════════════════════════════════════════════════════════

# ─────────────────────────────────────────────────────────────────────────────
#  SRV-01  Race conditions on shared variables (CWE-362)
# ─────────────────────────────────────────────────────────────────────────────

class RaceConditionChecker(_SRVChecker):
    """
    Flags accesses to global/static variables that occur inside a function
    with no mutex held at that point.

    Strategy
    ────────
    For every function in the TU, simulate the lock-hold state token by
    token.  When a shared-variable token is encountered while the held-lock
    set is empty, record a finding.

    CWE-362: Concurrent Execution Using Shared Resource with Improper
             Synchronisation ('Race Condition')
    """

    name: ClassVar[str]        = "srv-race-condition"
    description: ClassVar[str] = "Race condition on shared variable (CWE-362)"
    error_ids: ClassVar[FrozenSet[str]] = frozenset({"sharedVarRace"})
    default_severity: ClassVar[DiagnosticSeverity] = DiagnosticSeverity.WARNING
    cwe_ids: ClassVar[Dict[str, int]] = {"sharedVarRace": 362}

    def __init__(self) -> None:
        super().__init__()
        # (tok, var_name, func_name)
        self._findings: List[Tuple[Any, str, str]] = []

    def collect_evidence(self, ctx: CheckerContext) -> None:
        cfg = ctx.cfg
        shared_ids, shared_names = self._find_shared_var_ids(cfg)
        if not shared_ids:
            return

        func_map = self._build_func_token_map(cfg)

        for fname, tokens in func_map.items():
            if fname == "<global>":
                continue
            held: Set[int] = set()
            lock_cnt: Dict[int, int] = defaultdict(int)

            for tok in tokens:
                s = _tok_str(tok)

                # ── maintain lock state ──────────────────────────────
                if tok.type == "name" and s in _LOCK_FUNCS:
                    mid = self._first_arg_varid(tok)
                    lock_cnt[mid] += 1
                    held.add(mid)
                elif tok.type == "name" and s in _UNLOCK_FUNCS:
                    mid = self._first_arg_varid(tok)
                    if lock_cnt[mid] > 0:
                        lock_cnt[mid] -= 1
                        if lock_cnt[mid] == 0:
                            held.discard(mid)

                # ── check shared-variable access ─────────────────────
                vid = int(getattr(tok, "varId", 0) or 0)
                if vid in shared_ids and not held:
                    self._findings.append((tok, shared_names[vid], fname))

    def diagnose(self, ctx: CheckerContext) -> None:
        seen: Set[Tuple[str, int]] = set()
        for tok, vname, fname in self._findings:
            key = self._seen_key(tok)
            if key in seen:
                continue
            seen.add(key)
            self._emit(
                error_id="sharedVarRace",
                message=(
                    f"Shared variable '{vname}' accessed in '{fname}' "
                    f"without holding any mutex — possible race condition "
                    f"(CWE-362)"
                ),
                file=_tok_file(tok),
                line=_tok_line(tok),
                column=_tok_col(tok),
                severity=DiagnosticSeverity.WARNING,
                confidence=Confidence.MEDIUM,
            )


# ─────────────────────────────────────────────────────────────────────────────
#  SRV-02  TOCTOU (CWE-367)
# ─────────────────────────────────────────────────────────────────────────────

class TOCTOURaceChecker(_SRVChecker):
    """
    Detects time-of-check / time-of-use races on filesystem paths.

    Pattern: within the same function, a check function (access, stat, …)
    is followed by a use function (open, unlink, chmod, …) on the *same*
    path argument, with no lock spanning both.

    CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition
    """

    name: ClassVar[str]        = "srv-toctou"
    description: ClassVar[str] = "TOCTOU race condition (CWE-367)"
    error_ids: ClassVar[FrozenSet[str]] = frozenset({"toctouRace"})
    default_severity: ClassVar[DiagnosticSeverity] = DiagnosticSeverity.WARNING
    cwe_ids: ClassVar[Dict[str, int]] = {"toctouRace": 367}

    def __init__(self) -> None:
        super().__init__()
        # (check_tok, use_tok, path_arg, check_fn, use_fn)
        self._findings: List[Tuple[Any, Any, str, str, str]] = []

    def collect_evidence(self, ctx: CheckerContext) -> None:
        cfg = ctx.cfg
        func_map = self._build_func_token_map(cfg)

        for fname, tokens in func_map.items():
            # First pass: record check calls keyed by path arg
            # list of (tok, path_arg, func_name)
            checks: List[Tuple[Any, str, str]] = []

            for tok in tokens:
                if tok.type != "name":
                    continue
                s = _tok_str(tok)
                if s in _TOCTOU_CHECK_FUNCS:
                    path = self._first_arg_name(tok) or ""
                    checks.append((tok, path, s))

            if not checks:
                continue

            # Second pass: find use calls that follow a check on the
            # same path with no intervening lock
            held: Set[int] = set()
            lock_cnt: Dict[int, int] = defaultdict(int)

            for tok in tokens:
                s = _tok_str(tok)

                if tok.type == "name" and s in _LOCK_FUNCS:
                    mid = self._first_arg_varid(tok)
                    lock_cnt[mid] += 1
                    held.add(mid)
                elif tok.type == "name" and s in _UNLOCK_FUNCS:
                    mid = self._first_arg_varid(tok)
                    if lock_cnt[mid] > 0:
                        lock_cnt[mid] -= 1
                        if lock_cnt[mid] == 0:
                            held.discard(mid)

                if tok.type != "name" or s not in _TOCTOU_USE_FUNCS:
                    continue
                path = self._first_arg_name(tok) or ""
                use_line = _tok_line(tok)

                for chk_tok, chk_path, chk_fn in checks:
                    if (
                        chk_path
                        and chk_path == path
                        and _tok_line(chk_tok) < use_line
                        and not held
                    ):
                        self._findings.append(
                            (chk_tok, tok, path, chk_fn, s)
                        )

    def diagnose(self, ctx: CheckerContext) -> None:
        seen: Set[Tuple[str, int]] = set()
        for chk_tok, use_tok, path, chk_fn, use_fn in self._findings:
            key = self._seen_key(use_tok)
            if key in seen:
                continue
            seen.add(key)
            self._emit(
                error_id="toctouRace",
                message=(
                    f"TOCTOU: path '{path}' checked by '{chk_fn}()' at "
                    f"line {_tok_line(chk_tok)}, then used by '{use_fn}()' "
                    f"— another process may alter the path between the "
                    f"check and the use (CWE-367)"
                ),
                file=_tok_file(use_tok),
                line=_tok_line(use_tok),
                column=_tok_col(use_tok),
                severity=DiagnosticSeverity.WARNING,
                confidence=Confidence.HIGH,
                secondary=(_tok_loc(chk_tok),),
            )


# ─────────────────────────────────────────────────────────────────────────────
#  SRV-03  Mutex Misuse (CWE-667)
# ─────────────────────────────────────────────────────────────────────────────

class MutexMisuseChecker(_SRVChecker):
    """
    Detects per-function mutex discipline violations:

    - double-lock on a non-recursive mutex
    - unlock without a prior matching lock
    - mutex locked but never unlocked in that function (lock leak)

    CWE-667: Improper Locking
    """

    name: ClassVar[str]        = "srv-mutex-misuse"
    description: ClassVar[str] = "Mutex misuse: double-lock / spurious-unlock / leak"
    error_ids: ClassVar[FrozenSet[str]] = frozenset({
        "mutexDoubleLock",
        "mutexSpuriousUnlock",
        "mutexLockLeak",
    })
    default_severity: ClassVar[DiagnosticSeverity] = DiagnosticSeverity.ERROR
    cwe_ids: ClassVar[Dict[str, int]] = {
        "mutexDoubleLock":      667,
        "mutexSpuriousUnlock":  667,
        "mutexLockLeak":        667,
    }

    def __init__(self) -> None:
        super().__init__()
        # (error_id, message, tok)
        self._findings: List[Tuple[str, str, Any]] = []

    def collect_evidence(self, ctx: CheckerContext) -> None:
        cfg = ctx.cfg
        func_map = self._build_func_token_map(cfg)

        for fname, tokens in func_map.items():
            if fname == "<global>":
                continue

            # mutex_id → lock count
            lock_cnt: Dict[int, int] = defaultdict(int)
            # mutex_id → token of first acquisition
            first_tok: Dict[int, Any] = {}

            for tok in tokens:
                if tok.type != "name":
                    continue
                s = _tok_str(tok)

                if s in _LOCK_FUNCS:
                    family = _LOCK_FUNCS[s]
                    is_recursive = (
                        "recursive" in family
                        or "nest" in family
                    )
                    mid   = self._first_arg_varid(tok)
                    mname = self._first_arg_name(tok) or "?"

                    if lock_cnt[mid] > 0 and not is_recursive:
                        prev_line = _tok_line(first_tok.get(mid, tok))
                        self._findings.append((
                            "mutexDoubleLock",
                            f"Non-recursive mutex '{mname}' locked twice in "
                            f"'{fname}' (first lock at line {prev_line})",
                            tok,
                        ))
                    else:
                        if lock_cnt[mid] == 0:
                            first_tok[mid] = tok
                        lock_cnt[mid] += 1

                elif s in _UNLOCK_FUNCS:
                    mid   = self._first_arg_varid(tok)
                    mname = self._first_arg_name(tok) or "?"
                    if lock_cnt[mid] == 0:
                        self._findings.append((
                            "mutexSpuriousUnlock",
                            f"Mutex '{mname}' unlocked in '{fname}' "
                            f"without a prior matching lock",
                            tok,
                        ))
                    else:
                        lock_cnt[mid] -= 1

            # Any still-held mutex at end of function = lock leak
            for mid, cnt in lock_cnt.items():
                if cnt > 0:
                    ft = first_tok.get(mid)
                    if ft:
                        self._findings.append((
                            "mutexLockLeak",
                            f"Mutex (varId={mid}) locked in '{fname}' "
                            f"but never unlocked — lock leak",
                            ft,
                        ))

    def diagnose(self, ctx: CheckerContext) -> None:
        seen: Set[Tuple[str, int]] = set()
        for eid, msg, tok in self._findings:
            key = self._seen_key(tok)
            if key in seen:
                continue
            seen.add(key)
            self._emit(
                error_id=eid,
                message=msg,
                file=_tok_file(tok),
                line=_tok_line(tok),
                column=_tok_col(tok),
                severity=DiagnosticSeverity.ERROR,
                confidence=Confidence.MEDIUM,
            )


# ─────────────────────────────────────────────────────────────────────────────
#  SRV-04  Deadlock via lock-order inversion (CWE-833)
# ─────────────────────────────────────────────────────────────────────────────

class DeadlockChecker(_SRVChecker):
    """
    Detects potential deadlock through global lock-order inversion.

    Algorithm
    ─────────
    1. For each function, record the ordered sequence in which distinct
       mutexes are first acquired: (mutex_A, mutex_B, …).
    2. Build a directed "A must precede B" constraint graph.
    3. If both (A, B) and (B, A) appear as edges from *different* functions,
       flag the second-seen acquisition site.

    CWE-833: Deadlock
    """

    name: ClassVar[str]        = "srv-deadlock"
    description: ClassVar[str] = "Potential deadlock via lock-order inversion (CWE-833)"
    error_ids: ClassVar[FrozenSet[str]] = frozenset({"potentialDeadlock"})
    default_severity: ClassVar[DiagnosticSeverity] = DiagnosticSeverity.ERROR
    cwe_ids: ClassVar[Dict[str, int]] = {"potentialDeadlock": 833}

    def __init__(self) -> None:
        super().__init__()
        self._findings: List[Tuple[Any, str]] = []

    def collect_evidence(self, ctx: CheckerContext) -> None:
        cfg = ctx.cfg
        func_map = self._build_func_token_map(cfg)

        # func_name → ordered list of (mutex_id, tok) for first-seen acqs.
        func_order: Dict[str, List[Tuple[int, Any]]] = defaultdict(list)
        mutex_names: Dict[int, str] = {}

        for fname, tokens in func_map.items():
            if fname == "<global>":
                continue
            seen_in_func: Set[int] = set()
            for tok in tokens:
                if tok.type != "name":
                    continue
                s = _tok_str(tok)
                if s not in _LOCK_FUNCS:
                    continue
                mid = self._first_arg_varid(tok)
                if mid == 0:
                    continue
                mname = self._first_arg_name(tok) or f"mutex_{mid}"
                mutex_names[mid] = mname
                if mid not in seen_in_func:
                    seen_in_func.add(mid)
                    func_order[fname].append((mid, tok))

        # Build global precedence edges:
        # pair (A, B)  →  (func_name, tok_B)  meaning "A locked before B"
        precedence: Dict[Tuple[int, int], Tuple[str, Any]] = {}

        for fname, order in func_order.items():
            for i, (mid_a, _) in enumerate(order):
                for mid_b, tok_b in order[i + 1:]:
                    pair = (mid_a, mid_b)
                    if pair not in precedence:
                        precedence[pair] = (fname, tok_b)

        # Detect inversions
        for (a, b), (fn_ab, tok_ab) in precedence.items():
            inv = (b, a)
            if inv not in precedence:
                continue
            fn_ba, tok_ba = precedence[inv]
            if fn_ab == fn_ba:
                continue  # same function — cannot deadlock with itself
            na = mutex_names.get(a, f"mutex_{a}")
            nb = mutex_names.get(b, f"mutex_{b}")
            self._findings.append((
                tok_ab,
                f"Potential deadlock: '{fn_ab}' acquires '{na}' then '{nb}', "
                f"but '{fn_ba}' acquires '{nb}' then '{na}' — "
                f"inconsistent lock ordering (CWE-833)",
            ))

    def diagnose(self, ctx: CheckerContext) -> None:
        seen: Set[Tuple[str, int]] = set()
        for tok, msg in self._findings:
            key = self._seen_key(tok)
            if key in seen:
                continue
            seen.add(key)
            self._emit(
                error_id="potentialDeadlock",
                message=msg,
                file=_tok_file(tok),
                line=_tok_line(tok),
                column=_tok_col(tok),
                severity=DiagnosticSeverity.ERROR,
                confidence=Confidence.MEDIUM,
            )


# ─────────────────────────────────────────────────────────────────────────────
#  SRV-05  Lock-order hierarchy violation (CWE-833)
# ─────────────────────────────────────────────────────────────────────────────

class LockHierarchyChecker(_SRVChecker):
    """
    Enforces a canonical lock hierarchy derived from mutex declaration order.

    Variables declared earlier in the translation unit (lower line number)
    have higher priority and must be acquired *first*.  Attempting to acquire
    a higher-priority mutex while already holding a lower-priority one is a
    lock-hierarchy violation.

    CWE-833: Deadlock (lock-order inversion sub-class)
    """

    name: ClassVar[str]        = "srv-lock-hierarchy"
    description: ClassVar[str] = "Lock-hierarchy violation (CWE-833)"
    error_ids: ClassVar[FrozenSet[str]] = frozenset({"lockHierarchyViolation"})
    default_severity: ClassVar[DiagnosticSeverity] = DiagnosticSeverity.WARNING
    cwe_ids: ClassVar[Dict[str, int]] = {"lockHierarchyViolation": 833}

    def __init__(self) -> None:
        super().__init__()
        self._findings: List[Tuple[Any, str]] = []

    def collect_evidence(self, ctx: CheckerContext) -> None:
        cfg = ctx.cfg

        # Build mutex → declaration line (= priority; lower is higher priority)
        mutex_prio: Dict[int, int] = {}    # varId → decl_line
        mutex_name: Dict[int, str] = {}    # varId → name

        for var in _iter_variables(cfg):
            name_tok = getattr(var, "nameToken", None)
            if name_tok is None:
                continue
            vname = _tok_str(name_tok)
            type_tok = getattr(var, "typeStartToken", None)
            if type_tok is None:
                continue
            tstr = _tok_str(type_tok)
            if tstr not in _MUTEX_TYPES and "mutex" not in vname.lower():
                continue
            vid = int(getattr(var, "Id", 0) or 0)
            if vid:
                mutex_prio[vid] = _tok_line(name_tok)
                mutex_name[vid] = vname

        if len(mutex_prio) < 2:
            return

        func_map = self._build_func_token_map(cfg)

        for fname, tokens in func_map.items():
            if fname == "<global>":
                continue
            # List of (priority, mutex_id, tok) currently held
            held_stack: List[Tuple[int, int, Any]] = []

            for tok in tokens:
                if tok.type != "name":
                    continue
                s = _tok_str(tok)

                if s in _LOCK_FUNCS:
                    mid = self._first_arg_varid(tok)
                    if mid not in mutex_prio:
                        continue
                    prio = mutex_prio[mid]
                    # Any held mutex with *higher* line number (= lower priority)
                    # should not be held when acquiring this one
                    for h_prio, h_mid, h_tok in held_stack:
                        if h_prio > prio:
                            self._findings.append((
                                tok,
                                f"Lock-hierarchy violation in '{fname}': "
                                f"acquiring '{mutex_name.get(mid,'?')}' "
                                f"(decl line {prio}) while holding "
                                f"'{mutex_name.get(h_mid,'?')}' "
                                f"(decl line {h_prio}) — "
                                f"higher-priority locks must be acquired first "
                                f"(CWE-833)",
                            ))
                    held_stack.append((prio, mid, tok))

                elif s in _UNLOCK_FUNCS:
                    mid = self._first_arg_varid(tok)
                    held_stack = [
                        (p, m, t) for p, m, t in held_stack if m != mid
                    ]

    def diagnose(self, ctx: CheckerContext) -> None:
        seen: Set[Tuple[str, int]] = set()
        for tok, msg in self._findings:
            key = self._seen_key(tok)
            if key in seen:
                continue
            seen.add(key)
            self._emit(
                error_id="lockHierarchyViolation",
                message=msg,
                file=_tok_file(tok),
                line=_tok_line(tok),
                column=_tok_col(tok),
                severity=DiagnosticSeverity.WARNING,
                confidence=Confidence.MEDIUM,
            )


# ─────────────────────────────────────────────────────────────────────────────
#  SRV-06  Shared variable written without protection (CWE-362)
# ─────────────────────────────────────────────────────────────────────────────

class UnprotectedSharedWriteChecker(_SRVChecker):
    """
    Flags write accesses to global/static variables that occur while no
    mutex is held.

    A token is considered a *write* when it is the left-hand operand
    (astOperand1) of an assignment AST node.

    CWE-362: Race Condition
    """

    name: ClassVar[str]        = "srv-unprotected-write"
    description: ClassVar[str] = "Shared variable written without lock (CWE-362)"
    error_ids: ClassVar[FrozenSet[str]] = frozenset({"unprotectedSharedWrite"})
    default_severity: ClassVar[DiagnosticSeverity] = DiagnosticSeverity.WARNING
    cwe_ids: ClassVar[Dict[str, int]] = {"unprotectedSharedWrite": 362}

    def __init__(self) -> None:
        super().__init__()
        self._findings: List[Tuple[Any, str, str]] = []

    def collect_evidence(self, ctx: CheckerContext) -> None:
        cfg = ctx.cfg
        shared_ids, shared_names = self._find_shared_var_ids(cfg)
        if not shared_ids:
            return

        func_map = self._build_func_token_map(cfg)

        for fname, tokens in func_map.items():
            if fname == "<global>":
                continue
            held: Set[int] = set()
            lock_cnt: Dict[int, int] = defaultdict(int)

            for tok in tokens:
                s = _tok_str(tok)

                # Maintain lock state for name tokens
                if tok.type == "name":
                    if s in _LOCK_FUNCS:
                        mid = self._first_arg_varid(tok)
                        lock_cnt[mid] += 1
                        held.add(mid)
                    elif s in _UNLOCK_FUNCS:
                        mid = self._first_arg_varid(tok)
                        if lock_cnt[mid] > 0:
                            lock_cnt[mid] -= 1
                            if lock_cnt[mid] == 0:
                                held.discard(mid)

                # Check for write to shared variable
                vid = int(getattr(tok, "varId", 0) or 0)
                if vid not in shared_ids:
                    continue
                parent = getattr(tok, "astParent", None)
                is_write = (
                    parent is not None
                    and getattr(parent, "isAssignmentOp", False)
                    and getattr(parent, "astOperand1", None) is tok
                )
                if is_write and not held:
                    self._findings.append((
                        tok, shared_names[vid], fname,
                    ))

    def diagnose(self, ctx: CheckerContext) -> None:
        seen: Set[Tuple[str, int]] = set()
        for tok, vname, fname in self._findings:
            key = self._seen_key(tok)
            if key in seen:
                continue
            seen.add(key)
            self._emit(
                error_id="unprotectedSharedWrite",
                message=(
                    f"Shared variable '{vname}' written in '{fname}' "
                    f"without holding any mutex — possible data race "
                    f"(CWE-362)"
                ),
                file=_tok_file(tok),
                line=_tok_line(tok),
                column=_tok_col(tok),
                severity=DiagnosticSeverity.WARNING,
                confidence=Confidence.MEDIUM,
            )


# ─────────────────────────────────────────────────────────────────────────────
#  SRV-07  Non-atomic read-modify-write (CWE-366)
# ─────────────────────────────────────────────────────────────────────────────

class NonAtomicRMWChecker(_SRVChecker):
    """
    Detects read-modify-write operators (++, --, +=, -=, …) applied to
    global/static variables outside any lock or _Atomic type.

    CWE-366: Race Condition within a Thread
    """

    name: ClassVar[str]        = "srv-non-atomic-rmw"
    description: ClassVar[str] = "Non-atomic read-modify-write on shared variable (CWE-366)"
    error_ids: ClassVar[FrozenSet[str]] = frozenset({"nonAtomicRMW"})
    default_severity: ClassVar[DiagnosticSeverity] = DiagnosticSeverity.WARNING
    cwe_ids: ClassVar[Dict[str, int]] = {"nonAtomicRMW": 366}

    def __init__(self) -> None:
        super().__init__()
        # (tok, var_name, op, func_name)
        self._findings: List[Tuple[Any, str, str, str]] = []

    def collect_evidence(self, ctx: CheckerContext) -> None:
        cfg = ctx.cfg
        shared_ids, shared_names = self._find_shared_var_ids(cfg)
        if not shared_ids:
            return

        func_map = self._build_func_token_map(cfg)

        for fname, tokens in func_map.items():
            if fname == "<global>":
                continue
            held: Set[int] = set()
            lock_cnt: Dict[int, int] = defaultdict(int)

            for tok in tokens:
                s = _tok_str(tok)

                # Maintain lock state
                if tok.type == "name":
                    if s in _LOCK_FUNCS:
                        mid = self._first_arg_varid(tok)
                        lock_cnt[mid] += 1
                        held.add(mid)
                    elif s in _UNLOCK_FUNCS:
                        mid = self._first_arg_varid(tok)
                        if lock_cnt[mid] > 0:
                            lock_cnt[mid] -= 1
                            if lock_cnt[mid] == 0:
                                held.discard(mid)
                    continue  # name tokens are not RMW operators

                # Check for RMW operator on a shared variable
                if s not in _RMW_OPS:
                    continue

                # Operand 1 is the variable being modified
                op1 = getattr(tok, "astOperand1", None)
                if op1 is None:
                    continue
                vid = int(getattr(op1, "varId", 0) or 0)
                if vid not in shared_ids:
                    continue
                if held:
                    continue  # protected — fine

                # Check if variable has _Atomic type qualifier
                var_obj = getattr(op1, "variable", None)
                vt_tok = getattr(var_obj, "typeStartToken", None) if var_obj else None
                type_str = _tok_str(vt_tok) if vt_tok else ""
                if _ATOMIC_TYPE_RE.search(type_str):
                    continue  # atomic type — fine

                self._findings.append((
                    tok, shared_names[vid], s, fname,
                ))

    def diagnose(self, ctx: CheckerContext) -> None:
        seen: Set[Tuple[str, int]] = set()
        for tok, vname, op, fname in self._findings:
            key = self._seen_key(tok)
            if key in seen:
                continue
            seen.add(key)
            self._emit(
                error_id="nonAtomicRMW",
                message=(
                    f"Non-atomic RMW '{op}' on shared variable '{vname}' "
                    f"in '{fname}' without a lock or _Atomic type — "
                    f"race condition possible (CWE-366)"
                ),
                file=_tok_file(tok),
                line=_tok_line(tok),
                column=_tok_col(tok),
                severity=DiagnosticSeverity.WARNING,
                confidence=Confidence.MEDIUM,
            )


# ─────────────────────────────────────────────────────────────────────────────
#  SRV-08  Data races — cross-function conflicting accesses (CWE-362)
# ─────────────────────────────────────────────────────────────────────────────

class DataRaceChecker(_SRVChecker):
    """
    Conservative cross-function data race detector.

    For each global/static variable, collect every (function, lock_set, is_write)
    access triple.  Two accesses on the *same* variable from *different*
    functions are a data race if:

    - at least one is a write, AND
    - they share no common lock (lock sets are disjoint)

    CWE-362: Race Condition
    """

    name: ClassVar[str]        = "srv-data-race"
    description: ClassVar[str] = "Data race: conflicting accesses without common lock (CWE-362)"
    error_ids: ClassVar[FrozenSet[str]] = frozenset({"dataRace"})
    default_severity: ClassVar[DiagnosticSeverity] = DiagnosticSeverity.ERROR
    cwe_ids: ClassVar[Dict[str, int]] = {"dataRace": 362}

    def __init__(self) -> None:
        super().__init__()
        self._findings: List[Tuple[Any, str]] = []

    def collect_evidence(self, ctx: CheckerContext) -> None:
        cfg = ctx.cfg
        shared_ids, shared_names = self._find_shared_var_ids(cfg)
        if not shared_ids:
            return

        func_map = self._build_func_token_map(cfg)

        # var_id → list of (func_name, frozenset(lock_ids), is_write, tok)
        accesses: Dict[int, List[Tuple[str, FrozenSet[int], bool, Any]]] = \
            defaultdict(list)

        for fname, tokens in func_map.items():
            if fname == "<global>":
                continue
            held: Set[int] = set()
            lock_cnt: Dict[int, int] = defaultdict(int)

            for tok in tokens:
                s = _tok_str(tok)

                if tok.type == "name":
                    if s in _LOCK_FUNCS:
                        mid = self._first_arg_varid(tok)
                        lock_cnt[mid] += 1
                        held.add(mid)
                    elif s in _UNLOCK_FUNCS:
                        mid = self._first_arg_varid(tok)
                        if lock_cnt[mid] > 0:
                            lock_cnt[mid] -= 1
                            if lock_cnt[mid] == 0:
                                held.discard(mid)

                vid = int(getattr(tok, "varId", 0) or 0)
                if vid not in shared_ids:
                    continue

                parent = getattr(tok, "astParent", None)
                is_write = (
                    parent is not None
                    and getattr(parent, "isAssignmentOp", False)
                    and getattr(parent, "astOperand1", None) is tok
                )
                accesses[vid].append((
                    fname, frozenset(held), is_write, tok,
                ))

        # Find conflicting pairs
        for vid, acc_list in accesses.items():
            vname = shared_names.get(vid, f"var_{vid}")
            writes = [a for a in acc_list if a[2]]
            reads  = [a for a in acc_list if not a[2]]

            # write vs. read, write vs. write — from different functions
            for w_fn, w_ls, _, w_tok in writes:
                for r_fn, r_ls, r_is_w, r_tok in reads + [
                    (fn, ls, True, t)
                    for fn, ls, iw, t in writes
                    if fn != w_fn and iw
                ]:
                    if r_fn == w_fn:
                        continue
                    if w_ls & r_ls:
                        continue  # common lock — safe
                    self._findings.append((
                        w_tok,
                        f"Data race on '{vname}': "
                        f"written in '{w_fn}' (locks={set(w_ls) or '∅'}) "
                        f"and {'written' if r_is_w else 'read'} in "
                        f"'{r_fn}' (locks={set(r_ls) or '∅'}) — "
                        f"no common lock guards both accesses (CWE-362)",
                    ))

    def diagnose(self, ctx: CheckerContext) -> None:
        seen: Set[Tuple[str, int]] = set()
        for tok, msg in self._findings:
            key = self._seen_key(tok)
            if key in seen:
                continue
            seen.add(key)
            self._emit(
                error_id="dataRace",
                message=msg,
                file=_tok_file(tok),
                line=_tok_line(tok),
                column=_tok_col(tok),
                severity=DiagnosticSeverity.ERROR,
                confidence=Confidence.MEDIUM,
            )


# ─────────────────────────────────────────────────────────────────────────────
#  SRV-09  Unsafe call inside signal handler (CWE-828)
# ─────────────────────────────────────────────────────────────────────────────

class SignalHandlerSafetyChecker(_SRVChecker):
    """
    Detects calls to async-signal-unsafe functions inside signal handlers.

    Discovery
    ─────────
    1. Find all handler function names registered via signal() or via
       assignment to a .sa_handler / .sa_sigaction struct field.
    2. For each discovered handler, scan its body for calls to functions
       in _SIGNAL_UNSAFE_FUNCS.

    Additionally flags:
    - mutex lock/unlock calls inside handlers (may deadlock if the signal
      fires while the mutex is held by the interrupted thread)
    - condition-variable waits inside handlers

    CWE-828: Signal Handler with Functionality that is not
             Asynchronous-Signal-Safe
    """

    name: ClassVar[str]        = "srv-signal-handler"
    description: ClassVar[str] = "Unsafe call inside signal handler (CWE-828)"
    error_ids: ClassVar[FrozenSet[str]] = frozenset({
        "unsafeSignalHandlerCall",
        "signalHandlerMutexCall",
    })
    default_severity: ClassVar[DiagnosticSeverity] = DiagnosticSeverity.ERROR
    cwe_ids: ClassVar[Dict[str, int]] = {
        "unsafeSignalHandlerCall": 828,
        "signalHandlerMutexCall":  828,
    }

    def __init__(self) -> None:
        super().__init__()
        self._handler_names: Set[str] = set()
        self._findings: List[Tuple[str, str, Any]] = []

    def collect_evidence(self, ctx: CheckerContext) -> None:
        cfg = ctx.cfg

        # ── Phase 1: discover handler names ──────────────────────────────────
        for tok in _iter_tokens(cfg):
            if tok.type != "name":
                continue
            s = _tok_str(tok)

            # signal(SIGNUM, handler_name)
            if s == "signal":
                # Walk linearly inside the parentheses for the 2nd argument
                nxt = getattr(tok, "next", None)
                if nxt is None or _tok_str(nxt) != "(":
                    continue
                inner = getattr(nxt, "next", None)
                depth, comma_seen = 1, False
                while inner and depth > 0:
                    si = _tok_str(inner)
                    if si == "(":
                        depth += 1
                    elif si == ")":
                        depth -= 1
                    elif si == "," and depth == 1:
                        comma_seen = True
                    elif (
                        comma_seen
                        and inner.type == "name"
                        and depth == 1
                        and si not in {"SIG_DFL", "SIG_IGN", "SIG_ERR"}
                    ):
                        self._handler_names.add(si)
                        break
                    inner = getattr(inner, "next", None)

            # sa_handler / sa_sigaction struct-field assignment
            if s in {"sa_handler", "sa_sigaction"}:
                parent = getattr(tok, "astParent", None)
                if parent and getattr(parent, "isAssignmentOp", False):
                    rhs = getattr(parent, "astOperand2", None)
                    if rhs and rhs.type == "name":
                        self._handler_names.add(_tok_str(rhs))

        if not self._handler_names:
            return

        # ── Phase 2: scan handler bodies ─────────────────────────────────────
        for tok in _iter_tokens(cfg):
            if tok.type != "name":
                continue
            fname = self._scope_name(tok)
            if fname not in self._handler_names:
                continue

            s = _tok_str(tok)
            nxt = getattr(tok, "next", None)
            if nxt is None or _tok_str(nxt) != "(":
                continue  # not a call

            if s in _LOCK_FUNCS or s in _UNLOCK_FUNCS:
                self._findings.append((
                    "signalHandlerMutexCall",
                    f"Signal handler '{fname}' calls mutex function '{s}()' "
                    f"— not async-signal-safe; may deadlock if signal "
                    f"fires while the mutex is held (CWE-828)",
                    tok,
                ))
            elif s in _SIGNAL_UNSAFE_FUNCS:
                self._findings.append((
                    "unsafeSignalHandlerCall",
                    f"Signal handler '{fname}' calls '{s}()' which is not "
                    f"async-signal-safe (POSIX.1-2017) — undefined behaviour "
                    f"if the signal interrupts a call to the same function "
                    f"(CWE-828)",
                    tok,
                ))

    def diagnose(self, ctx: CheckerContext) -> None:
        seen: Set[Tuple[str, int]] = set()
        for eid, msg, tok in self._findings:
            key = self._seen_key(tok)
            if key in seen:
                continue
            seen.add(key)
            self._emit(
                error_id=eid,
                message=msg,
                file=_tok_file(tok),
                line=_tok_line(tok),
                column=_tok_col(tok),
                severity=DiagnosticSeverity.ERROR,
                confidence=Confidence.HIGH,
            )


# ══════════════════════════════════════════════════════════════════════════════
#  PART 3 — REGISTRY
# ══════════════════════════════════════════════════════════════════════════════

_SRV_REGISTRY = CheckerRegistry()

for _cls in [
    RaceConditionChecker,
    TOCTOURaceChecker,
    MutexMisuseChecker,
    DeadlockChecker,
    LockHierarchyChecker,
    UnprotectedSharedWriteChecker,
    NonAtomicRMWChecker,
    DataRaceChecker,
    SignalHandlerSafetyChecker,
]:
    _SRV_REGISTRY.register(_cls)


# ══════════════════════════════════════════════════════════════════════════════
#  PART 4 — ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

def print_diagnostic(diag):
    """
    Print a Diagnostic object in standard Cppcheck format:
    [filename:line]: (severity) message [addon-errorId]
    """
    loc = f"{diag.location.file}:{diag.location.line}"
    severity = diag.severity.value
    msg = diag.message
    if diag.extra:
        msg += f" ({diag.extra})"
    error_id = f"{diag.addon}-{diag.error_id}"
    sys.stderr.write(f"[{loc}]: ({severity}) {msg} [{error_id}]\n")


def main(dump_file: str) -> int:
    """
    Cppcheck addon entry point.

    Parameters
    ----------
    dump_file : str
        Path to the ``.dump`` file produced by ``cppcheck --dump``.

    Returns
    -------
    int
        0  — no findings
        1  — one or more findings emitted
        2  — internal error (missing dependency, bad file, …)
    """
    try:
        from cppcheckdata import parsedump
    except ImportError:
        sys.stderr.write(
            "ERROR: 'cppcheckdata' module not found.\n"
            "       Install it with:  pip install cppcheckdata\n"
        )
        return 2

    try:
        data = parsedump(dump_file)
    except Exception as exc:
        sys.stderr.write(f"ERROR: cannot parse dump file '{dump_file}': {exc}\n")
        return 2

    sm      = SuppressionManager()
    runner  = CheckerRunner(registry=_SRV_REGISTRY, suppressions=sm)
    found   = False

    for cfg in getattr(data, "configurations", []):
        sm.load_inline_suppressions(cfg)
        results: CheckerRunResults = runner.run(cfg)
        for diag in results.diagnostics:
            print_diagnostic(diag)
            found = True

    return 1 if found else 0


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write(
            "Usage: python3 SharedResourceValidator.py <file.c.dump>\n"
        )
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
