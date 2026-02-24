#!/usr/bin/env python3
"""
CompilerBarrierChecker.py — Cppcheck addon
===========================================
Domain  : Compiler barrier and memory-ordering misuse in C
Checkers: CBC-01 … CBC-10
CWEs    : 362, 366, 367, 667, 696

Hardening contract
------------------
* NEVER call int(tok.varId) directly.
* ALWAYS use _safe_vid() / _safe_vid_tok() for ALL varId access.
* Findings emitted as single-line JSON on stdout (cppcheck addon protocol).
"""

from __future__ import annotations

import sys
import json
import re
from collections import defaultdict
from typing import (
    Dict, FrozenSet, Iterator, List, Optional, Set, Tuple
)

# ---------------------------------------------------------------------------
# Bootstrap: locate cppcheckdata
# ---------------------------------------------------------------------------
try:
    import cppcheckdata
except ImportError:
    import os as _os
    import importlib.util as _ilu

    _addon_dir = _os.path.dirname(_os.path.abspath(__file__))
    for _candidate in [
        _os.path.join(_addon_dir, "cppcheckdata.py"),
        _os.path.join(_addon_dir, "..", "cppcheckdata.py"),
        "/usr/share/cppcheck/addons/cppcheckdata.py",
        "/usr/lib/cppcheck/addons/cppcheckdata.py",
    ]:
        if _os.path.isfile(_candidate):
            _spec = _ilu.spec_from_file_location("cppcheckdata", _candidate)
            cppcheckdata = _ilu.module_from_spec(_spec)      # type: ignore[assignment]
            _spec.loader.exec_module(_spec.loader)            # type: ignore[union-attr]
            break
    else:
        sys.exit("CompilerBarrierChecker: cannot locate cppcheckdata.py")


# ===========================================================================
# §1  Hardened variable-ID helpers            (hardening contract)
# ===========================================================================

def _safe_vid(tok) -> int:
    """Return tok.varId as int, or 0 on any failure — NEVER raises."""
    try:
        raw = tok.varId
        if raw is None:
            return 0
        return int(raw)
    except (TypeError, ValueError, AttributeError):
        return 0


def _safe_vid_tok(tok) -> int:
    """Symmetric alias kept for readability parity with other suite addons."""
    return _safe_vid(tok)


# ===========================================================================
# §2  Generic token helpers
# ===========================================================================

def _s(tok) -> str:
    """Safe tok.str — returns '' on any failure."""
    try:
        return tok.str or ""
    except AttributeError:
        return ""


def _tokens(cfg) -> Iterator:
    """Yield every token in the configuration in source order."""
    try:
        for tok in cfg.tokenlist:
            yield tok
    except (AttributeError, TypeError):
        pass


def _tok_file_line(tok) -> Tuple[str, int, int]:
    try:
        f  = tok.file    or ""
        ln = int(tok.linenr) if tok.linenr is not None else 0
        co = int(tok.column) if tok.column is not None else 0
        return f, ln, co
    except (AttributeError, TypeError, ValueError):
        return "", 0, 0


def _var_name(tok) -> str:
    """Return the canonical variable name for tok, or ''."""
    try:
        if tok.variable:
            return tok.variable.name or ""
    except AttributeError:
        pass
    return _s(tok)


def _is_function_call(tok) -> bool:
    """True if tok is a name token immediately followed by '('."""
    try:
        return (tok.isName
                and tok.next is not None
                and _s(tok.next) == '(')
    except AttributeError:
        return False


def _next_tok(tok, skip: int = 1):
    """Return the token `skip` steps forward, or None."""
    t = tok
    for _ in range(skip):
        if t is None:
            return None
        t = t.next
    return t


def _prev_tok(tok, skip: int = 1):
    """Return the token `skip` steps backward, or None."""
    t = tok
    for _ in range(skip):
        if t is None:
            return None
        t = t.previous
    return t


def _scan_forward(tok, count: int) -> List:
    """Collect up to `count` tokens starting at tok (inclusive)."""
    result = []
    t = tok
    while t is not None and len(result) < count:
        result.append(t)
        t = t.next
    return result


def _scan_backward(tok, count: int) -> List:
    """Collect up to `count` tokens ending at tok (inclusive, reversed)."""
    result = []
    t = tok
    while t is not None and len(result) < count:
        result.append(t)
        t = t.previous
    return result


def _call_args(call_name_tok) -> List:
    """
    Return a flat list of the *first* token of each top-level argument
    for the call whose name token is `call_name_tok`.
    """
    args: List = []
    tok = call_name_tok.next   # '('
    if tok is None or _s(tok) != '(':
        return args
    tok = tok.next
    depth = 0
    arg_start = tok
    while tok is not None:
        s = _s(tok)
        if s == '(':
            depth += 1
        elif s == ')':
            if depth == 0:
                if arg_start is not None and arg_start is not tok:
                    args.append(arg_start)
                break
            depth -= 1
        elif s == ',' and depth == 0:
            if arg_start is not None:
                args.append(arg_start)
            arg_start = tok.next
        tok = tok.next
    return args


def _arg_at(call_name_tok, index: int):
    """Return first token of argument `index` (0-based), or None."""
    args = _call_args(call_name_tok)
    if 0 <= index < len(args):
        return args[index]
    return None


def _int_value(tok) -> Optional[int]:
    """If tok is an integer literal, return its int value, else None."""
    try:
        s = _s(tok).rstrip("uUlL")
        if s.startswith(("0x", "0X")):
            return int(s, 16)
        if re.fullmatch(r'\d+', s):
            return int(s)
    except (ValueError, AttributeError):
        pass
    return None


# ===========================================================================
# §3  Volatile / qualifier introspection
# ===========================================================================

def _is_volatile(tok) -> bool:
    """
    Return True if the variable referenced by tok is volatile-qualified.
    Checks tok.variable.isVolatile when available; falls back to scanning
    the declaration's type tokens for the 'volatile' keyword.
    """
    try:
        v = tok.variable
        if v is None:
            return False
        # cppcheckdata may expose isVolatile directly
        try:
            if v.isVolatile:
                return True
        except AttributeError:
            pass
        # Fallback: scan type tokens
        ts = v.typeStartToken
        te = v.typeEndToken
        if ts is None:
            return False
        t = ts
        while t is not None:
            if _s(t) == "volatile":
                return True
            if t is te:
                break
            t = t.next
        return False
    except AttributeError:
        return False


def _is_global_or_static(tok) -> bool:
    """
    Return True if the variable referenced by tok is global or
    has static storage duration.
    """
    try:
        v = tok.variable
        if v is None:
            return False
        try:
            if v.isGlobal or v.isStatic:
                return True
        except AttributeError:
            pass
        # isLocal == False implies global in cppcheckdata
        try:
            return not v.isLocal
        except AttributeError:
            return False
    except AttributeError:
        return False


def _is_atomic_qualified(tok) -> bool:
    """
    Return True if the variable referenced by tok is _Atomic-qualified
    (C11) or uses stdatomic.h atomic types.
    """
    try:
        v = tok.variable
        if v is None:
            return False
        ts = v.typeStartToken
        te = v.typeEndToken
        if ts is None:
            return False
        t = ts
        while t is not None:
            s_t = _s(t)
            if s_t in ("_Atomic", "atomic_int", "atomic_long",
                       "atomic_uint", "atomic_ulong",
                       "atomic_bool", "atomic_flag",
                       "atomic_size_t", "atomic_intptr_t",
                       "atomic_uintptr_t", "atomic_ptrdiff_t",
                       "atomic_intmax_t", "atomic_uintmax_t",
                       "atomic_char", "atomic_schar", "atomic_uchar",
                       "atomic_short", "atomic_ushort",
                       "atomic_llong", "atomic_ullong",
                       "sig_atomic_t"):
                return True
            if t is te:
                break
            t = t.next
        return False
    except AttributeError:
        return False


def _is_sig_atomic_t(tok) -> bool:
    """Return True if the variable type is sig_atomic_t."""
    try:
        v = tok.variable
        if v is None:
            return False
        ts = v.typeStartToken
        te = v.typeEndToken
        if ts is None:
            return False
        t = ts
        while t is not None:
            if _s(t) == "sig_atomic_t":
                return True
            if t is te:
                break
            t = t.next
        return False
    except AttributeError:
        return False


# ===========================================================================
# §4  Barrier recognition
# ===========================================================================

# Recognised compiler barrier forms (token sequences / patterns)
#
#   GCC/Clang:    asm volatile("" ::: "memory")
#   MSVC:         _ReadWriteBarrier()
#   Linux kernel: barrier() — macro expanding to asm volatile
#   C11:          atomic_thread_fence(memory_order_seq_cst) etc.
#   GCC builtins: __sync_synchronize()
#                 __atomic_thread_fence(...)

_BARRIER_CALL_NAMES: FrozenSet[str] = frozenset({
    # GCC/Clang builtins
    "__sync_synchronize",
    "__atomic_thread_fence",
    "__asm_barrier",
    # C11 stdatomic
    "atomic_thread_fence",
    "atomic_signal_fence",
    # MSVC
    "_ReadWriteBarrier",
    "_ReadBarrier",
    "_WriteBarrier",
    "MemoryBarrier",
    # Linux kernel macro (after expansion)
    "barrier",
    "smp_mb",
    "smp_rmb",
    "smp_wmb",
    "mb",
    "rmb",
    "wmb",
    # Windows
    "InterlockedCompareExchange",
    "InterlockedExchange",
    "_mm_mfence",
    "_mm_sfence",
    "_mm_lfence",
})

# Inline asm barrier pattern:  asm volatile ( "" ::: "memory" )
_ASM_BARRIER_RE = re.compile(
    r'(asm|__asm|__asm__)\s*(volatile|__volatile__)\s*\(\s*""\s*:::\s*"memory"\s*\)'
)


def _tok_is_barrier(tok) -> bool:
    """
    Return True if `tok` is the start of a compiler barrier expression.
    Recognises:
      - Named barrier function calls
      - asm volatile("" ::: "memory") — detected by checking the asm keyword
    """
    s = _s(tok)

    # Named function or macro call
    if s in _BARRIER_CALL_NAMES and _is_function_call(tok):
        return True

    # asm / __asm__ keyword — check the raw token string window
    if s in ("asm", "__asm", "__asm__"):
        # Peek forward for 'volatile' then '(' then '"' then ':::' "memory"
        window = _scan_forward(tok, 12)
        text = " ".join(_s(t) for t in window)
        if _ASM_BARRIER_RE.search(text):
            return True

    return False


# ===========================================================================
# §5  Mutex lock / unlock recognition
# ===========================================================================

_LOCK_FUNCS: FrozenSet[str] = frozenset({
    "pthread_mutex_lock",
    "pthread_mutex_trylock",
    "pthread_rwlock_rdlock",
    "pthread_rwlock_wrlock",
    "pthread_spin_lock",
    "mtx_lock",
    "EnterCriticalSection",
    "AcquireSRWLockExclusive",
    "AcquireSRWLockShared",
    "omp_set_lock",
    "flockfile",
})

_UNLOCK_FUNCS: FrozenSet[str] = frozenset({
    "pthread_mutex_unlock",
    "pthread_rwlock_unlock",
    "pthread_spin_unlock",
    "mtx_unlock",
    "LeaveCriticalSection",
    "ReleaseSRWLockExclusive",
    "ReleaseSRWLockShared",
    "omp_unset_lock",
    "funlockfile",
})


def _is_lock_call(tok) -> bool:
    return _s(tok) in _LOCK_FUNCS and _is_function_call(tok)


def _is_unlock_call(tok) -> bool:
    return _s(tok) in _UNLOCK_FUNCS and _is_function_call(tok)


# ===========================================================================
# §6  Signal handler detection
# ===========================================================================

_SIGNAL_REGISTER_FUNCS: FrozenSet[str] = frozenset({
    "signal", "sigaction", "bsd_signal", "sysv_signal",
})


def _collect_signal_handler_names(cfg) -> Set[str]:
    """
    Walk the token list looking for signal()/sigaction() calls and collect
    the names of functions registered as handlers.

    signal(SIGINT, my_handler)        → {"my_handler"}
    sigaction(SIGINT, &sa, NULL)      → struct inspection not feasible;
                                        we look for sa.sa_handler = X earlier.
    """
    handlers: Set[str] = set()

    for tok in _tokens(cfg):
        if not _is_function_call(tok):
            continue

        name = _s(tok)

        # signal(signum, handler_fn)
        if name == "signal":
            handler_arg = _arg_at(tok, 1)
            if handler_arg is not None:
                h = _s(handler_arg)
                if h not in ("SIG_DFL", "SIG_IGN", "NULL", "0"):
                    handlers.add(h)
            continue

        # sigaction: look backwards for  .sa_handler = name  assignment
        # (we scan the whole TU for sa_handler assignments)

    # Also collect sa_handler / sa_sigaction assignments
    for tok in _tokens(cfg):
        if _s(tok) == "sa_handler" or _s(tok) == "sa_sigaction":
            # expect:  .sa_handler = identifier
            eq = tok.next
            if eq is None or _s(eq) != '=':
                continue
            rhs = eq.next
            if rhs is None:
                continue
            h = _s(rhs)
            if h not in ("SIG_DFL", "SIG_IGN", "NULL", "0"):
                handlers.add(h)

    return handlers


def _collect_function_body_tokens(cfg, func_name: str) -> List:
    """
    Return the list of tokens inside the body of function `func_name`.
    Stops at the matching closing brace.
    Returns [] if function is not found.
    """
    result: List = []
    for tok in _tokens(cfg):
        if _s(tok) != func_name:
            continue
        if not tok.isName:
            continue
        # Is this a function definition?  Next non-paren should be '{'
        t = tok.next
        if t is None or _s(t) != '(':
            continue
        # Skip parameter list
        depth = 0
        while t is not None:
            if _s(t) == '(':
                depth += 1
            elif _s(t) == ')':
                depth -= 1
                if depth == 0:
                    t = t.next
                    break
            t = t.next
        if t is None or _s(t) != '{':
            continue
        # Collect body
        depth = 0
        while t is not None:
            s = _s(t)
            if s == '{':
                depth += 1
            elif s == '}':
                depth -= 1
                if depth == 0:
                    result.append(t)
                    break
            result.append(t)
            t = t.next
        break
    return result


# ===========================================================================
# §7  MMIO pointer detection helpers
# ===========================================================================

# Pattern:  volatile uint32_t *reg = (volatile uint32_t *)0xDEAD0000;
# or:       uint32_t *reg = (uint32_t *)0xDEAD0000;   ← missing volatile (CBC-09)

def _is_integer_cast_to_pointer(tok) -> bool:
    """
    Detect:  (SomeType *) <integer_literal>
    tok should point at the '(' of the cast.
    Returns True if this looks like a fixed-address MMIO cast.
    """
    if _s(tok) != '(':
        return False
    # Collect tokens until matching ')'
    t = tok.next
    depth = 0
    cast_tokens = []
    while t is not None:
        s = _s(t)
        if s == '(':
            depth += 1
        elif s == ')':
            if depth == 0:
                after = t.next
                break
            depth -= 1
        cast_tokens.append(s)
        t = t.next
    else:
        return False

    # Cast must contain '*'
    if '*' not in cast_tokens:
        return False
    # The token after ')' must be an integer literal
    if after is None:
        return False
    val = _int_value(after)
    if val is None:
        return False
    # Must be a plausible MMIO address (> some threshold, e.g. > 0x1000)
    # to avoid flagging   (int *)0   or   (void *)NULL
    return val > 0x1000


# ===========================================================================
# §8  Emission helper
# ===========================================================================

def _emit(checker_id: str, cwe: int, severity: str,
          msg: str, tok) -> None:
    """Emit one JSON finding on stdout — cppcheck addon wire protocol."""
    filename, linenr, col = _tok_file_line(tok)
    record = {
        "file":     filename,
        "linenr":   linenr,
        "column":   col,
        "severity": severity,
        "message":  msg,
        "addon":    "CompilerBarrierChecker",
        "errorId":  checker_id,
        "cwe":      cwe,
    }
    sys.stdout.write(json.dumps(record) + "\n")
    sys.stdout.flush()


# ===========================================================================
# §9  Base checker class
# ===========================================================================

class _BaseChecker:
    checker_id: str = "CBC-00"
    cwe:        int = 0
    severity:   str = "style"

    def check(self, cfg) -> None:
        raise NotImplementedError


# ===========================================================================
# §10  Individual checkers
# ===========================================================================

# ---------------------------------------------------------------------------
# CBC-01  missing_compiler_barrier  (CWE-667)
#
# Pattern: inside a loop body, a volatile write to variable V is followed
# within the same iteration (short token window) by a plain load of a
# *different* non-volatile, non-atomic global/static variable G, with no
# barrier between them.
#
# This is characteristic of:
#   while (1) {
#       status_reg = 1;        // volatile write — signals HW
#       int val = shared_var;  // non-volatile load — may be hoisted!
#   }
# ---------------------------------------------------------------------------

class _CBC01_MissingBarrier(_BaseChecker):
    checker_id = "CBC-01"
    cwe        = 667
    severity   = "error"

    _WINDOW = 30   # tokens to scan after the volatile write

    def check(self, cfg) -> None:
        for tok in _tokens(cfg):
            # Detect a volatile write: assignment whose LHS is volatile
            if _s(tok) != '=':
                continue
            lhs = tok.astOperand1
            rhs = tok.astOperand2
            if lhs is None or rhs is None:
                continue
            if not _is_volatile(lhs):
                continue

            lhs_vid = _safe_vid(lhs)

            # Scan forward for a non-volatile, non-atomic global load
            # without an intervening barrier
            t = tok.next
            found_barrier = False
            for _ in range(self._WINDOW):
                if t is None:
                    break
                if _tok_is_barrier(t):
                    found_barrier = True
                    break
                # A load of a different global/static non-volatile variable
                rhs_vid = _safe_vid(t)
                if (rhs_vid != 0
                        and rhs_vid != lhs_vid
                        and t.isName
                        and _is_global_or_static(t)
                        and not _is_volatile(t)
                        and not _is_atomic_qualified(t)):
                    # Check we are on the RHS of some expression (heuristic:
                    # previous meaningful token is not '=' pointing at t)
                    prev = t.previous
                    if prev is not None and _s(prev) == '=':
                        # This is an LHS — skip
                        t = t.next
                        continue
                    if not found_barrier:
                        vname  = _var_name(lhs)
                        gname  = _var_name(t)
                        msg = (
                            f"Volatile write to '{vname}' followed by "
                            f"non-volatile load of shared variable '{gname}' "
                            f"without a compiler barrier. The compiler may "
                            f"hoist the load above the write, creating a "
                            f"race condition. Insert "
                            f"asm volatile(\"\" ::: \"memory\") between them "
                            f"(CWE-667)."
                        )
                        _emit(self.checker_id, self.cwe, self.severity,
                              msg, tok)
                        break
                t = t.next


# ---------------------------------------------------------------------------
# CBC-02  mmio_write_without_barrier  (CWE-696)
#
# Pattern: two consecutive assignments through the SAME volatile pointer
# variable with no barrier between them.
#
#   *MMIO_REG_A = val1;
#   *MMIO_REG_B = val2;   ← compiler may reorder these two stores
# ---------------------------------------------------------------------------

class _CBC02_MMIOWriteWithoutBarrier(_BaseChecker):
    checker_id = "CBC-02"
    cwe        = 696
    severity   = "error"

    _WINDOW = 20

    def check(self, cfg) -> None:
        # Track last volatile-pointer write per (file, function scope)
        # Key: varId of the pointer variable; Value: (write_tok, target_name)
        last_write: Dict[int, Tuple] = {}

        for tok in _tokens(cfg):
            s = _s(tok)

            # Reset on barrier
            if _tok_is_barrier(tok):
                last_write.clear()
                continue

            # Reset on statement boundary (semicolon) handled implicitly
            # by updating last_write only on detected writes.

            # Detect  *ptr = expr   or   ptr->field = expr
            # We look for '*' immediately before a volatile variable,
            # or '.' / '->' dereference chains — keep it to unary '*' form
            # for tractability.

            if s != '=':
                continue
            lhs = tok.astOperand1
            if lhs is None:
                continue

            # Is lhs a dereference of a volatile pointer?
            #   AST: lhs may be '*' node whose child is the pointer variable
            lhs_s = _s(lhs)
            if lhs_s == '*':
                ptr_child = lhs.astOperand1 or lhs.astOperand2
                if ptr_child is None:
                    continue
                if not _is_volatile(ptr_child):
                    continue
                ptr_vid = _safe_vid(ptr_child)
                if ptr_vid == 0:
                    # May still be a global pointer — use name hash
                    ptr_vid = hash(_var_name(ptr_child)) & 0xFFFFFFFF

                if ptr_vid in last_write:
                    prev_tok, prev_name = last_write[ptr_vid]
                    curr_name = _var_name(ptr_child)
                    msg = (
                        f"Consecutive writes through volatile MMIO pointer "
                        f"'{curr_name}' at lines "
                        f"{_tok_file_line(prev_tok)[1]} and "
                        f"{_tok_file_line(tok)[1]} without a compiler "
                        f"barrier. The compiler or store buffer may reorder "
                        f"these writes, corrupting the device register "
                        f"sequence. Insert asm volatile(\"\" ::: \"memory\") "
                        f"between MMIO writes (CWE-696)."
                    )
                    _emit(self.checker_id, self.cwe, self.severity, msg, tok)
                    # Update to the current write so further consecutive
                    # writes also produce findings
                    last_write[ptr_vid] = (tok, _var_name(ptr_child))
                else:
                    last_write[ptr_vid] = (tok, _var_name(ptr_child))
            else:
                # Not a volatile dereference — clear entries for any
                # variable written here (approximation: clear all if we
                # cross a non-volatile assignment, since ordering context
                # has changed).
                if _is_volatile(lhs):
                    pass   # handled above
                else:
                    last_write.clear()


# ---------------------------------------------------------------------------
# CBC-03  lock_without_barrier_pair  (CWE-667)
#
# Pattern: a mutex lock call followed (within a window) by an assignment
# to a non-volatile, non-atomic global variable, with no compiler barrier
# between the lock call and the store.
#
# Motivation: the lock itself is a barrier at the hardware level on x86,
# but on weakly-ordered architectures (ARM, POWER) a software compiler
# barrier is still required to prevent the compiler from sinking the store
# above the lock.
# ---------------------------------------------------------------------------

class _CBC03_LockWithoutBarrier(_BaseChecker):
    checker_id = "CBC-03"
    cwe        = 667
    severity   = "warning"

    _WINDOW = 40

    def check(self, cfg) -> None:
        for tok in _tokens(cfg):
            if not _is_lock_call(tok):
                continue
            lock_name = _s(tok)

            # Scan forward for the first global non-atomic store
            t = tok.next
            barrier_seen = False
            for _ in range(self._WINDOW):
                if t is None:
                    break
                if _tok_is_barrier(t):
                    barrier_seen = True
                    break
                if _is_unlock_call(t):
                    break
                if _s(t) == '=':
                    lhs = t.astOperand1
                    if lhs is None:
                        t = t.next
                        continue
                    if (_is_global_or_static(lhs)
                            and not _is_volatile(lhs)
                            and not _is_atomic_qualified(lhs)):
                        if not barrier_seen:
                            vname = _var_name(lhs)
                            msg = (
                                f"Store to non-atomic global '{vname}' after "
                                f"'{lock_name}()' without an intervening "
                                f"compiler barrier. On weakly-ordered "
                                f"architectures the compiler may move this "
                                f"store above the lock acquisition. "
                                f"Insert atomic_thread_fence("
                                f"memory_order_acquire) or "
                                f"asm volatile(\"\" ::: \"memory\") after "
                                f"the lock call (CWE-667)."
                            )
                            _emit(self.checker_id, self.cwe, self.severity,
                                  msg, t)
                            break
                t = t.next


# ---------------------------------------------------------------------------
# CBC-04  signal_handler_nonvolatile  (CWE-366)
#
# Pattern: a function registered as a signal handler writes to a variable
# that is not qualified  volatile sig_atomic_t.
# ---------------------------------------------------------------------------

class _CBC04_SignalHandlerNonvolatile(_BaseChecker):
    checker_id = "CBC-04"
    cwe        = 366
    severity   = "error"

    def check(self, cfg) -> None:
        handler_names = _collect_signal_handler_names(cfg)
        if not handler_names:
            return

        for func in cfg.functions:
            try:
                fname = func.name
            except AttributeError:
                continue
            if fname not in handler_names:
                continue

            # Walk the body tokens of this function
            body = _collect_function_body_tokens(cfg, fname)
            for tok in body:
                if _s(tok) != '=':
                    continue
                lhs = tok.astOperand1
                if lhs is None:
                    continue
                # Must be a write (not compound comparison)
                if _s(tok.next or tok) in ('=',):
                    continue

                # Flag if not (volatile AND sig_atomic_t)
                is_vol = _is_volatile(lhs)
                is_sig = _is_sig_atomic_t(lhs)

                if not (is_vol and is_sig):
                    vname = _var_name(lhs)
                    if not vname:
                        continue
                    qualifier_issue = []
                    if not is_vol:
                        qualifier_issue.append("not 'volatile'")
                    if not is_sig:
                        qualifier_issue.append("not 'sig_atomic_t'")
                    qual_str = " and ".join(qualifier_issue)
                    msg = (
                        f"Signal handler '{fname}' writes to '{vname}' which "
                        f"is {qual_str}. Only 'volatile sig_atomic_t' "
                        f"variables are safe to access from a signal handler "
                        f"without a compiler barrier; all other accesses are "
                        f"undefined behaviour (CWE-366)."
                    )
                    _emit(self.checker_id, self.cwe, self.severity, msg, tok)


# ---------------------------------------------------------------------------
# CBC-05  barrier_in_wrong_order  (CWE-696)
#
# Pattern:  load X  →  barrier  →  store X
# The barrier is placed BETWEEN the load and the subsequent store of the
# same variable, i.e. after the read that it was supposed to guard.
# The correct pattern for a load barrier is:  barrier  →  load.
#
# We detect:  tok_load(V)  <within 10 tokens>  barrier  <within 10 tokens>
#             tok_store(V)
# where V is the same variable.
# ---------------------------------------------------------------------------

class _CBC05_BarrierWrongOrder(_BaseChecker):
    checker_id = "CBC-05"
    cwe        = 696
    severity   = "error"

    _PRE_WINDOW  = 8
    _POST_WINDOW = 8

    def check(self, cfg) -> None:
        toks = list(_tokens(cfg))
        for i, tok in enumerate(toks):
            if not _tok_is_barrier(tok):
                continue

            # Look backward for a load (name token with a varId on RHS of '=')
            pre  = toks[max(0, i - self._PRE_WINDOW): i]
            post = toks[i + 1: i + 1 + self._POST_WINDOW]

            # Collect varIds that appear as RHS values before the barrier
            loaded_vids: Set[int] = set()
            for t in pre:
                if t.isName and _safe_vid(t) != 0:
                    # Simple heuristic: if previous token is not '='
                    # (i.e., this token is being *read*, not written)
                    prev = t.previous
                    if prev is not None and _s(prev) == '=':
                        continue   # this is an LHS write — skip
                    loaded_vids.add(_safe_vid(t))

            if not loaded_vids:
                continue

            # Look forward for a store to one of those same variables
            for t in post:
                if _s(t) != '=':
                    continue
                lhs = t.astOperand1
                if lhs is None:
                    continue
                lhs_vid = _safe_vid(lhs)
                if lhs_vid in loaded_vids:
                    vname = _var_name(lhs)
                    msg = (
                        f"Compiler barrier appears AFTER the load of "
                        f"'{vname}' and BEFORE the store. "
                        f"A barrier placed between a dependent load and "
                        f"store does not prevent the compiler from reordering "
                        f"the load with earlier operations. "
                        f"Move the barrier to BEFORE the load (CWE-696)."
                    )
                    _emit(self.checker_id, self.cwe, self.severity, msg, tok)
                    break


# ---------------------------------------------------------------------------
# CBC-06  missing_release_barrier  (CWE-362)
#
# Pattern: assignment to a non-atomic global immediately before an unlock
# call, with no barrier or atomic_store_explicit/release between them.
# ---------------------------------------------------------------------------

class _CBC06_MissingReleaseBarrier(_BaseChecker):
    checker_id = "CBC-06"
    cwe        = 362
    severity   = "warning"

    _WINDOW = 25

    def check(self, cfg) -> None:
        for tok in _tokens(cfg):
            if not _is_unlock_call(tok):
                continue
            unlock_name = _s(tok)

            # Scan BACKWARD for a global non-atomic store
            t = tok.previous
            barrier_seen = False
            for _ in range(self._WINDOW):
                if t is None:
                    break
                if _tok_is_barrier(t):
                    barrier_seen = True
                    break
                if _is_lock_call(t):
                    break
                if _s(t) == '=':
                    lhs = t.astOperand1
                    if lhs is None:
                        t = t.previous
                        continue
                    if (_is_global_or_static(lhs)
                            and not _is_volatile(lhs)
                            and not _is_atomic_qualified(lhs)):
                        if not barrier_seen:
                            vname = _var_name(lhs)
                            msg = (
                                f"Store to non-atomic global '{vname}' "
                                f"immediately before '{unlock_name}()' "
                                f"without a release barrier. On weakly-ordered "
                                f"architectures the store may become visible "
                                f"to other threads after the lock is released, "
                                f"creating a data race window. "
                                f"Insert atomic_thread_fence("
                                f"memory_order_release) before the unlock "
                                f"(CWE-362)."
                            )
                            _emit(self.checker_id, self.cwe, self.severity,
                                  msg, tok)
                            break
                t = t.previous


# ---------------------------------------------------------------------------
# CBC-07  double_barrier  (style)
#
# Pattern: two consecutive asm volatile("" ::: "memory") (or equivalent)
# with no intervening memory-touching operation.  Redundant and suggests
# a copy-paste mistake.
# ---------------------------------------------------------------------------

class _CBC07_DoubleBarrier(_BaseChecker):
    checker_id = "CBC-07"
    cwe        = 0          # style finding — no CWE
    severity   = "style"

    _WINDOW = 12

    def check(self, cfg) -> None:
        last_barrier: Optional[object] = None
        memory_op_since_last = False

        for tok in _tokens(cfg):
            if _tok_is_barrier(tok):
                if last_barrier is not None and not memory_op_since_last:
                    msg = (
                        f"Two consecutive compiler barriers with no "
                        f"intervening memory operation. The second barrier "
                        f"at line {_tok_file_line(tok)[1]} is redundant. "
                        f"This often indicates a copy-paste error — verify "
                        f"the barrier placement is intentional."
                    )
                    _emit(self.checker_id, 0, self.severity, msg, tok)
                last_barrier = tok
                memory_op_since_last = False
                continue

            # Memory operations: assignments, loads (name with varId),
            # function calls (may have side effects)
            s = _s(tok)
            if s in ('=', '+=', '-=', '*=', '/=', '|=', '&=', '^='):
                memory_op_since_last = True
            elif tok.isName and _safe_vid(tok) != 0:
                memory_op_since_last = True
            elif _is_function_call(tok):
                memory_op_since_last = True

            # A function call boundary resets — don't track across functions
            if s == '{':
                last_barrier = None
                memory_op_since_last = False


# ---------------------------------------------------------------------------
# CBC-08  barrier_after_return  (CWE-696)
#
# Pattern: return statement followed (within a small window) by a compiler
# barrier.  The barrier is unreachable and provides no ordering guarantee.
# ---------------------------------------------------------------------------

class _CBC08_BarrierAfterReturn(_BaseChecker):
    checker_id = "CBC-08"
    cwe        = 696
    severity   = "warning"

    _WINDOW = 6

    def check(self, cfg) -> None:
        for tok in _tokens(cfg):
            if _s(tok) != "return":
                continue

            # Scan forward for a barrier before the next statement '{' or '}'
            t = tok.next
            for _ in range(self._WINDOW):
                if t is None:
                    break
                s = _s(t)
                if s in ('{', '}', ';') and s != ';':
                    break
                if _tok_is_barrier(t):
                    msg = (
                        f"Compiler barrier at line {_tok_file_line(t)[1]} "
                        f"appears after a 'return' statement and is "
                        f"unreachable. It provides no memory ordering "
                        f"guarantee. Move the barrier to before the 'return' "
                        f"if ordering is required (CWE-696)."
                    )
                    _emit(self.checker_id, self.cwe, self.severity, msg, t)
                    break
                t = t.next


# ---------------------------------------------------------------------------
# CBC-09  nonvolatile_mmio_pointer  (CWE-696)
#
# Pattern: a pointer is initialised from a cast of an integer literal
# (classic MMIO register mapping) but the pointer type lacks 'volatile'.
#
#   uint32_t *gpio = (uint32_t *)0x40020000;   ← should be volatile!
# ---------------------------------------------------------------------------

class _CBC09_NonvolatileMMIOPointer(_BaseChecker):
    checker_id = "CBC-09"
    cwe        = 696
    severity   = "error"

    def check(self, cfg) -> None:
        for tok in _tokens(cfg):
            # Look for '=' assignment
            if _s(tok) != '=':
                continue
            lhs = tok.astOperand1
            rhs = tok.astOperand2
            if lhs is None or rhs is None:
                continue

            # RHS must be a cast-from-integer: starts with '('
            if _s(rhs) != '(':
                continue
            if not _is_integer_cast_to_pointer(rhs):
                continue

            # LHS must be a pointer variable that is NOT volatile-qualified
            if _is_volatile(lhs):
                continue   # already correct

            vname = _var_name(lhs)
            if not vname:
                continue

            msg = (
                f"Pointer '{vname}' is initialised from a fixed hardware "
                f"address but is not declared 'volatile'. The compiler may "
                f"cache or eliminate reads/writes through this pointer, "
                f"breaking MMIO communication. Declare it as "
                f"'volatile <type> *{vname}' (CWE-696)."
            )
            _emit(self.checker_id, self.cwe, self.severity, msg, tok)


# ---------------------------------------------------------------------------
# CBC-10  setjmp_barrier_missing  (CWE-667)
#
# Pattern: a call to setjmp() where local variables modified between
# setjmp() and a potential longjmp() are not volatile-qualified.
#
# C99 §7.13.2.1: "All accessible objects have values … as of the time
# longjmp() was called, except that the values of objects of automatic
# storage duration that do not have volatile-qualified type and have
# been changed between the setjmp invocation and the longjmp call are
# indeterminate."
#
# Heuristic: after a setjmp call, flag any assignment to a non-volatile
# local variable within the same function scope (up to a closing brace
# or return), because that variable's value will be indeterminate on
# longjmp.
# ---------------------------------------------------------------------------

class _CBC10_SetjmpBarrierMissing(_BaseChecker):
    checker_id = "CBC-10"
    cwe        = 667
    severity   = "warning"

    _WINDOW = 60   # tokens to scan after setjmp call

    def check(self, cfg) -> None:
        for tok in _tokens(cfg):
            if _s(tok) not in ("setjmp", "_setjmp", "sigsetjmp"):
                continue
            if not _is_function_call(tok):
                continue

            # Scan forward for assignments to non-volatile locals
            t = tok.next
            depth = 0
            for _ in range(self._WINDOW):
                if t is None:
                    break
                s = _s(t)
                if s == '{':
                    depth += 1
                elif s == '}':
                    if depth == 0:
                        break
                    depth -= 1
                elif s == 'return':
                    break

                if s == '=':
                    lhs = t.astOperand1
                    if lhs is not None:
                        v = None
                        try:
                            v = lhs.variable
                        except AttributeError:
                            pass
                        if v is not None:
                            try:
                                is_local = v.isLocal
                            except AttributeError:
                                is_local = False
                            if is_local and not _is_volatile(lhs):
                                vname = _var_name(lhs)
                                if vname:
                                    msg = (
                                        f"Local variable '{vname}' is "
                                        f"modified after setjmp() but is not "
                                        f"'volatile'-qualified. If longjmp() "
                                        f"is called, '{vname}' will have an "
                                        f"indeterminate value (C99 §7.13.2.1). "
                                        f"Declare it 'volatile' or restructure "
                                        f"the code to avoid modification "
                                        f"between setjmp/longjmp (CWE-667)."
                                    )
                                    _emit(self.checker_id, self.cwe,
                                          self.severity, msg, t)
                t = t.next


# ===========================================================================
# §11  Registry and runner
# ===========================================================================

_ALL_CHECKERS: List[_BaseChecker] = [
    _CBC01_MissingBarrier(),
    _CBC02_MMIOWriteWithoutBarrier(),
    _CBC03_LockWithoutBarrier(),
    _CBC04_SignalHandlerNonvolatile(),
    _CBC05_BarrierWrongOrder(),
    _CBC06_MissingReleaseBarrier(),
    _CBC07_DoubleBarrier(),
    _CBC08_BarrierAfterReturn(),
    _CBC09_NonvolatileMMIOPointer(),
    _CBC10_SetjmpBarrierMissing(),
]


def analyse(filename: str, *, checkers=None) -> None:
    """Parse one cppcheck .dump file and run all registered checkers."""
    if checkers is None:
        checkers = _ALL_CHECKERS
    try:
        data = cppcheckdata.CppcheckData(filename)
    except Exception as exc:
        sys.stderr.write(
            f"CompilerBarrierChecker: failed to parse '{filename}': {exc}\n"
        )
        return
    for cfg in data.configurations:
        for chk in checkers:
            try:
                chk.check(cfg)
            except Exception as exc:
                sys.stderr.write(
                    f"CompilerBarrierChecker: checker {chk.checker_id} "
                    f"raised {type(exc).__name__}: {exc}\n"
                )


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write(
            "Usage: python3 CompilerBarrierChecker.py <file.c.dump> [...]\n"
            "       Produce dumps with: cppcheck --dump <source.c>\n"
        )
        sys.exit(1)
    for _dump in sys.argv[1:]:
        analyse(_dump)
