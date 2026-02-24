"""
ConcurrencyInvariantChecker.py — Cppcheck addon
================================================
Detects concurrency invariant violations: mutex misuse, lock-order
inversions, unprotected shared data, weak atomics, and TOCTOU races.

Checkers
--------
CIC-01  lock_not_released           Mutex locked on all paths but never unlocked
CIC-02  double_lock                 pthread_mutex_lock called twice on same mutex
CIC-03  unlock_without_lock         pthread_mutex_unlock with no prior lock
CIC-04  shared_var_unprotected      Global/static var written outside any lock
CIC-05  lock_order_inversion        Two mutexes always acquired in inconsistent order
CIC-06  condition_wait_missing_loop pthread_cond_wait not inside a while loop
CIC-07  atomic_mo_too_weak          atomic store with memory_order_relaxed on flag
CIC-08  sleep_under_lock            sleep/usleep called while mutex is held
CIC-09  trylock_result_unchecked    pthread_mutex_trylock return value not checked
CIC-10  toctou_file_race            access()/stat() followed by open() without lock

CWE mapping
-----------
CIC-01, CIC-02  → CWE-764 (Multiple Locks of a Critical Resource)
CIC-03          → CWE-765 (Multiple Unlocks of a Critical Resource)
CIC-04          → CWE-362 (Race Condition / Concurrent Execution)
CIC-05, CIC-08  → CWE-833 (Deadlock)
CIC-06, CIC-07  → CWE-362 (Race Condition)
CIC-09          → CWE-252 (Unchecked Return Value)
CIC-10          → CWE-367 (TOCTOU Race Condition)
"""

import sys
from collections   import defaultdict
from dataclasses   import dataclass, field
from typing        import Dict, List, Optional, Set, Tuple

try:
    import cppcheckdata
except ImportError:
    cppcheckdata = None  # type: ignore


# ===========================================================================
# §1  Safe accessor layer  (identical shim contract as other addons)
# ===========================================================================

def _str(tok):
    if tok is None:
        return ''
    try:
        return tok.str or ''
    except AttributeError:
        return ''

def _line(tok):
    if tok is None:
        return 0
    try:
        return int(tok.linenr) if tok.linenr is not None else 0
    except (AttributeError, TypeError, ValueError):
        return 0

def _file(tok):
    if tok is None:
        return ''
    try:
        return tok.file or ''
    except AttributeError:
        return ''

def _op1(tok):
    try:
        return tok.astOperand1 if tok else None
    except AttributeError:
        return None

def _op2(tok):
    try:
        return tok.astOperand2 if tok else None
    except AttributeError:
        return None

def _parent(tok):
    try:
        return tok.astParent if tok else None
    except AttributeError:
        return None

def _nxt(tok):
    try:
        return tok.next if tok else None
    except AttributeError:
        return None

def _var(tok):
    try:
        return tok.variable if tok else None
    except AttributeError:
        return None

def _vid(var):
    if var is None:
        return None
    try:
        v = var.Id
        return str(v) if v is not None else None
    except AttributeError:
        return None

def _vid_tok(tok):
    return _vid(_var(tok))

def _is_number(tok):
    try:
        return bool(tok.isNumber) if tok else False
    except AttributeError:
        return False

def _is_name(tok):
    try:
        return bool(tok.isName) if tok else False
    except AttributeError:
        return False

def _is_macro(tok):
    try:
        return bool(tok.isExpandedMacro) if tok else False
    except AttributeError:
        return False

def _scope_type(tok):
    try:
        s = tok.scope if tok else None
        return (s.type or '') if s else ''
    except AttributeError:
        return ''

def _var_is_global(v):
    try:
        return bool(v.isGlobal) if v else False
    except AttributeError:
        return False

def _var_is_static(v):
    try:
        return bool(v.isStatic) if v else False
    except AttributeError:
        return False

def _var_is_local(v):
    try:
        return bool(v.isLocal) if v else False
    except AttributeError:
        return False


# ===========================================================================
# §2  Call-site utilities
# ===========================================================================

def _call_name(paren_tok):
    if _str(paren_tok) != '(':
        return None
    fn = _op1(paren_tok)
    if fn is None:
        return None
    name = _str(fn)
    return name if (name and (name[0].isalpha() or name[0] == '_')) else None


def _call_args(paren_tok):
    args = []
    if paren_tok is None:
        return args
    node = _op2(paren_tok)
    while node is not None:
        if _str(node) == ',':
            left = _op1(node)
            if left is not None:
                args.append(left)
            node = _op2(node)
        else:
            args.append(node)
            break
    return args


def _mutex_arg_key(arg_tok):
    """
    Return a stable string key for a mutex argument:
      &mtx     → vid of mtx
      mtx      → vid of mtx
      mtx[i]   → vid of mtx  (conservative)
    """
    if arg_tok is None:
        return None
    s = _str(arg_tok)
    if s == '&':
        inner = _op1(arg_tok)
        v = _var(inner)
        return _vid(v)
    if s == '[':
        arr = _op1(arg_tok)
        v = _var(arr)
        return _vid(v)
    v = _var(arg_tok)
    return _vid(v)


# ===========================================================================
# §3  Lock-state FSM per function scope
# ===========================================================================

_LOCK_FUNCS   = frozenset({
    'pthread_mutex_lock',
    'mtx_lock',
    'EnterCriticalSection',
})
_UNLOCK_FUNCS = frozenset({
    'pthread_mutex_unlock',
    'mtx_unlock',
    'LeaveCriticalSection',
})
_TRYLOCK_FUNCS = frozenset({
    'pthread_mutex_trylock',
    'mtx_trylock',
    'TryEnterCriticalSection',
})
_COND_WAIT_FUNCS = frozenset({
    'pthread_cond_wait',
    'pthread_cond_timedwait',
    'cnd_wait',
    'cnd_timedwait',
})
_SLEEP_FUNCS = frozenset({
    'sleep', 'usleep', 'nanosleep',
    'Sleep',  # Windows
})
_ATOMIC_STORE_FUNCS = frozenset({
    'atomic_store',
    'atomic_store_explicit',
    '__atomic_store_n',
})
_TOCTOU_CHECK_FUNCS = frozenset({
    'access', 'stat', 'lstat', 'fstat',
    'faccessat', 'euidaccess',
})
_TOCTOU_USE_FUNCS = frozenset({
    'open', 'fopen', 'creat',
    'openat', 'mkdir', 'unlink', 'rename',
})
_RELAXED_ORDER_TOKENS = frozenset({
    'memory_order_relaxed',
    '__ATOMIC_RELAXED',
})


@dataclass
class _LockFSM:
    """Per-function lock tracking state."""
    # mutex_key → list of tok where it was locked (stack for nesting)
    held: Dict[str, List] = field(default_factory=lambda: defaultdict(list))
    # ordered list of (mutex_key, tok) for lock-order tracking
    acquire_seq: List[Tuple[str, object]] = field(default_factory=list)


# ===========================================================================
# §4  Shared variable tracker
# ===========================================================================

class _SharedVarTracker:
    """
    Tracks global/static variables and whether each write occurs while
    at least one mutex is held.
    """

    def __init__(self):
        # vid → list of (tok, lock_held: bool)
        self._writes: Dict[str, List[Tuple[object, bool]]] = defaultdict(list)

    def record_write(self, vid: str, tok, lock_held: bool):
        self._writes[vid].append((tok, lock_held))

    def unprotected_writes(self):
        """Yield (vid, tok) for writes with no lock held."""
        for vid, accesses in self._writes.items():
            has_protected = any(lh for _, lh in accesses)
            for tok, lock_held in accesses:
                if not lock_held and has_protected:
                    # Some accesses protected, this one isn't — definite race
                    yield vid, tok
                elif not lock_held and len(accesses) > 1:
                    # Multiple unprotected writes to same global
                    yield vid, tok
                    break


# ===========================================================================
# §5  Lock-order database (cross-function / cross-cfg)
# ===========================================================================

class _LockOrderDB:
    """
    Records observed lock acquisition orders: (A, B) means A was locked
    before B in some code path.  An inversion is (A,B) and (B,A) both seen.
    """

    def __init__(self):
        # frozenset(a,b) → list of (a_first, tok)
        self._orders: Dict[frozenset, List[Tuple[str, object]]] = \
            defaultdict(list)

    def record(self, held_keys: List[str], new_key: str, tok):
        for h in held_keys:
            if h == new_key:
                continue
            key = frozenset({h, new_key})
            self._orders[key].append((h, tok))  # h acquired before new_key

    def inversions(self):
        """Yield (key_a, key_b, tok_a, tok_b) for lock-order inversions."""
        for pair, orders in self._orders.items():
            if len(orders) < 2:
                continue
            first_locks = [o[0] for o in orders]
            unique_firsts = set(first_locks)
            if len(unique_firsts) > 1:
                # Two different locks were seen as "first" → inversion
                pair_list = list(pair)
                a, b = pair_list[0], pair_list[1]
                tok = orders[-1][1]
                yield a, b, tok


# ===========================================================================
# §6  Individual checkers
# ===========================================================================

def _chk_cic02_double_lock(fsm: _LockFSM, mutex_key: str, tok, errors):
    """CIC-02: double lock on non-recursive mutex."""
    if mutex_key and fsm.held[mutex_key]:
        errors.append(_mk('CIC-02', tok,
            f"double_lock: "
            f"Mutex (key='{mutex_key}') locked again while already held "
            f"(first lock at line {_line(fsm.held[mutex_key][0])}). "
            f"pthread_mutex_t is not recursive by default; this causes "
            f"deadlock. Use PTHREAD_MUTEX_RECURSIVE or restructure code. "
            f"[CWE-764]",
            'error'))


def _chk_cic03_unlock_without_lock(fsm: _LockFSM, mutex_key: str, tok, errors):
    """CIC-03: unlock with no prior lock."""
    if mutex_key and not fsm.held[mutex_key]:
        errors.append(_mk('CIC-03', tok,
            f"unlock_without_lock: "
            f"pthread_mutex_unlock called on mutex (key='{mutex_key}') "
            f"which does not appear to be locked in this scope. "
            f"Unlocking a mutex that is not owned is undefined behaviour. "
            f"[CWE-765]",
            'error'))


def _chk_cic08_sleep_under_lock(fsm: _LockFSM, call_name: str, tok, errors):
    """CIC-08: sleep/usleep while holding a lock."""
    held_keys = [k for k, stack in fsm.held.items() if stack]
    if held_keys:
        errors.append(_mk('CIC-08', tok,
            f"sleep_under_lock: "
            f"'{call_name}()' called while mutex/mutexes "
            f"{held_keys} are held. "
            f"Sleeping under a lock starves other threads attempting to "
            f"acquire it, which can cause priority inversion or deadlock. "
            f"Release the lock before sleeping. [CWE-833]",
            'warning'))


def _chk_cic06_cond_wait_loop(tok, errors):
    """
    CIC-06: pthread_cond_wait not inside a while loop.
    We look at the lexical context: if the enclosing scope keyword is 'if'
    rather than 'while', the condition check is not re-evaluated after
    spurious wake-ups.
    """
    # Walk up AST parents looking for while/if keyword context
    p = _parent(tok)
    depth = 0
    while p is not None and depth < 8:
        ps = _str(p)
        if ps == 'while':
            return  # correctly inside while — OK
        if ps == 'if':
            errors.append(_mk('CIC-06', tok,
                f"condition_wait_missing_loop: "
                f"pthread_cond_wait appears inside an 'if' statement rather "
                f"than a 'while' loop. "
                f"Condition variables can experience spurious wake-ups; "
                f"the predicate must be re-checked in a loop: "
                f"while(!ready) pthread_cond_wait(&cv, &mtx). [CWE-362]",
                'warning'))
            return
        p = _parent(p)
        depth += 1


def _chk_cic07_atomic_mo(tok, errors):
    """
    CIC-07: atomic_store_explicit / __atomic_store_n with memory_order_relaxed.
    Relaxed stores are safe only for counters; using them for flag-based
    synchronisation is a classic race.
    """
    if _str(tok) != '(':
        return
    fname = _call_name(tok)
    if fname not in _ATOMIC_STORE_FUNCS:
        return

    args = _call_args(tok)
    # atomic_store_explicit(ptr, val, order) — order is args[2]
    # __atomic_store_n(ptr, val, memorder)   — order is args[2]
    if len(args) < 3:
        return

    order_tok = args[2]
    order_str = _str(order_tok)
    if order_str in _RELAXED_ORDER_TOKENS:
        errors.append(_mk('CIC-07', tok,
            f"atomic_mo_too_weak: "
            f"'{fname}' uses memory_order_relaxed. "
            f"Relaxed stores provide no synchronisation guarantee: "
            f"other threads may never observe the store, or may observe it "
            f"in an unexpected order relative to surrounding code. "
            f"Use memory_order_release for flag/signal stores and "
            f"memory_order_acquire for the paired load. [CWE-362]",
            'warning'))


def _chk_cic09_trylock_unchecked(tok, errors):
    """CIC-09: trylock return value discarded."""
    if _str(tok) != '(':
        return
    if _call_name(tok) not in _TRYLOCK_FUNCS:
        return

    # If the call is a statement on its own (not used in assignment/if/while)
    p = _parent(tok)
    if p is None:
        errors.append(_mk('CIC-09', tok,
            f"trylock_result_unchecked: "
            f"Return value of trylock call is not checked. "
            f"If the lock is not acquired, code continues as if it were, "
            f"creating an unprotected critical section. "
            f"Always check: if(pthread_mutex_trylock(&m)==0){{...}}. "
            f"[CWE-252]",
            'error'))
        return

    ps = _str(p)
    # Acceptable parents: =, if, while, !, ==, !=
    _SAFE_PARENTS = {'=', '==', '!=', '!', 'if', 'while', '?'}
    if ps not in _SAFE_PARENTS:
        errors.append(_mk('CIC-09', tok,
            f"trylock_result_unchecked: "
            f"pthread_mutex_trylock return value appears unused "
            f"(parent token: '{ps}'). "
            f"Treat the result as a required conditional. [CWE-252]",
            'error'))


# ===========================================================================
# §7  TOCTOU checker (stateful, tracks check→use pairs)
# ===========================================================================

class _ToctouTracker:
    """
    Track access()/stat() calls; if an open()/fopen() call follows on the
    same filename argument (string literal or same variable) without an
    intervening lock, flag it.
    """

    def __init__(self):
        # key (file_arg_str) → tok where check happened
        self._pending: Dict[str, object] = {}

    def on_check(self, fname_key: str, tok):
        self._pending[fname_key] = tok

    def on_use(self, fname_key: str, tok, held_locks: List[str], errors):
        check_tok = self._pending.pop(fname_key, None)
        if check_tok is None:
            return
        if not held_locks:
            errors.append(_mk('CIC-10', tok,
                f"toctou_file_race: "
                f"File '{fname_key}' checked (access/stat at line "
                f"{_line(check_tok)}) then used (open/fopen at line "
                f"{_line(tok)}) without holding a lock. "
                f"An attacker can replace the file between check and use "
                f"(symlink attack). "
                f"Use open(O_CREAT|O_EXCL) or openat() with O_NOFOLLOW "
                f"instead of a separate access() check. [CWE-367]",
                'error'))

    def _filename_key(self, arg_tok) -> Optional[str]:
        if arg_tok is None:
            return None
        try:
            if arg_tok.isString:
                return _str(arg_tok)
        except AttributeError:
            pass
        v = _var(arg_tok)
        if v is not None:
            return _vid(v)
        return None

    def handle_call(self, paren_tok, held_locks: List[str], errors):
        fname = _call_name(paren_tok)
        if fname is None:
            return
        args = _call_args(paren_tok)
        if not args:
            return

        # All TOCTOU check/use functions take filename as first arg
        path_key = self._filename_key(args[0])
        if path_key is None:
            return

        if fname in _TOCTOU_CHECK_FUNCS:
            self.on_check(path_key, paren_tok)
        elif fname in _TOCTOU_USE_FUNCS:
            self.on_use(path_key, paren_tok, held_locks, errors)


# ===========================================================================
# §8  Per-cfg scanner
# ===========================================================================

def _scan_cfg(cfg, lock_order_db: _LockOrderDB,
              shared_tracker: _SharedVarTracker):
    errors      = []
    fsm         = _LockFSM()
    toctou      = _ToctouTracker()

    def _held_keys():
        return [k for k, stack in fsm.held.items() if stack]

    for tok in cfg.tokenlist:
        if _is_macro(tok):
            continue

        s = _str(tok)

        if s != '(':
            # Track writes to global/static variables
            if s == '=':
                lhs = _op1(tok)
                if lhs is not None:
                    v = _var(lhs)
                    if v is not None and (_var_is_global(v) or _var_is_static(v)):
                        vid = _vid(v)
                        if vid:
                            lock_held = bool(_held_keys())
                            shared_tracker.record_write(vid, tok, lock_held)
            continue

        # ── Call site ──────────────────────────────────────────────────────
        fname = _call_name(tok)
        if fname is None:
            continue

        args = _call_args(tok)
        mutex_key = _mutex_arg_key(args[0]) if args else None

        # CIC-02 / lock acquisition
        if fname in _LOCK_FUNCS:
            _chk_cic02_double_lock(fsm, mutex_key, tok, errors)
            held = _held_keys()
            if mutex_key:
                lock_order_db.record(held, mutex_key, tok)
                fsm.held[mutex_key].append(tok)
                fsm.acquire_seq.append((mutex_key, tok))

        # CIC-03 / unlock
        elif fname in _UNLOCK_FUNCS:
            _chk_cic03_unlock_without_lock(fsm, mutex_key, tok, errors)
            if mutex_key and fsm.held[mutex_key]:
                fsm.held[mutex_key].pop()

        # CIC-09 / trylock
        elif fname in _TRYLOCK_FUNCS:
            _chk_cic09_trylock_unchecked(tok, errors)
            # Optimistically mark as acquired for further analysis
            if mutex_key:
                fsm.held[mutex_key].append(tok)

        # CIC-06 / cond_wait loop check
        elif fname in _COND_WAIT_FUNCS:
            _chk_cic06_cond_wait_loop(tok, errors)

        # CIC-07 / weak atomic store
        elif fname in _ATOMIC_STORE_FUNCS:
            _chk_cic07_atomic_mo(tok, errors)

        # CIC-08 / sleep under lock
        elif fname in _SLEEP_FUNCS:
            _chk_cic08_sleep_under_lock(fsm, fname, tok, errors)

        # CIC-10 / TOCTOU
        toctou.handle_call(tok, _held_keys(), errors)

    # ── End-of-cfg: CIC-01 lock never released ────────────────────────────
    for mutex_key, stack in fsm.held.items():
        if stack:
            first_tok = stack[0]
            errors.append(_mk('CIC-01', first_tok,
                f"lock_not_released: "
                f"Mutex (key='{mutex_key}') locked at line {_line(first_tok)} "
                f"is never unlocked in this function scope. "
                f"This leaks the mutex, permanently blocking any other thread "
                f"that attempts to acquire it. "
                f"Ensure every lock path has a matching unlock, or use RAII "
                f"wrappers (C++ std::lock_guard / std::unique_lock). "
                f"[CWE-764]",
                'error'))

    return errors


# ===========================================================================
# §9  Post-cfg checkers that need global state
# ===========================================================================

def _post_analysis(lock_order_db: _LockOrderDB,
                   shared_tracker: _SharedVarTracker,
                   errors: list):
    # CIC-05: lock order inversions
    for a, b, tok in lock_order_db.inversions():
        errors.append(_mk('CIC-05', tok,
            f"lock_order_inversion: "
            f"Mutexes '{a}' and '{b}' are acquired in inconsistent order "
            f"across different code paths. "
            f"Thread 1 may hold '{a}' and wait for '{b}' while Thread 2 "
            f"holds '{b}' and waits for '{a}', causing a circular deadlock. "
            f"Establish a global lock hierarchy and always acquire mutexes "
            f"in the same order. [CWE-833]",
            'error'))

    # CIC-04: unprotected shared variable writes
    for vid, tok in shared_tracker.unprotected_writes():
        errors.append(_mk('CIC-04', tok,
            f"shared_var_unprotected: "
            f"Global/static variable (id='{vid}') written at line "
            f"{_line(tok)} without holding any mutex. "
            f"In a multi-threaded program this is a data race; "
            f"the write is not atomic and can be observed partially "
            f"or not at all by other threads. "
            f"Protect all accesses with a consistent mutex. [CWE-362]",
            'warning'))


# ===========================================================================
# §10  Error helpers & emission
# ===========================================================================

def _mk(checker_id, tok, msg, severity='warning'):
    return {'id': checker_id, 'tok': tok, 'msg': msg, 'severity': severity}


_SEV = {'error': 'error', 'warning': 'warning', 'style': 'style'}


def _emit(errors, filter_ids=None):
    for e in errors:
        tok      = e['tok']
        msg      = e['msg']
        cid      = e['id']
        severity = _SEV.get(e.get('severity', 'warning'), 'warning')

        if filter_ids and cid not in filter_ids:
            continue

        if cppcheckdata is not None:
            try:
                cppcheckdata.reportError(
                    tok, severity, msg, 'ConcurrencyInvariantChecker', cid)
            except TypeError:
                try:
                    cppcheckdata.reportError(tok, severity, msg)
                except Exception:
                    pass
        else:
            print(f"[{cid}] {_file(tok)}:{_line(tok)}: {msg}",
                  file=sys.stderr)


# ===========================================================================
# §11  Entry point
# ===========================================================================

def analyse(filename, filter_ids=None):
    if cppcheckdata is None:
        print("ERROR: cppcheckdata module not found.", file=sys.stderr)
        sys.exit(1)

    data          = cppcheckdata.parsedump(filename)
    lock_order_db = _LockOrderDB()
    shared_trk    = _SharedVarTracker()
    all_errors    = []

    for cfg in data.configurations:
        all_errors.extend(
            _scan_cfg(cfg, lock_order_db, shared_trk))

    _post_analysis(lock_order_db, shared_trk, all_errors)
    _emit(all_errors, filter_ids)


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(
            "Usage: python3 ConcurrencyInvariantChecker.py <file.c.dump>",
            file=sys.stderr)
        sys.exit(1)
    analyse(sys.argv[1])
