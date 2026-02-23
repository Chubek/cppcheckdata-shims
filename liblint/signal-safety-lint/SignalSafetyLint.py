#!/usr/bin/env python3
"""
SignalSafetyLint.py — Cppcheck addon for signal-handler safety defects.

Checkers
────────
  sig-01  async-signal-unsafe-call        CWE-479  — Async-signal-unsafe
                                                      function called inside a
                                                      signal handler
  sig-02  signal-handler-modifies-global  CWE-828  — Non-volatile,
                                                      non-sig_atomic_t global
                                                      written inside handler
  sig-03  signal-flag-not-volatile        CWE-364  — Flag variable used as
                                                      signal indicator not
                                                      declared volatile
                                                      sig_atomic_t
  sig-04  signal-handler-calls-signal     CWE-662  — Handler re-registers
                                                      itself or another signal
                                                      inside its own body
                                                      (non-reentrant SIGINT
                                                      pattern)
  sig-05  signal-handler-missing-errno-save CWE-364 — Handler uses a function
                                                       that may modify errno
                                                       without saving/restoring
                                                       errno first
  sig-06  signal-longjmp-unsafe           CWE-828  — longjmp / siglongjmp
                                                      called from inside a
                                                      signal handler

════════════════════════════════════════════════════════════════════════════════
CONTRACT — mandatory reading for every developer extending this addon
════════════════════════════════════════════════════════════════════════════════

  1. SAFE VARIABLE-ID ACCESS
     ─────────────────────────
     The `varId` attribute on cppcheckdata Token objects is NOT guaranteed
     to be a decimal integer string.  It may be:
       • None              — token has no associated variable
       • '0'               — cppcheck sentinel "no variable"
       • '560e31248150'    — raw pointer printed as hex (observed in practice)
       • any other non-decimal string

     ALWAYS obtain a variable-id via one of the two helpers below.
     NEVER write  int(tok.varId)  or  tok.varId == some_int  directly.

       _safe_vid(vid)      — converts any raw varId value → Optional[int]
                             returns None for None, '0', hex strings, etc.
       _safe_vid_tok(tok)  — convenience: _safe_vid(getattr(tok, 'varId', None))

  2. ATTRIBUTE ACCESS
     ─────────────────
     All token / scope / variable attributes must be obtained with
     getattr(obj, 'attr', default).  Never access tok.attr directly;
     shim objects may lack attributes depending on cppcheck version.

  3. OUTPUT FORMAT
     ──────────────
     All findings MUST be emitted via _Finding.emit().  The format is:

       [file]:[line]: ([severity]) [message] [error-id]
       [file]:[line]: note: [context note]   ← optional secondary locations

  4. GRACEFUL DEGRADATION
     ──────────────────────
     Wrap every checker body in try/except and continue on failure.
     The addon must never crash the cppcheck process.

  5. NO EXTERNAL DEPENDENCIES
     ──────────────────────────
     Only the Python standard library and cppcheckdata are permitted.

════════════════════════════════════════════════════════════════════════════════
"""

from __future__ import annotations

import sys
import re
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

# ── cppcheckdata import (graceful) ───────────────────────────────────────────
try:
    import cppcheckdata  # type: ignore[import-untyped]
except ImportError:
    cppcheckdata = None  # type: ignore[assignment]


# ═════════════════════════════════════════════════════════════════════════════
#  PART 0 — SAFE VARIABLE-ID HELPERS  (contract §1)
# ═════════════════════════════════════════════════════════════════════════════

def _safe_vid(vid: Any) -> Optional[int]:
    """
    Safely convert a raw varId value to int.

    Returns None when the value is:
      • None
      • 0 / '0'           (cppcheck sentinel for "no variable")
      • a hex string      (e.g. '560e31248150')
      • any non-decimal string
    """
    if vid is None:
        return None
    try:
        result = int(str(vid), 10)
        return result if result != 0 else None
    except (ValueError, TypeError):
        return None


def _safe_vid_tok(tok: Any) -> Optional[int]:
    """Convenience wrapper: _safe_vid applied to tok.varId."""
    return _safe_vid(getattr(tok, "varId", None))


# ═════════════════════════════════════════════════════════════════════════════
#  PART 1 — TOKEN HELPERS
# ═════════════════════════════════════════════════════════════════════════════

def _tok_str(tok: Any) -> str:
    return getattr(tok, "str", "") or ""


def _tok_file(tok: Any) -> str:
    return getattr(tok, "file", "") or ""


def _tok_line(tok: Any) -> int:
    return int(getattr(tok, "linenr", 0) or 0)


def _iter_tokens(cfg: Any):
    yield from (getattr(cfg, "tokenlist", None) or [])


def _iter_scopes(cfg: Any):
    yield from (getattr(cfg, "scopes", None) or [])


def _iter_variables(cfg: Any):
    yield from (getattr(cfg, "variables", None) or [])


# ═════════════════════════════════════════════════════════════════════════════
#  PART 2 — FINDING + BASE CHECKER
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class _Finding:
    error_id: str
    severity: str
    message: str
    file: str
    line: int
    notes: List[Tuple[str, int, str]] = field(default_factory=list)

    def emit(self) -> None:
        print(f"{self.file}:{self.line}: ({self.severity}) "
              f"{self.message} [{self.error_id}]")
        for nfile, nline, note in self.notes:
            print(f"{nfile}:{nline}: note: {note}")


class _BaseChecker:
    error_id: str = ""
    severity: str = "warning"

    def __init__(self) -> None:
        self._findings: List[_Finding] = []

    def check(self, cfg: Any, handler_names: Set[str],
              handler_scopes: Set[Any]) -> None:
        raise NotImplementedError

    def run(self, cfg: Any, handler_names: Set[str],
            handler_scopes: Set[Any]) -> None:
        try:
            self.check(cfg, handler_names, handler_scopes)
        except Exception as exc:
            sys.stderr.write(
                f"[SignalSafetyLint] {self.__class__.__name__} "
                f"raised {type(exc).__name__}: {exc}\n"
            )

    def emit_all(self) -> None:
        for f in self._findings:
            f.emit()

    def _add(self, msg: str, file: str, line: int,
             notes: Optional[List[Tuple[str, int, str]]] = None) -> None:
        self._findings.append(_Finding(
            error_id=self.error_id,
            severity=self.severity,
            message=msg,
            file=file,
            line=line,
            notes=notes or [],
        ))


# ═════════════════════════════════════════════════════════════════════════════
#  PART 3 — SHARED KNOWLEDGE TABLES
# ═════════════════════════════════════════════════════════════════════════════

# POSIX.1-2017 §2.4.3 — functions NOT in the async-signal-safe list.
# This is a curated subset covering the most commonly encountered calls.
_SIGNAL_UNSAFE: FrozenSet[str] = frozenset({
    # stdio
    "printf", "fprintf", "sprintf", "snprintf",
    "vprintf", "vfprintf", "vsprintf", "vsnprintf",
    "puts", "fputs", "fputc", "putchar", "putc",
    "fgets", "fgetc", "getchar", "getc",
    "fopen", "fclose", "fflush", "fread", "fwrite",
    "freopen", "feof", "ferror", "clearerr",
    "fseek", "ftell", "rewind", "fgetpos", "fsetpos",
    "scanf", "fscanf", "sscanf",
    "perror",
    # heap
    "malloc", "calloc", "realloc", "free",
    "new", "delete",
    # string / locale
    "strtok", "strtok_r",
    "setlocale", "localeconv",
    # time (non-reentrant)
    "localtime", "gmtime", "ctime", "asctime", "mktime",
    # environment
    "getenv", "setenv", "unsetenv", "putenv",
    # process
    "exit", "_exit", "abort", "atexit",
    "system", "popen", "pclose",
    # threads / synchronization
    "pthread_mutex_lock", "pthread_mutex_trylock",
    "pthread_mutex_unlock",
    "pthread_cond_wait", "pthread_cond_signal",
    "pthread_cond_broadcast",
    # logging
    "syslog", "openlog", "closelog",
    # dynamic linking
    "dlopen", "dlclose", "dlsym",
    # sleep
    "sleep", "usleep", "nanosleep",
    # random (non-reentrant state)
    "rand", "srand",
    # other commonly misused
    "opendir", "closedir", "readdir",
    "gethostbyname", "getaddrinfo",
})

# Functions that set / read errno as a side-effect and are NOT safe
# inside a handler without surrounding errno save/restore.
_ERRNO_CLOBBERERS: FrozenSet[str] = frozenset({
    "read", "write", "open", "close",
    "send", "recv", "sendto", "recvfrom",
    "waitpid", "wait",
    "kill", "sigprocmask",
    "fcntl", "ioctl",
    "stat", "fstat", "lstat",
    "unlink", "rename", "mkdir", "rmdir",
    "pipe", "dup", "dup2",
    "execve", "execvp", "execv",
}) | _SIGNAL_UNSAFE   # every unsafe call also clobbers errno

# Signal registration functions.
_SIGNAL_REG: FrozenSet[str] = frozenset({
    "signal", "sigaction", "bsd_signal",
})

# longjmp variants that are forbidden inside handlers.
_LONGJMP: FrozenSet[str] = frozenset({
    "longjmp", "siglongjmp", "_longjmp",
})


# ═════════════════════════════════════════════════════════════════════════════
#  PART 4 — HANDLER DISCOVERY
# ═════════════════════════════════════════════════════════════════════════════

def _collect_handler_names(cfg: Any) -> Set[str]:
    """
    Scan token stream for signal()/sigaction() calls and extract handler names.

    Handles two calling patterns:

      signal(SIGINT, my_handler)
        → second positional argument is the handler name token

      sa.sa_handler = my_handler   /   sa.sa_sigaction = my_handler
        → RHS of assignment to a known sigaction struct member

    Returns a set of function-name strings.
    """
    handlers: Set[str] = set()

    for tok in _iter_tokens(cfg):
        s = _tok_str(tok)

        # ── pattern A: signal(signum, handler) ───────────────────────────
        if s in _SIGNAL_REG:
            paren = getattr(tok, "next", None)
            if paren is None or _tok_str(paren) != "(":
                continue
            # Collect comma-separated arguments
            args = _collect_call_args(paren)
            # signal() and bsd_signal(): second arg (index 1) is handler
            # sigaction(): third arg (index 2) is struct; we also check below
            if s in {"signal", "bsd_signal"} and len(args) >= 2:
                name = _tok_str(args[1])
                if _is_identifier(name):
                    handlers.add(name)
            # For sigaction, we still catch direct function-pointer stores below

        # ── pattern B: sa.sa_handler = my_handler ────────────────────────
        if s in {"sa_handler", "sa_sigaction"}:
            parent = getattr(tok, "astParent", None)
            if parent is None:
                continue
            if _tok_str(parent) != "=":
                continue
            lhs = getattr(parent, "astOperand1", None)
            rhs = getattr(parent, "astOperand2", None)
            if lhs is None or rhs is None:
                continue
            # Verify LHS involves the known field name
            if _tok_str(lhs) not in {"sa_handler", "sa_sigaction", "."}:
                if s not in _tok_str(lhs):
                    continue
            name = _tok_str(rhs)
            if _is_identifier(name):
                handlers.add(name)

    # Remove noise: SIG_DFL, SIG_IGN, NULL are not real handlers
    handlers.discard("SIG_DFL")
    handlers.discard("SIG_IGN")
    handlers.discard("NULL")
    handlers.discard("0")

    return handlers


def _collect_handler_scopes(cfg: Any, handler_names: Set[str]) -> Set[Any]:
    """
    Return the set of scope objects whose function name is in handler_names.

    We match against the token immediately before the scope's opening '{'.
    """
    scopes: Set[Any] = set()
    for scope in _iter_scopes(cfg):
        if getattr(scope, "type", "") != "Function":
            continue
        body_start = getattr(scope, "bodyStart", None)
        if body_start is None:
            continue
        # Walk backward past whitespace to the identifier token
        prev = getattr(body_start, "previous", None)
        # Skip closing ')' of parameter list
        if prev and _tok_str(prev) == ")":
            link = getattr(prev, "link", None)
            if link is not None:
                prev = getattr(link, "previous", None)
        if prev and _tok_str(prev) in handler_names:
            scopes.add(scope)
    return scopes


def _scope_contains(scope: Any, tok: Any) -> bool:
    """
    Return True if *tok* is lexically inside *scope*.

    Uses the token's own scope chain rather than positional line checks
    to avoid false positives across files.
    """
    s = getattr(tok, "scope", None)
    while s is not None:
        if s is scope:
            return True
        s = getattr(s, "nestedIn", None)
    return False


# ═════════════════════════════════════════════════════════════════════════════
#  PART 5 — CALL-SITE HELPERS
# ═════════════════════════════════════════════════════════════════════════════

def _collect_call_args(paren_tok: Any) -> List[Any]:
    """
    Given the '(' token of a call, return a flat list of argument root tokens.

    Walks the comma-separated AST under astOperand2 of the '(' node.
    Falls back to a linear scan if the AST is not populated.
    """
    arg_root = getattr(paren_tok, "astOperand2", None)
    if arg_root is not None:
        result: List[Any] = []
        _flatten_arg_tree(arg_root, result)
        return result

    # Fallback: linear scan between '(' and matching ')'
    result = []
    tok = getattr(paren_tok, "next", None)
    depth = 0
    current_arg_start = tok
    while tok is not None:
        s = _tok_str(tok)
        if s == "(":
            depth += 1
        elif s == ")":
            if depth == 0:
                if current_arg_start and current_arg_start is not tok:
                    result.append(current_arg_start)
                break
            depth -= 1
        elif s == "," and depth == 0:
            if current_arg_start and current_arg_start is not tok:
                result.append(current_arg_start)
            current_arg_start = getattr(tok, "next", None)
        tok = getattr(tok, "next", None)
    return result


def _flatten_arg_tree(tok: Any, out: List[Any]) -> None:
    if tok is None:
        return
    if _tok_str(tok) == ",":
        _flatten_arg_tree(getattr(tok, "astOperand1", None), out)
        _flatten_arg_tree(getattr(tok, "astOperand2", None), out)
    else:
        out.append(tok)


def _is_identifier(name: str) -> bool:
    return bool(re.match(r"^[A-Za-z_]\w*$", name))


def _is_call_site(tok: Any) -> bool:
    """Return True if *tok* is the name token of a function call."""
    nxt = getattr(tok, "next", None)
    return (nxt is not None and _tok_str(nxt) == "("
            and _is_identifier(_tok_str(tok)))


# ═════════════════════════════════════════════════════════════════════════════
#  PART 6 — GLOBAL VARIABLE ANALYSIS
# ═════════════════════════════════════════════════════════════════════════════

def _collect_global_vids(cfg: Any) -> Dict[int, Any]:
    """
    Return {varId → variable_object} for every global variable in cfg.

    Only non-static, non-const globals (candidates for signal flag misuse).
    """
    result: Dict[int, Any] = {}
    for var in _iter_variables(cfg):
        if not getattr(var, "isGlobal", False):
            continue
        vid = _safe_vid(getattr(var, "Id", None))
        if vid is not None:
            result[vid] = var
    return result


def _var_is_volatile_sig_atomic(var: Any) -> bool:
    """
    Heuristic: check if a variable has the volatile sig_atomic_t type.

    We inspect the type-name tokens of the variable's declaration.
    cppcheck exposes these through typeStartToken / typeEndToken.
    """
    is_volatile = getattr(var, "isVolatile", False)

    # Check the token stream for "sig_atomic_t"
    type_start = getattr(var, "typeStartToken", None)
    type_end = getattr(var, "typeEndToken", None)
    has_sig_atomic = False

    tok = type_start
    while tok is not None:
        if _tok_str(tok) == "sig_atomic_t":
            has_sig_atomic = True
            break
        if tok is type_end:
            break
        tok = getattr(tok, "next", None)

    # If cppcheck didn't link typeStartToken, fall back to valueType string
    if not has_sig_atomic:
        vt = getattr(var, "valueType", None)
        if vt is not None:
            type_str = str(getattr(vt, "type", "") or "")
            if "sig_atomic_t" in type_str:
                has_sig_atomic = True

    return is_volatile and has_sig_atomic


# ═════════════════════════════════════════════════════════════════════════════
#  PART 7 — INDIVIDUAL CHECKERS
# ═════════════════════════════════════════════════════════════════════════════

# ─────────────────────────────────────────────────────────────────────────────
#  sig-01  Async-Signal-Unsafe Call  (CWE-479)
# ─────────────────────────────────────────────────────────────────────────────
#
#  POSIX.1-2017 §2.4.3 defines a specific list of async-signal-safe functions.
#  Any call to a function NOT on that list from inside a signal handler is
#  undefined behaviour — the function may deadlock (if it uses a mutex already
#  held by the interrupted thread) or corrupt internal state.
#
#  Detection: for every token inside a handler scope, check if it is a
#  call-site whose name appears in the unsafe-function table.
# ─────────────────────────────────────────────────────────────────────────────

class _Sig01_AsyncUnsafeCall(_BaseChecker):
    error_id = "async-signal-unsafe-call"
    severity = "error"

    def check(self, cfg: Any, handler_names: Set[str],
              handler_scopes: Set[Any]) -> None:
        if not handler_scopes:
            return
        for tok in _iter_tokens(cfg):
            if not _is_call_site(tok):
                continue
            name = _tok_str(tok)
            if name not in _SIGNAL_UNSAFE:
                continue
            # Check if this call is inside a handler scope.
            for scope in handler_scopes:
                if _scope_contains(scope, tok):
                    # Retrieve handler name for the note.
                    body_start = getattr(scope, "bodyStart", None)
                    handler_name = "<handler>"
                    if body_start:
                        prev = getattr(body_start, "previous", None)
                        if prev and _tok_str(prev) == ")":
                            link = getattr(prev, "link", None)
                            if link:
                                prev = getattr(link, "previous", None)
                        if prev:
                            handler_name = _tok_str(prev)
                    self._add(
                        msg=(
                            f"Async-signal-unsafe function '{name}' called "
                            f"inside signal handler '{handler_name}' — "
                            f"undefined behaviour under POSIX.1-2017 §2.4.3 "
                            f"(CWE-479)"
                        ),
                        file=_tok_file(tok),
                        line=_tok_line(tok),
                    )
                    break  # one scope match is enough


# ─────────────────────────────────────────────────────────────────────────────
#  sig-02  Signal Handler Modifies Non-Volatile Global  (CWE-828)
# ─────────────────────────────────────────────────────────────────────────────
#
#  Writing to a global variable inside a signal handler is only safe if
#  the variable is declared  volatile sig_atomic_t.  Writing to any other
#  global type creates a data race: the write may be non-atomic and the
#  compiler is free to cache the value in a register for the interrupted
#  thread's read.
#
#  Detection: for each assignment operator token inside a handler scope,
#  check if the LHS variable is a global that is NOT volatile sig_atomic_t.
# ─────────────────────────────────────────────────────────────────────────────

class _Sig02_ModifiesGlobal(_BaseChecker):
    error_id = "signal-handler-modifies-global"
    severity = "warning"

    def check(self, cfg: Any, handler_names: Set[str],
              handler_scopes: Set[Any]) -> None:
        if not handler_scopes:
            return
        global_vids = _collect_global_vids(cfg)
        if not global_vids:
            return

        # Build a lookup: varId → variable object for every variable so we
        # can resolve token → variable for the assignment LHS.
        vid_to_var: Dict[int, Any] = {}
        for var in _iter_variables(cfg):
            vid = _safe_vid(getattr(var, "Id", None))
            if vid is not None:
                vid_to_var[vid] = var

        for tok in _iter_tokens(cfg):
            # Assignment operators: =, +=, -=, etc.
            if not getattr(tok, "isAssignmentOp", False):
                continue
            lhs = getattr(tok, "astOperand1", None)
            if lhs is None:
                continue
            vid = _safe_vid_tok(lhs)
            if vid not in global_vids:
                continue
            var = vid_to_var.get(vid)
            if var is None:
                continue
            if _var_is_volatile_sig_atomic(var):
                continue  # correct usage

            for scope in handler_scopes:
                if _scope_contains(scope, tok):
                    var_name = _tok_str(lhs)
                    self._add(
                        msg=(
                            f"Signal handler writes to global variable "
                            f"'{var_name}' (id={vid}) which is not declared "
                            f"'volatile sig_atomic_t' — data race (CWE-828)"
                        ),
                        file=_tok_file(tok),
                        line=_tok_line(tok),
                    )
                    break


# ─────────────────────────────────────────────────────────────────────────────
#  sig-03  Signal Flag Not Declared volatile sig_atomic_t  (CWE-364)
# ─────────────────────────────────────────────────────────────────────────────
#
#  The canonical correct pattern for a signal flag is:
#
#    volatile sig_atomic_t g_caught = 0;
#
#  Any global that is:
#    1. Written inside a signal handler, AND
#    2. Read in the main thread (outside any handler scope)
#
#  must be volatile sig_atomic_t.  If it is not, we flag the declaration site.
#
#  This checker focuses on the *declaration* site rather than the use site,
#  complementing sig-02 which flags the assignment site.
# ─────────────────────────────────────────────────────────────────────────────

class _Sig03_FlagNotVolatile(_BaseChecker):
    error_id = "signal-flag-not-volatile"
    severity = "warning"

    def check(self, cfg: Any, handler_names: Set[str],
              handler_scopes: Set[Any]) -> None:
        if not handler_scopes:
            return
        global_vids = _collect_global_vids(cfg)
        if not global_vids:
            return

        # Find globals written inside handlers.
        written_in_handler: Set[int] = set()
        for tok in _iter_tokens(cfg):
            if not getattr(tok, "isAssignmentOp", False):
                continue
            lhs = getattr(tok, "astOperand1", None)
            if lhs is None:
                continue
            vid = _safe_vid_tok(lhs)
            if vid not in global_vids:
                continue
            for scope in handler_scopes:
                if _scope_contains(scope, tok):
                    written_in_handler.add(vid)
                    break

        if not written_in_handler:
            return

        # For each such variable, check its declaration.
        vid_to_var: Dict[int, Any] = {
            _safe_vid(getattr(var, "Id", None)): var
            for var in _iter_variables(cfg)
            if _safe_vid(getattr(var, "Id", None)) is not None
        }

        for vid in written_in_handler:
            var = vid_to_var.get(vid)
            if var is None:
                continue
            if _var_is_volatile_sig_atomic(var):
                continue
            name_tok = getattr(var, "nameToken", None)
            if name_tok is None:
                continue
            var_name = _tok_str(name_tok)
            self._add(
                msg=(
                    f"Global variable '{var_name}' is used as a signal flag "
                    f"but is not declared 'volatile sig_atomic_t' — "
                    f"compiler may cache or reorder reads (CWE-364)"
                ),
                file=_tok_file(name_tok),
                line=_tok_line(name_tok),
            )


# ─────────────────────────────────────────────────────────────────────────────
#  sig-04  Signal Handler Re-Registers Signal  (CWE-662)
# ─────────────────────────────────────────────────────────────────────────────
#
#  On some UNIX implementations (particularly older SVR4 systems and any
#  system not providing SA_RESTART / SA_RESETHAND control), a signal()
#  call inside a handler to re-arm the same signal creates a race window:
#
#    Handler invoked → signal resets to SIG_DFL → handler re-arms signal
#                                 ↑ race window here ↑
#
#  Additionally, calling signal() inside a handler is itself an
#  async-signal-unsafe operation on many implementations.
#
#  Detection: flag any call to signal()/sigaction() inside a handler scope.
# ─────────────────────────────────────────────────────────────────────────────

class _Sig04_HandlerCallsSignal(_BaseChecker):
    error_id = "signal-handler-calls-signal"
    severity = "warning"

    def check(self, cfg: Any, handler_names: Set[str],
              handler_scopes: Set[Any]) -> None:
        if not handler_scopes:
            return
        for tok in _iter_tokens(cfg):
            if not _is_call_site(tok):
                continue
            if _tok_str(tok) not in _SIGNAL_REG:
                continue
            for scope in handler_scopes:
                if _scope_contains(scope, tok):
                    self._add(
                        msg=(
                            f"Signal handler calls '{_tok_str(tok)}()' to "
                            f"re-register a signal — creates a race window "
                            f"between reset and re-arm (CWE-662)"
                        ),
                        file=_tok_file(tok),
                        line=_tok_line(tok),
                    )
                    break


# ─────────────────────────────────────────────────────────────────────────────
#  sig-05  Missing errno Save/Restore  (CWE-364)
# ─────────────────────────────────────────────────────────────────────────────
#
#  errno is a thread-local variable that many async-signal-safe syscalls
#  modify as a side effect (e.g. read(), write(), kill()).  If a signal
#  handler calls any such function, it may clobber the errno value that
#  the interrupted code was about to inspect, causing the interrupted
#  code to misinterpret the error.
#
#  The correct pattern is:
#
#    void handler(int sig) {
#        int saved_errno = errno;
#        write(STDERR_FILENO, "caught\n", 7);
#        errno = saved_errno;
#    }
#
#  Detection heuristic
#  ───────────────────
#  1. Locate handlers that call any _ERRNO_CLOBBERERS function.
#  2. Check whether the handler body assigns to a variable named "errno"
#     (save) AND assigns errno back at the end (restore).
#  3. If either is missing, flag the clobbering call.
# ─────────────────────────────────────────────────────────────────────────────

class _Sig05_MissingErrnoSave(_BaseChecker):
    error_id = "signal-handler-missing-errno-save"
    severity = "warning"

    def check(self, cfg: Any, handler_names: Set[str],
              handler_scopes: Set[Any]) -> None:
        if not handler_scopes:
            return

        for scope in handler_scopes:
            body_start = getattr(scope, "bodyStart", None)
            body_end = getattr(scope, "bodyEnd", None)
            if body_start is None or body_end is None:
                continue

            # Collect all call sites and errno mentions inside this handler.
            clobbering_calls: List[Tuple[str, str, int]] = []  # (name, file, line)
            errno_saved = False
            errno_restored = False

            tok = getattr(body_start, "next", None)
            while tok is not None and tok is not body_end:
                s = _tok_str(tok)

                # Detect errno assignment:  errno = saved / saved = errno
                if getattr(tok, "isAssignmentOp", False) and s == "=":
                    lhs = getattr(tok, "astOperand1", None)
                    rhs = getattr(tok, "astOperand2", None)
                    if lhs and _tok_str(lhs) == "errno":
                        errno_restored = True
                    if rhs and _tok_str(rhs) == "errno":
                        errno_saved = True

                # Detect calls to errno-clobbering functions
                if _is_call_site(tok) and s in _ERRNO_CLOBBERERS:
                    clobbering_calls.append((s, _tok_file(tok), _tok_line(tok)))

                tok = getattr(tok, "next", None)

            # Flag calls that occur without proper save/restore.
            if clobbering_calls and not (errno_saved and errno_restored):
                for fname, ffile, fline in clobbering_calls:
                    note_msg = (
                        "errno save (int saved=errno) not found in handler"
                        if not errno_saved
                        else "errno restore (errno=saved) not found in handler"
                    )
                    self._add(
                        msg=(
                            f"Signal handler calls '{fname}()' which may "
                            f"modify errno without saving/restoring it first "
                            f"— interrupted code may see wrong errno (CWE-364)"
                        ),
                        file=ffile,
                        line=fline,
                        notes=[(ffile, fline, note_msg)],
                    )


# ─────────────────────────────────────────────────────────────────────────────
#  sig-06  longjmp / siglongjmp from Handler  (CWE-828)
# ─────────────────────────────────────────────────────────────────────────────
#
#  Calling longjmp() from a signal handler is explicitly prohibited by
#  POSIX unless the target setjmp() was set up inside the same signal
#  context.  On most implementations it leaves the interrupted thread's
#  signal mask, stack, and mutex state in an undefined condition.
#
#  siglongjmp() is slightly safer (it restores the signal mask), but is
#  still dangerous unless the program was specifically designed for it.
#
#  Detection: flag any longjmp/siglongjmp call inside a handler scope.
# ─────────────────────────────────────────────────────────────────────────────

class _Sig06_LongjmpUnsafe(_BaseChecker):
    error_id = "signal-longjmp-unsafe"
    severity = "error"

    def check(self, cfg: Any, handler_names: Set[str],
              handler_scopes: Set[Any]) -> None:
        if not handler_scopes:
            return
        for tok in _iter_tokens(cfg):
            if not _is_call_site(tok):
                continue
            name = _tok_str(tok)
            if name not in _LONGJMP:
                continue
            for scope in handler_scopes:
                if _scope_contains(scope, tok):
                    self._add(
                        msg=(
                            f"'{name}()' called from inside a signal handler "
                            f"— leaves program in undefined state "
                            f"(POSIX.1-2017 §2.4.3, CWE-828)"
                        ),
                        file=_tok_file(tok),
                        line=_tok_line(tok),
                    )
                    break


# ═════════════════════════════════════════════════════════════════════════════
#  PART 8 — REGISTRY + RUNNER
# ═════════════════════════════════════════════════════════════════════════════

_CHECKERS = [
    _Sig01_AsyncUnsafeCall,
    _Sig02_ModifiesGlobal,
    _Sig03_FlagNotVolatile,
    _Sig04_HandlerCallsSignal,
    _Sig05_MissingErrnoSave,
    _Sig06_LongjmpUnsafe,
]


def _run(dump_file: str) -> None:
    if cppcheckdata is None:
        sys.stderr.write("SignalSafetyLint: cppcheckdata not available\n")
        sys.exit(1)

    data = cppcheckdata.parsedump(dump_file)
    for cfg in data.configurations:
        # Two-pass:
        #   Pass 1 — collect handler names and handler scopes (cheap, global)
        #   Pass 2 — run all checkers with that context
        handler_names = _collect_handler_names(cfg)
        handler_scopes = _collect_handler_scopes(cfg, handler_names)

        for checker_cls in _CHECKERS:
            checker = checker_cls()
            checker.run(cfg, handler_names, handler_scopes)
            checker.emit_all()


# ═════════════════════════════════════════════════════════════════════════════
#  PART 9 — ENTRY POINT
# ═════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write(
            "Usage: python SignalSafetyLint.py <file.c.dump>\n"
        )
        sys.exit(1)
    _run(sys.argv[1])
