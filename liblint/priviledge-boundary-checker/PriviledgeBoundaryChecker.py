#!/usr/bin/env python3
"""
PrivilegeBoundaryChecker.py
══════════════════════════════════════════════════════════════════════════
Cppcheck addon: detects violations of privilege separation discipline in
C/C++ code.  Covers uid/gid management, capability transitions, TOCTOU
windows around privilege boundaries, and tainted data crossing into
privileged execution contexts.

Output format (plain text, cppcheck-addon compatible):
    [filename:line]: (severity) message [errorId]

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CHECKER INVENTORY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  PBC-01  PrivilegedOperationChecker     CWE-250  error
  PBC-02  UncheckedPrivDropChecker       CWE-273  error
  PBC-03  PermanentPrivDropChecker       CWE-269  error
  PBC-04  TaintedExecChecker             CWE-284  warning
  PBC-05  UnsafeTmpFileChecker           CWE-377  warning
  PBC-06  SignalMaskPrivChecker          CWE-362  warning
  PBC-07  CapabilityRaiseChecker         CWE-272  error
  PBC-08  PrivReacquisitionChecker       CWE-693  warning

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CONTRACT — READ BEFORE MODIFYING
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
1.  NEVER call int(tok.varId) directly. Always use _safe_vid(raw)
    or _safe_vid_tok(tok).  varId values from .dump files may be
    hex addresses, "0", or None — all of which int() will crash on.

2.  NEVER assume tok.astOperand1 / astOperand2 / astParent are
    populated.  Always guard: op = getattr(tok, "astOperandN", None).

3.  All checkers inherit _BaseChecker and implement:
        check(cfg, priv_state, tainted, sanitized) -> List[_Finding]

4.  Plain-text output ONLY.  No JSON paths anywhere.

5.  Privilege-altering calls are in _PRIV_DROP_CALLS, _PRIV_RAISE_CALLS,
    _PRIV_QUERY_CALLS.  Add new entries there — not inside checker logic.

6.  Taint sources are in _TAINT_SOURCES_RETURN / _TAINT_SOURCES_OUTPARAM.
    Keep these tables canonical.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Usage:
    cppcheck --dump --check-level=exhaustive target.c
    python PrivilegeBoundaryChecker.py target.c.dump
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

import cppcheckdata

# ══════════════════════════════════════════════════════════════════════════
#  §1  PRIVILEGE-CALL TAXONOMY
# ══════════════════════════════════════════════════════════════════════════

# Calls that unconditionally DROP privilege (uid ≥ 0 arg → permanent).
_PRIV_DROP_CALLS: FrozenSet[str] = frozenset({
    "setuid", "setgid",
    "setreuid", "setregid",
    "setresuid", "setresgid",
})

# Calls that DROP privilege only temporarily (euid / egid only).
_PRIV_DROP_TEMP_CALLS: FrozenSet[str] = frozenset({
    "seteuid", "setegid",
})

# Calls that RAISE privilege (restore saved uid/gid or set to 0).
_PRIV_RAISE_CALLS: FrozenSet[str] = frozenset({
    "seteuid", "setegid",           # when arg is 0 or saved-uid
    "setuid",                       # when arg is 0
    "setresuid", "setresgid",       # when effective arg is 0
    "cap_set_proc",                 # POSIX capabilities
    "prctl",                        # PR_SET_SECUREBITS etc.
})

# Calls that QUERY current privilege level.
_PRIV_QUERY_CALLS: FrozenSet[str] = frozenset({
    "getuid", "geteuid",
    "getgid", "getegid",
    "getresuid", "getresgid",
})

# Calls that are dangerous if performed WHILE privileged.
_PRIVILEGED_DANGEROUS_CALLS: FrozenSet[str] = frozenset({
    # File-system operations that race with an attacker.
    "access", "stat", "lstat",
    "open",   "openat",
    "creat",  "mkdir", "mkfifo",
    "chown",  "lchown", "fchown",
    "chmod",  "lchmod",
    "rename", "link", "symlink",
    "unlink", "rmdir",
    # Process operations.
    "system", "popen", "execve", "execvp", "execvpe",
    "execl",  "execlp", "execle",
    "posix_spawn",
})

# Temporary-file creation calls that need O_EXCL.
_TMPFILE_CALLS: FrozenSet[str] = frozenset({
    "open", "openat", "creat",
    "fopen",
    "tmpnam",           # inherently unsafe
    "tempnam",          # inherently unsafe
    "mktemp",           # inherently unsafe
})

# Safe tmpfile alternatives — presence nearby suppresses PBC-05.
_SAFE_TMPFILE_CALLS: FrozenSet[str] = frozenset({
    "mkstemp", "mkostemp", "mkostemps", "mkdtemp",
    "tmpfile",
})

# Signal-mask calls that should bracket privilege transitions.
_SIGNAL_MASK_CALLS: FrozenSet[str] = frozenset({
    "sigprocmask", "pthread_sigmask",
    "sigemptyset", "sigfillset",
    "sigaction",
})

# Exec-family calls that execute external processes.
_EXEC_CALLS: FrozenSet[str] = frozenset({
    "system", "popen",
    "execve", "execvp", "execvpe",
    "execl",  "execlp", "execle",
    "posix_spawn", "posix_spawnp",
})

# Taint sources: functions whose RETURN VALUE is attacker-influenced.
_TAINT_SOURCES_RETURN: FrozenSet[str] = frozenset({
    "recv", "recvfrom", "recvmsg",
    "read", "fread",
    "fgets", "gets", "getchar",
    "scanf", "fscanf", "sscanf",
    "getenv",
    "atoi", "atol", "atoll",
    "strtol", "strtoul", "strtoll", "strtoull",
    "ntohl", "ntohs", "ntohll",
    "be32toh", "be16toh", "be64toh",
    "le32toh", "le16toh", "le64toh",
    # argv / environment are tainted at entry; reflected via getenv
})

# Taint sources: (function, out_param_index) — -1 means all ptr args.
_TAINT_SOURCES_OUTPARAM: Tuple[Tuple[str, int], ...] = (
    ("recv",     1),
    ("recvfrom", 1),
    ("read",     1),
    ("fread",    0),
    ("fgets",    0),
    ("gets",     0),
    ("scanf",   -1),
    ("fscanf",  -1),
)

# Sanitizers — a tainted varId passing through any of these is clean.
_SANITIZERS: FrozenSet[str] = frozenset({
    "validate_path", "sanitize_path",
    "realpath",       # resolves symlinks — often used as sanitizer
    "basename",       # strips directory component
    "whitelist_check",
    "escape_shell_arg",
    "assert",
    "bounds_check",
})


# ══════════════════════════════════════════════════════════════════════════
#  §2  SAFE varId HELPERS  (see CONTRACT §1)
# ══════════════════════════════════════════════════════════════════════════

def _safe_vid(raw: Any) -> Optional[int]:
    """
    Convert a raw varId to a positive int, or return None.

    Rejects: None, 0/"0" (cppcheck sentinel), hex-address strings.
    """
    if raw is None:
        return None
    try:
        v = int(raw)
        return v if v > 0 else None
    except (ValueError, TypeError):
        return None


def _safe_vid_tok(tok: Any) -> Optional[int]:
    return _safe_vid(getattr(tok, "varId", None))


# ══════════════════════════════════════════════════════════════════════════
#  §3  TOKEN / AST TRAVERSAL HELPERS
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

def _tok_next(tok: Any) -> Any:
    return getattr(tok, "next", None)

def _tok_prev(tok: Any) -> Any:
    return getattr(tok, "previous", None)

def _tok_scope(tok: Any) -> Any:
    return getattr(tok, "scope", None)


def _iter_tokens(cfg: Any):
    yield from getattr(cfg, "tokenlist", [])

def _iter_scopes(cfg: Any):
    yield from getattr(cfg, "scopes", [])

def _iter_variables(cfg: Any):
    yield from getattr(cfg, "variables", [])


def _called_name(tok: Any) -> Optional[str]:
    """
    If tok is the '(' of a call, return the callee name string.
    Returns None for casts and non-call parens.
    """
    if _tok_str(tok) != "(":
        return None
    if getattr(tok, "isCast", False):
        return None
    op1 = _tok_op1(tok)
    if op1 is None:
        return None
    s = _tok_str(op1)
    if s in {"->", "."}:
        right = _tok_op2(op1)
        return _tok_str(right) if right is not None else None
    return s or None


def _get_call_args(call_paren: Any) -> List[Any]:
    """Flatten the argument list of a call '(' token into a list."""
    op2 = _tok_op2(call_paren)
    if op2 is None:
        return []
    result: List[Any] = []
    _flatten_comma(op2, result)
    return result


def _flatten_comma(tok: Any, out: List[Any]) -> None:
    if tok is None:
        return
    if _tok_str(tok) == ",":
        _flatten_comma(_tok_op1(tok), out)
        _flatten_comma(_tok_op2(tok), out)
    else:
        out.append(tok)


def _is_in_loop(tok: Any) -> bool:
    scope = _tok_scope(tok)
    while scope is not None:
        if getattr(scope, "type", "") in {"While", "For", "Do"}:
            return True
        scope = getattr(scope, "nestedIn", None)
    return False


def _enclosing_function_name(tok: Any) -> Optional[str]:
    scope = _tok_scope(tok)
    while scope is not None:
        if getattr(scope, "type", "") == "Function":
            return getattr(scope, "className", None)
        scope = getattr(scope, "nestedIn", None)
    return None


def _scan_forward(start_tok: Any, steps: int):
    """Yield up to `steps` tokens starting after start_tok."""
    tok = _tok_next(start_tok)
    for _ in range(steps):
        if tok is None:
            return
        yield tok
        tok = _tok_next(tok)


def _scan_backward(start_tok: Any, steps: int):
    """Yield up to `steps` tokens going backward from start_tok."""
    tok = _tok_prev(start_tok)
    for _ in range(steps):
        if tok is None:
            return
        yield tok
        tok = _tok_prev(tok)


def _get_int_arg_value(arg_tok: Any) -> Optional[int]:
    """
    Try to resolve a call argument to a compile-time integer constant.
    Uses ValueFlow first, falls back to literal parsing.
    """
    # ValueFlow known value
    for v in getattr(arg_tok, "values", None) or []:
        if getattr(v, "valueKind", "") == "known":
            iv = getattr(v, "intvalue", None)
            if iv is not None:
                try:
                    return int(iv)
                except (ValueError, TypeError):
                    pass
    # Literal token
    s = _tok_str(arg_tok)
    try:
        return int(s, 0)
    except (ValueError, TypeError):
        return None


# ══════════════════════════════════════════════════════════════════════════
#  §4  TAINT COLLECTION
# ══════════════════════════════════════════════════════════════════════════

def _collect_tainted_vids(cfg: Any) -> Set[int]:
    """
    Single-pass + propagation taint collection.
    Returns positive integer varIds considered attacker-tainted.
    """
    tainted: Set[int] = set()

    # Pass 1 — direct sources
    for tok in _iter_tokens(cfg):
        if _tok_str(tok) != "(":
            continue
        name = _called_name(tok)
        if name is None:
            continue

        # Return-value sources: var = source(...)
        if name in _TAINT_SOURCES_RETURN:
            par = _tok_parent(tok)
            if par is not None and getattr(par, "isAssignmentOp", False):
                lhs = _tok_op1(par)
                vid = _safe_vid_tok(lhs)
                if vid is not None:
                    tainted.add(vid)
            # One level up in case of implicit conversion node
            if par is not None:
                gp = _tok_parent(par)
                if gp is not None and getattr(gp, "isAssignmentOp", False):
                    lhs = _tok_op1(gp)
                    vid = _safe_vid_tok(lhs)
                    if vid is not None:
                        tainted.add(vid)

        # Out-parameter sources
        for (src, out_idx) in _TAINT_SOURCES_OUTPARAM:
            if name != src:
                continue
            args = _get_call_args(tok)
            if out_idx == -1:
                for arg in args:
                    inner = _tok_op1(arg) if _tok_str(arg) == "&" else arg
                    vid = _safe_vid_tok(inner)
                    if vid is not None:
                        tainted.add(vid)
            elif 0 <= out_idx < len(args):
                arg = args[out_idx]
                inner = _tok_op1(arg) if _tok_str(arg) == "&" else arg
                vid = _safe_vid_tok(inner)
                if vid is not None:
                    tainted.add(vid)

    # Pass 2 — one-hop assignment propagation
    changed = True
    while changed:
        changed = False
        for tok in _iter_tokens(cfg):
            if not getattr(tok, "isAssignmentOp", False):
                continue
            if _tok_str(tok) != "=":
                continue
            lhs_vid = _safe_vid_tok(_tok_op1(tok))
            rhs_vid = _safe_vid_tok(_tok_op2(tok))
            if lhs_vid is None or rhs_vid is None:
                continue
            if rhs_vid in tainted and lhs_vid not in tainted:
                tainted.add(lhs_vid)
                changed = True

    return tainted


def _collect_sanitized_vids(cfg: Any, tainted: Set[int]) -> Set[int]:
    sanitized: Set[int] = set()
    for tok in _iter_tokens(cfg):
        if _tok_str(tok) != "(":
            continue
        if _called_name(tok) not in _SANITIZERS:
            continue
        for arg in _get_call_args(tok):
            vid = _safe_vid_tok(arg)
            if vid is not None and vid in tainted:
                sanitized.add(vid)
    return sanitized


# ══════════════════════════════════════════════════════════════════════════
#  §5  PRIVILEGE STATE TRACKING
# ══════════════════════════════════════════════════════════════════════════

@dataclass
class _PrivEvent:
    """A single privilege-altering call site."""
    tok: Any           # the '(' token of the call
    call_name: str
    kind: str          # "drop", "drop_temp", "raise", "query"
    arg_value: Optional[int]   # first integer argument if known
    file: str
    line: int

    # Was the return value checked?
    return_checked: bool = False
    # For raise: was this seteuid(0) specifically?
    raises_to_root: bool = False


def _collect_priv_events(cfg: Any) -> List[_PrivEvent]:
    """
    Walk the token list and record every privilege-altering call.
    Also annotate whether the return value was checked.
    """
    events: List[_PrivEvent] = []

    for tok in _iter_tokens(cfg):
        if _tok_str(tok) != "(":
            continue
        name = _called_name(tok)
        if name is None:
            continue

        # Classify the call
        if name in _PRIV_DROP_CALLS:
            kind = "drop"
        elif name in _PRIV_DROP_TEMP_CALLS:
            kind = "drop_temp"
        elif name in _PRIV_RAISE_CALLS and name not in _PRIV_DROP_CALLS:
            kind = "raise"
        else:
            continue

        args = _get_call_args(tok)
        arg_val: Optional[int] = None
        if args:
            arg_val = _get_int_arg_value(args[0])

        # For seteuid/setuid — does first arg resolve to 0?
        raises_to_root = (
            kind in {"raise", "drop_temp"}
            and arg_val == 0
        )
        # If setuid(0) that counts as a raise
        if name == "setuid" and arg_val == 0:
            kind = "raise"
            raises_to_root = True

        ev = _PrivEvent(
            tok=tok,
            call_name=name,
            kind=kind,
            arg_value=arg_val,
            file=_tok_file(tok),
            line=_tok_line(tok),
            raises_to_root=raises_to_root,
        )

        # Check if the return value is used in a conditional
        ev.return_checked = _return_value_checked(tok)
        events.append(ev)

    return events


def _return_value_checked(call_paren: Any) -> bool:
    """
    Heuristic: is the return value of this call tested?

    Patterns accepted:
      - if (setuid(...)) { ... }
      - if (setuid(...) == -1) { ... }
      - rc = setuid(...); if (rc ...) { ... }
      - result checked via assert / err() / err_sys()
    """
    par = _tok_parent(call_paren)
    if par is None:
        return False

    par_str = _tok_str(par)

    # Direct: if (setuid(...)) or while (setuid(...))
    if par_str in {"if", "while", "for"}:
        return True

    # Comparison: setuid(...) == -1  or  setuid(...) != 0
    if par_str in {"==", "!=", "<", ">", "<=", ">="}:
        return True

    # Assignment: rc = setuid(...)
    if getattr(par, "isAssignmentOp", False):
        lhs = _tok_op1(par)
        lhs_vid = _safe_vid_tok(lhs)
        if lhs_vid is not None:
            # Look forward up to 40 tokens for that vid in an if/comparison
            tok = _tok_next(par)
            for _ in range(40):
                if tok is None:
                    break
                if _safe_vid_tok(tok) == lhs_vid:
                    p2 = _tok_parent(tok)
                    if p2 is not None and _tok_str(p2) in {
                        "if", "while", "==", "!=", "<", ">", "<=", ">=",
                    }:
                        return True
                tok = _tok_next(tok)

    # Negation / logical-not: !setuid(...)
    if par_str == "!":
        return True

    return False


# ══════════════════════════════════════════════════════════════════════════
#  §6  FINDING MODEL
# ══════════════════════════════════════════════════════════════════════════

@dataclass
class _Finding:
    filename: str
    line: int
    severity: str
    message: str
    error_id: str
    secondary_file: str = ""
    secondary_line: int = 0

    def format(self) -> str:
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
#  §7  BASE CHECKER
# ══════════════════════════════════════════════════════════════════════════

class _BaseChecker:
    name: str = "base"

    def check(
        self,
        cfg: Any,
        priv_events: List[_PrivEvent],
        tainted: Set[int],
        sanitized: Set[int],
    ) -> List[_Finding]:
        raise NotImplementedError

    @staticmethod
    def _f(
        tok: Any,
        severity: str,
        message: str,
        error_id: str,
        sec_tok: Any = None,
    ) -> _Finding:
        return _Finding(
            filename=_tok_file(tok),
            line=_tok_line(tok),
            severity=severity,
            message=message,
            error_id=error_id,
            secondary_file=_tok_file(sec_tok) if sec_tok else "",
            secondary_line=_tok_line(sec_tok) if sec_tok else 0,
        )


# ══════════════════════════════════════════════════════════════════════════
#  §8  CHECKER IMPLEMENTATIONS
# ══════════════════════════════════════════════════════════════════════════

# ─────────────────────────────────────────────────────────────────────────
#  PBC-01  PrivilegedOperationChecker  (CWE-250)
# ─────────────────────────────────────────────────────────────────────────

class PrivilegedOperationChecker(_BaseChecker):
    """
    Flags file-system / process operations that are risky when called
    while the process still holds elevated privilege.

    Specifically: dangerous calls that appear BEFORE any privilege-drop
    event in the same function, suggesting they execute as root / setuid.

    CWE-250: Execution with Unnecessary Privileges.
    """

    name = "PBC-01"

    def check(
        self,
        cfg: Any,
        priv_events: List[_PrivEvent],
        tainted: Set[int],
        sanitized: Set[int],
    ) -> List[_Finding]:
        findings: List[_Finding] = []
        seen: Set[Tuple[str, int]] = set()

        # Build a set of lines at which a privilege drop occurs.
        drop_lines: Set[int] = {
            ev.line for ev in priv_events
            if ev.kind in {"drop", "drop_temp"}
        }

        if not drop_lines:
            # No privilege-drop at all in this translation unit —
            # we cannot determine privilege state.  Skip.
            return findings

        first_drop = min(drop_lines)

        for tok in _iter_tokens(cfg):
            if _tok_str(tok) != "(":
                continue
            name = _called_name(tok)
            if name not in _PRIVILEGED_DANGEROUS_CALLS:
                continue

            line = _tok_line(tok)
            if line >= first_drop:
                # Call is after the first privilege drop — acceptable.
                continue

            key = (_tok_file(tok), line)
            if key in seen:
                continue
            seen.add(key)

            findings.append(self._f(
                tok,
                "error",
                f"Dangerous call '{name}()' executed before privilege drop "
                f"at line {first_drop} — process may run with excessive "
                f"privilege (CWE-250)",
                "privilegedOperation",
            ))

        return findings


# ─────────────────────────────────────────────────────────────────────────
#  PBC-02  UncheckedPrivDropChecker  (CWE-273)
# ─────────────────────────────────────────────────────────────────────────

class UncheckedPrivDropChecker(_BaseChecker):
    """
    Flags setuid/setgid/setresuid calls whose return value is not checked.

    If setuid() fails (e.g., due to kernel limits or a race), the process
    continues running with elevated privilege.  The caller MUST test the
    return value.

    CWE-273: Improper Check for Dropped Privileges.
    """

    name = "PBC-02"

    def check(
        self,
        cfg: Any,
        priv_events: List[_PrivEvent],
        tainted: Set[int],
        sanitized: Set[int],
    ) -> List[_Finding]:
        findings: List[_Finding] = []

        for ev in priv_events:
            if ev.kind not in {"drop", "drop_temp"}:
                continue
            if ev.return_checked:
                continue

            findings.append(self._f(
                ev.tok,
                "error",
                f"Return value of '{ev.call_name}()' is not checked — "
                f"if the call fails the process continues with elevated "
                f"privilege (CWE-273)",
                "uncheckedPrivDrop",
            ))

        return findings


# ─────────────────────────────────────────────────────────────────────────
#  PBC-03  PermanentPrivDropChecker  (CWE-269)
# ─────────────────────────────────────────────────────────────────────────

class PermanentPrivDropChecker(_BaseChecker):
    """
    Detects patterns where a "permanent" privilege drop is attempted
    but might be reversible because the saved-uid was not also cleared.

    Pattern:
        seteuid(nobody)       ← only drops effective uid
        // no setuid(nobody)  ← saved uid still 0; seteuid(0) restores it

    Also flags: setresuid(-1, unprivileged, -1) which leaves saved-uid
    at root, allowing later restoration.

    CWE-269: Improper Privilege Management.
    """

    name = "PBC-03"

    def check(
        self,
        cfg: Any,
        priv_events: List[_PrivEvent],
        tainted: Set[int],
        sanitized: Set[int],
    ) -> List[_Finding]:
        findings: List[_Finding] = []

        # Check 1: seteuid used but setuid never called in same TU.
        has_setuid   = any(
            ev.call_name in {"setuid", "setresuid", "setresgid"}
            for ev in priv_events
        )
        has_seteuid  = [
            ev for ev in priv_events
            if ev.call_name in {"seteuid", "setegid"}
            and ev.kind == "drop_temp"
        ]

        if has_seteuid and not has_setuid:
            for ev in has_seteuid:
                findings.append(self._f(
                    ev.tok,
                    "error",
                    f"'{ev.call_name}()' only drops effective uid/gid; saved "
                    f"uid is preserved — privilege drop is reversible (CWE-269). "
                    f"Use setuid()/setresuid() to clear the saved uid.",
                    "reversiblePrivDrop",
                ))

        # Check 2: setresuid(real, effective, -1) — saved not cleared.
        for ev in priv_events:
            if ev.call_name not in {"setresuid", "setresgid"}:
                continue
            args = _get_call_args(ev.tok)
            if len(args) < 3:
                continue
            saved_val = _get_int_arg_value(args[2])
            # -1 (0xFFFFFFFF as unsigned, or -1 signed) means "keep current"
            if saved_val is not None and (saved_val == -1 or saved_val == 0xFFFFFFFF):
                findings.append(self._f(
                    ev.tok,
                    "error",
                    f"'{ev.call_name}()' called with saved-uid argument of -1 "
                    f"— saved privilege is preserved and privilege drop is "
                    f"reversible (CWE-269)",
                    "savedUidNotCleared",
                ))

        return findings


# ─────────────────────────────────────────────────────────────────────────
#  PBC-04  TaintedExecChecker  (CWE-284)
# ─────────────────────────────────────────────────────────────────────────

class TaintedExecChecker(_BaseChecker):
    """
    Flags exec-family / system() calls where any argument carries a
    wire-tainted varId that has not been sanitized — especially dangerous
    when the process is (or was) privileged.

    CWE-284: Improper Access Control (tainted command / path injection).
    """

    name = "PBC-04"

    def check(
        self,
        cfg: Any,
        priv_events: List[_PrivEvent],
        tainted: Set[int],
        sanitized: Set[int],
    ) -> List[_Finding]:
        findings: List[_Finding] = []
        seen: Set[Tuple[str, int]] = set()

        for tok in _iter_tokens(cfg):
            if _tok_str(tok) != "(":
                continue
            name = _called_name(tok)
            if name not in _EXEC_CALLS:
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

                findings.append(self._f(
                    tok,
                    "warning",
                    f"Tainted data passed to '{name}()' without sanitization "
                    f"— command/path injection risk across privilege boundary "
                    f"(CWE-284)",
                    "taintedExec",
                ))
                break

        return findings


# ─────────────────────────────────────────────────────────────────────────
#  PBC-05  UnsafeTmpFileChecker  (CWE-377)
# ─────────────────────────────────────────────────────────────────────────

class UnsafeTmpFileChecker(_BaseChecker):
    """
    Flags temporary file creation in world-writable directories (like /tmp)
    without atomic O_EXCL semantics, particularly dangerous when done
    before a privilege drop.

    Also flags inherently unsafe calls: tmpnam(), tempnam(), mktemp().

    CWE-377: Insecure Temporary File.
    """

    name = "PBC-05"

    _INHERENTLY_UNSAFE: FrozenSet[str] = frozenset({
        "tmpnam", "tempnam", "mktemp",
    })

    # open() flags that provide O_EXCL atomicity
    _O_EXCL   = 0x0080          # Linux; also common on BSD
    _O_CREAT  = 0x0040

    def check(
        self,
        cfg: Any,
        priv_events: List[_PrivEvent],
        tainted: Set[int],
        sanitized: Set[int],
    ) -> List[_Finding]:
        findings: List[_Finding] = []
        seen: Set[Tuple[str, int]] = set()

        # Is there any safe tmpfile alternative in the TU?
        has_safe_alt = False
        for tok in _iter_tokens(cfg):
            if _tok_str(tok) == "(" and _called_name(tok) in _SAFE_TMPFILE_CALLS:
                has_safe_alt = True
                break

        for tok in _iter_tokens(cfg):
            if _tok_str(tok) != "(":
                continue
            name = _called_name(tok)
            if name not in _TMPFILE_CALLS:
                continue

            key = (_tok_file(tok), _tok_line(tok))
            if key in seen:
                continue

            # Inherently unsafe calls are always flagged
            if name in self._INHERENTLY_UNSAFE:
                seen.add(key)
                findings.append(self._f(
                    tok,
                    "warning",
                    f"'{name}()' is inherently unsafe — it creates a race "
                    f"condition (TOCTOU) between name generation and file "
                    f"creation (CWE-377). Use mkstemp() instead.",
                    "unsafeTmpFile",
                ))
                continue

            # For open()/fopen(): check if O_EXCL|O_CREAT is present
            if name in {"open", "openat"}:
                args = _get_call_args(tok)
                flags_idx = 1 if name == "open" else 2
                if flags_idx < len(args):
                    flags_val = _get_int_arg_value(args[flags_idx])
                    if flags_val is not None:
                        has_excl  = bool(flags_val & self._O_EXCL)
                        has_creat = bool(flags_val & self._O_CREAT)
                        if has_creat and has_excl:
                            continue   # O_CREAT|O_EXCL is atomic — safe

                # Path is a string literal pointing into /tmp?
                path_arg = args[0] if args else None
                if path_arg is not None and self._is_tmp_path(path_arg):
                    seen.add(key)
                    findings.append(self._f(
                        tok,
                        "warning",
                        f"'{name}()' into shared temp directory without "
                        f"O_CREAT|O_EXCL — TOCTOU race condition possible "
                        f"(CWE-377). Use O_CREAT|O_EXCL or mkstemp().",
                        "unsafeTmpFile",
                    ))

        return findings

    def _is_tmp_path(self, arg_tok: Any) -> bool:
        """Return True if arg_tok looks like a /tmp/… path literal."""
        s = _tok_str(arg_tok)
        # String literals start and end with "
        if s.startswith('"') and (
            '/tmp/' in s or '/var/tmp/' in s or '/dev/shm/' in s
        ):
            return True
        return False


# ─────────────────────────────────────────────────────────────────────────
#  PBC-06  SignalMaskPrivChecker  (CWE-362)
# ─────────────────────────────────────────────────────────────────────────

class SignalMaskPrivChecker(_BaseChecker):
    """
    Privilege transitions (setuid/seteuid) create a window during which
    a signal could fire and the signal handler runs with the wrong
    privilege level.  The correct pattern is:

        sigprocmask(SIG_BLOCK, ...)
        setuid(unprivileged)
        sigprocmask(SIG_UNBLOCK, ...)

    This checker flags privilege transitions that are NOT bracketed by
    sigprocmask / pthread_sigmask calls within a close token window.

    CWE-362: Race Condition (privilege-signal TOCTOU window).
    """

    name = "PBC-06"
    _WINDOW = 60   # tokens to scan before/after

    def check(
        self,
        cfg: Any,
        priv_events: List[_PrivEvent],
        tainted: Set[int],
        sanitized: Set[int],
    ) -> List[_Finding]:
        findings: List[_Finding] = []

        for ev in priv_events:
            if ev.kind not in {"drop", "drop_temp", "raise"}:
                continue

            has_before = self._has_signal_mask_nearby(
                ev.tok, before=True
            )
            has_after  = self._has_signal_mask_nearby(
                ev.tok, before=False
            )

            if not (has_before and has_after):
                findings.append(self._f(
                    ev.tok,
                    "warning",
                    f"Privilege transition '{ev.call_name}()' is not "
                    f"bracketed by sigprocmask()/pthread_sigmask() — "
                    f"signal handler may execute with unexpected privilege "
                    f"level (CWE-362)",
                    "unsignaledPrivChange",
                ))

        return findings

    def _has_signal_mask_nearby(self, tok: Any, before: bool) -> bool:
        scanner = _scan_backward if before else _scan_forward
        for t in scanner(tok, self._WINDOW):
            if _tok_str(t) == "(" and _called_name(t) in _SIGNAL_MASK_CALLS:
                return True
        return False


# ─────────────────────────────────────────────────────────────────────────
#  PBC-07  CapabilityRaiseChecker  (CWE-272)
# ─────────────────────────────────────────────────────────────────────────

class CapabilityRaiseChecker(_BaseChecker):
    """
    Flags seteuid(0) / setuid(0) calls that RE-RAISE privilege after it
    was previously dropped, particularly inside already-privileged scopes.

    A process that drops privilege should almost never need to re-acquire
    it — this pattern suggests the privilege drop was ineffective or that
    privilege is being used as a mutable toggle, which is inherently racy.

    CWE-272: Least Privilege Violation (capability re-raise).
    """

    name = "PBC-07"

    def check(
        self, cfg: Any,
        priv_events: List[_PrivEvent],
        tainted: Set[int],
        sanitized: Set[int],
    ) -> List[_Finding]:
        findings: List[_Finding] = []

        raise_events = [ev for ev in priv_events if ev.raises_to_root]
        if not raise_events:
            return findings

        drop_lines = sorted(
            ev.line for ev in priv_events
            if ev.kind in {"drop", "drop_temp"}
        )

        for ev in raise_events:
            # Flag if a raise-to-root comes AFTER a drop (re-acquisition).
            prior_drops = [l for l in drop_lines if l < ev.line]
            if prior_drops:
                findings.append(self._f(
                    ev.tok,
                    "error",
                    f"'{ev.call_name}(0)' re-acquires root privilege after "
                    f"it was dropped at line {prior_drops[-1]} — privilege "
                    f"should not be used as a mutable toggle (CWE-272)",
                    "capabilityRaise",
                ))
            else:
                # Raise without a prior drop: process was never unprivileged
                findings.append(self._f(
                    ev.tok,
                    "error",
                    f"'{ev.call_name}(0)' escalates to root privilege "
                    f"with no prior privilege drop — least-privilege "
                    f"principle violated (CWE-272)",
                    "capabilityRaise",
                ))

        return findings


# ─────────────────────────────────────────────────────────────────────────
#  PBC-08  PrivReacquisitionChecker  (CWE-693)
# ─────────────────────────────────────────────────────────────────────────

class PrivReacquisitionChecker(_BaseChecker):
    """
    Flags the pattern where a privilege drop is immediately followed
    (within a short token window) by a privilege re-acquisition, making
    the drop effectively a no-op and defeating any protection mechanism.

    Pattern:
        seteuid(nobody)      // drop
        // < 20 tokens >
        seteuid(0)           // re-raise — protection mechanism defeated

    CWE-693: Protection Mechanism Failure.
    """

    name = "PBC-08"
    _PROXIMITY_LINES = 10   # lines between drop and re-raise to flag

    def check(
        self,
        cfg: Any,
        priv_events: List[_PrivEvent],
        tainted: Set[int],
        sanitized: Set[int],
    ) -> List[_Finding]:
        findings: List[_Finding] = []

        drops  = [ev for ev in priv_events if ev.kind in {"drop", "drop_temp"}]
        raises = [ev for ev in priv_events if ev.kind == "raise" or ev.raises_to_root]

        for drop in drops:
            for raise_ev in raises:
                if raise_ev.line <= drop.line:
                    continue
                gap = raise_ev.line - drop.line
                if gap <= self._PROXIMITY_LINES:
                    findings.append(self._f(
                        raise_ev.tok,
                        "warning",
                        f"Privilege re-acquired by '{raise_ev.call_name}()' "
                        f"only {gap} line(s) after drop by "
                        f"'{drop.call_name}()' at line {drop.line} — "
                        f"protection mechanism is defeated (CWE-693)",
                        "privReacquisition",
                        sec_tok=drop.tok,
                    ))

        return findings


# ══════════════════════════════════════════════════════════════════════════
#  §9  RUNNER
# ══════════════════════════════════════════════════════════════════════════

_ALL_CHECKERS: List[_BaseChecker] = [
    PrivilegedOperationChecker(),
    UncheckedPrivDropChecker(),
    PermanentPrivDropChecker(),
    TaintedExecChecker(),
    UnsafeTmpFileChecker(),
    SignalMaskPrivChecker(),
    CapabilityRaiseChecker(),
    PrivReacquisitionChecker(),
]


def _run_on_dump(dump_path: str) -> None:
    try:
        data = cppcheckdata.CppcheckData(dump_path)
    except Exception as exc:
        sys.stderr.write(
            f"PrivilegeBoundaryChecker: cannot load '{dump_path}': {exc}\n"
        )
        sys.exit(1)

    for cfg in data.configurations:
        # Shared analysis — computed once per configuration
        priv_events = _collect_priv_events(cfg)
        tainted     = _collect_tainted_vids(cfg)
        sanitized   = _collect_sanitized_vids(cfg, tainted)

        all_findings: List[_Finding] = []

        for checker in _ALL_CHECKERS:
            try:
                found = checker.check(cfg, priv_events, tainted, sanitized)
                all_findings.extend(found)
            except Exception as exc:
                sys.stderr.write(
                    f"PrivilegeBoundaryChecker: checker {checker.name} "
                    f"failed on '{dump_path}': {exc}\n"
                )

        all_findings.sort(key=lambda f: (f.filename, f.line))
        for finding in all_findings:
            print(finding.format())


def main() -> None:
    if len(sys.argv) < 2:
        sys.stderr.write(
            "Usage: python PrivilegeBoundaryChecker.py "
            "<file.c.dump> [file2.c.dump ...]\n"
        )
        sys.exit(1)
    for dump_path in sys.argv[1:]:
        _run_on_dump(dump_path)


if __name__ == "__main__":
    main()
