#!/usr/bin/env python3
"""
NullabilityFlowChecker.py  —  Cppcheck addon
=============================================
Detects null-pointer dereferences, unchecked nullable returns,
annotation violations, and null-propagation patterns.

Checkers
--------
NFC-01  unchecked-deref            CWE-476  error
NFC-02  null-deref-in-branch       CWE-476  error
NFC-03  null-passed-to-nonnull     CWE-476  warning
NFC-04  null-returned-unused       CWE-252  warning
NFC-05  double-null-check          style    style
NFC-06  null-arithmetic            CWE-476  error
NFC-07  getenv-unchecked           CWE-476  warning
NFC-08  realloc-null-stomp         CWE-401  error
NFC-09  null-in-format             CWE-476  error
NFC-10  conditional-deref-after-free CWE-416 error

Usage
-----
  cppcheck --addon=NullabilityFlowChecker.py  <file.c>
"""

from __future__ import annotations

import sys
import re
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# Cppcheck addon bootstrap
# ---------------------------------------------------------------------------
import cppcheckdata  # type: ignore

# ---------------------------------------------------------------------------
# Null-state lattice
# ---------------------------------------------------------------------------
class NS(Enum):
    UNKNOWN    = auto()   # no information yet
    MAYBE_NULL = auto()   # came from a nullable source, unchecked
    NULL       = auto()   # known to be null (inside null branch)
    NON_NULL   = auto()   # known to be non-null (past null-guard check)
    FREED      = auto()   # was freed (for NFC-10)


# ---------------------------------------------------------------------------
# Nullable source catalogue
# Sources whose return value MUST be null-checked before use.
# ---------------------------------------------------------------------------
_NULLABLE_ALLOC: Set[str] = {
    "malloc", "calloc", "realloc", "aligned_alloc",
    "valloc", "pvalloc",
}

_NULLABLE_IO: Set[str] = {
    "fopen", "freopen", "tmpfile", "popen",
    "fdopen", "fmemopen", "open_memstream",
}

_NULLABLE_SYSTEM: Set[str] = {
    "getenv", "secure_getenv",
    "dlopen",
    "strdup", "strndup",
    "getcwd",
    "realpath",
    "opendir",
    "tmpnam",    # deprecated but still common
}

_NULLABLE_POSIX: Set[str] = {
    "shmat",
    "mmap",      # returns MAP_FAILED, not NULL, but often misused
}

_ALL_NULLABLE: Set[str] = _NULLABLE_ALLOC | _NULLABLE_IO | _NULLABLE_SYSTEM

_FORMAT_FUNCS: Set[str] = {
    "printf", "fprintf", "sprintf", "snprintf",
    "vprintf", "vfprintf", "vsprintf", "vsnprintf",
    "dprintf",
}

_FREE_FUNCS: Set[str] = {"free", "fclose", "pclose", "closedir", "dlclose"}


# ---------------------------------------------------------------------------
# Reporting helper
# ---------------------------------------------------------------------------
def _report(cfg, tok, msg_id: str, msg: str, severity: str, cwe: int = 0) -> None:
    cwe_str = f" CWE-{cwe}" if cwe else ""
    cppcheckdata.reportError(tok, severity, msg, "NullabilityFlowChecker", msg_id)


# ---------------------------------------------------------------------------
# Utility: token helpers
# ---------------------------------------------------------------------------
def _tok_str(tok) -> str:
    return tok.str if tok else ""


def _next_tok(tok):
    return tok.next if tok else None


def _peek(tok, offset: int = 1):
    t = tok
    for _ in range(offset):
        if t is None:
            return None
        t = t.next
    return t


def _find_closing_brace(open_brace_tok):
    """Walk forward from '{' to its matching '}'.  Returns the token or None."""
    depth = 0
    t = open_brace_tok
    while t:
        if t.str == "{":
            depth += 1
        elif t.str == "}":
            depth -= 1
            if depth == 0:
                return t
        t = t.next
    return None


def _token_index(tok) -> int:
    """Return a monotone ordinal for comparison purposes."""
    # cppcheckdata tokens carry a linenr and column; encode as a big int
    return tok.linenr * 10000 + tok.column


# ---------------------------------------------------------------------------
# Per-function analysis state
# ---------------------------------------------------------------------------
@dataclass
class _FuncState:
    # variable name → current NS
    ns: Dict[str, NS] = field(default_factory=dict)
    # variable name → token where MAYBE_NULL was first assigned (for messages)
    assign_tok: Dict[str, object] = field(default_factory=dict)
    # set of (var, linenr) already reported to avoid duplicate NFC-01
    reported: Set[Tuple[str, int]] = field(default_factory=set)
    # null-check history: var → set of linenr where checked
    checked_lines: Dict[str, Set[int]] = field(default_factory=dict)
    # For NFC-10: vars that were checked non-null then freed
    freed_after_check: Set[str] = field(default_factory=set)

    def mark(self, var: str, state: NS, tok=None) -> None:
        self.ns[var] = state
        if tok and state == NS.MAYBE_NULL:
            self.assign_tok[var] = tok

    def get(self, var: str) -> NS:
        return self.ns.get(var, NS.UNKNOWN)

    def record_check(self, var: str, linenr: int) -> None:
        self.checked_lines.setdefault(var, set()).add(linenr)

    def was_checked_before(self, var: str, linenr: int) -> bool:
        return linenr in self.checked_lines.get(var, set())


# ---------------------------------------------------------------------------
# Scope guard stack for branch tracking
# We record (var, branch_ns, end_token_index) tuples.
# ---------------------------------------------------------------------------
@dataclass
class _ScopeGuard:
    var: str
    branch_ns: NS       # NS.NULL or NS.NON_NULL for this scope
    end_idx: int        # token index of the closing '}'
    prior_ns: NS        # ns BEFORE we entered the branch (to restore)


# ---------------------------------------------------------------------------
# Main checker class
# ---------------------------------------------------------------------------
class NullabilityFlowChecker:

    def __init__(self, cfg) -> None:
        self.cfg = cfg

    # -----------------------------------------------------------------------
    # Public entry point
    # -----------------------------------------------------------------------
    def check(self) -> None:
        for func in self.cfg.functions:
            self._check_function(func)

    # -----------------------------------------------------------------------
    # Per-function walk
    # -----------------------------------------------------------------------
    def _check_function(self, func) -> None:
        start = func.token
        if start is None:
            return

        # Find the opening '{' of the function body
        t = start
        while t and t.str != "{":
            t = t.next
        if t is None:
            return
        body_open = t
        body_close = _find_closing_brace(body_open)
        if body_close is None:
            return

        body_end_idx = _token_index(body_close)

        state = _FuncState()
        scope_stack: List[_ScopeGuard] = []

        t = body_open.next
        while t and _token_index(t) < body_end_idx:
            # ------------------------------------------------------------------
            # 1. Expire scope guards whose end has been reached
            # ------------------------------------------------------------------
            idx = _token_index(t)
            while scope_stack and scope_stack[-1].end_idx <= idx:
                g = scope_stack.pop()
                # Restore prior NS when leaving a branch scope
                if state.get(g.var) == g.branch_ns:
                    state.mark(g.var, g.prior_ns)

            # ------------------------------------------------------------------
            # 2. Assignment detection:  IDENT = NULLABLE_CALL ( ... )
            # ------------------------------------------------------------------
            if (t.str not in ("{", "}", ";") and
                    t.isName and _tok_str(_next_tok(t)) == "="):
                lhs = t.str
                rhs_start = _peek(t, 2)
                if rhs_start and rhs_start.isName:
                    func_name = rhs_start.str
                    next_after = _next_tok(rhs_start)
                    if _tok_str(next_after) == "(":
                        # Special: realloc(p, n) where lhs == p → NFC-08
                        if func_name == "realloc":
                            self._check_realloc_stomp(t, lhs, next_after, state)
                        if func_name in _ALL_NULLABLE:
                            state.mark(lhs, NS.MAYBE_NULL, t)
                        elif func_name == "getenv":
                            state.mark(lhs, NS.MAYBE_NULL, t)
                    # Assignment from NULL literal
                    elif _tok_str(rhs_start) == "NULL" or _tok_str(rhs_start) == "0":
                        prior = state.get(lhs)
                        state.mark(lhs, NS.NULL)
                    # Assignment from non-null (e.g., address-of, literal)
                    elif _tok_str(rhs_start) == "&":
                        state.mark(lhs, NS.NON_NULL)

            # ------------------------------------------------------------------
            # 3. Direct call: IDENT ( where IDENT is nullable but result ignored
            #    i.e., the token before is NOT '='
            # ------------------------------------------------------------------
            if (t.isName and _tok_str(_next_tok(t)) == "(" and
                    t.str in _ALL_NULLABLE):
                prev = t.previous
                if prev and prev.str != "=":
                    _report(self.cfg, t,
                            "NFC-04",
                            f"Return value of '{t.str}()' (nullable) is not checked. "
                            f"Dereferencing it is undefined behaviour. (CWE-252)",
                            "warning", 252)

            # ------------------------------------------------------------------
            # 4. getenv() used without check — always MAYBE_NULL
            # ------------------------------------------------------------------
            if t.isName and t.str == "getenv" and _tok_str(_next_tok(t)) == "(":
                # Find the variable being assigned to (already handled in §2).
                # Here we only warn if getenv result is used inline without storing.
                prev = t.previous
                if prev and prev.str != "=":
                    _report(self.cfg, t,
                            "NFC-07",
                            "Return value of 'getenv()' is nullable and is used "
                            "without being stored and null-checked. (CWE-476)",
                            "warning", 476)

            # ------------------------------------------------------------------
            # 5. Null-check detection:  if ( IDENT == NULL )
            #                           if ( IDENT != NULL )
            #                           if ( ! IDENT )
            #                           if ( IDENT )
            # ------------------------------------------------------------------
            if t.str == "if" and _tok_str(_next_tok(t)) == "(":
                self._handle_if(t, state, scope_stack)

            # ------------------------------------------------------------------
            # 6. Dereference detection
            # ------------------------------------------------------------------
            # *p
            if t.str == "*" and _next_tok(t) and _next_tok(t).isName:
                var = _next_tok(t).str
                # Make sure this really is a dereference, not multiplication.
                # Heuristic: previous token is not a name/number/closing paren
                prev = t.previous
                if prev and prev.str in (";", "{", "}", "(", ",", "=",
                                         "return", "!", "&", "|", "^",
                                         "+", "-", "*", "/",
                                         "if", "while", "for"):
                    self._check_deref(t, var, state)

            # p->member
            if t.str == "->" and t.previous and t.previous.isName:
                var = t.previous.str
                self._check_deref(t.previous, var, state)

            # p[idx]
            if t.str == "[" and t.previous and t.previous.isName:
                var = t.previous.str
                # Exclude cases like func_name[...] which are array decls
                prev2 = t.previous.previous
                if prev2 and prev2.str not in ("char", "int", "long",
                                                "float", "double", "void",
                                                "struct", "enum", "union"):
                    self._check_deref(t.previous, var, state)

            # ------------------------------------------------------------------
            # 7. Pointer arithmetic on null:  p + N  where p is NULL/MAYBE_NULL
            # ------------------------------------------------------------------
            if t.str in ("+", "-") and t.previous and t.previous.isName:
                var = t.previous.str
                ns = state.get(var)
                if ns in (NS.NULL, NS.MAYBE_NULL):
                    key = (var, t.linenr)
                    if key not in state.reported:
                        state.reported.add(key)
                        _report(self.cfg, t,
                                "NFC-06",
                                f"Pointer '{var}' may be null; arithmetic on a "
                                f"null pointer is undefined behaviour. (CWE-476)",
                                "error", 476)

            # ------------------------------------------------------------------
            # 8. free()/fclose() call → mark FREED for NFC-10
            # ------------------------------------------------------------------
            if t.isName and t.str in _FREE_FUNCS:
                n = _next_tok(t)
                if n and n.str == "(":
                    arg = _next_tok(n)
                    if arg and arg.isName:
                        var = arg.str
                        if state.get(var) == NS.NON_NULL:
                            state.freed_after_check.add(var)
                        state.mark(var, NS.FREED)

            # ------------------------------------------------------------------
            # 9. NFC-10: deref of freed pointer that was previously non-null
            # ------------------------------------------------------------------
            if t.str == "*" and _next_tok(t) and _next_tok(t).isName:
                var = _next_tok(t).str
                if state.get(var) == NS.FREED and var in state.freed_after_check:
                    key = (var, t.linenr)
                    if key not in state.reported:
                        state.reported.add(key)
                        _report(self.cfg, t,
                                "NFC-10",
                                f"Pointer '{var}' was freed but is dereferenced "
                                f"afterwards. (CWE-416)",
                                "error", 416)

            # ------------------------------------------------------------------
            # 10. realloc null stomp (also triggered in §2; guarded by flag)
            # ------------------------------------------------------------------
            # Handled inside _check_realloc_stomp() called from §2.

            # ------------------------------------------------------------------
            # 11. printf %s with nullable argument — NFC-09
            # ------------------------------------------------------------------
            if t.isName and t.str in _FORMAT_FUNCS:
                self._check_format_null(t, state)

            # ------------------------------------------------------------------
            # 12. nonnull attribute violations — NFC-03
            # ------------------------------------------------------------------
            # We detect calls where an argument is the NULL literal and the
            # parameter carries __attribute__((nonnull)).
            # cppcheckdata exposes function attributes via func.token attributes;
            # we do a lighter-weight syntactic scan here.
            if t.isName and _tok_str(_next_tok(t)) == "(":
                self._check_nonnull_call(t, state)

            t = t.next

    # -----------------------------------------------------------------------
    # Handle 'if' statement null checks
    # -----------------------------------------------------------------------
    def _handle_if(self, if_tok, state: _FuncState,
                   scope_stack: List[_ScopeGuard]) -> None:
        """
        Inspect the condition of an 'if' and update the null-state for the
        variable inside the branch body.
        """
        # Walk to the '('
        t = if_tok.next  # '('
        if t is None or t.str != "(":
            return

        # Collect condition tokens up to the matching ')'
        depth = 0
        cond_toks = []
        t = t.next
        while t:
            if t.str == "(":
                depth += 1
            elif t.str == ")":
                if depth == 0:
                    break
                depth -= 1
            cond_toks.append(t)
            t = t.next

        if not cond_toks:
            return

        # Pattern matching on condition
        var, branch_null_ns, branch_nonnull_ns = self._parse_null_condition(cond_toks)
        if var is None:
            return

        # Find the opening '{' of the then-branch
        # (skip optional whitespace/newline tokens)
        then_open = t.next if t else None
        while then_open and then_open.str not in ("{", ";"):
            then_open = then_open.next
        if then_open is None or then_open.str != "{":
            return

        then_close = _find_closing_brace(then_open)
        if then_close is None:
            return

        # NFC-05: double null check
        prior_ns = state.get(var)
        if prior_ns == NS.NULL and branch_null_ns == NS.NULL:
            _report(self.cfg, if_tok,
                    "NFC-05",
                    f"Pointer '{var}' was already known to be null; "
                    f"redundant null check. (style)",
                    "style", 0)
        if prior_ns == NS.NON_NULL and branch_null_ns == NS.NULL:
            _report(self.cfg, if_tok,
                    "NFC-05",
                    f"Pointer '{var}' was already known to be non-null; "
                    f"redundant null check. (style)",
                    "style", 0)

        # Record the null check
        state.record_check(var, if_tok.linenr)

        # Push scope guard for the then-branch
        scope_stack.append(_ScopeGuard(
            var=var,
            branch_ns=branch_null_ns,
            end_idx=_token_index(then_close),
            prior_ns=prior_ns,
        ))
        # Set the state for the then-branch
        state.mark(var, branch_null_ns)

        # If there is an else-branch, we ideally would push the inverse NS.
        # We handle this partially: after the then-branch closes, we restore.
        # A full CFG-aware implementation would also push the else scope.
        # For the token-walk heuristic, this is sufficient for the primary checks.

    def _parse_null_condition(
        self, cond_toks
    ) -> Tuple[Optional[str], NS, NS]:
        """
        Parse a null-check condition.
        Returns (var_name, null_branch_ns, non_null_branch_ns).
        Returns (None, ...) if pattern not recognised.
        """
        strs = [tok.str for tok in cond_toks]

        # Pattern: IDENT == NULL  or  IDENT == 0
        if len(strs) == 3 and strs[1] == "==" and strs[2] in ("NULL", "0"):
            return strs[0], NS.NULL, NS.NON_NULL

        # Pattern: NULL == IDENT
        if len(strs) == 3 and strs[0] in ("NULL", "0") and strs[1] == "==":
            return strs[2], NS.NULL, NS.NON_NULL

        # Pattern: IDENT != NULL  or  IDENT != 0
        if len(strs) == 3 and strs[1] == "!=" and strs[2] in ("NULL", "0"):
            return strs[0], NS.NON_NULL, NS.NULL

        # Pattern: NULL != IDENT
        if len(strs) == 3 and strs[0] in ("NULL", "0") and strs[1] == "!=":
            return strs[2], NS.NON_NULL, NS.NULL

        # Pattern: !IDENT   (null in then-branch)
        if len(strs) == 2 and strs[0] == "!" and cond_toks[1].isName:
            return strs[1], NS.NULL, NS.NON_NULL

        # Pattern: IDENT   (non-null in then-branch)
        if len(strs) == 1 and cond_toks[0].isName:
            return strs[0], NS.NON_NULL, NS.NULL

        return None, NS.UNKNOWN, NS.UNKNOWN

    # -----------------------------------------------------------------------
    # Dereference checker
    # -----------------------------------------------------------------------
    def _check_deref(self, tok, var: str, state: _FuncState) -> None:
        ns = state.get(var)
        key = (var, tok.linenr)
        if key in state.reported:
            return
        if ns == NS.MAYBE_NULL:
            state.reported.add(key)
            _report(self.cfg, tok,
                    "NFC-01",
                    f"Pointer '{var}' may be null (returned by a nullable "
                    f"function) and is dereferenced without a null check. "
                    f"(CWE-476)",
                    "error", 476)
        elif ns == NS.NULL:
            state.reported.add(key)
            _report(self.cfg, tok,
                    "NFC-02",
                    f"Pointer '{var}' is null in this branch and is "
                    f"dereferenced. (CWE-476)",
                    "error", 476)

    # -----------------------------------------------------------------------
    # realloc null stomp
    # -----------------------------------------------------------------------
    def _check_realloc_stomp(self, lhs_tok, lhs: str, open_paren, state) -> None:
        """
        Detect:  p = realloc(p, new_size);
        where the original pointer is overwritten before checking for NULL.
        """
        # Parse arguments: realloc(arg1, arg2)
        t = open_paren.next  # first arg
        if t is None:
            return
        first_arg = t.str
        if first_arg == lhs:
            _report(self.cfg, lhs_tok,
                    "NFC-08",
                    f"'realloc' result stored back into '{lhs}': if realloc "
                    f"returns NULL the original pointer is lost (memory leak). "
                    f"Use a temporary. (CWE-401)",
                    "error", 401)

    # -----------------------------------------------------------------------
    # Format string null check
    # -----------------------------------------------------------------------
    def _check_format_null(self, func_tok, state: _FuncState) -> None:
        """
        Detect printf-family calls that pass a MAYBE_NULL/NULL pointer
        as a %s argument.
        """
        # Collect all arguments between '(' and ')'
        t = func_tok.next  # should be '('
        if t is None or t.str != "(":
            return

        # Collect raw argument tokens (comma-separated)
        args: List[List] = []
        current: List = []
        depth = 0
        t = t.next
        while t and not (t.str == ")" and depth == 0):
            if t.str == "(":
                depth += 1
            elif t.str == ")":
                depth -= 1
            elif t.str == "," and depth == 0:
                args.append(current)
                current = []
                t = t.next
                continue
            current.append(t)
            t = t.next
        if current:
            args.append(current)

        # The first arg (or second for fprintf) should be the format string.
        # Determine format arg index.
        fname = func_tok.str
        if fname in ("fprintf", "vfprintf", "dprintf"):
            fmt_idx = 1
        else:
            fmt_idx = 0

        if len(args) <= fmt_idx:
            return

        # Extract format string literal
        fmt_toks = args[fmt_idx]
        fmt_str = ""
        for ft in fmt_toks:
            if ft.str.startswith('"') and ft.str.endswith('"'):
                fmt_str = ft.str[1:-1]
                break

        if not fmt_str:
            return

        # Find all %s positions
        positions = [i for i, c in enumerate(fmt_str)
                     if fmt_str[i] == "%" and i + 1 < len(fmt_str)
                     and fmt_str[i + 1] == "s"]

        for pos_idx, _ in enumerate(positions):
            arg_idx = fmt_idx + 1 + pos_idx
            if arg_idx >= len(args):
                break
            arg_toks = args[arg_idx]
            if not arg_toks:
                continue
            arg_var = arg_toks[0].str
            ns = state.get(arg_var)
            if ns in (NS.NULL, NS.MAYBE_NULL):
                key = (arg_var, func_tok.linenr)
                if key not in state.reported:
                    state.reported.add(key)
                    _report(self.cfg, func_tok,
                            "NFC-09",
                            f"Argument '{arg_var}' passed as '%%s' to "
                            f"'{fname}' may be null. Passing null for %%s "
                            f"is undefined behaviour. (CWE-476)",
                            "error", 476)

    # -----------------------------------------------------------------------
    # nonnull attribute call-site check
    # -----------------------------------------------------------------------
    def _check_nonnull_call(self, func_tok, state: _FuncState) -> None:
        """
        Syntactic scan: if we see  func(NULL, ...)  for any function,
        report NFC-03 as a conservative warning.

        A production implementation would cross-reference the callee's
        declaration for the nonnull attribute; here we report when NULL
        is literally passed to any pointer parameter position.
        """
        t = func_tok.next  # '('
        if t is None or t.str != "(":
            return

        # Skip known false-positive sources
        if func_tok.str in (_ALL_NULLABLE | _FORMAT_FUNCS | _FREE_FUNCS):
            return

        arg_idx = 0
        depth = 0
        t = t.next
        while t and not (t.str == ")" and depth == 0):
            if t.str == "(":
                depth += 1
            elif t.str == ")":
                depth -= 1
            elif t.str == "," and depth == 0:
                arg_idx += 1
                t = t.next
                continue
            if depth == 0 and t.str in ("NULL", "0") and arg_idx >= 0:
                _report(self.cfg, func_tok,
                        "NFC-03",
                        f"NULL passed as argument {arg_idx + 1} to "
                        f"'{func_tok.str}()'; if the parameter is "
                        f"declared __attribute__((nonnull)) this is "
                        f"undefined behaviour. (CWE-476)",
                        "warning", 476)
                break  # one warning per call site
            t = t.next


# ---------------------------------------------------------------------------
# Cppcheck addon entry point
# ---------------------------------------------------------------------------
def get_addon_id() -> str:
    return "NullabilityFlowChecker"


def check_file(dumpfile: str, *args) -> None:
    """Called by Cppcheck for each translation unit."""
    cfg_data = cppcheckdata.parsedump(dumpfile)
    for cfg in cfg_data.configurations:
        checker = NullabilityFlowChecker(cfg)
        checker.check()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: cppcheck --addon=NullabilityFlowChecker.py <file.c>")
        sys.exit(1)
    check_file(sys.argv[1])
