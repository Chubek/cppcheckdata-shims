#!/usr/bin/env python3
"""
ResourceExhaustionGuard.py
══════════════════════════

Cppcheck addon — Resource Exhaustion Pattern Detection
Checker IDs : REG-01 … REG-04
Author      : ResourceExhaustionGuard project
License     : MIT

OUTPUT FORMAT
─────────────
  Single location : [file:line]: (severity) message [errorId]
  Multi-location  : [file:line] -> [file:line]: (severity) message [errorId]

SAFE-VID CONTRACT  (read this before writing a new checker)
────────────────────────────────────────────────────────────
  Never call  int(tok.varId)  directly.
  Always call _safe_vid(tok.varId) or _safe_vid_tok(tok).

  cppcheckdata may surface varId as:
    • A proper integer      → returned as-is (unless 0)
    • The string "0"        → treated as "no variable" → None
    • A hex address string  → unparseable → None
    • None                  → None

  A return value of None means "this token does not identify a
  named variable" and should be skipped by the caller.

ADDING A NEW CHECKER
────────────────────
  1. Subclass _BaseChecker.
  2. Override check(cfg) → List[_Finding].
  3. Use _safe_vid / _safe_vid_tok for every varId access.
  4. Register the subclass in CHECKERS at the bottom.
"""

from __future__ import annotations

import sys
import os
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

# ──────────────────────────────────────────────────────────────────────────────
#  0.  DEPENDENCY IMPORT
# ──────────────────────────────────────────────────────────────────────────────

try:
    import cppcheckdata  # type: ignore[import-untyped]
except ImportError:
    sys.exit("cppcheckdata not found. Run: pip install cppcheckdata")

# ──────────────────────────────────────────────────────────────────────────────
#  1.  SAFE varId HELPERS   ← the single source of truth for varId access
# ──────────────────────────────────────────────────────────────────────────────

def _safe_vid(vid: Any) -> Optional[int]:
    """
    Safely convert a cppcheckdata varId to a plain Python int.

    Parameters
    ----------
    vid : Any
        Raw value obtained from ``token.varId``.  May be an int, a
        decimal string, a hex-address string, or None.

    Returns
    -------
    int
        The variable ID (always ≥ 1) when the token genuinely
        references a named variable.
    None
        When vid is None, zero, or non-numeric (e.g. a memory-address
        string such as '560e31248150' produced by some cppcheckdata
        versions).

    Examples
    --------
    >>> _safe_vid(42)          # plain int           → 42
    >>> _safe_vid("42")        # decimal string      → 42
    >>> _safe_vid(0)           # cppcheck "no-var"   → None
    >>> _safe_vid("0")         # string "0"          → None
    >>> _safe_vid(None)        # absent              → None
    >>> _safe_vid("560e31248150")  # hex address str → None
    """
    if vid is None:
        return None
    try:
        v = int(vid)          # raises ValueError for "560e31248150"
        return v if v != 0 else None
    except (ValueError, TypeError):
        return None


def _safe_vid_tok(tok: Any) -> Optional[int]:
    """
    Convenience wrapper: extract and sanitise varId from a token.

    Equivalent to ``_safe_vid(getattr(tok, 'varId', None))``.
    Always prefer this over reading ``tok.varId`` directly.

    Parameters
    ----------
    tok : Any
        A cppcheckdata Token object (may be None).

    Returns
    -------
    int | None
        See :func:`_safe_vid`.
    """
    if tok is None:
        return None
    return _safe_vid(getattr(tok, "varId", None))


# ──────────────────────────────────────────────────────────────────────────────
#  2.  TEXT REPORTER
# ──────────────────────────────────────────────────────────────────────────────

class _Finding:
    """
    One diagnostic finding.

    Attributes
    ----------
    filename  : primary source file
    line      : primary line number
    severity  : e.g. "warning", "error"
    message   : human-readable description
    error_id  : e.g. "REG-01-UnboundedLoop"
    secondary : optional (filename, line) for multi-location format
    """

    __slots__ = ("filename", "line", "severity", "message",
                 "error_id", "secondary")

    def __init__(
        self,
        filename: str,
        line: int,
        severity: str,
        message: str,
        error_id: str,
        secondary: Optional[Tuple[str, int]] = None,
    ) -> None:
        self.filename  = filename
        self.line      = line
        self.severity  = severity
        self.message   = message
        self.error_id  = error_id
        self.secondary = secondary

    def format(self) -> str:
        """
        Render the finding as a text line.

        Single-location  : ``[file:line]: (sev) msg [id]``
        Multi-location   : ``[file:line] -> [file:line]: (sev) msg [id]``
        """
        primary = f"[{self.filename}:{self.line}]"
        if self.secondary:
            sec_file, sec_line = self.secondary
            loc = f"{primary} -> [{sec_file}:{sec_line}]"
        else:
            loc = primary
        return f"{loc}: ({self.severity}) {self.message} [{self.error_id}]"


class TextReporter:
    """Collects findings and writes them to stdout."""

    def __init__(self) -> None:
        self._findings: List[_Finding] = []

    def add(self, finding: _Finding) -> None:
        self._findings.append(finding)

    def flush(self) -> None:
        for f in self._findings:
            print(f.format())
        self._findings.clear()


# ──────────────────────────────────────────────────────────────────────────────
#  3.  TOKEN / SCOPE UTILITIES
# ──────────────────────────────────────────────────────────────────────────────

def _tok_str(tok: Any) -> str:
    return getattr(tok, "str", "") or ""


def _tok_file(tok: Any) -> str:
    return getattr(tok, "file", "") or ""


def _tok_line(tok: Any) -> int:
    raw = getattr(tok, "linenr", 0)
    try:
        return int(raw) if raw else 0
    except (ValueError, TypeError):
        return 0


def _is_in_loop(tok: Any) -> bool:
    """Walk the scope chain upward; return True if any enclosing scope is a loop."""
    scope = getattr(tok, "scope", None)
    while scope is not None:
        if getattr(scope, "type", "") in {"While", "For", "Do"}:
            return True
        scope = getattr(scope, "nestedIn", None)
    return False


def _called_name(tok: Any) -> Optional[str]:
    """
    If tok is the '(' of a call-expression, return the callee name.
    Returns None when tok is not a call site.
    """
    if _tok_str(tok) != "(":
        return None
    op1 = getattr(tok, "astOperand1", None)
    if op1 is None:
        return None
    # Detect cast: casts have isCast attribute
    if getattr(tok, "isCast", False):
        return None
    return _tok_str(op1) or None


def _collect_call_args(call_paren: Any) -> List[Any]:
    """
    Return a flat list of argument tokens for a call whose '(' is
    ``call_paren``.  We walk astOperand2 (the argument-list subtree).
    """
    args: List[Any] = []
    arg_root = getattr(call_paren, "astOperand2", None)

    def _harvest(node: Any) -> None:
        if node is None:
            return
        if _tok_str(node) == ",":
            _harvest(getattr(node, "astOperand1", None))
            _harvest(getattr(node, "astOperand2", None))
        else:
            args.append(node)

    _harvest(arg_root)
    return args


# ──────────────────────────────────────────────────────────────────────────────
#  4.  TAINT-SOURCE IDENTIFICATION
# ──────────────────────────────────────────────────────────────────────────────

#: Functions whose return value is considered tainted (externally controlled).
_TAINT_RETURN_SOURCES: FrozenSet[str] = frozenset({
    "read", "recv", "recvfrom", "recvmsg",
    "fread", "fgets", "getchar", "fgetc", "getc",
    "scanf", "fscanf", "sscanf",
    "getenv", "secure_getenv",
    "atoi", "atol", "atoll", "strtol", "strtoul", "strtoll",
    "strtod", "strtof",
})

#: Function parameters that are tainted when passed from argv/env.
_TAINT_PARAM_SOURCES: FrozenSet[str] = frozenset({
    "atoi", "atol", "atoll", "strtol", "strtoul",
})


def _collect_tainted_var_ids(cfg: Any) -> Set[int]:
    """
    Scan the token list and return the set of varIds that receive a
    tainted value (direct assignment from a taint-source call, or from
    argv/argc).

    All varId accesses go through :func:`_safe_vid` / :func:`_safe_vid_tok`.
    No raw ``int(tok.varId)`` calls appear here.
    """
    tainted: Set[int] = set()

    for tok in cfg.tokenlist:
        tok_s = _tok_str(tok)

        # ── Pattern A: direct assignment  ptr = taint_source(…)
        #   AST shape:  '='  with astOperand1=lhs, astOperand2='('
        if tok_s == "=":
            lhs = getattr(tok, "astOperand1", None)
            rhs = getattr(tok, "astOperand2", None)
            lhs_vid = _safe_vid_tok(lhs)          # ← safe
            callee  = _called_name(rhs)
            if lhs_vid is not None and callee in _TAINT_RETURN_SOURCES:
                tainted.add(lhs_vid)

        # ── Pattern B: the '(' of a call whose result is assigned
        #   Some dump formats record the assignment differently; handle both.
        if tok_s == "(":
            callee = _called_name(tok)
            if callee not in _TAINT_RETURN_SOURCES:
                continue
            parent = getattr(tok, "astParent", None)
            if parent is None:
                continue
            if _tok_str(parent) == "=":
                lhs    = getattr(parent, "astOperand1", None)
                lhs_vid = _safe_vid_tok(lhs)       # ← safe
                if lhs_vid is not None:
                    tainted.add(lhs_vid)

        # ── Pattern C: argv/argc are always tainted (main parameters)
        #   cppcheck marks main's parameters with isArgument=True or we
        #   detect them by name.
        if tok_s in {"argv", "argc"}:
            vid = _safe_vid_tok(tok)               # ← safe
            if vid is not None:
                tainted.add(vid)

    return tainted


# ──────────────────────────────────────────────────────────────────────────────
#  5.  CHECKER BASE CLASS
# ──────────────────────────────────────────────────────────────────────────────

class _BaseChecker:
    """
    Abstract base for all ResourceExhaustionGuard checkers.

    Subclasses must override :meth:`check` and set the class attributes
    ``CHECKER_ID``, ``CWE``, and ``SEVERITY``.

    varId discipline
    ────────────────
    All subclasses MUST use :func:`_safe_vid` or :func:`_safe_vid_tok`
    instead of accessing ``tok.varId`` directly.  This is enforced by
    convention; a linter rule or CI grep can verify it.
    """

    CHECKER_ID: str = "REG-00-Base"
    CWE:        int = 0
    SEVERITY:   str = "warning"

    def check(self, cfg: Any, tainted: Set[int]) -> List[_Finding]:  # noqa: D102
        raise NotImplementedError

    # ── protected helpers ─────────────────────────────────────────────

    def _finding(
        self,
        tok: Any,
        message: str,
        secondary: Optional[Tuple[str, int]] = None,
    ) -> _Finding:
        return _Finding(
            filename  = _tok_file(tok),
            line      = _tok_line(tok),
            severity  = self.SEVERITY,
            message   = message,
            error_id  = self.CHECKER_ID,
            secondary = secondary,
        )


# ──────────────────────────────────────────────────────────────────────────────
#  6.  REG-01  UnboundedLoopChecker  (CWE-400)
# ──────────────────────────────────────────────────────────────────────────────

class UnboundedLoopChecker(_BaseChecker):
    """
    REG-01 — Tainted loop bounds without upper-bound validation.

    Heuristic
    ─────────
    Find ``for`` / ``while`` / ``do`` scopes whose controlling token
    references a variable that is in the tainted set.  Emit a finding if
    no ValueFlow upper bound can be demonstrated on that variable.

    CWE-400 : Uncontrolled Resource Consumption
    """

    CHECKER_ID = "REG-01-UnboundedLoop"
    CWE        = 400
    SEVERITY   = "warning"

    def check(self, cfg: Any, tainted: Set[int]) -> List[_Finding]:
        findings: List[_Finding] = []
        reported: Set[Tuple[str, int]] = set()   # avoid duplicate sites

        for tok in cfg.tokenlist:
            # Only examine tokens inside a loop scope
            if not _is_in_loop(tok):
                continue

            # We want identifier tokens that reference tainted variables
            if not getattr(tok, "isName", False):
                continue

            vid = _safe_vid_tok(tok)             # ← safe
            if vid is None or vid not in tainted:
                continue

            # Skip if cppcheck ValueFlow gives a bounded range
            if self._has_upper_bound(tok):
                continue

            site = (_tok_file(tok), _tok_line(tok))
            if site in reported:
                continue
            reported.add(site)

            var_name = _tok_str(tok)
            findings.append(self._finding(
                tok,
                f"Loop bound '{var_name}' derives from external input "
                f"without upper-bound validation (CWE-{self.CWE})",
            ))

        return findings

    @staticmethod
    def _has_upper_bound(tok: Any) -> bool:
        """
        Return True when ValueFlow records a known finite upper bound
        for this token (i.e. all values have a non-None intvalue).
        """
        values = list(getattr(tok, "values", None) or [])
        if not values:
            return False
        # If every value has a concrete intvalue, the range is bounded
        return all(
            getattr(v, "intvalue", None) is not None
            for v in values
        )


# ──────────────────────────────────────────────────────────────────────────────
#  7.  REG-02  AllocationInLoopChecker  (CWE-770)
# ──────────────────────────────────────────────────────────────────────────────

_ALLOC_FUNCS: FrozenSet[str] = frozenset({
    "malloc", "calloc", "realloc", "aligned_alloc",
    "strdup", "strndup",
})
_FREE_FUNCS: FrozenSet[str] = frozenset({"free"})


class AllocationInLoopChecker(_BaseChecker):
    """
    REG-02 — Heap allocation inside a loop with tainted bounds or no free().

    Two sub-patterns are detected:

    A. ``malloc``/``calloc``/``realloc`` called inside a loop whose bound
       is in the tainted set.
    B. The allocated pointer variable is never passed to ``free()``
       anywhere in the same configuration.

    CWE-770 : Allocation of Resources Without Limits or Throttling
    """

    CHECKER_ID = "REG-02-AllocInLoop"
    CWE        = 770
    SEVERITY   = "warning"

    def check(self, cfg: Any, tainted: Set[int]) -> List[_Finding]:
        findings: List[_Finding] = []

        # Pass 1 — collect all varIds ever passed to free()
        freed_vids: Set[int] = set()
        for tok in cfg.tokenlist:
            if _tok_str(tok) != "(":
                continue
            callee = _called_name(tok)
            if callee not in _FREE_FUNCS:
                continue
            for arg in _collect_call_args(tok):
                vid = _safe_vid_tok(arg)           # ← safe
                if vid is not None:
                    freed_vids.add(vid)

        # Pass 2 — find allocations inside loops
        for tok in cfg.tokenlist:
            if _tok_str(tok) != "(":
                continue
            callee = _called_name(tok)
            if callee not in _ALLOC_FUNCS:
                continue
            if not _is_in_loop(tok):
                continue

            # Find the varId of the LHS pointer (if any)
            parent = getattr(tok, "astParent", None)
            alloc_vid: Optional[int] = None
            if parent and _tok_str(parent) == "=":
                lhs    = getattr(parent, "astOperand1", None)
                alloc_vid = _safe_vid_tok(lhs)     # ← safe

            # Sub-pattern A: tainted loop bound
            loop_bound_tainted = self._loop_contains_tainted_bound(tok, tainted)

            # Sub-pattern B: allocated var never freed
            never_freed = (alloc_vid is not None and alloc_vid not in freed_vids)

            if loop_bound_tainted:
                findings.append(self._finding(
                    tok,
                    f"'{callee}()' called inside a loop whose bound "
                    f"is externally controlled (CWE-{self.CWE})",
                ))
            elif never_freed and alloc_vid is not None:
                findings.append(self._finding(
                    tok,
                    f"'{callee}()' inside loop — allocated memory "
                    f"(varId={alloc_vid}) is never freed (CWE-{self.CWE})",
                ))

        return findings

    @staticmethod
    def _loop_contains_tainted_bound(tok: Any, tainted: Set[int]) -> bool:
        """
        Walk the enclosing loop scope's condition / init / iter tokens
        looking for a tainted variable reference.
        """
        scope = getattr(tok, "scope", None)
        while scope is not None:
            if getattr(scope, "type", "") in {"While", "For", "Do"}:
                # Scan tokens from scope start to bodyStart
                start    = getattr(scope, "classDef",   None)  # keyword token
                body_st  = getattr(scope, "bodyStart",  None)
                if start and body_st:
                    t = start
                    while t is not None and t is not body_st:
                        vid = _safe_vid_tok(t)              # ← safe
                        if vid is not None and vid in tainted:
                            return True
                        t = getattr(t, "next", None)
            scope = getattr(scope, "nestedIn", None)
        return False


# ──────────────────────────────────────────────────────────────────────────────
#  8.  REG-03  FileDescriptorLeakChecker  (CWE-775)
# ──────────────────────────────────────────────────────────────────────────────

_FD_OPEN_FUNCS:  FrozenSet[str] = frozenset({"open", "openat", "creat"})
_FD_CLOSE_FUNCS: FrozenSet[str] = frozenset({"close"})


class FileDescriptorLeakChecker(_BaseChecker):
    """
    REG-03 — File-descriptor leaks.

    Detects two patterns:

    A. ``open()`` / ``openat()`` called inside a loop with no matching
       ``close()`` *inside the same loop body*.
    B. A variable that receives an ``open()`` return value is never passed
       to ``close()`` anywhere in the function.

    CWE-775 : Missing Release of File Descriptor after Effective Lifetime
    """

    CHECKER_ID = "REG-03-FDLeak"
    CWE        = 775
    SEVERITY   = "warning"

    def check(self, cfg: Any, tainted: Set[int]) -> List[_Finding]:
        findings: List[_Finding] = []

        # Track: varId → open-call token
        fd_opens:  Dict[int, Any] = {}
        fd_closed: Set[int]       = set()

        for tok in cfg.tokenlist:
            if _tok_str(tok) != "(":
                continue
            callee = _called_name(tok)

            # ── record open() calls ──────────────────────────────────
            if callee in _FD_OPEN_FUNCS:
                parent  = getattr(tok, "astParent", None)
                lhs_vid: Optional[int] = None
                if parent and _tok_str(parent) == "=":
                    lhs     = getattr(parent, "astOperand1", None)
                    lhs_vid = _safe_vid_tok(lhs)       # ← safe

                if lhs_vid is not None:
                    fd_opens[lhs_vid] = tok

                    # Sub-pattern A: open inside loop
                    if _is_in_loop(tok):
                        # Check whether close() appears inside the same loop
                        if not self._close_in_same_loop(tok, cfg):
                            findings.append(self._finding(
                                tok,
                                f"'{callee}()' called inside loop but "
                                f"'close()' is outside the loop body — "
                                f"descriptor may leak (CWE-{self.CWE})",
                            ))

            # ── record close() calls ─────────────────────────────────
            if callee in _FD_CLOSE_FUNCS:
                for arg in _collect_call_args(tok):
                    vid = _safe_vid_tok(arg)           # ← safe
                    if vid is not None:
                        fd_closed.add(vid)

        # Sub-pattern B: fd variable never closed
        for vid, open_tok in fd_opens.items():
            if vid not in fd_closed:
                findings.append(self._finding(
                    open_tok,
                    f"File descriptor (varId={vid}) opened but "
                    f"'close()' never called (CWE-{self.CWE})",
                ))

        return findings

    @staticmethod
    def _close_in_same_loop(open_tok: Any, cfg: Any) -> bool:
        """
        Return True if a ``close()`` call appears textually between the
        enclosing loop's bodyStart and bodyEnd tokens.
        """
        # Find enclosing loop scope
        scope = getattr(open_tok, "scope", None)
        loop_scope = None
        while scope is not None:
            if getattr(scope, "type", "") in {"While", "For", "Do"}:
                loop_scope = scope
                break
            scope = getattr(scope, "nestedIn", None)
        if loop_scope is None:
            return False

        body_start = getattr(loop_scope, "bodyStart", None)
        body_end   = getattr(loop_scope, "bodyEnd",   None)
        if body_start is None or body_end is None:
            return False

        # Walk tokens within [bodyStart … bodyEnd]
        inside = False
        t = body_start
        while t is not None:
            if t is body_start:
                inside = True
            if t is body_end:
                break
            if inside and _tok_str(t) == "(":
                callee = _called_name(t)
                if callee in _FD_CLOSE_FUNCS:
                    return True
            t = getattr(t, "next", None)
        return False


# ──────────────────────────────────────────────────────────────────────────────
#  9.  REG-04  UnboundedRecursionChecker  (CWE-674)
# ──────────────────────────────────────────────────────────────────────────────

class UnboundedRecursionChecker(_BaseChecker):
    """
    REG-04 — Tainted recursion depth / mutual recursion cycles.

    Two sub-patterns:

    A. A function calls itself (directly) and the controlling parameter
       or local variable is in the tainted set.
    B. A cycle of ≥ 2 functions (mutual recursion) where at least one
       function in the cycle accepts external input as its first parameter.

    CWE-674 : Uncontrolled Recursion
    """

    CHECKER_ID = "REG-04-UnboundedRecursion"
    CWE        = 674
    SEVERITY   = "warning"

    def check(self, cfg: Any, tainted: Set[int]) -> List[_Finding]:
        findings: List[_Finding] = []

        # Build a simple call graph: function-name → set of called names
        call_graph: Dict[str, Set[str]] = {}
        func_tok:   Dict[str, Any]      = {}   # name → representative token

        for func in cfg.functions:
            fname = getattr(func, "name", None) or ""
            if not fname:
                continue
            call_graph[fname] = set()
            tok_def = getattr(func, "tokenDef", None)
            if tok_def:
                func_tok[fname] = tok_def

            # Walk function body tokens
            body_start = self._func_body_start(func)
            body_end   = self._func_body_end(func)
            if body_start is None:
                continue

            t = getattr(body_start, "next", None)
            while t is not None and t is not body_end:
                if _tok_str(t) == "(":
                    callee_name = _called_name(t)
                    if callee_name:
                        call_graph[fname].add(callee_name)
                t = getattr(t, "next", None)

        # Sub-pattern A: direct self-recursion with tainted param
        for func in cfg.functions:
            fname = getattr(func, "name", None) or ""
            if fname not in call_graph:
                continue
            if fname not in call_graph[fname]:
                continue   # not self-recursive

            if self._func_has_tainted_param(func, tainted):
                tok_ref = func_tok.get(fname)
                if tok_ref:
                    findings.append(self._finding(
                        tok_ref,
                        f"Function '{fname}' recurses directly; its depth "
                        f"parameter derives from external input (CWE-{self.CWE})",
                    ))

        # Sub-pattern B: mutual recursion cycles
        cycles = self._find_cycles(call_graph)
        for cycle in cycles:
            if len(cycle) < 2:
                continue
            # Check if any function in cycle has a tainted param
            for fname in cycle:
                func_obj = self._find_func_obj(cfg, fname)
                if func_obj and self._func_has_tainted_param(func_obj, tainted):
                    # Report at the first function token in the cycle
                    tok_ref = func_tok.get(fname)
                    if tok_ref:
                        cycle_str = " → ".join(sorted(cycle))
                        findings.append(self._finding(
                            tok_ref,
                            f"Mutual recursion cycle [{cycle_str}] involves "
                            f"externally-controlled depth via '{fname}' "
                            f"(CWE-{self.CWE})",
                        ))
                    break   # one finding per cycle

        return findings

    # ── internal helpers ──────────────────────────────────────────────

    @staticmethod
    def _func_body_start(func: Any) -> Optional[Any]:
        tok = getattr(func, "tokenDef", None)
        if tok is None:
            return None
        while tok is not None and _tok_str(tok) != "{":
            tok = getattr(tok, "next", None)
        return tok

    @staticmethod
    def _func_body_end(func: Any) -> Optional[Any]:
        body_start = UnboundedRecursionChecker._func_body_start(func)
        if body_start is None:
            return None
        return getattr(body_start, "link", None)

    @staticmethod
    def _func_has_tainted_param(func: Any, tainted: Set[int]) -> bool:
        """
        Return True if any parameter of *func* has its varId in *tainted*.
        Uses :func:`_safe_vid_tok` on each parameter's nameToken.
        """
        for arg in getattr(func, "argument", {}).values():
            name_tok = getattr(arg, "nameToken", None)
            vid = _safe_vid_tok(name_tok)          # ← safe
            if vid is not None and vid in tainted:
                return True
        return False

    @staticmethod
    def _find_func_obj(cfg: Any, name: str) -> Optional[Any]:
        for func in cfg.functions:
            if getattr(func, "name", "") == name:
                return func
        return None

    @staticmethod
    def _find_cycles(graph: Dict[str, Set[str]]) -> List[Set[str]]:
        """
        Detect strongly-connected components with ≥ 2 nodes using an
        iterative DFS (Kosaraju's algorithm, simplified).

        Returns a list of sets; each set is one cycle.
        """
        # Kosaraju step 1: finish-order DFS on the original graph
        visited:      Set[str]       = set()
        finish_order: List[str]      = []

        def dfs1(node: str) -> None:
            stack = [(node, iter(graph.get(node, set())))]
            visited.add(node)
            while stack:
                n, children = stack[-1]
                try:
                    child = next(children)
                    if child in graph and child not in visited:
                        visited.add(child)
                        stack.append((child, iter(graph.get(child, set()))))
                except StopIteration:
                    finish_order.append(n)
                    stack.pop()

        for node in graph:
            if node not in visited:
                dfs1(node)

        # Build reversed graph
        rev: Dict[str, Set[str]] = {n: set() for n in graph}
        for src, dsts in graph.items():
            for dst in dsts:
                if dst in rev:
                    rev[dst].add(src)

        # Kosaraju step 2: DFS on reversed graph in reverse finish order
        visited2:  Set[str]       = set()
        scc_list: List[Set[str]] = []

        def dfs2(node: str, component: Set[str]) -> None:
            stack = [node]
            visited2.add(node)
            component.add(node)
            while stack:
                n = stack.pop()
                for child in rev.get(n, set()):
                    if child not in visited2:
                        visited2.add(child)
                        component.add(child)
                        stack.append(child)

        for node in reversed(finish_order):
            if node not in visited2:
                component: Set[str] = set()
                dfs2(node, component)
                if len(component) >= 2:
                    scc_list.append(component)

        return scc_list


# ──────────────────────────────────────────────────────────────────────────────
#  10.  CHECKER REGISTRY
# ──────────────────────────────────────────────────────────────────────────────

#: Add new checker classes here.  Order determines report order.
CHECKERS: List[type] = [
    UnboundedLoopChecker,
    AllocationInLoopChecker,
    FileDescriptorLeakChecker,
    UnboundedRecursionChecker,
]


# ──────────────────────────────────────────────────────────────────────────────
#  11.  MAIN ENTRY POINT
# ──────────────────────────────────────────────────────────────────────────────

def _run_on_dump(dump_file: str, reporter: TextReporter) -> None:
    """Load one .dump file and run all checkers against every configuration."""
    data = cppcheckdata.CppcheckData(dump_file)

    for cfg in data.configurations:
        # Build the tainted-variable set once per configuration
        tainted = _collect_tainted_var_ids(cfg)

        # Instantiate and run each checker
        for checker_cls in CHECKERS:
            checker  = checker_cls()
            findings = checker.check(cfg, tainted)
            for f in findings:
                reporter.add(f)


def main() -> None:
    if len(sys.argv) < 2:
        sys.exit(f"Usage: python {os.path.basename(__file__)} <file.c.dump>")

    reporter = TextReporter()

    for dump_file in sys.argv[1:]:
        if not os.path.isfile(dump_file):
            print(f"[WARN] dump file not found: {dump_file}", file=sys.stderr)
            continue
        _run_on_dump(dump_file, reporter)

    reporter.flush()


if __name__ == "__main__":
    main()
