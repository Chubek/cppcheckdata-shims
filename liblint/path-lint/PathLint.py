#!/usr/bin/env python3
"""
PathLint.py  —  Cppcheck addon (cppcheckdata-shims compatible)

Checks for filesystem path and file-handling vulnerabilities:

  PLT-01  Path traversal via unsanitized input              (CWE-22)
  PLT-02  External control of filename or path              (CWE-73)
  PLT-03  Unsafe temporary file creation                    (CWE-377)
  PLT-04  Overly permissive file permission bits            (CWE-732)
  PLT-05  Symbolic link attack (TOCTOU on path)             (CWE-59)
  PLT-06  Insecure file-open flags (missing O_CREAT|O_EXCL) (CWE-atomic / CWE-362)
  PLT-07  Path not sanitized before use in file API         (CWE-22)

Usage:
  cppcheck --dump source.c
  python3 PathLint.py source.c.dump [--cli]

All token-type checks use tok.type == "name"|"number"|"string"|"op"
as required by the cppcheckdata-shims library.
"""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass, field
from typing import (
    Dict,
    FrozenSet,
    Iterator,
    List,
    Optional,
    Set,
    Tuple,
)

# ── shims-compatible import ────────────────────────────────────────────────────
try:
    import cppcheckdata
except ImportError:
    sys.stderr.write(
        "PathLint: 'cppcheckdata' not found. "
        "Add the shims directory to PYTHONPATH.\n"
    )
    sys.exit(1)

# ── output mode ───────────────────────────────────────────────────────────────
_CLI_MODE: bool = "--cli" in sys.argv


# ══════════════════════════════════════════════════════════════════════════════
# § 1 — Token type predicates
#       Shims expose tok.type as a plain string; there are no boolean
#       properties like tok.isIdentifier.  Every type check MUST go through
#       these helpers so a future shims change only requires editing one place.
# ══════════════════════════════════════════════════════════════════════════════

def _is_name(tok) -> bool:
    """Identifier or keyword token  (shims: tok.type == 'name')."""
    try:
        return tok.type == "name"
    except AttributeError:
        return False


def _is_number(tok) -> bool:
    """Numeric literal token  (shims: tok.type == 'number')."""
    try:
        return tok.type == "number"
    except AttributeError:
        return False


def _is_string(tok) -> bool:
    """String literal token  (shims: tok.type == 'string')."""
    try:
        return tok.type == "string"
    except AttributeError:
        return False


def _is_op(tok) -> bool:
    """Operator / punctuation token  (shims: tok.type == 'op')."""
    try:
        return tok.type == "op"
    except AttributeError:
        return False


# ══════════════════════════════════════════════════════════════════════════════
# § 2 — Token navigation helpers
# ══════════════════════════════════════════════════════════════════════════════

def _tok_linenr(tok) -> int:
    try:
        return int(tok.linenr)
    except (AttributeError, TypeError, ValueError):
        return 0


def _tok_col(tok) -> int:
    try:
        return int(tok.col)
    except (AttributeError, TypeError, ValueError):
        return 0


def _tok_file(tok, fallback: str) -> str:
    try:
        f = tok.file
        return f if f else fallback
    except AttributeError:
        return fallback


def _next_tok(tok):
    """Safe .next access; returns None when tok is None."""
    return tok.next if tok is not None else None


def _prev_tok(tok):
    """Safe .previous access; returns None when tok is None."""
    return tok.previous if tok is not None else None


def _open_paren_after(tok):
    """
    Return the '(' that directly follows tok (ignoring nothing — the next
    token must literally be '(').  Returns None otherwise.
    """
    nxt = _next_tok(tok)
    if nxt is not None and nxt.str == "(":
        return nxt
    return None


def _walk_args(open_paren_tok) -> Iterator:
    """
    Yield every token inside a balanced parenthesis group, using .link when
    the shims have populated it, otherwise falling back to depth counting.

    Yields tokens at depth 1 only (direct arguments), including commas.
    """
    if open_paren_tok is None or open_paren_tok.str != "(":
        return

    close = getattr(open_paren_tok, "link", None)
    if close is not None:
        t = open_paren_tok.next
        while t is not None and t is not close:
            yield t
            t = t.next
    else:
        depth = 0
        t = open_paren_tok
        while t is not None:
            if t.str == "(":
                depth += 1
            elif t.str == ")":
                depth -= 1
                if depth == 0:
                    return
            if depth > 0 and t is not open_paren_tok:
                yield t
            t = t.next


def _first_arg(open_paren_tok):
    """Return the first non-'(' token inside the argument list."""
    nxt = _next_tok(open_paren_tok)
    if nxt is not None and nxt.str != ")":
        return nxt
    return None


def _nth_arg(open_paren_tok, n: int):
    """
    Return the n-th argument token (0-based), advancing past commas at depth 1.
    Returns None when the argument doesn't exist.
    """
    depth = 0
    idx   = -1
    t     = open_paren_tok
    while t is not None:
        if t.str == "(":
            depth += 1
            t = t.next
            continue
        if t.str == ")":
            depth -= 1
            if depth <= 0:
                break
            t = t.next
            continue
        if depth == 1:
            if t.str == ",":
                t = t.next
                continue
            idx += 1
            if idx == n:
                return t
        t = t.next
    return None


def _string_inner(tok) -> Optional[str]:
    """
    Extract the text between the outer double-quotes of a string-literal token.
    Returns None when the token is not a string literal.
    """
    if tok is None or not _is_string(tok):
        return None
    s = tok.str
    if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
        return s[1:-1]
    return None


def _numeric_value(tok) -> Optional[int]:
    """
    Parse the integer value of a number token, handling hex (0x…) and octal
    (0…) literals.  Returns None on failure.
    """
    if tok is None or not _is_number(tok):
        return None
    s = tok.str.rstrip("uUlL")          # strip integer suffixes
    try:
        return int(s, 0)                # base=0 → auto-detect prefix
    except ValueError:
        return None


def _scope_token_range(scope) -> Tuple[int, int]:
    """Return (first_line, last_line) of a scope's body, or (0, 0)."""
    try:
        return int(scope.bodyStart.linenr), int(scope.bodyEnd.linenr)
    except (AttributeError, TypeError, ValueError):
        return 0, 0


def _tokens_in_scope(scope, tokenlist: list) -> Iterator:
    """Yield tokens whose line falls within scope.bodyStart … scope.bodyEnd."""
    lo, hi = _scope_token_range(scope)
    if lo == 0:
        return
    for tok in tokenlist:
        try:
            ln = int(tok.linenr)
        except (AttributeError, TypeError, ValueError):
            continue
        if lo <= ln <= hi:
            yield tok


# ══════════════════════════════════════════════════════════════════════════════
# § 3 — Shared vocabulary (regular expressions + frozensets)
# ══════════════════════════════════════════════════════════════════════════════

# ── 3.1 Input-tainted identifier names ───────────────────────────────────────
#
# A conservative enumeration of names that commonly originate from external
# (untrusted) sources: network, command-line, environment, HTTP, databases.

_TAINT_SOURCE_RE = re.compile(
    r"^(?:"
    # network / HTTP input
    r"argv|getenv|getparam|get_param|request_uri|query_string"
    r"|http_path|url_path|req_path|post_data|form_field"
    r"|user_input|userinput|client_input|remote_input"
    # generic "input" names
    r"|input|inp|user|user_data|username|filename|filepath|path"
    r"|fname|fpath|dir|dirname|base|basename|uri|resource"
    # database / config reads often echo external data
    r"|row|record|column|config_val|cfg_val"
    r")$",
    re.IGNORECASE,
)

# Functions whose return value is considered tainted
_TAINT_FUNC_RE = re.compile(
    r"^(?:getenv|fgets|gets|read|recv|recvfrom|recvmsg"
    r"|scanf|fscanf|sscanf|getchar|getline|getdelim"
    r"|readline|curl_easy_getinfo"
    r"|sqlite3_column_text|PQgetvalue|mysql_fetch_row"
    r")$",
)

# ── 3.2 Sanitization / validation function names ──────────────────────────────

_SANITIZE_RE = re.compile(
    r"^(?:"
    r"sanitize(?:_path|_filename|_input)?|validate(?:_path|_filename|_input)?"
    r"|clean(?:_path|_filename)?|normalize(?:_path)?"
    r"|realpath|canonicalize_file_name|PathCanonicalize"
    r"|basename|strip_path|remove_dotdot|path_escape"
    r"|check_path|verify_path|safe_path|is_safe_path"
    r")$",
    re.IGNORECASE,
)

# ── 3.3 File-API sinks ────────────────────────────────────────────────────────

# Sinks that accept a filename/path as their first argument
_FILE_OPEN_SINK_RE = re.compile(
    r"^(?:fopen|fopen64|open|open64|openat|creat|creat64"
    r"|CreateFile|CreateFileA|CreateFileW"
    r"|freopen|freopen64"
    r")$",
)

# Sinks that accept a path but do NOT open a file-descriptor
_FILE_PATH_SINK_RE = re.compile(
    r"^(?:"
    r"unlink|unlinkat|remove|rename|renameat"
    r"|mkdir|mkdirat|rmdir|chmod|chown|chdir|chroot"
    r"|stat|lstat|fstatat|access|faccessat"
    r"|execve|execvp|execv|execlp|execl"
    r"|dlopen|LoadLibrary|LoadLibraryA|LoadLibraryW"
    r"|link|symlink|readlink|realpath"
    r")$",
)

# Combined: any function that consumes a path
_ANY_FILE_SINK_RE = re.compile(
    r"^(?:"
    + _FILE_OPEN_SINK_RE.pattern[3:-2]   # strip '^(?:' and ')$'
    + r"|"
    + _FILE_PATH_SINK_RE.pattern[3:-2]
    + r")$"
)

# ── 3.4 Unsafe temp-file functions ───────────────────────────────────────────

_UNSAFE_TMPFILE_RE = re.compile(
    r"^(?:tmpnam|tempnam|mktemp"
    r"|tmpnam_r|tempnam_r"     # some libc extensions
    r")$",
)

# Safe temp-file alternatives (presence means the code IS using safe APIs)
_SAFE_TMPFILE_RE = re.compile(
    r"^(?:mkstemp|mkdtemp|mkostemp|mkostemps|mkstemp64"
    r"|tmpfile|tmpfile64"
    r")$",
)

# ── 3.5 Symbolic-link / TOCTOU patterns ──────────────────────────────────────

# Existence / access checks that are subject to race conditions
_TOCTOU_CHECK_RE = re.compile(
    r"^(?:access|faccessat|stat|lstat|fstatat|access64|stat64"
    r"|PathFileExists|GetFileAttributes"
    r")$",
)

# Open functions that are safe IF used with O_NOFOLLOW / AT_SYMLINK_NOFOLLOW
_FOLLOW_SENSITIVE_OPEN_RE = re.compile(
    r"^(?:open|open64|openat|fopen|fopen64|freopen)$",
)

# ── 3.6 File-permission bit analysis ─────────────────────────────────────────

# Dangerous mode bits (world-writable, world-executable, setuid, setgid)
_DANGEROUS_MODE_BITS = 0o0002 | 0o0001   # o+w, o+x
_SETUID_BIT           = 0o4000
_SETGID_BIT           = 0o2000

# Functions whose second (or specific) argument is a permission mode
_CHMOD_FUNC_RE = re.compile(
    r"^(?:chmod|fchmod|fchmodat|open|open64|openat|creat|creat64|mkdir|mkdirat)$",
)

# Argument position (0-based) of the mode parameter for each function
_MODE_ARG_POS: Dict[str, int] = {
    "chmod":    1,
    "fchmod":   1,
    "fchmodat": 3,
    "open":     2,     # open(path, flags, mode)
    "open64":   2,
    "openat":   3,     # openat(dirfd, path, flags, mode)
    "creat":    1,
    "creat64":  1,
    "mkdir":    1,
    "mkdirat":  2,
}

# ── 3.7 open() flag analysis ─────────────────────────────────────────────────

# Flags of interest for atomic file creation
_O_CREAT   = 0o0100    # POSIX value — cross-reference with platform headers
_O_EXCL    = 0o0200
_O_TMPFILE = 0o20000000  # Linux extension

# Flag names as they appear in source
_O_CREAT_NAMES  : FrozenSet[str] = frozenset({"O_CREAT"})
_O_EXCL_NAMES   : FrozenSet[str] = frozenset({"O_EXCL"})
_O_NOFOLLOW_NAMES: FrozenSet[str] = frozenset({"O_NOFOLLOW"})

# ── 3.8 "path-like" variable name heuristic ──────────────────────────────────

_PATH_VAR_RE = re.compile(
    r"(?:path|file|fname|fpath|dir(?:ectory)?|name|uri|resource|location"
    r"|dest(?:ination)?|target|src|source)",
    re.IGNORECASE,
)

# ── 3.9 Dot-dot / traversal pattern in string literals ───────────────────────

_DOTDOT_RE = re.compile(r"\.\./|\.\.\\")


# ══════════════════════════════════════════════════════════════════════════════
# § 4 — Diagnostic data class and emitter
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class Diagnostic:
    filename: str
    line:     int
    col:      int
    severity: str      # "error" | "warning" | "style" | "performance" | "portability"
    message:  str
    error_id: str      # e.g. "PLT-01"
    cwe:      int


def _emit(diag: Diagnostic) -> None:
    if _CLI_MODE:
        sys.stdout.write(
            json.dumps({
                "file":     diag.filename,
                "line":     diag.line,
                "column":   diag.col,
                "severity": diag.severity,
                "message":  diag.message,
                "id":       diag.error_id,
                "cwe":      diag.cwe,
            }) + "\n"
        )
        sys.stdout.flush()
    else:
        sys.stderr.write(
            f"[{diag.filename}:{diag.line}]: "
            f"({diag.severity}) {diag.message} [{diag.error_id}]\n"
        )


# ══════════════════════════════════════════════════════════════════════════════
# § 5 — Base checker
# ══════════════════════════════════════════════════════════════════════════════

class _BaseChecker:
    """
    Provides:
      • _report()       — deduplicating diagnostic factory
      • check()         — override in subclasses
      • _tainted_names  — set of names considered tainted by the taint pass
    """

    def __init__(self) -> None:
        # (filename, line, error_id) → already emitted
        self._seen: Set[Tuple[str, int, str]] = set()

    # ------------------------------------------------------------------
    def _report(
        self,
        tok,
        fallback: str,
        severity: str,
        message: str,
        error_id: str,
        cwe: int,
    ) -> Optional[Diagnostic]:
        key = (_tok_file(tok, fallback), _tok_linenr(tok), error_id)
        if key in self._seen:
            return None
        self._seen.add(key)
        return Diagnostic(
            filename=_tok_file(tok, fallback),
            line=_tok_linenr(tok),
            col=_tok_col(tok),
            severity=severity,
            message=message,
            error_id=error_id,
            cwe=cwe,
        )

    # ------------------------------------------------------------------
    def check(
        self,
        cfg,
        fallback_file: str,
        tainted_names: Set[str],
    ) -> Iterator[Diagnostic]:
        raise NotImplementedError


# ══════════════════════════════════════════════════════════════════════════════
# § 6 — Lightweight taint propagation pass
#
#  We do a single forward scan over the token list to build a set of
#  "tainted" identifier names.  A name is tainted if:
#    (a) It matches _TAINT_SOURCE_RE directly, OR
#    (b) It was assigned the return value of a taint-source function, OR
#    (c) A sanitizing function was NOT called on it before its first use
#        in a file API.
#
#  This is deliberately coarse — false negatives are preferable to
#  drowning the user in false positives for a style/security linter.
# ══════════════════════════════════════════════════════════════════════════════

def _build_tainted_names(tokenlist: list) -> Set[str]:
    """
    Return the set of identifier names considered tainted in this
    translation unit.

    Strategy:
      1. Seed with names that match _TAINT_SOURCE_RE.
      2. Mark any variable assigned from a call to _TAINT_FUNC_RE as tainted.
      3. Remove names that flow through _SANITIZE_RE before reaching a sink.

    We do NOT do full dataflow — we work purely on names (strings), which
    means aliased pointers can fool us.  That is acceptable for an addon.
    """
    tainted: Set[str] = set()
    sanitized: Set[str] = set()

    i = 0
    n = len(tokenlist)

    while i < n:
        tok = tokenlist[i]

        # ── Seed rule (a): name matches taint-source pattern ──────────────
        if _is_name(tok) and _TAINT_SOURCE_RE.match(tok.str):
            tainted.add(tok.str)

        # ── Seed rule (b): lhs = taint_func(…) ───────────────────────────
        #   Pattern:  <name> = <taint_func> (
        if _is_name(tok):
            nxt = tok.next
            if nxt is not None and nxt.str == "=":
                rhs = nxt.next
                if rhs is not None and _is_name(rhs):
                    if _TAINT_FUNC_RE.match(rhs.str):
                        paren = _open_paren_after(rhs)
                        if paren is not None:
                            tainted.add(tok.str)

        # ── Sanitize rule: sanitize_func( tainted_name ) → clean ─────────
        if _is_name(tok) and _SANITIZE_RE.match(tok.str):
            paren = _open_paren_after(tok)
            if paren is not None:
                for arg in _walk_args(paren):
                    if _is_name(arg) and arg.str in tainted:
                        sanitized.add(arg.str)

        i += 1

    # Names that were sanitized at least once are removed from the taint set.
    # (Overly optimistic, but prevents excessive false-positives.)
    return tainted - sanitized


# ══════════════════════════════════════════════════════════════════════════════
# § 7 — PLT-01 : Path traversal via unsanitized input  (CWE-22)
# ══════════════════════════════════════════════════════════════════════════════

class PathTraversalChecker(_BaseChecker):
    """
    Fires when a tainted identifier is passed as the first (path) argument to
    any file-API sink without an intervening sanitizing call.

    Also fires when a string literal containing '../' or '..\' is passed
    directly to a file sink (hardcoded traversal — rare but seen in test code).
    """

    def check(self, cfg, fallback_file: str, tainted_names: Set[str]) -> Iterator[Diagnostic]:
        tl = cfg.tokenlist
        i  = 0
        while i < len(tl):
            tok = tl[i]

            if not _is_name(tok):
                i += 1
                continue

            if not _ANY_FILE_SINK_RE.match(tok.str):
                i += 1
                continue

            paren = _open_paren_after(tok)
            if paren is None:
                i += 1
                continue

            path_arg = _first_arg(paren)
            if path_arg is None:
                i += 1
                continue

            # Case A: tainted identifier
            if _is_name(path_arg) and path_arg.str in tainted_names:
                diag = self._report(
                    path_arg, fallback_file,
                    severity="error",
                    message=(
                        f"Tainted path '{path_arg.str}' passed to "
                        f"'{tok.str}()' without sanitization — "
                        f"path traversal possible (CWE-22)"
                    ),
                    error_id="PLT-01",
                    cwe=22,
                )
                if diag:
                    yield diag

            # Case B: literal containing '..'
            lit = _string_inner(path_arg)
            if lit and _DOTDOT_RE.search(lit):
                diag = self._report(
                    path_arg, fallback_file,
                    severity="warning",
                    message=(
                        f"String literal with '..' passed to '{tok.str}()' — "
                        f"hardcoded path traversal sequence (CWE-22)"
                    ),
                    error_id="PLT-01",
                    cwe=22,
                )
                if diag:
                    yield diag

            i += 1


# ══════════════════════════════════════════════════════════════════════════════
# § 8 — PLT-02 : External control of filename  (CWE-73)
# ══════════════════════════════════════════════════════════════════════════════

class ExternalFilenameChecker(_BaseChecker):
    """
    A tainted name reaching a file-path sink constitutes external control of
    the filename (CWE-73).

    CWE-73 differs from CWE-22 in scope: CWE-22 is specifically about '../'
    traversal; CWE-73 covers any externally-controlled path, including choosing
    arbitrary absolute paths.  We flag the broader case here.

    To avoid duplicate messages with PLT-01 we report a different error_id
    and message, and we focus on path-only sinks (not open sinks, which
    PLT-01 already covers).
    """

    def check(self, cfg, fallback_file: str, tainted_names: Set[str]) -> Iterator[Diagnostic]:
        tl = cfg.tokenlist
        i  = 0
        while i < len(tl):
            tok = tl[i]

            if _is_name(tok) and _FILE_PATH_SINK_RE.match(tok.str):
                paren = _open_paren_after(tok)
                if paren is not None:
                    path_arg = _first_arg(paren)
                    if (
                        path_arg is not None
                        and _is_name(path_arg)
                        and path_arg.str in tainted_names
                    ):
                        diag = self._report(
                            path_arg, fallback_file,
                            severity="error",
                            message=(
                                f"Externally-controlled path '{path_arg.str}' "
                                f"passed to '{tok.str}()' — attacker can "
                                f"redirect operation to arbitrary file "
                                f"(CWE-73)"
                            ),
                            error_id="PLT-02",
                            cwe=73,
                        )
                        if diag:
                            yield diag

            i += 1


# ══════════════════════════════════════════════════════════════════════════════
# § 9 — PLT-03 : Unsafe temporary file creation  (CWE-377)
# ══════════════════════════════════════════════════════════════════════════════

class UnsafeTmpfileChecker(_BaseChecker):
    """
    Detects calls to tmpnam / tempnam / mktemp — all of which exhibit a
    TOCTOU window between name generation and file creation.

    Also warns when the generated name is subsequently passed to fopen/open
    (the classic pattern).
    """

    def check(self, cfg, fallback_file: str, tainted_names: Set[str]) -> Iterator[Diagnostic]:
        tl = cfg.tokenlist

        # Names returned by unsafe tmp functions (for cross-reference)
        tmp_result_names: Set[str] = set()

        i = 0
        while i < len(tl):
            tok = tl[i]

            if not _is_name(tok):
                i += 1
                continue

            # ── Direct call to unsafe temp-file function ──────────────────
            if _UNSAFE_TMPFILE_RE.match(tok.str):
                paren = _open_paren_after(tok)
                if paren is not None:
                    diag = self._report(
                        tok, fallback_file,
                        severity="warning",
                        message=(
                            f"'{tok.str}()' creates a temporary filename "
                            f"insecurely — TOCTOU race between name "
                            f"generation and file creation; use mkstemp() "
                            f"or tmpfile() instead (CWE-377)"
                        ),
                        error_id="PLT-03",
                        cwe=377,
                    )
                    if diag:
                        yield diag

                    # Track what variable receives the result
                    # Pattern: <name> = tmpnam(…)
                    prev = _prev_tok(tok)
                    if prev is not None and prev.str == "=":
                        lhs = _prev_tok(prev)
                        if lhs is not None and _is_name(lhs):
                            tmp_result_names.add(lhs.str)

            # ── Unsafe name passed to fopen / open ────────────────────────
            if _FILE_OPEN_SINK_RE.match(tok.str):
                paren = _open_paren_after(tok)
                if paren is not None:
                    path_arg = _first_arg(paren)
                    if (
                        path_arg is not None
                        and _is_name(path_arg)
                        and path_arg.str in tmp_result_names
                    ):
                        diag = self._report(
                            path_arg, fallback_file,
                            severity="warning",
                            message=(
                                f"Filename from unsafe temp-file function "
                                f"passed to '{tok.str}()' — classic TOCTOU "
                                f"race condition (CWE-377)"
                            ),
                            error_id="PLT-03",
                            cwe=377,
                        )
                        if diag:
                            yield diag

            i += 1


# ══════════════════════════════════════════════════════════════════════════════
# § 10 — PLT-04 : Overly permissive file permissions  (CWE-732)
# ══════════════════════════════════════════════════════════════════════════════

class FilePermissionChecker(_BaseChecker):
    """
    Flags mode arguments that include world-writable (o+w = 002),
    world-executable (o+x = 001), setuid (4000), or setgid (2000) bits.

    Handles:
      • Octal literals:       open("f", O_RDWR|O_CREAT, 0777)
      • Hex literals:         chmod("f", 0x1FF)
      • Bitwise-OR of known dangerous octal constants in source text

    Strategy:
      The mode argument is frequently expressed as a bit-OR expression.
      We collect all number tokens within the mode argument sub-expression
      and OR them together, then test the combined mask.
    """

    def check(self, cfg, fallback_file: str, tainted_names: Set[str]) -> Iterator[Diagnostic]:
        tl = cfg.tokenlist
        i  = 0
        while i < len(tl):
            tok = tl[i]

            if not (_is_name(tok) and _CHMOD_FUNC_RE.match(tok.str)):
                i += 1
                continue

            paren = _open_paren_after(tok)
            if paren is None:
                i += 1
                continue

            mode_pos = _MODE_ARG_POS.get(tok.str)
            if mode_pos is None:
                i += 1
                continue

            mode_tok = _nth_arg(paren, mode_pos)
            if mode_tok is None:
                i += 1
                continue

            # Collect all number literals in the mode expression
            # (the expression ends at ')' or ',' at depth 0)
            combined_mode = 0
            found_any_literal = False
            t = mode_tok
            depth = 0
            while t is not None:
                if t.str == "(":
                    depth += 1
                elif t.str == ")":
                    if depth == 0:
                        break
                    depth -= 1
                elif t.str == "," and depth == 0:
                    break
                elif _is_number(t):
                    v = _numeric_value(t)
                    if v is not None:
                        combined_mode |= v
                        found_any_literal = True
                t = t.next

            if not found_any_literal:
                i += 1
                continue

            # Test dangerous bit combinations
            if combined_mode & _DANGEROUS_MODE_BITS:
                readable = oct(combined_mode)
                diag = self._report(
                    mode_tok, fallback_file,
                    severity="warning",
                    message=(
                        f"File-permission mode {readable} passed to "
                        f"'{tok.str}()' includes world-writable or "
                        f"world-executable bits — restrict to at most "
                        f"0640 for files, 0750 for directories (CWE-732)"
                    ),
                    error_id="PLT-04",
                    cwe=732,
                )
                if diag:
                    yield diag

            elif combined_mode & (_SETUID_BIT | _SETGID_BIT):
                readable = oct(combined_mode)
                diag = self._report(
                    mode_tok, fallback_file,
                    severity="warning",
                    message=(
                        f"File-permission mode {readable} passed to "
                        f"'{tok.str}()' sets setuid or setgid bit — "
                        f"this is rarely correct and poses escalation "
                        f"risk (CWE-732)"
                    ),
                    error_id="PLT-04",
                    cwe=732,
                )
                if diag:
                    yield diag

            i += 1


# ══════════════════════════════════════════════════════════════════════════════
# § 11 — PLT-05 : Symbolic link attack / TOCTOU  (CWE-59)
# ══════════════════════════════════════════════════════════════════════════════

class SymlinkAttackChecker(_BaseChecker):
    """
    Detects the classic check-then-act (TOCTOU) pattern:

        access(path, F_OK);   // or stat / lstat
        …
        open(path, …);        // separate operation → race window

    Heuristic:
      Within any single function scope, record every path-argument identifier
      that appears in a TOCTOU-check call.  If the same identifier later
      appears in an open/fopen call WITHOUT O_NOFOLLOW in the flags, flag it.

    Also flags:
      • lstat() used for security decisions while the subsequent open()
        lacks O_NOFOLLOW — lstat protects the stat itself but not the open.
      • fopen() — which has no way to pass O_NOFOLLOW — on a
        previously-checked path.
    """

    def check(self, cfg, fallback_file: str, tainted_names: Set[str]) -> Iterator[Diagnostic]:
        for scope in cfg.scopes:
            if scope.type != "Function":
                continue
            yield from self._check_scope(scope, cfg.tokenlist, fallback_file)

    def _check_scope(self, scope, tokenlist, fallback_file: str) -> Iterator[Diagnostic]:
        # Pass 1: collect path names that appear in TOCTOU-check calls
        checked_paths: Dict[str, object] = {}   # name → tok of the check call

        for tok in _tokens_in_scope(scope, tokenlist):
            if _is_name(tok) and _TOCTOU_CHECK_RE.match(tok.str):
                paren = _open_paren_after(tok)
                if paren is None:
                    continue
                path_arg = _first_arg(paren)
                if path_arg is not None and _is_name(path_arg):
                    checked_paths[path_arg.str] = tok

        if not checked_paths:
            return

        # Pass 2: look for open/fopen on the same path names
        for tok in _tokens_in_scope(scope, tokenlist):
            if not (_is_name(tok) and _FOLLOW_SENSITIVE_OPEN_RE.match(tok.str)):
                continue

            paren = _open_paren_after(tok)
            if paren is None:
                continue

            path_arg = _first_arg(paren)
            if path_arg is None or not _is_name(path_arg):
                continue

            if path_arg.str not in checked_paths:
                continue

            # The path was previously checked — look for O_NOFOLLOW in flags
            has_nofollow = self._flags_have_nofollow(paren)

            if not has_nofollow:
                check_tok = checked_paths[path_arg.str]
                diag = self._report(
                    tok, fallback_file,
                    severity="warning",
                    message=(
                        f"Path '{path_arg.str}' is checked by "
                        f"'{check_tok.str}()' then opened by '{tok.str}()' "
                        f"without O_NOFOLLOW — TOCTOU window allows "
                        f"symlink substitution attack (CWE-59)"
                    ),
                    error_id="PLT-05",
                    cwe=59,
                )
                if diag:
                    yield diag

    @staticmethod
    def _flags_have_nofollow(open_paren_tok) -> bool:
        """Return True if any argument token inside the call is O_NOFOLLOW."""
        for arg in _walk_args(open_paren_tok):
            if _is_name(arg) and arg.str in _O_NOFOLLOW_NAMES:
                return True
        return False


# ══════════════════════════════════════════════════════════════════════════════
# § 12 — PLT-06 : Insecure file-open flags  (CWE-362 / atomic creation)
# ══════════════════════════════════════════════════════════════════════════════

class InsecureOpenFlagsChecker(_BaseChecker):
    """
    When open() / openat() is called with O_CREAT but WITHOUT O_EXCL the call
    is not atomic — a race window exists between the existence check and the
    creation.

    Rules:
      R1. open(path, flags, mode) where flags contain O_CREAT but NOT O_EXCL
          → warn (should use O_CREAT | O_EXCL for new-file creation).

      R2. creat() — equivalent to open(O_CREAT|O_TRUNC|O_WRONLY) — does NOT
          include O_EXCL, so it is inherently racy when creating files that
          must not already exist.

      R3. fopen() with mode "w" or "wx" — "x" is a C11 exclusive-create flag;
          plain "w" is not atomic.
    """

    def check(self, cfg, fallback_file: str, tainted_names: Set[str]) -> Iterator[Diagnostic]:
        tl = cfg.tokenlist
        i  = 0
        while i < len(tl):
            tok = tl[i]

            if not _is_name(tok):
                i += 1
                continue

            # ── R1: open() / openat() with O_CREAT but no O_EXCL ─────────
            if tok.str in ("open", "open64", "openat"):
                paren = _open_paren_after(tok)
                if paren is not None:
                    flags_pos = 1 if tok.str != "openat" else 2
                    flag_tok  = _nth_arg(paren, flags_pos)
                    if flag_tok is not None:
                        has_creat, has_excl = self._scan_flags(paren, flags_pos)
                        if has_creat and not has_excl:
                            diag = self._report(
                                tok, fallback_file,
                                severity="warning",
                                message=(
                                    f"'{tok.str}()' uses O_CREAT without "
                                    f"O_EXCL — not atomic; another process "
                                    f"can create the file in the race window; "
                                    f"use O_CREAT|O_EXCL or mkstemp() "
                                    f"(CWE-362)"
                                ),
                                error_id="PLT-06",
                                cwe=362,
                            )
                            if diag:
                                yield diag

            # ── R2: creat() is never exclusive ────────────────────────────
            if tok.str in ("creat", "creat64"):
                paren = _open_paren_after(tok)
                if paren is not None:
                    diag = self._report(
                        tok, fallback_file,
                        severity="style",
                        message=(
                            f"'{tok.str}()' is equivalent to "
                            f"open(O_CREAT|O_WRONLY|O_TRUNC) without O_EXCL "
                            f"— prefer open() with O_CREAT|O_EXCL or "
                            f"mkstemp() for safe exclusive creation (CWE-362)"
                        ),
                        error_id="PLT-06",
                        cwe=362,
                    )
                    if diag:
                        yield diag

            # ── R3: fopen() with non-exclusive write mode ─────────────────
            if tok.str in ("fopen", "fopen64"):
                paren = _open_paren_after(tok)
                if paren is not None:
                    mode_tok = _nth_arg(paren, 1)
                    mode_str = _string_inner(mode_tok)
                    if mode_str is not None and "w" in mode_str and "x" not in mode_str:
                        diag = self._report(
                            tok, fallback_file,
                            severity="style",
                            message=(
                                f"fopen() with mode \"{mode_str}\" is not "
                                f"exclusive — another file at that path can "
                                f"be silently overwritten; use \"wx\" (C11) "
                                f"for exclusive creation (CWE-362)"
                            ),
                            error_id="PLT-06",
                            cwe=362,
                        )
                        if diag:
                            yield diag

            i += 1

    @staticmethod
    def _scan_flags(open_paren_tok, flags_arg_pos: int) -> Tuple[bool, bool]:
        """
        Walk the flags expression (a bit-OR of names/numbers) and return
        (has_O_CREAT, has_O_EXCL).
        """
        has_creat = False
        has_excl  = False

        # Start from the flags argument
        t = _nth_arg(open_paren_tok, flags_arg_pos)
        depth = 0
        while t is not None:
            if t.str == "(":
                depth += 1
            elif t.str == ")":
                if depth == 0:
                    break
                depth -= 1
            elif t.str == "," and depth == 0:
                break
            elif _is_name(t):
                if t.str in _O_CREAT_NAMES:
                    has_creat = True
                if t.str in _O_EXCL_NAMES:
                    has_excl = True
            elif _is_number(t):
                v = _numeric_value(t)
                if v is not None:
                    if v & _O_CREAT:
                        has_creat = True
                    if v & _O_EXCL:
                        has_excl = True
            t = t.next

        return has_creat, has_excl


# ══════════════════════════════════════════════════════════════════════════════
# § 13 — PLT-07 : Path not sanitized before use in file API  (CWE-22 variant)
# ══════════════════════════════════════════════════════════════════════════════

class PathSanitizationChecker(_BaseChecker):
    """
    Looks for path-like variable names (matching _PATH_VAR_RE) that are:
      1. Populated by a string-copy / snprintf / strcat that could embed
         user data, AND
      2. Passed to a file sink WITHOUT an intervening call to realpath(),
         canonicalize_file_name(), or a user-defined sanitizer.

    This is complementary to PLT-01:
      • PLT-01 uses the coarse taint set from _build_tainted_names.
      • PLT-07 uses scope-local analysis to catch paths built via
        string manipulation that don't originate from a named taint source.

    Heuristic signals that a path variable is "constructed" from input:
      • sprintf / snprintf / strcpy / strcat / strlcat writes into it
      • strncpy into it
      • gets / fgets reads into it
    """

    _BUILD_FUNC_RE = re.compile(
        r"^(?:sprintf|snprintf|vsprintf|vsnprintf"
        r"|strcpy|strncpy|strlcpy"
        r"|strcat|strncat|strlcat"
        r"|gets|fgets|read|recv"
        r"|memcpy|memmove"
        r")$",
    )

    def check(self, cfg, fallback_file: str, tainted_names: Set[str]) -> Iterator[Diagnostic]:
        for scope in cfg.scopes:
            if scope.type != "Function":
                continue
            yield from self._check_scope(scope, cfg.tokenlist, fallback_file)

    def _check_scope(self, scope, tokenlist, fallback_file: str) -> Iterator[Diagnostic]:
        # Pass 1: find path-like names that are written to by a build function
        constructed_paths: Set[str] = set()

        for tok in _tokens_in_scope(scope, tokenlist):
            if not (_is_name(tok) and self._BUILD_FUNC_RE.match(tok.str)):
                continue
            paren = _open_paren_after(tok)
            if paren is None:
                continue
            # For sprintf/snprintf/strcpy the destination is the FIRST arg
            dst = _first_arg(paren)
            if dst is None:
                continue
            # Dereference one level of '*' or '&' if present
            if _is_op(dst) and dst.str in ("*", "&"):
                dst = dst.next
            if dst is not None and _is_name(dst) and _PATH_VAR_RE.search(dst.str):
                constructed_paths.add(dst.str)

        if not constructed_paths:
            return

        # Pass 2: find sanitizing calls that clear a name
        sanitized_paths: Set[str] = set()
        for tok in _tokens_in_scope(scope, tokenlist):
            if _is_name(tok) and _SANITIZE_RE.match(tok.str):
                paren = _open_paren_after(tok)
                if paren is None:
                    continue
                for arg in _walk_args(paren):
                    if _is_name(arg) and arg.str in constructed_paths:
                        sanitized_paths.add(arg.str)

        unsafe_paths = constructed_paths - sanitized_paths
        if not unsafe_paths:
            return

        # Pass 3: flag uses of unsafe paths in file-API sinks
        for tok in _tokens_in_scope(scope, tokenlist):
            if not (_is_name(tok) and _ANY_FILE_SINK_RE.match(tok.str)):
                continue
            paren = _open_paren_after(tok)
            if paren is None:
                continue
            path_arg = _first_arg(paren)
            if path_arg is None or not _is_name(path_arg):
                continue
            if path_arg.str not in unsafe_paths:
                continue
            diag = self._report(
                path_arg, fallback_file,
                severity="warning",
                message=(
                    f"Path variable '{path_arg.str}' is constructed via "
                    f"string functions but passed to '{tok.str}()' without "
                    f"sanitization (realpath/canonicalize_file_name) — "
                    f"may allow path traversal (CWE-22)"
                ),
                error_id="PLT-07",
                cwe=22,
            )
            if diag:
                yield diag


# ══════════════════════════════════════════════════════════════════════════════
# § 14 — Entry point
# ══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: PathLint.py <file.c.dump> [--cli]\n")
        sys.exit(1)

    dump_file = sys.argv[1]

    try:
        data = cppcheckdata.parsedump(dump_file)
    except Exception as exc:
        sys.stderr.write(
            f"PathLint: failed to parse dump '{dump_file}': {exc}\n"
        )
        sys.exit(1)

    checkers: List[_BaseChecker] = [
        PathTraversalChecker(),      # PLT-01  CWE-22
        ExternalFilenameChecker(),   # PLT-02  CWE-73
        UnsafeTmpfileChecker(),      # PLT-03  CWE-377
        FilePermissionChecker(),     # PLT-04  CWE-732
        SymlinkAttackChecker(),      # PLT-05  CWE-59
        InsecureOpenFlagsChecker(),  # PLT-06  CWE-362
        PathSanitizationChecker(),   # PLT-07  CWE-22
    ]

    for cfg in data.configurations:
        fallback_file = cfg.tokenlist[0].file if cfg.tokenlist else dump_file

        # Shared taint set — computed once, shared across all checkers
        try:
            tainted = _build_tainted_names(cfg.tokenlist)
        except Exception as exc:
            sys.stderr.write(
                f"PathLint: taint-propagation pass failed: {exc}\n"
            )
            tainted = set()

        for checker in checkers:
            try:
                for diag in checker.check(cfg, fallback_file, tainted):
                    _emit(diag)
            except Exception as exc:
                sys.stderr.write(
                    f"PathLint: {checker.__class__.__name__} "
                    f"raised an unexpected error: {exc}\n"
                )


if __name__ == "__main__":
    main()
