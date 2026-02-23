#!/usr/bin/env python3
"""
DebugLeftoverFinder.py — Cppcheck addon (cppcheckdata-shims compatible)

Checks:
  DLF-01  Sensitive data written to log sinks              (CWE-532)
  DLF-02  Error/exception details exposed to callers       (CWE-209)
  DLF-03  Debug mode left enabled in production build      (CWE-489)
  DLF-04  Raw memory content exposed via format strings    (CWE-200)
  DLF-05  Leftover debug print statements                  (CWE-489)
  DLF-06  Core dumps not suppressed at startup             (CWE-215)
  DLF-07  Sensitive memory not zeroed before deallocation  (CWE-316)

Usage:
  cppcheck --dump source.c
  python3 DebugLeftoverFinder.py source.c.dump [--cli]
"""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass
from typing import Iterator, List, Optional, Set, Tuple

# ── shims-compatible import ───────────────────────────────────────────────────
try:
    import cppcheckdata
except ImportError:
    sys.stderr.write(
        "DebugLeftoverFinder: 'cppcheckdata' not found. "
        "Add the shims directory to PYTHONPATH.\n"
    )
    sys.exit(1)

# ── output mode ──────────────────────────────────────────────────────────────
_CLI_MODE: bool = "--cli" in sys.argv


# ═══════════════════════════════════════════════════════════════════════════════
# Token type helpers  (shims uses tok.type string, NOT tok.isIdentifier)
# ═══════════════════════════════════════════════════════════════════════════════

def _is_name(tok) -> bool:
    """True for identifier / keyword tokens.  Shims: tok.type == 'name'."""
    try:
        return tok.type == "name"
    except AttributeError:
        return False


def _is_number(tok) -> bool:
    """True for numeric literal tokens.  Shims: tok.type == 'number'."""
    try:
        return tok.type == "number"
    except AttributeError:
        return False


def _is_string(tok) -> bool:
    """True for string literal tokens.  Shims: tok.type == 'string'."""
    try:
        return tok.type == "string"
    except AttributeError:
        return False


def _is_op(tok) -> bool:
    """True for operator / punctuation tokens.  Shims: tok.type == 'op'."""
    try:
        return tok.type == "op"
    except AttributeError:
        return False


# ═══════════════════════════════════════════════════════════════════════════════
# Diagnostic data class + emitter
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class Diagnostic:
    filename: str
    line: int
    col: int
    severity: str
    message: str
    error_id: str
    cwe: int


def _emit(diag: Diagnostic) -> None:
    if _CLI_MODE:
        payload = {
            "file":     diag.filename,
            "line":     diag.line,
            "column":   diag.col,
            "severity": diag.severity,
            "message":  diag.message,
            "id":       diag.error_id,
            "cwe":      diag.cwe,
        }
        sys.stdout.write(json.dumps(payload) + "\n")
        sys.stdout.flush()
    else:
        sys.stderr.write(
            f"[{diag.filename}:{diag.line}]: "
            f"({diag.severity}) {diag.message} [{diag.error_id}]\n"
        )


# ═══════════════════════════════════════════════════════════════════════════════
# Shared regex patterns
# ═══════════════════════════════════════════════════════════════════════════════

_SENSITIVE_ID_RE = re.compile(
    r"(?:passw(?:or)?d|passwd|pwd|secret|api[_\-]?key|auth[_\-]?token"
    r"|credential|private[_\-]?key|session[_\-]?(?:id|token)|ssn"
    r"|credit[_\-]?card|cvv|pin|master[_\-]?key)",
    re.IGNORECASE,
)

_LOG_SINK_RE = re.compile(
    r"^(?:printf|fprintf|vprintf|vfprintf|sprintf|vsprintf|snprintf|vsnprintf"
    r"|puts|fputs|fputc|putchar"
    r"|syslog|vsyslog|openlog"
    r"|log(?:_(?:debug|info|warn|error|fatal|msg|printf|write))?f?"
    r"|NSLog|OutputDebugString|DbgPrint"
    r"|SDL_Log|SDL_LogError|SDL_LogWarn"
    r"|g_log|g_warning|g_message|g_debug|g_critical"
    r"|err|errx|warn|warnx"
    r")$",
    re.IGNORECASE,
)

_INTERNAL_LEAK_RE = re.compile(
    r"^(?:strerror|strerror_r|gai_strerror|hstrerror"
    r"|perror|errno|__FILE__|__LINE__|__func__|__FUNCTION__"
    r"|dlerror|curl_easy_strerror|sqlite3_errmsg"
    r"|GetLastError|FormatMessage"
    r")$",
)

_ZERO_FUNC_RE = re.compile(
    r"^(?:memset|explicit_bzero|SecureZeroMemory|RtlSecureZeroMemory"
    r"|bzero|OPENSSL_cleanse|sodium_memzero"
    r")$",
)

_PTR_FMT_RE = re.compile(
    r"%(?:\d+\$)?(?:[+\- #0*]*)(?:\d+|\*)?(?:\.\d+|\.\*)?[xXp]"
)

_DEBUG_FLAG_RE = re.compile(
    r"^(?:DEBUG|debug|_DEBUG|NDEBUG|DEBUG_MODE|debug_mode"
    r"|ENABLE_DEBUG|DEVELOPMENT|DEV_MODE"
    r")$",
)

_INTERNAL_PATH_RE = re.compile(
    r"(?:/proc/|/sys/|/dev/|/etc/shadow|/etc/passwd|/var/log"
    r"|\\\\\.\\\\|%SystemRoot%)",
    re.IGNORECASE,
)

_USER_SINK_RE = re.compile(
    r"^(?:printf|fprintf|sprintf|snprintf|puts|fputs"
    r"|send|sendto|sendmsg|write|fwrite"
    r"|http_response|respond|reply|emit_response"
    r")$",
    re.IGNORECASE,
)

_WRITE_SINK_RE = re.compile(
    r"^(?:write|send|sendto|fwrite|OutputDebugString)$",
)

_DEBUG_PRINT_RE = re.compile(
    r"^(?:DEBUG_PRINT|DPRINTF|debug_printf|dbg_printf|dbg_print"
    r"|debug_log|DBG|TRACE|DTRACE"
    r")$",
)

_BARE_PRINT_RE = re.compile(
    r"^(?:printf|puts|putchar|putchar_unlocked)$",
)

_ENABLE_DEBUG_FUNC_RE = re.compile(
    r"^(?:enable[_\-]?debug|set[_\-]?debug|activate[_\-]?debug"
    r"|debug[_\-]?on|debug[_\-]?enable"
    r")$",
    re.IGNORECASE,
)


# ═══════════════════════════════════════════════════════════════════════════════
# Token navigation helpers
# ═══════════════════════════════════════════════════════════════════════════════

def _tok_line(tok) -> int:
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
        return tok.file or fallback
    except AttributeError:
        return fallback


def _next_paren(tok):
    """Return the '(' token immediately following tok, skipping nothing."""
    t = tok.next if tok else None
    if t and t.str == "(":
        return t
    return None


def _string_literal_value(tok) -> Optional[str]:
    """
    Return the inner text of a string literal token, or None.
    Shims represent string literals with tok.type == 'string' and
    tok.str == '"..."'  (quotes included).
    """
    if tok is None:
        return None
    if not _is_string(tok):
        return None
    s = tok.str
    if s.startswith('"') and s.endswith('"') and len(s) >= 2:
        return s[1:-1]
    return None


def _is_function_scope(scope) -> bool:
    try:
        return scope.type == "Function"
    except AttributeError:
        return False


def _scope_tokens(scope, tokenlist: list):
    """Yield tokens that fall within a scope's brace range."""
    try:
        start_line = int(scope.bodyStart.linenr)
        end_line   = int(scope.bodyEnd.linenr)
    except (AttributeError, TypeError, ValueError):
        return
    for tok in tokenlist:
        try:
            ln = int(tok.linenr)
        except (AttributeError, TypeError, ValueError):
            continue
        if start_line <= ln <= end_line:
            yield tok


def _walk_to_close(open_paren_tok):
    """
    Given the '(' token, yield every token up to (but not including)
    the matching ')'.  Uses tok.link for the match when available,
    otherwise falls back to depth counting.
    """
    if open_paren_tok is None or open_paren_tok.str != "(":
        return

    close = getattr(open_paren_tok, "link", None)

    if close is not None:
        # Fast path: shims populated .link
        t = open_paren_tok.next
        while t is not None and t is not close:
            yield t
            t = t.next
    else:
        # Fallback: manual depth counting
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


# ═══════════════════════════════════════════════════════════════════════════════
# Base checker
# ═══════════════════════════════════════════════════════════════════════════════

class _BaseChecker:
    def __init__(self) -> None:
        self._seen: Set[Tuple[str, int, str]] = set()

    def _report(
        self,
        tok,
        fallback_file: str,
        severity: str,
        message: str,
        error_id: str,
        cwe: int,
    ) -> Optional[Diagnostic]:
        key = (_tok_file(tok, fallback_file), _tok_line(tok), error_id)
        if key in self._seen:
            return None
        self._seen.add(key)
        return Diagnostic(
            filename=_tok_file(tok, fallback_file),
            line=_tok_line(tok),
            col=_tok_col(tok),
            severity=severity,
            message=message,
            error_id=error_id,
            cwe=cwe,
        )

    def check(self, cfg, fallback_file: str) -> Iterator[Diagnostic]:
        raise NotImplementedError


# ═══════════════════════════════════════════════════════════════════════════════
# DLF-01 — Sensitive data in log sinks  (CWE-532)
# ═══════════════════════════════════════════════════════════════════════════════

class SensitiveDataInLogChecker(_BaseChecker):
    """
    Pattern: <log-sink-name> ( ... <sensitive-ident> ... )
    Requires tok.type == 'name' for both the sink and the argument.
    """

    def check(self, cfg, fallback_file: str) -> Iterator[Diagnostic]:
        tl = cfg.tokenlist
        i = 0
        while i < len(tl):
            tok = tl[i]
            if _is_name(tok) and _LOG_SINK_RE.match(tok.str):
                paren = _next_paren(tok)
                if paren is not None:
                    for arg_tok in _walk_to_close(paren):
                        if _is_name(arg_tok) and _SENSITIVE_ID_RE.search(arg_tok.str):
                            diag = self._report(
                                arg_tok,
                                fallback_file,
                                severity="warning",
                                message=(
                                    f"Sensitive identifier '{arg_tok.str}' "
                                    f"passed to log sink '{tok.str}' — may "
                                    f"expose credentials in log files (CWE-532)"
                                ),
                                error_id="DLF-01",
                                cwe=532,
                            )
                            if diag:
                                yield diag
            i += 1


# ═══════════════════════════════════════════════════════════════════════════════
# DLF-02 — Error messages leak internal information  (CWE-209)
# ═══════════════════════════════════════════════════════════════════════════════

class InternalInfoLeakChecker(_BaseChecker):
    """
    (a) strerror/errno/dlerror passed to a user-visible sink.
    (b) String literal with internal path fragment sent to any sink.
    """

    def check(self, cfg, fallback_file: str) -> Iterator[Diagnostic]:
        tl = cfg.tokenlist
        i = 0
        while i < len(tl):
            tok = tl[i]
            if _is_name(tok) and _USER_SINK_RE.match(tok.str):
                paren = _next_paren(tok)
                if paren is not None:
                    for arg_tok in _walk_to_close(paren):
                        # (a) internal-detail identifier
                        if _is_name(arg_tok) and _INTERNAL_LEAK_RE.match(arg_tok.str):
                            diag = self._report(
                                arg_tok,
                                fallback_file,
                                severity="warning",
                                message=(
                                    f"Internal detail '{arg_tok.str}' forwarded "
                                    f"to '{tok.str}' — do not expose system "
                                    f"internals to callers (CWE-209)"
                                ),
                                error_id="DLF-02",
                                cwe=209,
                            )
                            if diag:
                                yield diag
                        # (b) path-leaking string literal
                        lit = _string_literal_value(arg_tok)
                        if lit and _INTERNAL_PATH_RE.search(lit):
                            diag = self._report(
                                arg_tok,
                                fallback_file,
                                severity="warning",
                                message=(
                                    f"String literal with internal path passed "
                                    f"to '{tok.str}' — may expose filesystem "
                                    f"layout to caller (CWE-209)"
                                ),
                                error_id="DLF-02",
                                cwe=209,
                            )
                            if diag:
                                yield diag
            i += 1


# ═══════════════════════════════════════════════════════════════════════════════
# DLF-03 — Debug mode left enabled  (CWE-489)
# ═══════════════════════════════════════════════════════════════════════════════

class DebugModeEnabledChecker(_BaseChecker):
    """
    (a) <debug-flag-name> = <non-zero-number>
    (b) Call to enable_debug() / set_debug() etc.
    (c) Global/static variable with debug name initialised to non-zero.
    """

    def check(self, cfg, fallback_file: str) -> Iterator[Diagnostic]:
        tl = cfg.tokenlist

        # (a) + (b): linear token scan
        i = 0
        while i < len(tl):
            tok = tl[i]

            if _is_name(tok) and _DEBUG_FLAG_RE.match(tok.str):
                nxt = tok.next
                if nxt and nxt.str == "=":
                    val = nxt.next
                    if val and _is_number(val) and val.str not in ("0",):
                        diag = self._report(
                            tok,
                            fallback_file,
                            severity="warning",
                            message=(
                                f"Debug flag '{tok.str}' assigned non-zero "
                                f"value '{val.str}' — must be 0 in production "
                                f"(CWE-489)"
                            ),
                            error_id="DLF-03",
                            cwe=489,
                        )
                        if diag:
                            yield diag

            if _is_name(tok) and _ENABLE_DEBUG_FUNC_RE.match(tok.str):
                paren = _next_paren(tok)
                if paren is not None:
                    diag = self._report(
                        tok,
                        fallback_file,
                        severity="warning",
                        message=(
                            f"Call to '{tok.str}' activates debug mode — "
                            f"remove before production release (CWE-489)"
                        ),
                        error_id="DLF-03",
                        cwe=489,
                    )
                    if diag:
                        yield diag

            i += 1

        # (c) global/static debug-named variables
        for var in cfg.variables:
            try:
                if not (var.isGlobal or var.isStatic):
                    continue
                name_tok = var.nameToken
                if name_tok is None or not _DEBUG_FLAG_RE.match(name_tok.str):
                    continue
                t = name_tok.next
                if t and t.str == "=":
                    v = t.next
                    if v and _is_number(v) and v.str not in ("0",):
                        diag = self._report(
                            name_tok,
                            fallback_file,
                            severity="warning",
                            message=(
                                f"Global/static debug flag '{name_tok.str}' "
                                f"initialised to {v.str} — must be 0 in "
                                f"production (CWE-489)"
                            ),
                            error_id="DLF-03",
                            cwe=489,
                        )
                        if diag:
                            yield diag
            except Exception:
                continue


# ═══════════════════════════════════════════════════════════════════════════════
# DLF-04 — Raw memory content exposed  (CWE-200)
# ═══════════════════════════════════════════════════════════════════════════════

class MemoryExposureChecker(_BaseChecker):
    """
    (a) Format string with %p / %x / %X passed to any print sink.
    (b) write()/send() receiving a sensitive-named buffer argument.
    """

    def check(self, cfg, fallback_file: str) -> Iterator[Diagnostic]:
        tl = cfg.tokenlist
        i = 0
        while i < len(tl):
            tok = tl[i]

            # (a) print-family with pointer/hex format specifier
            if _is_name(tok) and _LOG_SINK_RE.match(tok.str):
                paren = _next_paren(tok)
                if paren is not None:
                    for arg_tok in _walk_to_close(paren):
                        lit = _string_literal_value(arg_tok)
                        if lit and _PTR_FMT_RE.search(lit):
                            diag = self._report(
                                arg_tok,
                                fallback_file,
                                severity="warning",
                                message=(
                                    f"Format string with %%p/%%x/%%X passed to "
                                    f"'{tok.str}' — exposes memory addresses "
                                    f"or raw bytes to output (CWE-200)"
                                ),
                                error_id="DLF-04",
                                cwe=200,
                            )
                            if diag:
                                yield diag

            # (b) write()/send() with a sensitive buffer name
            if _is_name(tok) and _WRITE_SINK_RE.match(tok.str):
                paren = _next_paren(tok)
                if paren is not None:
                    for arg_tok in _walk_to_close(paren):
                        if _is_name(arg_tok) and _SENSITIVE_ID_RE.search(arg_tok.str):
                            diag = self._report(
                                arg_tok,
                                fallback_file,
                                severity="warning",
                                message=(
                                    f"Sensitive buffer '{arg_tok.str}' written "
                                    f"raw via '{tok.str}' — may expose "
                                    f"plaintext memory content (CWE-200)"
                                ),
                                error_id="DLF-04",
                                cwe=200,
                            )
                            if diag:
                                yield diag

            i += 1


# ═══════════════════════════════════════════════════════════════════════════════
# DLF-05 — Leftover debug print statements  (CWE-489)
# ═══════════════════════════════════════════════════════════════════════════════

class DebugPrintChecker(_BaseChecker):
    """
    (a) Known debug-print macros/functions: DEBUG_PRINT, DPRINTF, TRACE …
    (b) fprintf(stderr, …)
    (c) printf/puts whose first argument string starts with a debug marker.
    """

    _DEBUG_MARKER_RE = re.compile(
        r"^\s*(?:\[?debug\]?|dbg:|trace:|\[trace\]|\[dbg\])",
        re.IGNORECASE,
    )

    def check(self, cfg, fallback_file: str) -> Iterator[Diagnostic]:
        tl = cfg.tokenlist
        i = 0
        while i < len(tl):
            tok = tl[i]

            if not _is_name(tok):
                i += 1
                continue

            paren = _next_paren(tok)

            # (a) explicit debug-print identifiers
            if _DEBUG_PRINT_RE.match(tok.str) and paren is not None:
                diag = self._report(
                    tok,
                    fallback_file,
                    severity="style",
                    message=(
                        f"Leftover debug-print call '{tok.str}' — "
                        f"remove before production release (CWE-489)"
                    ),
                    error_id="DLF-05",
                    cwe=489,
                )
                if diag:
                    yield diag

            # (b) fprintf(stderr, …)
            elif tok.str == "fprintf" and paren is not None:
                first_arg = paren.next
                if first_arg and _is_name(first_arg) and first_arg.str == "stderr":
                    diag = self._report(
                        tok,
                        fallback_file,
                        severity="style",
                        message=(
                            "fprintf to stderr detected — verify this is not "
                            "a leftover debug statement (CWE-489)"
                        ),
                        error_id="DLF-05",
                        cwe=489,
                    )
                    if diag:
                        yield diag

            # (c) printf/puts with debug-marker string literal
            elif _BARE_PRINT_RE.match(tok.str) and paren is not None:
                first_arg = paren.next
                lit = _string_literal_value(first_arg) if first_arg else None
                if lit and self._DEBUG_MARKER_RE.match(lit):
                    diag = self._report(
                        tok,
                        fallback_file,
                        severity="style",
                        message=(
                            f"printf with debug marker '{lit[:40]}' — "
                            f"leftover debug output (CWE-489)"
                        ),
                        error_id="DLF-05",
                        cwe=489,
                    )
                    if diag:
                        yield diag

            i += 1


# ═══════════════════════════════════════════════════════════════════════════════
# DLF-06 — Core dumps not suppressed  (CWE-215)
# ═══════════════════════════════════════════════════════════════════════════════

class CoreDumpNotDisabledChecker(_BaseChecker):
    """
    Fires once per file when neither:
      prctl(PR_SET_DUMPABLE, 0)
    nor:
      setrlimit(RLIMIT_CORE, …)
    is found anywhere in the token list.
    """

    def check(self, cfg, fallback_file: str) -> Iterator[Diagnostic]:
        tl = cfg.tokenlist
        found_prctl   = False
        found_rlimit  = False

        for tok in tl:
            if not _is_name(tok):
                continue

            if tok.str == "prctl":
                paren = _next_paren(tok)
                if paren is None:
                    continue
                a1 = paren.next
                if a1 and a1.str == "PR_SET_DUMPABLE":
                    t = a1.next
                    if t and t.str == ",":
                        t = t.next
                    if t and t.str == "0":
                        found_prctl = True

            if tok.str == "setrlimit":
                paren = _next_paren(tok)
                if paren is None:
                    continue
                a1 = paren.next
                if a1 and a1.str == "RLIMIT_CORE":
                    found_rlimit = True

        if not found_prctl and not found_rlimit:
            anchor = tl[0] if tl else None
            if anchor is None:
                return
            diag = self._report(
                anchor,
                fallback_file,
                severity="warning",
                message=(
                    "No prctl(PR_SET_DUMPABLE,0) or setrlimit(RLIMIT_CORE,…) "
                    "found — core dumps may expose sensitive memory to the "
                    "filesystem (CWE-215)"
                ),
                error_id="DLF-06",
                cwe=215,
            )
            if diag:
                yield diag


# ═══════════════════════════════════════════════════════════════════════════════
# DLF-07 — Sensitive memory not zeroed before scope exit  (CWE-316)
# ═══════════════════════════════════════════════════════════════════════════════

class SensitiveMemoryNotClearedChecker(_BaseChecker):
    """
    Per function-scope:
    1. Find local variables (non-global, non-static) whose name matches
       _SENSITIVE_ID_RE.
    2. Scan scope tokens for a zeroing call whose first argument is that
       variable name.
    3. Warn if no zeroing call is found.
    """

    def check(self, cfg, fallback_file: str) -> Iterator[Diagnostic]:
        for scope in cfg.scopes:
            if not _is_function_scope(scope):
                continue

            # Determine scope line range for variable matching
            try:
                scope_start = int(scope.bodyStart.linenr)
            except (AttributeError, TypeError, ValueError):
                continue

            # Gather sensitive local variable name-tokens in this scope
            sensitive_vars: List = []
            for var in cfg.variables:
                try:
                    if var.isGlobal or var.isStatic:
                        continue
                    name_tok = var.nameToken
                    if name_tok is None:
                        continue
                    if not _SENSITIVE_ID_RE.search(name_tok.str):
                        continue
                    # Verify the variable's scope matches this function scope
                    v_scope = getattr(name_tok, "scope", None)
                    if v_scope is None:
                        continue
                    try:
                        if int(v_scope.bodyStart.linenr) != scope_start:
                            continue
                    except (AttributeError, TypeError, ValueError):
                        continue
                    sensitive_vars.append(name_tok)
                except Exception:
                    continue

            if not sensitive_vars:
                continue

            # Collect the first argument of every zeroing call in this scope
            zeroed_names: Set[str] = set()
            for tok in _scope_tokens(scope, cfg.tokenlist):
                if _is_name(tok) and _ZERO_FUNC_RE.match(tok.str):
                    paren = _next_paren(tok)
                    if paren is None:
                        continue
                    a = paren.next
                    if a and _is_name(a):
                        zeroed_names.add(a.str)

            # Warn on uncleared sensitive variables
            for name_tok in sensitive_vars:
                if name_tok.str not in zeroed_names:
                    diag = self._report(
                        name_tok,
                        fallback_file,
                        severity="warning",
                        message=(
                            f"Sensitive local variable '{name_tok.str}' is "
                            f"never cleared with memset/explicit_bzero before "
                            f"going out of scope — plaintext may linger in "
                            f"memory (CWE-316)"
                        ),
                        error_id="DLF-07",
                        cwe=316,
                    )
                    if diag:
                        yield diag


# ═══════════════════════════════════════════════════════════════════════════════
# Entry point
# ═══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    if len(sys.argv) < 2:
        sys.stderr.write(
            "Usage: DebugLeftoverFinder.py <file.c.dump> [--cli]\n"
        )
        sys.exit(1)

    dump_file = sys.argv[1]

    try:
        data = cppcheckdata.parsedump(dump_file)
    except Exception as exc:
        sys.stderr.write(
            f"DebugLeftoverFinder: failed to parse dump '{dump_file}': {exc}\n"
        )
        sys.exit(1)

    checkers: List[_BaseChecker] = [
        SensitiveDataInLogChecker(),        # DLF-01  CWE-532
        InternalInfoLeakChecker(),          # DLF-02  CWE-209
        DebugModeEnabledChecker(),          # DLF-03  CWE-489
        MemoryExposureChecker(),            # DLF-04  CWE-200
        DebugPrintChecker(),                # DLF-05  CWE-489
        CoreDumpNotDisabledChecker(),       # DLF-06  CWE-215
        SensitiveMemoryNotClearedChecker(), # DLF-07  CWE-316
    ]

    for cfg in data.configurations:
        if cfg.tokenlist:
            fallback = cfg.tokenlist[0].file or dump_file
        else:
            fallback = dump_file

        for checker in checkers:
            try:
                for diag in checker.check(cfg, fallback):
                    _emit(diag)
            except Exception as exc:
                sys.stderr.write(
                    f"DebugLeftoverFinder: {checker.__class__.__name__} "
                    f"raised an unexpected error: {exc}\n"
                )


if __name__ == "__main__":
    main()
