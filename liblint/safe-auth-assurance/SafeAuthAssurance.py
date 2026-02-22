#!/usr/bin/env python3
"""
SafeAuthAssurance.py — Cppcheck addon
======================================
Checks for authentication and credential-safety issues in C/C++ code.

Checks implemented
------------------
  SAA-01  hardcodedCredential        CWE-798  Hard-coded credentials
  SAA-02  plaintextPassword          CWE-256  Password stored / logged in plaintext
  SAA-03  sensitiveDataUnencrypted   CWE-312  Sensitive data stored without encryption
  SAA-04  missingAuthCheck           CWE-306  Critical operation without auth guard
  SAA-05  missingAuthzCheck          CWE-862  Privileged operation without authorisation check
  SAA-06  insecureCredentialStorage  CWE-522  Credentials stored insecurely (global/static)
  SAA-07  privilegeEscalationPath    CWE-269  Privilege escalation via setuid/setgid/capset

Usage
-----
  cppcheck --enable=all --addon=SafeAuthAssurance.py <source files>

Output format
-------------
  --cli mode  : JSON objects on stdout  (consumed by Cppcheck runner)
  otherwise   : [file:line]: (severity) message [errorId]  on stderr
"""

from __future__ import annotations

import json
import re
import sys
from collections import defaultdict
from typing import Dict, List, Optional, Set, Tuple

import cppcheckdata  # type: ignore

# ─────────────────────────────────────────────────────────────────────────────
# Compatibility shim: load cppcheckdata_shims if present, otherwise define
# lightweight stubs so the structural parts still work.
# ─────────────────────────────────────────────────────────────────────────────
try:
    from cppcheckdata_shims import Checker, CheckerContext  # type: ignore
    _HAVE_SHIMS = True
except ImportError:  # pragma: no cover
    _HAVE_SHIMS = False

    class CheckerContext:  # type: ignore
        """Minimal stub when shims are absent."""
        def __init__(self, cfg, filename: str):
            self.cfg      = cfg
            self.filename = filename

    class Checker:  # type: ignore
        """Minimal stub when shims are absent."""
        pass


# ═════════════════════════════════════════════════════════════════════════════
# §1  Diagnostic printer
# ═════════════════════════════════════════════════════════════════════════════

def _print_diagnostic(
    *,
    filename:  str,
    line:      int,
    column:    int,
    severity:  str,
    message:   str,
    error_id:  str,
    cwe:       int,
) -> None:
    """
    Emit one finding.

    • If ``--cli`` is in *sys.argv* the output is a JSON object written to
      *stdout* — the format consumed by the Cppcheck runner.
    • Otherwise a human-readable line is written to *stderr*.
    """
    if "--cli" in sys.argv:
        obj = {
            "file":    filename,
            "linenr":  line,
            "column":  column,
            "severity": severity,
            "message": message,
            "addon":   "SafeAuthAssurance",
            "errorId": error_id,
            "cwe":     cwe,
        }
        sys.stdout.write(json.dumps(obj) + "\n")
        sys.stdout.flush()
    else:
        sys.stderr.write(
            f"[{filename}:{line}]: ({severity}) {message} [addon-{error_id}]\n"
        )
        sys.stderr.flush()


# ═════════════════════════════════════════════════════════════════════════════
# §2  Shared pattern libraries
# ═════════════════════════════════════════════════════════════════════════════

# ── SAA-01 / SAA-06 : credential-related identifier names ────────────────────
_CRED_NAME_RE = re.compile(
    r"""
    (?:
        passw(?:or)?d   |   # password / passwd
        pwd             |
        secret          |
        api[_\-]?key    |
        auth[_\-]?token |
        access[_\-]?token|
        private[_\-]?key|
        credentials?    |
        pin             |
        passphrase      |
        master[_\-]?key |
        hmac[_\-]?key   |
        session[_\-]?(?:key|token|secret)
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)

# ── SAA-01 : string literals that look like real secrets ─────────────────────
# A non-trivial string (≥8 chars, not pure whitespace / format specifiers).
_SECRET_LITERAL_RE = re.compile(
    r'^"(?!%[a-z])(?!\s*")[^"]{8,}"$'
)

# Hard-coded token prefixes (env-var style values are almost always secrets)
_TOKEN_PREFIX_RE = re.compile(
    r'^"(?:Bearer |Basic |Token |sk[-_]|ghp_|xox[baprs]-|AKIA)',
    re.IGNORECASE,
)

# ── SAA-02 : logging / output functions ──────────────────────────────────────
_LOG_FUNCS: Set[str] = {
    "printf", "fprintf", "sprintf", "snprintf",
    "puts", "fputs", "write",
    "syslog", "vsyslog",
    "OutputDebugStringA", "OutputDebugStringW",
    "NSLog", "os_log",
    "log", "LOG", "LOGD", "LOGI", "LOGW", "LOGE",
    "g_print", "g_printerr",
    "qDebug", "qWarning", "qCritical",
}

# ── SAA-02 : storage functions that write to files / db ──────────────────────
_STORE_FUNCS: Set[str] = {
    "fwrite", "fputs", "fputc",
    "sqlite3_exec", "sqlite3_prepare_v2",
    "PQexec", "mysql_query",
    "write", "pwrite",
    "send", "sendto", "sendmsg",
    "strcpy", "strncpy", "memcpy", "memmove",
}

# ── SAA-03 : sensitive field names (not credential-specific) ─────────────────
_SENSITIVE_NAME_RE = re.compile(
    r"""
    (?:
        ssn | social[_\-]?security |
        credit[_\-]?card | card[_\-]?(?:number|num|no) | cvv | ccv |
        bank[_\-]?account | account[_\-]?(?:number|num) |
        dob | date[_\-]?of[_\-]?birth | birthdate |
        health[_\-]?(?:record|data|info) | medical |
        email[_\-]?address |
        phone[_\-]?(?:number|num) |
        tax[_\-]?id | tin |
        license[_\-]?(?:number|num|no) |
        encryption[_\-]?key | symmetric[_\-]?key
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)

# ── SAA-03 : encryption functions that should protect sensitive data ──────────
_ENCRYPT_FUNCS: Set[str] = {
    "EVP_EncryptInit_ex", "EVP_EncryptInit",
    "EVP_SealInit",
    "AES_encrypt", "AES_set_encrypt_key",
    "mbedtls_aes_crypt_cbc", "mbedtls_gcm_crypt_and_tag",
    "BCryptEncrypt",
    "CryptEncrypt",
    "SecretBox", "secretbox",       # libsodium
    "crypto_secretbox_easy",
    "RAND_bytes", "getrandom",
}

# ── SAA-04 : functions considered "critical" ─────────────────────────────────
_CRITICAL_FUNCS: Set[str] = {
    # file ops
    "unlink", "remove", "rename", "rmdir",
    "chmod", "chown", "chdir",
    # memory / process
    "execve", "execl", "execlp", "execv", "execvp",
    "fork", "vfork",
    "system", "popen",
    # network
    "bind", "listen", "accept",
    "connect", "send", "sendto",
    # privileged i/o
    "ioctl", "mmap",
    # database mutations
    "sqlite3_exec", "PQexec", "mysql_query",
    # cryptographic key ops
    "AES_set_encrypt_key", "EVP_PKEY_assign_RSA",
}

# ── SAA-04/05 : patterns that constitute an auth/authz check ─────────────────
_AUTH_CHECK_RE = re.compile(
    r"""
    (?:
        is_auth(?:enticated)?   |
        check_auth(?:entication)?|
        verify_auth             |
        authenticated?          |
        is_logged[_\-]?in       |
        has_(?:role|permission|privilege|access) |
        can_(?:access|read|write|execute|delete)|
        authori[sz]e(?:d)?      |
        check_(?:role|perm(?:ission)?|access|privilege)|
        validate_(?:token|session|credential|user)|
        verify_(?:token|session|user|signature)   |
        session_(?:valid|check|verify)            |
        token_(?:valid|check|verify)              |
        acl_check                                 |
        rbac_check                                |
        user_has_role                             |
        require_auth
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)

# ── SAA-05 : privileged / admin operations ────────────────────────────────────
_PRIV_OPS: Set[str] = {
    "setuid", "setgid", "setreuid", "setregid",
    "seteuid", "setegid",
    "capset", "cap_set_proc",
    "prctl",
    "chroot",
    "mount", "umount", "umount2",
    "kexec_load",
    "perf_event_open",
}

# ── SAA-07 : privilege-escalation call sites ──────────────────────────────────
_ESCALATION_FUNCS: Set[str] = {
    "setuid", "setgid", "setreuid", "setregid",
    "seteuid", "setegid",
    "capset", "cap_set_proc",
}

# Constants that mean uid==0 (root)
_ROOT_CONSTANT_RE = re.compile(r"^(?:0|ROOT_UID|UID_ROOT|PRIV_USER)$")


# ═════════════════════════════════════════════════════════════════════════════
# §3  Token-walking helpers
# ═════════════════════════════════════════════════════════════════════════════

def _tokens_in_cfg(cfg) -> list:
    """Return a flat list of all tokens in a configuration."""
    result = []
    for scope in cfg.scopes:
        tok = scope.bodyStart
        while tok and tok != scope.bodyEnd:
            result.append(tok)
            tok = tok.next
    return result


def _all_tokens(cfg) -> list:
    """Walk cfg.tokenlist (the canonical linear list)."""
    result = []
    tok = cfg.tokenlist
    while tok:
        result.append(tok)
        tok = tok.next
    return result


def _token_str(tok) -> str:
    return tok.str if tok else ""


def _is_string_literal(tok) -> bool:
    s = _token_str(tok)
    return s.startswith('"') and s.endswith('"') and len(s) >= 2


def _is_zero(tok) -> bool:
    """True if tok is the integer literal 0."""
    return _token_str(tok) in {"0", "0L", "0UL", "0LL", "0ULL"}


def _next_n(tok, n: int):
    """Advance *n* tokens, return the result (or None)."""
    cur = tok
    for _ in range(n):
        if cur is None:
            return None
        cur = cur.next
    return cur


def _prev_n(tok, n: int):
    cur = tok
    for _ in range(n):
        if cur is None:
            return None
        cur = cur.previous
    return cur


def _call_args(open_paren_tok) -> List:
    """
    Given the '(' token of a function call, collect the first-level
    argument tokens (one representative token per comma-separated slot).
    """
    args: List = []
    tok = open_paren_tok.next if open_paren_tok else None
    depth = 0
    while tok:
        s = tok.str
        if s == "(":
            depth += 1
            if depth == 1:
                args.append(tok)
        elif s == ")":
            if depth == 0:
                break
            depth -= 1
        elif s == "," and depth == 0:
            pass  # slot boundary — next token starts next arg
        else:
            if depth == 0 and (not args or tok.str == ","):
                args.append(tok)
        tok = tok.next
    return args


def _enclosing_function_name(tok) -> Optional[str]:
    """
    Walk backward through the token list to find the enclosing function
    definition name.  Returns None if we cannot determine it.
    """
    cur = tok
    while cur:
        if cur.function and cur.function.name:
            return cur.function.name
        cur = cur.previous
    return None


def _scope_contains_call(scope, func_names: Set[str]) -> bool:
    """Return True if any token inside *scope* is a call to one of *func_names*."""
    tok = scope.bodyStart
    while tok and tok != scope.bodyEnd:
        if tok.str in func_names:
            nxt = tok.next
            if nxt and nxt.str == "(":
                return True
        tok = tok.next
    return False


def _function_contains_pattern(scope, pattern: re.Pattern) -> bool:
    """Return True if any identifier token inside *scope* matches *pattern*."""
    tok = scope.bodyStart
    while tok and tok != scope.bodyEnd:
        if pattern.search(tok.str):
            return True
        tok = tok.next
    return False


# ═════════════════════════════════════════════════════════════════════════════
# §4  Individual checker classes
# ═════════════════════════════════════════════════════════════════════════════

class _AuthChecker:
    """Abstract base — all SAA checkers inherit from this."""

    #: Override in subclasses
    error_id: str = "safeAuthAssurance"
    cwe:      int = 0
    severity: str = "warning"

    def check(self, cfg, filename: str) -> List[dict]:
        """
        Run this checker against one configuration.
        Returns a list of finding dicts (keys: filename, line, column,
        severity, message, error_id, cwe).
        """
        raise NotImplementedError

    # convenience ────────────────────────────────────────────────────────────
    def _finding(
        self,
        filename: str,
        line: int,
        column: int,
        message: str,
    ) -> dict:
        return dict(
            filename  = filename,
            line      = line,
            column    = column,
            severity  = self.severity,
            message   = message,
            error_id  = self.error_id,
            cwe       = self.cwe,
        )


# ─────────────────────────────────────────────────────────────────────────────
# SAA-01  Hard-coded credentials  (CWE-798)
# ─────────────────────────────────────────────────────────────────────────────

class HardcodedCredentialChecker(_AuthChecker):
    """
    Detect assignments / initialisations where a credential-named variable
    is set to a non-trivial string literal.

    Patterns detected
    -----------------
    1. ``char password[] = "hunter2";``
    2. ``const char *api_key = "sk-...";``
    3. Assignment: ``token = "Bearer abc123...";``
    4. Function call argument whose name matches and value is a literal:
       ``login("admin", "P@ssw0rd1!");``
    """

    error_id = "hardcodedCredential"
    cwe      = 798
    severity = "error"

    def check(self, cfg, filename: str) -> List[dict]:
        findings: List[dict] = []
        tokens = _all_tokens(cfg)

        for i, tok in enumerate(tokens):
            # ── Pattern 1 & 2: variable declaration with string-literal init ─
            if tok.variable and _CRED_NAME_RE.search(tok.str):
                # look ahead for '=' then a string literal
                j = i + 1
                while j < len(tokens) and tokens[j].str in {"=", "[", "]", "0"}:
                    if tokens[j].str == "=" and j + 1 < len(tokens):
                        candidate = tokens[j + 1]
                        if _is_string_literal(candidate):
                            s = candidate.str
                            if (len(s) >= 10             # at least 8 real chars
                                    or _TOKEN_PREFIX_RE.match(s)):
                                findings.append(self._finding(
                                    filename,
                                    tok.linenr,
                                    tok.col,
                                    f"Hard-coded credential in variable "
                                    f"'{tok.str}': {s[:40]}"
                                    f"{'...' if len(s) > 43 else ''}",
                                ))
                        break
                    j += 1

            # ── Pattern 3: assignment expression tok = "..." ──────────────────
            if (tok.str == "="
                    and tok.astOperand1
                    and _CRED_NAME_RE.search(_token_str(tok.astOperand1))
                    and tok.astOperand2
                    and _is_string_literal(tok.astOperand2)):
                s = tok.astOperand2.str
                if len(s) >= 10 or _TOKEN_PREFIX_RE.match(s):
                    findings.append(self._finding(
                        filename,
                        tok.linenr,
                        tok.col,
                        f"Hard-coded credential assigned to "
                        f"'{_token_str(tok.astOperand1)}': "
                        f"{s[:40]}{'...' if len(s) > 43 else ''}",
                    ))

            # ── Pattern 4: token-prefix literals anywhere ─────────────────────
            if _is_string_literal(tok) and _TOKEN_PREFIX_RE.match(tok.str):
                findings.append(self._finding(
                    filename,
                    tok.linenr,
                    tok.col,
                    f"String literal looks like a hard-coded token/key: "
                    f"{tok.str[:40]}{'...' if len(tok.str) > 43 else ''}",
                ))

        return findings


# ─────────────────────────────────────────────────────────────────────────────
# SAA-02  Passwords stored / logged in plaintext  (CWE-256)
# ─────────────────────────────────────────────────────────────────────────────

class PlaintextPasswordChecker(_AuthChecker):
    """
    Detect credential-named variables passed to logging or file-write
    functions without any intermediate encryption.

    Approach
    --------
    For every call to a log / store function, walk its argument list.
    If an argument token's identifier name (or the expression it belongs to)
    matches _CRED_NAME_RE, emit a finding.
    """

    error_id = "plaintextPassword"
    cwe      = 256
    severity = "error"

    def check(self, cfg, filename: str) -> List[dict]:
        findings: List[dict] = []
        tokens = _all_tokens(cfg)

        for i, tok in enumerate(tokens):
            if tok.str not in (_LOG_FUNCS | _STORE_FUNCS):
                continue
            # next token must be '('
            nxt = tok.next
            if not nxt or nxt.str != "(":
                continue

            # scan argument tokens between '(' and matching ')'
            depth = 0
            cur = nxt
            while cur:
                if cur.str == "(":
                    depth += 1
                elif cur.str == ")":
                    depth -= 1
                    if depth == 0:
                        break
                elif depth >= 1 and _CRED_NAME_RE.search(cur.str):
                    findings.append(self._finding(
                        filename,
                        tok.linenr,
                        tok.col,
                        f"Credential '{cur.str}' passed to '{tok.str}' "
                        f"in apparent plaintext",
                    ))
                    break  # one finding per call site
                cur = cur.next

        return findings


# ─────────────────────────────────────────────────────────────────────────────
# SAA-03  Sensitive data stored without encryption  (CWE-312)
# ─────────────────────────────────────────────────────────────────────────────

class SensitiveDataUnencryptedChecker(_AuthChecker):
    """
    Flag scopes where a sensitive-data variable is written to a storage or
    network function but no encryption API appears in the same scope.

    Heuristic
    ---------
    For each function scope:
      • Collect sensitive variable names (_SENSITIVE_NAME_RE).
      • If any such name appears as an argument to a _STORE_FUNCS call …
      • … and *no* _ENCRYPT_FUNCS call appears anywhere in the scope …
      • → flag the first storage call site.
    """

    error_id = "sensitiveDataUnencrypted"
    cwe      = 312
    severity = "warning"

    def check(self, cfg, filename: str) -> List[dict]:
        findings: List[dict] = []

        for scope in cfg.scopes:
            if scope.type != "Function":
                continue

            # Step 1 — does this scope use any encryption call?
            has_encryption = _scope_contains_call(scope, _ENCRYPT_FUNCS)
            if has_encryption:
                continue

            # Step 2 — find storage calls that pass a sensitive variable
            tok = scope.bodyStart
            while tok and tok != scope.bodyEnd:
                if tok.str in _STORE_FUNCS:
                    nxt = tok.next
                    if not nxt or nxt.str != "(":
                        tok = tok.next
                        continue
                    # scan args
                    depth = 0
                    cur = nxt
                    found_sensitive: Optional[str] = None
                    while cur:
                        if cur.str == "(":
                            depth += 1
                        elif cur.str == ")":
                            depth -= 1
                            if depth == 0:
                                break
                        elif depth >= 1 and _SENSITIVE_NAME_RE.search(cur.str):
                            found_sensitive = cur.str
                            break
                        cur = cur.next
                    if found_sensitive:
                        findings.append(self._finding(
                            filename,
                            tok.linenr,
                            tok.col,
                            f"Sensitive field '{found_sensitive}' stored via "
                            f"'{tok.str}' without apparent encryption in scope",
                        ))
                tok = tok.next

        return findings


# ─────────────────────────────────────────────────────────────────────────────
# SAA-04  Missing authentication check before critical operation  (CWE-306)
# ─────────────────────────────────────────────────────────────────────────────

class MissingAuthCheckChecker(_AuthChecker):
    """
    For each function scope that calls a _CRITICAL_FUNCS function, verify
    that the scope (or a caller in the same TU) also contains an auth-check
    pattern.  If not, emit a finding.

    Conservative heuristic — if *any* `if`-guarded auth-check pattern
    appears before the critical call in the same scope, the scope is
    considered protected.
    """

    error_id = "missingAuthCheck"
    cwe      = 306
    severity = "warning"

    def check(self, cfg, filename: str) -> List[dict]:
        findings: List[dict] = []

        for scope in cfg.scopes:
            if scope.type != "Function":
                continue

            # Collect critical-call sites and auth-check presence per function
            critical_sites: List[Tuple[str, int, int]] = []
            auth_check_seen = False

            tok = scope.bodyStart
            while tok and tok != scope.bodyEnd:
                # Track auth-check patterns (in any identifier)
                if _AUTH_CHECK_RE.search(tok.str):
                    auth_check_seen = True

                # Detect critical function calls
                if tok.str in _CRITICAL_FUNCS:
                    nxt = tok.next
                    if nxt and nxt.str == "(":
                        critical_sites.append((tok.str, tok.linenr, tok.col))

                tok = tok.next

            if not auth_check_seen and critical_sites:
                for func_name, line, col in critical_sites:
                    findings.append(self._finding(
                        filename,
                        line,
                        col,
                        f"Critical operation '{func_name}' called without "
                        f"apparent authentication check in enclosing function",
                    ))

        return findings


# ─────────────────────────────────────────────────────────────────────────────
# SAA-05  Missing authorisation check before privileged operation  (CWE-862)
# ─────────────────────────────────────────────────────────────────────────────

class MissingAuthzCheckChecker(_AuthChecker):
    """
    Similar to SAA-04 but focuses on _PRIV_OPS (OS-level privilege calls).
    Flags privileged calls that are not guarded by an authz-pattern.
    """

    error_id = "missingAuthzCheck"
    cwe      = 862
    severity = "warning"

    # Authorisation patterns (stricter than auth-check)
    _AUTHZ_RE = re.compile(
        r"""
        (?:
            has_(?:role|perm(?:ission)?|privilege|access|cap(?:ability)?) |
            check_(?:cap(?:ability)?|perm(?:ission)?|privilege|access)    |
            can_(?:access|do|perform|execute)                              |
            authori[sz]e                                                   |
            acl_(?:check|allow)                                            |
            rbac_(?:check|allow)                                           |
            user_(?:is_(?:root|admin|superuser)|has_(?:role|cap))          |
            cap_(?:get_proc|set_proc|permitted)                            |
            getuid\s*\(\s*\)\s*==\s*0
        )
        """,
        re.IGNORECASE | re.VERBOSE,
    )

    def check(self, cfg, filename: str) -> List[dict]:
        findings: List[dict] = []

        for scope in cfg.scopes:
            if scope.type != "Function":
                continue

            priv_sites: List[Tuple[str, int, int]] = []
            authz_seen = False

            tok = scope.bodyStart
            while tok and tok != scope.bodyEnd:
                if self._AUTHZ_RE.search(tok.str):
                    authz_seen = True
                if _AUTH_CHECK_RE.search(tok.str):
                    authz_seen = True

                if tok.str in _PRIV_OPS:
                    nxt = tok.next
                    if nxt and nxt.str == "(":
                        priv_sites.append((tok.str, tok.linenr, tok.col))

                tok = tok.next

            if not authz_seen and priv_sites:
                for func_name, line, col in priv_sites:
                    findings.append(self._finding(
                        filename,
                        line,
                        col,
                        f"Privileged operation '{func_name}' called without "
                        f"apparent authorisation check in enclosing function",
                    ))

        return findings


# ─────────────────────────────────────────────────────────────────────────────
# SAA-06  Insecure credential storage  (CWE-522)
# ─────────────────────────────────────────────────────────────────────────────

class InsecureCredentialStorageChecker(_AuthChecker):
    """
    Detect credential-named variables declared at global or static scope.

    Two sub-patterns
    ----------------
    a) Global/static variable whose name matches _CRED_NAME_RE.
    b) Credential written into a struct field without a zeroise call nearby
       (``memset``/``explicit_bzero``/``SecureZeroMemory``).
    """

    error_id = "insecureCredentialStorage"
    cwe      = 522
    severity = "warning"

    _ZERO_FUNCS: Set[str] = {
        "memset", "explicit_bzero", "SecureZeroMemory",
        "RtlSecureZeroMemory", "bzero",
    }

    def check(self, cfg, filename: str) -> List[dict]:
        findings: List[dict] = []

        # ── Sub-pattern (a): global / static credential variables ──────────
        for var in cfg.variables:
            if not _CRED_NAME_RE.search(var.name):
                continue
            if var.isGlobal or var.isStatic:
                tok = var.nameToken
                line   = tok.linenr if tok else 0
                column = tok.col    if tok else 0
                scope_label = "global" if var.isGlobal else "static"
                findings.append(self._finding(
                    filename,
                    line,
                    column,
                    f"Credential variable '{var.name}' stored in {scope_label} "
                    f"scope (CWE-522): use secure per-request storage and "
                    f"zeroise after use",
                ))

        # ── Sub-pattern (b): credential variable written without zeroise ───
        # For each function scope, flag credential writes where the scope
        # has no zeroise call at all.
        for scope in cfg.scopes:
            if scope.type != "Function":
                continue

            has_zeroise = _scope_contains_call(scope, self._ZERO_FUNCS)
            if has_zeroise:
                continue

            tok = scope.bodyStart
            while tok and tok != scope.bodyEnd:
                # Assignment: password = ...
                if (tok.str == "="
                        and tok.astOperand1
                        and _CRED_NAME_RE.search(_token_str(tok.astOperand1))):
                    var_name = _token_str(tok.astOperand1)
                    findings.append(self._finding(
                        filename,
                        tok.linenr,
                        tok.col,
                        f"Credential '{var_name}' assigned without subsequent "
                        f"zeroise (memset/explicit_bzero) in the same scope",
                    ))
                tok = tok.next

        return findings


# ─────────────────────────────────────────────────────────────────────────────
# SAA-07  Privilege escalation paths  (CWE-269)
# ─────────────────────────────────────────────────────────────────────────────

class PrivilegeEscalationChecker(_AuthChecker):
    """
    Detect calls to setuid/setgid/capset that:

    a) Are called with a literal 0 (escalate to root unconditionally).
    b) Appear inside a function reachable from user-controlled input
       (heuristic: function name or any argument contains "user" / "input" /
       "request" / "client").
    c) Have no getuid() / geteuid() pre-check before them in the same scope.
    """

    error_id = "privilegeEscalationPath"
    cwe      = 269
    severity = "error"

    _USER_INPUT_RE = re.compile(
        r"(?:user|input|request|client|remote|network|untrusted)",
        re.IGNORECASE,
    )

    _GETUID_RE = re.compile(r"^(?:getuid|geteuid|getgid|getegid)$")

    def check(self, cfg, filename: str) -> List[dict]:
        findings: List[dict] = []

        for scope in cfg.scopes:
            if scope.type != "Function":
                continue

            # Is this scope associated with user/input context?
            func_is_user_facing = (
                scope.className is not None
                and self._USER_INPUT_RE.search(scope.className)
            )

            getuid_seen = False
            tok = scope.bodyStart
            while tok and tok != scope.bodyEnd:
                # Track whether a uid-query happened before the escalation
                if self._GETUID_RE.match(tok.str):
                    nxt = tok.next
                    if nxt and nxt.str == "(":
                        getuid_seen = True

                if tok.str in _ESCALATION_FUNCS:
                    nxt = tok.next
                    if not nxt or nxt.str != "(":
                        tok = tok.next
                        continue

                    call_tok = tok

                    # Peek at first argument
                    arg_tok = nxt.next  # token after '('
                    first_arg_is_zero = arg_tok and _is_zero(arg_tok)

                    if first_arg_is_zero:
                        findings.append(self._finding(
                            filename,
                            call_tok.linenr,
                            call_tok.col,
                            f"'{tok.str}(0)' unconditionally escalates to root "
                            f"(CWE-269): use drop-privilege pattern instead",
                        ))
                    elif func_is_user_facing and not getuid_seen:
                        findings.append(self._finding(
                            filename,
                            call_tok.linenr,
                            call_tok.col,
                            f"'{tok.str}' called in user-facing context without "
                            f"prior getuid() validation (CWE-269)",
                        ))

                tok = tok.next

        return findings


# ═════════════════════════════════════════════════════════════════════════════
# §5  Runner
# ═════════════════════════════════════════════════════════════════════════════

#: All checkers executed in order
_CHECKERS: List[_AuthChecker] = [
    HardcodedCredentialChecker(),       # SAA-01 CWE-798
    PlaintextPasswordChecker(),         # SAA-02 CWE-256
    SensitiveDataUnencryptedChecker(),  # SAA-03 CWE-312
    MissingAuthCheckChecker(),          # SAA-04 CWE-306
    MissingAuthzCheckChecker(),         # SAA-05 CWE-862
    InsecureCredentialStorageChecker(), # SAA-06 CWE-522
    PrivilegeEscalationChecker(),       # SAA-07 CWE-269
]


def _run_all_checkers(cfg, filename: str) -> List[dict]:
    """Run every checker against one configuration and aggregate findings."""
    all_findings: List[dict] = []
    for checker in _CHECKERS:
        try:
            all_findings.extend(checker.check(cfg, filename))
        except Exception as exc:  # pragma: no cover
            # Never crash the Cppcheck process — log to stderr and continue
            sys.stderr.write(
                f"[SafeAuthAssurance] Internal error in "
                f"{checker.__class__.__name__}: {exc}\n"
            )
    return all_findings


def _deduplicate(findings: List[dict]) -> List[dict]:
    """Remove exact duplicates (same file, line, errorId)."""
    seen: Set[Tuple] = set()
    unique: List[dict] = []
    for f in findings:
        key = (f["filename"], f["line"], f["error_id"])
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique

def main():
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: SafeAuthAssurance.py <dumpfile> [--cli]\n")
        sys.exit(1)

    dump_file = sys.argv[1]

    try:
        data = cppcheckdata.parsedump(dump_file)
    except Exception as exc:
        sys.stderr.write(f"SafeAuthAssurance: failed to parse dump: {exc}\n")
        sys.exit(1)

    checkers = [
        HardcodedCredentialChecker(),
        PlaintextPasswordChecker(),
        SensitiveDataUnencryptedChecker(),
        MissingAuthCheckChecker(),
        MissingAuthzCheckChecker(),
        InsecureCredentialStorageChecker(),
        PrivilegeEscalationChecker(),
    ]

    for cfg in data.configurations:
        # ── FIX: tokenlist is a list; index it to get the file attribute ──
        filename = cfg.tokenlist[0].file if cfg.tokenlist else dump_file

        for checker in checkers:
            try:
                checker.collect_evidence(cfg)
                for diag in checker.diagnose():
                    _print_diagnostic(diag)
            except Exception as exc:
                sys.stderr.write(
                    f"SafeAuthAssurance: checker "
                    f"{checker.__class__.__name__} raised: {exc}\n"
                )

if __name__ == "__main__":
    main()

