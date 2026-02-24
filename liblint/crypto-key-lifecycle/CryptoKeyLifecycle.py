#!/usr/bin/env python3
"""
CryptoKeyLifecycle.py  –  v3.0.0
Cppcheck addon: Cryptographic key lifecycle vulnerability detector.

Checkers
--------
CKL-01  Key buffer not zeroed before free / end-of-scope
CKL-02  Weak / broken cipher used  (DES, RC4, Blowfish, …)
CKL-03  Weak key size  (RSA<2048, EC<224, AES<128, …)
CKL-04  Weak RNG used to generate key material
CKL-05  IV / nonce reused across encryption calls
CKL-06  Key material passed to logging function
CKL-07  Key material written to file
CKL-08  ECB mode selected
CKL-09  AEAD authentication tag not checked
CKL-10  Hardcoded key literal

CWE mapping
-----------
CKL-01 → CWE-316   Cleartext Storage of Sensitive Information in Memory
CKL-02 → CWE-327   Use of a Broken or Risky Cryptographic Algorithm
CKL-03 → CWE-326   Inadequate Encryption Strength
CKL-04 → CWE-338   Use of Cryptographically Weak PRNG
CKL-05 → CWE-329   Not Using an Unpredictable IV with CBC Mode
CKL-06 → CWE-312   Cleartext Storage of Sensitive Information
CKL-07 → CWE-312   Cleartext Storage of Sensitive Information
CKL-08 → CWE-327   Use of a Broken or Risky Cryptographic Algorithm
CKL-09 → CWE-354   Improper Validation of Integrity Check Value
CKL-10 → CWE-321   Use of Hard-coded Cryptographic Key

Usage
-----
    cppcheck --addon=CryptoKeyLifecycle.py  <source-files>

Requirements
------------
    cppcheck >= 2.7  with Python addon support
    Python   >= 3.8
"""

import re
import sys
from collections import defaultdict

import cppcheckdata

# ---------------------------------------------------------------------------
# Addon identity  (used as the 4th argument to reportError)
# ---------------------------------------------------------------------------
ADDON_NAME = "CryptoKeyLifecycle"

# ---------------------------------------------------------------------------
# Severity constants  (valid Cppcheck severity strings)
# ---------------------------------------------------------------------------
SEV_ERROR   = "error"
SEV_WARNING = "warning"
SEV_STYLE   = "style"

# ---------------------------------------------------------------------------
# Heuristic databases
# ---------------------------------------------------------------------------

# Functions whose return value / first pointer argument is "key material"
_KEY_SOURCES: set[str] = {
    # OpenSSL
    "EVP_BytesToKey", "RAND_bytes", "RAND_priv_bytes",
    "RSA_generate_key", "RSA_generate_key_ex",
    "EC_KEY_generate_key", "DH_generate_key",
    "EVP_PKEY_keygen",
    # libsodium
    "crypto_secretbox_keygen", "crypto_aead_chacha20poly1305_keygen",
    "randombytes_buf",
    # generic / PKCS#11-style
    "GenerateKey", "generate_key", "derive_key", "key_derive",
    "KeyDerive", "pbkdf2", "PBKDF2", "hkdf_expand",
}

# Functions that zero memory (acceptable key-clear operations)
_ZERO_FUNCTIONS: set[str] = {
    "memset", "explicit_bzero", "SecureZeroMemory",
    "OPENSSL_cleanse", "sodium_memzero", "explicit_memset",
    "bzero", "RtlSecureZeroMemory",
}

# Free-like functions that release key buffers
_FREE_FUNCTIONS: set[str] = {
    "free", "EVP_PKEY_free", "RSA_free", "EC_KEY_free",
    "EVP_CIPHER_CTX_free", "OPENSSL_free", "sodium_free",
}

# Broken / weak cipher names (case-insensitive fragment match)
_WEAK_CIPHERS: list[tuple[str, str]] = [
    ("DES",        "DES (56-bit) is cryptographically broken"),
    ("3DES",       "Triple-DES has 112-bit effective security and known attacks"),
    ("TDES",       "Triple-DES has 112-bit effective security and known attacks"),
    ("RC2",        "RC2 is considered weak"),
    ("RC4",        "RC4 is cryptographically broken"),
    ("RC5",        "RC5 is considered weak"),
    ("BLOWFISH",   "Blowfish has a 64-bit block size enabling birthday attacks"),
    ("IDEA",       "IDEA is patented and considered legacy"),
    ("SKIPJACK",   "Skipjack is a legacy cipher"),
    ("SEED",       "SEED is a legacy cipher"),
    ("ARIA",       "ARIA is not widely vetted; prefer AES"),
    ("MD5",        "MD5 is broken for integrity / key derivation"),
    ("SHA1",       "SHA-1 is deprecated; use SHA-256 or stronger"),
]

# Weak RNG function names
_WEAK_RNGS: set[str] = {
    "rand", "random", "srand", "srandom",
    "drand48", "lrand48", "mrand48",
    "rand_r", "mt_rand",
}

# Logging / output functions
_LOG_FUNCTIONS: set[str] = {
    "printf", "fprintf", "sprintf", "snprintf",
    "vprintf", "vfprintf", "vsprintf", "vsnprintf",
    "puts", "fputs", "syslog", "vsyslog",
    "log", "LOG", "LOGI", "LOGD", "LOGW", "LOGE",
    "NSLog", "DbgPrint", "OutputDebugString",
    "perror", "err", "warn",
}

# File-write functions
_FILE_WRITE_FUNCTIONS: set[str] = {
    "fwrite", "fputs", "fprintf", "write",
    "WriteFile", "fputc", "putc",
}

# AEAD encryption functions that produce a tag
_AEAD_ENCRYPT: set[str] = {
    "EVP_EncryptFinal_ex",
    "EVP_AEAD_CTX_seal",
    "crypto_aead_chacha20poly1305_encrypt",
    "crypto_aead_xchacha20poly1305_ietf_encrypt",
    "crypto_secretbox_easy",
    "CCCrypt",          # when used with kCCModeGCM
    "gcm_encrypt",
}

# AEAD decryption / verification functions
_AEAD_DECRYPT: set[str] = {
    "EVP_DecryptFinal_ex",
    "EVP_AEAD_CTX_open",
    "crypto_aead_chacha20poly1305_decrypt",
    "crypto_aead_xchacha20poly1305_ietf_decrypt",
    "crypto_secretbox_open_easy",
    "gcm_decrypt",
}

# Regex: key-like variable name heuristic
_KEY_NAME_RE = re.compile(
    r"(key|secret|password|passwd|pwd|aeskey|hmackey|privkey|private_key"
    r"|session_key|master_key|enc_key|signing_key)",
    re.IGNORECASE,
)

# Regex: ECB mode strings
_ECB_RE = re.compile(r"\bECB\b", re.IGNORECASE)

# Regex: IV / nonce variable names
_IV_NAME_RE = re.compile(r"\b(iv|nonce|initialization_vector)\b", re.IGNORECASE)

# Regex: hardcoded hex key literal  (≥8 hex chars)
_HEX_KEY_RE = re.compile(r'"[0-9A-Fa-f]{8,}"')

# Regex: hardcoded byte-array initialiser for key buffers
_BYTE_INIT_RE = re.compile(r"\{(\s*(0x[0-9A-Fa-f]{2}[\s,]+){7,})\}")


# ---------------------------------------------------------------------------
# Tiny helper: emit a finding via the correct 5-argument reportError call
# ---------------------------------------------------------------------------
def _emit(token, severity: str, message: str, error_id: str) -> None:
    """Wrapper that always passes all five required positional arguments."""
    cppcheckdata.reportError(token, severity, message, ADDON_NAME, error_id)


# ===========================================================================
# Per-translation-unit analysis state
# ===========================================================================
class _KeyTaintDB:
    """
    Tracks which variable names are tainted as 'key material' within
    the current function scope.
    """
    def __init__(self) -> None:
        self._tainted: set[str] = set()
        # var-name → token of last assignment (for reporting)
        self._tokens: dict[str, object] = {}

    def taint(self, name: str, token) -> None:
        self._tainted.add(name)
        self._tokens[name] = token

    def is_tainted(self, name: str) -> bool:
        return name in self._tainted

    def tainted_names(self) -> set[str]:
        return set(self._tainted)

    def token_for(self, name: str):
        return self._tokens.get(name)

    def clear_scope(self) -> None:
        self._tainted.clear()
        self._tokens.clear()


class _IVTracker:
    """
    Tracks IV / nonce variables.  If the same variable is used in two
    separate encryption calls without being re-assigned between them,
    flag CKL-05.
    """
    def __init__(self) -> None:
        # iv_name → last-encrypt token (None = not yet used in encryption)
        self._state: dict[str, object] = {}
        # iv_name → was reassigned after last encryption?
        self._reassigned: dict[str, bool] = {}

    def note_assignment(self, iv_name: str) -> None:
        self._reassigned[iv_name] = True

    def note_encryption(self, iv_name: str, token) -> object:
        """Return the previous token if IV is being reused, else None."""
        prev = self._state.get(iv_name)
        reassigned = self._reassigned.get(iv_name, True)
        if prev is not None and not reassigned:
            return prev          # reuse detected
        self._state[iv_name] = token
        self._reassigned[iv_name] = False
        return None

    def clear_scope(self) -> None:
        self._state.clear()
        self._reassigned.clear()


class _AEADState:
    """
    Tracks whether the result of an AEAD decrypt call is checked.
    A decrypt call whose return value is never tested before being
    discarded indicates CKL-09.
    """
    def __init__(self) -> None:
        # function-call token → result checked?
        self._calls: dict[int, tuple[object, bool]] = {}

    def note_call(self, token) -> None:
        self._calls[id(token)] = (token, False)

    def note_check(self, call_token) -> None:
        k = id(call_token)
        if k in self._calls:
            tok, _ = self._calls[k]
            self._calls[k] = (tok, True)

    def unchecked(self):
        return [tok for tok, checked in self._calls.values() if not checked]

    def clear_scope(self) -> None:
        self._calls.clear()


# ===========================================================================
# Individual checker implementations
# ===========================================================================

def _check_ckl01_key_not_zeroed(cfg, taintdb: _KeyTaintDB) -> list[tuple]:
    """
    CKL-01: key buffer freed / goes out of scope without explicit zeroing.

    Strategy:
      - Walk tokens looking for free() / EVP_..._free() calls.
      - If the argument is tainted, check whether a zeroing call preceded it
        in the same basic block (simple backward scan up to the enclosing '{').
    """
    findings = []
    tokens = cfg.tokenlist

    for i, tok in enumerate(tokens):
        if tok.str not in _FREE_FUNCTIONS:
            continue
        # Grab argument (token after '(')
        arg_tok = _next_meaningful(tokens, i + 1)   # skip '('
        if arg_tok is None:
            continue
        arg_name = arg_tok.str
        if not taintdb.is_tainted(arg_name):
            # Also fire if name looks like a key by heuristic
            if not _KEY_NAME_RE.search(arg_name):
                continue

        # Scan backward for a zeroing call on the same variable
        zeroed = _scan_backward_for_zero(tokens, i, arg_name)
        if not zeroed:
            findings.append((
                tok,
                SEV_WARNING,
                f"Key/secret buffer '{arg_name}' is freed without prior "
                f"zeroing (use memset/explicit_bzero/OPENSSL_cleanse). "
                f"Sensitive key material may linger in heap. [CWE-316]",
                "CKL-01",
            ))
    return findings


def _check_ckl02_weak_cipher(cfg) -> list[tuple]:
    """CKL-02: Weak or broken cipher used."""
    findings = []
    for tok in cfg.tokenlist:
        # Check string literals and identifier names
        text = tok.str.upper()
        for pattern, reason in _WEAK_CIPHERS:
            if pattern in text:
                findings.append((
                    tok,
                    SEV_WARNING,
                    f"Weak/broken cryptographic algorithm detected: {reason}. "
                    f"Prefer AES-256-GCM or ChaCha20-Poly1305. [CWE-327]",
                    "CKL-02",
                ))
                break   # one report per token
    return findings


def _check_ckl03_weak_key_size(cfg) -> list[tuple]:
    """
    CKL-03: Insufficient key size.

    Heuristic: look for numeric constants adjacent to key-size-like
    identifiers (KEY_SIZE, keylen, rsa_bits, …) and flag values below
    accepted thresholds.
    """
    findings = []
    _KEY_SIZE_ID_RE = re.compile(
        r"(key_?size|key_?len|key_?bits|rsa_?bits|ec_?bits|key_?length)",
        re.IGNORECASE,
    )
    tokens = cfg.tokenlist
    for i, tok in enumerate(tokens):
        if not _KEY_SIZE_ID_RE.search(tok.str):
            continue
        # Look for an adjacent numeric literal (within 3 tokens)
        for delta in range(1, 4):
            if i + delta >= len(tokens):
                break
            candidate = tokens[i + delta]
            if not candidate.str.isdigit():
                continue
            size = int(candidate.str)
            msg = None
            if "rsa" in tok.str.lower() and size < 2048:
                msg = (f"RSA key size {size} bits is below the recommended "
                       f"minimum of 2048 bits. [CWE-326]")
            elif "ec" in tok.str.lower() and size < 224:
                msg = (f"EC key size {size} bits is below the recommended "
                       f"minimum of 224 bits. [CWE-326]")
            elif size < 128 and "aes" not in tok.str.lower():
                msg = (f"Key size {size} bits may be insufficient for "
                       f"symmetric encryption (minimum 128 bits). [CWE-326]")
            if msg:
                findings.append((candidate, SEV_WARNING, msg, "CKL-03"))
            break
    return findings


def _check_ckl04_weak_rng(cfg, taintdb: _KeyTaintDB) -> list[tuple]:
    """
    CKL-04: Weak / non-cryptographic RNG used to generate key material.
    """
    findings = []
    tokens = cfg.tokenlist
    for i, tok in enumerate(tokens):
        if tok.str not in _WEAK_RNGS:
            continue
        # Check if the result feeds into a key variable (next assignment)
        # or if caller context has key-like variable names
        context_name = _find_assignment_target(tokens, i)
        if context_name and _KEY_NAME_RE.search(context_name):
            findings.append((
                tok,
                SEV_ERROR,
                f"Non-cryptographic RNG '{tok.str}' used to generate key "
                f"material assigned to '{context_name}'. Use a CSPRNG such as "
                f"RAND_bytes() or getrandom(). [CWE-338]",
                "CKL-04",
            ))
        elif taintdb.is_tainted(context_name or ""):
            findings.append((
                tok,
                SEV_ERROR,
                f"Non-cryptographic RNG '{tok.str}' used; result flows into "
                f"tainted key variable. Use a CSPRNG. [CWE-338]",
                "CKL-04",
            ))
    return findings


def _check_ckl05_iv_reuse(cfg, iv_tracker: _IVTracker) -> list[tuple]:
    """
    CKL-05: IV / nonce reused across multiple encryption calls.
    """
    findings = []
    tokens = cfg.tokenlist
    encrypt_funcs = {
        "EVP_EncryptInit_ex", "EVP_EncryptInit",
        "EVP_CipherInit_ex",  "EVP_CipherInit",
        "AES_cbc_encrypt",    "AES_cfb_encrypt",
        "CCCrypt",
    }

    for i, tok in enumerate(tokens):
        # Track IV reassignments
        if _IV_NAME_RE.search(tok.str) and i + 1 < len(tokens):
            next_tok = tokens[i + 1]
            if next_tok.str in ("=", "["):
                iv_tracker.note_assignment(tok.str)

        # Check encryption calls for IV arguments
        if tok.str not in encrypt_funcs:
            continue
        # Walk the argument list looking for an IV-like name
        paren_depth = 0
        for j in range(i, min(i + 40, len(tokens))):
            t = tokens[j]
            if t.str == "(":
                paren_depth += 1
            elif t.str == ")":
                paren_depth -= 1
                if paren_depth == 0:
                    break
            elif paren_depth == 1 and _IV_NAME_RE.search(t.str):
                prev = iv_tracker.note_encryption(t.str, tok)
                if prev is not None:
                    findings.append((
                        tok,
                        SEV_ERROR,
                        f"IV/nonce '{t.str}' is reused across two calls to "
                        f"'{tok.str}' without being regenerated. IV reuse "
                        f"breaks confidentiality for CBC/CTR/GCM modes. "
                        f"[CWE-329]",
                        "CKL-05",
                    ))
    return findings


def _check_ckl06_key_in_logs(cfg, taintdb: _KeyTaintDB) -> list[tuple]:
    """CKL-06: Key material passed to a logging / output function."""
    findings = []
    tokens = cfg.tokenlist
    for i, tok in enumerate(tokens):
        if tok.str not in _LOG_FUNCTIONS:
            continue
        # Collect all identifier arguments
        for arg_name in _collect_call_args(tokens, i):
            if taintdb.is_tainted(arg_name) or _KEY_NAME_RE.search(arg_name):
                findings.append((
                    tok,
                    SEV_ERROR,
                    f"Key/secret material '{arg_name}' is passed to logging "
                    f"function '{tok.str}'. Logging sensitive material "
                    f"exposes keys to log files, syslog, etc. [CWE-312]",
                    "CKL-06",
                ))
    return findings


def _check_ckl07_key_to_file(cfg, taintdb: _KeyTaintDB) -> list[tuple]:
    """CKL-07: Key material written to a file (unencrypted)."""
    findings = []
    tokens = cfg.tokenlist
    for i, tok in enumerate(tokens):
        if tok.str not in _FILE_WRITE_FUNCTIONS:
            continue
        for arg_name in _collect_call_args(tokens, i):
            if taintdb.is_tainted(arg_name) or _KEY_NAME_RE.search(arg_name):
                findings.append((
                    tok,
                    SEV_WARNING,
                    f"Key/secret material '{arg_name}' is passed to file "
                    f"write function '{tok.str}'. Writing raw key material to "
                    f"disk may expose it to other processes. [CWE-312]",
                    "CKL-07",
                ))
    return findings


def _check_ckl08_ecb_mode(cfg) -> list[tuple]:
    """CKL-08: ECB mode selected – leaks plaintext structure."""
    findings = []
    for tok in cfg.tokenlist:
        if _ECB_RE.search(tok.str):
            findings.append((
                tok,
                SEV_WARNING,
                f"ECB (Electronic Code Book) mode detected in '{tok.str}'. "
                f"ECB mode is deterministic and leaks plaintext block patterns. "
                f"Use an authenticated mode such as AES-GCM or ChaCha20-Poly1305. "
                f"[CWE-327]",
                "CKL-08",
            ))
    return findings


def _check_ckl09_aead_tag_unchecked(cfg) -> list[tuple]:
    """
    CKL-09: AEAD decryption return value not checked.

    If an AEAD decrypt function's return value is not used in a conditional
    (if / assert / while), the authentication tag has not been verified.
    """
    findings = []
    tokens = cfg.tokenlist
    for i, tok in enumerate(tokens):
        if tok.str not in _AEAD_DECRYPT:
            continue
        # Look backward for assignment  (ret = decrypt_func(…))
        # or forward for use in conditional
        assigned_var = _find_assignment_target_backward(tokens, i)
        if assigned_var is None:
            # Return value discarded immediately → definitely unchecked
            findings.append((
                tok,
                SEV_ERROR,
                f"Return value of AEAD/authenticated decryption function "
                f"'{tok.str}' is discarded. The authentication tag MUST be "
                f"checked before using the decrypted data. [CWE-354]",
                "CKL-09",
            ))
            continue
        # Check whether assigned_var appears in an if/assert within ~20 tokens
        checked = _is_var_checked(tokens, i, assigned_var, lookahead=60)
        if not checked:
            findings.append((
                tok,
                SEV_ERROR,
                f"Return value of AEAD/authenticated decryption function "
                f"'{tok.str}' (stored in '{assigned_var}') does not appear to "
                f"be checked in a conditional. Always verify the MAC before "
                f"processing decrypted data. [CWE-354]",
                "CKL-09",
            ))
    return findings


def _check_ckl10_hardcoded_key(cfg) -> list[tuple]:
    """
    CKL-10: Hardcoded cryptographic key literal.

    Flags:
      - String literals that look like hex-encoded keys (≥8 hex chars)
      - Byte-array initialisers with ≥8 consecutive 0xNN values assigned to
        a key-like variable name.
    """
    findings = []
    tokens = cfg.tokenlist
    for i, tok in enumerate(tokens):
        # String literal: "AABBCCDD…"
        if tok.str.startswith('"') and _HEX_KEY_RE.search(tok.str):
            # Only flag if adjacent to a key-like identifier
            context = _surrounding_identifier(tokens, i)
            if context and _KEY_NAME_RE.search(context):
                findings.append((
                    tok,
                    SEV_ERROR,
                    f"Hardcoded hexadecimal key literal near '{context}'. "
                    f"Hardcoded keys cannot be rotated and are exposed in "
                    f"binaries. [CWE-321]",
                    "CKL-10",
                ))
            continue

        # Byte-array initialiser  { 0x01, 0x02, … }
        if tok.str == "{" and i > 0:
            # Reconstruct a short window as a string for regex matching
            window = " ".join(t.str for t in tokens[i:min(i + 30, len(tokens))])
            if _BYTE_INIT_RE.search(window):
                context = _surrounding_identifier(tokens, i)
                if context and _KEY_NAME_RE.search(context):
                    findings.append((
                        tok,
                        SEV_ERROR,
                        f"Hardcoded byte-array key initialiser near '{context}'. "
                        f"Hardcoded keys cannot be rotated and are exposed in "
                        f"binaries. [CWE-321]",
                        "CKL-10",
                    ))
    return findings


# ===========================================================================
# Taint-tracking helper:  build _KeyTaintDB for one cfg
# ===========================================================================
def _build_taint_db(cfg) -> _KeyTaintDB:
    """
    Walk tokens once and mark variables as 'key tainted' when they receive
    the result of a key-generating function or are named like keys.
    """
    db = _KeyTaintDB()
    tokens = cfg.tokenlist
    for i, tok in enumerate(tokens):
        # Pattern: varname = key_source_func(…)
        if tok.str in _KEY_SOURCES:
            target = _find_assignment_target_backward(tokens, i)
            if target:
                db.taint(target, tok)
        # Pattern: variable with a key-like name and an initialiser
        if _KEY_NAME_RE.search(tok.str) and i + 1 < len(tokens):
            nxt = tokens[i + 1]
            if nxt.str in ("=", "[", ",", ";"):
                db.taint(tok.str, tok)
    return db


# ===========================================================================
# Utility / helper functions
# ===========================================================================

def _next_meaningful(tokens: list, start: int):
    """Return the first non-'(' token at or after tokens[start]."""
    for i in range(start, min(start + 5, len(tokens))):
        if tokens[i].str != "(":
            return tokens[i]
    return None


def _find_assignment_target(tokens: list, call_idx: int) -> str | None:
    """
    Given index of a function-call token, scan backward for
       identifier  =  …  function_call
    and return the identifier name.
    """
    for delta in range(1, 6):
        j = call_idx - delta
        if j < 0:
            break
        t = tokens[j]
        if t.str == "=":
            # The token before '=' should be the variable name
            k = j - 1
            if k >= 0 and tokens[k].str.isidentifier():
                return tokens[k].str
    return None


def _find_assignment_target_backward(tokens: list, call_idx: int) -> str | None:
    """Alias for _find_assignment_target (same semantics)."""
    return _find_assignment_target(tokens, call_idx)


def _is_var_checked(tokens: list, start: int, var: str, lookahead: int) -> bool:
    """
    Return True if var appears inside an if / assert / while condition
    within *lookahead* tokens after *start*.
    """
    in_conditional = False
    depth = 0
    for i in range(start, min(start + lookahead, len(tokens))):
        t = tokens[i]
        if t.str in ("if", "assert", "while"):
            in_conditional = True
            depth = 0
        if in_conditional:
            if t.str == "(":
                depth += 1
            elif t.str == ")":
                depth -= 1
                if depth <= 0:
                    in_conditional = False
            elif t.str == var:
                return True
    return False


def _scan_backward_for_zero(tokens: list, free_idx: int, var: str) -> bool:
    """
    Scan backward from free_idx looking for a zeroing call on var.
    Stops at the nearest enclosing '{'.
    """
    for i in range(free_idx - 1, max(free_idx - 60, -1), -1):
        t = tokens[i]
        if t.str == "{":
            break
        if t.str in _ZERO_FUNCTIONS:
            # Check argument
            for delta in range(1, 8):
                j = i + delta
                if j >= len(tokens):
                    break
                if tokens[j].str == var:
                    return True
                if tokens[j].str == ")":
                    break
    return False


def _collect_call_args(tokens: list, call_idx: int) -> list[str]:
    """
    Return identifier names that appear as arguments to the call at call_idx.
    """
    args = []
    paren_depth = 0
    for i in range(call_idx, min(call_idx + 60, len(tokens))):
        t = tokens[i]
        if t.str == "(":
            paren_depth += 1
        elif t.str == ")":
            paren_depth -= 1
            if paren_depth <= 0:
                break
        elif paren_depth >= 1 and t.str.isidentifier() and t.str not in {
            "NULL", "nullptr", "true", "false",
        }:
            args.append(t.str)
    return args


def _surrounding_identifier(tokens: list, idx: int) -> str | None:
    """
    Return the nearest identifier within 5 tokens before *idx*.
    Used to associate a literal with a variable name.
    """
    for delta in range(1, 6):
        j = idx - delta
        if j < 0:
            break
        t = tokens[j]
        if t.str.isidentifier() and t.str not in {
            "const", "static", "unsigned", "signed",
            "char", "int", "uint8_t", "uint32_t",
        }:
            return t.str
    return None


# ===========================================================================
# Main analysis driver
# ===========================================================================

def analyse_cfg(cfg) -> list[tuple]:
    """Run all checkers on a single Control-Flow Graph (function body)."""
    findings: list[tuple] = []

    taintdb   = _build_taint_db(cfg)
    iv_tracker = _IVTracker()

    findings += _check_ckl01_key_not_zeroed(cfg, taintdb)
    findings += _check_ckl02_weak_cipher(cfg)
    findings += _check_ckl03_weak_key_size(cfg)
    findings += _check_ckl04_weak_rng(cfg, taintdb)
    findings += _check_ckl05_iv_reuse(cfg, iv_tracker)
    findings += _check_ckl06_key_in_logs(cfg, taintdb)
    findings += _check_ckl07_key_to_file(cfg, taintdb)
    findings += _check_ckl08_ecb_mode(cfg)
    findings += _check_ckl09_aead_tag_unchecked(cfg)
    findings += _check_ckl10_hardcoded_key(cfg)

    return findings


# ===========================================================================
# Entry point
# ===========================================================================

def main() -> None:
    args = cppcheckdata.ArgumentParser().parse_args()

    for dumpfile in args.dumpfile:
        data = cppcheckdata.CppcheckData(dumpfile)

        for cfg in data.iterconfigurations():
            all_findings = analyse_cfg(cfg)

            # De-duplicate: same (file, line, errorId) → report once
            seen: set[tuple[str, int, str]] = set()
            for tok, sev, msg, eid in all_findings:
                key = (tok.file, tok.linenr, eid)
                if key in seen:
                    continue
                seen.add(key)
                _emit(tok, sev, msg, eid)


if __name__ == "__main__":
    main()

