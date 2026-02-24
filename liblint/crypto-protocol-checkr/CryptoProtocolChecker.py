#!/usr/bin/env python3
"""
CryptoProtocolChecker.py — Cppcheck addon
==========================================
Domain  : Cryptographic protocol misuse in C
Checkers: CPC-01 … CPC-12
CWEs    : 295, 311, 321, 326, 327, 328, 329, 330, 338, 385

Hardening contract
------------------
* NEVER call int(tok.varId) directly.
* ALWAYS use _safe_vid() / _safe_vid_tok() for all varId access.
* All findings emitted as single-line JSON on stdout (cppcheck addon protocol).
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
            cppcheckdata = _ilu.module_from_spec(_spec)   # type: ignore[assignment]
            _spec.loader.exec_module(_spec.loader)         # type: ignore[union-attr]
            break
    else:
        sys.exit("CryptoProtocolChecker: cannot locate cppcheckdata.py")


# ===========================================================================
# §1  Hardened variable-ID helpers  (hardening contract)
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
    """Safe tok.str access — returns '' on failure."""
    try:
        return tok.str or ""
    except AttributeError:
        return ""


def _tokens(cfg) -> Iterator:
    """Yield every token in the configuration."""
    try:
        for tok in cfg.tokenlist:
            yield tok
    except (AttributeError, TypeError):
        pass


def _next_non_paren(tok):
    """Skip a single '(' … ')' wrapper and return the inner token, or tok."""
    try:
        if _s(tok) == '(':
            inner = tok.next
            if inner and _s(inner.next) == ')':
                return inner
        return tok
    except AttributeError:
        return tok


def _tok_file_line(tok) -> Tuple[str, int, int]:
    try:
        f  = tok.file    or ""
        ln = int(tok.linenr) if tok.linenr is not None else 0
        co = int(tok.column) if tok.column is not None else 0
        return f, ln, co
    except (AttributeError, TypeError, ValueError):
        return "", 0, 0


def _var_name(tok) -> str:
    """Return the variable name for tok, or ''."""
    try:
        if tok.variable:
            return tok.variable.name or ""
    except AttributeError:
        pass
    return _s(tok)


def _decl_type_str(tok) -> str:
    """
    Best-effort: return the full declared-type string for a variable token.
    Example: for 'unsigned char key[32]' returns 'unsigned char'.
    """
    try:
        v = tok.variable
        if v is None:
            return ""
        ts = v.typeStartToken
        te = v.typeEndToken
        if ts is None:
            return ""
        parts: List[str] = []
        t = ts
        while t is not None:
            s = _s(t)
            if s not in ('*', '[', ']', 'const', 'volatile', 'restrict'):
                parts.append(s)
            if t is te:
                break
            t = t.next
        return " ".join(parts).strip()
    except AttributeError:
        return ""


# ===========================================================================
# §3  Domain constants
# ===========================================================================

# ── CPC-01  Weak hash algorithms ────────────────────────────────────────────
_WEAK_HASH_FUNCS: FrozenSet[str] = frozenset({
    # OpenSSL
    "MD5", "MD5_Init", "MD5_Update", "MD5_Final",
    "SHA1", "SHA1_Init", "SHA1_Update", "SHA1_Final",
    "SHA", "SHA_Init", "SHA_Update", "SHA_Final",
    "MD4", "MD4_Init", "MD4_Update", "MD4_Final",
    "MD2", "RIPEMD160",
    # mbedTLS
    "mbedtls_md5_starts", "mbedtls_md5_update", "mbedtls_md5_finish",
    "mbedtls_md5",
    "mbedtls_sha1_starts", "mbedtls_sha1_update", "mbedtls_sha1_finish",
    "mbedtls_sha1",
    # libgcrypt
    "gcry_md_open",          # flagged when algorithm arg is GCRY_MD_MD5/SHA1
    # WolfSSL / Nettle / Botan (common prefixes)
    "wc_InitMd5", "wc_Md5Update", "wc_Md5Final",
    "wc_InitSha",  "wc_ShaUpdate",  "wc_ShaFinal",
    "nettle_md5_init", "nettle_sha1_init",
})

_WEAK_HASH_CONSTANTS: FrozenSet[str] = frozenset({
    "GCRY_MD_MD5", "GCRY_MD_SHA1", "GCRY_MD_MD4", "GCRY_MD_MD2",
    "CALG_MD5", "CALG_SHA1",                     # Windows CryptoAPI
    "NID_md5", "NID_sha1",                        # OpenSSL NID
    "MBEDTLS_MD_MD5", "MBEDTLS_MD_SHA1",
    "EVP_md5", "EVP_sha1",                        # used as EVP_DigestInit arg
})

# ── CPC-02  Weak cipher algorithms ──────────────────────────────────────────
_WEAK_CIPHER_FUNCS: FrozenSet[str] = frozenset({
    # OpenSSL legacy EVP
    "EVP_des_cbc", "EVP_des_ecb", "EVP_des_cfb", "EVP_des_ofb",
    "EVP_des_ede_cbc", "EVP_des_ede3_cbc",
    "EVP_rc4", "EVP_rc2_cbc", "EVP_rc2_ecb",
    "EVP_bf_cbc",  "EVP_bf_ecb",               # Blowfish
    "EVP_cast5_cbc",
    # mbedTLS
    "mbedtls_des_init", "mbedtls_des3_init",
    "mbedtls_arc4_init", "mbedtls_arc4_setup",
    # WolfSSL
    "wc_Des_SetKey", "wc_Des3_SetKey",
    "wc_Arc4SetKey",
    # Nettle
    "nettle_des_set_key", "nettle_arcfour_set_key",
})

_WEAK_CIPHER_CONSTANTS: FrozenSet[str] = frozenset({
    "NID_des_cbc", "NID_des_ede3_cbc",
    "NID_rc4", "NID_rc2_cbc",
    "CALG_DES", "CALG_3DES", "CALG_RC4", "CALG_RC2",
    "MBEDTLS_CIPHER_DES_CBC", "MBEDTLS_CIPHER_DES_EDE3_CBC",
    "MBEDTLS_CIPHER_ARC4_128",
})

# ── CPC-03  Hardcoded key / IV / password variable name patterns ─────────────
_SECRET_NAME_RE = re.compile(
    r'(key|iv|nonce|secret|password|passwd|pwd|salt|token|hmac_key|api_key)',
    re.IGNORECASE,
)

# ── CPC-04  Null IV detection ────────────────────────────────────────────────
_IV_INIT_FUNCS: FrozenSet[str] = frozenset({
    "EVP_EncryptInit", "EVP_EncryptInit_ex",
    "EVP_DecryptInit", "EVP_DecryptInit_ex",
    "EVP_CipherInit",  "EVP_CipherInit_ex",
    "mbedtls_aes_setiv",
    "mbedtls_gcm_starts",
    "wc_AesSetIV",
    "CCM_SetIv",
})

# ── CPC-05  ECB mode ─────────────────────────────────────────────────────────
_ECB_FUNCS: FrozenSet[str] = frozenset({
    "EVP_aes_128_ecb", "EVP_aes_192_ecb", "EVP_aes_256_ecb",
    "EVP_des_ecb", "EVP_bf_ecb", "EVP_rc2_ecb",
    "EVP_sm4_ecb",
})

_ECB_CONSTANTS: FrozenSet[str] = frozenset({
    "MBEDTLS_AES_ENCRYPT",           # used alone (ECB mode in mbedtls_aes_crypt_ecb)
    "MBEDTLS_MODE_ECB",
    "kCCModeECB",                    # Apple CommonCrypto
    "MODE_ECB",
    "CRYPT_MODE_ECB",                # Windows CAPI
})

_ECB_STRING_RE = re.compile(r'\bECB\b', re.IGNORECASE)

# ── CPC-06  Weak PRNG ────────────────────────────────────────────────────────
_WEAK_PRNG_FUNCS: FrozenSet[str] = frozenset({
    "rand", "rand_r", "random", "lrand48", "mrand48", "drand48",
    "srand", "srandom",
    # Windows
    "GetTickCount", "GetTickCount64",
})

# Context functions that signal crypto PRNG need
_CRYPTO_CONTEXT_FUNCS: FrozenSet[str] = frozenset({
    "EVP_EncryptInit", "EVP_EncryptInit_ex",
    "EVP_DecryptInit", "EVP_DecryptInit_ex",
    "RAND_bytes", "RAND_pseudo_bytes",
    "mbedtls_ctr_drbg_random",
    "wc_RNG_GenerateBlock",
    "getrandom", "getentropy",
    "BCryptGenRandom",
})

# ── CPC-07  Insufficient key size ────────────────────────────────────────────
# We look for RSA_generate_key(bits, ...) and similar
_KEY_GEN_FUNCS: Dict[str, Tuple[int, int]] = {
    # function → (arg_index_of_bits, minimum_safe_bits)
    "RSA_generate_key":           (0, 2048),
    "RSA_generate_key_ex":        (1, 2048),
    "EVP_RSA_gen":                (0, 2048),
    "DH_generate_parameters_ex":  (1, 2048),
    "DSA_generate_parameters_ex": (1, 2048),
    "EC_GROUP_new_by_curve_name": (0, 0),       # special: checked by curve name
    "mbedtls_rsa_gen_key":        (2, 2048),
    "wc_MakeRsaKey":              (1, 2048),
    "wc_DhGenerateParams":        (0, 2048),
}

# NIST curves below 224 bits
_WEAK_EC_CURVES: FrozenSet[str] = frozenset({
    "NID_secp112r1", "NID_secp112r2",
    "NID_secp128r1", "NID_secp128r2",
    "NID_sect113r1", "NID_sect113r2",
    "NID_sect131r1", "NID_sect131r2",
    "MBEDTLS_ECP_DP_SECP192R1",   # 192-bit — below recommended 224
    "MBEDTLS_ECP_DP_SECP192K1",
})

# ── CPC-08  Non-constant-time comparison ────────────────────────────────────
_TIMING_COMPARE_FUNCS: FrozenSet[str] = frozenset({
    "memcmp", "strcmp", "strncmp", "bcmp", "strcasecmp", "strncasecmp",
})

# Variable name patterns that indicate a secret
_SECRET_COMPARE_RE = re.compile(
    r'(key|token|hmac|signature|sig|password|passwd|pwd|secret|hash|digest|mac)',
    re.IGNORECASE,
)

# ── CPC-09  Deprecated TLS version ──────────────────────────────────────────
_DEPRECATED_TLS_METHODS: FrozenSet[str] = frozenset({
    # OpenSSL method functions (all deprecated in 1.1+)
    "SSLv2_method",   "SSLv2_client_method",   "SSLv2_server_method",
    "SSLv3_method",   "SSLv3_client_method",   "SSLv3_server_method",
    "TLSv1_method",   "TLSv1_client_method",   "TLSv1_server_method",
    "TLSv1_1_method", "TLSv1_1_client_method", "TLSv1_1_server_method",
    "DTLSv1_method",  "DTLSv1_client_method",  "DTLSv1_server_method",
})

_DEPRECATED_TLS_OPTIONS: FrozenSet[str] = frozenset({
    "SSL_OP_NO_TLSv1_2",   # disabling 1.2 forces 1.1 or lower
    "SSL_OP_NO_TLSv1_3",   # disabling 1.3 alone is advisory warning
})

_DEPRECATED_TLS_CONSTANTS: FrozenSet[str] = frozenset({
    "SSL2_VERSION", "SSL3_VERSION",
    "TLS1_VERSION", "TLS1_1_VERSION",
    "MBEDTLS_SSL_MINOR_VERSION_0",   # SSLv3
    "MBEDTLS_SSL_MINOR_VERSION_1",   # TLS 1.0
    "MBEDTLS_SSL_MINOR_VERSION_2",   # TLS 1.1
    "CURL_SSLVERSION_SSLv2", "CURL_SSLVERSION_SSLv3",
    "CURL_SSLVERSION_TLSv1_0", "CURL_SSLVERSION_TLSv1_1",
})

# ── CPC-10  SSL verification disabled ───────────────────────────────────────
_SSL_VERIFY_NONE: FrozenSet[str] = frozenset({"SSL_VERIFY_NONE"})

_CURL_VERIFY_OPTIONS: FrozenSet[str] = frozenset({
    "CURLOPT_SSL_VERIFYPEER",
    "CURLOPT_SSL_VERIFYHOST",
})

# ── CPC-11  Unauthenticated encryption ─────────────────────────────────────
_UNAUTH_ENC_FUNCS: FrozenSet[str] = frozenset({
    "EVP_aes_128_cbc", "EVP_aes_192_cbc", "EVP_aes_256_cbc",
    "EVP_aes_128_ctr", "EVP_aes_192_ctr", "EVP_aes_256_ctr",
    "EVP_aes_128_cfb", "EVP_aes_192_cfb", "EVP_aes_256_cfb",
    "mbedtls_aes_crypt_cbc", "mbedtls_aes_crypt_ctr",
    "wc_AesCbcEncrypt", "wc_AesCtrEncrypt",
})

_AUTH_ENC_FUNCS: FrozenSet[str] = frozenset({
    # AEAD modes
    "EVP_aes_128_gcm", "EVP_aes_256_gcm", "EVP_aes_128_ccm", "EVP_aes_256_ccm",
    "EVP_chacha20_poly1305",
    "mbedtls_gcm_init",  "mbedtls_ccm_init",
    "wc_AesGcmEncrypt",  "wc_AesCcmEncrypt",
    # HMAC
    "HMAC", "HMAC_Init", "HMAC_Init_ex",
    "mbedtls_md_hmac_starts",
    "wc_HmacInit",
    # Poly1305
    "poly1305_init", "Poly1305Update",
    "mbedtls_poly1305_init",
})

# ── CPC-12  Hardcoded salt in KDF ───────────────────────────────────────────
_KDF_FUNCS: FrozenSet[str] = frozenset({
    "PKCS5_PBKDF2_HMAC", "PKCS5_PBKDF2_HMAC_SHA1",
    "EVP_PBE_scrypt",
    "mbedtls_pkcs5_pbkdf2_hmac",
    "wc_PBKDF2", "wc_PBKDF1",
    "bcrypt",
    "Argon2_Context",   # libsodium / phc-winner-argon2
    "crypto_pwhash",    # libsodium
})


# ===========================================================================
# §4  Emission helper
# ===========================================================================

def _emit(checker_id: str, cwe: int, severity: str, msg: str, tok) -> None:
    """Emit one JSON finding on stdout — cppcheck addon wire protocol."""
    filename, linenr, col = _tok_file_line(tok)
    record = {
        "file":     filename,
        "linenr":   linenr,
        "column":   col,
        "severity": severity,
        "message":  msg,
        "addon":    "CryptoProtocolChecker",
        "errorId":  checker_id,
        "cwe":      cwe,
    }
    sys.stdout.write(json.dumps(record) + "\n")
    sys.stdout.flush()


# ===========================================================================
# §5  Shared AST / call-site utilities
# ===========================================================================

def _is_function_call(tok) -> bool:
    """True if tok is a function name immediately followed by '('."""
    try:
        return (
            tok.isName
            and tok.next is not None
            and _s(tok.next) == '('
        )
    except AttributeError:
        return False


def _call_args(call_name_tok) -> List:
    """
    Return a flat list of the top-level argument *name* tokens for a call.
    Skips nested parentheses so inner calls are not confused with commas.

    Example:  foo(a, bar(b, c), d)  → [tok(a), tok(d)]  (bar(...) skipped)
    We return the *first* token of each argument at depth-0.
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
    """Return the first token of argument `index` (0-based), or None."""
    args = _call_args(call_name_tok)
    if 0 <= index < len(args):
        return args[index]
    return None


def _int_value(tok) -> Optional[int]:
    """If tok is an integer literal, return its value, else None."""
    try:
        s = _s(tok).rstrip("uUlL")
        if s.startswith("0x") or s.startswith("0X"):
            return int(s, 16)
        if re.fullmatch(r'\d+', s):
            return int(s)
    except (ValueError, AttributeError):
        pass
    return None


def _is_string_literal(tok) -> bool:
    try:
        return tok.isString
    except AttributeError:
        s = _s(tok)
        return s.startswith('"') or s.startswith('L"')


def _string_literal_value(tok) -> str:
    """Strip surrounding quotes and return the string content."""
    s = _s(tok)
    # Strip optional L prefix and quotes
    s = re.sub(r'^L?"', '', s)
    s = s.rstrip('"')
    return s


def _collect_call_names_in_scope(cfg, scope_start, scope_end) -> Set[str]:
    """
    Walk tokens from scope_start to scope_end (exclusive) and collect every
    function name that appears in a call position.
    """
    names: Set[str] = set()
    tok = scope_start
    while tok is not None and tok is not scope_end:
        if _is_function_call(tok):
            names.add(_s(tok))
        tok = tok.next
    return names


def _surrounding_function_calls(tok, window: int = 40) -> Set[str]:
    """
    Return names of function calls within `window` tokens before/after tok.
    Used to detect auth calls adjacent to encryption calls (CPC-11).
    """
    names: Set[str] = set()
    t = tok
    for _ in range(window):
        if t is None:
            break
        if _is_function_call(t):
            names.add(_s(t))
        t = t.previous
    t = tok.next
    for _ in range(window):
        if t is None:
            break
        if _is_function_call(t):
            names.add(_s(t))
        t = t.next
    return names


# ===========================================================================
# §6  Base checker
# ===========================================================================

class _BaseChecker:
    checker_id: str = "CPC-00"
    cwe:        int = 0
    severity:   str = "style"

    def check(self, cfg) -> None:
        raise NotImplementedError


# ===========================================================================
# §7  Individual checkers
# ===========================================================================

# ---------------------------------------------------------------------------
# CPC-01  weak_hash_algorithm  (CWE-328)
# ---------------------------------------------------------------------------

class _CPC01_WeakHash(_BaseChecker):
    checker_id = "CPC-01"
    cwe        = 328
    severity   = "error"

    def check(self, cfg) -> None:
        for tok in _tokens(cfg):
            name = _s(tok)

            # Direct function calls to weak hash APIs
            if name in _WEAK_HASH_FUNCS and _is_function_call(tok):
                msg = (
                    f"Call to weak hash function '{name}'. "
                    f"MD5 and SHA-1 are cryptographically broken and must not "
                    f"be used for security purposes (signatures, integrity, "
                    f"password storage). Use SHA-256 or SHA-3 (CWE-328)."
                )
                _emit(self.checker_id, self.cwe, self.severity, msg, tok)
                continue

            # Weak hash algorithm constants passed to generic digest APIs
            if name in _WEAK_HASH_CONSTANTS and tok.isName:
                msg = (
                    f"Weak hash algorithm constant '{name}' used. "
                    f"This selects a broken digest algorithm that offers no "
                    f"collision resistance for security use-cases (CWE-328)."
                )
                _emit(self.checker_id, self.cwe, self.severity, msg, tok)

            # EVP_md5() / EVP_sha1() used as argument
            if name in ("EVP_md5", "EVP_sha1") and _is_function_call(tok):
                msg = (
                    f"Algorithm selector '{name}()' selects a weak digest. "
                    f"Replace with EVP_sha256() or EVP_sha3_256() (CWE-328)."
                )
                _emit(self.checker_id, self.cwe, self.severity, msg, tok)


# ---------------------------------------------------------------------------
# CPC-02  weak_cipher_algorithm  (CWE-327)
# ---------------------------------------------------------------------------

class _CPC02_WeakCipher(_BaseChecker):
    checker_id = "CPC-02"
    cwe        = 327
    severity   = "error"

    def check(self, cfg) -> None:
        for tok in _tokens(cfg):
            name = _s(tok)

            if name in _WEAK_CIPHER_FUNCS and _is_function_call(tok):
                algo = self._algo_from_func(name)
                msg = (
                    f"Call to weak cipher function '{name}' ({algo}). "
                    f"This algorithm provides inadequate security strength. "
                    f"Use AES-GCM (256-bit) or ChaCha20-Poly1305 (CWE-327)."
                )
                _emit(self.checker_id, self.cwe, self.severity, msg, tok)
                continue

            if name in _WEAK_CIPHER_CONSTANTS and tok.isName:
                msg = (
                    f"Weak cipher algorithm constant '{name}'. "
                    f"DES, 3DES, RC4, and RC2 are cryptographically broken "
                    f"or insufficiently strong (CWE-327)."
                )
                _emit(self.checker_id, self.cwe, self.severity, msg, tok)

    @staticmethod
    def _algo_from_func(name: str) -> str:
        name_l = name.lower()
        if "des3" in name_l or "ede3" in name_l:
            return "3DES"
        if "des" in name_l:
            return "DES"
        if "rc4" in name_l or "arc4" in name_l:
            return "RC4"
        if "rc2" in name_l:
            return "RC2"
        if "bf" in name_l or "blowfish" in name_l:
            return "Blowfish"
        return "weak cipher"


# ---------------------------------------------------------------------------
# CPC-03  hardcoded_key_or_iv  (CWE-321)
# ---------------------------------------------------------------------------

class _CPC03_HardcodedKey(_BaseChecker):
    checker_id = "CPC-03"
    cwe        = 321
    severity   = "error"

    # Minimum string length to flag (avoids flagging empty strings)
    _MIN_SECRET_LEN = 4

    def check(self, cfg) -> None:
        for tok in _tokens(cfg):
            # Only interested in '=' assignment operator
            if _s(tok) != '=':
                continue

            lhs = tok.astOperand1
            rhs = tok.astOperand2
            if lhs is None or rhs is None:
                continue

            # LHS variable name must match a secret-sounding name
            lhs_name = _var_name(lhs)
            if not lhs_name or not _SECRET_NAME_RE.search(lhs_name):
                continue

            # RHS must be a string or character-array literal
            if _is_string_literal(rhs):
                val = _string_literal_value(rhs)
                if len(val) >= self._MIN_SECRET_LEN:
                    msg = (
                        f"Hardcoded string literal assigned to secret variable "
                        f"'{lhs_name}'. Embedding cryptographic keys, IVs, "
                        f"passwords, or salts as literals creates a static, "
                        f"extractable secret (CWE-321). "
                        f"Load from a secure key store or environment variable."
                    )
                    _emit(self.checker_id, self.cwe, self.severity, msg, tok)
                continue

            # RHS is an integer literal (e.g. key = 0xDEADBEEF)
            if _int_value(rhs) is not None:
                msg = (
                    f"Hardcoded integer literal assigned to secret variable "
                    f"'{lhs_name}'. Hardcoded numeric keys are extractable "
                    f"from the binary (CWE-321)."
                )
                _emit(self.checker_id, self.cwe, self.severity, msg, tok)

            # Initialisation via brace with all literals: unsigned char key[] = {0x00,...}
            # Detect by checking if RHS is '{' — token-stream heuristic
            if _s(rhs) == '{':
                if self._all_literal_initialiser(rhs):
                    msg = (
                        f"Hardcoded byte-array literal initialises secret "
                        f"variable '{lhs_name}'. This key material is "
                        f"statically embedded and trivially extractable (CWE-321)."
                    )
                    _emit(self.checker_id, self.cwe, self.severity, msg, tok)

    @staticmethod
    def _all_literal_initialiser(brace_tok) -> bool:
        """
        Return True if every element inside '{' … '}' is an integer or
        character literal (i.e. no variable references).
        """
        tok = brace_tok.next
        depth = 0
        has_any = False
        while tok is not None:
            s = _s(tok)
            if s == '{':
                depth += 1
            elif s == '}':
                if depth == 0:
                    return has_any
                depth -= 1
            elif s == ',':
                pass
            elif depth == 0:
                has_any = True
                # A non-literal identifier → not all literals
                if tok.isName and _safe_vid(tok) != 0:
                    return False
            tok = tok.next
        return has_any


# ---------------------------------------------------------------------------
# CPC-04  null_iv  (CWE-329)
# ---------------------------------------------------------------------------

class _CPC04_NullIV(_BaseChecker):
    checker_id = "CPC-04"
    cwe        = 329
    severity   = "error"

    # For EVP_*Init* the IV is the 4th argument (index 3)
    # For mbedtls_aes_setiv the IV is the 2nd argument (index 1)
    _IV_ARG_INDEX: Dict[str, int] = {
        "EVP_EncryptInit":     3,
        "EVP_EncryptInit_ex":  3,
        "EVP_DecryptInit":     3,
        "EVP_DecryptInit_ex":  3,
        "EVP_CipherInit":      3,
        "EVP_CipherInit_ex":   3,
        "mbedtls_aes_setiv":   1,
        "mbedtls_gcm_starts":  3,
        "wc_AesSetIV":         1,
    }

    def check(self, cfg) -> None:
        for tok in _tokens(cfg):
            fname = _s(tok)
            if fname not in self._IV_ARG_INDEX:
                continue
            if not _is_function_call(tok):
                continue
            iv_idx = self._IV_ARG_INDEX[fname]
            iv_arg = _arg_at(tok, iv_idx)
            if iv_arg is None:
                continue

            # Pattern 1: NULL literal
            if _s(iv_arg) in ("NULL", "0", "nullptr"):
                msg = (
                    f"NULL/zero IV passed to '{fname}'. A null IV is "
                    f"predictable and destroys semantic security for CBC, "
                    f"CTR, and GCM modes. Generate a fresh random IV "
                    f"with RAND_bytes() for each encryption (CWE-329)."
                )
                _emit(self.checker_id, self.cwe, self.severity, msg, tok)
                continue

            # Pattern 2: variable whose name contains "zero"/"null"/"init"
            iv_name = _var_name(iv_arg).lower()
            if any(kw in iv_name for kw in ("zero", "null", "init", "empty")):
                msg = (
                    f"Potentially zero-valued IV variable '{_var_name(iv_arg)}' "
                    f"passed to '{fname}'. Verify this IV is unique and "
                    f"randomly generated per encryption (CWE-329)."
                )
                _emit(self.checker_id, self.cwe, self.severity, msg, tok)
                continue

            # Pattern 3: brace-initialiser that is all zeros passed directly
            if _s(iv_arg) == '{' and self._is_all_zero_initialiser(iv_arg):
                msg = (
                    f"All-zero brace-initialiser used as IV for '{fname}'. "
                    f"A constant IV is as dangerous as no IV (CWE-329)."
                )
                _emit(self.checker_id, self.cwe, self.severity, msg, tok)

    @staticmethod
    def _is_all_zero_initialiser(brace_tok) -> bool:
        tok = brace_tok.next
        depth = 0
        while tok is not None:
            s = _s(tok)
            if s == '{':
                depth += 1
            elif s == '}':
                if depth == 0:
                    return True
                depth -= 1
            elif s not in (',',) and depth == 0:
                if s != '0':
                    return False
            tok = tok.next
        return True


# ---------------------------------------------------------------------------
# CPC-05  ecb_mode  (CWE-327)
# ---------------------------------------------------------------------------

class _CPC05_ECBMode(_BaseChecker):
    checker_id = "CPC-05"
    cwe        = 327
    severity   = "error"

    def check(self, cfg) -> None:
        for tok in _tokens(cfg):
            name = _s(tok)

            # EVP_aes_*_ecb() call
            if name in _ECB_FUNCS and _is_function_call(tok):
                msg = (
                    f"ECB mode selected via '{name}()'. ECB is a deterministic "
                    f"block cipher mode that leaks plaintext block patterns "
                    f"(the 'penguin image' vulnerability). Use AES-GCM or "
                    f"ChaCha20-Poly1305 instead (CWE-327)."
                )
                _emit(self.checker_id, self.cwe, self.severity, msg, tok)
                continue

            # ECB mode constant used as argument
            if name in _ECB_CONSTANTS:
                msg = (
                    f"ECB mode constant '{name}' used. ECB mode is semantically "
                    f"insecure for any message longer than one block (CWE-327)."
                )
                _emit(self.checker_id, self.cwe, self.severity, msg, tok)
                continue

            # String literal containing "ECB"
            if _is_string_literal(tok):
                val = _string_literal_value(tok)
                if _ECB_STRING_RE.search(val):
                    msg = (
                        f"String literal '{val}' appears to specify ECB mode. "
                        f"ECB provides no semantic security (CWE-327)."
                    )
                    _emit(self.checker_id, self.cwe, self.severity, msg, tok)


# ---------------------------------------------------------------------------
# CPC-06  weak_prng_for_crypto  (CWE-338)
# ---------------------------------------------------------------------------

class _CPC06_WeakPRNG(_BaseChecker):
    """
    Flags use of non-cryptographic PRNGs.

    Heuristic: we flag EVERY call to rand()/random()/etc in a TU that also
    contains at least one cryptographic API call.  A TU with no crypto context
    may legitimately use rand() for simulation; a TU that initialises keys/IVs
    absolutely must not.
    """
    checker_id = "CPC-06"
    cwe        = 338
    severity   = "error"

    def check(self, cfg) -> None:
        # First pass: does this TU contain any crypto context?
        all_calls: Set[str] = set()
        weak_calls = []   # (tok, name)

        for tok in _tokens(cfg):
            if not _is_function_call(tok):
                continue
            name = _s(tok)
            all_calls.add(name)
            if name in _WEAK_PRNG_FUNCS:
                weak_calls.append((tok, name))

        has_crypto_context = bool(all_calls & _CRYPTO_CONTEXT_FUNCS)
        # Also flag if any hardcoded-key related crypto func present
        has_crypto_context = has_crypto_context or bool(
            all_calls & (_WEAK_HASH_FUNCS | _WEAK_CIPHER_FUNCS | _ECB_FUNCS
                         | _IV_INIT_FUNCS | _AUTH_ENC_FUNCS | _UNAUTH_ENC_FUNCS)
        )

        if not has_crypto_context:
            return

        for tok, name in weak_calls:
            msg = (
                f"Non-cryptographic PRNG '{name}()' used in a translation unit "
                f"that also performs cryptographic operations. "
                f"rand()/random() are not suitable for key, IV, nonce, or "
                f"token generation. Use RAND_bytes(), getrandom(), or "
                f"BCryptGenRandom() (CWE-338)."
            )
            _emit(self.checker_id, self.cwe, self.severity, msg, tok)


# ---------------------------------------------------------------------------
# CPC-07  insufficient_key_size  (CWE-326)
# ---------------------------------------------------------------------------

class _CPC07_InsufficientKeySize(_BaseChecker):
    checker_id = "CPC-07"
    cwe        = 326
    severity   = "warning"

    def check(self, cfg) -> None:
        for tok in _tokens(cfg):
            fname = _s(tok)

            # Weak elliptic curve check
            if fname == "EC_GROUP_new_by_curve_name" and _is_function_call(tok):
                curve_arg = _arg_at(tok, 0)
                if curve_arg is not None and _s(curve_arg) in _WEAK_EC_CURVES:
                    msg = (
                        f"Weak elliptic curve '{_s(curve_arg)}' (< 224 bits) "
                        f"passed to EC_GROUP_new_by_curve_name(). "
                        f"Use P-256 (secp256r1) or stronger (CWE-326)."
                    )
                    _emit(self.checker_id, self.cwe, self.severity, msg, tok)
                continue

            if fname not in _KEY_GEN_FUNCS:
                continue
            if not _is_function_call(tok):
                continue

            arg_idx, min_bits = _KEY_GEN_FUNCS[fname]
            if min_bits == 0:
                continue   # handled by curve-name branch above

            bits_arg = _arg_at(tok, arg_idx)
            if bits_arg is None:
                continue

            bits_val = _int_value(bits_arg)
            if bits_val is None:
                continue

            if bits_val < min_bits:
                msg = (
                    f"Key size {bits_val} bits passed to '{fname}()' is below "
                    f"the minimum recommended {min_bits} bits. "
                    f"Keys shorter than {min_bits} bits are vulnerable to "
                    f"factoring/discrete-log attacks (CWE-326)."
                )
                _emit(self.checker_id, self.cwe, self.severity, msg, tok)


# ---------------------------------------------------------------------------
# CPC-08  non_constant_time_compare  (CWE-385)
# ---------------------------------------------------------------------------

class _CPC08_NonConstantTimeCompare(_BaseChecker):
    checker_id = "CPC-08"
    cwe        = 385
    severity   = "warning"

    def check(self, cfg) -> None:
        for tok in _tokens(cfg):
            fname = _s(tok)
            if fname not in _TIMING_COMPARE_FUNCS:
                continue
            if not _is_function_call(tok):
                continue

            args = _call_args(tok)
            secret_args = [
                _var_name(a)
                for a in args
                if _SECRET_COMPARE_RE.search(_var_name(a))
            ]
            if not secret_args:
                continue

            secret_list = ", ".join(f"'{n}'" for n in secret_args)
            msg = (
                f"'{fname}()' used to compare secret-named buffer(s) "
                f"{secret_list}. Variable-time comparison enables timing "
                f"side-channel attacks that can recover secret values. "
                f"Use CRYPTO_memcmp(), timingsafe_bcmp(), or "
                f"mbedtls_ssl_safer_memcmp() (CWE-385)."
            )
            _emit(self.checker_id, self.cwe, self.severity, msg, tok)


# ---------------------------------------------------------------------------
# CPC-09  deprecated_tls_version  (CWE-327)
# ---------------------------------------------------------------------------

class _CPC09_DeprecatedTLS(_BaseChecker):
    checker_id = "CPC-09"
    cwe        = 327
    severity   = "error"

    def check(self, cfg) -> None:
        for tok in _tokens(cfg):
            name = _s(tok)

            # Deprecated method factory functions
            if name in _DEPRECATED_TLS_METHODS and _is_function_call(tok):
                version = self._version_from_method(name)
                msg = (
                    f"Deprecated TLS/SSL method '{name}()' selects {version}. "
                    f"SSLv2, SSLv3, TLS 1.0, and TLS 1.1 have known "
                    f"cryptographic weaknesses (POODLE, BEAST, DROWN). "
                    f"Use TLS_method() with SSL_CTX_set_min_proto_version"
                    f"(ctx, TLS1_2_VERSION) (CWE-327)."
                )
                _emit(self.checker_id, self.cwe, self.severity, msg, tok)
                continue

            # Version constants / option flags used directly
            if name in _DEPRECATED_TLS_CONSTANTS:
                msg = (
                    f"Deprecated TLS version constant '{name}' in use. "
                    f"This selects or enables a protocol version with known "
                    f"vulnerabilities. Enforce TLS 1.2+ as the minimum "
                    f"(CWE-327)."
                )
                _emit(self.checker_id, self.cwe, self.severity, msg, tok)
                continue

            # SSL_OP_NO_TLSv1_2 disabling forces downgrade
            if name in _DEPRECATED_TLS_OPTIONS:
                msg = (
                    f"Option '{name}' disables a modern TLS version, "
                    f"potentially forcing downgrade to a vulnerable protocol. "
                    f"Remove this option unless there is a documented "
                    f"operational requirement (CWE-327)."
                )
                _emit(self.checker_id, self.cwe, self.severity, msg, tok)

    @staticmethod
    def _version_from_method(name: str) -> str:
        nl = name.lower()
        if "sslv2" in nl:
            return "SSLv2"
        if "sslv3" in nl:
            return "SSLv3"
        if "tlsv1_1" in nl or "tls1_1" in nl:
            return "TLS 1.1"
        if "tlsv1" in nl or "tls1" in nl:
            return "TLS 1.0"
        if "dtls" in nl:
            return "DTLSv1.0"
        return "a deprecated version"


# ---------------------------------------------------------------------------
# CPC-10  ssl_verification_disabled  (CWE-295)
# ---------------------------------------------------------------------------

class _CPC10_SSLVerifyDisabled(_BaseChecker):
    checker_id = "CPC-10"
    cwe        = 295
    severity   = "error"

    def check(self, cfg) -> None:
        for tok in _tokens(cfg):
            # Pattern 1: SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, cb)
            if _s(tok) == "SSL_CTX_set_verify" and _is_function_call(tok):
                mode_arg = _arg_at(tok, 1)
                if mode_arg is not None and _s(mode_arg) in _SSL_VERIFY_NONE:
                    msg = (
                        "SSL_CTX_set_verify() called with SSL_VERIFY_NONE. "
                        "This disables certificate chain and hostname "
                        "verification, enabling trivial man-in-the-middle "
                        "attacks. Use SSL_VERIFY_PEER | "
                        "SSL_VERIFY_FAIL_IF_NO_PEER_CERT (CWE-295)."
                    )
                    _emit(self.checker_id, self.cwe, self.severity, msg, tok)
                continue

            # Pattern 2: SSL_set_verify(ssl, SSL_VERIFY_NONE, cb)
            if _s(tok) == "SSL_set_verify" and _is_function_call(tok):
                mode_arg = _arg_at(tok, 1)
                if mode_arg is not None and _s(mode_arg) in _SSL_VERIFY_NONE:
                    msg = (
                        "SSL_set_verify() called with SSL_VERIFY_NONE — "
                        "peer certificate validation disabled (CWE-295)."
                    )
                    _emit(self.checker_id, self.cwe, self.severity, msg, tok)
                continue

            # Pattern 3: curl_easy_setopt(h, CURLOPT_SSL_VERIFYPEER, 0L)
            if _s(tok) == "curl_easy_setopt" and _is_function_call(tok):
                opt_arg = _arg_at(tok, 1)
                val_arg = _arg_at(tok, 2)
                if opt_arg is None or val_arg is None:
                    continue
                opt_name = _s(opt_arg)
                if opt_name in _CURL_VERIFY_OPTIONS:
                    val = _int_value(val_arg)
                    if val == 0:
                        msg = (
                            f"curl_easy_setopt(..., {opt_name}, 0) disables "
                            f"SSL/TLS certificate or hostname verification. "
                            f"This permits MITM attacks. "
                            f"Set to 1L (CWE-295)."
                        )
                        _emit(self.checker_id, self.cwe, self.severity, msg,
                              tok)
                continue

            # Pattern 4: mbedtls_ssl_conf_authmode(..., MBEDTLS_SSL_VERIFY_NONE)
            if (_s(tok) == "mbedtls_ssl_conf_authmode"
                    and _is_function_call(tok)):
                mode_arg = _arg_at(tok, 1)
                if (mode_arg is not None
                        and _s(mode_arg) == "MBEDTLS_SSL_VERIFY_NONE"):
                    msg = (
                        "mbedtls_ssl_conf_authmode() set to "
                        "MBEDTLS_SSL_VERIFY_NONE disables peer certificate "
                        "verification (CWE-295)."
                    )
                    _emit(self.checker_id, self.cwe, self.severity, msg, tok)


# ---------------------------------------------------------------------------
# CPC-11  unauthenticated_encryption  (CWE-311)
# ---------------------------------------------------------------------------

class _CPC11_UnauthenticatedEncryption(_BaseChecker):
    """
    Flags non-AEAD encryption calls that have no adjacent authentication
    call (HMAC, GCM, CCM, Poly1305) within a heuristic token window.

    This is inherently a heuristic — encrypt-then-MAC in separate functions
    will produce false positives, so severity is 'warning'.
    """
    checker_id = "CPC-11"
    cwe        = 311
    severity   = "warning"

    _WINDOW = 80   # tokens to scan before/after for auth calls

    def check(self, cfg) -> None:
        for tok in _tokens(cfg):
            fname = _s(tok)
            if fname not in _UNAUTH_ENC_FUNCS:
                continue
            if not _is_function_call(tok):
                continue

            nearby = _surrounding_function_calls(tok, self._WINDOW)
            has_auth = bool(nearby & _AUTH_ENC_FUNCS)
            if has_auth:
                continue

            msg = (
                f"Encryption function '{fname}()' called without a nearby "
                f"authentication primitive (HMAC, GCM, CCM, Poly1305). "
                f"CBC and CTR modes provide confidentiality only — without "
                f"integrity protection an attacker can flip bits and perform "
                f"padding-oracle attacks. Use AES-GCM or encrypt-then-HMAC "
                f"(CWE-311)."
            )
            _emit(self.checker_id, self.cwe, self.severity, msg, tok)


# ---------------------------------------------------------------------------
# CPC-12  hardcoded_salt_constant  (CWE-321)
# ---------------------------------------------------------------------------

class _CPC12_HardcodedSalt(_BaseChecker):
    """
    Flags KDF function calls where the salt argument is a short/constant
    string literal or an all-same-byte literal array.
    """
    checker_id = "CPC-12"
    cwe        = 321
    severity   = "warning"

    # salt argument index for each KDF
    _SALT_ARG: Dict[str, int] = {
        "PKCS5_PBKDF2_HMAC":        3,
        "PKCS5_PBKDF2_HMAC_SHA1":   1,
        "EVP_PBE_scrypt":            1,
        "mbedtls_pkcs5_pbkdf2_hmac": 2,
        "wc_PBKDF2":                 2,
        "wc_PBKDF1":                 2,
        "crypto_pwhash":             3,
    }

    _MAX_SAFE_SALT_LEN = 8   # salts ≤ 8 bytes are suspiciously short

    def check(self, cfg) -> None:
        for tok in _tokens(cfg):
            fname = _s(tok)
            if fname not in self._SALT_ARG:
                continue
            if not _is_function_call(tok):
                continue

            salt_idx  = self._SALT_ARG[fname]
            salt_arg  = _arg_at(tok, salt_idx)
            if salt_arg is None:
                continue

            # Case A: string literal salt
            if _is_string_literal(salt_arg):
                val = _string_literal_value(salt_arg)
                if len(val) <= self._MAX_SAFE_SALT_LEN:
                    msg = (
                        f"Short string literal ('{val}', {len(val)} bytes) "
                        f"used as salt in '{fname}()'. "
                        f"A short constant salt provides minimal protection "
                        f"against rainbow-table attacks. "
                        f"Use at least 16 random bytes from RAND_bytes() "
                        f"(CWE-321)."
                    )
                    _emit(self.checker_id, self.cwe, self.severity, msg,
                          salt_arg)
                    continue
                # Long literal — still a constant, flag it
                msg = (
                    f"Constant string literal used as KDF salt in "
                    f"'{fname}()'. Even a long constant salt is shared "
                    f"across all passwords and enables pre-computation "
                    f"(CWE-321). Use a per-user random salt."
                )
                _emit(self.checker_id, self.cwe, self.severity, msg, salt_arg)
                continue

            # Case B: NULL salt
            if _s(salt_arg) in ("NULL", "0", "nullptr"):
                msg = (
                    f"NULL salt passed to KDF '{fname}()'. "
                    f"A missing salt collapses the KDF to an unsalted hash "
                    f"and enables rainbow-table attacks (CWE-321)."
                )
                _emit(self.checker_id, self.cwe, self.severity, msg, salt_arg)
                continue

            # Case C: variable whose name looks like a constant salt
            salt_name = _var_name(salt_arg).lower()
            if any(kw in salt_name for kw in
                   ("const", "fixed", "static", "hardcoded", "default")):
                msg = (
                    f"Variable '{_var_name(salt_arg)}' name suggests a "
                    f"constant salt passed to '{fname}()'. "
                    f"Verify that this salt is unique per user/credential "
                    f"(CWE-321)."
                )
                _emit(self.checker_id, self.cwe, self.severity, msg, salt_arg)


# ===========================================================================
# §8  Registry and runner
# ===========================================================================

_ALL_CHECKERS: List[_BaseChecker] = [
    _CPC01_WeakHash(),
    _CPC02_WeakCipher(),
    _CPC03_HardcodedKey(),
    _CPC04_NullIV(),
    _CPC05_ECBMode(),
    _CPC06_WeakPRNG(),
    _CPC07_InsufficientKeySize(),
    _CPC08_NonConstantTimeCompare(),
    _CPC09_DeprecatedTLS(),
    _CPC10_SSLVerifyDisabled(),
    _CPC11_UnauthenticatedEncryption(),
    _CPC12_HardcodedSalt(),
]


def analyse(filename: str, *, checkers=None) -> None:
    """Parse one cppcheck .dump file and run all checkers."""
    if checkers is None:
        checkers = _ALL_CHECKERS
    try:
        data = cppcheckdata.CppcheckData(filename)
    except Exception as exc:
        sys.stderr.write(
            f"CryptoProtocolChecker: failed to parse '{filename}': {exc}\n"
        )
        return
    for cfg in data.configurations:
        for chk in checkers:
            try:
                chk.check(cfg)
            except Exception as exc:
                sys.stderr.write(
                    f"CryptoProtocolChecker: checker {chk.checker_id} "
                    f"raised {type(exc).__name__}: {exc}\n"
                )


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write(
            "Usage: python3 CryptoProtocolChecker.py <file.c.dump> [...]\n"
            "       Produce dumps with: cppcheck --dump <source.c>\n"
        )
        sys.exit(1)
    for _dump in sys.argv[1:]:
        analyse(_dump)
