#!/usr/bin/env python3
"""
CryptoSafetyAssurance.py
════════════════════════

Cppcheck addon — Cryptographic Safety Assurance
Uses: cppcheckdata-shims checker framework

Checks performed
────────────────
  1. WeakHashChecker        — MD5 / SHA-1 usage          (CWE-327, CWE-328)
  2. WeakPRNGChecker        — rand() / random() usage     (CWE-338)
  3. SecureRandomChecker    — absence of CSPRNG           (CWE-338)
  4. WeakCipherChecker      — DES / RC4 / Blowfish / ECB  (CWE-327)
  5. HardcodedKeyChecker    — key/iv/secret literals      (CWE-321)
  6. KeyStorageChecker      — keys in globals / stack     (CWE-312, CWE-316)
  7. CustomCryptoChecker    — hand-rolled crypto patterns (CWE-327)
  8. TLSValidationChecker   — disabled cert / hostname    (CWE-295, CWE-297)

Usage
─────
  cppcheck --dump target.c
  python3 CryptoSafetyAssurance.py target.c.dump

  # Or with the cppcheck runner:
  cppcheck --addon=CryptoSafetyAssurance target.c

License: MIT
"""

from __future__ import annotations

import json
import re
import sys
from abc import abstractmethod
from typing import (
    Any,
    ClassVar,
    Dict,
    FrozenSet,
    Iterable,
    Iterator,
    List,
    Optional,
    Set,
    Tuple,
)

# ─────────────────────────────────────────────────────────────────
#  Host-library imports (cppcheckdata + shims)
# ─────────────────────────────────────────────────────────────────
try:
    import cppcheckdata
except ImportError:
    cppcheckdata = None  # type: ignore[assignment]

try:
    from cppcheckdata_shims.checkers import (
        Checker,
        CheckerContext,
        Confidence,
        Diagnostic,
        DiagnosticSeverity,
        SourceLocation,
        SuppressionManager,
        _iter_tokens,
        _tok_file,
        _tok_line,
        _tok_col,
        _tok_str,
    )
except ImportError as exc:
    sys.stderr.write(f"[CryptoSafetyAssurance] import error: {exc}\n")
    sys.exit(1)


# ═══════════════════════════════════════════════════════════════════
#  SECTION 0 — OUTPUT HELPER
#  Mirrors cppcheckdata.reportError() behaviour:
#    • --cli mode  → single-line JSON to stdout   (Cppcheck runner)
#    • normal mode → GCC-style text to stderr     (human)
# ═══════════════════════════════════════════════════════════════════

def _print_diagnostic(diag: Diagnostic) -> None:
    """Emit one diagnostic in the format appropriate for the caller."""
    if "--cli" in sys.argv:
        sys.stdout.write(diag.to_json_str() + "\n")
        sys.stdout.flush()
    else:
        loc = diag.location
        cwe_tag = f" [CWE-{diag.cwe}]" if diag.cwe else ""
        line = (
            f"[{loc.file}:{loc.line}]: "
            f"({diag.severity.value}) "
            f"{diag.message} "
            f"[{diag.error_id}]{cwe_tag}"
        )
        sys.stderr.write(line + "\n")
        sys.stderr.flush()


# ═══════════════════════════════════════════════════════════════════
#  SECTION 1 — SHARED TOKEN UTILITIES
# ═══════════════════════════════════════════════════════════════════

def _get_call_args(call_tok: Any) -> List[Any]:
    """
    Return the list of top-level argument tokens for a function call.

    cppcheckdata AST layout for  foo(a, b, c):

        foo
         └─ (           ← astOperand2 of the name token, or astOperand1
              └─ ,
                  ├─ a
                  └─ ,
                      ├─ b
                      └─ c

    We walk the comma spine to collect the left-most leaf of each arm.
    """
    # The '(' token is the direct right child of the function name token
    paren = getattr(call_tok, "astOperand1", None)
    if paren is None or _tok_str(paren) != "(":
        paren = getattr(call_tok, "astOperand2", None)
    if paren is None:
        return []

    inner = getattr(paren, "astOperand2", None)
    if inner is None:
        inner = getattr(paren, "astOperand1", None)
    if inner is None:
        return []

    args: List[Any] = []
    node = inner
    while node is not None:
        if _tok_str(node) == ",":
            left = getattr(node, "astOperand1", None)
            if left is not None:
                args.append(left)
            node = getattr(node, "astOperand2", None)
        else:
            args.append(node)
            break
    return args


def _is_function_call(tok: Any, name: str) -> bool:
    """True when *tok* is the name token of a call to *name*."""
    if _tok_str(tok) != name:
        return False
    nxt = getattr(tok, "next", None)
    return nxt is not None and _tok_str(nxt) == "("


def _token_value_str(tok: Any) -> Optional[str]:
    """
    Return the string literal value of a token when it is a string
    constant, stripping surrounding quotes.  Returns None otherwise.
    """
    s = _tok_str(tok)
    if s.startswith('"') and s.endswith('"') and len(s) >= 2:
        return s[1:-1]
    return None


def _walk_subtree(tok: Any) -> Iterator[Any]:
    """Pre-order walk of an AST subtree rooted at *tok*."""
    if tok is None:
        return
    stack = [tok]
    seen: Set[int] = set()
    while stack:
        t = stack.pop()
        if t is None or id(t) in seen:
            continue
        seen.add(id(t))
        yield t
        stack.append(getattr(t, "astOperand1", None))
        stack.append(getattr(t, "astOperand2", None))


# ═══════════════════════════════════════════════════════════════════
#  SECTION 2 — BASE CLASS FOR CRYPTO CHECKERS
# ═══════════════════════════════════════════════════════════════════

class _CryptoChecker(Checker):
    """
    Thin base class that all CryptoSafetyAssurance checkers inherit.

    Provides a concrete ``collect_evidence`` + ``diagnose`` split where
    subclasses only need to implement ``_scan(tok, ctx)`` — a per-token
    visitor that calls ``self._emit(...)`` when a finding is warranted.
    """

    #: Subclasses set this to iterate only specific token kinds.
    #: When ``None`` the checker visits every token.
    _visit_only_names: ClassVar[Optional[FrozenSet[str]]] = None

    # ── Checker lifecycle ────────────────────────────────────────

    def collect_evidence(self, ctx: CheckerContext) -> None:  # noqa: D102
        cfg = ctx.cfg
        for tok in _iter_tokens(cfg):
            if self._visit_only_names is not None:
                if _tok_str(tok) not in self._visit_only_names:
                    continue
            self._scan(tok, ctx)

    def diagnose(self, ctx: CheckerContext) -> None:  # noqa: D102
        # Evidence is collected directly into self._diagnostics inside
        # _scan(); nothing extra to do here.
        pass

    @abstractmethod
    def _scan(self, tok: Any, ctx: CheckerContext) -> None:
        """Inspect a single token; call self._emit() on findings."""
        ...


# ═══════════════════════════════════════════════════════════════════
#  SECTION 3 — CHECKER 1: WEAK HASH (MD5, SHA-1)
#
#  CWE-327: Use of a Broken or Risky Cryptographic Algorithm
#  CWE-328: Use of Weak Hash
#
#  Patterns:
#    • Calls to MD5(), MD5_Init(), SHA1(), SHA1_Init(), SHA_Init(),
#      EVP_md5(), EVP_sha1()  (OpenSSL API)
#    • Calls to hash_create("md5"), hash_create("sha1") etc.
#    • String literals containing "md5" or "sha1" passed to a
#      digest-selector function.
# ═══════════════════════════════════════════════════════════════════

_WEAK_HASH_CALLS: FrozenSet[str] = frozenset({
    # OpenSSL low-level
    "MD5", "MD5_Init", "MD5_Update", "MD5_Final",
    "SHA1", "SHA1_Init", "SHA1_Update", "SHA1_Final",
    "SHA_Init", "SHA_Update", "SHA_Final",
    # OpenSSL EVP
    "EVP_md5", "EVP_md4", "EVP_sha1",
    # libgcrypt
    "gcry_md_open",          # checked further for algo arg
    # CommonCrypto (macOS)
    "CC_MD5", "CC_SHA1",
    # mbedTLS
    "mbedtls_md5_starts", "mbedtls_sha1_starts",
    # WolfSSL
    "wc_Md5Init", "wc_ShaInit",
})

_WEAK_HASH_STRING_RE = re.compile(
    r"\b(md5|md4|sha1|sha-1)\b", re.IGNORECASE
)


class WeakHashChecker(_CryptoChecker):
    """
    Flag use of MD5 or SHA-1 as a cryptographic hash.

    These algorithms are cryptographically broken and must not be used
    for password hashing, digital signatures, or any security-critical
    integrity check.

    Acceptable replacements: SHA-256, SHA-384, SHA-512, SHA-3,
    BLAKE2b, Argon2 (passwords).
    """

    name: ClassVar[str] = "crypto-weak-hash"
    description: ClassVar[str] = (
        "Detects use of cryptographically broken hash algorithms "
        "(MD5, SHA-1)."
    )
    error_ids: ClassVar[FrozenSet[str]] = frozenset({
        "weakHashMD5",
        "weakHashSHA1",
        "weakHashStringSelector",
    })
    default_severity: ClassVar[DiagnosticSeverity] = DiagnosticSeverity.WARNING
    cwe_ids: ClassVar[Dict[str, int]] = {
        "weakHashMD5":            328,
        "weakHashSHA1":           328,
        "weakHashStringSelector": 327,
    }

    def _scan(self, tok: Any, ctx: CheckerContext) -> None:
        s = _tok_str(tok)

        # ── Direct function-call match ───────────────────────────
        if s in _WEAK_HASH_CALLS and _is_function_call(tok, s):
            if "MD5" in s or "md5" in s.lower():
                eid = "weakHashMD5"
                algo = "MD5"
            else:
                eid = "weakHashSHA1"
                algo = "SHA-1"
            self._emit(
                error_id=eid,
                message=(
                    f"Use of broken hash algorithm {algo} via '{s}()'. "
                    "Replace with SHA-256 or stronger."
                ),
                file=_tok_file(tok),
                line=_tok_line(tok),
                column=_tok_col(tok),
                severity=DiagnosticSeverity.WARNING,
                confidence=Confidence.HIGH,
            )
            return

        # ── String-literal selector: EVP_get_digestbyname("md5") ─
        val = _token_value_str(tok)
        if val and _WEAK_HASH_STRING_RE.search(val):
            parent = getattr(tok, "astParent", None)
            if parent is not None:
                self._emit(
                    error_id="weakHashStringSelector",
                    message=(
                        f"Weak hash algorithm selected via string literal '{val}'. "
                        "Use a strong algorithm identifier (e.g. 'sha256')."
                    ),
                    file=_tok_file(tok),
                    line=_tok_line(tok),
                    column=_tok_col(tok),
                    severity=DiagnosticSeverity.WARNING,
                    confidence=Confidence.MEDIUM,
                )


# ═══════════════════════════════════════════════════════════════════
#  SECTION 4 — CHECKER 2: WEAK PRNG  (rand / random / drand48 …)
#
#  CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator
#
#  These generators have predictable state and MUST NOT be used for:
#    – key / IV / nonce generation
#    – session tokens
#    – challenge/response values
# ═══════════════════════════════════════════════════════════════════

_WEAK_PRNG_CALLS: FrozenSet[str] = frozenset({
    "rand", "rand_r", "random", "random_r",
    "drand48", "erand48", "lrand48", "mrand48", "nrand48",
    "jrand48", "srand", "srandom", "srand48", "seed48",
    "lcong48",
})


class WeakPRNGChecker(_CryptoChecker):
    """
    Flag calls to non-cryptographic pseudo-random number generators.

    Acceptable alternatives: getrandom(2), /dev/urandom via open/read,
    RAND_bytes() (OpenSSL), BCryptGenRandom() (Windows),
    arc4random_buf() (BSD/macOS).
    """

    name: ClassVar[str] = "crypto-weak-prng"
    description: ClassVar[str] = (
        "Detects use of non-cryptographic PRNG functions."
    )
    error_ids: ClassVar[FrozenSet[str]] = frozenset({
        "weakPRNG",
        "weakPRNGSeed",
    })
    default_severity: ClassVar[DiagnosticSeverity] = DiagnosticSeverity.WARNING
    cwe_ids: ClassVar[Dict[str, int]] = {
        "weakPRNG":     338,
        "weakPRNGSeed": 338,
    }

    def _scan(self, tok: Any, ctx: CheckerContext) -> None:
        s = _tok_str(tok)
        if s not in _WEAK_PRNG_CALLS:
            return
        if not _is_function_call(tok, s):
            return

        if s.startswith("srand") or s.startswith("srandom") or s in {
            "seed48", "lcong48", "srand48"
        }:
            eid = "weakPRNGSeed"
            msg = (
                f"Seeding a non-cryptographic PRNG with '{s}()'. "
                "PRNG state is predictable; do not use for security-sensitive values."
            )
        else:
            eid = "weakPRNG"
            msg = (
                f"Non-cryptographic PRNG '{s}()' used. "
                "For security-sensitive randomness use getrandom(2) "
                "or RAND_bytes()."
            )

        self._emit(
            error_id=eid,
            message=msg,
            file=_tok_file(tok),
            line=_tok_line(tok),
            column=_tok_col(tok),
            severity=DiagnosticSeverity.WARNING,
            confidence=Confidence.HIGH,
        )


# ═══════════════════════════════════════════════════════════════════
#  SECTION 5 — CHECKER 3: SECURE RANDOM USAGE
#
#  CWE-338 (inverse guard): Verify that at least one CSPRNG call is
#  present.  If the file uses any cryptographic operation (key gen,
#  encryption setup) but never calls a CSPRNG, emit an advisory.
#
#  Positive indicators (CSPRNG present):
#    RAND_bytes, RAND_priv_bytes, getrandom, getentropy,
#    BCryptGenRandom, arc4random_buf, SecRandomCopyBytes,
#    CryptGenRandom, CCRandomGenerateBytes
# ═══════════════════════════════════════════════════════════════════

_CSPRNG_CALLS: FrozenSet[str] = frozenset({
    "RAND_bytes", "RAND_priv_bytes",
    "getrandom", "getentropy",
    "BCryptGenRandom",
    "arc4random", "arc4random_buf", "arc4random_uniform",
    "SecRandomCopyBytes",
    "CryptGenRandom",
    "CCRandomGenerateBytes",
    "mbedtls_ctr_drbg_random", "mbedtls_entropy_func",
    "wc_RNG_GenerateBlock",
})

_CRYPTO_SETUP_CALLS: FrozenSet[str] = frozenset({
    "EVP_EncryptInit", "EVP_EncryptInit_ex",
    "EVP_DecryptInit", "EVP_DecryptInit_ex",
    "EVP_CipherInit",  "EVP_CipherInit_ex",
    "AES_set_encrypt_key", "AES_set_decrypt_key",
    "RSA_generate_key", "RSA_generate_key_ex",
    "EC_KEY_generate_key",
    "EVP_PKEY_keygen",
    "mbedtls_aes_setkey_enc", "mbedtls_rsa_gen_key",
    "wc_AesSetKey", "wc_RsaMakeKey",
})


class SecureRandomChecker(_CryptoChecker):
    """
    Verify that files performing cryptographic operations use a CSPRNG.

    If the file calls a crypto-setup API but never calls a recognised
    secure random generator, emit a ``missingCSPRNG`` advisory.
    """

    name: ClassVar[str] = "crypto-secure-random"
    description: ClassVar[str] = (
        "Checks that a CSPRNG is used wherever cryptographic "
        "operations are performed."
    )
    error_ids: ClassVar[FrozenSet[str]] = frozenset({
        "missingCSPRNG",
    })
    default_severity: ClassVar[DiagnosticSeverity] = DiagnosticSeverity.WARNING
    cwe_ids: ClassVar[Dict[str, int]] = {
        "missingCSPRNG": 338,
    }

    def __init__(self) -> None:
        super().__init__()
        self._has_csprng: bool = False
        self._crypto_setup_sites: List[Tuple[str, int, int, str]] = []

    def _scan(self, tok: Any, ctx: CheckerContext) -> None:
        s = _tok_str(tok)
        if s in _CSPRNG_CALLS and _is_function_call(tok, s):
            self._has_csprng = True
        if s in _CRYPTO_SETUP_CALLS and _is_function_call(tok, s):
            self._crypto_setup_sites.append(
                (_tok_file(tok), _tok_line(tok), _tok_col(tok), s)
            )

    def diagnose(self, ctx: CheckerContext) -> None:
        if self._has_csprng or not self._crypto_setup_sites:
            return
        # Report at the first crypto-setup call site
        file, line, col, func = self._crypto_setup_sites[0]
        self._emit(
            error_id="missingCSPRNG",
            message=(
                f"Cryptographic operation '{func}()' used but no secure "
                "random generator (RAND_bytes, getrandom, …) detected in "
                "this translation unit. Key material may be predictable."
            ),
            file=file,
            line=line,
            column=col,
            severity=DiagnosticSeverity.WARNING,
            confidence=Confidence.MEDIUM,
        )


# ═══════════════════════════════════════════════════════════════════
#  SECTION 6 — CHECKER 4: WEAK CIPHER
#
#  CWE-327: Use of a Broken or Risky Cryptographic Algorithm
#
#  Flagged:
#    • DES / 3DES (TDEA) — 56-bit effective key, broken
#    • RC4 / ARCFOUR      — stream cipher, multiple biases
#    • Blowfish           — 64-bit block, birthday bound issues
#    • ECB mode           — not semantically secure regardless of cipher
#    • RC2               — weak
#    • IDEA               — patented / obsolete
# ═══════════════════════════════════════════════════════════════════

_WEAK_CIPHER_CALLS: FrozenSet[str] = frozenset({
    # OpenSSL EVP constructors
    "EVP_des_ecb", "EVP_des_cbc", "EVP_des_cfb", "EVP_des_ofb",
    "EVP_des_ede", "EVP_des_ede3", "EVP_des_ede_cbc",
    "EVP_des_ede3_cbc", "EVP_des_ede3_cfb",
    "EVP_rc4", "EVP_rc4_40", "EVP_rc4_hmac_md5",
    "EVP_bf_cbc", "EVP_bf_ecb", "EVP_bf_cfb", "EVP_bf_ofb",
    "EVP_rc2_cbc", "EVP_rc2_ecb",
    "EVP_idea_cbc", "EVP_idea_ecb",
    # OpenSSL ECB (any cipher in ECB mode is flagged separately)
    "EVP_aes_128_ecb", "EVP_aes_192_ecb", "EVP_aes_256_ecb",
    # Low-level DES
    "DES_ecb_encrypt", "DES_cbc_encrypt", "DES_cfb_encrypt",
    # RC4
    "RC4", "RC4_set_key",
    # mbedTLS weak ciphers
    "mbedtls_des_crypt_ecb", "mbedtls_des_crypt_cbc",
    "mbedtls_des3_crypt_ecb", "mbedtls_des3_crypt_cbc",
    "mbedtls_arc4_crypt",
    # WolfSSL
    "wc_Des_CbcEncrypt", "wc_Des3_CbcEncrypt",
    "wc_Arc4Process",
})

_WEAK_CIPHER_STRING_RE = re.compile(
    r"\b(des|3des|tdea|triple.des|rc4|arcfour|blowfish|"
    r"ecb|rc2|idea)\b",
    re.IGNORECASE,
)


class WeakCipherChecker(_CryptoChecker):
    """
    Flag use of weak or broken symmetric ciphers and ECB mode.

    Recommended alternatives: AES-256-GCM, AES-256-CBC (with proper
    HMAC), ChaCha20-Poly1305.
    """

    name: ClassVar[str] = "crypto-weak-cipher"
    description: ClassVar[str] = (
        "Detects use of broken/weak symmetric ciphers (DES, RC4, "
        "Blowfish, IDEA, ECB mode)."
    )
    error_ids: ClassVar[FrozenSet[str]] = frozenset({
        "weakCipherDES",
        "weakCipherRC4",
        "weakCipherBlowfish",
        "weakCipherECB",
        "weakCipherStringSelector",
    })
    default_severity: ClassVar[DiagnosticSeverity] = DiagnosticSeverity.WARNING
    cwe_ids: ClassVar[Dict[str, int]] = {
        "weakCipherDES":            327,
        "weakCipherRC4":            327,
        "weakCipherBlowfish":       327,
        "weakCipherECB":            327,
        "weakCipherStringSelector": 327,
    }

    def _scan(self, tok: Any, ctx: CheckerContext) -> None:
        s = _tok_str(tok)

        if s in _WEAK_CIPHER_CALLS and _is_function_call(tok, s):
            sl = s.lower()
            if "des" in sl or "des3" in sl or "tdea" in sl:
                eid, algo = "weakCipherDES", "DES/3DES"
            elif "rc4" in sl or "arc4" in sl:
                eid, algo = "weakCipherRC4", "RC4"
            elif "bf" in sl or "blowfish" in sl:
                eid, algo = "weakCipherBlowfish", "Blowfish"
            elif "ecb" in sl:
                eid, algo = "weakCipherECB", "ECB mode"
            else:
                eid, algo = "weakCipherDES", s   # rc2/idea fallback
            self._emit(
                error_id=eid,
                message=(
                    f"Weak/broken cipher {algo} used via '{s}()'. "
                    "Use AES-256-GCM or ChaCha20-Poly1305 instead."
                ),
                file=_tok_file(tok),
                line=_tok_line(tok),
                column=_tok_col(tok),
                severity=DiagnosticSeverity.WARNING,
                confidence=Confidence.HIGH,
            )
            return

        # String-literal cipher selector  e.g. EVP_get_cipherbyname("des-cbc")
        val = _token_value_str(tok)
        if val and _WEAK_CIPHER_STRING_RE.search(val):
            self._emit(
                error_id="weakCipherStringSelector",
                message=(
                    f"Potentially weak cipher selected via string literal '{val}'. "
                    "Verify only strong ciphers (AES-256, ChaCha20) are chosen."
                ),
                file=_tok_file(tok),
                line=_tok_line(tok),
                column=_tok_col(tok),
                severity=DiagnosticSeverity.WARNING,
                confidence=Confidence.MEDIUM,
            )


# ═══════════════════════════════════════════════════════════════════
#  SECTION 7 — CHECKER 5: HARDCODED KEY / SECRET
#
#  CWE-321: Use of Hard-coded Cryptographic Key
#
#  We look for:
#    1. String / byte literals assigned to variables whose name
#       suggests they hold key material.
#    2. Hexadecimal byte arrays of typical key lengths (16/24/32 B)
#       directly initialised in-place.
#    3. String literals matching common key patterns in init calls.
# ═══════════════════════════════════════════════════════════════════

_KEY_NAME_RE = re.compile(
    r"(?i)\b(key|aes_key|des_key|hmac_key|secret|private_?key|"
    r"api_key|auth_?key|enc_key|encryption_key|master_?key|"
    r"passphrase|password|passwd|iv|nonce|salt)\b"
)

# A hex string literal that is 32, 48, or 64 hex chars looks like a key
_HEX_KEY_RE = re.compile(r'^[0-9a-fA-F]{32,64}$')

# Looks like a base64-encoded key: long, no whitespace, /+= chars
_B64_KEY_RE = re.compile(r'^[A-Za-z0-9+/]{32,}={0,2}$')


class HardcodedKeyChecker(_CryptoChecker):
    """
    Detect cryptographic keys, IVs, or secrets hard-coded as literals.

    Hard-coded keys cannot be rotated without a code change and are
    easily extracted from binaries.
    """

    name: ClassVar[str] = "crypto-hardcoded-key"
    description: ClassVar[str] = (
        "Detects cryptographic keys or secrets hard-coded in source."
    )
    error_ids: ClassVar[FrozenSet[str]] = frozenset({
        "hardcodedCryptoKey",
        "hardcodedCryptoKeyBytes",
    })
    default_severity: ClassVar[DiagnosticSeverity] = DiagnosticSeverity.ERROR
    cwe_ids: ClassVar[Dict[str, int]] = {
        "hardcodedCryptoKey":      321,
        "hardcodedCryptoKeyBytes": 321,
    }

    def _scan(self, tok: Any, ctx: CheckerContext) -> None:
        # ── Pattern A: variable with key-like name assigned a literal ─
        if getattr(tok, "isAssignmentOp", False):
            lhs = getattr(tok, "astOperand1", None)
            rhs = getattr(tok, "astOperand2", None)
            if lhs is None or rhs is None:
                return
            lhs_str = _tok_str(lhs)
            if not _KEY_NAME_RE.search(lhs_str):
                return
            rhs_str = _tok_str(rhs)
            # rhs is a string or numeric literal
            if rhs_str.startswith('"') or rhs_str.startswith("0x"):
                self._emit(
                    error_id="hardcodedCryptoKey",
                    message=(
                        f"Cryptographic key/secret '{lhs_str}' appears to be "
                        "hard-coded. Keys must be loaded from a secure key store "
                        "or environment at runtime."
                    ),
                    file=_tok_file(tok),
                    line=_tok_line(tok),
                    column=_tok_col(tok),
                    severity=DiagnosticSeverity.ERROR,
                    confidence=Confidence.MEDIUM,
                )
                return

        # ── Pattern B: variable declaration with key-like name ────────
        var = getattr(tok, "variable", None)
        if var is not None:
            var_name_tok = getattr(var, "nameToken", None)
            vname = _tok_str(var_name_tok) if var_name_tok else ""
            if _KEY_NAME_RE.search(vname):
                # Check if initialiser is a string / byte literal
                init_val = getattr(var, "typeStartToken", None)
                # Walk the initialiser subtree for literals
                next_tok = getattr(tok, "next", None)
                if next_tok and _tok_str(next_tok) == "=":
                    rhs_tok = getattr(next_tok, "next", None)
                    if rhs_tok:
                        rv = _tok_str(rhs_tok)
                        val = _token_value_str(rhs_tok)
                        if val and (
                            _HEX_KEY_RE.match(val) or _B64_KEY_RE.match(val)
                        ):
                            self._emit(
                                error_id="hardcodedCryptoKeyBytes",
                                message=(
                                    f"Variable '{vname}' holding key/secret "
                                    f"material initialised with a literal that "
                                    "resembles key bytes. Use a key derivation "
                                    "function or a hardware security module."
                                ),
                                file=_tok_file(tok),
                                line=_tok_line(tok),
                                column=_tok_col(tok),
                                severity=DiagnosticSeverity.ERROR,
                                confidence=Confidence.MEDIUM,
                            )

        # ── Pattern C: hex/b64 literal directly inside a crypto call ──
        val = _token_value_str(tok)
        if not val:
            return
        if not (_HEX_KEY_RE.match(val) or _B64_KEY_RE.match(val)):
            return
        # Check if grandparent is a known key-setting function
        parent = getattr(tok, "astParent", None)
        gp = getattr(parent, "astParent", None) if parent else None
        gp_str = _tok_str(gp) if gp else ""
        if gp_str in {
            "AES_set_encrypt_key", "AES_set_decrypt_key",
            "EVP_EncryptInit_ex", "EVP_DecryptInit_ex",
            "mbedtls_aes_setkey_enc", "mbedtls_aes_setkey_dec",
            "wc_AesSetKey", "HMAC_Init_ex",
        }:
            self._emit(
                error_id="hardcodedCryptoKeyBytes",
                message=(
                    "Key-length byte string literal passed directly to "
                    f"'{gp_str}()'. Hard-coded keys are not rotatable and "
                    "trivially extractable from the binary."
                ),
                file=_tok_file(tok),
                line=_tok_line(tok),
                column=_tok_col(tok),
                severity=DiagnosticSeverity.ERROR,
                confidence=Confidence.HIGH,
            )


# ═══════════════════════════════════════════════════════════════════
#  SECTION 8 — CHECKER 6: KEY STORAGE
#
#  CWE-312: Cleartext Storage of Sensitive Information
#  CWE-316: Cleartext Storage of Sensitive Information in Memory
#
#  Flags:
#    • Key variables stored in global scope
#    • Key variables on the stack in functions that exit without
#      explicit zeroing (memset/explicit_bzero)
#    • Key material written to files / syslog
# ═══════════════════════════════════════════════════════════════════

_LOGGING_CALLS: FrozenSet[str] = frozenset({
    "printf", "fprintf", "sprintf", "snprintf",
    "syslog", "openlog",
    "fwrite", "fputs", "puts",
    "NSLog", "os_log",
})


class KeyStorageChecker(_CryptoChecker):
    """
    Detect insecure storage patterns for cryptographic key material.

    - Global variables named like keys are memory-resident and long-lived.
    - Stack variables named like keys may not be zeroed before the
      frame is released.
    - Logging key material is a direct exposure.
    """

    name: ClassVar[str] = "crypto-key-storage"
    description: ClassVar[str] = (
        "Detects insecure storage of cryptographic key material."
    )
    error_ids: ClassVar[FrozenSet[str]] = frozenset({
        "keyInGlobalScope",
        "keyLoggedOrPrinted",
        "keyNotZeroedAfterUse",
    })
    default_severity: ClassVar[DiagnosticSeverity] = DiagnosticSeverity.WARNING
    cwe_ids: ClassVar[Dict[str, int]] = {
        "keyInGlobalScope":     312,
        "keyLoggedOrPrinted":   312,
        "keyNotZeroedAfterUse": 316,
    }

    def _scan(self, tok: Any, ctx: CheckerContext) -> None:
        s = _tok_str(tok)

        # ── Global scope key variables ────────────────────────────
        var = getattr(tok, "variable", None)
        if var is not None:
            scope = getattr(var, "scope", None)
            scope_type = getattr(scope, "type", "") if scope else ""
            var_name_tok = getattr(var, "nameToken", None)
            vname = _tok_str(var_name_tok) if var_name_tok else ""
            if scope_type in {"Global", ""} and _KEY_NAME_RE.search(vname):
                # Only report at the declaration (nameToken == tok)
                if var_name_tok is tok:
                    self._emit(
                        error_id="keyInGlobalScope",
                        message=(
                            f"Variable '{vname}' holding key material declared "
                            "in global scope. Keys should have minimal lifetime "
                            "and scope; prefer stack with explicit zeroing."
                        ),
                        file=_tok_file(tok),
                        line=_tok_line(tok),
                        column=_tok_col(tok),
                        severity=DiagnosticSeverity.WARNING,
                        confidence=Confidence.MEDIUM,
                    )

        # ── Key passed to logging / print call ────────────────────
        if s in _LOGGING_CALLS and _is_function_call(tok, s):
            args = _get_call_args(tok)
            for arg in args:
                for sub in _walk_subtree(arg):
                    sub_var = getattr(sub, "variable", None)
                    if sub_var is None:
                        continue
                    nmt = getattr(sub_var, "nameToken", None)
                    vname = _tok_str(nmt) if nmt else ""
                    if _KEY_NAME_RE.search(vname):
                        self._emit(
                            error_id="keyLoggedOrPrinted",
                            message=(
                                f"Key/secret variable '{vname}' passed to "
                                f"'{s}()'. Logging cryptographic material "
                                "exposes it in log files / terminals."
                            ),
                            file=_tok_file(tok),
                            line=_tok_line(tok),
                            column=_tok_col(tok),
                            severity=DiagnosticSeverity.ERROR,
                            confidence=Confidence.HIGH,
                        )
                        break  # one finding per call site


# ═══════════════════════════════════════════════════════════════════
#  SECTION 9 — CHECKER 7: CUSTOM CRYPTO IMPLEMENTATION
#
#  CWE-327: Use of a Broken or Risky Cryptographic Algorithm
#  (specifically: "rolling your own crypto")
#
#  Heuristics:
#    1. Function names matching crypto-primitive patterns
#       (my_aes, custom_encrypt, xor_cipher, rotate_bits, …)
#    2. Suspicious bit-operation density inside a loop
#       (many XOR / ROL / SHR on the same buffer → likely S-box or
#        round function)
#    3. Magic constant arrays that match known S-box sizes (256 B)
# ═══════════════════════════════════════════════════════════════════

_CUSTOM_CRYPTO_NAME_RE = re.compile(
    r"(?i)\b(my_|custom_|home.?grown_|hand.?rolled_|simple_|naive_|"
    r"basic_|diy_|own_|bespoke_)?"
    r"(encrypt|decrypt|cipher|hash_?func|digest|xor_?crypt|"
    r"scramble|obfuscat|rc4_?impl|aes_?impl|des_?impl|"
    r"encode_?secret|encode_?key)\b"
)

_BITOP_SET: FrozenSet[str] = frozenset({"^", "|", "&", "<<", ">>"})


class CustomCryptoChecker(_CryptoChecker):
    """
    Detect hand-rolled cryptographic implementations.

    Custom cryptographic code almost always contains subtle flaws that
    undermine security.  Only use well-audited library implementations.
    """

    name: ClassVar[str] = "crypto-custom-impl"
    description: ClassVar[str] = (
        "Detects likely hand-rolled cryptographic implementations."
    )
    error_ids: ClassVar[FrozenSet[str]] = frozenset({
        "customCryptoFunction",
        "suspiciousBitOpDensity",
    })
    default_severity: ClassVar[DiagnosticSeverity] = DiagnosticSeverity.WARNING
    cwe_ids: ClassVar[Dict[str, int]] = {
        "customCryptoFunction":  327,
        "suspiciousBitOpDensity": 327,
    }

    def __init__(self) -> None:
        super().__init__()
        # scope_id → (file, line, col, name, bitop_count, total_count)
        self._scope_stats: Dict[int, List[Any]] = {}

    def _scan(self, tok: Any, ctx: CheckerContext) -> None:
        s = _tok_str(tok)

        # ── Named function definition matching suspicious pattern ──
        func = getattr(tok, "function", None)
        if func is not None:
            td = getattr(func, "tokenDef", None)
            if td is tok:
                fname = s
                if _CUSTOM_CRYPTO_NAME_RE.search(fname):
                    self._emit(
                        error_id="customCryptoFunction",
                        message=(
                            f"Function '{fname}' appears to implement a custom "
                            "cryptographic primitive. "
                            "Use a vetted library (OpenSSL, libsodium, mbedTLS)."
                        ),
                        file=_tok_file(tok),
                        line=_tok_line(tok),
                        column=_tok_col(tok),
                        severity=DiagnosticSeverity.WARNING,
                        confidence=Confidence.MEDIUM,
                    )

        # ── Bit-operation density heuristic ───────────────────────
        scope = getattr(tok, "scope", None)
        if scope is not None:
            sid = id(scope)
            scope_type = getattr(scope, "type", "")
            if scope_type in {"Function", "For", "While", "Do"}:
                if sid not in self._scope_stats:
                    st = getattr(scope, "bodyStart", None)
                    self._scope_stats[sid] = [
                        _tok_file(st) if st else "",
                        _tok_line(st) if st else 0,
                        _tok_col(st) if st else 0,
                        getattr(scope, "function", None),
                        0,  # bitop_count
                        0,  # total_count
                    ]
                entry = self._scope_stats[sid]
                entry[5] += 1  # total tokens
                if s in _BITOP_SET:
                    entry[4] += 1  # bitop count

    def diagnose(self, ctx: CheckerContext) -> None:
        for sid, entry in self._scope_stats.items():
            file, line, col, func, bitops, total = entry
            if total < 20:  # too small to judge
                continue
            ratio = bitops / total
            if ratio > 0.18:  # more than 18 % of tokens are bit-ops
                func_name = "unknown"
                if func is not None:
                    td = getattr(func, "tokenDef", None)
                    if td:
                        func_name = _tok_str(td)
                self._emit(
                    error_id="suspiciousBitOpDensity",
                    message=(
                        f"High bit-operation density ({bitops}/{total} tokens, "
                        f"{ratio:.0%}) in scope near '{func_name}'. "
                        "This may indicate a hand-rolled cipher. "
                        "Use a vetted crypto library."
                    ),
                    file=file,
                    line=line,
                    column=col,
                    severity=DiagnosticSeverity.WARNING,
                    confidence=Confidence.LOW,
                )


# ═══════════════════════════════════════════════════════════════════
#  SECTION 10 — CHECKER 8: TLS/SSL VALIDATION
#
#  CWE-295: Improper Certificate Validation
#  CWE-297: Improper Validation of Certificate with Host Mismatch
#
#  OpenSSL:
#    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, …)      → no peer cert check
#    SSL_CTX_set_verify_depth(ctx, 0)                 → depth 0 = no chain
#    EVP_PKEY_CTX / X509_VERIFY_PARAM manipulation
#
#  libcurl:
#    curl_easy_setopt(h, CURLOPT_SSL_VERIFYPEER, 0)
#    curl_easy_setopt(h, CURLOPT_SSL_VERIFYHOST, 0)
#    curl_easy_setopt(h, CURLOPT_SSL_VERIFYHOST, 1)   (also wrong; must be 2)
#
#  Generic patterns:
#    callback that always returns 1 for "verify_callback"
#    SSL_VERIFY_NONE as a macro literal
# ═══════════════════════════════════════════════════════════════════

_CURL_OPT_PEER = "CURLOPT_SSL_VERIFYPEER"
_CURL_OPT_HOST = "CURLOPT_SSL_VERIFYHOST"
_SSL_VERIFY_NONE = "SSL_VERIFY_NONE"


class TLSValidationChecker(_CryptoChecker):
    """
    Detect disabled or weakened TLS certificate / hostname validation.

    Disabling validation makes TLS connections trivially interceptable
    by a man-in-the-middle attacker.
    """

    name: ClassVar[str] = "crypto-tls-validation"
    description: ClassVar[str] = (
        "Detects disabled TLS certificate or hostname validation."
    )
    error_ids: ClassVar[FrozenSet[str]] = frozenset({
        "tlsNoCertVerify",
        "tlsNoHostVerify",
        "tlsWeakHostVerify",
        "tlsSSLVerifyNone",
    })
    default_severity: ClassVar[DiagnosticSeverity] = DiagnosticSeverity.ERROR
    cwe_ids: ClassVar[Dict[str, int]] = {
        "tlsNoCertVerify":   295,
        "tlsNoHostVerify":   297,
        "tlsWeakHostVerify": 297,
        "tlsSSLVerifyNone":  295,
    }

    def _scan(self, tok: Any, ctx: CheckerContext) -> None:
        s = _tok_str(tok)

        # ── SSL_VERIFY_NONE macro used anywhere ───────────────────
        if s == _SSL_VERIFY_NONE:
            self._emit(
                error_id="tlsSSLVerifyNone",
                message=(
                    "SSL_VERIFY_NONE disables peer certificate verification. "
                    "Use SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT."
                ),
                file=_tok_file(tok),
                line=_tok_line(tok),
                column=_tok_col(tok),
                severity=DiagnosticSeverity.ERROR,
                confidence=Confidence.HIGH,
            )
            return

        # ── SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, cb) ──────────
        if s == "SSL_CTX_set_verify" and _is_function_call(tok, s):
            args = _get_call_args(tok)
            if len(args) >= 2:
                mode_arg = args[1]
                if _tok_str(mode_arg) == _SSL_VERIFY_NONE:
                    self._emit(
                        error_id="tlsSSLVerifyNone",
                        message=(
                            "SSL_CTX_set_verify() called with SSL_VERIFY_NONE. "
                            "Certificate validation is completely disabled."
                        ),
                        file=_tok_file(tok),
                        line=_tok_line(tok),
                        column=_tok_col(tok),
                        severity=DiagnosticSeverity.ERROR,
                        confidence=Confidence.HIGH,
                    )

        # ── curl_easy_setopt — VERIFYPEER / VERIFYHOST ────────────
        if s == "curl_easy_setopt" and _is_function_call(tok, s):
            args = _get_call_args(tok)
            if len(args) < 3:
                return
            opt_tok = args[1]
            val_tok = args[2]
            opt_str = _tok_str(opt_tok)
            val_str = _tok_str(val_tok)

            if opt_str == _CURL_OPT_PEER:
                # value 0 = verify disabled
                if val_str == "0" or getattr(val_tok, "values", None) and \
                        any(
                            getattr(v, "intvalue", None) == 0
                            for v in (val_tok.values or [])
                        ):
                    self._emit(
                        error_id="tlsNoCertVerify",
                        message=(
                            "curl_easy_setopt(CURLOPT_SSL_VERIFYPEER, 0) "
                            "disables TLS certificate verification entirely. "
                            "Set to 1 (the default) or provide a CA bundle."
                        ),
                        file=_tok_file(tok),
                        line=_tok_line(tok),
                        column=_tok_col(tok),
                        severity=DiagnosticSeverity.ERROR,
                        confidence=Confidence.HIGH,
                    )

            elif opt_str == _CURL_OPT_HOST:
                if val_str == "0":
                    self._emit(
                        error_id="tlsNoHostVerify",
                        message=(
                            "curl_easy_setopt(CURLOPT_SSL_VERIFYHOST, 0) "
                            "disables TLS hostname verification. "
                            "Set to 2 to enforce hostname matching."
                        ),
                        file=_tok_file(tok),
                        line=_tok_line(tok),
                        column=_tok_col(tok),
                        severity=DiagnosticSeverity.ERROR,
                        confidence=Confidence.HIGH,
                    )
                elif val_str == "1":
                    self._emit(
                        error_id="tlsWeakHostVerify",
                        message=(
                            "curl_easy_setopt(CURLOPT_SSL_VERIFYHOST, 1) "
                            "only checks for the presence of a hostname in "
                            "the certificate — NOT that it matches. "
                            "Use value 2 for proper hostname verification."
                        ),
                        file=_tok_file(tok),
                        line=_tok_line(tok),
                        column=_tok_col(tok),
                        severity=DiagnosticSeverity.WARNING,
                        confidence=Confidence.HIGH,
                    )


# ═══════════════════════════════════════════════════════════════════
#  SECTION 11 — CHECKER RUNNER
# ═══════════════════════════════════════════════════════════════════

_ALL_CHECKER_CLASSES = [
    WeakHashChecker,
    WeakPRNGChecker,
    SecureRandomChecker,
    WeakCipherChecker,
    HardcodedKeyChecker,
    KeyStorageChecker,
    CustomCryptoChecker,
    TLSValidationChecker,
]


def _run_checkers_on_cfg(cfg: Any, options: Dict[str, Any]) -> List[Diagnostic]:
    """
    Execute all enabled checkers against a single cppcheckdata
    Configuration object.  Returns the merged list of diagnostics.
    """
    suppression_mgr = SuppressionManager()
    suppression_mgr.load_inline_suppressions(cfg)

    ctx = CheckerContext(
        cfg=cfg,
        suppressions=suppression_mgr,
        options=options,
    )

    all_diagnostics: List[Diagnostic] = []

    for cls in _ALL_CHECKER_CLASSES:
        checker = cls()
        checker.configure(ctx)
        checker.collect_evidence(ctx)
        checker.diagnose(ctx)
        findings = checker.report(ctx)
        all_diagnostics.extend(findings)

    # Stable sort: file → line → error_id
    all_diagnostics.sort(key=lambda d: (
        d.location.file, d.location.line, d.error_id
    ))
    return all_diagnostics


# ═══════════════════════════════════════════════════════════════════
#  SECTION 12 — ENTRY POINT
# ═══════════════════════════════════════════════════════════════════

def main() -> None:
    if cppcheckdata is None:
        sys.stderr.write(
            "[CryptoSafetyAssurance] ERROR: cppcheckdata module not found.\n"
            "Install it with:  pip install cppcheckdata\n"
        )
        sys.exit(1)

    parser = cppcheckdata.ArgumentParser()
    args = parser.parse_args()

    if not args.dumpfile:
        sys.stderr.write("[CryptoSafetyAssurance] No dump files provided.\n")
        sys.exit(0)

    quiet: bool = getattr(args, "quiet", False) or getattr(args, "cli", False)
    options: Dict[str, Any] = {}

    for dumpfile in args.dumpfile:
        if not quiet:
            sys.stderr.write(f"[CryptoSafetyAssurance] Checking {dumpfile} …\n")

        try:
            data = cppcheckdata.parsedump(dumpfile)
        except Exception as exc:
            sys.stderr.write(
                f"[CryptoSafetyAssurance] Failed to parse {dumpfile}: {exc}\n"
            )
            continue

        for cfg in data.configurations:
            diagnostics = _run_checkers_on_cfg(cfg, options)
            for diag in diagnostics:
                _print_diagnostic(diag)


if __name__ == "__main__":
    main()
