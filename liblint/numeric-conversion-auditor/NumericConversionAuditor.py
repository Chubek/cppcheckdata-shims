#!/usr/bin/env python3
"""
NumericConversionAuditor.py
═══════════════════════════════════════════════════════════════════════════

Cppcheck addon: numeric-conversion-auditor
Tier 1 | CWE-190, 191, 192, 193, 194, 195, 196, 197, 681

Detects dangerous numeric type conversions in C source code — the
boundary where a value is CAST or implicitly COERCED between types.
This is distinct from arithmetic overflow (covered by integer-lint):
the bug here is the conversion itself, independent of whether the
source value overflowed.

Checkers
────────
  NCA-01  signedUnsignedTruncation  CWE-195  signed → unsigned, may wrap
  NCA-02  unsignedToSignedOverflow  CWE-196  unsigned → signed, top-half wraps
  NCA-03  narrowingCast             CWE-197  wide type cast to narrow type
  NCA-04  floatToIntTruncation      CWE-681  float/double → integer, frac lost
  NCA-05  intToFloatPrecision       CWE-197  large int → float, precision lost
  NCA-06  enumOutOfRange            CWE-192  int cast to enum, no matching member
  NCA-07  charSignednessArithmetic  CWE-194  plain char used in sign-sensitive op
  NCA-08  wideningNarrowReturn      CWE-197  computes wide, returns narrow type
  NCA-09  taintedConversionSink     CWE-190  tainted value flows into cast sink

CONTRACT — Safe Variable-ID Access
───────────────────────────────────
ALL variable-ID access in this addon MUST use _safe_vid() or
_safe_vid_tok().  Direct int(tok.varId) calls are FORBIDDEN.

Rationale: cppcheckdata may return varId values as:
  - decimal strings  ("42")
  - hex address strings  ("560e31248150")  ← causes ValueError
  - None
  - 0  (cppcheck's "no variable" sentinel)

_safe_vid() normalises all cases to Optional[int], returning None
for the sentinel and for non-decimal strings.

Usage
─────
    cppcheck --dump myfile.c
    python NumericConversionAuditor.py myfile.c.dump

License: MIT
"""

from __future__ import annotations

import sys
import os
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

# ── cppcheckdata import (graceful degradation) ───────────────────────────
try:
    import cppcheckdata
except ImportError:
    sys.stderr.write("ERROR: cppcheckdata module not found.\n")
    sys.exit(1)

# ═══════════════════════════════════════════════════════════════════════════
#  PART 1 — SAFE VARIABLE-ID HELPERS  (hardening mandate)
# ═══════════════════════════════════════════════════════════════════════════

def _safe_vid(vid: Any) -> Optional[int]:
    """
    Safely convert a raw varId value to int.

    Returns None for:
      - None input
      - non-decimal strings (e.g. hex addresses like '560e31248150')
      - cppcheck's sentinel value 0 ("no variable")

    NEVER call int(tok.varId) directly.  Always use this function.
    """
    if vid is None:
        return None
    try:
        v = int(vid)
        return v if v != 0 else None
    except (ValueError, TypeError):
        return None


def _safe_vid_tok(tok: Any) -> Optional[int]:
    """
    Return the safe variable-ID for a token, or None.

    Wrapper around _safe_vid() for the common token access pattern.
    """
    return _safe_vid(getattr(tok, "varId", None))


# ═══════════════════════════════════════════════════════════════════════════
#  PART 2 — TOKEN / VALUEFLOW UTILITIES
# ═══════════════════════════════════════════════════════════════════════════

def _tok_str(tok: Any) -> str:
    return getattr(tok, "str", "") or ""


def _tok_file(tok: Any) -> str:
    return getattr(tok, "file", "") or ""


def _tok_line(tok: Any) -> int:
    return getattr(tok, "linenr", 0) or 0


def _tok_col(tok: Any) -> int:
    return getattr(tok, "column", 0) or 0


def _vf_int_values(tok: Any) -> List[int]:
    """Return all ValueFlow integer values for a token."""
    result: List[int] = []
    for v in getattr(tok, "values", None) or []:
        iv = getattr(v, "intvalue", None)
        if iv is not None:
            try:
                result.append(int(iv))
            except (ValueError, TypeError):
                pass
    return result


def _vf_float_values(tok: Any) -> List[float]:
    """Return all ValueFlow float values for a token."""
    result: List[float] = []
    for v in getattr(tok, "values", None) or []:
        fv = getattr(v, "floatvalue", None)
        if fv is not None:
            try:
                result.append(float(fv))
            except (ValueError, TypeError):
                pass
    return result


def _vf_known_int(tok: Any) -> Optional[int]:
    """Return the single known integer value, or None."""
    for v in getattr(tok, "values", None) or []:
        if getattr(v, "valueKind", "") == "known":
            iv = getattr(v, "intvalue", None)
            if iv is not None:
                try:
                    return int(iv)
                except (ValueError, TypeError):
                    pass
    return None


def _vt_type(tok: Any) -> str:
    """Return the ValueType.type string for a token, or ''."""
    vt = getattr(tok, "valueType", None)
    return getattr(vt, "type", "") or ""


def _vt_sign(tok: Any) -> str:
    """Return the ValueType.sign string for a token, or ''."""
    vt = getattr(tok, "valueType", None)
    return getattr(vt, "sign", "") or ""


def _vt_bits(tok: Any) -> int:
    """Return the bit-width of a token's value type (best-effort)."""
    _BITS: Dict[str, int] = {
        "bool": 1, "char": 8, "short": 16, "int": 32,
        "long": 32, "long long": 64,
        "float": 32, "double": 64, "long double": 80,
        "signed char": 8, "unsigned char": 8,
        "unsigned short": 16, "unsigned int": 32,
        "unsigned long": 32, "unsigned long long": 64,
    }
    return _BITS.get(_vt_type(tok), 0)


def _is_float_type(type_str: str) -> bool:
    return type_str in {"float", "double", "long double"}


def _is_int_type(type_str: str) -> bool:
    _INT_TYPES = {
        "bool", "char", "short", "int", "long", "long long",
        "signed char", "unsigned char", "unsigned short",
        "unsigned int", "unsigned long", "unsigned long long",
    }
    return type_str in _INT_TYPES


# ═══════════════════════════════════════════════════════════════════════════
#  PART 3 — FINDING MODEL
# ═══════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class _Finding:
    """A single diagnostic finding from a checker."""
    error_id: str
    message: str
    cwe: int
    file: str
    line: int
    column: int = 0
    severity: str = "warning"
    extra: str = ""

    def emit(self, addon: str = "NumericConversionAuditor") -> None:
        """Write cppcheck-compatible JSON to stdout."""
        import json
        obj = {
            "file": self.file,
            "linenr": self.line,
            "column": self.column,
            "severity": self.severity,
            "message": self.message,
            "addon": addon,
            "errorId": self.error_id,
            "cwe": self.cwe,
            "extra": self.extra,
        }
        sys.stdout.write(json.dumps(obj) + "\n")


# ═══════════════════════════════════════════════════════════════════════════
#  PART 4 — BASE CHECKER
# ═══════════════════════════════════════════════════════════════════════════

class _BaseChecker:
    """
    Minimal abstract base for NCA checkers.

    Subclasses implement check(cfg) and accumulate findings in
    self._findings.  All varId access MUST go through _safe_vid /
    _safe_vid_tok — never int(tok.varId) directly.
    """

    error_id: str = ""
    cwe: int = 0
    severity: str = "warning"

    def __init__(self) -> None:
        self._findings: List[_Finding] = []

    def check(self, cfg: Any) -> None:
        raise NotImplementedError

    def _emit(
        self,
        tok: Any,
        message: str,
        error_id: Optional[str] = None,
        cwe: Optional[int] = None,
        extra: str = "",
    ) -> None:
        self._findings.append(_Finding(
            error_id=error_id or self.error_id,
            message=message,
            cwe=cwe or self.cwe,
            file=_tok_file(tok),
            line=_tok_line(tok),
            column=_tok_col(tok),
            severity=self.severity,
            extra=extra,
        ))

    @property
    def findings(self) -> List[_Finding]:
        return list(self._findings)


# ═══════════════════════════════════════════════════════════════════════════
#  PART 5 — TYPE-SIZE TABLES  (shared by multiple checkers)
# ═══════════════════════════════════════════════════════════════════════════

# Maps ValueType.type → bit width
_TYPE_BITS: Dict[str, int] = {
    "bool":               1,
    "char":               8,
    "signed char":        8,
    "unsigned char":      8,
    "short":              16,
    "unsigned short":     16,
    "int":                32,
    "unsigned int":       32,
    "long":               32,
    "unsigned long":      32,
    "long long":          64,
    "unsigned long long": 64,
    "float":              32,
    "double":             64,
    "long double":        80,
}

# Signed integer max values (for NCA-02 unsigned→signed overflow check)
_SIGNED_MAX: Dict[int, int] = {
    8:  (1 << 7)  - 1,
    16: (1 << 15) - 1,
    32: (1 << 31) - 1,
    64: (1 << 63) - 1,
}

# Integer precision provided by float types (significant mantissa bits)
_FLOAT_MANTISSA_BITS: Dict[str, int] = {
    "float":       24,   # IEEE 754 single
    "double":      53,   # IEEE 754 double
    "long double": 64,   # x87 extended
}


# ═══════════════════════════════════════════════════════════════════════════
#  PART 6 — INDIVIDUAL CHECKERS
# ═══════════════════════════════════════════════════════════════════════════

# ─────────────────────────────────────────────────────────────────────────
#  NCA-01  signedUnsignedTruncation  (CWE-195)
#
#  A signed value is explicitly cast or implicitly assigned to an unsigned
#  type.  If the value is negative it wraps to a large positive number,
#  which can silently bypass length/bounds checks (e.g. size_t underflow).
#
#  Detection strategy:
#    • Walk assignment ops (=) where lhs is unsigned and rhs is signed
#    • Also walk explicit cast expressions where the target is unsigned
#    • Confirm via ValueFlow that the rhs CAN be negative
# ─────────────────────────────────────────────────────────────────────────

class _NCA01_SignedUnsignedTruncation(_BaseChecker):
    error_id = "signedUnsignedTruncation"
    cwe = 195
    severity = "warning"

    def check(self, cfg: Any) -> None:
        seen: Set[Tuple[str, int]] = set()

        for tok in getattr(cfg, "tokenlist", []):
            # ── Implicit assignment: x = expr where x is unsigned ────
            if getattr(tok, "isAssignmentOp", False) and _tok_str(tok) == "=":
                lhs = getattr(tok, "astOperand1", None)
                rhs = getattr(tok, "astOperand2", None)
                if lhs is None or rhs is None:
                    continue
                if getattr(rhs, "isCast", False):
                    continue  # explicit cast handled separately

                lhs_sign = _vt_sign(lhs)
                rhs_sign = _vt_sign(rhs)
                lhs_type = _vt_type(lhs)
                rhs_type = _vt_type(rhs)

                if lhs_sign != "unsigned" or rhs_sign != "signed":
                    continue
                if not _is_int_type(lhs_type) or not _is_int_type(rhs_type):
                    continue

                # ValueFlow confirms rhs can be negative?
                can_neg = any(v < 0 for v in _vf_int_values(rhs))
                if not can_neg:
                    continue

                key = (_tok_file(tok), _tok_line(tok))
                if key in seen:
                    continue
                seen.add(key)

                var_name = _tok_str(lhs)
                self._emit(
                    tok,
                    f"Signed-to-unsigned conversion of '{var_name}': "
                    f"'{rhs_type}' → '{lhs_type}'; negative value wraps to "
                    f"large positive (CWE-195).",
                )

            # ── Explicit cast: (unsigned T)expr ──────────────────────
            if getattr(tok, "isCast", False):
                inner = getattr(tok, "astOperand1", None)
                if inner is None:
                    continue

                lhs_sign = _vt_sign(tok)
                inner_sign = _vt_sign(inner)
                if lhs_sign != "unsigned" or inner_sign != "signed":
                    continue

                can_neg = any(v < 0 for v in _vf_int_values(inner))
                if not can_neg:
                    continue

                key = (_tok_file(tok), _tok_line(tok))
                if key in seen:
                    continue
                seen.add(key)

                self._emit(
                    tok,
                    f"Explicit cast from signed '{_vt_type(inner)}' to "
                    f"unsigned '{_vt_type(tok)}' with possible negative value "
                    f"(CWE-195).",
                )


# ─────────────────────────────────────────────────────────────────────────
#  NCA-02  unsignedToSignedOverflow  (CWE-196)
#
#  An unsigned value is assigned/cast to a signed type that cannot
#  represent the full range.  If the value exceeds SIGNED_MAX the
#  result is implementation-defined (typically becomes negative), which
#  can subvert checks like `if (len < 0) return ERROR;`.
# ─────────────────────────────────────────────────────────────────────────

class _NCA02_UnsignedToSignedOverflow(_BaseChecker):
    error_id = "unsignedToSignedOverflow"
    cwe = 196
    severity = "warning"

    def check(self, cfg: Any) -> None:
        seen: Set[Tuple[str, int]] = set()

        for tok in getattr(cfg, "tokenlist", []):
            if not (getattr(tok, "isAssignmentOp", False) and _tok_str(tok) == "="):
                continue

            lhs = getattr(tok, "astOperand1", None)
            rhs = getattr(tok, "astOperand2", None)
            if lhs is None or rhs is None:
                continue

            lhs_sign = _vt_sign(lhs)
            rhs_sign = _vt_sign(rhs)
            if lhs_sign != "signed" or rhs_sign != "unsigned":
                continue

            lhs_bits = _TYPE_BITS.get(_vt_type(lhs), 0)
            if lhs_bits == 0:
                continue

            signed_max = _SIGNED_MAX.get(lhs_bits, 0)
            if signed_max == 0:
                continue

            # Does any ValueFlow value exceed SIGNED_MAX?
            overflow = any(v > signed_max for v in _vf_int_values(rhs))
            if not overflow:
                continue

            key = (_tok_file(tok), _tok_line(tok))
            if key in seen:
                continue
            seen.add(key)

            self._emit(
                tok,
                f"Unsigned-to-signed conversion of '{_tok_str(lhs)}': "
                f"value may exceed SIGNED{lhs_bits}_MAX ({signed_max}), "
                f"resulting in implementation-defined behaviour (CWE-196).",
            )


# ─────────────────────────────────────────────────────────────────────────
#  NCA-03  narrowingCast  (CWE-197)
#
#  An explicit cast from a wider integer type to a narrower integer type.
#  High bits are silently discarded.  When the source value doesn't fit in
#  the destination, the truncated result is usually wrong and occasionally
#  dangerous (e.g. truncating a length, a file descriptor, or a return
#  code).
# ─────────────────────────────────────────────────────────────────────────

class _NCA03_NarrowingCast(_BaseChecker):
    error_id = "narrowingCast"
    cwe = 197
    severity = "warning"

    def check(self, cfg: Any) -> None:
        seen: Set[Tuple[str, int]] = set()

        for tok in getattr(cfg, "tokenlist", []):
            if not getattr(tok, "isCast", False):
                continue

            inner = getattr(tok, "astOperand1", None)
            if inner is None:
                continue

            dst_type = _vt_type(tok)
            src_type = _vt_type(inner)

            if not _is_int_type(dst_type) or not _is_int_type(src_type):
                continue

            dst_bits = _TYPE_BITS.get(dst_type, 0)
            src_bits = _TYPE_BITS.get(src_type, 0)

            if dst_bits == 0 or src_bits == 0 or dst_bits >= src_bits:
                continue

            # Can the actual value overflow the destination?
            dst_sign = _vt_sign(tok)
            if dst_sign == "unsigned":
                dst_max = (1 << dst_bits) - 1
                truncation = any(v > dst_max or v < 0
                                 for v in _vf_int_values(inner))
            else:
                dst_max = (1 << (dst_bits - 1)) - 1
                dst_min = -(1 << (dst_bits - 1))
                truncation = any(v > dst_max or v < dst_min
                                 for v in _vf_int_values(inner))

            if not truncation and _vf_int_values(inner):
                continue  # ValueFlow proves the value fits — skip

            key = (_tok_file(tok), _tok_line(tok))
            if key in seen:
                continue
            seen.add(key)

            self._emit(
                tok,
                f"Narrowing cast from '{src_type}' ({src_bits}-bit) to "
                f"'{dst_type}' ({dst_bits}-bit): high bits silently "
                f"discarded (CWE-197).",
            )


# ─────────────────────────────────────────────────────────────────────────
#  NCA-04  floatToIntTruncation  (CWE-681)
#
#  A floating-point value is converted (explicitly or implicitly) to an
#  integer type.  The fractional part is silently truncated.  Worse, if
#  the float value is outside the integer type's range the result is
#  undefined behaviour in C.
# ─────────────────────────────────────────────────────────────────────────

class _NCA04_FloatToIntTruncation(_BaseChecker):
    error_id = "floatToIntTruncation"
    cwe = 681
    severity = "warning"

    def check(self, cfg: Any) -> None:
        seen: Set[Tuple[str, int]] = set()

        for tok in getattr(cfg, "tokenlist", []):
            lhs_type: str = ""
            src_type: str = ""
            inner: Any = None
            report_tok: Any = tok

            # Case A: explicit cast (float/double) → int
            if getattr(tok, "isCast", False):
                inner = getattr(tok, "astOperand1", None)
                if inner is None:
                    continue
                lhs_type = _vt_type(tok)
                src_type = _vt_type(inner)

            # Case B: implicit assignment float → int
            elif getattr(tok, "isAssignmentOp", False) and _tok_str(tok) == "=":
                lhs = getattr(tok, "astOperand1", None)
                rhs = getattr(tok, "astOperand2", None)
                if lhs is None or rhs is None:
                    continue
                if getattr(rhs, "isCast", False):
                    continue
                lhs_type = _vt_type(lhs)
                src_type = _vt_type(rhs)
                inner = rhs
                report_tok = tok

            else:
                continue

            if not _is_float_type(src_type):
                continue
            if not _is_int_type(lhs_type):
                continue

            # If ValueFlow shows fractional part is always zero — skip
            float_vals = _vf_float_values(inner)
            if float_vals and all(v == int(v) for v in float_vals):
                continue

            key = (_tok_file(report_tok), _tok_line(report_tok))
            if key in seen:
                continue
            seen.add(key)

            self._emit(
                report_tok,
                f"Float-to-integer conversion: '{src_type}' → '{lhs_type}'; "
                f"fractional part silently truncated. If value is out of "
                f"'{lhs_type}' range, behaviour is undefined (CWE-681).",
            )


# ─────────────────────────────────────────────────────────────────────────
#  NCA-05  intToFloatPrecision  (CWE-197)
#
#  A large integer is converted to a floating-point type whose mantissa
#  cannot represent all integers of that width.  For example, a 64-bit
#  integer stored in a 32-bit float (24 mantissa bits) silently loses the
#  low 40 bits of precision — the conversion is NOT reversible.
# ─────────────────────────────────────────────────────────────────────────

class _NCA05_IntToFloatPrecision(_BaseChecker):
    error_id = "intToFloatPrecision"
    cwe = 197
    severity = "portability"

    def check(self, cfg: Any) -> None:
        seen: Set[Tuple[str, int]] = set()

        for tok in getattr(cfg, "tokenlist", []):
            lhs_type: str = ""
            src_type: str = ""
            inner: Any = None
            report_tok: Any = tok

            if getattr(tok, "isCast", False):
                inner = getattr(tok, "astOperand1", None)
                if inner is None:
                    continue
                lhs_type = _vt_type(tok)
                src_type = _vt_type(inner)
                report_tok = tok

            elif getattr(tok, "isAssignmentOp", False) and _tok_str(tok) == "=":
                lhs = getattr(tok, "astOperand1", None)
                rhs = getattr(tok, "astOperand2", None)
                if lhs is None or rhs is None:
                    continue
                if getattr(rhs, "isCast", False):
                    continue
                lhs_type = _vt_type(lhs)
                src_type = _vt_type(rhs)
                inner = rhs
                report_tok = tok

            else:
                continue

            if not _is_float_type(lhs_type):
                continue
            if not _is_int_type(src_type):
                continue

            src_bits = _TYPE_BITS.get(src_type, 0)
            float_mantissa = _FLOAT_MANTISSA_BITS.get(lhs_type, 64)

            if src_bits == 0 or src_bits <= float_mantissa:
                continue  # integer fits exactly in float mantissa

            key = (_tok_file(report_tok), _tok_line(report_tok))
            if key in seen:
                continue
            seen.add(key)

            self._emit(
                report_tok,
                f"Integer-to-float precision loss: {src_bits}-bit '{src_type}' "
                f"→ '{lhs_type}' ({float_mantissa} mantissa bits); "
                f"low {src_bits - float_mantissa} bits of precision silently "
                f"lost (CWE-197).",
                severity="portability",
            )

    def _emit(self, tok: Any, message: str, **kw: Any) -> None:
        severity = kw.pop("severity", self.severity)
        self._findings.append(_Finding(
            error_id=self.error_id,
            message=message,
            cwe=self.cwe,
            file=_tok_file(tok),
            line=_tok_line(tok),
            column=_tok_col(tok),
            severity=severity,
            extra=kw.get("extra", ""),
        ))


# ─────────────────────────────────────────────────────────────────────────
#  NCA-06  enumOutOfRange  (CWE-192)
#
#  An integer value is explicitly cast to an enum type, but no enumerator
#  has that value.  In C (unlike C++) this is well-defined but logically
#  wrong — downstream switch statements may fall through to the default
#  case or miss intended branches entirely.
# ─────────────────────────────────────────────────────────────────────────

class _NCA06_EnumOutOfRange(_BaseChecker):
    error_id = "enumOutOfRange"
    cwe = 192
    severity = "warning"

    def check(self, cfg: Any) -> None:
        # Build a map from enum-type-name → set of valid int values
        enum_values: Dict[str, Set[int]] = {}
        for scope in getattr(cfg, "scopes", []):
            if getattr(scope, "type", "") != "Enum":
                continue
            enum_name = getattr(scope, "className", None) or ""
            vals: Set[int] = set()
            for var in getattr(scope, "varlist", []) or []:
                name_tok = getattr(var, "nameToken", None)
                if name_tok is None:
                    continue
                known = _vf_known_int(name_tok)
                if known is not None:
                    vals.add(known)
            if enum_name:
                enum_values[enum_name] = vals

        if not enum_values:
            return  # no enum types found

        seen: Set[Tuple[str, int]] = set()

        for tok in getattr(cfg, "tokenlist", []):
            if not getattr(tok, "isCast", False):
                continue

            # Destination type must be an enum
            vt = getattr(tok, "valueType", None)
            if vt is None:
                continue
            if getattr(vt, "type", "") != "Record":
                continue
            type_scope = getattr(vt, "typeScope", None)
            if type_scope is None:
                continue
            if getattr(type_scope, "type", "") != "Enum":
                continue
            enum_name = getattr(type_scope, "className", None) or ""
            valid = enum_values.get(enum_name)
            if valid is None:
                continue

            inner = getattr(tok, "astOperand1", None)
            if inner is None:
                continue

            int_vals = _vf_int_values(inner)
            if not int_vals:
                continue

            bad = [v for v in int_vals if v not in valid]
            if not bad:
                continue

            key = (_tok_file(tok), _tok_line(tok))
            if key in seen:
                continue
            seen.add(key)

            self._emit(
                tok,
                f"Cast to enum '{enum_name}' with value(s) {bad} that have "
                f"no matching enumerator; switch statements may behave "
                f"unexpectedly (CWE-192).",
            )


# ─────────────────────────────────────────────────────────────────────────
#  NCA-07  charSignednessArithmetic  (CWE-194)
#
#  Plain `char` has implementation-defined signedness.  When a plain char
#  is used in arithmetic or comparison that depends on sign (e.g. compared
#  to EOF = -1, or used as an array index), code is non-portable and may
#  misbehave on platforms where char is unsigned.
# ─────────────────────────────────────────────────────────────────────────

class _NCA07_CharSignednessArithmetic(_BaseChecker):
    error_id = "charSignednessArithmetic"
    cwe = 194
    severity = "portability"

    # Operations that are sensitive to signedness
    _SIGN_SENSITIVE_OPS: FrozenSet[str] = frozenset({
        ">", "<", ">=", "<=", "==", "!=",
        "+", "-", "*", "/", "%", "&", "|", "^",
        ">>",   # right-shift is sign-sensitive
    })

    def check(self, cfg: Any) -> None:
        seen: Set[Tuple[str, int]] = set()

        for tok in getattr(cfg, "tokenlist", []):
            if _tok_str(tok) not in self._SIGN_SENSITIVE_OPS:
                continue

            for operand in (
                getattr(tok, "astOperand1", None),
                getattr(tok, "astOperand2", None),
            ):
                if operand is None:
                    continue

                vt = getattr(operand, "valueType", None)
                if vt is None:
                    continue

                # Plain char: type="char" with sign="" (not "signed"/"unsigned")
                if getattr(vt, "type", "") != "char":
                    continue
                if getattr(vt, "sign", "") != "":
                    continue  # explicitly signed or unsigned — fine

                key = (_tok_file(tok), _tok_line(tok))
                if key in seen:
                    continue
                seen.add(key)

                op_str = _tok_str(tok)
                self._emit(
                    tok,
                    f"Plain 'char' used in sign-sensitive operation '{op_str}': "
                    f"signedness of char is implementation-defined; use "
                    f"'signed char' or 'unsigned char' explicitly (CWE-194).",
                )
                break  # one finding per operator token is enough


# ─────────────────────────────────────────────────────────────────────────
#  NCA-08  wideningNarrowReturn  (CWE-197)
#
#  A function's return type is narrower than the type of the expression
#  it returns.  The computation is done in a wide type (e.g. long long)
#  but the truncated narrow value (e.g. int) is returned, silently
#  discarding high bits.
#
#  Pattern: return <expr> where typeof(expr) is wider than func return type.
# ─────────────────────────────────────────────────────────────────────────

class _NCA08_WideningNarrowReturn(_BaseChecker):
    error_id = "wideningNarrowReturn"
    cwe = 197
    severity = "warning"

    def check(self, cfg: Any) -> None:
        # Build a map from scope → function return type bits
        func_return_bits: Dict[Any, int] = {}
        for func in getattr(cfg, "functions", []):
            ret_type_tok = getattr(func, "tokenDef", None)
            if ret_type_tok is None:
                continue
            # Walk backwards from tokenDef to find return type token
            prev = getattr(ret_type_tok, "previous", None)
            if prev is None:
                continue
            ret_type_str = _vt_type(prev)
            bits = _TYPE_BITS.get(ret_type_str, 0)
            func_scope = getattr(func, "functionScope", None)
            if func_scope and bits:
                func_return_bits[func_scope] = bits

        seen: Set[Tuple[str, int]] = set()

        for tok in getattr(cfg, "tokenlist", []):
            if _tok_str(tok) != "return":
                continue

            expr = getattr(tok, "astOperand1", None)
            if expr is None:
                continue

            expr_type = _vt_type(expr)
            expr_bits = _TYPE_BITS.get(expr_type, 0)
            if expr_bits == 0:
                continue

            # Find the enclosing function scope
            scope = getattr(tok, "scope", None)
            while scope is not None:
                ret_bits = func_return_bits.get(scope)
                if ret_bits is not None:
                    break
                scope = getattr(scope, "nestedIn", None)

            if scope is None:
                continue
            ret_bits = func_return_bits.get(scope, 0)
            if ret_bits == 0 or expr_bits <= ret_bits:
                continue

            # Does any concrete value actually overflow?
            int_vals = _vf_int_values(expr)
            if int_vals:
                max_representable = (1 << (ret_bits - 1)) - 1
                min_representable = -(1 << (ret_bits - 1))
                if all(min_representable <= v <= max_representable
                       for v in int_vals):
                    continue  # ValueFlow proves it fits

            key = (_tok_file(tok), _tok_line(tok))
            if key in seen:
                continue
            seen.add(key)

            self._emit(
                tok,
                f"Function computes in {expr_bits}-bit '{expr_type}' but "
                f"returns {ret_bits}-bit type: high bits silently discarded "
                f"(CWE-197).",
            )


# ─────────────────────────────────────────────────────────────────────────
#  NCA-09  taintedConversionSink  (CWE-190)
#
#  A value from an untrusted source (recv, read, scanf, fgets, atoi,
#  strtol, getenv) flows into a widening or narrowing conversion that is
#  subsequently used as a loop bound, array index, or allocation size.
#
#  This check is intentionally conservative (token pattern matching) to
#  avoid false negatives, in keeping with the security-first posture of
#  this addon.
# ─────────────────────────────────────────────────────────────────────────

class _NCA09_TaintedConversionSink(_BaseChecker):
    error_id = "taintedConversionSink"
    cwe = 190
    severity = "warning"

    # Functions whose return value is attacker-controlled
    _TAINT_SOURCES: FrozenSet[str] = frozenset({
        "recv", "recvfrom", "read", "fread",
        "scanf", "fscanf", "sscanf",
        "fgets", "gets",
        "atoi", "atol", "atoll",
        "strtol", "strtoul", "strtoll", "strtoull",
        "getenv",
        "ntohl", "ntohs", "ntohll",
        "htonl", "htons",
    })

    # Conversion / arithmetic nodes that represent dangerous sinks
    _SINK_OPS: FrozenSet[str] = frozenset({
        "*", "+", "-",          # arithmetic with tainted operand
        "<<",                   # left-shift — overflow amplifier
        "[",                    # array subscript
    })

    # Allocation sinks
    _ALLOC_FUNCS: FrozenSet[str] = frozenset({
        "malloc", "calloc", "realloc", "alloca",
        "new", "kmalloc", "vmalloc",
    })

    def check(self, cfg: Any) -> None:
        # ── Pass 1: collect tainted varIds ───────────────────────────
        tainted_vids: Set[int] = set()

        for tok in getattr(cfg, "tokenlist", []):
            if _tok_str(tok) not in self._TAINT_SOURCES:
                continue

            # Pattern: var = source(...)
            parent = getattr(tok, "astParent", None)
            if parent is None:
                continue

            # Case A: assignment  var = recv(...)
            if getattr(parent, "isAssignmentOp", False):
                lhs = getattr(parent, "astOperand1", None)
                if lhs is not None:
                    vid = _safe_vid_tok(lhs)   # ← SAFE VID
                    if vid is not None:
                        tainted_vids.add(vid)

            # Case B: declaration init (handled similarly)
            # Case C: taint propagates through casts — track the cast result
            grandparent = getattr(parent, "astParent", None)
            if grandparent is not None and getattr(grandparent, "isAssignmentOp", False):
                lhs = getattr(grandparent, "astOperand1", None)
                if lhs is not None:
                    vid = _safe_vid_tok(lhs)   # ← SAFE VID
                    if vid is not None:
                        tainted_vids.add(vid)

        if not tainted_vids:
            return

        # ── Pass 2: detect tainted vids at conversion sinks ─────────
        seen: Set[Tuple[str, int]] = set()

        for tok in getattr(cfg, "tokenlist", []):
            # Sub-case A: tainted variable appears in a cast
            if getattr(tok, "isCast", False):
                inner = getattr(tok, "astOperand1", None)
                if inner is None:
                    continue
                vid = _safe_vid_tok(inner)     # ← SAFE VID
                if vid not in tainted_vids:
                    continue

                src_bits = _TYPE_BITS.get(_vt_type(inner), 0)
                dst_bits = _TYPE_BITS.get(_vt_type(tok), 0)
                if src_bits == 0 or dst_bits == 0:
                    continue

                key = (_tok_file(tok), _tok_line(tok))
                if key in seen:
                    continue
                seen.add(key)

                direction = "narrowing" if dst_bits < src_bits else "widening"
                self._emit(
                    tok,
                    f"Tainted value (from untrusted source) flows into "
                    f"{direction} cast '{_vt_type(inner)}' → '{_vt_type(tok)}'; "
                    f"potential integer overflow/truncation (CWE-190).",
                )

            # Sub-case B: tainted variable used in arithmetic sink op
            elif _tok_str(tok) in self._SINK_OPS:
                for operand in (
                    getattr(tok, "astOperand1", None),
                    getattr(tok, "astOperand2", None),
                ):
                    if operand is None:
                        continue
                    vid = _safe_vid_tok(operand)   # ← SAFE VID
                    if vid not in tainted_vids:
                        continue

                    key = (_tok_file(tok), _tok_line(tok))
                    if key in seen:
                        continue
                    seen.add(key)

                    self._emit(
                        tok,
                        f"Tainted value used in '{_tok_str(tok)}' operator "
                        f"without prior bounds/conversion validation; "
                        f"potential integer overflow (CWE-190).",
                    )
                    break

            # Sub-case C: tainted value passed to allocation function
            elif _tok_str(tok) in self._ALLOC_FUNCS:
                next_tok = getattr(tok, "next", None)
                if next_tok is None or _tok_str(next_tok) != "(":
                    continue
                arg = getattr(next_tok, "astOperand2", None)
                if arg is None:
                    continue
                vid = _safe_vid_tok(arg)       # ← SAFE VID
                if vid not in tainted_vids:
                    continue

                key = (_tok_file(tok), _tok_line(tok))
                if key in seen:
                    continue
                seen.add(key)

                self._emit(
                    tok,
                    f"Tainted value used as allocation size to '{_tok_str(tok)}' "
                    f"without bounds check; integer overflow may yield "
                    f"under-sized buffer (CWE-190).",
                )


# ═══════════════════════════════════════════════════════════════════════════
#  PART 7 — ADDON ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════

_ALL_CHECKERS: List[type] = [
    _NCA01_SignedUnsignedTruncation,
    _NCA02_UnsignedToSignedOverflow,
    _NCA03_NarrowingCast,
    _NCA04_FloatToIntTruncation,
    _NCA05_IntToFloatPrecision,
    _NCA06_EnumOutOfRange,
    _NCA07_CharSignednessArithmetic,
    _NCA08_WideningNarrowReturn,
    _NCA09_TaintedConversionSink,
]


def _run_on_dump(dump_file: str) -> int:
    """
    Parse a cppcheck dump file and run all NCA checkers.

    Returns 0 if no findings, 1 otherwise.
    """
    data = cppcheckdata.parsedump(dump_file)
    total = 0

    for cfg in data.configurations:
        for checker_cls in _ALL_CHECKERS:
            checker = checker_cls()
            try:
                checker.check(cfg)
            except Exception as exc:
                # Graceful degradation: never crash cppcheck's pipeline
                sys.stderr.write(
                    f"[NCA] {checker_cls.__name__} raised {type(exc).__name__}: "
                    f"{exc}\n"
                )
                continue

            for finding in checker.findings:
                finding.emit()
                total += 1

    return 1 if total > 0 else 0


def main() -> None:
    if len(sys.argv) < 2:
        sys.stderr.write(
            "Usage: python NumericConversionAuditor.py <file.c.dump>\n"
        )
        sys.exit(1)

    dump_file = sys.argv[1]
    if not os.path.isfile(dump_file):
        sys.stderr.write(f"ERROR: dump file not found: {dump_file}\n")
        sys.exit(1)

    sys.exit(_run_on_dump(dump_file))


if __name__ == "__main__":
    main()
