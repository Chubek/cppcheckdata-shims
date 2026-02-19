#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IntegerLint.py — Integer Safety Analyzer for Cppcheck
═══════════════════════════════════════════════════════

A Cppcheck addon that detects integer-related vulnerabilities via
lightweight token-list / AST analysis.

Target CWEs
────────────
  CWE-128  Wrap-around Error (allocation overflow)
  CWE-190  Integer Overflow or Wraparound
  CWE-191  Integer Underflow (Wrap or Wraparound)
  CWE-192  Integer Coercion Error (truncation)
  CWE-193  Off-by-one Error
  CWE-194  Unexpected Sign Extension
  CWE-195  Signed to Unsigned Conversion Error
  CWE-196  Unsigned to Signed Conversion Error
  CWE-197  Numeric Truncation Error
  CWE-681  Incorrect Conversion between Numeric Types

Architecture
────────────
  Eight linear-forward passes over the token list:

    0. ValueTracker          — pre-pass: forward interval estimation
    1. OverflowUnderflowCheck — CWE-190, CWE-191
    2. TruncationCheck       — CWE-192, CWE-197
    3. SignConversionCheck   — CWE-194, CWE-195, CWE-196, CWE-681
    4. OffByOneCheck         — CWE-193
    5. AllocationOverflowCheck — CWE-128, CWE-190
    6. MixedSignComparisonCheck — CWE-681
    7. ShiftOverflowCheck    — CWE-190

Constraint
──────────
  Uses the PUBLIC ``IntervalDomain`` from
  ``cppcheckdata_shims.abstract_domains``.  All interval queries use
  only the documented API of that class (lo/hi fields, lattice ops,
  arithmetic transfer functions, predicates).  No monkey-patching,
  no custom subclass, no fallback reimplementation.

Usage
─────
  cppcheck --dump myfile.c
  python IntegerLint.py myfile.c.dump
"""

from __future__ import annotations

import sys
from typing import Any, Dict, List, Optional, Set, Tuple

# ═══════════════════════════════════════════════════════════════════════
#  CPPCHECKDATA IMPORT
# ═══════════════════════════════════════════════════════════════════════

try:
    import cppcheckdata
except ImportError:
    sys.stderr.write(
        "IntegerLint: error: cannot import cppcheckdata.\n"
        "  Make sure cppcheckdata.py is on your PYTHONPATH or in the\n"
        "  same directory as this addon.\n"
    )
    sys.exit(1)

# ═══════════════════════════════════════════════════════════════════════
#  INTERVAL DOMAIN — from cppcheckdata_shims
# ═══════════════════════════════════════════════════════════════════════

try:
    from cppcheckdata_shims.abstract_domains import IntervalDomain
except ImportError:
    sys.stderr.write(
        "IntegerLint: error: cannot import IntervalDomain from\n"
        "  cppcheckdata_shims.abstract_domains.\n"
        "  Make sure cppcheckdata-shims is installed.\n"
    )
    sys.exit(1)


# ═══════════════════════════════════════════════════════════════════════
#  INTERVAL QUERY HELPERS
#
#  The shims IntervalDomain exposes .lo and .hi as floats (may be
#  ±inf) and provides is_bottom(), is_top(), contains(), etc.
#  The following thin helpers express the range predicates that our
#  checkers need, using ONLY the public IntervalDomain API.
# ═══════════════════════════════════════════════════════════════════════

def iv_can_exceed(iv: IntervalDomain, bound: float) -> bool:
    """Can any concrete value in *iv* exceed *bound*?"""
    if iv.is_bottom():
        return False
    return iv.hi > bound


def iv_can_be_below(iv: IntervalDomain, bound: float) -> bool:
    """Can any concrete value in *iv* be strictly below *bound*?"""
    if iv.is_bottom():
        return False
    return iv.lo < bound


def iv_can_be_negative(iv: IntervalDomain) -> bool:
    """Can any concrete value in *iv* be negative?"""
    return iv_can_be_below(iv, 0)


def iv_overlaps(a: IntervalDomain, b: IntervalDomain) -> bool:
    """Do the two intervals share at least one concrete value?"""
    if a.is_bottom() or b.is_bottom():
        return False
    return a.lo <= b.hi and b.lo <= a.hi


# ═══════════════════════════════════════════════════════════════════════
#  PLATFORM MODEL  (LP64)
#
#  Canonical type name → (bit_width, is_signed)
# ═══════════════════════════════════════════════════════════════════════

TYPE_INFO: Dict[str, Tuple[int, bool]] = {
    # --- 8-bit ---
    "bool":               (8,  False),
    "_Bool":              (8,  False),
    "char":               (8,  True),
    "signed char":        (8,  True),
    "unsigned char":      (8,  False),
    "uint8_t":            (8,  False),
    "int8_t":             (8,  True),
    # --- 16-bit ---
    "short":              (16, True),
    "signed short":       (16, True),
    "short int":          (16, True),
    "signed short int":   (16, True),
    "unsigned short":     (16, False),
    "unsigned short int": (16, False),
    "uint16_t":           (16, False),
    "int16_t":            (16, True),
    # --- 32-bit ---
    "int":                (32, True),
    "signed":             (32, True),
    "signed int":         (32, True),
    "unsigned":           (32, False),
    "unsigned int":       (32, False),
    "uint32_t":           (32, False),
    "int32_t":            (32, True),
    # --- 64-bit ---
    "long":               (64, True),
    "signed long":        (64, True),
    "long int":           (64, True),
    "signed long int":    (64, True),
    "unsigned long":      (64, False),
    "unsigned long int":  (64, False),
    "long long":          (64, True),
    "signed long long":   (64, True),
    "long long int":      (64, True),
    "signed long long int": (64, True),
    "unsigned long long":      (64, False),
    "unsigned long long int":  (64, False),
    "uint64_t":           (64, False),
    "int64_t":            (64, True),
    "size_t":             (64, False),
    "ssize_t":            (64, True),
    "ptrdiff_t":          (64, True),
    "uintptr_t":          (64, False),
    "intptr_t":           (64, True),
}


# ═══════════════════════════════════════════════════════════════════════
#  TYPE RESOLUTION HELPERS
# ═══════════════════════════════════════════════════════════════════════

def _vt_to_canonical(vt: Any) -> Optional[str]:
    """Convert a cppcheckdata ValueType to a canonical type name."""
    if vt is None:
        return None
    orig = getattr(vt, "originalTypeName", None)
    if orig and orig in TYPE_INFO:
        return orig
    base = getattr(vt, "type", None)
    if base in ("float", "double", "long double"):
        return None
    sign = getattr(vt, "sign", None)
    if sign == "unsigned":
        prefix = "unsigned "
    else:
        prefix = ""
    if base:
        name = prefix + base
        if name in TYPE_INFO:
            return name
        # Try just the base
        if base in TYPE_INFO:
            return base
    return None


def get_type_info_vt(vt: Any) -> Optional[Tuple[int, bool]]:
    """Return (bits, is_signed) for a ValueType, or None."""
    name = _vt_to_canonical(vt)
    if name and name in TYPE_INFO:
        return TYPE_INFO[name]
    # Heuristic from sign + type fields
    if vt is None:
        return None
    base = getattr(vt, "type", None)
    sign = getattr(vt, "sign", None)
    if base == "char":
        return (8, sign != "unsigned")
    if base == "short":
        return (16, sign != "unsigned")
    if base == "int":
        return (32, sign != "unsigned")
    if base == "long":
        return (64, sign != "unsigned")
    if base == "long long":
        return (64, sign != "unsigned")
    return None


def get_type_info_token(tok: Any) -> Optional[Tuple[int, bool]]:
    """Return (bits, is_signed) for a token, or None."""
    if tok is None:
        return None
    vt = getattr(tok, "valueType", None)
    if vt:
        info = get_type_info_vt(vt)
        if info:
            return info
    return None


def type_range(bits: int, signed: bool) -> Tuple[int, int]:
    """Return (min_val, max_val) for an integer type."""
    if signed:
        return (-(1 << (bits - 1)), (1 << (bits - 1)) - 1)
    else:
        return (0, (1 << bits) - 1)


def type_range_interval(bits: int, signed: bool) -> IntervalDomain:
    """Return an IntervalDomain for the full range of an integer type.

    Uses ``IntervalDomain.range(lo, hi)`` — the public constructor from
    cppcheckdata_shims that accepts integer endpoints.
    """
    lo, hi = type_range(bits, signed)
    return IntervalDomain.range(lo, hi)


def is_pointer_type(tok: Any) -> bool:
    """Check if a token has pointer type."""
    vt = getattr(tok, "valueType", None)
    if vt:
        p = getattr(vt, "pointer", 0)
        if p and p > 0:
            return True
    return False


def is_integer_type(tok: Any) -> bool:
    """Check if a token has integer type."""
    return get_type_info_token(tok) is not None


def get_bits(tok: Any) -> Optional[int]:
    """Get bit-width of a token's type, or None."""
    info = get_type_info_token(tok)
    return info[0] if info else None


def is_signed(tok: Any) -> Optional[bool]:
    """Check if a token's type is signed."""
    info = get_type_info_token(tok)
    return info[1] if info else None


def is_unsigned(tok: Any) -> Optional[bool]:
    """Check if a token's type is unsigned."""
    info = get_type_info_token(tok)
    if info is None:
        return None
    return not info[1]


# ═══════════════════════════════════════════════════════════════════════
#  AST / TOKEN HELPERS
# ═══════════════════════════════════════════════════════════════════════

def expr_tokens(tok: Any):
    """Yield all tokens in the AST subtree rooted at *tok* (pre-order)."""
    if tok is None:
        return
    yield tok
    yield from expr_tokens(getattr(tok, "astOperand1", None))
    yield from expr_tokens(getattr(tok, "astOperand2", None))


def is_in_sizeof(tok: Any) -> bool:
    """Check if *tok* is inside a ``sizeof()`` expression."""
    cur = getattr(tok, "astParent", None)
    while cur:
        if getattr(cur, "str", "") == "sizeof":
            return True
        cur = getattr(cur, "astParent", None)
    return False


def is_cast_token(tok: Any) -> bool:
    """Check if a token IS a cast expression."""
    return getattr(tok, "str", "") == "(" and getattr(tok, "isCast", False)


def get_enclosing_function(tok: Any) -> Any:
    """Get the enclosing function scope of a token, or None."""
    scope = getattr(tok, "scope", None)
    while scope:
        if getattr(scope, "type", "") == "Function":
            return scope
        scope = getattr(scope, "nestedIn", None)
    return None


# ═══════════════════════════════════════════════════════════════════════
#  INTERVAL ESTIMATION HELPERS
# ═══════════════════════════════════════════════════════════════════════

def interval_from_values(tok: Any) -> Optional[IntervalDomain]:
    """Build an IntervalDomain from Cppcheck value-flow data on a token."""
    vals = getattr(tok, "values", None)
    if not vals:
        return None
    int_vals: list[int] = []
    for v in vals:
        iv = getattr(v, "intvalue", None)
        if iv is not None:
            int_vals.append(int(iv))
    if not int_vals:
        return None
    return IntervalDomain.range(min(int_vals), max(int_vals))


def interval_from_number(tok: Any) -> Optional[IntervalDomain]:
    """Build a constant interval if the token is a literal number."""
    if tok and getattr(tok, "isNumber", False):
        try:
            s = tok.str.rstrip("uUlL")
            if s.startswith("0x") or s.startswith("0X"):
                v = int(s, 16)
            elif s.startswith("0b") or s.startswith("0B"):
                v = int(s, 2)
            elif len(s) > 1 and s.startswith("0") and all(
                c in "01234567" for c in s
            ):
                v = int(s, 8)
            else:
                v = int(s)
            return IntervalDomain.const(v)
        except (ValueError, OverflowError):
            pass
    return None


# ═══════════════════════════════════════════════════════════════════════
#  DEDUPLICATION
# ═══════════════════════════════════════════════════════════════════════

_reported_set: Set[Tuple[str, int, int]] = set()


def _already_reported(file: str, line: int, cwe_id: int) -> bool:
    key = (file, line, cwe_id)
    if key in _reported_set:
        return True
    _reported_set.add(key)
    return False


# ═══════════════════════════════════════════════════════════════════════
#  REPORTING
# ═══════════════════════════════════════════════════════════════════════

def report_finding(
    tok: Any,
    severity: str,
    msg: str,
    cwe_id: int,
    addon_name: str = "IntegerLint",
) -> None:
    """Emit a Cppcheck-compatible diagnostic to stdout."""
    file_ = getattr(tok, "file", "<unknown>")
    line = getattr(tok, "linenr", 0)
    col = getattr(tok, "column", 0)
    if _already_reported(file_, line, cwe_id):
        return
    sys.stdout.write(
        f"[{file_}:{line}:{col}] ({severity}) {addon_name}: "
        f"{msg} [CWE-{cwe_id}]\n"
    )
    sys.stdout.flush()


# ═══════════════════════════════════════════════════════════════════════
#  UTILITY: FIRST TOKEN HELPER
# ═══════════════════════════════════════════════════════════════════════

def _first_token(cfg: Any) -> Any:
    """Get the first token from a configuration's tokenlist.

    cppcheckdata stores tokenlist as the first Token object (linked via
    ``.next``), not a Python list.  Handle both forms defensively.
    """
    tl = getattr(cfg, "tokenlist", None)
    if tl is not None:
        if isinstance(tl, list):
            return tl[0] if tl else None
        return tl  # it IS the first Token
    return None


# ═══════════════════════════════════════════════════════════════════════
#  PASS 0 — VALUE TRACKER (pre-pass)
#
#  A lightweight forward pass that estimates integer intervals for
#  variables via assignments, declarations, and Cppcheck value-flow
#  data.  No CFG, no fixpoint — single linear scan.
# ═══════════════════════════════════════════════════════════════════════

class ValueTracker:
    """Forward interval estimation for variables."""

    def __init__(self) -> None:
        # varId → IntervalDomain
        self.intervals: Dict[int, IntervalDomain] = {}

    # ── public query ─────────────────────────────────────────────────

    def get_var_interval(self, var_id: Optional[int]) -> Optional[IntervalDomain]:
        if var_id is None:
            return None
        return self.intervals.get(var_id)

    def get_token_interval(self, tok: Any) -> Optional[IntervalDomain]:
        """Estimate an interval for *tok*."""
        if tok is None:
            return None

        # 1. Literal number
        iv = interval_from_number(tok)
        if iv is not None:
            return iv

        # 2. Cppcheck value-flow
        iv = interval_from_values(tok)
        if iv is not None:
            return iv

        # 3. Tracked variable
        vid = getattr(tok, "varId", None)
        if vid and vid in self.intervals:
            return self.intervals[vid]

        # 4. Unary minus  (IntervalDomain.negate)
        if (
            getattr(tok, "str", "") == "-"
            and getattr(tok, "astOperand1", None) is not None
            and getattr(tok, "astOperand2", None) is None
        ):
            sub = self.get_token_interval(tok.astOperand1)
            if sub:
                return sub.negate()

        # 5. Binary arithmetic
        op1 = getattr(tok, "astOperand1", None)
        op2 = getattr(tok, "astOperand2", None)
        if op1 is not None and op2 is not None:
            iv1 = self.get_token_interval(op1)
            iv2 = self.get_token_interval(op2)
            if iv1 is not None and iv2 is not None:
                s = getattr(tok, "str", "")
                if s == "+":
                    return iv1.add(iv2)
                if s == "-":
                    return iv1.sub(iv2)
                if s == "*":
                    return iv1.mul(iv2)
                if s == "<<":
                    return iv1.shift_left(iv2)

        return None

    # ── pass execution ───────────────────────────────────────────────

    def run(self, cfg: Any) -> None:
        """Run a single forward scan over the token list."""
        t = _first_token(cfg)
        while t:
            self._process_token(t)
            t = t.next

    def _process_token(self, tok: Any) -> None:
        """Process a single token for value tracking."""
        s = getattr(tok, "str", "")

        # ── simple assignment: var = expr ──
        if s == "=" and not getattr(tok, "isCast", False):
            lhs = getattr(tok, "astOperand1", None)
            rhs = getattr(tok, "astOperand2", None)
            if lhs and rhs:
                vid = getattr(lhs, "varId", None)
                if vid:
                    rhs_iv = self.get_token_interval(rhs)
                    if rhs_iv is not None:
                        self._set(vid, rhs_iv)
                    else:
                        # Can't estimate RHS — use the type's full range
                        info = get_type_info_token(lhs)
                        if info:
                            self._set(vid, type_range_interval(*info))

        # ── compound assignments: +=, -=, *=, <<= ──
        elif s in ("+=", "-=", "*=", "<<="):
            lhs = getattr(tok, "astOperand1", None)
            rhs = getattr(tok, "astOperand2", None)
            if lhs and rhs:
                vid = getattr(lhs, "varId", None)
                if vid:
                    cur = self.get_var_interval(vid)
                    rhs_iv = self.get_token_interval(rhs)
                    if cur is not None and rhs_iv is not None:
                        if s == "+=":
                            self._set(vid, cur.add(rhs_iv))
                        elif s == "-=":
                            self._set(vid, cur.sub(rhs_iv))
                        elif s == "*=":
                            self._set(vid, cur.mul(rhs_iv))
                        elif s == "<<=":
                            self._set(vid, cur.shift_left(rhs_iv))

        # ── declaration initialiser ──
        var_obj = getattr(tok, "variable", None)
        if var_obj is not None:
            nt = getattr(var_obj, "nameToken", None)
            if nt is tok:
                vid = getattr(tok, "varId", None)
                if vid and vid not in self.intervals:
                    # Check for initialiser
                    nxt = tok.next
                    if nxt and getattr(nxt, "str", "") == "=":
                        rhs_tok = getattr(nxt, "astOperand2", None)
                        if rhs_tok is None and nxt.next:
                            rhs_tok = nxt.next
                        if rhs_tok:
                            rhs_iv = self.get_token_interval(rhs_tok)
                            if rhs_iv is not None:
                                self._set(vid, rhs_iv)
                                return
                    # No initialiser — seed with type range
                    vt_info = get_type_info_token(tok)
                    if vt_info:
                        self._set(vid, type_range_interval(*vt_info))

    def _set(self, vid: int, iv: IntervalDomain) -> None:
        """Set or join interval for a variable."""
        if vid in self.intervals:
            self.intervals[vid] = self.intervals[vid].join(iv)
        else:
            self.intervals[vid] = iv


# ═══════════════════════════════════════════════════════════════════════
#  PASS 1 — OVERFLOW / UNDERFLOW CHECK  (CWE-190, CWE-191)
# ═══════════════════════════════════════════════════════════════════════

class OverflowUnderflowCheck:
    """Detect integer overflow (CWE-190) and underflow (CWE-191)."""

    def __init__(self, tracker: ValueTracker) -> None:
        self.tracker = tracker

    def run(self, cfg: Any) -> None:
        t = _first_token(cfg)
        while t:
            self._check(t)
            t = t.next

    def _check(self, tok: Any) -> None:
        s = getattr(tok, "str", "")
        if s not in ("+", "-", "*", "<<"):
            return

        op1 = getattr(tok, "astOperand1", None)
        op2 = getattr(tok, "astOperand2", None)
        if op1 is None or op2 is None:
            return

        # Skip if inside sizeof
        if is_in_sizeof(tok):
            return

        # Skip pointer arithmetic
        if is_pointer_type(op1) or is_pointer_type(op2):
            return

        # Need at least one integer operand
        if not is_integer_type(op1) and not is_integer_type(op2):
            return

        iv1 = self.tracker.get_token_interval(op1)
        iv2 = self.tracker.get_token_interval(op2)
        if iv1 is None or iv2 is None:
            return

        # Compute result interval
        if s == "+":
            result = iv1.add(iv2)
        elif s == "-":
            result = iv1.sub(iv2)
        elif s == "*":
            result = iv1.mul(iv2)
        elif s == "<<":
            result = iv1.shift_left(iv2)
        else:
            return

        # Determine destination type
        info = self._dest_type(tok, op1)
        if info is None:
            return
        bits, signed = info
        tmin, tmax = type_range(bits, signed)
        signedness_str = "signed" if signed else "unsigned"

        if iv_can_exceed(result, tmax):
            report_finding(
                tok,
                "warning",
                f"Integer overflow in '{s}': result can reach "
                f"{int(result.hi)} which exceeds max {tmax} for "
                f"{bits}-bit {signedness_str} type",
                190,
            )
        if iv_can_be_below(result, tmin):
            report_finding(
                tok,
                "warning",
                f"Integer underflow in '{s}': result can reach "
                f"{int(result.lo)} which is below min {tmin} for "
                f"{bits}-bit {signedness_str} type",
                191,
            )

    @staticmethod
    def _dest_type(tok: Any, fallback: Any) -> Optional[Tuple[int, bool]]:
        """Determine the destination type for an arithmetic result."""
        # Check if parent is an assignment
        parent = getattr(tok, "astParent", None)
        if parent and getattr(parent, "str", "") == "=":
            lhs = getattr(parent, "astOperand1", None)
            if lhs:
                info = get_type_info_token(lhs)
                if info:
                    return info
        # Operator's own type
        info = get_type_info_token(tok)
        if info:
            return info
        # Fallback to first operand's type
        return get_type_info_token(fallback)


# ═══════════════════════════════════════════════════════════════════════
#  PASS 2 — TRUNCATION CHECK  (CWE-192, CWE-197)
# ═══════════════════════════════════════════════════════════════════════

class TruncationCheck:
    """Detect narrowing conversions that may lose data."""

    def __init__(self, tracker: ValueTracker) -> None:
        self.tracker = tracker

    def run(self, cfg: Any) -> None:
        t = _first_token(cfg)
        while t:
            self._check_assignment(t)
            self._check_cast(t)
            self._check_return(t)
            t = t.next

    def _check_assignment(self, tok: Any) -> None:
        if getattr(tok, "str", "") != "=":
            return
        if getattr(tok, "isCast", False):
            return
        lhs = getattr(tok, "astOperand1", None)
        rhs = getattr(tok, "astOperand2", None)
        if not lhs or not rhs:
            return
        lhs_info = get_type_info_token(lhs)
        rhs_info = get_type_info_token(rhs)
        if not lhs_info or not rhs_info:
            return
        lhs_bits, lhs_signed = lhs_info
        rhs_bits, rhs_signed = rhs_info
        if rhs_bits <= lhs_bits:
            return  # not narrowing

        lhs_min, lhs_max = type_range(lhs_bits, lhs_signed)
        rhs_iv = self.tracker.get_token_interval(rhs)
        if rhs_iv is not None:
            if iv_can_exceed(rhs_iv, lhs_max) or iv_can_be_below(rhs_iv, lhs_min):
                report_finding(
                    tok,
                    "warning",
                    f"Truncation: assigning {rhs_bits}-bit value "
                    f"(range [{int(rhs_iv.lo)}, {int(rhs_iv.hi)}]) to "
                    f"{lhs_bits}-bit "
                    f"{'signed' if lhs_signed else 'unsigned'} variable "
                    f"(range [{lhs_min}, {lhs_max}])",
                    192,
                )
        else:
            report_finding(
                tok,
                "portability",
                f"Possible truncation: {rhs_bits}-bit value assigned to "
                f"{lhs_bits}-bit "
                f"{'signed' if lhs_signed else 'unsigned'} variable",
                197,
            )

    def _check_cast(self, tok: Any) -> None:
        if not is_cast_token(tok):
            return
        src = getattr(tok, "astOperand1", None)
        if not src:
            return
        dst_info = get_type_info_token(tok)
        src_info = get_type_info_token(src)
        if not dst_info or not src_info:
            return
        dst_bits, dst_signed = dst_info
        src_bits, src_signed = src_info
        if src_bits <= dst_bits:
            return

        dst_min, dst_max = type_range(dst_bits, dst_signed)
        src_iv = self.tracker.get_token_interval(src)
        if src_iv is not None and (
            iv_can_exceed(src_iv, dst_max) or iv_can_be_below(src_iv, dst_min)
        ):
            report_finding(
                tok,
                "warning",
                f"Truncation in cast: {src_bits}-bit value "
                f"(range [{int(src_iv.lo)}, {int(src_iv.hi)}]) cast to "
                f"{dst_bits}-bit "
                f"{'signed' if dst_signed else 'unsigned'} type "
                f"(range [{dst_min}, {dst_max}])",
                192,
            )
        elif src_iv is None:
            report_finding(
                tok,
                "portability",
                f"Possible truncation in cast: {src_bits}-bit to "
                f"{dst_bits}-bit "
                f"{'signed' if dst_signed else 'unsigned'}",
                197,
            )

    def _check_return(self, tok: Any) -> None:
        if getattr(tok, "str", "") != "return":
            return
        nxt = tok.next
        if nxt is None or getattr(nxt, "str", "") == ";":
            return
        ret_expr = getattr(tok, "astOperand1", None)
        if ret_expr is None:
            ret_expr = nxt
        expr_info = get_type_info_token(ret_expr)
        if not expr_info:
            return
        func_scope = get_enclosing_function(tok)
        if not func_scope:
            return
        fn = getattr(func_scope, "function", None)
        if not fn:
            return
        fn_tok = getattr(fn, "tokenDef", None) or getattr(fn, "token", None)
        if not fn_tok:
            return
        prev = getattr(fn_tok, "previous", None)
        if prev:
            ret_info = get_type_info_token(prev)
            if ret_info:
                ret_bits, ret_signed = ret_info
                expr_bits, _ = expr_info
                if expr_bits > ret_bits:
                    report_finding(
                        tok,
                        "portability",
                        f"Possible truncation in return: {expr_bits}-bit "
                        f"expression returned as {ret_bits}-bit type",
                        197,
                    )


# ═══════════════════════════════════════════════════════════════════════
#  PASS 3 — SIGN CONVERSION CHECK  (CWE-194, 195, 196, 681)
# ═══════════════════════════════════════════════════════════════════════

class SignConversionCheck:
    """Detect hazardous signed ↔ unsigned conversions."""

    def __init__(self, tracker: ValueTracker) -> None:
        self.tracker = tracker

    def run(self, cfg: Any) -> None:
        t = _first_token(cfg)
        while t:
            self._check_assignment(t)
            self._check_cast(t)
            self._check_array_index(t)
            t = t.next

    def _check_assignment(self, tok: Any) -> None:
        if getattr(tok, "str", "") != "=":
            return
        lhs = getattr(tok, "astOperand1", None)
        rhs = getattr(tok, "astOperand2", None)
        if not lhs or not rhs:
            return
        lhs_info = get_type_info_token(lhs)
        rhs_info = get_type_info_token(rhs)
        if not lhs_info or not rhs_info:
            return
        lhs_bits, lhs_signed = lhs_info
        rhs_bits, rhs_signed = rhs_info

        rhs_iv = self.tracker.get_token_interval(rhs)

        # Signed → Unsigned
        if rhs_signed and not lhs_signed:
            if rhs_iv is not None and iv_can_be_negative(rhs_iv):
                report_finding(
                    tok,
                    "warning",
                    f"Signed to unsigned conversion: signed value "
                    f"(range [{int(rhs_iv.lo)}, {int(rhs_iv.hi)}]) "
                    f"assigned to unsigned {lhs_bits}-bit variable; "
                    f"negative values will wrap",
                    195,
                )
            elif rhs_iv is None:
                report_finding(
                    tok,
                    "portability",
                    f"Signed to unsigned conversion: signed {rhs_bits}-bit "
                    f"value assigned to unsigned {lhs_bits}-bit variable",
                    195,
                )

        # Unsigned → Signed
        if not rhs_signed and lhs_signed:
            lhs_max = (1 << (lhs_bits - 1)) - 1
            if rhs_iv is not None and iv_can_exceed(rhs_iv, lhs_max):
                report_finding(
                    tok,
                    "warning",
                    f"Unsigned to signed conversion: unsigned value "
                    f"(range [{int(rhs_iv.lo)}, {int(rhs_iv.hi)}]) "
                    f"assigned to signed {lhs_bits}-bit variable; "
                    f"values > {lhs_max} will be negative",
                    194,
                )
            elif rhs_iv is None and rhs_bits >= lhs_bits:
                report_finding(
                    tok,
                    "portability",
                    f"Unsigned to signed conversion: unsigned "
                    f"{rhs_bits}-bit value assigned to signed "
                    f"{lhs_bits}-bit variable",
                    194,
                )

    def _check_cast(self, tok: Any) -> None:
        if not is_cast_token(tok):
            return
        src = getattr(tok, "astOperand1", None)
        if not src:
            return
        dst_info = get_type_info_token(tok)
        src_info = get_type_info_token(src)
        if not dst_info or not src_info:
            return
        dst_bits, dst_signed = dst_info
        src_bits, src_signed = src_info
        if src_signed == dst_signed:
            return

        src_iv = self.tracker.get_token_interval(src)

        if src_signed and not dst_signed:
            # Signed → unsigned cast
            if src_iv and iv_can_be_negative(src_iv):
                report_finding(
                    tok,
                    "warning",
                    f"Sign change in cast: signed value (can be negative) "
                    f"cast to unsigned {dst_bits}-bit type",
                    196,
                )
            elif src_iv is None:
                report_finding(
                    tok,
                    "portability",
                    f"Sign change in cast: signed {src_bits}-bit cast to "
                    f"unsigned {dst_bits}-bit",
                    681,
                )
        else:
            # Unsigned → signed cast
            dst_max = (1 << (dst_bits - 1)) - 1
            if src_iv and iv_can_exceed(src_iv, dst_max):
                report_finding(
                    tok,
                    "warning",
                    f"Sign change in cast: unsigned value (can exceed "
                    f"{dst_max}) cast to signed {dst_bits}-bit type",
                    196,
                )
            elif src_iv is None:
                report_finding(
                    tok,
                    "portability",
                    f"Sign change in cast: unsigned {src_bits}-bit cast to "
                    f"signed {dst_bits}-bit",
                    681,
                )

    def _check_array_index(self, tok: Any) -> None:
        if getattr(tok, "str", "") != "[":
            return
        idx = getattr(tok, "astOperand2", None)
        if not idx:
            return
        idx_info = get_type_info_token(idx)
        if not idx_info or not idx_info[1]:
            return  # not signed
        idx_iv = self.tracker.get_token_interval(idx)
        if idx_iv is not None and iv_can_be_negative(idx_iv):
            report_finding(
                tok,
                "warning",
                f"Potentially negative array index: signed index "
                f"(range [{int(idx_iv.lo)}, {int(idx_iv.hi)}])",
                194,
            )


# ═══════════════════════════════════════════════════════════════════════
#  PASS 4 — OFF-BY-ONE CHECK  (CWE-193)
# ═══════════════════════════════════════════════════════════════════════

class OffByOneCheck:
    """Detect common off-by-one patterns."""

    def __init__(self, tracker: ValueTracker) -> None:
        self.tracker = tracker

    def run(self, cfg: Any) -> None:
        t = _first_token(cfg)
        while t:
            self._check_loop_bound(t)
            self._check_malloc_strlen(t)
            self._check_access_at_sizeof(t)
            t = t.next

    def _check_loop_bound(self, tok: Any) -> None:
        """Detect ``i <= N`` loop condition where ``<`` is correct."""
        if getattr(tok, "str", "") != "<=":
            return
        op1 = getattr(tok, "astOperand1", None)
        op2 = getattr(tok, "astOperand2", None)
        if not op1 or not op2:
            return
        scope = getattr(tok, "scope", None)
        scope_type = getattr(scope, "type", "") if scope else ""
        if scope_type not in ("For", "While"):
            return

        rhs_str = getattr(op2, "str", "")
        # Pattern: i <= sizeof(...)
        if rhs_str == "sizeof":
            report_finding(
                tok,
                "warning",
                "Off-by-one: loop condition uses '<=' with sizeof; "
                "consider '<'",
                193,
            )
            return

        # Pattern: RHS is an array variable
        rhs_var = getattr(op2, "variable", None)
        if rhs_var and getattr(rhs_var, "isArray", False):
            report_finding(
                tok,
                "warning",
                "Off-by-one: loop condition uses '<=' with array bound; "
                "consider '<'",
                193,
            )
            return

        # Pattern: i <= strlen(...)
        if rhs_str == "(":
            fn = getattr(op2, "astOperand1", None)
            if fn and getattr(fn, "str", "") == "strlen":
                report_finding(
                    tok,
                    "warning",
                    "Off-by-one: loop uses '<= strlen(...)'; if writing, "
                    "NUL terminator may be overwritten",
                    193,
                )
                return

        # Generic: LHS is a loop variable used as array index in body
        lhs_vid = getattr(op1, "varId", None)
        if lhs_vid and scope:
            body_start = getattr(scope, "bodyStart", None)
            body_end = getattr(scope, "bodyEnd", None)
            if body_start and body_end:
                bt = body_start.next
                while bt and bt != body_end:
                    if (
                        getattr(bt, "str", "") == "["
                        and getattr(bt, "astOperand2", None) is not None
                    ):
                        idx = bt.astOperand2
                        if getattr(idx, "varId", None) == lhs_vid:
                            report_finding(
                                tok,
                                "warning",
                                "Off-by-one: loop variable used as array "
                                "index with '<=' bound",
                                193,
                            )
                            return
                    bt = bt.next

    def _check_malloc_strlen(self, tok: Any) -> None:
        """Detect ``malloc(strlen(s))`` without ``+1``."""
        if getattr(tok, "str", "") != "(":
            return
        fn = getattr(tok, "astOperand1", None)
        if not fn:
            return
        fn_name = getattr(fn, "str", "")
        if fn_name not in ("malloc", "calloc", "realloc"):
            return
        arg = getattr(tok, "astOperand2", None)
        if not arg:
            return

        has_strlen = False
        has_plus_one = False
        for et in expr_tokens(arg):
            if getattr(et, "str", "") == "strlen":
                has_strlen = True
            if getattr(et, "str", "") == "+":
                o1 = getattr(et, "astOperand1", None)
                o2 = getattr(et, "astOperand2", None)
                if (o1 and getattr(o1, "str", "") == "1") or (
                    o2 and getattr(o2, "str", "") == "1"
                ):
                    has_plus_one = True

        if has_strlen and not has_plus_one:
            report_finding(
                tok,
                "warning",
                f"{fn_name}(strlen(...)) without +1: no space for "
                f"NUL terminator",
                193,
            )

    def _check_access_at_sizeof(self, tok: Any) -> None:
        """Detect ``buf[sizeof(buf)]`` — one past the end."""
        if getattr(tok, "str", "") != "[":
            return
        arr = getattr(tok, "astOperand1", None)
        idx = getattr(tok, "astOperand2", None)
        if not arr or not idx:
            return

        # Pattern: buf[sizeof(buf)]
        if getattr(idx, "str", "") == "sizeof":
            sizeof_arg = getattr(idx, "astOperand2", None) or getattr(
                idx, "astOperand1", None
            )
            if sizeof_arg and getattr(sizeof_arg, "varId", None) == getattr(
                arr, "varId", None
            ):
                report_finding(
                    tok,
                    "warning",
                    f"Off-by-one: accessing "
                    f"'{getattr(arr, 'str', '')}[sizeof("
                    f"{getattr(arr, 'str', '')})]' which is one past "
                    f"the end",
                    193,
                )
                return

        # Pattern: buf[N] where N is the declared dimension
        arr_var = getattr(arr, "variable", None)
        if arr_var and getattr(arr_var, "isArray", False):
            idx_iv = self.tracker.get_token_interval(idx)
            if idx_iv is not None:
                nt = getattr(arr_var, "nameToken", None)
                if nt:
                    t = nt.next
                    if t and getattr(t, "str", "") == "[":
                        dim_tok = t.next
                        if dim_tok and getattr(dim_tok, "isNumber", False):
                            try:
                                dim = int(dim_tok.str)
                                if idx_iv.contains(dim):
                                    report_finding(
                                        tok,
                                        "warning",
                                        f"Off-by-one: array "
                                        f"'{getattr(arr, 'str', '')}'"
                                        f" has {dim} elements but "
                                        f"index can be {dim}",
                                        193,
                                    )
                            except ValueError:
                                pass


# ═══════════════════════════════════════════════════════════════════════
#  PASS 5 — ALLOCATION OVERFLOW CHECK  (CWE-128, CWE-190)
# ═══════════════════════════════════════════════════════════════════════

class AllocationOverflowCheck:
    """Detect multiplication overflow in allocation sizes."""

    SIZE_T_MAX: float = float((1 << 64) - 1)

    def __init__(self, tracker: ValueTracker) -> None:
        self.tracker = tracker

    def run(self, cfg: Any) -> None:
        t = _first_token(cfg)
        while t:
            self._check(t)
            t = t.next

    def _check(self, tok: Any) -> None:
        if getattr(tok, "str", "") != "(":
            return
        fn = getattr(tok, "astOperand1", None)
        if not fn:
            return
        fn_name = getattr(fn, "str", "")
        if fn_name not in ("malloc", "realloc", "calloc", "aligned_alloc"):
            return
        # calloc handles overflow internally on many platforms
        if fn_name == "calloc":
            return
        arg = getattr(tok, "astOperand2", None)
        if not arg:
            return

        for et in expr_tokens(arg):
            if getattr(et, "str", "") == "*":
                op1 = getattr(et, "astOperand1", None)
                op2 = getattr(et, "astOperand2", None)
                if op1 and op2:
                    iv1 = self.tracker.get_token_interval(op1)
                    iv2 = self.tracker.get_token_interval(op2)
                    if iv1 and iv2:
                        result = iv1.mul(iv2)
                        if iv_can_exceed(result, self.SIZE_T_MAX):
                            report_finding(
                                et,
                                "warning",
                                f"Allocation size overflow: {fn_name}() "
                                f"argument contains multiplication that "
                                f"can exceed SIZE_MAX",
                                128,
                            )
                    else:
                        # Both unknown and non-constant
                        o1c = interval_from_number(op1)
                        o2c = interval_from_number(op2)
                        if not o1c and not o2c:
                            report_finding(
                                et,
                                "warning",
                                f"Potential allocation size overflow: "
                                f"{fn_name}() argument has unchecked "
                                f"multiplication of non-constant values",
                                128,
                            )
                break  # at most once per alloc

            if getattr(et, "str", "") == "<<":
                op1 = getattr(et, "astOperand1", None)
                op2 = getattr(et, "astOperand2", None)
                if op1 and op2:
                    iv1 = self.tracker.get_token_interval(op1)
                    iv2 = self.tracker.get_token_interval(op2)
                    if iv1 and iv2:
                        result = iv1.shift_left(iv2)
                        if result.is_top() or iv_can_exceed(
                            result, self.SIZE_T_MAX
                        ):
                            report_finding(
                                et,
                                "warning",
                                f"Allocation size overflow: {fn_name}() "
                                f"argument contains left-shift that may "
                                f"overflow",
                                128,
                            )
                break


# ═══════════════════════════════════════════════════════════════════════
#  PASS 6 — MIXED-SIGN COMPARISON CHECK  (CWE-681)
# ═══════════════════════════════════════════════════════════════════════

class MixedSignComparisonCheck:
    """Detect comparisons between signed and unsigned values."""

    _CMP_OPS = frozenset(("<", "<=", ">", ">=", "==", "!="))

    def __init__(self, tracker: ValueTracker) -> None:
        self.tracker = tracker

    def run(self, cfg: Any) -> None:
        t = _first_token(cfg)
        while t:
            self._check(t)
            t = t.next

    def _check(self, tok: Any) -> None:
        if getattr(tok, "str", "") not in self._CMP_OPS:
            return
        if not getattr(tok, "isComparisonOp", False):
            return
        op1 = getattr(tok, "astOperand1", None)
        op2 = getattr(tok, "astOperand2", None)
        if not op1 or not op2:
            return

        # Suppress comparison with literal 0 (always safe)
        if getattr(op1, "str", "") == "0" or getattr(op2, "str", "") == "0":
            return

        info1 = get_type_info_token(op1)
        info2 = get_type_info_token(op2)
        if not info1 or not info2:
            return
        bits1, signed1 = info1
        bits2, signed2 = info2
        if signed1 == signed2:
            return

        # Determine which is signed
        if signed1:
            signed_op, unsigned_op = op1, op2
            signed_bits, unsigned_bits = bits1, bits2
        else:
            signed_op, unsigned_op = op2, op1
            signed_bits, unsigned_bits = bits2, bits1

        signed_iv = self.tracker.get_token_interval(signed_op)
        if signed_iv is not None and iv_can_be_negative(signed_iv):
            report_finding(
                tok,
                "warning",
                f"Mixed-sign comparison: signed {signed_bits}-bit value "
                f"(can be negative, range [{int(signed_iv.lo)}, "
                f"{int(signed_iv.hi)}]) compared with unsigned "
                f"{unsigned_bits}-bit value. Implicit conversion may "
                f"reverse the comparison result.",
                681,
            )
        elif signed_iv is None:
            report_finding(
                tok,
                "portability",
                f"Mixed-sign comparison: signed {signed_bits}-bit "
                f"compared with unsigned {unsigned_bits}-bit value",
                681,
            )


# ═══════════════════════════════════════════════════════════════════════
#  PASS 7 — SHIFT OVERFLOW CHECK  (CWE-190)
# ═══════════════════════════════════════════════════════════════════════

class ShiftOverflowCheck:
    """Detect undefined/dangerous shift operations."""

    def __init__(self, tracker: ValueTracker) -> None:
        self.tracker = tracker

    def run(self, cfg: Any) -> None:
        t = _first_token(cfg)
        while t:
            self._check(t)
            t = t.next

    def _check(self, tok: Any) -> None:
        s = getattr(tok, "str", "")
        if s not in ("<<", ">>"):
            return
        lhs = getattr(tok, "astOperand1", None)
        rhs = getattr(tok, "astOperand2", None)
        if not lhs or not rhs:
            return

        lhs_info = get_type_info_token(lhs)
        rhs_iv = self.tracker.get_token_interval(rhs)
        rhs_info = get_type_info_token(rhs)

        # ── Shift amount >= bit-width ──
        if lhs_info and rhs_iv:
            bits, signed = lhs_info
            if rhs_iv.lo >= bits:
                report_finding(
                    tok,
                    "error",
                    f"Undefined behavior: shift amount "
                    f"[{int(rhs_iv.lo)}, {int(rhs_iv.hi)}] >= "
                    f"type width ({bits} bits)",
                    190,
                )
                return  # don't double-report
            elif iv_can_exceed(rhs_iv, bits - 1):
                report_finding(
                    tok,
                    "warning",
                    f"Shift amount (range [{int(rhs_iv.lo)}, "
                    f"{int(rhs_iv.hi)}]) may exceed type width "
                    f"({bits} bits) — undefined behavior",
                    190,
                )

        # ── Negative shift amount ──
        if rhs_info and rhs_info[1]:  # signed shift amount
            if rhs_iv is not None and iv_can_be_negative(rhs_iv):
                report_finding(
                    tok,
                    "error",
                    f"Undefined behavior: shift amount can be negative "
                    f"(range [{int(rhs_iv.lo)}, {int(rhs_iv.hi)}])",
                    190,
                )

        # ── Left-shift of negative signed value ──
        if s == "<<" and lhs_info and lhs_info[1]:  # signed LHS
            lhs_iv = self.tracker.get_token_interval(lhs)
            if lhs_iv is not None and iv_can_be_negative(lhs_iv):
                report_finding(
                    tok,
                    "warning",
                    f"Left-shift of possibly negative signed value "
                    f"(range [{int(lhs_iv.lo)}, {int(lhs_iv.hi)}]) — "
                    f"undefined behavior in C",
                    190,
                )

        # ── Shift into sign bit ──
        if s == "<<" and lhs_info:
            bits, signed = lhs_info
            if signed:
                lhs_iv = self.tracker.get_token_interval(lhs)
                if (
                    lhs_iv
                    and rhs_iv
                    and not iv_can_be_negative(lhs_iv)
                ):
                    result = lhs_iv.shift_left(rhs_iv)
                    smax = (1 << (bits - 1)) - 1
                    if not result.is_top() and iv_can_exceed(result, smax):
                        report_finding(
                            tok,
                            "warning",
                            f"Left-shift overflow: result of signed shift "
                            f"may exceed {smax} ({bits}-bit signed max), "
                            f"which is undefined behavior",
                            190,
                        )


# ═══════════════════════════════════════════════════════════════════════
#  MAIN CHECKER  — ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════════════

class IntegerLintChecker:
    """
    Orchestrator for all eight passes.

    Usage::

        checker = IntegerLintChecker()
        data = cppcheckdata.parsedump("myfile.c.dump")
        checker.check(data)
    """

    def check(self, data: Any) -> None:
        for cfg in data.configurations:
            # Pass 0: value tracker
            tracker = ValueTracker()
            tracker.run(cfg)

            # Passes 1–7
            OverflowUnderflowCheck(tracker).run(cfg)
            TruncationCheck(tracker).run(cfg)
            SignConversionCheck(tracker).run(cfg)
            OffByOneCheck(tracker).run(cfg)
            AllocationOverflowCheck(tracker).run(cfg)
            MixedSignComparisonCheck(tracker).run(cfg)
            ShiftOverflowCheck(tracker).run(cfg)


# ═══════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════

def main() -> None:
    if len(sys.argv) < 2:
        sys.stderr.write(
            "Usage: python IntegerLint.py <file.c.dump> "
            "[<file2.c.dump> ...]\n"
        )
        sys.exit(1)

    checker = IntegerLintChecker()
    for dump_file in sys.argv[1:]:
        try:
            data = cppcheckdata.parsedump(dump_file)
        except Exception as e:
            sys.stderr.write(
                f"IntegerLint: error: cannot parse '{dump_file}': {e}\n"
            )
            continue
        checker.check(data)


if __name__ == "__main__":
    main()
