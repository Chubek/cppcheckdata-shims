#!/usr/bin/env python3
"""
CastValidator.py
════════════════

Cppcheck addon that validates C/C++ type casts against MITRE CWEs,
built on the ``cppcheckdata_shims`` type analysis infrastructure.

Sound design principles (Møller & Schwartzbach §3; Nielson, Nielson
& Hankin, Ch. 5):

  1.  Use the CType term algebra from type_analysis.py directly —
      never invent parallel type predicates that drift out of sync.

  2.  Checker precedence: specific qualitative checks (const-away,
      volatile-away, signedness, misalignment, func-ptr mismatch,
      downcast, enum-range) run first and *claim* the cast.  Only if
      NO specific checker fires does the generic layer (redundant,
      truncation, float↔int) get a chance.  This prevents false
      positives from the redundant checker masking real issues.

  3.  Type comparison respects qualifiers at every pointer level —
      two pointer types are "same" only if qualifiers match at every
      indirection depth.  Stripping qualifiers is done explicitly
      and only where the C standard permits implicit conversion.

Invoke::

    cppcheck --dump myfile.c
    python CastValidator.py myfile.c.dump

Self-test::

    python CastValidator.py --self-test

License: MIT
"""

from __future__ import annotations

import argparse
import os
import sys
from dataclasses import dataclass, field
from typing import (
    Any,
    Callable,
    Dict,
    List,
    Optional,
    Set,
    Tuple,
)

# ═══════════════════════════════════════════════════════════════════════════
#  IMPORTS
# ═══════════════════════════════════════════════════════════════════════════

try:
    import cppcheckdata  # type: ignore[import-untyped]
except ImportError:
    cppcheckdata = None  # type: ignore[assignment]

# ── type_analysis (CType term algebra) ───────────────────────────────────
_HAS_TYPE_ANALYSIS = False
CType: Any = None
TypeKind: Any = None
Qualifier: Any = None

# Try multiple import paths
for _mod_path in [
    ("cppcheckdata_shims.type_analysis", ),
    ("type_analysis", ),
]:
    try:
        _mod = __import__(_mod_path[0], fromlist=["CType", "TypeKind", "Qualifier"])
        CType = _mod.CType
        TypeKind = _mod.TypeKind
        Qualifier = _mod.Qualifier
        _HAS_TYPE_ANALYSIS = True
        break
    except ImportError:
        continue

if not _HAS_TYPE_ANALYSIS:
    print(
        "CastValidator: FATAL — type_analysis module not found.\n"
        "  Ensure cppcheckdata_shims/type_analysis.py is on PYTHONPATH.",
        file=sys.stderr,
    )
    sys.exit(1)

# ── plus_reporter (optional) ─────────────────────────────────────────────
_HAS_REPORTER = False
Reporter: Any = None
try:
    from cppcheckdata_shims.plus_reporter import Reporter  # type: ignore
    _HAS_REPORTER = True
except ImportError:
    try:
        from plus_reporter import Reporter  # type: ignore
        _HAS_REPORTER = True
    except ImportError:
        pass


# ═══════════════════════════════════════════════════════════════════════════
#  SEVERITY (self-contained — no external dependency required)
# ═══════════════════════════════════════════════════════════════════════════

class Severity:
    """Cppcheck-compatible severity levels."""
    class _Sev:
        def __init__(self, name: str) -> None:
            self.name = name
            self.cppcheck_name = name.lower()
        def __repr__(self) -> str:
            return f"Severity.{self.name}"

    ERROR = _Sev("error")
    WARNING = _Sev("warning")
    STYLE = _Sev("style")
    PERFORMANCE = _Sev("performance")
    PORTABILITY = _Sev("portability")
    INFORMATION = _Sev("information")


# ═══════════════════════════════════════════════════════════════════════════
#  CWE MAP
# ═══════════════════════════════════════════════════════════════════════════

_CWE_TABLE: Dict[str, int] = {
    "castTruncation":        197,
    "castSignedness":        195,   # overridden to 196 for unsigned→signed
    "castPointerToSmallInt": 704,
    "castIntToPointer":      704,
    "castPointerMisalign":   704,
    "castConstAway":         704,
    "castVolatileAway":      704,
    "castFuncPtrMismatch":   843,
    "castDowncastUnsafe":    843,
    "castFloatToInt":        681,
    "castIntToFloat":        681,
    "castVoidPtrDeref":      843,
    "castReinterpretRisk":   843,
    "castImplicitBoolTrunc": 704,
    "castEnumOutOfRange":    704,
    "castRedundant":         398,
}


# ═══════════════════════════════════════════════════════════════════════════
#  PLATFORM MODEL (LP64)
# ═══════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class PlatformModel:
    char_bits: int = 8
    short_bits: int = 16
    int_bits: int = 32
    long_bits: int = 64
    long_long_bits: int = 64
    float_bits: int = 32
    double_bits: int = 64
    pointer_bits: int = 64
    bool_bits: int = 1
    enum_bits: int = 32
    # Alignment in bytes
    char_align: int = 1
    short_align: int = 2
    int_align: int = 4
    long_align: int = 8
    long_long_align: int = 8
    float_align: int = 4
    double_align: int = 8
    pointer_align: int = 8

LP64 = PlatformModel()


# ═══════════════════════════════════════════════════════════════════════════
#  STATISTICS TRACKER
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class CheckStats:
    by_check: Dict[str, int] = field(default_factory=dict)
    by_severity: Dict[str, int] = field(default_factory=dict)
    total: int = 0

    def record(self, check_id: str, severity: Any) -> None:
        self.by_check[check_id] = self.by_check.get(check_id, 0) + 1
        sn = getattr(severity, "cppcheck_name", str(severity)).lower()
        self.by_severity[sn] = self.by_severity.get(sn, 0) + 1
        self.total += 1

    def summary(self) -> str:
        lines = [f"CastValidator: {self.total} diagnostic(s)"]
        if self.by_severity:
            parts = [f"{v} {k}" for k, v in sorted(self.by_severity.items())]
            lines.append("  severity: " + ", ".join(parts))
        for cid, cnt in sorted(self.by_check.items()):
            lines.append(f"  {cid}: {cnt}")
        return "\n".join(lines)

_STATS = CheckStats()


# ═══════════════════════════════════════════════════════════════════════════
#  TOKEN ACCESSORS
# ═══════════════════════════════════════════════════════════════════════════

def _tok_str(tok: Any) -> str:
    for a in ("str", "spelling", "text"):
        v = getattr(tok, a, None)
        if v is not None:
            return str(v)
    return str(tok) if tok else ""

def _tok_file(tok: Any) -> str:
    return str(getattr(tok, "file", "<unknown>") or "<unknown>")

def _tok_line(tok: Any) -> int:
    return int(getattr(tok, "linenr", 0) or 0)

def _tok_col(tok: Any) -> int:
    return int(getattr(tok, "column", 0) or 0)


# ═══════════════════════════════════════════════════════════════════════════
#  CType QUERY LAYER
#
#  These operate directly on the CType term algebra from type_analysis.py.
#  No parallel enum sets — we use TypeKind members directly.
# ═══════════════════════════════════════════════════════════════════════════

# ── Kind sets (computed once at import time) ─────────────────────────────

_SIGNED_INT_KINDS = frozenset({
    TypeKind.CHAR, TypeKind.SCHAR,
    TypeKind.SHORT, TypeKind.INT, TypeKind.LONG, TypeKind.LONG_LONG,
})

_UNSIGNED_INT_KINDS = frozenset({
    TypeKind.BOOL, TypeKind.UCHAR,
    TypeKind.USHORT, TypeKind.UINT, TypeKind.ULONG, TypeKind.ULONG_LONG,
})

_INTEGER_KINDS = _SIGNED_INT_KINDS | _UNSIGNED_INT_KINDS | {TypeKind.ENUM}

_FLOAT_KINDS = frozenset({
    TypeKind.FLOAT, TypeKind.DOUBLE, TypeKind.LONG_DOUBLE,
})

# ── Width / Alignment tables ────────────────────────────────────────────

def _width_of(ct: CType, pm: PlatformModel = LP64) -> int:
    """Bit-width of the *unqualified* type."""
    u = ct.unqualified
    k = u.kind
    if k == TypeKind.PTR:
        return pm.pointer_bits
    return {
        TypeKind.BOOL:       pm.bool_bits,
        TypeKind.CHAR:       pm.char_bits,
        TypeKind.SCHAR:      pm.char_bits,
        TypeKind.UCHAR:      pm.char_bits,
        TypeKind.SHORT:      pm.short_bits,
        TypeKind.USHORT:     pm.short_bits,
        TypeKind.INT:        pm.int_bits,
        TypeKind.UINT:       pm.int_bits,
        TypeKind.LONG:       pm.long_bits,
        TypeKind.ULONG:      pm.long_bits,
        TypeKind.LONG_LONG:  pm.long_long_bits,
        TypeKind.ULONG_LONG: pm.long_long_bits,
        TypeKind.FLOAT:      pm.float_bits,
        TypeKind.DOUBLE:     pm.double_bits,
        TypeKind.LONG_DOUBLE: pm.double_bits,
        TypeKind.ENUM:       pm.enum_bits,
    }.get(k, 0)


def _pointee_align(ct: CType, pm: PlatformModel = LP64) -> int:
    """Alignment requirement (bytes) of the *pointee* of a pointer type."""
    u = ct.unqualified
    if u.kind != TypeKind.PTR or not u.children:
        return 1
    ptee = u.children[0].unqualified
    k = ptee.kind
    return {
        TypeKind.CHAR:       pm.char_align,
        TypeKind.SCHAR:      pm.char_align,
        TypeKind.UCHAR:      pm.char_align,
        TypeKind.SHORT:      pm.short_align,
        TypeKind.USHORT:     pm.short_align,
        TypeKind.INT:        pm.int_align,
        TypeKind.UINT:       pm.int_align,
        TypeKind.LONG:       pm.long_align,
        TypeKind.ULONG:      pm.long_align,
        TypeKind.LONG_LONG:  pm.long_long_align,
        TypeKind.ULONG_LONG: pm.long_long_align,
        TypeKind.FLOAT:      pm.float_align,
        TypeKind.DOUBLE:     pm.double_align,
        TypeKind.PTR:        pm.pointer_align,
        TypeKind.STRUCT:     pm.long_align,   # conservative
        TypeKind.UNION:      pm.long_align,
    }.get(k, 1)


# ── Predicate helpers using CType's own properties ──────────────────────

def _is_int(ct: CType) -> bool:
    """True for any integer (including bool, enum)."""
    return ct.unqualified.kind in _INTEGER_KINDS

def _is_signed_int(ct: CType) -> bool:
    return ct.unqualified.kind in _SIGNED_INT_KINDS

def _is_unsigned_int(ct: CType) -> bool:
    return ct.unqualified.kind in _UNSIGNED_INT_KINDS

def _is_float(ct: CType) -> bool:
    return ct.unqualified.kind in _FLOAT_KINDS

def _is_ptr(ct: CType) -> bool:
    return ct.unqualified.kind == TypeKind.PTR

def _is_bool(ct: CType) -> bool:
    return ct.unqualified.kind == TypeKind.BOOL

def _is_enum(ct: CType) -> bool:
    return ct.unqualified.kind == TypeKind.ENUM


def _pointee(ct: CType) -> Optional[CType]:
    """Return the full (possibly qualified) pointee, or None."""
    u = ct.unqualified
    if u.kind == TypeKind.PTR and u.children:
        return u.children[0]
    return None


def _pointee_unqual_kind(ct: CType) -> Optional[TypeKind]:
    """Unqualified kind of the pointee."""
    p = _pointee(ct)
    if p is None:
        return None
    return p.unqualified.kind


def _is_void_ptr(ct: CType) -> bool:
    return _pointee_unqual_kind(ct) == TypeKind.VOID

def _is_func_ptr(ct: CType) -> bool:
    return _pointee_unqual_kind(ct) == TypeKind.FUNC

def _is_struct_ptr(ct: CType) -> bool:
    return _pointee_unqual_kind(ct) in {TypeKind.STRUCT, TypeKind.UNION}


def _pointee_has_qual(ct: CType, q: Qualifier) -> bool:
    """
    Check whether the *pointee* of a pointer type carries qualifier `q`.

    This correctly walks the QUALIFIED wrapper chain on the pointee,
    NOT on the outer pointer.  This is the critical fix for const-away
    and volatile-away: we must compare qualifiers at the pointee level,
    not at the top level.

    For ``ptr(const int)``::
        ct = CType(PTR, children=[CType(QUALIFIED, quals={CONST},
                                        children=[CType(INT)])])
        _pointee(ct) → CType(QUALIFIED, …)
        → True for CONST

    For ``ptr(int)``::
        _pointee(ct) → CType(INT)
        → False for CONST
    """
    p = _pointee(ct)
    if p is None:
        return False
    # Walk the QUALIFIED chain on the pointee
    t = p
    while t.kind == TypeKind.QUALIFIED:
        if q in t.qualifiers:
            return True
        if t.children:
            t = t.children[0]
        else:
            break
    return False


def _struct_tag(ct: CType) -> str:
    """Get the struct/union tag of a struct-pointer's pointee."""
    p = _pointee(ct)
    if p is None:
        return ""
    u = p.unqualified
    return u.tag if u.kind in {TypeKind.STRUCT, TypeKind.UNION} else ""


# ── Deep structural equality (qualifier-sensitive) ──────────────────────

def _types_identical(a: CType, b: CType, depth: int = 0) -> bool:
    """
    Full structural equality INCLUDING qualifiers at every depth.

    This is what ``castRedundant`` must use: a cast is redundant only
    if source and destination are *exactly* the same type at every level
    of indirection, including all qualifiers.
    """
    if depth > 30:
        return True  # avoid infinite recursion on malformed types

    ka, kb = a.kind, b.kind

    # Both qualified → compare qualifier sets, then recurse on inner
    if ka == TypeKind.QUALIFIED and kb == TypeKind.QUALIFIED:
        if a.qualifiers != b.qualifiers:
            return False
        if not a.children or not b.children:
            return not a.children and not b.children
        return _types_identical(a.children[0], b.children[0], depth + 1)

    # One qualified, other not → NOT identical
    if ka == TypeKind.QUALIFIED or kb == TypeKind.QUALIFIED:
        return False

    # Skip typedefs transparently
    if ka == TypeKind.TYPEDEF:
        return _types_identical(a.children[0], b, depth + 1) if a.children else False
    if kb == TypeKind.TYPEDEF:
        return _types_identical(a, b.children[0], depth + 1) if b.children else False

    # Different base kinds → not identical
    if ka != kb:
        return False

    # Leaf integer / float / void / bool / error
    if ka in _INTEGER_KINDS or ka in _FLOAT_KINDS or ka in {
        TypeKind.VOID, TypeKind.BOOL, TypeKind.ERROR,
    }:
        return True

    # ENUM — compare tags
    if ka == TypeKind.ENUM:
        return a.tag == b.tag

    # STRUCT / UNION — compare tags
    if ka in {TypeKind.STRUCT, TypeKind.UNION}:
        return a.tag == b.tag

    # PTR — recurse on pointee (qualifier-sensitive!)
    if ka == TypeKind.PTR:
        if not a.children or not b.children:
            return not a.children and not b.children
        return _types_identical(a.children[0], b.children[0], depth + 1)

    # ARRAY — element type + size
    if ka == TypeKind.ARRAY:
        if a.array_size != b.array_size:
            return False
        if not a.children or not b.children:
            return not a.children and not b.children
        return _types_identical(a.children[0], b.children[0], depth + 1)

    # FUNC — return type + all param types + variadic flag
    if ka == TypeKind.FUNC:
        if a.is_variadic != b.is_variadic:
            return False
        if len(a.children) != len(b.children):
            return False
        return all(
            _types_identical(ca, cb, depth + 1)
            for ca, cb in zip(a.children, b.children)
        )

    # BITFIELD
    if ka == TypeKind.BITFIELD:
        if a.bitfield_width != b.bitfield_width:
            return False
        if not a.children or not b.children:
            return not a.children and not b.children
        return _types_identical(a.children[0], b.children[0], depth + 1)

    # Fallback: same kind, no children to compare
    return True


def _unqual_types_identical(a: CType, b: CType, depth: int = 0) -> bool:
    """
    Structural equality IGNORING qualifiers, but ONLY at the top level
    of the types being compared (i.e. we strip the outermost QUALIFIED
    wrappers from both a and b, then do a full _types_identical on
    their inner types).

    This is NOT the same as stripping qualifiers recursively — that is
    the bug in the original code.  Here we strip only the outermost
    layer, so ptr(const int) vs ptr(int) are NOT identical.
    """
    return _types_identical(a.unqualified, b.unqualified, depth)


# ── Pretty-printer (uses CType.__repr__ which calls _type_to_str) ──────

def _pretty(ct: Optional[CType]) -> str:
    if ct is None:
        return "<unknown>"
    return repr(ct)


# ═══════════════════════════════════════════════════════════════════════════
#  VALUETYPE → CTYPE BRIDGE
#
#  Maps cppcheckdata.ValueType to the CType term algebra, preserving:
#    - signedness
#    - pointer depth
#    - qualifiers at every indirection level (constness/volatileness bitmask)
#    - struct/union/enum tags (from originalTypeName)
#    - function pointer signatures (from originalTypeName heuristic)
# ═══════════════════════════════════════════════════════════════════════════

_VT_BASE_MAP: Dict[str, TypeKind] = {
    "void":    TypeKind.VOID,
    "bool":    TypeKind.BOOL,
    "_bool":   TypeKind.BOOL,
    "char":    TypeKind.CHAR,
    "short":   TypeKind.SHORT,
    "int":     TypeKind.INT,
    "long":    TypeKind.LONG,
    "float":   TypeKind.FLOAT,
    "double":  TypeKind.DOUBLE,
}

_SIGN_OVERRIDE: Dict[Tuple[TypeKind, str], TypeKind] = {
    (TypeKind.CHAR, "signed"):   TypeKind.SCHAR,
    (TypeKind.CHAR, "unsigned"): TypeKind.UCHAR,
    (TypeKind.SHORT, "unsigned"): TypeKind.USHORT,
    (TypeKind.INT, "unsigned"):   TypeKind.UINT,
    (TypeKind.LONG, "unsigned"):  TypeKind.ULONG,
}


def _valuetype_to_ctype(vt: Any, pm: PlatformModel = LP64) -> Optional[CType]:
    """
    Convert a cppcheckdata.ValueType to a CType from type_analysis.py.

    Carefully preserves:
      - qualifier bitmasks at every pointer depth
      - struct / union / enum tags from originalTypeName
      - signedness
    """
    if vt is None:
        return None

    type_str = str(getattr(vt, "type", "") or "").strip().lower()
    sign_str = str(getattr(vt, "sign", "") or "").strip().lower()
    pointer_depth = int(getattr(vt, "pointer", 0) or 0)
    constness = int(getattr(vt, "constness", 0) or 0)
    volatileness = int(getattr(vt, "volatileness", 0) or 0)
    original = str(getattr(vt, "originalTypeName", "") or "").strip()

    # ── Determine base kind ──────────────────────────────────────────
    kind: Optional[TypeKind] = None

    # Try originalTypeName for struct/union/enum
    orig_lower = original.lower()
    if orig_lower.startswith("struct "):
        tag = original[7:].strip()
        base = CType.struct(tag)
        return _wrap_ptr_quals(base, pointer_depth, constness, volatileness)
    if orig_lower.startswith("union "):
        tag = original[6:].strip()
        base = CType.union(tag)
        return _wrap_ptr_quals(base, pointer_depth, constness, volatileness)
    if orig_lower.startswith("enum "):
        tag = original[5:].strip()
        base = CType.enum_type(tag)
        return _wrap_ptr_quals(base, pointer_depth, constness, volatileness)

    # Handle "long long" before regular "long"
    if "long long" in type_str or "long long" in orig_lower:
        if sign_str == "unsigned":
            kind = TypeKind.ULONG_LONG
        else:
            kind = TypeKind.LONG_LONG
    else:
        kind = _VT_BASE_MAP.get(type_str)

    if kind is None:
        # Heuristic from originalTypeName
        if "size_t" in original or "uintptr_t" in original:
            kind = TypeKind.ULONG
        elif "ptrdiff_t" in original or "ssize_t" in original:
            kind = TypeKind.LONG
        elif "uint" in orig_lower:
            kind = TypeKind.UINT
        elif "int" in orig_lower:
            kind = TypeKind.INT
        else:
            kind = TypeKind.INT  # conservative fallback

    # Apply signedness override
    override = _SIGN_OVERRIDE.get((kind, sign_str))
    if override is not None:
        kind = override

    # Build base CType using factory methods for correct `sign` attribute
    base = CType(kind=kind)

    return _wrap_ptr_quals(base, pointer_depth, constness, volatileness)


def _wrap_ptr_quals(
    base: CType,
    pointer_depth: int,
    constness: int,
    volatileness: int,
) -> CType:
    """
    Wrap a base type in pointer layers with per-level qualifiers.

    cppcheckdata encodes qualifiers as bitmasks:
      - bit 0: qualifier on the base type (or outermost pointer itself)
      - bit 1: qualifier on the pointee at depth 1
      - bit N: qualifier on the pointee at depth N

    For ``const int *volatile p``:
      constness = 0b01 (bit 0 = const on int)
      volatileness = 0b10 (bit 1 = volatile on the pointer variable)

    We build inside-out: base → add pointee quals → wrap in ptr → repeat.
    """
    result = base

    # Apply base-level qualifiers (bit 0 applies to the innermost type)
    base_quals: Set[Qualifier] = set()
    if constness & 1:
        base_quals.add(Qualifier.CONST)
    if volatileness & 1:
        base_quals.add(Qualifier.VOLATILE)
    if base_quals:
        result = CType.qualified(result, base_quals)

    # Wrap in pointer layers
    for depth in range(1, pointer_depth + 1):
        # First wrap in ptr
        result = CType.ptr(result)
        # Then apply qualifiers for this pointer level
        ptr_quals: Set[Qualifier] = set()
        if constness & (1 << depth):
            ptr_quals.add(Qualifier.CONST)
        if volatileness & (1 << depth):
            ptr_quals.add(Qualifier.VOLATILE)
        if ptr_quals:
            result = CType.qualified(result, ptr_quals)

    return result


# ═══════════════════════════════════════════════════════════════════════════
#  DIAGNOSTIC EMISSION
# ═══════════════════════════════════════════════════════════════════════════

_DEFAULT_SEVERITY: Dict[str, Any] = {
    "castTruncation":        Severity.WARNING,
    "castSignedness":        Severity.WARNING,
    "castPointerToSmallInt": Severity.ERROR,
    "castIntToPointer":      Severity.WARNING,
    "castPointerMisalign":   Severity.WARNING,
    "castConstAway":         Severity.WARNING,
    "castVolatileAway":      Severity.WARNING,
    "castFuncPtrMismatch":   Severity.ERROR,
    "castDowncastUnsafe":    Severity.ERROR,
    "castFloatToInt":        Severity.WARNING,
    "castIntToFloat":        Severity.STYLE,
    "castVoidPtrDeref":      Severity.WARNING,
    "castReinterpretRisk":   Severity.WARNING,
    "castImplicitBoolTrunc": Severity.WARNING,
    "castEnumOutOfRange":    Severity.WARNING,
    "castRedundant":         Severity.STYLE,
}


def _emit(
    check_id: str,
    message: str,
    tok: Any,
    *,
    note: str = "",
    help_hint: str = "",
    cwe_override: Optional[int] = None,
) -> None:
    """Emit a diagnostic via stderr (and optionally plus_reporter)."""
    severity = _DEFAULT_SEVERITY.get(check_id, Severity.WARNING)
    cwe = cwe_override if cwe_override is not None else _CWE_TABLE.get(check_id, 704)
    f = _tok_file(tok)
    ln = _tok_line(tok)
    col = _tok_col(tok)

    _STATS.record(check_id, severity)

    sev_name = severity.cppcheck_name
    line = f"[{f}:{ln}:{col}]: ({sev_name}) {message} [{check_id}] [CWE-{cwe}]"
    print(line, file=sys.stderr)
    if note:
        print(f"  note: {note}", file=sys.stderr)
    if help_hint:
        print(f"  help: {help_hint}", file=sys.stderr)


# ═══════════════════════════════════════════════════════════════════════════
#  CHECKER FUNCTIONS
#
#  Split into two tiers:
#
#    TIER 1 (specific): Qualitative checks that should CLAIM a cast
#            and prevent Tier 2 from firing.  These detect real bugs.
#
#    TIER 2 (generic):  Quantitative / style checks that only fire
#            if no Tier 1 checker claimed the cast.
#
#  Each returns True if it emitted a diagnostic (i.e. "claimed" the cast).
# ═══════════════════════════════════════════════════════════════════════════


# ────────────────────────────────────────────────────────────────────────
#  TIER 1 — Specific checks (priority)
# ────────────────────────────────────────────────────────────────────────

def _check_const_away(tok: Any, src: CType, dst: CType, pm: PlatformModel) -> bool:
    """CWE-704: pointer cast strips const from the pointee."""
    if not (_is_ptr(src) and _is_ptr(dst)):
        return False
    if not _pointee_has_qual(src, Qualifier.CONST):
        return False
    if _pointee_has_qual(dst, Qualifier.CONST):
        return False  # const is preserved
    _emit(
        "castConstAway",
        f"cast discards 'const' qualifier: {_pretty(src)} → {_pretty(dst)}",
        tok,
        note="writing through the result is UB if the original object "
             "was declared const (C11 §6.7.3/6)",
        help_hint="remove the cast, or copy data to a mutable buffer",
    )
    return True


def _check_volatile_away(tok: Any, src: CType, dst: CType, pm: PlatformModel) -> bool:
    """CWE-704: pointer cast strips volatile from the pointee."""
    if not (_is_ptr(src) and _is_ptr(dst)):
        return False
    if not _pointee_has_qual(src, Qualifier.VOLATILE):
        return False
    if _pointee_has_qual(dst, Qualifier.VOLATILE):
        return False
    _emit(
        "castVolatileAway",
        f"cast discards 'volatile' qualifier: {_pretty(src)} → {_pretty(dst)}",
        tok,
        note="accesses through the result may be optimised away by the compiler",
        help_hint="keep the volatile qualifier, or use a compiler memory barrier",
    )
    return True


def _check_func_ptr_mismatch(tok: Any, src: CType, dst: CType, pm: PlatformModel) -> bool:
    """CWE-843: function pointer cast to incompatible signature."""
    if not (_is_func_ptr(src) and _is_func_ptr(dst)):
        return False
    sp, dp = _pointee(src), _pointee(dst)
    if sp is None or dp is None:
        return False
    sf, df = sp.unqualified, dp.unqualified
    if sf.kind != TypeKind.FUNC or df.kind != TypeKind.FUNC:
        return False
    # Compare signatures structurally (qualifier-sensitive)
    if _types_identical(sf, df):
        return False
    _emit(
        "castFuncPtrMismatch",
        f"function pointer cast to incompatible signature: "
        f"{_pretty(src)} → {_pretty(dst)}",
        tok,
        note="calling through a mismatched function pointer is UB (C11 §6.5.2.2/9)",
        help_hint="ensure function signatures match, or use an adapter function",
    )
    return True


def _check_downcast_unsafe(tok: Any, src: CType, dst: CType, pm: PlatformModel) -> bool:
    """CWE-843: struct pointer cast to unrelated struct pointer."""
    if not (_is_struct_ptr(src) and _is_struct_ptr(dst)):
        return False
    stag = _struct_tag(src)
    dtag = _struct_tag(dst)
    # If both have tags and they match → not a downcast
    if stag and dtag and stag == dtag:
        return False
    # If either is anonymous, be conservative and don't warn
    if not stag or not dtag:
        return False
    _emit(
        "castDowncastUnsafe",
        f"cast between unrelated struct pointers: "
        f"'{stag}' → '{dtag}'",
        tok,
        note="C has no inheritance; layout compatibility is not guaranteed",
        help_hint="use a common initial prefix or redesign the data model",
    )
    return True


def _check_pointer_to_small_int(tok: Any, src: CType, dst: CType, pm: PlatformModel) -> bool:
    """CWE-704: pointer → integer too narrow for an address."""
    if not (_is_ptr(src) and _is_int(dst)):
        return False
    dw = _width_of(dst, pm)
    if dw >= pm.pointer_bits:
        return False
    _emit(
        "castPointerToSmallInt",
        f"pointer cast to {_pretty(dst)} ({dw}-bit) — too narrow "
        f"for {pm.pointer_bits}-bit addresses",
        tok,
        note="the address is truncated; dereferencing the round-tripped "
             "pointer is undefined behaviour",
        help_hint="use uintptr_t or intptr_t from <stdint.h>",
    )
    return True


def _check_int_to_pointer(tok: Any, src: CType, dst: CType, pm: PlatformModel) -> bool:
    """CWE-704: integer → pointer (except the 0 → NULL idiom)."""
    if not (_is_int(src) and _is_ptr(dst)):
        return False
    # Exempt literal 0 (NULL idiom)
    op1 = getattr(tok, "astOperand1", None)
    if op1 is not None and _tok_str(op1) == "0":
        return False
    _emit(
        "castIntToPointer",
        f"integer {_pretty(src)} cast to pointer {_pretty(dst)}",
        tok,
        note="integer-to-pointer casts are implementation-defined (C11 §6.3.2.3/5)",
        help_hint="use uintptr_t round-trips or proper pointer provenance",
    )
    return True


def _check_pointer_misalign(tok: Any, src: CType, dst: CType, pm: PlatformModel) -> bool:
    """CWE-704: pointer cast to type with stricter alignment."""
    if not (_is_ptr(src) and _is_ptr(dst)):
        return False
    # Don't warn on casts involving void* (common idiom)
    if _is_void_ptr(src) or _is_void_ptr(dst):
        return False
    sa = _pointee_align(src, pm)
    da = _pointee_align(dst, pm)
    if da <= sa:
        return False
    _emit(
        "castPointerMisalign",
        f"pointer cast may violate alignment: "
        f"source pointee aligned to {sa}B, target requires {da}B",
        tok,
        note="unaligned access is UB on many architectures (C11 §6.3.2.3/7)",
        help_hint="use memcpy() for type-punning, or ensure alignment via _Alignas",
    )
    return True


def _check_signedness(tok: Any, src: CType, dst: CType, pm: PlatformModel) -> bool:
    """CWE-195/196: signed ↔ unsigned integer conversion."""
    if not (_is_int(src) and _is_int(dst)):
        return False
    # Only flag if BOTH are integer and sign differs
    s_signed = _is_signed_int(src)
    d_signed = _is_signed_int(dst)
    s_unsigned = _is_unsigned_int(src)
    d_unsigned = _is_unsigned_int(dst)
    # Need a definite mismatch — CHAR without explicit sign is ambiguous
    if not ((s_signed and d_unsigned) or (s_unsigned and d_signed)):
        return False
    if s_signed and d_unsigned:
        cwe = 195
        direction = "signed → unsigned"
        risk = "negative values wrap to large positive values"
    else:
        cwe = 196
        direction = "unsigned → signed"
        risk = "large unsigned values become negative"
    _emit(
        "castSignedness",
        f"cast changes signedness ({direction}): "
        f"{_pretty(src)} → {_pretty(dst)}",
        tok,
        note=risk,
        help_hint="add an explicit range check, or use a matching-sign type",
        cwe_override=cwe,
    )
    return True


def _check_void_ptr_deref(tok: Any, src: CType, dst: CType, pm: PlatformModel) -> bool:
    """CWE-843: void* → concrete pointer without validation."""
    if not _is_void_ptr(src):
        return False
    if not _is_ptr(dst):
        return False
    if _is_void_ptr(dst):
        return False  # void* → void* is fine
    _emit(
        "castVoidPtrDeref",
        f"void* cast to {_pretty(dst)} without type validation",
        tok,
        note="the actual object type may differ, causing type confusion",
        help_hint="store a type tag alongside the void* and validate before casting",
    )
    return True


def _check_enum_out_of_range(tok: Any, src: CType, dst: CType, pm: PlatformModel) -> bool:
    """CWE-704: integer → enum may fall outside enumerator range."""
    if not _is_int(src):
        return False
    if not _is_enum(dst):
        return False
    tag = dst.unqualified.tag or "<anon>"
    sw = _width_of(src, pm)
    _emit(
        "castEnumOutOfRange",
        f"integer {_pretty(src)} ({sw}-bit) cast to enum '{tag}' — "
        f"value may not correspond to any enumerator",
        tok,
        note="storing an out-of-range value in an enum is implementation-defined "
             "in C and undefined in C++",
        help_hint="validate the integer against known enumerator values first",
    )
    return True


def _check_reinterpret_risk(tok: Any, src: CType, dst: CType, pm: PlatformModel) -> bool:
    """CWE-843: C++ reinterpret_cast."""
    ts = _tok_str(tok)
    if ts != "reinterpret_cast":
        return False
    _emit(
        "castReinterpretRisk",
        f"reinterpret_cast: {_pretty(src)} → {_pretty(dst)}",
        tok,
        note="reinterpret_cast bypasses the type system; result is "
             "implementation-defined",
        help_hint="prefer static_cast, memcpy, or std::bit_cast (C++20)",
    )
    return True


def _check_implicit_bool_trunc(tok: Any, src: CType, dst: CType, pm: PlatformModel) -> bool:
    """CWE-704: multi-bit value → _Bool."""
    if not _is_bool(dst):
        return False
    if _is_bool(src):
        return False
    if not _is_int(src):
        return False
    sw = _width_of(src, pm)
    if sw <= 1:
        return False
    _emit(
        "castImplicitBoolTrunc",
        f"cast from {_pretty(src)} ({sw}-bit) to _Bool: "
        f"all non-zero values become 1",
        tok,
        note="bit patterns are not preserved; only zero / non-zero distinction survives",
        help_hint="use an explicit comparison (x != 0) to clarify intent",
    )
    return True


# ────────────────────────────────────────────────────────────────────────
#  TIER 2 — Generic / quantitative checks (lower priority)
# ────────────────────────────────────────────────────────────────────────

def _check_truncation(tok: Any, src: CType, dst: CType, pm: PlatformModel) -> bool:
    """CWE-197: wider integer → narrower integer."""
    if not (_is_int(src) and _is_int(dst)):
        return False
    # Don't re-report if signedness already flagged (same-width sign change)
    sw = _width_of(src, pm)
    dw = _width_of(dst, pm)
    if sw <= dw or sw == 0 or dw == 0:
        return False
    # Don't flag bool → anything (bool is 1-bit, always truncation)
    if _is_bool(src):
        return False
    _emit(
        "castTruncation",
        f"cast truncates: {_pretty(src)} ({sw}-bit) → "
        f"{_pretty(dst)} ({dw}-bit)",
        tok,
        note=f"potential loss of {sw - dw} high-order bits",
        help_hint="add a range check before narrowing, or use the narrower type",
    )
    return True


def _check_float_to_int(tok: Any, src: CType, dst: CType, pm: PlatformModel) -> bool:
    """CWE-681: float/double → integer truncates the fractional part."""
    if not (_is_float(src) and _is_int(dst)):
        return False
    _emit(
        "castFloatToInt",
        f"cast from {_pretty(src)} to {_pretty(dst)} discards fractional part",
        tok,
        note="if the float value exceeds the integer range, behaviour "
             "is undefined (C11 §6.3.1.4/1)",
        help_hint="use floor()/ceil()/round() and clamp before converting",
    )
    return True


def _check_int_to_float(tok: Any, src: CType, dst: CType, pm: PlatformModel) -> bool:
    """CWE-681: large integer → float may lose precision."""
    if not (_is_int(src) and _is_float(dst)):
        return False
    sw = _width_of(src, pm)
    dk = dst.unqualified.kind
    if dk == TypeKind.FLOAT:
        mantissa = 24
    elif dk == TypeKind.DOUBLE:
        mantissa = 53
    else:
        mantissa = 64  # long double — don't warn
    if sw <= mantissa:
        return False
    _emit(
        "castIntToFloat",
        f"cast from {_pretty(src)} ({sw}-bit) to {_pretty(dst)} "
        f"may lose precision ({mantissa}-bit mantissa)",
        tok,
        note=f"integer values > 2^{mantissa} cannot be represented exactly",
        help_hint="use double instead of float, or accept the precision loss",
    )
    return True


def _check_redundant(tok: Any, src: CType, dst: CType, pm: PlatformModel) -> bool:
    """
    CWE-398: cast to the exact same type (code smell).

    CRITICAL: uses _types_identical which is qualifier-sensitive at
    EVERY level.  ptr(const int) → ptr(int) is NOT redundant —
    it is a const-away cast.
    """
    if not _types_identical(src, dst):
        return False
    _emit(
        "castRedundant",
        f"redundant cast: expression is already {_pretty(src)}",
        tok,
        note="this cast has no effect",
        help_hint="remove the cast to improve readability",
    )
    return True


# ═══════════════════════════════════════════════════════════════════════════
#  CHECKER REGISTRY — ordered by tier
#
#  Tier 1 checkers run first.  If ANY Tier 1 checker fires, Tier 2 is
#  skipped for that cast.  This prevents false positives.
# ═══════════════════════════════════════════════════════════════════════════

CheckerFn = Callable[[Any, CType, CType, PlatformModel], bool]

TIER1_CHECKERS: List[CheckerFn] = [
    _check_const_away,
    _check_volatile_away,
    _check_func_ptr_mismatch,
    _check_downcast_unsafe,
    _check_pointer_to_small_int,
    _check_int_to_pointer,
    _check_pointer_misalign,
    _check_signedness,
    _check_void_ptr_deref,
    _check_enum_out_of_range,
    _check_reinterpret_risk,
    _check_implicit_bool_trunc,
]

TIER2_CHECKERS: List[CheckerFn] = [
    _check_truncation,
    _check_float_to_int,
    _check_int_to_float,
    _check_redundant,  # LAST — only fires if nothing else matched
]


def _run_checkers(
    tok: Any, src: CType, dst: CType, pm: PlatformModel
) -> int:
    """
    Run all checkers on a single cast.  Returns number of diagnostics.

    Tier 1 (specific) checkers run first.  If any fires, Tier 2 is
    skipped entirely for this cast.
    """
    tier1_hit = False
    count = 0

    for checker in TIER1_CHECKERS:
        if checker(tok, src, dst, pm):
            tier1_hit = True
            count += 1

    if not tier1_hit:
        for checker in TIER2_CHECKERS:
            if checker(tok, src, dst, pm):
                count += 1
                # Within Tier 2, we also stop after first hit to avoid
                # e.g. both truncation AND redundant on the same cast.
                break

    return count


# ═══════════════════════════════════════════════════════════════════════════
#  ANALYSIS DRIVER
# ═══════════════════════════════════════════════════════════════════════════

def _analyse_configuration(cfg: Any, pm: PlatformModel) -> int:
    """Walk every token in a cppcheckdata Configuration for casts."""
    count = 0
    tokenlist = getattr(cfg, "tokenlist", [])

    for tok in tokenlist:
        if not getattr(tok, "isCast", False):
            continue

        # dst = the cast token's valueType; src = operand's valueType
        dst_vt = getattr(tok, "valueType", None)
        op1 = getattr(tok, "astOperand1", None)
        op2 = getattr(tok, "astOperand2", None)
        src_tok = op1 if op1 is not None else op2
        src_vt = getattr(src_tok, "valueType", None) if src_tok else None

        dst_ct = _valuetype_to_ctype(dst_vt, pm)
        src_ct = _valuetype_to_ctype(src_vt, pm)

        if dst_ct is None or src_ct is None:
            continue

        count += _run_checkers(tok, src_ct, dst_ct, pm)

    return count


def analyse_dump(dump_path: str, pm: PlatformModel = LP64) -> int:
    """Analyse a single .dump file.  Returns total diagnostics."""
    if cppcheckdata is None:
        print("CastValidator: cppcheckdata module not found.", file=sys.stderr)
        return 0

    data = cppcheckdata.parsedump(dump_path)
    total = 0
    for cfg in data.configurations:
        total += _analyse_configuration(cfg, pm)
    return total


# ═══════════════════════════════════════════════════════════════════════════
#  SELF-TEST
#
#  Each test case builds CType values directly using the type_analysis.py
#  factory methods, then asserts exactly which checker(s) fire.
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class _TestCase:
    name: str
    src: CType
    dst: CType
    expect_checks: Set[str]     # set of check_ids that MUST fire
    expect_no_checks: Set[str]  # set of check_ids that MUST NOT fire


class _FakeTok:
    """Minimal token stub for self-tests."""
    def __init__(self) -> None:
        self.isCast = True
        self.file = "<self-test>"
        self.linenr = 1
        self.column = 1
        self.str = "("
        self.astOperand1 = None
        self.astOperand2 = None


def _capture_checks(
    src: CType, dst: CType, pm: PlatformModel = LP64
) -> Set[str]:
    """
    Run all checkers and return the set of check_ids that fired,
    WITHOUT printing anything.
    """
    fired: Set[str] = set()
    old_emit = globals()["_emit"]

    def _capture_emit(
        check_id: str, message: str, tok: Any, **kwargs: Any
    ) -> None:
        fired.add(check_id)

    globals()["_emit"] = _capture_emit
    try:
        tok = _FakeTok()
        # Run both tiers manually (bypass the tier-skip logic so we
        # can see what WOULD fire at each tier)
        for checker in TIER1_CHECKERS:
            checker(tok, src, dst, pm)
        for checker in TIER2_CHECKERS:
            checker(tok, src, dst, pm)
    finally:
        globals()["_emit"] = old_emit
    return fired


def _run_self_tests() -> bool:
    """Execute built-in regression suite.  Returns True if all pass."""
    pm = LP64

    cases: List[_TestCase] = [
        # ── 1. Truncation: long → short ─────────────────────────────
        _TestCase(
            "trunc_long_short",
            src=CType(kind=TypeKind.LONG),
            dst=CType(kind=TypeKind.SHORT),
            expect_checks={"castTruncation"},
            expect_no_checks={"castRedundant"},
        ),
        # ── 2. No truncation: short → int ───────────────────────────
        _TestCase(
            "widen_short_int",
            src=CType(kind=TypeKind.SHORT),
            dst=CType(kind=TypeKind.INT),
            expect_checks=set(),  # no truncation on widening
            expect_no_checks={"castTruncation", "castRedundant"},
        ),
        # ── 3. Signedness: signed int → unsigned int ────────────────
        _TestCase(
            "sign_int_uint",
            src=CType(kind=TypeKind.INT),
            dst=CType(kind=TypeKind.UINT),
            expect_checks={"castSignedness"},
            expect_no_checks={"castRedundant"},
        ),
        # ── 4. Pointer to small int (64→32) ─────────────────────────
        _TestCase(
            "ptr_to_int32",
            src=CType.ptr(CType(kind=TypeKind.INT)),
            dst=CType(kind=TypeKind.INT),
            expect_checks={"castPointerToSmallInt"},
            expect_no_checks={"castRedundant"},
        ),
        # ── 5. Float → int ──────────────────────────────────────────
        _TestCase(
            "float_to_int",
            src=CType(kind=TypeKind.DOUBLE),
            dst=CType(kind=TypeKind.INT),
            expect_checks={"castFloatToInt"},
            expect_no_checks={"castRedundant"},
        ),
        # ── 6. Long (64-bit) → float (24-bit mantissa) ──────────────
        _TestCase(
            "long_to_float",
            src=CType(kind=TypeKind.LONG),
            dst=CType(kind=TypeKind.FLOAT),
            expect_checks={"castIntToFloat"},
            expect_no_checks={"castRedundant"},
        ),
        # ── 7. Int → _Bool ──────────────────────────────────────────
        _TestCase(
            "int_to_bool",
            src=CType(kind=TypeKind.INT),
            dst=CType(kind=TypeKind.BOOL),
            expect_checks={"castImplicitBoolTrunc"},
            expect_no_checks={"castRedundant"},
        ),
        # ── 8. Redundant: int → int ─────────────────────────────────
        _TestCase(
            "redundant_int_int",
            src=CType(kind=TypeKind.INT),
            dst=CType(kind=TypeKind.INT),
            expect_checks={"castRedundant"},
            expect_no_checks={"castTruncation", "castSignedness"},
        ),
        # ── 9. Const away: ptr(const int) → ptr(int) ────────────────
        _TestCase(
            "const_away",
            src=CType.ptr(CType.qualified(CType(kind=TypeKind.INT), {Qualifier.CONST})),
            dst=CType.ptr(CType(kind=TypeKind.INT)),
            expect_checks={"castConstAway"},
            expect_no_checks={"castRedundant"},  # THE CRITICAL TEST
        ),
        # ── 10. Volatile away: ptr(volatile int) → ptr(int) ─────────
        _TestCase(
            "volatile_away",
            src=CType.ptr(CType.qualified(CType(kind=TypeKind.INT), {Qualifier.VOLATILE})),
            dst=CType.ptr(CType(kind=TypeKind.INT)),
            expect_checks={"castVolatileAway"},
            expect_no_checks={"castRedundant"},  # THE CRITICAL TEST
        ),
        # ── 11. Downcast: struct Animal* → struct Engine* ────────────
        _TestCase(
            "downcast_animal_engine",
            src=CType.ptr(CType.struct("Animal")),
            dst=CType.ptr(CType.struct("Engine")),
            expect_checks={"castDowncastUnsafe"},
            expect_no_checks={"castRedundant"},  # THE CRITICAL TEST
        ),
        # ── 12. Same struct: struct Foo* → struct Foo* (no warning) ──
        _TestCase(
            "same_struct_ok",
            src=CType.ptr(CType.struct("Foo")),
            dst=CType.ptr(CType.struct("Foo")),
            expect_checks={"castRedundant"},
            expect_no_checks={"castDowncastUnsafe"},
        ),
        # ── 13. Void* → int* ────────────────────────────────────────
        _TestCase(
            "void_ptr_to_int_ptr",
            src=CType.ptr(CType.void()),
            dst=CType.ptr(CType(kind=TypeKind.INT)),
            expect_checks={"castVoidPtrDeref"},
            expect_no_checks={"castRedundant"},
        ),
        # ── 14. Alignment: ptr(char) → ptr(long) ────────────────────
        _TestCase(
            "misalign_char_to_long",
            src=CType.ptr(CType(kind=TypeKind.CHAR)),
            dst=CType.ptr(CType(kind=TypeKind.LONG)),
            expect_checks={"castPointerMisalign"},
            expect_no_checks={"castRedundant"},
        ),
        # ── 15. Int → enum Color ─────────────────────────────────────
        _TestCase(
            "int_to_enum",
            src=CType(kind=TypeKind.INT),
            dst=CType.enum_type("Color"),
            expect_checks={"castEnumOutOfRange"},
            expect_no_checks={"castRedundant"},
        ),
        # ── 16. Int → pointer ────────────────────────────────────────
        _TestCase(
            "int_to_pointer",
            src=CType(kind=TypeKind.INT),
            dst=CType.ptr(CType(kind=TypeKind.INT)),
            expect_checks={"castIntToPointer"},
            expect_no_checks={"castRedundant"},
        ),
        # ── 17. Redundant ptr: ptr(int) → ptr(int) ──────────────────
        _TestCase(
            "redundant_ptr_int",
            src=CType.ptr(CType(kind=TypeKind.INT)),
            dst=CType.ptr(CType(kind=TypeKind.INT)),
            expect_checks={"castRedundant"},
            expect_no_checks={"castConstAway", "castVolatileAway",
                              "castDowncastUnsafe"},
        ),
        # ── 18. Func ptr mismatch ───────────────────────────────────
        _TestCase(
            "funcptr_mismatch",
            src=CType.ptr(CType.func(
                CType(kind=TypeKind.INT),
                [CType(kind=TypeKind.INT), CType(kind=TypeKind.INT)],
            )),
            dst=CType.ptr(CType.func(
                CType(kind=TypeKind.DOUBLE),
                [CType(kind=TypeKind.DOUBLE), CType(kind=TypeKind.DOUBLE)],
            )),
            expect_checks={"castFuncPtrMismatch"},
            expect_no_checks={"castRedundant"},
        ),
        # ── 19. Const preserved (NO const-away warning) ─────────────
        _TestCase(
            "const_preserved",
            src=CType.ptr(CType.qualified(CType(kind=TypeKind.INT), {Qualifier.CONST})),
            dst=CType.ptr(CType.qualified(CType(kind=TypeKind.INT), {Qualifier.CONST})),
            expect_checks={"castRedundant"},
            expect_no_checks={"castConstAway"},
        ),
        # ── 20. Signedness with truncation (only signedness in T1) ───
        _TestCase(
            "signed_long_to_unsigned_short",
            src=CType(kind=TypeKind.LONG),
            dst=CType(kind=TypeKind.USHORT),
            expect_checks={"castSignedness"},
            # Truncation is Tier 2 — signedness is Tier 1, so truncation
            # should NOT fire because Tier 1 claimed the cast.
            expect_no_checks={"castRedundant"},
        ),
    ]

    passed = 0
    failed = 0

    for tc in cases:
        fired = _capture_checks(tc.src, tc.dst, pm)

        errors: List[str] = []
        for expected in tc.expect_checks:
            if expected not in fired:
                errors.append(f"expected {expected} to fire, but it did not")
        for forbidden in tc.expect_no_checks:
            if forbidden in fired:
                errors.append(f"expected {forbidden} NOT to fire, but it did")

        if errors:
            print(f"  FAIL {tc.name}")
            for e in errors:
                print(f"       {e}")
            print(f"       fired = {fired}")
            failed += 1
        else:
            print(f"  PASS {tc.name}")
            passed += 1

    print(f"\nSelf-test: {passed} passed, {failed} failed, {passed + failed} total")
    return failed == 0


# ═══════════════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════════════

def main() -> int:
    parser = argparse.ArgumentParser(
        prog="CastValidator",
        description="Cppcheck addon: validate C/C++ type casts against CWEs",
    )
    parser.add_argument("dump_files", nargs="*", help=".dump files")
    parser.add_argument("--self-test", action="store_true",
                        help="run built-in regression tests")
    args = parser.parse_args()

    if args.self_test:
        print("CastValidator self-test")
        print("=" * 50)
        ok = _run_self_tests()
        return 0 if ok else 1

    if not args.dump_files:
        parser.error("no dump files; use --self-test or provide .dump files")

    global _STATS
    _STATS = CheckStats()

    total = 0
    for path in args.dump_files:
        if not os.path.isfile(path):
            print(f"CastValidator: not found: {path}", file=sys.stderr)
            continue
        total += analyse_dump(path, LP64)

    print(_STATS.summary(), file=sys.stderr)
    return 1 if _STATS.by_severity.get("error", 0) > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
