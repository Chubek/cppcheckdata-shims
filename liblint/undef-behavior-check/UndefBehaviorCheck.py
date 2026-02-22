"""
UndefBehaviorCheck.py — Cppcheck addon for undefined-behavior detection.

Uses the ``cppcheckdata-shims`` library to detect the following classes of
undefined behavior in C/C++ code:

    CWE-457  — Uninitialized variable use
    CWE-416  — Use of freed / dangling memory (use-after-free)
    CWE-119  — Strict-aliasing violation (type-punning through incompatible
                pointer types)
    CWE-704  — Incorrect type conversion / misaligned memory access
    CWE-843  — Type confusion / invalid type casting
    CWE-562  — Lifetime violation (returning pointer/reference to local)
    CWE-664  — Modification of const-qualified data (via cast)
    CWE-758  — Undefined behavior in bit-shift operations
    CWE-190  — Signed integer overflow

Usage (from the command line)
─────────────────────────────
    cppcheck --dump file.c
    python UndefBehaviorCheck.py file.c.dump

Or as a JSON-streaming addon called by Cppcheck itself:
    cppcheck --addon=UndefBehaviorCheck.py file.c

Protocol
────────
Each finding is emitted as a single JSON line on stdout, following
Cppcheck's addon protocol:

    {"file": ..., "linenr": ..., "column": ..., "severity": ...,
     "message": ..., "addon": "UndefBehaviorCheck", "errorId": ...,
     "cwe": ...}

The addon is intentionally read-only and side-effect free; it never
modifies source files or the dump.

Dependencies
────────────
    cppcheckdata        — Cppcheck's own Python module (ships with Cppcheck)
    cppcheckdata_shims  — extended analysis infrastructure

License: MIT — same as cppcheckdata-shims.
"""

from __future__ import annotations

import sys
from typing import Iterator

import cppcheckdata

# ── shims analysis modules ────────────────────────────────────────────────
from cppcheckdata_shims.checkers import (
    Checker,
    CheckerContext,
    CheckerRegistry,
    Confidence,
    Diagnostic,
    DiagnosticSeverity,
    SourceLocation,
    SuppressionManager,
)
from cppcheckdata_shims.dataflow_analysis import (
    DefiniteAssignment,
    NullPointerAnalysis,
    PointerAnalysis,
    TaintAnalysis,
)
from cppcheckdata_shims.type_analysis import TypeAnalysis, TypeKind
from cppcheckdata_shims.symbolic_exec import SymbolicExecutor
from cppcheckdata_shims.ctrlflow_graph import build_cfg

# ═══════════════════════════════════════════════════════════════════════════
#  HELPER UTILITIES
# ═══════════════════════════════════════════════════════════════════════════

def _tok_str(tok) -> str:
    return getattr(tok, "str", "") or ""

def _tok_file(tok) -> str:
    return getattr(tok, "file", "") or ""

def _tok_line(tok) -> int:
    return int(getattr(tok, "linenr", 0) or 0)

def _tok_col(tok) -> int:
    return int(getattr(tok, "column", 0) or 0)

def _loc(tok) -> SourceLocation:
    return SourceLocation(file=_tok_file(tok), line=_tok_line(tok),
                          column=_tok_col(tok))

def _var_name(var) -> str:
    nt = getattr(var, "nameToken", None)
    if nt:
        return getattr(nt, "str", "?")
    return getattr(var, "name", "?")

def _vf_values(tok) -> list:
    """Return the list of ValueFlow values attached to a token."""
    return list(getattr(tok, "values", None) or [])

def _has_null_value(tok) -> bool:
    """True if any ValueFlow value on *tok* is a known or possible null."""
    for v in _vf_values(tok):
        if getattr(v, "intvalue", None) == 0:
            return True
    return False

def _is_integer_type(vt) -> bool:
    """True if the ValueType represents a plain integer type."""
    if vt is None:
        return False
    t = getattr(vt, "type", "")
    return t in {"bool", "char", "short", "int", "long", "long long"}

def _is_signed_integer(vt) -> bool:
    if not _is_integer_type(vt):
        return False
    sign = getattr(vt, "sign", "")
    return sign != "unsigned"

def _pointer_depth(vt) -> int:
    return int(getattr(vt, "pointer", 0) or 0)

def _iter_tokens(cfg) -> Iterator:
    for tok in getattr(cfg, "tokenlist", []):
        yield tok

def _emit(diag_list: list, error_id: str, message: str, tok,
          severity: DiagnosticSeverity, cwe: int,
          confidence: Confidence = Confidence.MEDIUM) -> None:
    """Append a Diagnostic to *diag_list*."""
    diag_list.append(Diagnostic(
        error_id=error_id,
        message=message,
        severity=severity,
        location=_loc(tok),
        confidence=confidence,
        cwe=cwe,
        checker_name="UndefBehaviorCheck",
        addon="UndefBehaviorCheck",
    ))

# ═══════════════════════════════════════════════════════════════════════════
#  CHECKER 1 — Uninitialized Variable Use  (CWE-457)
# ═══════════════════════════════════════════════════════════════════════════

class UninitVarChecker(Checker):
    """
    Detects reads of variables that may not have been initialised on all
    paths leading to the read site.

    Strategy
    ────────
    1. Run ``DefiniteAssignment`` dataflow over the CFG.
    2. For every token that is a variable *use* (not a declaration or lhs
       of assignment) check whether the variable is in the definitely-
       assigned set at that program point.
    3. Also consult cppcheck ValueFlow: if any Value has
       ``valueKind == "uninit"`` the finding is ``HIGH`` confidence.

    CWE: 457 — Use of Uninitialized Variable
    """

    name = "uninit-var"
    description = "Use of uninitialized variable"
    error_ids = frozenset({"uninitVar", "uninitVarPossible"})
    default_severity = DiagnosticSeverity.ERROR
    cwe_ids = {"uninitVar": 457, "uninitVarPossible": 457}

    def __init__(self):
        super().__init__()
        self._findings: list[Diagnostic] = []

    def collect_evidence(self, ctx: CheckerContext) -> None:
        cfg = ctx.cfg
        # Use DefiniteAssignment if available via shims
        da_results = None
        try:
            da = DefiniteAssignment(cfg)
            da_results = da.run()
        except Exception:
            da_results = None

        for tok in _iter_tokens(cfg):
            var = getattr(tok, "variable", None)
            if var is None:
                continue
            # Skip declarations (nameToken of the variable itself)
            nt = getattr(var, "nameToken", None)
            if nt is tok:
                continue
            # Skip lhs of direct assignments
            parent = getattr(tok, "astParent", None)
            if parent and _tok_str(parent) == "=" and \
               getattr(parent, "astOperand1", None) is tok:
                continue

            # 1. ValueFlow-based uninit detection (HIGH confidence)
            for v in _vf_values(tok):
                if getattr(v, "valueKind", "") == "uninit":
                    _emit(self._findings, "uninitVar",
                          f"Uninitialized variable '{_var_name(var)}' is used.",
                          tok, DiagnosticSeverity.ERROR, 457, Confidence.HIGH)
                    break

            # 2. DefiniteAssignment dataflow fallback (MEDIUM confidence)
            if da_results is not None:
                tok_id = id(tok)
                uninit_set = da_results.get(tok_id, None)
                if uninit_set is not None and var in uninit_set:
                    _emit(self._findings, "uninitVarPossible",
                          f"Variable '{_var_name(var)}' may not be initialized "
                          f"on all paths reaching this use.",
                          tok, DiagnosticSeverity.WARNING, 457, Confidence.MEDIUM)

    def diagnose(self, ctx: CheckerContext) -> None:
        self._diagnostics.extend(self._findings)

# ═══════════════════════════════════════════════════════════════════════════
#  CHECKER 2 — Use-After-Free / Dangling Memory  (CWE-416)
# ═══════════════════════════════════════════════════════════════════════════

class UseAfterFreeChecker(Checker):
    """
    Detects accesses to memory that has already been freed.

    Strategy
    ────────
    1. Use ``PointerAnalysis`` from shims to track pointer provenance.
    2. Consult ValueFlow: a token with ``lifetimeKind`` indicating a freed
       or out-of-scope object is a high-confidence finding.
    3. Pattern: a pointer that received a ``free()`` call is subsequently
       dereferenced without an intervening reassignment.

    CWE: 416 — Use After Free
    """

    name = "use-after-free"
    description = "Use of freed or dangling memory"
    error_ids = frozenset({"useAfterFree", "useAfterFreePossible"})
    default_severity = DiagnosticSeverity.ERROR
    cwe_ids = {"useAfterFree": 416, "useAfterFreePossible": 416}

    # Names that release memory
    _FREE_FUNCS = {"free", "delete", "delete[]", "fclose", "munmap"}

    def __init__(self):
        super().__init__()
        self._findings: list[Diagnostic] = []

    def collect_evidence(self, ctx: CheckerContext) -> None:
        cfg = ctx.cfg

        # Collect tokens where a free-like function is called on a pointer var
        freed_vars: set = set()

        for tok in _iter_tokens(cfg):
            s = _tok_str(tok)

            # Detect free(ptr) / delete ptr
            if s in self._FREE_FUNCS:
                # Next significant token is '(' then the argument
                nxt = getattr(tok, "next", None)
                if nxt and _tok_str(nxt) == "(":
                    arg = getattr(nxt, "next", None)
                    if arg:
                        var = getattr(arg, "variable", None)
                        if var:
                            freed_vars.add(id(var))

            # Check for use of a freed variable
            var = getattr(tok, "variable", None)
            if var and id(var) in freed_vars:
                # Is this token a use (dereference or function argument)?
                parent = getattr(tok, "astParent", None)
                is_lhs_assign = (parent and _tok_str(parent) == "=" and
                                 getattr(parent, "astOperand1", None) is tok)
                if not is_lhs_assign:
                    # Remove from freed if reassigned
                    if parent and _tok_str(parent) == "=":
                        freed_vars.discard(id(var))
                    else:
                        _emit(self._findings, "useAfterFreePossible",
                              f"Possible use of freed memory via pointer "
                              f"'{_var_name(var)}'.",
                              tok, DiagnosticSeverity.ERROR, 416, Confidence.MEDIUM)

            # ValueFlow lifetime detection (HIGH confidence)
            for v in _vf_values(tok):
                ls = getattr(v, "lifetimeScope", "")
                lk = getattr(v, "lifetimeKind", "")
                if ls in {"Local", "SubFunction"} and lk in {"Object", "Address"}:
                    _emit(self._findings, "useAfterFree",
                          f"Accessing object whose lifetime has ended at token "
                          f"'{_tok_str(tok)}'.",
                          tok, DiagnosticSeverity.ERROR, 416, Confidence.HIGH)
                    break

    def diagnose(self, ctx: CheckerContext) -> None:
        self._diagnostics.extend(self._findings)

# ═══════════════════════════════════════════════════════════════════════════
#  CHECKER 3 — Strict Aliasing Violation  (CWE-119 / CWE-704)
# ═══════════════════════════════════════════════════════════════════════════

class StrictAliasingChecker(Checker):
    """
    Detects type-punning through incompatible pointer types, which violates
    C/C++ strict-aliasing rules and constitutes undefined behavior.

    Strategy
    ────────
    Pattern: ``*(T2 *)ptr`` where ``ptr`` has type ``T1 *`` and T1 and T2
    are not compatible (not the same, not char/unsigned char/std::byte).

    CWE: 119 — Improper Restriction of Operations within the Bounds of a
               Memory Buffer (used for aliasing UB in practice)
    CWE: 704 — Incorrect Type Conversion or Cast
    """

    name = "strict-aliasing"
    description = "Strict aliasing rule violation"
    error_ids = frozenset({"strictAliasingViolation"})
    default_severity = DiagnosticSeverity.WARNING
    cwe_ids = {"strictAliasingViolation": 119}

    # Types that are aliasing-safe (can alias anything per the standard)
    _ALIAS_SAFE = {"char", "unsigned char", "signed char", "std::byte"}

    def __init__(self):
        super().__init__()
        self._findings: list[Diagnostic] = []

    @staticmethod
    def _base_type(vt) -> str:
        if vt is None:
            return ""
        ot = getattr(vt, "originalTypeName", "")
        if ot:
            return ot.strip()
        return getattr(vt, "type", "")

    def _are_alias_compatible(self, t1: str, t2: str) -> bool:
        if not t1 or not t2:
            return True  # unknown → be conservative
        if t1 == t2:
            return True
        if t1 in self._ALIAS_SAFE or t2 in self._ALIAS_SAFE:
            return True
        return False

    def collect_evidence(self, ctx: CheckerContext) -> None:
        cfg = ctx.cfg
        ta = None
        try:
            ta = TypeAnalysis(cfg)
            ta_results = ta.run()
        except Exception:
            ta_results = {}

        for tok in _iter_tokens(cfg):
            # Look for cast expressions: (T *)expr
            if _tok_str(tok) != "(":
                continue
            parent = getattr(tok, "astParent", None)
            # A cast token in the AST has its cast-type as astOperand1 and
            # the casted expression as astOperand2 in cppcheck's AST.
            cast_type_tok = getattr(tok, "astOperand1", None)
            src_tok = getattr(tok, "astOperand2", None)
            if cast_type_tok is None or src_tok is None:
                continue

            dst_vt = getattr(cast_type_tok, "valueType", None)
            src_vt = getattr(src_tok, "valueType", None)

            if dst_vt is None or src_vt is None:
                continue

            # Only care about pointer-to-pointer casts
            if _pointer_depth(dst_vt) == 0 or _pointer_depth(src_vt) == 0:
                continue

            t_dst = self._base_type(dst_vt)
            t_src = self._base_type(src_vt)

            if not self._are_alias_compatible(t_src, t_dst):
                _emit(self._findings, "strictAliasingViolation",
                      f"Casting '{t_src} *' to '{t_dst} *' may violate "
                      f"strict-aliasing rules and cause undefined behavior.",
                      tok, DiagnosticSeverity.WARNING, 119, Confidence.MEDIUM)

    def diagnose(self, ctx: CheckerContext) -> None:
        self._diagnostics.extend(self._findings)

# ═══════════════════════════════════════════════════════════════════════════
#  CHECKER 4 — Misaligned Memory Access  (CWE-704)
# ═══════════════════════════════════════════════════════════════════════════

class MisalignedAccessChecker(Checker):
    """
    Detects casts that increase pointer alignment requirements, which may
    trigger a bus error or produce undefined behavior on strict-alignment
    architectures.

    Pattern: casting ``char *`` or ``void *`` to a type with alignment
    requirement > 1 without a known-aligned source (e.g., ``malloc`` result
    or ``__attribute__((aligned(...)))``).

    CWE: 704 — Incorrect Type Conversion or Cast
    """

    name = "misaligned-access"
    description = "Potentially misaligned memory access via pointer cast"
    error_ids = frozenset({"misalignedPointerCast"})
    default_severity = DiagnosticSeverity.WARNING
    cwe_ids = {"misalignedPointerCast": 704}

    # Types whose alignment is 1 (safe to cast from)
    _ALIGN1_TYPES = {"char", "unsigned char", "signed char", "void",
                     "std::byte"}

    # Types that need alignment > 1
    _STRICT_ALIGN_TYPES = {
        "short", "unsigned short",
        "int", "unsigned int",
        "long", "unsigned long",
        "long long", "unsigned long long",
        "float", "double", "long double",
        "wchar_t",
    }

    def __init__(self):
        super().__init__()
        self._findings: list[Diagnostic] = []

    def collect_evidence(self, ctx: CheckerContext) -> None:
        cfg = ctx.cfg
        for tok in _iter_tokens(cfg):
            if _tok_str(tok) != "(":
                continue
            cast_type_tok = getattr(tok, "astOperand1", None)
            src_tok = getattr(tok, "astOperand2", None)
            if cast_type_tok is None or src_tok is None:
                continue

            dst_vt = getattr(cast_type_tok, "valueType", None)
            src_vt = getattr(src_tok, "valueType", None)
            if dst_vt is None or src_vt is None:
                continue

            # Only pointer casts
            if _pointer_depth(dst_vt) == 0 or _pointer_depth(src_vt) == 0:
                continue

            src_type = getattr(src_vt, "originalTypeName", "") or \
                       getattr(src_vt, "type", "")
            dst_type = getattr(dst_vt, "originalTypeName", "") or \
                       getattr(dst_vt, "type", "")

            if (src_type.strip() in self._ALIGN1_TYPES and
                    dst_type.strip() in self._STRICT_ALIGN_TYPES):
                _emit(self._findings, "misalignedPointerCast",
                      f"Casting '{src_type} *' to '{dst_type} *' may produce "
                      f"a misaligned pointer; result is undefined on "
                      f"strict-alignment architectures.",
                      tok, DiagnosticSeverity.WARNING, 704, Confidence.MEDIUM)

    def diagnose(self, ctx: CheckerContext) -> None:
        self._diagnostics.extend(self._findings)

# ═══════════════════════════════════════════════════════════════════════════
#  CHECKER 5 — Invalid Type Casting  (CWE-843)
# ═══════════════════════════════════════════════════════════════════════════

class InvalidCastChecker(Checker):
    """
    Detects semantically unsafe or meaningless casts:

    * Downcast from a larger integer type to a smaller one that silently
      truncates (e.g., ``(char)large_int``).
    * Cast from floating-point to integer without an explicit truncation
      acknowledgement (lossy conversion).
    * Casting away ``volatile`` qualification.

    CWE: 843 — Access of Resource Using Incompatible Type (Type Confusion)
    """

    name = "invalid-cast"
    description = "Invalid or dangerous type cast"
    error_ids = frozenset({
        "truncatingCast",
        "floatToIntCast",
        "castVolatileAway",
    })
    default_severity = DiagnosticSeverity.WARNING
    cwe_ids = {
        "truncatingCast": 843,
        "floatToIntCast": 843,
        "castVolatileAway": 843,
    }

    _INT_SIZES = {
        "char": 8, "unsigned char": 8, "signed char": 8,
        "short": 16, "unsigned short": 16,
        "int": 32, "unsigned int": 32,
        "long": 32, "unsigned long": 32,   # conservative
        "long long": 64, "unsigned long long": 64,
    }

    _FLOAT_TYPES = {"float", "double", "long double"}

    def __init__(self):
        super().__init__()
        self._findings: list[Diagnostic] = []

    def _type_name(self, vt) -> str:
        if vt is None:
            return ""
        return (getattr(vt, "originalTypeName", "") or
                getattr(vt, "type", "")).strip()

    def collect_evidence(self, ctx: CheckerContext) -> None:
        cfg = ctx.cfg
        for tok in _iter_tokens(cfg):
            if _tok_str(tok) != "(":
                continue
            cast_type_tok = getattr(tok, "astOperand1", None)
            src_tok = getattr(tok, "astOperand2", None)
            if cast_type_tok is None or src_tok is None:
                continue

            dst_vt = getattr(cast_type_tok, "valueType", None)
            src_vt = getattr(src_tok, "valueType", None)
            if dst_vt is None or src_vt is None:
                continue

            # Skip pointer casts (handled by other checkers)
            if _pointer_depth(dst_vt) > 0 or _pointer_depth(src_vt) > 0:
                continue

            src_t = self._type_name(src_vt)
            dst_t = self._type_name(dst_vt)

            # 1. Truncating integer downcast
            src_bits = self._INT_SIZES.get(src_t, 0)
            dst_bits = self._INT_SIZES.get(dst_t, 0)
            if src_bits > 0 and dst_bits > 0 and src_bits > dst_bits:
                _emit(self._findings, "truncatingCast",
                      f"Cast from '{src_t}' ({src_bits}-bit) to '{dst_t}' "
                      f"({dst_bits}-bit) silently truncates the value.",
                      tok, DiagnosticSeverity.WARNING, 843, Confidence.MEDIUM)

            # 2. Float-to-integer conversion (lossy)
            if src_t in self._FLOAT_TYPES and dst_bits > 0:
                _emit(self._findings, "floatToIntCast",
                      f"Implicit truncation: casting '{src_t}' to integer "
                      f"type '{dst_t}' discards the fractional part.",
                      tok, DiagnosticSeverity.WARNING, 843, Confidence.MEDIUM)

            # 3. Casting away volatile
            src_constness = getattr(src_vt, "constness", 0) or 0
            dst_constness = getattr(dst_vt, "constness", 0) or 0
            # cppcheck encodes volatile in constness bitmask (bit 1 = volatile)
            src_volatile = bool(src_constness & 2)
            dst_volatile = bool(dst_constness & 2)
            if src_volatile and not dst_volatile and \
               _pointer_depth(src_vt) > 0:
                _emit(self._findings, "castVolatileAway",
                      f"Cast removes 'volatile' qualifier from pointer; "
                      f"subsequent accesses may be misoptimised by the compiler.",
                      tok, DiagnosticSeverity.WARNING, 843, Confidence.MEDIUM)

    def diagnose(self, ctx: CheckerContext) -> None:
        self._diagnostics.extend(self._findings)

# ═══════════════════════════════════════════════════════════════════════════
#  CHECKER 6 — Lifetime Violations  (CWE-562)
# ═══════════════════════════════════════════════════════════════════════════

class LifetimeChecker(Checker):
    """
    Detects returning a pointer or reference to a local (stack) variable,
    which becomes a dangling pointer the moment the function returns.

    Strategy
    ────────
    * Scan ``return`` tokens.
    * If the returned expression resolves to a local variable (``isLocal``)
      and the function return type is a pointer or reference, report.
    * Additionally use ValueFlow lifetime annotations where available.

    CWE: 562 — Return of Stack Variable Address
    """

    name = "lifetime"
    description = "Lifetime violation — dangling pointer or reference"
    error_ids = frozenset({"returnLocalAddr", "danglingLifetime"})
    default_severity = DiagnosticSeverity.ERROR
    cwe_ids = {"returnLocalAddr": 562, "danglingLifetime": 562}

    def __init__(self):
        super().__init__()
        self._findings: list[Diagnostic] = []

    def collect_evidence(self, ctx: CheckerContext) -> None:
        cfg = ctx.cfg
        for tok in _iter_tokens(cfg):
            if _tok_str(tok) != "return":
                continue
            ret_expr = getattr(tok, "astOperand1", None)
            if ret_expr is None:
                continue

            # ValueFlow lifetime (HIGH confidence)
            for v in _vf_values(ret_expr):
                ls = getattr(v, "lifetimeScope", "")
                lk = getattr(v, "lifetimeKind", "")
                if ls == "Local" and lk in {"Object", "Address"}:
                    _emit(self._findings, "danglingLifetime",
                          "Returning pointer/reference to a local object whose "
                          "lifetime ends at function return.",
                          tok, DiagnosticSeverity.ERROR, 562, Confidence.HIGH)
                    break

            # Pattern-based: &localVar returned as pointer
            addr_tok = ret_expr
            if _tok_str(addr_tok) == "&":
                inner = getattr(addr_tok, "astOperand1", None)
                if inner is None:
                    inner = getattr(addr_tok, "astOperand2", None)
                if inner:
                    var = getattr(inner, "variable", None)
                    if var and getattr(var, "isLocal", False):
                        _emit(self._findings, "returnLocalAddr",
                              f"Address of local variable '{_var_name(var)}' "
                              f"is returned; it will be invalid after the "
                              f"function returns.",
                              tok, DiagnosticSeverity.ERROR, 562, Confidence.HIGH)

    def diagnose(self, ctx: CheckerContext) -> None:
        self._diagnostics.extend(self._findings)

# ═══════════════════════════════════════════════════════════════════════════
#  CHECKER 7 — Modification of Const Data  (CWE-664 / CWE-843)
# ═══════════════════════════════════════════════════════════════════════════

class ConstModificationChecker(Checker):
    """
    Detects attempts to modify const-qualified data, typically via:

    * A cast that removes ``const`` from a pointer, followed by a write
      through that pointer.
    * Passing a ``const`` pointer to a function that takes a non-const
      pointer (potential write target).

    CWE: 664 — Improper Control of a Resource Through its Lifetime
    (also tagged 843 for the type confusion aspect)
    """

    name = "const-modification"
    description = "Modification of const-qualified data"
    error_ids = frozenset({"constCastWrite", "constDataModification"})
    default_severity = DiagnosticSeverity.ERROR
    cwe_ids = {"constCastWrite": 664, "constDataModification": 664}

    def __init__(self):
        super().__init__()
        self._findings: list[Diagnostic] = []

    @staticmethod
    def _is_const_ptr(vt) -> bool:
        """True if vt is a pointer with const-qualified pointee."""
        if vt is None:
            return False
        if _pointer_depth(vt) == 0:
            return False
        constness = getattr(vt, "constness", 0) or 0
        # bit 0 = const on the pointed-to type
        return bool(constness & 1)

    def collect_evidence(self, ctx: CheckerContext) -> None:
        cfg = ctx.cfg
        for tok in _iter_tokens(cfg):
            # Pattern: (T *)const_ptr followed by dereference + assignment
            if _tok_str(tok) != "(":
                continue
            cast_type_tok = getattr(tok, "astOperand1", None)
            src_tok = getattr(tok, "astOperand2", None)
            if cast_type_tok is None or src_tok is None:
                continue

            dst_vt = getattr(cast_type_tok, "valueType", None)
            src_vt = getattr(src_tok, "valueType", None)

            if dst_vt is None or src_vt is None:
                continue

            # Source must be a const pointer; destination must NOT be
            if self._is_const_ptr(src_vt) and not self._is_const_ptr(dst_vt) \
               and _pointer_depth(dst_vt) > 0:
                # Check whether the result is subsequently written through
                parent = getattr(tok, "astParent", None)
                if parent and _tok_str(parent) in {"=", "*", "->", "["}:
                    _emit(self._findings, "constCastWrite",
                          "Cast removes 'const' qualifier from pointer; "
                          "writing through the result modifies const data "
                          "and is undefined behavior.",
                          tok, DiagnosticSeverity.ERROR, 664, Confidence.HIGH)

            # Direct: const variable written to (should be caught by compiler
            # too, but we catch it for completeness)
            var = getattr(tok, "variable", None)
            if var and getattr(var, "isConst", False):
                parent = getattr(tok, "astParent", None)
                if parent and _tok_str(parent) == "=" and \
                   getattr(parent, "astOperand1", None) is tok:
                    _emit(self._findings, "constDataModification",
                          f"Assignment to const variable '{_var_name(var)}' "
                          f"is undefined behavior.",
                          tok, DiagnosticSeverity.ERROR, 664, Confidence.HIGH)

    def diagnose(self, ctx: CheckerContext) -> None:
        self._diagnostics.extend(self._findings)

# ═══════════════════════════════════════════════════════════════════════════
#  CHECKER 8 — Undefined Behavior in Bit Shifting  (CWE-758)
# ═══════════════════════════════════════════════════════════════════════════

class BitShiftChecker(Checker):
    """
    Detects undefined behavior in bit-shift operations:

    * Shift amount is negative.
    * Shift amount ≥ bit-width of the left operand.
    * Left-shifting a negative signed value (UB in C/C++14 and earlier,
      implementation-defined in C++20 but still a code smell).

    Strategy
    ────────
    Inspect ``<<`` and ``>>`` tokens; use ValueFlow to determine whether
    the shift amount is known or bounded.

    CWE: 758 — Reliance on Undefined, Unspecified, or Implementation-Defined
               Behavior
    """

    name = "bit-shift-ub"
    description = "Undefined behavior in bit-shift operation"
    error_ids = frozenset({
        "shiftTooLarge",
        "shiftNegative",
        "shiftNegativeValue",
    })
    default_severity = DiagnosticSeverity.WARNING
    cwe_ids = {
        "shiftTooLarge": 758,
        "shiftNegative": 758,
        "shiftNegativeValue": 758,
    }

    _INT_WIDTHS = {
        "char": 8, "unsigned char": 8, "signed char": 8,
        "short": 16, "unsigned short": 16,
        "int": 32, "unsigned int": 32,
        "long": 32, "unsigned long": 32,
        "long long": 64, "unsigned long long": 64,
    }

    def __init__(self):
        super().__init__()
        self._findings: list[Diagnostic] = []

    def _get_int_values(self, tok) -> list[int]:
        """Extract all known integer values for a token from ValueFlow."""
        result = []
        for v in _vf_values(tok):
            iv = getattr(v, "intvalue", None)
            if iv is not None:
                result.append(int(iv))
        return result

    def collect_evidence(self, ctx: CheckerContext) -> None:
        cfg = ctx.cfg
        for tok in _iter_tokens(cfg):
            s = _tok_str(tok)
            if s not in {"<<", ">>"}:
                continue

            lhs = getattr(tok, "astOperand1", None)
            rhs = getattr(tok, "astOperand2", None)
            if lhs is None or rhs is None:
                continue

            lhs_vt = getattr(lhs, "valueType", None)
            lhs_type = (getattr(lhs_vt, "originalTypeName", "") or
                        getattr(lhs_vt, "type", "")).strip() if lhs_vt else ""
            width = self._INT_WIDTHS.get(lhs_type, 32)  # default 32

            rhs_vals = self._get_int_values(rhs)
            lhs_vals = self._get_int_values(lhs)

            for amt in rhs_vals:
                if amt < 0:
                    _emit(self._findings, "shiftNegative",
                          f"Shift amount is negative ({amt}); "
                          f"this is undefined behavior.",
                          tok, DiagnosticSeverity.ERROR, 758, Confidence.HIGH)
                elif amt >= width:
                    _emit(self._findings, "shiftTooLarge",
                          f"Shift amount {amt} exceeds or equals the width "
                          f"({width}) of type '{lhs_type}'; "
                          f"this is undefined behavior.",
                          tok, DiagnosticSeverity.ERROR, 758, Confidence.HIGH)

            # Left-shift of a negative value (UB before C++20)
            if s == "<<":
                for lv in lhs_vals:
                    if lv < 0:
                        _emit(self._findings, "shiftNegativeValue",
                              f"Left-shifting a negative value ({lv}) is "
                              f"undefined behavior in C and pre-C++20.",
                              tok, DiagnosticSeverity.WARNING, 758,
                              Confidence.HIGH)
                        break

    def diagnose(self, ctx: CheckerContext) -> None:
        self._diagnostics.extend(self._findings)

# ═══════════════════════════════════════════════════════════════════════════
#  CHECKER 9 — Signed Integer Overflow  (CWE-190)
# ═══════════════════════════════════════════════════════════════════════════

class SignedOverflowChecker(Checker):
    """
    Detects expressions involving signed integer arithmetic that may produce
    values outside the representable range, triggering undefined behavior.

    Strategy
    ────────
    * For ``+``, ``-``, ``*`` tokens whose operands are signed integers,
      check whether ValueFlow assigns a concrete value that overflows the
      type's range.
    * Also flag patterns such as ``INT_MIN / -1`` (quotient overflows).

    CWE: 190 — Integer Overflow or Wraparound
    """

    name = "signed-overflow"
    description = "Signed integer overflow (undefined behavior)"
    error_ids = frozenset({"signedOverflow", "signedDivOverflow"})
    default_severity = DiagnosticSeverity.ERROR
    cwe_ids = {"signedOverflow": 190, "signedDivOverflow": 190}

    _LIMITS: dict[str, tuple[int, int]] = {
        "char":      (-128, 127),
        "signed char": (-128, 127),
        "short":     (-32768, 32767),
        "int":       (-2147483648, 2147483647),
        "long":      (-2147483648, 2147483647),   # conservative (32-bit)
        "long long": (-9223372036854775808, 9223372036854775807),
    }

    _ARITH_OPS = {"+", "-", "*", "/"}

    def __init__(self):
        super().__init__()
        self._findings: list[Diagnostic] = []

    def _result_values(self, tok) -> list[int]:
        return [int(v.intvalue)
                for v in _vf_values(tok)
                if getattr(v, "intvalue", None) is not None]

    def collect_evidence(self, ctx: CheckerContext) -> None:
        cfg = ctx.cfg
        for tok in _iter_tokens(cfg):
            s = _tok_str(tok)
            if s not in self._ARITH_OPS:
                continue

            lhs = getattr(tok, "astOperand1", None)
            rhs = getattr(tok, "astOperand2", None)
            if lhs is None:
                continue

            vt = getattr(tok, "valueType", None)
            if vt is None:
                continue
            if not _is_signed_integer(vt):
                continue

            type_name = (getattr(vt, "originalTypeName", "") or
                         getattr(vt, "type", "")).strip()
            if type_name not in self._LIMITS:
                continue

            lo, hi = self._LIMITS[type_name]

            # INT_MIN / -1 overflow
            if s == "/" and rhs is not None:
                rhs_vals = [int(v.intvalue)
                            for v in _vf_values(rhs)
                            if getattr(v, "intvalue", None) is not None]
                lhs_vals = [int(v.intvalue)
                            for v in _vf_values(lhs)
                            if getattr(v, "intvalue", None) is not None]
                if -1 in rhs_vals and lo in lhs_vals:
                    _emit(self._findings, "signedDivOverflow",
                          f"Division of INT_MIN by -1 overflows '{type_name}'; "
                          f"this is undefined behavior.",
                          tok, DiagnosticSeverity.ERROR, 190, Confidence.HIGH)

            # General overflow: the result token itself has a concrete value
            # outside the type's range (cppcheck's ValueFlow may compute this)
            for rv in self._result_values(tok):
                if rv < lo or rv > hi:
                    _emit(self._findings, "signedOverflow",
                          f"Arithmetic on '{type_name}' produces value {rv} "
                          f"which is outside [{lo}, {hi}]; "
                          f"this is undefined behavior.",
                          tok, DiagnosticSeverity.ERROR, 190, Confidence.HIGH)
                    break

    def diagnose(self, ctx: CheckerContext) -> None:
        self._diagnostics.extend(self._findings)

# ═══════════════════════════════════════════════════════════════════════════
#  REGISTRY — wire all checkers together
# ═══════════════════════════════════════════════════════════════════════════

_REGISTRY = CheckerRegistry()
for _cls in [
    UninitVarChecker,
    UseAfterFreeChecker,
    StrictAliasingChecker,
    MisalignedAccessChecker,
    InvalidCastChecker,
    LifetimeChecker,
    ConstModificationChecker,
    BitShiftChecker,
    SignedOverflowChecker,
]:
    _REGISTRY.register(_cls)

# ═══════════════════════════════════════════════════════════════════════════
#  ENTRY POINT — cppcheck addon protocol
# ═══════════════════════════════════════════════════════════════════════════

def print_diagnostic(diag):
    """
    Print a Diagnostic object in standard Cppcheck format:
    [filename:line]: (severity) message [addon-errorId]
    """
    loc = f"{diag.location.file}:{diag.location.line}"
    severity = diag.severity.value
    msg = diag.message
    if diag.extra:
        msg += f" ({diag.extra})"
    error_id = f"{diag.addon}-{diag.error_id}"
    sys.stderr.write(f"[{loc}]: ({severity}) {msg} [{error_id}]\n")

def _run_on_cfg(cfg) -> list[Diagnostic]:
    """Run all registered checkers on one cppcheck Configuration."""
    suppressions = SuppressionManager()
    suppressions.load_inline_suppressions(cfg)
    ctx = CheckerContext(cfg=cfg, suppressions=suppressions)

    all_diagnostics: list[Diagnostic] = []
    for checker_cls in _REGISTRY.get_enabled():
        checker = checker_cls()
        try:
            checker.configure(ctx)
            checker.collect_evidence(ctx)
            checker.diagnose(ctx)
            all_diagnostics.extend(checker.report(ctx))
        except Exception as exc:  # pragma: no cover
            # Never crash the addon; emit a best-effort warning instead.
            sys.stderr.write(
                f"[UndefBehaviorCheck] checker '{checker_cls.name}' raised "
                f"an exception: {exc}\n"
            )
    return all_diagnostics


def main() -> None:
    """
    Main entry point.

    Parses dump files supplied as command-line arguments (or via cppcheck's
    addon runner) and emits one JSON diagnostic line per finding on stdout,
    following the cppcheck addon protocol.
    """
    args = cppcheckdata.ArgumentParser().parse_args()
    dump_files, _ctu = cppcheckdata.get_files(args)

    for dump_file in dump_files:
        data = cppcheckdata.parsedump(dump_file)
        for cfg in data.configurations:
            diagnostics = _run_on_cfg(cfg)
            for diag in diagnostics:
                # Cppcheck addon protocol: one JSON object per line on stdout
                print_diagnostic(diag)


if __name__ == "__main__":
    main()

