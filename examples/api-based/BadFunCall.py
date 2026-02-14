#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BadFunCall.py  –  Function-Call Checker addon for cppcheck / cppcheckdata-shims
================================================================================

Detects six categories of function-call errors:

    FC01  Call to undefined but declared function (no definition found)
    FC02  Parameter count mismatch (too few / too many arguments)
    FC03  Type mismatch between actual argument and formal parameter
    FC04  Implicit conversion may lose precision (narrowing)
    FC05  Const-correctness violation (non-const arg → const param, or reverse)
    FC06  Incompatible calling convention or linkage

Architecture
------------
Phase 1 – Collection       : CallCollector walks tokens once (O(n)) and builds
                             CallSite / FunctionDecl / FunctionPtrCall / VarArgCall
Phase 2 – Function DB      : FunctionDatabase indexes every declaration /
                             definition with FunctionInfo records
Phase 3 – Parameter Anal.  : ParameterAnalyzer matches actuals ↔ formals
Phase 4 – Undefined Det.   : UndefinedFunctionDetector cross-checks decls vs defs
Phase 5 – Validation       : FunctionCallValidator orchestrates all six rules

Usage (stand-alone)
-------------------
    python3 BadFunCall.py  my_project.c.dump          # human-readable stderr
    python3 BadFunCall.py  my_project.c.dump --cli     # JSON on stdout

Usage (cppcheck addon)
----------------------
    cppcheck --addon=BadFunCall  my_project.c

Dependencies
------------
Only the standard ``cppcheckdata`` module that ships with Cppcheck (≥ 2.x).
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import (
    Dict,
    List,
    Optional,
    Sequence,
    Set,
    Tuple,
)

# ---------------------------------------------------------------------------
# cppcheckdata import  (works both when run by cppcheck and stand-alone)
# ---------------------------------------------------------------------------
try:
    import cppcheckdata
except ImportError:
    # When invoked directly, cppcheckdata.py must be on sys.path or in cwd.
    import importlib, pathlib

    _here = pathlib.Path(__file__).resolve().parent
    sys.path.insert(0, str(_here))
    cppcheckdata = importlib.import_module("cppcheckdata")

# Re-export helpers we use frequently
reportError = cppcheckdata.reportError
simpleMatch = cppcheckdata.simpleMatch
getArguments = cppcheckdata.getArguments
get_function_call_name_args = cppcheckdata.get_function_call_name_args

ADDON_NAME = "BadFunCall"


# ═══════════════════════════════════════════════════════════════════════════
#  §0  Enumerations & tiny value objects
# ═══════════════════════════════════════════════════════════════════════════

class Severity(str, Enum):
    ERROR   = "error"
    WARNING = "warning"
    STYLE   = "style"
    PERF    = "performance"
    PORT    = "portability"
    INFO    = "information"


class CallingConvention(Enum):
    """Common x86 / x86-64 calling conventions."""
    CDECL       = auto()
    STDCALL     = auto()
    FASTCALL    = auto()
    THISCALL    = auto()
    VECTORCALL  = auto()
    UNKNOWN     = auto()


class Linkage(Enum):
    C   = auto()
    CXX = auto()
    UNKNOWN = auto()


# ═══════════════════════════════════════════════════════════════════════════
#  §1  Data-transfer objects
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class ParamInfo:
    """One formal parameter of a function."""
    index: int                        # 0-based position
    name: Optional[str]               # may be None for unnamed params
    type_name: Optional[str]          # resolved type string
    is_const: bool = False
    is_pointer: int = 0               # pointer depth
    is_reference: bool = False
    is_unsigned: bool = False
    is_signed: bool = False
    original_type: Optional[str] = None


@dataclass
class ArgInfo:
    """One actual argument at a call site."""
    index: int
    token: object                     # cppcheckdata.Token
    type_name: Optional[str] = None
    is_const: bool = False
    is_pointer: int = 0
    is_reference: bool = False
    is_unsigned: bool = False
    is_signed: bool = False
    original_type: Optional[str] = None


@dataclass
class FunctionInfo:
    """Aggregated knowledge about a single function name."""
    name: str
    qualified_name: str               # e.g. "Namespace::Class::func"
    params: List[ParamInfo] = field(default_factory=list)
    is_variadic: bool = False
    is_defined: bool = False          # True iff we found a body
    is_declared: bool = False         # True iff we found a prototype
    return_type: Optional[str] = None
    calling_convention: CallingConvention = CallingConvention.CDECL
    linkage: Linkage = Linkage.UNKNOWN
    has_noreturn: bool = False
    has_attribute_const: bool = False
    decl_token: object = None         # first declaration token
    def_token: object = None          # definition token (if any)
    file: Optional[str] = None
    linenr: int = 0


@dataclass
class CallSite:
    """A single call expression we discovered."""
    name: str
    qualified_name: str
    token: object                     # the name-token of the call
    args: List[ArgInfo] = field(default_factory=list)
    is_function_pointer: bool = False
    file: Optional[str] = None
    linenr: int = 0


@dataclass
class Diagnostic:
    """One reported problem."""
    rule: str           # e.g. "FC01"
    severity: str
    message: str
    file: Optional[str]
    linenr: int
    column: int = 0
    extra: str = ""


# ═══════════════════════════════════════════════════════════════════════════
#  §2  Type-compatibility helpers
# ═══════════════════════════════════════════════════════════════════════════

# Canonical width of each arithmetic type (bits).
_TYPE_WIDTH: Dict[str, int] = {
    "bool":        1,
    "char":        8,
    "short":      16,
    "wchar_t":    32,
    "int":        32,
    "long":       64,
    "long long":  64,
    "float":      32,
    "double":     64,
    "long double": 80,
}

_INTEGRAL_TYPES: Set[str] = {
    "bool", "char", "short", "wchar_t", "int", "long", "long long",
}

_FLOAT_TYPES: Set[str] = {"float", "double", "long double"}

_ARITHMETIC_TYPES: Set[str] = _INTEGRAL_TYPES | _FLOAT_TYPES


def _base_type(vt) -> Optional[str]:
    """Return the base type string from a cppcheckdata.ValueType (or None)."""
    if vt is None:
        return None
    return vt.type  # e.g. "int", "double", "record", "void", …


def _is_arithmetic(t: Optional[str]) -> bool:
    return t in _ARITHMETIC_TYPES if t else False


def _width(t: Optional[str]) -> int:
    return _TYPE_WIDTH.get(t, 0) if t else 0


def _is_narrowing(src: Optional[str], dst: Optional[str]) -> bool:
    """Return True when *src* → *dst* is a narrowing (precision-losing) conversion."""
    if src is None or dst is None:
        return False
    # float → integral is always narrowing
    if src in _FLOAT_TYPES and dst in _INTEGRAL_TYPES:
        return True
    # wider → narrower
    if _width(src) > _width(dst):
        return True
    # unsigned ↔ signed of same width can lose the sign bit
    # (handled separately below in the analyzer)
    return False


def _types_compatible(param: ParamInfo, arg: ArgInfo) -> Tuple[bool, str]:
    """
    Check deep compatibility.  Returns (ok, reason).
    *ok* is True when the types are fully compatible (no diagnostic).
    """
    pt = param.type_name
    at = arg.type_name

    # If either type is unknown we cannot diagnose – assume ok.
    if pt is None or at is None:
        return True, ""

    # --- pointer depth mismatch -------------------------------------------
    if param.is_pointer != arg.is_pointer:
        # void* accepts anything, and NULL (0) is acceptable for any pointer
        if param.is_pointer and param.type_name in ("void",):
            return True, ""
        return False, (
            f"pointer depth mismatch: parameter '{param.name}' has "
            f"depth {param.is_pointer}, argument has depth {arg.is_pointer}"
        )

    # --- both are pointers: check pointed-to type -------------------------
    if param.is_pointer > 0 and arg.is_pointer > 0:
        if pt != at and pt != "void" and at != "void":
            return False, (
                f"pointed-to type mismatch: expected '{pt}*', got '{at}*'"
            )
        return True, ""

    # --- arithmetic types --------------------------------------------------
    if _is_arithmetic(pt) and _is_arithmetic(at):
        if pt == at:
            # exact match — but watch for signed/unsigned mismatch
            if param.is_unsigned != arg.is_unsigned:
                return True, ""   # only a style issue, not a hard mismatch
            return True, ""
        # Different arithmetic types: check if narrowing
        # (narrowing is reported as FC04, not FC03)
        return True, ""

    # --- record (struct/class/union) types --------------------------------
    if pt == "record" or at == "record":
        # Without full class-hierarchy info we allow it when names match
        p_orig = param.original_type or pt
        a_orig = arg.original_type or at
        if p_orig != a_orig:
            return False, (
                f"record type mismatch: expected '{p_orig}', got '{a_orig}'"
            )
        return True, ""

    # --- void parameter (should not appear, but be safe) ------------------
    if pt == "void":
        return True, ""

    # --- catch-all: different named types ---------------------------------
    if pt != at:
        return False, f"type mismatch: expected '{pt}', got '{at}'"

    return True, ""


# ═══════════════════════════════════════════════════════════════════════════
#  §3  Phase 1 – Collection (single O(n) token walk)
# ═══════════════════════════════════════════════════════════════════════════

class CallCollector:
    """
    Walk ``cfg.tokenlist`` once and collect:
      • every function declaration / definition  →  list[FunctionInfo]
      • every call site                         →  list[CallSite]
    """

    def __init__(self):
        self.functions: Dict[str, FunctionInfo] = {}   # qualified_name → info
        self.call_sites: List[CallSite] = []

    # ------------------------------------------------------------------
    #  Public entry point
    # ------------------------------------------------------------------
    def collect(self, cfg) -> None:
        """Process one cppcheckdata *Configuration*."""
        self._collect_from_scopes(cfg)
        self._collect_calls(cfg)

    # ------------------------------------------------------------------
    #  Collect declarations / definitions from Scope + Function objects
    # ------------------------------------------------------------------
    def _collect_from_scopes(self, cfg) -> None:
        for scope in cfg.scopes:
            if scope.type == "Function":
                func = scope.function
                if func is None:
                    continue
                qname = self._qualified_name(func, scope)
                info = self._get_or_create(qname)
                info.is_defined = True
                info.def_token = func.token or func.tokenDef
                self._fill_params(info, func)
                self._fill_attributes(info, func, scope)
                if info.def_token:
                    info.file = getattr(info.def_token, "file", None)
                    info.linenr = getattr(info.def_token, "linenr", 0)

        # Also sweep Function objects that are only *declared* (no scope body)
        for func in cfg.functions:
            qname = self._qualified_function_name(func)
            info = self._get_or_create(qname)
            info.is_declared = True
            if info.decl_token is None:
                info.decl_token = func.tokenDef or func.token
            self._fill_params(info, func)
            self._fill_attributes(info, func, None)
            if func.token is not None or func.tokenDef is not None:
                tok = func.token or func.tokenDef
                info.file = getattr(tok, "file", None)
                info.linenr = getattr(tok, "linenr", 0)
            # If a body scope exists the earlier loop already set is_defined
            if func.nestedIn and func.nestedIn.type == "Function":
                info.is_defined = True

    # ------------------------------------------------------------------
    #  Collect call sites from token stream
    # ------------------------------------------------------------------
    def _collect_calls(self, cfg) -> None:
        for token in cfg.tokenlist:
            name, raw_args = get_function_call_name_args(token)
            if name is None:
                continue

            cs = CallSite(
                name=name.split("::")[-1],
                qualified_name=name,
                token=token,
                file=token.file,
                linenr=token.linenr,
            )

            if raw_args is not None:
                for idx, argtok in enumerate(raw_args):
                    ai = self._make_arg_info(idx, argtok)
                    cs.args.append(ai)

            # function-pointer detection: no linked Function object
            if token.function is None:
                cs.is_function_pointer = True

            self.call_sites.append(cs)

    # ------------------------------------------------------------------
    #  Helpers
    # ------------------------------------------------------------------
    def _get_or_create(self, qname: str) -> FunctionInfo:
        if qname not in self.functions:
            short = qname.split("::")[-1]
            self.functions[qname] = FunctionInfo(
                name=short, qualified_name=qname
            )
        return self.functions[qname]

    @staticmethod
    def _qualified_name(func_obj, scope) -> str:
        parts: List[str] = []
        nametok = func_obj.token or func_obj.tokenDef
        if nametok:
            parts.append(nametok.str)
        s = scope.nestedIn if scope else None
        while s:
            if s.className:
                parts.append(s.className)
            s = s.nestedIn
        parts.reverse()
        return "::".join(parts) if parts else "<anonymous>"

    @staticmethod
    def _qualified_function_name(func_obj) -> str:
        parts: List[str] = []
        nametok = func_obj.tokenDef or func_obj.token
        if nametok:
            parts.append(nametok.str)
            t = nametok.previous
            while t and t.previous and t.str == "::" and t.previous.isName:
                parts.append(t.previous.str)
                t = t.previous.previous
        scope = func_obj.nestedIn
        while scope:
            if scope.className and scope.className not in parts:
                parts.append(scope.className)
            scope = scope.nestedIn
        parts.reverse()
        return "::".join(parts) if parts else "<anonymous>"

    def _fill_params(self, info: FunctionInfo, func_obj) -> None:
        """Populate info.params from the Function object's argument list."""
        if info.params:
            return  # already filled from a prior pass
        if not hasattr(func_obj, "argument"):
            return
        arg_map = func_obj.argument  # dict: 1-based index → Variable
        for idx in sorted(arg_map.keys()):
            var = arg_map[idx]
            pi = ParamInfo(index=idx - 1, name=var.nameToken.str if var.nameToken else None)
            if var.typeStartToken:
                pi.type_name = self._reconstruct_type(var)
                pi.is_const = var.isConst if hasattr(var, "isConst") else False
                pi.is_pointer = var.isPointer if hasattr(var, "isPointer") else 0
                pi.is_reference = var.isReference if hasattr(var, "isReference") else False
                # Use nameToken's valueType when available for richer info
                if var.nameToken and var.nameToken.valueType:
                    vt = var.nameToken.valueType
                    pi.type_name = _base_type(vt) or pi.type_name
                    pi.is_pointer = vt.pointer
                    pi.is_const = bool(vt.constness)
                    pi.is_unsigned = (vt.sign == "unsigned")
                    pi.is_signed = (vt.sign == "signed")
                    pi.original_type = vt.originalTypeName
            info.params.append(pi)
        # Variadic detection: check for "..." among the declaration tokens
        if func_obj.tokenDef:
            tok = func_obj.tokenDef
            if tok.next and tok.next.str == "(":
                inner = tok.next.next
                while inner and inner != tok.next.link:
                    if inner.str == "...":
                        info.is_variadic = True
                        break
                    inner = inner.next
        # Return type
        if func_obj.tokenDef and func_obj.tokenDef.previous:
            info.return_type = func_obj.tokenDef.previous.str

    @staticmethod
    def _reconstruct_type(var) -> str:
        """Walk typeStartToken → typeEndToken to build a type string."""
        parts: List[str] = []
        tok = var.typeStartToken
        end = var.typeEndToken
        while tok:
            parts.append(tok.str)
            if tok == end:
                break
            tok = tok.next
        return " ".join(parts)

    @staticmethod
    def _make_arg_info(idx: int, argtok) -> ArgInfo:
        ai = ArgInfo(index=idx, token=argtok)
        if argtok.valueType:
            vt = argtok.valueType
            ai.type_name = _base_type(vt)
            ai.is_pointer = vt.pointer
            ai.is_const = bool(vt.constness)
            ai.is_unsigned = (vt.sign == "unsigned")
            ai.is_signed = (vt.sign == "signed")
            ai.original_type = vt.originalTypeName
            ai.is_reference = (vt.reference is not None)
        return ai

    def _fill_attributes(
        self, info: FunctionInfo, func_obj, scope
    ) -> None:
        """Detect calling convention, linkage, and GNU/MSVC attributes."""
        # Linkage: extern "C" appears on the token before the declaration
        tok = func_obj.tokenDef or func_obj.token
        if tok:
            if tok.externLang:
                if tok.externLang == "C":
                    info.linkage = Linkage.C
                elif tok.externLang == "C++":
                    info.linkage = Linkage.CXX
            # Walk backwards looking for __attribute__ or __declspec tokens
            t = tok.previous
            depth = 0
            while t and depth < 12:
                s = t.str
                if s in ("__cdecl", "__attribute__((cdecl))"):
                    info.calling_convention = CallingConvention.CDECL
                elif s in ("__stdcall", "__attribute__((stdcall))",
                           "WINAPI", "CALLBACK", "APIENTRY"):
                    info.calling_convention = CallingConvention.STDCALL
                elif s in ("__fastcall", "__attribute__((fastcall))"):
                    info.calling_convention = CallingConvention.FASTCALL
                elif s in ("__thiscall",):
                    info.calling_convention = CallingConvention.THISCALL
                elif s in ("__vectorcall",):
                    info.calling_convention = CallingConvention.VECTORCALL
                elif s == "__attribute__":
                    # scan for noreturn / const inside (( … ))
                    a = t.next
                    while a and a.str != ")":
                        if a.str == "noreturn":
                            info.has_noreturn = True
                        if a.str == "const":
                            info.has_attribute_const = True
                        a = a.next
                t = t.previous
                depth += 1


# ═══════════════════════════════════════════════════════════════════════════
#  §4  Phase 2 – Function Database
# ═══════════════════════════════════════════════════════════════════════════

class FunctionDatabase:
    """
    Central registry that merges information from possibly several
    translation units (configurations) and answers queries such as
    "Is function X defined anywhere?" and "What are X's parameters?".
    """

    def __init__(self):
        self._db: Dict[str, FunctionInfo] = {}

    def merge(self, collector: CallCollector) -> None:
        for qname, info in collector.functions.items():
            if qname in self._db:
                existing = self._db[qname]
                if info.is_defined:
                    existing.is_defined = True
                    existing.def_token = info.def_token or existing.def_token
                if info.is_declared:
                    existing.is_declared = True
                if not existing.params and info.params:
                    existing.params = info.params
                if info.is_variadic:
                    existing.is_variadic = True
            else:
                self._db[qname] = info

    def lookup(self, qualified_name: str) -> Optional[FunctionInfo]:
        """Exact qualified lookup."""
        return self._db.get(qualified_name)

    def lookup_fuzzy(self, name: str) -> List[FunctionInfo]:
        """Return all entries whose short name matches *name*."""
        return [
            info
            for info in self._db.values()
            if info.name == name
        ]

    def all_functions(self) -> List[FunctionInfo]:
        return list(self._db.values())


# ═══════════════════════════════════════════════════════════════════════════
#  §5  Phase 3 – Parameter Analyzer
# ═══════════════════════════════════════════════════════════════════════════

class ParameterAnalyzer:
    """
    For a given (CallSite, FunctionInfo) pair, compare each actual
    argument against the corresponding formal parameter.
    """

    def __init__(self, db: FunctionDatabase):
        self.db = db

    def analyze(self, cs: CallSite, fi: FunctionInfo) -> List[Diagnostic]:
        diags: List[Diagnostic] = []

        # ── FC02: arity check ────────────────────────────────────────
        n_formals = len(fi.params)
        n_actuals = len(cs.args)
        if fi.is_variadic:
            # For variadic, at least the fixed params must be supplied
            if n_actuals < n_formals:
                diags.append(Diagnostic(
                    rule="FC02",
                    severity=Severity.ERROR,
                    message=(
                        f"Too few arguments to variadic function "
                        f"'{cs.qualified_name}': expected at least "
                        f"{n_formals}, got {n_actuals}"
                    ),
                    file=cs.file,
                    linenr=cs.linenr,
                ))
        else:
            if n_actuals < n_formals:
                diags.append(Diagnostic(
                    rule="FC02",
                    severity=Severity.ERROR,
                    message=(
                        f"Too few arguments to '{cs.qualified_name}': "
                        f"expected {n_formals}, got {n_actuals}"
                    ),
                    file=cs.file,
                    linenr=cs.linenr,
                ))
            elif n_actuals > n_formals and n_formals > 0:
                diags.append(Diagnostic(
                    rule="FC02",
                    severity=Severity.ERROR,
                    message=(
                        f"Too many arguments to '{cs.qualified_name}': "
                        f"expected {n_formals}, got {n_actuals}"
                    ),
                    file=cs.file,
                    linenr=cs.linenr,
                ))

        # ── Per-argument checks (FC03, FC04, FC05) ───────────────────
        check_count = min(n_formals, n_actuals)
        for i in range(check_count):
            param = fi.params[i]
            arg = cs.args[i]
            diags.extend(self._check_one(cs, param, arg))

        # ── Variadic extra args: default promotions (FC04) ───────────
        if fi.is_variadic and n_actuals > n_formals:
            for i in range(n_formals, n_actuals):
                arg = cs.args[i]
                diags.extend(self._check_variadic_promotion(cs, arg))

        return diags

    # ------------------------------------------------------------------
    def _check_one(
        self, cs: CallSite, param: ParamInfo, arg: ArgInfo
    ) -> List[Diagnostic]:
        diags: List[Diagnostic] = []
        pname = param.name or f"#{param.index + 1}"

        # ── FC03: hard type mismatch ─────────────────────────────────
        ok, reason = _types_compatible(param, arg)
        if not ok:
            diags.append(Diagnostic(
                rule="FC03",
                severity=Severity.ERROR,
                message=(
                    f"In call to '{cs.qualified_name}', argument "
                    f"{arg.index + 1} ({pname}): {reason}"
                ),
                file=cs.file,
                linenr=cs.linenr,
            ))

        # ── FC04: narrowing conversion ───────────────────────────────
        pt = param.type_name
        at = arg.type_name
        if _is_arithmetic(pt) and _is_arithmetic(at) and _is_narrowing(at, pt):
            diags.append(Diagnostic(
                rule="FC04",
                severity=Severity.WARNING,
                message=(
                    f"Implicit narrowing conversion in call to "
                    f"'{cs.qualified_name}': argument {arg.index + 1} "
                    f"({pname}) converts '{at}' → '{pt}'"
                ),
                file=cs.file,
                linenr=cs.linenr,
            ))

        # Signed/unsigned mismatch of same width
        if (
            _is_arithmetic(pt)
            and _is_arithmetic(at)
            and pt == at
            and param.is_unsigned != arg.is_unsigned
        ):
            diags.append(Diagnostic(
                rule="FC04",
                severity=Severity.WARNING,
                message=(
                    f"Signed/unsigned mismatch in call to "
                    f"'{cs.qualified_name}': argument {arg.index + 1} "
                    f"({pname}) — parameter is "
                    f"{'unsigned' if param.is_unsigned else 'signed'}, "
                    f"argument is "
                    f"{'unsigned' if arg.is_unsigned else 'signed'}"
                ),
                file=cs.file,
                linenr=cs.linenr,
            ))

        # ── FC05: const-correctness ──────────────────────────────────
        if param.is_pointer > 0 or param.is_reference:
            # Passing non-const pointer/ref to const-param is fine.
            # Passing const pointer/ref to NON-const param is a violation:
            #   the callee may modify the pointed-to object.
            if arg.is_const and not param.is_const:
                diags.append(Diagnostic(
                    rule="FC05",
                    severity=Severity.WARNING,
                    message=(
                        f"Const-correctness violation in call to "
                        f"'{cs.qualified_name}': argument {arg.index + 1} "
                        f"({pname}) passes a const-qualified object to a "
                        f"non-const parameter"
                    ),
                    file=cs.file,
                    linenr=cs.linenr,
                ))

        return diags

    # ------------------------------------------------------------------
    @staticmethod
    def _check_variadic_promotion(cs: CallSite, arg: ArgInfo) -> List[Diagnostic]:
        """
        In a variadic context the *default argument promotions* apply:
          • char, short  → int
          • float        → double
        If the caller passes e.g. a float, warn that it will be promoted.
        """
        diags: List[Diagnostic] = []
        at = arg.type_name
        if at == "float":
            diags.append(Diagnostic(
                rule="FC04",
                severity=Severity.WARNING,
                message=(
                    f"In variadic call to '{cs.qualified_name}', argument "
                    f"{arg.index + 1} of type 'float' will be promoted to "
                    f"'double' (default argument promotion)"
                ),
                file=cs.file,
                linenr=cs.linenr,
            ))
        elif at in ("char", "short", "bool"):
            diags.append(Diagnostic(
                rule="FC04",
                severity=Severity.INFO,
                message=(
                    f"In variadic call to '{cs.qualified_name}', argument "
                    f"{arg.index + 1} of type '{at}' will be promoted to "
                    f"'int' (default argument promotion)"
                ),
                file=cs.file,
                linenr=cs.linenr,
            ))
        return diags


# ═══════════════════════════════════════════════════════════════════════════
#  §6  Phase 4 – Undefined-Function Detector
# ═══════════════════════════════════════════════════════════════════════════

# Well-known POSIX / compiler-builtin names that are *expected* to lack a
# definition inside the analysed translation unit.
_KNOWN_EXTERNALS: Set[str] = {
    "printf", "fprintf", "sprintf", "snprintf", "vprintf", "vfprintf",
    "vsprintf", "vsnprintf", "scanf", "fscanf", "sscanf",
    "malloc", "calloc", "realloc", "free",
    "memcpy", "memmove", "memset", "memcmp",
    "strlen", "strcpy", "strncpy", "strcmp", "strncmp",
    "strcat", "strncat", "strstr", "strchr", "strrchr",
    "abs", "labs", "llabs", "fabs",
    "sin", "cos", "tan", "sqrt", "pow", "log", "exp",
    "fopen", "fclose", "fread", "fwrite", "fseek", "ftell",
    "exit", "abort", "atexit", "_exit",
    "open", "close", "read", "write", "lseek",
    "stat", "fstat", "lstat",
    "getenv", "setenv", "unsetenv",
    "pthread_create", "pthread_join", "pthread_mutex_init",
    "pthread_mutex_lock", "pthread_mutex_unlock",
    "__builtin_expect", "__builtin_unreachable",
    "__builtin_popcount", "__builtin_clz", "__builtin_ctz",
}


class UndefinedFunctionDetector:
    """FC01: flag every call whose target is declared but not defined."""

    def __init__(self, db: FunctionDatabase):
        self.db = db

    def detect(self, call_sites: List[CallSite]) -> List[Diagnostic]:
        diags: List[Diagnostic] = []
        seen: Set[str] = set()

        for cs in call_sites:
            qname = cs.qualified_name
            if qname in seen:
                continue

            # Try exact, then fuzzy
            fi = self.db.lookup(qname)
            if fi is None:
                candidates = self.db.lookup_fuzzy(cs.name)
                fi = candidates[0] if candidates else None

            if fi is None:
                # Not even declared → likely an implicit declaration or a
                # system function.  We only flag *declared-but-undefined*.
                continue

            if fi.is_declared and not fi.is_defined:
                short = fi.name
                if short in _KNOWN_EXTERNALS:
                    continue  # skip well-known library symbols
                diags.append(Diagnostic(
                    rule="FC01",
                    severity=Severity.WARNING,
                    message=(
                        f"Call to declared but undefined function "
                        f"'{qname}' (declared at "
                        f"{fi.file}:{fi.linenr})"
                    ),
                    file=cs.file,
                    linenr=cs.linenr,
                ))
                seen.add(qname)
        return diags


# ═══════════════════════════════════════════════════════════════════════════
#  §7  Phase 4b – Calling-Convention / Linkage Checker
# ═══════════════════════════════════════════════════════════════════════════

class ConventionChecker:
    """FC06: detect mismatched calling conventions or linkage."""

    def __init__(self, db: FunctionDatabase):
        self.db = db

    def check(self, call_sites: List[CallSite]) -> List[Diagnostic]:
        diags: List[Diagnostic] = []
        for cs in call_sites:
            fi = self.db.lookup(cs.qualified_name)
            if fi is None:
                candidates = self.db.lookup_fuzzy(cs.name)
                fi = candidates[0] if candidates else None
            if fi is None:
                continue

            # Linkage mismatch: calling a C++ function from an extern "C"
            # context (or vice-versa) may cause name-mangling issues at link
            # time; at the AST level we can only flag obvious mismatches.
            call_tok = cs.token
            caller_linkage = Linkage.UNKNOWN
            if call_tok and call_tok.externLang:
                caller_linkage = (
                    Linkage.C if call_tok.externLang == "C" else Linkage.CXX
                )

            if (
                caller_linkage != Linkage.UNKNOWN
                and fi.linkage != Linkage.UNKNOWN
                and caller_linkage != fi.linkage
            ):
                diags.append(Diagnostic(
                    rule="FC06",
                    severity=Severity.PORT,
                    message=(
                        f"Linkage mismatch: call to '{cs.qualified_name}' "
                        f"has {fi.linkage.name} linkage, but call site is in "
                        f"a {caller_linkage.name} context"
                    ),
                    file=cs.file,
                    linenr=cs.linenr,
                ))

            # Calling-convention mismatch across redeclarations
            # (comparing all FunctionInfo entries that share the short name)
            all_decls = self.db.lookup_fuzzy(cs.name)
            conventions = {d.calling_convention for d in all_decls
                          if d.calling_convention != CallingConvention.UNKNOWN}
            if len(conventions) > 1:
                diags.append(Diagnostic(
                    rule="FC06",
                    severity=Severity.PORT,
                    message=(
                        f"Conflicting calling conventions for "
                        f"'{cs.name}': "
                        + ", ".join(sorted(c.name for c in conventions))
                    ),
                    file=cs.file,
                    linenr=cs.linenr,
                ))
        return diags


# ═══════════════════════════════════════════════════════════════════════════
#  §8  Phase 5 – Orchestrator / Validator
# ═══════════════════════════════════════════════════════════════════════════

class FunctionCallValidator:
    """
    Top-level driver: runs all six checks over the collected data and
    emits diagnostics.
    """

    def __init__(self):
        self.db = FunctionDatabase()
        self.diagnostics: List[Diagnostic] = []

    def run(self, cfg) -> List[Diagnostic]:
        """Analyse one cppcheckdata configuration."""
        collector = CallCollector()
        collector.collect(cfg)

        self.db.merge(collector)

        # Phase 4a – undefined functions
        undef_det = UndefinedFunctionDetector(self.db)
        self.diagnostics.extend(undef_det.detect(collector.call_sites))

        # Phase 3 – parameter analysis (FC02..FC05)
        param_anal = ParameterAnalyzer(self.db)
        for cs in collector.call_sites:
            fi = self.db.lookup(cs.qualified_name)
            if fi is None:
                candidates = self.db.lookup_fuzzy(cs.name)
                fi = candidates[0] if candidates else None
            if fi is None:
                continue
            self.diagnostics.extend(param_anal.analyze(cs, fi))

        # Phase 4b – calling convention / linkage
        conv_chk = ConventionChecker(self.db)
        self.diagnostics.extend(conv_chk.check(collector.call_sites))

        return self.diagnostics


# ═══════════════════════════════════════════════════════════════════════════
#  §9  Reporting bridge
# ═══════════════════════════════════════════════════════════════════════════

def _severity_to_cppcheck(sev: str) -> str:
    """Map our Severity to cppcheck severity strings."""
    mapping = {
        "error":       "error",
        "warning":     "warning",
        "style":       "style",
        "performance": "performance",
        "portability": "portability",
        "information": "information",
    }
    if isinstance(sev, Severity):
        return mapping.get(sev.value, "warning")
    return mapping.get(sev, "warning")


def emit(diag: Diagnostic, token=None) -> None:
    """Send a Diagnostic through cppcheckdata.reportError."""
    loc = token or diag  # both have .file / .linenr / .column
    reportError(
        loc,
        _severity_to_cppcheck(diag.severity),
        diag.message,
        ADDON_NAME,
        diag.rule,
        extra=diag.extra,
    )


# ═══════════════════════════════════════════════════════════════════════════
#  §10  Main entry point
# ═══════════════════════════════════════════════════════════════════════════

def check(cfg) -> None:
    """
    Called once per configuration by cppcheck's addon runner, or
    manually from ``__main__`` below.
    """
    validator = FunctionCallValidator()
    diags = validator.run(cfg)
    for d in diags:
        emit(d)


# ---------------------------------------------------------------------------
#  Stand-alone driver (for testing / CLI use)
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    parser = cppcheckdata.ArgumentParser(
        description="BadFunCall — function-call checker addon"
    ) if hasattr(cppcheckdata, "ArgumentParser") else None

    # Fallback: manual argument parsing for older cppcheckdata
    if parser is None:
        if len(sys.argv) < 2:
            sys.stderr.write(
                "Usage: BadFunCall.py <dumpfile> [--cli]\n"
            )
            sys.exit(1)
        dumpfiles = [a for a in sys.argv[1:] if not a.startswith("-")]
    else:
        args = parser.parse_args()
        dumpfiles = args.dumpfile if hasattr(args, "dumpfile") else args

    for dumpfile in dumpfiles:
        data = cppcheckdata.CppcheckData(dumpfile)
        for cfg in data.configurations:
            check(cfg)

    sys.exit(cppcheckdata.EXIT_CODE)
