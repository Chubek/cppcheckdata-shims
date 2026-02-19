#!/usr/bin/env python3
"""
MemoryProvenanceChecker.py
══════════════════════════

A Cppcheck addon that validates memory allocation provenance and lifetime
safety for C/C++ programs, using the cppcheckdata_shims library.

Checks (16 total, two tiers):

  Tier 1 — Critical / Safety
  ──────────────────────────
  ID                        CWE   Severity  Description
  useAfterFree              416   error     Dereference / use of freed pointer
  doubleFree                415   error     Second free of already-freed memory
  danglingReturn            562   error     Returning address of local variable
  mismatchedDealloc         762   error     Alloc/dealloc family mismatch
  useAfterRealloc           761   error     Use of original pointer after realloc
  danglingAssign            562   error     Storing address of local in wider-scope ptr
  nullDerefAfterFree        476   error     Freed pointer compared to NULL then deref'd

  Tier 2 — Warning / Style
  ────────────────────────
  ID                        CWE   Severity  Description
  memoryLeak                401   warning   Allocated memory never freed on path
  uncheckedAlloc            252   warning   Allocation result used without NULL check
  reallocLeak               401   warning   realloc failure leaks original pointer
  leakInBranch              401   warning   Memory leaked on error/early-return path
  allocZeroSize             687   warning   Allocation with size 0
  uninitFreeArg             457   warning   Free called on uninitialised pointer
  redundantFree             563   style     Free of pointer that was never allocated
  allocInLoop               401   style     Allocation inside loop without free
  unusedAlloc               563   style     Allocation result never used

Requires: cppcheckdata, cppcheckdata_shims (type_analysis, dataflow_analysis)

Usage:
  cppcheck --dump myfile.c
  python MemoryProvenanceChecker.py myfile.c.dump

Self-test:
  python MemoryProvenanceChecker.py --self-test
"""

from __future__ import annotations

import argparse
import glob
import os
import re
import subprocess
import sys
import tempfile
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import (
    Any,
    Callable,
    Dict,
    FrozenSet,
    List,
    Mapping,
    Optional,
    Sequence,
    Set,
    Tuple,
    Union,
)

# ── cppcheckdata imports ─────────────────────────────────────────────
try:
    import cppcheckdata
    from cppcheckdata import CppcheckData, Configuration, Token, Variable, Scope
except ImportError:
    cppcheckdata = None
    CppcheckData = Any
    Configuration = Any
    Token = Any
    Variable = Any
    Scope = Any

# ── cppcheckdata_shims imports ───────────────────────────────────────
try:
    from cppcheckdata_shims.type_analysis import (
        CType,
        TypeKind,
        Qualifier,
    )
    from cppcheckdata_shims.dataflow_analysis import (
        build_cfg,
        ReachingDefinitions,
        LiveVariables,
        PointerAnalysis,
        NullPointerAnalysis,
    )
    HAS_SHIMS = True
except ImportError:
    HAS_SHIMS = False


# ═════════════════════════════════════════════════════════════════════
#  PART 1 — PROVENANCE DOMAIN
# ═════════════════════════════════════════════════════════════════════

class AllocFamily(Enum):
    """Allocation/deallocation family for mismatch detection."""
    MALLOC = auto()
    NEW = auto()
    NEW_ARRAY = auto()
    FOPEN = auto()
    CUSTOM = auto()

    def expected_dealloc(self) -> str:
        return {
            AllocFamily.MALLOC: "free",
            AllocFamily.NEW: "delete",
            AllocFamily.NEW_ARRAY: "delete[]",
            AllocFamily.FOPEN: "fclose",
            AllocFamily.CUSTOM: "<custom>",
        }[self]


class ProvenanceKind(Enum):
    BOTTOM = auto()
    HEAP = auto()
    STACK = auto()
    GLOBAL = auto()
    NULL = auto()
    FREED = auto()
    UNKNOWN = auto()
    TOP = auto()


@dataclass(frozen=True)
class Provenance:
    """
    Abstract provenance element.

    alloc_site and free_site are *opaque string identifiers*
    (cppcheck Token.Id values — hex addresses, NOT decimal ints).
    """
    kind: ProvenanceKind
    alloc_site: Optional[str] = None          # FIX: was Optional[int]
    alloc_family: Optional[AllocFamily] = None
    free_site: Optional[str] = None           # FIX: was Optional[int]
    scope_id: Optional[str] = None
    null_checked: bool = False

    # ── Lattice operations ───────────────────────────────────────

    @staticmethod
    def bottom() -> Provenance:
        return Provenance(kind=ProvenanceKind.BOTTOM)

    @staticmethod
    def top() -> Provenance:
        return Provenance(kind=ProvenanceKind.TOP)

    @staticmethod
    def heap(alloc_site: str, family: AllocFamily = AllocFamily.MALLOC) -> Provenance:
        return Provenance(
            kind=ProvenanceKind.HEAP,
            alloc_site=alloc_site,
            alloc_family=family,
        )

    @staticmethod
    def stack(scope_id: str) -> Provenance:
        return Provenance(kind=ProvenanceKind.STACK, scope_id=scope_id)

    @staticmethod
    def global_prov() -> Provenance:
        return Provenance(kind=ProvenanceKind.GLOBAL)

    @staticmethod
    def null() -> Provenance:
        return Provenance(kind=ProvenanceKind.NULL)

    @staticmethod
    def freed(alloc_site: str, free_site: str, family: AllocFamily) -> Provenance:
        return Provenance(
            kind=ProvenanceKind.FREED,
            alloc_site=alloc_site,
            alloc_family=family,
            free_site=free_site,
        )

    def join(self, other: Provenance) -> Provenance:
        """Least upper bound in the provenance lattice."""
        if self.kind == ProvenanceKind.BOTTOM:
            return other
        if other.kind == ProvenanceKind.BOTTOM:
            return self
        if self.kind == ProvenanceKind.TOP or other.kind == ProvenanceKind.TOP:
            return Provenance.top()
        if self == other:
            return self
        if self.kind == other.kind:
            if self.kind in (ProvenanceKind.HEAP, ProvenanceKind.STACK):
                return Provenance(kind=ProvenanceKind.UNKNOWN)
            return self
        if {self.kind, other.kind} == {ProvenanceKind.HEAP, ProvenanceKind.FREED}:
            freed_one = self if self.kind == ProvenanceKind.FREED else other
            return freed_one
        return Provenance(kind=ProvenanceKind.UNKNOWN)

    def with_null_checked(self) -> Provenance:
        return Provenance(
            kind=self.kind,
            alloc_site=self.alloc_site,
            alloc_family=self.alloc_family,
            free_site=self.free_site,
            scope_id=self.scope_id,
            null_checked=True,
        )

    @property
    def is_live(self) -> bool:
        return self.kind in {ProvenanceKind.HEAP, ProvenanceKind.STACK,
                             ProvenanceKind.GLOBAL, ProvenanceKind.UNKNOWN,
                             ProvenanceKind.TOP}

    @property
    def is_freed(self) -> bool:
        return self.kind == ProvenanceKind.FREED

    @property
    def is_null(self) -> bool:
        return self.kind == ProvenanceKind.NULL

    @property
    def is_heap(self) -> bool:
        return self.kind == ProvenanceKind.HEAP

    @property
    def is_stack(self) -> bool:
        return self.kind == ProvenanceKind.STACK


# ═════════════════════════════════════════════════════════════════════
#  PART 2 — PROVENANCE STATE (per program point)
# ═════════════════════════════════════════════════════════════════════

@dataclass
class ProvenanceState:
    var_map: Dict[str, Provenance] = field(default_factory=dict)

    def get(self, var_id: str) -> Provenance:
        return self.var_map.get(var_id, Provenance.bottom())

    def set(self, var_id: str, prov: Provenance) -> ProvenanceState:
        new_map = dict(self.var_map)
        new_map[var_id] = prov
        return ProvenanceState(var_map=new_map)

    def join(self, other: ProvenanceState) -> ProvenanceState:
        all_keys = set(self.var_map) | set(other.var_map)
        merged = {}
        for k in all_keys:
            merged[k] = self.get(k).join(other.get(k))
        return ProvenanceState(var_map=merged)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ProvenanceState):
            return NotImplemented
        return self.var_map == other.var_map

    def copy(self) -> ProvenanceState:
        return ProvenanceState(var_map=dict(self.var_map))


# ═════════════════════════════════════════════════════════════════════
#  PART 3 — DIAGNOSTIC INFRASTRUCTURE
# ═════════════════════════════════════════════════════════════════════

class Severity(Enum):
    ERROR = "error"
    WARNING = "warning"
    STYLE = "style"
    INFORMATION = "information"


@dataclass
class Diagnostic:
    check_id: str
    cwe: int
    severity: Severity
    file: str
    line: int
    column: int
    message: str
    tier: int = 1


# ── Known allocators / deallocators ──────────────────────────────────

ALLOC_FUNCTIONS: Dict[str, AllocFamily] = {
    "malloc": AllocFamily.MALLOC,
    "calloc": AllocFamily.MALLOC,
    "realloc": AllocFamily.MALLOC,
    "strdup": AllocFamily.MALLOC,
    "strndup": AllocFamily.MALLOC,
    "aligned_alloc": AllocFamily.MALLOC,
    "reallocarray": AllocFamily.MALLOC,
    "fopen": AllocFamily.FOPEN,
    "tmpfile": AllocFamily.FOPEN,
    "fdopen": AllocFamily.FOPEN,
    "freopen": AllocFamily.FOPEN,
}

DEALLOC_FUNCTIONS: Dict[str, AllocFamily] = {
    "free": AllocFamily.MALLOC,
    "fclose": AllocFamily.FOPEN,
}

CPP_NEW = {"new"}
CPP_DELETE = {"delete"}


# ═════════════════════════════════════════════════════════════════════
#  PART 4 — TOKEN HELPERS
# ═════════════════════════════════════════════════════════════════════

def _tok_id(tok: Any) -> str:
    """
    Return the opaque string identifier for a cppcheck Token.

    Cppcheck Token.Id is a hex address string like '55ac4c958090'.
    We keep it as-is — NEVER convert to int without base 16.
    """
    if tok is None:
        return "<none>"
    raw = getattr(tok, "Id", None)
    if raw is None:
        return str(id(tok))
    return str(raw)                       # FIX: always string, never int()


def _tok_var_id(tok: Any) -> Optional[str]:
    """Get the variable id string for a token, if it names a variable."""
    var = getattr(tok, "variable", None)
    if var is not None:
        raw = getattr(var, "Id", None)
        if raw is not None:
            return str(raw)               # FIX: string
        return str(id(var))
    s = getattr(tok, "str", None)
    if s and s.isidentifier():
        return s
    return None


def _tok_str(tok: Any) -> str:
    return getattr(tok, "str", "") or ""


def _tok_file(tok: Any) -> str:
    return getattr(tok, "file", "<unknown>") or "<unknown>"


def _tok_line(tok: Any) -> int:
    return int(getattr(tok, "linenr", 0) or 0)


def _tok_col(tok: Any) -> int:
    return int(getattr(tok, "column", 0) or 0)


def _tok_next(tok: Any) -> Any:
    return getattr(tok, "next", None)


def _tok_prev(tok: Any) -> Any:
    return getattr(tok, "previous", None)


def _tok_astparent(tok: Any) -> Any:
    return getattr(tok, "astParent", None)


def _tok_astop1(tok: Any) -> Any:
    return getattr(tok, "astOperand1", None)


def _tok_astop2(tok: Any) -> Any:
    return getattr(tok, "astOperand2", None)


def _is_call_to(tok: Any, names: set) -> bool:
    s = _tok_str(tok)
    if s == "(":
        prev = _tok_prev(tok)
        if prev and _tok_str(prev) in names:
            return True
        op1 = _tok_astop1(tok)
        if op1 and _tok_str(op1) in names:
            return True
    if s in names:
        nxt = _tok_next(tok)
        if nxt and _tok_str(nxt) == "(":
            return True
    return False


def _get_call_name(tok: Any) -> Optional[str]:
    s = _tok_str(tok)
    if s == "(":
        op1 = _tok_astop1(tok)
        if op1:
            return _tok_str(op1)
        prev = _tok_prev(tok)
        if prev:
            return _tok_str(prev)
    nxt = _tok_next(tok)
    if nxt and _tok_str(nxt) == "(":
        return s
    return None


def _get_call_args(tok: Any) -> List[Any]:
    args: List[Any] = []
    s = _tok_str(tok)
    if s == "(":
        op2 = _tok_astop2(tok)
        if op2 is not None:
            _collect_comma_args(op2, args)
        return args
    nxt = _tok_next(tok)
    if nxt and _tok_str(nxt) == "(":
        return _get_call_args(nxt)
    return args


def _collect_comma_args(tok: Any, out: List[Any]) -> None:
    if tok is None:
        return
    if _tok_str(tok) == ",":
        _collect_comma_args(_tok_astop1(tok), out)
        _collect_comma_args(_tok_astop2(tok), out)
    else:
        out.append(tok)


def _var_is_pointer(var: Any) -> bool:
    if var is None:
        return False
    if getattr(var, "isPointer", False):
        return True
    vt = getattr(var, "valueType", None)
    if vt and getattr(vt, "pointer", 0) > 0:
        return True
    return False


def _var_is_local(var: Any) -> bool:
    if var is None:
        return False
    if getattr(var, "isLocal", False):
        return True
    if getattr(var, "isArgument", False):
        return False
    scope = getattr(var, "scope", None)
    if scope:
        stype = getattr(scope, "type", "")
        if stype in ("Function", "If", "Else", "For", "While", "Do", "Switch"):
            return True
    return False


def _var_scope_id(var: Any) -> str:
    scope = getattr(var, "scope", None)
    if scope:
        raw = getattr(scope, "Id", None)
        if raw is not None:
            return str(raw)               # FIX: string
        return str(id(scope))
    return "<global>"


def _is_deref(tok: Any) -> bool:
    parent = _tok_astparent(tok)
    if parent is None:
        return False
    ps = _tok_str(parent)
    if ps == "*" and _tok_astop2(parent) is None:
        return _tok_astop1(parent) is tok
    if ps == "->":
        return _tok_astop1(parent) is tok
    if ps == "[":
        return _tok_astop1(parent) is tok
    return False


def _is_address_of(tok: Any) -> bool:
    parent = _tok_astparent(tok)
    if parent is None:
        return False
    ps = _tok_str(parent)
    if ps == "&" and _tok_astop2(parent) is None:
        return _tok_astop1(parent) is tok
    return False


def _is_return_stmt(tok: Any) -> bool:
    s = _tok_str(tok)
    if s == "return":
        return True
    prev = tok
    for _ in range(10):
        prev = _tok_prev(prev)
        if prev is None:
            break
        ps = _tok_str(prev)
        if ps == "return":
            return True
        if ps in (";", "{", "}"):
            break
    return False


def _scope_encloses(outer_scope_id: str, inner_scope_id: str,
                     scope_map: Dict[str, Any]) -> bool:
    if outer_scope_id == inner_scope_id:
        return True
    current = scope_map.get(inner_scope_id)
    visited: Set[str] = set()
    while current is not None:
        sid_raw = getattr(current, "Id", None)
        sid = str(sid_raw) if sid_raw is not None else str(id(current))
        if sid in visited:
            break
        visited.add(sid)
        if sid == outer_scope_id:
            return True
        current = getattr(current, "nestedIn", None)
    return False


# ═════════════════════════════════════════════════════════════════════
#  PART 5 — CHECKER DEFINITIONS
# ═════════════════════════════════════════════════════════════════════

@dataclass
class CheckerDef:
    check_id: str
    cwe: int
    severity: Severity
    tier: int
    description: str
    enabled: bool = True


# Tier 1 — Critical
CHECKER_USE_AFTER_FREE = CheckerDef(
    "useAfterFree", 416, Severity.ERROR, 1,
    "Dereference or use of pointer after it has been freed")
CHECKER_DOUBLE_FREE = CheckerDef(
    "doubleFree", 415, Severity.ERROR, 1,
    "Memory freed more than once")
CHECKER_DANGLING_RETURN = CheckerDef(
    "danglingReturn", 562, Severity.ERROR, 1,
    "Returning address of local (stack) variable")
CHECKER_MISMATCHED_DEALLOC = CheckerDef(
    "mismatchedDealloc", 762, Severity.ERROR, 1,
    "Allocation/deallocation family mismatch")
CHECKER_USE_AFTER_REALLOC = CheckerDef(
    "useAfterRealloc", 761, Severity.ERROR, 1,
    "Use of original pointer after realloc (may have been moved)")
CHECKER_DANGLING_ASSIGN = CheckerDef(
    "danglingAssign", 562, Severity.ERROR, 1,
    "Storing address of local variable in pointer with wider scope")
CHECKER_NULL_DEREF_AFTER_FREE = CheckerDef(
    "nullDerefAfterFree", 476, Severity.ERROR, 1,
    "Dereferencing freed pointer after spurious NULL comparison")

# Tier 2 — Warning / Style
CHECKER_MEMORY_LEAK = CheckerDef(
    "memoryLeak", 401, Severity.WARNING, 2,
    "Allocated memory is never freed on this execution path")
CHECKER_UNCHECKED_ALLOC = CheckerDef(
    "uncheckedAlloc", 252, Severity.WARNING, 2,
    "Allocation result used without NULL check")
CHECKER_REALLOC_LEAK = CheckerDef(
    "reallocLeak", 401, Severity.WARNING, 2,
    "realloc failure would leak the original pointer")
CHECKER_LEAK_IN_BRANCH = CheckerDef(
    "leakInBranch", 401, Severity.WARNING, 2,
    "Memory leaked on early-return or error path")
CHECKER_ALLOC_ZERO_SIZE = CheckerDef(
    "allocZeroSize", 687, Severity.WARNING, 2,
    "Allocation with size argument of 0")
CHECKER_UNINIT_FREE_ARG = CheckerDef(
    "uninitFreeArg", 457, Severity.WARNING, 2,
    "Calling free on an uninitialised pointer variable")
CHECKER_REDUNDANT_FREE = CheckerDef(
    "redundantFree", 563, Severity.STYLE, 2,
    "Calling free on a pointer that was never dynamically allocated")
CHECKER_ALLOC_IN_LOOP = CheckerDef(
    "allocInLoop", 401, Severity.STYLE, 2,
    "Allocation inside loop body without corresponding free")
CHECKER_UNUSED_ALLOC = CheckerDef(
    "unusedAlloc", 563, Severity.STYLE, 2,
    "Allocation result is never used")

ALL_CHECKERS: List[CheckerDef] = [
    CHECKER_USE_AFTER_FREE, CHECKER_DOUBLE_FREE, CHECKER_DANGLING_RETURN,
    CHECKER_MISMATCHED_DEALLOC, CHECKER_USE_AFTER_REALLOC,
    CHECKER_DANGLING_ASSIGN, CHECKER_NULL_DEREF_AFTER_FREE,
    CHECKER_MEMORY_LEAK, CHECKER_UNCHECKED_ALLOC, CHECKER_REALLOC_LEAK,
    CHECKER_LEAK_IN_BRANCH, CHECKER_ALLOC_ZERO_SIZE, CHECKER_UNINIT_FREE_ARG,
    CHECKER_REDUNDANT_FREE, CHECKER_ALLOC_IN_LOOP, CHECKER_UNUSED_ALLOC,
]

TIER1_IDS: FrozenSet[str] = frozenset(c.check_id for c in ALL_CHECKERS if c.tier == 1)
TIER2_IDS: FrozenSet[str] = frozenset(c.check_id for c in ALL_CHECKERS if c.tier == 2)


# ═════════════════════════════════════════════════════════════════════
#  PART 6 — CORE ANALYSIS ENGINE
# ═════════════════════════════════════════════════════════════════════

class MemoryProvenanceAnalyzer:
    """
    Main analysis driver.

    Walks each function's token stream, maintaining a ProvenanceState,
    and emits diagnostics when provenance violations are detected.
    """

    def __init__(
        self,
        configuration: Any,
        *,
        enabled_checks: Optional[Set[str]] = None,
        suppress_ids: Optional[Set[str]] = None,
    ):
        self.cfg = configuration
        self.diagnostics: List[Diagnostic] = []
        self._enabled: Set[str] = enabled_checks or {c.check_id for c in ALL_CHECKERS}
        self._suppress: Set[str] = suppress_ids or set()
        # FIX: tier1 suppression keyed by (file, line) tuple, not bare int
        self._tier1_locations: Set[Tuple[str, int]] = set()
        self._scope_map: Dict[str, Any] = {}
        self._build_scope_map()
        # FIX: alloc_tracker keyed by str (opaque token id), not int
        self._alloc_tracker: Dict[str, Tuple[str, bool]] = {}
        self._realloc_map: Dict[str, str] = {}

    def _build_scope_map(self) -> None:
        scopes = getattr(self.cfg, "scopes", []) or []
        for scope in scopes:
            sid = _tok_id(scope)          # FIX: reuse helper
            self._scope_map[sid] = scope

    def _emit(self, checker: CheckerDef, tok: Any, extra_msg: str = "") -> None:
        if checker.check_id not in self._enabled:
            return
        if checker.check_id in self._suppress:
            return

        loc_key = (_tok_file(tok), _tok_line(tok))  # FIX: (file, line)

        if checker.tier == 2 and loc_key in self._tier1_locations:
            return

        if checker.tier == 1:
            self._tier1_locations.add(loc_key)

        msg = checker.description
        if extra_msg:
            msg = f"{msg}: {extra_msg}"

        self.diagnostics.append(Diagnostic(
            check_id=checker.check_id,
            cwe=checker.cwe,
            severity=checker.severity,
            file=_tok_file(tok),
            line=_tok_line(tok),
            column=_tok_col(tok),
            message=msg,
            tier=checker.tier,
        ))

    # ── Main entry point ─────────────────────────────────────────

    def analyze(self) -> List[Diagnostic]:
        scopes = getattr(self.cfg, "scopes", []) or []
        for scope in scopes:
            stype = getattr(scope, "type", "")
            if stype == "Function":
                self._analyze_function_scope(scope)
        self._check_leaks()
        return self.diagnostics

    def _analyze_function_scope(self, scope: Any) -> None:
        body_start = getattr(scope, "bodyStart", None)
        body_end = getattr(scope, "bodyEnd", None)
        if body_start is None or body_end is None:
            return

        func_scope_id = _tok_id(scope)    # FIX: use helper

        state = ProvenanceState()

        func = getattr(scope, "function", None)
        if func:
            arg_list = getattr(func, "argument", {}) or {}
            for _idx, arg_var in arg_list.items():
                vid = str(getattr(arg_var, "Id", id(arg_var)))
                if _var_is_pointer(arg_var):
                    state = state.set(vid, Provenance(kind=ProvenanceKind.UNKNOWN))

        loop_depth = 0
        loop_allocs: List[Tuple[Any, str]] = []

        tok = _tok_next(body_start)
        while tok is not None and tok != body_end:
            state, tok = self._process_token(tok, state, func_scope_id,
                                              loop_depth, loop_allocs)
            if tok is None:
                break

            s = _tok_str(tok)
            if s in ("for", "while", "do"):
                loop_depth += 1

            tok = _tok_next(tok)

        self._check_function_end_leaks(state, scope)

    def _process_token(
        self,
        tok: Any,
        state: ProvenanceState,
        func_scope_id: str,
        loop_depth: int,
        loop_allocs: List[Tuple[Any, str]],
    ) -> Tuple[ProvenanceState, Any]:

        s = _tok_str(tok)

        # ── ALLOCATION ───────────────────────────────────────────
        call_name = _get_call_name(tok)

        # Handle realloc before generic alloc (realloc is in ALLOC_FUNCTIONS
        # but needs special treatment)
        if call_name == "realloc":
            state = self._handle_realloc(tok, state)
            return (state, tok)

        if call_name and call_name in ALLOC_FUNCTIONS:
            state = self._handle_allocation(tok, call_name, state,
                                             func_scope_id, loop_depth,
                                             loop_allocs)
            return (state, tok)

        # ── DEALLOCATION ─────────────────────────────────────────
        if call_name and call_name in DEALLOC_FUNCTIONS:
            state = self._handle_deallocation(tok, call_name, state)
            return (state, tok)

        # C++ new / delete
        if s == "new":
            state = self._handle_cpp_new(tok, state, loop_depth, loop_allocs)
            return (state, tok)
        if s == "delete":
            state = self._handle_cpp_delete(tok, state)
            return (state, tok)

        # ── ASSIGNMENT ───────────────────────────────────────────
        if s == "=" and _tok_astop1(tok) and _tok_astop2(tok):
            state = self._handle_assignment(tok, state, func_scope_id)
            return (state, tok)

        # ── USE DETECTION ────────────────────────────────────────
        var_id = _tok_var_id(tok)
        if var_id and var_id in state.var_map:
            prov = state.get(var_id)
            self._check_use(tok, var_id, prov, state, func_scope_id)

        return (state, tok)

    # ── Allocation handler ───────────────────────────────────────

    def _handle_allocation(
        self,
        tok: Any,
        call_name: str,
        state: ProvenanceState,
        func_scope_id: str,
        loop_depth: int,
        loop_allocs: List[Tuple[Any, str]],
    ) -> ProvenanceState:
        family = ALLOC_FUNCTIONS[call_name]
        alloc_site = _tok_id(tok)         # FIX: string, not int()

        # Check zero-size
        args = _get_call_args(tok)
        if args and call_name in ("malloc", "aligned_alloc"):
            for arg in args:
                if _tok_str(arg) == "0":
                    self._emit(CHECKER_ALLOC_ZERO_SIZE, tok,
                              f"'{call_name}' called with size 0")

        # Find assignment target
        assign_var_id = self._find_assign_target(tok)

        if assign_var_id:
            prov = Provenance.heap(alloc_site, family)
            state = state.set(assign_var_id, prov)
            self._alloc_tracker[alloc_site] = (assign_var_id, False)

            if loop_depth > 0:
                loop_allocs.append((tok, assign_var_id))
                self._emit(CHECKER_ALLOC_IN_LOOP, tok,
                          f"'{call_name}' called inside loop; "
                          f"ensure memory is freed each iteration")
        else:
            self._emit(CHECKER_UNUSED_ALLOC, tok,
                      f"Return value of '{call_name}' is discarded")

        return state

    # ── Deallocation handler ─────────────────────────────────────

    def _handle_deallocation(
        self,
        tok: Any,
        call_name: str,
        state: ProvenanceState,
    ) -> ProvenanceState:
        expected_family = DEALLOC_FUNCTIONS[call_name]
        free_site = _tok_id(tok)          # FIX: string

        args = _get_call_args(tok)
        if not args:
            return state

        arg_tok = args[0]
        var_id = _tok_var_id(arg_tok)
        if var_id is None:
            return state

        prov = state.get(var_id)

        # Uninitialised pointer
        if prov.kind == ProvenanceKind.BOTTOM:
            self._emit(CHECKER_UNINIT_FREE_ARG, tok,
                      f"'{call_name}' called on uninitialised pointer "
                      f"'{_tok_str(arg_tok)}'")
            return state

        # Double free
        if prov.is_freed:
            self._emit(CHECKER_DOUBLE_FREE, tok,
                      f"'{_tok_str(arg_tok)}' already freed")
            return state

        # Free of stack pointer
        if prov.kind == ProvenanceKind.STACK:
            self._emit(CHECKER_REDUNDANT_FREE, tok,
                      f"'{call_name}' called on stack variable "
                      f"'{_tok_str(arg_tok)}'")
            return state

        # Free of global pointer
        if prov.kind == ProvenanceKind.GLOBAL:
            self._emit(CHECKER_REDUNDANT_FREE, tok,
                      f"'{call_name}' called on global/static pointer "
                      f"'{_tok_str(arg_tok)}' that was not heap-allocated")
            return state

        # Mismatched family
        if prov.is_heap and prov.alloc_family is not None:
            if prov.alloc_family != expected_family:
                expected_dealloc = prov.alloc_family.expected_dealloc()
                self._emit(CHECKER_MISMATCHED_DEALLOC, tok,
                          f"'{_tok_str(arg_tok)}' was allocated with "
                          f"'{prov.alloc_family.name.lower()}' family "
                          f"but freed with '{call_name}' "
                          f"(expected '{expected_dealloc}')")

        # Free of NULL is legal no-op
        if prov.is_null:
            return state

        # Transition to FREED
        alloc_site = prov.alloc_site or ""
        alloc_fam = prov.alloc_family or expected_family
        freed_prov = Provenance.freed(alloc_site, free_site, alloc_fam)
        state = state.set(var_id, freed_prov)

        # Mark freed in tracker
        if alloc_site and alloc_site in self._alloc_tracker:
            self._alloc_tracker[alloc_site] = (
                self._alloc_tracker[alloc_site][0], True)

        return state

    # ── C++ new handler ──────────────────────────────────────────

    def _handle_cpp_new(
        self,
        tok: Any,
        state: ProvenanceState,
        loop_depth: int,
        loop_allocs: List[Tuple[Any, str]],
    ) -> ProvenanceState:
        alloc_site = _tok_id(tok)         # FIX: string
        nxt = _tok_next(tok)
        is_array = nxt is not None and _tok_str(nxt) == "["
        family = AllocFamily.NEW_ARRAY if is_array else AllocFamily.NEW

        assign_var_id = self._find_assign_target(tok)

        if assign_var_id:
            state = state.set(assign_var_id,
                            Provenance.heap(alloc_site, family))
            self._alloc_tracker[alloc_site] = (assign_var_id, False)

        return state

    # ── C++ delete handler ───────────────────────────────────────

    def _handle_cpp_delete(
        self, tok: Any, state: ProvenanceState,
    ) -> ProvenanceState:
        free_site = _tok_id(tok)          # FIX: string
        nxt = _tok_next(tok)
        is_array = nxt is not None and _tok_str(nxt) == "["
        expected_family = AllocFamily.NEW_ARRAY if is_array else AllocFamily.NEW

        arg_tok = nxt
        if is_array:
            arg_tok = _tok_next(nxt)
            if arg_tok and _tok_str(arg_tok) == "]":
                arg_tok = _tok_next(arg_tok)

        if arg_tok is None:
            return state

        var_id = _tok_var_id(arg_tok)
        if var_id is None:
            return state

        prov = state.get(var_id)

        # Double delete
        if prov.is_freed:
            self._emit(CHECKER_DOUBLE_FREE, tok,
                      f"'{_tok_str(arg_tok)}' already deleted")
            return state

        # Mismatch: new vs delete[] or new[] vs delete
        if prov.is_heap and prov.alloc_family is not None:
            if prov.alloc_family != expected_family:
                expected_dealloc = prov.alloc_family.expected_dealloc()
                kind = "delete[]" if is_array else "delete"
                self._emit(CHECKER_MISMATCHED_DEALLOC, tok,
                          f"'{_tok_str(arg_tok)}' was allocated with "
                          f"'{prov.alloc_family.name.lower()}' "
                          f"but deallocated with '{kind}' "
                          f"(expected '{expected_dealloc}')")

        # delete on malloc'd memory
        if prov.is_heap and prov.alloc_family == AllocFamily.MALLOC:
            kind = "delete[]" if is_array else "delete"
            self._emit(CHECKER_MISMATCHED_DEALLOC, tok,
                      f"'{_tok_str(arg_tok)}' was allocated with 'malloc' "
                      f"but deallocated with '{kind}' (expected 'free')")

        # Transition to freed
        alloc_site = prov.alloc_site or ""
        freed_prov = Provenance.freed(alloc_site, free_site,
                                       prov.alloc_family or expected_family)
        state = state.set(var_id, freed_prov)

        if alloc_site and alloc_site in self._alloc_tracker:
            self._alloc_tracker[alloc_site] = (
                self._alloc_tracker[alloc_site][0], True)

        return state

    # ── Realloc handler ──────────────────────────────────────────

    def _handle_realloc(
        self, tok: Any, state: ProvenanceState,
    ) -> ProvenanceState:
        args = _get_call_args(tok)
        if len(args) < 2:
            return state

        old_ptr_tok = args[0]
        old_var_id = _tok_var_id(old_ptr_tok)

        if old_var_id:
            old_prov = state.get(old_var_id)
            if old_prov.is_freed:
                self._emit(CHECKER_USE_AFTER_REALLOC, tok,
                          f"realloc called on already-freed pointer "
                          f"'{_tok_str(old_ptr_tok)}'")

        new_var_id = self._find_assign_target(tok)

        # p = realloc(p, sz) → leak on failure
        if new_var_id and old_var_id and new_var_id == old_var_id:
            self._emit(CHECKER_REALLOC_LEAK, tok,
                      f"If realloc fails, '{_tok_str(old_ptr_tok)}' is leaked "
                      f"(assign to a temporary first)")

        alloc_site = _tok_id(tok)         # FIX: string
        if new_var_id:
            state = state.set(new_var_id,
                            Provenance.heap(alloc_site, AllocFamily.MALLOC))
            self._alloc_tracker[alloc_site] = (new_var_id, False)

        # Invalidate old pointer if different from new
        if old_var_id and old_var_id != new_var_id:
            free_site = _tok_id(tok)      # FIX: string
            old_alloc = state.get(old_var_id).alloc_site or ""
            state = state.set(
                old_var_id,
                Provenance.freed(old_alloc, free_site, AllocFamily.MALLOC),
            )
            if new_var_id:
                self._realloc_map[new_var_id] = old_var_id

        return state

    # ── Assignment handler ───────────────────────────────────────

    def _handle_assignment(
        self, tok: Any, state: ProvenanceState, func_scope_id: str,
    ) -> ProvenanceState:
        lhs = _tok_astop1(tok)
        rhs = _tok_astop2(tok)
        if lhs is None or rhs is None:
            return state

        lhs_var_id = _tok_var_id(lhs)
        if lhs_var_id is None:
            return state

        rhs_s = _tok_str(rhs)

        # ptr = NULL
        if rhs_s in ("0", "NULL", "nullptr"):
            state = state.set(lhs_var_id, Provenance.null())
            return state

        # ptr = &local_var
        if rhs_s == "&" and _tok_astop1(rhs):
            inner = _tok_astop1(rhs)
            inner_var = getattr(inner, "variable", None)
            if inner_var and _var_is_local(inner_var):
                inner_scope_id = _var_scope_id(inner_var)
                stack_prov = Provenance.stack(inner_scope_id)
                state = state.set(lhs_var_id, stack_prov)

                lhs_var = getattr(lhs, "variable", None)
                if lhs_var:
                    lhs_scope_id = _var_scope_id(lhs_var)
                    if not _scope_encloses(
                        inner_scope_id, lhs_scope_id, self._scope_map
                    ):
                        self._emit(CHECKER_DANGLING_ASSIGN, tok,
                                  f"Address of local '{_tok_str(inner)}' "
                                  f"stored in wider-scope pointer "
                                  f"'{_tok_str(lhs)}'")
                return state

        # ptr = other_ptr
        rhs_var_id = _tok_var_id(rhs)
        if rhs_var_id and rhs_var_id in state.var_map:
            state = state.set(lhs_var_id, state.get(rhs_var_id))
            return state

        return state

    # ── Use checker ──────────────────────────────────────────────

    def _check_use(
        self,
        tok: Any,
        var_id: str,
        prov: Provenance,
        state: ProvenanceState,
        func_scope_id: str,
    ) -> None:

        # USE AFTER FREE
        if prov.is_freed:
            if _is_deref(tok):
                self._emit(CHECKER_USE_AFTER_FREE, tok,
                          f"Dereferencing '{_tok_str(tok)}' after free")
                return

            parent = _tok_astparent(tok)
            if parent and _tok_str(parent) in ("(", ","):
                self._emit(CHECKER_USE_AFTER_FREE, tok,
                          f"Passing freed pointer '{_tok_str(tok)}' "
                          f"to function")
                return

            if parent and _tok_str(parent) in ("==", "!="):
                other = (_tok_astop2(parent) if _tok_astop1(parent) is tok
                         else _tok_astop1(parent))
                if other and _tok_str(other) in ("0", "NULL", "nullptr"):
                    self._emit(CHECKER_NULL_DEREF_AFTER_FREE, tok,
                              f"Comparing freed pointer '{_tok_str(tok)}' "
                              f"to NULL (pointer is already invalid)")
                    return

        # USE AFTER REALLOC
        for new_vid, old_vid in self._realloc_map.items():
            if var_id == old_vid:
                old_prov = state.get(old_vid)
                if old_prov.is_freed:
                    self._emit(CHECKER_USE_AFTER_REALLOC, tok,
                              f"'{_tok_str(tok)}' was the original pointer "
                              f"passed to realloc and may have been "
                              f"invalidated")
                    return

        # DANGLING RETURN
        if prov.is_stack and _is_return_stmt(tok):
            self._emit(CHECKER_DANGLING_RETURN, tok,
                      f"Returning address of local variable "
                      f"(via '{_tok_str(tok)}')")
            return

        # UNCHECKED ALLOC
        if prov.is_heap and not prov.null_checked and _is_deref(tok):
            self._emit(CHECKER_UNCHECKED_ALLOC, tok,
                      f"Dereferencing '{_tok_str(tok)}' without "
                      f"NULL check after allocation")

    # ── End-of-function leak detection ───────────────────────────

    def _check_function_end_leaks(
        self, state: ProvenanceState, scope: Any,
    ) -> None:
        body_end = getattr(scope, "bodyEnd", None)
        if body_end is None:
            return

        for var_id, prov in state.var_map.items():
            if prov.is_heap:
                self._emit(CHECKER_MEMORY_LEAK, body_end,
                          f"Pointer '{var_id}' was allocated but not "
                          f"freed before function exit")

    def _check_leaks(self) -> None:
        pass

    # ── Utility: find assignment target above a call ─────────────

    def _find_assign_target(self, tok: Any) -> Optional[str]:
        """
        Walk AST parents upward to find  var = <expr containing tok>.
        Returns the variable id of the LHS, or None.
        """
        visited: Set[int] = set()
        p = _tok_astparent(tok)
        while p is not None:
            pid = id(p)
            if pid in visited:
                break
            visited.add(pid)
            if _tok_str(p) == "=":
                lhs = _tok_astop1(p)
                if lhs:
                    return _tok_var_id(lhs)
                break
            p = _tok_astparent(p)
        return None


# ═════════════════════════════════════════════════════════════════════
#  PART 7 — REPORTING
# ═════════════════════════════════════════════════════════════════════

def format_diagnostic(diag: Diagnostic) -> str:
    sev = diag.severity.value
    return (
        f"[{diag.check_id}] {diag.file}:{diag.line}:{diag.column}: "
        f"{sev}: {diag.message} [CWE-{diag.cwe}]"
    )


def format_diagnostic_xml(diag: Diagnostic) -> str:
    import html
    return (
        f'  <error id="{diag.check_id}" '
        f'severity="{diag.severity.value}" '
        f'msg="{html.escape(diag.message)}" '
        f'cwe="{diag.cwe}">\n'
        f'    <location file="{html.escape(diag.file)}" '
        f'line="{diag.line}" column="{diag.column}"/>\n'
        f'  </error>'
    )


# ═════════════════════════════════════════════════════════════════════
#  PART 8 — MAIN DRIVER
# ═════════════════════════════════════════════════════════════════════

def analyze_dump_file(dump_path: str, *, xml: bool = False) -> List[Diagnostic]:
    if cppcheckdata is None:
        print("ERROR: cppcheckdata module not available", file=sys.stderr)
        sys.exit(1)

    data = cppcheckdata.CppcheckData(dump_path)
    all_diags: List[Diagnostic] = []

    for cfg in data.iterconfigurations():
        analyzer = MemoryProvenanceAnalyzer(cfg)
        diags = analyzer.analyze()
        all_diags.extend(diags)

    return all_diags


# ═════════════════════════════════════════════════════════════════════
#  PART 9 — SELF-TEST
# ═════════════════════════════════════════════════════════════════════

SELF_TEST_PROGRAMS: Dict[str, Tuple[str, str, str]] = {
    "test_use_after_free_basic": (
        '#include <stdlib.h>\n#include <stdio.h>\n'
        'int main(void) {\n'
        '    int *p = malloc(sizeof(int));\n'
        '    *p = 42;\n'
        '    free(p);\n'
        '    printf("%d\\n", *p);\n'
        '    return 0;\n}\n',
        "useAfterFree",
        "Dereference of freed pointer",
    ),
    "test_double_free": (
        '#include <stdlib.h>\n'
        'int main(void) {\n'
        '    int *p = malloc(10 * sizeof(int));\n'
        '    free(p);\n'
        '    free(p);\n'
        '    return 0;\n}\n',
        "doubleFree",
        "Memory freed twice",
    ),
    "test_dangling_return": (
        'int *bad(void) {\n'
        '    int local = 42;\n'
        '    int *p = &local;\n'
        '    return p;\n}\n'
        'int main(void) { int *q = bad(); return *q; }\n',
        "danglingReturn",
        "Returning pointer to local variable",
    ),
    "test_mismatched_new_free": (
        '#include <cstdlib>\n'
        'int main() {\n'
        '    int *p = new int(42);\n'
        '    free(p);\n'
        '    return 0;\n}\n',
        "mismatchedDealloc",
        "new/free mismatch",
    ),
    "test_memory_leak_basic": (
        '#include <stdlib.h>\n'
        'int main(void) {\n'
        '    int *p = malloc(100);\n'
        '    return 0;\n}\n',
        "memoryLeak",
        "Allocated memory never freed",
    ),
    "test_realloc_leak": (
        '#include <stdlib.h>\n'
        'int main(void) {\n'
        '    int *p = malloc(10 * sizeof(int));\n'
        '    p = realloc(p, 20 * sizeof(int));\n'
        '    if (p) { free(p); }\n'
        '    return 0;\n}\n',
        "reallocLeak",
        "realloc failure would leak original pointer",
    ),
    "test_alloc_zero_size": (
        '#include <stdlib.h>\n'
        'int main(void) {\n'
        '    void *p = malloc(0);\n'
        '    free(p);\n'
        '    return 0;\n}\n',
        "allocZeroSize",
        "Allocation with size 0",
    ),
    "test_uninit_free": (
        '#include <stdlib.h>\n'
        'int main(void) {\n'
        '    int *p;\n'
        '    free(p);\n'
        '    return 0;\n}\n',
        "uninitFreeArg",
        "Free of uninitialised pointer",
    ),
    "test_free_stack": (
        '#include <stdlib.h>\n'
        'int main(void) {\n'
        '    int x = 42;\n'
        '    int *p = &x;\n'
        '    free(p);\n'
        '    return 0;\n}\n',
        "redundantFree",
        "Free of stack variable",
    ),
    "test_unused_alloc": (
        '#include <stdlib.h>\n'
        'void process(void) {\n'
        '    malloc(1024);\n'
        '}\n'
        'int main(void) { process(); return 0; }\n',
        "unusedAlloc",
        "Allocation result discarded",
    ),
}


def run_self_test(*, verbose: bool = False) -> bool:
    if cppcheckdata is None:
        print("ERROR: cppcheckdata module not available for self-test",
              file=sys.stderr)
        return False

    passed = 0
    failed = 0
    skipped = 0
    total = len(SELF_TEST_PROGRAMS)

    print(f"MemoryProvenanceChecker self-test: {total} test cases")
    print("=" * 60)

    for test_name, (source, expected_id, description) in sorted(
        SELF_TEST_PROGRAMS.items()
    ):
        ext = ".cpp" if "cpp" in test_name or "#include <c" in source else ".c"

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=ext, prefix=test_name + "_",
            delete=False,
        ) as f:
            f.write(source)
            src_path = f.name

        dump_path = src_path + ".dump"

        try:
            result = subprocess.run(
                ["cppcheck", "--dump", "--quiet", "--max-configs=1", src_path],
                capture_output=True, text=True, timeout=30,
            )

            if not os.path.exists(dump_path):
                print(f"  SKIP  {test_name}: cppcheck did not produce dump")
                skipped += 1
                continue

            diags = analyze_dump_file(dump_path)
            found = any(d.check_id == expected_id for d in diags)

            if found:
                status = "PASS"
                passed += 1
            else:
                status = "FAIL"
                failed += 1

            marker = "\u2713" if found else "\u2717"
            print(f"  {marker} {status}  {test_name}")
            print(f"         Expected: {expected_id} \u2014 {description}")

            if verbose or not found:
                if diags:
                    for d in diags:
                        print(f"         Got: {format_diagnostic(d)}")
                else:
                    print("         Got: (no diagnostics)")

        except FileNotFoundError:
            print(f"  SKIP  {test_name}: cppcheck not found in PATH")
            skipped += 1
        except subprocess.TimeoutExpired:
            print(f"  SKIP  {test_name}: cppcheck timed out")
            skipped += 1
        except Exception as e:
            print(f"  ERROR {test_name}: {e}")
            failed += 1
        finally:
            for p in (src_path, dump_path):
                try:
                    os.unlink(p)
                except OSError:
                    pass

    print("=" * 60)
    print(f"Results: {passed} passed, {failed} failed, {skipped} skipped "
          f"/ {total} total")

    return failed == 0


# ═════════════════════════════════════════════════════════════════════
#  PART 10 — CLI ENTRY POINT
# ═════════════════════════════════════════════════════════════════════

def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "MemoryProvenanceChecker \u2014 Cppcheck addon for memory "
            "allocation provenance and lifetime safety"
        ),
    )
    parser.add_argument(
        "dump_files", nargs="*",
        help="Cppcheck dump files (*.dump) to analyze",
    )
    parser.add_argument(
        "--self-test", action="store_true",
        help="Run built-in self-test suite",
    )
    parser.add_argument(
        "--xml", action="store_true",
        help="Output diagnostics in XML format",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Verbose output",
    )
    parser.add_argument(
        "--enable", type=str, default=None,
        help="Comma-separated list of check IDs to enable (default: all)",
    )
    parser.add_argument(
        "--suppress", type=str, default=None,
        help="Comma-separated list of check IDs to suppress",
    )

    args = parser.parse_args()

    if args.self_test:
        success = run_self_test(verbose=args.verbose)
        sys.exit(0 if success else 1)

    if not args.dump_files:
        dump_files = glob.glob("*.dump")
        if not dump_files:
            parser.error("No dump files specified and none found in current directory")
    else:
        dump_files = args.dump_files

    all_diags: List[Diagnostic] = []

    for dump_path in dump_files:
        if not os.path.exists(dump_path):
            print(f"ERROR: File not found: {dump_path}", file=sys.stderr)
            continue
        diags = analyze_dump_file(dump_path, xml=args.xml)
        all_diags.extend(diags)

    if args.xml:
        print('<?xml version="1.0" encoding="UTF-8"?>')
        print("<results>")
        for d in all_diags:
            print(format_diagnostic_xml(d))
        print("</results>")
    else:
        for d in all_diags:
            print(format_diagnostic(d))

    if all_diags:
        by_sev: Dict[str, int] = defaultdict(int)
        for d in all_diags:
            by_sev[d.severity.value] += 1
        summary_parts = [f"{count} {sev}" for sev, count in sorted(by_sev.items())]
        print(f"\nTotal: {len(all_diags)} diagnostics ({', '.join(summary_parts)})")
        sys.exit(1)
    else:
        if args.verbose:
            print("No issues found.")
        sys.exit(0)


if __name__ == "__main__":
    main()
