#!/usr/bin/env python3
"""
Buflint.py — Memory-safety checker addon for Cppcheck
======================================================

Detects three classes of memory-safety defects in C / C++ code:

    1.  Use-After-Free  (UAF)   — dereferencing or reading a pointer after it
        has been passed to a deallocation function.
    2.  Double-Free     (DF)    — calling a deallocation function on a pointer
        that has already been deallocated without an intervening reallocation.
    3.  Buffer Overflow (BOF)   — writing to (or reading from) an array /
        heap buffer at an index that may exceed the allocated size.

The checker is designed to run as a Cppcheck addon:

    cppcheck --dump my_source.c
    python Buflint.py my_source.c.dump

It can also be executed on multiple dump files at once:

    python Buflint.py src/*.c.dump

Architecture
------------
The three checkers share a common two-phase pipeline:

    Phase 1 — *Collection*
        Walk the token list and record "events" (allocations, deallocations,
        dereferences, array subscripts).  Events are associated with the
        variable they operate on (by ``varId``).

    Phase 2 — *Analysis*
        For every pair of events that could constitute a defect, query the
        ``cppcheckdata_shims`` CFG / data-flow / abstract-interpretation
        infrastructure to determine whether the defect is *feasible* (i.e.
        there exists at least one intra-procedural path on which the bad
        event sequence occurs without an intervening "fix" event).

This separation keeps the token walk O(n) and concentrates the more
expensive graph queries on a small number of candidate pairs.

Dependencies
------------
- ``cppcheckdata``          (ships with Cppcheck, also vendored in deps/)
- ``cppcheckdata_shims``    (the companion analysis library)

License: Same as the parent project.
"""

from __future__ import annotations

import json
import sys
import os
import re
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import (
    Any,
    Dict,
    FrozenSet,
    Iterable,
    List,
    Optional,
    Set,
    Sequence,
    Tuple,
    Union,
)

# ---------------------------------------------------------------------------
# Path bootstrap — make sure we can import both cppcheckdata and the shims
# regardless of how the user invoked us.
# ---------------------------------------------------------------------------
_HERE = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.abspath(os.path.join(_HERE, os.pardir, os.pardir))
for _candidate in (_PROJECT_ROOT, os.path.join(_PROJECT_ROOT, "deps")):
    if _candidate not in sys.path:
        sys.path.insert(0, _candidate)

import cppcheckdata                                     # Cppcheck dump parser

# -- cppcheckdata_shims imports --------------------------------------------
from cppcheckdata_shims.ctrlflow_graph import (
    CFGBuilder,
    BasicBlock,
    CFGEdge,
    EdgeKind,
)
from cppcheckdata_shims.ctrlflow_analysis import (
    DominatorTree,
    compute_dominators,
    compute_post_dominators,
    reachable,
    all_paths_pass_through,
)
from cppcheckdata_shims.dataflow_engine import (
    DataFlowEngine,
    DataFlowDirection,
    DataFlowResult,
)
from cppcheckdata_shims.dataflow_analysis import (
    ReachingDefinitions,
    LiveVariables,
)
from cppcheckdata_shims.abstract_domains import (
    FlatLattice,
    LatticeElement,
    SignDomain,
    IntervalDomain,
    Interval,
    NullnessLattice,
    NullnessValue,
)
from cppcheckdata_shims.abstract_interp import (
    AbstractInterpreter,
    TransferFunction,
    AbstractState,
)
from cppcheckdata_shims.checkers import (
    CheckerBase,
    Severity,
    Finding,
    CheckerRegistry,
)

# ═══════════════════════════════════════════════════════════════════════════
#  CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════

ADDON_NAME = "buflint"

# Functions that allocate heap memory and return a pointer.
ALLOC_FUNCTIONS: FrozenSet[str] = frozenset({
    "malloc", "calloc", "realloc", "strdup", "strndup",
    "aligned_alloc", "pvalloc", "valloc", "memalign",
    "reallocarray",
    # C++ (when the addon inspects C++ dumps)
    "operator new", "operator new[]",
})

# Functions that deallocate heap memory.
DEALLOC_FUNCTIONS: FrozenSet[str] = frozenset({
    "free", "cfree",
    "operator delete", "operator delete[]",
})

# Functions that *reallocate* — the old pointer becomes invalid on success.
REALLOC_FUNCTIONS: FrozenSet[str] = frozenset({
    "realloc", "reallocarray",
})

# Dangerous copy / fill functions whose buffer-size argument we check.
# Mapping: function-name  →  (dest-arg-index, size-arg-index, elem-size)
# ``elem_size`` is None when the size argument is already in bytes.
BUFWRITE_FUNCTIONS: Dict[str, Tuple[int, int, Optional[int]]] = {
    "memcpy":   (0, 2, None),
    "memmove":  (0, 2, None),
    "memset":   (0, 2, None),
    "strncpy":  (0, 2, None),
    "strncat":  (0, 2, None),
    "snprintf": (0, 1, None),
    "fread":    (0, 2, None),   # size*nmemb handled separately
    "fwrite":   (0, 2, None),
    "read":     (1, 2, None),   # POSIX read(fd, buf, count)
    "recv":     (1, 2, None),
    "recvfrom": (1, 2, None),
}

# ═══════════════════════════════════════════════════════════════════════════
#  EVENT MODEL
# ═══════════════════════════════════════════════════════════════════════════

class EventKind(Enum):
    """Discriminator for pointer / buffer events."""
    ALLOC       = auto()
    DEALLOC     = auto()
    REALLOC     = auto()
    DEREF       = auto()   # *p, p->m, p[i]
    ASSIGN      = auto()   # p = <expr>  (resets tracking)
    SUBSCRIPT   = auto()   # arr[idx]
    BUFWRITE    = auto()   # memcpy(dst, src, n) etc.
    NULL_CHECK  = auto()   # if (p == NULL) / if (!p)
    ADDR_TAKEN  = auto()   # &p — pointer escapes, suppress findings

@dataclass(frozen=True, slots=True)
class PtrEvent:
    """A single observable event on a tracked pointer variable."""
    kind: EventKind
    token: Any                     # cppcheckdata.Token
    var_id: int                    # varId of the pointer variable
    var_name: str                  # human-readable name
    scope_id: Optional[str]        # enclosing scope id
    func_name: Optional[str] = None  # name of called function (alloc/dealloc)
    extra: Any = None              # kind-specific payload

@dataclass(frozen=True, slots=True)
class BufEvent:
    """A single observable event on a buffer / array variable."""
    kind: EventKind
    token: Any                     # token at the subscript / call
    var_id: int
    var_name: str
    scope_id: Optional[str]
    alloc_size_tok: Optional[Any] = None   # token representing size expr
    index_tok: Optional[Any] = None        # token representing index expr
    callee: Optional[str] = None           # e.g. "memcpy"
    size_arg_tok: Optional[Any] = None     # token for the byte-count arg

# ═══════════════════════════════════════════════════════════════════════════
#  POINTER-STATE LATTICE  (for abstract interpretation)
# ═══════════════════════════════════════════════════════════════════════════

class PtrState(Enum):
    """
    Abstract state of a single pointer variable.

    Lattice Hasse diagram::

            ⊤  (unknown)
           / \\
        alloc  freed
           \\ /
            ⊥  (uninitialised)

    The ``join`` is the LUB in this four-element lattice.
    """
    BOTTOM      = "bottom"
    ALLOCATED   = "allocated"
    FREED       = "freed"
    TOP         = "top"


def _ptr_join(a: PtrState, b: PtrState) -> PtrState:
    """Least upper bound in the PtrState lattice."""
    if a is b:
        return a
    if a is PtrState.BOTTOM:
        return b
    if b is PtrState.BOTTOM:
        return a
    # Any two distinct non-bottom elements join to TOP.
    return PtrState.TOP


def _ptr_leq(a: PtrState, b: PtrState) -> bool:
    """Partial-order test:  a ⊑ b."""
    if a is PtrState.BOTTOM or b is PtrState.TOP:
        return True
    return a is b

# ═══════════════════════════════════════════════════════════════════════════
#  HELPER UTILITIES
# ═══════════════════════════════════════════════════════════════════════════

def _tok_loc(token) -> str:
    """Format a token's location as ``file:line:col``."""
    f = getattr(token, "file", "<unknown>")
    ln = getattr(token, "linenr", 0)
    col = getattr(token, "column", 0)
    return f"{f}:{ln}:{col}"


def _get_function_name(tok) -> Optional[str]:
    """
    If *tok* sits at a function-call name position (``tok ( ... )``),
    return the fully-qualified function name; otherwise ``None``.
    """
    name, _args = cppcheckdata.get_function_call_name_args(tok)
    return name


def _get_arguments(tok) -> List:
    """Return the argument tokens of a function call at *tok*."""
    _name, args = cppcheckdata.get_function_call_name_args(tok)
    return args if args else []


def _var_name_of(tok) -> str:
    """Best-effort human-readable name for the variable at *tok*."""
    if tok.variable and hasattr(tok.variable, "nameToken"):
        nt = tok.variable.nameToken
        if nt:
            return nt.str
    return tok.str


def _enclosing_function_scope(tok):
    """Walk up the scope chain and return the first Function scope, or None."""
    scope = tok.scope
    while scope:
        if scope.type == "Function":
            return scope
        scope = scope.nestedIn
    return None


def _enclosing_function_name(tok) -> Optional[str]:
    scope = _enclosing_function_scope(tok)
    if scope and scope.function and scope.function.name:
        return scope.function.name
    if scope and scope.className:
        return scope.className
    return None


def _known_int_value(tok) -> Optional[int]:
    """Return the known integer value of *tok*, or ``None``."""
    if tok is None:
        return None
    return tok.getKnownIntValue()


def _is_pointer_type(tok) -> bool:
    """Return ``True`` if *tok* has a pointer ``ValueType``."""
    vt = tok.valueType
    if vt and vt.pointer and vt.pointer >= 1:
        return True
    return False


def _is_array_variable(tok) -> bool:
    """Return ``True`` if *tok*'s variable is declared as an array."""
    v = tok.variable
    if v is None:
        return False
    if hasattr(v, "isArray") and v.isArray:
        return True
    return False


def _array_dimension(tok) -> Optional[int]:
    """
    If the variable at *tok* is a fixed-size array, return its first
    dimension as an integer.  Otherwise ``None``.
    """
    v = tok.variable
    if v is None:
        return None
    if hasattr(v, "dimensions") and v.dimensions:
        for dim in v.dimensions:
            if hasattr(dim, "known") and dim.known:
                return int(dim.known)
            # Some Cppcheck versions expose it differently.
            if isinstance(dim, dict) and "known" in dim:
                return int(dim["known"])
            if isinstance(dim, (int, float)):
                return int(dim)
    return None


def _allocation_byte_count(alloc_tok) -> Optional[int]:
    """
    Try to determine the byte count of an allocation from its argument.
    E.g. for ``malloc(128)`` return 128.
    Only succeeds if the argument has a known integer value.
    """
    args = _get_arguments(alloc_tok)
    if not args:
        return None
    fn = _get_function_name(alloc_tok)
    if fn in ("calloc",):
        # calloc(nmemb, size) → nmemb * size
        if len(args) >= 2:
            n = _known_int_value(args[0])
            s = _known_int_value(args[1])
            if n is not None and s is not None:
                return n * s
        return None
    # malloc(size), aligned_alloc(align, size), etc.
    if args:
        return _known_int_value(args[0])
    return None

# ═══════════════════════════════════════════════════════════════════════════
#  PHASE 1 — EVENT COLLECTION
# ═══════════════════════════════════════════════════════════════════════════

class EventCollector:
    """
    Walk a single Cppcheck configuration's token list and produce ordered
    sequences of ``PtrEvent`` and ``BufEvent`` per variable.
    """

    def __init__(self) -> None:
        # varId → list of PtrEvent, in token-list order
        self.ptr_events: Dict[int, List[PtrEvent]] = {}
        # varId → list of BufEvent
        self.buf_events: Dict[int, List[BufEvent]] = {}
        # varId → known allocation size (bytes), if determinable
        self.alloc_sizes: Dict[int, Optional[int]] = {}
        # varId → set of scope-ids where the pointer escapes (&p)
        self.escaped: Dict[int, Set[str]] = {}

    # -- public API --------------------------------------------------------

    def collect(self, cfg) -> None:
        """Iterate over all tokens in *cfg* and record events."""
        tok = cfg.tokenlist
        if isinstance(tok, list):
            iterator = iter(tok)
        else:
            # cfg.tokenlist is the first Token; walk via .next
            iterator = self._walk_tokens(tok)

        for token in iterator:
            self._visit_token(token)

    # -- internals ---------------------------------------------------------

    @staticmethod
    def _walk_tokens(first_token):
        """Yield tokens from a linked-list head."""
        t = first_token
        while t:
            yield t
            t = t.next

    def _record_ptr(self, ev: PtrEvent) -> None:
        self.ptr_events.setdefault(ev.var_id, []).append(ev)

    def _record_buf(self, ev: BufEvent) -> None:
        self.buf_events.setdefault(ev.var_id, []).append(ev)

    def _visit_token(self, tok) -> None:
        # --- 1. Function call: alloc / dealloc / realloc / bufwrite -------
        fn_name = _get_function_name(tok)
        if fn_name:
            self._visit_call(tok, fn_name)
            return

        # --- 2. Dereference: unary *, ->, or [] on a pointer var ----------
        if tok.isOp and tok.str == "*" and tok.astOperand1 and not tok.astOperand2:
            operand = tok.astOperand1
            if operand.varId:
                self._record_ptr(PtrEvent(
                    kind=EventKind.DEREF,
                    token=tok,
                    var_id=operand.varId,
                    var_name=_var_name_of(operand),
                    scope_id=_sid(tok),
                ))

        if tok.isOp and tok.str == "->" and tok.astOperand1:
            operand = tok.astOperand1
            if operand.varId:
                self._record_ptr(PtrEvent(
                    kind=EventKind.DEREF,
                    token=tok,
                    var_id=operand.varId,
                    var_name=_var_name_of(operand),
                    scope_id=_sid(tok),
                ))

        # --- 3. Array subscript a[i] — for buffer-overflow checks ---------
        if tok.isOp and tok.str == "[" and tok.astOperand1 and tok.astOperand2:
            arr = tok.astOperand1
            idx = tok.astOperand2
            if arr.varId:
                # Also record as DEREF for use-after-free
                if _is_pointer_type(arr):
                    self._record_ptr(PtrEvent(
                        kind=EventKind.DEREF,
                        token=tok,
                        var_id=arr.varId,
                        var_name=_var_name_of(arr),
                        scope_id=_sid(tok),
                    ))
                self._record_buf(BufEvent(
                    kind=EventKind.SUBSCRIPT,
                    token=tok,
                    var_id=arr.varId,
                    var_name=_var_name_of(arr),
                    scope_id=_sid(tok),
                    index_tok=idx,
                ))

        # --- 4. Assignment  p = ... — resets pointer tracking -------------
        if tok.isAssignmentOp and tok.str == "=" and tok.astOperand1:
            lhs = tok.astOperand1
            if lhs.varId and _is_pointer_type(lhs):
                # Is the RHS itself an alloc?
                rhs = tok.astOperand2
                rhs_fn = _get_function_name(rhs) if rhs else None
                if rhs_fn and rhs_fn in ALLOC_FUNCTIONS:
                    sz = _allocation_byte_count(rhs)
                    self._record_ptr(PtrEvent(
                        kind=EventKind.ALLOC,
                        token=tok,
                        var_id=lhs.varId,
                        var_name=_var_name_of(lhs),
                        scope_id=_sid(tok),
                        func_name=rhs_fn,
                        extra=sz,
                    ))
                    self.alloc_sizes[lhs.varId] = sz
                elif rhs_fn and rhs_fn in REALLOC_FUNCTIONS:
                    self._record_ptr(PtrEvent(
                        kind=EventKind.REALLOC,
                        token=tok,
                        var_id=lhs.varId,
                        var_name=_var_name_of(lhs),
                        scope_id=_sid(tok),
                        func_name=rhs_fn,
                    ))
                else:
                    self._record_ptr(PtrEvent(
                        kind=EventKind.ASSIGN,
                        token=tok,
                        var_id=lhs.varId,
                        var_name=_var_name_of(lhs),
                        scope_id=_sid(tok),
                    ))

        # --- 5. Address-of  &p — pointer escapes -------------------------
        if tok.isOp and tok.str == "&" and tok.astOperand1 and not tok.astOperand2:
            operand = tok.astOperand1
            if operand.varId:
                self.escaped.setdefault(operand.varId, set()).add(_sid(tok))
                self._record_ptr(PtrEvent(
                    kind=EventKind.ADDR_TAKEN,
                    token=tok,
                    var_id=operand.varId,
                    var_name=_var_name_of(operand),
                    scope_id=_sid(tok),
                ))

    def _visit_call(self, tok, fn_name: str) -> None:
        """Handle a function-call token."""
        args = _get_arguments(tok)

        # -- Deallocation --------------------------------------------------
        if fn_name in DEALLOC_FUNCTIONS:
            if args and args[0].varId:
                arg = args[0]
                self._record_ptr(PtrEvent(
                    kind=EventKind.DEALLOC,
                    token=tok,
                    var_id=arg.varId,
                    var_name=_var_name_of(arg),
                    scope_id=_sid(tok),
                    func_name=fn_name,
                ))
            return

        # -- Allocation (direct call, not via assignment) ------------------
        #    e.g.  foo(malloc(16))  — we don't track these as they
        #    produce a temporary.  Only record when assigned (see above).

        # -- Realloc: first arg becomes invalid ----------------------------
        if fn_name in REALLOC_FUNCTIONS:
            if args and args[0].varId:
                arg = args[0]
                self._record_ptr(PtrEvent(
                    kind=EventKind.REALLOC,
                    token=tok,
                    var_id=arg.varId,
                    var_name=_var_name_of(arg),
                    scope_id=_sid(tok),
                    func_name=fn_name,
                ))
            return

        # -- Buffer-write functions ----------------------------------------
        if fn_name in BUFWRITE_FUNCTIONS:
            dest_idx, size_idx, _elem = BUFWRITE_FUNCTIONS[fn_name]
            if len(args) > max(dest_idx, size_idx):
                dest_tok = args[dest_idx]
                size_tok = args[size_idx]
                if dest_tok.varId:
                    self._record_buf(BufEvent(
                        kind=EventKind.BUFWRITE,
                        token=tok,
                        var_id=dest_tok.varId,
                        var_name=_var_name_of(dest_tok),
                        scope_id=_sid(tok),
                        callee=fn_name,
                        size_arg_tok=size_tok,
                    ))
                    # Also record as a DEREF for UAF purposes
                    if _is_pointer_type(dest_tok):
                        self._record_ptr(PtrEvent(
                            kind=EventKind.DEREF,
                            token=tok,
                            var_id=dest_tok.varId,
                            var_name=_var_name_of(dest_tok),
                            scope_id=_sid(tok),
                        ))


def _sid(tok) -> Optional[str]:
    """Return the scope-id string for a token, or None."""
    if tok.scope:
        return tok.scope.Id if hasattr(tok.scope, "Id") else str(id(tok.scope))
    return tok.scopeId

# ═══════════════════════════════════════════════════════════════════════════
#  PHASE 2a — USE-AFTER-FREE CHECKER
# ═══════════════════════════════════════════════════════════════════════════

class UseAfterFreeChecker(CheckerBase):
    """
    For every (DEALLOC, DEREF) pair on the same ``varId``, query the CFG
    to determine whether the deref is reachable from the dealloc without
    an intervening re-assignment or re-allocation.

    Complexity per function: O(E · D) where E = #events and D = cost of a
    single reachability query (typically O(|V| + |E|) in the CFG).
    """

    name = "buflint-use-after-free"
    description = "Detects dereferences of freed pointers"

    def __init__(self) -> None:
        super().__init__()
        self.findings: List[Finding] = []

    def check(
        self,
        ptr_events: Dict[int, List[PtrEvent]],
        escaped: Dict[int, Set[str]],
        cfg,
        cfg_cache: Dict[str, Any],
    ) -> List[Finding]:
        self.findings.clear()

        for var_id, events in ptr_events.items():
            # Skip variables whose address is taken — they may be freed
            # through an alias we cannot track intraprocedurally.
            if var_id in escaped and escaped[var_id]:
                continue

            deallocs = [e for e in events if e.kind is EventKind.DEALLOC]
            derefs   = [e for e in events if e.kind is EventKind.DEREF]

            if not deallocs or not derefs:
                continue

            for dealloc in deallocs:
                for deref in derefs:
                    if self._is_uaf(dealloc, deref, events, cfg, cfg_cache):
                        self.findings.append(Finding(
                            severity=Severity.ERROR,
                            error_id="useAfterFree",
                            message=(
                                f"Use after free: '{deref.var_name}' was freed "
                                f"by {dealloc.func_name}() at "
                                f"{_tok_loc(dealloc.token)}"
                            ),
                            token=deref.token,
                            addon=ADDON_NAME,
                            extra_locations=[dealloc.token],
                        ))

        return self.findings

    # -- internal ----------------------------------------------------------

    @staticmethod
    def _is_uaf(
        dealloc: PtrEvent,
        deref: PtrEvent,
        all_events: List[PtrEvent],
        cfg,
        cfg_cache: Dict[str, Any],
    ) -> bool:
        """
        Return ``True`` if the deref is reachable from the dealloc without
        any intervening re-assignment / re-allocation of the same variable.
        """
        # Quick ordering heuristic: dealloc must appear *before* deref in
        # the token list (by line number, then column).
        if (dealloc.token.linenr, dealloc.token.column) >= \
           (deref.token.linenr, deref.token.column):
            return False

        # Build / retrieve the CFG for the enclosing function.
        func_scope = _enclosing_function_scope(dealloc.token)
        if func_scope is None:
            return False
        scope_key = func_scope.Id if hasattr(func_scope, "Id") else str(id(func_scope))

        if scope_key not in cfg_cache:
            try:
                builder = CFGBuilder()
                cfg_cache[scope_key] = builder.build(func_scope)
            except Exception:
                # If CFG construction fails (e.g. very complex function),
                # fall back to the conservative token-order heuristic.
                return _token_order_heuristic(dealloc, deref, all_events)

        func_cfg = cfg_cache[scope_key]

        # Locate the basic blocks containing the two tokens.
        bb_dealloc = _find_block(func_cfg, dealloc.token)
        bb_deref   = _find_block(func_cfg, deref.token)
        if bb_dealloc is None or bb_deref is None:
            return _token_order_heuristic(dealloc, deref, all_events)

        # Check reachability.
        if not reachable(func_cfg, bb_dealloc, bb_deref):
            return False

        # Check that no intervening event "kills" the freed state.
        # Kill events: ALLOC, REALLOC, ASSIGN on the same varId.
        kill_kinds = {EventKind.ALLOC, EventKind.REALLOC, EventKind.ASSIGN}
        kills = [
            e for e in all_events
            if e.kind in kill_kinds
            and (dealloc.token.linenr, dealloc.token.column)
                < (e.token.linenr, e.token.column)
                < (deref.token.linenr, deref.token.column)
        ]

        if not kills:
            return True   # No kill between dealloc and deref.

        # If kills exist, check whether *all* paths from dealloc to deref
        # pass through at least one kill.
        for kill_ev in kills:
            bb_kill = _find_block(func_cfg, kill_ev.token)
            if bb_kill is not None:
                if all_paths_pass_through(func_cfg, bb_dealloc, bb_deref, bb_kill):
                    return False   # Every path is "healed" by this kill.

        # There exists at least one path that bypasses all kills.
        return True

# ═══════════════════════════════════════════════════════════════════════════
#  PHASE 2b — DOUBLE-FREE CHECKER
# ═══════════════════════════════════════════════════════════════════════════

class DoubleFreeChecker(CheckerBase):
    """
    For every pair of DEALLOC events on the same ``varId``, check
    whether the second dealloc is reachable from the first without an
    intervening re-allocation or re-assignment.
    """

    name = "buflint-double-free"
    description = "Detects double deallocation of the same pointer"

    def __init__(self) -> None:
        super().__init__()
        self.findings: List[Finding] = []

    def check(
        self,
        ptr_events: Dict[int, List[PtrEvent]],
        escaped: Dict[int, Set[str]],
        cfg,
        cfg_cache: Dict[str, Any],
    ) -> List[Finding]:
        self.findings.clear()

        for var_id, events in ptr_events.items():
            if var_id in escaped and escaped[var_id]:
                continue

            deallocs = [e for e in events if e.kind is EventKind.DEALLOC]
            if len(deallocs) < 2:
                continue

            # Check every ordered pair.
            for i, first in enumerate(deallocs):
                for second in deallocs[i + 1:]:
                    if self._is_double_free(first, second, events, cfg, cfg_cache):
                        self.findings.append(Finding(
                            severity=Severity.ERROR,
                            error_id="doubleFree",
                            message=(
                                f"Double free of '{first.var_name}': first freed "
                                f"at {_tok_loc(first.token)}, freed again at "
                                f"{_tok_loc(second.token)}"
                            ),
                            token=second.token,
                            addon=ADDON_NAME,
                            extra_locations=[first.token],
                        ))

        return self.findings

    @staticmethod
    def _is_double_free(
        first: PtrEvent,
        second: PtrEvent,
        all_events: List[PtrEvent],
        cfg,
        cfg_cache: Dict[str, Any],
    ) -> bool:
        if (first.token.linenr, first.token.column) >= \
           (second.token.linenr, second.token.column):
            return False

        func_scope = _enclosing_function_scope(first.token)
        if func_scope is None:
            return False
        scope_key = func_scope.Id if hasattr(func_scope, "Id") else str(id(func_scope))

        if scope_key not in cfg_cache:
            try:
                builder = CFGBuilder()
                cfg_cache[scope_key] = builder.build(func_scope)
            except Exception:
                return _token_order_heuristic(first, second, all_events)

        func_cfg = cfg_cache[scope_key]

        bb_first  = _find_block(func_cfg, first.token)
        bb_second = _find_block(func_cfg, second.token)
        if bb_first is None or bb_second is None:
            return _token_order_heuristic(first, second, all_events)

        if not reachable(func_cfg, bb_first, bb_second):
            return False

        kill_kinds = {EventKind.ALLOC, EventKind.REALLOC, EventKind.ASSIGN}
        kills = [
            e for e in all_events
            if e.kind in kill_kinds
            and (first.token.linenr, first.token.column)
                < (e.token.linenr, e.token.column)
                < (second.token.linenr, second.token.column)
        ]

        if not kills:
            return True

        for kill_ev in kills:
            bb_kill = _find_block(func_cfg, kill_ev.token)
            if bb_kill is not None:
                if all_paths_pass_through(func_cfg, bb_first, bb_second, bb_kill):
                    return False

        return True

# ═══════════════════════════════════════════════════════════════════════════
#  PHASE 2c — BUFFER OVERFLOW CHECKER
# ═══════════════════════════════════════════════════════════════════════════

class BufferOverflowChecker(CheckerBase):
    """
    Two sub-checks:

    1. **Static array subscript** — ``arr[idx]`` where ``arr`` has a known
       fixed size and ``idx`` has a known (or bounded) value outside
       ``[0, size)``.

    2. **Heap buffer write** — ``memcpy(dst, src, n)`` where ``dst`` was
       allocated with a known byte count and ``n`` exceeds it.

    When exact values are unavailable, the checker falls back to interval
    abstract interpretation to obtain bounds on the index / size.
    """

    name = "buflint-buffer-overflow"
    description = "Detects out-of-bounds buffer accesses"

    def __init__(self) -> None:
        super().__init__()
        self.findings: List[Finding] = []

    def check(
        self,
        buf_events: Dict[int, List[BufEvent]],
        alloc_sizes: Dict[int, Optional[int]],
        cfg,
        cfg_cache: Dict[str, Any],
    ) -> List[Finding]:
        self.findings.clear()

        for var_id, events in buf_events.items():
            for ev in events:
                if ev.kind is EventKind.SUBSCRIPT:
                    self._check_subscript(ev, alloc_sizes.get(var_id))
                elif ev.kind is EventKind.BUFWRITE:
                    self._check_bufwrite(ev, alloc_sizes.get(var_id))

        return self.findings

    # -- subscript: arr[idx] -----------------------------------------------

    def _check_subscript(
        self,
        ev: BufEvent,
        heap_size: Optional[int],
    ) -> None:
        # Determine the buffer capacity.
        capacity = _array_dimension(ev.token.astOperand1) if ev.token.astOperand1 else None
        if capacity is None and heap_size is not None:
            # Heap buffer: capacity in *elements* = heap_size / sizeof(element)
            elem_size = self._element_byte_size(ev.token.astOperand1)
            if elem_size and elem_size > 0:
                capacity = heap_size // elem_size
            else:
                capacity = heap_size  # assume byte array

        if capacity is None:
            return  # Cannot determine size — give up.

        # Determine the index value.
        idx_tok = ev.index_tok
        if idx_tok is None:
            idx_tok = ev.token.astOperand2

        if idx_tok is None:
            return

        # -- Exact known value ---------------------------------------------
        idx_val = _known_int_value(idx_tok)
        if idx_val is not None:
            if idx_val < 0 or idx_val >= capacity:
                self.findings.append(Finding(
                    severity=Severity.ERROR,
                    error_id="bufferOverflow",
                    message=(
                        f"Out-of-bounds access: '{ev.var_name}[{idx_val}]' — "
                        f"valid range is [0, {capacity - 1}]"
                    ),
                    token=ev.token,
                    addon=ADDON_NAME,
                ))
            return

        # -- Interval fallback ---------------------------------------------
        lo, hi = self._interval_bounds(idx_tok)
        if lo is not None and hi is not None:
            if lo < 0 or hi >= capacity:
                self.findings.append(Finding(
                    severity=Severity.WARNING,
                    error_id="possibleBufferOverflow",
                    message=(
                        f"Possible out-of-bounds access: '{ev.var_name}' "
                        f"indexed with value in [{lo}, {hi}], "
                        f"buffer capacity is {capacity}"
                    ),
                    token=ev.token,
                    addon=ADDON_NAME,
                ))

    # -- bufwrite: memcpy(dst, src, n) -------------------------------------

    def _check_bufwrite(
        self,
        ev: BufEvent,
        heap_size: Optional[int],
    ) -> None:
        capacity = None
        # Try array dimension first.
        arr_tok = ev.token  # token is at the call site
        # We need the destination token, which is args[dest_idx].
        dest_tok_id = ev.var_id
        if ev.token.astOperand1 and ev.token.astOperand1.varId == dest_tok_id:
            capacity = _array_dimension(ev.token.astOperand1)

        if capacity is None and heap_size is not None:
            capacity = heap_size

        if capacity is None:
            return

        size_tok = ev.size_arg_tok
        if size_tok is None:
            return

        size_val = _known_int_value(size_tok)
        if size_val is not None:
            if size_val > capacity:
                self.findings.append(Finding(
                    severity=Severity.ERROR,
                    error_id="bufferOverflowWrite",
                    message=(
                        f"Buffer overflow: {ev.callee}() writes {size_val} bytes "
                        f"into '{ev.var_name}' which has capacity {capacity} bytes"
                    ),
                    token=ev.token,
                    addon=ADDON_NAME,
                ))
            return

        lo, hi = self._interval_bounds(size_tok)
        if lo is not None and hi is not None and hi > capacity:
            self.findings.append(Finding(
                severity=Severity.WARNING,
                error_id="possibleBufferOverflowWrite",
                message=(
                    f"Possible buffer overflow: {ev.callee}() may write up "
                    f"to {hi} bytes into '{ev.var_name}' "
                    f"(capacity {capacity} bytes)"
                ),
                token=ev.token,
                addon=ADDON_NAME,
            ))

    # -- helpers -----------------------------------------------------------

    @staticmethod
    def _element_byte_size(tok) -> Optional[int]:
        """Heuristic for the byte size of one array element."""
        if tok is None:
            return None
        vt = tok.valueType
        if vt is None:
            return None
        TYPE_SIZES = {
            "char": 1, "bool": 1,
            "short": 2, "wchar_t": 2,
            "int": 4, "long": 4, "float": 4,
            "long long": 8, "double": 8,
            "long double": 16,
        }
        return TYPE_SIZES.get(vt.type)

    @staticmethod
    def _interval_bounds(tok) -> Tuple[Optional[int], Optional[int]]:
        """
        Attempt to extract an interval [lo, hi] from Cppcheck's value list.

        Cppcheck attaches ``values`` to tokens; each ``Value`` may carry
        ``intvalue``, and the set of all non-impossible values gives an
        approximation of the range.

        If no values are available, return (None, None).
        """
        if tok is None or not tok.values:
            return (None, None)

        int_vals: List[int] = []
        for v in tok.values:
            if hasattr(v, "intvalue") and v.intvalue is not None:
                int_vals.append(v.intvalue)

        if not int_vals:
            return (None, None)

        return (min(int_vals), max(int_vals))

# ═══════════════════════════════════════════════════════════════════════════
#  CFG HELPER — map tokens to basic blocks
# ═══════════════════════════════════════════════════════════════════════════

def _find_block(func_cfg, token) -> Optional[BasicBlock]:
    """
    Return the :class:`BasicBlock` that contains *token*, or ``None``.

    The lookup is by line/column range: each basic block tracks the first
    and last token it covers.
    """
    if func_cfg is None:
        return None

    blocks: Iterable[BasicBlock] = getattr(func_cfg, "blocks", [])
    if not blocks:
        blocks = getattr(func_cfg, "basic_blocks", [])

    tok_line = token.linenr
    tok_col  = token.column

    for bb in blocks:
        # Primary strategy: the block stores a list of tokens.
        bb_tokens = getattr(bb, "tokens", None)
        if bb_tokens:
            for bt in bb_tokens:
                if getattr(bt, "Id", None) == getattr(token, "Id", object()):
                    return bb
                if (getattr(bt, "linenr", -1) == tok_line and
                        getattr(bt, "column", -1) == tok_col):
                    return bb

        # Fallback: line-range membership.
        start = getattr(bb, "start_line", None)
        end   = getattr(bb, "end_line", None)
        if start is not None and end is not None:
            if start <= tok_line <= end:
                return bb

    return None

# ═══════════════════════════════════════════════════════════════════════════
#  TOKEN-ORDER HEURISTIC FALLBACK
# ═══════════════════════════════════════════════════════════════════════════

def _token_order_heuristic(
    ev_a: PtrEvent,
    ev_b: PtrEvent,
    all_events: List[PtrEvent],
) -> bool:
    """
    Conservative intra-procedural heuristic when CFG is unavailable.

    Return ``True`` if *ev_a* appears before *ev_b* in the token stream
    and no ALLOC / REALLOC / ASSIGN event on the same variable appears
    between them.
    """
    a_pos = (ev_a.token.linenr, ev_a.token.column)
    b_pos = (ev_b.token.linenr, ev_b.token.column)
    if a_pos >= b_pos:
        return False

    kill_kinds = {EventKind.ALLOC, EventKind.REALLOC, EventKind.ASSIGN}
    for ev in all_events:
        if ev.kind in kill_kinds:
            ev_pos = (ev.token.linenr, ev.token.column)
            if a_pos < ev_pos < b_pos:
                return False
    return True

# ═══════════════════════════════════════════════════════════════════════════
#  ABSTRACT-INTERPRETATION–BASED DEEP PATH CHECK  (optional enhancement)
# ═══════════════════════════════════════════════════════════════════════════

class PtrStateTransfer(TransferFunction):
    """
    Transfer function for the :class:`PtrState` lattice.

    Maps each ``PtrEvent`` to a state transition on the tracked variable's
    abstract value.
    """

    def __init__(self, var_id: int, events_by_block: Dict[str, List[PtrEvent]]):
        self._var_id = var_id
        self._events_by_block = events_by_block

    def transfer(
        self,
        block: BasicBlock,
        in_state: Dict[int, PtrState],
    ) -> Dict[int, PtrState]:
        out = dict(in_state)
        block_key = getattr(block, "id", str(id(block)))

        for ev in self._events_by_block.get(block_key, []):
            if ev.var_id != self._var_id:
                continue
            if ev.kind is EventKind.ALLOC:
                out[self._var_id] = PtrState.ALLOCATED
            elif ev.kind is EventKind.DEALLOC:
                out[self._var_id] = PtrState.FREED
            elif ev.kind in (EventKind.REALLOC, EventKind.ASSIGN):
                out[self._var_id] = PtrState.ALLOCATED
            # DEREF / SUBSCRIPT do not change state.
        return out


def _run_ptr_abstract_interp(
    var_id: int,
    events: List[PtrEvent],
    func_cfg,
) -> Optional[Dict[str, Dict[int, PtrState]]]:
    """
    Run a forward abstract interpretation over *func_cfg* tracking the
    :class:`PtrState` of *var_id*.

    Returns a mapping  ``block-id → abstract state after block``, or
    ``None`` on failure.
    """
    if func_cfg is None:
        return None

    blocks = getattr(func_cfg, "blocks", []) or getattr(func_cfg, "basic_blocks", [])
    if not blocks:
        return None

    # Index events by block id.
    events_by_block: Dict[str, List[PtrEvent]] = {}
    for ev in events:
        bb = _find_block(func_cfg, ev.token)
        if bb is None:
            continue
        bb_key = getattr(bb, "id", str(id(bb)))
        events_by_block.setdefault(bb_key, []).append(ev)

    transfer = PtrStateTransfer(var_id, events_by_block)
    init_state: Dict[int, PtrState] = {var_id: PtrState.BOTTOM}

    try:
        interpreter = AbstractInterpreter(
            cfg=func_cfg,
            lattice_join=lambda a, b: {
                k: _ptr_join(a.get(k, PtrState.BOTTOM), b.get(k, PtrState.BOTTOM))
                for k in set(a) | set(b)
            },
            lattice_leq=lambda a, b: all(
                _ptr_leq(a.get(k, PtrState.BOTTOM), b.get(k, PtrState.BOTTOM))
                for k in set(a) | set(b)
            ),
            transfer=transfer.transfer,
            init_state=init_state,
            direction=DataFlowDirection.FORWARD,
        )
        result = interpreter.run()
        return result
    except Exception:
        return None

# ═══════════════════════════════════════════════════════════════════════════
#  REPORTING — emit Cppcheck-compatible diagnostics
# ═══════════════════════════════════════════════════════════════════════════

def _report_finding(finding: Finding) -> None:
    """Emit a single finding via :func:`cppcheckdata.reportError`."""
    tok = finding.token
    if tok is None:
        return
    cppcheckdata.reportError(
        tok,
        finding.severity.value if isinstance(finding.severity, Severity) else str(finding.severity),
        finding.message,
        finding.addon,
        finding.error_id,
    )


def _report_finding_json(finding: Finding) -> None:
    """Emit a finding as a JSON line (``--cli`` mode)."""
    tok = finding.token
    msg = {
        "file":     getattr(tok, "file", ""),
        "linenr":   getattr(tok, "linenr", 0),
        "column":   getattr(tok, "column", 0),
        "severity": finding.severity.value if isinstance(finding.severity, Severity) else str(finding.severity),
        "message":  finding.message,
        "addon":    finding.addon,
        "errorId":  finding.error_id,
        "extra":    "",
    }
    sys.stdout.write(json.dumps(msg) + "\n")

# ═══════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════

def analyse_configuration(cfg, *, verbose: bool = False) -> List[Finding]:
    """
    Run all three checkers on a single ``CppcheckData`` configuration.

    Parameters
    ----------
    cfg
        A configuration object from ``cppcheckdata.parsedump()``.
    verbose
        If ``True``, print progress information to stderr.

    Returns
    -------
    list[Finding]
        All findings across the three checkers.
    """
    collector = EventCollector()
    collector.collect(cfg)

    if verbose:
        n_ptr = sum(len(v) for v in collector.ptr_events.values())
        n_buf = sum(len(v) for v in collector.buf_events.values())
        sys.stderr.write(
            f"[buflint] Collected {n_ptr} pointer events, "
            f"{n_buf} buffer events across "
            f"{len(collector.ptr_events) + len(collector.buf_events)} variables\n"
        )

    cfg_cache: Dict[str, Any] = {}
    all_findings: List[Finding] = []

    # -- Use-After-Free ----------------------------------------------------
    uaf = UseAfterFreeChecker()
    all_findings.extend(
        uaf.check(collector.ptr_events, collector.escaped, cfg, cfg_cache)
    )

    # -- Double-Free -------------------------------------------------------
    df = DoubleFreeChecker()
    all_findings.extend(
        df.check(collector.ptr_events, collector.escaped, cfg, cfg_cache)
    )

    # -- Buffer Overflow ---------------------------------------------------
    bof = BufferOverflowChecker()
    all_findings.extend(
        bof.check(collector.buf_events, collector.alloc_sizes, cfg, cfg_cache)
    )

    if verbose:
        sys.stderr.write(
            f"[buflint] Found {len(all_findings)} potential defect(s)\n"
        )

    return all_findings


def main() -> int:
    """CLI entry point — compatible with Cppcheck's addon invocation."""
    import argparse

    parser = argparse.ArgumentParser(
        prog="Buflint",
        description="Memory-safety checker: UAF, Double-Free, Buffer Overflow",
    )
    parser.add_argument(
        "dumpfiles",
        nargs="+",
        metavar="FILE.dump",
        help="Cppcheck dump file(s) to analyse",
    )
    parser.add_argument(
        "--cli",
        action="store_true",
        default="--cli" in sys.argv,
        help="Emit findings as JSON lines (Cppcheck integration mode)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Print progress information to stderr",
    )
    parser.add_argument(
        "--max-findings",
        type=int,
        default=0,
        help="Stop after N findings (0 = unlimited)",
    )

    args = parser.parse_args(
        [a for a in sys.argv[1:] if a != "--cli"]  # argparse doesn't know --cli
    )

    total_findings = 0

    for dump_path in args.dumpfiles:
        if not dump_path.endswith(".dump"):
            sys.stderr.write(f"[buflint] Skipping non-dump file: {dump_path}\n")
            continue

        if not os.path.isfile(dump_path):
            sys.stderr.write(f"[buflint] File not found: {dump_path}\n")
            continue

        if args.verbose:
            sys.stderr.write(f"[buflint] Analysing {dump_path}\n")

        try:
            data = cppcheckdata.parsedump(dump_path)
        except Exception as exc:
            sys.stderr.write(f"[buflint] Failed to parse {dump_path}: {exc}\n")
            continue

        # Set up the global suppression list for this dump file.
        cppcheckdata.current_dumpfile_suppressions = (
            data.suppressions if hasattr(data, "suppressions") else []
        )

        for cfg_obj in data.configurations:
            findings = analyse_configuration(cfg_obj, verbose=args.verbose)

            for finding in findings:
                if args.cli or "--cli" in sys.argv:
                    _report_finding_json(finding)
                else:
                    _report_finding(finding)

                total_findings += 1
                if args.max_findings and total_findings >= args.max_findings:
                    if args.verbose:
                        sys.stderr.write(
                            f"[buflint] --max-findings={args.max_findings} "
                            f"reached, stopping.\n"
                        )
                    return 1 if total_findings else 0

    return 1 if total_findings else 0


if __name__ == "__main__":
    sys.exit(main())
