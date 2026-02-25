#!/usr/bin/env python3
"""
StackDepthAnalyzer.py
═════════════════════

A Cppcheck addon that estimates the maximum stack depth reachable from
every function, combining per-function frame-size computation with
call-graph analysis and recursion detection.

It uses the abstract execution substrate's IntervalDomain for sound
frame-size arithmetic and widening-based fixpoint for recursive chains.

Overview
--------
Phase 1 — Frame Size Estimation
    Walk every Function scope; sum declared-local sizes (from ValueType)
    plus alignment padding.  Flag alloca / VLA as unbounded.

Phase 2 — Call Graph Construction
    Build a directed graph  func → {callees}.  Annotate edges with the
    callee frame size.

Phase 3 — Maximum Stack Depth (DFS with memoisation)
    For acyclic chains: depth(f) = frame(f) + max(depth(callee) for callee in callees(f))
    For recursive SCCs: apply interval widening or report ∞.

Phase 4 — Reporting
    Warn when total depth exceeds a threshold; flag unbounded usage.

Usage
-----
    cppcheck --dump myfile.c
    python StackDepthAnalyzer.py [--verbose] [--threshold N] myfile.c.dump

Or via cppcheck's addon mechanism:
    cppcheck --addon=StackDepthAnalyzer myfile.c

Papers informing the design:
    - "Abstract Execution" (Larus, 1990) — trace-driven abstract
      interpretation with register/stack modelling.
    - "Static Cost Analysis for Upper Bounds" (Albert et al.) — cost
      recurrences for recursive call chains; our "cost" is stack bytes.
    - "Bound Analysis" (Sinn, Zuleger, Veith) — loop/recursion bound
      inference via lexicographic ranking functions.

License: MIT
"""

from __future__ import annotations

import sys
import os
import json
import math
import re
from enum import Enum, auto
from dataclasses import dataclass, field
from typing import (
    Any,
    Dict,
    FrozenSet,
    List,
    Optional,
    Set,
    Sequence,
    Tuple,
    Union,
)
from collections import defaultdict, deque

# ---------------------------------------------------------------------------
#  Import cppcheckdata (Cppcheck's dump-file parser)
# ---------------------------------------------------------------------------
try:
    import cppcheckdata
except ImportError:
    _parent = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if _parent not in sys.path:
        sys.path.insert(0, _parent)
    import cppcheckdata

# ---------------------------------------------------------------------------
#  Import the abstract execution substrate
# ---------------------------------------------------------------------------
try:
    from cppcheckdata_shims.abstract_domains import (
        IntervalDomain,
        FunctionDomain,
    )
    HAS_INTERVAL = True
except ImportError:
    HAS_INTERVAL = False
    IntervalDomain = None  # type: ignore
    FunctionDomain = None  # type: ignore

# ═══════════════════════════════════════════════════════════════════════════
#  PART 0 — CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════

ADDON_NAME = "StackDepthAnalyzer"
ADDON_VERSION = "1.0.0"

# Default stack budget (bytes).  Typical:
#   Linux user thread   : 8 MiB  = 8_388_608
#   Linux kernel stack  : 8 KiB  = 8_192  (or 16 KiB on 64-bit)
#   RTOS / embedded     : 1–4 KiB
DEFAULT_STACK_THRESHOLD: int = 8_388_608  # 8 MiB

# Warn if a single frame exceeds this
SINGLE_FRAME_WARN: int = 65_536  # 64 KiB

# Size of the return-address + saved-frame-pointer overhead per call
CALL_OVERHEAD: int = 16  # typical x86-64: 8 (ret addr) + 8 (rbp)

# Maximum recursion depth the analyzer itself will explore
MAX_ANALYSIS_DEPTH: int = 500

# Platform defaults (overridable via --pointer-size)
POINTER_SIZE: int = 8  # bytes
DEFAULT_ALIGNMENT: int = 16  # stack alignment

# ═══════════════════════════════════════════════════════════════════════════
#  PART 1 — TYPE SIZE ESTIMATION
# ═══════════════════════════════════════════════════════════════════════════
#
#  Given a cppcheckdata.Variable (or its ValueType), estimate the
#  number of bytes it occupies on the stack.
#
#  We use the ValueType attributes:
#    - type:  "int", "long", "char", "double", "float", "bool", etc.
#    - pointer: pointer indirection depth (>0 means pointer)
#    - bits:  bitfield width (or None)
#    - originalTypeName: for typedefs, struct names, etc.
#    - typeScopeId / typeScope: for struct/class types
# ═══════════════════════════════════════════════════════════════════════════

# Size table for fundamental types (bytes, assuming LP64 / x86-64)
_TYPE_SIZE: Dict[str, int] = {
    "bool":          1,
    "char":          1,
    "short":         2,
    "wchar_t":       4,
    "int":           4,
    "long":          8,   # LP64; on Windows LLP64 this is 4
    "long long":     8,
    "float":         4,
    "double":        8,
    "long double":  16,   # x86-64 System V ABI
    "void":          0,
}


def estimate_type_size(vt) -> int:
    """
    Estimate the byte-size of a ValueType.

    Parameters
    ----------
    vt : cppcheckdata.ValueType (or None)

    Returns
    -------
    int : estimated size in bytes; 0 if unknown or void.
    """
    if vt is None:
        return POINTER_SIZE  # unknown → assume pointer-sized

    # Pointers are always pointer-sized regardless of pointee
    if vt.pointer and vt.pointer > 0:
        return POINTER_SIZE

    # Bitfield
    if vt.bits is not None and vt.bits > 0:
        return max(1, (vt.bits + 7) // 8)

    # Fundamental type
    type_str = vt.type
    if type_str in _TYPE_SIZE:
        return _TYPE_SIZE[type_str]

    # Record (struct/class/union) — try to compute from typeScope
    if type_str == "record" and vt.typeScope is not None:
        return _estimate_scope_size(vt.typeScope)

    # Enum — typically int-sized
    if type_str == "record" or (vt.typeScope and hasattr(vt.typeScope, 'type')
                                 and vt.typeScope.type == "Enum"):
        return 4

    # Container types (std::vector, std::string, etc.) — three pointers
    if type_str == "container":
        return 3 * POINTER_SIZE  # typical: begin, end, capacity

    # Smart pointer
    if type_str == "smart-pointer":
        return POINTER_SIZE  # control block pointer + data pointer ≈ 2×ptr
        # Simplified to 1 ptr; shared_ptr is 2.

    # Unknown / 'unknown int'
    if "int" in (type_str or ""):
        return 4

    # Fallback
    return POINTER_SIZE


def _estimate_scope_size(scope) -> int:
    """
    Estimate the size of a struct/class/union scope by summing its
    member variables.

    For unions, we take the max instead of the sum.
    """
    if scope is None:
        return 0

    is_union = (hasattr(scope, 'type') and scope.type == "Union")
    total = 0

    var_list = getattr(scope, 'varlist', None) or []
    for var in var_list:
        member_size = _estimate_variable_size(var)
        if is_union:
            total = max(total, member_size)
        else:
            # Account for alignment padding
            alignment = min(member_size, DEFAULT_ALIGNMENT) if member_size > 0 else 1
            if alignment > 0 and total % alignment != 0:
                total += alignment - (total % alignment)
            total += member_size

    # Struct alignment: round up to alignment of largest member
    if not is_union and total > 0:
        largest_member = max(
            (_estimate_variable_size(v) for v in var_list),
            default=1,
        )
        alignment = min(largest_member, DEFAULT_ALIGNMENT)
        if alignment > 0 and total % alignment != 0:
            total += alignment - (total % alignment)

    return total


def _estimate_variable_size(var) -> int:
    """
    Estimate the stack footprint of a single variable.

    Handles:
    - Simple types (via ValueType)
    - Fixed-size arrays (dimensions from Token AST)
    - VLAs / alloca: returns -1 as a sentinel for "unbounded"
    """
    if var is None:
        return 0

    # Check for array
    is_array = getattr(var, 'isArray', False)
    dimensions = getattr(var, 'dimensions', None)

    # Get the element type size
    vt = getattr(var, 'valueType', None)
    element_size = estimate_type_size(vt)

    if is_array and dimensions:
        total_elements = 1
        for dim in dimensions:
            dim_size = getattr(dim, 'size', None)
            if dim_size is not None and dim_size > 0:
                total_elements *= dim_size
            else:
                # Variable-length array — unbounded
                return -1
        return element_size * total_elements

    return element_size


# ═══════════════════════════════════════════════════════════════════════════
#  PART 2 — FRAME SIZE COMPUTATION
# ═══════════════════════════════════════════════════════════════════════════
#
#  For each function scope, compute:
#    - The total local-variable frame size
#    - Whether the function uses alloca / VLAs (unbounded frame)
#    - The call overhead (return address + saved registers)
# ═══════════════════════════════════════════════════════════════════════════

class FrameSizeKind(Enum):
    """Classification of a function's frame size."""
    BOUNDED = auto()      # Frame size is a known constant
    UNBOUNDED = auto()    # Frame size depends on runtime values (VLA/alloca)


@dataclass
class FrameInfo:
    """
    Stack frame information for a single function.

    Attributes
    ----------
    function_name : str
        Fully qualified function name.
    file : str
        Source file.
    line : int
        Line number of the function definition.
    local_size : int
        Total size of local variables in bytes (or -1 if unbounded).
    call_overhead : int
        Return address + saved frame pointer bytes.
    total_frame : int
        local_size + call_overhead (or -1 if unbounded).
    kind : FrameSizeKind
        Whether the frame is bounded or unbounded.
    has_alloca : bool
        True if the function calls alloca().
    has_vla : bool
        True if the function declares a variable-length array.
    variables : list
        Per-variable size breakdown.
    interval : optional
        IntervalDomain representing the frame size range (if substrate
        is available).
    """
    function_name: str = ""
    file: str = ""
    line: int = 0
    local_size: int = 0
    call_overhead: int = CALL_OVERHEAD
    total_frame: int = 0
    kind: FrameSizeKind = FrameSizeKind.BOUNDED
    has_alloca: bool = False
    has_vla: bool = False
    variables: List[Tuple[str, int]] = field(default_factory=list)
    interval: Any = None  # IntervalDomain if available

    def __post_init__(self):
        if self.local_size < 0:
            self.kind = FrameSizeKind.UNBOUNDED
            self.total_frame = -1
        else:
            self.total_frame = self.local_size + self.call_overhead


def compute_frame_info(scope, func_name: str) -> FrameInfo:
    """
    Compute the FrameInfo for a function scope.

    Parameters
    ----------
    scope : cppcheckdata Scope (type == "Function")
    func_name : the function's qualified name

    Returns
    -------
    FrameInfo
    """
    info = FrameInfo(function_name=func_name)

    if scope and scope.bodyStart:
        info.file = getattr(scope.bodyStart, 'file', "")
        info.line = getattr(scope.bodyStart, 'linenr', 0)

    # ---- Enumerate local variables from the scope's varlist ----
    local_size = 0
    unbounded = False

    var_list = getattr(scope, 'varlist', None) or []
    for var in var_list:
        # Only count local (automatic) variables, not parameters
        # (parameters are part of the caller's frame or passed in registers)
        is_local = getattr(var, 'isLocal', False)
        is_arg = getattr(var, 'isArgument', False)
        is_static = getattr(var, 'isStatic', False)

        # Skip non-local, arguments, and static locals
        if not is_local or is_arg or is_static:
            continue

        var_name = getattr(var, 'nameToken', None)
        var_name_str = var_name.str if var_name else "<unknown>"

        var_size = _estimate_variable_size(var)

        if var_size < 0:
            unbounded = True
            info.has_vla = True
            info.variables.append((var_name_str, -1))
        else:
            # Apply alignment: each variable is aligned to min(size, 16)
            alignment = min(var_size, DEFAULT_ALIGNMENT) if var_size > 0 else 1
            if alignment > 1 and local_size % alignment != 0:
                local_size += alignment - (local_size % alignment)
            local_size += var_size
            info.variables.append((var_name_str, var_size))

    # ---- Check for alloca() calls in the function body ----
    if scope and scope.bodyStart and scope.bodyEnd:
        tok = scope.bodyStart
        while tok and tok != scope.bodyEnd:
            if (tok.str == "alloca" and tok.next and tok.next.str == "("):
                unbounded = True
                info.has_alloca = True
                break
            # Also check for __builtin_alloca
            if (tok.str == "__builtin_alloca" and tok.next
                    and tok.next.str == "("):
                unbounded = True
                info.has_alloca = True
                break
            tok = tok.next

    # ---- Final frame size ----
    if unbounded:
        info.local_size = -1
        info.kind = FrameSizeKind.UNBOUNDED
        info.total_frame = -1
    else:
        # Align the total frame to DEFAULT_ALIGNMENT
        if local_size % DEFAULT_ALIGNMENT != 0:
            local_size += DEFAULT_ALIGNMENT - (local_size % DEFAULT_ALIGNMENT)
        info.local_size = local_size
        info.total_frame = local_size + CALL_OVERHEAD

    # ---- Build IntervalDomain if available ----
    if HAS_INTERVAL and IntervalDomain is not None:
        if info.kind == FrameSizeKind.BOUNDED:
            info.interval = IntervalDomain.const(info.total_frame)
        else:
            # Unbounded: [CALL_OVERHEAD, +∞)
            info.interval = IntervalDomain.at_least(float(CALL_OVERHEAD))

    return info


# ═══════════════════════════════════════════════════════════════════════════
#  PART 3 — CALL GRAPH CONSTRUCTION
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class CallGraphEdge:
    """A directed edge in the call graph."""
    caller: str
    callee: str
    call_site_file: str = ""
    call_site_line: int = 0


@dataclass
class CallGraph:
    """
    Directed call graph over function names.

    Attributes
    ----------
    adjacency : dict
        caller → set of callee names
    edges : list
        All edges with call-site information
    nodes : set
        All function names that appear as caller or callee
    """
    adjacency: Dict[str, Set[str]] = field(default_factory=lambda: defaultdict(set))
    edges: List[CallGraphEdge] = field(default_factory=list)
    nodes: Set[str] = field(default_factory=set)

    def add_edge(self, caller: str, callee: str,
                 file: str = "", line: int = 0) -> None:
        self.adjacency[caller].add(callee)
        self.edges.append(CallGraphEdge(caller, callee, file, line))
        self.nodes.add(caller)
        self.nodes.add(callee)

    def callees(self, func: str) -> Set[str]:
        return self.adjacency.get(func, set())

    def callers(self, func: str) -> Set[str]:
        result: Set[str] = set()
        for caller, callees in self.adjacency.items():
            if func in callees:
                result.add(caller)
        return result

    # ---- SCC detection (Tarjan's algorithm) ----

    def compute_sccs(self) -> List[FrozenSet[str]]:
        """
        Compute strongly-connected components using Tarjan's algorithm.

        Returns a list of SCCs in reverse topological order (callees
        before callers for DAG edges between SCCs).
        """
        index_counter = [0]
        stack: List[str] = []
        on_stack: Set[str] = set()
        index: Dict[str, int] = {}
        lowlink: Dict[str, int] = {}
        result: List[FrozenSet[str]] = []

        def strongconnect(v: str) -> None:
            index[v] = index_counter[0]
            lowlink[v] = index_counter[0]
            index_counter[0] += 1
            stack.append(v)
            on_stack.add(v)

            for w in self.adjacency.get(v, set()):
                if w not in index:
                    strongconnect(w)
                    lowlink[v] = min(lowlink[v], lowlink[w])
                elif w in on_stack:
                    lowlink[v] = min(lowlink[v], index[w])

            if lowlink[v] == index[v]:
                scc: Set[str] = set()
                while True:
                    w = stack.pop()
                    on_stack.discard(w)
                    scc.add(w)
                    if w == v:
                        break
                result.append(frozenset(scc))

        for node in self.nodes:
            if node not in index:
                strongconnect(node)

        return result

    def is_recursive(self, func: str) -> bool:
        """Check if a function is (directly or mutually) recursive."""
        sccs = self.compute_sccs()
        for scc in sccs:
            if func in scc:
                # Recursive if SCC has size > 1, or self-loop
                if len(scc) > 1:
                    return True
                if func in self.adjacency.get(func, set()):
                    return True
        return False


def build_call_graph(cfg) -> CallGraph:
    """
    Build a call graph from a Cppcheck configuration.

    Walks every token in the token list; when a function-call pattern
    is detected (name followed by '('), we resolve the callee and
    record the caller→callee edge.

    Parameters
    ----------
    cfg : cppcheckdata.Configuration

    Returns
    -------
    CallGraph
    """
    cg = CallGraph()

    token_list = getattr(cfg, 'tokenlist', None) or []
    for tok in token_list:
        if not tok.isName:
            continue
        if not tok.next or tok.next.str != "(":
            continue

        # Determine the callee name
        callee_name = _resolve_callee_name(tok)
        if not callee_name:
            continue

        # Determine the caller (the enclosing function scope)
        caller_name = _enclosing_function_name(tok)
        if not caller_name:
            continue

        # Skip self-identification: don't confuse a function definition
        # header with a call.  The definition token is typically linked
        # to the function object.
        if tok.function and tok in (tok.function.token, tok.function.tokenDef):
            continue

        cg.add_edge(
            caller_name,
            callee_name,
            file=getattr(tok, 'file', ""),
            line=getattr(tok, 'linenr', 0),
        )

    return cg


def _resolve_callee_name(tok) -> Optional[str]:
    """
    Resolve the fully-qualified callee name from a call-site token.
    """
    if tok.function:
        # Cppcheck resolved the function — use its definition
        func = tok.function
        name = ""
        nametok = func.tokenDef if func.tokenDef else func.token
        if nametok:
            name = nametok.str
            t = nametok
            while (t.previous and t.previous.previous
                   and t.previous.str == "::"
                   and t.previous.previous.isName):
                name = t.previous.previous.str + "::" + name
                t = t.previous.previous
            scope = func.nestedIn
            while scope:
                cn = getattr(scope, 'className', None)
                if cn:
                    name = cn + "::" + name
                scope = getattr(scope, 'nestedIn', None)
        return name or tok.str

    # Unresolved call: just use the token text (possibly qualified)
    name = tok.str
    t = tok
    while (t.previous and t.previous.previous
           and t.previous.str == "::"
           and t.previous.previous.isName):
        name = t.previous.previous.str + "::" + name
        t = t.previous.previous
    return name


def _enclosing_function_name(tok) -> Optional[str]:
    """
    Find the name of the function enclosing a token.
    """
    scope = tok.scope
    while scope:
        if hasattr(scope, 'type') and scope.type == "Function":
            func = getattr(scope, 'function', None)
            if func:
                name = ""
                nametok = func.tokenDef or func.token
                if nametok:
                    name = nametok.str
                    t = nametok
                    while (t.previous and t.previous.previous
                           and t.previous.str == "::"
                           and t.previous.previous.isName):
                        name = t.previous.previous.str + "::" + name
                        t = t.previous.previous
                    ns = func.nestedIn
                    while ns:
                        cn = getattr(ns, 'className', None)
                        if cn:
                            name = cn + "::" + name
                        ns = getattr(ns, 'nestedIn', None)
                return name or None
            # Fallback: look at bodyStart
            if scope.bodyStart:
                t = scope.bodyStart.previous
                while t and t.str in (")", "const", "noexcept",
                                       "override", "final"):
                    if t.str == ")" and t.link:
                        t = t.link
                        t = t.previous if t else None
                    else:
                        t = t.previous
                if t and t.isName:
                    return t.str
        scope = getattr(scope, 'nestedIn', None)
    return None


# ═══════════════════════════════════════════════════════════════════════════
#  PART 4 — MAXIMUM STACK DEPTH COMPUTATION
# ═══════════════════════════════════════════════════════════════════════════
#
#  depth(f) = frame(f) + max{ depth(g) | g ∈ callees(f) }
#
#  For acyclic call graphs this is a simple DFS with memoisation.
#  For recursive SCCs we use one of two strategies:
#
#    (a) If a recursion depth bound is annotatable or inferrable,
#        depth = bound × frame_size_of_scc_members + callee_depths.
#
#    (b) Otherwise, report the depth as UNBOUNDED (∞).
#
#  When the abstract-execution substrate is available, we use
#  IntervalDomain widening to find a fixpoint:
#
#    depth_interval(f) = frame_interval(f) ⊕ ⊔{ depth_interval(g) }
#
#  and widen until stable.
# ═══════════════════════════════════════════════════════════════════════════

INF_DEPTH = float("inf")


@dataclass
class StackDepthResult:
    """
    Result of the stack depth analysis for a single function.

    Attributes
    ----------
    function_name : str
    file : str
    line : int
    frame : FrameInfo
        Per-function frame information.
    max_depth : Union[int, float]
        Maximum reachable stack depth in bytes from this function
        as an entry point.  float('inf') if unbounded.
    depth_path : List[str]
        The call chain that achieves the maximum depth.
    is_recursive : bool
        Whether this function participates in a recursive SCC.
    scc_members : FrozenSet[str]
        The SCC this function belongs to (singleton if non-recursive).
    depth_interval : optional
        IntervalDomain [lo, hi] for the stack depth if substrate available.
    warnings : List[str]
    """
    function_name: str = ""
    file: str = ""
    line: int = 0
    frame: Optional[FrameInfo] = None
    max_depth: Union[int, float] = 0
    depth_path: List[str] = field(default_factory=list)
    is_recursive: bool = False
    scc_members: FrozenSet[str] = field(default_factory=frozenset)
    depth_interval: Any = None
    warnings: List[str] = field(default_factory=list)

    @property
    def is_unbounded(self) -> bool:
        return self.max_depth == INF_DEPTH

    def depth_str(self) -> str:
        if self.is_unbounded:
            return "∞ (unbounded)"
        return f"{int(self.max_depth)} bytes"


class StackDepthComputer:
    """
    Computes maximum stack depth for all functions.

    Parameters
    ----------
    frames : dict
        function_name → FrameInfo
    call_graph : CallGraph
    threshold : int
        Stack budget in bytes for warning purposes.
    """

    def __init__(
        self,
        frames: Dict[str, FrameInfo],
        call_graph: CallGraph,
        threshold: int = DEFAULT_STACK_THRESHOLD,
    ):
        self.frames = frames
        self.cg = call_graph
        self.threshold = threshold

        # Memoisation cache
        self._memo: Dict[str, Tuple[Union[int, float], List[str]]] = {}

        # SCC index: function → its SCC
        self._scc_map: Dict[str, FrozenSet[str]] = {}
        self._sccs = self.cg.compute_sccs()
        for scc in self._sccs:
            for func in scc:
                self._scc_map[func] = scc

        # Track which functions are in non-trivial SCCs (recursive)
        self._recursive_funcs: Set[str] = set()
        for scc in self._sccs:
            if len(scc) > 1:
                self._recursive_funcs |= scc
            elif len(scc) == 1:
                f = next(iter(scc))
                if f in self.cg.adjacency.get(f, set()):
                    self._recursive_funcs.add(f)

        # Interval-based depth computation
        self._interval_memo: Dict[str, Any] = {}

    def compute_all(self) -> Dict[str, StackDepthResult]:
        """
        Compute stack depth for every known function.

        Returns
        -------
        dict : function_name → StackDepthResult
        """
        results: Dict[str, StackDepthResult] = {}

        for func_name in self.frames:
            result = self._compute_one(func_name)
            results[func_name] = result

        return results

    def _compute_one(self, func_name: str) -> StackDepthResult:
        """Compute depth for a single function as entry point."""
        frame = self.frames.get(func_name)
        result = StackDepthResult(
            function_name=func_name,
            file=frame.file if frame else "",
            line=frame.line if frame else 0,
            frame=frame,
            scc_members=self._scc_map.get(func_name, frozenset({func_name})),
            is_recursive=func_name in self._recursive_funcs,
        )

        if frame is None:
            # No frame info (external function); assume CALL_OVERHEAD only
            result.max_depth = CALL_OVERHEAD
            result.depth_path = [func_name]
            return result

        # Unbounded frame → unbounded depth
        if frame.kind == FrameSizeKind.UNBOUNDED:
            result.max_depth = INF_DEPTH
            result.depth_path = [func_name]
            result.warnings.append(
                f"Function '{func_name}' has unbounded frame size "
                f"({'alloca' if frame.has_alloca else 'VLA'})"
            )
            self._build_interval(result)
            return result

        # DFS with memoisation
        visiting: Set[str] = set()
        depth, path = self._dfs_depth(func_name, visiting)
        result.max_depth = depth
        result.depth_path = path

        # Build interval
        self._build_interval(result)

        # Generate warnings
        self._generate_warnings(result)

        return result

    def _dfs_depth(
        self, func: str, visiting: Set[str]
    ) -> Tuple[Union[int, float], List[str]]:
        """
        DFS computation of max stack depth from `func`.

        Parameters
        ----------
        func : function name
        visiting : set of functions currently on the DFS stack (cycle detection)

        Returns
        -------
        (max_depth, path) where path is the call chain achieving max_depth
        """
        # Already computed?
        if func in self._memo:
            return self._memo[func]

        # Cycle detected → recursive
        if func in visiting:
            # We don't know the recursion depth; report ∞
            return (INF_DEPTH, [func, "... (recursive cycle)"])

        frame = self.frames.get(func)
        if frame is None:
            # External/unknown function: assume just CALL_OVERHEAD
            result = (CALL_OVERHEAD, [func])
            self._memo[func] = result
            return result

        if frame.kind == FrameSizeKind.UNBOUNDED:
            result = (INF_DEPTH, [func])
            self._memo[func] = result
            return result

        my_frame = frame.total_frame
        callees = self.cg.callees(func)

        if not callees:
            # Leaf function
            result = (my_frame, [func])
            self._memo[func] = result
            return result

        visiting.add(func)

        max_callee_depth = 0
        max_callee_path: List[str] = []

        for callee in callees:
            callee_depth, callee_path = self._dfs_depth(callee, visiting)
            if callee_depth > max_callee_depth:
                max_callee_depth = callee_depth
                max_callee_path = callee_path

        visiting.discard(func)

        total = my_frame + max_callee_depth
        if math.isinf(max_callee_depth):
            total = INF_DEPTH

        path = [func] + max_callee_path
        result = (total, path)
        self._memo[func] = result
        return result

    def _build_interval(self, result: StackDepthResult) -> None:
        """
        Build an IntervalDomain for the stack depth if the substrate
        is available.
        """
        if not HAS_INTERVAL or IntervalDomain is None:
            return

        if result.is_unbounded:
            result.depth_interval = IntervalDomain.at_least(
                float(result.frame.total_frame if result.frame
                      and result.frame.total_frame >= 0
                      else CALL_OVERHEAD)
            )
        else:
            # Concrete depth: [depth, depth]
            result.depth_interval = IntervalDomain.const(
                int(result.max_depth)
            )

        # For recursive functions, attempt widening-based refinement
        if result.is_recursive and result.frame:
            result.depth_interval = self._widen_recursive_depth(
                result.function_name
            )

    def _widen_recursive_depth(self, func: str) -> Any:
        """
        Use interval widening to compute a fixpoint depth for a
        recursive function.

        The transfer function is:
            depth(f) = frame(f) + max(depth(callee) for callee in callees(f))

        For callees in the same SCC, we iterate with widening.

        Returns an IntervalDomain.
        """
        if not HAS_INTERVAL or IntervalDomain is None:
            return None

        frame = self.frames.get(func)
        if frame is None or frame.total_frame < 0:
            return IntervalDomain.at_least(float(CALL_OVERHEAD))

        scc = self._scc_map.get(func, frozenset())
        frame_size = float(frame.total_frame)

        # Initialize all SCC members to their frame size
        current: Dict[str, Any] = {}
        for member in scc:
            mf = self.frames.get(member)
            if mf and mf.total_frame >= 0:
                current[member] = IntervalDomain.const(mf.total_frame)
            else:
                current[member] = IntervalDomain.at_least(float(CALL_OVERHEAD))

        # Iterate with widening
        MAX_ITER = 20
        for iteration in range(MAX_ITER):
            changed = False
            for member in scc:
                mf = self.frames.get(member)
                mf_size = float(mf.total_frame if mf and mf.total_frame >= 0
                                else CALL_OVERHEAD)

                # Compute max callee depth
                callee_intervals = []
                for callee in self.cg.callees(member):
                    if callee in current:
                        callee_intervals.append(current[callee])
                    elif callee in self.frames:
                        cf = self.frames[callee]
                        if cf.total_frame >= 0:
                            callee_intervals.append(
                                IntervalDomain.const(cf.total_frame)
                            )
                        else:
                            callee_intervals.append(
                                IntervalDomain.at_least(float(CALL_OVERHEAD))
                            )
                    else:
                        callee_intervals.append(
                            IntervalDomain.const(float(CALL_OVERHEAD))
                        )

                if callee_intervals:
                    # Join all callee intervals (sound over-approximation of max)
                    max_callee = callee_intervals[0]
                    for ci in callee_intervals[1:]:
                        max_callee = max_callee.join(ci)
                    new_depth = IntervalDomain.const(mf_size).add(max_callee)
                else:
                    new_depth = IntervalDomain.const(mf_size)

                # Widen
                old = current[member]
                widened = old.widen(new_depth)
                if not new_depth.leq(old):
                    changed = True
                current[member] = widened

            if not changed:
                break

        # Narrow to tighten (optional, a few iterations)
        for _ in range(3):
            for member in scc:
                mf = self.frames.get(member)
                mf_size = float(mf.total_frame if mf and mf.total_frame >= 0
                                else CALL_OVERHEAD)
                callee_intervals = []
                for callee in self.cg.callees(member):
                    if callee in current:
                        callee_intervals.append(current[callee])
                if callee_intervals:
                    max_callee = callee_intervals[0]
                    for ci in callee_intervals[1:]:
                        max_callee = max_callee.join(ci)
                    new_depth = IntervalDomain.const(mf_size).add(max_callee)
                else:
                    new_depth = IntervalDomain.const(mf_size)

                current[member] = current[member].narrow(new_depth)

        return current.get(func, IntervalDomain.at_least(float(CALL_OVERHEAD)))

    def _generate_warnings(self, result: StackDepthResult) -> None:
        """Add warning strings to the result."""
        if result.is_unbounded:
            reason = ""
            if result.frame:
                if result.frame.has_alloca:
                    reason = " (uses alloca)"
                elif result.frame.has_vla:
                    reason = " (uses variable-length array)"
            if result.is_recursive:
                reason += " (recursive)"
            result.warnings.append(
                f"Unbounded stack depth for '{result.function_name}'{reason}"
            )
        elif result.max_depth > self.threshold:
            result.warnings.append(
                f"Stack depth {result.depth_str()} exceeds threshold "
                f"of {self.threshold} bytes for '{result.function_name}' — "
                f"call chain: {' → '.join(result.depth_path)}"
            )

        if (result.frame and result.frame.kind == FrameSizeKind.BOUNDED
                and result.frame.total_frame > SINGLE_FRAME_WARN):
            result.warnings.append(
                f"Large single frame: '{result.function_name}' uses "
                f"{result.frame.total_frame} bytes of stack"
            )

        if result.is_recursive:
            result.warnings.append(
                f"Function '{result.function_name}' is part of a recursive "
                f"SCC: {{{', '.join(sorted(result.scc_members))}}}"
            )


# ═══════════════════════════════════════════════════════════════════════════
#  PART 5 — ENTRY POINT DETECTION
# ═══════════════════════════════════════════════════════════════════════════

# Names recognised as program / thread entry points
_ENTRY_POINT_NAMES = frozenset({
    "main", "wmain", "_tmain", "WinMain", "wWinMain",
    "DllMain", "_DllMainCRTStartup",
})

_THREAD_ENTRY_PATTERNS = [
    re.compile(r".*thread.*", re.IGNORECASE),
    re.compile(r".*task.*main.*", re.IGNORECASE),
    re.compile(r".*worker.*", re.IGNORECASE),
]


def find_entry_points(
    frames: Dict[str, FrameInfo],
    call_graph: CallGraph,
) -> List[str]:
    """
    Identify likely program entry points.

    An entry point is:
    - main() or platform-specific equivalents
    - A function with no callers (root of the call graph)
    - A function whose name matches thread-entry patterns
    """
    entries: List[str] = []

    for name in frames:
        base_name = name.split("::")[-1] if "::" in name else name

        if base_name in _ENTRY_POINT_NAMES:
            entries.append(name)
            continue

        if not call_graph.callers(name):
            entries.append(name)
            continue

        for pat in _THREAD_ENTRY_PATTERNS:
            if pat.match(base_name):
                entries.append(name)
                break

    return entries


# ═══════════════════════════════════════════════════════════════════════════
#  PART 6 — REPORTING
# ═══════════════════════════════════════════════════════════════════════════

class _Location:
    """Minimal location object for cppcheckdata.reportError."""
    def __init__(self, file: str, linenr: int, column: int = 0):
        self.file = file
        self.linenr = linenr
        self.column = column


def report_results(
    results: Dict[str, StackDepthResult],
    entry_points: List[str],
    dump_file: str,
    threshold: int,
    verbose: bool = False,
) -> None:
    """
    Report the stack depth analysis results.

    Parameters
    ----------
    results : dict of function_name → StackDepthResult
    entry_points : list of entry-point function names
    dump_file : path to the .dump file
    threshold : stack budget in bytes
    verbose : detailed stderr output
    """

    # ---- Per-function diagnostics ----
    for func_name, result in sorted(results.items()):
        loc = _Location(result.file or "<unknown>", result.line or 0)

        # Unbounded stack
        if result.is_unbounded:
            reason_parts = []
            if result.frame and result.frame.has_alloca:
                reason_parts.append("alloca()")
            if result.frame and result.frame.has_vla:
                reason_parts.append("VLA")
            if result.is_recursive:
                reason_parts.append("recursion")
            reason = ", ".join(reason_parts) if reason_parts else "unknown"

            cppcheckdata.reportError(
                loc, "warning",
                f"Function '{func_name}' has unbounded stack usage "
                f"(reason: {reason})",
                ADDON_NAME, "unboundedStack",
                extra=reason,
            )
            continue

        # Exceeds threshold
        if result.max_depth > threshold:
            chain = " → ".join(result.depth_path[:10])
            if len(result.depth_path) > 10:
                chain += f" → ... ({len(result.depth_path) - 10} more)"

            cppcheckdata.reportError(
                loc, "performance",
                f"Function '{func_name}' can reach {result.depth_str()} "
                f"of stack depth (budget: {threshold} bytes). "
                f"Call chain: {chain}",
                ADDON_NAME, "highStackDepth",
                extra=result.depth_str(),
            )
            continue

        # Large single frame
        if (result.frame and result.frame.kind == FrameSizeKind.BOUNDED
                and result.frame.total_frame > SINGLE_FRAME_WARN):
            cppcheckdata.reportError(
                loc, "style",
                f"Function '{func_name}' has a large stack frame: "
                f"{result.frame.total_frame} bytes",
                ADDON_NAME, "largeStackFrame",
                extra=f"{result.frame.total_frame} bytes",
            )

        # Recursive SCC
        if result.is_recursive:
            cppcheckdata.reportError(
                loc, "style",
                f"Function '{func_name}' is recursive "
                f"(SCC: {{{', '.join(sorted(result.scc_members))}}}); "
                f"stack depth depends on recursion depth",
                ADDON_NAME, "recursiveStack",
            )

    # ---- Entry-point summary ----
    for ep in entry_points:
        r = results.get(ep)
        if r:
            loc = _Location(r.file or "<unknown>", r.line or 0)
            if r.is_unbounded:
                cppcheckdata.reportError(
                    loc, "warning",
                    f"Entry point '{ep}' has unbounded maximum stack depth",
                    ADDON_NAME, "entryPointUnboundedStack",
                )
            elif r.max_depth > threshold:
                cppcheckdata.reportError(
                    loc, "performance",
                    f"Entry point '{ep}' maximum stack depth: "
                    f"{r.depth_str()} exceeds budget of {threshold} bytes",
                    ADDON_NAME, "entryPointHighStack",
                    extra=r.depth_str(),
                )

    # ---- Verbose output ----
    if verbose:
        sys.stderr.write(f"\n{'='*70}\n")
        sys.stderr.write(f"  {ADDON_NAME} v{ADDON_VERSION} — Stack Depth Report\n")
        sys.stderr.write(f"  Stack budget: {threshold} bytes\n")
        sys.stderr.write(f"  Functions analysed: {len(results)}\n")
        sys.stderr.write(f"  Entry points: {', '.join(entry_points) or '(none detected)'}\n")
        sys.stderr.write(f"{'='*70}\n\n")

        # Sort by depth descending
        sorted_results = sorted(
            results.values(),
            key=lambda r: r.max_depth if not math.isinf(r.max_depth) else 1e18,
            reverse=True,
        )

        for r in sorted_results:
            flag = ""
            if r.is_unbounded:
                flag = " ⚠ UNBOUNDED"
            elif r.max_depth > threshold:
                flag = " ⚠ OVER BUDGET"
            elif r.is_recursive:
                flag = " ↻ RECURSIVE"

            sys.stderr.write(f"  {r.function_name}{flag}\n")
            sys.stderr.write(f"    Frame size:  {r.frame.total_frame if r.frame and r.frame.total_frame >= 0 else '∞'} bytes\n")
            sys.stderr.write(f"    Max depth:   {r.depth_str()}\n")
            sys.stderr.write(f"    Call chain:  {' → '.join(r.depth_path[:15])}\n")

            if r.frame and r.frame.variables:
                sys.stderr.write(f"    Locals:\n")
                for vname, vsize in r.frame.variables:
                    size_str = f"{vsize} bytes" if vsize >= 0 else "∞ (VLA)"
                    sys.stderr.write(f"      {vname}: {size_str}\n")

            if r.depth_interval is not None:
                sys.stderr.write(f"    Interval:    {r.depth_interval}\n")

            if r.warnings:
                for w in r.warnings:
                    sys.stderr.write(f"    ⚠ {w}\n")

            sys.stderr.write("\n")

    # ---- Machine-readable summary ----
    summary_data = {
        "functions_analyzed": len(results),
        "entry_points": entry_points,
        "threshold_bytes": threshold,
        "functions": [
            {
                "name": r.function_name,
                "frame_bytes": r.frame.total_frame if r.frame and r.frame.total_frame >= 0 else None,
                "max_depth_bytes": int(r.max_depth) if not math.isinf(r.max_depth) else None,
                "is_unbounded": r.is_unbounded,
                "is_recursive": r.is_recursive,
                "call_chain_length": len(r.depth_path),
                "depth_path": r.depth_path[:20],
            }
            for r in sorted(results.values(), key=lambda x: x.function_name)
        ],
    }
    cppcheckdata.reportSummary(dump_file, "stackDepthAnalysis", summary_data)


# ═══════════════════════════════════════════════════════════════════════════
#  PART 7 — MAIN ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════

def main():
    """
    Main entry point for the StackDepthAnalyzer addon.

    Usage:
        python StackDepthAnalyzer.py [options] <file.dump> [file2.dump ...]

    Options:
        --verbose, -v        Detailed output to stderr
        --threshold N        Stack budget in bytes (default: 8388608)
        --pointer-size N     Pointer size in bytes (default: 8)
        --alignment N        Default stack alignment (default: 16)
        --call-overhead N    Per-call overhead in bytes (default: 16)
    """
    global DEFAULT_STACK_THRESHOLD, POINTER_SIZE, DEFAULT_ALIGNMENT, CALL_OVERHEAD

    verbose = "--verbose" in sys.argv or "-v" in sys.argv
    threshold = DEFAULT_STACK_THRESHOLD

    # Parse options
    args = []
    i = 1
    while i < len(sys.argv):
        a = sys.argv[i]
        if a in ("--verbose", "-v"):
            pass  # already handled
        elif a == "--threshold" and i + 1 < len(sys.argv):
            i += 1
            threshold = int(sys.argv[i])
        elif a == "--pointer-size" and i + 1 < len(sys.argv):
            i += 1
            POINTER_SIZE = int(sys.argv[i])
        elif a == "--alignment" and i + 1 < len(sys.argv):
            i += 1
            DEFAULT_ALIGNMENT = int(sys.argv[i])
        elif a == "--call-overhead" and i + 1 < len(sys.argv):
            i += 1
            CALL_OVERHEAD = int(sys.argv[i])
        elif not a.startswith("-"):
            args.append(a)
        i += 1

    if not args:
        sys.stderr.write(
            f"{ADDON_NAME} v{ADDON_VERSION}\n"
            f"Usage: {sys.argv[0]} [options] <file.dump> ...\n"
            f"\nOptions:\n"
            f"  --verbose, -v        Detailed output to stderr\n"
            f"  --threshold N        Stack budget in bytes (default: {DEFAULT_STACK_THRESHOLD})\n"
            f"  --pointer-size N     Pointer size in bytes (default: {POINTER_SIZE})\n"
            f"  --alignment N        Stack alignment (default: {DEFAULT_ALIGNMENT})\n"
            f"  --call-overhead N    Per-call overhead bytes (default: {CALL_OVERHEAD})\n"
        )
        sys.exit(1)

    cppcheckdata.log_checker(ADDON_NAME, ADDON_NAME)

    for dump_file in args:
        if not os.path.isfile(dump_file):
            sys.stderr.write(f"Error: file not found: {dump_file}\n")
            continue

        try:
            data = cppcheckdata.CppcheckData(dump_file)
        except Exception as e:
            sys.stderr.write(f"Error parsing {dump_file}: {e}\n")
            continue

        for cfg in data.iterconfigurations():
            if verbose:
                sys.stderr.write(
                    f"\n{'#'*70}\n"
                    f"# {ADDON_NAME} — Analysing configuration: {cfg.name}\n"
                    f"# Dump file: {dump_file}\n"
                    f"# Pointer size: {POINTER_SIZE}B | "
                    f"Alignment: {DEFAULT_ALIGNMENT}B | "
                    f"Call overhead: {CALL_OVERHEAD}B\n"
                    f"{'#'*70}\n"
                )

            # Phase 1: Compute frame sizes for all functions
            frames: Dict[str, FrameInfo] = {}

            scopes = getattr(cfg, 'scopes', None) or []
            for scope in scopes:
                if not hasattr(scope, 'type') or scope.type != "Function":
                    continue
                if not scope.bodyStart:
                    continue

                func_name = _scope_function_name(scope)
                if not func_name:
                    func_name = f"<anon@{scope.bodyStart.linenr}>"

                frame = compute_frame_info(scope, func_name)
                frames[func_name] = frame

            if verbose:
                sys.stderr.write(
                    f"\n  Phase 1: {len(frames)} function frames computed\n"
                )

            # Phase 2: Build call graph
            call_graph = build_call_graph(cfg)

            if verbose:
                sys.stderr.write(
                    f"  Phase 2: Call graph — {len(call_graph.nodes)} nodes, "
                    f"{len(call_graph.edges)} edges, "
                    f"{len(call_graph.compute_sccs())} SCCs\n"
                )

            # Phase 3: Compute maximum stack depths
            computer = StackDepthComputer(frames, call_graph, threshold)
            results = computer.compute_all()

            if verbose:
                sys.stderr.write(
                    f"  Phase 3: Stack depths computed for "
                    f"{len(results)} functions\n"
                )

            # Phase 4: Detect entry points and report
            entry_points = find_entry_points(frames, call_graph)

            report_results(
                results,
                entry_points,
                dump_file,
                threshold,
                verbose=verbose,
            )


def _scope_function_name(scope) -> Optional[str]:
    """Extract the function name from a Function scope."""
    func = getattr(scope, 'function', None)
    if func:
        name = ""
        nametok = getattr(func, 'tokenDef', None) or getattr(func, 'token', None)
        if nametok:
            name = nametok.str
            t = nametok
            while (t.previous and t.previous.previous
                   and t.previous.str == "::"
                   and t.previous.previous.isName):
                name = t.previous.previous.str + "::" + name
                t = t.previous.previous
            ns = getattr(func, 'nestedIn', None)
            while ns:
                cn = getattr(ns, 'className', None)
                if cn:
                    name = cn + "::" + name
                ns = getattr(ns, 'nestedIn', None)
        return name or None

    if scope.bodyStart:
        t = scope.bodyStart.previous
        while t and t.str in (")", "const", "noexcept", "override", "final"):
            if t.str == ")" and t.link:
                t = t.link
                t = t.previous if t else None
            else:
                t = t.previous
        if t and t.isName:
            return t.str
    return None


if __name__ == "__main__":
    main()
