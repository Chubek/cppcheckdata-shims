"""
memory_abstraction.py — Memory Model for Cppcheck Static Analysis
=================================================================

Provides a layered memory abstraction over Cppcheck's data model:

  Layer 0: MemoryLocation — unique identifiers for memory cells
  Layer 1: AllocationSite — tracks how/where memory was born
  Layer 2: PointsToGraph  — flow-insensitive pointer analysis
  Layer 3: AbstractStore   — maps locations → abstract values
  Layer 4: MemoryState     — full memory state (store + stack + heap metadata)
  Layer 5: MayModAnalysis  — function side-effect inference

Usage
-----
    from cppcheckdata_shims.memory_abstraction import (
        MemoryModel,
        MemoryLocation,
        PointsToGraph,
        AbstractStore,
        MemoryState,
    )

    data = cppcheckdata.parsedump("example.c.dump")
    cfg = data.configurations[0]

    model = MemoryModel(cfg)
    model.build()

    # Query points-to information
    ptg = model.points_to_graph
    targets = ptg.points_to(some_variable)

    # Build a memory state for analysis
    state = model.initial_state(function_scope)
    state = state.write(loc, abstract_value)
    val = state.read(loc)

    # Query side effects
    may_mod = model.may_mod_analysis
    modified = may_mod.may_modify("process_data")

Licence: No restrictions, use this as you need.
"""

from __future__ import annotations

import enum
import itertools
import weakref
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import (
    Any,
    Callable,
    Dict,
    FrozenSet,
    Iterable,
    Iterator,
    List,
    Mapping,
    Optional,
    Set,
    Sequence,
    Tuple,
    Union,
)


# ---------------------------------------------------------------------------
# 0. Memory Location Kinds and Identifiers
# ---------------------------------------------------------------------------

class LocationKind(enum.Enum):
    """Classification of memory locations."""
    GLOBAL      = "global"       # Global / file-scope variable
    LOCAL       = "local"        # Stack-allocated local variable
    ARGUMENT    = "argument"     # Function parameter
    HEAP        = "heap"         # Dynamically allocated (malloc/calloc/realloc/new)
    FIELD       = "field"        # Struct/class field (offset from base)
    ELEMENT     = "element"      # Array element (index from base)
    RETURN      = "return"       # Function return value slot
    UNKNOWN     = "unknown"      # Conservatively unknown location
    NULL        = "null"         # The null/zero location
    STRING_LIT  = "string_lit"   # String literal storage


class AllocatorKind(enum.Enum):
    """How a heap location was allocated."""
    MALLOC      = "malloc"
    CALLOC      = "calloc"
    REALLOC     = "realloc"
    NEW         = "new"
    NEW_ARRAY   = "new[]"
    STRDUP      = "strdup"
    CUSTOM      = "custom"       # User-defined allocator
    STACK       = "stack"        # Stack allocation (alloca / VLA)
    STATIC      = "static"       # Static storage duration
    UNKNOWN     = "unknown"


class DeallocatorKind(enum.Enum):
    """How a heap location should be / was deallocated."""
    FREE        = "free"
    DELETE      = "delete"
    DELETE_ARRAY = "delete[]"
    REALLOC     = "realloc"      # realloc can free the old block
    CUSTOM      = "custom"
    NONE        = "none"         # Not yet freed / not applicable


# Matching table: which deallocator is correct for each allocator
ALLOC_DEALLOC_MATCH: Dict[AllocatorKind, FrozenSet[DeallocatorKind]] = {
    AllocatorKind.MALLOC:    frozenset({DeallocatorKind.FREE, DeallocatorKind.REALLOC}),
    AllocatorKind.CALLOC:    frozenset({DeallocatorKind.FREE, DeallocatorKind.REALLOC}),
    AllocatorKind.REALLOC:   frozenset({DeallocatorKind.FREE, DeallocatorKind.REALLOC}),
    AllocatorKind.STRDUP:    frozenset({DeallocatorKind.FREE}),
    AllocatorKind.NEW:       frozenset({DeallocatorKind.DELETE}),
    AllocatorKind.NEW_ARRAY: frozenset({DeallocatorKind.DELETE_ARRAY}),
    AllocatorKind.STACK:     frozenset(),  # cannot be explicitly freed
    AllocatorKind.STATIC:    frozenset(),  # cannot be explicitly freed
    AllocatorKind.CUSTOM:    frozenset({DeallocatorKind.CUSTOM, DeallocatorKind.FREE}),
    AllocatorKind.UNKNOWN:   frozenset({DeallocatorKind.FREE, DeallocatorKind.DELETE,
                                        DeallocatorKind.DELETE_ARRAY, DeallocatorKind.CUSTOM}),
}


@dataclass(frozen=True, eq=True)
class AllocationSite:
    """
    Identifies where and how a memory location was created.

    In a flow-insensitive analysis, all objects allocated at the same
    program point are collapsed into one abstract allocation site
    (see literature-on-static-program-analysis, §3.1).
    """
    token_id: Optional[str]       # Token.Id of the allocation point (None for globals/params)
    file: Optional[str] = None
    line: Optional[int] = None
    column: Optional[int] = None
    allocator: AllocatorKind = AllocatorKind.UNKNOWN
    label: Optional[str] = None   # Human-readable label, e.g. "malloc@main:42"

    def __repr__(self) -> str:
        if self.label:
            return f"AllocSite({self.label})"
        loc = f"{self.file}:{self.line}" if self.file else "?"
        return f"AllocSite({self.allocator.value}@{loc})"


@dataclass(frozen=True, eq=True)
class MemoryLocation:
    """
    Abstract memory location — the fundamental unit of the memory model.

    A MemoryLocation is uniquely identified by its kind + base_id + offset.
    For simple variables, offset is 0.  For struct fields, offset is the
    field name.  For array elements, offset is an abstract index.

    MemoryLocations are *immutable* and *hashable* so they can be used
    as dictionary keys and set elements.
    """
    kind: LocationKind
    base_id: str                              # Unique base identifier
    offset: Union[str, int, None] = None      # Field name, array index, or None
    alloc_site: Optional[AllocationSite] = None
    variable_id: Optional[str] = None         # cppcheckdata Variable.Id if applicable
    scope_id: Optional[str] = None            # Enclosing Scope.Id
    name: Optional[str] = None                # Human-readable name

    # -- Derived locations ---------------------------------------------------

    def field(self, field_name: str) -> "MemoryLocation":
        """Return the location of a named field within this location."""
        return MemoryLocation(
            kind=LocationKind.FIELD,
            base_id=self.base_id,
            offset=field_name,
            alloc_site=self.alloc_site,
            variable_id=self.variable_id,
            scope_id=self.scope_id,
            name=f"{self.name}.{field_name}" if self.name else field_name,
        )

    def element(self, index: Union[int, str] = "*") -> "MemoryLocation":
        """
        Return the location of an array element.
        index='*' means summarised / unknown index.
        """
        return MemoryLocation(
            kind=LocationKind.ELEMENT,
            base_id=self.base_id,
            offset=index,
            alloc_site=self.alloc_site,
            variable_id=self.variable_id,
            scope_id=self.scope_id,
            name=f"{self.name}[{index}]" if self.name else f"[{index}]",
        )

    @property
    def is_null(self) -> bool:
        return self.kind == LocationKind.NULL

    @property
    def is_heap(self) -> bool:
        return self.kind == LocationKind.HEAP

    @property
    def is_stack(self) -> bool:
        return self.kind in (LocationKind.LOCAL, LocationKind.ARGUMENT)

    @property
    def is_global(self) -> bool:
        return self.kind == LocationKind.GLOBAL

    def __repr__(self) -> str:
        if self.name:
            return f"Loc({self.name})"
        suffix = f"+{self.offset}" if self.offset is not None else ""
        return f"Loc({self.kind.value}:{self.base_id}{suffix})"


# Sentinel locations
NULL_LOCATION = MemoryLocation(
    kind=LocationKind.NULL,
    base_id="__null__",
    name="NULL",
)

UNKNOWN_LOCATION = MemoryLocation(
    kind=LocationKind.UNKNOWN,
    base_id="__unknown__",
    name="<unknown>",
)


# ---------------------------------------------------------------------------
# 1. Abstract Values for the Memory Model
# ---------------------------------------------------------------------------

class AbstractValueKind(enum.Enum):
    """Kind of abstract value stored in a memory cell."""
    TOP         = "top"         # Any value (no information)
    BOTTOM      = "bottom"      # Unreachable / uninitialized
    CONCRETE    = "concrete"    # Known concrete integer/float
    INTERVAL    = "interval"    # Numeric interval [lo, hi]
    POINTER     = "pointer"     # Points-to set
    SYMBOL      = "symbol"      # Symbolic variable (for symbolic execution)
    NULL        = "null"        # Definitely null
    NON_NULL    = "non_null"    # Definitely non-null (but unknown target)
    MAYBE_NULL  = "maybe_null"  # May or may not be null
    FREED       = "freed"       # Memory has been deallocated
    UNINIT      = "uninit"      # Uninitialized memory


@dataclass(frozen=True)
class AbstractValue:
    """
    An abstract value in the memory model.

    This is the *payload* stored at each MemoryLocation.  The memory
    model itself is agnostic to the analysis domain — AbstractValue
    serves as the common currency between different analyses.
    """
    kind: AbstractValueKind
    concrete_int: Optional[int] = None
    concrete_float: Optional[float] = None
    interval_lo: Optional[int] = None
    interval_hi: Optional[int] = None
    points_to: FrozenSet[MemoryLocation] = frozenset()
    symbol_name: Optional[str] = None
    symbol_id: Optional[int] = None
    extra: Any = None  # Domain-specific payload

    # -- Constructors (class methods) ----------------------------------------

    @classmethod
    def top(cls) -> "AbstractValue":
        return cls(kind=AbstractValueKind.TOP)

    @classmethod
    def bottom(cls) -> "AbstractValue":
        return cls(kind=AbstractValueKind.BOTTOM)

    @classmethod
    def null(cls) -> "AbstractValue":
        return cls(kind=AbstractValueKind.NULL, points_to=frozenset({NULL_LOCATION}))

    @classmethod
    def non_null(cls) -> "AbstractValue":
        return cls(kind=AbstractValueKind.NON_NULL)

    @classmethod
    def maybe_null(cls) -> "AbstractValue":
        return cls(kind=AbstractValueKind.MAYBE_NULL)

    @classmethod
    def freed(cls) -> "AbstractValue":
        return cls(kind=AbstractValueKind.FREED)

    @classmethod
    def uninit(cls) -> "AbstractValue":
        return cls(kind=AbstractValueKind.UNINIT)

    @classmethod
    def from_int(cls, value: int) -> "AbstractValue":
        return cls(kind=AbstractValueKind.CONCRETE, concrete_int=value)

    @classmethod
    def from_float(cls, value: float) -> "AbstractValue":
        return cls(kind=AbstractValueKind.CONCRETE, concrete_float=value)

    @classmethod
    def from_interval(cls, lo: Optional[int], hi: Optional[int]) -> "AbstractValue":
        if lo is not None and hi is not None and lo == hi:
            return cls.from_int(lo)
        return cls(kind=AbstractValueKind.INTERVAL, interval_lo=lo, interval_hi=hi)

    @classmethod
    def from_pointer(cls, targets: Iterable[MemoryLocation]) -> "AbstractValue":
        pts = frozenset(targets)
        if not pts:
            return cls.null()
        has_null = NULL_LOCATION in pts
        non_null_targets = pts - {NULL_LOCATION}
        if not non_null_targets and has_null:
            return cls.null()
        kind = AbstractValueKind.MAYBE_NULL if has_null else AbstractValueKind.POINTER
        return cls(kind=kind, points_to=pts)

    @classmethod
    def from_symbol(cls, name: str, sym_id: Optional[int] = None) -> "AbstractValue":
        return cls(kind=AbstractValueKind.SYMBOL, symbol_name=name, symbol_id=sym_id)

    # -- Lattice operations --------------------------------------------------

    def is_top(self) -> bool:
        return self.kind == AbstractValueKind.TOP

    def is_bottom(self) -> bool:
        return self.kind == AbstractValueKind.BOTTOM

    def join(self, other: "AbstractValue") -> "AbstractValue":
        """Least upper bound in the abstract value lattice."""
        if self.is_bottom():
            return other
        if other.is_bottom():
            return self
        if self.is_top() or other.is_top():
            return AbstractValue.top()
        if self == other:
            return self

        # Both are pointer-like: merge points-to sets
        if self.kind in _POINTER_KINDS and other.kind in _POINTER_KINDS:
            merged = self.points_to | other.points_to
            has_null = NULL_LOCATION in merged
            kind = AbstractValueKind.MAYBE_NULL if has_null else AbstractValueKind.POINTER
            return AbstractValue(kind=kind, points_to=merged)

        # Both are intervals or concrete integers: widen to interval
        if self.kind in _NUMERIC_KINDS and other.kind in _NUMERIC_KINDS:
            lo_a = self.concrete_int if self.kind == AbstractValueKind.CONCRETE else self.interval_lo
            hi_a = self.concrete_int if self.kind == AbstractValueKind.CONCRETE else self.interval_hi
            lo_b = other.concrete_int if other.kind == AbstractValueKind.CONCRETE else other.interval_lo
            hi_b = other.concrete_int if other.kind == AbstractValueKind.CONCRETE else other.interval_hi
            lo = min(lo_a, lo_b) if lo_a is not None and lo_b is not None else None
            hi = max(hi_a, hi_b) if hi_a is not None and hi_b is not None else None
            return AbstractValue.from_interval(lo, hi)

        # Nullness join
        if self.kind in _NULLNESS_KINDS and other.kind in _NULLNESS_KINDS:
            if self.kind == other.kind:
                return self
            return AbstractValue.maybe_null()

        # Freed + anything non-bottom = top (conservative)
        if self.kind == AbstractValueKind.FREED or other.kind == AbstractValueKind.FREED:
            return AbstractValue.top()

        return AbstractValue.top()

    def meet(self, other: "AbstractValue") -> "AbstractValue":
        """Greatest lower bound in the abstract value lattice."""
        if self.is_top():
            return other
        if other.is_top():
            return self
        if self.is_bottom() or other.is_bottom():
            return AbstractValue.bottom()
        if self == other:
            return self

        # Pointer intersection
        if self.kind in _POINTER_KINDS and other.kind in _POINTER_KINDS:
            intersected = self.points_to & other.points_to
            if not intersected:
                return AbstractValue.bottom()
            return AbstractValue.from_pointer(intersected)

        # Interval intersection
        if self.kind in _NUMERIC_KINDS and other.kind in _NUMERIC_KINDS:
            lo_a = self.concrete_int if self.kind == AbstractValueKind.CONCRETE else self.interval_lo
            hi_a = self.concrete_int if self.kind == AbstractValueKind.CONCRETE else self.interval_hi
            lo_b = other.concrete_int if other.kind == AbstractValueKind.CONCRETE else other.interval_lo
            hi_b = other.concrete_int if other.kind == AbstractValueKind.CONCRETE else other.interval_hi
            lo = max(lo_a, lo_b) if lo_a is not None and lo_b is not None else (lo_a or lo_b)
            hi = min(hi_a, hi_b) if hi_a is not None and hi_b is not None else (hi_a or hi_b)
            if lo is not None and hi is not None and lo > hi:
                return AbstractValue.bottom()
            return AbstractValue.from_interval(lo, hi)

        return AbstractValue.bottom()

    def leq(self, other: "AbstractValue") -> bool:
        """Partial order: self ⊑ other."""
        if self.is_bottom():
            return True
        if other.is_top():
            return True
        if self == other:
            return True
        joined = self.join(other)
        return joined == other

    def __repr__(self) -> str:
        if self.kind == AbstractValueKind.CONCRETE:
            v = self.concrete_int if self.concrete_int is not None else self.concrete_float
            return f"AVal({v})"
        if self.kind == AbstractValueKind.INTERVAL:
            return f"AVal([{self.interval_lo}, {self.interval_hi}])"
        if self.kind in _POINTER_KINDS:
            targets = ", ".join(str(t) for t in self.points_to)
            return f"AVal({self.kind.value} -> {{{targets}}})"
        if self.kind == AbstractValueKind.SYMBOL:
            return f"AVal(sym:{self.symbol_name})"
        return f"AVal({self.kind.value})"


_POINTER_KINDS = frozenset({
    AbstractValueKind.POINTER,
    AbstractValueKind.NULL,
    AbstractValueKind.NON_NULL,
    AbstractValueKind.MAYBE_NULL,
})

_NULLNESS_KINDS = frozenset({
    AbstractValueKind.NULL,
    AbstractValueKind.NON_NULL,
    AbstractValueKind.MAYBE_NULL,
})

_NUMERIC_KINDS = frozenset({
    AbstractValueKind.CONCRETE,
    AbstractValueKind.INTERVAL,
})


# ---------------------------------------------------------------------------
# 2. Abstract Store
# ---------------------------------------------------------------------------

class AbstractStore:
    """
    An immutable mapping from MemoryLocation → AbstractValue.

    The store uses a persistent/copy-on-write strategy: each write
    returns a *new* store sharing structure with the old one.  This
    makes it safe to use in fixpoint computations where you need
    both the old and new states simultaneously.
    """

    __slots__ = ("_map", "_hash_cache")

    def __init__(self, mapping: Optional[Dict[MemoryLocation, AbstractValue]] = None):
        # Internally we use a plain dict; the "immutable" contract is
        # enforced by always copying on mutation.
        self._map: Dict[MemoryLocation, AbstractValue] = dict(mapping) if mapping else {}
        self._hash_cache: Optional[int] = None

    # -- Read / Write --------------------------------------------------------

    def read(self, loc: MemoryLocation) -> AbstractValue:
        """
        Read the abstract value at *loc*.

        Returns AbstractValue.top() for locations not in the store
        (i.e., we assume nothing about untracked locations).
        """
        return self._map.get(loc, AbstractValue.top())

    def write(self, loc: MemoryLocation, val: AbstractValue) -> "AbstractStore":
        """Return a new store with *loc* bound to *val*."""
        new_map = dict(self._map)
        if val.is_top():
            new_map.pop(loc, None)  # top = no info = remove
        else:
            new_map[loc] = val
        return AbstractStore(new_map)

    def kill(self, loc: MemoryLocation) -> "AbstractStore":
        """Remove *loc* from the store (equivalent to writing top)."""
        if loc not in self._map:
            return self
        new_map = dict(self._map)
        del new_map[loc]
        return AbstractStore(new_map)

    def kill_many(self, locs: Iterable[MemoryLocation]) -> "AbstractStore":
        """Remove multiple locations."""
        new_map = dict(self._map)
        for loc in locs:
            new_map.pop(loc, None)
        return AbstractStore(new_map)

    # -- Bulk operations -----------------------------------------------------

    def restrict_to(self, locs: Set[MemoryLocation]) -> "AbstractStore":
        """Return a store containing only the given locations."""
        return AbstractStore({k: v for k, v in self._map.items() if k in locs})

    def project_out(self, locs: Set[MemoryLocation]) -> "AbstractStore":
        """Return a store with the given locations removed."""
        return AbstractStore({k: v for k, v in self._map.items() if k not in locs})

    def overlay(self, other: "AbstractStore") -> "AbstractStore":
        """
        Return a new store that is ``self`` updated with all bindings
        from ``other``.  (other takes priority.)
        """
        new_map = dict(self._map)
        new_map.update(other._map)
        return AbstractStore(new_map)

    # -- Lattice operations --------------------------------------------------

    def join(self, other: "AbstractStore") -> "AbstractStore":
        """
        Pointwise join of two stores.

        For locations present in both stores, values are joined.
        For locations present in only one store, the value is joined
        with top (which yields top, so they are effectively removed).
        """
        all_keys = set(self._map.keys()) | set(other._map.keys())
        result: Dict[MemoryLocation, AbstractValue] = {}
        for k in all_keys:
            v1 = self._map.get(k, AbstractValue.top())
            v2 = other._map.get(k, AbstractValue.top())
            joined = v1.join(v2)
            if not joined.is_top():
                result[k] = joined
        return AbstractStore(result)

    def meet(self, other: "AbstractStore") -> "AbstractStore":
        """Pointwise meet of two stores."""
        # Only keys in *both* stores survive (conservative)
        common_keys = set(self._map.keys()) & set(other._map.keys())
        result: Dict[MemoryLocation, AbstractValue] = {}
        for k in common_keys:
            met = self._map[k].meet(other._map[k])
            if not met.is_bottom():
                result[k] = met
        return AbstractStore(result)

    def widen(self, other: "AbstractStore", iteration: int = 0) -> "AbstractStore":
        """
        Widening: join with forced extrapolation on intervals.

        After *iteration* stable steps, intervals are widened to [-∞, +∞].
        """
        all_keys = set(self._map.keys()) | set(other._map.keys())
        result: Dict[MemoryLocation, AbstractValue] = {}
        for k in all_keys:
            v_old = self._map.get(k, AbstractValue.bottom())
            v_new = other._map.get(k, AbstractValue.bottom())
            if v_old == v_new:
                if not v_old.is_top():
                    result[k] = v_old
                continue
            # Widening on intervals
            if (v_old.kind in _NUMERIC_KINDS and v_new.kind in _NUMERIC_KINDS):
                lo_old = v_old.concrete_int if v_old.kind == AbstractValueKind.CONCRETE else v_old.interval_lo
                hi_old = v_old.concrete_int if v_old.kind == AbstractValueKind.CONCRETE else v_old.interval_hi
                lo_new = v_new.concrete_int if v_new.kind == AbstractValueKind.CONCRETE else v_new.interval_lo
                hi_new = v_new.concrete_int if v_new.kind == AbstractValueKind.CONCRETE else v_new.interval_hi
                # Widen: if lower bound decreased, go to -∞; if upper increased, go to +∞
                lo = lo_old if (lo_new is not None and lo_old is not None and lo_new >= lo_old) else None
                hi = hi_old if (hi_new is not None and hi_old is not None and hi_new <= hi_old) else None
                widened = AbstractValue.from_interval(lo, hi)
                if not widened.is_top():
                    result[k] = widened
            else:
                joined = v_old.join(v_new)
                if not joined.is_top():
                    result[k] = joined
        return AbstractStore(result)

    def leq(self, other: "AbstractStore") -> bool:
        """Partial order: self ⊑ other (pointwise)."""
        for k, v in self._map.items():
            v2 = other._map.get(k, AbstractValue.top())
            if not v.leq(v2):
                return False
        return True

    # -- Iteration / introspection -------------------------------------------

    def locations(self) -> FrozenSet[MemoryLocation]:
        return frozenset(self._map.keys())

    def items(self) -> Iterator[Tuple[MemoryLocation, AbstractValue]]:
        return iter(self._map.items())

    def __len__(self) -> int:
        return len(self._map)

    def __contains__(self, loc: MemoryLocation) -> bool:
        return loc in self._map

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, AbstractStore):
            return NotImplemented
        return self._map == other._map

    def __hash__(self) -> int:
        if self._hash_cache is None:
            self._hash_cache = hash(frozenset(self._map.items()))
        return self._hash_cache

    def __repr__(self) -> str:
        entries = ", ".join(f"{k}: {v}" for k, v in sorted(
            self._map.items(), key=lambda kv: str(kv[0])
        ))
        return f"Store({{{entries}}})"


# ---------------------------------------------------------------------------
# 3. Stack Frame
# ---------------------------------------------------------------------------

@dataclass
class StackFrame:
    """
    Represents one activation record on the abstract call stack.

    Contains the local store (local variables and parameters) plus
    metadata about the call site.
    """
    function_name: str
    function_id: Optional[str]            # Cppcheck Function.Id
    scope_id: Optional[str]               # Cppcheck Scope.Id of function body
    call_site_token_id: Optional[str]     # Token.Id of the call site (None for entry)
    locals: Dict[str, MemoryLocation]     # variable_id → MemoryLocation
    return_loc: Optional[MemoryLocation]  # Where to write the return value

    def __repr__(self) -> str:
        return (f"Frame({self.function_name}, "
                f"locals={len(self.locals)}, "
                f"call_site={self.call_site_token_id})")


# ---------------------------------------------------------------------------
# 4. Heap Metadata
# ---------------------------------------------------------------------------

class HeapStatus(enum.Enum):
    """Lifecycle state of a heap allocation."""
    ALLOCATED   = "allocated"
    FREED       = "freed"
    REALLOC     = "reallocated"  # Original block freed by realloc
    ESCAPED     = "escaped"      # Pointer escaped analysis scope
    UNKNOWN     = "unknown"


@dataclass
class HeapBlock:
    """
    Metadata for one abstract heap allocation.
    """
    location: MemoryLocation
    alloc_site: AllocationSite
    status: HeapStatus = HeapStatus.ALLOCATED
    dealloc_site: Optional[AllocationSite] = None  # Where it was freed
    size: Optional[AbstractValue] = None           # Abstract size
    refcount: int = 1                               # Number of live pointers (approximate)
    escaped: bool = False                           # Has the pointer been passed externally

    @property
    def is_live(self) -> bool:
        return self.status == HeapStatus.ALLOCATED

    @property
    def is_freed(self) -> bool:
        return self.status in (HeapStatus.FREED, HeapStatus.REALLOC)

    def __repr__(self) -> str:
        return (f"HeapBlock({self.location.name}, "
                f"status={self.status.value}, "
                f"alloc={self.alloc_site})")


# ---------------------------------------------------------------------------
# 5. Points-To Graph
# ---------------------------------------------------------------------------

class PointsToGraph:
    """
    Flow-insensitive, field-sensitive points-to graph.

    Nodes are MemoryLocations; edges are may-point-to relations.
    An edge (a, b) means the memory cell at *a* may contain a pointer
    to *b*.

    Construction uses Andersen's inclusion-based analysis adapted
    for the Cppcheck data model:
      - Assignment ``p = &x``  →  pts(p) ⊇ {loc(x)}
      - Copy       ``p = q``   →  pts(p) ⊇ pts(q)
      - Load       ``p = *q``  →  ∀r ∈ pts(q): pts(p) ⊇ pts(r)
      - Store      ``*p = q``  →  ∀r ∈ pts(p): pts(r) ⊇ pts(q)

    The analysis iterates to a fixpoint using a worklist algorithm.
    """

    def __init__(self) -> None:
        # Adjacency: source_loc → set of target_locs
        self._edges: Dict[MemoryLocation, Set[MemoryLocation]] = defaultdict(set)
        # Reverse adjacency (for efficient lookup)
        self._rev_edges: Dict[MemoryLocation, Set[MemoryLocation]] = defaultdict(set)
        # All nodes
        self._nodes: Set[MemoryLocation] = set()

    # -- Mutation (during construction) --------------------------------------

    def add_edge(self, source: MemoryLocation, target: MemoryLocation) -> bool:
        """
        Add a may-point-to edge.  Returns True if the edge was new.
        """
        self._nodes.add(source)
        self._nodes.add(target)
        if target in self._edges[source]:
            return False
        self._edges[source].add(target)
        self._rev_edges[target].add(source)
        return True

    def add_edges(self, source: MemoryLocation, targets: Iterable[MemoryLocation]) -> int:
        """Add multiple edges, return count of new edges."""
        count = 0
        for t in targets:
            if self.add_edge(source, t):
                count += 1
        return count

    # -- Query ---------------------------------------------------------------

    def points_to(self, loc: MemoryLocation) -> FrozenSet[MemoryLocation]:
        """Return the set of locations that *loc* may point to."""
        return frozenset(self._edges.get(loc, set()))

    def pointed_to_by(self, loc: MemoryLocation) -> FrozenSet[MemoryLocation]:
        """Return the set of locations that may point to *loc*."""
        return frozenset(self._rev_edges.get(loc, set()))

    def may_alias(self, a: MemoryLocation, b: MemoryLocation) -> bool:
        """
        Check if two pointers may alias (i.e., their points-to sets intersect).
        """
        pts_a = self._edges.get(a, set())
        pts_b = self._edges.get(b, set())
        return bool(pts_a & pts_b)

    def must_alias(self, a: MemoryLocation, b: MemoryLocation) -> bool:
        """
        Check if two pointers must alias (singleton, equal points-to sets).
        """
        pts_a = self._edges.get(a, set())
        pts_b = self._edges.get(b, set())
        return len(pts_a) == 1 and pts_a == pts_b

    def reachable_from(self, roots: Iterable[MemoryLocation]) -> FrozenSet[MemoryLocation]:
        """BFS: all locations reachable by following points-to edges from roots."""
        visited: Set[MemoryLocation] = set()
        queue = deque(roots)
        while queue:
            loc = queue.popleft()
            if loc in visited:
                continue
            visited.add(loc)
            queue.extend(self._edges.get(loc, set()))
        return frozenset(visited)

    @property
    def nodes(self) -> FrozenSet[MemoryLocation]:
        return frozenset(self._nodes)

    @property
    def num_edges(self) -> int:
        return sum(len(targets) for targets in self._edges.values())

    def __repr__(self) -> str:
        return f"PointsToGraph(nodes={len(self._nodes)}, edges={self.num_edges})"


# ---------------------------------------------------------------------------
# 6. Memory State — Full Abstract State for Analysis
# ---------------------------------------------------------------------------

@dataclass
class MemoryState:
    """
    Complete abstract memory state, combining:
      - store:       AbstractStore (locations → values)
      - call_stack:  list of StackFrames
      - heap_blocks: dict of HeapBlock metadata
      - points_to:   PointsToGraph (shared, may be read-only)

    MemoryState is the unit passed between analysis steps.
    It supports fork/clone for path-sensitive analyses.
    """
    store: AbstractStore = field(default_factory=AbstractStore)
    call_stack: List[StackFrame] = field(default_factory=list)
    heap_blocks: Dict[str, HeapBlock] = field(default_factory=dict)  # base_id → HeapBlock
    points_to: Optional[PointsToGraph] = None

    # -- High-level operations -----------------------------------------------

    def read(self, loc: MemoryLocation) -> AbstractValue:
        """Read from the abstract store."""
        return self.store.read(loc)

    def write(self, loc: MemoryLocation, val: AbstractValue) -> "MemoryState":
        """Write to the abstract store, returning a new state."""
        return MemoryState(
            store=self.store.write(loc, val),
            call_stack=list(self.call_stack),
            heap_blocks=dict(self.heap_blocks),
            points_to=self.points_to,
        )

    def allocate(
        self,
        alloc_site: AllocationSite,
        size: Optional[AbstractValue] = None,
        name: Optional[str] = None,
    ) -> Tuple["MemoryState", MemoryLocation]:
        """
        Model a heap allocation.  Returns (new_state, new_location).
        """
        loc = MemoryLocation(
            kind=LocationKind.HEAP,
            base_id=f"heap_{alloc_site.token_id or 'unknown'}",
            alloc_site=alloc_site,
            name=name or f"heap@{alloc_site.line}",
        )
        block = HeapBlock(
            location=loc,
            alloc_site=alloc_site,
            status=HeapStatus.ALLOCATED,
            size=size,
        )
        new_blocks = dict(self.heap_blocks)
        new_blocks[loc.base_id] = block

        # For calloc, initialize to zero; for malloc, mark as uninit
        if alloc_site.allocator == AllocatorKind.CALLOC:
            new_store = self.store.write(loc, AbstractValue.from_int(0))
        else:
            new_store = self.store.write(loc, AbstractValue.uninit())

        return MemoryState(
            store=new_store,
            call_stack=list(self.call_stack),
            heap_blocks=new_blocks,
            points_to=self.points_to,
        ), loc

    def deallocate(
        self,
        loc: MemoryLocation,
        dealloc_site: Optional[AllocationSite] = None,
    ) -> Tuple["MemoryState", Optional[str]]:
        """
        Model a deallocation (free/delete).
        Returns (new_state, error_message_or_None).
        """
        error: Optional[str] = None

        if loc.is_null:
            # free(NULL) is a no-op in C
            return self, None

        block = self.heap_blocks.get(loc.base_id)
        if block is None:
            error = f"Freeing non-heap memory: {loc}"
            return self, error

        if block.status == HeapStatus.FREED:
            error = f"Double free: {loc} (previously freed at {block.dealloc_site})"
            return self, error

        # Check allocator/deallocator match
        if dealloc_site and block.alloc_site:
            valid_deallocs = ALLOC_DEALLOC_MATCH.get(
                block.alloc_site.allocator, frozenset()
            )
            if dealloc_site.allocator != AllocatorKind.UNKNOWN:
                dealloc_kind = _allocator_to_deallocator(dealloc_site.allocator)
                if dealloc_kind and dealloc_kind not in valid_deallocs:
                    error = (f"Mismatched deallocation: {loc} allocated with "
                             f"{block.alloc_site.allocator.value} but freed with "
                             f"{dealloc_kind.value}")

        new_blocks = dict(self.heap_blocks)
        new_blocks[loc.base_id] = HeapBlock(
            location=block.location,
            alloc_site=block.alloc_site,
            status=HeapStatus.FREED,
            dealloc_site=dealloc_site,
            size=block.size,
            refcount=0,
            escaped=block.escaped,
        )
        new_store = self.store.write(loc, AbstractValue.freed())

        return MemoryState(
            store=new_store,
            call_stack=list(self.call_stack),
            heap_blocks=new_blocks,
            points_to=self.points_to,
        ), error

    def push_frame(self, frame: StackFrame) -> "MemoryState":
        """Push a new call frame onto the stack."""
        new_stack = list(self.call_stack) + [frame]
        return MemoryState(
            store=self.store,
            call_stack=new_stack,
            heap_blocks=dict(self.heap_blocks),
            points_to=self.points_to,
        )

    def pop_frame(self) -> Tuple["MemoryState", Optional[StackFrame]]:
        """Pop the top call frame, returning (new_state, popped_frame)."""
        if not self.call_stack:
            return self, None
        frame = self.call_stack[-1]
        new_stack = self.call_stack[:-1]
        # Kill all locals of the popped frame
        locals_to_kill = set(frame.locals.values())
        new_store = self.store.kill_many(locals_to_kill)
        return MemoryState(
            store=new_store,
            call_stack=new_stack,
            heap_blocks=dict(self.heap_blocks),
            points_to=self.points_to,
        ), frame

    @property
    def current_frame(self) -> Optional[StackFrame]:
        return self.call_stack[-1] if self.call_stack else None

    def find_leaks(self) -> List[HeapBlock]:
        """
        Find heap blocks that are still allocated but no longer reachable
        from any live pointer in the store.
        """
        leaks: List[HeapBlock] = []
        # Collect all pointer targets reachable from the store
        reachable_bases: Set[str] = set()
        for loc, val in self.store.items():
            if val.kind in _POINTER_KINDS:
                for target in val.points_to:
                    if target.kind == LocationKind.HEAP:
                        reachable_bases.add(target.base_id)

        for base_id, block in self.heap_blocks.items():
            if block.is_live and base_id not in reachable_bases and not block.escaped:
                leaks.append(block)
        return leaks

    def clone(self) -> "MemoryState":
        """Deep copy for path forking."""
        return MemoryState(
            store=AbstractStore(dict(self.store._map)),
            call_stack=[StackFrame(
                function_name=f.function_name,
                function_id=f.function_id,
                scope_id=f.scope_id,
                call_site_token_id=f.call_site_token_id,
                locals=dict(f.locals),
                return_loc=f.return_loc,
            ) for f in self.call_stack],
            heap_blocks={k: HeapBlock(
                location=v.location,
                alloc_site=v.alloc_site,
                status=v.status,
                dealloc_site=v.dealloc_site,
                size=v.size,
                refcount=v.refcount,
                escaped=v.escaped,
            ) for k, v in self.heap_blocks.items()},
            points_to=self.points_to,  # shared (read-only after construction)
        )

    def join(self, other: "MemoryState") -> "MemoryState":
        """Join two memory states (for merge points in CFG)."""
        joined_store = self.store.join(other.store)
        # Merge heap blocks conservatively
        merged_blocks: Dict[str, HeapBlock] = {}
        all_ids = set(self.heap_blocks.keys()) | set(other.heap_blocks.keys())
        for bid in all_ids:
            b1 = self.heap_blocks.get(bid)
            b2 = other.heap_blocks.get(bid)
            if b1 and b2:
                # If status disagrees, conservatively mark allocated
                # (a leak check later will catch if one path freed it)
                status = b1.status if b1.status == b2.status else HeapStatus.ALLOCATED
                merged_blocks[bid] = HeapBlock(
                    location=b1.location,
                    alloc_site=b1.alloc_site,
                    status=status,
                    dealloc_site=b1.dealloc_site if b1.status == b2.status else None,
                    size=b1.size,  # approximate
                    refcount=max(b1.refcount, b2.refcount),
                    escaped=b1.escaped or b2.escaped,
                )
            elif b1:
                merged_blocks[bid] = b1
            elif b2:
                merged_blocks[bid] = b2
        # Use the longer call stack (they should match at merge points)
        stack = self.call_stack if len(self.call_stack) >= len(other.call_stack) else other.call_stack
        return MemoryState(
            store=joined_store,
            call_stack=list(stack),
            heap_blocks=merged_blocks,
            points_to=self.points_to,
        )

    def __repr__(self) -> str:
        return (f"MemoryState(store={len(self.store)} locs, "
                f"stack_depth={len(self.call_stack)}, "
                f"heap_blocks={len(self.heap_blocks)})")


def _allocator_to_deallocator(alloc: AllocatorKind) -> Optional[DeallocatorKind]:
    """Infer expected deallocator from the allocator function name."""
    mapping = {
        AllocatorKind.MALLOC: DeallocatorKind.FREE,
        AllocatorKind.CALLOC: DeallocatorKind.FREE,
        AllocatorKind.REALLOC: DeallocatorKind.FREE,
        AllocatorKind.STRDUP: DeallocatorKind.FREE,
        AllocatorKind.NEW: DeallocatorKind.DELETE,
        AllocatorKind.NEW_ARRAY: DeallocatorKind.DELETE_ARRAY,
    }
    return mapping.get(alloc)


# ---------------------------------------------------------------------------
# 7. Location Factory — Builds MemoryLocations from Cppcheck Objects
# ---------------------------------------------------------------------------

class LocationFactory:
    """
    Creates and caches MemoryLocation objects from Cppcheck data model
    elements (Variable, Token, Scope, etc.).

    Each Variable gets at most one MemoryLocation.  Each allocation
    site (identified by Token.Id) gets at most one MemoryLocation.
    """

    def __init__(self) -> None:
        self._var_cache: Dict[str, MemoryLocation] = {}       # Variable.Id → loc
        self._alloc_cache: Dict[str, MemoryLocation] = {}     # Token.Id → loc
        self._return_cache: Dict[str, MemoryLocation] = {}    # Function.Id → return loc
        self._counter = itertools.count(0)

    def for_variable(self, variable) -> MemoryLocation:
        """
        Create/retrieve the MemoryLocation for a cppcheckdata.Variable.
        """
        vid = variable.Id
        if vid in self._var_cache:
            return self._var_cache[vid]

        if variable.isGlobal:
            kind = LocationKind.GLOBAL
        elif variable.isArgument:
            kind = LocationKind.ARGUMENT
        else:
            kind = LocationKind.LOCAL

        name_str = variable.nameToken.str if variable.nameToken else f"var_{vid}"

        loc = MemoryLocation(
            kind=kind,
            base_id=f"var_{vid}",
            variable_id=vid,
            scope_id=variable.scopeId if hasattr(variable, "scopeId") else None,
            name=name_str,
        )
        self._var_cache[vid] = loc
        return loc

    def for_allocation(self, token, allocator: AllocatorKind = AllocatorKind.UNKNOWN) -> MemoryLocation:
        """
        Create/retrieve the MemoryLocation for a heap allocation at *token*.
        """
        tid = token.Id
        if tid in self._alloc_cache:
            return self._alloc_cache[tid]

        site = AllocationSite(
            token_id=tid,
            file=getattr(token, "file", None),
            line=getattr(token, "linenr", None),
            column=getattr(token, "column", None),
            allocator=allocator,
            label=f"{allocator.value}@{getattr(token, 'file', '?')}:{getattr(token, 'linenr', '?')}",
        )
        loc = MemoryLocation(
            kind=LocationKind.HEAP,
            base_id=f"heap_{tid}",
            alloc_site=site,
            name=site.label,
        )
        self._alloc_cache[tid] = loc
        return loc

    def for_return(self, function) -> MemoryLocation:
        """
        Create/retrieve the return-value location for a function.
        """
        fid = function.Id
        if fid in self._return_cache:
            return self._return_cache[fid]

        loc = MemoryLocation(
            kind=LocationKind.RETURN,
            base_id=f"ret_{fid}",
            name=f"return({function.name})" if function.name else f"return({fid})",
        )
        self._return_cache[fid] = loc
        return loc

    def for_string_literal(self, token) -> MemoryLocation:
        """
        Create a location representing a string literal's storage.
        """
        return MemoryLocation(
            kind=LocationKind.STRING_LIT,
            base_id=f"strlit_{token.Id}",
            name=f'"{token.str}"' if token.str else f"strlit_{token.Id}",
        )

    def fresh(self, kind: LocationKind = LocationKind.UNKNOWN, name: Optional[str] = None) -> MemoryLocation:
        """Create a fresh, unique memory location."""
        idx = next(self._counter)
        return MemoryLocation(
            kind=kind,
            base_id=f"fresh_{idx}",
            name=name or f"fresh_{idx}",
        )


# ---------------------------------------------------------------------------
# 8. May-Mod Analysis — Function Side-Effect Inference
# ---------------------------------------------------------------------------

class MayModAnalysis:
    """
    Flow-insensitive may-modify analysis.

    For each function f, computes the set of MemoryLocations that f
    (or any function transitively called by f) may write to.

    This corresponds to the analysis described in the static analysis
    literature (§3.1): "we find the side effects of every function f,
    i.e., the set of possible locations ... that the function itself
    or any function that it may (transitively) invoke, may modify."

    The analysis uses the points-to graph to resolve pointer writes.
    """

    def __init__(
        self,
        points_to: PointsToGraph,
        location_factory: LocationFactory,
    ) -> None:
        self._ptg = points_to
        self._loc_factory = location_factory
        # function_id → set of locations that function may modify
        self._may_mod: Dict[str, Set[MemoryLocation]] = defaultdict(set)
        # function_id → set of function_ids it may call
        self._call_edges: Dict[str, Set[str]] = defaultdict(set)
        self._solved = False

    def add_direct_mod(self, function_id: str, loc: MemoryLocation) -> None:
        """Record that *function_id* directly modifies *loc*."""
        self._may_mod[function_id].add(loc)
        # If loc is a pointer, and there's a store through it,
        # also add everything it may point to
        for target in self._ptg.points_to(loc):
            self._may_mod[function_id].add(target)

    def add_call_edge(self, caller_id: str, callee_id: str) -> None:
        """Record that *caller_id* may call *callee_id*."""
        self._call_edges[caller_id].add(callee_id)

    def solve(self) -> None:
        """
        Compute the transitive closure of may-modify sets.

        Uses a worklist algorithm: propagate callee's may-mod sets
        upward to callers until fixpoint.
        """
        # Build reverse call graph
        callers_of: Dict[str, Set[str]] = defaultdict(set)
        for caller, callees in self._call_edges.items():
            for callee in callees:
                callers_of[callee].add(caller)

        # Worklist: start with all functions
        worklist: deque = deque(self._may_mod.keys())
        in_worklist: Set[str] = set(worklist)

        while worklist:
            fid = worklist.popleft()
            in_worklist.discard(fid)

            # Collect may-mod from callees
            old_size = len(self._may_mod[fid])
            for callee_id in self._call_edges.get(fid, set()):
                self._may_mod[fid] |= self._may_mod.get(callee_id, set())

            # If changed, re-process callers
            if len(self._may_mod[fid]) > old_size:
                for caller_id in callers_of.get(fid, set()):
                    if caller_id not in in_worklist:
                        worklist.append(caller_id)
                        in_worklist.add(caller_id)

        self._solved = True

    def may_modify(self, function_id: str) -> FrozenSet[MemoryLocation]:
        """Return the set of locations that *function_id* may modify."""
        if not self._solved:
            self.solve()
        return frozenset(self._may_mod.get(function_id, set()))

    def may_modify_location(self, function_id: str, loc: MemoryLocation) -> bool:
        """Check if *function_id* may modify *loc*."""
        return loc in self.may_modify(function_id)

    def __repr__(self) -> str:
        total = sum(len(v) for v in self._may_mod.values())
        return f"MayModAnalysis(functions={len(self._may_mod)}, total_mods={total})"


# ---------------------------------------------------------------------------
# 9. Points-To Graph Builder — Andersen-style Analysis on Cppcheck Tokens
# ---------------------------------------------------------------------------

# Known allocator / deallocator function names
_ALLOCATORS: Dict[str, AllocatorKind] = {
    "malloc":  AllocatorKind.MALLOC,
    "calloc":  AllocatorKind.CALLOC,
    "realloc": AllocatorKind.REALLOC,
    "strdup":  AllocatorKind.STRDUP,
    "strndup": AllocatorKind.STRDUP,
    "alloca":  AllocatorKind.STACK,
    # C++ (textual matching; actual new expressions are operators)
}

_DEALLOCATORS: Dict[str, DeallocatorKind] = {
    "free":    DeallocatorKind.FREE,
    "realloc": DeallocatorKind.REALLOC,
}


class PointsToBuilder:
    """
    Builds a PointsToGraph from a Cppcheck Configuration using
    Andersen's inclusion-based analysis.

    The algorithm:
      1. Scan all tokens to collect constraints:
         - Address-of:  p = &x      → pts(p) ⊇ {x}
         - Copy:        p = q       → pts(p) ⊇ pts(q)
         - Load:        p = *q      → ∀r ∈ pts(q): pts(p) ⊇ pts(r)
         - Store:       *p = q      → ∀r ∈ pts(p): pts(r) ⊇ pts(q)
         - Alloc:       p = malloc  → pts(p) ⊇ {heap_site}
      2. Iterate to fixpoint using a worklist.
    """

    # Constraint kinds
    _ADDR_OF = 0   # pts(dst) ⊇ {src}
    _COPY    = 1   # pts(dst) ⊇ pts(src)
    _LOAD    = 2   # pts(dst) ⊇ pts(*src)
    _STORE   = 3   # pts(*dst) ⊇ pts(src)

    def __init__(self, cfg_data, location_factory: Optional[LocationFactory] = None) -> None:
        self._cfg = cfg_data
        self._loc_factory = location_factory or LocationFactory()
        self._constraints: List[Tuple[int, MemoryLocation, MemoryLocation]] = []
        self._graph = PointsToGraph()

    @property
    def location_factory(self) -> LocationFactory:
        return self._loc_factory

    def build(self) -> PointsToGraph:
        """Run the full analysis and return the points-to graph."""
        self._collect_constraints()
        self._solve_constraints()
        return self._graph

    def _var_loc(self, variable) -> MemoryLocation:
        """Get MemoryLocation for a cppcheckdata Variable."""
        return self._loc_factory.for_variable(variable)

    def _collect_constraints(self) -> None:
        """
        Scan the token list and extract points-to constraints.
        """
        for token in self._cfg.tokenlist:
            # Skip non-AST-root tokens (we process from AST roots)
            if token.astParent is not None:
                continue
            self._collect_from_ast(token)

    def _collect_from_ast(self, token) -> None:
        """Recursively collect constraints from an AST subtree."""
        if token is None:
            return

        # Process children first (bottom-up)
        self._collect_from_ast(token.astOperand1)
        self._collect_from_ast(token.astOperand2)

        # Assignment: lhs = rhs
        if token.isAssignmentOp and token.str == "=":
            lhs = token.astOperand1
            rhs = token.astOperand2
            if lhs is None or rhs is None:
                return
            self._process_assignment(lhs, rhs)

        # Variable declaration with initialization
        # (handled via assignment tokens in Cppcheck's normalized form)

        # Function call (allocator detection)
        if (token.str == "(" and token.astOperand1 is not None
                and token.astOperand1.isName):
            func_name = token.astOperand1.str
            if func_name in _ALLOCATORS:
                self._process_allocation(token)

    def _process_assignment(self, lhs, rhs) -> None:
        """
        Process an assignment ``lhs = rhs`` for points-to constraints.
        """
        # Case 1: p = &x (address-of)
        if rhs.str == "&" and rhs.astOperand1 and rhs.astOperand1.variable:
            if lhs.variable:
                src_loc = self._var_loc(rhs.astOperand1.variable)
                dst_loc = self._var_loc(lhs.variable)
                self._constraints.append((self._ADDR_OF, dst_loc, src_loc))
                return

        # Case 2: p = q (pointer copy)
        if lhs.variable and rhs.variable:
            if lhs.variable.isPointer or rhs.variable.isPointer:
                dst_loc = self._var_loc(lhs.variable)
                src_loc = self._var_loc(rhs.variable)
                self._constraints.append((self._COPY, dst_loc, src_loc))
                return

        # Case 3: p = *q (load through pointer)
        if rhs.str == "*" and rhs.astOperand1 and not rhs.astOperand2:
            if rhs.astOperand1.variable and lhs.variable:
                src_loc = self._var_loc(rhs.astOperand1.variable)
                dst_loc = self._var_loc(lhs.variable)
                self._constraints.append((self._LOAD, dst_loc, src_loc))
                return

        # Case 4: *p = q (store through pointer)
        if lhs.str == "*" and lhs.astOperand1 and not lhs.astOperand2:
            if lhs.astOperand1.variable and rhs.variable:
                dst_loc = self._var_loc(lhs.astOperand1.variable)
                src_loc = self._var_loc(rhs.variable)
                self._constraints.append((self._STORE, dst_loc, src_loc))
                return

        # Case 5: p = malloc(...) etc. (handled in _process_allocation)
        # Case 6: p = func_call(...) — conservative: p may point to anything
        #   (We handle this by not adding a constraint, letting p remain top.)

    def _process_allocation(self, call_token) -> None:
        """
        Handle ``p = malloc(size)`` or similar.
        call_token is the '(' token; its astParent might be '='.
        """
        func_name_token = call_token.astOperand1
        if func_name_token is None:
            return
        func_name = func_name_token.str
        alloc_kind = _ALLOCATORS.get(func_name, AllocatorKind.UNKNOWN)

        # Find the assignment target: walk up to find '='
        assign = call_token.astParent
        if assign is None or not assign.isAssignmentOp:
            # Result not captured — potential leak, but no constraint to add
            return

        lhs = assign.astOperand1
        if lhs is None or not lhs.variable:
            return

        heap_loc = self._loc_factory.for_allocation(call_token, alloc_kind)
        dst_loc = self._var_loc(lhs.variable)
        self._constraints.append((self._ADDR_OF, dst_loc, heap_loc))

    def _solve_constraints(self) -> None:
        """
        Solve all collected constraints using a worklist fixpoint.
        """
        # Initialize: process all ADDR_OF constraints immediately
        # Then iterate COPY/LOAD/STORE until fixpoint
        worklist: deque = deque()
        changed_locs: Set[MemoryLocation] = set()

        for kind, dst, src in self._constraints:
            if kind == self._ADDR_OF:
                if self._graph.add_edge(dst, src):
                    changed_locs.add(dst)

        # Seed worklist with all non-ADDR_OF constraints
        complex_constraints = [
            (kind, dst, src)
            for kind, dst, src in self._constraints
            if kind != self._ADDR_OF
        ]

        max_iterations = 100
        for iteration in range(max_iterations):
            any_change = False

            for kind, dst, src in complex_constraints:
                if kind == self._COPY:
                    # pts(dst) ⊇ pts(src)
                    src_pts = self._graph.points_to(src)
                    if self._graph.add_edges(dst, src_pts) > 0:
                        any_change = True

                elif kind == self._LOAD:
                    # pts(dst) ⊇ ⋃{pts(r) | r ∈ pts(src)}
                    for r in self._graph.points_to(src):
                        if self._graph.add_edges(dst, self._graph.points_to(r)) > 0:
                            any_change = True

                elif kind == self._STORE:
                    # ∀r ∈ pts(dst): pts(r) ⊇ pts(src)
                    src_pts = self._graph.points_to(src)
                    for r in self._graph.points_to(dst):
                        if self._graph.add_edges(r, src_pts) > 0:
                            any_change = True

            if not any_change:
                break


# ---------------------------------------------------------------------------
# 10. MemoryModel — Top-Level Facade
# ---------------------------------------------------------------------------

class MemoryModel:
    """
    Top-level facade that integrates all components of the memory
    abstraction.

    Usage::

        model = MemoryModel(cfg_data)
        model.build()

        # Access sub-components
        ptg = model.points_to_graph
        may_mod = model.may_mod_analysis
        factory = model.location_factory

        # Build initial state for a function
        state = model.initial_state(function_scope)

        # Check for issues
        alloc_sites = model.find_allocation_sites()
        dealloc_sites = model.find_deallocation_sites()
    """

    def __init__(self, cfg_data) -> None:
        self._cfg = cfg_data
        self._location_factory = LocationFactory()
        self._points_to_graph: Optional[PointsToGraph] = None
        self._may_mod: Optional[MayModAnalysis] = None
        self._alloc_sites: Optional[List[Tuple[AllocationSite, Any]]] = None   # (site, token)
        self._dealloc_sites: Optional[List[Tuple[DeallocatorKind, Any]]] = None  # (kind, token)
        self._built = False

    @property
    def location_factory(self) -> LocationFactory:
        return self._location_factory

    @property
    def points_to_graph(self) -> PointsToGraph:
        if self._points_to_graph is None:
            raise RuntimeError("Call build() before accessing points_to_graph")
        return self._points_to_graph

    @property
    def may_mod_analysis(self) -> MayModAnalysis:
        if self._may_mod is None:
            raise RuntimeError("Call build() before accessing may_mod_analysis")
        return self._may_mod

    def build(self) -> "MemoryModel":
        """
        Run all analyses: points-to, may-mod, allocation/deallocation site detection.
        Returns self for chaining.
        """
        # Phase 1: Points-to graph
        ptb = PointsToBuilder(self._cfg, self._location_factory)
        self._points_to_graph = ptb.build()

        # Phase 2: May-mod analysis
        self._may_mod = MayModAnalysis(self._points_to_graph, self._location_factory)
        self._build_may_mod()

        # Phase 3: Collect allocation / deallocation sites
        self._alloc_sites = []
        self._dealloc_sites = []
        self._scan_alloc_dealloc()

        self._built = True
        return self

    def _build_may_mod(self) -> None:
        """
        Scan all functions and populate the may-mod analysis with
        direct modification and call-edge information.
        """
        assert self._may_mod is not None

        # Build a map: scope_id → function_id
        scope_to_func: Dict[str, str] = {}
        for func in self._cfg.functions:
            if func.Id:
                # The function's body scope
                for scope in self._cfg.scopes:
                    if scope.functionId == func.Id:
                        scope_to_func[scope.Id] = func.Id
                        break

        for token in self._cfg.tokenlist:
            if token.scope is None:
                continue

            # Determine which function this token is in
            func_id = scope_to_func.get(token.scopeId)
            if func_id is None:
                # Walk up nested scopes
                scope = token.scope
                while scope:
                    fid = scope_to_func.get(scope.Id)
                    if fid:
                        func_id = fid
                        break
                    scope = scope.nestedIn
            if func_id is None:
                continue

            # Direct modifications: assignments
            if token.isAssignmentOp and token.astOperand1 and token.astOperand1.variable:
                loc = self._location_factory.for_variable(token.astOperand1.variable)
                self._may_mod.add_direct_mod(func_id, loc)

            # Store through pointer: *p = ...
            if (token.isAssignmentOp and token.astOperand1
                    and token.astOperand1.str == "*"
                    and token.astOperand1.astOperand1
                    and token.astOperand1.astOperand1.variable):
                ptr_loc = self._location_factory.for_variable(
                    token.astOperand1.astOperand1.variable
                )
                self._may_mod.add_direct_mod(func_id, ptr_loc)

            # Function calls: add call edges
            if (token.isName and token.function
                    and token.next and token.next.str == "("):
                callee_id = token.function.Id
                if callee_id:
                    self._may_mod.add_call_edge(func_id, callee_id)

        self._may_mod.solve()

    def _scan_alloc_dealloc(self) -> None:
        """Scan for allocation and deallocation call sites."""
        assert self._alloc_sites is not None
        assert self._dealloc_sites is not None

        for token in self._cfg.tokenlist:
            if not token.isName:
                continue
            if token.next is None or token.next.str != "(":
                continue

            name = token.str
            if name in _ALLOCATORS:
                site = AllocationSite(
                    token_id=token.Id,
                    file=token.file,
                    line=token.linenr,
                    column=token.column,
                    allocator=_ALLOCATORS[name],
                    label=f"{name}@{token.file}:{token.linenr}",
                )
                self._alloc_sites.append((site, token))

            if name in _DEALLOCATORS:
                self._dealloc_sites.append((_DEALLOCATORS[name], token))

    def find_allocation_sites(self) -> List[Tuple[AllocationSite, Any]]:
        """Return all detected allocation sites as (AllocationSite, token) pairs."""
        if self._alloc_sites is None:
            raise RuntimeError("Call build() first")
        return list(self._alloc_sites)

    def find_deallocation_sites(self) -> List[Tuple[DeallocatorKind, Any]]:
        """Return all detected deallocation sites as (DeallocatorKind, token) pairs."""
        if self._dealloc_sites is None:
            raise RuntimeError("Call build() first")
        return list(self._dealloc_sites)

    def initial_state(self, function_scope=None) -> MemoryState:
        """
        Create an initial MemoryState for analysis.

        If *function_scope* is provided (a cppcheckdata Scope with
        type="Function"), the state includes the function's parameters
        and local variables in the store.
        """
        store = AbstractStore()
        frame_locals: Dict[str, MemoryLocation] = {}

        if function_scope is not None:
            # Initialize global variables
            for var in self._cfg.variables:
                if var.isGlobal:
                    loc = self._location_factory.for_variable(var)
                    store = store.write(loc, AbstractValue.top())

            # Initialize function parameters
            func = function_scope.function
            if func:
                for arg_nr, arg_var in func.argument.items():
                    if arg_var:
                        loc = self._location_factory.for_variable(arg_var)
                        # Parameters start as symbolic (unconstrained) values
                        if arg_var.isPointer:
                            store = store.write(loc, AbstractValue.maybe_null())
                        else:
                            store = store.write(loc, AbstractValue.top())
                        frame_locals[arg_var.Id] = loc

            # Initialize local variables as uninitialized
            for var in function_scope.varlist:
                loc = self._location_factory.for_variable(var)
                store = store.write(loc, AbstractValue.uninit())
                frame_locals[var.Id] = loc

        frame = StackFrame(
            function_name=function_scope.className if function_scope else "<global>",
            function_id=function_scope.functionId if function_scope else None,
            scope_id=function_scope.Id if function_scope else None,
            call_site_token_id=None,
            locals=frame_locals,
            return_loc=self._location_factory.for_return(function_scope.function)
                       if function_scope and function_scope.function else None,
        )

        return MemoryState(
            store=store,
            call_stack=[frame],
            heap_blocks={},
            points_to=self._points_to_graph,
        )

    def location_for_variable(self, variable) -> MemoryLocation:
        """Get or create the MemoryLocation for a Variable."""
        return self._location_factory.for_variable(variable)

    def location_for_token(self, token) -> Optional[MemoryLocation]:
        """
        Get the MemoryLocation for a token, if it refers to a variable.
        Returns None for non-variable tokens.
        """
        if token.variable:
            return self._location_factory.for_variable(token.variable)
        return None

    def __repr__(self) -> str:
        if not self._built:
            return "MemoryModel(not built)"
        return (f"MemoryModel(ptg={self._points_to_graph}, "
                f"may_mod={self._may_mod}, "
                f"alloc_sites={len(self._alloc_sites or [])}, "
                f"dealloc_sites={len(self._dealloc_sites or [])})")


# ---------------------------------------------------------------------------
# 11. Convenience Functions
# ---------------------------------------------------------------------------

def build_memory_model(cfg_data) -> MemoryModel:
    """
    One-liner to build a complete memory model from a Cppcheck Configuration.

    Usage::

        model = build_memory_model(cfg)
        ptg = model.points_to_graph
    """
    return MemoryModel(cfg_data).build()


def find_pointer_issues(cfg_data) -> List[Dict[str, Any]]:
    """
    High-level convenience function: scan a Configuration for common
    pointer-related issues.

    Returns a list of dicts with keys:
        - 'kind':    'null_deref' | 'use_after_free' | 'double_free' |
                     'leak' | 'mismatched_dealloc' | 'uninitialized'
        - 'token':   The Cppcheck Token where the issue was detected
        - 'message': Human-readable description
        - 'severity': 'error' | 'warning' | 'style'
    """
    issues: List[Dict[str, Any]] = []
    model = build_memory_model(cfg_data)

    # -- Check for use of uninitialized pointers --
    for var in cfg_data.variables:
        if not var.isPointer:
            continue
        if var.isArgument or var.isGlobal or var.isExtern:
            continue
        loc = model.location_for_variable(var)

        # Find first use after declaration
        if var.nameToken:
            tok = var.nameToken.next
            found_assignment = False
            while tok:
                if tok.variable == var:
                    if tok.astParent and tok.astParent.isAssignmentOp:
                        lhs = tok.astParent.astOperand1
                        if lhs and lhs.variable == var:
                            found_assignment = True
                            break
                    # Used before assignment
                    if not found_assignment:
                        issues.append({
                            "kind": "uninitialized",
                            "token": tok,
                            "message": f"Pointer '{var.nameToken.str}' used before initialization",
                            "severity": "warning",
                        })
                        break
                tok = tok.next

    # -- Check allocator/deallocator matching --
    alloc_map: Dict[str, Tuple[AllocatorKind, Any]] = {}  # var_id → (allocator, token)

    for site, token in model.find_allocation_sites():
        # Find the variable assigned to
        assign = token.astParent
        if assign is None:
            continue
        # Walk up past the '(' to find '='
        while assign and not assign.isAssignmentOp:
            assign = assign.astParent
        if assign and assign.astOperand1 and assign.astOperand1.variable:
            vid = assign.astOperand1.variable.Id
            alloc_map[vid] = (site.allocator, token)

    for dealloc_kind, token in model.find_deallocation_sites():
        # Find the argument to free/delete
        if token.next and token.next.str == "(":
            arg_tok = token.next.astOperand2
            if arg_tok is None:
                # Try astOperand1 for single-arg calls
                arg_tok = token.next.astOperand1
            if arg_tok and arg_tok.variable:
                vid = arg_tok.variable.Id
                if vid in alloc_map:
                    alloc_kind, alloc_tok = alloc_map[vid]
                    valid = ALLOC_DEALLOC_MATCH.get(alloc_kind, frozenset())
                    if dealloc_kind not in valid and valid:
                        issues.append({
                            "kind": "mismatched_dealloc",
                            "token": token,
                            "message": (
                                f"Mismatched deallocation: allocated with "
                                f"'{alloc_kind.value}' at line {alloc_tok.linenr}, "
                                f"freed with '{dealloc_kind.value}'"
                            ),
                            "severity": "error",
                        })

    return issues


def check_null_after_alloc(cfg_data) -> List[Dict[str, Any]]:
    """
    Check if return values of malloc/calloc/realloc are tested for NULL
    before use.

    Returns a list of issue dicts.
    """
    issues: List[Dict[str, Any]] = []
    model = build_memory_model(cfg_data)

    for site, alloc_token in model.find_allocation_sites():
        if site.allocator not in (AllocatorKind.MALLOC, AllocatorKind.CALLOC,
                                  AllocatorKind.REALLOC, AllocatorKind.STRDUP):
            continue

        # Find the variable the result is assigned to
        assign = alloc_token.astParent
        while assign and not assign.isAssignmentOp:
            assign = assign.astParent
        if not assign or not assign.astOperand1:
            continue
        lhs = assign.astOperand1
        if not lhs.variable:
            continue

        target_var = lhs.variable
        target_var_id = target_var.varId

        # Scan forward from the allocation for:
        #   1. A null check (comparison with NULL/0)
        #   2. A dereference
        tok = assign.next if assign.next else assign
        has_null_check = False
        scope_depth = 0

        while tok:
            # Track scope depth to avoid going too far
            if tok.str == "{":
                scope_depth += 1
            elif tok.str == "}":
                scope_depth -= 1
                if scope_depth < -1:
                    break

            # Check for null comparison
            if (tok.isComparisonOp
                    and tok.astOperand1 and tok.astOperand2):
                op1 = tok.astOperand1
                op2 = tok.astOperand2
                checks_var = ((op1.varId == target_var_id)
                              or (op2.varId == target_var_id))
                checks_null = (
                    (op1.str in ("0", "NULL", "nullptr"))
                    or (op2.str in ("0", "NULL", "nullptr"))
                    or (op1.isNumber and op1.getKnownIntValue() == 0)
                    or (op2.isNumber and op2.getKnownIntValue() == 0)
                )
                if checks_var and checks_null:
                    has_null_check = True
                    break

            # Check for dereference before null check
            if tok.str == "*" and tok.astOperand1 and not tok.astOperand2:
                if tok.astOperand1.varId == target_var_id:
                    if not has_null_check:
                        issues.append({
                            "kind": "null_deref",
                            "token": tok,
                            "message": (
                                f"Pointer '{target_var.nameToken.str}' dereferenced "
                                f"without null check after {site.allocator.value}() "
                                f"at line {alloc_token.linenr}"
                            ),
                            "severity": "warning",
                        })
                    break

            # Check for array access p[i] before null check
            if tok.str == "[" and tok.astOperand1:
                if tok.astOperand1.varId == target_var_id:
                    if not has_null_check:
                        issues.append({
                            "kind": "null_deref",
                            "token": tok,
                            "message": (
                                f"Pointer '{target_var.nameToken.str}' used in "
                                f"array access without null check after "
                                f"{site.allocator.value}() at line {alloc_token.linenr}"
                            ),
                            "severity": "warning",
                        })
                    break

            # Stop at reassignment
            if (tok.isAssignmentOp and tok.astOperand1
                    and tok.astOperand1.varId == target_var_id):
                break

            # Stop at function boundary
            if tok.scope and tok.scope.type == "Function" and tok.str == "}":
                break

            tok = tok.next

    return issues
