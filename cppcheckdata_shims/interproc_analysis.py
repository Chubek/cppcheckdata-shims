"""
cppcheckdata_shims/interproc_analysis.py
=========================================

Interprocedural analysis framework for C/C++ programs via Cppcheck dump data.

Implements the core ideas from Chapter 8 of Møller & Schwartzbach,
"Static Program Analysis":

  §8.1  Interprocedural Control-Flow Graphs (supergraph construction)
  §8.2  Context-insensitive interprocedural analysis
  §8.3  Context-sensitive analysis with call strings (k-CFA)
  §8.4  Context-sensitive analysis with the functional approach
        (procedure summaries mapping entry states → exit states)

Design principles
-----------------
* **Facade pattern** — orchestrates ctrlflow_graph, callgraph,
  dataflow_analyses, distrib_analysis, and abstract_domains without
  duplicating their logic.
* **Lazy computation & caching** — procedure summaries and per-context
  results are computed on demand and memoised.
* **Pluggable abstract domains** — any lattice that conforms to
  abstract_domains.AbstractDomain can be used.
* **Pluggable transfer functions** — users supply per-statement
  transformers; the framework handles call/return wiring.

Public API (quick reference)
----------------------------
    InterproceduralCFG          — supergraph builder (§8.1)
    ContextInsensitiveAnalysis  — simplest whole-program analysis (§8.2)
    CallStringSensitiveAnalysis — k-CFA context sensitivity (§8.3)
    FunctionalAnalysis          — summary-based optimal precision (§8.4)
    analyze()                   — convenience entry point
    ContextPolicy (enum)        — choose a context-sensitivity strategy
    ProcedureSummary            — cached entry→exit abstract-state map

Typical usage
-------------
    >>> from cppcheckdata_shims.interproc_analysis import (
    ...     analyze, ContextPolicy)
    >>> from cppcheckdata_shims.abstract_domains import SignDomain
    >>> results = analyze(
    ...     cfg_data,                 # Cppcheck dump / raw cfg provider
    ...     domain=SignDomain(),
    ...     transfer=my_sign_xfer,
    ...     policy=ContextPolicy.FUNCTIONAL,
    ... )
    >>> results.query_function("foo")
    {SignState({'x': '+', 'result': '+'}), ...}

References
----------
[MS]  Anders Møller & Michael I. Schwartzbach, "Static Program Analysis",
      Department of Computer Science, Aarhus University, October 2024 revision.
      Chapter 8: Interprocedural Analysis.
[RHS] T. Reps, S. Horwitz, M. Sagiv, "Precise Interprocedural Dataflow
      Analysis via Graph Reachability", POPL 1995.
"""

from __future__ import annotations

import enum
import itertools
import logging
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import (
    Any,
    Callable,
    Deque,
    Dict,
    FrozenSet,
    Generic,
    Hashable,
    Iterable,
    Iterator,
    List,
    Mapping,
    Optional,
    Protocol,
    Sequence,
    Set,
    Tuple,
    TypeVar,
    Union,
    runtime_checkable,
)

# ---------------------------------------------------------------------------
# Internal imports — reuse existing shims; never duplicate their logic.
# ---------------------------------------------------------------------------
try:
    from cppcheckdata_shims import ctrlflow_graph as cfg_mod
    from cppcheckdata_shims import callgraph as cg_mod
    from cppcheckdata_shims import dataflow_analyses as dfa_mod
    from cppcheckdata_shims import distrib_analysis as dist_mod
    from cppcheckdata_shims import abstract_domains as dom_mod
except ImportError:
    # Graceful degradation when running stand-alone or during documentation
    # generation.  Callers that actually invoke analysis will get a clear
    # error at the point of use.
    cfg_mod = None   # type: ignore[assignment]
    cg_mod = None    # type: ignore[assignment]
    dfa_mod = None   # type: ignore[assignment]
    dist_mod = None  # type: ignore[assignment]
    dom_mod = None   # type: ignore[assignment]

__all__ = [
    "ContextPolicy",
    "CallingContext",
    "CallString",
    "FunctionalContext",
    "ProcedureSummary",
    "InterproceduralCFG",
    "InterproceduralAnalysisBase",
    "ContextInsensitiveAnalysis",
    "CallStringSensitiveAnalysis",
    "FunctionalAnalysis",
    "InterproceduralResult",
    "analyze",
]

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Type variables
# ---------------------------------------------------------------------------
S = TypeVar("S")          # abstract State
D = TypeVar("S")          # abstract Domain element
N = TypeVar("N")          # CFG Node id
F = TypeVar("F")          # Function id
C = TypeVar("C")          # Context id (hashable)

_BOTTOM_SENTINEL = object()  # internal marker for ⊥


# ═══════════════════════════════════════════════════════════════════════════
# §0  PROTOCOLS — structural subtyping contracts for pluggable components
# ═══════════════════════════════════════════════════════════════════════════

@runtime_checkable
class AbstractDomainProto(Protocol):
    """Minimal protocol an abstract domain must satisfy.

    Mirrors abstract_domains.AbstractDomain but expressed as a Protocol so
    that third-party lattices work without inheritance.
    """

    def bottom(self) -> Any:
        """Return the bottom element ⊥."""
        ...

    def top(self) -> Any:
        """Return the top element ⊤."""
        ...

    def join(self, a: Any, b: Any) -> Any:
        """Least upper bound (⊔)."""
        ...

    def leq(self, a: Any, b: Any) -> bool:
        """Partial-order test a ⊑ b."""
        ...

    def eq(self, a: Any, b: Any) -> bool:
        """Equality test in the lattice."""
        ...


@runtime_checkable
class TransferFunctionProto(Protocol):
    """Protocol for a per-statement transfer function.

    ``apply(node, state)`` returns the abstract state *after* executing
    the statement represented by *node*, given *state* on entry.
    """

    def apply(self, node: Any, state: Any) -> Any:
        ...


class TransferFnCallable:
    """Adapter that wraps a plain ``(node, state) → state`` callable into
    a :class:`TransferFunctionProto`."""

    __slots__ = ("_fn",)

    def __init__(self, fn: Callable[[Any, Any], Any]) -> None:
        self._fn = fn

    def apply(self, node: Any, state: Any) -> Any:
        return self._fn(node, state)


def _ensure_transfer(
    xfer: Union[TransferFunctionProto, Callable[..., Any]],
) -> TransferFunctionProto:
    """Coerce a callable into a TransferFunctionProto if necessary."""
    if isinstance(xfer, TransferFunctionProto):
        return xfer
    if callable(xfer):
        return TransferFnCallable(xfer)
    raise TypeError(
        f"transfer must be callable or implement TransferFunctionProto, "
        f"got {type(xfer).__name__}"
    )


# ═══════════════════════════════════════════════════════════════════════════
# §1  CONTEXT REPRESENTATIONS  (§8.3 call-strings, §8.4 functional)
# ═══════════════════════════════════════════════════════════════════════════

class ContextPolicy(enum.Enum):
    """Which flavour of context sensitivity to use.

    Members
    -------
    INSENSITIVE
        Merge all calling contexts (§8.2).  Fastest, least precise.
    CALL_STRING
        Distinguish contexts by a bounded call-string of depth *k* (§8.3).
    FUNCTIONAL
        Summary-based approach mapping entry states → exit states (§8.4).
        Optimal precision — equivalent to unlimited inlining.
    """

    INSENSITIVE = "insensitive"
    CALL_STRING = "call_string"
    FUNCTIONAL = "functional"


@dataclass(frozen=True)
class CallingContext:
    """Abstract base for a calling context token.

    Every context is *hashable* and *immutable* so that it can serve as a
    dictionary key in the summary / result caches.
    """

    def extend(self, call_site: Any) -> "CallingContext":
        """Return a new context obtained by *pushing* ``call_site``."""
        raise NotImplementedError

    def truncate(self, k: int) -> "CallingContext":
        """Return a context bounded to depth *k* (for call-string)."""
        raise NotImplementedError


@dataclass(frozen=True)
class InsensitiveContext(CallingContext):
    """Singleton context — every call is analysed in the same context.

    Corresponds to the context-insensitive treatment of §8.2.
    """

    _tag: int = 0  # just a frozen sentinel

    def extend(self, call_site: Any) -> "InsensitiveContext":
        return self  # context never changes

    def truncate(self, k: int) -> "InsensitiveContext":
        return self

    def __repr__(self) -> str:
        return "⊤ctx"


# Module-level singleton
INSENSITIVE_CTX = InsensitiveContext()


@dataclass(frozen=True)
class CallString(CallingContext):
    """A bounded call-string of depth ≤ *k*.

    Internally stored as a *tuple* of call-site identifiers (most recent
    call last), e.g. ``(site_A, site_B)`` means "``A`` called ``B``
    which called the current function".

    Per §8.3, when the string grows beyond *k* the oldest entries are
    discarded (left-truncation).
    """

    sites: Tuple[Any, ...] = ()
    k: int = 1

    # -- construction helpers ------------------------------------------------

    @classmethod
    def empty(cls, k: int = 1) -> "CallString":
        """Create an empty call-string with bound *k*."""
        return cls(sites=(), k=k)

    # -- CallingContext interface --------------------------------------------

    def extend(self, call_site: Any) -> "CallString":
        """Push *call_site* and truncate to *k*."""
        new_sites = (*self.sites, call_site)
        if len(new_sites) > self.k:
            new_sites = new_sites[-self.k:]
        return CallString(sites=new_sites, k=self.k)

    def truncate(self, k: int) -> "CallString":
        return CallString(sites=self.sites[-k:] if k else (), k=k)

    # -- pretty-printing -----------------------------------------------------

    def __repr__(self) -> str:
        inner = ", ".join(str(s) for s in self.sites)
        return f"CS<{inner}>"


@dataclass(frozen=True)
class FunctionalContext(CallingContext):
    """Context for the functional / summary-based approach (§8.4).

    The 'context' is the *abstract entry state* of the function.  Two calls
    to the same function with the same abstract entry state share a single
    summary.
    """

    entry_state: Any = None  # the frozen abstract state at function entry

    def extend(self, call_site: Any) -> "FunctionalContext":
        # For the functional approach the call_site is actually the
        # *abstract state* flowing into the callee; we store it directly.
        return FunctionalContext(entry_state=call_site)

    def truncate(self, k: int) -> "FunctionalContext":
        return self  # not applicable

    def __repr__(self) -> str:
        return f"Fn<{self.entry_state!r}>"


# ═══════════════════════════════════════════════════════════════════════════
# §2  INTERPROCEDURAL CFG (SUPERGRAPH)  — §8.1
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class ICFGEdge:
    """An edge in the interprocedural CFG (supergraph).

    Attributes
    ----------
    src, dst : Any
        Source and destination node identifiers.
    kind : str
        One of ``"intra"``, ``"call"``, ``"return"``, ``"call-to-return"``
        (the last models local state that survives across calls).
    call_site : Any | None
        For ``"call"`` and ``"return"`` edges, the call-site identifier.
    """

    src: Any
    dst: Any
    kind: str = "intra"
    call_site: Optional[Any] = None

    def __repr__(self) -> str:
        tag = f" @{self.call_site}" if self.call_site is not None else ""
        return f"({self.src})--[{self.kind}{tag}]-->({self.dst})"


@dataclass
class ICFGNode:
    """A node in the supergraph.

    Attributes
    ----------
    nid : Any
        Unique node id (typically ``(function_id, local_node_id)``).
    function : Any
        Identifier of the enclosing function.
    kind : str
        ``"entry"`` | ``"exit"`` | ``"call"`` | ``"after_call"`` | ``"normal"``
    stmt : Any | None
        Reference to the underlying Cppcheck AST / token node, if any.
    """

    nid: Any
    function: Any
    kind: str = "normal"
    stmt: Optional[Any] = None


class InterproceduralCFG:
    """Interprocedural control-flow graph (supergraph).

    Construction follows §8.1 of [MS]:

    *  Each function's intraprocedural CFG is embedded as-is.
    *  A **call node** $c$ gains:

       - a *call edge* to the callee's **entry** node,
       - a **call-to-return** edge to the **after-call** node $c'$ (to
         propagate caller-local state that the callee cannot touch), and

    *  The callee's **exit** node gains a *return edge* back to $c'$.

    Parameters
    ----------
    cfg_provider
        An object or dict mapping function ids to per-function CFGs
        (``ctrlflow_graph.CFG`` instances or compatible).
    callgraph
        Call-graph object (``callgraph.CallGraph`` or compatible mapping
        caller → [(call_site, callee)]).
    """

    def __init__(
        self,
        cfg_provider: Any,
        callgraph: Any,
    ) -> None:
        # ---- store raw providers ------------------------------------------
        self._cfg_provider = cfg_provider
        self._callgraph_raw = callgraph

        # ---- supergraph storage -------------------------------------------
        self.nodes: Dict[Any, ICFGNode] = {}
        self.edges: List[ICFGEdge] = []
        self._succ: Dict[Any, List[ICFGEdge]] = defaultdict(list)
        self._pred: Dict[Any, List[ICFGEdge]] = defaultdict(list)

        # function → entry/exit node ids
        self._entries: Dict[Any, Any] = {}
        self._exits: Dict[Any, Any] = {}

        # call_site → (call_node_id, after_call_node_id, callee_func_id)
        self._call_info: Dict[Any, Tuple[Any, Any, Any]] = {}

        # ---- build -------------------------------------------------------
        self._build()

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    def _build(self) -> None:
        """Assemble the supergraph from per-function CFGs + call graph."""
        func_cfgs = self._resolve_cfgs()
        call_edges_raw = self._resolve_callgraph()

        # Phase 1: embed each function's CFG
        for fid, local_cfg in func_cfgs.items():
            self._embed_function(fid, local_cfg)

        # Phase 2: wire call / return / call-to-return edges
        for caller_fid, calls in call_edges_raw.items():
            for call_site, callee_fid in calls:
                if callee_fid not in self._entries:
                    logger.debug(
                        "Skipping call to unknown function %s from %s",
                        callee_fid,
                        caller_fid,
                    )
                    continue
                self._wire_call(caller_fid, call_site, callee_fid)

    def _resolve_cfgs(self) -> Dict[Any, Any]:
        """Normalise *cfg_provider* into ``{func_id: cfg}``."""
        if isinstance(self._cfg_provider, dict):
            return dict(self._cfg_provider)
        # Support the ctrlflow_graph module's builder API
        if hasattr(self._cfg_provider, "functions"):
            return {f: self._cfg_provider.get_cfg(f)
                    for f in self._cfg_provider.functions()}
        if hasattr(self._cfg_provider, "items"):
            return dict(self._cfg_provider.items())
        raise TypeError(
            f"Cannot resolve CFG provider of type {type(self._cfg_provider).__name__}"
        )

    def _resolve_callgraph(self) -> Dict[Any, List[Tuple[Any, Any]]]:
        """Normalise *callgraph* into ``{caller: [(call_site, callee)]}``."""
        cg = self._callgraph_raw
        if isinstance(cg, dict):
            return dict(cg)
        # Support callgraph.CallGraph from the shims library
        if hasattr(cg, "callers"):
            result: Dict[Any, List[Tuple[Any, Any]]] = defaultdict(list)
            for caller in cg.callers():
                for site, callee in cg.calls_from(caller):
                    result[caller].append((site, callee))
            return dict(result)
        if hasattr(cg, "items"):
            return dict(cg.items())
        raise TypeError(
            f"Cannot resolve call graph of type {type(cg).__name__}"
        )

    # helpers for unique supergraph node ids
    @staticmethod
    def _nid(func: Any, local: Any) -> Tuple[Any, Any]:
        return (func, local)

    @staticmethod
    def _after_call_nid(func: Any, call_site: Any) -> Tuple[Any, Any, str]:
        return (func, call_site, "after_call")

    def _embed_function(self, fid: Any, local_cfg: Any) -> None:
        """Copy a single function's CFG nodes/edges into the supergraph."""
        nodes, edges, entry, exit_ = self._unpack_cfg(local_cfg)

        entry_nid = self._nid(fid, entry)
        exit_nid = self._nid(fid, exit_)
        self._entries[fid] = entry_nid
        self._exits[fid] = exit_nid

        for n in nodes:
            nid = self._nid(fid, n)
            kind = "entry" if n == entry else (
                "exit" if n == exit_ else "normal")
            stmt_ref = self._node_stmt(local_cfg, n)
            self.nodes[nid] = ICFGNode(nid=nid, function=fid, kind=kind,
                                       stmt=stmt_ref)

        for src, dst in edges:
            e = ICFGEdge(
                src=self._nid(fid, src),
                dst=self._nid(fid, dst),
                kind="intra",
            )
            self.edges.append(e)
            self._succ[e.src].append(e)
            self._pred[e.dst].append(e)

    def _wire_call(
        self, caller_fid: Any, call_site: Any, callee_fid: Any
    ) -> None:
        """Add call / return / call-to-return edges for one call site."""
        call_nid = self._nid(caller_fid, call_site)
        after_nid = self._after_call_nid(caller_fid, call_site)
        callee_entry = self._entries[callee_fid]
        callee_exit = self._exits[callee_fid]

        # Ensure the after-call node exists
        if after_nid not in self.nodes:
            self.nodes[after_nid] = ICFGNode(
                nid=after_nid, function=caller_fid, kind="after_call"
            )

        # Mark the call node
        if call_nid in self.nodes:
            self.nodes[call_nid].kind = "call"

        # --- call edge: call_node → callee entry --------------------------
        ce = ICFGEdge(src=call_nid, dst=callee_entry,
                      kind="call", call_site=call_site)
        self.edges.append(ce)
        self._succ[ce.src].append(ce)
        self._pred[ce.dst].append(ce)

        # --- return edge: callee exit → after_call ------------------------
        re = ICFGEdge(src=callee_exit, dst=after_nid,
                      kind="return", call_site=call_site)
        self.edges.append(re)
        self._succ[re.src].append(re)
        self._pred[re.dst].append(re)

        # --- call-to-return edge: call_node → after_call ------------------
        # (propagates caller-local state across the call)
        ctr = ICFGEdge(src=call_nid, dst=after_nid,
                       kind="call-to-return", call_site=call_site)
        self.edges.append(ctr)
        self._succ[ctr.src].append(ctr)
        self._pred[ctr.dst].append(ctr)

        # --- rewire original intraprocedural successors --------------------
        # Any existing intra edge from call_nid that went to the *next*
        # intraprocedural statement should now target after_nid instead,
        # because the "real" flow goes through the callee.  We leave the
        # intra edges as-is for now — the analysis framework will simply
        # ignore them when it encounters a "call" node.  This keeps the
        # supergraph construction idempotent.

        self._call_info[call_site] = (call_nid, after_nid, callee_fid)

    # ---- CFG unpacking helpers -------------------------------------------

    @staticmethod
    def _unpack_cfg(
        local_cfg: Any,
    ) -> Tuple[List[Any], List[Tuple[Any, Any]], Any, Any]:
        """Extract (nodes, edges, entry, exit) from a CFG object.

        Supports both ctrlflow_graph.CFG instances and plain dicts.
        """
        if isinstance(local_cfg, dict):
            return (
                local_cfg["nodes"],
                local_cfg["edges"],
                local_cfg["entry"],
                local_cfg["exit"],
            )
        # ctrlflow_graph.CFG-compatible object
        nodes: List[Any] = list(
            getattr(local_cfg, "nodes", None) or local_cfg.node_ids()
        )
        edges: List[Tuple[Any, Any]] = []
        if hasattr(local_cfg, "edges"):
            edges = list(local_cfg.edges)
        elif hasattr(local_cfg, "edge_list"):
            edges = list(local_cfg.edge_list())
        else:
            # fallback: iterate successors
            for n in nodes:
                for s in local_cfg.successors(n):
                    edges.append((n, s))
        entry = getattr(local_cfg, "entry", nodes[0] if nodes else None)
        exit_ = getattr(local_cfg, "exit", nodes[-1] if nodes else None)
        return nodes, edges, entry, exit_

    @staticmethod
    def _node_stmt(local_cfg: Any, node_id: Any) -> Optional[Any]:
        """Try to obtain the AST / token reference for a CFG node."""
        if hasattr(local_cfg, "node_data"):
            data = local_cfg.node_data(node_id)
            if data is not None:
                return data
        if hasattr(local_cfg, "stmt_at"):
            return local_cfg.stmt_at(node_id)
        return None

    # ------------------------------------------------------------------
    # Query API
    # ------------------------------------------------------------------

    def successors(self, nid: Any) -> List[ICFGEdge]:
        """Return all outgoing edges from *nid*."""
        return self._succ.get(nid, [])

    def predecessors(self, nid: Any) -> List[ICFGEdge]:
        """Return all incoming edges to *nid*."""
        return self._pred.get(nid, [])

    def entry_of(self, func: Any) -> Any:
        """Entry node id for *func*."""
        return self._entries[func]

    def exit_of(self, func: Any) -> Any:
        """Exit node id for *func*."""
        return self._exits[func]

    def functions(self) -> Iterable[Any]:
        """All function ids in the supergraph."""
        return self._entries.keys()

    def call_sites(self) -> Iterable[Any]:
        """All call-site ids."""
        return self._call_info.keys()

    def call_info(self, call_site: Any) -> Tuple[Any, Any, Any]:
        """``(call_node, after_call_node, callee_func)`` for a call site."""
        return self._call_info[call_site]

    def is_call_node(self, nid: Any) -> bool:
        node = self.nodes.get(nid)
        return node is not None and node.kind == "call"

    def is_after_call_node(self, nid: Any) -> bool:
        node = self.nodes.get(nid)
        return node is not None and node.kind == "after_call"

    def __repr__(self) -> str:
        return (
            f"InterproceduralCFG(functions={len(self._entries)}, "
            f"nodes={len(self.nodes)}, edges={len(self.edges)})"
        )


# ═══════════════════════════════════════════════════════════════════════════
# §3  PROCEDURE SUMMARIES  (§8.4)
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class ProcedureSummary:
    """Mapping from abstract entry states to abstract exit states for a
    single function.

    Per §8.4, if ``summary[s] = t`` then whenever the function is entered in
    abstract state *s*, the exit state is approximated by *t*.

    ``summary[s] = UNREACHABLE`` (represented as ``None``) means the exit
    is unreachable when the function is entered in state *s*.

    Internally stored as a dictionary ``{frozen_entry_state: exit_state}``.
    """

    function: Any
    _map: Dict[Any, Optional[Any]] = field(default_factory=dict)

    # sentinel
    UNREACHABLE: Optional[Any] = None

    def get(self, entry_state: Any) -> Optional[Any]:
        """Look up the exit state for *entry_state* (``None`` = unreachable /
        not yet computed)."""
        return self._map.get(self._freeze(entry_state))

    def put(self, entry_state: Any, exit_state: Optional[Any]) -> bool:
        """Store or update.  Returns ``True`` if the value changed."""
        key = self._freeze(entry_state)
        old = self._map.get(key, _BOTTOM_SENTINEL)
        self._map[key] = exit_state
        return old is _BOTTOM_SENTINEL or old != exit_state

    def known_entries(self) -> Iterable[Any]:
        return self._map.keys()

    @staticmethod
    def _freeze(state: Any) -> Any:
        """Make *state* hashable for use as a dict key."""
        if isinstance(state, dict):
            return tuple(sorted(state.items()))
        if isinstance(state, (set, frozenset)):
            return frozenset(state)
        if isinstance(state, list):
            return tuple(state)
        return state  # assume already hashable

    def __repr__(self) -> str:
        entries = len(self._map)
        return f"ProcedureSummary({self.function!r}, entries={entries})"


class SummaryCache:
    """Global cache of :class:`ProcedureSummary` objects keyed by function."""

    def __init__(self) -> None:
        self._cache: Dict[Any, ProcedureSummary] = {}

    def get_or_create(self, func: Any) -> ProcedureSummary:
        if func not in self._cache:
            self._cache[func] = ProcedureSummary(function=func)
        return self._cache[func]

    def __getitem__(self, func: Any) -> ProcedureSummary:
        return self._cache[func]

    def __contains__(self, func: Any) -> bool:
        return func in self._cache

    def clear(self) -> None:
        self._cache.clear()

    def all_summaries(self) -> Dict[Any, ProcedureSummary]:
        return dict(self._cache)


# ═══════════════════════════════════════════════════════════════════════════
# §4  ANALYSIS RESULT CONTAINER
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class InterproceduralResult:
    """Container for interprocedural analysis results.

    Attributes
    ----------
    node_states : dict[(context, node_id)] → abstract state
        The abstract state at each (context, node) pair.
    summaries : SummaryCache
        Procedure summaries (populated by functional analysis).
    policy : ContextPolicy
        The context-sensitivity strategy that was used.
    icfg : InterproceduralCFG
        The supergraph.
    converged : bool
        ``True`` if the fixed-point iteration converged.
    iterations : int
        Number of fixed-point iterations performed.
    """

    node_states: Dict[Tuple[Any, Any], Any] = field(default_factory=dict)
    summaries: SummaryCache = field(default_factory=SummaryCache)
    policy: ContextPolicy = ContextPolicy.INSENSITIVE
    icfg: Optional[InterproceduralCFG] = None
    converged: bool = False
    iterations: int = 0

    # ---- convenience queries ------------------------------------------

    def state_at(self, node: Any, context: Optional[CallingContext] = None) -> Any:
        """Return the abstract state at *node* (in *context*).

        If *context* is ``None`` and the analysis was context-insensitive,
        the single result is returned.  Otherwise a ``KeyError`` is raised.
        """
        if context is None:
            context = INSENSITIVE_CTX
        return self.node_states[(context, node)]

    def query_function(
        self, func: Any, what: str = "exit"
    ) -> Dict[Any, Any]:
        """Return ``{context: state}`` at the entry or exit of *func*.

        Parameters
        ----------
        func : function identifier
        what : ``"entry"`` or ``"exit"``
        """
        if self.icfg is None:
            return {}
        target = (
            self.icfg.entry_of(func) if what == "entry"
            else self.icfg.exit_of(func)
        )
        return {
            ctx: st
            for (ctx, nid), st in self.node_states.items()
            if nid == target
        }

    def summary_of(self, func: Any) -> Optional[ProcedureSummary]:
        """Return the procedure summary for *func* if available."""
        if func in self.summaries:
            return self.summaries[func]
        return None

    def all_states(self) -> Dict[Tuple[Any, Any], Any]:
        return dict(self.node_states)


# ═══════════════════════════════════════════════════════════════════════════
# §5  ANALYSIS ENGINE — BASE CLASS
# ═══════════════════════════════════════════════════════════════════════════

class InterproceduralAnalysisBase:
    """Abstract base for the three analysis flavours.

    Subclasses implement :meth:`_initial_context`, :meth:`_extend_context`,
    and :meth:`_propagate_return` to realise the specific context-sensitivity
    policy.

    The core fixed-point loop is a **worklist algorithm** (cf.
    ``PropagationWorkListAlgorithm`` in §5.10 of [MS]).
    """

    # -- configuration -----------------------------------------------------

    MAX_ITERATIONS: int = 100_000  # safety net

    def __init__(
        self,
        icfg: InterproceduralCFG,
        domain: AbstractDomainProto,
        transfer: Union[TransferFunctionProto, Callable[..., Any]],
        *,
        entry_state: Any = None,
        entry_function: Optional[Any] = None,
        direction: str = "forward",
    ) -> None:
        self.icfg = icfg
        self.domain = domain
        self.transfer = _ensure_transfer(transfer)
        self.direction = direction
        self._entry_state = entry_state if entry_state is not None else domain.top()

        # Resolve entry function (defaults to first function in the ICFG)
        if entry_function is not None:
            self._entry_func = entry_function
        else:
            funcs = list(icfg.functions())
            if not funcs:
                raise ValueError("ICFG has no functions")
            self._entry_func = funcs[0]

        # result accumulator
        self._states: Dict[Tuple[Any, Any], Any] = {}
        self._summaries = SummaryCache()
        self._iterations = 0

    # -- abstract hooks for subclasses -------------------------------------

    def _initial_context(self) -> CallingContext:
        """Return the initial calling context for the program entry."""
        raise NotImplementedError

    def _extend_context_for_call(
        self,
        current_ctx: CallingContext,
        call_site: Any,
        callee: Any,
        caller_state: Any,
    ) -> CallingContext:
        """Return the context under which the *callee* should be analysed."""
        raise NotImplementedError

    def _combine_at_return(
        self,
        caller_ctx: CallingContext,
        callee_ctx: CallingContext,
        caller_state_at_call: Any,
        callee_exit_state: Any,
        call_site: Any,
    ) -> Any:
        """Combine caller-local state with the callee exit state at the
        after-call node.

        Default: simply return the callee exit state (no caller-local
        preservation).  Subclasses or users can override for richer
        semantics (e.g., restoring caller-local variables).
        """
        return callee_exit_state

    # -- parameter-argument / return-value mapping -------------------------

    def _map_args_to_params(
        self,
        caller_state: Any,
        call_site: Any,
        callee: Any,
    ) -> Any:
        """Map actual arguments (in *caller_state*) to formal parameters of
        *callee*.

        Default implementation returns *caller_state* unchanged.  Override
        for variable-renaming analyses (e.g., sign analysis where formals
        and actuals have different names).
        """
        return caller_state

    def _map_return_to_caller(
        self,
        callee_exit_state: Any,
        call_site: Any,
        callee: Any,
    ) -> Any:
        """Map callee exit state back to caller namespace.

        Default: identity.
        """
        return callee_exit_state

    # ------------------------------------------------------------------
    # Worklist-based fixed-point iteration
    # ------------------------------------------------------------------

    def run(self) -> InterproceduralResult:
        """Execute the analysis and return an :class:`InterproceduralResult`."""
        ctx0 = self._initial_context()
        entry_nid = self.icfg.entry_of(self._entry_func)

        # seed the entry node
        self._propagate(ctx0, entry_nid, self._entry_state)

        # worklist: items are (context, node_id)
        worklist: Deque[Tuple[CallingContext, Any]] = deque()
        worklist.append((ctx0, entry_nid))

        converged = False
        self._iterations = 0

        while worklist and self._iterations < self.MAX_ITERATIONS:
            self._iterations += 1
            ctx, nid = worklist.popleft()

            current_state = self._states.get((ctx, nid))
            if current_state is None:
                continue

            node_obj = self.icfg.nodes.get(nid)
            if node_obj is None:
                continue

            # Apply the transfer function (for non-call, non-after-call nodes)
            if node_obj.kind == "call":
                # At a call node we do NOT apply the user transfer function;
                # instead we push to the callee and propagate over
                # call-to-return edges.
                self._handle_call_node(ctx, nid, current_state, worklist)
            elif node_obj.kind == "after_call":
                # The after-call node is populated by _handle_return;
                # we just propagate its state to intra successors.
                post_state = current_state
                self._propagate_intra(ctx, nid, post_state, worklist)
            else:
                # Normal or entry node — apply the transfer function
                post_state = self.transfer.apply(node_obj.stmt, current_state)
                self._propagate_intra(ctx, nid, post_state, worklist)

                # If this is an exit node, handle return edges
                if node_obj.kind == "exit":
                    self._handle_exit_node(ctx, nid, post_state, worklist)

        converged = len(worklist) == 0

        if not converged:
            logger.warning(
                "Interprocedural analysis did not converge after %d iterations",
                self._iterations,
            )

        return InterproceduralResult(
            node_states=dict(self._states),
            summaries=self._summaries,
            policy=self._policy_tag(),
            icfg=self.icfg,
            converged=converged,
            iterations=self._iterations,
        )

    def _policy_tag(self) -> ContextPolicy:
        return ContextPolicy.INSENSITIVE

    # ------------------------------------------------------------------
    # Propagation helpers
    # ------------------------------------------------------------------

    def _propagate(
        self,
        ctx: CallingContext,
        nid: Any,
        new_state: Any,
    ) -> bool:
        """Join *new_state* into the state at ``(ctx, nid)``.

        Returns ``True`` if the stored state changed.
        """
        key = (ctx, nid)
        old = self._states.get(key)
        if old is None:
            self._states[key] = new_state
            return True
        joined = self.domain.join(old, new_state)
        if self.domain.eq(joined, old):
            return False
        self._states[key] = joined
        return True

    def _propagate_intra(
        self,
        ctx: CallingContext,
        nid: Any,
        post_state: Any,
        worklist: Deque[Tuple[CallingContext, Any]],
    ) -> None:
        """Propagate *post_state* along intraprocedural successor edges."""
        for edge in self.icfg.successors(nid):
            if edge.kind == "intra":
                if self._propagate(ctx, edge.dst, post_state):
                    worklist.append((ctx, edge.dst))

    def _handle_call_node(
        self,
        ctx: CallingContext,
        call_nid: Any,
        caller_state: Any,
        worklist: Deque[Tuple[CallingContext, Any]],
    ) -> None:
        """Process a call node: propagate to callee entry & call-to-return."""
        for edge in self.icfg.successors(call_nid):
            if edge.kind == "call":
                callee_entry = edge.dst
                callee_func = self.icfg.nodes[callee_entry].function
                call_site = edge.call_site

                # Map arguments → parameters
                param_state = self._map_args_to_params(
                    caller_state, call_site, callee_func
                )

                # Determine callee context
                callee_ctx = self._extend_context_for_call(
                    ctx, call_site, callee_func, param_state
                )

                # Record for return-edge handling
                self._record_pending_return(
                    callee_ctx, callee_func, ctx, call_nid, call_site
                )

                if self._propagate(callee_ctx, callee_entry, param_state):
                    worklist.append((callee_ctx, callee_entry))

            elif edge.kind == "call-to-return":
                # Propagate caller-local state across the call
                # (conservative: send the full caller state through)
                if self._propagate(ctx, edge.dst, caller_state):
                    worklist.append((ctx, edge.dst))

    def _handle_exit_node(
        self,
        callee_ctx: CallingContext,
        exit_nid: Any,
        callee_exit_state: Any,
        worklist: Deque[Tuple[CallingContext, Any]],
    ) -> None:
        """Process a function exit: propagate back through return edges."""
        func = self.icfg.nodes[exit_nid].function

        # Update procedure summary
        summary = self._summaries.get_or_create(func)
        # The entry state for this context
        entry_nid = self.icfg.entry_of(func)
        entry_state = self._states.get((callee_ctx, entry_nid))
        if entry_state is not None:
            summary.put(entry_state, callee_exit_state)

        # For each pending return site, propagate callee result back
        for edge in self.icfg.successors(exit_nid):
            if edge.kind == "return":
                after_call_nid = edge.dst
                call_site = edge.call_site

                # Look up all (caller_ctx, call_nid) pairs that invoked
                # this callee in context callee_ctx
                for (
                    caller_ctx,
                    call_nid,
                ) in self._get_callers_for(callee_ctx, func, call_site):
                    caller_state_at_call = self._states.get(
                        (caller_ctx, call_nid)
                    )

                    # Map callee return → caller namespace
                    mapped_return = self._map_return_to_caller(
                        callee_exit_state, call_site, func
                    )

                    combined = self._combine_at_return(
                        caller_ctx,
                        callee_ctx,
                        caller_state_at_call,
                        mapped_return,
                        call_site,
                    )

                    if self._propagate(caller_ctx, after_call_nid, combined):
                        worklist.append((caller_ctx, after_call_nid))

    # ------------------------------------------------------------------
    # Pending-return bookkeeping
    # ------------------------------------------------------------------

    _pending_returns: Dict[
        Tuple[Any, Any],  # (callee_ctx, callee_func)
        List[Tuple[Any, Any, Any]],  # [(caller_ctx, call_nid, call_site)]
    ]

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)

    def _record_pending_return(
        self,
        callee_ctx: CallingContext,
        callee_func: Any,
        caller_ctx: CallingContext,
        call_nid: Any,
        call_site: Any,
    ) -> None:
        if not hasattr(self, "_pending_returns"):
            self._pending_returns = defaultdict(list)
        key = (callee_ctx, callee_func)
        entry = (caller_ctx, call_nid, call_site)
        if entry not in self._pending_returns[key]:
            self._pending_returns[key].append(entry)

    def _get_callers_for(
        self,
        callee_ctx: CallingContext,
        callee_func: Any,
        call_site: Any,
    ) -> List[Tuple[CallingContext, Any]]:
        """Return ``[(caller_ctx, call_nid)]`` for callers that triggered
        *callee_func* in *callee_ctx* through *call_site*."""
        if not hasattr(self, "_pending_returns"):
            return []
        key = (callee_ctx, callee_func)
        results = []
        for caller_ctx, call_nid, cs in self._pending_returns.get(key, []):
            if cs == call_site:
                results.append((caller_ctx, call_nid))
        return results


# ═══════════════════════════════════════════════════════════════════════════
# §6  CONTEXT-INSENSITIVE ANALYSIS  (§8.2)
# ═══════════════════════════════════════════════════════════════════════════

class ContextInsensitiveAnalysis(InterproceduralAnalysisBase):
    """Context-insensitive interprocedural analysis.

    All call sites share a single context (``⊤ctx``).  This merges
    information from all callers, which is fast but may produce
    spurious dataflow along interprocedurally invalid paths.

    From §8.2:
        "The simplest approach to interprocedural analysis simply ignores
         the calling context, thereby merging the abstract states from
         all callers."
    """

    def _initial_context(self) -> CallingContext:
        return INSENSITIVE_CTX

    def _extend_context_for_call(
        self, current_ctx, call_site, callee, caller_state
    ) -> CallingContext:
        return INSENSITIVE_CTX

    def _policy_tag(self) -> ContextPolicy:
        return ContextPolicy.INSENSITIVE


# ═══════════════════════════════════════════════════════════════════════════
# §7  CALL-STRING SENSITIVE ANALYSIS  (§8.3)
# ═══════════════════════════════════════════════════════════════════════════

class CallStringSensitiveAnalysis(InterproceduralAnalysisBase):
    """Context-sensitive analysis using bounded call strings (k-CFA).

    From §8.3:
        "A simple approach to obtaining context sensitivity is to
         distinguish calls by a *call string*, which is a sequence of
         call sites that records the recent call history."

    Parameters
    ----------
    k : int
        Maximum call-string depth.  ``k=0`` is equivalent to
        context-insensitive; ``k=∞`` is exact but may not terminate
        for recursive programs.
    """

    def __init__(
        self,
        icfg: InterproceduralCFG,
        domain: AbstractDomainProto,
        transfer: Union[TransferFunctionProto, Callable[..., Any]],
        *,
        k: int = 1,
        entry_state: Any = None,
        entry_function: Optional[Any] = None,
        direction: str = "forward",
    ) -> None:
        self._k = k
        super().__init__(
            icfg,
            domain,
            transfer,
            entry_state=entry_state,
            entry_function=entry_function,
            direction=direction,
        )

    def _initial_context(self) -> CallingContext:
        return CallString.empty(self._k)

    def _extend_context_for_call(
        self, current_ctx, call_site, callee, caller_state
    ) -> CallingContext:
        assert isinstance(current_ctx, CallString)
        return current_ctx.extend(call_site)

    def _policy_tag(self) -> ContextPolicy:
        return ContextPolicy.CALL_STRING


# ═══════════════════════════════════════════════════════════════════════════
# §8  FUNCTIONAL / SUMMARY-BASED ANALYSIS  (§8.4)
# ═══════════════════════════════════════════════════════════════════════════

class FunctionalAnalysis(InterproceduralAnalysisBase):
    """Context-sensitive analysis with the functional approach.

    From §8.4:
        "A lattice element for a CFG node *v* is a map
         $m_v : State \\to lift(State)$ such that $m_v(s)$ approximates
         the possible states at *v* given that the current function
         containing *v* was entered in a state that matches *s*."

    The context is the *abstract entry state* of the function.  This yields
    **optimal precision** — it is as precise as fully inlining all function
    calls (even recursive ones).

    Procedure summaries are automatically computed and cached in the
    :attr:`summaries` of the result.
    """

    def _initial_context(self) -> CallingContext:
        return FunctionalContext(entry_state=self._freeze(self._entry_state))

    def _extend_context_for_call(
        self, current_ctx, call_site, callee, caller_state
    ) -> CallingContext:
        # The callee context IS the abstract entry state
        return FunctionalContext(entry_state=self._freeze(caller_state))

    def _combine_at_return(
        self,
        caller_ctx,
        callee_ctx,
        caller_state_at_call,
        callee_exit_state,
        call_site,
    ) -> Any:
        """For the functional approach, we can attempt to use the cached
        summary for efficiency.  Falls back to the base implementation."""
        return callee_exit_state

    def _policy_tag(self) -> ContextPolicy:
        return ContextPolicy.FUNCTIONAL

    @staticmethod
    def _freeze(state: Any) -> Any:
        """Make state hashable."""
        return ProcedureSummary._freeze(state)

    # ---- Summary-based short-circuit -------------------------------------

    def _handle_call_node(
        self,
        ctx: CallingContext,
        call_nid: Any,
        caller_state: Any,
        worklist: Deque[Tuple[CallingContext, Any]],
    ) -> None:
        """Override call handling to try using an existing summary first.

        If a summary already maps the callee's entry state to an exit
        state, we use it directly instead of re-analysing the callee body.
        This is the key performance optimisation of the functional approach.
        """
        for edge in self.icfg.successors(call_nid):
            if edge.kind == "call":
                callee_entry = edge.dst
                callee_func = self.icfg.nodes[callee_entry].function
                call_site = edge.call_site

                param_state = self._map_args_to_params(
                    caller_state, call_site, callee_func
                )

                # Check if we already have a summary
                summary = self._summaries.get_or_create(callee_func)
                cached_exit = summary.get(param_state)

                if cached_exit is not None:
                    # Use the summary directly — skip callee analysis
                    mapped_return = self._map_return_to_caller(
                        cached_exit, call_site, callee_func
                    )
                    # Find the after-call node
                    for ret_edge in self.icfg.successors(call_nid):
                        if ret_edge.kind == "call-to-return":
                            if self._propagate(ctx, ret_edge.dst, mapped_return):
                                worklist.append((ctx, ret_edge.dst))
                    continue

                # No summary yet — fall through to normal processing
                callee_ctx = self._extend_context_for_call(
                    ctx, call_site, callee_func, param_state
                )
                self._record_pending_return(
                    callee_ctx, callee_func, ctx, call_nid, call_site
                )
                if self._propagate(callee_ctx, callee_entry, param_state):
                    worklist.append((callee_ctx, callee_entry))

            elif edge.kind == "call-to-return":
                if self._propagate(ctx, edge.dst, caller_state):
                    worklist.append((ctx, edge.dst))


# ═══════════════════════════════════════════════════════════════════════════
# §9  BRIDGE TO distrib_analysis (IFDS/IDE)
# ═══════════════════════════════════════════════════════════════════════════

class IFDSInterproceduralAdapter:
    """Adapter that wraps :mod:`distrib_analysis`'s IFDS/IDE tabulation
    solver to expose the same :class:`InterproceduralResult` interface.

    This is useful when the dataflow problem is *distributive* (i.e.,
    transfer functions distribute over meet/join), because the IFDS/IDE
    algorithm from [RHS] solves such problems in $O(E \\cdot D^3)$ time.

    Parameters
    ----------
    icfg : InterproceduralCFG
    problem
        An IFDS/IDE problem descriptor compatible with
        ``distrib_analysis.IFDSProblem`` or ``distrib_analysis.IDEProblem``.
    """

    def __init__(self, icfg: InterproceduralCFG, problem: Any) -> None:
        self.icfg = icfg
        self._problem = problem

    def run(self) -> InterproceduralResult:
        """Delegate to the IFDS/IDE tabulation solver and wrap results."""
        if dist_mod is None:
            raise ImportError(
                "distrib_analysis module not available; "
                "cannot use IFDS/IDE adapter"
            )

        # Build the supergraph in the format expected by distrib_analysis
        supergraph = self._build_dist_supergraph()

        # Solve
        solver = dist_mod.TabulationSolver(supergraph, self._problem)
        raw_result = solver.solve()

        # Convert to InterproceduralResult
        result = InterproceduralResult(
            policy=ContextPolicy.FUNCTIONAL,  # IFDS is inherently context-sensitive
            icfg=self.icfg,
            converged=True,
        )

        # Map raw tabulation results → node_states
        for nid, facts in raw_result.items():
            result.node_states[(INSENSITIVE_CTX, nid)] = facts

        return result

    def _build_dist_supergraph(self) -> Any:
        """Convert our ICFG into the supergraph representation expected by
        ``distrib_analysis``."""
        if not hasattr(dist_mod, "Supergraph"):
            # Fallback: return the raw ICFG and let the solver adapt
            return self.icfg

        return dist_mod.Supergraph(
            nodes=list(self.icfg.nodes.keys()),
            edges=[(e.src, e.dst, e.kind) for e in self.icfg.edges],
            entry_points={
                f: self.icfg.entry_of(f) for f in self.icfg.functions()
            },
            exit_points={
                f: self.icfg.exit_of(f) for f in self.icfg.functions()
            },
        )


# ═══════════════════════════════════════════════════════════════════════════
# §10  BRIDGE TO dataflow_analyses (intraprocedural kernels)
# ═══════════════════════════════════════════════════════════════════════════

class IntraproceduralKernelAdapter:
    """Run an existing intraprocedural analysis from
    :mod:`dataflow_analyses` within a single-function scope and return the
    result.

    This is used internally by the interprocedural engines to compute
    the intraprocedural portion of a function body.  It avoids
    reimplementing the worklist algorithm for intraprocedural segments.
    """

    def __init__(
        self,
        local_cfg: Any,
        domain: AbstractDomainProto,
        transfer: TransferFunctionProto,
        entry_state: Any,
        direction: str = "forward",
    ) -> None:
        self._cfg = local_cfg
        self._domain = domain
        self._transfer = transfer
        self._entry_state = entry_state
        self._direction = direction

    def run(self) -> Dict[Any, Any]:
        """Run the intraprocedural kernel and return ``{node_id: state}``."""
        if dfa_mod is not None and hasattr(dfa_mod, "WorklistSolver"):
            solver = dfa_mod.WorklistSolver(
                cfg=self._cfg,
                domain=self._domain,
                transfer=self._transfer,
                entry_state=self._entry_state,
                direction=self._direction,
            )
            return solver.solve()

        # Fallback: minimal built-in worklist
        return self._builtin_worklist()

    def _builtin_worklist(self) -> Dict[Any, Any]:
        """Minimal worklist solver for when dfa_mod is unavailable."""
        nodes, edges, entry, exit_ = InterproceduralCFG._unpack_cfg(self._cfg)
        succ: Dict[Any, List[Any]] = defaultdict(list)
        for s, d in edges:
            succ[s].append(d)

        states: Dict[Any, Any] = {n: self._domain.bottom() for n in nodes}
        states[entry] = self._entry_state

        wl: Deque[Any] = deque([entry])
        while wl:
            n = wl.popleft()
            post = self._transfer.apply(n, states[n])
            for s in succ[n]:
                joined = self._domain.join(states[s], post)
                if not self._domain.eq(joined, states[s]):
                    states[s] = joined
                    wl.append(s)

        return states


# ═══════════════════════════════════════════════════════════════════════════
# §11  CONVENIENCE ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════

def analyze(
    cfg_data: Any,
    *,
    domain: AbstractDomainProto,
    transfer: Union[TransferFunctionProto, Callable[..., Any]],
    callgraph: Optional[Any] = None,
    policy: ContextPolicy = ContextPolicy.FUNCTIONAL,
    k: int = 1,
    entry_state: Any = None,
    entry_function: Optional[Any] = None,
    direction: str = "forward",
    max_iterations: int = 100_000,
) -> InterproceduralResult:
    """One-shot convenience function for interprocedural analysis.

    Parameters
    ----------
    cfg_data
        Either a pre-built :class:`InterproceduralCFG`, or a mapping /
        provider from which one can be constructed.
    domain
        Abstract domain (lattice) — must satisfy :class:`AbstractDomainProto`.
    transfer
        Transfer function — callable ``(node, state) → state`` or object
        with an ``apply`` method.
    callgraph
        Call-graph (required unless *cfg_data* is already an
        :class:`InterproceduralCFG`).
    policy
        Context-sensitivity strategy.
    k
        Call-string depth (only used when ``policy == CALL_STRING``).
    entry_state
        Initial abstract state at program entry.  Defaults to ``domain.top()``.
    entry_function
        Which function to start from.  Defaults to the first function.
    direction
        ``"forward"`` or ``"backward"``.
    max_iterations
        Safety cap on the worklist iterations.

    Returns
    -------
    InterproceduralResult
        Analysis results including per-node states, procedure summaries,
        and convergence information.

    Examples
    --------
    >>> # Assuming appropriate domain, transfer, cfg_data, and callgraph:
    >>> result = analyze(
    ...     cfg_data,
    ...     domain=sign_domain,
    ...     transfer=sign_transfer,
    ...     callgraph=cg,
    ...     policy=ContextPolicy.FUNCTIONAL,
    ... )
    >>> result.query_function("main", "exit")
    {Fn<{...}>: {'x': '+', 'y': '0'}}
    """
    # ---- Build ICFG if necessary -----------------------------------------
    if isinstance(cfg_data, InterproceduralCFG):
        icfg = cfg_data
    else:
        if callgraph is None:
            # Attempt to extract a call graph from cfg_data if it carries one
            if hasattr(cfg_data, "callgraph"):
                callgraph = cfg_data.callgraph
            elif cg_mod is not None and hasattr(cg_mod, "build_callgraph"):
                callgraph = cg_mod.build_callgraph(cfg_data)
            else:
                raise ValueError(
                    "callgraph must be provided when cfg_data is not an "
                    "InterproceduralCFG"
                )
        icfg = InterproceduralCFG(cfg_data, callgraph)

    # ---- Instantiate the chosen engine -----------------------------------
    common_kw = dict(
        entry_state=entry_state,
        entry_function=entry_function,
        direction=direction,
    )

    if policy == ContextPolicy.INSENSITIVE:
        engine: InterproceduralAnalysisBase = ContextInsensitiveAnalysis(
            icfg, domain, transfer, **common_kw
        )
    elif policy == ContextPolicy.CALL_STRING:
        engine = CallStringSensitiveAnalysis(
            icfg, domain, transfer, k=k, **common_kw
        )
    elif policy == ContextPolicy.FUNCTIONAL:
        engine = FunctionalAnalysis(icfg, domain, transfer, **common_kw)
    else:
        raise ValueError(f"Unknown context policy: {policy!r}")

    engine.MAX_ITERATIONS = max_iterations

    # ---- Run & return ----------------------------------------------------
    return engine.run()


# ═══════════════════════════════════════════════════════════════════════════
# §12  UTILITIES
# ═══════════════════════════════════════════════════════════════════════════

def compute_summary(
    func: Any,
    cfg_provider: Any,
    domain: AbstractDomainProto,
    transfer: Union[TransferFunctionProto, Callable[..., Any]],
    entry_states: Iterable[Any],
) -> ProcedureSummary:
    """Standalone helper: compute a :class:`ProcedureSummary` for *func*
    by running an intraprocedural analysis for each *entry_state*.

    This is a simplified version of the functional approach that does NOT
    handle callees inside *func* — use :func:`analyze` with
    ``ContextPolicy.FUNCTIONAL`` for full interprocedural treatment.

    Parameters
    ----------
    func : function identifier
    cfg_provider : mapping or CFG object for *func*
    domain : abstract domain
    transfer : transfer function
    entry_states : iterable of abstract states to analyse

    Returns
    -------
    ProcedureSummary
    """
    xfer = _ensure_transfer(transfer)
    local_cfg = (
        cfg_provider[func]
        if isinstance(cfg_provider, dict)
        else cfg_provider.get_cfg(func)
    )

    summary = ProcedureSummary(function=func)

    for es in entry_states:
        adapter = IntraproceduralKernelAdapter(
            local_cfg, domain, xfer, entry_state=es
        )
        result = adapter.run()
        # The exit state is the result at the exit node
        _, _, _, exit_node = InterproceduralCFG._unpack_cfg(local_cfg)
        exit_state = result.get(exit_node, domain.bottom())
        summary.put(es, exit_state)

    return summary


def reachable_functions(
    icfg: InterproceduralCFG,
    entry_function: Optional[Any] = None,
) -> Set[Any]:
    """Return the set of functions reachable from *entry_function* through
    the call graph embedded in the ICFG."""
    if entry_function is None:
        funcs = list(icfg.functions())
        if not funcs:
            return set()
        entry_function = funcs[0]

    visited: Set[Any] = set()
    queue: Deque[Any] = deque([entry_function])
    while queue:
        f = queue.popleft()
        if f in visited:
            continue
        visited.add(f)
        # Find call edges from f's nodes
        exit_nid = icfg.exit_of(f)
        entry_nid = icfg.entry_of(f)
        for nid, node in icfg.nodes.items():
            if node.function != f:
                continue
            for edge in icfg.successors(nid):
                if edge.kind == "call":
                    callee = icfg.nodes[edge.dst].function
                    if callee not in visited:
                        queue.append(callee)
    return visited


def topological_order(
    icfg: InterproceduralCFG,
    entry_function: Optional[Any] = None,
) -> List[Any]:
    """Return functions in (approximate) reverse topological order of the
    call graph.  Useful for bottom-up summary computation.

    SCCs (due to recursion) are handled by collapsing cycles.
    """
    reachable = reachable_functions(icfg, entry_function)

    # Build adjacency
    adj: Dict[Any, Set[Any]] = defaultdict(set)
    for nid, node in icfg.nodes.items():
        if node.function not in reachable:
            continue
        for edge in icfg.successors(nid):
            if edge.kind == "call":
                callee = icfg.nodes[edge.dst].function
                if callee in reachable and callee != node.function:
                    adj[node.function].add(callee)

    # Kahn's algorithm (reverse post-order)
    in_deg: Dict[Any, int] = {f: 0 for f in reachable}
    for f, callees in adj.items():
        for c in callees:
            in_deg[c] = in_deg.get(c, 0) + 1

    queue: Deque[Any] = deque(f for f, d in in_deg.items() if d == 0)
    order: List[Any] = []
    while queue:
        f = queue.popleft()
        order.append(f)
        for c in adj.get(f, set()):
            in_deg[c] -= 1
            if in_deg[c] == 0:
                queue.append(c)

    # Append any remaining (part of cycles)
    remaining = reachable - set(order)
    order.extend(sorted(remaining, key=str))

    # Reverse so leaf functions come first (bottom-up)
    order.reverse()
    return order


def print_results(
    result: InterproceduralResult,
    *,
    functions: Optional[Iterable[Any]] = None,
    file: Any = None,
) -> None:
    """Pretty-print analysis results.

    Parameters
    ----------
    result : InterproceduralResult
    functions : restrict output to these functions (default: all)
    file : output stream (default: stdout)
    """
    import sys

    out = file or sys.stdout

    print(f"=== Interprocedural Analysis Results ===", file=out)
    print(f"Policy: {result.policy.value}", file=out)
    print(f"Converged: {result.converged}", file=out)
    print(f"Iterations: {result.iterations}", file=out)

    if result.icfg is None:
        print("(no ICFG available)", file=out)
        return

    target_funcs = set(functions) if functions else set(
        result.icfg.functions())

    for func in sorted(target_funcs, key=str):
        print(f"\n--- Function: {func} ---", file=out)

        # Entry states
        entry_map = result.query_function(func, "entry")
        if entry_map:
            print(f"  Entry states:", file=out)
            for ctx, st in sorted(entry_map.items(), key=lambda x: str(x[0])):
                print(f"    [{ctx}] → {st}", file=out)

        # Exit states
        exit_map = result.query_function(func, "exit")
        if exit_map:
            print(f"  Exit states:", file=out)
            for ctx, st in sorted(exit_map.items(), key=lambda x: str(x[0])):
                print(f"    [{ctx}] → {st}", file=out)

        # Summary
        summary = result.summary_of(func)
        if summary is not None:
            print(f"  Summary: {summary}", file=out)
            for entry_key in summary.known_entries():
                exit_val = summary.get(entry_key)
                tag = "unreachable" if exit_val is None else str(exit_val)
                print(f"    {entry_key} → {tag}", file=out)

    print(f"\n{'='*40}", file=out)
