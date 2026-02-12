"""
cppcheckdata_shims.callgraph
==============================

Builds the interprocedural call graph from a Cppcheck ``Configuration``.

The call graph is a directed graph where:
- **Nodes** are ``cppcheckdata.Function`` objects (plus synthetic nodes for
  external/library calls and the program entry point).
- **Edges** represent call relationships, annotated with the call site
  (the ``Token`` of the call expression) and the resolution method.

Resolution methods
------------------
``DIRECT``
    The callee is statically known (ordinary function call).
``FUNCTION_POINTER``
    The callee is invoked through a function pointer.  The set of possible
    targets is resolved conservatively via type-compatible signature matching.
``UNRESOLVED``
    The callee could not be resolved (e.g. calls through opaque ``void*``
    casts, callbacks from external libraries, variadic dispatch tables, …).
    An edge to a synthetic "UNKNOWN" node is created.

Public API
----------
    CallGraphNode       - a node in the call graph
    CallGraphEdge       - a directed edge (call site)
    CallGraph           - the whole-program call graph
    build_callgraph     - build from a Configuration
    CallResolutionKind  - enum of resolution methods

Typical usage::

    import cppcheckdata
    from cppcheckdata_shims.callgraph import build_callgraph

    data = cppcheckdata.parsedump("foo.c.dump")
    for cfg in data.configurations:
        cg = build_callgraph(cfg)
        for node in cg.nodes.values():
            print(f"{node.name}: calls {[e.callee.name for e in node.out_edges]}")
        print(cg.to_dot())

Relationship to other modules
-----------------------------
* Uses :mod:`controlflow_graph` optionally — if CFGs have already been built,
  they can be passed in to provide more precise call-site information.
* Is consumed by :mod:`dataflow_engine` (for interprocedural analysis),
  :mod:`abstract_interp`, :mod:`symbolic_exec`, and :mod:`constraint_engine`.
"""

from __future__ import annotations

import enum
import itertools
from collections import OrderedDict, defaultdict, deque
from dataclasses import dataclass, field
from typing import (
    Any,
    Callable,
    Deque,
    Dict,
    FrozenSet,
    Iterable,
    Iterator,
    List,
    Optional,
    Sequence,
    Set,
    Tuple,
    Union,
)


# ---------------------------------------------------------------------------
# Resolution kinds
# ---------------------------------------------------------------------------

class CallResolutionKind(enum.Enum):
    """How a call edge was resolved."""

    DIRECT           = "direct"
    FUNCTION_POINTER = "function-pointer"
    UNRESOLVED       = "unresolved"


# ---------------------------------------------------------------------------
# Node kinds
# ---------------------------------------------------------------------------

class NodeKind(enum.Enum):
    """Classification of a call-graph node."""

    FUNCTION  = "function"      # A real function defined in the TU
    EXTERNAL  = "external"      # A library/external function (declaration only)
    UNKNOWN   = "unknown"       # Synthetic sink for unresolved calls
    ENTRY     = "entry"         # Synthetic program entry (e.g. wraps main)


# ---------------------------------------------------------------------------
# CallGraphNode
# ---------------------------------------------------------------------------

class CallGraphNode:
    """A node in the call graph.

    Attributes
    ----------
    id : str
        Unique identifier.  For real functions this is the
        ``cppcheckdata.Function.Id``; for synthetic nodes it is a
        descriptive string.
    name : str
        Human-readable name of the function.
    kind : NodeKind
        What this node represents.
    function : cppcheckdata.Function or None
        The underlying Cppcheck function object (``None`` for synthetic
        nodes).
    out_edges : list[CallGraphEdge]
        Outgoing call edges (this function calls …).
    in_edges : list[CallGraphEdge]
        Incoming call edges (… calls this function).
    """

    __slots__ = ("id", "name", "kind", "function", "out_edges", "in_edges",
                 "_signature_key")

    def __init__(
        self,
        node_id: str,
        name: str,
        kind: NodeKind = NodeKind.FUNCTION,
        function=None,
    ) -> None:
        self.id: str = node_id
        self.name: str = name
        self.kind: NodeKind = kind
        self.function = function
        self.out_edges: List[CallGraphEdge] = []
        self.in_edges: List[CallGraphEdge] = []
        self._signature_key: Optional[Tuple] = None  # lazily computed

    # ----- queries ----------------------------------------------------------

    @property
    def callees(self) -> List[CallGraphNode]:
        """All direct successor nodes (functions called by this one)."""
        return [e.callee for e in self.out_edges]

    @property
    def callers(self) -> List[CallGraphNode]:
        """All direct predecessor nodes (functions that call this one)."""
        return [e.caller for e in self.in_edges]

    @property
    def is_leaf(self) -> bool:
        return len(self.out_edges) == 0

    @property
    def is_root(self) -> bool:
        return len(self.in_edges) == 0

    @property
    def is_recursive(self) -> bool:
        """Does this function call itself (directly)?"""
        return any(e.callee is self for e in self.out_edges)

    def __repr__(self) -> str:
        return f"CallGraphNode({self.name!r}, kind={self.kind.value})"

    def __hash__(self) -> int:
        return hash(self.id)

    def __eq__(self, other) -> bool:
        if isinstance(other, CallGraphNode):
            return self.id == other.id
        return NotImplemented


# ---------------------------------------------------------------------------
# CallGraphEdge
# ---------------------------------------------------------------------------

class CallGraphEdge:
    """A directed edge in the call graph representing a call site.

    Attributes
    ----------
    caller : CallGraphNode
        The calling function.
    callee : CallGraphNode
        The called function.
    call_token : cppcheckdata.Token or None
        The token at the call site (the function name or the expression
        being invoked).  ``None`` for synthetic edges.
    resolution : CallResolutionKind
        How this call was resolved.
    call_expr_tokens : list
        Additional tokens forming the call expression (arguments, etc.).
    file : str or None
        Source file of the call site.
    line : int or None
        Line number of the call site.
    """

    __slots__ = ("caller", "callee", "call_token", "resolution",
                 "call_expr_tokens", "file", "line")

    def __init__(
        self,
        caller: CallGraphNode,
        callee: CallGraphNode,
        call_token=None,
        resolution: CallResolutionKind = CallResolutionKind.DIRECT,
        call_expr_tokens: Optional[List] = None,
    ) -> None:
        self.caller = caller
        self.callee = callee
        self.call_token = call_token
        self.resolution = resolution
        self.call_expr_tokens = call_expr_tokens or []
        self.file: Optional[str] = None
        self.line: Optional[int] = None
        if call_token is not None:
            self.file = getattr(call_token, "file", None)
            self.line = getattr(call_token, "linenr", None)

    def __repr__(self) -> str:
        loc = ""
        if self.file and self.line:
            loc = f" @ {self.file}:{self.line}"
        return (
            f"CallGraphEdge({self.caller.name} -> {self.callee.name}, "
            f"{self.resolution.value}{loc})"
        )

    def __hash__(self) -> int:
        tok_id = id(self.call_token) if self.call_token else 0
        return hash((self.caller.id, self.callee.id, tok_id))

    def __eq__(self, other) -> bool:
        if isinstance(other, CallGraphEdge):
            return (
                self.caller.id == other.caller.id
                and self.callee.id == other.callee.id
                and self.call_token is other.call_token
            )
        return NotImplemented


# ---------------------------------------------------------------------------
# CallGraph
# ---------------------------------------------------------------------------

class CallGraph:
    """Whole-program (whole-TU) call graph.

    Attributes
    ----------
    nodes : OrderedDict[str, CallGraphNode]
        All nodes, keyed by node id.
    edges : list[CallGraphEdge]
        All edges.
    entry : CallGraphNode or None
        The synthetic entry node (wraps ``main`` if present).
    unknown : CallGraphNode
        The synthetic UNKNOWN sink node.
    config : cppcheckdata.Configuration
        The Cppcheck configuration this call graph was built from.
    """

    def __init__(self, config) -> None:
        self.config = config
        self.nodes: OrderedDict[str, CallGraphNode] = OrderedDict()
        self.edges: List[CallGraphEdge] = []
        self.entry: Optional[CallGraphNode] = None
        # Create the synthetic unknown node
        self.unknown = CallGraphNode(
            node_id="__UNKNOWN__",
            name="<unknown>",
            kind=NodeKind.UNKNOWN,
        )
        self.nodes[self.unknown.id] = self.unknown
        # Index: function name -> list of nodes (handles overloading in C++)
        self._name_index: Dict[str, List[CallGraphNode]] = defaultdict(list)
        # Index: function Id (cppcheckdata) -> node
        self._func_id_index: Dict[str, CallGraphNode] = {}
        # Index: signature key -> list of nodes (for fptr resolution)
        self._sig_index: Dict[Tuple, List[CallGraphNode]] = defaultdict(list)

    # ----- node management --------------------------------------------------

    def get_or_create_node(
        self,
        function=None,
        name: Optional[str] = None,
        kind: NodeKind = NodeKind.FUNCTION,
        node_id: Optional[str] = None,
    ) -> CallGraphNode:
        """Return existing node for *function*, or create one.

        Parameters
        ----------
        function : cppcheckdata.Function, optional
            The Cppcheck function object.
        name : str, optional
            The function name (used when *function* is ``None``).
        kind : NodeKind
            Classification.
        node_id : str, optional
            Explicit id (defaults to ``function.Id`` or *name*).
        """
        if function is not None:
            fid = getattr(function, "Id", None) or str(id(function))
            if fid in self._func_id_index:
                return self._func_id_index[fid]
            fname = getattr(function, "name", None) or "<anon>"
            node = CallGraphNode(
                node_id=fid,
                name=fname,
                kind=kind,
                function=function,
            )
            self.nodes[fid] = node
            self._func_id_index[fid] = node
            self._name_index[fname].append(node)
            return node

        # No function object — external or synthetic
        nid = node_id or name or "__UNNAMED__"
        if nid in self.nodes:
            return self.nodes[nid]
        nm = name or nid
        node = CallGraphNode(node_id=nid, name=nm, kind=kind)
        self.nodes[nid] = node
        self._name_index[nm].append(node)
        return node

    # ----- edge management --------------------------------------------------

    def add_edge(
        self,
        caller: CallGraphNode,
        callee: CallGraphNode,
        call_token=None,
        resolution: CallResolutionKind = CallResolutionKind.DIRECT,
        call_expr_tokens: Optional[List] = None,
    ) -> CallGraphEdge:
        """Create a call edge and wire it up."""
        edge = CallGraphEdge(
            caller=caller,
            callee=callee,
            call_token=call_token,
            resolution=resolution,
            call_expr_tokens=call_expr_tokens,
        )
        self.edges.append(edge)
        caller.out_edges.append(edge)
        callee.in_edges.append(edge)
        return edge

    # ----- lookups ----------------------------------------------------------

    def functions_by_name(self, name: str) -> List[CallGraphNode]:
        """Return all function nodes with the given name."""
        return list(self._name_index.get(name, []))

    def node_for_function(self, function) -> Optional[CallGraphNode]:
        """Return the node corresponding to a ``cppcheckdata.Function``."""
        fid = getattr(function, "Id", None) or str(id(function))
        return self._func_id_index.get(fid)

    @property
    def roots(self) -> List[CallGraphNode]:
        """Nodes with no callers (excluding UNKNOWN)."""
        return [
            n for n in self.nodes.values()
            if n.is_root and n.kind != NodeKind.UNKNOWN
        ]

    @property
    def leaves(self) -> List[CallGraphNode]:
        """Nodes with no callees."""
        return [
            n for n in self.nodes.values()
            if n.is_leaf and n.kind != NodeKind.UNKNOWN
        ]

    # ----- whole-graph queries ----------------------------------------------

    def transitive_callees(self, node: CallGraphNode) -> Set[CallGraphNode]:
        """Return all functions transitively reachable from *node*."""
        visited: Set[CallGraphNode] = set()
        worklist: Deque[CallGraphNode] = deque([node])
        while worklist:
            n = worklist.popleft()
            if n in visited:
                continue
            visited.add(n)
            for e in n.out_edges:
                worklist.append(e.callee)
        visited.discard(node)
        return visited

    def transitive_callers(self, node: CallGraphNode) -> Set[CallGraphNode]:
        """Return all functions that transitively call *node*."""
        visited: Set[CallGraphNode] = set()
        worklist: Deque[CallGraphNode] = deque([node])
        while worklist:
            n = worklist.popleft()
            if n in visited:
                continue
            visited.add(n)
            for e in n.in_edges:
                worklist.append(e.caller)
        visited.discard(node)
        return visited

    def is_recursive(self, node: CallGraphNode) -> bool:
        """Is *node* part of a (possibly indirect) recursive cycle?"""
        return node in self.transitive_callees(node)

    def strongly_connected_components(self) -> List[List[CallGraphNode]]:
        """Compute SCCs using Tarjan's algorithm.

        Returns a list of SCCs in reverse topological order (callees before
        callers).  Each SCC with more than one node represents mutual
        recursion.
        """
        index_counter = [0]
        stack: List[CallGraphNode] = []
        lowlink: Dict[str, int] = {}
        index: Dict[str, int] = {}
        on_stack: Set[str] = set()
        result: List[List[CallGraphNode]] = []

        def strongconnect(v: CallGraphNode):
            index[v.id] = index_counter[0]
            lowlink[v.id] = index_counter[0]
            index_counter[0] += 1
            stack.append(v)
            on_stack.add(v.id)

            for e in v.out_edges:
                w = e.callee
                if w.id not in index:
                    strongconnect(w)
                    lowlink[v.id] = min(lowlink[v.id], lowlink[w.id])
                elif w.id in on_stack:
                    lowlink[v.id] = min(lowlink[v.id], index[w.id])

            if lowlink[v.id] == index[v.id]:
                scc: List[CallGraphNode] = []
                while True:
                    w = stack.pop()
                    on_stack.discard(w.id)
                    scc.append(w)
                    if w.id == v.id:
                        break
                result.append(scc)

        for v in self.nodes.values():
            if v.id not in index:
                strongconnect(v)

        return result

    def topological_order(self) -> List[CallGraphNode]:
        """Return nodes in (approximate) topological order.

        Uses the SCC decomposition: SCCs are returned callee-first,
        and nodes within an SCC are in arbitrary order.
        """
        sccs = self.strongly_connected_components()
        return [node for scc in sccs for node in scc]

    def bottom_up_order(self) -> List[CallGraphNode]:
        """Alias for :meth:`topological_order` — callees before callers."""
        return self.topological_order()

    def top_down_order(self) -> List[CallGraphNode]:
        """Callers before callees."""
        return list(reversed(self.topological_order()))

    # ----- statistics -------------------------------------------------------

    def statistics(self) -> Dict[str, Any]:
        """Return a dict with summary statistics."""
        n_func = sum(1 for n in self.nodes.values()
                     if n.kind == NodeKind.FUNCTION)
        n_ext = sum(1 for n in self.nodes.values()
                    if n.kind == NodeKind.EXTERNAL)
        n_direct = sum(1 for e in self.edges
                       if e.resolution == CallResolutionKind.DIRECT)
        n_fptr = sum(1 for e in self.edges
                     if e.resolution == CallResolutionKind.FUNCTION_POINTER)
        n_unresolved = sum(1 for e in self.edges
                          if e.resolution == CallResolutionKind.UNRESOLVED)
        sccs = self.strongly_connected_components()
        n_recursive = sum(1 for scc in sccs if len(scc) > 1)
        n_self_recursive = sum(1 for n in self.nodes.values() if n.is_recursive)
        return {
            "functions": n_func,
            "external_functions": n_ext,
            "total_nodes": len(self.nodes),
            "total_edges": len(self.edges),
            "direct_calls": n_direct,
            "function_pointer_calls": n_fptr,
            "unresolved_calls": n_unresolved,
            "sccs": len(sccs),
            "recursive_sccs": n_recursive,
            "self_recursive_functions": n_self_recursive,
            "root_functions": len(self.roots),
            "leaf_functions": len(self.leaves),
        }

    # ----- serialisation ----------------------------------------------------

    def to_dot(self, title: Optional[str] = None) -> str:
        """Return a Graphviz DOT representation."""
        lines = ["digraph CallGraph {"]
        lines.append("  rankdir=TB;")
        if title:
            lines.append(f'  label="{title}";')
        lines.append('  node [shape=box, fontname="Helvetica", fontsize=10];')

        kind_attrs = {
            NodeKind.FUNCTION: 'style=filled, fillcolor="#ddeeff"',
            NodeKind.EXTERNAL: 'style=filled, fillcolor="#fff3cd", shape=ellipse',
            NodeKind.UNKNOWN:  'style=filled, fillcolor="#ffcccc", shape=diamond',
            NodeKind.ENTRY:    'style=filled, fillcolor="#ccffcc", shape=invhouse',
        }
        for n in self.nodes.values():
            attrs = kind_attrs.get(n.kind, "")
            escaped = n.name.replace('"', '\\"')
            lines.append(f'  "{n.id}" [label="{escaped}", {attrs}];')

        res_attrs = {
            CallResolutionKind.DIRECT: "",
            CallResolutionKind.FUNCTION_POINTER: ", style=dashed, color=blue",
            CallResolutionKind.UNRESOLVED: ", style=dotted, color=red",
        }
        for e in self.edges:
            attrs = res_attrs.get(e.resolution, "")
            elabel = e.resolution.value
            if e.line:
                elabel += f":{e.line}"
            lines.append(
                f'  "{e.caller.id}" -> "{e.callee.id}" '
                f'[label="{elabel}"{attrs}];'
            )
        lines.append("}")
        return "\n".join(lines)

    def __repr__(self) -> str:
        return (
            f"CallGraph(nodes={len(self.nodes)}, edges={len(self.edges)})"
        )


# ===========================================================================
# SIGNATURE UTILITIES (for function pointer resolution)
# ===========================================================================

def _normalize_type_str(type_str: Optional[str]) -> str:
    """Normalise a type string for comparison.

    Strips qualifiers (``const``, ``volatile``, ``restrict``), collapses
    whitespace, and removes ``struct``/``union``/``enum`` tag keywords
    for looser matching.
    """
    if not type_str:
        return ""
    s = type_str
    for qual in ("const", "volatile", "restrict", "struct", "union", "enum",
                 "__restrict", "__volatile", "__const"):
        s = s.replace(qual, "")
    # Collapse whitespace
    return " ".join(s.split())


def _extract_signature_key(function) -> Optional[Tuple]:
    """Extract a signature key ``(return_type, (arg_types…))`` from a
    ``cppcheckdata.Function``.

    Returns ``None`` if insufficient type information is available.
    """
    # Return type
    ret_type = _normalize_type_str(getattr(function, "returnType", None))
    if not ret_type:
        # Try tokenDef
        tok_def = getattr(function, "tokenDef", None)
        if tok_def and hasattr(tok_def, "valueType") and tok_def.valueType:
            vt = tok_def.valueType
            ret_type = _normalize_type_str(
                getattr(vt, "type", "") or ""
            )

    # Argument types
    arg_list = getattr(function, "argument", None) or {}
    arg_types: List[str] = []
    for idx in sorted(arg_list.keys()):
        arg_var = arg_list[idx]
        if arg_var is None:
            arg_types.append("")
            continue
        # nameToken.valueType is the richest source
        name_tok = getattr(arg_var, "nameToken", None)
        if name_tok and hasattr(name_tok, "valueType") and name_tok.valueType:
            vt = name_tok.valueType
            type_str = _normalize_type_str(
                getattr(vt, "type", "") or ""
            )
            # Include pointer depth
            pointer = getattr(vt, "pointer", 0) or 0
            if pointer:
                type_str += " " + "*" * pointer
            arg_types.append(type_str)
        else:
            # Fallback: typeStartToken .. typeEndToken
            type_str = _type_from_start_end(arg_var)
            arg_types.append(_normalize_type_str(type_str))

    if not ret_type and not arg_types:
        return None
    return (ret_type, tuple(arg_types))


def _type_from_start_end(variable) -> str:
    """Reconstruct a type string from ``typeStartToken`` … ``typeEndToken``."""
    start = getattr(variable, "typeStartToken", None)
    end = getattr(variable, "typeEndToken", None)
    if start is None:
        return ""
    parts = []
    tok = start
    while tok:
        parts.append(tok.str)
        if tok is end:
            break
        tok = tok.next
    return " ".join(parts)


def _signatures_compatible(
    fptr_sig: Optional[Tuple],
    func_sig: Optional[Tuple],
) -> bool:
    """Check whether *func_sig* is compatible with *fptr_sig*.

    Uses a relaxed check: we compare arity first, then compare each
    normalised type string.  Empty type strings are treated as wildcards
    (match anything), so missing type info doesn't cause false negatives.
    """
    if fptr_sig is None or func_sig is None:
        # Insufficient info — conservatively compatible
        return True

    fptr_ret, fptr_args = fptr_sig
    func_ret, func_args = func_sig

    # Arity must match
    if len(fptr_args) != len(func_args):
        return False

    # Return type (skip if either is empty)
    if fptr_ret and func_ret and fptr_ret != func_ret:
        return False

    # Argument types
    for fa, ga in zip(fptr_args, func_args):
        if fa and ga and fa != ga:
            return False

    return True


# ===========================================================================
# FUNCTION-POINTER TYPE EXTRACTION FROM VARIABLES
# ===========================================================================

def _is_function_pointer_var(variable) -> bool:
    """Heuristic: is *variable* a function pointer?

    Checks ``variable.isPointer`` combined with the type tokens containing
    ``(``, or the nameToken's valueType being a function pointer.
    """
    if variable is None:
        return False

    # Check nameToken's valueType for "type" == "..." with pointer
    name_tok = getattr(variable, "nameToken", None)
    if name_tok and hasattr(name_tok, "valueType") and name_tok.valueType:
        vt = name_tok.valueType
        # Cppcheck sets valueType.type to things like "int", "void", etc.
        # For function pointers, the type string in the token stream usually
        # contains '(' and ')'.
        pass  # fall through to heuristic below

    # Heuristic: look at typeStartToken .. typeEndToken for '(' which
    # indicates a function pointer declaration like  void (*fp)(int)
    type_str = _type_from_start_end(variable)
    if "(" in type_str and "*" in type_str and ")" in type_str:
        return True

    # Check if isPointer and the type involves a function-like syntax
    is_ptr = getattr(variable, "isPointer", False)
    is_array = getattr(variable, "isArray", False)
    if is_ptr or is_array:
        # If the type string contains parentheses it's likely a fptr
        if "(" in type_str:
            return True

    return False


def _extract_fptr_signature(variable) -> Optional[Tuple]:
    """Try to extract the pointed-to function's signature from a
    function-pointer variable declaration.

    Returns ``(return_type, (arg_types…))`` or ``None``.
    """
    # Strategy: parse the type token stream
    # e.g.  void ( * fp ) ( int , char * ) ;
    # return_type = "void", arg_types = ("int", "char *")

    start_tok = getattr(variable, "typeStartToken", None)
    end_tok = getattr(variable, "typeEndToken", None)
    if start_tok is None:
        return None

    # Collect all type tokens as strings
    toks: List[str] = []
    tok = start_tok
    while tok:
        toks.append(tok.str)
        if tok is end_tok:
            break
        tok = tok.next

    # Also collect tokens after typeEndToken until ';' or end to capture
    # the full parameter list.  The nameToken is typically inside the decl.
    name_tok = getattr(variable, "nameToken", None)
    if name_tok:
        # Continue from name_tok forward to capture the param list
        tok = name_tok.next if name_tok else None
        extra: List[str] = []
        paren_depth = 0
        while tok:
            if tok.str == "(":
                paren_depth += 1
            elif tok.str == ")":
                paren_depth -= 1
                if paren_depth < 0:
                    extra.append(tok.str)
                    break
            elif tok.str in (";", "{"):
                break
            extra.append(tok.str)
            tok = tok.next
        full_str = " ".join(toks) + " " + " ".join(extra)
    else:
        full_str = " ".join(toks)

    return _parse_fptr_signature_string(full_str)


def _parse_fptr_signature_string(s: str) -> Optional[Tuple]:
    """Parse a function pointer type string into ``(ret_type, (arg_types…))``.

    Handles patterns like:
    - ``void ( * ) ( int , char * )``
    - ``int ( * fp ) ( double )``
    - ``void ( * ) ( void )``
    """
    # Find the first '(' which starts the (* ...) part
    idx = s.find("(")
    if idx < 0:
        return None

    ret_type = _normalize_type_str(s[:idx].strip())

    # Find the matching ')' for the (* name) part
    depth = 0
    end_star = -1
    for i in range(idx, len(s)):
        if s[i] == "(":
            depth += 1
        elif s[i] == ")":
            depth -= 1
            if depth == 0:
                end_star = i
                break
    if end_star < 0:
        return None

    # Now find the parameter list '(' ... ')'
    param_start = s.find("(", end_star + 1)
    if param_start < 0:
        return (ret_type, ())

    depth = 0
    param_end = -1
    for i in range(param_start, len(s)):
        if s[i] == "(":
            depth += 1
        elif s[i] == ")":
            depth -= 1
            if depth == 0:
                param_end = i
                break
    if param_end < 0:
        return (ret_type, ())

    param_str = s[param_start + 1 : param_end].strip()
    if not param_str or param_str == "void":
        return (ret_type, ())

    # Split by ',' respecting nested parens
    args: List[str] = []
    current: List[str] = []
    depth = 0
    for ch in param_str:
        if ch == "(":
            depth += 1
            current.append(ch)
        elif ch == ")":
            depth -= 1
            current.append(ch)
        elif ch == "," and depth == 0:
            args.append(_normalize_type_str("".join(current).strip()))
            current = []
        else:
            current.append(ch)
    if current:
        args.append(_normalize_type_str("".join(current).strip()))

    return (ret_type, tuple(args))


# ===========================================================================
# CALL SITE DETECTION
# ===========================================================================

def _find_enclosing_function(token, cfg_config) -> Optional[Any]:
    """Find the ``cppcheckdata.Function`` whose scope contains *token*.

    Walks ``cfg_config.scopes`` to find the innermost Function scope that
    spans the token's position.
    """
    # Use token.scope if available (Cppcheck >= 2.x populates this)
    tok_scope = getattr(token, "scope", None)
    if tok_scope is not None:
        # Walk up to find the function scope
        s = tok_scope
        while s is not None:
            if getattr(s, "type", None) == "Function":
                return getattr(s, "function", None)
            s = getattr(s, "nestedIn", None)

    # Fallback: linear scan of function scopes
    for scope in cfg_config.scopes:
        if scope.type != "Function":
            continue
        body_start = scope.bodyStart
        body_end = scope.bodyEnd
        if body_start is None or body_end is None:
            continue
        # Compare by Id (integer string in the dump)
        try:
            start_id = int(body_start.Id)
            end_id = int(body_end.Id)
            tok_id = int(token.Id)
            if start_id <= tok_id <= end_id:
                return scope.function
        except (ValueError, TypeError, AttributeError):
            pass

    return None


class _CallSite:
    """Internal representation of a detected call site."""
    __slots__ = ("call_token", "callee_name", "callee_function",
                 "caller_function", "is_fptr_call", "fptr_variable",
                 "call_arg_tokens")

    def __init__(self) -> None:
        self.call_token = None
        self.callee_name: Optional[str] = None
        self.callee_function = None       # cppcheckdata.Function or None
        self.caller_function = None       # cppcheckdata.Function
        self.is_fptr_call: bool = False
        self.fptr_variable = None         # cppcheckdata.Variable or None
        self.call_arg_tokens: List = []


def _detect_call_sites(cfg_config) -> List[_CallSite]:
    """Scan the token list for function call sites.

    A call site is detected when we find a token whose:
    - ``str`` is a function name or expression,
    - followed by ``(`` (the argument list),
    - and the token has ``astParent`` whose ``str`` is ``(``.

    Alternatively, Cppcheck annotates calls: ``token.function`` points to
    the called ``cppcheckdata.Function``.
    """
    call_sites: List[_CallSite] = []
    seen_tokens: Set[str] = set()  # by Id, to avoid duplicates

    for token in cfg_config.tokenlist:
        # Strategy 1: Cppcheck resolved the call (token.function is set)
        func_ref = getattr(token, "function", None)
        if func_ref is not None:
            # This token is a reference to a function
            # Check that it's actually a call (next token should be '(')
            next_tok = token.next
            if next_tok and next_tok.str == "(":
                tok_id = getattr(token, "Id", str(id(token)))
                if tok_id in seen_tokens:
                    continue
                seen_tokens.add(tok_id)

                cs = _CallSite()
                cs.call_token = token
                cs.callee_name = token.str
                cs.callee_function = func_ref
                cs.caller_function = _find_enclosing_function(token, cfg_config)
                cs.is_fptr_call = False
                call_sites.append(cs)
                continue

        # Strategy 2: Look for pattern  name '(' where name is an identifier
        # and it looks like a function call in the AST.
        # We check the AST: if token.astParent exists and astParent.str == '('
        # then the token is the function being called.
        ast_parent = getattr(token, "astParent", None)
        if ast_parent is None:
            continue

        if ast_parent.str != "(":
            continue

        # The '(' token's astOperand1 should be the function being called
        op1 = getattr(ast_parent, "astOperand1", None)
        if op1 is not token:
            continue

        # Skip if we already handled via token.function
        tok_id = getattr(token, "Id", str(id(token)))
        if tok_id in seen_tokens:
            continue
        seen_tokens.add(tok_id)

        cs = _CallSite()
        cs.call_token = token
        cs.callee_name = token.str if token.isName else None

        # Is this a function pointer call?
        var_ref = getattr(token, "variable", None)
        if var_ref is not None and _is_function_pointer_var(var_ref):
            cs.is_fptr_call = True
            cs.fptr_variable = var_ref
        elif not token.isName:
            # Expression like (*fptr)(args) — treat as fptr call
            cs.is_fptr_call = True
        else:
            # Could be a call to a function not seen in this TU (external)
            cs.is_fptr_call = False

        cs.caller_function = _find_enclosing_function(token, cfg_config)
        call_sites.append(cs)

    return call_sites


# ===========================================================================
# BUILDER
# ===========================================================================

class _CallGraphBuilder:
    """Construct a ``CallGraph`` from a ``cppcheckdata.Configuration``."""

    def __init__(self, cfg_config, include_external: bool = True) -> None:
        self.cfg_config = cfg_config
        self.include_external = include_external
        self.cg = CallGraph(cfg_config)
        # Signature index for function-pointer resolution
        self._sig_cache: Dict[str, Optional[Tuple]] = {}

    def build(self) -> CallGraph:
        # Phase 1: Create nodes for all defined functions
        self._create_function_nodes()

        # Phase 2: Build signature index for fptr resolution
        self._build_signature_index()

        # Phase 3: Detect call sites and create edges
        self._process_call_sites()

        # Phase 4: Set up entry node
        self._setup_entry()

        return self.cg

    # ----- Phase 1 ----------------------------------------------------------

    def _create_function_nodes(self) -> None:
        """Create a ``CallGraphNode`` for each ``Function`` in the config."""
        for func in self.cfg_config.functions:
            self.cg.get_or_create_node(function=func, kind=NodeKind.FUNCTION)

    # ----- Phase 2 ----------------------------------------------------------

    def _build_signature_index(self) -> None:
        """Build an index from signature keys to function nodes."""
        for func in self.cfg_config.functions:
            sig = _extract_signature_key(func)
            self._sig_cache[func.Id] = sig
            node = self.cg.node_for_function(func)
            if node is not None:
                node._signature_key = sig
                if sig is not None:
                    self.cg._sig_index[sig].append(node)

    # ----- Phase 3 ----------------------------------------------------------

    def _process_call_sites(self) -> None:
        """For each detected call site, create the appropriate edge(s)."""
        call_sites = _detect_call_sites(self.cfg_config)

        for cs in call_sites:
            caller_node = self._resolve_caller(cs)
            if caller_node is None:
                # Call outside any function scope (shouldn't happen, but be safe)
                continue

            if cs.is_fptr_call:
                self._resolve_fptr_call(cs, caller_node)
            else:
                self._resolve_direct_call(cs, caller_node)

    def _resolve_caller(self, cs: _CallSite) -> Optional[CallGraphNode]:
        """Get or create the caller node."""
        if cs.caller_function is not None:
            return self.cg.get_or_create_node(
                function=cs.caller_function, kind=NodeKind.FUNCTION
            )
        # Call from a non-function scope (e.g. global initialiser)
        # Attach to a synthetic "global init" node
        return self.cg.get_or_create_node(
            name="<global-init>", kind=NodeKind.EXTERNAL,
            node_id="__GLOBAL_INIT__",
        )

    def _resolve_direct_call(
        self, cs: _CallSite, caller_node: CallGraphNode
    ) -> None:
        """Resolve a direct (non-fptr) call."""
        # Try the Cppcheck-resolved function first
        if cs.callee_function is not None:
            callee_node = self.cg.get_or_create_node(
                function=cs.callee_function, kind=NodeKind.FUNCTION
            )
            self.cg.add_edge(
                caller_node, callee_node,
                call_token=cs.call_token,
                resolution=CallResolutionKind.DIRECT,
            )
            return

        # Try by name
        if cs.callee_name:
            candidates = self.cg.functions_by_name(cs.callee_name)
            if candidates:
                for callee_node in candidates:
                    self.cg.add_edge(
                        caller_node, callee_node,
                        call_token=cs.call_token,
                        resolution=CallResolutionKind.DIRECT,
                    )
                return

            # Not found — external function
            if self.include_external:
                callee_node = self.cg.get_or_create_node(
                    name=cs.callee_name,
                    kind=NodeKind.EXTERNAL,
                    node_id=f"__EXT__{cs.callee_name}",
                )
                self.cg.add_edge(
                    caller_node, callee_node,
                    call_token=cs.call_token,
                    resolution=CallResolutionKind.DIRECT,
                )
                return

        # Completely unresolved
        self.cg.add_edge(
            caller_node, self.cg.unknown,
            call_token=cs.call_token,
            resolution=CallResolutionKind.UNRESOLVED,
        )

    def _resolve_fptr_call(
        self, cs: _CallSite, caller_node: CallGraphNode
    ) -> None:
        """Resolve a function-pointer call conservatively.

        Uses type-based signature matching (similar to rapid type analysis):
        any function whose signature is compatible with the function pointer's
        declared type is a potential target.
        """
        fptr_sig: Optional[Tuple] = None
        if cs.fptr_variable is not None:
            fptr_sig = _extract_fptr_signature(cs.fptr_variable)

        resolved_any = False

        if fptr_sig is not None:
            # Check all functions for signature compatibility
            for node in self.cg.nodes.values():
                if node.kind != NodeKind.FUNCTION:
                    continue
                if node.function is None:
                    continue
                func_sig = self._sig_cache.get(node.function.Id)
                if _signatures_compatible(fptr_sig, func_sig):
                    self.cg.add_edge(
                        caller_node, node,
                        call_token=cs.call_token,
                        resolution=CallResolutionKind.FUNCTION_POINTER,
                    )
                    resolved_any = True

        # Also try to resolve through ValueFlow: if the fptr variable has
        # known values that are function addresses, use those.
        if cs.fptr_variable is not None:
            vf_targets = self._resolve_fptr_via_valueflow(cs.fptr_variable)
            for target_node in vf_targets:
                # Avoid duplicate edges
                already = any(
                    e.callee is target_node
                    and e.call_token is cs.call_token
                    for e in caller_node.out_edges
                )
                if not already:
                    self.cg.add_edge(
                        caller_node, target_node,
                        call_token=cs.call_token,
                        resolution=CallResolutionKind.FUNCTION_POINTER,
                    )
                    resolved_any = True

        if not resolved_any:
            # Totally unresolved function pointer call
            self.cg.add_edge(
                caller_node, self.cg.unknown,
                call_token=cs.call_token,
                resolution=CallResolutionKind.UNRESOLVED,
            )

    def _resolve_fptr_via_valueflow(self, variable) -> List[CallGraphNode]:
        """Use Cppcheck's ValueFlow to find function targets.

        If the variable has ``values`` (a list of ``ValueFlow.Value``) where
        ``value.tokvalue`` refers to a function token, we can resolve the
        target.
        """
        results: List[CallGraphNode] = []
        name_tok = getattr(variable, "nameToken", None)
        if name_tok is None:
            return results

        values = getattr(name_tok, "values", None)
        if not values:
            return results

        for val in values:
            tok_val = getattr(val, "tokvalue", None)
            if tok_val is None:
                continue
            # Check if tokvalue.function is set
            func_ref = getattr(tok_val, "function", None)
            if func_ref is not None:
                node = self.cg.node_for_function(func_ref)
                if node is not None:
                    results.append(node)
                continue
            # Check if tokvalue is a name that matches a known function
            if tok_val.isName:
                candidates = self.cg.functions_by_name(tok_val.str)
                results.extend(candidates)

        return results

    # ----- Phase 4 ----------------------------------------------------------

    def _setup_entry(self) -> None:
        """Create a synthetic entry node pointing to ``main`` (if present)."""
        entry = self.cg.get_or_create_node(
            name="<entry>", kind=NodeKind.ENTRY, node_id="__ENTRY__"
        )
        self.cg.entry = entry

        # Find 'main'
        main_nodes = self.cg.functions_by_name("main")
        if main_nodes:
            for mn in main_nodes:
                self.cg.add_edge(entry, mn, resolution=CallResolutionKind.DIRECT)
        else:
            # No main — connect entry to all roots (library code, etc.)
            for n in list(self.cg.nodes.values()):
                if (
                    n.kind == NodeKind.FUNCTION
                    and n.is_root
                    and n is not entry
                ):
                    self.cg.add_edge(
                        entry, n, resolution=CallResolutionKind.DIRECT
                    )


# ===========================================================================
# PUBLIC API
# ===========================================================================

def build_callgraph(
    cfg_config,
    include_external: bool = True,
) -> CallGraph:
    """Build the call graph for a Cppcheck ``Configuration``.

    Parameters
    ----------
    cfg_config : cppcheckdata.Configuration
        A configuration from a parsed dump file.
    include_external : bool, optional
        If ``True`` (default), create nodes for functions that are called
        but not defined in this translation unit (library functions, etc.).
        If ``False``, calls to undefined functions are routed to the
        ``UNKNOWN`` node.

    Returns
    -------
    CallGraph
        The constructed call graph.

    Example
    -------
    ::

        import cppcheckdata
        from cppcheckdata_shims.callgraph import build_callgraph

        data = cppcheckdata.parsedump("example.c.dump")
        cg = build_callgraph(data.configurations[0])

        # Print all call edges
        for edge in cg.edges:
            print(f"{edge.caller.name} -> {edge.callee.name}  "
                  f"[{edge.resolution.value}]")

        # Compute bottom-up traversal order for interprocedural analysis
        for node in cg.bottom_up_order():
            print(node.name)
    """
    builder = _CallGraphBuilder(cfg_config, include_external=include_external)
    return builder.build()


# ---------------------------------------------------------------------------
# Convenience utilities
# ---------------------------------------------------------------------------

def callgraph_summary(cg: CallGraph) -> str:
    """Return a human-readable multi-line summary."""
    stats = cg.statistics()
    lines = [
        f"Call Graph Summary",
        f"  Functions (defined):  {stats['functions']}",
        f"  External functions:   {stats['external_functions']}",
        f"  Total nodes:          {stats['total_nodes']}",
        f"  Total edges:          {stats['total_edges']}",
        f"  Direct calls:         {stats['direct_calls']}",
        f"  FPtr calls:           {stats['function_pointer_calls']}",
        f"  Unresolved calls:     {stats['unresolved_calls']}",
        f"  SCCs:                 {stats['sccs']}",
        f"  Recursive SCCs:       {stats['recursive_sccs']}",
        f"  Self-recursive funcs: {stats['self_recursive_functions']}",
        f"  Root functions:       {stats['root_functions']}",
        f"  Leaf functions:       {stats['leaf_functions']}",
        f"",
        f"Functions:",
    ]
    for node in cg.nodes.values():
        if node.kind in (NodeKind.UNKNOWN, NodeKind.ENTRY):
            continue
        callee_names = [e.callee.name for e in node.out_edges]
        caller_names = [e.caller.name for e in node.in_edges]
        lines.append(
            f"  {node.name} ({node.kind.value}): "
            f"calls [{', '.join(callee_names)}], "
            f"called by [{', '.join(caller_names)}]"
        )
    return "\n".join(lines)


def find_recursive_functions(cg: CallGraph) -> List[Set[CallGraphNode]]:
    """Return a list of sets of mutually-recursive functions.

    Each set contains ≥ 1 function.  Singleton sets indicate direct
    self-recursion.  Sets with multiple elements indicate mutual recursion.
    """
    sccs = cg.strongly_connected_components()
    result: List[Set[CallGraphNode]] = []
    for scc in sccs:
        # A single-element SCC is only recursive if it has a self-edge
        if len(scc) == 1:
            node = scc[0]
            if node.is_recursive:
                result.append({node})
        else:
            # Multi-element SCC = mutual recursion
            result.append(set(scc))
    return result


def unreachable_functions(cg: CallGraph) -> List[CallGraphNode]:
    """Return functions not reachable from the entry point."""
    if cg.entry is None:
        return []

    reachable: Set[CallGraphNode] = set()
    worklist: Deque[CallGraphNode] = deque([cg.entry])
    while worklist:
        n = worklist.popleft()
        if n in reachable:
            continue
        reachable.add(n)
        for e in n.out_edges:
            worklist.append(e.callee)

    return [
        n for n in cg.nodes.values()
        if n not in reachable
        and n.kind == NodeKind.FUNCTION
    ]
