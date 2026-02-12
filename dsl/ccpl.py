"""
ccpl.py — Cppcheck Configuration Pattern Language (CCPL)
=========================================================

A bottom-up tree automaton with:
  - Global state for cross-match data accumulation
  - Trace-locking for sequential pattern protocols
  - Guards (post-match predicates)
  - Predicates (pre-match filters)
  - Callback-driven match notification with rich context

Parses pattern specifications from S-expressions via the ``sexpdata`` library.

Depends on:
    - sexpdata          (S-expression parsing)
    - cppcheckdata      (Cppcheck dump file model)
"""

from __future__ import annotations

import copy
import enum
import logging
import re
import time
from dataclasses import dataclass, field
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

try:
    import sexpdata
except ImportError:
    sexpdata = None  # type: ignore

try:
    import cppcheckdata
except ImportError:
    cppcheckdata = None  # type: ignore

logger = logging.getLogger(__name__)


# ===================================================================
#  PART 1 — S-EXPRESSION PARSING LAYER
# ===================================================================

def _parse_sexp(text: str) -> Any:
    """Parse an S-expression string into a nested Python structure.

    Uses ``sexpdata.loads`` to parse, then normalises the result:
      - ``sexpdata.Symbol`` → ``str``
      - ``list`` → ``list`` (recursively normalised)
      - atoms (int, float, str) → kept as-is

    Parameters
    ----------
    text : str
        An S-expression string, e.g. ``"(defpattern div-by-zero (/ ?x 0))"``

    Returns
    -------
    Nested list/atom structure.

    Raises
    ------
    CCPLParseError
        If ``sexpdata`` is not available or the input is malformed.
    """
    if sexpdata is None:
        raise CCPLParseError("sexpdata library is required for CCPL. "
                             "Install with: pip install sexpdata")
    try:
        parsed = sexpdata.loads(text)
    except Exception as e:
        raise CCPLParseError(f"Failed to parse S-expression: {e}") from e
    return _normalise(parsed)


def _parse_sexp_many(text: str) -> List[Any]:
    """Parse a string containing multiple top-level S-expressions.

    Returns
    -------
    list
        List of normalised parse trees, one per top-level form.
    """
    if sexpdata is None:
        raise CCPLParseError("sexpdata library is required for CCPL")
    # sexpdata does not natively parse multiple forms; we wrap in a list
    # and strip the outer layer.
    wrapped = f"({text})"
    try:
        parsed = sexpdata.loads(wrapped)
    except Exception as e:
        raise CCPLParseError(f"Failed to parse S-expression stream: {e}") from e
    return [_normalise(item) for item in parsed]


def _normalise(obj: Any) -> Any:
    """Recursively normalise sexpdata output to plain Python types."""
    if isinstance(obj, list):
        return [_normalise(x) for x in obj]
    # sexpdata.Symbol → str
    if hasattr(obj, 'value') and callable(getattr(obj, 'value', None)):
        return str(obj.value())
    if hasattr(obj, '_val'):
        return str(obj._val)
    # sexpdata uses Symbol class; try tosexp fallback
    type_name = type(obj).__name__
    if type_name == 'Symbol':
        return str(obj)
    if type_name == 'Quoted':
        inner = getattr(obj, '_val', obj)
        return ['quote', _normalise(inner)]
    if type_name == 'Bracket':
        inner = getattr(obj, '_val', obj)
        return ['bracket', _normalise(inner)]
    if isinstance(obj, (int, float, bool)):
        return obj
    if isinstance(obj, str):
        return obj
    # Fallback
    return str(obj)


def _sexp_to_string(obj: Any) -> str:
    """Convert a normalised S-expression back to string form."""
    if isinstance(obj, list):
        inner = " ".join(_sexp_to_string(x) for x in obj)
        return f"({inner})"
    if isinstance(obj, str):
        if " " in obj or "(" in obj or ")" in obj:
            escaped = obj.replace('"', '\\"')
            return f'"{escaped}"'
        return obj
    return str(obj)


# ===================================================================
#  PART 2 — EXCEPTIONS
# ===================================================================

class CCPLError(Exception):
    """Base exception for all CCPL errors."""
    pass


class CCPLParseError(CCPLError):
    """Raised when S-expression parsing fails."""
    pass


class CCPLCompileError(CCPLError):
    """Raised when a pattern specification is malformed."""
    pass


class CCPLRuntimeError(CCPLError):
    """Raised during pattern matching execution."""
    pass


# ===================================================================
#  PART 3 — PATTERN AST
# ===================================================================

class PatternNodeKind(enum.Enum):
    """Kinds of nodes in a compiled CCPL pattern tree."""
    LITERAL = "literal"           # exact match on a string/number
    WILDCARD = "wildcard"         # matches anything: _
    CAPTURE = "capture"           # captures into a named binding: ?name
    TYPED_CAPTURE = "typed"       # captures with type constraint: ?name:type
    REST_CAPTURE = "rest"         # captures remaining children: ?...name
    SEQUENCE = "sequence"         # ordered list of child patterns (tree node)
    ALTERNATION = "alternation"   # (or pat1 pat2 ...)
    NEGATION = "negation"         # (not pat)
    REPETITION = "repetition"     # (* pat) — zero or more
    PLUS_REP = "plus_rep"         # (+ pat) — one or more
    OPTIONAL = "optional"         # (? pat) — zero or one
    PREDICATE_REF = "pred_ref"    # (pred name) — reference to a named predicate
    GUARD_REF = "guard_ref"       # (guard name) — reference to a named guard
    DEEP = "deep"                 # (deep pat) — match anywhere in subtree
    ANY_OF = "any_of"             # (any-of val1 val2 ...) — match any literal
    BIND = "bind"                 # (bind name pat) — bind subtree to name
    HEAD = "head"                 # match only the head (first element) of a list
    WHERE = "where"               # (where pat guard-expr) — inline guard


@dataclass
class PatternNode:
    """A node in a compiled CCPL pattern tree."""
    kind: PatternNodeKind
    value: Any = None                          # for LITERAL: the value to match
    name: Optional[str] = None                 # for CAPTURE/BIND: binding name
    type_constraint: Optional[str] = None      # for TYPED_CAPTURE: "name"/"number"/"op"/...
    children: List["PatternNode"] = field(default_factory=list)
    source: Optional[str] = None               # original S-expression fragment

    def pretty(self, indent: int = 0) -> str:
        prefix = "  " * indent
        parts = [f"{prefix}{self.kind.value}"]
        if self.value is not None:
            parts.append(f" value={self.value!r}")
        if self.name:
            parts.append(f" name={self.name}")
        if self.type_constraint:
            parts.append(f" type={self.type_constraint}")
        result = "".join(parts)
        for child in self.children:
            result += "\n" + child.pretty(indent + 1)
        return result


# ===================================================================
#  PART 4 — PATTERN COMPILER
# ===================================================================

# Type constraints that can be used in ?name:type captures
_TYPE_CONSTRAINTS = {
    "name": lambda tok: getattr(tok, "isName", False),
    "number": lambda tok: getattr(tok, "isNumber", False),
    "int": lambda tok: getattr(tok, "isInt", False),
    "float": lambda tok: getattr(tok, "isFloat", False),
    "string": lambda tok: getattr(tok, "isString", False),
    "op": lambda tok: getattr(tok, "isOp", False),
    "arith": lambda tok: getattr(tok, "isArithmeticalOp", False),
    "assign": lambda tok: getattr(tok, "isAssignmentOp", False),
    "cmp": lambda tok: getattr(tok, "isComparisonOp", False),
    "logic": lambda tok: getattr(tok, "isLogicalOp", False),
    "bool": lambda tok: getattr(tok, "isBoolean", False),
    "char": lambda tok: getattr(tok, "isChar", False),
    "ptr": lambda tok: (getattr(tok, "valueType", None) is not None
                        and getattr(tok.valueType, "pointer", 0) > 0),
    "var": lambda tok: getattr(tok, "variable", None) is not None,
    "func": lambda tok: getattr(tok, "function", None) is not None,
    "any": lambda tok: True,
}


class PatternCompiler:
    """Compiles normalised S-expressions into ``PatternNode`` trees.

    The compiler recognises the following pattern forms:

    - ``_`` — wildcard (matches anything)
    - ``?name`` — capture variable
    - ``?name:type`` — typed capture (e.g., ``?x:name``, ``?n:int``)
    - ``?...name`` — rest capture (captures remaining siblings)
    - ``"literal"`` or ``symbol`` — exact literal match
    - ``123`` — exact numeric literal match
    - ``(or pat1 pat2 ...)`` — alternation
    - ``(not pat)`` — negation
    - ``(* pat)`` — zero-or-more repetition
    - ``(+ pat)`` — one-or-more repetition
    - ``(? pat)`` — optional (zero or one)
    - ``(deep pat)`` — match anywhere in subtree (deep descent)
    - ``(any-of v1 v2 ...)`` — match any of the listed literals
    - ``(bind name pat)`` — bind the matched subtree to ``name``
    - ``(where pat guard-name)`` — match pat, then apply named guard
    - ``(pred name)`` — apply named predicate to current node
    - ``(guard name)`` — attach named guard to enclosing match
    - ``(head pat)`` — match only the head element of a list node
    - ``(seq pat1 pat2 ...)`` — explicit sequence (usually implicit in lists)
    """

    def compile(self, sexp: Any) -> PatternNode:
        """Compile a normalised S-expression into a PatternNode tree.

        Parameters
        ----------
        sexp : any
            Output of ``_normalise(_parse_sexp(...))``.

        Returns
        -------
        PatternNode
        """
        return self._compile(sexp)

    def compile_from_string(self, text: str) -> PatternNode:
        """Parse and compile a pattern from an S-expression string."""
        sexp = _parse_sexp(text)
        return self._compile(sexp)

    def _compile(self, sexp: Any) -> PatternNode:
        """Recursive compilation."""
        # Atom cases
        if isinstance(sexp, str):
            return self._compile_atom(sexp)
        if isinstance(sexp, (int, float, bool)):
            return PatternNode(PatternNodeKind.LITERAL, value=sexp,
                               source=str(sexp))

        # List cases
        if isinstance(sexp, list):
            if not sexp:
                return PatternNode(PatternNodeKind.LITERAL, value=[],
                                   source="()")

            head = sexp[0] if isinstance(sexp[0], str) else None

            # Special forms
            if head == "or" and len(sexp) >= 3:
                children = [self._compile(s) for s in sexp[1:]]
                return PatternNode(PatternNodeKind.ALTERNATION,
                                   children=children,
                                   source=_sexp_to_string(sexp))

            if head == "not" and len(sexp) == 2:
                child = self._compile(sexp[1])
                return PatternNode(PatternNodeKind.NEGATION,
                                   children=[child],
                                   source=_sexp_to_string(sexp))

            if head == "*" and len(sexp) == 2:
                child = self._compile(sexp[1])
                return PatternNode(PatternNodeKind.REPETITION,
                                   children=[child],
                                   source=_sexp_to_string(sexp))

            if head == "+" and len(sexp) == 2:
                child = self._compile(sexp[1])
                return PatternNode(PatternNodeKind.PLUS_REP,
                                   children=[child],
                                   source=_sexp_to_string(sexp))

            if head == "?" and len(sexp) == 2:
                child = self._compile(sexp[1])
                return PatternNode(PatternNodeKind.OPTIONAL,
                                   children=[child],
                                   source=_sexp_to_string(sexp))

            if head == "deep" and len(sexp) == 2:
                child = self._compile(sexp[1])
                return PatternNode(PatternNodeKind.DEEP,
                                   children=[child],
                                   source=_sexp_to_string(sexp))

            if head == "any-of" and len(sexp) >= 2:
                values = sexp[1:]
                return PatternNode(PatternNodeKind.ANY_OF,
                                   value=values,
                                   source=_sexp_to_string(sexp))

            if head == "bind" and len(sexp) == 3:
                name = str(sexp[1])
                child = self._compile(sexp[2])
                return PatternNode(PatternNodeKind.BIND,
                                   name=name, children=[child],
                                   source=_sexp_to_string(sexp))

            if head == "where" and len(sexp) == 3:
                child = self._compile(sexp[1])
                guard_name = str(sexp[2])
                return PatternNode(PatternNodeKind.WHERE,
                                   name=guard_name, children=[child],
                                   source=_sexp_to_string(sexp))

            if head == "pred" and len(sexp) == 2:
                return PatternNode(PatternNodeKind.PREDICATE_REF,
                                   name=str(sexp[1]),
                                   source=_sexp_to_string(sexp))

            if head == "guard" and len(sexp) == 2:
                return PatternNode(PatternNodeKind.GUARD_REF,
                                   name=str(sexp[1]),
                                   source=_sexp_to_string(sexp))

            if head == "head" and len(sexp) == 2:
                child = self._compile(sexp[1])
                return PatternNode(PatternNodeKind.HEAD,
                                   children=[child],
                                   source=_sexp_to_string(sexp))

            if head == "seq":
                children = [self._compile(s) for s in sexp[1:]]
                return PatternNode(PatternNodeKind.SEQUENCE,
                                   children=children,
                                   source=_sexp_to_string(sexp))

            # Default: treat as a tree node (SEQUENCE) — the head is the
            # operator/function and the rest are children
            children = [self._compile(s) for s in sexp]
            return PatternNode(PatternNodeKind.SEQUENCE,
                               children=children,
                               source=_sexp_to_string(sexp))

        # Fallback
        return PatternNode(PatternNodeKind.LITERAL, value=sexp,
                           source=str(sexp))

    def _compile_atom(self, s: str) -> PatternNode:
        """Compile a string atom."""
        # Wildcard
        if s == "_":
            return PatternNode(PatternNodeKind.WILDCARD, source="_")

        # Rest capture: ?...name
        if s.startswith("?...") and len(s) > 4:
            name = s[4:]
            return PatternNode(PatternNodeKind.REST_CAPTURE, name=name,
                               source=s)

        # Typed capture: ?name:type
        if s.startswith("?") and ":" in s and len(s) > 2:
            rest = s[1:]
            parts = rest.split(":", 1)
            if len(parts) == 2 and parts[0] and parts[1]:
                name, type_c = parts
                if type_c not in _TYPE_CONSTRAINTS:
                    raise CCPLCompileError(
                        f"Unknown type constraint '{type_c}' in '{s}'. "
                        f"Valid types: {', '.join(sorted(_TYPE_CONSTRAINTS))}")
                return PatternNode(PatternNodeKind.TYPED_CAPTURE,
                                   name=name, type_constraint=type_c,
                                   source=s)

        # Simple capture: ?name
        if s.startswith("?") and len(s) > 1:
            name = s[1:]
            return PatternNode(PatternNodeKind.CAPTURE, name=name, source=s)

        # Literal
        return PatternNode(PatternNodeKind.LITERAL, value=s, source=s)


# ===================================================================
#  PART 5 — MATCH CONTEXT
# ===================================================================

@dataclass
class MatchBinding:
    """A single captured binding from a pattern match."""
    name: str
    value: Any                # the matched Cppcheck object (Token, etc.)
    token: Optional[Any] = None  # the Token if the value is a token
    text: Optional[str] = None   # string representation

    def __repr__(self):
        return f"MatchBinding({self.name}={self.text or self.value!r})"


@dataclass
class MatchContext:
    """Rich context object passed to callbacks on successful match.

    Attributes
    ----------
    pattern_name : str
        Name of the matched pattern rule.
    bindings : dict
        Named capture bindings: ``{name: MatchBinding}``.
    matched_node : any
        The root Cppcheck object (Token, Scope, etc.) that was matched.
    matched_children : list
        The list of child objects that participated in the match.
    global_state : dict
        Reference to the engine's mutable global state.
    location : tuple or None
        ``(file, line, column)`` if determinable.
    pattern : PatternNode
        The compiled pattern that matched.
    rule : "Rule"
        The full rule object (including guards, predicates, etc.).
    match_depth : int
        Depth in the tree at which the match occurred.
    timestamp : float
        Time of match (``time.monotonic()``).
    """
    pattern_name: str
    bindings: Dict[str, MatchBinding]
    matched_node: Any
    matched_children: List[Any] = field(default_factory=list)
    global_state: Dict[str, Any] = field(default_factory=dict)
    location: Optional[Tuple[str, int, int]] = None
    pattern: Optional[PatternNode] = None
    rule: Optional["Rule"] = None
    match_depth: int = 0
    timestamp: float = 0.0

    def __getitem__(self, name: str) -> Any:
        """Shortcut to get a binding value by name."""
        b = self.bindings.get(name)
        if b is None:
            raise KeyError(f"No binding named '{name}'")
        return b.value

    def get(self, name: str, default: Any = None) -> Any:
        """Get a binding value, with default."""
        b = self.bindings.get(name)
        return b.value if b is not None else default

    def has(self, name: str) -> bool:
        """Check if a binding exists."""
        return name in self.bindings

    def token_of(self, name: str) -> Optional[Any]:
        """Get the Token object for a binding, if available."""
        b = self.bindings.get(name)
        return b.token if b is not None else None

    def set_global(self, key: str, value: Any) -> None:
        """Write to global state."""
        self.global_state[key] = value

    def get_global(self, key: str, default: Any = None) -> Any:
        """Read from global state."""
        return self.global_state.get(key, default)

    def append_global(self, key: str, value: Any) -> None:
        """Append to a list in global state (creates list if needed)."""
        lst = self.global_state.setdefault(key, [])
        lst.append(value)

    def pretty(self) -> str:
        lines = [f"Match: {self.pattern_name}"]
        if self.location:
            f, l, c = self.location
            lines.append(f"  at {f}:{l}:{c}")
        for name, binding in sorted(self.bindings.items()):
            lines.append(f"  {name} = {binding.text or binding.value!r}")
        return "\n".join(lines)


# ===================================================================
#  PART 6 — RULES
# ===================================================================

# Predicate: (engine_state, node) → bool
PredicateFunc = Callable[[Dict[str, Any], Any], bool]

# Guard: (MatchContext) → bool
GuardFunc = Callable[[MatchContext], bool]

# Callback: (MatchContext) → None
CallbackFunc = Callable[[MatchContext], None]


@dataclass
class Rule:
    """A named CCPL rule: pattern + predicate + guard + callback + trace-lock.

    Attributes
    ----------
    name : str
        Unique name for this rule.
    pattern : PatternNode
        Compiled pattern tree.
    callback : CallbackFunc
        Called on successful match (after guard passes).
    predicate : PredicateFunc or None
        Pre-match filter. If returns False, the pattern is not attempted.
    guard : GuardFunc or None
        Post-match filter. If returns False, the match is discarded.
    lock_to : str or None
        If set, upon matching this rule the engine enters trace-lock mode
        and will *only* accept the rule named ``lock_to``.
    unlock : bool
        If True, matching this rule releases any active trace-lock.
    priority : int
        Lower number = higher priority. Rules are tried in priority order.
    enabled : bool
        Can be dynamically disabled.
    tags : set
        Optional tags for filtering/grouping.
    description : str
        Human-readable description.
    source_sexp : str
        Original S-expression source (for debugging/serialisation).
    """
    name: str
    pattern: PatternNode
    callback: CallbackFunc
    predicate: Optional[PredicateFunc] = None
    guard: Optional[GuardFunc] = None
    lock_to: Optional[str] = None
    unlock: bool = False
    priority: int = 100
    enabled: bool = True
    tags: Set[str] = field(default_factory=set)
    description: str = ""
    source_sexp: str = ""


# ===================================================================
#  PART 7 — PATTERN MATCHER (bottom-up tree automaton core)
# ===================================================================

class PatternMatcher:
    """Core matching engine: matches a ``PatternNode`` against Cppcheck AST nodes.

    The matching is **bottom-up**: we first match children, then the parent.
    This implements the tree automaton semantics where states propagate from
    leaves to the root.
    """

    def __init__(self,
                 predicates: Optional[Dict[str, PredicateFunc]] = None,
                 guards: Optional[Dict[str, GuardFunc]] = None):
        self._predicates = predicates or {}
        self._guards = guards or {}

    def match(self, pattern: PatternNode, node: Any,
              bindings: Optional[Dict[str, MatchBinding]] = None,
              engine_state: Optional[Dict[str, Any]] = None,
              depth: int = 0) -> Optional[Dict[str, MatchBinding]]:
        """Attempt to match ``pattern`` against ``node``.

        Parameters
        ----------
        pattern : PatternNode
            Compiled pattern.
        node : any
            A Cppcheck Token, Scope, or other dump object. Can also be
            a plain string/number for testing.
        bindings : dict, optional
            Existing bindings (for recursive matching). Copied, not mutated.
        engine_state : dict, optional
            Global engine state (for predicate evaluation).
        depth : int
            Current tree depth.

        Returns
        -------
        dict or None
            Updated bindings dict if match succeeds, ``None`` if it fails.
        """
        bindings = dict(bindings) if bindings else {}
        engine_state = engine_state or {}
        return self._match(pattern, node, bindings, engine_state, depth)

    def _match(self, pat: PatternNode, node: Any,
               bindings: Dict[str, MatchBinding],
               state: Dict[str, Any],
               depth: int) -> Optional[Dict[str, MatchBinding]]:
        """Recursive matching dispatch."""

        kind = pat.kind

        # ---- WILDCARD ----
        if kind == PatternNodeKind.WILDCARD:
            return bindings

        # ---- LITERAL ----
        if kind == PatternNodeKind.LITERAL:
            return self._match_literal(pat, node, bindings)

        # ---- CAPTURE ----
        if kind == PatternNodeKind.CAPTURE:
            return self._match_capture(pat, node, bindings)

        # ---- TYPED CAPTURE ----
        if kind == PatternNodeKind.TYPED_CAPTURE:
            return self._match_typed_capture(pat, node, bindings)

        # ---- REST CAPTURE ----
        if kind == PatternNodeKind.REST_CAPTURE:
            # Handled specially inside SEQUENCE matching
            return self._match_capture(pat, node, bindings)

        # ---- SEQUENCE ----
        if kind == PatternNodeKind.SEQUENCE:
            return self._match_sequence(pat, node, bindings, state, depth)

        # ---- ALTERNATION ----
        if kind == PatternNodeKind.ALTERNATION:
            for child in pat.children:
                result = self._match(child, node, dict(bindings), state, depth)
                if result is not None:
                    return result
            return None

        # ---- NEGATION ----
        if kind == PatternNodeKind.NEGATION:
            child_result = self._match(pat.children[0], node,
                                       dict(bindings), state, depth)
            if child_result is None:
                return bindings  # negation succeeds when child fails
            return None

        # ---- DEEP ----
        if kind == PatternNodeKind.DEEP:
            return self._match_deep(pat.children[0], node, bindings,
                                    state, depth)

        # ---- ANY_OF ----
        if kind == PatternNodeKind.ANY_OF:
            node_str = self._node_str(node)
            for v in pat.value:
                if node_str == str(v):
                    return bindings
                if isinstance(v, (int, float)) and self._node_number(node) == v:
                    return bindings
            return None

        # ---- BIND ----
        if kind == PatternNodeKind.BIND:
            result = self._match(pat.children[0], node, dict(bindings),
                                 state, depth)
            if result is not None:
                result[pat.name] = MatchBinding(
                    name=pat.name, value=node,
                    token=node if self._is_token(node) else None,
                    text=self._node_str(node),
                )
            return result

        # ---- WHERE (inline guard) ----
        if kind == PatternNodeKind.WHERE:
            result = self._match(pat.children[0], node, dict(bindings),
                                 state, depth)
            if result is not None:
                guard_name = pat.name
                guard_fn = self._guards.get(guard_name)
                if guard_fn is not None:
                    ctx = MatchContext(
                        pattern_name="<where>",
                        bindings=result,
                        matched_node=node,
                        global_state=state,
                    )
                    if not guard_fn(ctx):
                        return None
            return result

        # ---- PREDICATE_REF ----
        if kind == PatternNodeKind.PREDICATE_REF:
            pred_fn = self._predicates.get(pat.name)
            if pred_fn is None:
                logger.warning("Unknown predicate '%s'", pat.name)
                return None
            if pred_fn(state, node):
                return bindings
            return None

        # ---- GUARD_REF ----
        if kind == PatternNodeKind.GUARD_REF:
            # Guard refs are collected and applied post-match by the engine
            # During structural matching, they always succeed
            return bindings

        # ---- OPTIONAL ----
        if kind == PatternNodeKind.OPTIONAL:
            result = self._match(pat.children[0], node, dict(bindings),
                                 state, depth)
            if result is not None:
                return result
            return bindings  # optional: succeed even if child fails

        # ---- REPETITION (* and +) ----
        if kind in (PatternNodeKind.REPETITION, PatternNodeKind.PLUS_REP):
            return self._match_repetition(pat, node, bindings, state, depth)

        # ---- HEAD ----
        if kind == PatternNodeKind.HEAD:
            children = self._get_children(node)
            if children:
                return self._match(pat.children[0], children[0],
                                   bindings, state, depth + 1)
            return None

        return None

    # ---- Matching helpers ----

    def _match_literal(self, pat: PatternNode, node: Any,
                       bindings: Dict[str, MatchBinding]
                       ) -> Optional[Dict[str, MatchBinding]]:
        """Match a literal value against a node."""
        expected = pat.value
        # Compare as string
        node_str = self._node_str(node)
        if node_str == str(expected):
            return bindings
        # Compare as number
        if isinstance(expected, (int, float)):
            node_num = self._node_number(node)
            if node_num is not None and node_num == expected:
                return bindings
        # Compare lists
        if isinstance(expected, list) and isinstance(node, list):
            if expected == [] and node == []:
                return bindings
        return None

    def _match_capture(self, pat: PatternNode, node: Any,
                       bindings: Dict[str, MatchBinding]
                       ) -> Optional[Dict[str, MatchBinding]]:
        """Match a capture variable — always succeeds, recording the binding."""
        name = pat.name
        # If already bound, check consistency
        if name in bindings:
            existing = bindings[name]
            if self._node_str(node) != existing.text:
                return None
            return bindings
        bindings[name] = MatchBinding(
            name=name, value=node,
            token=node if self._is_token(node) else None,
            text=self._node_str(node),
        )
        return bindings

    def _match_typed_capture(self, pat: PatternNode, node: Any,
                             bindings: Dict[str, MatchBinding]
                             ) -> Optional[Dict[str, MatchBinding]]:
        """Match a typed capture: check type constraint, then bind."""
        type_c = pat.type_constraint
        checker = _TYPE_CONSTRAINTS.get(type_c)
        if checker is None:
            return None
        if not self._is_token(node):
            # For non-token nodes, only "any" type passes
            if type_c != "any":
                return None
        else:
            if not checker(node):
                return None
        return self._match_capture(pat, node, bindings)

    def _match_sequence(self, pat: PatternNode, node: Any,
                        bindings: Dict[str, MatchBinding],
                        state: Dict[str, Any],
                        depth: int) -> Optional[Dict[str, MatchBinding]]:
        """Match a SEQUENCE pattern against a tree node.

        For Cppcheck tokens, a 'tree node' is a token with AST children
        (astOperand1, astOperand2). The sequence pattern's children are
        matched against [token_str, astOperand1, astOperand2].

        For plain lists (testing), we match element by element.
        """
        pat_children = pat.children
        node_children = self._get_node_as_list(node)

        if not pat_children:
            return bindings if not node_children else None

        return self._match_children(pat_children, node_children,
                                    bindings, state, depth + 1)

    def _match_children(self, patterns: List[PatternNode],
                        nodes: List[Any],
                        bindings: Dict[str, MatchBinding],
                        state: Dict[str, Any],
                        depth: int) -> Optional[Dict[str, MatchBinding]]:
        """Match a list of pattern children against a list of node children.

        Handles REST_CAPTURE (?...name) to consume remaining elements.
        """
        pi = 0  # pattern index
        ni = 0  # node index

        while pi < len(patterns):
            pat_child = patterns[pi]

            # Rest capture: consumes all remaining nodes
            if pat_child.kind == PatternNodeKind.REST_CAPTURE:
                rest = nodes[ni:]
                bindings[pat_child.name] = MatchBinding(
                    name=pat_child.name, value=rest,
                    text=str([self._node_str(n) for n in rest]),
                )
                return bindings

            # Repetition: try to match as many nodes as possible
            if pat_child.kind == PatternNodeKind.REPETITION:
                # Greedy: try matching from all remaining, then fewer
                inner = pat_child.children[0]
                for end in range(len(nodes), ni - 1, -1):
                    sub_bindings = dict(bindings)
                    ok = True
                    for j in range(ni, end):
                        result = self._match(inner, nodes[j],
                                             dict(sub_bindings), state, depth)
                        if result is None:
                            ok = False
                            break
                        sub_bindings = result
                    if ok:
                        # Try matching remaining patterns against remaining nodes
                        rest_result = self._match_children(
                            patterns[pi + 1:], nodes[end:],
                            sub_bindings, state, depth)
                        if rest_result is not None:
                            return rest_result
                return None

            # Plus repetition: at least one
            if pat_child.kind == PatternNodeKind.PLUS_REP:
                inner = pat_child.children[0]
                for end in range(len(nodes), ni, -1):  # at least 1
                    sub_bindings = dict(bindings)
                    ok = True
                    for j in range(ni, end):
                        result = self._match(inner, nodes[j],
                                             dict(sub_bindings), state, depth)
                        if result is None:
                            ok = False
                            break
                        sub_bindings = result
                    if ok:
                        rest_result = self._match_children(
                            patterns[pi + 1:], nodes[end:],
                            sub_bindings, state, depth)
                        if rest_result is not None:
                            return rest_result
                return None

            # Optional: try with and without
            if pat_child.kind == PatternNodeKind.OPTIONAL:
                inner = pat_child.children[0]
                # Try matching one node
                if ni < len(nodes):
                    result = self._match(inner, nodes[ni],
                                         dict(bindings), state, depth)
                    if result is not None:
                        rest_result = self._match_children(
                            patterns[pi + 1:], nodes[ni + 1:],
                            result, state, depth)
                        if rest_result is not None:
                            return rest_result
                # Try skipping
                rest_result = self._match_children(
                    patterns[pi + 1:], nodes[ni:],
                    dict(bindings), state, depth)
                if rest_result is not None:
                    return rest_result
                return None

            # Normal case: match one pattern against one node
            if ni >= len(nodes):
                return None  # ran out of nodes

            result = self._match(pat_child, nodes[ni], dict(bindings),
                                 state, depth)
            if result is None:
                return None

            bindings = result
            pi += 1
            ni += 1

        # All patterns consumed; check if there are leftover nodes
        if ni < len(nodes):
            return None  # unmatched nodes remain

        return bindings

    def _match_deep(self, pattern: PatternNode, node: Any,
                    bindings: Dict[str, MatchBinding],
                    state: Dict[str, Any],
                    depth: int) -> Optional[Dict[str, MatchBinding]]:
        """Deep descent: match pattern anywhere in the subtree of node."""
        # Try at current node
        result = self._match(pattern, node, dict(bindings), state, depth)
        if result is not None:
            return result

        # Descend into children
        for child in self._get_children(node):
            if child is not None:
                result = self._match_deep(pattern, child, dict(bindings),
                                          state, depth + 1)
                if result is not None:
                    return result

        return None

    def _match_repetition(self, pat: PatternNode, node: Any,
                          bindings: Dict[str, MatchBinding],
                          state: Dict[str, Any],
                          depth: int) -> Optional[Dict[str, MatchBinding]]:
        """Match repetition patterns against a single node.

        For single-node context (not inside a sequence), repetition
        degenerates: * always matches (zero occurrences), + requires the
        inner pattern to match the node.
        """
        if pat.kind == PatternNodeKind.REPETITION:
            # Zero or more: try matching, but succeed either way
            result = self._match(pat.children[0], node, dict(bindings),
                                 state, depth)
            return result if result is not None else bindings

        if pat.kind == PatternNodeKind.PLUS_REP:
            # One or more: must match at least once
            return self._match(pat.children[0], node, dict(bindings),
                               state, depth)

        return None

    # ---- Node access helpers ----

    @staticmethod
    def _is_token(node: Any) -> bool:
        """Check if node is a Cppcheck Token."""
        return hasattr(node, "str") and hasattr(node, "astOperand1")

    @staticmethod
    def _node_str(node: Any) -> str:
        """Get string representation of a node."""
        if node is None:
            return ""
        if isinstance(node, str):
            return node
        if isinstance(node, (int, float, bool)):
            return str(node)
        s = getattr(node, "str", None)
        if s is not None:
            return s
        return str(node)

    @staticmethod
    def _node_number(node: Any) -> Optional[Union[int, float]]:
        """Try to extract a numeric value from a node."""
        if isinstance(node, (int, float)):
            return node
        s = None
        if isinstance(node, str):
            s = node
        elif hasattr(node, "str"):
            s = node.str
        if s is not None:
            try:
                return int(s)
            except ValueError:
                try:
                    return float(s)
                except ValueError:
                    pass
        return None

    def _get_children(self, node: Any) -> List[Any]:
        """Get the AST children of a node."""
        if isinstance(node, list):
            return node
        children = []
        # Cppcheck Token: AST children
        op1 = getattr(node, "astOperand1", None)
        op2 = getattr(node, "astOperand2", None)
        if op1 is not None:
            children.append(op1)
        if op2 is not None:
            children.append(op2)
        return children

    def _get_node_as_list(self, node: Any) -> List[Any]:
        """Represent a node as a list: [operator, child1, child2, ...].

        For Cppcheck Tokens:
          - The token's .str is represented as a string element.
          - astOperand1 and astOperand2 are the children.

        For plain lists (testing): used directly.
        """
        if isinstance(node, list):
            return node

        if self._is_token(node):
            elements: List[Any] = [node.str]
            if node.astOperand1 is not None:
                elements.append(node.astOperand1)
            if node.astOperand2 is not None:
                elements.append(node.astOperand2)
            return elements

        # Scope or other objects: return their stringified form as single element
        return [self._node_str(node)]


# ===================================================================
#  PART 8 — CCPL ENGINE
# ===================================================================

class TraceLock:
    """Represents an active trace-lock."""
    def __init__(self, required_rule: str, locked_by: str):
        self.required_rule = required_rule   # only this rule may match next
        self.locked_by = locked_by           # the rule that set the lock


@dataclass
class MatchRecord:
    """Record of a successful match (for history/tracing)."""
    rule_name: str
    location: Optional[Tuple[str, int, int]]
    bindings: Dict[str, str]
    timestamp: float


class CCPLEngine:
    """The CCPL matching engine.

    Manages rules, global state, trace-locks, and drives bottom-up
    matching over Cppcheck dump data.

    Usage::

        engine = CCPLEngine()

        # Register predicates and guards
        engine.register_predicate("is_in_loop", my_pred_fn)
        engine.register_guard("nonzero_divisor", my_guard_fn)

        # Add rules from S-expressions
        engine.add_rule_from_sexp(
            "(defrule div-by-zero (/ ?x 0))",
            callback=on_div_by_zero,
            guard="nonzero_divisor",
        )

        # Or add rules programmatically
        engine.add_rule(Rule(
            name="null-deref",
            pattern=compiler.compile_from_string("(* ?ptr:ptr)"),
            callback=on_null_deref,
            predicate=lambda s, n: True,
        ))

        # Run on Cppcheck data
        engine.run(cppcheck_cfg_data)
        print(engine.global_state)
    """

    def __init__(self):
        self._rules: List[Rule] = []
        self._rule_map: Dict[str, Rule] = {}
        self._predicates: Dict[str, PredicateFunc] = {}
        self._guards: Dict[str, GuardFunc] = {}
        self._compiler = PatternCompiler()
        self._matcher: Optional[PatternMatcher] = None
        self._global_state: Dict[str, Any] = {}
        self._trace_lock: Optional[TraceLock] = None
        self._match_history: List[MatchRecord] = []
        self._stats: Dict[str, int] = {
            "nodes_visited": 0,
            "matches_attempted": 0,
            "matches_succeeded": 0,
            "predicates_failed": 0,
            "guards_failed": 0,
            "lock_skips": 0,
        }

    # ---- Public properties ----

    @property
    def global_state(self) -> Dict[str, Any]:
        """The mutable global state dictionary."""
        return self._global_state

    @property
    def match_history(self) -> List[MatchRecord]:
        """History of all successful matches."""
        return self._match_history

    @property
    def trace_locked(self) -> bool:
        """Whether the engine is currently trace-locked."""
        return self._trace_lock is not None

    @property
    def trace_lock_target(self) -> Optional[str]:
        """The rule name required by the current trace-lock, or None."""
        return self._trace_lock.required_rule if self._trace_lock else None

    @property
    def stats(self) -> Dict[str, int]:
        """Engine statistics."""
        return dict(self._stats)

    # ---- Registration ----

    def register_predicate(self, name: str, func: PredicateFunc) -> None:
        """Register a named predicate function.

        Predicates are called *before* structural matching:
        ``func(engine_state, node) → bool``.
        """
        self._predicates[name] = func
        self._matcher = None  # invalidate cached matcher

    def register_guard(self, name: str, func: GuardFunc) -> None:
        """Register a named guard function.

        Guards are called *after* structural matching succeeds:
        ``func(match_context) → bool``.
        """
        self._guards[name] = func
        self._matcher = None

    def add_rule(self, rule: Rule) -> None:
        """Add a pre-built Rule to the engine."""
        if rule.name in self._rule_map:
            raise CCPLError(f"Duplicate rule name: '{rule.name}'")
        self._rules.append(rule)
        self._rule_map[rule.name] = rule
        # Sort by priority
        self._rules.sort(key=lambda r: r.priority)
        self._matcher = None

    def add_rule_from_sexp(
        self,
        sexp_text: str,
        callback: CallbackFunc,
        predicate: Optional[Union[str, PredicateFunc]] = None,
        guard: Optional[Union[str, GuardFunc]] = None,
        lock_to: Optional[str] = None,
        unlock: bool = False,
        priority: int = 100,
        tags: Optional[Set[str]] = None,
        description: str = "",
    ) -> Rule:
        """Parse an S-expression rule definition and add it.

        The S-expression should have the form::

            (defrule <name> <pattern> [:option value ...])

        Or simply a bare pattern (name auto-generated).

        Parameters
        ----------
        sexp_text : str
            S-expression defining the rule.
        callback : callable
            Function called on match.
        predicate : str or callable, optional
            Name of registered predicate, or inline function.
        guard : str or callable, optional
            Name of registered guard, or inline function.
        lock_to : str, optional
            Rule name to trace-lock to upon match.
        unlock : bool
            Whether matching this rule unlocks any trace-lock.
        priority : int
            Rule priority (lower = higher priority).
        tags : set, optional
            Tags for this rule.
        description : str
            Human-readable description.

        Returns
        -------
        Rule
            The created and registered rule.
        """
        parsed = _parse_sexp(sexp_text)

        # Extract name and pattern from defrule form
        if isinstance(parsed, list) and len(parsed) >= 3:
            head = parsed[0] if isinstance(parsed[0], str) else None
            if head == "defrule":
                name = str(parsed[1])
                pattern_sexp = parsed[2]
                # Parse options from remaining elements
                opts = parsed[3:] if len(parsed) > 3 else []
                lock_to, unlock, priority, tags_extra, desc_extra = \
                    self._parse_rule_options(opts, lock_to, unlock, priority,
                                            tags or set(), description)
                tags = tags_extra
                description = desc_extra
            else:
                name = f"rule_{len(self._rules)}"
                pattern_sexp = parsed
        else:
            name = f"rule_{len(self._rules)}"
            pattern_sexp = parsed

        pattern = self._compiler._compile(pattern_sexp)

        # Resolve predicate
        pred_fn = None
        if isinstance(predicate, str):
            pred_fn = self._predicates.get(predicate)
            if pred_fn is None:
                raise CCPLError(f"Unknown predicate: '{predicate}'")
        elif callable(predicate):
            pred_fn = predicate

        # Resolve guard
        guard_fn = None
        if isinstance(guard, str):
            guard_fn = self._guards.get(guard)
            if guard_fn is None:
                raise CCPLError(f"Unknown guard: '{guard}'")
        elif callable(guard):
            guard_fn = guard

        rule = Rule(
            name=name,
            pattern=pattern,
            callback=callback,
            predicate=pred_fn,
            guard=guard_fn,
            lock_to=lock_to,
            unlock=unlock,
            priority=priority,
            enabled=True,
            tags=tags or set(),
            description=description,
            source_sexp=sexp_text,
        )
        self.add_rule(rule)
        return rule

    def _parse_rule_options(self, opts: List[Any],
                            lock_to, unlock, priority, tags, description):
        """Parse keyword options from a defrule form."""
        i = 0
        while i < len(opts):
            key = opts[i] if isinstance(opts[i], str) else ""
            if key == ":lock-to" and i + 1 < len(opts):
                lock_to = str(opts[i + 1])
                i += 2
            elif key == ":unlock":
                unlock = True
                i += 1
            elif key == ":priority" and i + 1 < len(opts):
                priority = int(opts[i + 1])
                i += 2
            elif key == ":tags" and i + 1 < len(opts):
                tag_val = opts[i + 1]
                if isinstance(tag_val, list):
                    tags = tags | set(str(t) for t in tag_val)
                else:
                    tags = tags | {str(tag_val)}
                i += 2
            elif key == ":description" and i + 1 < len(opts):
                description = str(opts[i + 1])
                i += 2
            else:
                i += 1
        return lock_to, unlock, priority, tags, description

    # ---- Bulk loading ----

    def load_rules(self, sexp_text: str,
                   callback_registry: Dict[str, CallbackFunc]) -> List[Rule]:
        """Load multiple rules from a multi-form S-expression string.

        Each form should be ``(defrule name pattern [:options...])`` and
        the callback is looked up in ``callback_registry`` by rule name.

        Returns list of created rules.
        """
        forms = _parse_sexp_many(sexp_text)
        rules = []
        for form in forms:
            if isinstance(form, list) and len(form) >= 3:
                head = form[0] if isinstance(form[0], str) else None
                if head == "defrule":
                    name = str(form[1])
                    cb = callback_registry.get(name)
                    if cb is None:
                        logger.warning("No callback for rule '%s'; using no-op",
                                       name)
                        cb = lambda ctx: None
                    rule = self.add_rule_from_sexp(
                        _sexp_to_string(form), callback=cb)
                    rules.append(rule)
        return rules

    # ---- State management ----

    def reset(self) -> None:
        """Reset engine state (global state, trace-lock, history, stats)."""
        self._global_state.clear()
        self._trace_lock = None
        self._match_history.clear()
        self._stats = {k: 0 for k in self._stats}

    def set_global(self, key: str, value: Any) -> None:
        """Set a value in global state."""
        self._global_state[key] = value

    def get_global(self, key: str, default: Any = None) -> Any:
        """Get a value from global state."""
        return self._global_state.get(key, default)

    def enable_rule(self, name: str) -> None:
        """Enable a rule by name."""
        if name in self._rule_map:
            self._rule_map[name].enabled = True

    def disable_rule(self, name: str) -> None:
        """Disable a rule by name."""
        if name in self._rule_map:
            self._rule_map[name].enabled = False

    def force_unlock(self) -> None:
        """Force-release any active trace-lock."""
        self._trace_lock = None

    # ---- Execution ----

    def run(self, cfg_data, bottom_up: bool = True) -> List[MatchContext]:
        """Run all rules against a Cppcheck configuration's token list.

        Parameters
        ----------
        cfg_data : cppcheckdata.Configuration or similar
            Must have a ``tokenlist`` attribute.
        bottom_up : bool
            If True (default), process AST nodes bottom-up (leaves first).
            If False, process tokens in linear order.

        Returns
        -------
        list of MatchContext
            All successful matches.
        """
        token_list = getattr(cfg_data, "tokenlist", [])
        if not token_list:
            logger.warning("Empty token list")
            return []

        if bottom_up:
            return self._run_bottom_up(token_list)
        else:
            return self._run_linear(token_list)

    def run_on_tokens(self, tokens: List[Any],
                      bottom_up: bool = True) -> List[MatchContext]:
        """Run rules on a raw token list."""
        if bottom_up:
            return self._run_bottom_up(tokens)
        return self._run_linear(tokens)

    def run_on_node(self, node: Any) -> List[MatchContext]:
        """Run rules on a single AST node (and its subtree, bottom-up)."""
        self._ensure_matcher()
        nodes = self._collect_subtree_bottom_up(node)
        return self._process_nodes(nodes)

    def match_pattern(self, pattern_sexp: str, node: Any) -> Optional[Dict[str, MatchBinding]]:
        """One-shot pattern match: compile pattern and match against node.

        Returns bindings dict or None.
        """
        self._ensure_matcher()
        pattern = self._compiler.compile_from_string(pattern_sexp)
        return self._matcher.match(pattern, node,
                                   engine_state=self._global_state)

    # ---- Internal execution ----

    def _ensure_matcher(self) -> None:
        """Lazily create/recreate the PatternMatcher."""
        if self._matcher is None:
            self._matcher = PatternMatcher(
                predicates=self._predicates,
                guards=self._guards,
            )

    def _run_bottom_up(self, tokens: List[Any]) -> List[MatchContext]:
        """Run bottom-up: collect all AST nodes, sort leaves-first, process."""
        self._ensure_matcher()

        # Collect all AST root tokens (those whose astParent is None or
        # not in the token list)
        ast_roots = []
        token_set = set(id(t) for t in tokens)
        for token in tokens:
            parent = getattr(token, "astParent", None)
            if parent is None or id(parent) not in token_set:
                if getattr(token, "astOperand1", None) is not None or \
                   getattr(token, "astOperand2", None) is not None:
                    ast_roots.append(token)

        # For each AST root, collect subtree bottom-up
        all_nodes: List[Any] = []
        visited: Set[int] = set()

        for root in ast_roots:
            subtree = self._collect_subtree_bottom_up(root)
            for node in subtree:
                nid = id(node)
                if nid not in visited:
                    visited.add(nid)
                    all_nodes.append(node)

        # Also process non-AST tokens (leaves without AST structure)
        for token in tokens:
            nid = id(token)
            if nid not in visited:
                visited.add(nid)
                all_nodes.append(token)

        return self._process_nodes(all_nodes)

    def _run_linear(self, tokens: List[Any]) -> List[MatchContext]:
        """Run in linear token order."""
        self._ensure_matcher()
        return self._process_nodes(tokens)

    def _collect_subtree_bottom_up(self, root: Any) -> List[Any]:
        """Post-order traversal of AST rooted at ``root``."""
        result: List[Any] = []
        visited: Set[int] = set()

        def _visit(node):
            if node is None:
                return
            nid = id(node)
            if nid in visited:
                return
            visited.add(nid)
            op1 = getattr(node, "astOperand1", None)
            op2 = getattr(node, "astOperand2", None)
            if op1 is not None:
                _visit(op1)
            if op2 is not None:
                _visit(op2)
            result.append(node)

        _visit(root)
        return result

    def _process_nodes(self, nodes: List[Any]) -> List[MatchContext]:
        """Process a list of nodes against all rules."""
        all_matches: List[MatchContext] = []

        for node in nodes:
            self._stats["nodes_visited"] += 1
            matches = self._try_rules(node)
            all_matches.extend(matches)

        return all_matches

    def _try_rules(self, node: Any) -> List[MatchContext]:
        """Try all rules against a single node, respecting trace-lock."""
        matches: List[MatchContext] = []

        for rule in self._rules:
            if not rule.enabled:
                continue

            # ---- TRACE-LOCK CHECK ----
            if self._trace_lock is not None:
                if rule.name != self._trace_lock.required_rule:
                    self._stats["lock_skips"] += 1
                    continue

            self._stats["matches_attempted"] += 1

            # ---- PRE-MATCH PREDICATE ----
            if rule.predicate is not None:
                try:
                    if not rule.predicate(self._global_state, node):
                        self._stats["predicates_failed"] += 1
                        continue
                except Exception as e:
                    logger.debug("Predicate '%s' raised: %s", rule.name, e)
                    self._stats["predicates_failed"] += 1
                    continue

            # ---- STRUCTURAL MATCHING ----
            bindings = self._matcher.match(
                rule.pattern, node,
                engine_state=self._global_state,
            )
            if bindings is None:
                continue

            # ---- BUILD MATCH CONTEXT ----
            location = self._extract_location(node)
            ctx = MatchContext(
                pattern_name=rule.name,
                bindings=bindings,
                matched_node=node,
                matched_children=self._matcher._get_children(node),
                global_state=self._global_state,
                location=location,
                pattern=rule.pattern,
                rule=rule,
                match_depth=0,
                timestamp=time.monotonic(),
            )

            # ---- POST-MATCH GUARD ----
            if rule.guard is not None:
                try:
                    if not rule.guard(ctx):
                        self._stats["guards_failed"] += 1
                        continue
                except Exception as e:
                    logger.debug("Guard '%s' raised: %s", rule.name, e)
                    self._stats["guards_failed"] += 1
                    continue

            # ---- Also check inline guards from GUARD_REF nodes in pattern ----
            guard_refs = self._collect_guard_refs(rule.pattern)
            guard_passed = True
            for guard_name in guard_refs:
                guard_fn = self._guards.get(guard_name)
                if guard_fn is not None:
                    try:
                        if not guard_fn(ctx):
                            guard_passed = False
                            break
                    except Exception:
                        guard_passed = False
                        break
            if not guard_passed:
                self._stats["guards_failed"] += 1
                continue

            # ---- MATCH SUCCEEDED ----
            self._stats["matches_succeeded"] += 1
            matches.append(ctx)

            # Record history
            self._match_history.append(MatchRecord(
                rule_name=rule.name,
                location=location,
                bindings={k: v.text or "" for k, v in bindings.items()},
                timestamp=ctx.timestamp,
            ))

            # ---- TRACE-LOCK MANAGEMENT ----
            if rule.unlock:
                self._trace_lock = None
            if rule.lock_to is not None:
                self._trace_lock = TraceLink(
                    required_rule=rule.lock_to,
                    locked_by=rule.name,
                )

            # ---- INVOKE CALLBACK ----
            try:
                rule.callback(ctx)
            except Exception as e:
                logger.error("Callback for rule '%s' raised: %s",
                             rule.name, e)

        return matches

    def _collect_guard_refs(self, pattern: PatternNode) -> List[str]:
        """Collect all GUARD_REF names from a pattern tree."""
        refs: List[str] = []
        if pattern.kind == PatternNodeKind.GUARD_REF and pattern.name:
            refs.append(pattern.name)
        for child in pattern.children:
            refs.extend(self._collect_guard_refs(child))
        return refs

    @staticmethod
    def _extract_location(node: Any) -> Optional[Tuple[str, int, int]]:
        """Extract (file, line, column) from a node if available."""
        f = getattr(node, "file", None)
        l = getattr(node, "linenr", None)
        c = getattr(node, "column", 0)
        if f is not None and l is not None:
            return (f, int(l), int(c or 0))
        return None

    # ---- Reporting ----

    def report(self) -> str:
        """Generate a human-readable report of all matches."""
        lines = [
            "=" * 60,
            "  CCPL ENGINE REPORT",
            "=" * 60,
            f"  Rules loaded       : {len(self._rules)}",
            f"  Nodes visited      : {self._stats['nodes_visited']}",
            f"  Matches attempted  : {self._stats['matches_attempted']}",
            f"  Matches succeeded  : {self._stats['matches_succeeded']}",
            f"  Predicates failed  : {self._stats['predicates_failed']}",
            f"  Guards failed      : {self._stats['guards_failed']}",
            f"  Lock skips         : {self._stats['lock_skips']}",
            f"  Trace locked       : {self.trace_locked}",
            "=" * 60,
        ]
        if self._match_history:
            lines.append("")
            lines.append("  MATCH HISTORY:")
            lines.append("-" * 60)
            for i, rec in enumerate(self._match_history):
                loc_str = ""
                if rec.location:
                    f, l, c = rec.location
                    loc_str = f" at {f}:{l}:{c}"
                bindings_str = ", ".join(f"{k}={v}"
                                         for k, v in rec.bindings.items())
                lines.append(f"  [{i+1}] {rec.rule_name}{loc_str}"
                             f"  bindings: {{{bindings_str}}}")
            lines.append("-" * 60)
        return "\n".join(lines)


# Alias for internal use (the TraceLink was a typo for TraceLink; keep compat)
TraceLink = TraceLock


# ===================================================================
#  PART 9 — BUILT-IN PREDICATES AND GUARDS
# ===================================================================

def predicate_is_in_function(state: Dict[str, Any], node: Any) -> bool:
    """Predicate: node is inside a function scope."""
    scope = getattr(node, "scope", None)
    if scope is None:
        return False
    while scope:
        if getattr(scope, "type", "") == "Function":
            return True
        scope = getattr(scope, "nestedIn", None)
    return False


def predicate_is_in_loop(state: Dict[str, Any], node: Any) -> bool:
    """Predicate: node is inside a loop (for/while/do)."""
    scope = getattr(node, "scope", None)
    if scope is None:
        return False
    while scope:
        if getattr(scope, "type", "") in ("For", "While", "Do"):
            return True
        scope = getattr(scope, "nestedIn", None)
    return False


def predicate_is_in_condition(state: Dict[str, Any], node: Any) -> bool:
    """Predicate: node is inside an if/switch condition scope."""
    scope = getattr(node, "scope", None)
    if scope is None:
        return False
    while scope:
        if getattr(scope, "type", "") in ("If", "Else", "Switch"):
            return True
        scope = getattr(scope, "nestedIn", None)
    return False


def predicate_has_known_value(state: Dict[str, Any], node: Any) -> bool:
    """Predicate: token has at least one known value from ValueFlow."""
    values = getattr(node, "values", None)
    if not values:
        return False
    return any(getattr(v, "valueKind", "") == "known" for v in values)


def predicate_is_assignment_target(state: Dict[str, Any], node: Any) -> bool:
    """Predicate: token is the LHS of an assignment."""
    parent = getattr(node, "astParent", None)
    if parent is None:
        return False
    if getattr(parent, "isAssignmentOp", False):
        return getattr(parent, "astOperand1", None) is node
    return False


def guard_nonzero(ctx: MatchContext) -> bool:
    """Guard: the 'divisor' or 'rhs' binding must not be provably zero."""
    for name in ("divisor", "rhs", "x"):
        b = ctx.bindings.get(name)
        if b is not None and b.token is not None:
            tok = b.token
            known = getattr(tok, "getKnownIntValue", lambda: None)()
            if known is not None and known == 0:
                return False
    return True


def guard_not_null(ctx: MatchContext) -> bool:
    """Guard: the 'ptr' binding is not provably null."""
    b = ctx.bindings.get("ptr")
    if b is not None and b.token is not None:
        tok = b.token
        known = getattr(tok, "getKnownIntValue", lambda: None)()
        if known is not None and known == 0:
            return False  # provably null → guard fails
    return True


def guard_first_occurrence(ctx: MatchContext) -> bool:
    """Guard: this is the first match for this pattern name + variable combination.

    Prevents duplicate reports for the same variable at the same location.
    """
    key = f"_seen_{ctx.pattern_name}"
    seen = ctx.global_state.setdefault(key, set())
    ident = (ctx.location, frozenset(
        (k, v.text) for k, v in ctx.bindings.items()))
    if ident in seen:
        return False
    seen.add(ident)
    return True


# ===================================================================
#  PART 10 — CONVENIENCE API
# ===================================================================

def create_engine(
    rules_sexp: Optional[str] = None,
    callbacks: Optional[Dict[str, CallbackFunc]] = None,
    predicates: Optional[Dict[str, PredicateFunc]] = None,
    guards: Optional[Dict[str, GuardFunc]] = None,
) -> CCPLEngine:
    """Create a CCPL engine with optional pre-loaded rules.

    Parameters
    ----------
    rules_sexp : str, optional
        S-expression string with multiple ``(defrule ...)`` forms.
    callbacks : dict, optional
        Mapping of rule name → callback function.
    predicates : dict, optional
        Mapping of predicate name → predicate function.
    guards : dict, optional
        Mapping of guard name → guard function.

    Returns
    -------
    CCPLEngine
    """
    engine = CCPLEngine()

    # Register built-in predicates
    engine.register_predicate("is_in_function", predicate_is_in_function)
    engine.register_predicate("is_in_loop", predicate_is_in_loop)
    engine.register_predicate("is_in_condition", predicate_is_in_condition)
    engine.register_predicate("has_known_value", predicate_has_known_value)
    engine.register_predicate("is_assignment_target", predicate_is_assignment_target)

    # Register built-in guards
    engine.register_guard("nonzero", guard_nonzero)
    engine.register_guard("not_null", guard_not_null)
    engine.register_guard("first_occurrence", guard_first_occurrence)

    # Register user predicates/guards
    if predicates:
        for name, fn in predicates.items():
            engine.register_predicate(name, fn)
    if guards:
        for name, fn in guards.items():
            engine.register_guard(name, fn)

    # Load rules
    if rules_sexp and callbacks:
        engine.load_rules(rules_sexp, callbacks)

    return engine


def compile_pattern(sexp_text: str) -> PatternNode:
    """Compile a single pattern from an S-expression string."""
    return PatternCompiler().compile_from_string(sexp_text)


def match_once(pattern_sexp: str, node: Any) -> Optional[Dict[str, MatchBinding]]:
    """One-shot pattern match. Returns bindings or None."""
    engine = CCPLEngine()
    return engine.match_pattern(pattern_sexp, node)


# ===================================================================
#  PART 11 — MODULE EXPORTS
# ===================================================================

__all__ = [
    # Exceptions
    "CCPLError", "CCPLParseError", "CCPLCompileError", "CCPLRuntimeError",
    # Pattern AST
    "PatternNodeKind", "PatternNode",
    # Compiler
    "PatternCompiler",
    # Match context
    "MatchBinding", "MatchContext",
    # Rules
    "Rule", "PredicateFunc", "GuardFunc", "CallbackFunc",
    # Matcher
    "PatternMatcher",
    # Engine
    "CCPLEngine", "TraceLink", "TraceLink", "MatchRecord",
    # Built-in predicates
    "predicate_is_in_function", "predicate_is_in_loop",
    "predicate_is_in_condition", "predicate_has_known_value",
    "predicate_is_assignment_target",
    # Built-in guards
    "guard_nonzero", "guard_not_null", "guard_first_occurrence",
    # Convenience
    "create_engine", "compile_pattern", "match_once",
]
