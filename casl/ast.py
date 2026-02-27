"""casl/ast.py – Complete AST definitions for CASL and CSQL.

CASL (Cppcheck Addon Specification Language) is the top-level specification
language for declaring abstract domains, embedding structural queries, and
defining temporal / dataflow / syntactic properties that compile into
Cppcheck addons.

CSQL (Cppcheck Semantic Query Language) is the embedded structural query
sublanguage used to find, filter, and bind program entities (variables,
functions, CFG nodes, tokens, scopes) from cppcheckdata dump files.

Both languages use an S-expression concrete syntax.  This module defines
the *abstract* syntax – a tree of frozen dataclasses that the parser
produces and the compiler consumes.

Design invariants
-----------------
* Every AST node is a frozen dataclass (immutable after construction).
* Nodes that carry children use tuples, never lists, to preserve
  immutability through nesting.
* Every node records its source location (``SourceLoc``) for diagnostics.
* The hierarchy mirrors the two-world separation:
      CSQL  →  structural queries  →  ``Query*`` nodes
      CASL  →  temporal / dataflow / syntactic properties  →  ``Prop*``,
               ``Domain*``, ``Checker*``, ``Module`` nodes
* Atomic propositions (the "namespace bridge" between the two worlds)
  are ``PropAtom`` nodes that embed a CSQL predicate.
* Temporal formulas are a clean sub-AST (``LTL*`` / ``CTL*``) whose
  leaves are ``PropAtom``s.

Style conventions (matching cppcheckdata-shims codebase)
--------------------------------------------------------
* ``from __future__ import annotations`` for PEP 604 unions.
* ``@dataclass(frozen=True, slots=True)`` where possible.
* ``Enum`` with ``auto()`` for finite kind sets.
* Heavy use of ``typing`` generics; ``Tuple`` over ``List`` for
  immutable sequences inside frozen dataclasses.
* ``__repr__`` / ``pretty`` helpers on key nodes for debugging.

Module layout
-------------
§1  Source location & common helpers
§2  CSQL AST  – queries, patterns, predicates, bindings
§3  CASL AST  – domains, properties, formulas, checkers, modules
§4  Visitor protocol
"""

from __future__ import annotations

import textwrap
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import (
    Any,
    Callable,
    Generic,
    Mapping,
    Optional,
    Protocol,
    Sequence,
    Tuple,
    TypeVar,
    Union,
    runtime_checkable,
)

# ════════════════════════════════════════════════════════════════════════
# §1  Source location & common helpers
# ════════════════════════════════════════════════════════════════════════


@dataclass(frozen=True, slots=True)
class SourceLoc:
    """Points back to a position in a ``.casl`` / ``.csql`` source file.

    Every AST node carries one of these so that later compiler phases
    (type-checking, code-generation) can emit precise diagnostics.
    """

    file: str = "<unknown>"
    line: int = 0
    col: int = 0

    def __str__(self) -> str:
        return f"{self.file}:{self.line}:{self.col}"


#: Sentinel for nodes synthesised by the compiler (no source position).
NO_LOC = SourceLoc()


@dataclass(frozen=True, slots=True)
class Ident:
    """A source-level identifier (variable name, domain name, etc.).

    Carries the raw text *and* the location where it was written so
    that "undefined name" errors can point at the right place.
    """

    name: str
    loc: SourceLoc = field(default=NO_LOC, repr=False)

    def __str__(self) -> str:  # noqa: D105
        return self.name

    def __eq__(self, other: object) -> bool:  # noqa: D105
        if isinstance(other, Ident):
            return self.name == other.name
        if isinstance(other, str):
            return self.name == other
        return NotImplemented

    def __hash__(self) -> int:  # noqa: D105
        return hash(self.name)


# ════════════════════════════════════════════════════════════════════════
# §2  CSQL AST – structural queries
# ════════════════════════════════════════════════════════════════════════
#
# CSQL is a pure query language over the cppcheckdata object model.
# A query finds program entities (tokens, variables, functions, scopes,
# CFG nodes) that satisfy structural predicates, and *binds* them to
# names so that CASL properties can reference them.
#
# Concrete S-expression grammar (informative, see parser for canonical):
#
#   query ::= (query <from-clause> <where-clause>? <bind-clause>?)
#   from  ::= (from <entity-source>+)
#   where ::= (where <predicate>)
#   bind  ::= (bind <binding>+)
#
# ────────────────────────────────────────────────────────────────────────

# --- Entity kinds that CSQL can iterate over -------------------------

class EntityKind(Enum):
    """The kinds of program entity a ``(from ...)`` clause can range over.

    These map directly onto top-level collections exposed by the
    ``cppcheckdata`` / ``cppcheckdata_shims`` APIs.
    """

    TOKEN = auto()       # cppcheckdata.Token
    VARIABLE = auto()    # cppcheckdata.Variable
    FUNCTION = auto()    # cppcheckdata.Function / scope.type=="Function"
    SCOPE = auto()       # cppcheckdata.Scope
    CFG_NODE = auto()    # cppcheckdata_shims.ctrlflow_graph.CFGNode
    CFG_EDGE = auto()    # cppcheckdata_shims.ctrlflow_graph.CFGEdge
    VALUE = auto()       # cppcheckdata.Value  (value-flow facts)
    SUPPRESSION = auto() # cppcheckdata.Suppression


# --- Predicate sub-AST -----------------------------------------------

class CmpOp(Enum):
    """Comparison operators used in ``(cmp ...)`` predicates."""

    EQ = auto()   # ==
    NE = auto()   # !=
    LT = auto()   # <
    LE = auto()   # <=
    GT = auto()   # >
    GE = auto()   # >=

    def symbol(self) -> str:
        """Return the conventional infix symbol."""
        return {
            CmpOp.EQ: "==", CmpOp.NE: "!=",
            CmpOp.LT: "<",  CmpOp.LE: "<=",
            CmpOp.GT: ">",  CmpOp.GE: ">=",
        }[self]


class UnaryLogicOp(Enum):
    """Unary logical connective (for ``PredicateUnary``)."""

    NOT = auto()


class BinaryLogicOp(Enum):
    """Binary logical connective (for ``PredicateBinary``)."""

    AND = auto()
    OR = auto()
    IMPLIES = auto()


# Predicate hierarchy --------------------------------------------------
#
# Predicates evaluate to bool in the context of a set of bindings
# produced by the ``from`` clause.  They form a small expression tree.

@dataclass(frozen=True, slots=True)
class PredicateTrue:
    """Trivially true – the identity element of conjunction."""

    loc: SourceLoc = field(default=NO_LOC, repr=False)


@dataclass(frozen=True, slots=True)
class PredicateFalse:
    """Trivially false – the identity element of disjunction."""

    loc: SourceLoc = field(default=NO_LOC, repr=False)


@dataclass(frozen=True, slots=True)
class PredicateAttrAccess:
    """Access an attribute chain on a bound entity.

    Example: ``(. v typeStartToken str)`` → ``v.typeStartToken.str``

    Used as the *left-hand side* of comparisons and as a boolean test
    (truthy check) when used bare in a ``(where ...)`` position.
    """

    root: Ident
    attrs: Tuple[str, ...]
    loc: SourceLoc = field(default=NO_LOC, repr=False)

    def pretty(self) -> str:
        """Dot-separated path string for diagnostics."""
        return ".".join([str(self.root), *self.attrs])


@dataclass(frozen=True, slots=True)
class PredicateLiteral:
    """A literal value (string, int, float, bool, None) inside a predicate."""

    value: Union[str, int, float, bool, None]
    loc: SourceLoc = field(default=NO_LOC, repr=False)


@dataclass(frozen=True, slots=True)
class PredicateCmp:
    """Binary comparison: ``(cmp <op> <lhs> <rhs>)``.

    ``lhs`` and ``rhs`` are each either an ``PredicateAttrAccess`` (path
    into a bound entity) or a ``PredicateLiteral``.
    """

    op: CmpOp
    lhs: PredicateExpr
    rhs: PredicateExpr
    loc: SourceLoc = field(default=NO_LOC, repr=False)


@dataclass(frozen=True, slots=True)
class PredicateMatch:
    """Regex match: ``(match <attr-access> <pattern>)``."""

    target: PredicateAttrAccess
    pattern: str
    loc: SourceLoc = field(default=NO_LOC, repr=False)


@dataclass(frozen=True, slots=True)
class PredicateIn:
    """Set membership: ``(in <expr> <expr>+)``."""

    target: PredicateExpr
    choices: Tuple[PredicateExpr, ...]
    loc: SourceLoc = field(default=NO_LOC, repr=False)


@dataclass(frozen=True, slots=True)
class PredicateHas:
    """Existence check: ``(has <attr-access>)``.

    True when the attribute chain resolves to a non-None value.
    """

    target: PredicateAttrAccess
    loc: SourceLoc = field(default=NO_LOC, repr=False)


@dataclass(frozen=True, slots=True)
class PredicateIsA:
    """Type/kind test: ``(is-a <binding> <entity-kind>)``.

    Tests whether a bound entity has a particular EntityKind or
    cppcheckdata type name (e.g. ``"Token"``, ``"Variable"``).
    """

    target: Ident
    kind: str  # EntityKind name or cppcheckdata class name
    loc: SourceLoc = field(default=NO_LOC, repr=False)


@dataclass(frozen=True, slots=True)
class PredicateCall:
    """Call a named helper predicate: ``(call <name> <arg>*)``.

    The ``name`` resolves to either a built-in predicate function or a
    user-defined predicate registered in a battery.  Arguments are
    arbitrary predicate expressions.
    """

    name: Ident
    args: Tuple[PredicateExpr, ...]
    loc: SourceLoc = field(default=NO_LOC, repr=False)


@dataclass(frozen=True, slots=True)
class PredicateUnary:
    """Unary connective: ``(not <pred>)``."""

    op: UnaryLogicOp
    operand: Predicate
    loc: SourceLoc = field(default=NO_LOC, repr=False)


@dataclass(frozen=True, slots=True)
class PredicateBinary:
    """Binary connective: ``(and <p> <q>)``, ``(or <p> <q>)``, ``(=> <p> <q>)``."""

    op: BinaryLogicOp
    lhs: Predicate
    rhs: Predicate
    loc: SourceLoc = field(default=NO_LOC, repr=False)


@dataclass(frozen=True, slots=True)
class PredicateQuantifier:
    """Quantified predicate over a sub-query.

    ``(forall <binding> <entity-source> <pred>)``
    ``(exists <binding> <entity-source> <pred>)``

    This lets a ``where`` clause express "for every call-site of f, …"
    or "there exists a path where …" without leaving CSQL.
    """

    quantifier: str  # "forall" | "exists"
    binding: Ident
    source: EntitySource
    body: Predicate
    loc: SourceLoc = field(default=NO_LOC, repr=False)


# Union types for predicate sub-expressions ----------------------------

#: An "expression" inside a predicate (things that produce a value).
PredicateExpr = Union[
    PredicateAttrAccess,
    PredicateLiteral,
    PredicateCall,
]

#: A full boolean predicate.
Predicate = Union[
    PredicateTrue,
    PredicateFalse,
    PredicateCmp,
    PredicateMatch,
    PredicateIn,
    PredicateHas,
    PredicateIsA,
    PredicateCall,
    PredicateUnary,
    PredicateBinary,
    PredicateQuantifier,
]


# --- Entity sources ---------------------------------------------------

@dataclass(frozen=True, slots=True)
class EntitySource:
    """A single source in a ``(from ...)`` clause.

    ``(from (token t) (variable v :scope (. t scope)))``

    Each source introduces a binding name and optionally constrains it
    to be related to a previously-bound entity via keyword filters.
    """

    kind: EntityKind
    binding: Ident
    filters: Tuple[Tuple[str, PredicateExpr], ...] = ()
    loc: SourceLoc = field(default=NO_LOC, repr=False)


# --- Binding declaration in the ``bind`` clause -----------------------

@dataclass(frozen=True, slots=True)
class BindingDecl:
    """Exports a named value from the query result.

    ``(bind (name (. v nameToken str)) (type (. v typeStartToken str)))``

    Each binding maps an export name to an expression that will be
    evaluated against the matched entities.
    """

    name: Ident
    expr: PredicateExpr
    loc: SourceLoc = field(default=NO_LOC, repr=False)


# --- Top-level CSQL query --------------------------------------------

@dataclass(frozen=True, slots=True)
class CsqlQuery:
    """A complete CSQL query.

    ::

        (query
          (from (variable v) (token t :variable v))
          (where (and (not (has (. v nameToken)))
                      (cmp == (. t str) "malloc")))
          (bind (var-name (. v nameToken str))
                (alloc-tok t)))

    This is the fundamental unit that CASL embeds to select the program
    entities a property reasons about.
    """

    sources: Tuple[EntitySource, ...]
    predicate: Predicate  # defaults to PredicateTrue if omitted
    bindings: Tuple[BindingDecl, ...]
    loc: SourceLoc = field(default=NO_LOC, repr=False)

    def bound_names(self) -> Tuple[Ident, ...]:
        """Return the names exported by this query's ``bind`` clause."""
        return tuple(b.name for b in self.bindings)

    def source_names(self) -> Tuple[Ident, ...]:
        """Return the names introduced by this query's ``from`` clause."""
        return tuple(s.binding for s in self.sources)


# ════════════════════════════════════════════════════════════════════════
# §3  CASL AST – domains, properties, formulas, checkers, modules
# ════════════════════════════════════════════════════════════════════════
#
# CASL is the top-level language.  A CASL *module* declares:
#   • imports (batteries / other modules)
#   • abstract domain declarations
#   • CSQL query definitions
#   • property definitions (syntactic, dataflow, temporal)
#   • checker definitions (combine property + severity + message)
#
# ────────────────────────────────────────────────────────────────────────

# --- Imports -----------------------------------------------------------

@dataclass(frozen=True, slots=True)
class ImportBattery:
    """``(import-battery <name>)`` – load a standard-library battery."""

    name: Ident
    loc: SourceLoc = field(default=NO_LOC, repr=False)


@dataclass(frozen=True, slots=True)
class ImportModule:
    """``(import <path>)`` – load another CASL module."""

    path: str
    alias: Optional[Ident] = None
    loc: SourceLoc = field(default=NO_LOC, repr=False)


Import = Union[ImportBattery, ImportModule]


# --- Abstract domain declarations ------------------------------------

class DomainBase(Enum):
    """The built-in abstract domain families that CASL knows about.

    These correspond to concrete classes in
    ``cppcheckdata_shims.abstract_domains``.
    """

    SIGN = auto()
    PARITY = auto()
    CONSTANT = auto()
    INTERVAL = auto()
    CONGRUENCE = auto()
    BITFIELD = auto()
    STRIDED_INTERVAL = auto()
    BOOL = auto()
    SET = auto()
    FLAT = auto()
    PRODUCT = auto()
    REDUCED_PRODUCT = auto()
    FUNCTION = auto()
    CUSTOM = auto()  # User-provided Python class


@dataclass(frozen=True, slots=True)
class DomainParam:
    """A parameter in a domain declaration.

    Example: ``(domain-param width 32)`` inside an interval domain
    declaration to set the bit-width.
    """

    name: Ident
    value: Union[str, int, float, bool]
    loc: SourceLoc = field(default=NO_LOC, repr=False)


@dataclass(frozen=True, slots=True)
class DomainDecl:
    """Declare a named abstract domain for use in dataflow properties.

    ::

        (domain allocation-state
          :base flat
          :elements (unallocated allocated freed)
          :params ((widening-delay 3)))
    """

    name: Ident
    base: DomainBase
    elements: Optional[Tuple[str, ...]] = None  # for flat/set domains
    params: Tuple[DomainParam, ...] = ()
    python_class: Optional[str] = None  # for CUSTOM base
    loc: SourceLoc = field(default=NO_LOC, repr=False)


# --- Atomic propositions (the "namespace bridge") --------------------

@dataclass(frozen=True, slots=True)
class PropAtom:
    """An atomic proposition – the bridge between CSQL and CASL.

    An atomic proposition is a predicate that can be evaluated at a
    specific CFG node / program point.  It is the leaf of every temporal
    formula.

    The ``predicate`` field holds a CSQL ``Predicate`` that will be
    evaluated in the context of bindings produced by the enclosing
    query.  The optional ``at`` field names the CFG-node binding to
    evaluate at (defaults to the implicit "current node").

    ::

        (atom freed?
          :at n
          :pred (cmp == (call domain-value allocation-state (. n) ptr) "freed"))
    """

    name: Ident
    predicate: Predicate
    at: Optional[Ident] = None  # CFG-node binding to evaluate at
    loc: SourceLoc = field(default=NO_LOC, repr=False)


# --- LTL formula sub-AST ---------------------------------------------
#
# Linear Temporal Logic over paths in the CFG.
# Used for path-sensitive properties ("along every execution path …").

class LTLOp(Enum):
    """LTL temporal operators."""

    NEXT = auto()      # X φ
    GLOBALLY = auto()  # G φ
    FINALLY = auto()   # F φ
    UNTIL = auto()     # φ U ψ
    RELEASE = auto()   # φ R ψ
    WEAK_UNTIL = auto()  # φ W ψ


@dataclass(frozen=True, slots=True)
class LTLAtom:
    """Leaf of an LTL formula – references a ``PropAtom`` by name."""

    name: Ident
    loc: SourceLoc = field(default=NO_LOC, repr=False)


@dataclass(frozen=True, slots=True)
class LTLBool:
    """Constant true / false in LTL."""

    value: bool
    loc: SourceLoc = field(default=NO_LOC, repr=False)


@dataclass(frozen=True, slots=True)
class LTLNot:
    """Negation: ``(ltl-not φ)``."""

    operand: LTLFormula
    loc: SourceLoc = field(default=NO_LOC, repr=False)


@dataclass(frozen=True, slots=True)
class LTLAnd:
    """Conjunction: ``(ltl-and φ ψ)``."""

    operands: Tuple[LTLFormula, ...]
    loc: SourceLoc = field(default=NO_LOC, repr=False)


@dataclass(frozen=True, slots=True)
class LTLOr:
    """Disjunction: ``(ltl-or φ ψ)``."""

    operands: Tuple[LTLFormula, ...]
    loc: SourceLoc = field(default=NO_LOC, repr=False)


@dataclass(frozen=True, slots=True)
class LTLImplies:
    """Implication: ``(ltl-implies φ ψ)``."""

    lhs: LTLFormula
    rhs: LTLFormula
    loc: SourceLoc = field(default=NO_LOC, repr=False)


@dataclass(frozen=True, slots=True)
class LTLUnary:
    """Unary temporal operator: ``(X φ)``, ``(G φ)``, ``(F φ)``."""

    op: LTLOp  # NEXT | GLOBALLY | FINALLY
    operand: LTLFormula
    loc: SourceLoc = field(default=NO_LOC, repr=False)


@dataclass(frozen=True, slots=True)
class LTLBinary:
    """Binary temporal operator: ``(U φ ψ)``, ``(R φ ψ)``, ``(W φ ψ)``."""

    op: LTLOp  # UNTIL | RELEASE | WEAK_UNTIL
    lhs: LTLFormula
    rhs: LTLFormula
    loc: SourceLoc = field(default=NO_LOC, repr=False)


#: Union of all LTL formula nodes.
LTLFormula = Union[
    LTLAtom,
    LTLBool,
    LTLNot,
    LTLAnd,
    LTLOr,
    LTLImplies,
    LTLUnary,
    LTLBinary,
]


# --- CTL formula sub-AST ---------------------------------------------
#
# Computation Tree Logic for branching-time properties ("on all/some
# paths from this point …").  CTL uses path quantifiers (A/E) composed
# with temporal operators (X/G/F/U).

class CTLPathQ(Enum):
    """CTL path quantifiers."""

    A = auto()  # for All paths
    E = auto()  # there Exists a path


class CTLTempOp(Enum):
    """CTL temporal operators (appear after a path quantifier)."""

    X = auto()  # neXt
    G = auto()  # Globally
    F = auto()  # Finally (Future)
    U = auto()  # Until


@dataclass(frozen=True, slots=True)
class CTLAtom:
    """Leaf of a CTL formula – references a ``PropAtom`` by name."""

    name: Ident
    loc: SourceLoc = field(default=NO_LOC, repr=False)


@dataclass(frozen=True, slots=True)
class CTLBool:
    """Constant true / false in CTL."""

    value: bool
    loc: SourceLoc = field(default=NO_LOC, repr=False)


@dataclass(frozen=True, slots=True)
class CTLNot:
    """Negation: ``(ctl-not φ)``."""

    operand: CTLFormula
    loc: SourceLoc = field(default=NO_LOC, repr=False)


@dataclass(frozen=True, slots=True)
class CTLAnd:
    """Conjunction: ``(ctl-and φ ψ)``."""

    operands: Tuple[CTLFormula, ...]
    loc: SourceLoc = field(default=NO_LOC, repr=False)


@dataclass(frozen=True, slots=True)
class CTLOr:
    """Disjunction: ``(ctl-or φ ψ)``."""

    operands: Tuple[CTLFormula, ...]
    loc: SourceLoc = field(default=NO_LOC, repr=False)


@dataclass(frozen=True, slots=True)
class CTLImplies:
    """Implication: ``(ctl-implies φ ψ)``."""

    lhs: CTLFormula
    rhs: CTLFormula
    loc: SourceLoc = field(default=NO_LOC, repr=False)


@dataclass(frozen=True, slots=True)
class CTLUnary:
    """Quantified unary temporal: ``(AX φ)``, ``(EF φ)``, ``(AG φ)``, etc.

    ::

        (AG (ctl-implies allocated? (AF freed?)))
    """

    path: CTLPathQ  # A or E
    op: CTLTempOp   # X, G, or F
    operand: CTLFormula
    loc: SourceLoc = field(default=NO_LOC, repr=False)

    def pretty_op(self) -> str:
        """E.g. ``'AG'``, ``'EF'``."""
        return f"{self.path.name}{self.op.name}"


@dataclass(frozen=True, slots=True)
class CTLUntil:
    """Quantified Until: ``(AU φ ψ)`` or ``(EU φ ψ)``."""

    path: CTLPathQ
    lhs: CTLFormula
    rhs: CTLFormula
    loc: SourceLoc = field(default=NO_LOC, repr=False)

    def pretty_op(self) -> str:
        """E.g. ``'AU'``, ``'EU'``."""
        return f"{self.path.name}U"


#: Union of all CTL formula nodes.
CTLFormula = Union[
    CTLAtom,
    CTLBool,
    CTLNot,
    CTLAnd,
    CTLOr,
    CTLImplies,
    CTLUnary,
    CTLUntil,
]

#: Any temporal formula (LTL or CTL).
TemporalFormula = Union[LTLFormula, CTLFormula]


# --- Transfer-function declarations (for dataflow properties) ---------

@dataclass(frozen=True, slots=True)
class TransferCase:
    """One case in a transfer function: pattern → new abstract value.

    ::

        (case (match (. node token str) "malloc") allocated)
        (case (match (. node token str) "free")   freed)
    """

    guard: Predicate
    result_value: Ident  # element name in the abstract domain
    loc: SourceLoc = field(default=NO_LOC, repr=False)


@dataclass(frozen=True, slots=True)
class TransferFuncDecl:
    """Declare a transfer function for abstract interpretation.

    ::

        (transfer-func allocation-transfer
          :domain allocation-state
          :var    ptr
          :cases  ((case (match (. node token str) "malloc") allocated)
                   (case (match (. node token str) "free")   freed)))
    """

    name: Ident
    domain: Ident        # references a DomainDecl
    variable: Ident      # the tracked variable binding
    cases: Tuple[TransferCase, ...]
    default: Optional[Ident] = None  # default domain element if no case matches
    loc: SourceLoc = field(default=NO_LOC, repr=False)


# --- Property kinds ---------------------------------------------------

class PropertyKind(Enum):
    """The flavour of analysis a property triggers."""

    SYNTACTIC = auto()   # Pure pattern-match (no fixpoint)
    DATAFLOW = auto()    # Abstract-interpretation with fixpoint
    TEMPORAL_LTL = auto()  # LTL model checking over CFG paths
    TEMPORAL_CTL = auto()  # CTL model checking over CFG tree
    SAFETY = auto()      # Simple invariant over reachable states


@dataclass(frozen=True, slots=True)
class PropSyntactic:
    """A purely syntactic property: true whenever the CSQL query matches.

    ::

        (property unused-variable
          :kind syntactic
          :query unused-locals-query
          :message "Variable '{var-name}' is never used.")
    """

    name: Ident
    query: Ident  # references a named CsqlQuery
    loc: SourceLoc = field(default=NO_LOC, repr=False)


@dataclass(frozen=True, slots=True)
class PropDataflow:
    """A dataflow property: asserts something about fixpoint results.

    ::

        (property double-free-df
          :kind dataflow
          :query alloc-sites-query
          :domain allocation-state
          :transfer allocation-transfer
          :bad-states (freed)
          :on-bad "Double free of '{ptr-name}' — state is already freed.")
    """

    name: Ident
    query: Ident           # CSQL query that selects analysis scope
    domain: Ident          # references a DomainDecl
    transfer: Ident        # references a TransferFuncDecl
    bad_states: Tuple[str, ...]  # domain elements that signal a violation
    on_bad_message: str    # diagnostic template
    loc: SourceLoc = field(default=NO_LOC, repr=False)


@dataclass(frozen=True, slots=True)
class PropTemporalLTL:
    """An LTL temporal property.

    ::

        (property alloc-must-free
          :kind ltl
          :query alloc-free-query
          :atoms ((allocated? ...) (freed? ...))
          :formula (G (ltl-implies allocated? (F freed?)))
          :on-violation "Resource '{ptr-name}' allocated but never freed.")
    """

    name: Ident
    query: Ident                    # CSQL query for scope
    atoms: Tuple[PropAtom, ...]     # atomic propositions
    formula: LTLFormula
    on_violation_message: str
    loc: SourceLoc = field(default=NO_LOC, repr=False)


@dataclass(frozen=True, slots=True)
class PropTemporalCTL:
    """A CTL temporal property.

    ::

        (property double-free-ctl
          :kind ctl
          :query alloc-free-query
          :atoms ((allocated? ...) (freed? ...) (use-after-free? ...))
          :formula (AG (ctl-implies freed?
                         (ctl-not (EF use-after-free?))))
          :on-violation "Use after free of '{ptr-name}'.")
    """

    name: Ident
    query: Ident
    atoms: Tuple[PropAtom, ...]
    formula: CTLFormula
    on_violation_message: str
    loc: SourceLoc = field(default=NO_LOC, repr=False)


@dataclass(frozen=True, slots=True)
class PropSafety:
    """A safety invariant checked over reachable states.

    Uses the existing ``transition_system.SafetyChecker`` substrate.

    ::

        (property no-null-deref
          :kind safety
          :query deref-sites-query
          :invariant (not (cmp == (. ptr value) null))
          :on-violation "Null pointer dereference: '{ptr-name}'.")
    """

    name: Ident
    query: Ident
    invariant: Predicate   # must hold at every reachable state
    on_violation_message: str
    loc: SourceLoc = field(default=NO_LOC, repr=False)


#: Union of all property nodes.
Property = Union[
    PropSyntactic,
    PropDataflow,
    PropTemporalLTL,
    PropTemporalCTL,
    PropSafety,
]


# --- Severity ---------------------------------------------------------

class Severity(Enum):
    """Diagnostic severity levels, matching Cppcheck conventions."""

    ERROR = auto()
    WARNING = auto()
    STYLE = auto()
    PERFORMANCE = auto()
    PORTABILITY = auto()
    INFORMATION = auto()


# --- Checker definition -----------------------------------------------

@dataclass(frozen=True, slots=True)
class CheckerDecl:
    """Combine a property with reporting metadata to form a checker.

    ::

        (checker double-free-checker
          :property double-free-ctl
          :severity error
          :id "doubleFree"
          :cwe 415
          :message "Double free detected for '{ptr-name}'."
          :verbose "Pointer '{ptr-name}' freed at {free-loc} was already freed at {first-free-loc}.")
    """

    name: Ident
    property_ref: Ident        # references a Property
    severity: Severity
    error_id: str              # Cppcheck error id (e.g. "doubleFree")
    cwe: Optional[int] = None  # CWE number
    message: Optional[str] = None  # short message (template)
    verbose: Optional[str] = None  # verbose message (template)
    enabled: bool = True       # can be disabled at module level
    loc: SourceLoc = field(default=NO_LOC, repr=False)


# --- Named query definition (top-level wrapper) -----------------------

@dataclass(frozen=True, slots=True)
class QueryDef:
    """A named, reusable CSQL query declared at module scope.

    ::

        (define-query alloc-free-pairs
          (query
            (from (token alloc-tok) (token free-tok) (variable ptr))
            (where (and (cmp == (. alloc-tok str) "malloc")
                        (cmp == (. free-tok str) "free")
                        (call same-pointer ptr alloc-tok free-tok)))
            (bind (ptr-name (. ptr nameToken str))
                  (alloc-loc (call source-location alloc-tok))
                  (free-loc  (call source-location free-tok)))))
    """

    name: Ident
    query: CsqlQuery
    doc: Optional[str] = None
    loc: SourceLoc = field(default=NO_LOC, repr=False)


# --- Named atom definition (top-level wrapper) -----------------------

@dataclass(frozen=True, slots=True)
class AtomDef:
    """A named atomic proposition declared at module scope.

    Can be referenced by multiple temporal properties.

    ::

        (define-atom freed?
          :at n
          :pred (cmp == (call domain-value allocation-state (. n) ptr) "freed"))
    """

    name: Ident
    atom: PropAtom
    doc: Optional[str] = None
    loc: SourceLoc = field(default=NO_LOC, repr=False)


# --- Module configuration -------------------------------------------

@dataclass(frozen=True, slots=True)
class ModuleConfig:
    """Optional module-level configuration block.

    ::

        (config
          :max-depth 200
          :max-states 50000
          :widening-delay 3
          :timeout 60)
    """

    params: Tuple[Tuple[str, Union[str, int, float, bool]], ...]
    loc: SourceLoc = field(default=NO_LOC, repr=False)

    def get(self, key: str, default: Any = None) -> Any:
        """Look up a config parameter by name."""
        for k, v in self.params:
            if k == key:
                return v
        return default


# --- Module (top-level compilation unit) -----------------------------

@dataclass(frozen=True, slots=True)
class Module:
    """A complete CASL module – the root of the AST.

    ::

        (module double-free-checker
          :doc "Detects double-free and use-after-free bugs."

          (import-battery memory)

          (config :max-depth 200)

          (domain allocation-state ...)
          (define-query alloc-free-pairs ...)
          (define-atom  freed? ...)

          (transfer-func allocation-transfer ...)

          (property double-free-ctl ...)
          (checker  double-free-checker ...))
    """

    name: Ident
    doc: Optional[str] = None
    imports: Tuple[Import, ...] = ()
    config: Optional[ModuleConfig] = None
    domains: Tuple[DomainDecl, ...] = ()
    queries: Tuple[QueryDef, ...] = ()
    atoms: Tuple[AtomDef, ...] = ()
    transfers: Tuple[TransferFuncDecl, ...] = ()
    properties: Tuple[Property, ...] = ()
    checkers: Tuple[CheckerDecl, ...] = ()
    loc: SourceLoc = field(default=NO_LOC, repr=False)

    # ---- Convenience accessors ------------------------------------

    def query_by_name(self, name: str) -> Optional[QueryDef]:
        """Look up a query definition by name."""
        for q in self.queries:
            if q.name == name:
                return q
        return None

    def property_by_name(self, name: str) -> Optional[Property]:
        """Look up a property definition by name."""
        for p in self.properties:
            if p.name == name:  # type: ignore[union-attr]
                return p
        return None

    def checker_by_name(self, name: str) -> Optional[CheckerDecl]:
        """Look up a checker definition by name."""
        for c in self.checkers:
            if c.name == name:
                return c
        return None

    def domain_by_name(self, name: str) -> Optional[DomainDecl]:
        """Look up a domain declaration by name."""
        for d in self.domains:
            if d.name == name:
                return d
        return None

    def atom_by_name(self, name: str) -> Optional[AtomDef]:
        """Look up an atom definition by name."""
        for a in self.atoms:
            if a.name == name:
                return a
        return None

    def transfer_by_name(self, name: str) -> Optional[TransferFuncDecl]:
        """Look up a transfer function declaration by name."""
        for t in self.transfers:
            if t.name == name:
                return t
        return None

    def all_names(self) -> Tuple[Ident, ...]:
        """Return every name defined in this module (for collision detection)."""
        names: list[Ident] = []
        for collection in (
            self.domains, self.queries, self.atoms,
            self.transfers, self.properties, self.checkers,
        ):
            for item in collection:
                names.append(item.name)  # type: ignore[union-attr]
        return tuple(names)


# ════════════════════════════════════════════════════════════════════════
# §4  Visitor protocol
# ════════════════════════════════════════════════════════════════════════
#
# A generic visitor / transformer protocol for AST traversal.
# Compiler phases (type-checker, code-generator, optimizer) implement
# this protocol.

# Type variable for the visitor return type.
T = TypeVar("T")


@runtime_checkable
class CsqlVisitor(Protocol[T]):
    """Visitor protocol for CSQL AST nodes."""

    def visit_query(self, node: CsqlQuery) -> T: ...
    def visit_entity_source(self, node: EntitySource) -> T: ...
    def visit_binding_decl(self, node: BindingDecl) -> T: ...

    # Predicates
    def visit_pred_true(self, node: PredicateTrue) -> T: ...
    def visit_pred_false(self, node: PredicateFalse) -> T: ...
    def visit_pred_cmp(self, node: PredicateCmp) -> T: ...
    def visit_pred_match(self, node: PredicateMatch) -> T: ...
    def visit_pred_in(self, node: PredicateIn) -> T: ...
    def visit_pred_has(self, node: PredicateHas) -> T: ...
    def visit_pred_is_a(self, node: PredicateIsA) -> T: ...
    def visit_pred_call(self, node: PredicateCall) -> T: ...
    def visit_pred_unary(self, node: PredicateUnary) -> T: ...
    def visit_pred_binary(self, node: PredicateBinary) -> T: ...
    def visit_pred_quantifier(self, node: PredicateQuantifier) -> T: ...

    # Expressions
    def visit_attr_access(self, node: PredicateAttrAccess) -> T: ...
    def visit_literal(self, node: PredicateLiteral) -> T: ...


@runtime_checkable
class LTLVisitor(Protocol[T]):
    """Visitor protocol for LTL formula nodes."""

    def visit_ltl_atom(self, node: LTLAtom) -> T: ...
    def visit_ltl_bool(self, node: LTLBool) -> T: ...
    def visit_ltl_not(self, node: LTLNot) -> T: ...
    def visit_ltl_and(self, node: LTLAnd) -> T: ...
    def visit_ltl_or(self, node: LTLOr) -> T: ...
    def visit_ltl_implies(self, node: LTLImplies) -> T: ...
    def visit_ltl_unary(self, node: LTLUnary) -> T: ...
    def visit_ltl_binary(self, node: LTLBinary) -> T: ...


@runtime_checkable
class CTLVisitor(Protocol[T]):
    """Visitor protocol for CTL formula nodes."""

    def visit_ctl_atom(self, node: CTLAtom) -> T: ...
    def visit_ctl_bool(self, node: CTLBool) -> T: ...
    def visit_ctl_not(self, node: CTLNot) -> T: ...
    def visit_ctl_and(self, node: CTLAnd) -> T: ...
    def visit_ctl_or(self, node: CTLOr) -> T: ...
    def visit_ctl_implies(self, node: CTLImplies) -> T: ...
    def visit_ctl_unary(self, node: CTLUnary) -> T: ...
    def visit_ctl_until(self, node: CTLUntil) -> T: ...


@runtime_checkable
class CaslVisitor(Protocol[T]):
    """Visitor protocol for top-level CASL AST nodes."""

    def visit_module(self, node: Module) -> T: ...
    def visit_import_battery(self, node: ImportBattery) -> T: ...
    def visit_import_module(self, node: ImportModule) -> T: ...
    def visit_domain_decl(self, node: DomainDecl) -> T: ...
    def visit_query_def(self, node: QueryDef) -> T: ...
    def visit_atom_def(self, node: AtomDef) -> T: ...
    def visit_transfer_func(self, node: TransferFuncDecl) -> T: ...
    def visit_prop_syntactic(self, node: PropSyntactic) -> T: ...
    def visit_prop_dataflow(self, node: PropDataflow) -> T: ...
    def visit_prop_temporal_ltl(self, node: PropTemporalLTL) -> T: ...
    def visit_prop_temporal_ctl(self, node: PropTemporalCTL) -> T: ...
    def visit_prop_safety(self, node: PropSafety) -> T: ...
    def visit_checker_decl(self, node: CheckerDecl) -> T: ...
    def visit_config(self, node: ModuleConfig) -> T: ...


# ════════════════════════════════════════════════════════════════════════
# §5  Dispatch helpers
# ════════════════════════════════════════════════════════════════════════
#
# Since we use Union types rather than a class hierarchy with virtual
# ``accept`` methods, we provide dispatch functions that route a node
# to the correct visitor method based on its type.


def dispatch_predicate(pred: Predicate, visitor: CsqlVisitor[T]) -> T:
    """Dispatch a ``Predicate`` node to the appropriate visitor method."""
    _PRED_DISPATCH: dict[type, str] = {
        PredicateTrue: "visit_pred_true",
        PredicateFalse: "visit_pred_false",
        PredicateCmp: "visit_pred_cmp",
        PredicateMatch: "visit_pred_match",
        PredicateIn: "visit_pred_in",
        PredicateHas: "visit_pred_has",
        PredicateIsA: "visit_pred_is_a",
        PredicateCall: "visit_pred_call",
        PredicateUnary: "visit_pred_unary",
        PredicateBinary: "visit_pred_binary",
        PredicateQuantifier: "visit_pred_quantifier",
    }
    method_name = _PRED_DISPATCH.get(type(pred))
    if method_name is None:
        raise TypeError(f"Unknown predicate node type: {type(pred).__name__}")
    return getattr(visitor, method_name)(pred)


def dispatch_ltl(formula: LTLFormula, visitor: LTLVisitor[T]) -> T:
    """Dispatch an ``LTLFormula`` node to the appropriate visitor method."""
    _LTL_DISPATCH: dict[type, str] = {
        LTLAtom: "visit_ltl_atom",
        LTLBool: "visit_ltl_bool",
        LTLNot: "visit_ltl_not",
        LTLAnd: "visit_ltl_and",
        LTLOr: "visit_ltl_or",
        LTLImplies: "visit_ltl_implies",
        LTLUnary: "visit_ltl_unary",
        LTLBinary: "visit_ltl_binary",
    }
    method_name = _LTL_DISPATCH.get(type(formula))
    if method_name is None:
        raise TypeError(f"Unknown LTL node type: {type(formula).__name__}")
    return getattr(visitor, method_name)(formula)


def dispatch_ctl(formula: CTLFormula, visitor: CTLVisitor[T]) -> T:
    """Dispatch a ``CTLFormula`` node to the appropriate visitor method."""
    _CTL_DISPATCH: dict[type, str] = {
        CTLAtom: "visit_ctl_atom",
        CTLBool: "visit_ctl_bool",
        CTLNot: "visit_ctl_not",
        CTLAnd: "visit_ctl_and",
        CTLOr: "visit_ctl_or",
        CTLImplies: "visit_ctl_implies",
        CTLUnary: "visit_ctl_unary",
        CTLUntil: "visit_ctl_until",
    }
    method_name = _CTL_DISPATCH.get(type(formula))
    if method_name is None:
        raise TypeError(f"Unknown CTL node type: {type(formula).__name__}")
    return getattr(visitor, method_name)(formula)


def dispatch_property(prop: Property, visitor: CaslVisitor[T]) -> T:
    """Dispatch a ``Property`` node to the appropriate visitor method."""
    _PROP_DISPATCH: dict[type, str] = {
        PropSyntactic: "visit_prop_syntactic",
        PropDataflow: "visit_prop_dataflow",
        PropTemporalLTL: "visit_prop_temporal_ltl",
        PropTemporalCTL: "visit_prop_temporal_ctl",
        PropSafety: "visit_prop_safety",
    }
    method_name = _PROP_DISPATCH.get(type(prop))
    if method_name is None:
        raise TypeError(f"Unknown property node type: {type(prop).__name__}")
    return getattr(visitor, method_name)(prop)


def dispatch_import(imp: Import, visitor: CaslVisitor[T]) -> T:
    """Dispatch an ``Import`` node to the appropriate visitor method."""
    if isinstance(imp, ImportBattery):
        return visitor.visit_import_battery(imp)
    if isinstance(imp, ImportModule):
        return visitor.visit_import_module(imp)
    raise TypeError(f"Unknown import node type: {type(imp).__name__}")


# ════════════════════════════════════════════════════════════════════════
# §6  Pretty-printing helpers
# ════════════════════════════════════════════════════════════════════════
#
# Minimal S-expression pretty-printer for debugging / round-trip tests.
# NOT the canonical serializer (that lives in casl/printer.py), but
# useful for __repr__ in REPL sessions and test diagnostics.


def _indent(text: str, prefix: str = "  ") -> str:
    return textwrap.indent(text, prefix)


def pretty_predicate(pred: Predicate) -> str:
    """Return a human-readable S-expression string for a predicate."""
    if isinstance(pred, PredicateTrue):
        return "true"
    if isinstance(pred, PredicateFalse):
        return "false"
    if isinstance(pred, PredicateCmp):
        return (
            f"(cmp {pred.op.symbol()} "
            f"{pretty_pred_expr(pred.lhs)} "
            f"{pretty_pred_expr(pred.rhs)})"
        )
    if isinstance(pred, PredicateMatch):
        return f'(match {pred.target.pretty()} "{pred.pattern}")'
    if isinstance(pred, PredicateIn):
        choices = " ".join(pretty_pred_expr(c) for c in pred.choices)
        return f"(in {pretty_pred_expr(pred.target)} {choices})"
    if isinstance(pred, PredicateHas):
        return f"(has {pred.target.pretty()})"
    if isinstance(pred, PredicateIsA):
        return f"(is-a {pred.target} {pred.kind!r})"
    if isinstance(pred, PredicateCall):
        args = " ".join(pretty_pred_expr(a) for a in pred.args)
        return f"(call {pred.name}{' ' + args if args else ''})"
    if isinstance(pred, PredicateUnary):
        return f"({pred.op.name.lower()} {pretty_predicate(pred.operand)})"
    if isinstance(pred, PredicateBinary):
        op_str = {
            BinaryLogicOp.AND: "and",
            BinaryLogicOp.OR: "or",
            BinaryLogicOp.IMPLIES: "=>",
        }[pred.op]
        return (
            f"({op_str} {pretty_predicate(pred.lhs)} "
            f"{pretty_predicate(pred.rhs)})"
        )
    if isinstance(pred, PredicateQuantifier):
        return (
            f"({pred.quantifier} {pred.binding} "
            f"({pred.source.kind.name.lower()} {pred.source.binding}) "
            f"{pretty_predicate(pred.body)})"
        )
    return f"<unknown-predicate {type(pred).__name__}>"


def pretty_pred_expr(expr: PredicateExpr) -> str:
    """Return a human-readable S-expression for a predicate expression."""
    if isinstance(expr, PredicateAttrAccess):
        return f"(. {expr.pretty()})"
    if isinstance(expr, PredicateLiteral):
        if isinstance(expr.value, str):
            return f'"{expr.value}"'
        if expr.value is None:
            return "nil"
        if isinstance(expr.value, bool):
            return "true" if expr.value else "false"
        return str(expr.value)
    if isinstance(expr, PredicateCall):
        args = " ".join(pretty_pred_expr(a) for a in expr.args)
        return f"(call {expr.name}{' ' + args if args else ''})"
    return f"<unknown-expr {type(expr).__name__}>"


def pretty_ltl(formula: LTLFormula) -> str:
    """Return a human-readable string for an LTL formula."""
    if isinstance(formula, LTLAtom):
        return str(formula.name)
    if isinstance(formula, LTLBool):
        return "⊤" if formula.value else "⊥"
    if isinstance(formula, LTLNot):
        return f"(¬ {pretty_ltl(formula.operand)})"
    if isinstance(formula, LTLAnd):
        return "(" + " ∧ ".join(pretty_ltl(o) for o in formula.operands) + ")"
    if isinstance(formula, LTLOr):
        return "(" + " ∨ ".join(pretty_ltl(o) for o in formula.operands) + ")"
    if isinstance(formula, LTLImplies):
        return f"({pretty_ltl(formula.lhs)} → {pretty_ltl(formula.rhs)})"
    if isinstance(formula, LTLUnary):
        op_sym = {LTLOp.NEXT: "X", LTLOp.GLOBALLY: "G", LTLOp.FINALLY: "F"}
        return f"({op_sym.get(formula.op, formula.op.name)} {pretty_ltl(formula.operand)})"
    if isinstance(formula, LTLBinary):
        op_sym = {LTLOp.UNTIL: "U", LTLOp.RELEASE: "R", LTLOp.WEAK_UNTIL: "W"}
        return (
            f"({pretty_ltl(formula.lhs)} "
            f"{op_sym.get(formula.op, formula.op.name)} "
            f"{pretty_ltl(formula.rhs)})"
        )
    return f"<unknown-ltl {type(formula).__name__}>"


def pretty_ctl(formula: CTLFormula) -> str:
    """Return a human-readable string for a CTL formula."""
    if isinstance(formula, CTLAtom):
        return str(formula.name)
    if isinstance(formula, CTLBool):
        return "⊤" if formula.value else "⊥"
    if isinstance(formula, CTLNot):
        return f"(¬ {pretty_ctl(formula.operand)})"
    if isinstance(formula, CTLAnd):
        return "(" + " ∧ ".join(pretty_ctl(o) for o in formula.operands) + ")"
    if isinstance(formula, CTLOr):
        return "(" + " ∨ ".join(pretty_ctl(o) for o in formula.operands) + ")"
    if isinstance(formula, CTLImplies):
        return f"({pretty_ctl(formula.lhs)} → {pretty_ctl(formula.rhs)})"
    if isinstance(formula, CTLUnary):
        return f"({formula.pretty_op()} {pretty_ctl(formula.operand)})"
    if isinstance(formula, CTLUntil):
        return (
            f"({formula.path.name}["
            f"{pretty_ctl(formula.lhs)} U {pretty_ctl(formula.rhs)}])"
        )
    return f"<unknown-ctl {type(formula).__name__}>"
