#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
casl/ast.py
===========

Abstract Syntax Tree node definitions for CASL.

The AST is a typed, hierarchical representation of a CASL specification.
Each node type corresponds to a syntactic construct in the language.

Node Categories
---------------
- **Top-level**: AddonSpec, Metadata, Import
- **Declarations**: DomainDecl, PatternDecl, QueryDecl, CheckerDecl,
  TransferDecl, FunctionDecl
- **Expressions**: Literal, Identifier, BinaryOp, UnaryOp, Call, FieldAccess,
  IfExpr, LetExpr, MatchExpr
- **Patterns**: NodePattern, SequencePattern, StarPattern, BindingPattern
- **Types**: TypeRef, DomainType, SetType, MapType

Design Notes
------------
All nodes inherit from :class:`ASTNode`, which provides:
- Common ``location`` attribute for error reporting
- ``accept(visitor)`` method for the visitor pattern
- ``children()`` iterator for generic traversal

Nodes are frozen dataclasses where possible to ensure immutability after
construction, simplifying analysis passes.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import (
    Any,
    Dict,
    Iterator,
    List,
    Mapping,
    Optional,
    Sequence,
    Tuple,
    Union,
    TYPE_CHECKING,
)

if TYPE_CHECKING:
    from casl.visitor import ASTVisitor
    from casl.errors import SourceLocation

__all__ = [
    # Base
    "ASTNode",
    # Top-level
    "AddonSpec",
    "Metadata",
    "Import",
    # Declarations
    "DomainDecl",
    "DomainElement",
    "PatternDecl",
    "QueryDecl",
    "CheckerDecl",
    "TransferDecl",
    "FunctionDecl",
    "VarDecl",
    # Expressions
    "Expr",
    "Literal",
    "Identifier",
    "BinaryOp",
    "UnaryOp",
    "Call",
    "FieldAccess",
    "IndexAccess",
    "IfExpr",
    "LetExpr",
    "MatchExpr",
    "MatchArm",
    "LambdaExpr",
    "SetExpr",
    "MapExpr",
    "TupleExpr",
    # Patterns (code patterns, not match patterns)
    "CodePattern",
    "NodePattern",
    "SequencePattern",
    "StarPattern",
    "OptionalPattern",
    "OrPattern",
    "BindingPattern",
    "GuardedPattern",
    "WildcardPattern",
    # Constraints / conditions
    "Constraint",
    "WhereClause",
    "FlowsTo",
    "Reaches",
    "Dominates",
    "DataflowFact",
    # Actions
    "Action",
    "ReportAction",
    "LogAction",
    "SetFactAction",
    "AbortAction",
    # Types
    "TypeExpr",
    "TypeRef",
    "DomainType",
    "SetType",
    "MapType",
    "TupleType",
    "FunctionType",
    # Dataflow specifications
    "DataflowSpec",
    "LatticeSpec",
    "TransferSpec",
    "DirectionSpec",
]


# ═══════════════════════════════════════════════════════════════════════════
# BASE CLASS
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class ASTNode(abc.ABC):
    """Abstract base for all AST nodes.
    
    Attributes
    ----------
    location : SourceLocation | None
        Source location for error reporting.
    annotations : dict
        Arbitrary metadata attached by analysis passes.
    """
    
    location: Optional["SourceLocation"] = field(
        default=None, compare=False, repr=False
    )
    annotations: Dict[str, Any] = field(
        default_factory=dict, compare=False, repr=False
    )
    
    @abc.abstractmethod
    def accept(self, visitor: "ASTVisitor") -> Any:
        """Accept a visitor (double-dispatch)."""
        ...
    
    def children(self) -> Iterator["ASTNode"]:
        """Yield all child nodes (for generic traversal)."""
        for name, value in self.__dict__.items():
            if name in ("location", "annotations"):
                continue
            if isinstance(value, ASTNode):
                yield value
            elif isinstance(value, (list, tuple)):
                for item in value:
                    if isinstance(item, ASTNode):
                        yield item
            elif isinstance(value, dict):
                for v in value.values():
                    if isinstance(v, ASTNode):
                        yield v
    
    def walk(self) -> Iterator["ASTNode"]:
        """Recursively yield this node and all descendants (pre-order)."""
        yield self
        for child in self.children():
            yield from child.walk()


# ═══════════════════════════════════════════════════════════════════════════
# TOP-LEVEL NODES
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class Metadata(ASTNode):
    """Addon metadata block.
    
    (metadata
      (name "my-addon")
      (version "1.0.0")
      (author "...")
      (description "..."))
    """
    
    name: str = ""
    version: str = "0.1.0"
    author: str = ""
    description: str = ""
    tags: List[str] = field(default_factory=list)
    
    def accept(self, visitor: "ASTVisitor") -> Any:
        return visitor.visit_metadata(self)


@dataclass
class Import(ASTNode):
    """Import declaration.
    
    (import <module> [as <alias>] [only <names>])
    """
    
    module: str = ""
    alias: Optional[str] = None
    names: List[str] = field(default_factory=list)  # selective import
    
    def accept(self, visitor: "ASTVisitor") -> Any:
        return visitor.visit_import(self)


@dataclass
class AddonSpec(ASTNode):
    """Root node — complete CASL addon specification.
    
    (addon <name>
      (metadata ...)
      (import ...)
      (domain ...)
      (pattern ...)
      (query ...)
      (checker ...))
    """
    
    name: str = ""
    metadata: Optional[Metadata] = None
    imports: List[Import] = field(default_factory=list)
    domains: List["DomainDecl"] = field(default_factory=list)
    functions: List["FunctionDecl"] = field(default_factory=list)
    transfers: List["TransferDecl"] = field(default_factory=list)
    patterns: List["PatternDecl"] = field(default_factory=list)
    queries: List["QueryDecl"] = field(default_factory=list)
    checkers: List["CheckerDecl"] = field(default_factory=list)
    dataflows: List["DataflowSpec"] = field(default_factory=list)
    
    def accept(self, visitor: "ASTVisitor") -> Any:
        return visitor.visit_addon_spec(self)


# ═══════════════════════════════════════════════════════════════════════════
# DECLARATIONS
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class VarDecl(ASTNode):
    """Variable declaration in patterns/queries.
    
    (var <name> [: <type>])
    """
    
    name: str = ""
    type_annotation: Optional["TypeExpr"] = None
    
    def accept(self, visitor: "ASTVisitor") -> Any:
        return visitor.visit_var_decl(self)


@dataclass
class DomainElement(ASTNode):
    """A single element in a finite domain.
    
    (element <name> [(<properties>...)])
    """
    
    name: str = ""
    properties: Dict[str, "Expr"] = field(default_factory=dict)
    
    def accept(self, visitor: "ASTVisitor") -> Any:
        return visitor.visit_domain_element(self)


@dataclass
class DomainDecl(ASTNode):
    """Abstract domain declaration.
    
    (domain <name>
      (kind <finite|powerset|interval|product|...>)
      (elements <elem>...)           ; for finite domains
      (carrier <type>)               ; for parametric domains
      (bottom <expr>)
      (top <expr>)
      (join <binary-op>)
      (meet <binary-op>)
      (leq <binary-op>)
      (widen <binary-op>))           ; optional widening
    
    The domain can reference built-in domains (Sign, Interval, Parity, etc.)
    or define a custom finite lattice.
    """
    
    name: str = ""
    kind: str = "finite"  # finite, powerset, interval, product, map, lifted
    elements: List[DomainElement] = field(default_factory=list)
    carrier: Optional["TypeExpr"] = None
    bottom: Optional["Expr"] = None
    top: Optional["Expr"] = None
    join: Optional["Expr"] = None   # λ (a, b) -> ...
    meet: Optional["Expr"] = None
    leq: Optional["Expr"] = None    # λ (a, b) -> bool
    widen: Optional["Expr"] = None
    
    # For product domains
    components: List[Tuple[str, str]] = field(default_factory=list)
    
    # For map domains
    key_domain: Optional[str] = None
    value_domain: Optional[str] = None
    
    def accept(self, visitor: "ASTVisitor") -> Any:
        return visitor.visit_domain_decl(self)


@dataclass
class FunctionDecl(ASTNode):
    """Named function declaration.
    
    (define (<name> <params>...)
      <body>)
    """
    
    name: str = ""
    params: List[VarDecl] = field(default_factory=list)
    return_type: Optional["TypeExpr"] = None
    body: Optional["Expr"] = None
    
    def accept(self, visitor: "ASTVisitor") -> Any:
        return visitor.visit_function_decl(self)


@dataclass
class TransferDecl(ASTNode):
    """Transfer function declaration.
    
    (transfer <name>
      (domain <domain-ref>)
      (direction <forward|backward>)
      (cases
        ((assign ?lhs ?rhs) <expr>)
        ((call ?fn ?args) <expr>)
        ...))
    """
    
    name: str = ""
    domain: str = ""
    direction: str = "forward"
    cases: List[Tuple["CodePattern", "Expr"]] = field(default_factory=list)
    default: Optional["Expr"] = None  # identity if not specified
    
    def accept(self, visitor: "ASTVisitor") -> Any:
        return visitor.visit_transfer_decl(self)


# ═══════════════════════════════════════════════════════════════════════════
# CODE PATTERNS (PQL-style)
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class CodePattern(ASTNode):
    """Base class for code patterns."""
    pass


@dataclass
class WildcardPattern(CodePattern):
    """Matches anything: _"""
    
    def accept(self, visitor: "ASTVisitor") -> Any:
        return visitor.visit_wildcard_pattern(self)


@dataclass
class BindingPattern(CodePattern):
    """Captures a matched node into a variable: ?name or ?name:type"""
    
    name: str = ""
    type_constraint: Optional[str] = None  # "Token", "Function", "Variable", etc.
    nested: Optional[CodePattern] = None   # ?x:(assign _ _)
    
    def accept(self, visitor: "ASTVisitor") -> Any:
        return visitor.visit_binding_pattern(self)


@dataclass
class NodePattern(CodePattern):
    """Matches a specific AST node type with sub-patterns.
    
    (assign ?lhs ?rhs)
    (call ?callee ?args...)
    (if ?cond ?then ?else)
    (binop ?op ?left ?right)
    (return ?value)
    """
    
    node_type: str = ""  # "assign", "call", "if", "return", "binop", etc.
    children: List[CodePattern] = field(default_factory=list)
    
    def accept(self, visitor: "ASTVisitor") -> Any:
        return visitor.visit_node_pattern(self)


@dataclass
class SequencePattern(CodePattern):
    """Matches a sequence of statements in order.
    
    (seq <pat1> <pat2> ...)
    
    Unlike PQL which requires contiguous matches, we allow intervening
    statements — this is a "may follow" pattern.
    """
    
    patterns: List[CodePattern] = field(default_factory=list)
    contiguous: bool = False  # if True, no intervening statements allowed
    
    def accept(self, visitor: "ASTVisitor") -> Any:
        return visitor.visit_sequence_pattern(self)


@dataclass
class StarPattern(CodePattern):
    """Matches zero or more of a sub-pattern (Kleene star).
    
    (* <pattern>)
    (+ <pattern>)  ; one or more
    """
    
    inner: CodePattern = field(default_factory=WildcardPattern)
    min_count: int = 0
    max_count: Optional[int] = None  # None = unlimited
    
    def accept(self, visitor: "ASTVisitor") -> Any:
        return visitor.visit_star_pattern(self)


@dataclass
class OptionalPattern(CodePattern):
    """Matches zero or one of a sub-pattern.
    
    (? <pattern>)
    """
    
    inner: Optional[CodePattern] = None
    
    def accept(self, visitor: "ASTVisitor") -> Any:
        return visitor.visit_optional_pattern(self)


@dataclass
class OrPattern(CodePattern):
    """Matches any of several alternatives.
    
    (or <pat1> <pat2> ...)
    """
    
    alternatives: List[CodePattern] = field(default_factory=list)
    
    def accept(self, visitor: "ASTVisitor") -> Any:
        return visitor.visit_or_pattern(self)


@dataclass
class GuardedPattern(CodePattern):
    """Pattern with additional constraint.
    
    (when <pattern> <condition>)
    """
    
    pattern: Optional[CodePattern] = None
    guard: Optional["Expr"] = None
    
    def accept(self, visitor: "ASTVisitor") -> Any:
        return visitor.visit_guarded_pattern(self)


@dataclass
class PatternDecl(ASTNode):
    """Named pattern declaration.
    
    (pattern <name>
      (vars (?x Token) (?y Variable) ...)
      (match <code-pattern>)
      (where <constraints>...))
    """
    
    name: str = ""
    variables: List[VarDecl] = field(default_factory=list)
    match: Optional[CodePattern] = None
    where: List["Constraint"] = field(default_factory=list)
    
    def accept(self, visitor: "ASTVisitor") -> Any:
        return visitor.visit_pattern_decl(self)


# ═══════════════════════════════════════════════════════════════════════════
# CONSTRAINTS
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class Constraint(ASTNode):
    """Base class for constraints in where-clauses."""
    pass


@dataclass
class WhereClause(Constraint):
    """Generic boolean constraint: (where <expr>)"""
    
    condition: Optional["Expr"] = None
    
    def accept(self, visitor: "ASTVisitor") -> Any:
        return visitor.visit_where_clause(self)


@dataclass
class FlowsTo(Constraint):
    """Dataflow reachability: (flows-to ?src ?dst [via ?domain])
    
    True if abstract value can flow from ?src to ?dst.
    """
    
    source: Optional["Expr"] = None
    destination: Optional["Expr"] = None
    domain: Optional[str] = None
    
    def accept(self, visitor: "ASTVisitor") -> Any:
        return visitor.visit_flows_to(self)


@dataclass
class Reaches(Constraint):
    """Control-flow reachability: (reaches ?from ?to)
    
    True if ?to is reachable from ?from in the CFG.
    """
    
    source: Optional["Expr"] = None
    destination: Optional["Expr"] = None
    
    def accept(self, visitor: "ASTVisitor") -> Any:
        return visitor.visit_reaches(self)


@dataclass
class Dominates(Constraint):
    """Dominance relation: (dominates ?a ?b)
    
    True if ?a dominates ?b in the CFG.
    """
    
    dominator: Optional["Expr"] = None
    dominated: Optional["Expr"] = None
    
    def accept(self, visitor: "ASTVisitor") -> Any:
        return visitor.visit_dominates(self)


@dataclass
class DataflowFact(Constraint):
    """Assert/query a dataflow fact: (fact ?var <domain> <value> at ?loc)"""
    
    variable: Optional["Expr"] = None
    domain: Optional[str] = None
    value: Optional["Expr"] = None
    location: Optional["Expr"] = None  # program point, not source location
    
    def accept(self, visitor: "ASTVisitor") -> Any:
        return visitor.visit_dataflow_fact(self)


# ═══════════════════════════════════════════════════════════════════════════
# EXPRESSIONS
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class Expr(ASTNode):
    """Base class for expressions."""
    pass


@dataclass
class Literal(Expr):
    """Literal value: integer, string, boolean, symbol."""
    
    value: Any = None
    kind: str = "unknown"  # "int", "float", "string", "bool", "symbol", "nil"
    
    def accept(self, visitor: "ASTVisitor") -> Any:
        return visitor.visit_literal(self)


@dataclass
class Identifier(Expr):
    """Variable or name reference."""
    
    name: str = ""
    
    def accept(self, visitor: "ASTVisitor") -> Any:
        return visitor.visit_identifier(self)


@dataclass
class BinaryOp(Expr):
    """Binary operation: (op left right)"""
    
    op: str = ""
    left: Optional[Expr] = None
    right: Optional[Expr] = None
    
    def accept(self, visitor: "ASTVisitor") -> Any:
        return visitor.visit_binary_op(self)


@dataclass
class UnaryOp(Expr):
    """Unary operation: (op operand)"""
    
    op: str = ""
    operand: Optional[Expr] = None
    
    def accept(self, visitor: "ASTVisitor") -> Any:
        return visitor.visit_unary_op(self)


@dataclass
class Call(Expr):
    """Function call: (fn arg1 arg2 ...)"""
    
    function: Optional[Expr] = None
    arguments: List[Expr] = field(default_factory=list)
    
    def accept(self, visitor: "ASTVisitor") -> Any:
        return visitor.visit_call(self)


@dataclass
class FieldAccess(Expr):
    """Field access: (. obj field) or obj.field"""
    
    object: Optional[Expr] = None
    field: str = ""
    
    def accept(self, visitor: "ASTVisitor") -> Any:
        return visitor.visit_field_access(self)


@dataclass
class IndexAccess(Expr):
    """Index access: ([] obj index)"""
    
    object: Optional[Expr] = None
    index: Optional[Expr] = None
    
    def accept(self, visitor: "ASTVisitor") -> Any:
        return visitor.visit_index_access(self)


@dataclass
class IfExpr(Expr):
    """Conditional expression: (if cond then else)"""
    
    condition: Optional[Expr] = None
    then_branch: Optional[Expr] = None
    else_branch: Optional[Expr] = None
    
    def accept(self, visitor: "ASTVisitor") -> Any:
        return visitor.visit_if_expr(self)


@dataclass
class LetExpr(Expr):
    """Local binding: (let ((x val) ...) body)"""
    
    bindings: List[Tuple[str, Expr]] = field(default_factory=list)
    body: Optional[Expr] = None
    
    def accept(self, visitor: "ASTVisitor") -> Any:
        return visitor.visit_let_expr(self)


@dataclass
class MatchArm(ASTNode):
    """Single arm in a match expression."""
    
    pattern: Optional[CodePattern] = None
    guard: Optional[Expr] = None
    body: Optional[Expr] = None
    
    def accept(self, visitor: "ASTVisitor") -> Any:
        return visitor.visit_match_arm(self)


@dataclass
class MatchExpr(Expr):
    """Pattern matching: (match scrutinee (pat1 => body1) ...)"""
    
    scrutinee: Optional[Expr] = None
    arms: List[MatchArm] = field(default_factory=list)
    
    def accept(self, visitor: "ASTVisitor") -> Any:
        return visitor.visit_match_expr(self)


@dataclass
class LambdaExpr(Expr):
    """Anonymous function: (lambda (params...) body)"""
    
    params: List[str] = field(default_factory=list)
    body: Optional[Expr] = None
    
    def accept(self, visitor: "ASTVisitor") -> Any:
        return visitor.visit_lambda_expr(self)


@dataclass
class SetExpr(Expr):
    """Set literal: (set elem1 elem2 ...)"""
    
    elements: List[Expr] = field(default_factory=list)
    
    def accept(self, visitor: "ASTVisitor") -> Any:
        return visitor.visit_set_expr(self)


@dataclass
class MapExpr(Expr):
    """Map literal: (map (k1 v1) (k2 v2) ...)"""
    
    entries: List[Tuple[Expr, Expr]] = field(default_factory=list)
    
    def accept(self, visitor: "ASTVisitor") -> Any:
        return visitor.visit_map_expr(self)


@dataclass
class TupleExpr(Expr):
    """Tuple: (tuple a b c)"""
    
    elements: List[Expr] = field(default_factory=list)
    
    def accept(self, visitor: "ASTVisitor") -> Any:
        return visitor.visit_tuple_expr(self)


# ═══════════════════════════════════════════════════════════════════════════
# ACTIONS
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class Action(ASTNode):
    """Base class for actions triggered on pattern match."""
    pass


@dataclass
class ReportAction(Action):
    """Report a diagnostic: (report <severity> <message> <location>)"""
    
    severity: str = "warning"  # "error", "warning", "style", "performance"
    message: Optional[Expr] = None  # format string
    location: Optional[Expr] = None  # which bound variable to use for location
    cwe: Optional[int] = None
    certainty: str = "possible"  # "certain", "possible"
    
    def accept(self, visitor: "ASTVisitor") -> Any:
        return visitor.visit_report_action(self)


@dataclass
class LogAction(Action):
    """Log for debugging: (log <format> <args>...)"""
    
    format: Optional[Expr] = None
    arguments: List[Expr] = field(default_factory=list)
    
    def accept(self, visitor: "ASTVisitor") -> Any:
        return visitor.visit_log_action(self)


@dataclass
class SetFactAction(Action):
    """Set a dataflow fact: (set-fact ?var domain value)"""
    
    variable: Optional[Expr] = None
    domain: str = ""
    value: Optional[Expr] = None
    
    def accept(self, visitor: "ASTVisitor") -> Any:
        return visitor.visit_set_fact_action(self)


@dataclass
class AbortAction(Action):
    """Abort analysis on this path: (abort)"""
    
    def accept(self, visitor: "ASTVisitor") -> Any:
        return visitor.visit_abort_action(self)


# ═══════════════════════════════════════════════════════════════════════════
# QUERIES AND CHECKERS
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class QueryDecl(ASTNode):
    """Named query that combines patterns with dataflow analysis.
    
    (query <name>
      (uses <pattern-name>)
      (requires <dataflow-spec>)
      (returns <expression>)
      (action <action>...))
    """
    
    name: str = ""
    pattern: Optional[str] = None    # reference to PatternDecl
    pattern_inline: Optional[CodePattern] = None  # or inline pattern
    requires: List[str] = field(default_factory=list)  # dataflow specs needed
    returns: Optional[Expr] = None
    actions: List[Action] = field(default_factory=list)
    
    def accept(self, visitor: "ASTVisitor") -> Any:
        return visitor.visit_query_decl(self)


@dataclass
class CheckerDecl(ASTNode):
    """Top-level checker that runs queries and reports issues.
    
    (checker <name>
      (severity <level>)
      (cwe <id>)
      (message <format-string>)
      (query <query-name>)
      (enabled <bool>))
    """
    
    name: str = ""
    severity: str = "warning"
    cwe: Optional[int] = None
    message: str = ""
    query: Optional[str] = None      # reference to QueryDecl
    query_inline: Optional[QueryDecl] = None  # or inline query
    enabled: bool = True
    
    def accept(self, visitor: "ASTVisitor") -> Any:
        return visitor.visit_checker_decl(self)


# ═══════════════════════════════════════════════════════════════════════════
# TYPES
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class TypeExpr(ASTNode):
    """Base class for type expressions."""
    pass


@dataclass
class TypeRef(TypeExpr):
    """Reference to a named type: Token, Variable, Function, etc."""
    
    name: str = ""
    
    def accept(self, visitor: "ASTVisitor") -> Any:
        return visitor.visit_type_ref(self)


@dataclass
class DomainType(TypeExpr):
    """Type representing abstract domain values: (Domain Sign)"""
    
    domain: str = ""
    
    def accept(self, visitor: "ASTVisitor") -> Any:
        return visitor.visit_domain_type(self)


@dataclass
class SetType(TypeExpr):
    """Set type: (Set T)"""
    
    element_type: Optional[TypeExpr] = None
    
    def accept(self, visitor: "ASTVisitor") -> Any:
        return visitor.visit_set_type(self)


@dataclass
class MapType(TypeExpr):
    """Map type: (Map K V)"""
    
    key_type: Optional[TypeExpr] = None
    value_type: Optional[TypeExpr] = None
    
    def accept(self, visitor: "ASTVisitor") -> Any:
        return visitor.visit_map_type(self)


@dataclass
class TupleType(TypeExpr):
    """Tuple type: (Tuple T1 T2 ...)"""
    
    element_types: List[TypeExpr] = field(default_factory=list)
    
    def accept(self, visitor: "ASTVisitor") -> Any:
        return visitor.visit_tuple_type(self)


@dataclass
class FunctionType(TypeExpr):
    """Function type: (-> T1 T2 ... Tresult)"""
    
    param_types: List[TypeExpr] = field(default_factory=list)
    return_type: Optional[TypeExpr] = None
    
    def accept(self, visitor: "ASTVisitor") -> Any:
        return visitor.visit_function_type(self)


# ═══════════════════════════════════════════════════════════════════════════
# DATAFLOW SPECIFICATIONS
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class LatticeSpec(ASTNode):
    """Specification of a lattice structure.
    
    (lattice
      (domain <name>)
      (bottom <expr>)
      (top <expr>)
      (join <fn>)
      (widen <fn>))
    """
    
    domain: str = ""
    bottom: Optional[Expr] = None
    top: Optional[Expr] = None
    join: Optional[Expr] = None
    widen: Optional[Expr] = None
    
    def accept(self, visitor: "ASTVisitor") -> Any:
        return visitor.visit_lattice_spec(self)


@dataclass
class DirectionSpec(ASTNode):
    """Dataflow direction: forward or backward."""
    
    direction: str = "forward"
    
    def accept(self, visitor: "ASTVisitor") -> Any:
        return visitor.visit_direction_spec(self)


@dataclass
class TransferSpec(ASTNode):
    """Transfer function specification for dataflow.
    
    (transfer
      (on (assign ?x ?e)
        (update state ?x (eval ?e state)))
      (on (call ?f ?args)
        ...))
    """
    
    cases: List[Tuple[CodePattern, Expr]] = field(default_factory=list)
    
    def accept(self, visitor: "ASTVisitor") -> Any:
        return visitor.visit_transfer_spec(self)


@dataclass
class DataflowSpec(ASTNode):
    """Complete dataflow analysis specification.
    
    (dataflow <name>
      (domain <domain-ref>)
      (direction forward|backward)
      (lattice ...)
      (transfer ...)
      (initial <expr>)
      (interprocedural <policy>))
    """
    
    name: str = ""
    domain: str = ""
    direction: str = "forward"
    lattice: Optional[LatticeSpec] = None
    transfer: Optional[TransferSpec] = None
    initial: Optional[Expr] = None
    interprocedural: str = "context-insensitive"  # or "call-string", "functional"
    
    def accept(self, visitor: "ASTVisitor") -> Any:
        return visitor.visit_dataflow_spec(self)
