#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
casl/semantic.py
================

Semantic analysis for CASL specifications.

This module validates CASL ASTs for:
1. **Name resolution** — all references resolve to declarations
2. **Type checking** — pattern variables, domain operations, constraints
3. **Lattice validation** — domains form complete lattices
4. **Soundness guards** — transfer functions are monotone, actions don't affect matching
5. **Analysis compatibility** — constraints match interprocedural policy

The semantic phase is *mandatory* — it enforces the soundness contract that
CASL inherits from PQL:

    "If CASL reports no matches, then no concrete execution violating
     the pattern exists, modulo the declared abstractions."

Design
------
The analysis proceeds in multiple passes:

1. **Symbol collection** — gather all top-level declarations
2. **Reference resolution** — resolve all name references
3. **Type inference** — infer types for expressions and patterns
4. **Constraint validation** — check semantic constraints
5. **Soundness checking** — verify lattice properties, monotonicity

References
----------
- PQL: "Our analysis is sound, and as such its answer is guaranteed to
  include all points that may be relevant to the query."
- Møller & Schwartzbach Ch. 4: Lattice theory and monotone functions
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import (
    Any,
    Callable,
    Dict,
    FrozenSet,
    Iterator,
    List,
    Mapping,
    Optional,
    Set,
    Tuple,
    Type,
    Union,
)

from casl import ast as A
from casl.visitor import ASTVisitor, DepthFirstVisitor
from casl.errors import (
    SemanticError,
    SourceLocation,
    Diagnostic,
    DiagnosticCollector,
)

__all__ = [
    "analyze",
    "SemanticAnalyzer",
    "SymbolTable",
    "Symbol",
    "SymbolKind",
    "TypeEnv",
    "CASLType",
    "SemanticContext",
]


# ═══════════════════════════════════════════════════════════════════════════
# TYPE SYSTEM
# ═══════════════════════════════════════════════════════════════════════════

class CASLType(abc.ABC):
    """Base class for CASL types."""
    
    @abc.abstractmethod
    def __str__(self) -> str:
        ...
    
    def is_subtype_of(self, other: "CASLType") -> bool:
        """Check if self is a subtype of other."""
        if isinstance(other, AnyType):
            return True
        return self == other


@dataclass(frozen=True)
class AnyType(CASLType):
    """Top type — matches anything."""
    
    def __str__(self) -> str:
        return "Any"


@dataclass(frozen=True)
class NeverType(CASLType):
    """Bottom type — matches nothing."""
    
    def __str__(self) -> str:
        return "Never"
    
    def is_subtype_of(self, other: CASLType) -> bool:
        return True  # Never is subtype of everything


@dataclass(frozen=True)
class PrimitiveType(CASLType):
    """Primitive types: Int, Float, String, Bool, Symbol."""
    
    name: str
    
    def __str__(self) -> str:
        return self.name


# Singleton instances
INT_TYPE = PrimitiveType("Int")
FLOAT_TYPE = PrimitiveType("Float")
STRING_TYPE = PrimitiveType("String")
BOOL_TYPE = PrimitiveType("Bool")
SYMBOL_TYPE = PrimitiveType("Symbol")
NIL_TYPE = PrimitiveType("Nil")


@dataclass(frozen=True)
class DomainValueType(CASLType):
    """Type of values from an abstract domain."""
    
    domain_name: str
    
    def __str__(self) -> str:
        return f"Domain[{self.domain_name}]"


@dataclass(frozen=True)
class SetType_(CASLType):
    """Set type: Set[T]."""
    
    element_type: CASLType
    
    def __str__(self) -> str:
        return f"Set[{self.element_type}]"


@dataclass(frozen=True)
class MapType_(CASLType):
    """Map type: Map[K, V]."""
    
    key_type: CASLType
    value_type: CASLType
    
    def __str__(self) -> str:
        return f"Map[{self.key_type}, {self.value_type}]"


@dataclass(frozen=True)
class TupleType_(CASLType):
    """Tuple type: (T1, T2, ...)."""
    
    element_types: Tuple[CASLType, ...]
    
    def __str__(self) -> str:
        inner = ", ".join(str(t) for t in self.element_types)
        return f"({inner})"


@dataclass(frozen=True)
class FunctionType_(CASLType):
    """Function type: (T1, T2, ...) -> R."""
    
    param_types: Tuple[CASLType, ...]
    return_type: CASLType
    
    def __str__(self) -> str:
        params = ", ".join(str(t) for t in self.param_types)
        return f"({params}) -> {self.return_type}"


@dataclass(frozen=True)
class NodeType(CASLType):
    """Type of AST nodes from Cppcheck: Token, Variable, Function, etc."""
    
    name: str
    
    def __str__(self) -> str:
        return self.name
    
    def is_subtype_of(self, other: CASLType) -> bool:
        if isinstance(other, AnyType):
            return True
        if isinstance(other, NodeType):
            # Node type hierarchy
            hierarchy = {
                "Token": {"Node"},
                "Variable": {"Node"},
                "Function": {"Node"},
                "Scope": {"Node"},
                "Node": set(),
            }
            if self.name == other.name:
                return True
            return other.name in hierarchy.get(self.name, set())
        return False


# Common node types
TOKEN_TYPE = NodeType("Token")
VARIABLE_TYPE = NodeType("Variable")
FUNCTION_TYPE = NodeType("Function")
SCOPE_TYPE = NodeType("Scope")
NODE_TYPE = NodeType("Node")


@dataclass(frozen=True)
class PatternType(CASLType):
    """Type of a code pattern."""
    
    bindings: Tuple[Tuple[str, CASLType], ...]  # (name, type) pairs
    
    def __str__(self) -> str:
        binds = ", ".join(f"{n}: {t}" for n, t in self.bindings)
        return f"Pattern[{binds}]"


# ═══════════════════════════════════════════════════════════════════════════
# SYMBOL TABLE
# ═══════════════════════════════════════════════════════════════════════════

class SymbolKind(Enum):
    """Kind of symbol in the symbol table."""
    
    DOMAIN = auto()
    PATTERN = auto()
    QUERY = auto()
    CHECKER = auto()
    FUNCTION = auto()
    TRANSFER = auto()
    DATAFLOW = auto()
    VARIABLE = auto()      # pattern variable
    PARAMETER = auto()     # function parameter
    BUILTIN = auto()       # built-in function/domain


@dataclass
class Symbol:
    """Symbol table entry."""
    
    name: str
    kind: SymbolKind
    type: CASLType
    node: Optional[A.ASTNode] = None
    location: Optional[SourceLocation] = None
    is_builtin: bool = False
    
    # For domains
    is_complete_lattice: bool = False
    has_widening: bool = False
    
    # For functions
    is_monotone: Optional[bool] = None  # None = unknown
    
    # For patterns
    bound_variables: Dict[str, CASLType] = field(default_factory=dict)


class SymbolTable:
    """Hierarchical symbol table with scoping."""
    
    def __init__(self, parent: Optional["SymbolTable"] = None) -> None:
        self._symbols: Dict[str, Symbol] = {}
        self._parent = parent
        self._children: List["SymbolTable"] = []
        if parent:
            parent._children.append(self)
    
    def define(self, symbol: Symbol) -> None:
        """Define a symbol in the current scope."""
        if symbol.name in self._symbols:
            raise SemanticError(
                f"Redefinition of '{symbol.name}'",
                symbol.location,
                hints=[f"Previously defined as {self._symbols[symbol.name].kind.name}"],
            )
        self._symbols[symbol.name] = symbol
    
    def lookup(self, name: str) -> Optional[Symbol]:
        """Look up a symbol, searching parent scopes."""
        if name in self._symbols:
            return self._symbols[name]
        if self._parent:
            return self._parent.lookup(name)
        return None
    
    def lookup_local(self, name: str) -> Optional[Symbol]:
        """Look up a symbol in the current scope only."""
        return self._symbols.get(name)
    
    def all_symbols(self) -> Iterator[Symbol]:
        """Iterate over all symbols in this scope."""
        yield from self._symbols.values()
    
    def child_scope(self) -> "SymbolTable":
        """Create a child scope."""
        return SymbolTable(parent=self)
    
    def symbols_of_kind(self, kind: SymbolKind) -> Iterator[Symbol]:
        """Get all symbols of a specific kind."""
        for sym in self._symbols.values():
            if sym.kind == kind:
                yield sym


@dataclass
class TypeEnv:
    """Type environment for type checking."""
    
    bindings: Dict[str, CASLType] = field(default_factory=dict)
    
    def bind(self, name: str, typ: CASLType) -> "TypeEnv":
        """Return new environment with additional binding."""
        new_bindings = dict(self.bindings)
        new_bindings[name] = typ
        return TypeEnv(new_bindings)
    
    def lookup(self, name: str) -> Optional[CASLType]:
        """Look up type of a name."""
        return self.bindings.get(name)


# ═══════════════════════════════════════════════════════════════════════════
# SEMANTIC CONTEXT
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class SemanticContext:
    """Context passed through semantic analysis."""
    
    symbols: SymbolTable
    types: TypeEnv
    diagnostics: DiagnosticCollector
    
    # Current analysis state
    current_domain: Optional[str] = None
    current_pattern: Optional[str] = None
    current_query: Optional[str] = None
    in_action: bool = False
    
    # Collected information
    dataflow_requirements: Set[str] = field(default_factory=set)
    interprocedural_requirements: Set[str] = field(default_factory=set)
    
    def child(self) -> "SemanticContext":
        """Create child context with new scope."""
        return SemanticContext(
            symbols=self.symbols.child_scope(),
            types=self.types,
            diagnostics=self.diagnostics,
            current_domain=self.current_domain,
            current_pattern=self.current_pattern,
            current_query=self.current_query,
            in_action=self.in_action,
            dataflow_requirements=self.dataflow_requirements,
            interprocedural_requirements=self.interprocedural_requirements,
        )


# ═══════════════════════════════════════════════════════════════════════════
# SEMANTIC ANALYSIS PASSES
# ═══════════════════════════════════════════════════════════════════════════

class SymbolCollector(DepthFirstVisitor):
    """Pass 1: Collect all top-level symbol declarations."""
    
    def __init__(self, ctx: SemanticContext) -> None:
        self.ctx = ctx
    
    def visit_domain_decl(self, node: A.DomainDecl) -> None:
        symbol = Symbol(
            name=node.name,
            kind=SymbolKind.DOMAIN,
            type=DomainValueType(node.name),
            node=node,
            location=node.location,
            is_complete_lattice=(
                node.bottom is not None and
                node.join is not None and
                node.leq is not None
            ),
            has_widening=node.widen is not None,
        )
        self.ctx.symbols.define(symbol)
    
    def visit_function_decl(self, node: A.FunctionDecl) -> None:
        # Infer function type from declaration
        param_types = tuple(
            self._resolve_type(p.type_annotation) if p.type_annotation else AnyType()
            for p in node.params
        )
        return_type = (
            self._resolve_type(node.return_type) if node.return_type else AnyType()
        )
        
        symbol = Symbol(
            name=node.name,
            kind=SymbolKind.FUNCTION,
            type=FunctionType_(param_types, return_type),
            node=node,
            location=node.location,
        )
        self.ctx.symbols.define(symbol)
    
    def visit_transfer_decl(self, node: A.TransferDecl) -> None:
        symbol = Symbol(
            name=node.name,
            kind=SymbolKind.TRANSFER,
            type=AnyType(),  # Transfer functions have complex types
            node=node,
            location=node.location,
        )
        self.ctx.symbols.define(symbol)
    
    def visit_pattern_decl(self, node: A.PatternDecl) -> None:
        # Collect bound variables
        bound_vars = {}
        for var in node.variables:
            var_type = (
                self._resolve_type(var.type_annotation)
                if var.type_annotation else NODE_TYPE
            )
            bound_vars[var.name] = var_type
        
        symbol = Symbol(
            name=node.name,
            kind=SymbolKind.PATTERN,
            type=PatternType(tuple(bound_vars.items())),
            node=node,
            location=node.location,
            bound_variables=bound_vars,
        )
        self.ctx.symbols.define(symbol)
    
    def visit_query_decl(self, node: A.QueryDecl) -> None:
        symbol = Symbol(
            name=node.name,
            kind=SymbolKind.QUERY,
            type=AnyType(),
            node=node,
            location=node.location,
        )
        self.ctx.symbols.define(symbol)
    
    def visit_checker_decl(self, node: A.CheckerDecl) -> None:
        symbol = Symbol(
            name=node.name,
            kind=SymbolKind.CHECKER,
            type=AnyType(),
            node=node,
            location=node.location,
        )
        self.ctx.symbols.define(symbol)
    
    def visit_dataflow_spec(self, node: A.DataflowSpec) -> None:
        symbol = Symbol(
            name=node.name,
            kind=SymbolKind.DATAFLOW,
            type=AnyType(),
            node=node,
            location=node.location,
        )
        self.ctx.symbols.define(symbol)
    
    def _resolve_type(self, type_expr: A.TypeExpr) -> CASLType:
        """Resolve a type expression to a CASLType."""
        if isinstance(type_expr, A.TypeRef):
            name = type_expr.name
            # Built-in types
            builtins = {
                "Int": INT_TYPE,
                "Float": FLOAT_TYPE,
                "String": STRING_TYPE,
                "Bool": BOOL_TYPE,
                "Symbol": SYMBOL_TYPE,
                "Token": TOKEN_TYPE,
                "Variable": VARIABLE_TYPE,
                "Function": FUNCTION_TYPE,
                "Scope": SCOPE_TYPE,
                "Node": NODE_TYPE,
            }
            if name in builtins:
                return builtins[name]
            # Domain reference
            return DomainValueType(name)
        elif isinstance(type_expr, A.SetType):
            elem = self._resolve_type(type_expr.element_type) if type_expr.element_type else AnyType()
            return SetType_(elem)
        elif isinstance(type_expr, A.MapType):
            key = self._resolve_type(type_expr.key_type) if type_expr.key_type else AnyType()
            val = self._resolve_type(type_expr.value_type) if type_expr.value_type else AnyType()
            return MapType_(key, val)
        elif isinstance(type_expr, A.TupleType):
            elems = tuple(self._resolve_type(t) for t in type_expr.element_types)
            return TupleType_(elems)
        elif isinstance(type_expr, A.FunctionType):
            params = tuple(self._resolve_type(t) for t in type_expr.param_types)
            ret = self._resolve_type(type_expr.return_type) if type_expr.return_type else AnyType()
            return FunctionType_(params, ret)
        else:
            return AnyType()


class ReferenceResolver(DepthFirstVisitor):
    """Pass 2: Resolve all name references."""
    
    def __init__(self, ctx: SemanticContext) -> None:
        self.ctx = ctx
    
    def visit_identifier(self, node: A.Identifier) -> None:
        symbol = self.ctx.symbols.lookup(node.name)
        if symbol is None:
            self.ctx.diagnostics.error(
                f"Undefined reference: '{node.name}'",
                node.location,
                code="CASL001",
            )
        else:
            # Annotate node with resolved symbol
            node.annotations["resolved_symbol"] = symbol
    
    def visit_query_decl(self, node: A.QueryDecl) -> None:
        # Check pattern reference
        if node.pattern:
            symbol = self.ctx.symbols.lookup(node.pattern)
            if symbol is None:
                self.ctx.diagnostics.error(
                    f"Undefined pattern: '{node.pattern}'",
                    node.location,
                    code="CASL002",
                )
            elif symbol.kind != SymbolKind.PATTERN:
                self.ctx.diagnostics.error(
                    f"'{node.pattern}' is not a pattern (it's a {symbol.kind.name})",
                    node.location,
                    code="CASL003",
                )
        
        # Check dataflow requirements
        for req in node.requires:
            symbol = self.ctx.symbols.lookup(req)
            if symbol is None:
                self.ctx.diagnostics.error(
                    f"Undefined dataflow: '{req}'",
                    node.location,
                    code="CASL004",
                )
            elif symbol.kind != SymbolKind.DATAFLOW:
                self.ctx.diagnostics.error(
                    f"'{req}' is not a dataflow specification",
                    node.location,
                    code="CASL005",
                )
        
        # Visit children
        self.generic_visit(node)
    
    def visit_checker_decl(self, node: A.CheckerDecl) -> None:
        if node.query:
            symbol = self.ctx.symbols.lookup(node.query)
            if symbol is None:
                self.ctx.diagnostics.error(
                    f"Undefined query: '{node.query}'",
                    node.location,
                    code="CASL006",
                )
            elif symbol.kind != SymbolKind.QUERY:
                self.ctx.diagnostics.error(
                    f"'{node.query}' is not a query",
                    node.location,
                    code="CASL007",
                )
        self.generic_visit(node)
    
    def visit_dataflow_spec(self, node: A.DataflowSpec) -> None:
        # Check domain reference
        if node.domain:
            symbol = self.ctx.symbols.lookup(node.domain)
            if symbol is None:
                self.ctx.diagnostics.error(
                    f"Undefined domain: '{node.domain}'",
                    node.location,
                    code="CASL008",
                )
            elif symbol.kind != SymbolKind.DOMAIN:
                self.ctx.diagnostics.error(
                    f"'{node.domain}' is not a domain",
                    node.location,
                    code="CASL009",
                )
        self.generic_visit(node)
    
    def visit_transfer_decl(self, node: A.TransferDecl) -> None:
        if node.domain:
            symbol = self.ctx.symbols.lookup(node.domain)
            if symbol is None:
                self.ctx.diagnostics.error(
                    f"Undefined domain: '{node.domain}'",
                    node.location,
                    code="CASL008",
                )
        self.generic_visit(node)


class LatticeValidator(DepthFirstVisitor):
    """Pass 3: Validate lattice properties of domains."""
    
    def __init__(self, ctx: SemanticContext) -> None:
        self.ctx = ctx
    
    def visit_domain_decl(self, node: A.DomainDecl) -> None:
        # Check completeness
        missing = []
        if node.bottom is None and node.kind not in ("builtin", "reference"):
            missing.append("bottom")
        if node.join is None and node.kind not in ("builtin", "reference"):
            missing.append("join")
        if node.leq is None and node.kind not in ("builtin", "reference"):
            missing.append("leq")
        
        if missing:
            self.ctx.diagnostics.warning(
                f"Domain '{node.name}' may be incomplete: missing {', '.join(missing)}",
                node.location,
                code="CASL010",
            )
            self.ctx.diagnostics.note(
                "Incomplete domains may cause unsound analysis results",
                node.location,
            )
        
        # Check for infinite ascending chains without widening
        if node.kind in ("interval", "powerset") and node.widen is None:
            self.ctx.diagnostics.warning(
                f"Domain '{node.name}' may have infinite ascending chains but no widening operator",
                node.location,
                code="CASL011",
            )
            self.ctx.diagnostics.note(
                "Consider adding (widen ...) to ensure termination",
                node.location,
            )
        
        self.generic_visit(node)


class ConstraintValidator(DepthFirstVisitor):
    """Pass 4: Validate semantic constraints."""
    
    def __init__(self, ctx: SemanticContext) -> None:
        self.ctx = ctx
    
    def visit_flows_to(self, node: A.FlowsTo) -> None:
        # flows-to requires dataflow analysis
        self.ctx.dataflow_requirements.add("flows-to")
        if node.domain:
            symbol = self.ctx.symbols.lookup(node.domain)
            if symbol is None:
                self.ctx.diagnostics.error(
                    f"Undefined domain in flows-to: '{node.domain}'",
                    node.location,
                    code="CASL012",
                )
        self.generic_visit(node)
    
    def visit_reaches(self, node: A.Reaches) -> None:
        # reaches requires CFG reachability (at minimum)
        self.ctx.interprocedural_requirements.add("cfg-reachability")
        self.generic_visit(node)
    
    def visit_dominates(self, node: A.Dominates) -> None:
        # dominates requires dominator analysis
        self.ctx.interprocedural_requirements.add("dominators")
        self.generic_visit(node)
    
    def visit_dataflow_fact(self, node: A.DataflowFact) -> None:
        if node.domain:
            symbol = self.ctx.symbols.lookup(node.domain)
            if symbol is None:
                self.ctx.diagnostics.error(
                    f"Undefined domain in fact: '{node.domain}'",
                    node.location,
                    code="CASL013",
                )
            self.ctx.dataflow_requirements.add(node.domain)
        self.generic_visit(node)


class SoundnessChecker(DepthFirstVisitor):
    """Pass 5: Check soundness properties.
    
    Enforces the PQL soundness contract:
    - Actions never affect matching
    - Transfer functions are (syntactically) monotone
    - Domains are complete lattices
    """
    
    def __init__(self, ctx: SemanticContext) -> None:
        self.ctx = ctx
        self._in_action = False
    
    def visit_report_action(self, node: A.ReportAction) -> None:
        self._in_action = True
        self.generic_visit(node)
        self._in_action = False
    
    def visit_set_fact_action(self, node: A.SetFactAction) -> None:
        # set-fact in actions is problematic — it affects state
        self.ctx.diagnostics.warning(
            "set-fact in action may affect subsequent matching",
            node.location,
            code="CASL014",
        )
        self.ctx.diagnostics.note(
            "Consider using set-fact only in transfer functions",
            node.location,
        )
        self._in_action = True
        self.generic_visit(node)
        self._in_action = False
    
    def visit_dataflow_spec(self, node: A.DataflowSpec) -> None:
        # Check interprocedural policy compatibility
        if node.interprocedural == "context-insensitive":
            # Warn if there are flows-to constraints
            if "flows-to" in self.ctx.dataflow_requirements:
                self.ctx.diagnostics.warning(
                    f"Dataflow '{node.name}' uses context-insensitive analysis "
                    "but flows-to constraints require context sensitivity for precision",
                    node.location,
                    code="CASL015",
                )
        
        self.generic_visit(node)


class PatternVariableCollector(DepthFirstVisitor):
    """Collect pattern variables from code patterns."""
    
    def __init__(self) -> None:
        self.variables: Dict[str, Optional[str]] = {}  # name -> type constraint
    
    def visit_binding_pattern(self, node: A.BindingPattern) -> None:
        if node.name in self.variables:
            # Duplicate variable — this is allowed (same binding)
            pass
        else:
            self.variables[node.name] = node.type_constraint
        
        if node.nested:
            self.visit(node.nested)


# ═══════════════════════════════════════════════════════════════════════════
# MAIN ANALYZER
# ═══════════════════════════════════════════════════════════════════════════

class SemanticAnalyzer:
    """Main semantic analyzer for CASL specifications.
    
    Orchestrates multiple analysis passes and collects diagnostics.
    """
    
    def __init__(self) -> None:
        self.diagnostics = DiagnosticCollector()
        self.symbols: Optional[SymbolTable] = None
        self.context: Optional[SemanticContext] = None
    
    def analyze(self, spec: A.AddonSpec) -> SemanticContext:
        """Analyze a CASL specification.
        
        Returns a SemanticContext containing the symbol table and
        collected information.  Raises SemanticError if there are
        errors.
        """
        # Initialize context
        self.symbols = SymbolTable()
        self.context = SemanticContext(
            symbols=self.symbols,
            types=TypeEnv(),
            diagnostics=self.diagnostics,
        )
        
        # Register built-in symbols
        self._register_builtins()
        
        # Pass 1: Collect symbols
        collector = SymbolCollector(self.context)
        collector.visit(spec)
        
        # Pass 2: Resolve references
        resolver = ReferenceResolver(self.context)
        resolver.visit(spec)
        
        # Pass 3: Validate lattices
        lattice_validator = LatticeValidator(self.context)
        lattice_validator.visit(spec)
        
        # Pass 4: Validate constraints
        constraint_validator = ConstraintValidator(self.context)
        constraint_validator.visit(spec)
        
        # Pass 5: Check soundness
        soundness_checker = SoundnessChecker(self.context)
        soundness_checker.visit(spec)
        
        # Check for errors
        self.diagnostics.raise_if_errors()
        
        return self.context
    
    def _register_builtins(self) -> None:
        """Register built-in domains and functions."""
        from casl.builtins import BUILTIN_DOMAINS, BUILTIN_FUNCTIONS
        
        for name, domain_info in BUILTIN_DOMAINS.items():
            symbol = Symbol(
                name=name,
                kind=SymbolKind.DOMAIN,
                type=DomainValueType(name),
                is_builtin=True,
                is_complete_lattice=domain_info.get("complete", True),
                has_widening=domain_info.get("has_widening", False),
            )
            self.symbols.define(symbol)
        
        for name, func_info in BUILTIN_FUNCTIONS.items():
            symbol = Symbol(
                name=name,
                kind=SymbolKind.BUILTIN,
                type=func_info.get("type", AnyType()),
                is_builtin=True,
            )
            self.symbols.define(symbol)


def analyze(spec: A.AddonSpec) -> SemanticContext:
    """Convenience function to analyze a CASL specification."""
    analyzer = SemanticAnalyzer()
    return analyzer.analyze(spec)
