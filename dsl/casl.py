"""
casl.py — Cppcheck Addon Specification Language (CASL)
======================================================

A declarative, compositional DSL for specifying Cppcheck addons that
compile to self-contained Python code using the cppcheckdata-shims library.

Usage::

    from casl import compile_casl, load_casl_file

    # Compile CASL source to Python addon code
    python_code = compile_casl('''
        addon NullCheck {
            version = "1.0.0"
            author = "Example Author"
        }

        pattern ptr_deref = //token[@str="*" and #is_unary_op];

        rule NullPointerDereference {
            severity = error
            message = "Potential null pointer dereference at {location}"
            when ptr_deref and not has_null_check(target)
            report location, target
        }
    ''')

    # Or load from file
    python_code = load_casl_file("mycheck.casl")

    # Execute the generated addon
    exec(python_code)

Depends on:
    - parsimonious (PEG parser)
    - cppcheckdata (Cppcheck dump model)
    - cppcheckdata-shims (analysis library)
"""

from __future__ import annotations

import enum
import hashlib
import keyword
import logging
import re
import textwrap
from dataclasses import dataclass, field
from pathlib import Path
from typing import (
    Any,
    Callable,
    Dict,
    FrozenSet,
    Iterator,
    List,
    Mapping,
    Optional,
    Sequence,
    Set,
    Tuple,
    Union,
)

from parsimonious.grammar import Grammar
from parsimonious.nodes import Node, NodeVisitor
from parsimonious.exceptions import ParseError, VisitationError

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════
#  PART 1 — CASL GRAMMAR (Parsimonious PEG)
# ═══════════════════════════════════════════════════════════════════

CASL_GRAMMAR = Grammar(r'''
    # ─────────────────────────────────────────────────────────────
    # Top-Level Structure
    # ─────────────────────────────────────────────────────────────
    
    module              = _ preamble? declaration* _
    preamble            = addon_block
    
    addon_block         = "addon" _ identifier _ "{" _ addon_field* _ "}" _
    addon_field         = identifier _ "=" _ literal _ ";"? _
    
    # ─────────────────────────────────────────────────────────────
    # Declarations
    # ─────────────────────────────────────────────────────────────
    
    declaration         = import_decl
                        / type_decl
                        / const_decl
                        / pattern_decl
                        / query_decl
                        / predicate_decl
                        / function_decl
                        / rule_decl
                        / aspect_decl
                        / phase_decl
                        / message_decl
                        / config_decl
    
    # ─────────────────────────────────────────────────────────────
    # Import System
    # ─────────────────────────────────────────────────────────────
    
    import_decl         = simple_import / from_import / include_import
    simple_import       = "import" _ module_path _ ("as" _ identifier)? _ ";" _
    from_import         = "from" _ module_path _ "import" _ import_names _ ";" _
    include_import      = "include" _ string_literal _ ";" _
    module_path         = identifier ("." identifier)*
    import_names        = "*" / (identifier ("," _ identifier)*)
    
    # ─────────────────────────────────────────────────────────────
    # Type Declarations
    # ─────────────────────────────────────────────────────────────
    
    type_decl           = "type" _ identifier _ type_params? _ "=" _ type_expr _ ";" _
    type_params         = "<" _ identifier ("," _ identifier)* _ ">"
    
    type_expr           = union_type / intersection_type / base_type
    union_type          = base_type _ ("|" _ base_type)+
    intersection_type   = base_type _ ("&" _ base_type)+
    base_type           = nullable_type / list_type / set_type / map_type
                        / tuple_type / function_type / record_type
                        / parameterized_type / primitive_type / type_ref
    
    nullable_type       = base_type _ "?"
    list_type           = "[" _ type_expr _ "]"
    set_type            = "{" _ type_expr _ "}"
    map_type            = "{" _ type_expr _ ":" _ type_expr _ "}"
    tuple_type          = "(" _ type_expr ("," _ type_expr)* _ ")"
    function_type       = "(" _ type_list? _ ")" _ "->" _ type_expr
    record_type         = "record" _ "{" _ record_field* _ "}"
    record_field        = identifier _ ":" _ type_expr _ ","? _
    
    parameterized_type  = type_ref _ "<" _ type_expr ("," _ type_expr)* _ ">"
    type_ref            = identifier
    type_list           = type_expr ("," _ type_expr)*
    
    primitive_type      = "Token" / "Scope" / "Function" / "Variable" / "Value"
                        / "Configuration" / "Node" / "Location"
                        / "Int" / "Float" / "String" / "Bool" / "Unit" / "Any" / "Never"
    
    # ─────────────────────────────────────────────────────────────
    # Constant Declarations
    # ─────────────────────────────────────────────────────────────
    
    const_decl          = "const" _ identifier _ (":" _ type_expr)? _ "=" _ expr _ ";" _
    
    # ─────────────────────────────────────────────────────────────
    # Pattern Declarations (CCQL-style)
    # ─────────────────────────────────────────────────────────────
    
    pattern_decl        = "pattern" _ identifier _ pattern_params? _ "=" _ pattern_body _ ";" _
    pattern_params      = "(" _ pattern_param ("," _ pattern_param)* _ ")"
    pattern_param       = identifier _ (":" _ type_expr)?
    pattern_body        = ccql_pattern / sexp_pattern / composed_pattern
    
    ccql_pattern        = "/" "/" ~r"[^;]+"
    sexp_pattern        = "'" _ sexp
    composed_pattern    = pattern_combinator
    
    pattern_combinator  = pattern_ref _ (pattern_op _ pattern_ref)*
    pattern_ref         = identifier / "(" _ pattern_combinator _ ")"
    pattern_op          = ">>>" / "|||" / "&&&" / "---"
    
    # ─────────────────────────────────────────────────────────────
    # Query Declarations (Named CCQL)
    # ─────────────────────────────────────────────────────────────
    
    query_decl          = "query" _ identifier _ query_params? _ (":" _ type_expr)? _ "=" _ query_body _ ";" _
    query_params        = "(" _ query_param ("," _ query_param)* _ ")"
    query_param         = identifier _ (":" _ type_expr)? _ ("=" _ expr)?
    query_body          = ccql_expr / expr
    ccql_expr           = ~r'`[^`]+`'
    
    # ─────────────────────────────────────────────────────────────
    # Predicate Declarations
    # ─────────────────────────────────────────────────────────────
    
    predicate_decl      = "predicate" _ identifier _ "(" _ predicate_params? _ ")" _ (":" _ "Bool")? _ "=" _ expr _ ";" _
    predicate_params    = identifier _ (":" _ type_expr)? _ ("," _ identifier _ (":" _ type_expr)?)*
    
    # ─────────────────────────────────────────────────────────────
    # Function Declarations
    # ─────────────────────────────────────────────────────────────
    
    function_decl       = "fn" _ identifier _ "(" _ fn_params? _ ")" _ (":" _ type_expr)? _ fn_body _
    fn_params           = fn_param ("," _ fn_param)*
    fn_param            = identifier _ (":" _ type_expr)? _ ("=" _ expr)?
    fn_body             = "=" _ expr _ ";" / block
    
    # ─────────────────────────────────────────────────────────────
    # Rule Declarations
    # ─────────────────────────────────────────────────────────────
    
    rule_decl           = "rule" _ identifier _ rule_modifiers? _ "{" _ rule_body _ "}" _
    rule_modifiers      = "[" _ rule_modifier ("," _ rule_modifier)* _ "]"
    rule_modifier       = "enabled" / "disabled" / "experimental" / "deprecated"
                        / "cwe" _ "(" _ integer _ ")"
                        / "cert" _ "(" _ string_literal _ ")"
                        / "misra" _ "(" _ string_literal _ ")"
    
    rule_body           = rule_clause*
    rule_clause         = severity_clause / message_clause / when_clause / where_clause
                        / match_clause / requires_clause / report_clause / fix_clause
                        / metadata_clause
    
    severity_clause     = "severity" _ "=" _ severity_level _ ";"? _
    severity_level      = "error" / "warning" / "style" / "performance" / "portability" / "information"
    
    message_clause      = "message" _ "=" _ (template_string / string_literal) _ ";"? _
    template_string     = "t" string_literal
    
    when_clause         = "when" _ expr _ ";"? _
    where_clause        = "where" _ let_binding+ _
    let_binding         = "let" _ identifier _ (":" _ type_expr)? _ "=" _ expr _ ";"? _
    
    match_clause        = "match" _ pattern_ref _ ("as" _ identifier)? _ ";"? _
    requires_clause     = "requires" _ expr _ ";"? _
    report_clause       = "report" _ report_item ("," _ report_item)* _ ";"? _
    report_item         = identifier / "@" identifier / expr
    fix_clause          = "fix" _ string_literal _ ";"? _
    metadata_clause     = "meta" _ identifier _ "=" _ literal _ ";"? _
    
    # ─────────────────────────────────────────────────────────────
    # Aspect Declarations
    # ─────────────────────────────────────────────────────────────
    
    aspect_decl         = "aspect" _ aspect_kind _ identifier? _ "{" _ aspect_body _ "}" _
    aspect_kind         = "analysis" / "traversal" / "reporting" / "configuration"
                        / "lifecycle" / "dataflow" / "symbolic" / "abstract"
    aspect_body         = aspect_item*
    aspect_item         = aspect_entry / aspect_handler / aspect_hook
    aspect_entry        = identifier _ "=" _ expr _ ";"? _
    aspect_handler      = "on" _ event_name _ handler_params? _ block _
    handler_params      = "(" _ fn_params? _ ")"
    aspect_hook         = "before" _ identifier _ block _ / "after" _ identifier _ block _
    event_name          = "enter" / "exit" / "visit" / "match" / "error" / "complete"
                        / "token" / "scope" / "function" / "variable"
    
    # ─────────────────────────────────────────────────────────────
    # Phase Declarations (Analysis Pipeline)
    # ─────────────────────────────────────────────────────────────
    
    phase_decl          = "phase" _ identifier _ phase_order? _ "{" _ phase_body _ "}" _
    phase_order         = "[" _ ("before" / "after") _ identifier _ "]"
    phase_body          = phase_item*
    phase_item          = "input" _ ":" _ type_expr _ ";"? _
                        / "output" _ ":" _ type_expr _ ";"? _
                        / "requires" _ ":" _ identifier ("," _ identifier)* _ ";"? _
                        / "provides" _ ":" _ identifier ("," _ identifier)* _ ";"? _
                        / "run" _ block _
    
    # ─────────────────────────────────────────────────────────────
    # Message Templates
    # ─────────────────────────────────────────────────────────────
    
    message_decl        = "message" _ identifier _ "(" _ message_params? _ ")" _ "=" _ template_string _ ";" _
    message_params      = identifier ("," _ identifier)*
    
    # ─────────────────────────────────────────────────────────────
    # Configuration Block
    # ─────────────────────────────────────────────────────────────
    
    config_decl         = "config" _ "{" _ config_item* _ "}" _
    config_item         = "option" _ identifier _ ":" _ type_expr _ ("=" _ expr)? _ config_meta? _ ";"? _
    config_meta         = "[" _ config_attr ("," _ config_attr)* _ "]"
    config_attr         = identifier _ "=" _ literal
    
    # ─────────────────────────────────────────────────────────────
    # Expressions
    # ─────────────────────────────────────────────────────────────
    
    expr                = pipe_expr
    pipe_expr           = or_expr (_ "|>" _ or_expr)*
    or_expr             = and_expr (_ ("||" / "or") _ and_expr)*
    and_expr            = not_expr (_ ("&&" / "and") _ not_expr)*
    not_expr            = ("!" / "not") _ not_expr / comparison_expr
    
    comparison_expr     = range_expr (_ comparison_op _ range_expr)?
    comparison_op       = "==" / "!=" / "<=" / ">=" / "<" / ">" / "in" / "not" _ "in" / "is" / "is" _ "not"
                        / "matches" / "contains" / "startswith" / "endswith"
    
    range_expr          = additive_expr (_ ".." _ additive_expr)?
    additive_expr       = multiplicative_expr (_ ("+" / "-" / "++") _ multiplicative_expr)*
    multiplicative_expr = unary_expr (_ ("*" / "/" / "%") _ unary_expr)*
    unary_expr          = ("-" / "+" / "~") _ unary_expr / postfix_expr
    
    postfix_expr        = primary_expr postfix_op*
    postfix_op          = call_op / index_op / member_op / null_coalesce_op / force_op
    call_op             = "(" _ arg_list? _ ")"
    index_op            = "[" _ expr _ "]"
    member_op           = "." identifier / "?." identifier / "::" identifier
    null_coalesce_op    = "??" _ primary_expr
    force_op            = "!"
    
    arg_list            = arg ("," _ arg)*
    arg                 = (identifier _ "=")? _ expr
    
    primary_expr        = if_expr / match_expr / for_expr / let_expr / lambda_expr
                        / try_expr / block / grouped_expr / collection_expr
                        / query_expr / pattern_match_expr
                        / literal / builtin_ref / identifier
    
    # ─────────────────────────────────────────────────────────────
    # Control Expressions
    # ─────────────────────────────────────────────────────────────
    
    if_expr             = "if" _ expr _ "then" _ expr _ ("else" _ expr)?
    
    match_expr          = "match" _ expr _ "{" _ match_arm+ _ "}"
    match_arm           = match_pattern _ "=>" _ expr _ ","? _
    match_pattern       = "_" / literal / identifier / constructor_pattern / guard_pattern
    constructor_pattern = identifier _ "(" _ match_pattern ("," _ match_pattern)* _ ")"
    guard_pattern       = match_pattern _ "if" _ expr
    
    for_expr            = "for" _ identifier _ "in" _ expr _ ("where" _ expr)? _ ("yield" _ expr / block)
    
    let_expr            = "let" _ identifier _ (":" _ type_expr)? _ "=" _ expr _ "in" _ expr
    
    lambda_expr         = "\\" _ lambda_params _ "->" _ expr
                        / "|" _ lambda_params? _ "|" _ expr
    lambda_params       = identifier ("," _ identifier)*
    
    try_expr            = "try" _ expr _ catch_clause* _ finally_clause?
    catch_clause        = "catch" _ identifier _ (":" _ type_expr)? _ "=>" _ expr
    finally_clause      = "finally" _ block
    
    block               = "{" _ block_stmt* _ expr? _ "}"
    block_stmt          = "let" _ identifier _ (":" _ type_expr)? _ "=" _ expr _ ";" _
                        / "var" _ identifier _ (":" _ type_expr)? _ ("=" _ expr)? _ ";" _
                        / expr _ ";" _
    
    grouped_expr        = "(" _ expr _ ")"
    
    # ─────────────────────────────────────────────────────────────
    # Collection Expressions
    # ─────────────────────────────────────────────────────────────
    
    collection_expr     = list_expr / set_expr / map_expr / comprehension
    list_expr           = "[" _ (expr ("," _ expr)*)? _ "]"
    set_expr            = "#{" _ (expr ("," _ expr)*)? _ "}"
    map_expr            = "#{" _ (map_entry ("," _ map_entry)*)? _ "}"
    map_entry           = expr _ ":" _ expr
    
    comprehension       = list_comp / set_comp / map_comp
    list_comp           = "[" _ expr _ "|" _ comp_clauses _ "]"
    set_comp            = "#{" _ expr _ "|" _ comp_clauses _ "}"
    map_comp            = "#{" _ expr _ ":" _ expr _ "|" _ comp_clauses _ "}"
    comp_clauses        = comp_clause ("," _ comp_clause)*
    comp_clause         = identifier _ "<-" _ expr / expr
    
    # ─────────────────────────────────────────────────────────────
    # Query/Pattern Expressions
    # ─────────────────────────────────────────────────────────────
    
    query_expr          = "query" _ ccql_expr
    pattern_match_expr  = "matches" _ "(" _ expr _ "," _ pattern_ref _ ")"
    
    # ─────────────────────────────────────────────────────────────
    # Built-in References
    # ─────────────────────────────────────────────────────────────
    
    builtin_ref         = "@" identifier / "$" identifier / "#" identifier
    
    # ─────────────────────────────────────────────────────────────
    # S-Expressions (for CCPL patterns)
    # ─────────────────────────────────────────────────────────────
    
    sexp                = sexp_atom / sexp_list
    sexp_list           = "(" _ sexp* _ ")"
    sexp_atom           = sexp_string / sexp_symbol / number
    sexp_string         = string_literal
    sexp_symbol         = ~r"[a-zA-Z_@#$%&*+\-/<=>?!][a-zA-Z0-9_@#$%&*+\-/<=>?!.]*"
    
    # ─────────────────────────────────────────────────────────────
    # Literals
    # ─────────────────────────────────────────────────────────────
    
    literal             = string_literal / number / boolean / null_literal / regex_literal
    string_literal      = ~r'"(?:[^"\\]|\\.)*"' / ~r"'(?:[^'\\]|\\.)*'"
    number              = float_literal / integer
    float_literal       = ~r"-?\d+\.\d+([eE][+-]?\d+)?"
    integer             = ~r"-?\d+"
    boolean             = "true" / "false"
    null_literal        = "null" / "none" / "nil"
    regex_literal       = ~r"r/(?:[^/\\]|\\.)+/[imsx]*"
    
    # ─────────────────────────────────────────────────────────────
    # Identifiers & Whitespace
    # ─────────────────────────────────────────────────────────────
    
    identifier          = ~r"[a-zA-Z_][a-zA-Z0-9_]*"
    _                   = ~r"(\s|//[^\n]*|/\*.*?\*/)* "x
''')


# ═══════════════════════════════════════════════════════════════════
#  PART 2 — AST NODE DEFINITIONS
# ═══════════════════════════════════════════════════════════════════

class ASTNode:
    """Base class for all CASL AST nodes."""
    
    def __init__(self, loc: Optional[Tuple[int, int]] = None):
        self.loc = loc  # (line, column)
    
    def accept(self, visitor: "ASTVisitor") -> Any:
        method_name = f"visit_{self.__class__.__name__}"
        method = getattr(visitor, method_name, visitor.generic_visit)
        return method(self)


# ─────────────────────────────────────────────────────────────
# Module & Metadata
# ─────────────────────────────────────────────────────────────

@dataclass
class Module(ASTNode):
    """Root AST node for a CASL module."""
    name: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    imports: List["ImportDecl"] = field(default_factory=list)
    declarations: List[ASTNode] = field(default_factory=list)
    source_path: Optional[str] = None


@dataclass
class AddonMetadata(ASTNode):
    """Addon block metadata."""
    name: str = ""
    fields: Dict[str, Any] = field(default_factory=dict)


# ─────────────────────────────────────────────────────────────
# Import Declarations
# ─────────────────────────────────────────────────────────────

class ImportKind(enum.Enum):
    SIMPLE = "simple"       # import foo.bar
    FROM = "from"           # from foo.bar import x, y
    INCLUDE = "include"     # include "path/to/file.casl"
    STAR = "star"           # from foo import *


@dataclass
class ImportDecl(ASTNode):
    """Import declaration."""
    kind: ImportKind = ImportKind.SIMPLE
    module_path: str = ""
    names: List[str] = field(default_factory=list)
    alias: Optional[str] = None


# ─────────────────────────────────────────────────────────────
# Type System
# ─────────────────────────────────────────────────────────────

class TypeKind(enum.Enum):
    PRIMITIVE = "primitive"
    REFERENCE = "reference"
    PARAMETERIZED = "parameterized"
    LIST = "list"
    SET = "set"
    MAP = "map"
    TUPLE = "tuple"
    FUNCTION = "function"
    RECORD = "record"
    UNION = "union"
    INTERSECTION = "intersection"
    NULLABLE = "nullable"


@dataclass
class TypeExpr(ASTNode):
    """Type expression."""
    kind: TypeKind = TypeKind.PRIMITIVE
    name: str = ""                              # For PRIMITIVE, REFERENCE
    params: List["TypeExpr"] = field(default_factory=list)  # For PARAMETERIZED, LIST, etc.
    fields: Dict[str, "TypeExpr"] = field(default_factory=dict)  # For RECORD
    
    def __str__(self) -> str:
        if self.kind == TypeKind.PRIMITIVE:
            return self.name
        if self.kind == TypeKind.REFERENCE:
            return self.name
        if self.kind == TypeKind.LIST:
            return f"[{self.params[0]}]"
        if self.kind == TypeKind.SET:
            return "{" + str(self.params[0]) + "}"
        if self.kind == TypeKind.MAP:
            return "{" + f"{self.params[0]}: {self.params[1]}" + "}"
        if self.kind == TypeKind.NULLABLE:
            return f"{self.params[0]}?"
        if self.kind == TypeKind.UNION:
            return " | ".join(str(p) for p in self.params)
        if self.kind == TypeKind.TUPLE:
            return "(" + ", ".join(str(p) for p in self.params) + ")"
        if self.kind == TypeKind.FUNCTION:
            args = ", ".join(str(p) for p in self.params[:-1])
            ret = self.params[-1] if self.params else "Unit"
            return f"({args}) -> {ret}"
        if self.kind == TypeKind.PARAMETERIZED:
            args = ", ".join(str(p) for p in self.params)
            return f"{self.name}<{args}>"
        return self.name


@dataclass
class TypeDecl(ASTNode):
    """Type declaration."""
    name: str = ""
    type_params: List[str] = field(default_factory=list)
    definition: TypeExpr = field(default_factory=lambda: TypeExpr())


# ─────────────────────────────────────────────────────────────
# Constants & Variables
# ─────────────────────────────────────────────────────────────

@dataclass
class ConstDecl(ASTNode):
    """Constant declaration."""
    name: str = ""
    type_annotation: Optional[TypeExpr] = None
    value: "Expr" = None


# ─────────────────────────────────────────────────────────────
# Patterns
# ─────────────────────────────────────────────────────────────

class PatternKind(enum.Enum):
    CCQL = "ccql"           # //token[@str="x"]
    SEXP = "sexp"           # S-expression (CCPL)
    COMPOSED = "composed"   # Pattern combinators
    REFERENCE = "reference" # Reference to another pattern


@dataclass
class PatternDecl(ASTNode):
    """Pattern declaration."""
    name: str = ""
    params: List[Tuple[str, Optional[TypeExpr]]] = field(default_factory=list)
    kind: PatternKind = PatternKind.CCQL
    body: Any = None  # String for CCQL, list for SEXP, PatternCombinator for COMPOSED


@dataclass
class PatternCombinator(ASTNode):
    """Pattern combinator expression."""
    op: str = ""        # ">>>", "|||", "&&&", "---"
    operands: List[Any] = field(default_factory=list)


# ─────────────────────────────────────────────────────────────
# Queries
# ─────────────────────────────────────────────────────────────

@dataclass
class QueryDecl(ASTNode):
    """Query declaration."""
    name: str = ""
    params: List[Tuple[str, Optional[TypeExpr], Optional["Expr"]]] = field(default_factory=list)
    return_type: Optional[TypeExpr] = None
    body: Any = None  # CCQL string or Expr


# ─────────────────────────────────────────────────────────────
# Predicates
# ─────────────────────────────────────────────────────────────

@dataclass
class PredicateDecl(ASTNode):
    """Predicate declaration."""
    name: str = ""
    params: List[Tuple[str, Optional[TypeExpr]]] = field(default_factory=list)
    body: "Expr" = None


# ─────────────────────────────────────────────────────────────
# Functions
# ─────────────────────────────────────────────────────────────

@dataclass
class FunctionDecl(ASTNode):
    """Function declaration."""
    name: str = ""
    params: List[Tuple[str, Optional[TypeExpr], Optional["Expr"]]] = field(default_factory=list)
    return_type: Optional[TypeExpr] = None
    body: "Expr" = None
    is_pure: bool = True


# ─────────────────────────────────────────────────────────────
# Rules
# ─────────────────────────────────────────────────────────────

class Severity(enum.Enum):
    ERROR = "error"
    WARNING = "warning"
    STYLE = "style"
    PERFORMANCE = "performance"
    PORTABILITY = "portability"
    INFORMATION = "information"


@dataclass
class RuleModifier(ASTNode):
    """Rule modifier."""
    kind: str = ""      # "enabled", "disabled", "cwe", "cert", "misra"
    value: Any = None   # For cwe(123), cert("STR01-C"), etc.


@dataclass
class RuleDecl(ASTNode):
    """Rule declaration."""
    name: str = ""
    modifiers: List[RuleModifier] = field(default_factory=list)
    severity: Severity = Severity.WARNING
    message: Optional["Expr"] = None
    when_clause: Optional["Expr"] = None
    where_bindings: List[Tuple[str, Optional[TypeExpr], "Expr"]] = field(default_factory=list)
    match_pattern: Optional[str] = None
    match_binding: Optional[str] = None
    requires_clause: Optional["Expr"] = None
    report_items: List["Expr"] = field(default_factory=list)
    fix_suggestion: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


# ─────────────────────────────────────────────────────────────
# Aspects
# ─────────────────────────────────────────────────────────────

class AspectKind(enum.Enum):
    ANALYSIS = "analysis"
    TRAVERSAL = "traversal"
    REPORTING = "reporting"
    CONFIGURATION = "configuration"
    LIFECYCLE = "lifecycle"
    DATAFLOW = "dataflow"
    SYMBOLIC = "symbolic"
    ABSTRACT = "abstract"


@dataclass
class AspectHandler(ASTNode):
    """Event handler in an aspect."""
    event: str = ""     # "enter", "exit", "visit", "match", etc.
    params: List[Tuple[str, Optional[TypeExpr]]] = field(default_factory=list)
    body: "Expr" = None


@dataclass
class AspectHook(ASTNode):
    """Before/after hook."""
    kind: str = ""      # "before", "after"
    target: str = ""    # Function name
    body: "Expr" = None


@dataclass
class AspectDecl(ASTNode):
    """Aspect declaration."""
    kind: AspectKind = AspectKind.ANALYSIS
    name: Optional[str] = None
    entries: Dict[str, "Expr"] = field(default_factory=dict)
    handlers: List[AspectHandler] = field(default_factory=list)
    hooks: List[AspectHook] = field(default_factory=list)


# ─────────────────────────────────────────────────────────────
# Phases
# ─────────────────────────────────────────────────────────────

@dataclass
class PhaseDecl(ASTNode):
    """Phase declaration."""
    name: str = ""
    order: Optional[Tuple[str, str]] = None  # ("before"|"after", phase_name)
    input_type: Optional[TypeExpr] = None
    output_type: Optional[TypeExpr] = None
    requires: List[str] = field(default_factory=list)
    provides: List[str] = field(default_factory=list)
    run_body: Optional["Expr"] = None


# ─────────────────────────────────────────────────────────────
# Messages
# ─────────────────────────────────────────────────────────────

@dataclass
class MessageDecl(ASTNode):
    """Message template declaration."""
    name: str = ""
    params: List[str] = field(default_factory=list)
    template: str = ""


# ─────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────

@dataclass
class ConfigOption(ASTNode):
    """Configuration option."""
    name: str = ""
    type_annotation: TypeExpr = field(default_factory=lambda: TypeExpr())
    default_value: Optional["Expr"] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ConfigDecl(ASTNode):
    """Configuration block."""
    options: List[ConfigOption] = field(default_factory=list)


# ─────────────────────────────────────────────────────────────
# Expressions
# ─────────────────────────────────────────────────────────────

class ExprKind(enum.Enum):
    # Literals
    INTEGER = "integer"
    FLOAT = "float"
    STRING = "string"
    BOOLEAN = "boolean"
    NULL = "null"
    REGEX = "regex"
    
    # Identifiers & References
    IDENTIFIER = "identifier"
    BUILTIN = "builtin"         # @foo, $foo, #foo
    
    # Operators
    BINARY_OP = "binary_op"
    UNARY_OP = "unary_op"
    
    # Access
    MEMBER_ACCESS = "member_access"
    INDEX_ACCESS = "index_access"
    CALL = "call"
    
    # Control
    IF = "if"
    MATCH = "match"
    FOR = "for"
    LET = "let"
    LAMBDA = "lambda"
    TRY = "try"
    BLOCK = "block"
    
    # Collections
    LIST = "list"
    SET = "set"
    MAP = "map"
    COMPREHENSION = "comprehension"
    
    # Special
    PIPE = "pipe"
    RANGE = "range"
    QUERY = "query"
    PATTERN_MATCH = "pattern_match"
    TEMPLATE = "template"


@dataclass
class Expr(ASTNode):
    """Expression node."""
    kind: ExprKind = ExprKind.NULL
    value: Any = None
    children: List["Expr"] = field(default_factory=list)
    type_annotation: Optional[TypeExpr] = None
    
    # For specific expression kinds
    op: Optional[str] = None            # For BINARY_OP, UNARY_OP
    name: Optional[str] = None          # For IDENTIFIER, MEMBER_ACCESS, CALL
    args: List["Expr"] = field(default_factory=list)  # For CALL
    kwargs: Dict[str, "Expr"] = field(default_factory=dict)
    arms: List[Tuple[Any, "Expr"]] = field(default_factory=list)  # For MATCH
    bindings: List[Tuple[str, Optional[TypeExpr], "Expr"]] = field(default_factory=list)
    
    @staticmethod
    def integer(v: int) -> "Expr":
        return Expr(kind=ExprKind.INTEGER, value=v)
    
    @staticmethod
    def float_(v: float) -> "Expr":
        return Expr(kind=ExprKind.FLOAT, value=v)
    
    @staticmethod
    def string(v: str) -> "Expr":
        return Expr(kind=ExprKind.STRING, value=v)
    
    @staticmethod
    def boolean(v: bool) -> "Expr":
        return Expr(kind=ExprKind.BOOLEAN, value=v)
    
    @staticmethod
    def null() -> "Expr":
        return Expr(kind=ExprKind.NULL, value=None)
    
    @staticmethod
    def identifier(name: str) -> "Expr":
        return Expr(kind=ExprKind.IDENTIFIER, name=name)
    
    @staticmethod
    def builtin(prefix: str, name: str) -> "Expr":
        return Expr(kind=ExprKind.BUILTIN, value=prefix, name=name)
    
    @staticmethod
    def binary(op: str, left: "Expr", right: "Expr") -> "Expr":
        return Expr(kind=ExprKind.BINARY_OP, op=op, children=[left, right])
    
    @staticmethod
    def unary(op: str, operand: "Expr") -> "Expr":
        return Expr(kind=ExprKind.UNARY_OP, op=op, children=[operand])
    
    @staticmethod
    def call(callee: "Expr", args: List["Expr"],
             kwargs: Optional[Dict[str, "Expr"]] = None) -> "Expr":
        return Expr(kind=ExprKind.CALL, children=[callee],
                    args=args, kwargs=kwargs or {})
    
    @staticmethod
    def member(obj: "Expr", member: str, optional: bool = False) -> "Expr":
        return Expr(kind=ExprKind.MEMBER_ACCESS, name=member,
                    children=[obj], value=optional)
    
    @staticmethod
    def index(obj: "Expr", idx: "Expr") -> "Expr":
        return Expr(kind=ExprKind.INDEX_ACCESS, children=[obj, idx])
    
    @staticmethod
    def if_(cond: "Expr", then_: "Expr",
            else_: Optional["Expr"] = None) -> "Expr":
        children = [cond, then_]
        if else_:
            children.append(else_)
        return Expr(kind=ExprKind.IF, children=children)
    
    @staticmethod
    def match_(scrutinee: "Expr",
               arms: List[Tuple[Any, "Expr"]]) -> "Expr":
        return Expr(kind=ExprKind.MATCH, children=[scrutinee], arms=arms)
    
    @staticmethod
    def for_(var: str, iterable: "Expr", body: "Expr",
             filter_: Optional["Expr"] = None) -> "Expr":
        children = [iterable, body]
        if filter_:
            children.append(filter_)
        return Expr(kind=ExprKind.FOR, name=var, children=children)
    
    @staticmethod
    def let_(bindings: List[Tuple[str, Optional[TypeExpr], "Expr"]],
             body: "Expr") -> "Expr":
        return Expr(kind=ExprKind.LET, bindings=bindings, children=[body])
    
    @staticmethod
    def lambda_(params: List[str], body: "Expr") -> "Expr":
        return Expr(kind=ExprKind.LAMBDA, value=params, children=[body])
    
    @staticmethod
    def block_(stmts: List["Expr"], result: Optional["Expr"] = None) -> "Expr":
        children = stmts
        if result:
            children.append(result)
        return Expr(kind=ExprKind.BLOCK, children=children)
    
    @staticmethod
    def list_(elements: List["Expr"]) -> "Expr":
        return Expr(kind=ExprKind.LIST, children=elements)
    
    @staticmethod
    def set_(elements: List["Expr"]) -> "Expr":
        return Expr(kind=ExprKind.SET, children=elements)
    
    @staticmethod
    def map_(entries: List[Tuple["Expr", "Expr"]]) -> "Expr":
        return Expr(kind=ExprKind.MAP, value=entries)
    
    @staticmethod
    def pipe(left: "Expr", right: "Expr") -> "Expr":
        return Expr(kind=ExprKind.PIPE, children=[left, right])
    
    @staticmethod
    def query(ccql: str) -> "Expr":
        return Expr(kind=ExprKind.QUERY, value=ccql)
    
    @staticmethod
    def template(template_str: str) -> "Expr":
        return Expr(kind=ExprKind.TEMPLATE, value=template_str)


# ═══════════════════════════════════════════════════════════════════
#  PART 3 — AST VISITOR (Parse Tree → AST)
# ═══════════════════════════════════════════════════════════════════

class CASLASTBuilder(NodeVisitor):
    """Transforms Parsimonious parse tree into CASL AST."""
    
    def __init__(self):
        self._current_module = Module()
        self._errors: List[str] = []
    
    def generic_visit(self, node, visited_children):
        """Default: return children or node text."""
        if visited_children:
            # Flatten single-element lists
            if len(visited_children) == 1:
                return visited_children[0]
            return visited_children
        return node.text.strip()
    
    # ─────────────────────────────────────────────────────────────
    # Module
    # ─────────────────────────────────────────────────────────────
    
    def visit_module(self, node, visited_children):
        _, preamble, declarations, _ = visited_children
        module = Module()
        
        if preamble and not isinstance(preamble, list):
            preamble = [preamble]
        for p in (preamble or []):
            if isinstance(p, AddonMetadata):
                module.name = p.name
                module.metadata = p.fields
        
        for decl in self._flatten(declarations):
            if isinstance(decl, ImportDecl):
                module.imports.append(decl)
            elif isinstance(decl, ASTNode):
                module.declarations.append(decl)
        
        return module
    
    def visit_preamble(self, node, visited_children):
        return visited_children[0] if visited_children else None
    
    def visit_addon_block(self, node, visited_children):
        _, _, name, _, _, _, fields, _, _, _ = visited_children
        metadata = AddonMetadata(name=name)
        for f in self._flatten(fields):
            if isinstance(f, tuple) and len(f) == 2:
                metadata.fields[f[0]] = f[1]
        return metadata
    
    def visit_addon_field(self, node, visited_children):
        name, _, _, _, value, *_ = visited_children
        return (name, value)
    
    # ─────────────────────────────────────────────────────────────
    # Declarations
    # ─────────────────────────────────────────────────────────────
    
    def visit_declaration(self, node, visited_children):
        return visited_children[0]
    
    # ─────────────────────────────────────────────────────────────
    # Imports
    # ─────────────────────────────────────────────────────────────
    
    def visit_import_decl(self, node, visited_children):
        return visited_children[0]
    
    def visit_simple_import(self, node, visited_children):
        _, _, path, _, alias_part, _, _, _ = visited_children
        alias = None
        if alias_part and not isinstance(alias_part, list):
            alias = alias_part
        elif isinstance(alias_part, list) and len(alias_part) >= 3:
            alias = alias_part[2]
        return ImportDecl(kind=ImportKind.SIMPLE, module_path=path, alias=alias)
    
    def visit_from_import(self, node, visited_children):
        _, _, path, _, _, _, names, _, _, _ = visited_children
        if names == "*":
            return ImportDecl(kind=ImportKind.STAR, module_path=path)
        name_list = self._flatten([names])
        return ImportDecl(kind=ImportKind.FROM, module_path=path, names=name_list)
    
    def visit_include_import(self, node, visited_children):
        _, _, path, _, _, _ = visited_children
        return ImportDecl(kind=ImportKind.INCLUDE, module_path=self._unescape_string(path))
    
    def visit_module_path(self, node, visited_children):
        return node.text.strip()
    
    def visit_import_names(self, node, visited_children):
        if node.text.strip() == "*":
            return "*"
        return self._flatten(visited_children)
    
    # ─────────────────────────────────────────────────────────────
    # Types
    # ─────────────────────────────────────────────────────────────
    
    def visit_type_decl(self, node, visited_children):
        _, _, name, _, params, _, _, _, type_expr, _, _, _ = visited_children
        param_list = self._flatten([params]) if params else []
        return TypeDecl(name=name, type_params=param_list, definition=type_expr)
    
    def visit_type_params(self, node, visited_children):
        _, _, first, rest, _, _ = visited_children
        params = [first]
        for item in self._flatten([rest]):
            if isinstance(item, str) and item not in (',', '<', '>'):
                params.append(item)
        return params
    
    def visit_type_expr(self, node, visited_children):
        return visited_children[0]
    
    def visit_union_type(self, node, visited_children):
        first, _, rest = visited_children
        types = [first]
        for item in self._flatten([rest]):
            if isinstance(item, TypeExpr):
                types.append(item)
        return TypeExpr(kind=TypeKind.UNION, params=types)
    
    def visit_intersection_type(self, node, visited_children):
        first, _, rest = visited_children
        types = [first]
        for item in self._flatten([rest]):
            if isinstance(item, TypeExpr):
                types.append(item)
        return TypeExpr(kind=TypeKind.INTERSECTION, params=types)
    
    def visit_base_type(self, node, visited_children):
        return visited_children[0]
    
    def visit_nullable_type(self, node, visited_children):
        base, _, _ = visited_children
        return TypeExpr(kind=TypeKind.NULLABLE, params=[base])
    
    def visit_list_type(self, node, visited_children):
        _, _, elem_type, _, _ = visited_children
        return TypeExpr(kind=TypeKind.LIST, params=[elem_type])
    
    def visit_set_type(self, node, visited_children):
        _, _, elem_type, _, _ = visited_children
        return TypeExpr(kind=TypeKind.SET, params=[elem_type])
    
    def visit_map_type(self, node, visited_children):
        _, _, key_type, _, _, _, value_type, _, _ = visited_children
        return TypeExpr(kind=TypeKind.MAP, params=[key_type, value_type])
    
    def visit_tuple_type(self, node, visited_children):
        _, _, first, rest, _, _ = visited_children
        types = [first]
        for item in self._flatten([rest]):
            if isinstance(item, TypeExpr):
                types.append(item)
        return TypeExpr(kind=TypeKind.TUPLE, params=types)
    
    def visit_function_type(self, node, visited_children):
        _, _, params, _, _, _, _, _, return_type = visited_children
        param_types = self._flatten([params]) if params else []
        return TypeExpr(kind=TypeKind.FUNCTION, params=param_types + [return_type])
    
    def visit_record_type(self, node, visited_children):
        _, _, _, _, fields, _, _ = visited_children
        field_dict = {}
        for f in self._flatten([fields]):
            if isinstance(f, tuple) and len(f) == 2:
                field_dict[f[0]] = f[1]
        return TypeExpr(kind=TypeKind.RECORD, fields=field_dict)
    
    def visit_record_field(self, node, visited_children):
        name, _, _, _, type_expr, *_ = visited_children
        return (name, type_expr)
    
    def visit_parameterized_type(self, node, visited_children):
        name, _, _, _, first, rest, _, _ = visited_children
        params = [first]
        for item in self._flatten([rest]):
            if isinstance(item, TypeExpr):
                params.append(item)
        return TypeExpr(kind=TypeKind.PARAMETERIZED, name=name, params=params)
    
    def visit_type_ref(self, node, visited_children):
        name = visited_children[0] if visited_children else node.text.strip()
        return TypeExpr(kind=TypeKind.REFERENCE, name=name)
    
    def visit_primitive_type(self, node, visited_children):
        return TypeExpr(kind=TypeKind.PRIMITIVE, name=node.text.strip())
    
    # ─────────────────────────────────────────────────────────────
    # Constants
    # ─────────────────────────────────────────────────────────────
    
    def visit_const_decl(self, node, visited_children):
        _, _, name, _, type_ann, _, _, _, value, _, _, _ = visited_children
        t = self._extract_type(type_ann)
        return ConstDecl(name=name, type_annotation=t, value=value)
    
    # ─────────────────────────────────────────────────────────────
    # Patterns
    # ─────────────────────────────────────────────────────────────
    
    def visit_pattern_decl(self, node, visited_children):
        _, _, name, _, params, _, _, _, body, _, _, _ = visited_children
        param_list = self._extract_params(params)
        kind, body_value = self._extract_pattern_body(body)
        return PatternDecl(name=name, params=param_list, kind=kind, body=body_value)
    
    def visit_pattern_params(self, node, visited_children):
        _, _, first, rest, _, _ = visited_children
        params = [first]
        for item in self._flatten([rest]):
            if isinstance(item, tuple):
                params.append(item)
        return params
    
    def visit_pattern_param(self, node, visited_children):
        name, _, type_part = visited_children
        t = self._extract_type(type_part)
        return (name, t)
    
    def visit_pattern_body(self, node, visited_children):
        return visited_children[0]
    
    def visit_ccql_pattern(self, node, visited_children):
        # Extract the CCQL query string
        text = node.text.strip()
        if text.startswith("//"):
            return ("ccql", text)
        return ("ccql", "//" + text)
    
    def visit_sexp_pattern(self, node, visited_children):
        _, _, sexp = visited_children
        return ("sexp", sexp)
    
    def visit_composed_pattern(self, node, visited_children):
        return ("composed", visited_children[0])
    
    def visit_pattern_combinator(self, node, visited_children):
        first, _, rest = visited_children
        if not rest or (isinstance(rest, list) and len(rest) == 0):
            return first
        operands = [first]
        ops = []
        for item in self._flatten([rest]):
            if isinstance(item, str) and item in (">>>", "|||", "&&&", "---"):
                ops.append(item)
            elif item and item not in (">>>", "|||", "&&&", "---"):
                operands.append(item)
        if ops:
            return PatternCombinator(op=ops[0], operands=operands)
        return first
    
    def visit_pattern_ref(self, node, visited_children):
        result = visited_children[0] if visited_children else node.text.strip()
        if isinstance(result, str):
            return result
        return result
    
    # ─────────────────────────────────────────────────────────────
    # Queries
    # ─────────────────────────────────────────────────────────────
    
    def visit_query_decl(self, node, visited_children):
        _, _, name, _, params, _, ret_type, _, _, _, body, _, _, _ = visited_children
        param_list = self._extract_query_params(params)
        t = self._extract_type(ret_type)
        return QueryDecl(name=name, params=param_list, return_type=t, body=body)
    
    def visit_query_params(self, node, visited_children):
        _, _, first, rest, _, _ = visited_children
        params = [first]
        for item in self._flatten([rest]):
            if isinstance(item, tuple):
                params.append(item)
        return params
    
    def visit_query_param(self, node, visited_children):
        name, _, type_part, _, default_part = visited_children
        t = self._extract_type(type_part)
        default = self._extract_default(default_part)
        return (name, t, default)
    
    def visit_query_body(self, node, visited_children):
        return visited_children[0]
    
    def visit_ccql_expr(self, node, visited_children):
        text = node.text.strip()
        if text.startswith("`") and text.endswith("`"):
            return Expr.query(text[1:-1])
        return Expr.query(text)
    
    # ─────────────────────────────────────────────────────────────
    # Predicates
    # ─────────────────────────────────────────────────────────────
    
    def visit_predicate_decl(self, node, visited_children):
        _, _, name, _, _, _, params, _, _, _, _, _, _, _, body, _, _, _ = visited_children
        param_list = self._extract_predicate_params(params)
        return PredicateDecl(name=name, params=param_list, body=body)
    
    def visit_predicate_params(self, node, visited_children):
        return self._flatten(visited_children)
    
    # ─────────────────────────────────────────────────────────────
    # Functions
    # ─────────────────────────────────────────────────────────────
    
    def visit_function_decl(self, node, visited_children):
        _, _, name, _, _, _, params, _, _, _, ret_type, _, body, _ = visited_children
        param_list = self._extract_fn_params(params)
        t = self._extract_type(ret_type)
        body_expr = self._extract_fn_body(body)
        return FunctionDecl(name=name, params=param_list, return_type=t, body=body_expr)
    
    def visit_fn_params(self, node, visited_children):
        first, rest = visited_children
        params = [first]
        for item in self._flatten([rest]):
            if isinstance(item, tuple):
                params.append(item)
        return params
    
    def visit_fn_param(self, node, visited_children):
        name, _, type_part, _, default_part = visited_children
        t = self._extract_type(type_part)
        default = self._extract_default(default_part)
        return (name, t, default)
    
    def visit_fn_body(self, node, visited_children):
        return visited_children[0]
    
    # ─────────────────────────────────────────────────────────────
    # Rules
    # ─────────────────────────────────────────────────────────────
    
    def visit_rule_decl(self, node, visited_children):
        _, _, name, _, modifiers, _, _, _, body, _, _, _ = visited_children
        rule = RuleDecl(name=name)
        rule.modifiers = self._flatten([modifiers]) if modifiers else []
        
        for clause in self._flatten([body]):
            if isinstance(clause, tuple):
                kind, value = clause
                if kind == "severity":
                    rule.severity = value
                elif kind == "message":
                    rule.message = value
                elif kind == "when":
                    rule.when_clause = value
                elif kind == "where":
                    rule.where_bindings.extend(value)
                elif kind == "match":
                    rule.match_pattern = value[0]
                    rule.match_binding = value[1] if len(value) > 1 else None
                elif kind == "requires":
                    rule.requires_clause = value
                elif kind == "report":
                    rule.report_items.extend(value)
                elif kind == "fix":
                    rule.fix_suggestion = value
                elif kind == "meta":
                    rule.metadata[value[0]] = value[1]
        
        return rule
    
    def visit_rule_modifiers(self, node, visited_children):
        _, _, first, rest, _, _ = visited_children
        mods = [first]
        for item