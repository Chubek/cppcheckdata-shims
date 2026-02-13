# casl/ast_nodes.py
"""
CASL Abstract Syntax Tree node definitions.

Every node carries source location information for error reporting.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional, Union


# ── Source Location ──────────────────────────────────────────────

@dataclass(frozen=True)
class Loc:
    """Source location for diagnostics."""
    file: str = "<unknown>"
    line: int = 0
    col: int = 0

    def __str__(self):
        return f"{self.file}:{self.line}:{self.col}"


# ── Enums ────────────────────────────────────────────────────────

class Severity(Enum):
    ERROR = "error"
    WARNING = "warning"
    STYLE = "style"
    PORTABILITY = "portability"
    PERFORMANCE = "performance"
    INFORMATION = "information"


class Confidence(Enum):
    CERTAIN = "certain"
    PROBABLE = "probable"
    POSSIBLE = "possible"


class OnEvent(Enum):
    TOKEN = "token"
    SCOPE = "scope"
    FUNCTION = "function"
    VARIABLE = "variable"
    CFG = "cfg"
    INIT = "init"
    FINISH = "finish"


class AssignOp(Enum):
    EQ = "="
    PLUS_EQ = "+="
    MINUS_EQ = "-="
    STAR_EQ = "*="
    SLASH_EQ = "/="
    PIPE_EQ = "|="
    AMP_EQ = "&="


class UnaryOp(Enum):
    NOT = "!"
    NEG = "-"
    BITNOT = "~"


class BinOp(Enum):
    OR = "||"
    AND = "&&"
    BIT_OR = "|"
    BIT_XOR = "^"
    BIT_AND = "&"
    EQ = "=="
    NE = "!="
    LT = "<"
    GT = ">"
    LE = "<="
    GE = ">="
    ADD = "+"
    SUB = "-"
    MUL = "*"
    DIV = "/"
    MOD = "%"


# ── Type Expressions ────────────────────────────────────────────

@dataclass
class TypeName:
    name: str
    loc: Loc = field(default_factory=Loc)


@dataclass
class TypeGeneric:
    name: str
    args: list[TypeExpr]
    loc: Loc = field(default_factory=Loc)


TypeExpr = Union[TypeName, TypeGeneric]


# ── Expressions ──────────────────────────────────────────────────

@dataclass
class Identifier:
    name: str
    loc: Loc = field(default_factory=Loc)


@dataclass
class IntLiteral:
    value: int
    loc: Loc = field(default_factory=Loc)


@dataclass
class FloatLiteral:
    value: float
    loc: Loc = field(default_factory=Loc)


@dataclass
class StringLiteral:
    value: str
    loc: Loc = field(default_factory=Loc)


@dataclass
class BoolLiteral:
    value: bool
    loc: Loc = field(default_factory=Loc)


@dataclass
class NullLiteral:
    loc: Loc = field(default_factory=Loc)


@dataclass
class ListLiteral:
    elements: list[Expr]
    loc: Loc = field(default_factory=Loc)


@dataclass
class MapLiteral:
    entries: list[tuple[Expr, Expr]]
    loc: Loc = field(default_factory=Loc)


@dataclass
class SetLiteral:
    elements: list[Expr]
    loc: Loc = field(default_factory=Loc)


@dataclass
class UnaryExpr:
    op: UnaryOp
    operand: Expr
    loc: Loc = field(default_factory=Loc)


@dataclass
class BinaryExpr:
    op: BinOp
    left: Expr
    right: Expr
    loc: Loc = field(default_factory=Loc)


@dataclass
class TernaryExpr:
    condition: Expr
    then_expr: Expr
    else_expr: Expr
    loc: Loc = field(default_factory=Loc)


@dataclass
class CallExpr:
    callee: Expr
    args: list[Expr]
    loc: Loc = field(default_factory=Loc)


@dataclass
class IndexExpr:
    obj: Expr
    index: Expr
    loc: Loc = field(default_factory=Loc)


@dataclass
class MemberExpr:
    obj: Expr
    member: str
    loc: Loc = field(default_factory=Loc)


@dataclass
class MethodCallExpr:
    obj: Expr
    method: str
    args: list[Expr]
    loc: Loc = field(default_factory=Loc)


@dataclass
class LambdaExpr:
    params: list[Param]
    return_type: Optional[TypeExpr]
    body: list[Stmt]
    loc: Loc = field(default_factory=Loc)


@dataclass
class MatchExpr:
    subject: Expr
    arms: list[MatchArm]
    loc: Loc = field(default_factory=Loc)


@dataclass
class MatchArm:
    pattern: Expr  # simplified: literal or identifier or wildcard
    body: Expr
    loc: Loc = field(default_factory=Loc)


Expr = Union[
    Identifier, IntLiteral, FloatLiteral, StringLiteral, BoolLiteral,
    NullLiteral, ListLiteral, MapLiteral, SetLiteral, UnaryExpr,
    BinaryExpr, TernaryExpr, CallExpr, IndexExpr, MemberExpr,
    MethodCallExpr, LambdaExpr, MatchExpr,
]


# ── Pattern Expressions (PQL-inspired) ──────────────────────────

@dataclass
class TokenPattern:
    constraints: dict[str, Expr]
    loc: Loc = field(default_factory=Loc)


@dataclass
class ScopePattern:
    name: str
    loc: Loc = field(default_factory=Loc)


@dataclass
class CallPattern:
    callee: Expr
    args: list[Expr]
    loc: Loc = field(default_factory=Loc)


@dataclass
class AssignPattern:
    lhs: PatternExpr
    rhs: PatternExpr
    loc: Loc = field(default_factory=Loc)


@dataclass
class DerefPattern:
    operand: PatternExpr
    loc: Loc = field(default_factory=Loc)


@dataclass
class BinopPattern:
    op: str
    left: PatternExpr
    right: PatternExpr
    loc: Loc = field(default_factory=Loc)


@dataclass
class WildcardPattern:
    loc: Loc = field(default_factory=Loc)


PatternExpr = Union[
    TokenPattern, ScopePattern, CallPattern, AssignPattern,
    DerefPattern, BinopPattern, WildcardPattern,
]


# ── Statements ───────────────────────────────────────────────────

@dataclass
class Param:
    name: str
    type_annotation: Optional[TypeExpr] = None
    loc: Loc = field(default_factory=Loc)


@dataclass
class LetStmt:
    name: str
    mutable: bool
    type_annotation: Optional[TypeExpr]
    value: Expr
    loc: Loc = field(default_factory=Loc)


@dataclass
class AssignStmt:
    target: Expr  # Identifier, MemberExpr, or IndexExpr
    op: AssignOp
    value: Expr
    loc: Loc = field(default_factory=Loc)


@dataclass
class IfStmt:
    condition: Expr
    then_body: list[Stmt]
    elif_clauses: list[tuple[Expr, list[Stmt]]]
    else_body: Optional[list[Stmt]]
    loc: Loc = field(default_factory=Loc)


@dataclass
class ForStmt:
    var: str
    iterable: Expr
    body: list[Stmt]
    loc: Loc = field(default_factory=Loc)


@dataclass
class WhileStmt:
    condition: Expr
    body: list[Stmt]
    loc: Loc = field(default_factory=Loc)


@dataclass
class ReturnStmt:
    value: Optional[Expr]
    loc: Loc = field(default_factory=Loc)


@dataclass
class EmitStmt:
    error_id: str
    args: list[Expr]
    loc: Loc = field(default_factory=Loc)


@dataclass
class BreakStmt:
    loc: Loc = field(default_factory=Loc)


@dataclass
class ContinueStmt:
    loc: Loc = field(default_factory=Loc)


@dataclass
class ExprStmt:
    expr: Expr
    loc: Loc = field(default_factory=Loc)


Stmt = Union[
    LetStmt, AssignStmt, IfStmt, ForStmt, WhileStmt,
    ReturnStmt, EmitStmt, BreakStmt, ContinueStmt, ExprStmt,
]


# ── Top-Level Declarations ──────────────────────────────────────

@dataclass
class AddonField:
    key: str
    value: Expr
    loc: Loc = field(default_factory=Loc)


@dataclass
class AddonDecl:
    name: str
    description: Optional[str]
    fields: list[AddonField]
    loc: Loc = field(default_factory=Loc)


@dataclass
class ImportStmt:
    path: list[str]  # e.g. ["utils", "taint_helpers"]
    loc: Loc = field(default_factory=Loc)


@dataclass
class PatternClauseMatch:
    pattern: PatternExpr
    loc: Loc = field(default_factory=Loc)


@dataclass
class PatternClauseWhere:
    condition: Expr
    loc: Loc = field(default_factory=Loc)


@dataclass
class PatternClauseEnsures:
    condition: Expr
    loc: Loc = field(default_factory=Loc)


PatternClause = Union[PatternClauseMatch, PatternClauseWhere, PatternClauseEnsures]


@dataclass
class PatternDecl:
    name: str
    params: list[Param]
    clauses: list[PatternClause]
    docstring: Optional[str] = None
    loc: Loc = field(default_factory=Loc)


@dataclass
class QueryDecl:
    name: str
    params: list[Param]
    return_type: TypeExpr
    body: list[Stmt]
    docstring: Optional[str] = None
    loc: Loc = field(default_factory=Loc)


@dataclass
class OnBlock:
    event: OnEvent
    body: list[Stmt]
    loc: Loc = field(default_factory=Loc)


@dataclass
class SuppressDecl:
    error_id: str
    file_glob: Optional[str]
    loc: Loc = field(default_factory=Loc)


@dataclass
class FnDecl:
    name: str
    params: list[Param]
    return_type: Optional[TypeExpr]
    body: list[Stmt]
    docstring: Optional[str] = None
    loc: Loc = field(default_factory=Loc)


@dataclass
class CheckerDecl:
    name: str
    error_id: Optional[str]
    severity: Optional[Severity]
    cwe: Optional[int]
    confidence: Optional[Confidence]
    patterns: list[PatternDecl]
    queries: list[QueryDecl]
    on_blocks: list[OnBlock]
    suppressions: list[SuppressDecl]
    functions: list[FnDecl]
    lets: list[LetStmt]
    docstring: Optional[str] = None
    loc: Loc = field(default_factory=Loc)


@dataclass
class ConstDecl:
    name: str
    type_annotation: Optional[TypeExpr]
    value: Expr
    loc: Loc = field(default_factory=Loc)


@dataclass
class TypeAliasDecl:
    name: str
    target: TypeExpr
    loc: Loc = field(default_factory=Loc)


TopLevel = Union[
    AddonDecl, ImportStmt, CheckerDecl, FnDecl,
    ConstDecl, TypeAliasDecl, LetStmt, ExprStmt,
]


@dataclass
class Program:
    addon: Optional[AddonDecl]
    items: list[TopLevel]
    loc: Loc = field(default_factory=Loc)
