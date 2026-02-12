"""
ccql.py — Cppcheck Configuration Query Language (CCQL)
=======================================================

A terse, XPath-like, fully declarative query language for querying
``cppcheckdata.Configuration`` objects with built-in memoization.

Usage::

    from ccql import CCQL

    data = cppcheckdata.parsedump("example.c.dump")
    cfg = data.configurations[0]

    q = CCQL(cfg)

    # All functions with exactly one parameter
    q("//function[count(->@argument) = 1]")

    # All pointer variables that are never checked for null
    q("//variable[#is_ptr and not has(//token[@str='!=' and ..->@variable = $self])]")

    # All tokens that divide by a literal zero
    q("//token[@str='/' and ->@astOperand2[@str='0']]")

Depends on:
    - cppcheckdata  (Cppcheck dump file model)
"""

from __future__ import annotations

import enum
import functools
import hashlib
import logging
import operator
import re
import time
import weakref
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
    Sequence,
    Set,
    Tuple,
    Union,
)

try:
    import cppcheckdata
except ImportError:
    cppcheckdata = None  # type: ignore

logger = logging.getLogger(__name__)


# ===================================================================
#  PART 1 — EXCEPTIONS
# ===================================================================

class CCQLError(Exception):
    """Base exception for all CCQL errors."""
    pass


class CCQLSyntaxError(CCQLError):
    """Raised when a query string is malformed."""
    def __init__(self, message: str, query: str = "", position: int = -1):
        self.query = query
        self.position = position
        if position >= 0 and query:
            pointer = " " * position + "^"
            message = f"{message}\n  {query}\n  {pointer}"
        super().__init__(message)


class CCQLRuntimeError(CCQLError):
    """Raised during query evaluation."""
    pass


# ===================================================================
#  PART 2 — TOKENISER (lexer for query strings)
# ===================================================================

class TokType(enum.Enum):
    """Lexical token types for CCQL query strings."""
    AXIS_DESC = "//"        # descendant axis
    AXIS_CHILD = "/"        # child axis
    AXIS_PARENT = ".."      # parent axis
    AXIS_SIBLING = "~"      # sibling axis
    AXIS_FOLLOW = "->"      # follow reference
    AXIS_BACK = "<-"        # back reference
    PIPE = "|"              # pipeline
    LBRACKET = "["          # predicate open
    RBRACKET = "]"          # predicate close
    LPAREN = "("            # grouping / sub-query open
    RPAREN = ")"            # grouping / sub-query close
    LBRACE = "{"            # projection open
    RBRACE = "}"            # projection close
    COMMA = ","             # separator
    COLON = ":"             # type filter separator
    AT = "@"                # attribute access
    HASH = "#"              # built-in predicate marker
    DOLLAR = "$"            # variable reference
    STAR = "*"              # wildcard
    NOT = "not"             # logical not
    AND = "and"             # logical and
    OR = "or"              # logical or
    HAS = "has"             # existential sub-query
    COUNT = "count"         # count sub-query
    OP_EQ = "="             # equals
    OP_NEQ = "!="           # not equals
    OP_LT = "<"             # less than
    OP_GT = ">"             # greater than
    OP_LTE = "<="           # less than or equal
    OP_GTE = ">="           # greater than or equal
    OP_MATCH = "~="         # regex match
    OP_STARTS = "^="        # starts with
    OP_ENDS = "$="          # ends with
    IDENT = "IDENT"         # identifier
    NUMBER = "NUMBER"       # numeric literal
    STRING = "STRING"       # quoted string literal
    EOF = "EOF"             # end of input


@dataclass
class Tok:
    """A lexical token."""
    type: TokType
    value: Any
    pos: int

    def __repr__(self):
        return f"Tok({self.type.name}, {self.value!r}, @{self.pos})"


# Keywords that get their own token types
_KEYWORDS = {"not": TokType.NOT, "and": TokType.AND, "or": TokType.OR,
             "has": TokType.HAS, "count": TokType.COUNT}

# Two-character operators (order matters: check these before single-char)
_TWO_CHAR_OPS = {
    "//": TokType.AXIS_DESC,
    "->": TokType.AXIS_FOLLOW,
    "<-": TokType.AXIS_BACK,
    "..": TokType.AXIS_PARENT,
    "!=": TokType.OP_NEQ,
    "<=": TokType.OP_LTE,
    ">=": TokType.OP_GTE,
    "~=": TokType.OP_MATCH,
    "^=": TokType.OP_STARTS,
    "$=": TokType.OP_ENDS,
}

# Single-character operators
_ONE_CHAR_OPS = {
    "/": TokType.AXIS_CHILD,
    "~": TokType.AXIS_SIBLING,
    "|": TokType.PIPE,
    "[": TokType.LBRACKET,
    "]": TokType.RBRACKET,
    "(": TokType.LPAREN,
    ")": TokType.RPAREN,
    "{": TokType.LBRACE,
    "}": TokType.RBRACE,
    ",": TokType.COMMA,
    ":": TokType.COLON,
    "@": TokType.AT,
    "#": TokType.HASH,
    "$": TokType.DOLLAR,
    "*": TokType.STAR,
    "=": TokType.OP_EQ,
    "<": TokType.OP_LT,
    ">": TokType.OP_GT,
}


def _tokenise(query: str) -> List[Tok]:
    """Tokenise a CCQL query string.

    Parameters
    ----------
    query : str
        The raw query string.

    Returns
    -------
    list of Tok
        Token list, ending with an EOF token.

    Raises
    ------
    CCQLSyntaxError
        On invalid characters or unterminated strings.
    """
    tokens: List[Tok] = []
    i = 0
    n = len(query)

    while i < n:
        # Skip whitespace
        if query[i].isspace():
            i += 1
            continue

        # String literals
        if query[i] in ('"', "'"):
            quote = query[i]
            start = i
            i += 1
            parts: List[str] = []
            while i < n and query[i] != quote:
                if query[i] == '\\' and i + 1 < n:
                    i += 1
                    parts.append(query[i])
                else:
                    parts.append(query[i])
                i += 1
            if i >= n:
                raise CCQLSyntaxError("Unterminated string literal", query, start)
            i += 1  # skip closing quote
            tokens.append(Tok(TokType.STRING, "".join(parts), start))
            continue

        # Numbers (integers and floats, including negative)
        if query[i].isdigit() or (query[i] == '-' and i + 1 < n and query[i + 1].isdigit()):
            start = i
            if query[i] == '-':
                i += 1
            while i < n and (query[i].isdigit() or query[i] == '.'):
                i += 1
            text = query[start:i]
            try:
                val = int(text) if '.' not in text else float(text)
            except ValueError:
                raise CCQLSyntaxError(f"Invalid number: {text}", query, start)
            tokens.append(Tok(TokType.NUMBER, val, start))
            continue

        # Two-character operators
        if i + 1 < n:
            two = query[i:i + 2]
            if two in _TWO_CHAR_OPS:
                tokens.append(Tok(_TWO_CHAR_OPS[two], two, i))
                i += 2
                continue

        # Single-character operators
        if query[i] in _ONE_CHAR_OPS:
            tokens.append(Tok(_ONE_CHAR_OPS[query[i]], query[i], i))
            i += 1
            continue

        # Identifiers and keywords
        if query[i].isalpha() or query[i] == '_':
            start = i
            while i < n and (query[i].isalnum() or query[i] in ('_', '-')):
                i += 1
            text = query[start:i]
            if text in _KEYWORDS:
                tokens.append(Tok(_KEYWORDS[text], text, start))
            else:
                tokens.append(Tok(TokType.IDENT, text, start))
            continue

        raise CCQLSyntaxError(f"Unexpected character: {query[i]!r}",
                              query, i)

    tokens.append(Tok(TokType.EOF, None, n))
    return tokens


# ===================================================================
#  PART 3 — AST NODES (query plan)
# ===================================================================

class QNodeKind(enum.Enum):
    """Kinds of query plan nodes."""
    PIPELINE = "pipeline"         # chain of steps: step | step | ...
    STEP = "step"                 # axis + selector + predicates + projection
    SELECTOR = "selector"         # kind[:type_filter]
    PREDICATE = "predicate"       # [expr]
    PROJECTION = "projection"     # {field, field, ...}
    ATTR_ACCESS = "attr_access"   # @attr
    BUILTIN_PRED = "builtin"      # #predname
    VAR_REF = "var_ref"           # $name
    LITERAL = "literal"           # string/number
    COMPARE = "compare"           # @attr op value
    LOGIC_NOT = "logic_not"       # not expr
    LOGIC_AND = "logic_and"       # expr and expr
    LOGIC_OR = "logic_or"         # expr or expr
    HAS_QUERY = "has_query"       # has(subquery)
    COUNT_QUERY = "count_query"   # count(subquery) op number
    SUB_QUERY = "sub_query"       # (subquery) — used in predicates
    WILDCARD = "wildcard"         # *


class AxisKind(enum.Enum):
    """Axis kinds."""
    DESCENDANT = "//"     # deep search
    CHILD = "/"           # direct children
    PARENT = ".."         # parent
    SIBLING = "~"         # siblings
    FOLLOW = "->"         # follow reference
    BACK = "<-"           # reverse lookup
    SELF = "."            # implicit: no axis


_AXIS_MAP = {
    TokType.AXIS_DESC: AxisKind.DESCENDANT,
    TokType.AXIS_CHILD: AxisKind.CHILD,
    TokType.AXIS_PARENT: AxisKind.PARENT,
    TokType.AXIS_SIBLING: AxisKind.SIBLING,
    TokType.AXIS_FOLLOW: AxisKind.FOLLOW,
    TokType.AXIS_BACK: AxisKind.BACK,
}


@dataclass
class QNode:
    """A node in the query plan AST."""
    kind: QNodeKind
    axis: AxisKind = AxisKind.SELF
    value: Any = None            # for LITERAL, SELECTOR kind string, ATTR name, etc.
    type_filter: Optional[str] = None  # for SELECTOR: e.g. "Function"
    op: Optional[str] = None     # for COMPARE: "=", "!=", etc.
    children: List["QNode"] = field(default_factory=list)
    fields: List[str] = field(default_factory=list)  # for PROJECTION
    source: str = ""             # original text fragment

    def pretty(self, indent: int = 0) -> str:
        prefix = "  " * indent
        parts = [f"{prefix}{self.kind.value}"]
        if self.axis != AxisKind.SELF:
            parts.append(f" axis={self.axis.value}")
        if self.value is not None:
            parts.append(f" value={self.value!r}")
        if self.type_filter:
            parts.append(f" type={self.type_filter}")
        if self.op:
            parts.append(f" op={self.op}")
        if self.fields:
            parts.append(f" fields={self.fields}")
        result = "".join(parts)
        for child in self.children:
            result += "\n" + child.pretty(indent + 1)
        return result


# ===================================================================
#  PART 4 — PARSER
# ===================================================================

class _Parser:
    """Recursive descent parser for CCQL queries.

    Grammar (simplified)::

        query       → step ('|' step)*
        step        → axis? selector predicate* projection?
        axis        → '//' | '/' | '..' | '~' | '->' | '<-'
        selector    → kind (':' IDENT)?
        kind        → 'token' | 'scope' | 'function' | 'variable'
                     | 'value' | 'directive' | 'container' | 'typeinfo' | '*'
        predicate   → '[' expr ']'
        expr        → or_expr
        or_expr     → and_expr ('or' and_expr)*
        and_expr    → not_expr ('and' not_expr)*
        not_expr    → 'not' not_expr | atom
        atom        → attr_test | builtin_ref | has_expr | count_expr
                     | var_ref | '(' expr ')' | sub_step
        attr_test   → '@' IDENT (op value)?
        builtin_ref → '#' IDENT
        var_ref     → '$' IDENT
        has_expr    → 'has' '(' query ')'
        count_expr  → 'count' '(' query ')' op NUMBER
        sub_step    → axis selector predicate*
        projection  → '{' field (',' field)* '}'
        field       → '@' IDENT | IDENT | '*'
        op          → '=' | '!=' | '<' | '>' | '<=' | '>=' | '~=' | '^=' | '$='
    """

    SELECTOR_KINDS = frozenset({
        "token", "scope", "function", "variable", "value",
        "directive", "container", "typeinfo", "macro",
    })

    def __init__(self, tokens: List[Tok], query: str):
        self._tokens = tokens
        self._query = query
        self._pos = 0

    def _peek(self) -> Tok:
        return self._tokens[self._pos]

    def _advance(self) -> Tok:
        tok = self._tokens[self._pos]
        self._pos += 1
        return tok

    def _expect(self, tt: TokType) -> Tok:
        tok = self._peek()
        if tok.type != tt:
            raise CCQLSyntaxError(
                f"Expected {tt.name}, got {tok.type.name} ({tok.value!r})",
                self._query, tok.pos)
        return self._advance()

    def _at(self, *types: TokType) -> bool:
        return self._peek().type in types

    def _is_axis(self) -> bool:
        return self._peek().type in _AXIS_MAP

    def _is_selector_start(self) -> bool:
        tok = self._peek()
        if tok.type == TokType.STAR:
            return True
        if tok.type == TokType.IDENT and tok.value in self.SELECTOR_KINDS:
            return True
        return False

    def parse(self) -> QNode:
        """Parse the full query → returns a PIPELINE node."""
        node = self._parse_pipeline()
        if self._peek().type != TokType.EOF:
            tok = self._peek()
            raise CCQLSyntaxError(
                f"Unexpected token after query: {tok.value!r}",
                self._query, tok.pos)
        return node

    def _parse_pipeline(self) -> QNode:
        """query → step ('|' step)*"""
        steps = [self._parse_step()]
        while self._at(TokType.PIPE):
            self._advance()
            steps.append(self._parse_step())
        if len(steps) == 1:
            return steps[0]
        return QNode(QNodeKind.PIPELINE, children=steps)

    def _parse_step(self) -> QNode:
        """step → axis? selector predicate* projection?"""
        # Parse axis
        axis = AxisKind.SELF
        if self._is_axis():
            axis = _AXIS_MAP[self._advance().type]

        # Parse selector
        if self._at(TokType.STAR):
            self._advance()
            selector = QNode(QNodeKind.WILDCARD, value="*")
        elif self._at(TokType.IDENT) and self._peek().value in self.SELECTOR_KINDS:
            kind = self._advance().value
            type_filter = None
            if self._at(TokType.COLON):
                self._advance()
                type_filter = self._expect(TokType.IDENT).value
            selector = QNode(QNodeKind.SELECTOR, value=kind,
                             type_filter=type_filter)
        elif self._at(TokType.AT):
            # Bare attribute reference: @attr
            # Treat as implicit token selector
            selector = QNode(QNodeKind.SELECTOR, value="token")
        elif self._at(TokType.HASH):
            selector = QNode(QNodeKind.SELECTOR, value="token")
        else:
            # If we're at EOF or pipe or bracket, this might be an empty step
            # inside a sub-expression; use wildcard
            selector = QNode(QNodeKind.WILDCARD, value="*")

        # Parse predicates
        predicates: List[QNode] = []
        while self._at(TokType.LBRACKET):
            predicates.append(self._parse_predicate())

        # Parse projection
        projection = None
        if self._at(TokType.LBRACE):
            projection = self._parse_projection()

        step = QNode(QNodeKind.STEP, axis=axis,
                     children=[selector] + predicates)
        if projection is not None:
            step.children.append(projection)
        return step

    def _parse_predicate(self) -> QNode:
        """predicate → '[' expr ']'"""
        self._expect(TokType.LBRACKET)
        expr = self._parse_expr()
        self._expect(TokType.RBRACKET)
        return QNode(QNodeKind.PREDICATE, children=[expr])

    def _parse_projection(self) -> QNode:
        """projection → '{' field (',' field)* '}'"""
        self._expect(TokType.LBRACE)
        fields: List[str] = []
        fields.append(self._parse_field())
        while self._at(TokType.COMMA):
            self._advance()
            fields.append(self._parse_field())
        self._expect(TokType.RBRACE)
        return QNode(QNodeKind.PROJECTION, fields=fields)

    def _parse_field(self) -> str:
        if self._at(TokType.AT):
            self._advance()
            return "@" + self._expect(TokType.IDENT).value
        if self._at(TokType.STAR):
            self._advance()
            return "*"
        return self._expect(TokType.IDENT).value

    # ---- Expression parsing (predicates) ----

    def _parse_expr(self) -> QNode:
        return self._parse_or()

    def _parse_or(self) -> QNode:
        left = self._parse_and()
        while self._at(TokType.OR):
            self._advance()
            right = self._parse_and()
            left = QNode(QNodeKind.LOGIC_OR, children=[left, right])
        return left

    def _parse_and(self) -> QNode:
        left = self._parse_not()
        while self._at(TokType.AND):
            self._advance()
            right = self._parse_not()
            left = QNode(QNodeKind.LOGIC_AND, children=[left, right])
        return left

    def _parse_not(self) -> QNode:
        if self._at(TokType.NOT):
            self._advance()
            child = self._parse_not()
            return QNode(QNodeKind.LOGIC_NOT, children=[child])
        return self._parse_atom()

    def _parse_atom(self) -> QNode:
        # @attr [op value]
        if self._at(TokType.AT):
            return self._parse_attr_test()

        # #builtin
        if self._at(TokType.HASH):
            self._advance()
            name = self._expect(TokType.IDENT).value
            return QNode(QNodeKind.BUILTIN_PRED, value=name)

        # $variable
        if self._at(TokType.DOLLAR):
            self._advance()
            name = self._expect(TokType.IDENT).value
            return QNode(QNodeKind.VAR_REF, value=name)

        # has(subquery)
        if self._at(TokType.HAS):
            return self._parse_has()

        # count(subquery) op number
        if self._at(TokType.COUNT):
            return self._parse_count()

        # (expr)
        if self._at(TokType.LPAREN):
            self._advance()
            expr = self._parse_expr()
            self._expect(TokType.RPAREN)
            return expr

        # Sub-step inside predicate: axis selector predicate*
        if self._is_axis() or self._is_selector_start():
            step = self._parse_step()
            return QNode(QNodeKind.SUB_QUERY, children=[step])

        # Literal (string or number)
        if self._at(TokType.STRING, TokType.NUMBER):
            tok = self._advance()
            return QNode(QNodeKind.LITERAL, value=tok.value)

        # IDENT used as literal value
        if self._at(TokType.IDENT):
            tok = self._advance()
            return QNode(QNodeKind.LITERAL, value=tok.value)

        tok = self._peek()
        raise CCQLSyntaxError(
            f"Unexpected token in predicate: {tok.type.name} ({tok.value!r})",
            self._query, tok.pos)

    def _parse_attr_test(self) -> QNode:
        """@attr [op value]"""
        self._expect(TokType.AT)
        attr = self._expect(TokType.IDENT).value
        attr_node = QNode(QNodeKind.ATTR_ACCESS, value=attr)

        # Check for comparison operator
        if self._at(TokType.OP_EQ, TokType.OP_NEQ, TokType.OP_LT,
                    TokType.OP_GT, TokType.OP_LTE, TokType.OP_GTE,
                    TokType.OP_MATCH, TokType.OP_STARTS, TokType.OP_ENDS):
            op_tok = self._advance()
            # RHS: literal, @attr, $var, or sub-step
            if self._at(TokType.AT):
                rhs = self._parse_attr_test()
            elif self._at(TokType.DOLLAR):
                self._advance()
                name = self._expect(TokType.IDENT).value
                rhs = QNode(QNodeKind.VAR_REF, value=name)
            elif self._at(TokType.STRING, TokType.NUMBER):
                rhs = QNode(QNodeKind.LITERAL, value=self._advance().value)
            elif self._at(TokType.IDENT):
                rhs = QNode(QNodeKind.LITERAL, value=self._advance().value)
            else:
                tok = self._peek()
                raise CCQLSyntaxError(
                    f"Expected value after operator, got {tok.type.name}",
                    self._query, tok.pos)
            return QNode(QNodeKind.COMPARE, op=op_tok.value,
                         children=[attr_node, rhs])

        # Bare @attr → existence test (truthy)
        return attr_node

    def _parse_has(self) -> QNode:
        """has(subquery)"""
        self._expect(TokType.HAS)
        self._expect(TokType.LPAREN)
        sub = self._parse_pipeline()
        self._expect(TokType.RPAREN)
        return QNode(QNodeKind.HAS_QUERY, children=[sub])

    def _parse_count(self) -> QNode:
        """count(subquery) op number"""
        self._expect(TokType.COUNT)
        self._expect(TokType.LPAREN)
        sub = self._parse_pipeline()
        self._expect(TokType.RPAREN)
        # Expect comparison
        if not self._at(TokType.OP_EQ, TokType.OP_NEQ, TokType.OP_LT,
                        TokType.OP_GT, TokType.OP_LTE, TokType.OP_GTE):
            tok = self._peek()
            raise CCQLSyntaxError(
                f"Expected comparison operator after count(), got {tok.type.name}",
                self._query, tok.pos)
        op_tok = self._advance()
        num_tok = self._expect(TokType.NUMBER)
        num_node = QNode(QNodeKind.LITERAL, value=num_tok.value)
        return QNode(QNodeKind.COUNT_QUERY, op=op_tok.value,
                     children=[sub, num_node])


def parse_query(query: str) -> QNode:
    """Parse a CCQL query string into a query plan AST.

    Parameters
    ----------
    query : str
        The CCQL query string.

    Returns
    -------
    QNode
        Root of the query plan tree.
    """
    tokens = _tokenise(query)
    parser = _Parser(tokens, query)
    return parser.parse()


# ===================================================================
#  PART 5 — MEMOISATION CACHE
# ===================================================================

class _MemoCache:
    """LRU-like memoisation cache keyed by (query_fingerprint, config_id).

    The cache stores results of intermediate and final query evaluations.
    Since a ``Configuration`` is immutable during analysis, results are
    stable and can be safely reused.

    Implementation: a dict mapping fingerprint → result, with optional
    capacity bound and hit/miss statistics.
    """

    def __init__(self, capacity: int = 4096):
        self._store: Dict[str, Any] = {}
        self._capacity = capacity
        self._hits = 0
        self._misses = 0
        self._evictions = 0
        # Access order for LRU eviction (simple approach: just track insertion order)
        self._order: List[str] = []

    def get(self, key: str) -> Optional[Any]:
        """Get cached result, or None if not cached."""
        result = self._store.get(key)
        if result is not None:
            self._hits += 1
            return result
        self._misses += 1
        return None

    def put(self, key: str, value: Any) -> None:
        """Store a result in the cache."""
        if key in self._store:
            self._store[key] = value
            return
        if len(self._store) >= self._capacity:
            # Evict oldest
            if self._order:
                oldest = self._order.pop(0)
                self._store.pop(oldest, None)
                self._evictions += 1
        self._store[key] = value
        self._order.append(key)

    def invalidate(self) -> None:
        """Clear the entire cache."""
        self._store.clear()
        self._order.clear()

    def stats(self) -> Dict[str, int]:
        return {
            "hits": self._hits,
            "misses": self._misses,
            "evictions": self._evictions,
            "size": len(self._store),
            "capacity": self._capacity,
        }

    @staticmethod
    def fingerprint(query: str, context_id: str = "",
                    extra: str = "") -> str:
        """Compute a cache key fingerprint.

        Uses a hash of the query text, context ID, and any extra
        discriminator to produce a compact, collision-resistant key.
        """
        raw = f"{query}\x00{context_id}\x00{extra}"
        return hashlib.md5(raw.encode("utf-8")).hexdigest()


# ===================================================================
#  PART 6 — BUILT-IN PREDICATES REGISTRY
# ===================================================================

# Each built-in predicate is a function: (node) → bool
_BUILTIN_PREDICATES: Dict[str, Callable[[Any], bool]] = {}


def _register_builtin(name: str, fn: Callable[[Any], bool]) -> None:
    _BUILTIN_PREDICATES[name] = fn


# Token predicates
_register_builtin("is_name", lambda n: getattr(n, "isName", False))
_register_builtin("is_number", lambda n: getattr(n, "isNumber", False))
_register_builtin("is_int", lambda n: getattr(n, "isInt", False))
_register_builtin("is_float", lambda n: getattr(n, "isFloat", False))
_register_builtin("is_string", lambda n: getattr(n, "isString", False))
_register_builtin("is_char", lambda n: getattr(n, "isChar", False))
_register_builtin("is_boolean", lambda n: getattr(n, "isBoolean", False))
_register_builtin("is_op", lambda n: getattr(n, "isOp", False))
_register_builtin("is_arith", lambda n: getattr(n, "isArithmeticalOp", False))
_register_builtin("is_assign", lambda n: getattr(n, "isAssignmentOp", False))
_register_builtin("is_cmp", lambda n: getattr(n, "isComparisonOp", False))
_register_builtin("is_logic", lambda n: getattr(n, "isLogicalOp", False))
_register_builtin("is_cast", lambda n: getattr(n, "isCast", False))
_register_builtin("is_expanded_macro",
                   lambda n: getattr(n, "isExpandedMacro", False))
_register_builtin("is_binary_op",
                   lambda n: (getattr(n, "astOperand1", None) is not None and
                              getattr(n, "astOperand2", None) is not None))
_register_builtin("is_unary_op",
                   lambda n: (getattr(n, "astOperand1", None) is not None and
                              getattr(n, "astOperand2", None) is None))
_register_builtin("is_leaf",
                   lambda n: (getattr(n, "astOperand1", None) is None and
                              getattr(n, "astOperand2", None) is None))

# Variable predicates
_register_builtin("is_ptr", lambda n: getattr(n, "isPointer", False) or
                  (getattr(n, "valueType", None) is not None and
                   getattr(n.valueType, "pointer", 0) > 0))
_register_builtin("is_array", lambda n: getattr(n, "isArray", False))
_register_builtin("is_const", lambda n: getattr(n, "isConst", False))
_register_builtin("is_static", lambda n: getattr(n, "isStatic", False))
_register_builtin("is_volatile", lambda n: getattr(n, "isVolatile", False))
_register_builtin("is_extern", lambda n: getattr(n, "isExtern", False))
_register_builtin("is_global", lambda n: getattr(n, "isGlobal", False) or
                  getattr(n, "access", "") == "Global")
_register_builtin("is_local", lambda n: getattr(n, "isLocal", False) or
                  getattr(n, "access", "") == "Local")
_register_builtin("is_arg", lambda n: getattr(n, "isArgument", False) or
                  getattr(n, "access", "") == "Argument")
_register_builtin("is_reference", lambda n: getattr(n, "isReference", False))
_register_builtin("is_class", lambda n: getattr(n, "isClass", False))

# Scope predicates
_register_builtin("is_executable",
                   lambda n: getattr(n, "isExecutable", False))

# Function predicates
_register_builtin("is_virtual",
                   lambda n: getattr(n, "hasVirtualSpecifier", False))
_register_builtin("is_noreturn",
                   lambda n: getattr(n, "isAttributeNoreturn", False))
_register_builtin("is_inline",
                   lambda n: getattr(n, "isInlineKeyword", False))

# ValueFlow predicates
_register_builtin("has_known_value", lambda n: (
    bool(getattr(n, "values", None)) and
    any(getattr(v, "valueKind", "") == "known"
        for v in getattr(n, "values", []))
))
_register_builtin("has_possible_value", lambda n: (
    bool(getattr(n, "values", None)) and
    any(getattr(v, "valueKind", "") == "possible"
        for v in getattr(n, "values", []))
))
_register_builtin("has_impossible_value", lambda n: (
    bool(getattr(n, "impossible_values", None))
))


# ===================================================================
#  PART 7 — COLLECTION RESOLVER
# ===================================================================

def _node_kind(node: Any) -> Optional[str]:
    """Determine what kind of Cppcheck object ``node`` is."""
    cls_name = type(node).__name__
    _map = {
        "Token": "token",
        "Scope": "scope",
        "Function": "function",
        "Variable": "variable",
        "Value": "value",
        "Directive": "directive",
        "Container": "container",
        "TypedefInfo": "typeinfo",
        "MacroUsage": "macro",
    }
    return _map.get(cls_name)


class _CollectionResolver:
    """Resolves selector kinds to the appropriate lists from a Configuration.

    Also builds indices for reverse lookups and sibling queries.
    """

    def __init__(self, cfg: Any):
        self._cfg = cfg
        # Pre-built indices (lazily populated)
        self._token_by_id: Optional[Dict[str, Any]] = None
        self._scope_by_id: Optional[Dict[str, Any]] = None
        self._var_by_id: Optional[Dict[str, Any]] = None
        self._func_by_id: Optional[Dict[str, Any]] = None
        self._tokens_by_scope: Optional[Dict[str, List[Any]]] = None
        self._vars_by_scope: Optional[Dict[str, List[Any]]] = None

    def get_collection(self, kind: str) -> List[Any]:
        """Get the base collection for a selector kind."""
        cfg = self._cfg
        _map = {
            "token": lambda: getattr(cfg, "tokenlist", []),
            "scope": lambda: getattr(cfg, "scopes", []),
            "function": lambda: getattr(cfg, "functions", []),
            "variable": lambda: getattr(cfg, "variables", []),
            "value": lambda: self._all_values(),
            "directive": lambda: getattr(cfg, "directives", []),
            "container": lambda: getattr(cfg, "containers", []),
            "typeinfo": lambda: getattr(cfg, "typedefInfo", []),
            "macro": lambda: getattr(cfg, "macro_usage", []),
        }
        getter = _map.get(kind)
        if getter is None:
            return []
        return getter()

    def _all_values(self) -> List[Any]:
        """Collect all Value objects from all ValueFlows."""
        result = []
        for vf in getattr(self._cfg, "valueflow", []):
            for v in getattr(vf, "values", []):
                result.append(v)
        return result

    def get_all(self) -> List[Any]:
        """Get all objects (wildcard *)."""
        result: List[Any] = []
        for kind in ("token", "scope", "function", "variable",
                     "directive", "container", "typeinfo", "macro"):
            result.extend(self.get_collection(kind))
        return result

    # ---- Index builders ----

    def _ensure_token_index(self) -> Dict[str, Any]:
        if self._token_by_id is None:
            self._token_by_id = {}
            for tok in getattr(self._cfg, "tokenlist", []):
                tid = getattr(tok, "Id", None)
                if tid:
                    self._token_by_id[tid] = tok
        return self._token_by_id

    def _ensure_scope_index(self) -> Dict[str, Any]:
        if self._scope_by_id is None:
            self._scope_by_id = {}
            for sc in getattr(self._cfg, "scopes", []):
                sid = getattr(sc, "Id", None)
                if sid:
                    self._scope_by_id[sid] = sc
        return self._scope_by_id

    def _ensure_tokens_by_scope(self) -> Dict[str, List[Any]]:
        if self._tokens_by_scope is None:
            self._tokens_by_scope = {}
            for tok in getattr(self._cfg, "tokenlist", []):
                sid = getattr(tok, "scopeId", None) or (
                    getattr(getattr(tok, "scope", None), "Id", None)
                )
                if sid:
                    self._tokens_by_scope.setdefault(sid, []).append(tok)
        return self._tokens_by_scope

    def get_scope_of(self, node: Any) -> Optional[Any]:
        """Get the scope containing a node."""
        # Token → scope
        scope = getattr(node, "scope", None)
        if scope is not None:
            return scope
        # Variable → scope
        scope_id = getattr(node, "scopeId", None)
        if scope_id:
            idx = self._ensure_scope_index()
            return idx.get(scope_id)
        # Scope → nestedIn
        return getattr(node, "nestedIn", None)

    def get_children_of(self, node: Any, kind: str) -> List[Any]:
        """Get direct children of ``node`` of a given kind."""
        nk = _node_kind(node)

        if nk == "scope":
            if kind == "token":
                idx = self._ensure_tokens_by_scope()
                sid = getattr(node, "Id", None)
                return idx.get(sid, [])
            if kind == "variable":
                return getattr(node, "varlist", [])
            if kind == "function":
                return getattr(node, "functions", [])
            if kind == "scope":
                return getattr(node, "nestedList", [])

        if nk == "function":
            if kind == "variable":
                return list(getattr(node, "argument", {}).values())
            if kind == "token":
                tok = getattr(node, "token", None) or getattr(node, "tokenDef", None)
                return [tok] if tok else []

        if nk == "token":
            if kind == "token":
                children = []
                op1 = getattr(node, "astOperand1", None)
                op2 = getattr(node, "astOperand2", None)
                if op1: children.append(op1)
                if op2: children.append(op2)
                return children
            if kind == "value":
                return getattr(node, "values", []) or []
            if kind == "variable":
                v = getattr(node, "variable", None)
                return [v] if v else []
            if kind == "function":
                f = getattr(node, "function", None)
                return [f] if f else []

        return []

    def get_parent_of(self, node: Any) -> Optional[Any]:
        """Get the parent of a node (AST parent for tokens, nestedIn for scopes)."""
        # Token → astParent
        parent = getattr(node, "astParent", None)
        if parent is not None:
            return parent
        # Scope → nestedIn
        parent = getattr(node, "nestedIn", None)
        if parent is not None:
            return parent
        # Variable/Function → scope
        return self.get_scope_of(node)

    def get_siblings_of(self, node: Any) -> List[Any]:
        """Get sibling nodes (same scope, same kind)."""
        nk = _node_kind(node)
        if nk is None:
            return []
        parent = self.get_parent_of(node)
        if parent is None:
            # Top-level: siblings are all nodes of same kind
            return [n for n in self.get_collection(nk)
                    if n is not node]
        children = self.get_children_of(parent, nk)
        return [c for c in children if c is not node]

    def follow_reference(self, node: Any, attr: Optional[str] = None) -> List[Any]:
        """Follow a reference from a node.

        If ``attr`` is given, get that attribute. Otherwise, follow
        common references (variable, function, scope, link, etc.).
        """
        if attr:
            val = getattr(node, attr, None)
            if val is None:
                return []
            if isinstance(val, list):
                return val
            if isinstance(val, dict):
                return list(val.values())
            return [val]

        # Default: follow all common references
        results: List[Any] = []
        for a in ("variable", "function", "scope", "link", "typeScope",
                  "astOperand1", "astOperand2", "astParent",
                  "nameToken", "typeStartToken", "typeEndToken",
                  "bodyStart", "bodyEnd", "token", "tokenDef",
                  "nestedIn"):
            val = getattr(node, a, None)
            if val is not None:
                if isinstance(val, list):
                    results.extend(val)
                elif isinstance(val, dict):
                    results.extend(val.values())
                else:
                    results.append(val)
        return results

    def back_reference(self, node: Any, kind: str) -> List[Any]:
        """Reverse lookup: find all objects of ``kind`` that reference ``node``."""
        nk = _node_kind(node)
        node_id = getattr(node, "Id", id(node))

        results: List[Any] = []
        for candidate in self.get_collection(kind):
            # Check if any reference attribute of candidate points to node
            for attr in ("variable", "function", "scope", "link",
                         "typeScope", "astOperand1", "astOperand2",
                         "astParent", "nameToken", "token", "tokenDef",
                         "nestedIn", "bodyStart", "bodyEnd"):
                val = getattr(candidate, attr, None)
                if val is node:
                    results.append(candidate)
                    break
                elif val is not None and hasattr(val, "Id") and getattr(val, "Id", None) == node_id:
                    results.append(candidate)
                    break
        return results


# ===================================================================
#  PART 8 — QUERY EVALUATOR
# ===================================================================

# Comparison operators
_CMP_OPS: Dict[str, Callable[[Any, Any], bool]] = {
    "=": lambda a, b: _coerce_eq(a, b),
    "!=": lambda a, b: not _coerce_eq(a, b),
    "<": lambda a, b: _coerce_cmp(a, b, operator.lt),
    ">": lambda a, b: _coerce_cmp(a, b, operator.gt),
    "<=": lambda a, b: _coerce_cmp(a, b, operator.le),
    ">=": lambda a, b: _coerce_cmp(a, b, operator.ge),
    "~=": lambda a, b: bool(re.search(str(b), str(a))),
    "^=": lambda a, b: str(a).startswith(str(b)),
    "$=": lambda a, b: str(a).endswith(str(b)),
}


def _coerce_eq(a: Any, b: Any) -> bool:
    """Equality with type coercion."""
    if a is None and b is None:
        return True
    if a is None or b is None:
        return False
    # Direct comparison
    if a == b:
        return True
    # String comparison
    if str(a) == str(b):
        return True
    # Numeric comparison
    try:
        return float(a) == float(b)
    except (ValueError, TypeError):
        pass
    return False


def _coerce_cmp(a: Any, b: Any, op: Callable) -> bool:
    """Comparison with numeric coercion."""
    try:
        return op(float(a), float(b))
    except (ValueError, TypeError):
        try:
            return op(str(a), str(b))
        except TypeError:
            return False


def _get_attr(node: Any, name: str) -> Any:
    """Get an attribute from a node, with fallbacks.

    Supports dotted paths: ``valueType.pointer``.
    """
    parts = name.split(".")
    current = node
    for part in parts:
        if current is None:
            return None
        current = getattr(current, part, None)
    return current


def _node_matches_type_filter(node: Any, type_filter: str) -> bool:
    """Check if a node matches a type filter.

    For scopes: matches the ``type`` attribute (Function, If, For, etc.)
    For functions: matches the ``type`` attribute (Function, Constructor, etc.)
    For variables: matches the ``access`` attribute or variable properties.
    """
    # Scope type
    stype = getattr(node, "type", None)
    if stype is not None and isinstance(stype, str):
        if stype.lower() == type_filter.lower():
            return True

    # Access attribute
    access = getattr(node, "access", None)
    if access is not None and isinstance(access, str):
        if access.lower() == type_filter.lower():
            return True

    # Token type
    if type_filter.lower() in ("name", "op", "number", "string", "char",
                                "boolean"):
        tok_type = getattr(node, "type", None)
        if tok_type and isinstance(tok_type, str):
            if tok_type.lower() == type_filter.lower():
                return True

    return False


@dataclass
class _EvalContext:
    """Context for query evaluation."""
    resolver: _CollectionResolver
    cache: _MemoCache
    variables: Dict[str, Any] = field(default_factory=dict)
    config_id: str = ""


class _Evaluator:
    """Evaluates query plan ASTs against a Configuration.

    Uses memoisation at every step boundary: each step's result is cached
    by a fingerprint of (query source, input set hash).
    """

    def __init__(self, ctx: _EvalContext):
        self._ctx = ctx

    def evaluate(self, plan: QNode,
                 input_set: Optional[List[Any]] = None) -> List[Any]:
        """Evaluate a query plan against an input set.

        Parameters
        ----------
        plan : QNode
            The query plan AST.
        input_set : list, optional
            Input objects. If None, determined from the plan's axis/selector.

        Returns
        -------
        list
            Matching objects.
        """
        return self._eval(plan, input_set)

    def _eval(self, node: QNode, input_set: Optional[List[Any]]) -> List[Any]:
        kind = node.kind

        if kind == QNodeKind.PIPELINE:
            return self._eval_pipeline(node, input_set)
        if kind == QNodeKind.STEP:
            return self._eval_step(node, input_set)

        # For expression nodes (used in predicates), this shouldn't be called
        # directly with a set; handled in predicate evaluation
        return []

    def _eval_pipeline(self, node: QNode,
                       input_set: Optional[List[Any]]) -> List[Any]:
        """Evaluate a pipeline: chain steps, feeding output of one as input to next."""
        current = input_set
        for step in node.children:
            current = self._eval(step, current)
            if not current:
                return []
        return current

    def _eval_step(self, node: QNode,
                   input_set: Optional[List[Any]]) -> List[Any]:
        """Evaluate a single step: axis + selector + predicates + projection."""
        axis = node.axis
        children = node.children
        if not children:
            return []

        selector = children[0]  # SELECTOR or WILDCARD
        predicates = [c for c in children[1:] if c.kind == QNodeKind.PREDICATE]
        projections = [c for c in children[1:] if c.kind == QNodeKind.PROJECTION]

        # ---- Generate candidate set from axis ----
        candidates = self._apply_axis(axis, selector, input_set)

        # ---- Filter by selector kind + type ----
        candidates = self._apply_selector(selector, candidates)

        # ---- Check cache ----
        cache_key = self._step_cache_key(node, candidates)
        cached = self._ctx.cache.get(cache_key)
        if cached is not None:
            return cached

        # ---- Apply predicates ----
        for pred in predicates:
            candidates = self._apply_predicate(pred, candidates)
            if not candidates:
                break

        # ---- Apply projection ----
        if projections:
            candidates = self._apply_projection(projections[0], candidates)

        # ---- Deduplicate (preserve order) ----
        seen: Set[int] = set()
        deduped: List[Any] = []
        for c in candidates:
            cid = id(c) if not isinstance(c, dict) else id(frozenset(c.items()) if isinstance(c, dict) and all(isinstance(v, (str, int, float, bool, type(None))) for v in c.values()) else None) or id(c)
            if cid not in seen:
                seen.add(cid)
                deduped.append(c)

        # ---- Store in cache ----
        self._ctx.cache.put(cache_key, deduped)

        return deduped

    def _step_cache_key(self, node: QNode, candidates: List[Any]) -> str:
        """Generate a cache key for a step + candidate set."""
        # Use node source + size as fingerprint (not individual IDs, for speed)
        step_sig = node.pretty()
        set_sig = str(len(candidates))
        if candidates:
            first_id = str(getattr(candidates[0], "Id", id(candidates[0])))
            last_id = str(getattr(candidates[-1], "Id", id(candidates[-1])))
            set_sig = f"{len(candidates)}:{first_id}:{last_id}"
        return self._ctx.cache.fingerprint(step_sig, self._ctx.config_id,
                                           set_sig)

    def _apply_axis(self, axis: AxisKind, selector: QNode,
                    input_set: Optional[List[Any]]) -> List[Any]:
        """Apply the axis to produce a candidate set."""
        resolver = self._ctx.resolver

        # Determine target kind from selector
        target_kind = selector.value if selector.kind == QNodeKind.SELECTOR else None

        if axis == AxisKind.SELF or axis == AxisKind.DESCENDANT:
            if input_set is None:
                # Root query: get from configuration
                if target_kind and target_kind != "*":
                    return list(resolver.get_collection(target_kind))
                return list(resolver.get_all())
            if axis == AxisKind.SELF:
                return list(input_set)
            # Descendant: deep search from each input node
            results: List[Any] = []
            visited: Set[int] = set()
            for node in input_set:
                self._collect_descendants(node, target_kind, results,
                                          visited, resolver)
            # Also include objects from the collection that are reachable
            if target_kind and target_kind != "*":
                # For descendant axis at root level, just return the collection
                if not input_set:
                    return list(resolver.get_collection(target_kind))
            return results

        if axis == AxisKind.CHILD:
            if input_set is None:
                if target_kind:
                    return list(resolver.get_collection(target_kind))
                return list(resolver.get_all())
            results = []
            for node in input_set:
                if target_kind and target_kind != "*":
                    results.extend(resolver.get_children_of(node, target_kind))
                else:
                    for k in ("token", "scope", "function", "variable",
                              "value"):
                        results.extend(resolver.get_children_of(node, k))
            return results

        if axis == AxisKind.PARENT:
            if input_set is None:
                return []
            results = []
            for node in input_set:
                parent = resolver.get_parent_of(node)
                if parent is not None:
                    results.append(parent)
            return results

        if axis == AxisKind.SIBLING:
            if input_set is None:
                return []
            results = []
            for node in input_set:
                results.extend(resolver.get_siblings_of(node))
            return results

        if axis == AxisKind.FOLLOW:
            if input_set is None:
                return []
            results = []
            for node in input_set:
                results.extend(resolver.follow_reference(node))
            return results

        if axis == AxisKind.BACK:
            if input_set is None:
                return []
            results = []
            for node in input_set:
                tk = target_kind or "token"
                results.extend(resolver.back_reference(node, tk))
            return results

        return []

    def _collect_descendants(self, node: Any, target_kind: Optional[str],
                             results: List[Any], visited: Set[int],
                             resolver: _CollectionResolver,
                             depth: int = 0) -> None:
        """Recursively collect descendants."""
        if depth > 100:
            return  # prevent infinite recursion
        nid = id(node)
        if nid in visited:
            return
        visited.add(nid)

        # Check if this node matches the target kind
        nk = _node_kind(node)
        if target_kind is None or target_kind == "*" or nk == target_kind:
            results.append(node)

        # Descend into children of all kinds
        for kind in ("token", "scope", "function", "variable", "value"):
            for child in resolver.get_children_of(node, kind):
                if child is not None:
                    self._collect_descendants(child, target_kind, results,
                                              visited, resolver, depth + 1)

    def _apply_selector(self, selector: QNode,
                        candidates: List[Any]) -> List[Any]:
        """Filter candidates by selector kind and type filter."""
        if selector.kind == QNodeKind.WILDCARD:
            return candidates

        target_kind = selector.value
        type_filter = selector.type_filter

        result: List[Any] = []
        for node in candidates:
            # Kind check
            nk = _node_kind(node)
            if target_kind and target_kind != "*" and nk != target_kind:
                continue
            # Type filter check
            if type_filter and not _node_matches_type_filter(node, type_filter):
                continue
            result.append(node)
        return result

    def _apply_predicate(self, pred_node: QNode,
                         candidates: List[Any]) -> List[Any]:
        """Apply a predicate to filter candidates."""
        expr = pred_node.children[0] if pred_node.children else None
        if expr is None:
            return candidates
        return [node for node in candidates if self._eval_expr(expr, node)]

    def _eval_expr(self, expr: QNode, node: Any) -> bool:
        """Evaluate a predicate expression against a node.

        Returns True if the node passes the predicate.
        """
        kind = expr.kind

        if kind == QNodeKind.ATTR_ACCESS:
            # Bare @attr → existence/truthiness test
            val = _get_attr(node, expr.value)
            return bool(val)

        if kind == QNodeKind.COMPARE:
            lhs_node = expr.children[0]
            rhs_node = expr.children[1]
            lhs_val = self._resolve_value(lhs_node, node)
            rhs_val = self._resolve_value(rhs_node, node)
            cmp_fn = _CMP_OPS.get(expr.op)
            if cmp_fn is None:
                return False
            return cmp_fn(lhs_val, rhs_val)

        if kind == QNodeKind.BUILTIN_PRED:
            pred_fn = _BUILTIN_PREDICATES.get(expr.value)
            if pred_fn is None:
                logger.warning("Unknown built-in predicate: %s", expr.value)
                return False
            return pred_fn(node)

        if kind == QNodeKind.VAR_REF:
            var_name = expr.value
            if var_name == "self":
                return bool(node)
            val = self._ctx.variables.get(var_name)
            return bool(val)

        if kind == QNodeKind.LITERAL:
            return bool(expr.value)

        if kind == QNodeKind.LOGIC_NOT:
            return not self._eval_expr(expr.children[0], node)

        if kind == QNodeKind.LOGIC_AND:
            return (self._eval_expr(expr.children[0], node) and
                    self._eval_expr(expr.children[1], node))

        if kind == QNodeKind.LOGIC_OR:
            return (self._eval_expr(expr.children[0], node) or
                    self._eval_expr(expr.children[1], node))

        if kind == QNodeKind.HAS_QUERY:
            sub_plan = expr.children[0]
            sub_results = self._eval(sub_plan, [node])
            return len(sub_results) > 0

        if kind == QNodeKind.COUNT_QUERY:
            sub_plan = expr.children[0]
            num_node = expr.children[1]
            sub_results = self._eval(sub_plan, [node])
            count = len(sub_results)
            target = num_node.value if num_node.value is not None else 0
            cmp_fn = _CMP_OPS.get(expr.op)
            if cmp_fn is None:
                return False
            return cmp_fn(count, target)

        if kind == QNodeKind.SUB_QUERY:
            sub_results = self._eval(expr.children[0], [node])
            return len(sub_results) > 0

        return False

    def _resolve_value(self, val_node: QNode, context_node: Any) -> Any:
        """Resolve a value node (LHS or RHS of comparison) to a concrete value."""
        if val_node.kind == QNodeKind.ATTR_ACCESS:
            return _get_attr(context_node, val_node.value)
        if val_node.kind == QNodeKind.LITERAL:
            return val_node.value
        if val_node.kind == QNodeKind.VAR_REF:
            if val_node.value == "self":
                return context_node
            return self._ctx.variables.get(val_node.value)
        if val_node.kind == QNodeKind.BUILTIN_PRED:
            pred_fn = _BUILTIN_PREDICATES.get(val_node.value)
            if pred_fn:
                return pred_fn(context_node)
            return None
        return None

    def _apply_projection(self, proj_node: QNode,
                          candidates: List[Any]) -> List[Any]:
        """Apply a projection to produce dicts instead of raw objects.

        Returns a list of dicts, each containing the requested fields.
        """
        fields = proj_node.fields
        results: List[Any] = []
        for node in candidates:
            record: Dict[str, Any] = {}
            for fld in fields:
                if fld == "*":
                    # Include all known attributes
                    for attr in dir(node):
                        if not attr.startswith("_") and not callable(getattr(node, attr, None)):
                            record[attr] = getattr(node, attr, None)
                elif fld.startswith("@"):
                    attr_name = fld[1:]
                    record[attr_name] = _get_attr(node, attr_name)
                else:
                    record[fld] = _get_attr(node, fld)
            record["_node"] = node  # keep reference to original
            results.append(record)
        return results


# ===================================================================
#  PART 9 — CCQL PUBLIC API
# ===================================================================

class CCQL:
    """Cppcheck Configuration Query Language engine.

    Provides a fully declarative, XPath-like query interface over
    ``cppcheckdata.Configuration`` objects with built-in memoisation.

    Usage::

        data = cppcheckdata.parsedump("example.c.dump")
        cfg = data.configurations[0]
        q = CCQL(cfg)

        # Simple queries
        functions = q("//function")
        global_vars = q("//variable[#is_global]")

        # Complex queries
        unsafe_divs = q("//token[@str='/' and ->@astOperand2[#has_known_value and @str='0']]")

        # Parameterised queries
        q.set_variable("target_func", "malloc")
        calls = q("//token[@str = $target_func and #is_name]")

        # Projections
        func_info = q("//function{@name, @type, @access}")

        # Cache statistics
        print(q.cache_stats())

    Parameters
    ----------
    cfg : Configuration
        A ``cppcheckdata.Configuration`` object (from ``parsedump``).
    cache_capacity : int
        Maximum number of cached query results (default 4096).
    """

    def __init__(self, cfg: Any, cache_capacity: int = 4096):
        self._cfg = cfg
        self._cache = _MemoCache(capacity=cache_capacity)
        self._resolver = _CollectionResolver(cfg)
        self._variables: Dict[str, Any] = {}
        self._config_id = str(id(cfg))
        self._query_count = 0
        self._total_time = 0.0

    def __call__(self, query: str, **variables: Any) -> List[Any]:
        """Execute a CCQL query.

        Parameters
        ----------
        query : str
            The CCQL query string.
        **variables
            Named variables available as ``$name`` in predicates.

        Returns
        -------
        list
            List of matching objects (Tokens, Scopes, Functions, Variables,
            dicts if projection is used, etc.).
        """
        return self.query(query, **variables)

    def query(self, query: str, **variables: Any) -> List[Any]:
        """Execute a CCQL query.

        Parameters
        ----------
        query : str
            The CCQL query string.
        **variables
            Named variables available as ``$name`` in predicates.

        Returns
        -------
        list
            List of matching objects.
        """
        # Check top-level cache
        merged_vars = {**self._variables, **variables}
        var_sig = str(sorted(merged_vars.items()))
        top_key = self._cache.fingerprint(query, self._config_id, var_sig)
        cached = self._cache.get(top_key)
        if cached is not None:
            self._query_count += 1
            return cached

        t0 = time.monotonic()

        # Parse
        plan = parse_query(query)

        # Evaluate
        ctx = _EvalContext(
            resolver=self._resolver,
            cache=self._cache,
            variables=merged_vars,
            config_id=self._config_id,
        )
        evaluator = _Evaluator(ctx)
        result = evaluator.evaluate(plan)

        elapsed = time.monotonic() - t0
        self._total_time += elapsed
        self._query_count += 1

        # Cache top-level result
        self._cache.put(top_key, result)

        logger.debug("CCQL query '%s' returned %d results in %.4fs",
                     query, len(result), elapsed)
        return result

    def query_one(self, query: str, **variables: Any) -> Optional[Any]:
        """Execute a query and return the first result, or None."""
        results = self.query(query, **variables)
        return results[0] if results else None

    def query_exists(self, query: str, **variables: Any) -> bool:
        """Check if a query returns any results."""
        return len(self.query(query, **variables)) > 0

    def query_count(self, query: str, **variables: Any) -> int:
        """Return the number of results for a query."""
        return len(self.query(query, **variables))

    def set_variable(self, name: str, value: Any) -> None:
        """Set a persistent query variable.

        Available as ``$name`` in all subsequent queries.
        """
        self._variables[name] = value
        self._cache.invalidate()  # variable change invalidates cache

    def clear_variables(self) -> None:
        """Clear all persistent query variables."""
        self._variables.clear()
        self._cache.invalidate()

    def invalidate_cache(self) -> None:
        """Clear the memoisation cache."""
        self._cache.invalidate()

    def cache_stats(self) -> Dict[str, Any]:
        """Return cache statistics."""
        stats = self._cache.stats()
        stats["queries_executed"] = self._query_count
        stats["total_time_seconds"] = round(self._total_time, 4)
        return stats

    def explain(self, query: str) -> str:
        """Return the parsed query plan as a human-readable tree.

        Useful for debugging queries.
        """
        plan = parse_query(query)
        return plan.pretty()

    # ---- Convenience query methods ----

    def tokens(self, predicate: str = "") -> List[Any]:
        """Shortcut: query all tokens, optionally filtered.

        Parameters
        ----------
        predicate : str
            Optional predicate string (without brackets), e.g.
            ``"@str='/' and #is_arith"``.
        """
        if predicate:
            return self.query(f"//token[{predicate}]")
        return self.query("//token")

    def scopes(self, type_filter: str = "") -> List[Any]:
        """Shortcut: query all scopes, optionally by type."""
        if type_filter:
            return self.query(f"//scope:{type_filter}")
        return self.query("//scope")

    def functions(self, predicate: str = "") -> List[Any]:
        """Shortcut: query all functions."""
        if predicate:
            return self.query(f"//function[{predicate}]")
        return self.query("//function")

    def variables(self, predicate: str = "") -> List[Any]:
        """Shortcut: query all variables."""
        if predicate:
            return self.query(f"//variable[{predicate}]")
        return self.query("//variable")

    def find_calls(self, func_name: str) -> List[Any]:
        """Find all call sites for a named function.

        Returns tokens where the function is called.
        """
        return self.query(
            f'//token[@str="{func_name}" and #is_name and '
            f'has(//token[@str="("])]')

    def find_assignments_to(self, var_name: str) -> List[Any]:
        """Find all assignment operations targeting a named variable."""
        return self.query(
            f'//token[#is_assign and '
            f'has(/token[@str="{var_name}" and #is_name])]')

    def find_unsafe_patterns(self) -> Dict[str, List[Any]]:
        """Run a suite of built-in safety queries.

        Returns a dict of pattern name → list of matching tokens.
        """
        patterns: Dict[str, str] = {
            "division_by_zero":
                '//token[@str="/" and #is_arith]',
            "null_dereference":
                '//token[@str="*" and #is_unary_op and '
                'has(/token[#is_ptr])]',
            "array_access":
                '//token[@str="[" and #is_op]',
            "unsafe_functions":
                '//token[@str~="^(strcpy|strcat|sprintf|gets)$" and #is_name]',
            "uninitialized_vars":
                '//variable[#is_local and not #is_arg]',
            "global_mutable":
                '//variable[#is_global and not #is_const]',
        }
        results = {}
        for name, q in patterns.items():
            try:
                results[name] = self.query(q)
            except CCQLError:
                results[name] = []
        return results


# ===================================================================
#  PART 10 — STANDALONE HELPERS
# ===================================================================

def query_config(cfg: Any, query_str: str, **variables: Any) -> List[Any]:
    """One-shot query: create a CCQL engine and run a single query.

    Parameters
    ----------
    cfg : Configuration
        Cppcheck configuration object.
    query_str : str
        CCQL query string.
    **variables
        Query variables.

    Returns
    -------
    list
        Query results.
    """
    return CCQL(cfg)(query_str, **variables)


def query_dump(dump_path: str, query_str: str,
               config_name: str = "",
               **variables: Any) -> List[Any]:
    """Query a Cppcheck dump file directly.

    Parameters
    ----------
    dump_path : str
        Path to the ``.dump`` file.
    query_str : str
        CCQL query string.
    config_name : str
        Configuration name to use. If empty, uses the first configuration.
    **variables
        Query variables.

    Returns
    -------
    list
        Query results.
    """
    if cppcheckdata is None:
        raise CCQLError("cppcheckdata module is required")
    data = cppcheckdata.parsedump(dump_path)
    for cfg in data.configurations:
        if not config_name or cfg.name == config_name:
            return CCQL(cfg)(query_str, **variables)
    raise CCQLError(f"Configuration '{config_name}' not found in {dump_path}")


def explain_query(query_str: str) -> str:
    """Parse and pretty-print a CCQL query plan (no configuration needed)."""
    plan = parse_query(query_str)
    return plan.pretty()


# ===================================================================
#  PART 11 — MODULE EXPORTS
# ===================================================================

__all__ = [
    # Exceptions
    "CCQLError", "CCQLSyntaxError", "CCQLRuntimeError",
    # Core engine
    "CCQL",
    # Query plan
    "QNode", "QNodeKind", "AxisKind", "parse_query",
    # Standalone helpers
    "query_config", "query_dump", "explain_query",
]
