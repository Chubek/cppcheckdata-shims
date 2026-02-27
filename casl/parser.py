"""casl/parser.py – S-expression → CASL/CSQL AST parser.

Converts the output of ``sexpdata.loads`` (nested Python lists,
:class:`sexpdata.Symbol`, strings, ints, floats, bools) into the typed
AST nodes defined in :mod:`casl.ast`.

Design principles
-----------------
* **Single-pass, recursive-descent** over the S-expression tree.
* **Head-symbol dispatch** – every list ``(tag ...)`` is dispatched on
  ``tag`` (a :class:`sexpdata.Symbol`) to a dedicated ``_parse_<tag>``
  helper.
* **Fail-fast with location** – ``ParseError`` carries an optional
  ``SourceLoc`` so the user sees *where* in the source file the
  problem occurred.
* **No implicit coercions** – the parser validates shapes strictly;
  anything unexpected is an error, *not* silently ignored.
* **Frozen-dataclass convention** – mirrors the ``@dataclass(frozen=True,
  slots=True)`` style used throughout the shims codebase.

Public API
----------
``parse_module(text: str) -> casl.ast.Module``
    Parse a complete CASL source string.

``parse_csql_query(text: str) -> casl.ast.CsqlQuery``
    Parse a standalone CSQL query string (useful for REPL/tests).

``parse_property(text: str) -> casl.ast.Property``
    Parse a standalone property string.

S-expression surface syntax (overview)
--------------------------------------
::

    ;; Module-level
    (module <name>
      (import <name> ...)
      (domain <name> <lattice-expr>)
      (query  <name> (<binding> ...) <source> <pred>?)
      (atom   <name> (<param> ...) <csql-pred>)
      (transfer <name> (<param> ...) <abstract-effect>)
      (property <name> <kind> <body>)
      (checker  <name> (<prop-ref> ...) <severity> <message>))

    ;; CSQL query parts
    (from <entity-kind>)
    (from <entity-kind> (in <scope-expr>))
    (bind <name> <type>)
    (and <pred> <pred>)          ;; conjunction
    (or  <pred> <pred>)          ;; disjunction
    (not <pred>)                 ;; negation
    (has-attr <attr-name>)
    (attr-eq <attr-name> <value>)
    (attr-match <attr-name> <regex>)
    (type-is <type-expr>)
    (in-scope <scope-expr>)
    (calls <callee-expr>)
    (called-by <caller-expr>)
    (reaches <target-expr>)
    (dominates <dominator-expr>)
    (custom <func-name> <arg> ...)

    ;; Property kinds
    (syntactic <csql-pred>)
    (dataflow <domain-ref> <entry-fact> <check-expr>)
    (ltl <ltl-formula>)
    (ctl <ctl-formula>)
    (safety <invariant-pred>)

    ;; LTL formulas
    (prop <atom-name> <arg> ...)
    (ltl-not <f>)
    (ltl-and <f> <f>)
    (ltl-or  <f> <f>)
    (ltl-implies <f> <f>)
    (X  <f>)
    (F  <f>)
    (G  <f>)
    (U  <f> <f>)
    (R  <f> <f>)
    (W  <f> <f>)

    ;; CTL formulas
    (ctl-not <f>)
    (ctl-and <f> <f>)
    (ctl-or  <f> <f>)
    (ctl-implies <f> <f>)
    (AX <f>)  (EX <f>)
    (AF <f>)  (EF <f>)
    (AG <f>)  (EG <f>)
    (AU <f> <f>)  (EU <f> <f>)

    ;; Severity
    error | warning | style | performance | portability | information
"""

from __future__ import annotations

import enum
import re
from dataclasses import dataclass, field
from typing import (
    Any,
    Callable,
    Dict,
    Final,
    List,
    Mapping,
    NoReturn,
    Optional,
    Sequence,
    Tuple,
    Type,
    Union,
)

# ---------------------------------------------------------------------------
# sexpdata import
# ---------------------------------------------------------------------------
try:
    import sexpdata
    from sexpdata import Symbol, Quoted
except ImportError:  # pragma: no cover – allow static analysis w/o dep
    raise ImportError(
        "The 'sexpdata' package is required for CASL parsing. "
        "Install it with:  pip install sexpdata"
    )

# ---------------------------------------------------------------------------
# AST import  (sibling module)
# ---------------------------------------------------------------------------
try:
    from . import ast as A
except ImportError:
    import ast as A  # type: ignore[no-redef]


# ═══════════════════════════════════════════════════════════════════════
#  Error types
# ═══════════════════════════════════════════════════════════════════════

@dataclass(frozen=True, slots=True)
class ParseError(Exception):
    """Raised when an S-expression cannot be mapped to a valid AST node."""

    message: str
    loc: Optional[A.SourceLoc] = None

    def __str__(self) -> str:
        if self.loc is not None:
            return f"{self.loc.file}:{self.loc.line}:{self.loc.col}: {self.message}"
        return self.message


# ═══════════════════════════════════════════════════════════════════════
#  Helpers
# ═══════════════════════════════════════════════════════════════════════

# Type aliases for raw sexpdata output
Sexp = Any  # Union[list, Symbol, str, int, float, bool]


def _sym_name(s: Sexp) -> str:
    """Extract the string name from a ``sexpdata.Symbol``, or raise."""
    if isinstance(s, Symbol):
        return s.value()
    raise ParseError(f"Expected symbol, got {type(s).__name__}: {s!r}")


def _expect_symbol(s: Sexp, expected: str) -> None:
    """Assert that *s* is a :class:`Symbol` with value *expected*."""
    name = _sym_name(s)
    if name != expected:
        raise ParseError(f"Expected symbol '{expected}', got '{name}'")


def _expect_list(s: Sexp, *, min_len: int = 0, tag: Optional[str] = None) -> list:
    """Assert that *s* is a list, optionally with a minimum length and head tag."""
    if not isinstance(s, list):
        raise ParseError(
            f"Expected list{f' ({tag} ...)' if tag else ''}, "
            f"got {type(s).__name__}: {s!r}"
        )
    if len(s) < min_len:
        raise ParseError(
            f"List too short: expected at least {min_len} elements, "
            f"got {len(s)}: {s!r}"
        )
    if tag is not None and (not s or _sym_name(s[0]) != tag):
        actual = _sym_name(s[0]) if s and isinstance(s[0], Symbol) else repr(s[0]) if s else "<empty>"
        raise ParseError(f"Expected ({tag} ...), got ({actual} ...)")
    return s


def _head(s: list) -> str:
    """Return the head symbol name of a list form ``(tag ...)``."""
    if not s:
        raise ParseError("Unexpected empty list")
    return _sym_name(s[0])


def _as_str(s: Sexp) -> str:
    """Coerce *s* to a Python ``str`` – accepts Symbol or string literal."""
    if isinstance(s, Symbol):
        return s.value()
    if isinstance(s, str):
        return s
    raise ParseError(f"Expected string or symbol, got {type(s).__name__}: {s!r}")


def _as_int(s: Sexp) -> int:
    if isinstance(s, int) and not isinstance(s, bool):
        return s
    raise ParseError(f"Expected integer, got {type(s).__name__}: {s!r}")


def _as_number(s: Sexp) -> Union[int, float]:
    if isinstance(s, (int, float)) and not isinstance(s, bool):
        return s
    raise ParseError(f"Expected number, got {type(s).__name__}: {s!r}")


def _as_bool(s: Sexp) -> bool:
    if isinstance(s, bool):
        return s
    # Also accept symbol true/false
    if isinstance(s, Symbol):
        v = s.value().lower()
        if v in ("true", "#t", "t"):
            return True
        if v in ("false", "#f", "nil"):
            return False
    raise ParseError(f"Expected boolean, got {type(s).__name__}: {s!r}")


# ═══════════════════════════════════════════════════════════════════════
#  Dispatch registry
# ═══════════════════════════════════════════════════════════════════════

# Maps a head-symbol string to a parser callable.
# Populated by the ``@_register`` decorator below.

_CSQL_PRED_DISPATCH: Dict[str, Callable[..., A.Predicate]] = {}
_LTL_DISPATCH: Dict[str, Callable[..., A.LTLFormula]] = {}
_CTL_DISPATCH: Dict[str, Callable[..., A.CTLFormula]] = {}
_MODULE_ITEM_DISPATCH: Dict[str, Callable[..., Any]] = {}


def _register(table: dict, tag: str):
    """Decorator: register a parser function under *tag* in *table*."""
    def deco(fn):
        table[tag] = fn
        return fn
    return deco


# ═══════════════════════════════════════════════════════════════════════
#  Source location tracking
# ═══════════════════════════════════════════════════════════════════════

_current_file: str = "<string>"


def _loc(line: int = 0, col: int = 0) -> A.SourceLoc:
    return A.SourceLoc(file=_current_file, line=line, col=col)


# ═══════════════════════════════════════════════════════════════════════
#  CSQL Predicate parsers
# ═══════════════════════════════════════════════════════════════════════

def parse_predicate(s: Sexp) -> A.Predicate:
    """Parse a CSQL predicate from a raw S-expression."""
    if isinstance(s, list) and s:
        tag = _head(s)
        parser = _CSQL_PRED_DISPATCH.get(tag)
        if parser is not None:
            return parser(s)
        raise ParseError(f"Unknown CSQL predicate form: ({tag} ...)")
    raise ParseError(f"Expected predicate form (tag ...), got: {s!r}")


@_register(_CSQL_PRED_DISPATCH, "and")
def _parse_pred_and(s: list) -> A.PredicateAnd:
    _expect_list(s, min_len=3)
    children = tuple(parse_predicate(c) for c in s[1:])
    return A.PredicateAnd(children=children)


@_register(_CSQL_PRED_DISPATCH, "or")
def _parse_pred_or(s: list) -> A.PredicateOr:
    _expect_list(s, min_len=3)
    children = tuple(parse_predicate(c) for c in s[1:])
    return A.PredicateOr(children=children)


@_register(_CSQL_PRED_DISPATCH, "not")
def _parse_pred_not(s: list) -> A.PredicateNot:
    _expect_list(s, min_len=2)
    inner = parse_predicate(s[1])
    return A.PredicateNot(inner=inner)


@_register(_CSQL_PRED_DISPATCH, "has-attr")
def _parse_has_attr(s: list) -> A.PredicateHasAttr:
    _expect_list(s, min_len=2)
    attr = _as_str(s[1])
    return A.PredicateHasAttr(attr_name=attr)


@_register(_CSQL_PRED_DISPATCH, "attr-eq")
def _parse_attr_eq(s: list) -> A.PredicateAttrEq:
    _expect_list(s, min_len=3)
    attr = _as_str(s[1])
    value = _as_str(s[2])
    return A.PredicateAttrEq(attr_name=attr, value=value)


@_register(_CSQL_PRED_DISPATCH, "attr-match")
def _parse_attr_match(s: list) -> A.PredicateAttrMatch:
    _expect_list(s, min_len=3)
    attr = _as_str(s[1])
    pattern = _as_str(s[2])
    # Validate regex at parse time
    try:
        re.compile(pattern)
    except re.error as e:
        raise ParseError(f"Invalid regex in attr-match: {pattern!r}: {e}")
    return A.PredicateAttrMatch(attr_name=attr, pattern=pattern)


@_register(_CSQL_PRED_DISPATCH, "type-is")
def _parse_type_is(s: list) -> A.PredicateTypeIs:
    _expect_list(s, min_len=2)
    type_expr = _as_str(s[1])
    return A.PredicateTypeIs(type_expr=type_expr)


@_register(_CSQL_PRED_DISPATCH, "in-scope")
def _parse_in_scope(s: list) -> A.PredicateInScope:
    _expect_list(s, min_len=2)
    scope_expr = _as_str(s[1])
    return A.PredicateInScope(scope_expr=scope_expr)


@_register(_CSQL_PRED_DISPATCH, "calls")
def _parse_calls(s: list) -> A.PredicateCalls:
    _expect_list(s, min_len=2)
    callee = _as_str(s[1])
    return A.PredicateCalls(callee=callee)


@_register(_CSQL_PRED_DISPATCH, "called-by")
def _parse_called_by(s: list) -> A.PredicateCalledBy:
    _expect_list(s, min_len=2)
    caller = _as_str(s[1])
    return A.PredicateCalledBy(caller=caller)


@_register(_CSQL_PRED_DISPATCH, "reaches")
def _parse_reaches(s: list) -> A.PredicateReaches:
    _expect_list(s, min_len=2)
    target = _as_str(s[1])
    return A.PredicateReaches(target=target)


@_register(_CSQL_PRED_DISPATCH, "dominates")
def _parse_dominates(s: list) -> A.PredicateDominates:
    _expect_list(s, min_len=2)
    dominator = _as_str(s[1])
    return A.PredicateDominates(dominator=dominator)


@_register(_CSQL_PRED_DISPATCH, "custom")
def _parse_custom_pred(s: list) -> A.PredicateCustom:
    _expect_list(s, min_len=2)
    func_name = _as_str(s[1])
    args = tuple(_as_str(a) for a in s[2:])
    return A.PredicateCustom(func_name=func_name, args=args)


# ═══════════════════════════════════════════════════════════════════════
#  CSQL entity source & binding
# ═══════════════════════════════════════════════════════════════════════

def _parse_entity_kind(s: Sexp) -> A.EntityKind:
    """Parse an entity kind symbol into the enum."""
    name = _as_str(s)
    try:
        return A.EntityKind(name)
    except ValueError:
        # Try case-insensitive lookup
        for member in A.EntityKind:
            if member.value.lower() == name.lower():
                return member
        raise ParseError(
            f"Unknown entity kind: {name!r}. "
            f"Expected one of: {[e.value for e in A.EntityKind]}"
        )


def _parse_entity_source(s: Sexp) -> A.EntitySource:
    """Parse ``(from <kind>)`` or ``(from <kind> (in <scope>))``."""
    lst = _expect_list(s, min_len=2, tag="from")
    kind = _parse_entity_kind(lst[1])
    scope: Optional[str] = None
    if len(lst) >= 3:
        scope_form = _expect_list(lst[2], min_len=2, tag="in")
        scope = _as_str(scope_form[1])
    return A.EntitySource(kind=kind, scope=scope)


def _parse_binding(s: Sexp) -> A.BindingDecl:
    """Parse ``(bind <name> <type>)``."""
    lst = _expect_list(s, min_len=3, tag="bind")
    name = _as_str(lst[1])
    bind_type = _as_str(lst[2])
    return A.BindingDecl(name=name, bind_type=bind_type)


def _parse_bindings(s: Sexp) -> Tuple[A.BindingDecl, ...]:
    """Parse a list of bindings ``((bind n t) ...)``."""
    lst = _expect_list(s)
    return tuple(_parse_binding(b) for b in lst)


# ═══════════════════════════════════════════════════════════════════════
#  CSQL Query
# ═══════════════════════════════════════════════════════════════════════

def _parse_csql_query(s: Sexp) -> A.CsqlQuery:
    """Parse ``(query <name> (<bindings>) <source> [<pred>])``."""
    lst = _expect_list(s, min_len=4, tag="query")
    name = _as_str(lst[1])
    bindings = _parse_bindings(lst[2])
    source = _parse_entity_source(lst[3])
    predicate: Optional[A.Predicate] = None
    if len(lst) >= 5:
        predicate = parse_predicate(lst[4])
    return A.CsqlQuery(
        name=name,
        bindings=bindings,
        source=source,
        predicate=predicate,
        loc=_loc(),
    )


def parse_csql_query(text: str) -> A.CsqlQuery:
    """Public API: parse a standalone CSQL query from a string.

    >>> parse_csql_query('(query find-null-deref ((bind v variable)) (from variable) (type-is "int*"))')
    """
    sexps = sexpdata.loads(text, nil=None, true=None, false=None)
    return _parse_csql_query(sexps)


# ═══════════════════════════════════════════════════════════════════════
#  LTL formula parsers
# ═══════════════════════════════════════════════════════════════════════

def parse_ltl(s: Sexp) -> A.LTLFormula:
    """Parse an LTL formula from a raw S-expression."""
    # Bare symbol → treat as prop atom with no args
    if isinstance(s, Symbol):
        return A.PropAtom(name=s.value(), args=())

    if isinstance(s, list) and s:
        tag = _head(s)
        parser = _LTL_DISPATCH.get(tag)
        if parser is not None:
            return parser(s)
        raise ParseError(f"Unknown LTL formula form: ({tag} ...)")
    raise ParseError(f"Expected LTL formula, got: {s!r}")


@_register(_LTL_DISPATCH, "prop")
def _parse_ltl_prop(s: list) -> A.PropAtom:
    _expect_list(s, min_len=2)
    name = _as_str(s[1])
    args = tuple(_as_str(a) for a in s[2:])
    return A.PropAtom(name=name, args=args)


@_register(_LTL_DISPATCH, "ltl-true")
def _parse_ltl_true(s: list) -> A.LTLTrue:
    return A.LTLTrue()


@_register(_LTL_DISPATCH, "ltl-false")
def _parse_ltl_false(s: list) -> A.LTLFalse:
    return A.LTLFalse()


@_register(_LTL_DISPATCH, "ltl-not")
def _parse_ltl_not(s: list) -> A.LTLNot:
    _expect_list(s, min_len=2)
    return A.LTLNot(inner=parse_ltl(s[1]))


@_register(_LTL_DISPATCH, "ltl-and")
def _parse_ltl_and(s: list) -> A.LTLAnd:
    _expect_list(s, min_len=3)
    return A.LTLAnd(left=parse_ltl(s[1]), right=parse_ltl(s[2]))


@_register(_LTL_DISPATCH, "ltl-or")
def _parse_ltl_or(s: list) -> A.LTLOr:
    _expect_list(s, min_len=3)
    return A.LTLOr(left=parse_ltl(s[1]), right=parse_ltl(s[2]))


@_register(_LTL_DISPATCH, "ltl-implies")
def _parse_ltl_implies(s: list) -> A.LTLImplies:
    _expect_list(s, min_len=3)
    return A.LTLImplies(left=parse_ltl(s[1]), right=parse_ltl(s[2]))


@_register(_LTL_DISPATCH, "X")
def _parse_ltl_next(s: list) -> A.LTLNext:
    _expect_list(s, min_len=2)
    return A.LTLNext(inner=parse_ltl(s[1]))


@_register(_LTL_DISPATCH, "F")
def _parse_ltl_finally(s: list) -> A.LTLFinally:
    _expect_list(s, min_len=2)
    return A.LTLFinally(inner=parse_ltl(s[1]))


@_register(_LTL_DISPATCH, "G")
def _parse_ltl_globally(s: list) -> A.LTLGlobally:
    _expect_list(s, min_len=2)
    return A.LTLGlobally(inner=parse_ltl(s[1]))


@_register(_LTL_DISPATCH, "U")
def _parse_ltl_until(s: list) -> A.LTLUntil:
    _expect_list(s, min_len=3)
    return A.LTLUntil(left=parse_ltl(s[1]), right=parse_ltl(s[2]))


@_register(_LTL_DISPATCH, "R")
def _parse_ltl_release(s: list) -> A.LTLRelease:
    _expect_list(s, min_len=3)
    return A.LTLRelease(left=parse_ltl(s[1]), right=parse_ltl(s[2]))


@_register(_LTL_DISPATCH, "W")
def _parse_ltl_weak_until(s: list) -> A.LTLWeakUntil:
    _expect_list(s, min_len=3)
    return A.LTLWeakUntil(left=parse_ltl(s[1]), right=parse_ltl(s[2]))


# ═══════════════════════════════════════════════════════════════════════
#  CTL formula parsers
# ═══════════════════════════════════════════════════════════════════════

def parse_ctl(s: Sexp) -> A.CTLFormula:
    """Parse a CTL formula from a raw S-expression."""
    # Bare symbol → prop atom
    if isinstance(s, Symbol):
        return A.PropAtom(name=s.value(), args=())

    if isinstance(s, list) and s:
        tag = _head(s)
        # PropAtom is shared between LTL and CTL
        if tag == "prop":
            return _parse_ltl_prop(s)
        parser = _CTL_DISPATCH.get(tag)
        if parser is not None:
            return parser(s)
        raise ParseError(f"Unknown CTL formula form: ({tag} ...)")
    raise ParseError(f"Expected CTL formula, got: {s!r}")


@_register(_CTL_DISPATCH, "ctl-true")
def _parse_ctl_true(s: list) -> A.CTLTrue:
    return A.CTLTrue()


@_register(_CTL_DISPATCH, "ctl-false")
def _parse_ctl_false(s: list) -> A.CTLFalse:
    return A.CTLFalse()


@_register(_CTL_DISPATCH, "ctl-not")
def _parse_ctl_not(s: list) -> A.CTLNot:
    _expect_list(s, min_len=2)
    return A.CTLNot(inner=parse_ctl(s[1]))


@_register(_CTL_DISPATCH, "ctl-and")
def _parse_ctl_and(s: list) -> A.CTLAnd:
    _expect_list(s, min_len=3)
    return A.CTLAnd(left=parse_ctl(s[1]), right=parse_ctl(s[2]))


@_register(_CTL_DISPATCH, "ctl-or")
def _parse_ctl_or(s: list) -> A.CTLOr:
    _expect_list(s, min_len=3)
    return A.CTLOr(left=parse_ctl(s[1]), right=parse_ctl(s[2]))


@_register(_CTL_DISPATCH, "ctl-implies")
def _parse_ctl_implies(s: list) -> A.CTLImplies:
    _expect_list(s, min_len=3)
    return A.CTLImplies(left=parse_ctl(s[1]), right=parse_ctl(s[2]))


@_register(_CTL_DISPATCH, "AX")
def _parse_ctl_ax(s: list) -> A.CTLAX:
    _expect_list(s, min_len=2)
    return A.CTLAX(inner=parse_ctl(s[1]))


@_register(_CTL_DISPATCH, "EX")
def _parse_ctl_ex(s: list) -> A.CTLEX:
    _expect_list(s, min_len=2)
    return A.CTLEX(inner=parse_ctl(s[1]))


@_register(_CTL_DISPATCH, "AF")
def _parse_ctl_af(s: list) -> A.CTLAF:
    _expect_list(s, min_len=2)
    return A.CTLAF(inner=parse_ctl(s[1]))


@_register(_CTL_DISPATCH, "EF")
def _parse_ctl_ef(s: list) -> A.CTLEF:
    _expect_list(s, min_len=2)
    return A.CTLEF(inner=parse_ctl(s[1]))


@_register(_CTL_DISPATCH, "AG")
def _parse_ctl_ag(s: list) -> A.CTLAG:
    _expect_list(s, min_len=2)
    return A.CTLAG(inner=parse_ctl(s[1]))


@_register(_CTL_DISPATCH, "EG")
def _parse_ctl_eg(s: list) -> A.CTLEG:
    _expect_list(s, min_len=2)
    return A.CTLEG(inner=parse_ctl(s[1]))


@_register(_CTL_DISPATCH, "AU")
def _parse_ctl_au(s: list) -> A.CTLAU:
    _expect_list(s, min_len=3)
    return A.CTLAU(left=parse_ctl(s[1]), right=parse_ctl(s[2]))


@_register(_CTL_DISPATCH, "EU")
def _parse_ctl_eu(s: list) -> A.CTLEU:
    _expect_list(s, min_len=3)
    return A.CTLEU(left=parse_ctl(s[1]), right=parse_ctl(s[2]))


# ═══════════════════════════════════════════════════════════════════════
#  Property body parsers
# ═══════════════════════════════════════════════════════════════════════

def _parse_severity(s: Sexp) -> A.Severity:
    """Parse a severity symbol."""
    name = _as_str(s)
    try:
        return A.Severity(name)
    except ValueError:
        for member in A.Severity:
            if member.value.lower() == name.lower():
                return member
        raise ParseError(
            f"Unknown severity: {name!r}. "
            f"Expected one of: {[e.value for e in A.Severity]}"
        )


def _parse_property_body(kind_sym: str, rest: list) -> A.Property:
    """Parse the body of a property given its kind tag and remaining elements.

    Dispatches on ``kind_sym`` to produce the right ``Property`` variant.
    """
    if kind_sym == "syntactic":
        if not rest:
            raise ParseError("(syntactic) requires a predicate body")
        pred = parse_predicate(rest[0])
        return A.PropertySyntactic(predicate=pred)

    elif kind_sym == "dataflow":
        if len(rest) < 3:
            raise ParseError(
                "(dataflow <domain> <entry-fact> <check>) requires 3 arguments"
            )
        domain_ref = _as_str(rest[0])
        entry_fact = _as_str(rest[1])
        check_expr = _as_str(rest[2])
        return A.PropertyDataflow(
            domain_ref=domain_ref,
            entry_fact=entry_fact,
            check_expr=check_expr,
        )

    elif kind_sym == "ltl":
        if not rest:
            raise ParseError("(ltl) requires a formula body")
        formula = parse_ltl(rest[0])
        return A.PropertyLTL(formula=formula)

    elif kind_sym == "ctl":
        if not rest:
            raise ParseError("(ctl) requires a formula body")
        formula = parse_ctl(rest[0])
        return A.PropertyCTL(formula=formula)

    elif kind_sym == "safety":
        if not rest:
            raise ParseError("(safety) requires an invariant predicate")
        invariant = parse_predicate(rest[0])
        return A.PropertySafety(invariant=invariant)

    else:
        raise ParseError(f"Unknown property kind: {kind_sym!r}")


# ═══════════════════════════════════════════════════════════════════════
#  Lattice / domain expression parser
# ═══════════════════════════════════════════════════════════════════════

def _parse_lattice_expr(s: Sexp) -> A.LatticeExpr:
    """Parse a lattice expression for domain declarations.

    Accepts:
    - bare symbol → ``LatticeRef(name)``
    - ``(product <l1> <l2> ...)`` → ``LatticeProduct(...)``
    - ``(powerset <l>)`` → ``LatticePowerset(...)``
    - ``(map <key-type> <l>)`` → ``LatticeMap(...)``
    - ``(flat <base-type>)`` → ``LatticeFlat(...)``
    """
    if isinstance(s, Symbol):
        return A.LatticeRef(name=s.value())

    if isinstance(s, str):
        return A.LatticeRef(name=s)

    lst = _expect_list(s, min_len=1)
    tag = _head(lst)

    if tag == "product":
        _expect_list(lst, min_len=3)
        components = tuple(_parse_lattice_expr(c) for c in lst[1:])
        return A.LatticeProduct(components=components)

    elif tag == "powerset":
        _expect_list(lst, min_len=2)
        return A.LatticePowerset(base=_parse_lattice_expr(lst[1]))

    elif tag == "map":
        _expect_list(lst, min_len=3)
        key_type = _as_str(lst[1])
        value_lattice = _parse_lattice_expr(lst[2])
        return A.LatticeMap(key_type=key_type, value_lattice=value_lattice)

    elif tag == "flat":
        _expect_list(lst, min_len=2)
        base_type = _as_str(lst[1])
        return A.LatticeFlat(base_type=base_type)

    else:
        raise ParseError(f"Unknown lattice expression form: ({tag} ...)")


# ═══════════════════════════════════════════════════════════════════════
#  Abstract transfer effect parser
# ═══════════════════════════════════════════════════════════════════════

def _parse_abstract_effect(s: Sexp) -> A.AbstractEffect:
    """Parse an abstract effect expression for transfer declarations.

    Accepts:
    - ``(assign <var> <expr>)`` → variable update
    - ``(join <effect1> <effect2>)`` → join of effects
    - ``(seq <effect1> <effect2> ...)`` → sequential composition
    - ``(identity)`` → identity transfer
    - ``(call <func> <arg> ...)`` → call a helper
    - bare string/symbol → shorthand for ``(call <name>)``
    """
    if isinstance(s, (Symbol, str)):
        return A.AbstractEffectCall(func_name=_as_str(s), args=())

    lst = _expect_list(s, min_len=1)
    tag = _head(lst)

    if tag == "assign":
        _expect_list(lst, min_len=3)
        var = _as_str(lst[1])
        expr = _as_str(lst[2])
        return A.AbstractEffectAssign(var=var, expr=expr)

    elif tag == "join":
        _expect_list(lst, min_len=3)
        effects = tuple(_parse_abstract_effect(e) for e in lst[1:])
        return A.AbstractEffectJoin(effects=effects)

    elif tag == "seq":
        _expect_list(lst, min_len=2)
        effects = tuple(_parse_abstract_effect(e) for e in lst[1:])
        return A.AbstractEffectSeq(effects=effects)

    elif tag == "identity":
        return A.AbstractEffectIdentity()

    elif tag == "call":
        _expect_list(lst, min_len=2)
        func_name = _as_str(lst[1])
        args = tuple(_as_str(a) for a in lst[2:])
        return A.AbstractEffectCall(func_name=func_name, args=args)

    else:
        raise ParseError(f"Unknown abstract effect form: ({tag} ...)")


# ═══════════════════════════════════════════════════════════════════════
#  Module-level item parsers
# ═══════════════════════════════════════════════════════════════════════

@_register(_MODULE_ITEM_DISPATCH, "import")
def _parse_import(s: list) -> A.ImportDecl:
    """Parse ``(import <name> ...)``."""
    _expect_list(s, min_len=2, tag="import")
    names = tuple(_as_str(n) for n in s[1:])
    return A.ImportDecl(names=names, loc=_loc())


@_register(_MODULE_ITEM_DISPATCH, "domain")
def _parse_domain(s: list) -> A.DomainDecl:
    """Parse ``(domain <name> <lattice-expr>)``."""
    _expect_list(s, min_len=3, tag="domain")
    name = _as_str(s[1])
    lattice = _parse_lattice_expr(s[2])
    return A.DomainDecl(name=name, lattice=lattice, loc=_loc())


@_register(_MODULE_ITEM_DISPATCH, "query")
def _parse_query_item(s: list) -> A.CsqlQuery:
    """Parse ``(query <name> (<bindings>) <source> [<pred>])``."""
    return _parse_csql_query(s)


@_register(_MODULE_ITEM_DISPATCH, "atom")
def _parse_atom(s: list) -> A.PropAtomDecl:
    """Parse ``(atom <name> (<param> ...) <csql-pred>)``."""
    _expect_list(s, min_len=4, tag="atom")
    name = _as_str(s[1])
    params_list = _expect_list(s[2])
    params = tuple(_as_str(p) for p in params_list)
    predicate = parse_predicate(s[3])
    return A.PropAtomDecl(name=name, params=params, predicate=predicate, loc=_loc())


@_register(_MODULE_ITEM_DISPATCH, "transfer")
def _parse_transfer(s: list) -> A.TransferDecl:
    """Parse ``(transfer <name> (<param> ...) <abstract-effect>)``."""
    _expect_list(s, min_len=4, tag="transfer")
    name = _as_str(s[1])
    params_list = _expect_list(s[2])
    params = tuple(_as_str(p) for p in params_list)
    effect = _parse_abstract_effect(s[3])
    return A.TransferDecl(name=name, params=params, effect=effect, loc=_loc())


@_register(_MODULE_ITEM_DISPATCH, "property")
def _parse_property_decl(s: list) -> A.PropertyDecl:
    """Parse ``(property <name> (<kind> <body...>))``."""
    _expect_list(s, min_len=3, tag="property")
    name = _as_str(s[1])
    body_form = _expect_list(s[2], min_len=1)
    kind_sym = _head(body_form)
    prop = _parse_property_body(kind_sym, body_form[1:])
    return A.PropertyDecl(name=name, body=prop, loc=_loc())


@_register(_MODULE_ITEM_DISPATCH, "checker")
def _parse_checker(s: list) -> A.CheckerDecl:
    """Parse ``(checker <name> (<prop-ref> ...) <severity> <message>)``."""
    _expect_list(s, min_len=5, tag="checker")
    name = _as_str(s[1])
    props_list = _expect_list(s[2])
    prop_refs = tuple(_as_str(p) for p in props_list)
    severity = _parse_severity(s[3])
    message = _as_str(s[4])
    return A.CheckerDecl(
        name=name,
        prop_refs=prop_refs,
        severity=severity,
        message=message,
        loc=_loc(),
    )


# ═══════════════════════════════════════════════════════════════════════
#  Module parser
# ═══════════════════════════════════════════════════════════════════════

def _parse_module_from_sexp(s: Sexp) -> A.Module:
    """Parse a ``(module <name> <item>...)`` S-expression into a Module AST."""
    lst = _expect_list(s, min_len=2, tag="module")
    name = _as_str(lst[1])

    imports: list[A.ImportDecl] = []
    domains: list[A.DomainDecl] = []
    queries: list[A.CsqlQuery] = []
    atoms: list[A.PropAtomDecl] = []
    transfers: list[A.TransferDecl] = []
    properties: list[A.PropertyDecl] = []
    checkers: list[A.CheckerDecl] = []

    for item_sexp in lst[2:]:
        if not isinstance(item_sexp, list) or not item_sexp:
            raise ParseError(f"Expected module item (tag ...), got: {item_sexp!r}")

        tag = _head(item_sexp)
        parser = _MODULE_ITEM_DISPATCH.get(tag)
        if parser is None:
            raise ParseError(
                f"Unknown module-level form: ({tag} ...). "
                f"Expected one of: {sorted(_MODULE_ITEM_DISPATCH.keys())}"
            )

        node = parser(item_sexp)

        # Route to the appropriate collection
        if isinstance(node, A.ImportDecl):
            imports.append(node)
        elif isinstance(node, A.DomainDecl):
            domains.append(node)
        elif isinstance(node, A.CsqlQuery):
            queries.append(node)
        elif isinstance(node, A.PropAtomDecl):
            atoms.append(node)
        elif isinstance(node, A.TransferDecl):
            transfers.append(node)
        elif isinstance(node, A.PropertyDecl):
            properties.append(node)
        elif isinstance(node, A.CheckerDecl):
            checkers.append(node)
        else:
            raise ParseError(f"Internal error: unhandled node type {type(node)}")

    return A.Module(
        name=name,
        imports=tuple(imports),
        domains=tuple(domains),
        queries=tuple(queries),
        atoms=tuple(atoms),
        transfers=tuple(transfers),
        properties=tuple(properties),
        checkers=tuple(checkers),
        loc=_loc(),
    )


def parse_module(text: str, *, filename: str = "<string>") -> A.Module:
    """Parse a complete CASL module from an S-expression string.

    Parameters
    ----------
    text:
        The full CASL source text (S-expression syntax).
    filename:
        The filename to use for error messages and ``SourceLoc`` tracking.

    Returns
    -------
    A.Module
        The fully-parsed AST root node.

    Raises
    ------
    ParseError
        If the input is malformed or contains unrecognized forms.

    Example
    -------
    >>> src = '''
    ... (module null-deref-checker
    ...   (import cppcheckdata-shims)
    ...
    ...   (domain sign-domain sign-lattice)
    ...
    ...   (query find-ptrs
    ...     ((bind p variable))
    ...     (from variable)
    ...     (type-is ".*\\\\*"))
    ...
    ...   (atom is-null (p)
    ...     (attr-eq "value" "0"))
    ...
    ...   (atom is-deref (p)
    ...     (has-attr "astOperand1"))
    ...
    ...   (transfer assign-null (p)
    ...     (assign "abstract-val" "bottom"))
    ...
    ...   (property no-null-deref
    ...     (ltl (G (ltl-implies (prop is-null p) (ltl-not (F (prop is-deref p)))))))
    ...
    ...   (checker null-deref
    ...     (no-null-deref) error "Potential null pointer dereference"))
    ... '''
    >>> mod = parse_module(src, filename="null_deref.casl")
    >>> mod.name
    'null-deref-checker'
    >>> len(mod.properties)
    1
    """
    global _current_file
    _current_file = filename

    # sexpdata configuration: disable nil/true/false auto-mapping so
    # that Symbols like "nil", "t" are preserved as-is for our own
    # interpretation.
    try:
        raw = sexpdata.loads(text, nil=None, true=None, false=None)
    except Exception as e:
        raise ParseError(f"S-expression syntax error: {e}")

    return _parse_module_from_sexp(raw)


def parse_property(text: str) -> A.PropertyDecl:
    """Public API: parse a standalone property declaration from a string.

    >>> parse_property('(property p1 (syntactic (has-attr "isPointer")))')
    """
    raw = sexpdata.loads(text, nil=None, true=None, false=None)
    return _parse_property_decl(raw)


# ═══════════════════════════════════════════════════════════════════════
#  Multi-module / file parsing
# ═══════════════════════════════════════════════════════════════════════

def parse_file(path: str) -> A.Module:
    """Read and parse a ``.casl`` file into a Module AST.

    Parameters
    ----------
    path:
        Filesystem path to the CASL source file.

    Returns
    -------
    A.Module
    """
    import pathlib
    p = pathlib.Path(path)
    text = p.read_text(encoding="utf-8")
    return parse_module(text, filename=str(p))


def parse_string(text: str, *, filename: str = "<string>") -> A.Module:
    """Alias for :func:`parse_module` for discoverability."""
    return parse_module(text, filename=filename)


# ═══════════════════════════════════════════════════════════════════════
#  Roundtrip support: AST → S-expression string (for testing/debugging)
# ═══════════════════════════════════════════════════════════════════════

class Unparser:
    """Convert AST nodes back to S-expression strings.

    This is primarily useful for testing roundtrip correctness:
    ``parse(unparse(node)) == node``.
    """

    def __init__(self) -> None:
        self._indent: int = 0
        self._parts: list[str] = []

    def _emit(self, s: str) -> None:
        self._parts.append(s)

    def _nl(self) -> None:
        self._parts.append("\n" + "  " * self._indent)

    def unparse_module(self, mod: A.Module) -> str:
        self._parts = []
        self._emit(f"(module {mod.name}")
        self._indent += 1

        for imp in mod.imports:
            self._nl()
            names = " ".join(imp.names)
            self._emit(f"(import {names})")

        for dom in mod.domains:
            self._nl()
            self._emit(f"(domain {dom.name} {self._unparse_lattice(dom.lattice)})")

        for q in mod.queries:
            self._nl()
            self._unparse_query(q)

        for atom in mod.atoms:
            self._nl()
            params = " ".join(atom.params)
            pred = self._unparse_pred(atom.predicate)
            self._emit(f"(atom {atom.name} ({params}) {pred})")

        for tr in mod.transfers:
            self._nl()
            params = " ".join(tr.params)
            effect = self._unparse_effect(tr.effect)
            self._emit(f"(transfer {tr.name} ({params}) {effect})")

        for prop in mod.properties:
            self._nl()
            body = self._unparse_property_body(prop.body)
            self._emit(f"(property {prop.name} {body})")

        for ch in mod.checkers:
            self._nl()
            props = " ".join(ch.prop_refs)
            self._emit(
                f'(checker {ch.name} ({props}) '
                f'{ch.severity.value} "{ch.message}")'
            )

        self._emit(")")
        self._indent -= 1
        return "".join(self._parts)

    def _unparse_query(self, q: A.CsqlQuery) -> None:
        binds = " ".join(f"(bind {b.name} {b.bind_type})" for b in q.bindings)
        src = f"(from {q.source.kind.value}"
        if q.source.scope is not None:
            src += f" (in {q.source.scope})"
        src += ")"
        parts = [f"(query {q.name} ({binds}) {src}"]
        if q.predicate is not None:
            parts.append(f" {self._unparse_pred(q.predicate)}")
        parts.append(")")
        self._emit("".join(parts))

    def _unparse_pred(self, p: A.Predicate) -> str:
        if isinstance(p, A.PredicateAnd):
            children = " ".join(self._unparse_pred(c) for c in p.children)
            return f"(and {children})"
        elif isinstance(p, A.PredicateOr):
            children = " ".join(self._unparse_pred(c) for c in p.children)
            return f"(or {children})"
        elif isinstance(p, A.PredicateNot):
            return f"(not {self._unparse_pred(p.inner)})"
        elif isinstance(p, A.PredicateHasAttr):
            return f'(has-attr "{p.attr_name}")'
        elif isinstance(p, A.PredicateAttrEq):
            return f'(attr-eq "{p.attr_name}" "{p.value}")'
        elif isinstance(p, A.PredicateAttrMatch):
            return f'(attr-match "{p.attr_name}" "{p.pattern}")'
        elif isinstance(p, A.PredicateTypeIs):
            return f'(type-is "{p.type_expr}")'
        elif isinstance(p, A.PredicateInScope):
            return f"(in-scope {p.scope_expr})"
        elif isinstance(p, A.PredicateCalls):
            return f"(calls {p.callee})"
        elif isinstance(p, A.PredicateCalledBy):
            return f"(called-by {p.caller})"
        elif isinstance(p, A.PredicateReaches):
            return f"(reaches {p.target})"
        elif isinstance(p, A.PredicateDominates):
            return f"(dominates {p.dominator})"
        elif isinstance(p, A.PredicateCustom):
            args = " ".join(p.args)
            return f"(custom {p.func_name} {args})" if args else f"(custom {p.func_name})"
        else:
            return f"<unknown-pred:{type(p).__name__}>"

    def _unparse_lattice(self, l: A.LatticeExpr) -> str:
        if isinstance(l, A.LatticeRef):
            return l.name
        elif isinstance(l, A.LatticeProduct):
            components = " ".join(self._unparse_lattice(c) for c in l.components)
            return f"(product {components})"
        elif isinstance(l, A.LatticePowerset):
            return f"(powerset {self._unparse_lattice(l.base)})"
        elif isinstance(l, A.LatticeMap):
            return f"(map {l.key_type} {self._unparse_lattice(l.value_lattice)})"
        elif isinstance(l, A.LatticeFlat):
            return f"(flat {l.base_type})"
        else:
            return f"<unknown-lattice:{type(l).__name__}>"

    def _unparse_effect(self, e: A.AbstractEffect) -> str:
        if isinstance(e, A.AbstractEffectAssign):
            return f'(assign "{e.var}" "{e.expr}")'
        elif isinstance(e, A.AbstractEffectJoin):
            effects = " ".join(self._unparse_effect(x) for x in e.effects)
            return f"(join {effects})"
        elif isinstance(e, A.AbstractEffectSeq):
            effects = " ".join(self._unparse_effect(x) for x in e.effects)
            return f"(seq {effects})"
        elif isinstance(e, A.AbstractEffectIdentity):
            return "(identity)"
        elif isinstance(e, A.AbstractEffectCall):
            args = " ".join(e.args)
            return f"(call {e.func_name} {args})" if args else f"(call {e.func_name})"
        else:
            return f"<unknown-effect:{type(e).__name__}>"

    def _unparse_ltl(self, f: A.LTLFormula) -> str:
        if isinstance(f, A.PropAtom):
            args = " ".join(f.args)
            return f"(prop {f.name} {args})" if args else f"(prop {f.name})"
        elif isinstance(f, A.LTLTrue):
            return "(ltl-true)"
        elif isinstance(f, A.LTLFalse):
            return "(ltl-false)"
        elif isinstance(f, A.LTLNot):
            return f"(ltl-not {self._unparse_ltl(f.inner)})"
        elif isinstance(f, A.LTLAnd):
            return f"(ltl-and {self._unparse_ltl(f.left)} {self._unparse_ltl(f.right)})"
        elif isinstance(f, A.LTLOr):
            return f"(ltl-or {self._unparse_ltl(f.left)} {self._unparse_ltl(f.right)})"
        elif isinstance(f, A.LTLImplies):
            return f"(ltl-implies {self._unparse_ltl(f.left)} {self._unparse_ltl(f.right)})"
        elif isinstance(f, A.LTLNext):
            return f"(X {self._unparse_ltl(f.inner)})"
        elif isinstance(f, A.LTLFinally):
            return f"(F {self._unparse_ltl(f.inner)})"
        elif isinstance(f, A.LTLGlobally):
            return f"(G {self._unparse_ltl(f.inner)})"
        elif isinstance(f, A.LTLUntil):
            return f"(U {self._unparse_ltl(f.left)} {self._unparse_ltl(f.right)})"
        elif isinstance(f, A.LTLRelease):
            return f"(R {self._unparse_ltl(f.left)} {self._unparse_ltl(f.right)})"
        elif isinstance(f, A.LTLWeakUntil):
            return f"(W {self._unparse_ltl(f.left)} {self._unparse_ltl(f.right)})"
        else:
            return f"<unknown-ltl:{type(f).__name__}>"

    def _unparse_ctl(self, f: A.CTLFormula) -> str:
        if isinstance(f, A.PropAtom):
            args = " ".join(f.args)
            return f"(prop {f.name} {args})" if args else f"(prop {f.name})"
        elif isinstance(f, A.CTLTrue):
            return "(ctl-true)"
        elif isinstance(f, A.CTLFalse):
            return "(ctl-false)"
        elif isinstance(f, A.CTLNot):
            return f"(ctl-not {self._unparse_ctl(f.inner)})"
        elif isinstance(f, A.CTLAnd):
            return f"(ctl-and {self._unparse_ctl(f.left)} {self._unparse_ctl(f.right)})"
        elif isinstance(f, A.CTLOr):
            return f"(ctl-or {self._unparse_ctl(f.left)} {self._unparse_ctl(f.right)})"
        elif isinstance(f, A.CTLImplies):
            return f"(ctl-implies {self._unparse_ctl(f.left)} {self._unparse_ctl(f.right)})"
        elif isinstance(f, A.CTLAX):
            return f"(AX {self._unparse_ctl(f.inner)})"
        elif isinstance(f, A.CTLEX):
            return f"(EX {self._unparse_ctl(f.inner)})"
        elif isinstance(f, A.CTLAF):
            return f"(AF {self._unparse_ctl(f.inner)})"
        elif isinstance(f, A.CTLEF):
            return f"(EF {self._unparse_ctl(f.inner)})"
        elif isinstance(f, A.CTLAG):
            return f"(AG {self._unparse_ctl(f.inner)})"
        elif isinstance(f, A.CTLEG):
            return f"(EG {self._unparse_ctl(f.inner)})"
        elif isinstance(f, A.CTLAU):
            return f"(AU {self._unparse_ctl(f.left)} {self._unparse_ctl(f.right)})"
        elif isinstance(f, A.CTLEU):
            return f"(EU {self._unparse_ctl(f.left)} {self._unparse_ctl(f.right)})"
        else:
            return f"<unknown-ctl:{type(f).__name__}>"

    def _unparse_property_body(self, p: A.Property) -> str:
        if isinstance(p, A.PropertySyntactic):
            return f"(syntactic {self._unparse_pred(p.predicate)})"
        elif isinstance(p, A.PropertyDataflow):
            return f'(dataflow {p.domain_ref} "{p.entry_fact}" "{p.check_expr}")'
        elif isinstance(p, A.PropertyLTL):
            return f"(ltl {self._unparse_ltl(p.formula)})"
        elif isinstance(p, A.PropertyCTL):
            return f"(ctl {self._unparse_ctl(p.formula)})"
        elif isinstance(p, A.PropertySafety):
            return f"(safety {self._unparse_pred(p.invariant)})"
        else:
            return f"<unknown-property:{type(p).__name__}>"


def unparse(node: Union[A.Module, A.PropertyDecl, A.CsqlQuery]) -> str:
    """Convert an AST node back to its S-expression string representation.

    Useful for debugging, pretty-printing, and roundtrip testing.
    """
    u = Unparser()
    if isinstance(node, A.Module):
        return u.unparse_module(node)
    # Extend as needed for other top-level nodes
    raise TypeError(f"Cannot unparse {type(node).__name__}")


# ═══════════════════════════════════════════════════════════════════════
#  CLI entry point (for quick testing)
# ═══════════════════════════════════════════════════════════════════════

def _main() -> None:
    """Simple CLI: ``python -m casl.parser <file.casl>``."""
    import argparse
    import json
    import sys

    ap = argparse.ArgumentParser(
        description="Parse a CASL file and dump the AST."
    )
    ap.add_argument("file", help="Path to a .casl file")
    ap.add_argument(
        "--format",
        choices=("repr", "sexp"),
        default="repr",
        help="Output format (default: repr)",
    )
    args = ap.parse_args()

    try:
        mod = parse_file(args.file)
    except ParseError as e:
        print(f"Parse error: {e}", file=sys.stderr)
        sys.exit(1)

    if args.format == "repr":
        # Use dataclasses' built-in repr
        from pprint import pprint
        pprint(mod)
    elif args.format == "sexp":
        print(unparse(mod))


if __name__ == "__main__":
    _main()
