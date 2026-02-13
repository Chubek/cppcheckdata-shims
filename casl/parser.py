#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
casl/parser.py
==============

S-expression parser for CASL.

Uses ``sexpdata`` to parse raw S-expressions, then converts to CASL AST
nodes via a recursive-descent approach.

Grammar Overview
----------------
The CASL grammar (in pseudo-BNF over S-expressions):

    <addon>     ::= (addon <name> <section>*)
    <section>   ::= <metadata> | <import> | <domain> | <pattern>
                  | <query> | <checker> | <define> | <transfer>
                  | <dataflow>
    
    <metadata>  ::= (metadata (<key> <value>)*)
    <import>    ::= (import <module> [as <alias>] [only (<names>)])
    
    <domain>    ::= (domain <name> <domain-body>)
    <domain-body> ::= (kind <kind>) (elements ...) (bottom ...) ...
    
    <pattern>   ::= (pattern <name> (vars ...) (match <code-pat>) (where ...))
    <code-pat>  ::= <binding> | <node-pat> | <seq-pat> | <or-pat> | ...
    <binding>   ::= ?<name> | ?<name>:<type>
    <node-pat>  ::= (<node-type> <code-pat>*)
    
    <query>     ::= (query <name> (uses <pat>) (returns <expr>) (action ...))
    <checker>   ::= (checker <name> (severity ...) (message ...) (query ...))
    
    <expr>      ::= <literal> | <ident> | (<op> <expr>*) | (if ...) | ...
    <literal>   ::= <int> | <float> | <string> | #t | #f | nil

Sexpdata Mapping
----------------
- ``sexpdata.Symbol("foo")`` → identifier or keyword depending on context
- ``sexpdata.String("...")`` → string literal  
- ``int``, ``float`` → numeric literals
- ``list`` → compound form

Example
-------
    >>> from casl.parser import parse
    >>> ast = parse('''
    ...   (addon my-null-checker
    ...     (checker null-deref
    ...       (severity error)
    ...       (message "Null pointer dereference of {var}")
    ...       (query (pattern (deref ?ptr))
    ...              (where (fact ?ptr nullness null)))))
    ... ''')
    >>> ast.name
    'my-null-checker'
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple, Union

try:
    import sexpdata
    from sexpdata import Symbol
except ImportError:
    sexpdata = None  # type: ignore
    Symbol = None    # type: ignore

from casl import ast as A
from casl.errors import ParseError, SyntaxError_, SourceLocation

__all__ = ["parse", "parse_file", "Parser"]


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _is_symbol(x: Any) -> bool:
    """Check if x is a sexpdata Symbol."""
    if Symbol is None:
        return False
    return isinstance(x, Symbol)


def _symbol_name(x: Any) -> str:
    """Extract string from Symbol."""
    if _is_symbol(x):
        return x.value()
    if isinstance(x, str):
        return x
    raise TypeError(f"Expected symbol, got {type(x).__name__}")


def _is_keyword(x: Any) -> bool:
    """Check if x is a keyword (symbol starting with :)."""
    if not _is_symbol(x):
        return False
    return x.value().startswith(":")


def _keyword_name(x: Any) -> str:
    """Get keyword name without leading colon."""
    name = _symbol_name(x)
    return name[1:] if name.startswith(":") else name


def _is_pattern_var(x: Any) -> bool:
    """Check if x is a pattern variable (symbol starting with ?)."""
    if not _is_symbol(x):
        return False
    return x.value().startswith("?")


def _pattern_var_name(x: Any) -> Tuple[str, Optional[str]]:
    """Parse pattern variable, returning (name, type_constraint).
    
    ?foo → ("foo", None)
    ?foo:Token → ("foo", "Token")
    """
    name = _symbol_name(x)
    if not name.startswith("?"):
        raise ValueError(f"Not a pattern variable: {name}")
    rest = name[1:]
    if ":" in rest:
        varname, typeconst = rest.split(":", 1)
        return varname, typeconst
    return rest, None


def _is_string(x: Any) -> bool:
    """Check if x is a string literal."""
    return isinstance(x, str)


def _is_list(x: Any) -> bool:
    """Check if x is a list (compound form)."""
    return isinstance(x, list)


# ---------------------------------------------------------------------------
# PARSER
# ---------------------------------------------------------------------------

class Parser:
    """Recursive-descent parser for CASL S-expressions.
    
    Converts raw sexpdata output into CASL AST nodes.
    """
    
    def __init__(self, source: str, filename: Optional[str] = None) -> None:
        self.source = source
        self.filename = filename
        self._sexp: Any = None
    
    def parse(self) -> A.AddonSpec:
        """Parse the source and return an AddonSpec AST."""
        if sexpdata is None:
            raise ImportError("sexpdata library is required for CASL parsing")
        
        try:
            self._sexp = sexpdata.loads(self.source)
        except Exception as e:
            raise ParseError(f"S-expression parse error: {e}")
        
        # Handle multiple top-level forms
        if isinstance(self._sexp, list) and len(self._sexp) > 0:
            first = self._sexp[0] if _is_list(self._sexp[0]) else self._sexp
            if _is_list(first) and _is_list(first[0]):
                # Multiple forms — find the addon
                for form in first:
                    if self._is_form(form, "addon"):
                        return self._parse_addon(form)
                raise SyntaxError_("No (addon ...) form found")
            else:
                return self._parse_addon(self._sexp)
        
        raise SyntaxError_("Empty or invalid CASL specification")
    
    def _is_form(self, sexp: Any, tag: str) -> bool:
        """Check if sexp is a list starting with symbol `tag`."""
        if not _is_list(sexp) or len(sexp) == 0:
            return False
        return _is_symbol(sexp[0]) and _symbol_name(sexp[0]) == tag
    
    def _expect_form(self, sexp: Any, tag: str) -> List[Any]:
        """Assert sexp is a form with given tag, return tail."""
        if not self._is_form(sexp, tag):
            got = _symbol_name(sexp[0]) if _is_list(sexp) and sexp else str(sexp)
            raise SyntaxError_(f"Expected ({tag} ...), got {got}")
        return sexp[1:]
    
    # --- Top-level ---
    
    def _parse_addon(self, sexp: List[Any]) -> A.AddonSpec:
        """(addon <name> <section>*)"""
        tail = self._expect_form(sexp, "addon")
        if len(tail) < 1:
            raise SyntaxError_("addon requires a name")
        
        name = _symbol_name(tail[0])
        sections = tail[1:]
        
        addon = A.AddonSpec(name=name)
        
        for section in sections:
            self._parse_section(section, addon)
        
        return addon
    
    def _parse_section(self, sexp: Any, addon: A.AddonSpec) -> None:
        """Dispatch section parsing."""
        if not _is_list(sexp) or len(sexp) == 0:
            raise SyntaxError_(f"Invalid section: {sexp}")
        
        tag = _symbol_name(sexp[0])
        handlers = {
            "metadata": self._parse_metadata,
            "import": self._parse_import,
            "domain": self._parse_domain,
            "define": self._parse_function,
            "transfer": self._parse_transfer,
            "pattern": self._parse_pattern,
            "query": self._parse_query,
            "checker": self._parse_checker,
            "dataflow": self._parse_dataflow,
        }
        
        handler = handlers.get(tag)
        if handler is None:
            raise SyntaxError_(f"Unknown section type: {tag}")
        
        result = handler(sexp)
        
        # Append to appropriate list in addon
        if isinstance(result, A.Metadata):
            addon.metadata = result
        elif isinstance(result, A.Import):
            addon.imports.append(result)
        elif isinstance(result, A