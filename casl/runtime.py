#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
casl/runtime.py
===============

Runtime support library for CASL-generated addons.

This module provides the execution environment for checkers generated
from CASL specifications. It bridges the gap between:

- CASL's abstract pattern matching model
- Cppcheck's concrete AST representation (cppcheckdata)

Key Components
--------------
1. **PatternMatcher** — matches code patterns against Cppcheck tokens
2. **DataflowEngine** — runs dataflow analyses on the CFG
3. **ConstraintEvaluator** — evaluates where-clause constraints
4. **ActionExecutor** — executes actions on pattern matches
5. **DiagnosticEmitter** — reports findings to Cppcheck

Usage
-----
Generated addons use this module as:

    from casl.runtime import CASLRuntime
    
    def check(data):
        runtime = CASLRuntime(data)
        runtime.run_checker("my-checker", ...)

Thread Safety
-------------
CASLRuntime is not thread-safe. Each addon invocation should create
its own runtime instance.
"""

from __future__ import annotations

import abc
import re
from dataclasses import dataclass, field
from typing import (
    Any,
    Callable,
    Dict,
    FrozenSet,
    Generator,
    Generic,
    Iterator,
    List,
    Mapping,
    Optional,
    Sequence,
    Set,
    Tuple,
    TypeVar,
    Union,
)

__all__ = [
    "CASLRuntime",
    "PatternMatcher",
    "MatchResult",
    "DataflowEngine",
    "ConstraintEvaluator",
    "ActionExecutor",
    "DiagnosticEmitter",
    "CppcheckBinding",
]

T = TypeVar("T")


# ═══════════════════════════════════════════════════════════════════════════
# CPPCHECK BINDING
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class CppcheckBinding:
    """Binding to Cppcheck data structures.
    
    Wraps cppcheckdata objects with a uniform interface for pattern matching.
    """
    
    data: Any  # cppcheckdata.CppcheckData
    
    def tokens(self) -> Iterator[Any]:
        """Iterate over all tokens."""
        for cfg in self.data.configurations:
            token = cfg.tokenlist
            while token:
                yield token
                token = token.next
    
    def functions(self) -> Iterator[Any]:
        """Iterate over all functions."""
        for cfg in self.data.configurations:
            yield from cfg.functions
    
    def variables(self) -> Iterator[Any]:
        """Iterate over all variables."""
        for cfg in self.data.configurations:
            yield from cfg.variables
    
    def scopes(self) -> Iterator[Any]:
        """Iterate over all scopes."""
        for cfg in self.data.configurations:
            yield from cfg.scopes
    
    def get_token_type(self, token: Any) -> str:
        """Get the logical type of a token for pattern matching."""
        if hasattr(token, "isOp") and token.isOp:
            return "op"
        if hasattr(token, "isNumber") and token.isNumber:
            return "number"
        if hasattr(token, "isName") and token.isName:
            if hasattr(token, "function") and token.function:
                return "function-call"
            if hasattr(token, "variable") and token.variable:
                return "variable"
            return "name"
        if hasattr(token, "str"):
            tok_str = token.str
            if tok_str in ("=", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^="):
                return "assign"
            if tok_str == "(":
                return "lparen"
            if tok_str == ")":
                return "rparen"
            if tok_str == "[":
                return "lbracket"
            if tok_str == "]":
                return "rbracket"
            if tok_str == "{":
                return "lbrace"
            if tok_str == "}":
                return "rbrace"
            if tok_str == ";":
                return "semicolon"
            if tok_str == "*" and self._is_dereference(token):
                return "deref"
            if tok_str == "&" and self._is_address_of(token):
                return "address-of"
        return "token"
    
    def _is_dereference(self, token: Any) -> bool:
        """Check if * is a dereference (not multiplication)."""
        # Heuristic: dereference if preceded by operator or start of expression
        prev = token.previous
        if prev is None:
            return True
        prev_str = getattr(prev, "str", "")
        return prev_str in ("(", "[", ",", "=", "return", "if", "while", "for",
                           "+", "-", "*", "/", "%", "<", ">", "!", "~", "&", "|")
    
    def _is_address_of(self, token: Any) -> bool:
        """Check if & is address-of (not bitwise and)."""
        prev = token.previous
        if prev is None: