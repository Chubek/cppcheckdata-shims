#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cppcheckdata_shims/ast_helper.py
════════════════════════════════

AST traversal, querying, and manipulation utilities for Cppcheck addons.

This module provides a comprehensive toolkit for working with the Abstract
Syntax Tree (AST) representation in Cppcheck dump files. It builds upon
the raw `cppcheckdata.Token` objects and offers:

    ┌─────────────────────────────────────────────────────────────────┐
    │  AST Traversal                                                  │
    │    • Pre-order, post-order, level-order iteration               │
    │    • Parent chain walking                                       │
    │    • Subtree collection                                         │
    ├─────────────────────────────────────────────────────────────────┤
    │  AST Querying                                                   │
    │    • Pattern matching (operator, type, structure)               │
    │    • Expression classification                                  │
    │    • Relationship predicates (is_child_of, is_ancestor_of)      │
    ├─────────────────────────────────────────────────────────────────┤
    │  Expression Analysis                                            │
    │    • Side-effect detection                                      │
    │    • Purity analysis                                            │
    │    • Constant expression detection                              │
    │    • LValue/RValue classification                               │
    ├─────────────────────────────────────────────────────────────────┤
    │  Structural Utilities                                           │
    │    • Function call argument extraction                          │
    │    • Binary/unary operator classification                       │
    │    • Expression stringification                                 │
    │    • AST depth and size metrics                                 │
    └─────────────────────────────────────────────────────────────────┘

Design Principles
─────────────────
1. **Non-invasive**: Never modifies Token objects; all operations are
   read-only queries.

2. **Defensive**: All functions handle None tokens gracefully, returning
   sensible defaults (empty iterators, False, None) rather than raising.

3. **Composable**: Functions are designed to chain together for complex
   queries (e.g., find all function calls within a loop body).

4. **Sound for analysis**: When in doubt, functions err on the side of
   conservatism (e.g., `has_side_effects` returns True if uncertain).

Usage Example
─────────────
    from cppcheckdata_shims.ast_helper import (
        iter_ast_preorder,
        find_function_calls,
        is_lvalue,
        expr_to_string,
    )

    for tok in cfg.tokenlist:
        if tok.str == '=' and tok.astOperand1:
            # Check if LHS is valid lvalue
            if not is_lvalue(tok.astOperand1):
                report_error(tok, "Invalid assignment target")

            # Find all function calls in RHS
            for call in find_function_calls(tok.astOperand2):
                print(f"Call to {get_called_function_name(call)}")

License: MIT
"""

from __future__ import annotations

import re
from collections import deque
from dataclasses import dataclass
from enum import Enum, auto
from typing import (
    Any,
    Callable,
    Dict,
    FrozenSet,
    Generator,
    Iterable,
    Iterator,
    List,
    Optional,
    Set,
    Tuple,
    Union,
)


# ═══════════════════════════════════════════════════════════════════════════
#  TYPE ALIASES
# ═══════════════════════════════════════════════════════════════════════════

# We use Any for Token to avoid hard dependency on cppcheckdata module
# at import time, while still providing full functionality.
Token = Any


# ═══════════════════════════════════════════════════════════════════════════
#  CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════

# Arithmetic operators
ARITHMETIC_OPS: FrozenSet[str] = frozenset({
    '+', '-', '*', '/', '%',
    '++', '--',  # increment/decrement
})

# Bitwise operators
BITWISE_OPS: FrozenSet[str] = frozenset({
    '&', '|', '^', '~', '<<', '>>',
})

# Comparison operators
COMPARISON_OPS: FrozenSet[str] = frozenset({
    '==', '!=', '<', '>', '<=', '>=', '<=>',  # <=> is C++20 spaceship
})

# Logical operators
LOGICAL_OPS: FrozenSet[str] = frozenset({
    '&&', '||', '!',
})

# Assignment operators (including compound)
ASSIGNMENT_OPS: FrozenSet[str] = frozenset({
    '=', '+=', '-=', '*=', '/=', '%=',
    '&=', '|=', '^=', '<<=', '>>=',
})

# All binary operators
BINARY_OPS: FrozenSet[str] = frozenset({
    '+', '-', '*', '/', '%',
    '&', '|', '^', '<<', '>>',
    '==', '!=', '<', '>', '<=', '>=', '<=>',
    '&&', '||',
    '=', '+=', '-=', '*=', '/=', '%=',
    '&=', '|=', '^=', '<<=', '>>=',
    ',', '.*', '->*',
})

# Unary operators
UNARY_OPS: FrozenSet[str] = frozenset({
    '++', '--',  # prefix/postfix
    '+', '-',    # unary plus/minus
    '!', '~',    # logical/bitwise not
    '*',         # dereference
    '&',         # address-of
    'sizeof', 'alignof', 'typeof', 'typeid',
    'new', 'delete', 'throw',
})

# Operators that definitely have side effects
SIDE_EFFECT_OPS: FrozenSet[str] = frozenset({
    '=', '+=', '-=', '*=', '/=', '%=',
    '&=', '|=', '^=', '<<=', '>>=',
    '++', '--',
    'new', 'delete', 'throw',
})

# Memory allocation functions
ALLOC_FUNCTIONS: FrozenSet[str] = frozenset({
    'malloc', 'calloc', 'realloc', 'aligned_alloc',
    'strdup', 'strndup', 'wcsdup',
    'new',  # C++ new (represented as function in some contexts)
})

# Memory deallocation functions
DEALLOC_FUNCTIONS: FrozenSet[str] = frozenset({
    'free', 'delete',
})

# Functions known to have no side effects (pure)
PURE_FUNCTIONS: FrozenSet[str] = frozenset({
    'strlen', 'wcslen', 'strnlen', 'wcsnlen',
    'strcmp', 'strncmp', 'wcscmp', 'wcsncmp',
    'strchr', 'strrchr', 'wcschr', 'wcsrchr',
    'strstr', 'wcsstr',
    'memcmp', 'wmemcmp',
    'isalpha', 'isdigit', 'isalnum', 'isspace', 'isupper', 'islower',
    'isprint', 'iscntrl', 'ispunct', 'isxdigit', 'isgraph', 'isblank',
    'toupper', 'tolower',
    'abs', 'labs', 'llabs', 'fabs', 'fabsf', 'fabsl',
    'sqrt', 'sqrtf', 'sqrtl',
    'sin', 'cos', 'tan', 'asin', 'acos', 'atan', 'atan2',
    'sinh', 'cosh', 'tanh', 'asinh', 'acosh', 'atanh',
    'exp', 'exp2', 'expm1', 'log', 'log2', 'log10', 'log1p',
    'pow', 'powf', 'powl',
    'ceil', 'floor', 'trunc', 'round', 'nearbyint', 'rint',
    'fmod', 'remainder', 'fmax', 'fmin', 'fdim',
    'copysign', 'nan', 'isnan', 'isinf', 'isfinite', 'isnormal',
    'signbit', 'fpclassify',
    'atoi', 'atol', 'atoll', 'atof',
    'sizeof', 'alignof',
})


# ═══════════════════════════════════════════════════════════════════════════
#  PART 1 — SAFE ACCESSORS
# ═══════════════════════════════════════════════════════════════════════════

def tok_str(tok: Token) -> str:
    """
    Safely get the string representation of a token.

    Args:
        tok: A cppcheckdata Token object (may be None)

    Returns:
        The token's string value, or empty string if tok is None
    """
    if tok is None:
        return ""
    return getattr(tok, "str", "") or ""


def tok_op1(tok: Token) -> Optional[Token]:
    """
    Safely get astOperand1 of a token.

    Args:
        tok: A cppcheckdata Token object (may be None)

    Returns:
        The first AST operand, or None
    """
    if tok is None:
        return None
    return getattr(tok, "astOperand1", None)


def tok_op2(tok: Token) -> Optional[Token]:
    """
    Safely get astOperand2 of a token.

    Args:
        tok: A cppcheckdata Token object (may be None)

    Returns:
        The second AST operand, or None
    """
    if tok is None:
        return None
    return getattr(tok, "astOperand2", None)


def tok_parent(tok: Token) -> Optional[Token]:
    """
    Safely get astParent of a token.

    Args:
        tok: A cppcheckdata Token object (may be None)

    Returns:
        The AST parent, or None
    """
    if tok is None:
        return None
    return getattr(tok, "astParent", None)


def tok_var_id(tok: Token) -> int:
    """
    Safely get the variable ID of a token.

    Args:
        tok: A cppcheckdata Token object (may be None)

    Returns:
        The variable ID, or 0 if not a variable reference
    """
    if tok is None:
        return 0
    vid = getattr(tok, "varId", 0)
    return vid if vid else 0


def tok_variable(tok: Token) -> Optional[Any]:
    """
    Safely get the Variable object associated with a token.

    Args:
        tok: A cppcheckdata Token object (may be None)

    Returns:
        The Variable object, or None
    """
    if tok is None:
        return None
    return getattr(tok, "variable", None)


def tok_function(tok: Token) -> Optional[Any]:
    """
    Safely get the Function object associated with a token.

    Args:
        tok: A cppcheckdata Token object (may be None)

    Returns:
        The Function object, or None
    """
    if tok is None:
        return None
    return getattr(tok, "function", None)


def tok_scope(tok: Token) -> Optional[Any]:
    """
    Safely get the Scope object associated with a token.

    Args:
        tok: A cppcheckdata Token object (may be None)

    Returns:
        The Scope object, or None
    """
    if tok is None:
        return None
    return getattr(tok, "scope", None)


def tok_value_type(tok: Token) -> Optional[Any]:
    """
    Safely get the ValueType of a token.

    Args:
        tok: A cppcheckdata Token object (may be None)

    Returns:
        The ValueType object, or None
    """
    if tok is None:
        return None
    return getattr(tok, "valueType", None)


def tok_values(tok: Token) -> List[Any]:
    """
    Safely get the value-flow values of a token.

    Args:
        tok: A cppcheckdata Token object (may be None)

    Returns:
        List of Value objects (empty if none)
    """
    if tok is None:
        return []
    vals = getattr(tok, "values", None)
    return list(vals) if vals else []


def tok_link(tok: Token) -> Optional[Token]:
    """
    Safely get the linked token (for brackets, parentheses).

    Args:
        tok: A cppcheckdata Token object (may be None)

    Returns:
        The linked token, or None
    """
    if tok is None:
        return None
    return getattr(tok, "link", None)


def tok_next(tok: Token) -> Optional[Token]:
    """
    Safely get the next token in the token list.

    Args:
        tok: A cppcheckdata Token object (may be None)

    Returns:
        The next token, or None
    """
    if tok is None:
        return None
    return getattr(tok, "next", None)


def tok_previous(tok: Token) -> Optional[Token]:
    """
    Safely get the previous token in the token list.

    Args:
        tok: A cppcheckdata Token object (may be None)

    Returns:
        The previous token, or None
    """
    if tok is None:
        return None
    return getattr(tok, "previous", None)


def tok_file(tok: Token) -> str:
    """
    Safely get the source file of a token.

    Args:
        tok: A cppcheckdata Token object (may be None)

    Returns:
        The file path, or "<unknown>"
    """
    if tok is None:
        return "<unknown>"
    return getattr(tok, "file", "<unknown>") or "<unknown>"


def tok_line(tok: Token) -> int:
    """
    Safely get the line number of a token.

    Args:
        tok: A cppcheckdata Token object (may be None)

    Returns:
        The line number, or 0
    """
    if tok is None:
        return 0
    return int(getattr(tok, "linenr", 0) or 0)


def tok_column(tok: Token) -> int:
    """
    Safely get the column number of a token.

    Args:
        tok: A cppcheckdata Token object (may be None)

    Returns:
        The column number, or 0
    """
    if tok is None:
        return 0
    return int(getattr(tok, "column", 0) or 0)


# ═══════════════════════════════════════════════════════════════════════════
#  PART 2 — AST TRAVERSAL
# ═══════════════════════════════════════════════════════════════════════════

def iter_ast_preorder(root: Token) -> Iterator[Token]:
    """
    Iterate over AST nodes in pre-order (root, left, right).

    This is the most common traversal for analysis: you see each node
    before its children, which is useful for top-down analysis.

    Args:
        root: The root token of the AST subtree

    Yields:
        Tokens in pre-order sequence

    Example:
        >>> for tok in iter_ast_preorder(expr_root):
        ...     print(tok_str(tok))
    """
    if root is None:
        return
    stack: List[Token] = [root]
    while stack:
        node = stack.pop()
        yield node
        # Push right first so left is processed first (LIFO)
        op2 = tok_op2(node)
        if op2 is not None:
            stack.append(op2)
        op1 = tok_op1(node)
        if op1 is not None:
            stack.append(op1)


def iter_ast_postorder(root: Token) -> Iterator[Token]:
    """
    Iterate over AST nodes in post-order (left, right, root).

    Useful for bottom-up analysis where you need to process children
    before their parent (e.g., type inference, evaluation).

    Args:
        root: The root token of the AST subtree

    Yields:
        Tokens in post-order sequence
    """
    if root is None:
        return

    # Two-stack algorithm for iterative post-order
    stack1: List[Token] = [root]
    stack2: List[Token] = []

    while stack1:
        node = stack1.pop()
        stack2.append(node)
        op1 = tok_op1(node)
        if op1 is not None:
            stack1.append(op1)
        op2 = tok_op2(node)
        if op2 is not None:
            stack1.append(op2)

    while stack2:
        yield stack2.pop()


def iter_ast_levelorder(root: Token) -> Iterator[Token]:
    """
    Iterate over AST nodes in level-order (breadth-first).

    Processes all nodes at depth d before any node at depth d+1.
    Useful for finding the "closest" match to the root.

    Args:
        root: The root token of the AST subtree

    Yields:
        Tokens in level-order sequence
    """
    if root is None:
        return
    queue: deque[Token] = deque([root])
    while queue:
        node = queue.popleft()
        yield node
        op1 = tok_op1(node)
        if op1 is not None:
            queue.append(op1)
        op2 = tok_op2(node)
        if op2 is not None:
            queue.append(op2)


def iter_ast_leaves(root: Token) -> Iterator[Token]:
    """
    Iterate over leaf nodes of the AST (nodes with no children).

    Leaves are typically identifiers, literals, and constants.

    Args:
        root: The root token of the AST subtree

    Yields:
        Leaf tokens only
    """
    for tok in iter_ast_preorder(root):
        if tok_op1(tok) is None and tok_op2(tok) is None:
            yield tok


def iter_parents(tok: Token) -> Iterator[Token]:
    """
    Iterate up the parent chain from a token to the AST root.

    Does NOT include the starting token.

    Args:
        tok: Starting token

    Yields:
        Parent tokens from immediate parent to root
    """
    if tok is None:
        return
    current = tok_parent(tok)
    while current is not None:
        yield current
        current = tok_parent(current)


def iter_parents_inclusive(tok: Token) -> Iterator[Token]:
    """
    Iterate up the parent chain, including the starting token.

    Args:
        tok: Starting token

    Yields:
        The token itself, then all parents up to root
    """
    if tok is None:
        return
    current = tok
    while current is not None:
        yield current
        current = tok_parent(current)


def collect_subtree(root: Token) -> List[Token]:
    """
    Collect all tokens in an AST subtree as a list.

    Args:
        root: The root token of the AST subtree

    Returns:
        List of all tokens in pre-order
    """
    return list(iter_ast_preorder(root))


def ast_depth(root: Token) -> int:
    """
    Compute the depth (height) of an AST subtree.

    An empty tree has depth 0; a single node has depth 1.

    Args:
        root: The root token of the AST subtree

    Returns:
        The maximum depth of the tree
    """
    if root is None:
        return 0

    def _depth(node: Token) -> int:
        if node is None:
            return 0
        return 1 + max(_depth(tok_op1(node)), _depth(tok_op2(node)))

    return _depth(root)


def ast_size(root: Token) -> int:
    """
    Count the number of nodes in an AST subtree.

    Args:
        root: The root token of the AST subtree

    Returns:
        Total number of nodes
    """
    count = 0
    for _ in iter_ast_preorder(root):
        count += 1
    return count


def find_ast_root(tok: Token) -> Optional[Token]:
    """
    Find the root of the AST containing a given token.

    The root is the token with no astParent.

    Args:
        tok: Any token in the AST

    Returns:
        The root token, or None if tok is None
    """
    if tok is None:
        return None
    current = tok
    parent = tok_parent(current)
    while parent is not None:
        current = parent
        parent = tok_parent(current)
    return current


# ═══════════════════════════════════════════════════════════════════════════
#  PART 3 — AST PREDICATES
# ═══════════════════════════════════════════════════════════════════════════

def is_binary_op(tok: Token) -> bool:
    """
    Check if a token is a binary operator in the AST.

    A binary operator has both astOperand1 and astOperand2.

    Args:
        tok: Token to check

    Returns:
        True if tok is a binary operator
    """
    if tok is None:
        return False
    return tok_op1(tok) is not None and tok_op2(tok) is not None


def is_unary_op(tok: Token) -> bool:
    """
    Check if a token is a unary operator in the AST.

    A unary operator has astOperand1 but not astOperand2.

    Args:
        tok: Token to check

    Returns:
        True if tok is a unary operator
    """
    if tok is None:
        return False
    return tok_op1(tok) is not None and tok_op2(tok) is None


def is_leaf(tok: Token) -> bool:
    """
    Check if a token is a leaf node (no children).

    Args:
        tok: Token to check

    Returns:
        True if tok has no AST children
    """
    if tok is None:
        return False
    return tok_op1(tok) is None and tok_op2(tok) is None


def is_identifier(tok: Token) -> bool:
    """
    Check if a token is an identifier (variable/function name).

    Args:
        tok: Token to check

    Returns:
        True if tok is a name token
    """
    if tok is None:
        return False
    return bool(getattr(tok, "isName", False))


def is_number(tok: Token) -> bool:
    """
    Check if a token is a numeric literal.

    Args:
        tok: Token to check

    Returns:
        True if tok is a number
    """
    if tok is None:
        return False
    return bool(getattr(tok, "isNumber", False))


def is_string_literal(tok: Token) -> bool:
    """
    Check if a token is a string literal.

    Args:
        tok: Token to check

    Returns:
        True if tok is a string literal
    """
    if tok is None:
        return False
    return bool(getattr(tok, "isString", False))


def is_char_literal(tok: Token) -> bool:
    """
    Check if a token is a character literal.

    Args:
        tok: Token to check

    Returns:
        True if tok is a char literal
    """
    if tok is None:
        return False
    return bool(getattr(tok, "isChar", False))


def is_literal(tok: Token) -> bool:
    """
    Check if a token is any kind of literal.

    Args:
        tok: Token to check

    Returns:
        True if tok is a number, string, char, or boolean literal
    """
    if tok is None:
        return False
    return (
        bool(getattr(tok, "isNumber", False)) or
        bool(getattr(tok, "isString", False)) or
        bool(getattr(tok, "isChar", False)) or
        bool(getattr(tok, "isBoolean", False))
    )


def is_cast(tok: Token) -> bool:
    """
    Check if a token represents a cast expression.

    Args:
        tok: Token to check

    Returns:
        True if tok is a cast
    """
    if tok is None:
        return False
    return bool(getattr(tok, "isCast", False))


def is_comparison(tok: Token) -> bool:
    """
    Check if a token is a comparison operator.

    Args:
        tok: Token to check

    Returns:
        True if tok is a comparison operator
    """
    if tok is None:
        return False
    return bool(getattr(tok, "isComparisonOp", False)) or tok_str(tok) in COMPARISON_OPS


def is_logical_op(tok: Token) -> bool:
    """
    Check if a token is a logical operator (&&, ||, !).

    Args:
        tok: Token to check

    Returns:
        True if tok is a logical operator
    """
    if tok is None:
        return False
    return bool(getattr(tok, "isLogicalOp", False)) or tok_str(tok) in LOGICAL_OPS


def is_arithmetic_op(tok: Token) -> bool:
    """
    Check if a token is an arithmetic operator.

    Args:
        tok: Token to check

    Returns:
        True if tok is an arithmetic operator
    """
    if tok is None:
        return False
    return bool(getattr(tok, "isArithmeticalOp", False)) or tok_str(tok) in ARITHMETIC_OPS


def is_assignment(tok: Token) -> bool:
    """
    Check if a token is an assignment operator.

    Args:
        tok: Token to check

    Returns:
        True if tok is an assignment (including compound)
    """
    if tok is None:
        return False
    return bool(getattr(tok, "isAssignmentOp", False)) or tok_str(tok) in ASSIGNMENT_OPS


def is_compound_assignment(tok: Token) -> bool:
    """
    Check if a token is a compound assignment operator (+=, -=, etc.).

    Args:
        tok: Token to check

    Returns:
        True if tok is a compound assignment
    """
    if tok is None:
        return False
    s = tok_str(tok)
    return s in ASSIGNMENT_OPS and s != '='


def is_increment_decrement(tok: Token) -> bool:
    """
    Check if a token is ++ or --.

    Args:
        tok: Token to check

    Returns:
        True if tok is increment or decrement
    """
    return tok_str(tok) in ('++', '--')


def is_dereference(tok: Token) -> bool:
    """
    Check if a token is a pointer dereference (*ptr).

    Distinguishes unary * from binary multiplication.

    Args:
        tok: Token to check

    Returns:
        True if tok is a dereference operator
    """
    if tok is None:
        return False
    if tok_str(tok) != '*':
        return False
    # Unary * has operand1 but not operand2
    return tok_op1(tok) is not None and tok_op2(tok) is None


def is_address_of(tok: Token) -> bool:
    """
    Check if a token is an address-of operator (&var).

    Distinguishes unary & from binary bitwise AND.

    Args:
        tok: Token to check

    Returns:
        True if tok is address-of operator
    """
    if tok is None:
        return False
    if tok_str(tok) != '&':
        return False
    # Unary & has operand1 but not operand2
    return tok_op1(tok) is not None and tok_op2(tok) is None


def is_subscript(tok: Token) -> bool:
    """
    Check if a token is an array subscript operator [].

    Args:
        tok: Token to check

    Returns:
        True if tok is a subscript
    """
    return tok_str(tok) == '['


def is_member_access(tok: Token) -> bool:
    """
    Check if a token is a member access operator (. or ->).

    Args:
        tok: Token to check

    Returns:
        True if tok is member access
    """
    return tok_str(tok) in ('.', '->')


def is_function_call(tok: Token) -> bool:
    """
    Check if a token represents a function call.

    In Cppcheck AST, a function call is represented as '(' with
    astOperand1 being the function name/expression.

    Args:
        tok: Token to check

    Returns:
        True if tok is a function call
    """
    if tok is None:
        return False
    if tok_str(tok) != '(':
        return False
    # Must have operand1 (the function) and not be a cast
    if tok_op1(tok) is None:
        return False
    if is_cast(tok):
        return False
    return True


def is_sizeof(tok: Token) -> bool:
    """
    Check if a token is a sizeof expression.

    Args:
        tok: Token to check

    Returns:
        True if tok is sizeof
    """
    return tok_str(tok) == 'sizeof'


def is_ternary(tok: Token) -> bool:
    """
    Check if a token is a ternary conditional operator (?:).

    Args:
        tok: Token to check

    Returns:
        True if tok is the '?' of a ternary
    """
    return tok_str(tok) == '?'


def is_comma(tok: Token) -> bool:
    """
    Check if a token is a comma operator.

    Args:
        tok: Token to check

    Returns:
        True if tok is comma
    """
    return tok_str(tok) == ','


def is_in_sizeof(tok: Token) -> bool:
    """
    Check if a token is inside a sizeof() expression.

    Expressions inside sizeof are not evaluated at runtime.

    Args:
        tok: Token to check

    Returns:
        True if tok is within sizeof
    """
    for parent in iter_parents(tok):
        if tok_str(parent) == 'sizeof':
            return True
    return False


def is_in_typeof(tok: Token) -> bool:
    """
    Check if a token is inside a typeof/decltype expression.

    Args:
        tok: Token to check

    Returns:
        True if tok is within typeof/decltype
    """
    for parent in iter_parents(tok):
        s = tok_str(parent)
        if s in ('typeof', 'decltype', '__typeof__'):
            return True
    return False


def is_in_noexcept(tok: Token) -> bool:
    """
    Check if a token is inside a noexcept() specifier.

    Args:
        tok: Token to check

    Returns:
        True if tok is within noexcept
    """
    for parent in iter_parents(tok):
        if tok_str(parent) == 'noexcept':
            return True
    return False


def is_unevaluated_context(tok: Token) -> bool:
    """
    Check if a token is in an unevaluated context.

    Unevaluated contexts include sizeof, typeof, decltype, noexcept,
    and typeid (for non-polymorphic types).

    Args:
        tok: Token to check

    Returns:
        True if tok is in an unevaluated context
    """
    return is_in_sizeof(tok) or is_in_typeof(tok) or is_in_noexcept(tok)


# ═══════════════════════════════════════════════════════════════════════════
#  PART 4 — RELATIONSHIP PREDICATES
# ═══════════════════════════════════════════════════════════════════════════

def is_child_of(child: Token, parent: Token) -> bool:
    """
    Check if child is a direct child of parent in the AST.

    Args:
        child: Potential child token
        parent: Potential parent token

    Returns:
        True if child is astOperand1 or astOperand2 of parent
    """
    if child is None or parent is None:
        return False
    return tok_op1(parent) is child or tok_op2(parent) is child


def is_descendant_of(descendant: Token, ancestor: Token) -> bool:
    """
    Check if descendant is anywhere in the subtree rooted at ancestor.

    Args:
        descendant: Potential descendant token
        ancestor: Potential ancestor token

    Returns:
        True if descendant is in ancestor's subtree
    """
    if descendant is None or ancestor is None:
        return False
    if descendant is ancestor:
        return True
    for node in iter_ast_preorder(ancestor):
        if node is descendant:
            return True
    return False


def is_ancestor_of(ancestor: Token, descendant: Token) -> bool:
    """
    Check if ancestor is an ancestor of descendant.

    Args:
        ancestor: Potential ancestor token
        descendant: Potential descendant token

    Returns:
        True if ancestor is in descendant's parent chain
    """
    return is_descendant_of(descendant, ancestor)


def is_left_operand(tok: Token) -> bool:
    """
    Check if tok is the left operand of its parent.

    Args:
        tok: Token to check

    Returns:
        True if tok is astOperand1 of its parent
    """
    if tok is None:
        return False
    parent = tok_parent(tok)
    if parent is None:
        return False
    return tok_op1(parent) is tok


def is_right_operand(tok: Token) -> bool:
    """
    Check if tok is the right operand of its parent.

    Args:
        tok: Token to check

    Returns:
        True if tok is astOperand2 of its parent
    """
    if tok is None:
        return False
    parent = tok_parent(tok)
    if parent is None:
        return False
    return tok_op2(parent) is tok


def shares_subtree(tok1: Token, tok2: Token) -> bool:
    """
    Check if two tokens are in the same expression tree.

    Args:
        tok1: First token
        tok2: Second token

    Returns:
        True if tok1 and tok2 share the same AST root
    """
    if tok1 is None or tok2 is None:
        return False
    root1 = find_ast_root(tok1)
    root2 = find_ast_root(tok2)
    return root1 is root2 and root1 is not None


def get_common_ancestor(tok1: Token, tok2: Token) -> Optional[Token]:
    """
    Find the lowest common ancestor of two tokens in the AST.

    Args:
        tok1: First token
        tok2: Second token

    Returns:
        The lowest common ancestor, or None if not in same tree
    """
    if tok1 is None or tok2 is None:
        return None

    # Collect all ancestors of tok1
    ancestors1: Set[int] = set()
    for p in iter_parents_inclusive(tok1):
        ancestors1.add(id(p))

    # Find first ancestor of tok2 that's also ancestor of tok1
    for p in iter_parents_inclusive(tok2):
        if id(p) in ancestors1:
            return p

    return None


# ═══════════════════════════════════════════════════════════════════════════
#  PART 5 — EXPRESSION ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════

def is_lvalue(tok: Token) -> bool:
    """
    Check if an expression is an lvalue (can appear on LHS of assignment).

    An lvalue designates an object with storage. This includes:
    - Variable references
    - Dereferences (*p)
    - Array subscripts (a[i])
    - Member access (s.m, p->m)
    - String literals (in C, they decay to non-const char*)

    Args:
        tok: Token to check

    Returns:
        True if tok is an lvalue expression
    """
    if tok is None:
        return False

    s = tok_str(tok)

    # Variable reference
    if tok_var_id(tok) != 0:
        var = tok_variable(tok)
        # Check if it's not a const variable (simplified check)
        if var and getattr(var, "isConst", False):
            return False
        return True

    # Dereference: *expr
    if is_dereference(tok):
        return True

    # Array subscript: arr[i]
    if s == '[':
        return True

    # Member access: obj.member or ptr->member
    if s in ('.', '->'):
        return True

    # Parenthesized lvalue: (lvalue)
    if s == '(' and not is_cast(tok) and not is_function_call(tok):
        op1 = tok_op1(tok)
        if op1 is not None:
            return is_lvalue(op1)

    # Comma operator: result is RHS
    if s == ',':
        op2 = tok_op2(tok)
        if op2 is not None:
            return is_lvalue(op2)

    # Ternary: both branches must be lvalues (C++ only, simplified)
    if s == '?':
        op2 = tok_op2(tok)  # The ':' node
        if op2 and tok_str(op2) == ':':
            return is_lvalue(tok_op1(op2)) and is_lvalue(tok_op2(op2))

    return False


def is_rvalue(tok: Token) -> bool:
    """
    Check if an expression is an rvalue (not an lvalue).

    Args:
        tok: Token to check

    Returns:
        True if tok is an rvalue expression
    """
    if tok is None:
        return False
    return not is_lvalue(tok)


def is_modifiable_lvalue(tok: Token) -> bool:
    """
    Check if an expression is a modifiable lvalue.

    A modifiable lvalue is an lvalue that is not const-qualified
    and not an array type.

    Args:
        tok: Token to check

    Returns:
        True if tok is a modifiable lvalue
    """
    if not is_lvalue(tok):
        return False

    # Check for const
    var = tok_variable(tok)
    if var:
        if getattr(var, "isConst", False):
            return False
        if getattr(var, "isArray", False):
            return False

    vt = tok_value_type(tok)
    if vt:
        constness = getattr(vt, "constness", 0)
        if constness:
            return False

    return True


def has_side_effects(tok: Token) -> bool:
    """
    Check if an expression has (or may have) side effects.

    Side effects include:
    - Assignments (=, +=, etc.)
    - Increment/decrement (++, --)
    - Function calls (unless known pure)
    - Volatile accesses

    This function is CONSERVATIVE: it returns True if uncertain.

    Args:
        tok: Token to check

    Returns:
        True if the expression may have side effects
    """
    if tok is None:
        return False

    for node in iter_ast_preorder(tok):
        s = tok_str(node)

        # Side-effect operators
        if s in SIDE_EFFECT_OPS:
            return True

        # Function calls (unless known pure)
        if is_function_call(node):
            fname = get_called_function_name(node)
            if fname not in PURE_FUNCTIONS:
                return True

        # Volatile variable access
        var = tok_variable(node)
        if var and getattr(var, "isVolatile", False):
            return True

    return False


def is_pure_expression(tok: Token) -> bool:
    """
    Check if an expression is pure (no side effects).

    A pure expression always produces the same result for the same
    inputs and has no observable effects.

    Args:
        tok: Token to check

    Returns:
        True if the expression is definitely pure
    """
    return not has_side_effects(tok)


def is_constant_expression(tok: Token) -> bool:
    """
    Check if an expression is a compile-time constant.

    This is a simplified check that identifies obvious constants:
    - Literals
    - sizeof expressions
    - Arithmetic on constants
    - Const variables initialized with constants

    Args:
        tok: Token to check

    Returns:
        True if the expression is definitely constant
    """
    if tok is None:
        return False

    s = tok_str(tok)

    # Literals are constant
    if is_literal(tok):
        return True

    # sizeof is always constant
    if s == 'sizeof':
        return True

    # nullptr, NULL, true, false
    if s in ('nullptr', 'NULL', 'true', 'false'):
        return True

    # Const variable with known value
    if tok_var_id(tok) != 0:
        var = tok_variable(tok)
        if var and getattr(var, "isConst", False):
            # Check if we have a known value
            values = tok_values(tok)
            for v in values:
                if getattr(v, "valueKind", "") == "known":
                    return True
        return False

    # Arithmetic on constants
    if s in ('+', '-', '*', '/', '%', '&', '|', '^', '~', '<<', '>>', '!'):
        op1 = tok_op1(tok)
        op2 = tok_op2(tok)
        if op1 is not None and not is_constant_expression(op1):
            return False
        if op2 is not None and not is_constant_expression(op2):
            return False
        return True

    # Comparison on constants
    if s in ('==', '!=', '<', '>', '<=', '>='):
        return (is_constant_expression(tok_op1(tok)) and
                is_constant_expression(tok_op2(tok)))

    # Logical on constants
    if s in ('&&', '||'):
        return (is_constant_expression(tok_op1(tok)) and
                is_constant_expression(tok_op2(tok)))

    # Ternary with constant condition
    if s == '?':
        return (is_constant_expression(tok_op1(tok)) and
                is_constant_expression(tok_op2(tok)))

    # Cast of constant
    if is_cast(tok):
        return is_constant_expression(tok_op1(tok))

    return False


def may_be_zero(tok: Token) -> bool:
    """
    Check if an expression may evaluate to zero.

    Useful for division-by-zero and null-pointer checks.

    Args:
        tok: Token to check

    Returns:
        True if the expression may be zero (conservative)
    """
    if tok is None:
        return True  # Conservative

    # Check for literal zero
    s = tok_str(tok)
    if s in ('0', 'NULL', 'nullptr', 'false'):
        return True

    # Check value-flow
    values = tok_values(tok)
    for v in values:
        intval = getattr(v, "intvalue", None)
        if intval is not None and intval == 0:
            return True

    # If no values, be conservative
    if not values:
        return True

    return False


def must_be_zero(tok: Token) -> bool:
    """
    Check if an expression is definitely zero.

    Args:
        tok: Token to check

    Returns:
        True if the expression is definitely zero
    """
    if tok is None:
        return False

    s = tok_str(tok)
    if s in ('0', 'NULL', 'nullptr', 'false'):
        return True

    # Check for known zero value
    values = tok_values(tok)
    if values:
        for v in values:
            if getattr(v, "valueKind", "") == "known":
                intval = getattr(v, "intvalue", None)
                if intval is not None and intval == 0:
                    return True

    return False


def may_be_negative(tok: Token) -> bool:
    """
    Check if an expression may evaluate to a negative value.

    Args:
        tok: Token to check

    Returns:
        True if the expression may be negative (conservative)
    """
    if tok is None:
        return True  # Conservative

    # Check value-flow
    values = tok_values(tok)
    for v in values:
        intval = getattr(v, "intvalue", None)
        if intval is not None and intval < 0:
            return True

    # Check type signedness
    vt = tok_value_type(tok)
    if vt:
        sign = getattr(vt, "sign", None)
        if sign == "unsigned":
            return False

    # If no information, be conservative
    if not values:
        return True

    return False


# ═══════════════════════════════════════════════════════════════════════════
#  PART 6 — FUNCTION CALL ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════

def get_called_function_name(call_tok: Token) -> str:
    """
    Get the name of the function being called.

    Args:
        call_tok: The '(' token of a function call

    Returns:
        The function name, or empty string if not determinable
    """
    if call_tok is None or tok_str(call_tok) != '(':
        return ""

    op1 = tok_op1(call_tok)
    if op1 is None:
        return ""

    # Direct function call: func(...)
    if is_identifier(op1):
        return tok_str(op1)

    # Member function call: obj.method(...) or ptr->method(...)
    if tok_str(op1) in ('.', '->'):
        member = tok_op2(op1)
        if member:
            return tok_str(member)

    # Pointer-to-function call: (*pfn)(...)
    if is_dereference(op1):
        return ""  # Can't determine statically

    return tok_str(op1)


def get_call_arguments(call_tok: Token) -> List[Token]:
    """
    Get the argument expressions of a function call.

    Args:
        call_tok: The '(' token of a function call

    Returns:
        List of argument expression root tokens
    """
    if call_tok is None or tok_str(call_tok) != '(':
        return []

    args: List[Token] = []
    arg_root = tok_op2(call_tok)

    if arg_root is None:
        return args

    _flatten_comma_args(arg_root, args)
    return args


def _flatten_comma_args(tok: Token, out: List[Token]) -> None:
    """
    Helper to flatten comma-separated arguments.

    In Cppcheck AST, f(a, b, c) has astOperand2 as a tree of commas:
        (
         ├─ f
         └─ ,
             ├─ ,
             │   ├─ a
             │   └─ b
             └─ c
    """
    if tok is None:
        return

    if tok_str(tok) == ',':
        _flatten_comma_args(tok_op1(tok), out)
        _flatten_comma_args(tok_op2(tok), out)
    else:
        out.append(tok)


def get_call_argument(call_tok: Token, index: int) -> Optional[Token]:
    """
    Get a specific argument of a function call by index.

    Args:
        call_tok: The '(' token of a function call
        index: Zero-based argument index

    Returns:
        The argument expression, or None if index out of range
    """
    args = get_call_arguments(call_tok)
    if 0 <= index < len(args):
        return args[index]
    return None


def count_call_arguments(call_tok: Token) -> int:
    """
    Count the number of arguments in a function call.

    Args:
        call_tok: The '(' token of a function call

    Returns:
        Number of arguments
    """
    return len(get_call_arguments(call_tok))


def find_function_calls(root: Token) -> Iterator[Token]:
    """
    Find all function calls in an AST subtree.

    Args:
        root: Root of the AST to search

    Yields:
        The '(' token of each function call found
    """
    for tok in iter_ast_preorder(root):
        if is_function_call(tok):
            yield tok


def find_calls_to(root: Token, func_name: str) -> Iterator[Token]:
    """
    Find all calls to a specific function in an AST subtree.

    Args:
        root: Root of the AST to search
        func_name: Name of the function to find

    Yields:
        The '(' token of each matching call
    """
    for call in find_function_calls(root):
        if get_called_function_name(call) == func_name:
            yield call


def is_allocation_call(tok: Token) -> bool:
    """
    Check if a token is a memory allocation function call.

    Args:
        tok: Token to check

    Returns:
        True if tok is a call to malloc, calloc, etc.
    """
    if not is_function_call(tok):
        return False
    return get_called_function_name(tok) in ALLOC_FUNCTIONS


def is_deallocation_call(tok: Token) -> bool:
    """
    Check if a token is a memory deallocation function call.

    Args:
        tok: Token to check

    Returns:
        True if tok is a call to free, delete, etc.
    """
    if not is_function_call(tok):
        return False
    return get_called_function_name(tok) in DEALLOC_FUNCTIONS


# ═══════════════════════════════════════════════════════════════════════════
#  PART 7 — EXPRESSION STRINGIFICATION
# ═══════════════════════════════════════════════════════════════════════════

def expr_to_string(tok: Token, max_depth: int = 50) -> str:
    """
    Convert an AST expression back to a string representation.

    This produces a human-readable approximation of the original source.
    It's useful for error messages and debugging.

    Args:
        tok: Root of the expression AST
        max_depth: Maximum recursion depth (prevents infinite loops)

    Returns:
        String representation of the expression
    """
    if tok is None:
        return ""

    if max_depth <= 0:
        return "..."

    s = tok_str(tok)
    op1 = tok_op1(tok)
    op2 = tok_op2(tok)

    # Leaf node
    if op1 is None and op2 is None:
        return s

    # Unary operators
    if op1 is not None and op2 is None:
        inner = expr_to_string(op1, max_depth - 1)

        # Prefix operators
        if s in ('!', '~', '-', '+', '*', '&', 'sizeof', 'alignof',
                 'typeof', 'decltype', 'throw', 'new', 'delete'):
            if s in ('sizeof', 'alignof', 'typeof', 'decltype'):
                return f"{s}({inner})"
            return f"{s}{inner}"

        # Postfix increment/decrement
        if s in ('++', '--'):
            # Check if prefix or postfix based on AST structure
            # In Cppcheck, prefix ++ has the variable as operand1
            # This is a heuristic
            return f"{inner}{s}"

        # Cast
        if s == '(' and is_cast(tok):
            vt = tok_value_type(tok)
            type_str = getattr(vt, "originalTypeName", "?") if vt else "?"
            return f"({type_str}){inner}"

        # Parentheses (grouping)
        if s == '(':
            return f"({inner})"

        return f"{s}({inner})"

    # Binary operators
    if op1 is not None and op2 is not None:
        left = expr_to_string(op1, max_depth - 1)
        right = expr_to_string(op2, max_depth - 1)

        # Array subscript
        if s == '[':
            return f"{left}[{right}]"

        # Function call
        if s == '(' and is_function_call(tok):
            args = get_call_arguments(tok)
            args_str = ", ".join(expr_to_string(a, max_depth - 1)
                                 for a in args)
            return f"{left}({args_str})"

        # Member access
        if s in ('.', '->'):
            return f"{left}{s}{right}"

        # Ternary operator
        if s == '?':
            # op2 should be ':'
            if tok_str(op2) == ':':
                then_expr = expr_to_string(tok_op1(op2), max_depth - 1)
                else_expr = expr_to_string(tok_op2(op2), max_depth - 1)
                return f"({left} ? {then_expr} : {else_expr})"
            return f"({left} ? {right})"

        # Comma
        if s == ',':
            return f"{left}, {right}"

        # Standard binary operators
        return f"({left} {s} {right})"

    return s


def expr_to_simple_string(tok: Token) -> str:
    """
    Get a simplified string for an expression (for short display).

    This is less accurate but more concise than expr_to_string.

    Args:
        tok: Root of the expression AST

    Returns:
        Simplified string representation
    """
    if tok is None:
        return ""

    s = tok_str(tok)

    # For identifiers, just return the name
    if is_identifier(tok):
        return s

    # For literals, return the value
    if is_literal(tok):
        return s

    # For function calls, return func(...)
    if is_function_call(tok):
        fname = get_called_function_name(tok)
        return f"{fname}(...)"

    # For operators, use a placeholder
    return f"<{s}-expr>"


# ═══════════════════════════════════════════════════════════════════════════
#  PART 8 — PATTERN MATCHING
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class ASTPattern:
    """
    A pattern for matching AST structures.

    Attributes:
        op: Operator/token string to match (None = any)
        op1: Pattern for first operand (None = any, False = must be None)
        op2: Pattern for second operand (None = any, False = must be None)
        predicate: Additional predicate function
    """
    op: Optional[str] = None
    op1: Optional[Union['ASTPattern', bool]] = None
    op2: Optional[Union['ASTPattern', bool]] = None
    predicate: Optional[Callable[[Token], bool]] = None


def matches_pattern(tok: Token, pattern: ASTPattern) -> bool:
    """
    Check if a token matches an AST pattern.

    Args:
        tok: Token to check
        pattern: Pattern to match against

    Returns:
        True if tok matches the pattern

    Example:
        >>> # Match assignment to variable
        >>> pat = ASTPattern(op='=', op1=ASTPattern(predicate=is_identifier))
        >>> matches_pattern(assign_tok, pat)
        True
    """
    if tok is None:
        return False

    # Check operator
    if pattern.op is not None and tok_str(tok) != pattern.op:
        return False

    # Check operand1
    if pattern.op1 is not None:
        op1 = tok_op1(tok)
        if pattern.op1 is False:
            if op1 is not None:
                return False
        elif isinstance(pattern.op1, ASTPattern):
            if not matches_pattern(op1, pattern.op1):
                return False

    # Check operand2
    if pattern.op2 is not None:
        op2 = tok_op2(tok)
        if pattern.op2 is False:
            if op2 is not None:
                return False
        elif isinstance(pattern.op2, ASTPattern):
            if not matches_pattern(op2, pattern.op2):
                return False

    # Check predicate
    if pattern.predicate is not None:
        if not pattern.predicate(tok):
            return False

    return True


def find_matching(root: Token, pattern: ASTPattern) -> Iterator[Token]:
    """
    Find all tokens in a subtree matching a pattern.

    Args:
        root: Root of the AST to search
        pattern: Pattern to match

    Yields:
        Matching tokens
    """
    for tok in iter_ast_preorder(root):
        if matches_pattern(tok, pattern):
            yield tok


def find_first_matching(root: Token, pattern: ASTPattern) -> Optional[Token]:
    """
    Find the first token matching a pattern.

    Args:
        root: Root of the AST to search
        pattern: Pattern to match

    Returns:
        First matching token, or None
    """
    for tok in find_matching(root, pattern):
        return tok
    return None


# ═══════════════════════════════════════════════════════════════════════════
#  PART 9 — VARIABLE USAGE ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════

def find_variable_uses(root: Token, var_id: int) -> Iterator[Token]:
    """
    Find all uses of a variable in an AST subtree.

    Args:
        root: Root of the AST to search
        var_id: Variable ID to find

    Yields:
        Tokens referencing the variable
    """
    if var_id == 0:
        return

    for tok in iter_ast_preorder(root):
        if tok_var_id(tok) == var_id:
            yield tok


def find_variable_writes(root: Token, var_id: int) -> Iterator[Token]:
    """
    Find all writes to a variable in an AST subtree.

    A write occurs when the variable is:
    - LHS of assignment
    - Operand of ++/--
    - Passed by non-const reference/pointer (conservative)

    Args:
        root: Root of the AST to search
        var_id: Variable ID to find

    Yields:
        Tokens where the variable is written
    """
    if var_id == 0:
        return

    for tok in iter_ast_preorder(root):
        if tok_var_id(tok) != var_id:
            continue

        parent = tok_parent(tok)
        if parent is None:
            continue

        ps = tok_str(parent)

        # LHS of assignment
        if ps in ASSIGNMENT_OPS and is_left_operand(tok):
            yield tok
            continue

        # Operand of ++/--
        if ps in ('++', '--'):
            yield tok
            continue

        # Address taken (conservative: might be written through pointer)
        if ps == '&' and is_unary_op(parent):
            yield tok
            continue


def find_variable_reads(root: Token, var_id: int) -> Iterator[Token]:
    """
    Find all reads of a variable in an AST subtree.

    A read occurs when the variable's value is used (not just written).

    Args:
        root: Root of the AST to search
        var_id: Variable ID to find

    Yields:
        Tokens where the variable is read
    """
    if var_id == 0:
        return

    writes = set(id(t) for t in find_variable_writes(root, var_id))

    for tok in iter_ast_preorder(root):
        if tok_var_id(tok) != var_id:
            continue

        # Check if this is purely a write
        if id(tok) in writes:
            parent = tok_parent(tok)
            ps = tok_str(parent) if parent else ""
            # Pure writes: LHS of =, operand of prefix ++/--
            if ps == '=' and is_left_operand(tok):
                continue
            # Compound assignments read AND write
            # ++/-- read AND write

        yield tok


def get_variables_used(root: Token) -> Set[int]:
    """
    Get the set of variable IDs used in an expression.

    Args:
        root: Root of the AST

    Returns:
        Set of variable IDs
    """
    result: Set[int] = set()
    for tok in iter_ast_preorder(root):
        vid = tok_var_id(tok)
        if vid != 0:
            result.add(vid)
    return result


def get_variables_written(root: Token) -> Set[int]:
    """
    Get the set of variable IDs written in an expression.

    Args:
        root: Root of the AST

    Returns:
        Set of variable IDs that are written
    """
    result: Set[int] = set()
    for tok in iter_ast_preorder(root):
        vid = tok_var_id(tok)
        if vid == 0:
            continue

        parent = tok_parent(tok)
        if parent is None:
            continue

        ps = tok_str(parent)
        if ps in ASSIGNMENT_OPS and is_left_operand(tok):
            result.add(vid)
        elif ps in ('++', '--'):
            result.add(vid)

    return result


# ═══════════════════════════════════════════════════════════════════════════
#  PART 10 — SCOPE AND CONTEXT UTILITIES
# ═══════════════════════════════════════════════════════════════════════════

def get_enclosing_scope(tok: Token, scope_type: Optional[str] = None) -> Optional[Any]:
    """
    Get the enclosing scope of a token.

    Args:
        tok: Token to find scope for
        scope_type: Optional type filter ('Function', 'For', 'While', etc.)

    Returns:
        The enclosing Scope object, or None
    """
    scope = tok_scope(tok)
    while scope is not None:
        if scope_type is None or getattr(scope, "type", "") == scope_type:
            return scope
        scope = getattr(scope, "nestedIn", None)
    return None


def get_enclosing_function(tok: Token) -> Optional[Any]:
    """
    Get the enclosing function of a token.

    Args:
        tok: Token to find function for

    Returns:
        The enclosing Function object, or None
    """
    scope = get_enclosing_scope(tok, "Function")
    if scope:
        return getattr(scope, "function", None)
    return None


def is_in_loop(tok: Token) -> bool:
    """
    Check if a token is inside a loop.

    Args:
        tok: Token to check
    Returns:
        True if tok is inside a for, while, or do-while loop
    """
    scope = tok_scope(tok)
    while scope is not None:
        scope_type = getattr(scope, "type", "")
        if scope_type in ("For", "While", "Do"):
            return True
        scope = getattr(scope, "nestedIn", None)
    return False


def is_in_conditional(tok: Token) -> bool:
    """
    Check if a token is inside a conditional (if/else/switch).

    Args:
        tok: Token to check

    Returns:
        True if tok is inside a conditional construct
    """
    scope = tok_scope(tok)
    while scope is not None:
        scope_type = getattr(scope, "type", "")
        if scope_type in ("If", "Else", "Switch"):
            return True
        scope = getattr(scope, "nestedIn", None)
    return False


def is_in_try_block(tok: Token) -> bool:
    """
    Check if a token is inside a try block.

    Args:
        tok: Token to check

    Returns:
        True if tok is inside a try block
    """
    scope = tok_scope(tok)
    while scope is not None:
        scope_type = getattr(scope, "type", "")
        if scope_type == "Try":
            return True
        scope = getattr(scope, "nestedIn", None)
    return False


def is_in_catch_block(tok: Token) -> bool:
    """
    Check if a token is inside a catch block.

    Args:
        tok: Token to check

    Returns:
        True if tok is inside a catch block
    """
    scope = tok_scope(tok)
    while scope is not None:
        scope_type = getattr(scope, "type", "")
        if scope_type == "Catch":
            return True
        scope = getattr(scope, "nestedIn", None)
    return False


def get_loop_condition(loop_scope: Any) -> Optional[Token]:
    """
    Get the condition expression of a loop.

    Args:
        loop_scope: A Scope object of type For, While, or Do

    Returns:
        The condition token, or None
    """
    if loop_scope is None:
        return None

    scope_type = getattr(loop_scope, "type", "")
    if scope_type not in ("For", "While", "Do"):
        return None

    # The condition is typically in the scope's classStart area
    # This is a heuristic based on Cppcheck's structure
    class_start = getattr(loop_scope, "bodyStart", None)
    if class_start is None:
        return None

    # Walk backward to find the condition
    tok = tok_previous(class_start)
    while tok is not None:
        if tok_str(tok) == ')':
            # Found the end of condition, look for the expression
            link = tok_link(tok)
            if link:
                # The condition is between link and tok
                return tok_op1(tok) if tok_op1(tok) else tok_next(link)
        if tok_str(tok) in ('while', 'for', 'do'):
            break
        tok = tok_previous(tok)

    return None


def get_if_condition(if_scope: Any) -> Optional[Token]:
    """
    Get the condition expression of an if statement.

    Args:
        if_scope: A Scope object of type If

    Returns:
        The condition token, or None
    """
    if if_scope is None:
        return None

    if getattr(if_scope, "type", "") != "If":
        return None

    class_start = getattr(if_scope, "bodyStart", None)
    if class_start is None:
        return None

    # Walk backward to find ')'
    tok = tok_previous(class_start)
    while tok is not None:
        if tok_str(tok) == ')':
            link = tok_link(tok)
            if link:
                cond = tok_next(link)
                if cond and tok_str(cond) != ')':
                    # Return the AST root of the condition
                    return find_ast_root(cond)
        if tok_str(tok) == 'if':
            break
        tok = tok_previous(tok)

    return None


# ═══════════════════════════════════════════════════════════════════════════
#  PART 11 — TYPE UTILITIES
# ═══════════════════════════════════════════════════════════════════════════

def get_type_str(tok: Token) -> str:
    """
    Get a string representation of a token's type.

    Args:
        tok: Token to get type for

    Returns:
        Type string, or "?" if unknown
    """
    vt = tok_value_type(tok)
    if vt is None:
        return "?"

    # Try originalTypeName first
    orig = getattr(vt, "originalTypeName", "")
    if orig:
        return orig

    # Build from components
    parts = []

    sign = getattr(vt, "sign", "")
    if sign:
        parts.append(sign)

    type_name = getattr(vt, "type", "")
    if type_name:
        parts.append(type_name)

    pointer = getattr(vt, "pointer", 0)
    if pointer:
        parts.append("*" * pointer)

    return " ".join(parts) if parts else "?"


def is_pointer_type(tok: Token) -> bool:
    """
    Check if a token has a pointer type.

    Args:
        tok: Token to check

    Returns:
        True if tok has a pointer type
    """
    vt = tok_value_type(tok)
    if vt is None:
        return False
    pointer = getattr(vt, "pointer", 0)
    return pointer > 0


def is_array_type(tok: Token) -> bool:
    """
    Check if a token has an array type.

    Args:
        tok: Token to check

    Returns:
        True if tok has an array type
    """
    var = tok_variable(tok)
    if var:
        return bool(getattr(var, "isArray", False))
    return False


def is_integral_type(tok: Token) -> bool:
    """
    Check if a token has an integral type (int, char, etc.).

    Args:
        tok: Token to check

    Returns:
        True if tok has an integral type
    """
    vt = tok_value_type(tok)
    if vt is None:
        return False

    type_name = getattr(vt, "type", "")
    return type_name in (
        "bool", "char", "short", "int", "long",
        "char16_t", "char32_t", "wchar_t",
    )


def is_floating_type(tok: Token) -> bool:
    """
    Check if a token has a floating-point type.

    Args:
        tok: Token to check

    Returns:
        True if tok has a floating-point type
    """
    vt = tok_value_type(tok)
    if vt is None:
        return False

    type_name = getattr(vt, "type", "")
    return type_name in ("float", "double")


def is_signed_type(tok: Token) -> bool:
    """
    Check if a token has a signed type.

    Args:
        tok: Token to check

    Returns:
        True if tok has a signed type
    """
    vt = tok_value_type(tok)
    if vt is None:
        return True  # Default to signed (conservative)

    sign = getattr(vt, "sign", "")
    return sign != "unsigned"


def is_unsigned_type(tok: Token) -> bool:
    """
    Check if a token has an unsigned type.

    Args:
        tok: Token to check

    Returns:
        True if tok has an unsigned type
    """
    vt = tok_value_type(tok)
    if vt is None:
        return False

    sign = getattr(vt, "sign", "")
    return sign == "unsigned"


def get_sizeof_type(tok: Token) -> Optional[int]:
    """
    Get the size in bytes of a token's type.

    Args:
        tok: Token to get size for

    Returns:
        Size in bytes, or None if unknown
    """
    vt = tok_value_type(tok)
    if vt is None:
        return None

    # Check for explicit size information
    type_size = getattr(vt, "typeSize", None)
    if type_size:
        return int(type_size)

    # Estimate based on type name
    type_name = getattr(vt, "type", "")
    pointer = getattr(vt, "pointer", 0)

    if pointer > 0:
        return 8  # Assume 64-bit pointers

    size_map = {
        "bool": 1,
        "char": 1,
        "short": 2,
        "int": 4,
        "long": 8,  # Assume LP64
        "float": 4,
        "double": 8,
    }

    return size_map.get(type_name)


def get_array_size(tok: Token) -> Optional[int]:
    """
    Get the declared size of an array.

    Args:
        tok: Token referencing an array variable

    Returns:
        Array size, or None if unknown or not an array
    """
    var = tok_variable(tok)
    if var is None:
        return None

    if not getattr(var, "isArray", False):
        return None

    # Check for dimension information
    dimensions = getattr(var, "dimensions", None)
    if dimensions:
        # Return first dimension size
        for dim in dimensions:
            size = getattr(dim, "num", None)
            if size is not None:
                return int(size)

    return None


# ═══════════════════════════════════════════════════════════════════════════
#  PART 12 — TOKEN SEQUENCE UTILITIES
# ═══════════════════════════════════════════════════════════════════════════

def iter_tokens_in_range(start: Token, end: Token) -> Iterator[Token]:
    """
    Iterate over tokens from start to end (inclusive).

    Args:
        start: Starting token
        end: Ending token

    Yields:
        Tokens from start to end
    """
    if start is None:
        return

    current = start
    while current is not None:
        yield current
        if current is end:
            break
        current = tok_next(current)


def iter_tokens_in_scope(scope: Any) -> Iterator[Token]:
    """
    Iterate over all tokens in a scope.

    Args:
        scope: A Scope object

    Yields:
        Tokens within the scope
    """
    if scope is None:
        return

    start = getattr(scope, "bodyStart", None)
    end = getattr(scope, "bodyEnd", None)

    if start is None or end is None:
        return

    yield from iter_tokens_in_range(start, end)


def find_token_by_str(start: Token, target: str, end: Token = None) -> Optional[Token]:
    """
    Find the first token with a specific string value.

    Args:
        start: Starting token
        target: String to search for
        end: Optional ending token (exclusive)

    Returns:
        First matching token, or None
    """
    current = start
    while current is not None and current is not end:
        if tok_str(current) == target:
            return current
        current = tok_next(current)
    return None


def find_tokens_by_str(start: Token, target: str, end: Token = None) -> Iterator[Token]:
    """
    Find all tokens with a specific string value.

    Args:
        start: Starting token
        target: String to search for
        end: Optional ending token (exclusive)

    Yields:
        All matching tokens
    """
    current = start
    while current is not None and current is not end:
        if tok_str(current) == target:
            yield current
        current = tok_next(current)


def count_tokens_in_range(start: Token, end: Token) -> int:
    """
    Count tokens in a range.

    Args:
        start: Starting token
        end: Ending token (inclusive)

    Returns:
        Number of tokens
    """
    count = 0
    for _ in iter_tokens_in_range(start, end):
        count += 1
    return count


# ═══════════════════════════════════════════════════════════════════════════
#  PART 13 — STATEMENT CLASSIFICATION
# ═══════════════════════════════════════════════════════════════════════════

class StatementKind(Enum):
    """Classification of statement types."""
    UNKNOWN = auto()
    EXPRESSION = auto()
    DECLARATION = auto()
    ASSIGNMENT = auto()
    RETURN = auto()
    IF = auto()
    ELSE = auto()
    FOR = auto()
    WHILE = auto()
    DO_WHILE = auto()
    SWITCH = auto()
    CASE = auto()
    DEFAULT = auto()
    BREAK = auto()
    CONTINUE = auto()
    GOTO = auto()
    LABEL = auto()
    TRY = auto()
    CATCH = auto()
    THROW = auto()
    COMPOUND = auto()  # { ... }
    EMPTY = auto()     # ;


def classify_statement(tok: Token) -> StatementKind:
    """
    Classify the type of statement starting at a token.

    Args:
        tok: First token of a statement

    Returns:
        The statement kind
    """
    if tok is None:
        return StatementKind.UNKNOWN

    s = tok_str(tok)

    # Keywords
    if s == "return":
        return StatementKind.RETURN
    if s == "if":
        return StatementKind.IF
    if s == "else":
        return StatementKind.ELSE
    if s == "for":
        return StatementKind.FOR
    if s == "while":
        return StatementKind.WHILE
    if s == "do":
        return StatementKind.DO_WHILE
    if s == "switch":
        return StatementKind.SWITCH
    if s == "case":
        return StatementKind.CASE
    if s == "default":
        return StatementKind.DEFAULT
    if s == "break":
        return StatementKind.BREAK
    if s == "continue":
        return StatementKind.CONTINUE
    if s == "goto":
        return StatementKind.GOTO
    if s == "try":
        return StatementKind.TRY
    if s == "catch":
        return StatementKind.CATCH
    if s == "throw":
        return StatementKind.THROW

    # Compound statement
    if s == "{":
        return StatementKind.COMPOUND

    # Empty statement
    if s == ";":
        return StatementKind.EMPTY

    # Label (identifier followed by :)
    if is_identifier(tok):
        next_tok = tok_next(tok)
        if next_tok and tok_str(next_tok) == ":":
            next_next = tok_next(next_tok)
            if next_next and tok_str(next_next) != ":":  # Not ::
                return StatementKind.LABEL

    # Declaration vs expression
    # This is a heuristic; accurate detection requires type information
    var = tok_variable(tok)
    if var:
        name_tok = getattr(var, "nameToken", None)
        if name_tok is tok:
            return StatementKind.DECLARATION

    # Check for type keywords
    type_keywords = {
        "void", "char", "short", "int", "long", "float", "double",
        "signed", "unsigned", "bool", "auto", "const", "volatile",
        "static", "extern", "register", "inline", "struct", "class",
        "union", "enum", "typedef",
    }
    if s in type_keywords:
        return StatementKind.DECLARATION

    # Assignment statement
    root = find_ast_root(tok)
    if root and is_assignment(root):
        return StatementKind.ASSIGNMENT

    # Default to expression
    return StatementKind.EXPRESSION


# ═══════════════════════════════════════════════════════════════════════════
#  PART 14 — CONTROL FLOW UTILITIES
# ═══════════════════════════════════════════════════════════════════════════

def is_return_statement(tok: Token) -> bool:
    """
    Check if a token starts a return statement.

    Args:
        tok: Token to check

    Returns:
        True if tok is 'return'
    """
    return tok_str(tok) == "return"


def get_return_value(return_tok: Token) -> Optional[Token]:
    """
    Get the return value expression of a return statement.

    Args:
        return_tok: The 'return' token

    Returns:
        The return value expression, or None for bare return
    """
    if tok_str(return_tok) != "return":
        return None

    # In Cppcheck AST, return value is astOperand1
    return tok_op1(return_tok)


def is_break_statement(tok: Token) -> bool:
    """
    Check if a token is a break statement.

    Args:
        tok: Token to check

    Returns:
        True if tok is 'break'
    """
    return tok_str(tok) == "break"


def is_continue_statement(tok: Token) -> bool:
    """
    Check if a token is a continue statement.

    Args:
        tok: Token to check

    Returns:
        True if tok is 'continue'
    """
    return tok_str(tok) == "continue"


def is_goto_statement(tok: Token) -> bool:
    """
    Check if a token is a goto statement.

    Args:
        tok: Token to check

    Returns:
        True if tok is 'goto'
    """
    return tok_str(tok) == "goto"


def get_goto_label(goto_tok: Token) -> str:
    """
    Get the target label of a goto statement.

    Args:
        goto_tok: The 'goto' token

    Returns:
        The label name, or empty string
    """
    if tok_str(goto_tok) != "goto":
        return ""

    next_tok = tok_next(goto_tok)
    if next_tok and is_identifier(next_tok):
        return tok_str(next_tok)

    return ""


def can_fall_through(tok: Token) -> bool:
    """
    Check if control can fall through past a statement.

    Returns False for return, break, continue, goto, throw.

    Args:
        tok: First token of a statement

    Returns:
        True if control can fall through
    """
    s = tok_str(tok)
    return s not in ("return", "break", "continue", "goto", "throw")


def find_returns_in_scope(scope: Any) -> Iterator[Token]:
    """
    Find all return statements in a scope.

    Args:
        scope: A Scope object

    Yields:
        'return' tokens
    """
    for tok in iter_tokens_in_scope(scope):
        if tok_str(tok) == "return":
            yield tok


def find_exits_in_scope(scope: Any) -> Iterator[Token]:
    """
    Find all exit points (return, break, continue, goto, throw) in a scope.

    Args:
        scope: A Scope object

    Yields:
        Exit statement tokens
    """
    exit_keywords = {"return", "break", "continue", "goto", "throw"}
    for tok in iter_tokens_in_scope(scope):
        if tok_str(tok) in exit_keywords:
            yield tok


# ═══════════════════════════════════════════════════════════════════════════
#  PART 15 — CONVENIENCE SEARCH FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════

def find_assignments(root: Token) -> Iterator[Token]:
    """
    Find all assignment expressions in an AST subtree.

    Args:
        root: Root of the AST to search

    Yields:
        Assignment operator tokens
    """
    for tok in iter_ast_preorder(root):
        if is_assignment(tok):
            yield tok


def find_comparisons(root: Token) -> Iterator[Token]:
    """
    Find all comparison expressions in an AST subtree.

    Args:
        root: Root of the AST to search

    Yields:
        Comparison operator tokens
    """
    for tok in iter_ast_preorder(root):
        if is_comparison(tok):
            yield tok


def find_dereferences(root: Token) -> Iterator[Token]:
    """
    Find all pointer dereferences in an AST subtree.

    Args:
        root: Root of the AST to search

    Yields:
        Dereference operator tokens
    """
    for tok in iter_ast_preorder(root):
        if is_dereference(tok):
            yield tok


def find_array_accesses(root: Token) -> Iterator[Token]:
    """
    Find all array subscript operations in an AST subtree.

    Args:
        root: Root of the AST to search

    Yields:
        '[' tokens representing array access
    """
    for tok in iter_ast_preorder(root):
        if is_subscript(tok):
            yield tok


def find_null_checks(root: Token) -> Iterator[Token]:
    """
    Find comparisons against null (NULL, nullptr, 0).

    Args:
        root: Root of the AST to search

    Yields:
        Comparison tokens checking for null
    """
    for tok in iter_ast_preorder(root):
        if not is_comparison(tok):
            continue

        op1 = tok_op1(tok)
        op2 = tok_op2(tok)

        if op1 and tok_str(op1) in ("NULL", "nullptr", "0"):
            yield tok
        elif op2 and tok_str(op2) in ("NULL", "nullptr", "0"):
            yield tok


def find_arithmetic_on_pointers(root: Token) -> Iterator[Token]:
    """
    Find pointer arithmetic operations.

    Args:
        root: Root of the AST to search

    Yields:
        Arithmetic operator tokens involving pointers
    """
    for tok in iter_ast_preorder(root):
        s = tok_str(tok)
        if s not in ("+", "-", "+=", "-=", "++", "--"):
            continue

        op1 = tok_op1(tok)
        op2 = tok_op2(tok)

        if op1 and is_pointer_type(op1):
            yield tok
        elif op2 and is_pointer_type(op2):
            yield tok


# ═══════════════════════════════════════════════════════════════════════════
#  PART 16 — DEBUG UTILITIES
# ═══════════════════════════════════════════════════════════════════════════

def dump_ast(root: Token, indent: int = 0, max_depth: int = 20) -> str:
    """
    Create a string representation of an AST for debugging.

    Args:
        root: Root of the AST
        indent: Current indentation level
        max_depth: Maximum depth to display

    Returns:
        Multi-line string representation
    """
    if root is None:
        return " " * indent + "(null)\n"

    if max_depth <= 0:
        return " " * indent + "...\n"

    lines = []
    prefix = " " * indent

    # Node info
    s = tok_str(root)
    vid = tok_var_id(root)
    var_info = f" [var:{vid}]" if vid else ""
    type_info = ""
    vt = tok_value_type(root)
    if vt:
        type_info = f" <{get_type_str(root)}>"

    lines.append(f"{prefix}{s!r}{var_info}{type_info}\n")

    # Children
    op1 = tok_op1(root)
    op2 = tok_op2(root)

    if op1 is not None or op2 is not None:
        if op1 is not None:
            lines.append(f"{prefix}├─ op1:\n")
            lines.append(dump_ast(op1, indent + 4, max_depth - 1))
        if op2 is not None:
            lines.append(f"{prefix}└─ op2:\n")
            lines.append(dump_ast(op2, indent + 4, max_depth - 1))

    return "".join(lines)


def print_ast(root: Token, max_depth: int = 20) -> None:
    """
    Print an AST for debugging.

    Args:
        root: Root of the AST
        max_depth: Maximum depth to display
    """
    print(dump_ast(root, max_depth=max_depth))


def token_location(tok: Token) -> str:
    """
    Get a human-readable location string for a token.

    Args:
        tok: Token to locate

    Returns:
        String like "file.c:42:10"
    """
    if tok is None:
        return "<unknown>"

    file = tok_file(tok)
    line = tok_line(tok)
    col = tok_column(tok)

    return f"{file}:{line}:{col}"


def describe_token(tok: Token) -> str:
    """
    Get a detailed description of a token for debugging.

    Args:
        tok: Token to describe

    Returns:
        Multi-line description string
    """
    if tok is None:
        return "(null token)"

    lines = [
        f"Token: {tok_str(tok)!r}",
        f"  Location: {token_location(tok)}",
    ]

    vid = tok_var_id(tok)
    if vid:
        lines.append(f"  Variable ID: {vid}")

    var = tok_variable(tok)
    if var:
        var_name = getattr(var, "name", "?")
        lines.append(f"  Variable: {var_name}")

    vt = tok_value_type(tok)
    if vt:
        lines.append(f"  Type: {get_type_str(tok)}")

    values = tok_values(tok)
    if values:
        lines.append(f"  Values: {len(values)} value(s)")
        for v in values[:3]:  # Show first 3
            intval = getattr(v, "intvalue", None)
            kind = getattr(v, "valueKind", "?")
            if intval is not None:
                lines.append(f"    - {intval} ({kind})")

    return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════════
#  MODULE EXPORTS
# ═══════════════════════════════════════════════════════════════════════════

__all__ = [
    # Safe accessors
    "tok_str", "tok_op1", "tok_op2", "tok_parent",
    "tok_var_id", "tok_variable", "tok_function", "tok_scope",
    "tok_value_type", "tok_values", "tok_link",
    "tok_next", "tok_previous",
    "tok_file", "tok_line", "tok_column",

    # AST traversal
    "iter_ast_preorder", "iter_ast_postorder", "iter_ast_levelorder",
    "iter_ast_leaves", "iter_parents", "iter_parents_inclusive",
    "collect_subtree", "ast_depth", "ast_size", "find_ast_root",

    # AST predicates
    "is_binary_op", "is_unary_op", "is_leaf",
    "is_identifier", "is_number", "is_string_literal", "is_char_literal",
    "is_literal", "is_cast",
    "is_comparison", "is_logical_op", "is_arithmetic_op",
    "is_assignment", "is_compound_assignment", "is_increment_decrement",
    "is_dereference", "is_address_of", "is_subscript", "is_member_access",
    "is_function_call", "is_sizeof", "is_ternary", "is_comma",
    "is_in_sizeof", "is_in_typeof", "is_in_noexcept", "is_unevaluated_context",

    # Relationship predicates
    "is_child_of", "is_descendant_of", "is_ancestor_of",
    "is_left_operand", "is_right_operand",
    "shares_subtree", "get_common_ancestor",

    # Expression analysis
    "is_lvalue", "is_rvalue", "is_modifiable_lvalue",
    "has_side_effects", "is_pure_expression", "is_constant_expression",
    "may_be_zero", "must_be_zero", "may_be_negative",

    # Function call analysis
    "get_called_function_name", "get_call_arguments", "get_call_argument",
    "count_call_arguments", "find_function_calls", "find_calls_to",
    "is_allocation_call", "is_deallocation_call",

    # Expression stringification
    "expr_to_string", "expr_to_simple_string",

    # Pattern matching
    "ASTPattern", "matches_pattern", "find_matching", "find_first_matching",

    # Variable usage
    "find_variable_uses", "find_variable_writes", "find_variable_reads",
    "get_variables_used", "get_variables_written",

    # Scope and context
    "get_enclosing_scope", "get_enclosing_function",
    "is_in_loop", "is_in_conditional", "is_in_try_block", "is_in_catch_block",
    "get_loop_condition", "get_if_condition",

    # Type utilities
    "get_type_str", "is_pointer_type", "is_array_type",
    "is_integral_type", "is_floating_type",
    "is_signed_type", "is_unsigned_type",
    "get_sizeof_type", "get_array_size",

    # Token sequence utilities
    "iter_tokens_in_range", "iter_tokens_in_scope",
    "find_token_by_str", "find_tokens_by_str", "count_tokens_in_range",

    # Statement classification
    "StatementKind", "classify_statement",

    # Control flow utilities
    "is_return_statement", "get_return_value",
    "is_break_statement", "is_continue_statement",
    "is_goto_statement", "get_goto_label",
    "can_fall_through", "find_returns_in_scope", "find_exits_in_scope",

    # Convenience search functions
    "find_assignments", "find_comparisons", "find_dereferences",
    "find_array_accesses", "find_null_checks", "find_arithmetic_on_pointers",

    # Constants
    "ARITHMETIC_OPS", "BITWISE_OPS", "COMPARISON_OPS", "LOGICAL_OPS",
    "ASSIGNMENT_OPS", "BINARY_OPS", "UNARY_OPS", "SIDE_EFFECT_OPS",
    "ALLOC_FUNCTIONS", "DEALLOC_FUNCTIONS", "PURE_FUNCTIONS",

    # Debug utilities
    "dump_ast", "print_ast", "token_location", "describe_token",
]
