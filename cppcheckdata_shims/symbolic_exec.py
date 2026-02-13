"""
cppcheckdata_shims.symbolic_exec
===================================

Symbolic execution engine for C programs via Cppcheck dump files.

This module provides both **dynamic symbolic execution** (DSE) and
**static symbolic execution** (SSE) for C programs, using the CFGs and
call graphs built by the sibling modules.  It constructs symbolic
expressions, path conditions (guards), and interfaces with SMT solvers
to find bug-triggering inputs.

Theory
------
Symbolic execution [King 1976] executes a program abstractly, replacing
concrete inputs with symbolic constants.  Each variable maps to a
symbolic expression, and each branch introduces a constraint (path
condition / guard) on those symbols:

.. math::

    \\Sigma \\in \\text{Var} \\to \\text{SymExpr}

.. math::

    g ::= \\text{true} \\mid \\text{false} \\mid \\neg g
          \\mid g_1 \\land g_2 \\mid g_1 \\lor g_2
          \\mid \\text{as}_1\\ \\text{op}_r\\ \\text{as}_2

At each conditional branch ``if b then S₁ else S₂``:

- **DSE** forks: explores the true branch (adding ``g ∧ b`` to the path
  condition) and the false branch (adding ``g ∧ ¬b``) independently,
  producing a *tree* of paths.
- **SSE** merges: introduces fresh symbolic variables at join points,
  producing a single formula.

Loops are handled by **bounded unrolling** (up to *k* iterations) or
by importing **loop invariants** from abstract interpretation.

Architecture
------------
::

    ┌─────────────────────────────────────────────────────────────┐
    │                    SymbolicExecutor                          │
    │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │
    │  │  SymExpr      │  │ SymState     │  │ PathCondition    │  │
    │  │  (expression  │  │ (Σ: Var→Expr │  │ (g: constraint   │  │
    │  │   AST)        │  │  + guard)    │  │   conjunction)   │  │
    │  └──────┬────────┘  └──────┬───────┘  └──────┬───────────┘  │
    │         │                  │                  │              │
    │  ┌──────▼──────────────────▼──────────────────▼───────────┐ │
    │  │              Exploration Engine                         │ │
    │  │   DSE: worklist of (node, state, guard)                │ │
    │  │   SSE: merge at join points with fresh symbols         │ │
    │  └────────────────────────┬────────────────────────────────┘ │
    │                           │                                  │
    │  ┌────────────────────────▼────────────────────────────────┐ │
    │  │              SMT Solver Interface                       │ │
    │  │   z3 (preferred) / cvc5 / pysmt / internal simplifier  │ │
    │  └─────────────────────────────────────────────────────────┘ │
    └─────────────────────────────────────────────────────────────┘

Symbolic Expressions
~~~~~~~~~~~~~~~~~~~~
:class:`SymExpr` is a tree-structured symbolic expression:

- ``SymConst(value)`` — concrete integer / float
- ``SymVar(name, version)`` — symbolic variable (SSA-like versioning)
- ``SymBinOp(op, left, right)`` — binary operation
- ``SymUnaryOp(op, operand)`` — unary operation
- ``SymITE(cond, true_val, false_val)`` — if-then-else
- ``SymExtract / SymConcat`` — bit-level operations

Symbolic State
~~~~~~~~~~~~~~
:class:`SymState` maps variables to symbolic expressions and carries
the accumulated **path condition** (guard ``g``).

Exploration Strategies
~~~~~~~~~~~~~~~~~~~~~~
:class:`ExplorationStrategy` controls path selection:

- ``DFS`` — depth-first (finds deep bugs quickly)
- ``BFS`` — breadth-first (complete up to depth)
- ``RANDOM`` — random path selection
- ``COVERAGE`` — prioritize uncovered branches
- ``SHORTEST_DISTANCE`` — prioritize paths closest to target

SMT Solver
~~~~~~~~~~
:class:`SMTSolver` provides an abstract interface to satisfiability
solvers, with backends for z3, pysmt, and a built-in simplifier.

Public API
----------
    SymExpr, SymConst, SymVar, SymBinOp, SymUnaryOp, SymITE
    SymState
    PathCondition
    SymbolicExecutor
    ConcolicExecutor
    ExplorationStrategy
    SMTSolver, Z3Backend, InternalSimplifier
    TestCase
    execute_function
    execute_path
    find_assertion_violations
    find_bug_triggering_inputs

Usage example
-------------
::

    from cppcheckdata_shims.controlflow_graph import build_cfg
    from cppcheckdata_shims.symbolic_exec import (
        SymbolicExecutor, Z3Backend, execute_function,
    )

    cfg = build_cfg(some_function)
    results = execute_function(cfg, max_paths=1000)

    for path_result in results:
        if path_result.is_error:
            print(f"Bug found on path: {path_result.path}")
            print(f"  Inputs: {path_result.test_case}")
            print(f"  Error:  {path_result.error_message}")
"""

from __future__ import annotations

import abc
import copy
import enum
import hashlib
import itertools
import math
import operator
import os
import random
import sys
import time
import warnings
from collections import OrderedDict, defaultdict, deque
from dataclasses import dataclass, field
from typing import (
    Any,
    Callable,
    Deque,
    Dict,
    FrozenSet,
    Generic,
    Hashable,
    Iterable,
    Iterator,
    List,
    Mapping,
    Optional,
    Protocol,
    Sequence,
    Set,
    Tuple,
    Type,
    TypeVar,
    Union,
)

# Relative imports from sibling modules
from . import abstract_interp as ai
from . import dataflow_engine as dfe

# ===================================================================
# CONSTANTS
# ===================================================================

# Maximum integer for sentinel values
_MAX_INT = (1 << 63) - 1
_MIN_INT = -(1 << 63)

# Default limits
DEFAULT_MAX_PATHS = 10_000
DEFAULT_MAX_DEPTH = 500
DEFAULT_LOOP_BOUND = 10
DEFAULT_TIMEOUT_SECONDS = 300.0


# ===================================================================
# SYMBOLIC EXPRESSION AST
# ===================================================================

class SymExprKind(enum.Enum):
    """Kinds of symbolic expressions."""
    CONST = "const"
    VAR = "var"
    BINOP = "binop"
    UNARYOP = "unaryop"
    ITE = "ite"             # if-then-else
    EXTRACT = "extract"     # bit extraction
    CONCAT = "concat"       # bit concatenation
    FUNCTION_APP = "apply"  # uninterpreted function application
    MEMORY_READ = "mem_read"
    MEMORY_WRITE = "mem_write"


class SymExpr(abc.ABC):
    """Abstract base class for symbolic expressions.

    A symbolic expression is a tree-structured term representing a
    value that depends on symbolic inputs.  Concrete integers are
    leaves; operations build internal nodes.

    The expression language is:

    .. math::

        \\text{as} ::= \\alpha \\mid n \\mid \\text{as}_1\\ \\text{op}_a\\ \\text{as}_2
                       \\mid \\text{op}_u\\ \\text{as}
                       \\mid \\text{ite}(g, \\text{as}_1, \\text{as}_2)
    """

    __slots__ = ("_hash", "_simplified")

    @property
    @abc.abstractmethod
    def kind(self) -> SymExprKind:
        """The kind of this expression."""
        ...

    @property
    @abc.abstractmethod
    def children(self) -> Tuple["SymExpr", ...]:
        """Child sub-expressions (for tree traversal)."""
        ...

    @property
    def bit_width(self) -> Optional[int]:
        """Bit width of the expression, if known."""
        return None

    @abc.abstractmethod
    def substitute(self, mapping: Dict[str, "SymExpr"]) -> "SymExpr":
        """Substitute symbolic variables according to a mapping.

        Parameters
        ----------
        mapping : dict[str, SymExpr]
            Map from variable name to replacement expression.

        Returns
        -------
        SymExpr
        """
        ...

    def evaluate(self, env: Dict[str, int]) -> Optional[int]:
        """Evaluate the expression under a concrete environment.

        Parameters
        ----------
        env : dict[str, int]
            Map from variable name to concrete integer value.

        Returns
        -------
        int or None
            The concrete value, or ``None`` if evaluation fails.
        """
        return None  # default; subclasses override

    @property
    def is_concrete(self) -> bool:
        """Is this expression a concrete constant?"""
        return False

    @property
    def concrete_value(self) -> Optional[int]:
        """The concrete integer value, if this is a constant."""
        return None

    @property
    def free_variables(self) -> FrozenSet[str]:
        """Set of free symbolic variable names in this expression."""
        result: Set[str] = set()
        self._collect_free_vars(result)
        return frozenset(result)

    def _collect_free_vars(self, result: Set[str]) -> None:
        for child in self.children:
            child._collect_free_vars(result)

    def __repr__(self) -> str:
        return self._to_string()

    @abc.abstractmethod
    def _to_string(self) -> str:
        ...

    def __eq__(self, other) -> bool:
        if not isinstance(other, SymExpr):
            return NotImplemented
        return self._structural_eq(other)

    @abc.abstractmethod
    def _structural_eq(self, other: "SymExpr") -> bool:
        ...

    def __hash__(self) -> int:
        if not hasattr(self, "_hash") or self._hash is None:
            self._hash = self._compute_hash()
        return self._hash

    @abc.abstractmethod
    def _compute_hash(self) -> int:
        ...

    def simplify(self) -> "SymExpr":
        """Apply algebraic simplification rules.

        Returns a (possibly) simplified equivalent expression.
        """
        return _simplify_expr(self)


# ---- Concrete constant ---------------------------------------------------

class SymConst(SymExpr):
    """A concrete integer or float constant.

    Parameters
    ----------
    value : int or float
        The constant value.
    width : int, optional
        Bit width (default: 64).
    """

    __slots__ = ("value", "width", "_hash", "_simplified")

    def __init__(self, value: Union[int, float], width: int = 64) -> None:
        self.value = int(value) if isinstance(value, float) and value == int(value) else value
        self.width = width
        self._hash: Optional[int] = None
        self._simplified = False

    @property
    def kind(self) -> SymExprKind:
        return SymExprKind.CONST

    @property
    def children(self) -> Tuple[SymExpr, ...]:
        return ()

    @property
    def bit_width(self) -> Optional[int]:
        return self.width

    @property
    def is_concrete(self) -> bool:
        return True

    @property
    def concrete_value(self) -> Optional[int]:
        return int(self.value) if isinstance(self.value, (int, float)) else None

    def substitute(self, mapping: Dict[str, SymExpr]) -> SymExpr:
        return self

    def evaluate(self, env: Dict[str, int]) -> Optional[int]:
        return int(self.value)

    def _to_string(self) -> str:
        return str(self.value)

    def _structural_eq(self, other: SymExpr) -> bool:
        return isinstance(other, SymConst) and self.value == other.value

    def _compute_hash(self) -> int:
        return hash(("const", self.value))


# ---- Symbolic variable ---------------------------------------------------

class SymVar(SymExpr):
    """A symbolic variable (symbolic constant in the literature).

    Represents an unknown input value.  Variables are versioned (SSA-style)
    to track updates: ``x_0`` is the initial value, ``x_1`` after the first
    assignment, etc.

    Parameters
    ----------
    name : str
        The variable name.
    version : int
        SSA version number (0 = initial/input).
    width : int
        Bit width.
    """

    __slots__ = ("name", "version", "width", "_hash", "_simplified")

    def __init__(
        self, name: str, version: int = 0, width: int = 64
    ) -> None:
        self.name = name
        self.version = version
        self.width = width
        self._hash: Optional[int] = None
        self._simplified = False

    @property
    def kind(self) -> SymExprKind:
        return SymExprKind.VAR

    @property
    def children(self) -> Tuple[SymExpr, ...]:
        return ()

    @property
    def bit_width(self) -> Optional[int]:
        return self.width

    @property
    def qualified_name(self) -> str:
        """Fully qualified name with version: ``x_0``, ``x_1``, etc."""
        if self.version == 0:
            return self.name
        return f"{self.name}_{self.version}"

    def substitute(self, mapping: Dict[str, SymExpr]) -> SymExpr:
        key = self.qualified_name
        if key in mapping:
            return mapping[key]
        if self.name in mapping:
            return mapping[self.name]
        return self

    def evaluate(self, env: Dict[str, int]) -> Optional[int]:
        key = self.qualified_name
        if key in env:
            return env[key]
        if self.name in env:
            return env[self.name]
        return None

    def _collect_free_vars(self, result: Set[str]) -> None:
        result.add(self.qualified_name)

    def _to_string(self) -> str:
        return self.qualified_name

    def _structural_eq(self, other: SymExpr) -> bool:
        return (isinstance(other, SymVar)
                and self.name == other.name
                and self.version == other.version)

    def _compute_hash(self) -> int:
        return hash(("var", self.name, self.version))


# ---- Binary operation -----------------------------------------------------

class SymBinOp(SymExpr):
    """A binary operation on symbolic expressions.

    Parameters
    ----------
    op : str
        Operator string: ``'+'``, ``'-'``, ``'*'``, ``'/'``, ``'%'``,
        ``'<<'``, ``'>>'``, ``'&'``, ``'|'``, ``'^'``,
        ``'<'``, ``'<='``, ``'>'``, ``'>='``, ``'=='``, ``'!='``,
        ``'&&'``, ``'||'``.
    left : SymExpr
        Left operand.
    right : SymExpr
        Right operand.
    """

    __slots__ = ("op", "left", "right", "_hash", "_simplified")

    def __init__(self, op: str, left: SymExpr, right: SymExpr) -> None:
        self.op = op
        self.left = left
        self.right = right
        self._hash: Optional[int] = None
        self._simplified = False

    @property
    def kind(self) -> SymExprKind:
        return SymExprKind.BINOP

    @property
    def children(self) -> Tuple[SymExpr, ...]:
        return (self.left, self.right)

    @property
    def bit_width(self) -> Optional[int]:
        lw = self.left.bit_width
        rw = self.right.bit_width
        if lw is not None and rw is not None:
            return max(lw, rw)
        return lw or rw

    def substitute(self, mapping: Dict[str, SymExpr]) -> SymExpr:
        new_left = self.left.substitute(mapping)
        new_right = self.right.substitute(mapping)
        if new_left is self.left and new_right is self.right:
            return self
        return SymBinOp(self.op, new_left, new_right)

    def evaluate(self, env: Dict[str, int]) -> Optional[int]:
        lv = self.left.evaluate(env)
        rv = self.right.evaluate(env)
        if lv is None or rv is None:
            return None
        return _eval_binop(self.op, lv, rv)

    def _to_string(self) -> str:
        return f"({self.left} {self.op} {self.right})"

    def _structural_eq(self, other: SymExpr) -> bool:
        return (isinstance(other, SymBinOp)
                and self.op == other.op
                and self.left == other.left
                and self.right == other.right)

    def _compute_hash(self) -> int:
        return hash(("binop", self.op, hash(self.left), hash(self.right)))


# ---- Unary operation ------------------------------------------------------

class SymUnaryOp(SymExpr):
    """A unary operation on a symbolic expression.

    Parameters
    ----------
    op : str
        Operator: ``'-'`` (negation), ``'~'`` (bitwise NOT),
        ``'!'`` (logical NOT).
    operand : SymExpr
        The operand.
    """

    __slots__ = ("op", "operand", "_hash", "_simplified")

    def __init__(self, op: str, operand: SymExpr) -> None:
        self.op = op
        self.operand = operand
        self._hash: Optional[int] = None
        self._simplified = False

    @property
    def kind(self) -> SymExprKind:
        return SymExprKind.UNARYOP

    @property
    def children(self) -> Tuple[SymExpr, ...]:
        return (self.operand,)

    @property
    def bit_width(self) -> Optional[int]:
        return self.operand.bit_width

    def substitute(self, mapping: Dict[str, SymExpr]) -> SymExpr:
        new_op = self.operand.substitute(mapping)
        if new_op is self.operand:
            return self
        return SymUnaryOp(self.op, new_op)

    def evaluate(self, env: Dict[str, int]) -> Optional[int]:
        v = self.operand.evaluate(env)
        if v is None:
            return None
        return _eval_unaryop(self.op, v)

    def _to_string(self) -> str:
        return f"({self.op}{self.operand})"

    def _structural_eq(self, other: SymExpr) -> bool:
        return (isinstance(other, SymUnaryOp)
                and self.op == other.op
                and self.operand == other.operand)

    def _compute_hash(self) -> int:
        return hash(("unaryop", self.op, hash(self.operand)))


# ---- If-then-else ---------------------------------------------------------

class SymITE(SymExpr):
    """If-then-else symbolic expression.

    Represents ``cond ? true_val : false_val``.  Used for SSE merging
    at join points (introducing fresh symbolic variables guarded by
    path conditions).

    Parameters
    ----------
    condition : SymExpr
        The boolean condition.
    true_val : SymExpr
        Value when condition is true.
    false_val : SymExpr
        Value when condition is false.
    """

    __slots__ = ("condition", "true_val", "false_val", "_hash", "_simplified")

    def __init__(
        self, condition: SymExpr, true_val: SymExpr, false_val: SymExpr
    ) -> None:
        self.condition = condition
        self.true_val = true_val
        self.false_val = false_val
        self._hash: Optional[int] = None
        self._simplified = False

    @property
    def kind(self) -> SymExprKind:
        return SymExprKind.ITE

    @property
    def children(self) -> Tuple[SymExpr, ...]:
        return (self.condition, self.true_val, self.false_val)

    def substitute(self, mapping: Dict[str, SymExpr]) -> SymExpr:
        new_c = self.condition.substitute(mapping)
        new_t = self.true_val.substitute(mapping)
        new_f = self.false_val.substitute(mapping)
        if new_c is self.condition and new_t is self.true_val and new_f is self.false_val:
            return self
        return SymITE(new_c, new_t, new_f)

    def evaluate(self, env: Dict[str, int]) -> Optional[int]:
        cv = self.condition.evaluate(env)
        if cv is None:
            return None
        if cv:
            return self.true_val.evaluate(env)
        return self.false_val.evaluate(env)

    def _to_string(self) -> str:
        return f"(ite {self.condition} {self.true_val} {self.false_val})"

    def _structural_eq(self, other: SymExpr) -> bool:
        return (isinstance(other, SymITE)
                and self.condition == other.condition
                and self.true_val == other.true_val
                and self.false_val == other.false_val)

    def _compute_hash(self) -> int:
        return hash(("ite", hash(self.condition),
                     hash(self.true_val), hash(self.false_val)))


# ---- Uninterpreted function application -----------------------------------

class SymFunctionApp(SymExpr):
    """Application of an uninterpreted function.

    Used for modelling external function calls whose semantics are
    unknown.  The function is treated as an uninterpreted symbol,
    satisfying only congruence: ``f(a) = f(b)`` iff ``a = b``.

    Parameters
    ----------
    func_name : str
        The function name.
    arguments : tuple of SymExpr
        The arguments.
    call_id : int
        Unique identifier for this call site (to distinguish
        different calls to the same function).
    """

    __slots__ = ("func_name", "arguments", "call_id", "_hash", "_simplified")

    def __init__(
        self,
        func_name: str,
        arguments: Tuple[SymExpr, ...],
        call_id: int = 0,
    ) -> None:
        self.func_name = func_name
        self.arguments = arguments
        self.call_id = call_id
        self._hash: Optional[int] = None
        self._simplified = False

    @property
    def kind(self) -> SymExprKind:
        return SymExprKind.FUNCTION_APP

    @property
    def children(self) -> Tuple[SymExpr, ...]:
        return self.arguments

    def substitute(self, mapping: Dict[str, SymExpr]) -> SymExpr:
        new_args = tuple(a.substitute(mapping) for a in self.arguments)
        if all(na is oa for na, oa in zip(new_args, self.arguments)):
            return self
        return SymFunctionApp(self.func_name, new_args, self.call_id)

    def evaluate(self, env: Dict[str, int]) -> Optional[int]:
        return None  # uninterpreted

    def _to_string(self) -> str:
        args_str = ", ".join(str(a) for a in self.arguments)
        return f"{self.func_name}({args_str})"

    def _structural_eq(self, other: SymExpr) -> bool:
        return (isinstance(other, SymFunctionApp)
                and self.func_name == other.func_name
                and self.call_id == other.call_id
                and self.arguments == other.arguments)

    def _compute_hash(self) -> int:
        return hash(("app", self.func_name, self.call_id,
                     tuple(hash(a) for a in self.arguments)))


# ---- Memory read/write ---------------------------------------------------

class SymMemoryRead(SymExpr):
    """Symbolic memory read: ``mem[address]``.

    Parameters
    ----------
    address : SymExpr
        The address expression.
    mem_version : int
        Version of the memory state (SSA for memory).
    width : int
        Read width in bits.
    """

    __slots__ = ("address", "mem_version", "width", "_hash", "_simplified")

    def __init__(
        self, address: SymExpr, mem_version: int = 0, width: int = 64
    ) -> None:
        self.address = address
        self.mem_version = mem_version
        self.width = width
        self._hash: Optional[int] = None
        self._simplified = False

    @property
    def kind(self) -> SymExprKind:
        return SymExprKind.MEMORY_READ

    @property
    def children(self) -> Tuple[SymExpr, ...]:
        return (self.address,)

    @property
    def bit_width(self) -> Optional[int]:
        return self.width

    def substitute(self, mapping: Dict[str, SymExpr]) -> SymExpr:
        new_addr = self.address.substitute(mapping)
        if new_addr is self.address:
            return self
        return SymMemoryRead(new_addr, self.mem_version, self.width)

    def evaluate(self, env: Dict[str, int]) -> Optional[int]:
        return None  # requires memory model

    def _to_string(self) -> str:
        return f"mem_{self.mem_version}[{self.address}]"

    def _structural_eq(self, other: SymExpr) -> bool:
        return (isinstance(other, SymMemoryRead)
                and self.mem_version == other.mem_version
                and self.address == other.address)

    def _compute_hash(self) -> int:
        return hash(("mem_read", self.mem_version, hash(self.address)))


# ===================================================================
# EXPRESSION SIMPLIFIER
# ===================================================================

def _simplify_expr(expr: SymExpr) -> SymExpr:
    """Apply algebraic simplification rules to a symbolic expression.

    Rules applied:

    1. Constant folding: ``3 + 4 → 7``
    2. Identity: ``x + 0 → x``, ``x * 1 → x``, ``x & -1 → x``
    3. Annihilation: ``x * 0 → 0``, ``x & 0 → 0``
    4. Idempotency: ``x & x → x``, ``x | x → x``
    5. Inverse: ``x - x → 0``, ``x ^ x → 0``
    6. Double negation: ``--x → x``, ``!!x → x`` (boolean)
    7. ITE simplification: ``ite(true, a, b) → a``
    """
    if isinstance(expr, (SymConst, SymVar)):
        return expr

    if isinstance(expr, SymUnaryOp):
        inner = _simplify_expr(expr.operand)
        # Constant folding
        if inner.is_concrete:
            result = _eval_unaryop(expr.op, inner.concrete_value)
            if result is not None:
                return SymConst(result)
        # Double negation
        if expr.op == "-" and isinstance(inner, SymUnaryOp) and inner.op == "-":
            return inner.operand
        if expr.op == "~" and isinstance(inner, SymUnaryOp) and inner.op == "~":
            return inner.operand
        if expr.op == "!" and isinstance(inner, SymUnaryOp) and inner.op == "!":
            return inner.operand
        if inner is expr.operand:
            return expr
        return SymUnaryOp(expr.op, inner)

    if isinstance(expr, SymBinOp):
        left = _simplify_expr(expr.left)
        right = _simplify_expr(expr.right)
        op = expr.op

        # Constant folding
        if left.is_concrete and right.is_concrete:
            result = _eval_binop(op, left.concrete_value, right.concrete_value)
            if result is not None:
                return SymConst(result)

        # Identity and annihilation rules
        if op == "+":
            if right.is_concrete and right.concrete_value == 0:
                return left
            if left.is_concrete and left.concrete_value == 0:
                return right
        elif op == "-":
            if right.is_concrete and right.concrete_value == 0:
                return left
            if left == right:
                return SymConst(0)
        elif op == "*":
            if right.is_concrete:
                if right.concrete_value == 0:
                    return SymConst(0)
                if right.concrete_value == 1:
                    return left
            if left.is_concrete:
                if left.concrete_value == 0:
                    return SymConst(0)
                if left.concrete_value == 1:
                    return right
        elif op == "/":
            if right.is_concrete and right.concrete_value == 1:
                return left
            if left == right and right.is_concrete and right.concrete_value != 0:
                return SymConst(1)
        elif op == "%":
            if right.is_concrete and right.concrete_value == 1:
                return SymConst(0)
        elif op == "&":
            if right.is_concrete and right.concrete_value == 0:
                return SymConst(0)
            if left == right:
                return left
        elif op == "|":
            if right.is_concrete and right.concrete_value == 0:
                return left
            if left.is_concrete and left.concrete_value == 0:
                return right
            if left == right:
                return left
        elif op == "^":
            if left == right:
                return SymConst(0)
            if right.is_concrete and right.concrete_value == 0:
                return left
        elif op == "<<":
            if right.is_concrete and right.concrete_value == 0:
                return left
        elif op == ">>":
            if right.is_concrete and right.concrete_value == 0:
                return left
        elif op == "&&":
            if left.is_concrete:
                return right if left.concrete_value else SymConst(0)
            if right.is_concrete:
                return left if right.concrete_value else SymConst(0)
        elif op == "||":
            if left.is_concrete:
                return SymConst(1) if left.concrete_value else right
            if right.is_concrete:
                return SymConst(1) if right.concrete_value else left
        elif op == "==":
            if left == right:
                return SymConst(1)
        elif op == "!=":
            if left == right:
                return SymConst(0)

        if left is expr.left and right is expr.right:
            return expr
        return SymBinOp(op, left, right)

    if isinstance(expr, SymITE):
        cond = _simplify_expr(expr.condition)
        tv = _simplify_expr(expr.true_val)
        fv = _simplify_expr(expr.false_val)
        # Constant condition
        if cond.is_concrete:
            return tv if cond.concrete_value else fv
        # Same branches
        if tv == fv:
            return tv
        if (cond is expr.condition and tv is expr.true_val
                and fv is expr.false_val):
            return expr
        return SymITE(cond, tv, fv)

    return expr


def _eval_binop(op: str, a: int, b: int) -> Optional[int]:
    """Evaluate a binary operation on concrete integers."""
    try:
        ops: Dict[str, Callable[[int, int], int]] = {
            "+": operator.add,
            "-": operator.sub,
            "*": operator.mul,
            "/": lambda x, y: int(x / y) if y != 0 else None,
            "%": lambda x, y: x % y if y != 0 else None,
            "<<": lambda x, y: x << y if 0 <= y < 64 else None,
            ">>": lambda x, y: x >> y if 0 <= y < 64 else None,
            "&": operator.and_,
            "|": operator.or_,
            "^": operator.xor,
            "<": lambda x, y: int(x < y),
            "<=": lambda x, y: int(x <= y),
            ">": lambda x, y: int(x > y),
            ">=": lambda x, y: int(x >= y),
            "==": lambda x, y: int(x == y),
            "!=": lambda x, y: int(x != y),
            "&&": lambda x, y: int(bool(x) and bool(y)),
            "||": lambda x, y: int(bool(x) or bool(y)),
        }
        fn = ops.get(op)
        if fn is None:
            return None
        result = fn(a, b)
        return result
    except (ZeroDivisionError, OverflowError, ValueError):
        return None


def _eval_unaryop(op: str, a: int) -> Optional[int]:
    """Evaluate a unary operation on a concrete integer."""
    if op == "-":
        return -a
    if op == "~":
        return ~a
    if op == "!":
        return int(not a)
    if op == "++":
        return a + 1
    if op == "--":
        return a - 1
    return None


# ===================================================================
# PATH CONDITION (GUARD)
# ===================================================================

class PathCondition:
    """A conjunction of symbolic boolean constraints (the path guard ``g``).

    From the literature (chunk 601):

    .. math::

        g ::= \\text{true} \\mid \\text{false} \\mid \\neg g
              \\mid g_1 \\land g_2 \\mid \\text{as}_1\\ \\text{op}_r\\ \\text{as}_2

    The path condition accumulates constraints as execution proceeds
    through branches.  It is checked for satisfiability at each branch
    to prune infeasible paths.

    Parameters
    ----------
    constraints : list of SymExpr, optional
        Initial constraints (all implicitly AND-ed).
    """

    __slots__ = ("_constraints", "_simplified")

    def __init__(
        self, constraints: Optional[List[SymExpr]] = None
    ) -> None:
        self._constraints: List[SymExpr] = list(constraints) if constraints else []
        self._simplified = False

    @property
    def constraints(self) -> Tuple[SymExpr, ...]:
        """The conjunction of all constraints."""
        return tuple(self._constraints)

    @property
    def is_empty(self) -> bool:
        """No constraints (equivalent to ``true``)."""
        return len(self._constraints) == 0

    @property
    def num_constraints(self) -> int:
        return len(self._constraints)

    @property
    def free_variables(self) -> FrozenSet[str]:
        """All free symbolic variables in the path condition."""
        result: Set[str] = set()
        for c in self._constraints:
            result |= c.free_variables
        return frozenset(result)

    def add(self, constraint: SymExpr) -> "PathCondition":
        """Return a new PathCondition with an added constraint.

        Parameters
        ----------
        constraint : SymExpr
            The constraint to conjoin.

        Returns
        -------
        PathCondition
        """
        new_constraints = list(self._constraints)
        # Simplify the constraint
        simplified = constraint.simplify()
        # Check for trivially true
        if simplified.is_concrete and simplified.concrete_value:
            return PathCondition(new_constraints)
        # Check for trivially false
        if simplified.is_concrete and not simplified.concrete_value:
            new_constraints.append(simplified)
            pc = PathCondition(new_constraints)
            return pc
        new_constraints.append(simplified)
        return PathCondition(new_constraints)

    def negate_last(self) -> "PathCondition":
        """Return a new PathCondition with the last constraint negated.

        Useful for exploring the other branch after a fork.
        """
        if not self._constraints:
            return PathCondition()
        new_constraints = list(self._constraints[:-1])
        last = self._constraints[-1]
        negated = _negate_sym_expr(last)
        new_constraints.append(negated)
        return PathCondition(new_constraints)

    def as_conjunction(self) -> SymExpr:
        """Return the path condition as a single conjunctive SymExpr."""
        if not self._constraints:
            return SymConst(1)  # true
        result = self._constraints[0]
        for c in self._constraints[1:]:
            result = SymBinOp("&&", result, c)
        return result

    def evaluate(self, env: Dict[str, int]) -> Optional[bool]:
        """Evaluate the path condition under a concrete environment.

        Returns ``True`` if all constraints are satisfied, ``False``
        if any is violated, ``None`` if evaluation fails.
        """
        for c in self._constraints:
            val = c.evaluate(env)
            if val is None:
                return None
            if not val:
                return False
        return True

    def copy(self) -> "PathCondition":
        return PathCondition(list(self._constraints))

    def __repr__(self) -> str:
        if not self._constraints:
            return "true"
        return " ∧ ".join(str(c) for c in self._constraints)

    def __len__(self) -> int:
        return len(self._constraints)

    def __eq__(self, other) -> bool:
        if not isinstance(other, PathCondition):
            return NotImplemented
        return self._constraints == other._constraints

    def __hash__(self) -> int:
        return hash(tuple(hash(c) for c in self._constraints))


def _negate_sym_expr(expr: SymExpr) -> SymExpr:
    """Negate a symbolic boolean expression."""
    # Double-negation elimination
    if isinstance(expr, SymUnaryOp) and expr.op == "!":
        return expr.operand
    # Comparison negation
    if isinstance(expr, SymBinOp) and expr.op in _COMPARISON_NEGATION:
        return SymBinOp(_COMPARISON_NEGATION[expr.op], expr.left, expr.right)
    return SymUnaryOp("!", expr)


_COMPARISON_NEGATION: Dict[str, str] = {
    "<":  ">=",
    "<=": ">",
    ">":  "<=",
    ">=": "<",
    "==": "!=",
    "!=": "==",
}


# ===================================================================
# SYMBOLIC STATE
# ===================================================================

class SymState:
    """Symbolic execution state: environment + path condition.

    The symbolic state maps each program variable to a symbolic
    expression (its current symbolic value) and maintains the path
    condition that must hold for execution to reach this state.

    From the literature (chunk 601):

    .. math::

        \\Sigma \\in \\text{Var} \\to \\text{as}

    Parameters
    ----------
    env : dict, optional
        Initial symbolic environment.
    path_condition : PathCondition, optional
        Initial path condition.
    """

    __slots__ = (
        "env", "path_condition", "_var_versions", "_mem_version",
        "_call_counter", "depth", "path_trace",
    )

    def __init__(
        self,
        env: Optional[Dict[str, SymExpr]] = None,
        path_condition: Optional[PathCondition] = None,
    ) -> None:
        self.env: Dict[str, SymExpr] = dict(env) if env else {}
        self.path_condition: PathCondition = (
            path_condition if path_condition is not None
            else PathCondition()
        )
        self._var_versions: Dict[str, int] = defaultdict(int)
        self._mem_version: int = 0
        self._call_counter: int = 0
        self.depth: int = 0
        self.path_trace: List[Any] = []

    def get(self, var_name: str) -> SymExpr:
        """Get the symbolic expression for a variable.

        If the variable has not been assigned, returns a fresh symbolic
        variable (representing the unknown initial value).
        """
        if var_name in self.env:
            return self.env[var_name]
        # Create a fresh symbolic input variable
        sym_var = SymVar(var_name, version=0)
        self.env[var_name] = sym_var
        return sym_var

    def set(self, var_name: str, value: SymExpr) -> "SymState":
        """Return a new state with ``var_name`` mapped to ``value``.

        Increments the variable's SSA version.
        """
        new_state = self.copy()
        new_state._var_versions[var_name] += 1
        new_state.env[var_name] = value
        return new_state

    def add_constraint(self, constraint: SymExpr) -> "SymState":
        """Return a new state with an added path constraint."""
        new_state = self.copy()
        new_state.path_condition = self.path_condition.add(constraint)
        return new_state

    def fresh_version(self, var_name: str) -> int:
        """Get the next fresh SSA version for a variable."""
        self._var_versions[var_name] += 1
        return self._var_versions[var_name]

    def fresh_call_id(self) -> int:
        """Generate a unique call site identifier."""
        self._call_counter += 1
        return self._call_counter

    def fresh_memory_version(self) -> int:
        """Increment and return the memory SSA version."""
        self._mem_version += 1
        return self._mem_version

    @property
    def variables(self) -> Set[str]:
        """Set of variables in the symbolic environment."""
        return set(self.env.keys())

    def copy(self) -> "SymState":
        """Create a deep copy of this state."""
        new = SymState.__new__(SymState)
        new.env = dict(self.env)
        new.path_condition = self.path_condition.copy()
        new._var_versions = defaultdict(int, self._var_versions)
        new._mem_version = self._mem_version
        new._call_counter = self._call_counter
        new.depth = self.depth
        new.path_trace = list(self.path_trace)
        return new

    def __repr__(self) -> str:
        env_str = ", ".join(
            f"{k}: {v}" for k, v in sorted(self.env.items())
        )
        return f"SymState(env={{{env_str}}}, guard={self.path_condition})"


# ===================================================================
# SYMBOLIC EXPRESSION BUILDER FOR CPPCHECK TOKENS
# ===================================================================

class SymExprBuilder:
    """Builds symbolic expressions from Cppcheck AST tokens.

    Walks the token's ``astOperand1``/``astOperand2`` tree and converts
    each node to a :class:`SymExpr`.

    Parameters
    ----------
    state : SymState
        The current symbolic state.
    """

    def __init__(self, state: SymState) -> None:
        self.state = state

    def build(self, token) -> SymExpr:
        """Build a symbolic expression from a token.

        Parameters
        ----------
        token : cppcheckdata.Token

        Returns
        -------
        SymExpr
        """
        if token is None:
            return SymVar("__unknown__")

        # Integer literal
        if getattr(token, "isNumber", False):
            return self._build_number(token)

        # Character literal
        if token.str.startswith("'") and token.str.endswith("'"):
            try:
                if len(token.str) == 3:
                    return SymConst(ord(token.str[1]))
            except Exception:
                pass
            return SymVar("__char_unknown__")

        # Variable reference
        if getattr(token, "isName", False):
            return self._build_name(token)

        op1 = getattr(token, "astOperand1", None)
        op2 = getattr(token, "astOperand2", None)

        # Unary operator
        if op1 is not None and op2 is None:
            return self._build_unary(token, op1)

        # Binary operator
        if op1 is not None and op2 is not None:
            return self._build_binary(token, op1, op2)

        # Function call
        if token.str == "(" and op1 is not None:
            return self._build_call(token, op1)

        # Fallback: unknown symbolic value
        return SymVar(f"__token_{getattr(token, 'Id', '?')}__")

    def _build_number(self, token) -> SymExpr:
        """Build a SymConst from a numeric token."""
        try:
            val_str = token.str
            if val_str.startswith("0x") or val_str.startswith("0X"):
                return SymConst(int(val_str, 16))
            if val_str.startswith("0b") or val_str.startswith("0B"):
                return SymConst(int(val_str, 2))
            cleaned = val_str.rstrip("uUlLfF")
            if "." in cleaned or "e" in cleaned or "E" in cleaned:
                return SymConst(int(float(cleaned)))
            if cleaned.startswith("0") and len(cleaned) > 1 and cleaned.isdigit():
                return SymConst(int(cleaned, 8))
            return SymConst(int(cleaned))
        except (ValueError, OverflowError):
            return SymVar(f"__num_{token.str}__")

    def _build_name(self, token) -> SymExpr:
        """Build a symbolic expression for a name token."""
        var = getattr(token, "variable", None)
        if var is not None:
            var_id = _sym_variable_id(token)
            return self.state.get(var_id)

        # Enum constant — try Cppcheck values
        values = getattr(token, "values", None)
        if values:
            for v in values:
                if getattr(v, "valueKind", "") == "known":
                    try:
                        return SymConst(int(v.intvalue))
                    except (ValueError, AttributeError):
                        pass

        # sizeof or other compile-time constant
        if token.str == "sizeof":
            return SymVar("__sizeof__")

        # Unknown name (could be function name, macro, etc.)
        return SymVar(token.str)

    def _build_unary(self, token, op1) -> SymExpr:
        """Build a unary operation expression."""
        inner = self.build(op1)

        if token.str in ("-", "~", "!"):
            return SymUnaryOp(token.str, inner).simplify()

        if token.str in ("++", "--"):
            return SymUnaryOp(token.str, inner).simplify()

        if token.str == "*":
            # Pointer dereference → memory read
            return SymMemoryRead(inner, self.state._mem_version)

        if token.str == "&":
            # Address-of → uninterpreted
            return SymFunctionApp(
                "__addressof__", (inner,), self.state.fresh_call_id()
            )

        if token.str == "(":
            # Cast — pass through the inner expression
            return inner

        return inner

    def _build_binary(self, token, op1, op2) -> SymExpr:
        """Build a binary operation expression."""
        if token.str == "?":
            # Ternary: op1 is condition, op2 is ':' with true/false branches
            cond = self.build(op1)
            colon = op2
            if colon is not None and getattr(colon, "str", "") == ":":
                tv = self.build(getattr(colon, "astOperand1", None))
                fv = self.build(getattr(colon, "astOperand2", None))
                return SymITE(cond, tv, fv).simplify()

        left = self.build(op1)
        right = self.build(op2)

        if token.str in ("+", "-", "*", "/", "%",
                         "<<", ">>", "&", "|", "^",
                         "<", "<=", ">", ">=", "==", "!=",
                         "&&", "||"):
            return SymBinOp(token.str, left, right).simplify()

        if token.str == "=":
            return right  # assignment evaluates to the RHS

        if token.str in ("+=", "-=", "*=", "/=", "%=",
                         "<<=", ">>=", "&=", "|=", "^="):
            base_op = token.str[:-1]
            return SymBinOp(base_op, left, right).simplify()

        if token.str == ",":
            return right  # comma operator: value of right operand

        if token.str == "[":
            # Array subscript → memory read at base + index
            addr = SymBinOp("+", left, right).simplify()
            return SymMemoryRead(addr, self.state._mem_version)

        if token.str in (".", "->"):
            # Struct member → uninterpreted field access
            member = getattr(op2, "str", "?")
            return SymFunctionApp(
                f"__field_{member}__", (left,), self.state.fresh_call_id()
            )

        return SymBinOp(token.str, left, right)

    def _build_call(self, token, callee_tok) -> SymExpr:
        """Build a function call expression."""
        func_name = getattr(callee_tok, "str", "__unknown_func__")
        args_tok = getattr(token, "astOperand2", None)
        arg_exprs = self._collect_args(args_tok)
        return SymFunctionApp(
            func_name, tuple(arg_exprs), self.state.fresh_call_id()
        )

    def _collect_args(self, tok) -> List[SymExpr]:
        """Collect function call arguments."""
        if tok is None:
            return []
        result: List = []
        self._flatten_comma_args(tok, result)
        return result

    def _flatten_comma_args(self, tok, result: List) -> None:
        if tok is None:
            return
        if tok.str == ",":
            self._flatten_comma_args(
                getattr(tok, "astOperand1", None), result
            )
            self._flatten_comma_args(
                getattr(tok, "astOperand2", None), result
            )
        else:
            result.append(self.build(tok))


def _sym_variable_id(token) -> str:
    """Get a stable variable identifier from a token for symbolic execution."""
    var = getattr(token, "variable", None)
    if var is not None:
        vid = getattr(var, "Id", None)
        if vid:
            return f"v{vid}"
        name_tok = getattr(var, "nameToken", None)
        if name_tok:
            return getattr(name_tok, "str", token.str)
    return token.str


# ===================================================================
# SYMBOLIC TRANSFER FUNCTION
# ===================================================================

class SymTransferFunction:
    """Symbolic transfer function for CFG nodes.

    Interprets the tokens within a basic block symbolically, updating
    the symbolic state and path condition.

    Parameters
    ----------
    function_models : dict, optional
        Map from function name to callable
        ``(SymState, List[SymExpr]) → (SymState, SymExpr)``
        providing symbolic models for library functions.
    """

    def __init__(
        self,
        function_models: Optional[Dict[str, Callable]] = None,
    ) -> None:
        self.function_models = function_models or {}

    def __call__(self, node, state: SymState) -> SymState:
        """Apply the symbolic transfer function to a CFG node.

        Parameters
        ----------
        node : CFGNode
            The basic block.
        state : SymState
            The incoming symbolic state.

        Returns
        -------
        SymState
            The outgoing symbolic state.
        """
        tokens = getattr(node, "tokens", [])
        for tok in tokens:
            state = self._process_token(tok, state)
        return state

    def _process_token(self, tok, state: SymState) -> SymState:
        """Process a single token for symbolic execution."""
        # Assignment: x = expr
        if tok.str == "=" and not getattr(tok, "isComparisonOp", False):
            return self._process_assignment(tok, state)

        # Compound assignment
        if tok.str in ("+=", "-=", "*=", "/=", "%=",
                        "<<=", ">>=", "&=", "|=", "^="):
            return self._process_compound_assignment(tok, state)

        # Increment/decrement
        if tok.str in ("++", "--"):
            return self._process_incdec(tok, state)

        # Function call (for side effects / models)
        if tok.str == "(" and getattr(tok, "astOperand1", None) is not None:
            return self._process_call(tok, state)

        return state

    def _process_assignment(self, tok, state: SymState) -> SymState:
        """Handle ``lhs = rhs`` symbolically."""
        lhs = getattr(tok, "astOperand1", None)
        rhs = getattr(tok, "astOperand2", None)
        if lhs is None or rhs is None:
            return state

        builder = SymExprBuilder(state)
        rhs_expr = builder.build(rhs)

        if getattr(lhs, "isName", False) and getattr(lhs, "variable", None):
            var_id = _sym_variable_id(lhs)
            state = state.set(var_id, rhs_expr)
        elif lhs.str == "*":
            # Pointer write → bump memory version
            state = state.copy()
            state.fresh_memory_version()
        elif lhs.str == "[":
            state = state.copy()
            state.fresh_memory_version()

        return state

    def _process_compound_assignment(
        self, tok, state: SymState
    ) -> SymState:
        """Handle ``lhs op= rhs`` symbolically."""
        lhs = getattr(tok, "astOperand1", None)
        rhs = getattr(tok, "astOperand2", None)
        if lhs is None or rhs is None:
            return state

        builder = SymExprBuilder(state)
        lhs_expr = builder.build(lhs)
        rhs_expr = builder.build(rhs)
        base_op = tok.str[:-1]
        result_expr = SymBinOp(base_op, lhs_expr, rhs_expr).simplify()

        if getattr(lhs, "isName", False) and getattr(lhs, "variable", None):
            var_id = _sym_variable_id(lhs)
            state = state.set(var_id, result_expr)

        return state

    def _process_incdec(self, tok, state: SymState) -> SymState:
        """Handle ``x++``, ``x--``, ``++x``, ``--x``."""
        operand = getattr(tok, "astOperand1", None)
        if operand is None:
            return state

        if getattr(operand, "isName", False) and getattr(operand, "variable", None):
            var_id = _sym_variable_id(operand)
            builder = SymExprBuilder(state)
            old_val = builder.build(operand)
            if tok.str == "++":
                new_val = SymBinOp("+", old_val, SymConst(1)).simplify()
            else:
                new_val = SymBinOp("-", old_val, SymConst(1)).simplify()
            state = state.set(var_id, new_val)

        return state

    def _process_call(self, tok, state: SymState) -> SymState:
        """Handle function calls symbolically."""
        callee_tok = getattr(tok, "astOperand1", None)
        if callee_tok is None:
            return state

        func_name = getattr(callee_tok, "str", "")

        if func_name in self.function_models:
            builder = SymExprBuilder(state)
            args_tok = getattr(tok, "astOperand2", None)
            args = builder._collect_args(args_tok)
            model = self.function_models[func_name]
            try:
                new_state, _return_val = model(state, args)
                return new_state
            except Exception:
                pass

        # Unknown function: conservatively bump memory version
        state = state.copy()
        state.fresh_memory_version()
        return state


# ===================================================================
# EXPLORATION STRATEGY
# ===================================================================

class ExplorationStrategy(enum.Enum):
    """Path exploration strategies for symbolic execution."""
    DFS = "dfs"               # Depth-first search
    BFS = "bfs"               # Breadth-first search
    RANDOM = "random"         # Random path selection
    COVERAGE = "coverage"     # Coverage-guided (prioritize uncovered)
    SHORTEST_DISTANCE = "shortest_distance"  # Nearest to target


# ===================================================================
# SMT SOLVER INTERFACE
# ===================================================================

class SolverResult(enum.Enum):
    """Result of an SMT satisfiability check."""
    SAT = "sat"
    UNSAT = "unsat"
    UNKNOWN = "unknown"
    TIMEOUT = "timeout"


@dataclass
class SolverModel:
    """A satisfying assignment (model) from the SMT solver.

    Attributes
    ----------
    assignments : dict[str, int]
        Map from symbolic variable name to concrete value.
    """
    assignments: Dict[str, int] = field(default_factory=dict)

    def __getitem__(self, key: str) -> int:
        return self.assignments[key]

    def get(self, key: str, default: int = 0) -> int:
        return self.assignments.get(key, default)


class SMTSolver(abc.ABC):
    """Abstract interface to an SMT solver.

    Provides methods for checking satisfiability of symbolic
    constraints and extracting satisfying models.
    """

    @abc.abstractmethod
    def check_sat(
        self, path_condition: PathCondition, timeout: float = 10.0
    ) -> SolverResult:
        """Check satisfiability of a path condition.

        Parameters
        ----------
        path_condition : PathCondition
        timeout : float
            Timeout in seconds.

        Returns
        -------
        SolverResult
        """
        ...

    @abc.abstractmethod
    def get_model(
        self, path_condition: PathCondition, timeout: float = 10.0
    ) -> Optional[SolverModel]:
        """Get a satisfying model for a path condition.

        Parameters
        ----------
        path_condition : PathCondition
        timeout : float

        Returns
        -------
        SolverModel or None
            A satisfying assignment, or ``None`` if unsatisfiable.
        """
        ...

    def check_valid(
        self, assertion: SymExpr, path_condition: PathCondition,
        timeout: float = 10.0,
    ) -> SolverResult:
        """Check if an assertion is valid under a path condition.

        That is, check if ``path_condition → assertion`` is a tautology,
        by checking unsatisfiability of ``path_condition ∧ ¬assertion``.

        Returns
        -------
        SolverResult
            ``UNSAT`` means the assertion is valid (always holds).
            ``SAT`` means there exists a counter-example.
        """
        negated_pc = path_condition.add(_negate_sym_expr(assertion))
        return self.check_sat(negated_pc, timeout)


# ---- Z3 Backend -----------------------------------------------------------

class Z3Backend(SMTSolver):
    """SMT solver backend using the Z3 theorem prover.

    Requires the ``z3-solver`` package (``pip install z3-solver``).

    Parameters
    ----------
    bit_width : int
        Default bit-vector width for integer variables.
    use_bitvectors : bool
        If ``True``, model integers as bit-vectors (machine semantics).
        If ``False``, use unbounded integers (mathematical semantics).
    """

    def __init__(
        self, bit_width: int = 32, use_bitvectors: bool = False
    ) -> None:
        self.bit_width = bit_width
        self.use_bitvectors = use_bitvectors
        self._z3 = None
        try:
            import z3  # type: ignore
            self._z3 = z3
        except ImportError:
            warnings.warn(
                "z3-solver not installed; Z3Backend will not function. "
                "Install with: pip install z3-solver",
                stacklevel=2,
            )

    @property
    def available(self) -> bool:
        return self._z3 is not None

    def check_sat(
        self, path_condition: PathCondition, timeout: float = 10.0
    ) -> SolverResult:
        if not self.available:
            return SolverResult.UNKNOWN

        z3 = self._z3
        solver = z3.Solver()
        solver.set("timeout", int(timeout * 1000))

        var_cache: Dict[str, Any] = {}
        for constraint in path_condition.constraints:
            z3_expr = self._to_z3(constraint, var_cache)
            if z3_expr is not None:
                solver.add(z3_expr)

        result = solver.check()
        if result == z3.sat:
            return SolverResult.SAT
        if result == z3.unsat:
            return SolverResult.UNSAT
        return SolverResult.UNKNOWN

    def get_model(
        self, path_condition: PathCondition, timeout: float = 10.0
    ) -> Optional[SolverModel]:
        if not self.available:
            return None

        z3 = self._z3
        solver = z3.Solver()
        solver.set("timeout", int(timeout * 1000))

        var_cache: Dict[str, Any] = {}
        for constraint in path_condition.constraints:
            z3_expr = self._to_z3(constraint, var_cache)
            if z3_expr is not None:
                solver.add(z3_expr)

        if solver.check() != z3.sat:
            return None

        model = solver.model()
        assignments: Dict[str, int] = {}
        for name, z3_var in var_cache.items():
            val = model.eval(z3_var, model_completion=True)
            try:
                if self.use_bitvectors:
                    assignments[name] = val.as_signed_long()
                else:
                    assignments[name] = val.as_long()
            except (AttributeError, Exception):
                try:
                    assignments[name] = int(str(val))
                except (ValueError, Exception):
                    assignments[name] = 0

        return SolverModel(assignments)

    def _to_z3(self, expr: SymExpr, var_cache: Dict[str, Any]) -> Any:
        """Convert a SymExpr to a z3 expression."""
        z3 = self._z3
        if z3 is None:
            return None

        if isinstance(expr, SymConst):
            if self.use_bitvectors:
                return z3.BitVecVal(int(expr.value), self.bit_width)
            return z3.IntVal(int(expr.value))

        if isinstance(expr, SymVar):
            name = expr.qualified_name
            if name not in var_cache:
                if self.use_bitvectors:
                    var_cache[name] = z3.BitVec(name, self.bit_width)
                else:
                    var_cache[name] = z3.Int(name)
            return var_cache[name]

        if isinstance(expr, SymUnaryOp):
            inner = self._to_z3(expr.operand, var_cache)
            if inner is None:
                return None
            if expr.op == "-":
                return -inner
            if expr.op == "~":
                return ~inner if self.use_bitvectors else -1 - inner
            if expr.op == "!":
                return z3.If(inner == 0, z3.IntVal(1), z3.IntVal(0)) \
                    if not self.use_bitvectors else \
                    z3.If(inner == 0,
                          z3.BitVecVal(1, self.bit_width),
                          z3.BitVecVal(0, self.bit_width))
            return None

        if isinstance(expr, SymBinOp):
            left = self._to_z3(expr.left, var_cache)
            right = self._to_z3(expr.right, var_cache)
            if left is None or right is None:
                return None
            return self._z3_binop(expr.op, left, right)

        if isinstance(expr, SymITE):
            cond = self._to_z3(expr.condition, var_cache)
            tv = self._to_z3(expr.true_val, var_cache)
            fv = self._to_z3(expr.false_val, var_cache)
            if cond is None or tv is None or fv is None:
                return None
            return z3.If(cond != 0, tv, fv)

        return None  # unsupported expression type

    def _z3_binop(self, op: str, left, right):
        """Apply a binary operator in z3."""
        z3 = self._z3
        bv = self.use_bitvectors

        if op == "+":
            return left + right
        if op == "-":
            return left - right
        if op == "*":
            return left * right
        if op == "/":
            return left / right
        if op == "%":
            return left % right
        if op == "&":
            return left & right if bv else z3.IntVal(0)  # fallback
        if op == "|":
            return left | right if bv else z3.IntVal(0)
        if op == "^":
            return left ^ right if bv else z3.IntVal(0)
        if op == "<<":
            return left << right if bv else left * (2 ** right)
        if op == ">>":
            return z3.LShR(left, right) if bv else left / (2 ** right)
        if op == "<":
            return z3.If(left < right, _z3_one(z3, bv, self.bit_width),
                         _z3_zero(z3, bv, self.bit_width))
        if op == "<=":
            return z3.If(left <= right, _z3_one(z3, bv, self.bit_width),
                         _z3_zero(z3, bv, self.bit_width))
        if op == ">":
            return z3.If(left > right, _z3_one(z3, bv, self.bit_width),
                         _z3_zero(z3, bv, self.bit_width))
        if op == ">=":
            return z3.If(left >= right, _z3_one(z3, bv, self.bit_width),
                         _z3_zero(z3, bv, self.bit_width))
        if op == "==":
            return z3.If(left == right, _z3_one(z3, bv, self.bit_width),
                         _z3_zero(z3, bv, self.bit_width))
        if op == "!=":
            return z3.If(left != right, _z3_one(z3, bv, self.bit_width),
                         _z3_zero(z3, bv, self.bit_width))
        if op == "&&":
            return z3.If(z3.And(left != 0, right != 0),
                         _z3_one(z3, bv, self.bit_width),
                         _z3_zero(z3, bv, self.bit_width))
        if op == "||":
            return z3.If(z3.Or(left != 0, right != 0),
                         _z3_one(z3, bv, self.bit_width),
                         _z3_zero(z3, bv, self.bit_width))
        return None


def _z3_one(z3, bv: bool, width: int):
    return z3.BitVecVal(1, width) if bv else z3.IntVal(1)


def _z3_zero(z3, bv: bool, width: int):
    return z3.BitVecVal(0, width) if bv else z3.IntVal(0)


# ---- Internal Simplifier Backend ------------------------------------------

class InternalSimplifier(SMTSolver):
    """A lightweight, built-in constraint solver (no external dependencies).

    Uses algebraic simplification, constant propagation, and interval
    reasoning to check satisfiability.  Less powerful than Z3 but
    always available.

    Supports:
    - Constant propagation
    - Simple interval-based reasoning
    - Equality propagation
    """

    def __init__(self) -> None:
        self._interval_domain = ai.IntervalDomain(bit_width=64, signed=True)

    def check_sat(
        self, path_condition: PathCondition, timeout: float = 10.0
    ) -> SolverResult:
        if path_condition.is_empty:
            return SolverResult.SAT

        # Check for obviously false constraints
        for c in path_condition.constraints:
            if c.is_concrete and not c.concrete_value:
                return SolverResult.UNSAT

        # Try constant propagation
        simplified = self._propagate_constants(path_condition)
        for c in simplified.constraints:
            if c.is_concrete and not c.concrete_value:
                return SolverResult.UNSAT

        # Try interval reasoning
        result = self._interval_check(simplified)
        if result is not None:
            return result

        return SolverResult.UNKNOWN

    def get_model(
        self, path_condition: PathCondition, timeout: float = 10.0
    ) -> Optional[SolverModel]:
        sat_result = self.check_sat(path_condition, timeout)
        if sat_result == SolverResult.UNSAT:
            return None

        # Try to extract a model via equality constraints
        model: Dict[str, int] = {}
        for c in path_condition.constraints:
            self._extract_equalities(c, model)

        if model:
            # Verify the model
            if path_condition.evaluate(model) is True:
                return SolverModel(model)

        # Generate a simple model from interval reasoning
        intervals = self._compute_intervals(path_condition)
        for var_name, interval in intervals.items():
            if var_name not in model and interval is not None:
                lo, hi = interval
                if lo == hi:
                    model[var_name] = int(lo)
                elif lo != dfe.NEG_INF:
                    model[var_name] = int(lo)
                elif hi != dfe.POS_INF:
                    model[var_name] = int(hi)
                else:
                    model[var_name] = 0

        # Fill missing variables with 0
        for var_name in path_condition.free_variables:
            if var_name not in model:
                model[var_name] = 0

        if path_condition.evaluate(model) is True:
            return SolverModel(model)

        if sat_result == SolverResult.SAT:
            return SolverModel(model)  # best effort

        return None

    def _propagate_constants(
        self, pc: PathCondition
    ) -> PathCondition:
        """Propagate equality constraints to simplify other constraints."""
        equalities: Dict[str, SymExpr] = {}
        for c in pc.constraints:
            if isinstance(c, SymBinOp) and c.op == "==":
                if isinstance(c.left, SymVar) and c.right.is_concrete:
                    equalities[c.left.qualified_name] = c.right
                elif isinstance(c.right, SymVar) and c.left.is_concrete:
                    equalities[c.right.qualified_name] = c.left

        if not equalities:
            return pc

        new_constraints = []
        for c in pc.constraints:
            new_c = c.substitute(equalities).simplify()
            new_constraints.append(new_c)
        return PathCondition(new_constraints)

    def _interval_check(
        self, pc: PathCondition
    ) -> Optional[SolverResult]:
        """Use interval reasoning to check satisfiability."""
        intervals = self._compute_intervals(pc)
        for var, iv in intervals.items():
            if iv is not None and iv[0] > iv[1]:
                return SolverResult.UNSAT
        return None

    def _compute_intervals(
        self, pc: PathCondition
    ) -> Dict[str, Optional[Tuple[float, float]]]:
        """Compute variable intervals from the path condition."""
        domain = self._interval_domain
        intervals: Dict[str, ai.Interval] = {}

        for c in pc.constraints:
            if not isinstance(c, SymBinOp):
                continue
            if isinstance(c.left, SymVar) and c.right.is_concrete:
                var = c.left.qualified_name
                val = float(c.right.concrete_value)
                current = intervals.get(var, domain.top())
                if c.op == "<":
                    refined = domain.meet(current, (dfe.NEG_INF, val - 1))
                elif c.op == "<=":
                    refined = domain.meet(current, (dfe.NEG_INF, val))
                elif c.op == ">":
                    refined = domain.meet(current, (val + 1, dfe.POS_INF))
                elif c.op == ">=":
                    refined = domain.meet(current, (val, dfe.POS_INF))
                elif c.op == "==":
                    refined = domain.meet(current, (val, val))
                elif c.op == "!=":
                    refined = current  # weak
                else:
                    refined = current
                intervals[var] = refined

        return intervals

    def _extract_equalities(
        self, expr: SymExpr, model: Dict[str, int]
    ) -> None:
        """Extract variable = constant equalities from a constraint."""
        if isinstance(expr, SymBinOp) and expr.op == "==":
            if isinstance(expr.left, SymVar) and expr.right.is_concrete:
                model[expr.left.qualified_name] = expr.right.concrete_value
            elif isinstance(expr.right, SymVar) and expr.left.is_concrete:
                model[expr.right.qualified_name] = expr.left.concrete_value
        elif isinstance(expr, SymBinOp) and expr.op == "&&":
            self._extract_equalities(expr.left, model)
            self._extract_equalities(expr.right, model)


# ===================================================================
# TEST CASE
# ===================================================================

@dataclass
class TestCase:
    """A concrete test case generated by symbolic execution.

    Attributes
    ----------
    inputs : dict[str, int]
        Map from input variable name to concrete value.
    path : list
        The CFG path (sequence of node IDs).
    path_condition : PathCondition
        The path condition satisfied by these inputs.
    expected_output : dict[str, int]
        Expected output variable values (if determinable).
    covers_branches : set
        Set of branch edges covered by this test case.
    """
    inputs: Dict[str, int] = field(default_factory=dict)
    path: List[Any] = field(default_factory=list)
    path_condition: Optional[PathCondition] = None
    expected_output: Dict[str, int] = field(default_factory=dict)
    covers_branches: Set[Tuple] = field(default_factory=set)

    def __repr__(self) -> str:
        inputs_str = ", ".join(
            f"{k}={v}" for k, v in sorted(self.inputs.items())
        )
        return f"TestCase({inputs_str})"


# ===================================================================
# PATH RESULT
# ===================================================================

@dataclass
class PathResult:
    """Result of symbolically executing one path.

    Attributes
    ----------
    path : list
        Sequence of CFG node IDs visited.
    final_state : SymState
        Symbolic state at the end of the path.
    path_condition : PathCondition
        The accumulated path condition.
    is_feasible : bool
        Whether the path is satisfiable.
    is_complete : bool
        Whether the path reached a terminal node (exit/return).
    is_error : bool
        Whether the path triggered an error (assertion failure, etc.).
    error_kind : str
        Kind of error if ``is_error``.
    error_message : str
        Error message if ``is_error``.
    error_token : any
        Token at the error location.
    test_case : TestCase or None
        A concrete test case for this path (if feasible and model found).
    depth : int
        Path depth (number of branches taken).
    """
    path: List[Any] = field(default_factory=list)
    final_state: Optional[SymState] = None
    path_condition: Optional[PathCondition] = None
    is_feasible: bool = True
    is_complete: bool = False
    is_error: bool = False
    error_kind: str = ""
    error_message: str = ""
    error_token: Any = None
    test_case: Optional[TestCase] = None
    depth: int = 0


# ===================================================================
# SYMBOLIC EXECUTION WORKLIST ITEM
# ===================================================================

@dataclass
class _WorklistItem:
    """An item on the symbolic execution worklist."""
    node_id: Any
    state: SymState
    path: List[Any]
    depth: int = 0
    priority: float = 0.0

    def __lt__(self, other: "_WorklistItem") -> bool:
        return self.priority < other.priority


# ===================================================================
# SYMBOLIC EXECUTOR — MAIN ENGINE (DSE)
# ===================================================================

class SymbolicExecutor:
    """Dynamic symbolic execution (DSE) engine.

    Explores program paths by forking at branches, maintaining per-path
    symbolic states and path conditions.  Uses an SMT solver to check
    feasibility and generate test inputs.

    From the literature (chunk 601), at each ``if b then S₁ else S₂``:

    .. math::

        \\frac{\\langle\\Sigma, b\\rangle \\Rightarrow g_1 \\quad
               g \\wedge g_1\\ \\text{SAT} \\quad
               \\langle g \\wedge g_1, \\Sigma, S_1\\rangle \\Rightarrow
               \\langle g_2, \\Sigma_1\\rangle}
              {\\langle g, \\Sigma, \\text{if}\\ b\\ \\text{then}\\ S_1
               \\ \\text{else}\\ S_2\\rangle \\Rightarrow
               \\langle g_2, \\Sigma_1\\rangle}
        \\quad \\text{(big-iftrue)}

    Parameters
    ----------
    cfg : CFG
        The control-flow graph.
    solver : SMTSolver, optional
        The SMT solver (default: :class:`InternalSimplifier`).
    strategy : ExplorationStrategy
        Path exploration strategy.
    max_paths : int
        Maximum number of paths to explore.
    max_depth : int
        Maximum path depth (number of branches).
    loop_bound : int
        Maximum loop iterations (k-bounded unrolling).
    timeout : float
        Total timeout in seconds.
    function_models : dict, optional
        Symbolic models for called functions.
    check_assertions : bool
        Check ``assert()`` statements for violations.
    check_division_by_zero : bool
        Check for division by zero.
    check_array_bounds : bool
        Check for array out-of-bounds access.
    generate_tests : bool
        Generate concrete test cases for feasible paths.
    abstract_interp_result : InterpretationResult, optional
        Abstract interpretation results for loop invariant import.
    """

    def __init__(
        self,
        cfg,
        solver: Optional[SMTSolver] = None,
        strategy: ExplorationStrategy = ExplorationStrategy.DFS,
        max_paths: int = DEFAULT_MAX_PATHS,
        max_depth: int = DEFAULT_MAX_DEPTH,
        loop_bound: int = DEFAULT_LOOP_BOUND,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        function_models: Optional[Dict[str, Callable]] = None,
        check_assertions: bool = True,
        check_division_by_zero: bool = True,
        check_array_bounds: bool = False,
        generate_tests: bool = True,
        abstract_interp_result=None,
    ) -> None:
        self.cfg = cfg
        self.solver = solver or InternalSimplifier()
        self.strategy = strategy
        self.max_paths = max_paths
        self.max_depth = max_depth
        self.loop_bound = loop_bound
        self.timeout = timeout
        self.function_models = function_models or {}
        self.check_assertions = check_assertions
        self.check_division_by_zero = check_division_by_zero
        self.check_array_bounds = check_array_bounds
        self.generate_tests = generate_tests
        self.abstract_interp_result = abstract_interp_result

        self._transfer = SymTransferFunction(function_models)
        self._loop_counts: Dict[Tuple, Dict[Any, int]] = {}
        self._covered_branches: Set[Tuple] = set()
        self._path_results: List[PathResult] = []
        self._start_time: float = 0.0
        self._paths_explored: int = 0

    def run(self) -> List[PathResult]:
        """Run symbolic execution.

        Returns
        -------
        list[PathResult]
            Results for each explored path.
        """
        self._start_time = time.time()
        self._path_results = []
        self._paths_explored = 0

        # Build initial state
        initial_state = self._build_initial_state()
        entry_id = self._get_entry_node_id()

        # Initialize worklist
        worklist: Deque[_WorklistItem] = deque()
        worklist.append(_WorklistItem(
            node_id=entry_id,
            state=initial_state,
            path=[entry_id],
            depth=0,
        ))

        while worklist and self._paths_explored < self.max_paths:
            if self._timed_out():
                break

            item = self._select_next(worklist)
            if item is None:
                break

            self._explore_from(item, worklist)

        return self._path_results

    def _build_initial_state(self) -> SymState:
        """Build the initial symbolic state with symbolic inputs."""
        state = SymState()

        func = getattr(self.cfg, "function", None)
        if func is not None:
            arg_list = getattr(func, "argument", {})
            if isinstance(arg_list, dict):
                for idx, var in arg_list.items():
                    name_tok = getattr(var, "nameToken", None)
                    if name_tok:
                        var_name = _sym_variable_id_from_var(var)
                        # Create a fresh symbolic input
                        sym_input = SymVar(var_name, version=0)
                        state.env[var_name] = sym_input

        return state

    def _get_entry_node_id(self) -> Any:
        """Get the entry node ID from the CFG."""
        entry = getattr(self.cfg, "entry", None)
        if entry is not None:
            return getattr(entry, "id", 0)
        nodes = getattr(self.cfg, "nodes", {})
        if nodes:
            return min(nodes.keys()) if isinstance(nodes, dict) else 0
        return 0

    def _select_next(
        self, worklist: Deque[_WorklistItem]
    ) -> Optional[_WorklistItem]:
        """Select the next item from the worklist based on strategy."""
        if not worklist:
            return None

        if self.strategy == ExplorationStrategy.DFS:
            return worklist.pop()
        elif self.strategy == ExplorationStrategy.BFS:
            return worklist.popleft()
        elif self.strategy == ExplorationStrategy.RANDOM:
            idx = random.randint(0, len(worklist) - 1)
            item = worklist[idx]
            del worklist[idx]
            return item
        elif self.strategy == ExplorationStrategy.COVERAGE:
            # Prioritize items targeting uncovered branches
            best_idx = 0
            best_score = -1
            for i, item in enumerate(worklist):
                node_id = item.node_id
                score = self._coverage_score(node_id)
                if score > best_score:
                    best_score = score
                    best_idx = i
            item = worklist[best_idx]
            del worklist[best_idx]
            return item
        else:
            return worklist.pop()

    def _coverage_score(self, node_id: Any) -> int:
        """Score a node by how many uncovered successors it has."""
        node = self._get_node(node_id)
        if node is None:
            return 0
        edges = getattr(node, "outgoing", []) or getattr(node, "out_edges", [])
        score = 0
        for edge in edges:
            target = getattr(edge, "target", None) or getattr(edge, "dst", None)
            if target is not None:
                tid = getattr(target, "id", target)
                branch_key = (node_id, tid)
                if branch_key not in self._covered_branches:
                    score += 1
        return score

    def _explore_from(
        self, item: _WorklistItem, worklist: Deque[_WorklistItem]
    ) -> None:
        """Explore from a worklist item: execute the node and handle edges."""
        node_id = item.node_id
        state = item.state
        path = item.path
        depth = item.depth

        # Get the CFG node
        node = self._get_node(node_id)
        if node is None:
            self._record_path_result(path, state, is_complete=True)
            return

        # Execute the node symbolically
        state = self._transfer(node, state)
        state.depth = depth

        # Check for errors at this node
        self._check_node_errors(node, state, path)

        # Get outgoing edges
        edges = getattr(node, "outgoing", []) or getattr(node, "out_edges", [])

        if not edges:
            # Terminal node (exit, return)
            self._record_path_result(path, state, is_complete=True)
            return

        # Classify edges
        branch_edges = []
        fall_through = []
        for edge in edges:
            edge_type = str(
                getattr(edge, "type", None)
                or getattr(edge, "edge_type", "")
            ).upper()
            if "TRUE" in edge_type or "FALSE" in edge_type:
                branch_edges.append(edge)
            else:
                fall_through.append(edge)

        if branch_edges:
            self._handle_branch(
                node, branch_edges, state, path, depth, worklist
            )
        elif fall_through:
            for edge in fall_through:
                target_id = self._edge_target_id(edge)
                if target_id is not None:
                    self._covered_branches.add((node_id, target_id))
                    new_path = path + [target_id]
                    worklist.append(_WorklistItem(
                        node_id=target_id,
                        state=state.copy(),
                        path=new_path,
                        depth=depth,
                    ))
        else:
            self._record_path_result(path, state, is_complete=True)

    def _handle_branch(
        self,
        node,
        branch_edges: List,
        state: SymState,
        path: List,
        depth: int,
        worklist: Deque[_WorklistItem],
    ) -> None:
        """Handle a branch point: fork into true and false paths.

        Implements the ``big-iftrue`` and ``big-iffalse`` rules from
        chunk 601: evaluate the condition symbolically, check
        satisfiability of each branch, and fork.
        """
        if depth >= self.max_depth:
            self._record_path_result(
                path, state, is_complete=False
            )
            return

        node_id = getattr(node, "id", None)

        # Get the branch condition
        condition_tok = getattr(node, "condition", None)
        if condition_tok is None:
            # No condition available; explore all edges
            for edge in branch_edges:
                target_id = self._edge_target_id(edge)
                if target_id is not None:
                    self._covered_branches.add((node_id, target_id))
                    worklist.append(_WorklistItem(
                        node_id=target_id,
                        state=state.copy(),
                        path=path + [target_id],
                        depth=depth + 1,
                    ))
            return

        # Build the symbolic condition
        builder = SymExprBuilder(state)
        sym_cond = builder.build(condition_tok).simplify()

        # Separate true and false edges
        true_edges = []
        false_edges = []
        other_edges = []
        for edge in branch_edges:
            edge_type = str(
                getattr(edge, "type", None)
                or getattr(edge, "edge_type", "")
            ).upper()
            if "TRUE" in edge_type:
                true_edges.append(edge)
            elif "FALSE" in edge_type:
                false_edges.append(edge)
            else:
                other_edges.append(edge)

        # Check satisfiability of true branch: g ∧ cond
        true_pc = state.path_condition.add(sym_cond)
        true_sat = self.solver.check_sat(true_pc)

        # Check satisfiability of false branch: g ∧ ¬cond
        neg_cond = _negate_sym_expr(sym_cond)
        false_pc = state.path_condition.add(neg_cond)
        false_sat = self.solver.check_sat(false_pc)

        # Fork based on satisfiability
        if true_sat != SolverResult.UNSAT:
            for edge in true_edges:
                target_id = self._edge_target_id(edge)
                if target_id is not None:
                    # Check loop bound
                    if self._exceeds_loop_bound(path, target_id):
                        continue
                    true_state = state.copy()
                    true_state.path_condition = true_pc
                    true_state.path_trace.append(("branch_true", node_id))
                    self._covered_branches.add((node_id, target_id))
                    worklist.append(_WorklistItem(
                        node_id=target_id,
                        state=true_state,
                        path=path + [target_id],
                        depth=depth + 1,
                    ))

        if false_sat != SolverResult.UNSAT:
            for edge in false_edges:
                target_id = self._edge_target_id(edge)
                if target_id is not None:
                    if self._exceeds_loop_bound(path, target_id):
                        continue
                    false_state = state.copy()
                    false_state.path_condition = false_pc
                    false_state.path_trace.append(("branch_false", node_id))
                    self._covered_branches.add((node_id, target_id))
                    worklist.append(_WorklistItem(
                        node_id=target_id,
                        state=false_state,
                        path=path + [target_id],
                        depth=depth + 1,
                    ))

        # Handle other edges (switch cases, gotos, etc.)
        for edge in other_edges:
            target_id = self._edge_target_id(edge)
            if target_id is not None:
                self._covered_branches.add((node_id, target_id))
                worklist.append(_WorklistItem(
                    node_id=target_id,
                    state=state.copy(),
                    path=path + [target_id],
                    depth=depth + 1,
                ))

        # If both branches are infeasible, the current path is dead
        if true_sat == SolverResult.UNSAT and false_sat == SolverResult.UNSAT:
            self._record_path_result(
                path, state, is_complete=False, is_feasible=False
            )

    def _exceeds_loop_bound(self, path: List, target_id: Any) -> bool:
        """Check if visiting target_id would exceed the loop bound.

        Uses back-edge detection: if target_id already appears earlier
        in the path, it's a potential loop back-edge.
        """
        count = sum(1 for nid in path if nid == target_id)
        return count >= self.loop_bound

    def _check_node_errors(
        self, node, state: SymState, path: List
    ) -> None:
        """Check for errors at a CFG node during symbolic execution."""
        tokens = getattr(node, "tokens", [])
        for tok in tokens:
            # Division by zero
            if self.check_division_by_zero and tok.str in ("/", "%", "/=", "%="):
                self._check_sym_div_zero(tok, state, path)

            # Assertions
            if self.check_assertions and self._is_assert_call(tok):
                self._check_sym_assertion(tok, state, path)

    def _check_sym_div_zero(
        self, tok, state: SymState, path: List
    ) -> None:
        """Check for symbolic division by zero."""
        divisor_tok = getattr(tok, "astOperand2", None)
        if divisor_tok is None:
            return

        builder = SymExprBuilder(state)
        divisor_expr = builder.build(divisor_tok)

        # Can the divisor be zero under the current path condition?
        zero_constraint = SymBinOp("==", divisor_expr, SymConst(0))
        check_pc = state.path_condition.add(zero_constraint)
        result = self.solver.check_sat(check_pc)

        if result == SolverResult.SAT:
            model = self.solver.get_model(check_pc)
            self._path_results.append(PathResult(
                path=list(path),
                final_state=state,
                path_condition=check_pc,
                is_feasible=True,
                is_error=True,
                error_kind="division_by_zero",
                error_message=(
                    f"Division by zero: {divisor_expr} can be 0 "
                    f"(line {getattr(tok, 'linenr', '?')})"
                ),
                error_token=tok,
                test_case=self._model_to_test_case(model, path, check_pc),
                depth=state.depth,
            ))

    def _is_assert_call(self, tok) -> bool:
        """Check if a token is an assert() call."""
        if tok.str != "(":
            return False
        callee = getattr(tok, "astOperand1", None)
        if callee is None:
            return False
        name = getattr(callee, "str", "")
        return name in ("assert", "__assert", "__assert_fail",
                        "Assert", "ASSERT", "g_assert")

    def _check_sym_assertion(
        self, tok, state: SymState, path: List
    ) -> None:
        """Check if an assertion can be violated."""
        # The assertion condition is the argument
        args_tok = getattr(tok, "astOperand2", None)
        if args_tok is None:
            return

        builder = SymExprBuilder(state)
        assertion_expr = builder.build(args_tok)

        # Can the assertion be false (i.e., the argument be 0)?
        fail_constraint = SymBinOp("==", assertion_expr, SymConst(0))
        check_pc = state.path_condition.add(fail_constraint)
        result = self.solver.check_sat(check_pc)

        if result == SolverResult.SAT:
            model = self.solver.get_model(check_pc)
            self._path_results.append(PathResult(
                path=list(path),
                final_state=state,
                path_condition=check_pc,
                is_feasible=True,
                is_error=True,
                error_kind="assertion_violation",
                error_message=(
                    f"Assertion can fail: {assertion_expr} can be 0 "
                    f"(line {getattr(tok, 'linenr', '?')})"
                ),
                error_token=tok,
                test_case=self._model_to_test_case(model, path, check_pc),
                depth=state.depth,
            ))

    def _record_path_result(
        self,
        path: List,
        state: SymState,
        is_complete: bool = True,
        is_feasible: bool = True,
    ) -> None:
        """Record a completed path result."""
        self._paths_explored += 1

        test_case = None
        if self.generate_tests and is_feasible:
            model = self.solver.get_model(state.path_condition)
            test_case = self._model_to_test_case(
                model, path, state.path_condition
            )

        self._path_results.append(PathResult(
            path=list(path),
            final_state=state,
            path_condition=state.path_condition,
            is_feasible=is_feasible,
            is_complete=is_complete,
            test_case=test_case,
            depth=state.depth,
        ))

    def _model_to_test_case(
        self,
        model: Optional[SolverModel],
        path: List,
        pc: Optional[PathCondition],
    ) -> Optional[TestCase]:
        """Convert a solver model to a test case."""
        if model is None:
            return None
        return TestCase(
            inputs=dict(model.assignments),
            path=list(path),
            path_condition=pc,
        )

    def _get_node(self, node_id: Any):
        """Get a CFG node by ID."""
        nodes = getattr(self.cfg, "nodes", {})
        if isinstance(nodes, dict):
            return nodes.get(node_id)
        # Try as attribute
        for node in getattr(self.cfg, "all_nodes", lambda: [])():
            if getattr(node, "id", None) == node_id:
                return node
        return None

    def _edge_target_id(self, edge) -> Optional[Any]:
        """Get the target node ID of an edge."""
        target = (
            getattr(edge, "target", None)
            or getattr(edge, "dst", None)
            or getattr(edge, "to_node", None)
        )
        if target is not None:
            return getattr(target, "id", target)
        return getattr(edge, "target_id", None) or getattr(edge, "dst_id", None)

    def _timed_out(self) -> bool:
        return (time.time() - self._start_time) > self.timeout

    # ---- Statistics --------------------------------------------------------

    @property
    def paths_explored(self) -> int:
        return self._paths_explored

    @property
    def branches_covered(self) -> int:
        return len(self._covered_branches)

    @property
    def errors_found(self) -> int:
        return sum(1 for r in self._path_results if r.is_error)

    @property
    def feasible_paths(self) -> int:
        return sum(1 for r in self._path_results if r.is_feasible)

    def coverage_report(self) -> Dict[str, Any]:
        """Generate a coverage report."""
        total_nodes = len(getattr(self.cfg, "nodes", {}))
        visited_nodes = set()
        for r in self._path_results:
            visited_nodes.update(r.path)

        return {
            "paths_explored": self._paths_explored,
            "feasible_paths": self.feasible_paths,
            "errors_found": self.errors_found,
            "branches_covered": self.branches_covered,
            "nodes_visited": len(visited_nodes),
            "total_nodes": total_nodes,
            "node_coverage": (
                len(visited_nodes) / total_nodes if total_nodes else 0.0
            ),
        }


# ===================================================================
# STATIC SYMBOLIC EXECUTOR (SSE)
# ===================================================================

class StaticSymbolicExecutor:
    """Static symbolic execution (SSE) engine.

    Unlike DSE, SSE merges symbolic states at join points using
    ``ite`` (if-then-else) expressions, producing a single compact
    formula per program point.

    From the literature (chunk 602):

    *"SSE merges symbolic formulas at join points... introduces fresh
    symbolic variables α_x for each x such that Σ₁(x) ≠ Σ₂(x); sets
    Σ_merged(x) = α_x; and adds (g₁ ⇒ α_x = Σ₁(x)) ∨ (g₂ ⇒ α_x = Σ₂(x))
    to the path constraints."*

    Parameters
    ----------
    cfg : CFG
        The control-flow graph.
    solver : SMTSolver, optional
        The SMT solver.
    loop_bound : int
        Maximum loop unrolling iterations.
    function_models : dict, optional
        Symbolic models for called functions.
    """

    def __init__(
        self,
        cfg,
        solver: Optional[SMTSolver] = None,
        loop_bound: int = DEFAULT_LOOP_BOUND,
        function_models: Optional[Dict[str, Callable]] = None,
    ) -> None:
        self.cfg = cfg
        self.solver = solver or InternalSimplifier()
        self.loop_bound = loop_bound
        self.function_models = function_models or {}
        self._transfer = SymTransferFunction(function_models)
        self._merge_counter: int = 0

    def run(self) -> Dict[Any, SymState]:
        """Run static symbolic execution.

        Returns
        -------
        dict
            Map from CFG node ID to the merged symbolic state at that node.
        """
        entry_id = self._get_entry_node_id()
        initial_state = self._build_initial_state()

        # Forward dataflow with merging
        states: Dict[Any, SymState] = {entry_id: initial_state}
        worklist: Deque[Any] = deque([entry_id])
        visited_counts: Dict[Any, int] = defaultdict(int)

        while worklist:
            node_id = worklist.popleft()
            visited_counts[node_id] += 1

            if visited_counts[node_id] > self.loop_bound + 1:
                continue

            state = states.get(node_id)
            if state is None:
                continue

            node = self._get_node(node_id)
            if node is None:
                continue

            # Execute node
            out_state = self._transfer(node, state)

            # Process outgoing edges
            edges = (
                getattr(node, "outgoing", [])
                or getattr(node, "out_edges", [])
            )

            for edge in edges:
                target_id = self._edge_target_id(edge)
                if target_id is None:
                    continue

                # Refine state along edge
                edge_state = self._refine_edge(edge, node, out_state)

                if target_id in states:
                    # Merge with existing state at join point
                    merged = self._merge_states(
                        states[target_id], edge_state, node_id, target_id
                    )
                    if self._state_changed(states[target_id], merged):
                        states[target_id] = merged
                        worklist.append(target_id)
                else:
                    states[target_id] = edge_state
                    worklist.append(target_id)

        return states

    def _merge_states(
        self,
        state1: SymState,
        state2: SymState,
        source1_id: Any,
        target_id: Any,
    ) -> SymState:
        """Merge two symbolic states at a join point.

        Introduces fresh symbolic variables with ITE guards for
        variables that differ between the two states.
        """
        self._merge_counter += 1
        merged = SymState()

        all_vars = state1.variables | state2.variables
        for var in all_vars:
            expr1 = state1.get(var)
            expr2 = state2.get(var)

            if expr1 == expr2:
                merged.env[var] = expr1
            else:
                # Create ITE: if guard then expr1 else expr2
                guard1 = state1.path_condition.as_conjunction()
                merged.env[var] = SymITE(guard1, expr1, expr2).simplify()

        # Merge path conditions: g1 ∨ g2
        g1 = state1.path_condition.as_conjunction()
        g2 = state2.path_condition.as_conjunction()
        merged_guard = SymBinOp("||", g1, g2).simplify()
        merged.path_condition = PathCondition([merged_guard])

        return merged

    def _refine_edge(self, edge, node, state: SymState) -> SymState:
        """Refine state along a branch edge by adding the branch condition."""
        edge_type = str(
            getattr(edge, "type", None)
            or getattr(edge, "edge_type", "")
        ).upper()

        condition_tok = getattr(node, "condition", None)
        if condition_tok is None:
            return state

        if "TRUE" not in edge_type and "FALSE" not in edge_type:
            return state

        builder = SymExprBuilder(state)
        sym_cond = builder.build(condition_tok).simplify()

        if "FALSE" in edge_type:
            sym_cond = _negate_sym_expr(sym_cond)

        return state.add_constraint(sym_cond)

    def _state_changed(self, old: SymState, new: SymState) -> bool:
        """Check if a state has changed (simple structural comparison)."""
        if old.variables != new.variables:
            return True
        for var in old.variables:
            if old.get(var) != new.get(var):
                return True
        return False

    def _build_initial_state(self) -> SymState:
        state = SymState()
        func = getattr(self.cfg, "function", None)
        if func is not None:
            arg_list = getattr(func, "argument", {})
            if isinstance(arg_list, dict):
                for idx, var in arg_list.items():
                    name_tok = getattr(var, "nameToken", None)
                    if name_tok:
                        var_name = _sym_variable_id_from_var(var)
                        state.env[var_name] = SymVar(var_name, version=0)
        return state

    def _get_entry_node_id(self) -> Any:
        entry = getattr(self.cfg, "entry", None)
        if entry is not None:
            return getattr(entry, "id", 0)
        nodes = getattr(self.cfg, "nodes", {})
        if nodes:
            return min(nodes.keys()) if isinstance(nodes, dict) else 0
        return 0

    def _get_node(self, node_id: Any):
        nodes = getattr(self.cfg, "nodes", {})
        if isinstance(nodes, dict):
            return nodes.get(node_id)
        return None

    def _edge_target_id(self, edge) -> Optional[Any]:
        target = (
            getattr(edge, "target", None)
            or getattr(edge, "dst", None)
        )
        if target is not None:
            return getattr(target, "id", target)
        return getattr(edge, "target_id", None)


# ===================================================================
# CONCOLIC EXECUTOR
# ===================================================================

class ConcolicExecutor:
    """Concolic (concrete + symbolic) executor.

    Runs the program concretely with tracked symbolic state, using
    concrete values to guide path selection and symbolic constraints
    to generate new inputs that explore different paths (DART/SAGE
    style).

    The key idea: execute concretely (resolving all nondeterminism),
    collect the symbolic path condition, then systematically negate
    individual branch constraints to steer execution down new paths.

    Parameters
    ----------
    cfg : CFG
        The control-flow graph.
    solver : SMTSolver, optional
        The SMT solver.
    initial_inputs : dict, optional
        Initial concrete input values.
    max_iterations : int
        Maximum number of concolic iterations.
    loop_bound : int
        Maximum loop unrolling.
    function_models : dict, optional
        Symbolic function models.
    """

    def __init__(
        self,
        cfg,
        solver: Optional[SMTSolver] = None,
        initial_inputs: Optional[Dict[str, int]] = None,
        max_iterations: int = 100,
        loop_bound: int = DEFAULT_LOOP_BOUND,
        function_models: Optional[Dict[str, Callable]] = None,
    ) -> None:
        self.cfg = cfg
        self.solver = solver or InternalSimplifier()
        self.initial_inputs = initial_inputs or {}
        self.max_iterations = max_iterations
        self.loop_bound = loop_bound
        self.function_models = function_models or {}

        self._transfer = SymTransferFunction(function_models)
        self._explored_pcs: Set[int] = set()
        self._results: List[PathResult] = []

    def run(self) -> List[PathResult]:
        """Run concolic execution.

        Returns
        -------
        list[PathResult]
            Results for explored paths.
        """
        current_inputs = dict(self.initial_inputs)
        self._results = []

        for iteration in range(self.max_iterations):
            # Execute concretely with symbolic tracking
            path_result = self._execute_concolic(current_inputs)
            self._results.append(path_result)

            if path_result.path_condition is None:
                break

            # Hash the path condition to avoid repeats
            pc_hash = hash(path_result.path_condition)
            self._explored_pcs.add(pc_hash)

            # Generate new inputs by negating a branch constraint
            new_inputs = self._generate_new_inputs(path_result)
            if new_inputs is None:
                break

            current_inputs = new_inputs

        return self._results

    def _execute_concolic(
        self, concrete_inputs: Dict[str, int]
    ) -> PathResult:
        """Execute one concolic run: concrete execution with symbolic tracking."""
        # Build state with both concrete and symbolic values
        state = SymState()
        for name, value in concrete_inputs.items():
            # Symbolic: the symbolic variable
            state.env[name] = SymVar(name, version=0)

        entry_id = self._get_entry_node_id()
        path: List[Any] = [entry_id]
        node_id = entry_id

        depth = 0
        while depth < DEFAULT_MAX_DEPTH:
            node = self._get_node(node_id)
            if node is None:
                break

            # Transfer
            state = self._transfer(node, state)

            # Get edges
            edges = (
                getattr(node, "outgoing", [])
                or getattr(node, "out_edges", [])
            )
            if not edges:
                break

            # At a branch, use concrete values to determine direction
            branch_edges = [
                e for e in edges
                if "TRUE" in str(
                    getattr(e, "type", getattr(e, "edge_type", ""))
                ).upper()
                or "FALSE" in str(
                    getattr(e, "type", getattr(e, "edge_type", ""))
                ).upper()
            ]

            if branch_edges:
                # Evaluate condition concretely
                condition_tok = getattr(node, "condition", None)
                if condition_tok is not None:
                    builder = SymExprBuilder(state)
                    sym_cond = builder.build(condition_tok).simplify()
                    concrete_val = sym_cond.evaluate(concrete_inputs)

                    if concrete_val is None:
                        concrete_val = 1  # default: take true branch

                    if concrete_val:
                        constraint = sym_cond
                        taken_type = "TRUE"
                    else:
                        constraint = _negate_sym_expr(sym_cond)
                        taken_type = "FALSE"

                    state = state.add_constraint(constraint)

                    # Find the edge matching the concrete direction
                    target_edge = None
                    for e in branch_edges:
                        etype = str(
                            getattr(e, "type", getattr(e, "edge_type", ""))
                        ).upper()
                        if taken_type in etype:
                            target_edge = e
                            break
                    if target_edge is None and branch_edges:
                        target_edge = branch_edges[0]
                else:
                    target_edge = branch_edges[0] if branch_edges else None
            else:
                target_edge = edges[0] if edges else None

            if target_edge is None:
                break

            next_id = self._edge_target_id(target_edge)
            if next_id is None:
                break

            # Loop bound check
            if sum(1 for nid in path if nid == next_id) >= self.loop_bound:
                break

            path.append(next_id)
            node_id = next_id
            depth += 1

        return PathResult(
            path=path,
            final_state=state,
            path_condition=state.path_condition,
            is_feasible=True,
            is_complete=True,
            depth=depth,
        )

    def _generate_new_inputs(
        self, path_result: PathResult
    ) -> Optional[Dict[str, int]]:
        """Generate new inputs by systematically negating branch constraints.

        Tries negating the last unexplored branch, then the second-to-last,
        etc. (generational search).
        """
        pc = path_result.path_condition
        if pc is None or pc.is_empty:
            return None

        constraints = list(pc.constraints)

        # Try negating constraints from last to first
        for i in range(len(constraints) - 1, -1, -1):
            # Build a new PC: keep constraints 0..i-1, negate constraint i
            new_constraints = list(constraints[:i])
            negated = _negate_sym_expr(constraints[i])
            new_constraints.append(negated)
            new_pc = PathCondition(new_constraints)

            # Check if this PC has been explored
            pc_hash = hash(new_pc)
            if pc_hash in self._explored_pcs:
                continue

            # Try to get a model
            result = self.solver.check_sat(new_pc)
            if result == SolverResult.SAT:
                model = self.solver.get_model(new_pc)
                if model is not None:
                    self._explored_pcs.add(pc_hash)
                    return dict(model.assignments)

        return None

    def _get_entry_node_id(self) -> Any:
        entry = getattr(self.cfg, "entry", None)
        if entry is not None:
            return getattr(entry, "id", 0)
        return 0

    def _get_node(self, node_id: Any):
        nodes = getattr(self.cfg, "nodes", {})
        if isinstance(nodes, dict):
            return nodes.get(node_id)
        return None

    def _edge_target_id(self, edge) -> Optional[Any]:
        target = (
            getattr(edge, "target", None)
            or getattr(edge, "dst", None)
        )
        if target is not None:
            return getattr(target, "id", target)
        return getattr(edge, "target_id", None)


# ===================================================================
# BUILT-IN FUNCTION MODELS
# ===================================================================

def _model_abs(state: SymState, args: List[SymExpr]) -> Tuple[SymState, SymExpr]:
    """Symbolic model for abs(x)."""
    if not args:
        return state, SymVar("__abs_unknown__")
    x = args[0]
    cond = SymBinOp(">=", x, SymConst(0))
    result = SymITE(cond, x, SymUnaryOp("-", x))
    return state, result


def _model_min(state: SymState, args: List[SymExpr]) -> Tuple[SymState, SymExpr]:
    """Symbolic model for min(a, b)."""
    if len(args) < 2:
        return state, SymVar("__min_unknown__")
    a, b = args[0], args[1]
    cond = SymBinOp("<=", a, b)
    return state, SymITE(cond, a, b)


def _model_max(state: SymState, args: List[SymExpr]) -> Tuple[SymState, SymExpr]:
    """Symbolic model for max(a, b)."""
    if len(args) < 2:
        return state, SymVar("__max_unknown__")
    a, b = args[0], args[1]
    cond = SymBinOp(">=", a, b)
    return state, SymITE(cond, a, b)


BUILTIN_FUNCTION_MODELS: Dict[str, Callable] = {
    "abs": _model_abs,
    "min": _model_min,
    "max": _model_max,
}


# ===================================================================
# CONVENIENCE FUNCTIONS
# ===================================================================

def execute_function(
    cfg,
    *,
    solver: Optional[SMTSolver] = None,
    strategy: ExplorationStrategy = ExplorationStrategy.DFS,
    max_paths: int = DEFAULT_MAX_PATHS,
    max_depth: int = DEFAULT_MAX_DEPTH,
    loop_bound: int = DEFAULT_LOOP_BOUND,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    function_models: Optional[Dict[str, Callable]] = None,
    check_assertions: bool = True,
    check_division_by_zero: bool = True,
    generate_tests: bool = True,
) -> List[PathResult]:
    """Symbolically execute a function.

    Parameters
    ----------
    cfg : CFG
        The function's control-flow graph.
    solver : SMTSolver, optional
        SMT solver (default: InternalSimplifier).
    strategy : ExplorationStrategy
        Exploration strategy (default: DFS).
    max_paths : int
        Maximum paths to explore.
    max_depth : int
        Maximum path depth.
    loop_bound : int
        Maximum loop iterations.
    timeout : float
        Timeout in seconds.
    function_models : dict, optional
        Symbolic function models.
    check_assertions : bool
        Check assertions.
    check_division_by_zero : bool
        Check division by zero.
    generate_tests : bool
        Generate test cases.

    Returns
    -------
    list[PathResult]
    """
    all_models = dict(BUILTIN_FUNCTION_MODELS)
    if function_models:
        all_models.update(function_models)

    executor = SymbolicExecutor(
        cfg=cfg,
        solver=solver,
        strategy=strategy,
        max_paths=max_paths,
        max_depth=max_depth,
        loop_bound=loop_bound,
        timeout=timeout,
        function_models=all_models,
        check_assertions=check_assertions,
        check_division_by_zero=check_division_by_zero,
        generate_tests=generate_tests,
    )
    return executor.run()


def execute_path(
    cfg,
    path: List[Any],
    *,
    solver: Optional[SMTSolver] = None,
    function_models: Optional[Dict[str, Callable]] = None,
) -> PathResult:
    """Execute a specific path through a CFG symbolically.

    Parameters
    ----------
    cfg : CFG
    path : list
        Sequence of node IDs defining the path.
    solver : SMTSolver, optional
    function_models : dict, optional

    Returns
    -------
    PathResult
    """
    solver = solver or InternalSimplifier()
    transfer = SymTransferFunction(function_models or {})
    state = SymState()

    nodes = getattr(cfg, "nodes", {})

    for i, node_id in enumerate(path):
        node = nodes.get(node_id) if isinstance(nodes, dict) else None
        if node is None:
            continue

        # Execute node
        state = transfer(node, state)

        # If not the last node, add branch constraint
        if i < len(path) - 1:
            next_id = path[i + 1]
            condition_tok = getattr(node, "condition", None)
            if condition_tok is not None:
                builder = SymExprBuilder(state)
                sym_cond = builder.build(condition_tok).simplify()

                # Determine which branch was taken
                edges = (
                    getattr(node, "outgoing", [])
                    or getattr(node, "out_edges", [])
                )
                for edge in edges:
                    target_id = None
                    target = (
                        getattr(edge, "target", None)
                        or getattr(edge, "dst", None)
                    )
                    if target is not None:
                        target_id = getattr(target, "id", target)

                    if target_id == next_id:
                        edge_type = str(
                            getattr(edge, "type", getattr(edge, "edge_type", ""))
                        ).upper()
                        if "FALSE" in edge_type:
                            state = state.add_constraint(
                                _negate_sym_expr(sym_cond)
                            )
                        elif "TRUE" in edge_type:
                            state = state.add_constraint(sym_cond)
                        break

    # Check feasibility
    sat_result = solver.check_sat(state.path_condition)
    is_feasible = sat_result != SolverResult.UNSAT

    test_case = None
    if is_feasible:
        model = solver.get_model(state.path_condition)
        if model is not None:
            test_case = TestCase(
                inputs=dict(model.assignments),
                path=list(path),
                path_condition=state.path_condition,
            )

    return PathResult(
        path=list(path),
        final_state=state,
        path_condition=state.path_condition,
        is_feasible=is_feasible,
        is_complete=True,
        test_case=test_case,
        depth=len(path),
    )


def find_assertion_violations(
    cfg,
    *,
    solver: Optional[SMTSolver] = None,
    max_paths: int = DEFAULT_MAX_PATHS,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> List[PathResult]:
    """Find all assertion violations in a function.

    Parameters
    ----------
    cfg : CFG
    solver : SMTSolver, optional
    max_paths : int
    timeout : float

    Returns
    -------
    list[PathResult]
        Only error paths (assertion violations).
    """
    results = execute_function(
        cfg,
        solver=solver,
        max_paths=max_paths,
        timeout=timeout,
        check_assertions=True,
        check_division_by_zero=False,
        generate_tests=True,
    )
    return [r for r in results if r.is_error and r.error_kind == "assertion_violation"]


def find_bug_triggering_inputs(
    cfg,
    *,
    solver: Optional[SMTSolver] = None,
    max_paths: int = DEFAULT_MAX_PATHS,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    bug_kinds: Optional[Set[str]] = None,
) -> List[TestCase]:
    """Find concrete inputs that trigger bugs.

    Parameters
    ----------
    cfg : CFG
    solver : SMTSolver, optional
    max_paths : int
    timeout : float
    bug_kinds : set of str, optional
        Bug kinds to look for.  Default: all kinds.

    Returns
    -------
    list[TestCase]
        Test cases that trigger bugs.
    """
    if bug_kinds is None:
        bug_kinds = {"division_by_zero", "assertion_violation",
                     "null_dereference", "array_out_of_bounds"}

    results = execute_function(
        cfg,
        solver=solver,
        max_paths=max_paths,
        timeout=timeout,
        check_assertions="assertion_violation" in bug_kinds,
        check_division_by_zero="division_by_zero" in bug_kinds,
        generate_tests=True,
    )

    test_cases = []
    for r in results:
        if r.is_error and r.error_kind in bug_kinds and r.test_case is not None:
            test_cases.append(r.test_case)

    return test_cases


# ===================================================================
# UTILITIES
# ===================================================================

def _sym_variable_id_from_var(var) -> str:
    """Get a stable variable identifier from a Cppcheck Variable object."""
    vid = getattr(var, "Id", None)
    if vid:
        return f"v{vid}"
    name_tok = getattr(var, "nameToken", None)
    if name_tok:
        return getattr(name_tok, "str", "?")
    return "?"


def sym_expr_size(expr: SymExpr) -> int:
    """Count the number of nodes in a symbolic expression tree."""
    count = 1
    for child in expr.children:
        count += sym_expr_size(child)
    return count


def sym_expr_depth(expr: SymExpr) -> int:
    """Compute the depth of a symbolic expression tree."""
    if not expr.children:
        return 0
    return 1 + max(sym_expr_depth(c) for c in expr.children)


def collect_all_constraints(
    results: List[PathResult],
) -> List[PathCondition]:
    """Collect all path conditions from a list of path results."""
    return [
        r.path_condition for r in results
        if r.path_condition is not None
    ]
