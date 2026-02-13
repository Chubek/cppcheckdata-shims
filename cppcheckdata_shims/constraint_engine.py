"""
constraint_engine.py — Unified Constraint Generation, Solving & Property Checking
==================================================================================

Capstone module for the cppcheckdata-shims library.  Provides:

1. A typed first-order constraint language over program variables.
2. Constraint generators bridging abstract interpretation and symbolic execution.
3. A property-specification DSL for safety/liveness assertions.
4. A CEGAR (Counterexample-Guided Abstraction Refinement) driver.
5. Constraint-based domain reduction and cross-domain propagation.

Depends on:
    - controlflow_graph  (CFG construction)
    - callgraph          (interprocedural structure)
    - dataflow_engine     (lattice framework, worklist solvers)
    - abstract_interp     (abstract domains, interpreter)
    - symbolic_exec       (symbolic expressions, executors, SMT interface)
    - cppcheckdata        (Cppcheck dump file model)
"""

from __future__ import annotations

import enum
import itertools
import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import (
    Any,
    Callable,
    Dict,
    FrozenSet,
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

# ---------------------------------------------------------------------------
# Internal imports (sibling modules in the cppcheckdata-shims package)
# ---------------------------------------------------------------------------
try:
    from . import controlflow_graph as cfg_mod
    from . import callgraph as cg_mod
    from . import dataflow_engine as df_mod
    from . import abstract_interp as ai_mod
    from . import symbolic_exec as se_mod
except ImportError:
    import controlflow_graph as cfg_mod  # type: ignore
    import callgraph as cg_mod  # type: ignore
    import dataflow_engine as df_mod  # type: ignore
    import abstract_interp as ai_mod  # type: ignore
    import symbolic_exec as se_mod  # type: ignore

try:
    import cppcheckdata
except ImportError:
    cppcheckdata = None  # type: ignore

logger = logging.getLogger(__name__)

# ===================================================================
#  PART 1 — CONSTRAINT LANGUAGE
# ===================================================================

# -------------------------------------------------------------------
# 1.1  Types
# -------------------------------------------------------------------

class CType(enum.Enum):
    """Simplified C type system for constraint typing."""
    BOOL = "bool"
    INT = "int"
    UINT = "uint"
    LONG = "long"
    ULONG = "ulong"
    FLOAT = "float"
    DOUBLE = "double"
    POINTER = "pointer"
    UNKNOWN = "unknown"

    @property
    def is_integer(self) -> bool:
        return self in (CType.BOOL, CType.INT, CType.UINT,
                        CType.LONG, CType.ULONG)

    @property
    def is_floating(self) -> bool:
        return self in (CType.FLOAT, CType.DOUBLE)

    @property
    def is_numeric(self) -> bool:
        return self.is_integer or self.is_floating

    @property
    def bit_width(self) -> int:
        _widths = {
            CType.BOOL: 1, CType.INT: 32, CType.UINT: 32,
            CType.LONG: 64, CType.ULONG: 64, CType.FLOAT: 32,
            CType.DOUBLE: 64, CType.POINTER: 64, CType.UNKNOWN: 64,
        }
        return _widths[self]


def _infer_ctype(token) -> CType:
    """Best-effort inference of CType from a Cppcheck token."""
    if token is None:
        return CType.UNKNOWN
    vtype = getattr(token, "valueType", None)
    if vtype is None:
        return CType.UNKNOWN
    sign = getattr(vtype, "sign", "") or ""
    type_str = getattr(vtype, "type", "") or ""
    pointer = getattr(vtype, "pointer", 0) or 0
    if pointer:
        return CType.POINTER
    unsigned = sign == "unsigned"
    if type_str in ("int", "short", "char"):
        return CType.UINT if unsigned else CType.INT
    if type_str in ("long", "long long"):
        return CType.ULONG if unsigned else CType.LONG
    if type_str == "float":
        return CType.FLOAT
    if type_str == "double":
        return CType.DOUBLE
    if type_str == "bool":
        return CType.BOOL
    return CType.UNKNOWN


# -------------------------------------------------------------------
# 1.2  Constraint AST nodes
# -------------------------------------------------------------------

class Constraint(ABC):
    """Base class for all constraints in the unified constraint language.

    A *constraint* is a Boolean-valued expression over program variables,
    constants, and abstract-domain predicates.  Constraints form a first-order
    logic augmented with arithmetic, bit-vector, and pointer operations.
    """

    @abstractmethod
    def free_vars(self) -> FrozenSet[str]:
        """Return the set of free variable names mentioned in this constraint."""
        ...

    @abstractmethod
    def substitute(self, mapping: Mapping[str, "Constraint"]) -> "Constraint":
        """Substitute free variables according to *mapping*."""
        ...

    @abstractmethod
    def negate(self) -> "Constraint":
        """Return the logical negation of this constraint."""
        ...

    @abstractmethod
    def to_smt(self, ctx: "SMTContext") -> Any:
        """Translate this constraint to an SMT term in the given context."""
        ...

    @abstractmethod
    def pretty(self) -> str:
        """Human-readable representation."""
        ...

    def __repr__(self) -> str:
        return f"<Constraint: {self.pretty()}>"

    # Logical combinators (syntactic sugar)
    def __and__(self, other: "Constraint") -> "Constraint":
        return CAnd(self, other)

    def __or__(self, other: "Constraint") -> "Constraint":
        return COr(self, other)

    def __invert__(self) -> "Constraint":
        return self.negate()


class CTrue(Constraint):
    """Trivially-true constraint (⊤)."""
    def free_vars(self) -> FrozenSet[str]:
        return frozenset()
    def substitute(self, mapping):
        return self
    def negate(self):
        return CFalse()
    def to_smt(self, ctx):
        return ctx.mk_bool(True)
    def pretty(self):
        return "true"


class CFalse(Constraint):
    """Trivially-false constraint (⊥)."""
    def free_vars(self) -> FrozenSet[str]:
        return frozenset()
    def substitute(self, mapping):
        return self
    def negate(self):
        return CTrue()
    def to_smt(self, ctx):
        return ctx.mk_bool(False)
    def pretty(self):
        return "false"


@dataclass(frozen=True)
class CVar(Constraint):
    """A reference to a program variable (or symbolic variable)."""
    name: str
    ctype: CType = CType.UNKNOWN

    def free_vars(self):
        return frozenset({self.name})
    def substitute(self, mapping):
        return mapping.get(self.name, self)
    def negate(self):
        return CRelation(RelOp.EQ, self, CConst(0))
    def to_smt(self, ctx):
        return ctx.mk_var(self.name, self.ctype)
    def pretty(self):
        return self.name


@dataclass(frozen=True)
class CConst(Constraint):
    """A constant value (integer or floating-point)."""
    value: Union[int, float, bool]
    ctype: CType = CType.INT

    def free_vars(self):
        return frozenset()
    def substitute(self, mapping):
        return self
    def negate(self):
        if isinstance(self.value, bool):
            return CConst(not self.value, CType.BOOL)
        return CRelation(RelOp.EQ, self, CConst(0))
    def to_smt(self, ctx):
        return ctx.mk_const(self.value, self.ctype)
    def pretty(self):
        return str(self.value)


class RelOp(enum.Enum):
    EQ = "=="
    NE = "!="
    LT = "<"
    LE = "<="
    GT = ">"
    GE = ">="

    def flip(self) -> "RelOp":
        _flips = {
            RelOp.EQ: RelOp.EQ, RelOp.NE: RelOp.NE,
            RelOp.LT: RelOp.GT, RelOp.LE: RelOp.GE,
            RelOp.GT: RelOp.LT, RelOp.GE: RelOp.LE,
        }
        return _flips[self]

    def negate(self) -> "RelOp":
        _negs = {
            RelOp.EQ: RelOp.NE, RelOp.NE: RelOp.EQ,
            RelOp.LT: RelOp.GE, RelOp.LE: RelOp.GT,
            RelOp.GT: RelOp.LE, RelOp.GE: RelOp.LT,
        }
        return _negs[self]


@dataclass(frozen=True)
class CRelation(Constraint):
    """A binary relational constraint:  lhs <op> rhs."""
    op: RelOp
    lhs: Constraint
    rhs: Constraint

    def free_vars(self):
        return self.lhs.free_vars() | self.rhs.free_vars()
    def substitute(self, mapping):
        return CRelation(self.op, self.lhs.substitute(mapping),
                         self.rhs.substitute(mapping))
    def negate(self):
        return CRelation(self.op.negate(), self.lhs, self.rhs)
    def to_smt(self, ctx):
        l = self.lhs.to_smt(ctx)
        r = self.rhs.to_smt(ctx)
        return ctx.mk_rel(self.op, l, r)
    def pretty(self):
        return f"({self.lhs.pretty()} {self.op.value} {self.rhs.pretty()})"


class ArithOp(enum.Enum):
    ADD = "+"
    SUB = "-"
    MUL = "*"
    DIV = "/"
    MOD = "%"
    BAND = "&"
    BOR = "|"
    BXOR = "^"
    SHL = "<<"
    SHR = ">>"


@dataclass(frozen=True)
class CArith(Constraint):
    """An arithmetic / bitwise expression."""
    op: ArithOp
    lhs: Constraint
    rhs: Constraint
    ctype: CType = CType.INT

    def free_vars(self):
        return self.lhs.free_vars() | self.rhs.free_vars()
    def substitute(self, mapping):
        return CArith(self.op, self.lhs.substitute(mapping),
                       self.rhs.substitute(mapping), self.ctype)
    def negate(self):
        return CRelation(RelOp.EQ, self, CConst(0))
    def to_smt(self, ctx):
        l = self.lhs.to_smt(ctx)
        r = self.rhs.to_smt(ctx)
        return ctx.mk_arith(self.op, l, r, self.ctype)
    def pretty(self):
        return f"({self.lhs.pretty()} {self.op.value} {self.rhs.pretty()})"


@dataclass(frozen=True)
class CUnaryOp(Constraint):
    """A unary operation (negation, bitwise complement, logical not)."""
    op: str          # "-", "~", "!"
    operand: Constraint
    ctype: CType = CType.INT

    def free_vars(self):
        return self.operand.free_vars()
    def substitute(self, mapping):
        return CUnaryOp(self.op, self.operand.substitute(mapping), self.ctype)
    def negate(self):
        if self.op == "!":
            return self.operand
        return CRelation(RelOp.EQ, self, CConst(0))
    def to_smt(self, ctx):
        inner = self.operand.to_smt(ctx)
        return ctx.mk_unary(self.op, inner, self.ctype)
    def pretty(self):
        return f"({self.op}{self.operand.pretty()})"


@dataclass(frozen=True)
class CAnd(Constraint):
    """Logical conjunction."""
    lhs: Constraint
    rhs: Constraint

    def free_vars(self):
        return self.lhs.free_vars() | self.rhs.free_vars()
    def substitute(self, mapping):
        return CAnd(self.lhs.substitute(mapping), self.rhs.substitute(mapping))
    def negate(self):
        return COr(self.lhs.negate(), self.rhs.negate())
    def to_smt(self, ctx):
        return ctx.mk_and(self.lhs.to_smt(ctx), self.rhs.to_smt(ctx))
    def pretty(self):
        return f"({self.lhs.pretty()} ∧ {self.rhs.pretty()})"


@dataclass(frozen=True)
class COr(Constraint):
    """Logical disjunction."""
    lhs: Constraint
    rhs: Constraint

    def free_vars(self):
        return self.lhs.free_vars() | self.rhs.free_vars()
    def substitute(self, mapping):
        return COr(self.lhs.substitute(mapping), self.rhs.substitute(mapping))
    def negate(self):
        return CAnd(self.lhs.negate(), self.rhs.negate())
    def to_smt(self, ctx):
        return ctx.mk_or(self.lhs.to_smt(ctx), self.rhs.to_smt(ctx))
    def pretty(self):
        return f"({self.lhs.pretty()} ∨ {self.rhs.pretty()})"


@dataclass(frozen=True)
class CNot(Constraint):
    """Logical negation."""
    inner: Constraint

    def free_vars(self):
        return self.inner.free_vars()
    def substitute(self, mapping):
        return CNot(self.inner.substitute(mapping))
    def negate(self):
        return self.inner
    def to_smt(self, ctx):
        return ctx.mk_not(self.inner.to_smt(ctx))
    def pretty(self):
        return f"(¬{self.inner.pretty()})"


@dataclass(frozen=True)
class CImplies(Constraint):
    """Logical implication."""
    antecedent: Constraint
    consequent: Constraint

    def free_vars(self):
        return self.antecedent.free_vars() | self.consequent.free_vars()
    def substitute(self, mapping):
        return CImplies(self.antecedent.substitute(mapping),
                        self.consequent.substitute(mapping))
    def negate(self):
        return CAnd(self.antecedent, self.consequent.negate())
    def to_smt(self, ctx):
        return ctx.mk_implies(self.antecedent.to_smt(ctx),
                              self.consequent.to_smt(ctx))
    def pretty(self):
        return f"({self.antecedent.pretty()} ⇒ {self.consequent.pretty()})"


@dataclass(frozen=True)
class CForall(Constraint):
    """Universal quantification (over integer / pointer variables)."""
    var: str
    ctype: CType
    body: Constraint

    def free_vars(self):
        return self.body.free_vars() - {self.var}
    def substitute(self, mapping):
        new_mapping = {k: v for k, v in mapping.items() if k != self.var}
        return CForall(self.var, self.ctype, self.body.substitute(new_mapping))
    def negate(self):
        return CExists(self.var, self.ctype, self.body.negate())
    def to_smt(self, ctx):
        return ctx.mk_forall(self.var, self.ctype, self.body.to_smt(ctx))
    def pretty(self):
        return f"(∀ {self.var}:{self.ctype.value}. {self.body.pretty()})"


@dataclass(frozen=True)
class CExists(Constraint):
    """Existential quantification."""
    var: str
    ctype: CType
    body: Constraint

    def free_vars(self):
        return self.body.free_vars() - {self.var}
    def substitute(self, mapping):
        new_mapping = {k: v for k, v in mapping.items() if k != self.var}
        return CExists(self.var, self.ctype, self.body.substitute(new_mapping))
    def negate(self):
        return CForall(self.var, self.ctype, self.body.negate())
    def to_smt(self, ctx):
        return ctx.mk_exists(self.var, self.ctype, self.body.to_smt(ctx))
    def pretty(self):
        return f"(∃ {self.var}:{self.ctype.value}. {self.body.pretty()})"


@dataclass(frozen=True)
class CInRange(Constraint):
    """Range constraint:  lo ≤ var ≤ hi."""
    var: str
    lo: Union[int, float]
    hi: Union[int, float]

    def free_vars(self):
        return frozenset({self.var})
    def substitute(self, mapping):
        if self.var in mapping:
            v = mapping[self.var]
            return CAnd(CRelation(RelOp.LE, CConst(self.lo), v),
                        CRelation(RelOp.LE, v, CConst(self.hi)))
        return self
    def negate(self):
        v = CVar(self.var)
        return COr(CRelation(RelOp.LT, v, CConst(self.lo)),
                   CRelation(RelOp.GT, v, CConst(self.hi)))
    def to_smt(self, ctx):
        v = ctx.mk_var(self.var, CType.INT)
        lo_smt = ctx.mk_const(self.lo, CType.INT)
        hi_smt = ctx.mk_const(self.hi, CType.INT)
        return ctx.mk_and(ctx.mk_rel(RelOp.LE, lo_smt, v),
                          ctx.mk_rel(RelOp.LE, v, hi_smt))
    def pretty(self):
        return f"({self.lo} ≤ {self.var} ≤ {self.hi})"


@dataclass(frozen=True)
class CInSet(Constraint):
    """Set membership:  var ∈ {v₁, v₂, …}."""
    var: str
    values: FrozenSet[Union[int, float]]

    def free_vars(self):
        return frozenset({self.var})
    def substitute(self, mapping):
        if self.var in mapping:
            v = mapping[self.var]
            disjuncts = [CRelation(RelOp.EQ, v, CConst(val))
                         for val in sorted(self.values)]
            return _disjunction(disjuncts)
        return self
    def negate(self):
        v = CVar(self.var)
        conjuncts = [CRelation(RelOp.NE, v, CConst(val))
                     for val in sorted(self.values)]
        return _conjunction(conjuncts)
    def to_smt(self, ctx):
        v = ctx.mk_var(self.var, CType.INT)
        eqs = [ctx.mk_rel(RelOp.EQ, v, ctx.mk_const(val, CType.INT))
               for val in sorted(self.values)]
        return ctx.mk_or_many(eqs)
    def pretty(self):
        vals = ", ".join(str(v) for v in sorted(self.values))
        return f"({self.var} ∈ {{{vals}}})"


@dataclass(frozen=True)
class CDomainPredicate(Constraint):
    """An opaque predicate derived from an abstract domain element.

    This wraps an abstract value with its domain so that the constraint
    can be refined or checked without losing semantic information.
    """
    var: str
    domain_name: str
    abstract_value: Any          # the abstract element
    description: str = ""

    def free_vars(self):
        return frozenset({self.var})
    def substitute(self, mapping):
        return self  # opaque — no structural substitution
    def negate(self):
        return CNot(self)
    def to_smt(self, ctx):
        # Attempt to concretize through the domain's concretization
        return ctx.mk_domain_pred(self.var, self.domain_name,
                                  self.abstract_value)
    def pretty(self):
        desc = self.description or f"{self.domain_name}({self.abstract_value})"
        return f"[{self.var}: {desc}]"


# -------------------------------------------------------------------
# 1.3  Constraint utilities
# -------------------------------------------------------------------

def _conjunction(cs: Sequence[Constraint]) -> Constraint:
    """Fold a list of constraints into a conjunction, with identity CTrue."""
    result: Constraint = CTrue()
    for c in cs:
        if isinstance(c, CFalse):
            return CFalse()
        if isinstance(c, CTrue):
            continue
        result = c if isinstance(result, CTrue) else CAnd(result, c)
    return result


def _disjunction(cs: Sequence[Constraint]) -> Constraint:
    """Fold a list of constraints into a disjunction, with identity CFalse."""
    result: Constraint = CFalse()
    for c in cs:
        if isinstance(c, CTrue):
            return CTrue()
        if isinstance(c, CFalse):
            continue
        result = c if isinstance(result, CFalse) else COr(result, c)
    return result


def conjunction(*args: Constraint) -> Constraint:
    return _conjunction(args)


def disjunction(*args: Constraint) -> Constraint:
    return _disjunction(args)


def collect_conjuncts(c: Constraint) -> List[Constraint]:
    """Flatten nested conjunctions into a list."""
    if isinstance(c, CAnd):
        return collect_conjuncts(c.lhs) + collect_conjuncts(c.rhs)
    if isinstance(c, CTrue):
        return []
    return [c]


def collect_disjuncts(c: Constraint) -> List[Constraint]:
    """Flatten nested disjunctions into a list."""
    if isinstance(c, COr):
        return collect_disjuncts(c.lhs) + collect_disjuncts(c.rhs)
    if isinstance(c, CFalse):
        return []
    return [c]


def constraint_size(c: Constraint) -> int:
    """Count the number of AST nodes in a constraint."""
    if isinstance(c, (CTrue, CFalse, CVar, CConst)):
        return 1
    if isinstance(c, (CAnd, COr, CImplies, CRelation)):
        return 1 + constraint_size(c.lhs) + constraint_size(c.rhs)  # type: ignore
    if isinstance(c, CArith):
        return 1 + constraint_size(c.lhs) + constraint_size(c.rhs)
    if isinstance(c, (CNot, CUnaryOp)):
        inner = c.inner if isinstance(c, CNot) else c.operand
        return 1 + constraint_size(inner)
    if isinstance(c, (CForall, CExists)):
        return 1 + constraint_size(c.body)
    if isinstance(c, CInRange):
        return 3
    if isinstance(c, CInSet):
        return 1 + len(c.values)
    if isinstance(c, CDomainPredicate):
        return 1
    return 1


# ===================================================================
#  PART 2 — SMT CONTEXT (backend-agnostic translation layer)
# ===================================================================

class SMTContext(ABC):
    """Abstract interface for translating Constraints to an SMT solver backend."""

    @abstractmethod
    def mk_bool(self, value: bool) -> Any: ...
    @abstractmethod
    def mk_var(self, name: str, ctype: CType) -> Any: ...
    @abstractmethod
    def mk_const(self, value: Union[int, float, bool], ctype: CType) -> Any: ...
    @abstractmethod
    def mk_rel(self, op: RelOp, lhs: Any, rhs: Any) -> Any: ...
    @abstractmethod
    def mk_arith(self, op: ArithOp, lhs: Any, rhs: Any, ctype: CType) -> Any: ...
    @abstractmethod
    def mk_unary(self, op: str, inner: Any, ctype: CType) -> Any: ...
    @abstractmethod
    def mk_and(self, a: Any, b: Any) -> Any: ...
    @abstractmethod
    def mk_or(self, a: Any, b: Any) -> Any: ...
    @abstractmethod
    def mk_not(self, a: Any) -> Any: ...
    @abstractmethod
    def mk_implies(self, a: Any, b: Any) -> Any: ...
    @abstractmethod
    def mk_or_many(self, terms: List[Any]) -> Any: ...

    def mk_forall(self, var: str, ctype: CType, body: Any) -> Any:
        """Default: drop quantifier (treat as assertion)."""
        return body

    def mk_exists(self, var: str, ctype: CType, body: Any) -> Any:
        """Default: drop quantifier."""
        return body

    def mk_domain_pred(self, var: str, domain_name: str, abstract_value: Any) -> Any:
        """Default: try to convert domain value to range constraint."""
        return self.mk_bool(True)


class Z3SMTContext(SMTContext):
    """SMTContext implementation backed by Z3 (optional)."""

    def __init__(self):
        try:
            import z3
            self._z3 = z3
        except ImportError:
            raise ImportError("Z3 Python bindings ('z3-solver') required for Z3SMTContext")
        self._vars: Dict[str, Any] = {}

    def _get_sort(self, ctype: CType):
        z3 = self._z3
        if ctype.is_integer or ctype == CType.POINTER:
            return z3.BitVecSort(ctype.bit_width)
        if ctype.is_floating:
            if ctype == CType.FLOAT:
                return z3.Float32()
            return z3.Float64()
        return z3.BitVecSort(64)

    def mk_bool(self, value: bool):
        return self._z3.BoolVal(value)

    def mk_var(self, name: str, ctype: CType):
        if name not in self._vars:
            z3 = self._z3
            if ctype.is_integer or ctype == CType.POINTER:
                self._vars[name] = z3.BitVec(name, ctype.bit_width)
            elif ctype.is_floating:
                sort = z3.Float32() if ctype == CType.FLOAT else z3.Float64()
                self._vars[name] = z3.Const(name, sort)
            else:
                self._vars[name] = z3.BitVec(name, 64)
        return self._vars[name]

    def mk_const(self, value, ctype: CType):
        z3 = self._z3
        if isinstance(value, bool):
            return z3.BoolVal(value)
        if ctype.is_integer or ctype == CType.POINTER:
            return z3.BitVecVal(int(value), ctype.bit_width)
        if ctype.is_floating:
            sort = z3.Float32() if ctype == CType.FLOAT else z3.Float64()
            return z3.FPVal(float(value), sort)
        return z3.BitVecVal(int(value), 64)

    def mk_rel(self, op: RelOp, lhs, rhs):
        z3 = self._z3
        if op == RelOp.EQ: return lhs == rhs
        if op == RelOp.NE: return lhs != rhs
        # For bit-vectors, use signed comparison by default
        if z3.is_bv(lhs):
            if op == RelOp.LT: return lhs < rhs
            if op == RelOp.LE: return lhs <= rhs
            if op == RelOp.GT: return lhs > rhs
            if op == RelOp.GE: return lhs >= rhs
        if op == RelOp.LT: return lhs < rhs
        if op == RelOp.LE: return lhs <= rhs
        if op == RelOp.GT: return lhs > rhs
        if op == RelOp.GE: return lhs >= rhs
        return lhs == rhs

    def mk_arith(self, op: ArithOp, lhs, rhs, ctype: CType):
        z3 = self._z3
        _ops = {
            ArithOp.ADD: lambda a, b: a + b,
            ArithOp.SUB: lambda a, b: a - b,
            ArithOp.MUL: lambda a, b: a * b,
            ArithOp.DIV: lambda a, b: a / b,
            ArithOp.MOD: lambda a, b: a % b if z3.is_bv(a) else a % b,
            ArithOp.BAND: lambda a, b: a & b,
            ArithOp.BOR: lambda a, b: a | b,
            ArithOp.BXOR: lambda a, b: a ^ b,
            ArithOp.SHL: lambda a, b: a << b,
            ArithOp.SHR: lambda a, b: z3.LShR(a, b) if z3.is_bv(a) else a >> b,
        }
        fn = _ops.get(op, lambda a, b: a + b)
        return fn(lhs, rhs)

    def mk_unary(self, op: str, inner, ctype: CType):
        if op == "-":
            return -inner
        if op == "~":
            return ~inner
        if op == "!":
            z3 = self._z3
            if z3.is_bool(inner):
                return z3.Not(inner)
            return inner == self.mk_const(0, ctype)
        return inner

    def mk_and(self, a, b):
        return self._z3.And(a, b)

    def mk_or(self, a, b):
        return self._z3.Or(a, b)

    def mk_not(self, a):
        return self._z3.Not(a)

    def mk_implies(self, a, b):
        return self._z3.Implies(a, b)

    def mk_or_many(self, terms):
        if not terms:
            return self._z3.BoolVal(False)
        return self._z3.Or(*terms)

    def mk_forall(self, var, ctype, body):
        v = self.mk_var(var, ctype)
        return self._z3.ForAll([v], body)

    def mk_exists(self, var, ctype, body):
        v = self.mk_var(var, ctype)
        return self._z3.Exists([v], body)

    def mk_domain_pred(self, var, domain_name, abstract_value):
        """Attempt to concretize abstract domain values into Z3 constraints."""
        v_term = self.mk_var(var, CType.INT)
        # IntervalDomain concretization
        if hasattr(abstract_value, "lo") and hasattr(abstract_value, "hi"):
            lo = abstract_value.lo
            hi = abstract_value.hi
            parts = []
            if lo is not None and lo != float("-inf"):
                parts.append(v_term >= self.mk_const(int(lo), CType.INT))
            if hi is not None and hi != float("inf"):
                parts.append(v_term <= self.mk_const(int(hi), CType.INT))
            if parts:
                return self._z3.And(*parts) if len(parts) > 1 else parts[0]
        return self.mk_bool(True)


class InternalSMTContext(SMTContext):
    """Lightweight built-in SMT context that works with symbolic expression strings.

    Used as a fallback when Z3 is not available.  Does not perform real solving
    but can produce structured string representations and simple evaluations.
    """

    def mk_bool(self, value: bool) -> str:
        return "true" if value else "false"

    def mk_var(self, name: str, ctype: CType) -> str:
        return name

    def mk_const(self, value, ctype: CType) -> str:
        return str(value)

    def mk_rel(self, op: RelOp, lhs, rhs) -> str:
        return f"({lhs} {op.value} {rhs})"

    def mk_arith(self, op: ArithOp, lhs, rhs, ctype: CType) -> str:
        return f"({lhs} {op.value} {rhs})"

    def mk_unary(self, op: str, inner, ctype: CType) -> str:
        return f"({op}{inner})"

    def mk_and(self, a, b) -> str:
        return f"(and {a} {b})"

    def mk_or(self, a, b) -> str:
        return f"(or {a} {b})"

    def mk_not(self, a) -> str:
        return f"(not {a})"

    def mk_implies(self, a, b) -> str:
        return f"(=> {a} {b})"

    def mk_or_many(self, terms) -> str:
        if not terms:
            return "false"
        if len(terms) == 1:
            return terms[0]
        return f"(or {' '.join(terms)})"

    def mk_domain_pred(self, var, domain_name, abstract_value) -> str:
        return f"[{var}:{domain_name}]"


def get_smt_context(backend: str = "auto") -> SMTContext:
    """Factory for SMT contexts.

    Parameters
    ----------
    backend : str
        ``"z3"`` — require Z3.
        ``"internal"`` — use the built-in string-based context.
        ``"auto"`` — try Z3 first, fall back to internal.
    """
    if backend == "z3":
        return Z3SMTContext()
    if backend == "internal":
        return InternalSMTContext()
    try:
        return Z3SMTContext()
    except ImportError:
        logger.info("Z3 not available; using internal SMT context")
        return InternalSMTContext()


# ===================================================================
#  PART 3 — PROPERTY SPECIFICATION DSL
# ===================================================================

class PropertyKind(enum.Enum):
    """Classification of program properties."""
    SAFETY = "safety"                 # "bad thing never happens"
    REACHABILITY = "reachability"     # "good state is reachable"
    ASSERTION = "assertion"           # user-written assert()
    PRECONDITION = "precondition"     # function entry requirement
    POSTCONDITION = "postcondition"   # function exit guarantee
    INVARIANT = "invariant"           # loop / class invariant
    ABSENCE_OF_UB = "no_ub"          # absence of undefined behaviour


class CheckResult(enum.Enum):
    """Outcome of a property check."""
    VERIFIED = "verified"       # proven to hold
    VIOLATED = "violated"       # proven to be violated (witness found)
    UNKNOWN = "unknown"         # analysis was inconclusive
    TIMEOUT = "timeout"         # solver/analysis timed out
    ERROR = "error"             # internal error during checking


@dataclass
class Witness:
    """A concrete witness (counterexample or reachability witness)."""
    variable_assignments: Dict[str, Union[int, float, str]]
    path: List[str] = field(default_factory=list)        # sequence of locations
    path_condition: Optional[Constraint] = None
    description: str = ""

    def pretty(self) -> str:
        lines = [self.description] if self.description else []
        for var, val in sorted(self.variable_assignments.items()):
            lines.append(f"  {var} = {val}")
        if self.path:
            lines.append(f"  path: {' → '.join(self.path)}")
        return "\n".join(lines)


@dataclass
class PropertyCheckResult:
    """Full result of checking a single property."""
    property_: "Property"
    result: CheckResult
    message: str = ""
    witness: Optional[Witness] = None
    abstract_evidence: Optional[Constraint] = None   # invariant from AI
    time_seconds: float = 0.0
    method: str = ""       # "abstract_interpretation", "symbolic_execution", "cegar"

    def pretty(self) -> str:
        status = self.result.value.upper()
        msg = f"[{status}] {self.property_.pretty()}"
        if self.message:
            msg += f" — {self.message}"
        if self.witness:
            msg += f"\n  Witness:\n{self.witness.pretty()}"
        return msg


@dataclass
class Property:
    """A program property to check.

    Specifies *what* to check, *where*, and *how*.
    """
    name: str
    kind: PropertyKind
    constraint: Constraint
    location: Optional[str] = None        # CFG node id / label
    function_name: Optional[str] = None
    scope: str = "local"                  # "local" | "global"
    tags: Set[str] = field(default_factory=set)

    def pretty(self) -> str:
        where = ""
        if self.function_name:
            where += f" in {self.function_name}"
        if self.location:
            where += f" at {self.location}"
        return f"{self.kind.value}({self.name}){where}: {self.constraint.pretty()}"


# -------------------------------------------------------------------
# 3.1  Property builder helpers (DSL)
# -------------------------------------------------------------------

def assert_no_division_by_zero(var: str, function_name: Optional[str] = None) -> Property:
    """Property: *var* is never used as a zero divisor."""
    return Property(
        name=f"div_by_zero_{var}",
        kind=PropertyKind.ABSENCE_OF_UB,
        constraint=CRelation(RelOp.NE, CVar(var), CConst(0)),
        function_name=function_name,
        tags={"ub", "division"},
    )


def assert_in_range(var: str, lo: int, hi: int,
                    function_name: Optional[str] = None) -> Property:
    """Property: *var* stays within [lo, hi]."""
    return Property(
        name=f"range_{var}_{lo}_{hi}",
        kind=PropertyKind.SAFETY,
        constraint=CInRange(var, lo, hi),
        function_name=function_name,
        tags={"range"},
    )


def assert_not_null(ptr_var: str,
                    function_name: Optional[str] = None) -> Property:
    """Property: pointer *ptr_var* is never null."""
    return Property(
        name=f"not_null_{ptr_var}",
        kind=PropertyKind.SAFETY,
        constraint=CRelation(RelOp.NE, CVar(ptr_var, CType.POINTER), CConst(0)),
        function_name=function_name,
        tags={"null", "pointer"},
    )


def assert_no_overflow(var: str, bits: int = 32, signed: bool = True,
                       function_name: Optional[str] = None) -> Property:
    """Property: *var* does not overflow a given width."""
    if signed:
        lo = -(1 << (bits - 1))
        hi = (1 << (bits - 1)) - 1
    else:
        lo = 0
        hi = (1 << bits) - 1
    return Property(
        name=f"overflow_{var}_{bits}{'s' if signed else 'u'}",
        kind=PropertyKind.ABSENCE_OF_UB,
        constraint=CInRange(var, lo, hi),
        function_name=function_name,
        tags={"overflow"},
    )


def assert_array_bounds(index_var: str, size: int,
                        function_name: Optional[str] = None) -> Property:
    """Property: array index stays in [0, size)."""
    return Property(
        name=f"array_bounds_{index_var}_{size}",
        kind=PropertyKind.SAFETY,
        constraint=CAnd(
            CRelation(RelOp.GE, CVar(index_var), CConst(0)),
            CRelation(RelOp.LT, CVar(index_var), CConst(size)),
        ),
        function_name=function_name,
        tags={"bounds"},
    )


def invariant(name: str, constraint: Constraint,
              function_name: Optional[str] = None,
              location: Optional[str] = None) -> Property:
    """Declare a loop / program-point invariant."""
    return Property(
        name=name,
        kind=PropertyKind.INVARIANT,
        constraint=constraint,
        function_name=function_name,
        location=location,
        tags={"invariant"},
    )


def precondition(name: str, constraint: Constraint,
                 function_name: str) -> Property:
    """Declare a function precondition."""
    return Property(
        name=name,
        kind=PropertyKind.PRECONDITION,
        constraint=constraint,
        function_name=function_name,
        tags={"contract"},
    )


def postcondition(name: str, constraint: Constraint,
                  function_name: str) -> Property:
    """Declare a function postcondition."""
    return Property(
        name=name,
        kind=PropertyKind.POSTCONDITION,
        constraint=constraint,
        function_name=function_name,
        tags={"contract"},
    )


# ===================================================================
#  PART 4 — CONSTRAINT GENERATORS
# ===================================================================

class ConstraintGenerator(ABC):
    """Base class for modules that extract constraints from analysis results."""

    @abstractmethod
    def generate(self, target: Property) -> List[Constraint]:
        """Generate constraints relevant to *target* property."""
        ...


# -------------------------------------------------------------------
# 4.1  Constraint generation from abstract interpretation
# -------------------------------------------------------------------

class AbstractInterpretationConstraintGenerator(ConstraintGenerator):
    """Extracts constraints from abstract interpretation invariants.

    Given a fixpoint map  ``var → abstract_value``  at each program point,
    this generator converts each abstract value into a ``Constraint`` via the
    abstract domain's concretization function.
    """

    def __init__(self,
                 invariants: Dict[str, Dict[str, Any]],
                 domain: Optional[Any] = None):
        """
        Parameters
        ----------
        invariants : dict
            Mapping  ``location_id → {var_name → abstract_value}``.
        domain : AbstractDomain, optional
            The domain used during analysis (for concretization).
        """
        self._invariants = invariants
        self._domain = domain

    def generate(self, target: Property) -> List[Constraint]:
        constraints: List[Constraint] = []
        relevant_vars = target.constraint.free_vars()

        for loc_id, var_map in self._invariants.items():
            # If the property is location-specific, filter
            if target.location and loc_id != target.location:
                continue
            for var_name, abs_val in var_map.items():
                if var_name not in relevant_vars:
                    continue
                c = self._abstract_value_to_constraint(var_name, abs_val)
                if c is not None and not isinstance(c, CTrue):
                    constraints.append(c)
        return constraints

    def _abstract_value_to_constraint(self, var: str, abs_val: Any) -> Optional[Constraint]:
        """Convert an abstract value to a constraint.

        Handles interval, sign, congruence, bitfield domains and their products.
        """
        # Interval: has .lo and .hi
        if hasattr(abs_val, "lo") and hasattr(abs_val, "hi"):
            lo = abs_val.lo
            hi = abs_val.hi
            if lo is not None and hi is not None:
                if lo == float("-inf") and hi == float("inf"):
                    return CTrue()
                if lo == float("-inf"):
                    return CRelation(RelOp.LE, CVar(var), CConst(hi))
                if hi == float("inf"):
                    return CRelation(RelOp.GE, CVar(var), CConst(lo))
                return CInRange(var, lo, hi)

        # Sign domain: has .sign or is a string in {+, -, 0, ⊤, ⊥}
        sign_val = getattr(abs_val, "sign", None) or (abs_val if isinstance(abs_val, str) else None)
        if sign_val in ("+", "positive"):
            return CRelation(RelOp.GT, CVar(var), CConst(0))
        if sign_val in ("-", "negative"):
            return CRelation(RelOp.LT, CVar(var), CConst(0))
        if sign_val in ("0", "zero"):
            return CRelation(RelOp.EQ, CVar(var), CConst(0))
        if sign_val in (">=0", "non_negative"):
            return CRelation(RelOp.GE, CVar(var), CConst(0))
        if sign_val in ("<=0", "non_positive"):
            return CRelation(RelOp.LE, CVar(var), CConst(0))

        # Congruence domain: has .modulus and .remainder
        mod = getattr(abs_val, "modulus", None)
        rem = getattr(abs_val, "remainder", None)
        if mod is not None and rem is not None and mod > 0:
            # x ≡ rem (mod modulus) → encoded as  x mod m == r
            return CRelation(
                RelOp.EQ,
                CArith(ArithOp.MOD, CVar(var), CConst(mod)),
                CConst(rem),
            )

        # Product domain: has .components (list of abstract values)
        components = getattr(abs_val, "components", None)
        if components and isinstance(components, (list, tuple)):
            sub_constraints = []
            for comp in components:
                sc = self._abstract_value_to_constraint(var, comp)
                if sc is not None and not isinstance(sc, CTrue):
                    sub_constraints.append(sc)
            return _conjunction(sub_constraints) if sub_constraints else CTrue()

        # Fallback: opaque domain predicate
        if abs_val is not None:
            domain_name = type(abs_val).__name__ if self._domain is None else type(self._domain).__name__
            return CDomainPredicate(var, domain_name, abs_val)

        return CTrue()

    def invariant_at(self, location: str) -> Constraint:
        """Build the full invariant constraint at a given location."""
        var_map = self._invariants.get(location, {})
        parts = []
        for var_name, abs_val in var_map.items():
            c = self._abstract_value_to_constraint(var_name, abs_val)
            if c is not None and not isinstance(c, CTrue):
                parts.append(c)
        return _conjunction(parts)


# -------------------------------------------------------------------
# 4.2  Constraint generation from symbolic execution
# -------------------------------------------------------------------

class SymbolicExecutionConstraintGenerator(ConstraintGenerator):
    """Extracts path conditions from symbolic execution results.

    Converts symbolic expressions (``SymExpr`` from ``symbolic_exec``) into
    the unified ``Constraint`` language.
    """

    def __init__(self, execution_results: List[Any]):
        """
        Parameters
        ----------
        execution_results : list
            List of ``SymState`` or ``ExecutionResult`` objects from the
            symbolic execution engine.
        """
        self._results = execution_results

    def generate(self, target: Property) -> List[Constraint]:
        constraints: List[Constraint] = []
        for result in self._results:
            pc = self._extract_path_condition(result)
            if pc is not None and not isinstance(pc, CTrue):
                constraints.append(pc)
        return constraints

    def _extract_path_condition(self, result: Any) -> Optional[Constraint]:
        """Convert a symbolic execution result's path condition to a Constraint."""
        # SymState has .path_condition (a PathCondition object or list)
        pc = getattr(result, "path_condition", None)
        if pc is None:
            pc = getattr(result, "constraints", None)
        if pc is None:
            return None

        # If it's a PathCondition object with .constraints list
        constraint_list = getattr(pc, "constraints", None)
        if constraint_list is None:
            if isinstance(pc, list):
                constraint_list = pc
            else:
                return self._symexpr_to_constraint(pc)

        parts = []
        for sym_constraint in constraint_list:
            c = self._symexpr_to_constraint(sym_constraint)
            if c is not None:
                parts.append(c)
        return _conjunction(parts)

    def _symexpr_to_constraint(self, expr: Any) -> Optional[Constraint]:
        """Recursively convert a SymExpr AST node to a Constraint AST node."""
        if expr is None:
            return None

        cls_name = type(expr).__name__

        # SymConst
        if cls_name == "SymConst" or hasattr(expr, "value") and not hasattr(expr, "left"):
            val = getattr(expr, "value", expr)
            if isinstance(val, (int, float, bool)):
                return CConst(val)
            return None

        # SymVar
        if cls_name == "SymVar" or (hasattr(expr, "name") and not hasattr(expr, "op")):
            name = getattr(expr, "name", str(expr))
            return CVar(name)

        # SymBinOp
        if cls_name == "SymBinOp" or (hasattr(expr, "op") and hasattr(expr, "left") and hasattr(expr, "right")):
            op_str = str(getattr(expr, "op", ""))
            left_c = self._symexpr_to_constraint(getattr(expr, "left", None))
            right_c = self._symexpr_to_constraint(getattr(expr, "right", None))
            if left_c is None or right_c is None:
                return None

            # Relational operators → CRelation
            _rel_map = {
                "==": RelOp.EQ, "!=": RelOp.NE,
                "<": RelOp.LT, "<=": RelOp.LE,
                ">": RelOp.GT, ">=": RelOp.GE,
            }
            if op_str in _rel_map:
                return CRelation(_rel_map[op_str], left_c, right_c)

            # Logical operators
            if op_str == "&&" or op_str == "and":
                return CAnd(left_c, right_c)
            if op_str == "||" or op_str == "or":
                return COr(left_c, right_c)

            # Arithmetic operators → CArith
            _arith_map = {
                "+": ArithOp.ADD, "-": ArithOp.SUB,
                "*": ArithOp.MUL, "/": ArithOp.DIV,
                "%": ArithOp.MOD, "&": ArithOp.BAND,
                "|": ArithOp.BOR, "^": ArithOp.BXOR,
                "<<": ArithOp.SHL, ">>": ArithOp.SHR,
            }
            if op_str in _arith_map:
                return CArith(_arith_map[op_str], left_c, right_c)

            return None

        # SymUnaryOp
        if cls_name == "SymUnaryOp" or (hasattr(expr, "op") and hasattr(expr, "operand")):
            op_str = str(getattr(expr, "op", ""))
            operand_c = self._symexpr_to_constraint(getattr(expr, "operand", None))
            if operand_c is None:
                return None
            if op_str == "!":
                return CNot(operand_c)
            return CUnaryOp(op_str, operand_c)

        # SymITE (if-then-else)
        if cls_name == "SymITE":
            cond = self._symexpr_to_constraint(getattr(expr, "condition", None))
            then_v = self._symexpr_to_constraint(getattr(expr, "then_val", None))
            else_v = self._symexpr_to_constraint(getattr(expr, "else_val", None))
            if cond and then_v and else_v:
                return COr(CAnd(cond, then_v), CAnd(CNot(cond), else_v))
            return cond

        # SymFunctionApp
        if cls_name == "SymFunctionApp":
            # Treat as opaque
            func_name = getattr(expr, "name", "unknown")
            return CDomainPredicate("_return", f"func_{func_name}", expr,
                                    description=f"call to {func_name}")

        return None

    def path_conditions(self) -> List[Constraint]:
        """Return all path conditions as a list of Constraints."""
        pcs: List[Constraint] = []
        for result in self._results:
            pc = self._extract_path_condition(result)
            if pc is not None:
                pcs.append(pc)
        return pcs


# -------------------------------------------------------------------
# 4.3  Constraint generation from Cppcheck ValueFlow
# -------------------------------------------------------------------

class ValueFlowConstraintGenerator(ConstraintGenerator):
    """Generates constraints from Cppcheck's ValueFlow annotations.

    Cppcheck attaches ``values`` (of type ``Value``) to tokens, providing
    bounds, known values, and conditional information computed by Cppcheck's
    own analysis.
    """

    def __init__(self, cfg_data):
        """
        Parameters
        ----------
        cfg_data : cppcheckdata.CfgData or similar
            The Cppcheck configuration with tokenlist and scopes.
        """
        self._cfg_data = cfg_data

    def generate(self, target: Property) -> List[Constraint]:
        constraints: List[Constraint] = []
        relevant_vars = target.constraint.free_vars()
        token_list = getattr(self._cfg_data, "tokenlist", [])

        for token in token_list:
            var_name = getattr(token, "str", "")
            if var_name not in relevant_vars:
                continue

            values = getattr(token, "values", None)
            if not values:
                continue

            for val_obj in values:
                c = self._value_to_constraint(var_name, val_obj)
                if c is not None:
                    constraints.append(c)

        return constraints

    def _value_to_constraint(self, var: str, val_obj: Any) -> Optional[Constraint]:
        """Convert a Cppcheck Value object to a constraint."""
        # intvalue: known integer
        intval = getattr(val_obj, "intvalue", None)
        if intval is not None:
            cond = getattr(val_obj, "condition", None)
            if cond:
                # Conditional value: the value holds under some condition
                cond_str = getattr(cond, "str", "")
                return CImplies(
                    CDomainPredicate("_cond", "cppcheck", cond,
                                    description=f"condition: {cond_str}"),
                    CRelation(RelOp.EQ, CVar(var), CConst(intval))
                )
            return CRelation(RelOp.EQ, CVar(var), CConst(intval))

        # tokvalue: value is same as another token
        tokval = getattr(val_obj, "tokvalue", None)
        if tokval is not None:
            other_name = getattr(tokval, "str", None)
            if other_name:
                return CRelation(RelOp.EQ, CVar(var), CVar(other_name))

        # valueKind == "known" with intvalue already handled;
        # check for possible / impossible values
        possible = getattr(val_obj, "valueKind", "")
        if possible == "impossible" and intval is not None:
            return CRelation(RelOp.NE, CVar(var), CConst(intval))

        return None

    def all_constraints(self) -> List[Constraint]:
        """Extract all constraints from the ValueFlow data (not property-targeted)."""
        all_cs: List[Constraint] = []
        token_list = getattr(self._cfg_data, "tokenlist", [])
        for token in token_list:
            var_name = getattr(token, "str", "")
            if not var_name or not getattr(token, "variable", None):
                continue
            values = getattr(token, "values", None)
            if not values:
                continue
            for val_obj in values:
                c = self._value_to_constraint(var_name, val_obj)
                if c is not None:
                    all_cs.append(c)
        return all_cs


# ===================================================================
#  PART 5 — CONSTRAINT SOLVER INTERFACE
# ===================================================================

class SolverResult(enum.Enum):
    SAT = "sat"
    UNSAT = "unsat"
    UNKNOWN = "unknown"
    TIMEOUT = "timeout"


@dataclass
class SolverOutcome:
    """Result from a constraint solver invocation."""
    result: SolverResult
    model: Optional[Dict[str, Union[int, float, str]]] = None
    unsat_core: Optional[List[Constraint]] = None
    time_seconds: float = 0.0


class ConstraintSolver(ABC):
    """Abstract constraint solver interface."""

    @abstractmethod
    def check_sat(self, constraints: List[Constraint],
                  timeout_ms: int = 10000) -> SolverOutcome:
        """Check satisfiability of a conjunction of constraints."""
        ...

    @abstractmethod
    def check_valid(self, constraint: Constraint,
                    assumptions: List[Constraint],
                    timeout_ms: int = 10000) -> SolverOutcome:
        """Check if *constraint* is valid (holds for all values)
        under the given *assumptions*.

        Equivalent to checking UNSAT of ``assumptions ∧ ¬constraint``.
        """
        ...

    def check_implies(self, premises: List[Constraint],
                      conclusion: Constraint,
                      timeout_ms: int = 10000) -> SolverOutcome:
        """Check if ``premises ⇒ conclusion`` is valid."""
        return self.check_valid(conclusion, premises, timeout_ms)


class Z3ConstraintSolver(ConstraintSolver):
    """Constraint solver backed by Z3."""

    def __init__(self):
        try:
            import z3
            self._z3 = z3
        except ImportError:
            raise ImportError("Z3 required for Z3ConstraintSolver")
        self._ctx = Z3SMTContext()

    def check_sat(self, constraints, timeout_ms=10000):
        z3 = self._z3
        solver = z3.Solver()
        solver.set("timeout", timeout_ms)
        t0 = time.monotonic()
        for c in constraints:
            term = c.to_smt(self._ctx)
            solver.add(term)
        result = solver.check()
        elapsed = time.monotonic() - t0

        if result == z3.sat:
            model = solver.model()
            model_dict = {}
            for decl in model.decls():
                val = model[decl]
                name = decl.name()
                try:
                    model_dict[name] = val.as_long()
                except Exception:
                    model_dict[name] = str(val)
            return SolverOutcome(SolverResult.SAT, model=model_dict,
                                 time_seconds=elapsed)
        if result == z3.unsat:
            return SolverOutcome(SolverResult.UNSAT, time_seconds=elapsed)
        return SolverOutcome(SolverResult.UNKNOWN, time_seconds=elapsed)

    def check_valid(self, constraint, assumptions, timeout_ms=10000):
        z3 = self._z3
        solver = z3.Solver()
        solver.set("timeout", timeout_ms)
        t0 = time.monotonic()
        for a in assumptions:
            solver.add(a.to_smt(self._ctx))
        solver.add(z3.Not(constraint.to_smt(self._ctx)))
        result = solver.check()
        elapsed = time.monotonic() - t0

        if result == z3.unsat:
            # negation is unsat → original is valid
            return SolverOutcome(SolverResult.UNSAT, time_seconds=elapsed)
        if result == z3.sat:
            model = solver.model()
            model_dict = {}
            for decl in model.decls():
                val = model[decl]
                try:
                    model_dict[decl.name()] = val.as_long()
                except Exception:
                    model_dict[decl.name()] = str(val)
            return SolverOutcome(SolverResult.SAT, model=model_dict,
                                 time_seconds=elapsed)
        return SolverOutcome(SolverResult.UNKNOWN, time_seconds=elapsed)


class InternalConstraintSolver(ConstraintSolver):
    """Lightweight built-in solver using interval-based constraint propagation.

    Does not perform full SMT solving, but can handle simple range and
    relational constraints.  Useful as a quick filter before calling Z3.
    """

    def __init__(self):
        self._ctx = InternalSMTContext()

    def check_sat(self, constraints, timeout_ms=10000):
        t0 = time.monotonic()
        # Collect variable bounds from CInRange / CRelation constraints
        bounds: Dict[str, Tuple[float, float]] = {}  # var → (lo, hi)
        equalities: Dict[str, Set[int]] = {}
        disequalities: Dict[str, Set[int]] = {}

        for c in constraints:
            self._extract_bounds(c, bounds, equalities, disequalities)

        # Check for obvious contradictions
        for var in equalities:
            if var in disequalities:
                eqs = equalities[var]
                dis = disequalities[var]
                if eqs and eqs.issubset(dis):
                    return SolverOutcome(SolverResult.UNSAT,
                                         time_seconds=time.monotonic() - t0)
            if var in bounds:
                lo, hi = bounds[var]
                eqs = equalities[var]
                if eqs:
                    if all(v < lo or v > hi for v in eqs):
                        return SolverOutcome(SolverResult.UNSAT,
                                             time_seconds=time.monotonic() - t0)

        for var, (lo, hi) in bounds.items():
            if lo > hi:
                return SolverOutcome(SolverResult.UNSAT,
                                     time_seconds=time.monotonic() - t0)

        # Attempt to construct a model
        model: Dict[str, Union[int, float, str]] = {}
        for var in bounds:
            lo, hi = bounds[var]
            if var in equalities and equalities[var]:
                # Pick an equality value within bounds
                for v in sorted(equalities[var]):
                    if lo <= v <= hi:
                        if var not in disequalities or v not in disequalities[var]:
                            model[var] = int(v)
                            break
                else:
                    return SolverOutcome(SolverResult.UNKNOWN,
                                         time_seconds=time.monotonic() - t0)
            else:
                # Pick middle of range, avoiding disequalities
                dis = disequalities.get(var, set())
                candidate = int((lo + hi) / 2)
                for offset in range(100):
                    for c in (candidate + offset, candidate - offset):
                        if lo <= c <= hi and c not in dis:
                            model[var] = c
                            break
                    if var in model:
                        break
                if var not in model:
                    model[var] = int(lo)

        elapsed = time.monotonic() - t0
        return SolverOutcome(SolverResult.SAT, model=model,
                             time_seconds=elapsed)

    def check_valid(self, constraint, assumptions, timeout_ms=10000):
        # Valid iff ¬constraint under assumptions is UNSAT
        neg = constraint.negate()
        all_constraints = list(assumptions) + [neg]
        outcome = self.check_sat(all_constraints, timeout_ms)
        elapsed = outcome.time_seconds
        if outcome.result == SolverResult.UNSAT:
            return SolverOutcome(SolverResult.UNSAT, time_seconds=elapsed)
        if outcome.result == SolverResult.SAT:
            return SolverOutcome(SolverResult.SAT, model=outcome.model,
                                 time_seconds=elapsed)
        return SolverOutcome(SolverResult.UNKNOWN, time_seconds=elapsed)

    def _extract_bounds(self, c: Constraint,
                        bounds: Dict[str, Tuple[float, float]],
                        equalities: Dict[str, Set[int]],
                        disequalities: Dict[str, Set[int]]) -> None:
        """Extract simple bounds from a constraint into the accumulators."""
        if isinstance(c, CInRange):
            lo = float(c.lo) if c.lo is not None else float("-inf")
            hi = float(c.hi) if c.hi is not None else float("inf")
            if c.var in bounds:
                old_lo, old_hi = bounds[c.var]
                bounds[c.var] = (max(old_lo, lo), min(old_hi, hi))
            else:
                bounds[c.var] = (lo, hi)

        elif isinstance(c, CRelation):
            var = None
            val = None
            if isinstance(c.lhs, CVar) and isinstance(c.rhs, CConst):
                var, val = c.lhs.name, c.rhs.value
            elif isinstance(c.rhs, CVar) and isinstance(c.lhs, CConst):
                var, val = c.rhs.name, c.lhs.value
                # Flip the operator
                c = CRelation(c.op.flip(), CVar(var), CConst(val))

            if var is not None and isinstance(val, (int, float)):
                fval = float(val)
                if var not in bounds:
                    bounds[var] = (float("-inf"), float("inf"))
                lo, hi = bounds[var]

                if c.op == RelOp.EQ:
                    equalities.setdefault(var, set()).add(int(val))
                    bounds[var] = (max(lo, fval), min(hi, fval))
                elif c.op == RelOp.NE:
                    disequalities.setdefault(var, set()).add(int(val))
                elif c.op == RelOp.LT:
                    bounds[var] = (lo, min(hi, fval - 1))
                elif c.op == RelOp.LE:
                    bounds[var] = (lo, min(hi, fval))
                elif c.op == RelOp.GT:
                    bounds[var] = (max(lo, fval + 1), hi)
                elif c.op == RelOp.GE:
                    bounds[var] = (max(lo, fval), hi)

        elif isinstance(c, CAnd):
            self._extract_bounds(c.lhs, bounds, equalities, disequalities)
            self._extract_bounds(c.rhs, bounds, equalities, disequalities)

        elif isinstance(c, CInSet):
            if c.values:
                lo = min(c.values)
                hi = max(c.values)
                if c.var not in bounds:
                    bounds[c.var] = (float(lo), float(hi))
                else:
                    old_lo, old_hi = bounds[c.var]
                    bounds[c.var] = (max(old_lo, float(lo)),
                                     min(old_hi, float(hi)))
                equalities.setdefault(c.var, set()).update(int(v) for v in c.values)


def get_constraint_solver(backend: str = "auto") -> ConstraintSolver:
    """Factory for constraint solvers."""
    if backend == "z3":
        return Z3ConstraintSolver()
    if backend == "internal":
        return InternalConstraintSolver()
    try:
        return Z3ConstraintSolver()
    except ImportError:
        logger.info("Z3 not available; using internal constraint solver")
        return InternalConstraintSolver()


# ===================================================================
#  PART 6 — CONSTRAINT-BASED DOMAIN REDUCTION
# ===================================================================

class DomainReducer:
    """Cross-domain constraint propagation.

    Implements reduced-product style refinement: given constraints from
    multiple abstract domains, propagate information between them to
    tighten each domain's abstraction.

    This is the constraint-solving counterpart of abstract domain reduction
    described in the literature: "constraint solving can soundly rule out
    infeasible configurations and possibly detect unsatisfiability."
    """

    def __init__(self, solver: Optional[ConstraintSolver] = None):
        self._solver = solver or get_constraint_solver("auto")

    def reduce(self,
               invariant_constraints: List[Constraint],
               symbolic_constraints: List[Constraint],
               variables: Set[str]) -> Dict[str, Constraint]:
        """Reduce (tighten) constraints by cross-propagation.

        Parameters
        ----------
        invariant_constraints : list
            Constraints from abstract interpretation.
        symbolic_constraints : list
            Constraints from symbolic execution path conditions.
        variables : set
            Set of variable names to compute refined constraints for.

        Returns
        -------
        dict
            Mapping ``var_name → refined_constraint`` for each variable.
        """
        all_constraints = invariant_constraints + symbolic_constraints
        refined: Dict[str, Constraint] = {}

        for var in variables:
            # Collect all constraints mentioning this variable
            relevant = [c for c in all_constraints if var in c.free_vars()]
            if not relevant:
                refined[var] = CTrue()
                continue

            # Try to compute tighter bounds via solver
            tightened = self._tighten_bounds(var, relevant)
            refined[var] = tightened

        return refined

    def _tighten_bounds(self, var: str, constraints: List[Constraint]) -> Constraint:
        """Use the solver to compute tight bounds for a single variable."""
        # First, extract any existing bounds
        bounds_lo = float("-inf")
        bounds_hi = float("inf")

        for c in constraints:
            if isinstance(c, CInRange) and c.var == var:
                bounds_lo = max(bounds_lo, float(c.lo))
                bounds_hi = min(bounds_hi, float(c.hi))
            elif isinstance(c, CRelation):
                self._update_bounds_from_relation(c, var, bounds_lo, bounds_hi)

        # Binary search for tighter lower bound
        if bounds_lo != float("-inf") and bounds_hi != float("inf"):
            lo = int(bounds_lo)
            hi = int(bounds_hi)

            # Check if the constraint set is feasible
            all_plus_range = constraints + [CInRange(var, lo, hi)]
            feasibility = self._solver.check_sat(all_plus_range, timeout_ms=2000)
            if feasibility.result == SolverResult.UNSAT:
                return CFalse()

            # Try to tighten lower bound
            new_lo = self._binary_search_bound(var, constraints, lo, hi, "lower")
            # Try to tighten upper bound
            new_hi = self._binary_search_bound(var, constraints, lo, hi, "upper")

            if new_lo is not None:
                lo = new_lo
            if new_hi is not None:
                hi = new_hi

            return CInRange(var, lo, hi)

        return _conjunction(constraints)

    def _binary_search_bound(self, var: str, constraints: List[Constraint],
                             lo: int, hi: int, direction: str,
                             max_steps: int = 10) -> Optional[int]:
        """Binary search for tighter bound."""
        if hi - lo <= 1:
            return None

        best = lo if direction == "lower" else hi

        for _ in range(max_steps):
            if lo >= hi:
                break
            mid = (lo + hi) // 2

            if direction == "lower":
                # Can var be < mid?
                test = constraints + [CRelation(RelOp.LT, CVar(var), CConst(mid))]
                outcome = self._solver.check_sat(test, timeout_ms=1000)
                if outcome.result == SolverResult.UNSAT:
                    # var cannot be < mid, so lower bound is at least mid
                    lo = mid
                    best = mid
                elif outcome.result == SolverResult.SAT:
                    hi = mid
                else:
                    break
            else:
                # Can var be > mid?
                test = constraints + [CRelation(RelOp.GT, CVar(var), CConst(mid))]
                outcome = self._solver.check_sat(test, timeout_ms=1000)
                if outcome.result == SolverResult.UNSAT:
                    hi = mid
                    best = mid
                elif outcome.result == SolverResult.SAT:
                    lo = mid
                else:
                    break

        return best if best != (lo if direction == "lower" else hi) else None

    @staticmethod
    def _update_bounds_from_relation(c: CRelation, var: str,
                                     lo: float, hi: float) -> Tuple[float, float]:
        """Update bounds based on a relational constraint."""
        if isinstance(c.lhs, CVar) and c.lhs.name == var and isinstance(c.rhs, CConst):
            v = float(c.rhs.value)
            if c.op == RelOp.LE: hi = min(hi, v)
            elif c.op == RelOp.LT: hi = min(hi, v - 1)
            elif c.op == RelOp.GE: lo = max(lo, v)
            elif c.op == RelOp.GT: lo = max(lo, v + 1)
            elif c.op == RelOp.EQ: lo, hi = v, v
        return lo, hi


# ===================================================================
#  PART 7 — PROPERTY CHECKER (orchestration)
# ===================================================================

class PropertyChecker:
    """Orchestrator that checks a ``Property`` using available analysis.

    Strategy (sequential, configurable):
    1. **Quick Filter** — use the internal solver on Cppcheck ValueFlow constraints.
    2. **Abstract Interpretation** — check if the AI invariant implies the property.
    3. **Symbolic Execution** — check if any path can violate the property.
    4. **CEGAR** — if inconclusive, refine using counterexample-guided loop.
    """

    def __init__(
        self,
        solver: Optional[ConstraintSolver] = None,
        ai_generator: Optional[AbstractInterpretationConstraintGenerator] = None,
        se_generator: Optional[SymbolicExecutionConstraintGenerator] = None,
        vf_generator: Optional[ValueFlowConstraintGenerator] = None,
        timeout_ms: int = 30000,
        enable_cegar: bool = True,
        max_cegar_iterations: int = 5,
    ):
        self._solver = solver or get_constraint_solver("auto")
        self._ai_gen = ai_generator
        self._se_gen = se_generator
        self._vf_gen = vf_generator
        self._timeout_ms = timeout_ms
        self._enable_cegar = enable_cegar
        self._max_cegar_iters = max_cegar_iterations
        self._reducer = DomainReducer(self._solver)

    def check(self, prop: Property) -> PropertyCheckResult:
        """Check a single property. Returns a ``PropertyCheckResult``."""
        t0 = time.monotonic()

        # Phase 1: Quick filter via ValueFlow
        if self._vf_gen is not None:
            result = self._check_via_valueflow(prop, t0)
            if result is not None:
                return result

        # Phase 2: Abstract interpretation
        if self._ai_gen is not None:
            result = self._check_via_abstract_interpretation(prop, t0)
            if result is not None:
                return result

        # Phase 3: Symbolic execution
        if self._se_gen is not None:
            result = self._check_via_symbolic_execution(prop, t0)
            if result is not None:
                return result

        # Phase 4: CEGAR
        if self._enable_cegar and self._ai_gen is not None and self._se_gen is not None:
            result = self._check_via_cegar(prop, t0)
            if result is not None:
                return result

        elapsed = time.monotonic() - t0
        return PropertyCheckResult(
            property_=prop,
            result=CheckResult.UNKNOWN,
            message="All analysis methods were inconclusive",
            time_seconds=elapsed,
            method="none",
        )

    def check_all(self, properties: List[Property]) -> List[PropertyCheckResult]:
        """Check a list of properties, returning results for each."""
        return [self.check(p) for p in properties]

    # ----- Phase implementations -----

    def _check_via_valueflow(self, prop: Property,
                             t0: float) -> Optional[PropertyCheckResult]:
        """Phase 1: use Cppcheck's ValueFlow as a quick pre-filter."""
        try:
            vf_constraints = self._vf_gen.generate(prop)  # type: ignore
            if not vf_constraints:
                return None

            # Check:  vf_constraints ⇒ prop.constraint
            outcome = self._solver.check_implies(
                vf_constraints, prop.constraint,
                timeout_ms=min(self._timeout_ms // 4, 5000),
            )

            elapsed = time.monotonic() - t0
            if outcome.result == SolverResult.UNSAT:
                return PropertyCheckResult(
                    property_=prop,
                    result=CheckResult.VERIFIED,
                    message="Proven by Cppcheck ValueFlow data",
                    time_seconds=elapsed,
                    method="valueflow",
                )
            if outcome.result == SolverResult.SAT and outcome.model:
                return PropertyCheckResult(
                    property_=prop,
                    result=CheckResult.VIOLATED,
                    message="Counterexample found via ValueFlow",
                    witness=Witness(
                        variable_assignments=outcome.model,
                        description="ValueFlow counterexample",
                    ),
                    time_seconds=elapsed,
                    method="valueflow",
                )
        except Exception as e:
            logger.debug("ValueFlow check failed: %s", e)
        return None

    def _check_via_abstract_interpretation(self, prop: Property,
                                           t0: float) -> Optional[PropertyCheckResult]:
        """Phase 2: check if AI invariant implies the property."""
        try:
            ai_constraints = self._ai_gen.generate(prop)  # type: ignore
            if not ai_constraints:
                return None

            # Implication check:  invariant ⇒ property
            outcome = self._solver.check_implies(
                ai_constraints, prop.constraint,
                timeout_ms=self._timeout_ms // 2,
            )

            elapsed = time.monotonic() - t0
            if outcome.result == SolverResult.UNSAT:
                return PropertyCheckResult(
                    property_=prop,
                    result=CheckResult.VERIFIED,
                    message="Proven by abstract interpretation invariant",
                    abstract_evidence=_conjunction(ai_constraints),
                    time_seconds=elapsed,
                    method="abstract_interpretation",
                )
            # AI alone cannot refute (it over-approximates), so a SAT result
            # is not necessarily a true violation. Return None to proceed.
        except Exception as e:
            logger.debug("AI check failed: %s", e)
        return None

    def _check_via_symbolic_execution(self, prop: Property,
                                      t0: float) -> Optional[PropertyCheckResult]:
        """Phase 3: check if symbolic execution finds a violating path."""
        try:
            se_constraints = self._se_gen.generate(prop)  # type: ignore
            if not se_constraints:
                return None

            # For each path condition, check if it can violate the property
            for i, pc in enumerate(se_constraints):
                # Can this path reach a state where the property is violated?
                violation_query = [pc, prop.constraint.negate()]
                outcome = self._solver.check_sat(
                    violation_query,
                    timeout_ms=self._timeout_ms // (len(se_constraints) + 1),
                )

                elapsed = time.monotonic() - t0
                if outcome.result == SolverResult.SAT and outcome.model:
                    return PropertyCheckResult(
                        property_=prop,
                        result=CheckResult.VIOLATED,
                        message=f"Violating path #{i} found by symbolic execution",
                        witness=Witness(
                            variable_assignments=outcome.model,
                            path_condition=pc,
                            description=f"Path condition: {pc.pretty()}",
                        ),
                        time_seconds=elapsed,
                        method="symbolic_execution",
                    )

            # No path violated the property — but SE under-approximates,
            # so we can't claim VERIFIED. Return None.
        except Exception as e:
            logger.debug("SE check failed: %s", e)
        return None

    def _check_via_cegar(self, prop: Property,
                         t0: float) -> Optional[PropertyCheckResult]:
        """Phase 4: CEGAR loop combining AI and SE.

        Algorithm:
        1. Abstract interpretation produces invariant I (over-approximation).
        2. If I ⇒ φ, the property is verified.
        3. Otherwise, extract a potential counterexample from I ∧ ¬φ.
        4. Use symbolic execution to check if the counterexample is feasible.
        5. If feasible: TRUE VIOLATION. If spurious: REFINE and go to 1.
        """
        ai_constraints = self._ai_gen.generate(prop)  # type: ignore
        se_constraints = self._se_gen.generate(prop)  # type: ignore

        variables = prop.constraint.free_vars()

        for iteration in range(self._max_cegar_iters):
            logger.info("CEGAR iteration %d for property %s",
                        iteration + 1, prop.name)

            # Step 1: Refine constraints via cross-domain propagation
            refined = self._reducer.reduce(
                ai_constraints, se_constraints, variables
            )
            refined_list = [c for c in refined.values()
                           if not isinstance(c, CTrue)]

            # Step 2: Check refined invariant ⇒ property
            if refined_list:
                outcome = self._solver.check_implies(
                    refined_list, prop.constraint,
                    timeout_ms=self._timeout_ms // (self._max_cegar_iters + 1),
                )

                elapsed = time.monotonic() - t0
                if outcome.result == SolverResult.UNSAT:
                    return PropertyCheckResult(
                        property_=prop,
                        result=CheckResult.VERIFIED,
                        message=f"Proven by CEGAR (iteration {iteration + 1})",
                        abstract_evidence=_conjunction(refined_list),
                        time_seconds=elapsed,
                        method="cegar",
                    )

                # Step 3: Extract potential counterexample
                if outcome.result == SolverResult.SAT and outcome.model:
                    # Step 4: Check feasibility against SE path conditions
                    counterexample_constraints = [
                        CRelation(RelOp.EQ, CVar(var), CConst(val))
                        for var, val in outcome.model.items()
                        if isinstance(val, (int, float))
                    ]

                    is_feasible = False
                    for pc in se_constraints:
                        feasibility = self._solver.check_sat(
                            [pc] + counterexample_constraints,
                            timeout_ms=2000,
                        )
                        if feasibility.result == SolverResult.SAT:
                            is_feasible = True
                            break

                    elapsed = time.monotonic() - t0
                    if is_feasible:
                        return PropertyCheckResult(
                            property_=prop,
                            result=CheckResult.VIOLATED,
                            message=f"CEGAR: feasible counterexample at iteration {iteration + 1}",
                            witness=Witness(
                                variable_assignments=outcome.model,
                                description="CEGAR counterexample",
                            ),
                            time_seconds=elapsed,
                            method="cegar",
                        )
                    else:
                        # Spurious — add the negation of the counterexample
                        # as a constraint to refine
                        exclusion = _conjunction(counterexample_constraints).negate()
                        ai_constraints.append(exclusion)
                        logger.info("CEGAR: spurious counterexample, refining")
                        continue

            # Timeout check
            if time.monotonic() - t0 > self._timeout_ms / 1000.0:
                return PropertyCheckResult(
                    property_=prop,
                    result=CheckResult.TIMEOUT,
                    message=f"CEGAR timed out after {iteration + 1} iterations",
                    time_seconds=time.monotonic() - t0,
                    method="cegar",
                )

        elapsed = time.monotonic() - t0
        return PropertyCheckResult(
            property_=prop,
            result=CheckResult.UNKNOWN,
            message=f"CEGAR inconclusive after {self._max_cegar_iters} iterations",
            time_seconds=elapsed,
            method="cegar",
        )


# ===================================================================
#  PART 8 — AUTOMATED PROPERTY DISCOVERY
# ===================================================================

class PropertyDiscoverer:
    """Automatically discovers properties worth checking from program structure.

    Scans the CFG and token list for patterns that suggest implicit
    safety requirements (division, pointer dereference, array access,
    integer overflow).
    """

    def __init__(self, cfg_data=None):
        self._cfg_data = cfg_data

    def discover(self) -> List[Property]:
        """Discover properties from program structure."""
        properties: List[Property] = []
        if self._cfg_data is None:
            return properties

        properties.extend(self._discover_division_safety())
        properties.extend(self._discover_null_pointer_safety())
        properties.extend(self._discover_array_bounds())
        properties.extend(self._discover_user_assertions())
        return properties

    def _discover_division_safety(self) -> List[Property]:
        """Find all division operations and generate div-by-zero checks."""
        props: List[Property] = []
        seen: Set[str] = set()
        token_list = getattr(self._cfg_data, "tokenlist", [])

        for token in token_list:
            tok_str = getattr(token, "str", "")
            if tok_str in ("/", "%"):
                # Divisor is the next significant token (AST child)
                ast_rhs = getattr(token, "astOperand2", None)
                if ast_rhs is None:
                    continue

                divisor_name = getattr(ast_rhs, "str", None)
                if divisor_name is None:
                    continue

                # Check if it's a variable (not a literal)
                var = getattr(ast_rhs, "variable", None)
                if var is None:
                    # Could be a literal — check if it's zero
                    try:
                        if int(divisor_name) == 0:
                            key = f"div_zero_literal_{getattr(token, 'Id', id(token))}"
                            if key not in seen:
                                seen.add(key)
                                props.append(Property(
                                    name=key,
                                    kind=PropertyKind.ABSENCE_OF_UB,
                                    constraint=CFalse(),  # always violated
                                    function_name=self._enclosing_function(token),
                                    tags={"ub", "division", "literal_zero"},
                                ))
                    except (ValueError, TypeError):
                        pass
                    continue

                key = f"div_zero_{divisor_name}_{getattr(token, 'linenr', '?')}"
                if key not in seen:
                    seen.add(key)
                    props.append(assert_no_division_by_zero(
                        divisor_name,
                        function_name=self._enclosing_function(token),
                    ))

        return props

    def _discover_null_pointer_safety(self) -> List[Property]:
        """Find pointer dereferences and generate null-check properties."""
        props: List[Property] = []
        seen: Set[str] = set()
        token_list = getattr(self._cfg_data, "tokenlist", [])

        for token in token_list:
            tok_str = getattr(token, "str", "")
            if tok_str == "*":
                # Unary dereference: check the operand
                operand = getattr(token, "astOperand1", None)
                if operand is None:
                    continue
                ptr_name = getattr(operand, "str", None)
                ptr_var = getattr(operand, "variable", None)
                if ptr_name and ptr_var:
                    vtype = getattr(operand, "valueType", None)
                    if vtype and getattr(vtype, "pointer", 0):
                        key = f"null_{ptr_name}_{getattr(token, 'linenr', '?')}"
                        if key not in seen:
                            seen.add(key)
                            props.append(assert_not_null(
                                ptr_name,
                                function_name=self._enclosing_function(token),
                            ))

            elif tok_str == "[":
                # Array subscript: check the base pointer
                base = getattr(token, "astOperand1", None)
                if base:
                    base_name = getattr(base, "str", None)
                    base_var = getattr(base, "variable", None)
                    if base_name and base_var:
                        vtype = getattr(base, "valueType", None)
                        if vtype and getattr(vtype, "pointer", 0):
                            key = f"null_arr_{base_name}_{getattr(token, 'linenr', '?')}"
                            if key not in seen:
                                seen.add(key)
                                props.append(assert_not_null(
                                    base_name,
                                    function_name=self._enclosing_function(token),
                                ))

        return props

    def _discover_array_bounds(self) -> List[Property]:
        """Find array accesses and generate bounds-check properties."""
        props: List[Property] = []
        seen: Set[str] = set()
        token_list = getattr(self._cfg_data, "tokenlist", [])

        for token in token_list:
            tok_str = getattr(token, "str", "")
            if tok_str == "[":
                index_tok = getattr(token, "astOperand2", None)
                base_tok = getattr(token, "astOperand1", None)
                if index_tok is None or base_tok is None:
                    continue

                index_name = getattr(index_tok, "str", None)
                if not index_name or not getattr(index_tok, "variable", None):
                    continue

                # Try to determine array size from the variable's type
                base_var = getattr(base_tok, "variable", None)
                if base_var:
                    # Cppcheck stores array dimensions
                    dimensions = getattr(base_var, "dimensions", None)
                    if dimensions:
                        for dim in dimensions:
                            size = getattr(dim, "size", None)
                            if size and isinstance(size, int) and size > 0:
                                key = f"bounds_{index_name}_{size}_{getattr(token, 'linenr', '?')}"
                                if key not in seen:
                                    seen.add(key)
                                    props.append(assert_array_bounds(
                                        index_name, size,
                                        function_name=self._enclosing_function(token),
                                    ))
                                break

        return props

    def _discover_user_assertions(self) -> List[Property]:
        """Find assert() calls and convert them to properties."""
        props: List[Property] = []
        token_list = getattr(self._cfg_data, "tokenlist", [])

        for token in token_list:
            tok_str = getattr(token, "str", "")
            if tok_str == "assert":
                # The assertion expression is typically the function's argument
                next_tok = getattr(token, "next", None)
                if next_tok and getattr(next_tok, "str", "") == "(":
                    ast_arg = getattr(next_tok, "astOperand1", None) or \
                              getattr(next_tok, "astOperand2", None)
                    if ast_arg:
                        # Try to convert the AST to a constraint
                        c = self._token_ast_to_constraint(ast_arg)
                        if c is not None:
                            props.append(Property(
                                name=f"assert_line_{getattr(token, 'linenr', '?')}",
                                kind=PropertyKind.ASSERTION,
                                constraint=c,
                                function_name=self._enclosing_function(token),
                                tags={"user_assert"},
                            ))
        return props

    def _token_ast_to_constraint(self, token) -> Optional[Constraint]:
        """Best-effort conversion of a Cppcheck AST token tree to a Constraint."""
        if token is None:
            return None

        tok_str = getattr(token, "str", "")
        op1 = getattr(token, "astOperand1", None)
        op2 = getattr(token, "astOperand2", None)

        # Leaf: variable or constant
        if op1 is None and op2 is None:
            if getattr(token, "variable", None):
                return CVar(tok_str, _infer_ctype(token))
            try:
                return CConst(int(tok_str))
            except ValueError:
                try:
                    return CConst(float(tok_str))
                except ValueError:
                    return CVar(tok_str)

        # Relational
        _rel_map = {
            "==": RelOp.EQ, "!=": RelOp.NE,
            "<": RelOp.LT, "<=": RelOp.LE,
            ">": RelOp.GT, ">=": RelOp.GE,
        }
        if tok_str in _rel_map and op1 and op2:
            lc = self._token_ast_to_constraint(op1)
            rc = self._token_ast_to_constraint(op2)
            if lc and rc:
                return CRelation(_rel_map[tok_str], lc, rc)

        # Logical
        if tok_str == "&&" and op1 and op2:
            lc = self._token_ast_to_constraint(op1)
            rc = self._token_ast_to_constraint(op2)
            if lc and rc:
                return CAnd(lc, rc)
        if tok_str == "||" and op1 and op2:
            lc = self._token_ast_to_constraint(op1)
            rc = self._token_ast_to_constraint(op2)
            if lc and rc:
                return COr(lc, rc)
        if tok_str == "!" and op1:
            inner = self._token_ast_to_constraint(op1)
            if inner:
                return CNot(inner)

        # Arithmetic
        _arith_map = {
            "+": ArithOp.ADD, "-": ArithOp.SUB,
            "*": ArithOp.MUL, "/": ArithOp.DIV,
            "%": ArithOp.MOD, "&": ArithOp.BAND,
            "|": ArithOp.BOR, "^": ArithOp.BXOR,
            "<<": ArithOp.SHL, ">>": ArithOp.SHR,
        }
        if tok_str in _arith_map and op1 and op2:
            lc = self._token_ast_to_constraint(op1)
            rc = self._token_ast_to_constraint(op2)
            if lc and rc:
                return CArith(_arith_map[tok_str], lc, rc,
                              _infer_ctype(token))

        return None

    def _enclosing_function(self, token) -> Optional[str]:
        """Find the function name enclosing a token."""
        scope = getattr(token, "scope", None)
        while scope:
            if getattr(scope, "type", "") == "Function":
                func = getattr(scope, "function", None)
                if func:
                    return getattr(func, "name", None)
                return getattr(scope, "className", None)
            scope = getattr(scope, "nestedIn", None)
        return None


# ===================================================================
#  PART 9 — END-TO-END ANALYSIS DRIVER
# ===================================================================

@dataclass
class AnalysisConfig:
    """Configuration for the end-to-end analysis pipeline."""
    # Solver
    solver_backend: str = "auto"            # "z3", "internal", "auto"
    solver_timeout_ms: int = 30000

    # Abstract interpretation
    use_abstract_interpretation: bool = True
    abstract_domain: str = "interval"       # "interval", "sign", "congruence", etc.
    widening_threshold: int = 5

    # Symbolic execution
    use_symbolic_execution: bool = True
    se_mode: str = "dse"                    # "dse", "sse", "concolic"
    max_paths: int = 100
    loop_bound: int = 10

    # CEGAR
    enable_cegar: bool = True
    max_cegar_iterations: int = 5

    # Property discovery
    auto_discover_properties: bool = True

    # Reporting
    verbose: bool = False


@dataclass
class AnalysisReport:
    """Summary report of a complete analysis run."""
    config: AnalysisConfig
    properties_checked: int = 0
    verified: int = 0
    violated: int = 0
    unknown: int = 0
    timeout: int = 0
    errors: int = 0
    total_time_seconds: float = 0.0
    results: List[PropertyCheckResult] = field(default_factory=list)
    discovered_properties: List[Property] = field(default_factory=list)

    def summary(self) -> str:
        lines = [
            "=" * 60,
            "  CONSTRAINT ENGINE ANALYSIS REPORT",
            "=" * 60,
            f"  Properties checked : {self.properties_checked}",
            f"  Verified           : {self.verified}",
            f"  Violated           : {self.violated}",
            f"  Unknown            : {self.unknown}",
            f"  Timeout            : {self.timeout}",
            f"  Errors             : {self.errors}",
            f"  Total time         : {self.total_time_seconds:.3f}s",
            "=" * 60,
        ]
        if self.results:
            lines.append("")
            lines.append("  DETAILED RESULTS:")
            lines.append("-" * 60)
            for r in self.results:
                lines.append(f"  {r.pretty()}")
            lines.append("-" * 60)
        return "\n".join(lines)


class ConstraintEngine:
    """End-to-end analysis driver.

    This is the main entry point for users of the constraint engine.
    It orchestrates:
    1. CFG construction
    2. Abstract interpretation (via ``abstract_interp``)
    3. Symbolic execution (via ``symbolic_exec``)
    4. Property discovery
    5. Property checking with CEGAR refinement

    Usage::

        engine = ConstraintEngine(config=AnalysisConfig())
        report = engine.analyze(cppcheck_cfg_data, properties=[...])
        print(report.summary())
    """

    def __init__(self, config: Optional[AnalysisConfig] = None):
        self._config = config or AnalysisConfig()
        self._solver: Optional[ConstraintSolver] = None
        self._smt_ctx: Optional[SMTContext] = None

    def analyze(
        self,
        cfg_data=None,
        properties: Optional[List[Property]] = None,
        extra_constraints: Optional[List[Constraint]] = None,
    ) -> AnalysisReport:
        """Run the full analysis pipeline.

        Parameters
        ----------
        cfg_data : cppcheckdata configuration, optional
            The Cppcheck dump data to analyze.
        properties : list of Property, optional
            User-specified properties to check.
        extra_constraints : list of Constraint, optional
            Additional constraints to assume (e.g., preconditions).

        Returns
        -------
        AnalysisReport
        """
        t0 = time.monotonic()
        report = AnalysisReport(config=self._config)
        all_properties = list(properties or [])

        # Initialize solver
        self._solver = get_constraint_solver(self._config.solver_backend)
        self._smt_ctx = get_smt_context(self._config.solver_backend)

        # Phase A: Auto-discover properties
        if self._config.auto_discover_properties and cfg_data is not None:
            discoverer = PropertyDiscoverer(cfg_data)
            discovered = discoverer.discover()
            report.discovered_properties = discovered
            all_properties.extend(discovered)
            if self._config.verbose:
                logger.info("Discovered %d properties", len(discovered))

        if not all_properties:
            report.total_time_seconds = time.monotonic() - t0
            return report

        # Phase B: Run abstract interpretation
        ai_generator = None
        if self._config.use_abstract_interpretation and cfg_data is not None:
            ai_generator = self._run_abstract_interpretation(cfg_data)

        # Phase C: Run symbolic execution
        se_generator = None
        if self._config.use_symbolic_execution and cfg_data is not None:
            se_generator = self._run_symbolic_execution(cfg_data)

        # Phase D: ValueFlow constraint generator
        vf_generator = None
        if cfg_data is not None:
            vf_generator = ValueFlowConstraintGenerator(cfg_data)

        # Phase E: Check all properties
        checker = PropertyChecker(
            solver=self._solver,
            ai_generator=ai_generator,
            se_generator=se_generator,
            vf_generator=vf_generator,
            timeout_ms=self._config.solver_timeout_ms,
            enable_cegar=self._config.enable_cegar,
            max_cegar_iterations=self._config.max_cegar_iterations,
        )

        for prop in all_properties:
            result = checker.check(prop)
            report.results.append(result)
            report.properties_checked += 1

            if result.result == CheckResult.VERIFIED:
                report.verified += 1
            elif result.result == CheckResult.VIOLATED:
                report.violated += 1
            elif result.result == CheckResult.UNKNOWN:
                report.unknown += 1
            elif result.result == CheckResult.TIMEOUT:
                report.timeout += 1
            elif result.result == CheckResult.ERROR:
                report.errors += 1

        report.total_time_seconds = time.monotonic() - t0
        return report

    def _run_abstract_interpretation(self, cfg_data) -> Optional[AbstractInterpretationConstraintGenerator]:
        """Run abstract interpretation and return a constraint generator."""
        try:
            # Build CFGs for all functions
            scopes = getattr(cfg_data, "scopes", [])
            all_invariants: Dict[str, Dict[str, Any]] = {}

            for scope in scopes:
                if getattr(scope, "type", "") != "Function":
                    continue

                func = getattr(scope, "function", None)
                if func is None:
                    continue

                func_name = getattr(func, "name", "unknown")

                try:
                    # Build CFG
                    the_cfg = cfg_mod.build_cfg(scope)
                    if the_cfg is None:
                        continue

                    # Create abstract interpreter
                    # Use a factory approach to avoid hard-coding domain constructors
                    interp = self._create_abstract_interpreter(the_cfg)
                    if interp is None:
                        continue

                    # Run fixpoint computation
                    result = interp.analyze()
                    if result and hasattr(result, "invariants"):
                        for loc_id, state in result.invariants.items():
                            key = f"{func_name}::{loc_id}"
                            if hasattr(state, "env"):
                                all_invariants[key] = dict(state.env)
                            elif isinstance(state, dict):
                                all_invariants[key] = state
                except Exception as e:
                    logger.debug("AI failed for function %s: %s", func_name, e)
                    continue

            if all_invariants:
                return AbstractInterpretationConstraintGenerator(all_invariants)

        except Exception as e:
            logger.debug("Abstract interpretation phase failed: %s", e)
        return None

    def _create_abstract_interpreter(self, the_cfg) -> Optional[Any]:
        """Create an abstract interpreter for the configured domain."""
        try:
            domain_name = self._config.abstract_domain
            # Attempt to instantiate from abstract_interp module
            if hasattr(ai_mod, "AbstractInterpreter"):
                # Try to find the domain class
                domain_map = {
                    "interval": "IntervalDomain",
                    "sign": "SignDomain",
                    "congruence": "CongruenceDomain",
                    "bitfield": "BitfieldDomain",
                    "wrapping_interval": "WrappingIntervalDomain",
                }
                domain_cls_name = domain_map.get(domain_name, "IntervalDomain")
                domain_cls = getattr(ai_mod, domain_cls_name, None)
                if domain_cls is not None:
                    domain = domain_cls()
                    return ai_mod.AbstractInterpreter(
                        cfg=the_cfg,
                        domain=domain,
                        widening_threshold=self._config.widening_threshold,
                    )
        except Exception as e:
            logger.debug("Failed to create abstract interpreter: %s", e)
        return None

    def _run_symbolic_execution(self, cfg_data) -> Optional[SymbolicExecutionConstraintGenerator]:
        """Run symbolic execution and return a constraint generator."""
        try:
            scopes = getattr(cfg_data, "scopes", [])
            all_results: List[Any] = []

            for scope in scopes:
                if getattr(scope, "type", "") != "Function":
                    continue

                try:
                    the_cfg = cfg_mod.build_cfg(scope)
                    if the_cfg is None:
                        continue

                    executor = self._create_symbolic_executor(the_cfg)
                    if executor is None:
                        continue

                    results = executor.execute()
                    if results:
                        if isinstance(results, list):
                            all_results.extend(results)
                        else:
                            all_results.append(results)

                except Exception as e:
                    logger.debug("SE failed for scope: %s", e)
                    continue

            if all_results:
                return SymbolicExecutionConstraintGenerator(all_results)

        except Exception as e:
            logger.debug("Symbolic execution phase failed: %s", e)
        return None

    def _create_symbolic_executor(self, the_cfg) -> Optional[Any]:
        """Create a symbolic executor for the configured mode."""
        try:
            mode = self._config.se_mode
            if mode == "dse" and hasattr(se_mod, "SymbolicExecutor"):
                return se_mod.SymbolicExecutor(
                    cfg=the_cfg,
                    max_paths=self._config.max_paths,
                    loop_bound=self._config.loop_bound,
                )
            if mode == "sse" and hasattr(se_mod, "StaticSymbolicExecutor"):
                return se_mod.StaticSymbolicExecutor(
                    cfg=the_cfg,
                    loop_bound=self._config.loop_bound,
                )
            if mode == "concolic" and hasattr(se_mod, "ConcolicExecutor"):
                return se_mod.ConcolicExecutor(
                    cfg=the_cfg,
                    max_paths=self._config.max_paths,
                    loop_bound=self._config.loop_bound,
                )
        except Exception as e:
            logger.debug("Failed to create symbolic executor: %s", e)
        return None

    # ----- Convenience methods -----

    def check_property(self, prop: Property, cfg_data=None) -> PropertyCheckResult:
        """Check a single property (without full pipeline)."""
        report = self.analyze(cfg_data, properties=[prop])
        if report.results:
            return report.results[0]
        return PropertyCheckResult(
            property_=prop,
            result=CheckResult.ERROR,
            message="No result produced",
        )

    def check_constraint(self, constraint: Constraint,
                         assumptions: Optional[List[Constraint]] = None) -> SolverOutcome:
        """Directly check a constraint against assumptions using the solver."""
        if self._solver is None:
            self._solver = get_constraint_solver(self._config.solver_backend)
        assumptions = assumptions or []
        return self._solver.check_implies(assumptions, constraint,
                                          self._config.solver_timeout_ms)

    def is_satisfiable(self, constraints: List[Constraint]) -> SolverOutcome:
        """Check if a set of constraints is satisfiable."""
        if self._solver is None:
            self._solver = get_constraint_solver(self._config.solver_backend)
        return self._solver.check_sat(constraints, self._config.solver_timeout_ms)


# ===================================================================
#  PART 10 — CONSTRAINT SIMPLIFIER
# ===================================================================

class ConstraintSimplifier:
    """Simplifies constraint ASTs via algebraic rewriting rules.

    Applied as a post-pass to make constraints more readable and
    to reduce the load on the SMT solver.
    """

    def simplify(self, c: Constraint) -> Constraint:
        """Apply all simplification rules bottom-up."""
        return self._simplify(c)

    def _simplify(self, c: Constraint) -> Constraint:
        # Bottom-up: simplify children first
        if isinstance(c, CAnd):
            l = self._simplify(c.lhs)
            r = self._simplify(c.rhs)
            # Identity & annihilation
            if isinstance(l, CTrue): return r
            if isinstance(r, CTrue): return l
            if isinstance(l, CFalse): return CFalse()
            if isinstance(r, CFalse): return CFalse()
            # Idempotence (structural equality)
            if l is r or (isinstance(l, CVar) and isinstance(r, CVar)
                          and l.name == r.name):
                return l
            # Complementation
            if isinstance(r, CNot) and _structurally_equal(r.inner, l):
                return CFalse()
            if isinstance(l, CNot) and _structurally_equal(l.inner, r):
                return CFalse()
            return CAnd(l, r)

        if isinstance(c, COr):
            l = self._simplify(c.lhs)
            r = self._simplify(c.rhs)
            if isinstance(l, CFalse): return r
            if isinstance(r, CFalse): return l
            if isinstance(l, CTrue): return CTrue()
            if isinstance(r, CTrue): return CTrue()
            if l is r or (isinstance(l, CVar) and isinstance(r, CVar)
                          and l.name == r.name):
                return l
            if isinstance(r, CNot) and _structurally_equal(r.inner, l):
                return CTrue()
            if isinstance(l, CNot) and _structurally_equal(l.inner, r):
                return CTrue()
            return COr(l, r)

        if isinstance(c, CNot):
            inner = self._simplify(c.inner)
            # Double negation
            if isinstance(inner, CNot):
                return inner.inner
            if isinstance(inner, CTrue): return CFalse()
            if isinstance(inner, CFalse): return CTrue()
            return CNot(inner)

        if isinstance(c, CImplies):
            a = self._simplify(c.antecedent)
            b = self._simplify(c.consequent)
            if isinstance(a, CFalse): return CTrue()
            if isinstance(a, CTrue): return b
            if isinstance(b, CTrue): return CTrue()
            return CImplies(a, b)

        if isinstance(c, CRelation):
            l = self._simplify(c.lhs)
            r = self._simplify(c.rhs)
            # Constant folding
            if isinstance(l, CConst) and isinstance(r, CConst):
                return CTrue() if self._eval_relop(c.op, l.value, r.value) else CFalse()
            return CRelation(c.op, l, r)

        if isinstance(c, CArith):
            l = self._simplify(c.lhs)
            r = self._simplify(c.rhs)
            if isinstance(l, CConst) and isinstance(r, CConst):
                result = self._eval_arith(c.op, l.value, r.value)
                if result is not None:
                    return CConst(result, c.ctype)
            # Algebraic identities
            if c.op == ArithOp.ADD:
                if isinstance(r, CConst) and r.value == 0: return l
                if isinstance(l, CConst) and l.value == 0: return r
            if c.op == ArithOp.SUB:
                if isinstance(r, CConst) and r.value == 0: return l
            if c.op == ArithOp.MUL:
                if isinstance(r, CConst) and r.value == 1: return l
                if isinstance(l, CConst) and l.value == 1: return r
                if isinstance(r, CConst) and r.value == 0: return CConst(0, c.ctype)
                if isinstance(l, CConst) and l.value == 0: return CConst(0, c.ctype)
            return CArith(c.op, l, r, c.ctype)

        if isinstance(c, CInRange):
            if c.lo == float("-inf") and c.hi == float("inf"):
                return CTrue()
            if c.lo > c.hi:
                return CFalse()
            return c

        return c

    @staticmethod
    def _eval_relop(op: RelOp, a, b) -> bool:
        if op == RelOp.EQ: return a == b
        if op == RelOp.NE: return a != b
        if op == RelOp.LT: return a < b
        if op == RelOp.LE: return a <= b
        if op == RelOp.GT: return a > b
        if op == RelOp.GE: return a >= b
        return False

    @staticmethod
    def _eval_arith(op: ArithOp, a, b) -> Optional[Union[int, float]]:
        try:
            if op == ArithOp.ADD: return a + b
            if op == ArithOp.SUB: return a - b
            if op == ArithOp.MUL: return a * b
            if op == ArithOp.DIV: return a // b if b != 0 else None
            if op == ArithOp.MOD: return a % b if b != 0 else None
            if op == ArithOp.BAND: return int(a) & int(b)
            if op == ArithOp.BOR: return int(a) | int(b)
            if op == ArithOp.BXOR: return int(a) ^ int(b)
            if op == ArithOp.SHL: return int(a) << int(b)
            if op == ArithOp.SHR: return int(a) >> int(b)
        except (TypeError, ValueError, ZeroDivisionError):
            return None
        return None


def _structurally_equal(a: Constraint, b: Constraint) -> bool:
    """Check if two constraints are structurally identical."""
    if type(a) != type(b):
        return False
    if isinstance(a, CVar):
        return a.name == b.name  # type: ignore
    if isinstance(a, CConst):
        return a.value == b.value  # type: ignore
    if isinstance(a, (CTrue, CFalse)):
        return True
    if isinstance(a, CRelation):
        return (a.op == b.op and  # type: ignore
                _structurally_equal(a.lhs, b.lhs) and  # type: ignore
                _structurally_equal(a.rhs, b.rhs))  # type: ignore
    if isinstance(a, (CAnd, COr)):
        return (_structurally_equal(a.lhs, b.lhs) and  # type: ignore
                _structurally_equal(a.rhs, b.rhs))  # type: ignore
    if isinstance(a, CNot):
        return _structurally_equal(a.inner, b.inner)  # type: ignore
    return False


# ===================================================================
#  PART 11 — PUBLIC API
# ===================================================================

def analyze(cfg_data=None,
            properties: Optional[List[Property]] = None,
            config: Optional[AnalysisConfig] = None) -> AnalysisReport:
    """Convenience entry point: run the full analysis pipeline.

    Parameters
    ----------
    cfg_data : cppcheckdata configuration
        The Cppcheck dump data.
    properties : list of Property, optional
        Properties to check (auto-discovery fills in more).
    config : AnalysisConfig, optional
        Analysis configuration.

    Returns
    -------
    AnalysisReport
    """
    engine = ConstraintEngine(config)
    return engine.analyze(cfg_data, properties)


def check_property(prop: Property, cfg_data=None,
                   config: Optional[AnalysisConfig] = None) -> PropertyCheckResult:
    """Convenience: check a single property."""
    engine = ConstraintEngine(config)
    return engine.check_property(prop, cfg_data)


def check_satisfiability(constraints: List[Constraint],
                         backend: str = "auto") -> SolverOutcome:
    """Convenience: check satisfiability of constraints."""
    solver = get_constraint_solver(backend)
    return solver.check_sat(constraints)


def simplify(constraint: Constraint) -> Constraint:
    """Convenience: simplify a constraint."""
    return ConstraintSimplifier().simplify(constraint)


# ===================================================================
#  PART 12 — MODULE METADATA
# ===================================================================

__all__ = [
    # Constraint language
    "CType", "Constraint", "CTrue", "CFalse", "CVar", "CConst",
    "RelOp", "CRelation", "ArithOp", "CArith", "CUnaryOp",
    "CAnd", "COr", "CNot", "CImplies", "CForall", "CExists",
    "CInRange", "CInSet", "CDomainPredicate",
    "conjunction", "disjunction", "collect_conjuncts", "collect_disjuncts",
    "constraint_size",
    # SMT context
    "SMTContext", "Z3SMTContext", "InternalSMTContext", "get_smt_context",
    # Properties
    "PropertyKind", "CheckResult", "Witness", "PropertyCheckResult", "Property",
    "assert_no_division_by_zero", "assert_in_range", "assert_not_null",
    "assert_no_overflow", "assert_array_bounds",
    "invariant", "precondition", "postcondition",
    # Constraint generators
    "ConstraintGenerator",
    "AbstractInterpretationConstraintGenerator",
    "SymbolicExecutionConstraintGenerator",
    "ValueFlowConstraintGenerator",
    # Solver
    "SolverResult", "SolverOutcome", "ConstraintSolver",
    "Z3ConstraintSolver", "InternalConstraintSolver", "get_constraint_solver",
    # Reduction
    "DomainReducer",
    # Checker & Engine
    "PropertyChecker", "PropertyDiscoverer",
    "AnalysisConfig", "AnalysisReport", "ConstraintEngine",
    # Simplifier
    "ConstraintSimplifier", "simplify",
    # Convenience
    "analyze", "check_property", "check_satisfiability",
]
