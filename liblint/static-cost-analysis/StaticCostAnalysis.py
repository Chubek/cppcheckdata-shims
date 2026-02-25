#!/usr/bin/env python3
"""
StaticCostAnalysis.py
═════════════════════

A Cppcheck addon that performs static cost analysis on C/C++ programs
using the abstract execution substrate (abstract_vm.py, abstract_exec.py)
and the cppcheckdata dump-file API.

Overview
--------
For every function in the translation unit, this addon:

  1. Builds a control-flow graph (CFG) from the Cppcheck AST/scopes.
  2. Assigns abstract costs to each basic block based on the operations
     it contains (arithmetic, memory access, function calls, etc.).
  3. Infers loop iteration bounds via interval abstract interpretation.
  4. Computes an upper-bound cost estimate for each function by solving
     cost recurrences over the CFG.
  5. Reports:
     - Per-function cost summaries (O(1), O(n), O(n²), O(n log n), etc.)
     - Hotspot loops with high estimated cost
     - Potentially unbounded or super-linear constructs
     - Recursive functions with non-trivial cost recurrences

Theory
------
The analysis is grounded in several complementary frameworks:

  • Cost Relations (Albert et al., COSTA):
      Each function/loop generates a cost relation — a recurrence
      whose closed form (if solvable) gives the asymptotic bound.

  • Potential Method (Hoffmann et al.):
      "Potential measures what is, cost measures what happens."
      We track abstract potential that monotonically decreases
      along execution; initial potential ≥ total cost.

  • Interval-Based Loop Bound Inference (Cousot & Halbwachs):
      Loop iteration counts are inferred by widening/narrowing
      on the interval domain over the loop counter variable.

  • Parallel Cost Model:
      Fork/join constructs use max(cost_branch_i) instead of
      sum, reflecting wall-clock time on unbounded parallelism.

Usage
-----
  cppcheck --dump myfile.c
  python StaticCostAnalysis.py myfile.c.dump

Or via cppcheck's --addon mechanism:
  cppcheck --addon=StaticCostAnalysis myfile.c

License: MIT
"""

from __future__ import annotations

import sys
import os
import json
import math
import re
from enum import Enum, auto
from dataclasses import dataclass, field
from typing import (
    Any,
    Callable,
    Dict,
    FrozenSet,
    List,
    Optional,
    Set,
    Sequence,
    Tuple,
    Union,
)
from collections import defaultdict, deque
from functools import lru_cache

# ---------------------------------------------------------------------------
#  Import cppcheckdata (Cppcheck's dump-file parser)
# ---------------------------------------------------------------------------
try:
    import cppcheckdata
except ImportError:
    # When running inside cppcheck's addon framework, cppcheckdata.py is
    # on the path.  For standalone testing, try the parent directory.
    _parent = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if _parent not in sys.path:
        sys.path.insert(0, _parent)
    import cppcheckdata

# ---------------------------------------------------------------------------
#  Import the abstract execution substrate
# ---------------------------------------------------------------------------
try:
    from cppcheckdata_shims.abstract_domains import (
        IntervalDomain,
        ConstantDomain,
        FunctionDomain,
    )
except ImportError:
    # Provide minimal stubs if the shims library is not available,
    # so the addon can still run in degraded mode.
    IntervalDomain = None  # type: ignore
    ConstantDomain = None  # type: ignore
    FunctionDomain = None  # type: ignore

# Try to import the abstract VM/exec engine; degrade gracefully.
try:
    from cppcheckdata_shims.abstract_exec import AbsExecEngine, CostAnalysis
    from cppcheckdata_shims.abstract_vm import AbstractVM
    HAS_ABS_EXEC = True
except ImportError:
    HAS_ABS_EXEC = False

# ═══════════════════════════════════════════════════════════════════════════
#  PART 0 — ADDON METADATA & CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════

ADDON_NAME = "StaticCostAnalysis"
ADDON_VERSION = "1.0.0"

# Cost thresholds for reporting
WARN_FUNCTION_COST = 1000       # Warn if function cost exceeds this
STYLE_FUNCTION_COST = 100       # Style warning for moderate cost
WARN_LOOP_ITERATIONS = 10000   # Warn if loop may iterate this many times
MAX_RECURSION_DEPTH = 50        # Analysis recursion limit
PARALLEL_MODEL = False          # Set True to use max() for branches

# Cost weights for different operation types
COST_WEIGHTS = {
    "arithmetic":       1,     # +, -, *, /, %
    "comparison":       1,     # <, >, ==, !=, <=, >=
    "assignment":       1,     # =, +=, -=, etc.
    "memory_read":      4,     # array access, pointer dereference (read)
    "memory_write":     4,     # array access, pointer dereference (write)
    "function_call":   10,     # generic function call (unknown cost)
    "malloc":          50,     # heap allocation
    "free":            20,     # heap deallocation
    "io":             100,     # I/O operations (printf, scanf, read, write)
    "branch":           1,     # conditional branch
    "syscall":        200,     # system calls
    "nop":              0,     # no-op / declaration only
    "bitwise":          1,     # &, |, ^, ~, <<, >>
    "cast":             0,     # type cast (usually free)
    "return":           1,     # function return
    "increment":        1,     # ++, --
    "logical":          1,     # &&, ||, !
}

# Known function costs (overrides generic function_call cost)
KNOWN_FUNCTION_COSTS: Dict[str, "CostExpr"] = {}  # populated during init


# ═══════════════════════════════════════════════════════════════════════════
#  PART 1 — COST EXPRESSION ALGEBRA
# ═══════════════════════════════════════════════════════════════════════════
#
#  Cost expressions represent symbolic upper bounds.  They form a small
#  algebra that can be evaluated, simplified, and pretty-printed.
#
#  Grammar:
#    CostExpr ::= Const(n)
#               | Var(name)           -- symbolic (e.g. 'n', 'len')
#               | Add(e1, e2)
#               | Mul(e1, e2)
#               | Max(e1, e2)
#               | Log(e)
#               | Pow(e, k)           -- e^k for integer k
#               | Inf                 -- unbounded / unknown
# ═══════════════════════════════════════════════════════════════════════════

class CostExprKind(Enum):
    CONST = auto()
    VAR = auto()
    ADD = auto()
    MUL = auto()
    MAX = auto()
    LOG = auto()
    POW = auto()
    INF = auto()


@dataclass(frozen=True)
class CostExpr:
    """
    A symbolic cost expression representing an upper-bound cost.

    This is the core data structure for the cost analysis.  Cost
    expressions can be composed, simplified, and classified into
    asymptotic complexity classes.
    """
    kind: CostExprKind
    value: Optional[Union[int, float, str]] = None
    children: Tuple["CostExpr", ...] = ()

    # ---- Constructors (factory methods) ----------------------------------

    @staticmethod
    def const(n: Union[int, float]) -> CostExpr:
        """Constant cost."""
        return CostExpr(CostExprKind.CONST, value=n)

    @staticmethod
    def var(name: str) -> CostExpr:
        """Symbolic variable (e.g. input size parameter)."""
        return CostExpr(CostExprKind.VAR, value=name)

    @staticmethod
    def add(a: CostExpr, b: CostExpr) -> CostExpr:
        """Sum of two costs."""
        # Simplifications
        if a.kind == CostExprKind.CONST and a.value == 0:
            return b
        if b.kind == CostExprKind.CONST and b.value == 0:
            return a
        if a.kind == CostExprKind.INF or b.kind == CostExprKind.INF:
            return CostExpr.inf()
        if (a.kind == CostExprKind.CONST and b.kind == CostExprKind.CONST):
            return CostExpr.const(a.value + b.value)
        return CostExpr(CostExprKind.ADD, children=(a, b))

    @staticmethod
    def mul(a: CostExpr, b: CostExpr) -> CostExpr:
        """Product of two costs."""
        if a.kind == CostExprKind.CONST and a.value == 0:
            return CostExpr.const(0)
        if b.kind == CostExprKind.CONST and b.value == 0:
            return CostExpr.const(0)
        if a.kind == CostExprKind.CONST and a.value == 1:
            return b
        if b.kind == CostExprKind.CONST and b.value == 1:
            return a
        if a.kind == CostExprKind.INF or b.kind == CostExprKind.INF:
            return CostExpr.inf()
        if (a.kind == CostExprKind.CONST and b.kind == CostExprKind.CONST):
            return CostExpr.const(a.value * b.value)
        return CostExpr(CostExprKind.MUL, children=(a, b))

    @staticmethod
    def maximum(a: CostExpr, b: CostExpr) -> CostExpr:
        """Maximum of two costs (used for branches / parallel)."""
        if a.kind == CostExprKind.INF or b.kind == CostExprKind.INF:
            return CostExpr.inf()
        if a.kind == CostExprKind.CONST and b.kind == CostExprKind.CONST:
            return CostExpr.const(max(a.value, b.value))
        return CostExpr(CostExprKind.MAX, children=(a, b))

    @staticmethod
    def log(e: CostExpr) -> CostExpr:
        """Logarithmic cost."""
        if e.kind == CostExprKind.CONST and e.value is not None and e.value > 0:
            return CostExpr.const(math.ceil(math.log2(e.value)))
        return CostExpr(CostExprKind.LOG, children=(e,))

    @staticmethod
    def power(base: CostExpr, exp: int) -> CostExpr:
        """Polynomial cost base^exp."""
        if exp == 0:
            return CostExpr.const(1)
        if exp == 1:
            return base
        if base.kind == CostExprKind.CONST:
            return CostExpr.const(int(base.value ** exp))
        return CostExpr(CostExprKind.POW, value=exp, children=(base,))

    @staticmethod
    def inf() -> CostExpr:
        """Unbounded / unknown cost."""
        return CostExpr(CostExprKind.INF)

    # ---- Evaluation ------------------------------------------------------

    def evaluate(self, env: Optional[Dict[str, float]] = None) -> float:
        """
        Evaluate the cost expression given concrete variable bindings.

        Parameters
        ----------
        env : dict mapping variable names to numeric values

        Returns
        -------
        float : the evaluated cost (may be float('inf'))
        """
        env = env or {}
        k = self.kind

        if k == CostExprKind.CONST:
            return float(self.value)
        elif k == CostExprKind.VAR:
            return env.get(self.value, float("inf"))
        elif k == CostExprKind.ADD:
            return self.children[0].evaluate(env) + self.children[1].evaluate(env)
        elif k == CostExprKind.MUL:
            return self.children[0].evaluate(env) * self.children[1].evaluate(env)
        elif k == CostExprKind.MAX:
            return max(
                self.children[0].evaluate(env),
                self.children[1].evaluate(env),
            )
        elif k == CostExprKind.LOG:
            v = self.children[0].evaluate(env)
            return math.log2(max(v, 1.0))
        elif k == CostExprKind.POW:
            return self.children[0].evaluate(env) ** self.value
        elif k == CostExprKind.INF:
            return float("inf")
        return float("inf")

    # ---- Variables -------------------------------------------------------

    def free_vars(self) -> Set[str]:
        """Return all free symbolic variables in this expression."""
        if self.kind == CostExprKind.VAR:
            return {self.value}
        result: Set[str] = set()
        for child in self.children:
            result |= child.free_vars()
        return result

    # ---- Asymptotic classification ---------------------------------------

    def classify(self) -> str:
        """
        Classify the asymptotic complexity.

        Returns a human-readable string like 'O(1)', 'O(n)', 'O(n^2)',
        'O(n log n)', 'O(∞)', etc.
        """
        if self.kind == CostExprKind.CONST:
            return "O(1)"
        if self.kind == CostExprKind.INF:
            return "O(∞)"
        if self.kind == CostExprKind.VAR:
            return f"O({self.value})"
        if self.kind == CostExprKind.MUL:
            c0 = self.children[0]
            c1 = self.children[1]
            # n * log(n)
            if c1.kind == CostExprKind.LOG:
                inner = c1.children[0] if c1.children else None
                if inner and inner.kind == CostExprKind.VAR:
                    if c0.kind == CostExprKind.VAR and c0.value == inner.value:
                        return f"O({c0.value} log {c0.value})"
            if c0.kind == CostExprKind.LOG:
                inner = c0.children[0] if c0.children else None
                if inner and inner.kind == CostExprKind.VAR:
                    if c1.kind == CostExprKind.VAR and c1.value == inner.value:
                        return f"O({c1.value} log {c1.value})"
            # const * expr
            if c0.kind == CostExprKind.CONST:
                return c1.classify()
            if c1.kind == CostExprKind.CONST:
                return c0.classify()
            # var * var => O(n^2) or O(n*m)
            if c0.kind == CostExprKind.VAR and c1.kind == CostExprKind.VAR:
                if c0.value == c1.value:
                    return f"O({c0.value}²)"
                return f"O({c0.value}·{c1.value})"
            # fallback
            return f"O({self})"
        if self.kind == CostExprKind.POW:
            base = self.children[0]
            exp = self.value
            if base.kind == CostExprKind.VAR:
                if exp == 2:
                    return f"O({base.value}²)"
                if exp == 3:
                    return f"O({base.value}³)"
                return f"O({base.value}^{exp})"
            return f"O({self})"
        if self.kind == CostExprKind.LOG:
            inner = self.children[0] if self.children else None
            if inner and inner.kind == CostExprKind.VAR:
                return f"O(log {inner.value})"
            return f"O(log(...))"
        if self.kind == CostExprKind.ADD:
            # Classify as the dominant term
            c0_cls = self.children[0].classify()
            c1_cls = self.children[1].classify()
            # Simple dominance heuristic
            return _dominant_complexity(c0_cls, c1_cls)
        if self.kind == CostExprKind.MAX:
            c0_cls = self.children[0].classify()
            c1_cls = self.children[1].classify()
            return _dominant_complexity(c0_cls, c1_cls)
        return f"O({self})"

    # ---- Pretty printing -------------------------------------------------

    def __str__(self) -> str:
        k = self.kind
        if k == CostExprKind.CONST:
            return str(self.value)
        if k == CostExprKind.VAR:
            return str(self.value)
        if k == CostExprKind.ADD:
            return f"({self.children[0]} + {self.children[1]})"
        if k == CostExprKind.MUL:
            return f"({self.children[0]} * {self.children[1]})"
        if k == CostExprKind.MAX:
            return f"max({self.children[0]}, {self.children[1]})"
        if k == CostExprKind.LOG:
            return f"log({self.children[0]})"
        if k == CostExprKind.POW:
            return f"({self.children[0]})^{self.value}"
        if k == CostExprKind.INF:
            return "∞"
        return "?"

    def __repr__(self) -> str:
        return f"CostExpr({self})"


# ---- Complexity dominance heuristic --------------------------------------

_COMPLEXITY_ORDER = [
    "O(1)", "O(log n)", "O(n)", "O(n log n)",
    "O(n²)", "O(n³)", "O(∞)",
]

def _dominant_complexity(a: str, b: str) -> str:
    """Return the asymptotically dominant complexity class."""
    def _rank(s: str) -> int:
        # Normalize
        s_norm = s.lower().replace(" ", "")
        if s_norm == "o(1)":
            return 0
        if "log" in s_norm and "n" not in s_norm.replace("log", ""):
            return 1
        if "nlog" in s_norm or "n·log" in s_norm or "nlogn" in s_norm:
            return 3
        if "²" in s_norm or "^2" in s_norm:
            return 4
        if "³" in s_norm or "^3" in s_norm:
            return 5
        if "∞" in s_norm:
            return 99
        if "n" in s_norm or any(c.isalpha() for c in s_norm.replace("o(", "").replace(")", "")):
            return 2
        return 2  # default: linear
    ra, rb = _rank(a), _rank(b)
    return a if ra >= rb else b


# ═══════════════════════════════════════════════════════════════════════════
#  PART 2 — AST / TOKEN COST CLASSIFICATION
# ═══════════════════════════════════════════════════════════════════════════
#
#  These functions walk Cppcheck token streams and classify each
#  operation into a cost category, accumulating abstract cost per
#  basic block.
# ═══════════════════════════════════════════════════════════════════════════

# Known I/O and allocation function names
_IO_FUNCTIONS = frozenset({
    "printf", "fprintf", "sprintf", "snprintf", "scanf", "fscanf",
    "sscanf", "puts", "fputs", "fgets", "gets", "getchar", "putchar",
    "fread", "fwrite", "fopen", "fclose", "fseek", "ftell", "rewind",
    "read", "write", "open", "close", "send", "recv", "accept",
    "connect", "bind", "listen", "select", "poll", "epoll_wait",
    "cout", "cin", "cerr", "endl",
})

_ALLOC_FUNCTIONS = frozenset({
    "malloc", "calloc", "realloc", "aligned_alloc", "posix_memalign",
    "new", "new[]", "mmap",
})

_FREE_FUNCTIONS = frozenset({
    "free", "delete", "delete[]", "munmap",
})

_SYSCALL_FUNCTIONS = frozenset({
    "fork", "exec", "execve", "execvp", "system", "popen", "pclose",
    "clone", "wait", "waitpid", "kill", "signal", "sigaction",
    "mprotect", "brk", "sbrk", "ioctl",
})

_ARITHMETIC_OPS = frozenset({"+", "-", "*", "/", "%"})
_COMPARISON_OPS = frozenset({"<", ">", "<=", ">=", "==", "!="})
_ASSIGNMENT_OPS = frozenset({"=", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "<<=", ">>="})
_BITWISE_OPS = frozenset({"&", "|", "^", "~", "<<", ">>"})
_LOGICAL_OPS = frozenset({"&&", "||", "!"})
_INCREMENT_OPS = frozenset({"++", "--"})


def classify_token_cost(token) -> Tuple[str, int]:
    """
    Classify a single token's cost contribution.

    Parameters
    ----------
    token : cppcheckdata.Token

    Returns
    -------
    (category: str, cost: int)
    """
    if token is None:
        return ("nop", 0)

    s = token.str

    # Function call
    if token.isName and token.next and token.next.str == "(":
        fname = s
        # Resolve qualified names
        t = token
        while t.previous and t.previous.str == "::":
            if t.previous.previous and t.previous.previous.isName:
                fname = t.previous.previous.str + "::" + fname
                t = t.previous.previous
            else:
                break

        base_name = fname.split("::")[-1] if "::" in fname else fname

        if base_name in _IO_FUNCTIONS:
            return ("io", COST_WEIGHTS["io"])
        if base_name in _ALLOC_FUNCTIONS:
            return ("malloc", COST_WEIGHTS["malloc"])
        if base_name in _FREE_FUNCTIONS:
            return ("free", COST_WEIGHTS["free"])
        if base_name in _SYSCALL_FUNCTIONS:
            return ("syscall", COST_WEIGHTS["syscall"])

        return ("function_call", COST_WEIGHTS["function_call"])

    # Operators
    if s in _ARITHMETIC_OPS:
        return ("arithmetic", COST_WEIGHTS["arithmetic"])
    if s in _COMPARISON_OPS:
        return ("comparison", COST_WEIGHTS["comparison"])
    if s in _ASSIGNMENT_OPS:
        return ("assignment", COST_WEIGHTS["assignment"])
    if s in _BITWISE_OPS:
        return ("bitwise", COST_WEIGHTS["bitwise"])
    if s in _LOGICAL_OPS:
        return ("logical", COST_WEIGHTS["logical"])
    if s in _INCREMENT_OPS:
        return ("increment", COST_WEIGHTS["increment"])

    # Memory access: array indexing or pointer dereference
    if s == "[" and token.astParent:
        return ("memory_read", COST_WEIGHTS["memory_read"])
    if s == "*" and token.astOperand1 and not token.astOperand2:
        # Unary dereference
        return ("memory_read", COST_WEIGHTS["memory_read"])
    if s == "->" or s == ".":
        return ("memory_read", COST_WEIGHTS["memory_read"])

    # Return statement
    if s == "return":
        return ("return", COST_WEIGHTS["return"])

    # Cast
    if token.isCast:
        return ("cast", COST_WEIGHTS["cast"])

    return ("nop", 0)


def compute_block_cost(tokens: List) -> Tuple[CostExpr, Dict[str, int]]:
    """
    Compute the total abstract cost for a list of tokens (a basic block).

    Returns
    -------
    (total_cost_expr, category_breakdown)
        total_cost_expr: CostExpr  — the symbolic cost
        category_breakdown: dict   — counts per category
    """
    total = 0
    breakdown: Dict[str, int] = defaultdict(int)

    for tok in tokens:
        cat, cost = classify_token_cost(tok)
        if cost > 0:
            total += cost
            breakdown[cat] += 1

    return CostExpr.const(total), dict(breakdown)


# ═══════════════════════════════════════════════════════════════════════════
#  PART 3 — LOOP BOUND INFERENCE
# ═══════════════════════════════════════════════════════════════════════════
#
#  We attempt to infer loop iteration bounds by analyzing the loop
#  condition, initializer, and increment.  This uses interval abstract
#  interpretation when available, or pattern matching as a fallback.
#
#  Supported patterns:
#    for (i = a; i < b; i++)          →  bound = b - a
#    for (i = a; i < b; i += s)       →  bound = ceil((b - a) / s)
#    while (i < n) { ...; i++; }      →  bound = n  (conservative)
#    while (ptr != NULL)              →  bound = ∞  (unknown)
#
#  When the bound involves symbolic variables, we return a CostExpr
#  with those variables.
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class LoopInfo:
    """Information extracted from a loop construct."""
    scope_id: Optional[str] = None
    kind: str = "unknown"            # "for", "while", "do-while"
    counter_var: Optional[str] = None
    init_value: Optional[CostExpr] = None
    bound_value: Optional[CostExpr] = None
    step_value: Optional[CostExpr] = None
    iteration_bound: Optional[CostExpr] = None
    body_tokens: List = field(default_factory=list)
    nested_loops: List["LoopInfo"] = field(default_factory=list)
    line_number: int = 0
    file_name: str = ""


def _try_parse_int(token) -> Optional[int]:
    """Try to extract an integer literal from a token."""
    if token is None:
        return None
    try:
        if token.isNumber:
            s = token.str
            # Handle hex, octal, binary literals
            if s.startswith("0x") or s.startswith("0X"):
                return int(s, 16)
            if s.startswith("0b") or s.startswith("0B"):
                return int(s, 2)
            if s.startswith("0") and len(s) > 1 and s[1:].isdigit():
                return int(s, 8)
            # Strip suffixes like U, L, LL, ULL
            s = re.sub(r'[uUlL]+$', '', s)
            if '.' in s or 'e' in s or 'E' in s:
                return None  # floating point
            return int(s)
    except (ValueError, AttributeError):
        pass
    return None


def _token_to_cost_expr(token) -> CostExpr:
    """Convert a token (or simple AST subtree) to a CostExpr."""
    if token is None:
        return CostExpr.inf()

    v = _try_parse_int(token)
    if v is not None:
        return CostExpr.const(v)

    if token.isName:
        return CostExpr.var(token.str)

    # Handle simple binary expressions: a - b, a + b, a * b
    if token.astOperand1 and token.astOperand2:
        left = _token_to_cost_expr(token.astOperand1)
        right = _token_to_cost_expr(token.astOperand2)
        op_str = token.str
        if op_str == "+":
            return CostExpr.add(left, right)
        if op_str == "-":
            # left - right
            if (left.kind == CostExprKind.CONST and
                    right.kind == CostExprKind.CONST):
                return CostExpr.const(left.value - right.value)
            return CostExpr.add(left, CostExpr.mul(CostExpr.const(-1), right))
        if op_str == "*":
            return CostExpr.mul(left, right)

    return CostExpr.inf()


def infer_for_loop_bound(for_token) -> LoopInfo:
    """
    Infer the iteration bound of a for-loop.

    Analyzes the three clauses: init; condition; increment.

    Parameters
    ----------
    for_token : the 'for' keyword token

    Returns
    -------
    LoopInfo with the inferred bound
    """
    info = LoopInfo(kind="for")
    if for_token:
        info.line_number = getattr(for_token, 'linenr', 0)
        info.file_name = getattr(for_token, 'file', "")

    # Navigate to the parenthesized clause: for ( init ; cond ; incr )
    paren = for_token.next if for_token else None
    if not paren or paren.str != "(":
        info.iteration_bound = CostExpr.inf()
        return info

    # Collect all tokens inside the parentheses up to the matching ')'
    # Split by ';' into init, condition, increment
    clauses: List[List] = [[]]
    tok = paren.next
    depth = 1
    while tok and depth > 0:
        if tok.str == "(":
            depth += 1
        elif tok.str == ")":
            depth -= 1
            if depth == 0:
                break
        if tok.str == ";" and depth == 1:
            clauses.append([])
        else:
            clauses[-1].append(tok)
        tok = tok.next

    if len(clauses) < 3:
        info.iteration_bound = CostExpr.inf()
        return info

    init_tokens, cond_tokens, incr_tokens = clauses[0], clauses[1], clauses[2]

    # ---- Parse init clause ----
    # Look for: i = expr  or  int i = expr
    counter_name = None
    init_expr = None
    for i_idx, itok in enumerate(init_tokens):
        if itok.str == "=" and i_idx > 0:
            # Variable is the token before '='
            var_tok = init_tokens[i_idx - 1]
            if var_tok.isName:
                counter_name = var_tok.str
                # Init value is everything after '='
                if i_idx + 1 < len(init_tokens):
                    init_expr = _token_to_cost_expr(init_tokens[i_idx + 1])
                else:
                    init_expr = CostExpr.const(0)
            break

    info.counter_var = counter_name
    info.init_value = init_expr if init_expr else CostExpr.const(0)

    # ---- Parse condition clause ----
    # Look for: i < expr, i <= expr, i > expr, i >= expr, i != expr
    bound_expr = None
    cmp_op = None
    for c_idx, ctok in enumerate(cond_tokens):
        if ctok.str in ("<", "<=", ">", ">=", "!="):
            cmp_op = ctok.str
            if counter_name and c_idx > 0:
                # Verify the left side is our counter
                left_tok = cond_tokens[c_idx - 1]
                if left_tok.isName and left_tok.str == counter_name:
                    if c_idx + 1 < len(cond_tokens):
                        bound_expr = _token_to_cost_expr(cond_tokens[c_idx + 1])
            break

    if bound_expr is None:
        info.iteration_bound = CostExpr.inf()
        info.bound_value = CostExpr.inf()
        return info

    info.bound_value = bound_expr

    # ---- Parse increment clause ----
    # Look for: i++, ++i, i += s, i = i + s
    step = CostExpr.const(1)  # default step
    for etok in incr_tokens:
        if etok.str in ("++", "--"):
            step = CostExpr.const(1)
            break
        if etok.str == "+=" and counter_name:
            # Find the RHS
            idx = incr_tokens.index(etok)
            if idx + 1 < len(incr_tokens):
                step = _token_to_cost_expr(incr_tokens[idx + 1])
            break
        if etok.str == "-=" and counter_name:
            idx = incr_tokens.index(etok)
            if idx + 1 < len(incr_tokens):
                step = _token_to_cost_expr(incr_tokens[idx + 1])
            break

    info.step_value = step

    # ---- Compute iteration bound ----
    init_val = info.init_value
    bound_val = info.bound_value

    if cmp_op in ("<", "!="):
        # iterations = (bound - init) / step
        diff = CostExpr.add(
            bound_val,
            CostExpr.mul(CostExpr.const(-1), init_val)
        )
        if step.kind == CostExprKind.CONST and step.value == 1:
            info.iteration_bound = diff
        elif step.kind == CostExprKind.CONST and step.value > 0:
            # ceil(diff / step)
            if diff.kind == CostExprKind.CONST:
                info.iteration_bound = CostExpr.const(
                    math.ceil(diff.value / step.value)
                )
            else:
                # Can't simplify; approximate
                info.iteration_bound = diff  # conservative: ignore step
        else:
            info.iteration_bound = diff
    elif cmp_op == "<=":
        diff = CostExpr.add(
            bound_val,
            CostExpr.add(
                CostExpr.mul(CostExpr.const(-1), init_val),
                CostExpr.const(1),
            ),
        )
        if step.kind == CostExprKind.CONST and step.value == 1:
            info.iteration_bound = diff
        else:
            info.iteration_bound = diff
    elif cmp_op in (">", ">="):
        # Decrementing loop: i starts high, decrements
        diff = CostExpr.add(
            init_val,
            CostExpr.mul(CostExpr.const(-1), bound_val),
        )
        if cmp_op == ">":
            pass  # diff is correct
        else:  # >=
            diff = CostExpr.add(diff, CostExpr.const(1))
        info.iteration_bound = diff
    else:
        info.iteration_bound = CostExpr.inf()

    return info


def infer_while_loop_bound(while_token) -> LoopInfo:
    """
    Infer the iteration bound of a while-loop.

    While-loops are harder to analyze because initialization and
    increment are not syntactically delimited.  We use heuristics.
    """
    info = LoopInfo(kind="while")
    if while_token:
        info.line_number = getattr(while_token, 'linenr', 0)
        info.file_name = getattr(while_token, 'file', "")

    # Look at the condition
    paren = while_token.next if while_token else None
    if not paren or paren.str != "(":
        info.iteration_bound = CostExpr.inf()
        return info

    # Collect condition tokens
    cond_tokens = []
    tok = paren.next
    depth = 1
    while tok and depth > 0:
        if tok.str == "(":
            depth += 1
        elif tok.str == ")":
            depth -= 1
            if depth == 0:
                break
        cond_tokens.append(tok)
        tok = tok.next

    # Try to find a comparison pattern: var < expr
    for c_idx, ctok in enumerate(cond_tokens):
        if ctok.str in ("<", "<=", ">", ">="):
            if c_idx > 0 and cond_tokens[c_idx - 1].isName:
                info.counter_var = cond_tokens[c_idx - 1].str
                if c_idx + 1 < len(cond_tokens):
                    info.bound_value = _token_to_cost_expr(cond_tokens[c_idx + 1])
                    info.iteration_bound = info.bound_value
                    return info

    # while (ptr != NULL) or while (x) — unbounded
    info.iteration_bound = CostExpr.inf()
    return info


# ═══════════════════════════════════════════════════════════════════════════
#  PART 4 — FUNCTION COST ANALYZER
# ═══════════════════════════════════════════════════════════════════════════
#
#  The core analysis:
#    1. Walk every function's scope
#    2. Identify loops, branches, and straight-line code
#    3. Build a cost recurrence and solve it
#    4. Produce a CostExpr for the function
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class FunctionCostResult:
    """Result of analyzing a single function."""
    name: str
    file: str
    line: int
    total_cost: CostExpr
    complexity_class: str
    loops: List[LoopInfo] = field(default_factory=list)
    breakdown: Dict[str, int] = field(default_factory=dict)
    is_recursive: bool = False
    callees: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def __repr__(self) -> str:
        return (
            f"FunctionCost({self.name}, cost={self.total_cost}, "
            f"class={self.complexity_class})"
        )


class FunctionCostAnalyzer:
    """
    Analyzes the cost of all functions in a Cppcheck dump configuration.

    This is the main analysis engine.  It processes the AST/scope tree
    from a Cppcheck dump file, infers loop bounds, and computes
    upper-bound cost expressions.
    """

    def __init__(self, cfg):
        """
        Parameters
        ----------
        cfg : cppcheckdata.Configuration
            A configuration object from parsing a .dump file.
        """
        self.cfg = cfg
        self.results: Dict[str, FunctionCostResult] = {}
        self._call_graph: Dict[str, Set[str]] = defaultdict(set)
        self._analyzing: Set[str] = set()  # for recursion detection
        self._function_scopes: Dict[str, Any] = {}  # name -> scope
        self._function_tokens: Dict[str, Any] = {}  # name -> func def token

        # Build function index
        self._index_functions()

    def _index_functions(self) -> None:
        """Index all function definitions by name."""
        if not hasattr(self.cfg, 'functions') or self.cfg.functions is None:
            return
        for func in self.cfg.functions:
            if func.tokenDef:
                name = self._get_qualified_name(func)
                self._function_tokens[name] = func
                if func.nestedIn:
                    self._function_scopes[name] = func.nestedIn

    def _get_qualified_name(self, func) -> str:
        """Get the fully qualified name of a function."""
        name = func.name if hasattr(func, 'name') else ""
        if not name and func.tokenDef:
            name = func.tokenDef.str
        scope = func.nestedIn
        while scope:
            if hasattr(scope, 'className') and scope.className:
                name = scope.className + "::" + name
            scope = getattr(scope, 'nestedIn', None)
        return name

    def analyze_all(self) -> List[FunctionCostResult]:
        """
        Analyze all functions in the configuration.

        Returns
        -------
        list of FunctionCostResult
        """
        results = []

        # Iterate over all scopes to find function bodies
        if not hasattr(self.cfg, 'scopes') or self.cfg.scopes is None:
            return results

        for scope in self.cfg.scopes:
            if not hasattr(scope, 'type'):
                continue
            if scope.type != "Function":
                continue
            if not scope.bodyStart or not scope.bodyEnd:
                continue

            # Get function name
            func_name = self._scope_function_name(scope)
            if not func_name:
                func_name = f"<anonymous@{scope.bodyStart.linenr}>"

            result = self.analyze_function_scope(scope, func_name)
            results.append(result)
            self.results[func_name] = result

        return results

    def _scope_function_name(self, scope) -> Optional[str]:
        """Extract the function name from a Function scope."""
        if hasattr(scope, 'function') and scope.function:
            func = scope.function
            return self._get_qualified_name(func)
        # Fallback: look at the token before '{'
        if scope.bodyStart:
            tok = scope.bodyStart.previous
            while tok and tok.str in (")", "const", "noexcept", "override", "final"):
                if tok.str == ")":
                    tok = tok.link  # skip back to matching '('
                    if tok:
                        tok = tok.previous
                else:
                    tok = tok.previous
            if tok and tok.isName:
                return tok.str
        return None

    def analyze_function_scope(
        self, scope, func_name: str
    ) -> FunctionCostResult:
        """
        Analyze a single function's scope and compute its cost.

        Parameters
        ----------
        scope : the Function scope from cppcheckdata
        func_name : the function's name

        Returns
        -------
        FunctionCostResult
        """
        file_name = ""
        line_no = 0
        if scope.bodyStart:
            file_name = getattr(scope.bodyStart, 'file', "")
            line_no = getattr(scope.bodyStart, 'linenr', 0)

        result = FunctionCostResult(
            name=func_name,
            file=file_name,
            line=line_no,
            total_cost=CostExpr.const(0),
            complexity_class="O(1)",
        )

        # Check for recursion
        if func_name in self._analyzing:
            result.is_recursive = True
            result.total_cost = CostExpr.inf()
            result.complexity_class = "O(∞) [recursive]"
            result.warnings.append(
                f"Recursive function '{func_name}' — cost is potentially unbounded"
            )
            return result

        self._analyzing.add(func_name)

        try:
            # Walk the function body
            cost, breakdown, loops, callees = self._analyze_scope_body(scope)
            result.total_cost = cost
            result.complexity_class = cost.classify()
            result.breakdown = breakdown
            result.loops = loops
            result.callees = list(callees)

            # Check for recursive calls in callees
            if func_name in callees:
                result.is_recursive = True
                result.warnings.append(
                    f"Function '{func_name}' is directly recursive"
                )

            # Generate warnings
            concrete_cost = cost.evaluate({})
            if concrete_cost >= WARN_FUNCTION_COST:
                result.warnings.append(
                    f"High estimated cost: {cost} ({cost.classify()})"
                )
            elif concrete_cost >= STYLE_FUNCTION_COST:
                result.warnings.append(
                    f"Moderate estimated cost: {cost}"
                )

        finally:
            self._analyzing.discard(func_name)

        return result

    def _analyze_scope_body(
        self, scope
    ) -> Tuple[CostExpr, Dict[str, int], List[LoopInfo], Set[str]]:
        """
        Analyze the body of a scope (function, loop body, etc.).

        Returns
        -------
        (cost_expr, breakdown, loops, callees)
        """
        total_cost = CostExpr.const(0)
        breakdown: Dict[str, int] = defaultdict(int)
        loops: List[LoopInfo] = []
        callees: Set[str] = set()

        if not scope.bodyStart or not scope.bodyEnd:
            return total_cost, dict(breakdown), loops, callees

        tok = scope.bodyStart.next  # skip '{'

        while tok and tok != scope.bodyEnd:
            if tok is None:
                break

            # ---- For loop ----
            if tok.str == "for":
                loop_info = infer_for_loop_bound(tok)

                # Find the loop body scope
                body_cost = CostExpr.const(COST_WEIGHTS["branch"])
                # Look for the '{' that starts the loop body
                t = tok
                found_body = False
                while t and t.str != "{" and t != scope.bodyEnd:
                    t = t.next
                if t and t.str == "{" and t.link:
                    # Analyze tokens inside the loop body
                    inner_cost, inner_break, inner_loops, inner_callees = (
                        self._analyze_token_range(t.next, t.link)
                    )
                    body_cost = CostExpr.add(body_cost, inner_cost)
                    for k, v in inner_break.items():
                        breakdown[k] += v
                    loops.extend(inner_loops)
                    callees |= inner_callees
                    loop_info.nested_loops = inner_loops

                    # Skip past the loop body
                    tok = t.link.next
                    found_body = True

                if not found_body:
                    tok = tok.next
                    continue

                # Total loop cost = iterations × body_cost
                if loop_info.iteration_bound:
                    loop_cost = CostExpr.mul(
                        loop_info.iteration_bound, body_cost
                    )
                else:
                    loop_cost = CostExpr.mul(CostExpr.inf(), body_cost)

                total_cost = CostExpr.add(total_cost, loop_cost)
                loops.append(loop_info)
                continue

            # ---- While loop ----
            elif tok.str == "while":
                loop_info = infer_while_loop_bound(tok)

                t = tok
                while t and t.str != "{" and t != scope.bodyEnd:
                    t = t.next
                body_cost = CostExpr.const(COST_WEIGHTS["branch"])

                if t and t.str == "{" and t.link:
                    inner_cost, inner_break, inner_loops, inner_callees = (
                        self._analyze_token_range(t.next, t.link)
                    )
                    body_cost = CostExpr.add(body_cost, inner_cost)
                    for k, v in inner_break.items():
                        breakdown[k] += v
                    loops.extend(inner_loops)
                    callees |= inner_callees
                    tok = t.link.next
                else:
                    tok = tok.next if tok else None
                    continue

                if loop_info.iteration_bound:
                    loop_cost = CostExpr.mul(
                        loop_info.iteration_bound, body_cost
                    )
                else:
                    loop_cost = CostExpr.mul(CostExpr.inf(), body_cost)

                total_cost = CostExpr.add(total_cost, loop_cost)
                loops.append(loop_info)
                continue

            # ---- Do-while loop ----
            elif tok.str == "do":
                loop_info = LoopInfo(
                    kind="do-while",
                    line_number=getattr(tok, 'linenr', 0),
                    file_name=getattr(tok, 'file', ""),
                )

                t = tok.next
                body_cost = CostExpr.const(COST_WEIGHTS["branch"])

                if t and t.str == "{" and t.link:
                    inner_cost, inner_break, inner_loops, inner_callees = (
                        self._analyze_token_range(t.next, t.link)
                    )
                    body_cost = CostExpr.add(body_cost, inner_cost)
                    for k, v in inner_break.items():
                        breakdown[k] += v
                    callees |= inner_callees

                    # Look for the while condition after '}'
                    w = t.link.next
                    if w and w.str == "while":
                        wloop = infer_while_loop_bound(w)
                        loop_info.iteration_bound = wloop.iteration_bound
                        loop_info.counter_var = wloop.counter_var
                        # Skip past while(...)  ;
                        t2 = w
                        while t2 and t2.str != ";":
                            t2 = t2.next
                        tok = t2.next if t2 else None
                    else:
                        loop_info.iteration_bound = CostExpr.inf()
                        tok = t.link.next
                else:
                    loop_info.iteration_bound = CostExpr.inf()
                    tok = tok.next
                    continue

                if loop_info.iteration_bound:
                    loop_cost = CostExpr.mul(
                        loop_info.iteration_bound, body_cost
                    )
                else:
                    loop_cost = CostExpr.inf()

                total_cost = CostExpr.add(total_cost, loop_cost)
                loops.append(loop_info)
                continue

            # ---- If/else branch ----
            elif tok.str == "if":
                branch_cost = self._analyze_if_else(tok, scope.bodyEnd)
                total_cost = CostExpr.add(total_cost, branch_cost[0])
                for k, v in branch_cost[1].items():
                    breakdown[k] += v
                callees |= branch_cost[3]
                loops.extend(branch_cost[2])

                # Skip past the if/else structure
                tok = branch_cost[4]  # next token after if/else
                continue

            # ---- Switch ----
            elif tok.str == "switch":
                # Conservative: treat as a branch, skip the body
                t = tok
                while t and t.str != "{" and t != scope.bodyEnd:
                    t = t.next
                if t and t.str == "{" and t.link:
                    inner_cost, inner_break, inner_loops, inner_callees = (
                        self._analyze_token_range(t.next, t.link)
                    )
                    total_cost = CostExpr.add(total_cost, inner_cost)
                    for k, v in inner_break.items():
                        breakdown[k] += v
                    loops.extend(inner_loops)
                    callees |= inner_callees
                    tok = t.link.next
                else:
                    tok = tok.next
                continue

            # ---- Regular token ----
            else:
                cat, cost = classify_token_cost(tok)
                if cost > 0:
                    total_cost = CostExpr.add(total_cost, CostExpr.const(cost))
                    breakdown[cat] += 1

                # Track function calls
                if (tok.isName and tok.next and tok.next.str == "("):
                    callees.add(tok.str)

                tok = tok.next

        return total_cost, dict(breakdown), loops, callees

    def _analyze_token_range(
        self, start_tok, end_tok
    ) -> Tuple[CostExpr, Dict[str, int], List[LoopInfo], Set[str]]:
        """
        Analyze a range of tokens [start_tok, end_tok).

        This handles nested loops and branches within the range.
        """
        total_cost = CostExpr.const(0)
        breakdown: Dict[str, int] = defaultdict(int)
        loops: List[LoopInfo] = []
        callees: Set[str] = set()

        tok = start_tok
        while tok and tok != end_tok:
            if tok.str == "for":
                loop_info = infer_for_loop_bound(tok)
                t = tok
                while t and t.str != "{" and t != end_tok:
                    t = t.next
                body_cost = CostExpr.const(1)
                if t and t.str == "{" and t.link:
                    inner_cost, inner_break, inner_loops, inner_callees = (
                        self._analyze_token_range(t.next, t.link)
                    )
                    body_cost = CostExpr.add(body_cost, inner_cost)
                    for k, v in inner_break.items():
                        breakdown[k] += v
                    loops.extend(inner_loops)
                    callees |= inner_callees
                    tok = t.link.next
                else:
                    tok = tok.next if tok else None
                    continue

                if loop_info.iteration_bound:
                    loop_cost = CostExpr.mul(loop_info.iteration_bound, body_cost)
                else:
                    loop_cost = CostExpr.inf()
                total_cost = CostExpr.add(total_cost, loop_cost)
                loops.append(loop_info)
                continue

            elif tok.str == "while":
                loop_info = infer_while_loop_bound(tok)
                t = tok
                while t and t.str != "{" and t != end_tok:
                    t = t.next
                body_cost = CostExpr.const(1)
                if t and t.str == "{" and t.link:
                    inner_cost, inner_break, inner_loops, inner_callees = (
                        self._analyze_token_range(t.next, t.link)
                    )
                    body_cost = CostExpr.add(body_cost, inner_cost)
                    for k, v in inner_break.items():
                        breakdown[k] += v
                    loops.extend(inner_loops)
                    callees |= inner_callees
                    tok = t.link.next
                else:
                    tok = tok.next if tok else None
                    continue

                if loop_info.iteration_bound:
                    loop_cost = CostExpr.mul(loop_info.iteration_bound, body_cost)
                else:
                    loop_cost = CostExpr.inf()
                total_cost = CostExpr.add(total_cost, loop_cost)
                loops.append(loop_info)
                continue

            else:
                cat, cost = classify_token_cost(tok)
                if cost > 0:
                    total_cost = CostExpr.add(total_cost, CostExpr.const(cost))
                    breakdown[cat] += 1
                if tok.isName and tok.next and tok.next.str == "(":
                    callees.add(tok.str)
                tok = tok.next

        return total_cost, dict(breakdown), loops, callees

    def _analyze_if_else(
        self, if_token, scope_end
    ) -> Tuple[CostExpr, Dict[str, int], List[LoopInfo], Set[str], Any]:
        """
        Analyze an if/else-if/else chain.

        For cost analysis, we use max(branch_costs) if PARALLEL_MODEL
        is False (sequential: we want the worst-case branch), or
        sum if we want total work.  By default, we use max (upper bound
        on any single execution path).

        Returns
        -------
        (cost, breakdown, loops, callees, next_token)
        """
        branches: List[Tuple[CostExpr, Dict[str, int], List[LoopInfo], Set[str]]] = []
        tok = if_token
        next_tok = None

        while tok and tok.str in ("if", "else"):
            if tok.str == "if" or (tok.str == "else" and tok.next and tok.next.str == "if"):
                if tok.str == "else":
                    tok = tok.next  # skip to the 'if'

                # Skip condition: if (...)
                t = tok.next
                if t and t.str == "(":
                    t = t.link  # skip to ')'
                    if t:
                        t = t.next

                # Analyze body
                if t and t.str == "{" and t.link:
                    br_cost, br_break, br_loops, br_callees = (
                        self._analyze_token_range(t.next, t.link)
                    )
                    branches.append((br_cost, br_break, br_loops, br_callees))
                    tok = t.link.next
                else:
                    # Single-statement body
                    cat, cost = classify_token_cost(t)
                    branches.append((
                        CostExpr.const(cost),
                        {cat: 1} if cost > 0 else {},
                        [],
                        set(),
                    ))
                    # Skip to semicolon
                    while t and t.str != ";":
                        t = t.next
                    tok = t.next if t else None

            elif tok.str == "else":
                # else { ... }
                t = tok.next
                if t and t.str == "{" and t.link:
                    br_cost, br_break, br_loops, br_callees = (
                        self._analyze_token_range(t.next, t.link)
                    )
                    branches.append((br_cost, br_break, br_loops, br_callees))
                    tok = t.link.next
                else:
                    cat, cost = classify_token_cost(t)
                    branches.append((
                        CostExpr.const(cost),
                        {cat: 1} if cost > 0 else {},
                        [],
                        set(),
                    ))
                    while t and t.str != ";":
                        t = t.next
                    tok = t.next if t else None
                break  # else is the last branch
            else:
                break

        next_tok = tok

        # Combine branch costs
        if not branches:
            return (CostExpr.const(0), {}, [], set(), next_tok)

        # Use max for upper-bound on any single path
        combined_cost = branches[0][0]
        combined_break: Dict[str, int] = defaultdict(int)
        combined_loops: List[LoopInfo] = []
        combined_callees: Set[str] = set()

        for br_cost, br_break, br_loops, br_callees in branches:
            if PARALLEL_MODEL:
                combined_cost = CostExpr.maximum(combined_cost, br_cost)
            else:
                # Worst-case (max) for upper bound analysis
                combined_cost = CostExpr.maximum(combined_cost, br_cost)
            for k, v in br_break.items():
                combined_break[k] = max(combined_break[k], v)
            combined_loops.extend(br_loops)
            combined_callees |= br_callees

        # Add the branch decision cost itself
        combined_cost = CostExpr.add(
            CostExpr.const(COST_WEIGHTS["branch"]),
            combined_cost,
        )

        return (
            combined_cost,
            dict(combined_break),
            combined_loops,
            combined_callees,
            next_tok,
        )


# ═══════════════════════════════════════════════════════════════════════════
#  PART 5 — ABSTRACT EXECUTION INTEGRATION
# ═══════════════════════════════════════════════════════════════════════════
#
#  If the abstract execution substrate is available, we use it to
#  refine loop bounds via interval abstract interpretation and to
#  track cost accumulation through the abstract VM.
# ═══════════════════════════════════════════════════════════════════════════

class AbstractExecCostRefiner:
    """
    Uses the abstract execution engine to refine cost estimates.

    This integrates with AbsExecEngine / CostAnalysis to:
    - Run interval abstract interpretation on loop variables
    - Refine loop bounds with widening/narrowing
    - Track abstract cost via the VM's cost accounting
    """

    def __init__(self, cfg):
        self.cfg = cfg
        self.available = HAS_ABS_EXEC and IntervalDomain is not None

    def refine_loop_bound(self, loop_info: LoopInfo) -> CostExpr:
        """
        Attempt to refine a loop bound using interval AI.

        If the abstract execution substrate is not available, returns
        the original bound unchanged.
        """
        if not self.available:
            return loop_info.iteration_bound or CostExpr.inf()

        if loop_info.iteration_bound is None:
            return CostExpr.inf()

        # If the bound is already concrete, no refinement needed
        if loop_info.iteration_bound.kind == CostExprKind.CONST:
            return loop_info.iteration_bound

        # Attempt interval-based refinement
        try:
            return self._interval_refine(loop_info)
        except Exception:
            return loop_info.iteration_bound

    def _interval_refine(self, loop_info: LoopInfo) -> CostExpr:
        """
        Use interval widening/narrowing to compute a fixed-point
        bound for the loop counter.

        The procedure:
        1. Initialize counter to [init, init]
        2. Apply the loop body transfer (abstractly increment)
        3. Widen until stable
        4. Narrow to tighten
        5. The iteration count is (fixed_point.hi - init) / step
        """
        if not IntervalDomain:
            return loop_info.iteration_bound or CostExpr.inf()

        # Extract concrete init if possible
        init_val = None
        if loop_info.init_value and loop_info.init_value.kind == CostExprKind.CONST:
            init_val = int(loop_info.init_value.value)

        bound_val = None
        if loop_info.bound_value and loop_info.bound_value.kind == CostExprKind.CONST:
            bound_val = int(loop_info.bound_value.value)

        step_val = 1
        if loop_info.step_value and loop_info.step_value.kind == CostExprKind.CONST:
            step_val = max(1, int(loop_info.step_value.value))

        if init_val is not None and bound_val is not None:
            # Concrete case: just compute
            iterations = max(0, math.ceil((bound_val - init_val) / step_val))
            return CostExpr.const(iterations)

        if init_val is not None:
            # Counter starts at known value, bound is symbolic
            # Use widening to find stable state
            counter = IntervalDomain.const(init_val)
            step_interval = IntervalDomain.const(step_val)

            for _ in range(MAX_RECURSION_DEPTH):
                new_counter = counter.add(step_interval)
                widened = counter.widen(new_counter)
                if counter.leq(widened) and widened.leq(counter):
                    break
                counter = widened

            # The widened interval's hi is our bound
            if math.isfinite(counter.hi):
                return CostExpr.const(int(counter.hi - init_val) // step_val)

        # Fall back to original bound
        return loop_info.iteration_bound or CostExpr.inf()

    def run_cost_analysis(self, cfg) -> Optional[Dict[str, float]]:
        """
        Run the full CostAnalysis from abstract_exec if available.

        Returns a dict mapping function names to abstract cost values,
        or None if the substrate is not available.
        """
        if not self.available:
            return None

        try:
            analysis = CostAnalysis(cfg)
            analysis.run()
            return analysis.get_results()
        except Exception:
            return None


# ═══════════════════════════════════════════════════════════════════════════
#  PART 6 — REPORTING
# ═══════════════════════════════════════════════════════════════════════════

def report_results(
    results: List[FunctionCostResult],
    dump_file: str,
    verbose: bool = False,
) -> None:
    """
    Report the cost analysis results using cppcheckdata's reporting API.

    Parameters
    ----------
    results : list of FunctionCostResult
    dump_file : path to the dump file (for summary reporting)
    verbose : if True, print detailed analysis to stderr
    """
    for result in results:
        # Create a location-like object for reporting
        location = _make_location(result.file, result.line)

        # ---- High-cost function warning ----
        concrete = result.total_cost.evaluate({})
        if concrete >= WARN_FUNCTION_COST or result.total_cost.kind == CostExprKind.INF:
            severity = "performance"
            message = (
                f"Function '{result.name}' has high estimated cost: "
                f"{result.total_cost} — complexity: {result.complexity_class}"
            )
            cppcheckdata.reportError(
                location, severity, message,
                ADDON_NAME, "highCostFunction",
                extra=result.complexity_class,
            )

        elif concrete >= STYLE_FUNCTION_COST:
            severity = "style"
            message = (
                f"Function '{result.name}' has moderate estimated cost: "
                f"{result.total_cost} — complexity: {result.complexity_class}"
            )
            cppcheckdata.reportError(
                location, severity, message,
                ADDON_NAME, "moderateCostFunction",
                extra=result.complexity_class,
            )

        # ---- Loop-specific warnings ----
        for loop in result.loops:
            loop_loc = _make_location(
                loop.file_name or result.file,
                loop.line_number or result.line,
            )

            if loop.iteration_bound:
                bound_val = loop.iteration_bound.evaluate({})
                if bound_val >= WARN_LOOP_ITERATIONS:
                    cppcheckdata.reportError(
                        loop_loc, "performance",
                        f"Loop may iterate up to {loop.iteration_bound} times "
                        f"(≈{bound_val:.0f})",
                        ADDON_NAME, "highIterationLoop",
                    )
                elif loop.iteration_bound.kind == CostExprKind.INF:
                    cppcheckdata.reportError(
                        loop_loc, "warning",
                        f"Loop has unbounded iteration count — "
                        f"consider adding a bound or termination proof",
                        ADDON_NAME, "unboundedLoop",
                    )

        # ---- Recursive function warning ----
        if result.is_recursive:
            cppcheckdata.reportError(
                location, "style",
                f"Function '{result.name}' is recursive — "
                f"cost analysis may be imprecise without a depth bound",
                ADDON_NAME, "recursiveFunction",
            )

        # ---- Verbose output ----
        if verbose:
            sys.stderr.write(f"\n{'='*60}\n")
            sys.stderr.write(f"Function: {result.name}\n")
            sys.stderr.write(f"  File: {result.file}:{result.line}\n")
            sys.stderr.write(f"  Cost: {result.total_cost}\n")
            sys.stderr.write(f"  Complexity: {result.complexity_class}\n")
            sys.stderr.write(f"  Recursive: {result.is_recursive}\n")
            if result.callees:
                sys.stderr.write(f"  Callees: {', '.join(result.callees)}\n")
            if result.breakdown:
                sys.stderr.write(f"  Breakdown:\n")
                for cat, count in sorted(result.breakdown.items()):
                    sys.stderr.write(f"    {cat}: {count}\n")
            if result.loops:
                sys.stderr.write(f"  Loops:\n")
                for loop in result.loops:
                    sys.stderr.write(
                        f"    {loop.kind} at line {loop.line_number}: "
                        f"bound={loop.iteration_bound}, "
                        f"var={loop.counter_var}\n"
                    )
            if result.warnings:
                sys.stderr.write(f"  Warnings:\n")
                for w in result.warnings:
                    sys.stderr.write(f"    ⚠ {w}\n")

    # ---- Summary ----
    if results:
        summary = {
            "total_functions": len(results),
            "functions": [
                {
                    "name": r.name,
                    "cost": str(r.total_cost),
                    "complexity": r.complexity_class,
                    "recursive": r.is_recursive,
                    "loop_count": len(r.loops),
                }
                for r in results
            ],
        }
        cppcheckdata.reportSummary(dump_file, "costAnalysis", summary)


class _Location:
    """Minimal location object for cppcheckdata.reportError."""
    def __init__(self, file: str, linenr: int, column: int = 0):
        self.file = file
        self.linenr = linenr
        self.column = column


def _make_location(file: str, line: int) -> _Location:
    return _Location(file or "<unknown>", line or 0)


# ═══════════════════════════════════════════════════════════════════════════
#  PART 7 — MAIN ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════

def main():
    """
    Main entry point for the StaticCostAnalysis addon.

    Usage:
        python StaticCostAnalysis.py [--verbose] [--cli] file1.dump [file2.dump ...]
    """
    # Parse arguments
    verbose = "--verbose" in sys.argv or "-v" in sys.argv
    args = [a for a in sys.argv[1:] if not a.startswith("-")]

    if not args:
        sys.stderr.write(
            f"StaticCostAnalysis v{ADDON_VERSION}\n"
            f"Usage: {sys.argv[0]} [--verbose] [--cli] <file.dump> ...\n"
        )
        sys.exit(1)

    # Log checker registration
    cppcheckdata.log_checker("StaticCostAnalysis", ADDON_NAME)

    for dump_file in args:
        if not os.path.isfile(dump_file):
            sys.stderr.write(f"Error: file not found: {dump_file}\n")
            continue

        try:
            data = cppcheckdata.CppcheckData(dump_file)
        except Exception as e:
            sys.stderr.write(f"Error parsing {dump_file}: {e}\n")
            continue

        for cfg in data.iterconfigurations():
            if verbose:
                sys.stderr.write(
                    f"\n{'#'*60}\n"
                    f"# Analyzing configuration: {cfg.name}\n"
                    f"# Dump file: {dump_file}\n"
                    f"{'#'*60}\n"
                )

            # Primary analysis: AST-based cost analysis
            analyzer = FunctionCostAnalyzer(cfg)
            results = analyzer.analyze_all()

            # Optional: refine with abstract execution substrate
            refiner = AbstractExecCostRefiner(cfg)
            if refiner.available:
                for result in results:
                    for loop in result.loops:
                        refined = refiner.refine_loop_bound(loop)
                        loop.iteration_bound = refined
                # Re-compute costs with refined bounds
                # (In a production system, this would re-walk the CFG;
                #  here we just note the refinement.)

            # Report
            report_results(results, dump_file, verbose=verbose)


if __name__ == "__main__":
    main()
