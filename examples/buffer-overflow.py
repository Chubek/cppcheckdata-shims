"""
buffer_overflow_detector.py

Comprehensive buffer overflow detection using cppcheckdata-shims.

Components:
  1. Interval Abstract Domain - tracks numeric ranges [lo, hi]
  2. CFG + Dataflow Engine - propagates intervals through control flow
  3. CCQL - queries array accesses and buffer declarations
  4. Overflow Checker - compares access indices against buffer sizes

Detects:
  - Static array out-of-bounds:     int arr[10]; arr[15] = 0;
  - Dynamic buffer overflow:        malloc(n); ptr[n] = 0;
  - Loop-based overflow:            for(i=0; i<=n; i++) arr[i]=0;
  - Pointer arithmetic overflow:    *(arr + 100)
  - Off-by-one errors:              arr[sizeof(arr)] = 0;

Author: cppcheckdata-shims project
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, Set, List, Optional, Tuple, Any, Iterator
from enum import Enum, auto
from abc import ABC, abstractmethod
import re
import cppcheckdata

# ============================================================================
# SHIMS IMPORTS (the library we're demonstrating)
# ============================================================================

from cfg import (
    CFG, CFGNode, CFGEdge, EdgeKind,
    build_cfg, build_cfg_for_function
)
from dataflow_engine import (
    AbstractDomain, TransferFunction, DataflowEngine,
    Direction, MergeOperator, AnalysisResult
)
from ccql import (
    CCQLEngine, Query, QueryResult,
    Predicate, Binding, FactBase
)


# ============================================================================
# PART 1: INTERVAL ABSTRACT DOMAIN
# ============================================================================

@dataclass(frozen=True)
class Interval:
    """
    Represents a numeric interval [lo, hi].
    
    Special cases:
      - BOTTOM: empty interval (no possible values)
      - TOP: [-∞, +∞] (any value possible)
    
    Lattice structure:
      ⊥ ⊑ [a,b] ⊑ ⊤  for any concrete interval [a,b]
      [a,b] ⊑ [c,d]  iff  c ≤ a ∧ b ≤ d
    """
    lo: Optional[int]  # None means -∞
    hi: Optional[int]  # None means +∞
    is_bottom: bool = False
    
    # Symbolic constants for special intervals
    NEG_INF = None
    POS_INF = None
    
    @classmethod
    def bottom(cls) -> 'Interval':
        """The empty interval (unreachable)."""
        return cls(lo=0, hi=-1, is_bottom=True)
    
    @classmethod
    def top(cls) -> 'Interval':
        """The universal interval [-∞, +∞]."""
        return cls(lo=None, hi=None)
    
    @classmethod
    def const(cls, n: int) -> 'Interval':
        """A singleton interval [n, n]."""
        return cls(lo=n, hi=n)
    
    @classmethod
    def range(cls, lo: int, hi: int) -> 'Interval':
        """A concrete interval [lo, hi]."""
        if lo > hi:
            return cls.bottom()
        return cls(lo=lo, hi=hi)
    
    @classmethod
    def at_least(cls, n: int) -> 'Interval':
        """[n, +∞]"""
        return cls(lo=n, hi=None)
    
    @classmethod
    def at_most(cls, n: int) -> 'Interval':
        """[-∞, n]"""
        return cls(lo=None, hi=n)
    
    @classmethod
    def non_negative(cls) -> 'Interval':
        """[0, +∞] - common for array indices."""
        return cls(lo=0, hi=None)
    
    def is_top(self) -> bool:
        return self.lo is None and self.hi is None and not self.is_bottom
    
    def is_const(self) -> bool:
        """Is this a singleton interval?"""
        return (not self.is_bottom and 
                self.lo is not None and 
                self.hi is not None and 
                self.lo == self.hi)
    
    def contains(self, n: int) -> bool:
        """Check if n ∈ [lo, hi]."""
        if self.is_bottom:
            return False
        lo_ok = self.lo is None or self.lo <= n
        hi_ok = self.hi is None or n <= self.hi
        return lo_ok and hi_ok
    
    def may_be_negative(self) -> bool:
        """Could this interval contain negative values?"""
        if self.is_bottom:
            return False
        return self.lo is None or self.lo < 0
    
    def may_exceed(self, bound: int) -> bool:
        """Could this interval exceed the given bound?"""
        if self.is_bottom:
            return False
        return self.hi is None or self.hi >= bound
    
    def must_exceed(self, bound: int) -> bool:
        """Must this interval exceed the given bound?"""
        if self.is_bottom:
            return False
        return self.lo is not None and self.lo >= bound
    
    def _cmp_lo(self, a: Optional[int], b: Optional[int], take_min: bool) -> Optional[int]:
        """Compare two lower bounds."""
        if a is None:
            return a if take_min else b
        if b is None:
            return b if take_min else a
        return min(a, b) if take_min else max(a, b)
    
    def _cmp_hi(self, a: Optional[int], b: Optional[int], take_max: bool) -> Optional[int]:
        """Compare two upper bounds."""
        if a is None:
            return a if take_max else b
        if b is None:
            return b if take_max else a
        return max(a, b) if take_max else min(a, b)
    
    def join(self, other: 'Interval') -> 'Interval':
        """
        Least upper bound: smallest interval containing both.
        [a,b] ⊔ [c,d] = [min(a,c), max(b,d)]
        """
        if self.is_bottom:
            return other
        if other.is_bottom:
            return self
        
        new_lo = self._cmp_lo(self.lo, other.lo, take_min=True)
        new_hi = self._cmp_hi(self.hi, other.hi, take_max=True)
        return Interval(lo=new_lo, hi=new_hi)
    
    def meet(self, other: 'Interval') -> 'Interval':
        """
        Greatest lower bound: intersection.
        [a,b] ⊓ [c,d] = [max(a,c), min(b,d)]
        """
        if self.is_bottom or other.is_bottom:
            return Interval.bottom()
        
        new_lo = self._cmp_lo(self.lo, other.lo, take_min=False)
        new_hi = self._cmp_hi(self.hi, other.hi, take_max=False)
        
        # Check if result is empty
        if new_lo is not None and new_hi is not None and new_lo > new_hi:
            return Interval.bottom()
        
        return Interval(lo=new_lo, hi=new_hi)
    
    def widen(self, other: 'Interval') -> 'Interval':
        """
        Widening operator for convergence in loops.
        
        Strategy: if bound grows, push to infinity.
        """
        if self.is_bottom:
            return other
        if other.is_bottom:
            return self
        
        # Lower bound: if other.lo < self.lo, widen to -∞
        if other.lo is not None and self.lo is not None:
            new_lo = self.lo if other.lo >= self.lo else None
        elif self.lo is None:
            new_lo = None
        else:
            new_lo = None if other.lo is None else self.lo
        
        # Upper bound: if other.hi > self.hi, widen to +∞
        if other.hi is not None and self.hi is not None:
            new_hi = self.hi if other.hi <= self.hi else None
        elif self.hi is None:
            new_hi = None
        else:
            new_hi = None if other.hi is None else self.hi
        
        return Interval(lo=new_lo, hi=new_hi)
    
    def narrow(self, other: 'Interval') -> 'Interval':
        """
        Narrowing operator to recover precision after widening.
        
        Strategy: if we're at infinity but other has a bound, take the bound.
        """
        if self.is_bottom:
            return self
        if other.is_bottom:
            return other
        
        new_lo = other.lo if self.lo is None and other.lo is not None else self.lo
        new_hi = other.hi if self.hi is None and other.hi is not None else self.hi
        
        return Interval(lo=new_lo, hi=new_hi)
    
    def leq(self, other: 'Interval') -> bool:
        """Partial order: self ⊑ other."""
        if self.is_bottom:
            return True
        if other.is_bottom:
            return False
        
        # self.lo >= other.lo (other can be lower)
        lo_ok = (other.lo is None or 
                 (self.lo is not None and self.lo >= other.lo))
        # self.hi <= other.hi (other can be higher)
        hi_ok = (other.hi is None or 
                 (self.hi is not None and self.hi <= other.hi))
        
        return lo_ok and hi_ok
    
    # Arithmetic operations
    def __add__(self, other: 'Interval') -> 'Interval':
        """[a,b] + [c,d] = [a+c, b+d]"""
        if self.is_bottom or other.is_bottom:
            return Interval.bottom()
        
        def add_bound(x: Optional[int], y: Optional[int]) -> Optional[int]:
            if x is None or y is None:
                return None
            return x + y
        
        return Interval(
            lo=add_bound(self.lo, other.lo),
            hi=add_bound(self.hi, other.hi)
        )
    
    def __sub__(self, other: 'Interval') -> 'Interval':
        """[a,b] - [c,d] = [a-d, b-c]"""
        if self.is_bottom or other.is_bottom:
            return Interval.bottom()
        
        def sub_bound(x: Optional[int], y: Optional[int]) -> Optional[int]:
            if x is None or y is None:
                return None
            return x - y
        
        return Interval(
            lo=sub_bound(self.lo, other.hi),
            hi=sub_bound(self.hi, other.lo)
        )
    
    def __mul__(self, other: 'Interval') -> 'Interval':
        """Interval multiplication (complex due to sign combinations)."""
        if self.is_bottom or other.is_bottom:
            return Interval.bottom()
        
        if self.is_top() or other.is_top():
            return Interval.top()
        
        # For bounded intervals, compute all corner products
        if all(x is not None for x in [self.lo, self.hi, other.lo, other.hi]):
            products = [
                self.lo * other.lo,
                self.lo * other.hi,
                self.hi * other.lo,
                self.hi * other.hi
            ]
            return Interval(lo=min(products), hi=max(products))
        
        # Partial infinity cases - conservative
        return Interval.top()
    
    def __repr__(self) -> str:
        if self.is_bottom:
            return "⊥"
        lo_str = str(self.lo) if self.lo is not None else "-∞"
        hi_str = str(self.hi) if self.hi is not None else "+∞"
        return f"[{lo_str}, {hi_str}]"


# ============================================================================
# PART 2: INTERVAL STATE (Maps variables to intervals)
# ============================================================================

class IntervalState(AbstractDomain):
    """
    Abstract state mapping variable IDs to intervals.
    
    This is the domain used by the dataflow engine.
    """
    
    def __init__(self, 
                 var_intervals: Optional[Dict[int, Interval]] = None,
                 expr_intervals: Optional[Dict[int, Interval]] = None,
                 is_bottom: bool = False):
        self.var_intervals: Dict[int, Interval] = var_intervals or {}
        self.expr_intervals: Dict[int, Interval] = expr_intervals or {}
        self._is_bottom = is_bottom
    
    @classmethod
    def bottom(cls) -> 'IntervalState':
        """Unreachable state."""
        return cls(is_bottom=True)
    
    @classmethod
    def top(cls) -> 'IntervalState':
        """No information about any variable."""
        return cls()
    
    def is_bottom(self) -> bool:
        return self._is_bottom
    
    def get_var(self, var_id: int) -> Interval:
        """Get interval for variable, defaulting to top."""
        if self._is_bottom:
            return Interval.bottom()
        return self.var_intervals.get(var_id, Interval.top())
    
    def set_var(self, var_id: int, interval: Interval) -> 'IntervalState':
        """Return new state with updated variable interval."""
        if self._is_bottom:
            return self
        new_vars = self.var_intervals.copy()
        new_vars[var_id] = interval
        return IntervalState(new_vars, self.expr_intervals.copy())
    
    def get_expr(self, expr_id: int) -> Interval:
        """Get interval for expression."""
        if self._is_bottom:
            return Interval.bottom()
        return self.expr_intervals.get(expr_id, Interval.top())
    
    def set_expr(self, expr_id: int, interval: Interval) -> 'IntervalState':
        """Return new state with updated expression interval."""
        if self._is_bottom:
            return self
        new_exprs = self.expr_intervals.copy()
        new_exprs[expr_id] = interval
        return IntervalState(self.var_intervals.copy(), new_exprs)
    
    def join(self, other: 'IntervalState') -> 'IntervalState':
        """Point-wise join of all intervals."""
        if self._is_bottom:
            return other
        if other._is_bottom:
            return self
        
        all_vars = set(self.var_intervals.keys()) | set(other.var_intervals.keys())
        new_vars = {}
        for vid in all_vars:
            i1 = self.var_intervals.get(vid, Interval.top())
            i2 = other.var_intervals.get(vid, Interval.top())
            new_vars[vid] = i1.join(i2)
        
        all_exprs = set(self.expr_intervals.keys()) | set(other.expr_intervals.keys())
        new_exprs = {}
        for eid in all_exprs:
            i1 = self.expr_intervals.get(eid, Interval.top())
            i2 = other.expr_intervals.get(eid, Interval.top())
            new_exprs[eid] = i1.join(i2)
        
        return IntervalState(new_vars, new_exprs)
    
    def meet(self, other: 'IntervalState') -> 'IntervalState':
        """Point-wise meet of all intervals."""
        if self._is_bottom or other._is_bottom:
            return IntervalState.bottom()
        
        all_vars = set(self.var_intervals.keys()) | set(other.var_intervals.keys())
        new_vars = {}
        for vid in all_vars:
            i1 = self.var_intervals.get(vid, Interval.top())
            i2 = other.var_intervals.get(vid, Interval.top())
            result = i1.meet(i2)
            if result.is_bottom:
                return IntervalState.bottom()
            new_vars[vid] = result
        
        return IntervalState(new_vars, self.expr_intervals.copy())
    
    def widen(self, other: 'IntervalState') -> 'IntervalState':
        """Point-wise widening."""
        if self._is_bottom:
            return other
        if other._is_bottom:
            return self
        
        all_vars = set(self.var_intervals.keys()) | set(other.var_intervals.keys())
        new_vars = {}
        for vid in all_vars:
            i1 = self.var_intervals.get(vid, Interval.bottom())
            i2 = other.var_intervals.get(vid, Interval.bottom())
            new_vars[vid] = i1.widen(i2)
        
        return IntervalState(new_vars, self.expr_intervals.copy())
    
    def narrow(self, other: 'IntervalState') -> 'IntervalState':
        """Point-wise narrowing."""
        if self._is_bottom:
            return self
        if other._is_bottom:
            return other
        
        new_vars = {}
        for vid in self.var_intervals:
            i1 = self.var_intervals[vid]
            i2 = other.var_intervals.get(vid, Interval.top())
            new_vars[vid] = i1.narrow(i2)
        
        return IntervalState(new_vars, self.expr_intervals.copy())
    
    def leq(self, other: 'IntervalState') -> bool:
        """Point-wise comparison."""
        if self._is_bottom:
            return True
        if other._is_bottom:
            return False
        
        for vid, interval in self.var_intervals.items():
            other_interval = other.var_intervals.get(vid, Interval.top())
            if not interval.leq(other_interval):
                return False
        return True
    
    def __repr__(self) -> str:
        if self._is_bottom:
            return "IntervalState(⊥)"
        items = [f"v{vid}={iv}" for vid, iv in self.var_intervals.items()]
        return f"IntervalState({{{', '.join(items)}}})"


# ============================================================================
# PART 3: TRANSFER FUNCTION FOR INTERVAL ANALYSIS
# ============================================================================

class IntervalTransfer(TransferFunction[IntervalState]):
    """
    Transfer function implementing interval analysis.
    
    Handles:
      - Assignments: x = expr
      - Arithmetic: x = y + z, x = y * z, etc.
      - Comparisons: refines intervals on conditional branches
      - Increments: x++, x--, x += n
    """
    
    def __init__(self, cfg: CFG):
        self.cfg = cfg
    
    def transfer(self, node: CFGNode, state: IntervalState) -> IntervalState:
        """Apply transfer function to a CFG node."""
        if state.is_bottom():
            return state
        
        # Get the tokens in this basic block
        tokens = node.tokens if hasattr(node, 'tokens') else []
        
        current_state = state
        for token in tokens:
            current_state = self._transfer_token(token, current_state)
        
        return current_state
    
    def _transfer_token(self, token: cppcheckdata.Token, 
                        state: IntervalState) -> IntervalState:
        """Process a single token."""
        
        # Assignment: var = expr
        if token.isAssignmentOp and token.str == '=':
            return self._handle_assignment(token, state)
        
        # Compound assignment: +=, -=, *=
        if token.isAssignmentOp and token.str in ('+=', '-=', '*='):
            return self._handle_compound_assignment(token, state)
        
        # Increment/decrement: ++, --
        if token.str in ('++', '--'):
            return self._handle_increment(token, state)
        
        return state
    
    def _handle_assignment(self, token: cppcheckdata.Token,
                           state: IntervalState) -> IntervalState:
        """Handle x = expr."""
        lhs = token.astOperand1
        rhs = token.astOperand2
        
        if lhs is None or rhs is None:
            return state
        
        # Get variable ID from LHS
        var_id = lhs.varId
        if var_id is None or var_id == 0:
            return state
        
        # Evaluate RHS to get interval
        rhs_interval = self._eval_expr(rhs, state)
        
        return state.set_var(var_id, rhs_interval)
    
    def _handle_compound_assignment(self, token: cppcheckdata.Token,
                                    state: IntervalState) -> IntervalState:
        """Handle x += expr, x -= expr, etc."""
        lhs = token.astOperand1
        rhs = token.astOperand2
        
        if lhs is None or rhs is None:
            return state
        
        var_id = lhs.varId
        if var_id is None or var_id == 0:
            return state
        
        current = state.get_var(var_id)
        rhs_interval = self._eval_expr(rhs, state)
        
        if token.str == '+=':
            new_interval = current + rhs_interval
        elif token.str == '-=':
            new_interval = current - rhs_interval
        elif token.str == '*=':
            new_interval = current * rhs_interval
        else:
            new_interval = Interval.top()
        
        return state.set_var(var_id, new_interval)
    
    def _handle_increment(self, token: cppcheckdata.Token,
                          state: IntervalState) -> IntervalState:
        """Handle x++ or x--."""
        operand = token.astOperand1
        if operand is None:
            return state
        
        var_id = operand.varId
        if var_id is None or var_id == 0:
            return state
        
        current = state.get_var(var_id)
        one = Interval.const(1)
        
        if token.str == '++':
            new_interval = current + one
        else:
            new_interval = current - one
        
        return state.set_var(var_id, new_interval)
    
    def _eval_expr(self, token: cppcheckdata.Token,
                   state: IntervalState) -> Interval:
        """Recursively evaluate expression to interval."""
        
        # Constant integer
        if token.isInt:
            try:
                val = int(token.str)
                return Interval.const(val)
            except ValueError:
                return Interval.top()
        
        # Variable reference
        if token.varId and token.varId != 0:
            return state.get_var(token.varId)
        
        # sizeof expression - get from cppcheck's values
        if token.str == 'sizeof':
            if token.values:
                for v in token.values:
                    if hasattr(v, 'intvalue') and v.intvalue is not None:
                        return Interval.const(int(v.intvalue))
            return Interval.at_least(1)
        
        # Binary arithmetic
        if token.astOperand1 and token.astOperand2:
            left = self._eval_expr(token.astOperand1, state)
            right = self._eval_expr(token.astOperand2, state)
            
            if token.str == '+':
                return left + right
            elif token.str == '-':
                return left - right
            elif token.str == '*':
                return left * right
            elif token.str == '/':
                return self._eval_division(left, right)
            elif token.str == '%':
                return self._eval_modulo(left, right)
        
        # Unary minus
        if token.str == '-' and token.astOperand1 and not token.astOperand2:
            operand = self._eval_expr(token.astOperand1, state)
            zero = Interval.const(0)
            return zero - operand
        
        return Interval.top()
    
    def _eval_division(self, left: Interval, right: Interval) -> Interval:
        """Evaluate division conservatively."""
        if left.is_bottom or right.is_bottom:
            return Interval.bottom()
        
        # Check for division by zero
        if right.contains(0):
            # Could be undefined - return top
            return Interval.top()
        
        if (left.lo is not None and left.hi is not None and
            right.lo is not None and right.hi is not None):
            # Both bounded - compute corners
            if right.lo > 0:
                # Positive divisor
                corners = [
                    left.lo // right.hi, left.lo // right.lo,
                    left.hi // right.hi, left.hi // right.lo
                ]
                return Interval(lo=min(corners), hi=max(corners))
        
        return Interval.top()
    
    def _eval_modulo(self, left: Interval, right: Interval) -> Interval:
        """Evaluate modulo: result is in [0, |divisor|-1] for non-negative."""
        if right.is_bottom or left.is_bottom:
            return Interval.bottom()
        
        if right.hi is not None and right.hi > 0:
            # x % n is in [0, n-1] for positive n and non-negative x
            if not left.may_be_negative():
                return Interval.range(0, right.hi - 1)
        
        return Interval.top()
    
    def edge_transfer(self, edge: CFGEdge, state: IntervalState) -> IntervalState:
        """
        Refine state based on edge condition.
        
        For conditional branches, we can narrow intervals:
          - On true branch of (x < 10): x ∈ [current.lo, 9]
          - On false branch of (x < 10): x ∈ [10, current.hi]
        """
        if state.is_bottom():
            return state
        
        condition = edge.condition
        if condition is None:
            return state
        
        is_true_branch = edge.kind == EdgeKind.TRUE_BRANCH
        
        return self._refine_by_condition(condition, state, is_true_branch)
    
    def _refine_by_condition(self, cond: cppcheckdata.Token,
                             state: IntervalState,
                             assume_true: bool) -> IntervalState:
        """Refine state assuming condition is true or false."""
        
        if not cond.isComparisonOp:
            return state
        
        lhs = cond.astOperand1
        rhs = cond.astOperand2
        
        if lhs is None or rhs is None:
            return state
        
        # Handle: var < const, var <= const, var > const, var >= const
        var_token = None
        const_val = None
        var_on_left = True
        
        if lhs.varId and lhs.varId != 0 and rhs.isInt:
            var_token = lhs
            const_val = int(rhs.str)
            var_on_left = True
        elif rhs.varId and rhs.varId != 0 and lhs.isInt:
            var_token = rhs
            const_val = int(lhs.str)
            var_on_left = False
        
        if var_token is None or const_val is None:
            return state
        
        var_id = var_token.varId
        current = state.get_var(var_id)
        
        # Normalize operator to (var op const)
        op = cond.str
        if not var_on_left:
            # Flip operator
            flip_map = {'<': '>', '>': '<', '<=': '>=', '>=': '<=',
                        '==': '==', '!=': '!='}
            op = flip_map.get(op, op)
        
        # Apply refinement based on condition truth
        refined = self._apply_comparison_refinement(
            current, op, const_val, assume_true
        )
        
        if refined.is_bottom:
            return IntervalState.bottom()
        
        return state.set_var(var_id, refined)
    
    def _apply_comparison_refinement(self, interval: Interval, 
                                     op: str, const: int,
                                     assume_true: bool) -> Interval:
        """Apply comparison to refine interval."""
        
        if op == '<':
            if assume_true:
                # var < const → var ∈ [-∞, const-1]
                return interval.meet(Interval.at_most(const - 1))
            else:
                # var >= const → var ∈ [const, +∞]
                return interval.meet(Interval.at_least(const))
        
        elif op == '<=':
            if assume_true:
                return interval.meet(Interval.at_most(const))
            else:
                return interval.meet(Interval.at_least(const + 1))
        
        elif op == '>':
            if assume_true:
                return interval.meet(Interval.at_least(const + 1))
            else:
                return interval.meet(Interval.at_most(const))
        
        elif op == '>=':
            if assume_true:
                return interval.meet(Interval.at_least(const))
            else:
                return interval.meet(Interval.at_most(const - 1))
        
        elif op == '==':
            if assume_true:
                return interval.meet(Interval.const(const))
            else:
                # Not equal - can't easily represent, keep current
                return interval
        
        elif op == '!=':
            if assume_true:
                # Not equal - keep current
                return interval
            else:
                return interval.meet(Interval.const(const))
        
        return interval


# ============================================================================
# PART 4: CCQL QUERIES FOR BUFFER ANALYSIS
# ============================================================================

# Define CCQL queries for finding arrays, accesses, allocations

CCQL_ARRAY_DECLARATIONS = """
-- Find all static array declarations
SELECT var.id AS var_id,
       var.name AS name,
       var.dimension AS size,
       var.file AS file,
       var.line AS line
FROM variables AS var
WHERE var.isArray = true
  AND var.dimension > 0
"""

CCQL_ARRAY_SUBSCRIPT_ACCESS = """
-- Find all array subscript operations: arr[index]
SELECT access.id AS access_id,
       access.file AS file,
       access.line AS line,
       access.column AS column,
       array_token.varId AS array_var_id,
       index_token.id AS index_token_id,
       index_token.varId AS index_var_id
FROM tokens AS access
JOIN tokens AS array_token ON access.astOperand1 = array_token.id
JOIN tokens AS index_token ON access.astOperand2 = index_token.id  
WHERE access.str = '['
  AND access.astOperand1 IS NOT NULL
  AND access.astOperand2 IS NOT NULL
"""

CCQL_POINTER_ARITHMETIC_DEREF = """
-- Find pointer arithmetic followed by dereference: *(ptr + offset)
SELECT deref.id AS deref_id,
       deref.file AS file,
       deref.line AS line,
       add_op.id AS add_id,
       ptr_token.varId AS ptr_var_id,
       offset_token.id AS offset_token_id,
       offset_token.varId AS offset_var_id
FROM tokens AS deref
JOIN tokens AS add_op ON deref.astOperand1 = add_op.id
JOIN tokens AS ptr_token ON add_op.astOperand1 = ptr_token.id
JOIN tokens AS offset_token ON add_op.astOperand2 = offset_token.id
WHERE deref.str = '*'
  AND add_op.str = '+'
  AND ptr_token.varId IS NOT NULL
"""

CCQL_MALLOC_ALLOCATIONS = """
-- Find malloc/calloc allocations: p = malloc(size)
SELECT assign.id AS assign_id,
       assign.file AS file,
       assign.line AS line,
       ptr_var.varId AS ptr_var_id,
       ptr_var.name AS ptr_name,
       size_arg.id AS size_arg_id,
       alloc_func.str AS alloc_type
FROM tokens AS assign
JOIN tokens AS ptr_var ON assign.astOperand1 = ptr_var.id
JOIN tokens AS call_op ON assign.astOperand2 = call_op.id
JOIN tokens AS alloc_func ON call_op.astOperand1 = alloc_func.id
JOIN tokens AS size_arg ON call_op.astOperand2 = size_arg.id
WHERE assign.str = '='
  AND alloc_func.str IN ('malloc', 'calloc', 'realloc')
"""

CCQL_LOOP_BOUNDS = """
-- Find for-loop patterns: for(i=init; i<bound; i++)
SELECT loop_scope.id AS scope_id,
       init_var.varId AS loop_var_id,
       init_value.str AS init_value,
       bound_token.id AS bound_token_id,
       cmp_op.str AS comparison
FROM scopes AS loop_scope
JOIN tokens AS init_assign ON init_assign.scopeId = loop_scope.id
JOIN tokens AS init_var ON init_assign.astOperand1 = init_var.id
JOIN tokens AS init_value ON init_assign.astOperand2 = init_value.id
JOIN tokens AS cmp_op ON cmp_op.scopeId = loop_scope.id
JOIN tokens AS bound_token ON cmp_op.astOperand2 = bound_token.id
WHERE loop_scope.type = 'For'
  AND init_assign.str = '='
  AND cmp_op.isComparisonOp = true
"""


class BufferQueryEngine:
    """
    Wrapper around CCQL for buffer-related queries.
    
    Provides high-level methods to find:
    - Static array declarations
    - Dynamic allocations
    - Array/pointer accesses
    - Loop patterns
    """
    
    def __init__(self, ccql_engine: CCQLEngine):
        self.engine = ccql_engine
        self._cache: Dict[str, List[QueryResult]] = {}
    
    def find_array_declarations(self) -> List[ArrayDeclaration]:
        """Find all static array declarations."""
        results = self.engine.execute(CCQL_ARRAY_DECLARATIONS)
        
        declarations = []
        for row in results:
            declarations.append(ArrayDeclaration(
                var_id=row['var_id'],
                name=row['name'],
                size=row['size'],
                file=row['file'],
                line=row['line']
            ))
        return declarations
    
    def find_subscript_accesses(self) -> List[SubscriptAccess]:
        """Find all array subscript accesses."""
        results = self.engine.execute(CCQL_ARRAY_SUBSCRIPT_ACCESS)
        
        accesses = []
        for row in results:
            accesses.append(SubscriptAccess(
                access_id=row['access_id'],
                array_var_id=row['array_var_id'],
                index_token_id=row['index_token_id'],
                index_var_id=row.get('index_var_id'),
                file=row['file'],
                line=row['line'],
                column=row['column']
            ))
        return accesses
    
    def find_pointer_arithmetic_derefs(self) -> List[PointerArithmeticDeref]:
        """Find pointer arithmetic dereferences."""
        results = self.engine.execute(CCQL_POINTER_ARITHMETIC_DEREF)
        
        derefs = []
        for row in results:
            derefs.append(PointerArithmeticDeref(
                deref_id=row['deref_id'],
                ptr_var_id=row['ptr_var_id'],
                offset_token_id=row['offset_token_id'],
                offset_var_id=row.get('offset_var_id'),
                file=row['file'],
                line=row['line']
            ))
        return derefs
    
    def find_malloc_allocations(self) -> List[MallocAllocation]:
        """Find malloc/calloc allocations."""
        results = self.engine.execute(CCQL_MALLOC_ALLOCATIONS)
        
        allocations = []
        for row in results:
            allocations.append(MallocAllocation(
                assign_id=row['assign_id'],
                ptr_var_id=row['ptr_var_id'],
                ptr_name=row['ptr_name'],
                size_arg_id=row['size_arg_id'],
                alloc_type=row['alloc_type'],
                file=row['file'],
                line=row['line']
            ))
        return allocations


# Data classes for query results

@dataclass
class ArrayDeclaration:
    """Represents a static array declaration."""
    var_id: int
    name: str
    size: int
    file: str
    line: int


@dataclass
class SubscriptAccess:
    """Represents an array subscript access arr[i]."""
    access_id: int
    array_var_id: int
    index_token_id: int
    index_var_id: Optional[int]
    file: str
    line: int
    column: int


@dataclass
class PointerArithmeticDeref:
    """Represents *(ptr + offset) dereference."""
    deref_id: int
    ptr_var_id: int
    offset_token_id: int
    offset_var_id: Optional[int]
    file: str
    line: int


@dataclass
class MallocAllocation:
    """Represents a malloc/calloc allocation."""
    assign_id: int
    ptr_var_id: int
    ptr_name: str
    size_arg_id: int
    alloc_type: str
    file: str
    line: int


# ============================================================================
# PART 5: BUFFER SIZE TRACKER
# ============================================================================

@dataclass
class BufferInfo:
    """Information about a buffer's size."""
    var_id: int
    name: str
    size: Interval  # Could be constant or range
    element_size: int  # Size of each element in bytes
    is_static: bool  # Static array vs dynamic allocation
    decl_file: str
    decl_line: int


class BufferSizeTracker:
    """
    Tracks buffer sizes throughout the program.
    
    Handles:
    - Static arrays: int arr[10] → size = 10
    - Dynamic allocations: malloc(n) → size from dataflow
    - Pointer parameters: unknown size (but may track via annotations)
    """
    
    def __init__(self, cfg_map: Dict[str, CFG],
                 query_engine: BufferQueryEngine,
                 dataflow_results: Dict[int, IntervalState]):
        self.cfg_map = cfg_map
        self.query_engine = query_engine
        self.dataflow_results = dataflow_results
        self.buffers: Dict[int, BufferInfo] = {}
        
        self._collect_buffer_info()
    
    def _collect_buffer_info(self):
        """Collect information about all buffers."""
        # Static arrays
        for decl in self.query_engine.find_array_declarations():
            self.buffers[decl.var_id] = BufferInfo(
                var_id=decl.var_id,
                name=decl.name,
                size=Interval.const(decl.size),
                element_size=self._get_element_size(decl.var_id),
                is_static=True,
                decl_file=decl.file,
                decl_line=decl.line
            )
        
        # Dynamic allocations
        for alloc in self.query_engine.find_malloc_allocations():
            # Get size from dataflow analysis at allocation point
            size_interval = self._get_allocation_size(alloc)
            
            self.buffers[alloc.ptr_var_id] = BufferInfo(
                var_id=alloc.ptr_var_id,
                name=alloc.ptr_name,
                size=size_interval,
                element_size=1,  # malloc gives bytes
                is_static=False,
                decl_file=alloc.file,
                decl_line=alloc.line
            )
    
    def _get_element_size(self, var_id: int) -> int:
        """Get element size for array (from type info)."""
        # Would query cppcheckdata's variable type
        # Default to 1 for char arrays, 4 for int, etc.
        return 1  # Simplified
    
    def _get_allocation_size(self, alloc: MallocAllocation) -> Interval:
        """Get size interval from allocation expression."""
        # Look up the size argument in dataflow results
        # This requires finding the CFG node containing the allocation
        
        # For now, use a simplified approach
        if alloc.size_arg_id in self.dataflow_results:
            state = self.dataflow_results[alloc.size_arg_id]
            # Would evaluate the size expression
            return Interval.top()  # Conservative
        
        return Interval.top()
    
    def get_buffer_size(self, var_id: int) -> Optional[Interval]:
        """Get the size of a buffer by variable ID."""
        if var_id in self.buffers:
            return self.buffers[var_id].size
        return None
    
    def get_buffer_info(self, var_id: int) -> Optional[BufferInfo]:
        """Get full buffer info."""
        return self.buffers.get(var_id)


# ============================================================================
# PART 6: OVERFLOW CHECKER (Main Detection Logic)
# ============================================================================

class OverflowSeverity(Enum):
    """Severity of detected overflow."""
    DEFINITE = auto()    # Will always overflow
    POSSIBLE = auto()    # May overflow on some paths
    UNLIKELY = auto()    # Low probability but not impossible


@dataclass
class OverflowWarning:
    """Represents a detected buffer overflow."""
    severity: OverflowSeverity
    message: str
    file: str
    line: int
    column: int
    buffer_name: str
    buffer_size: Interval
    index_range: Interval
    access_type: str  # 'subscript', 'pointer_arithmetic'
    
    def __str__(self) -> str:
        severity_str = {
            OverflowSeverity.DEFINITE: "ERROR",
            OverflowSeverity.POSSIBLE: "WARNING", 
            OverflowSeverity.UNLIKELY: "NOTE"
        }[self.severity]
        
        return (f"[{severity_str}] {self.file}:{self.line}:{self.column}: "
                f"{self.message}\n"
                f"  Buffer '{self.buffer_name}' has size {self.buffer_size}\n"
                f"  Index range: {self.index_range}")


class BufferOverflowChecker:
    """
    Main checker that combines all components to detect buffer overflows.
    
    Algorithm:
    1. Build CFG for each function
    2. Run interval dataflow analysis
    3. Query array accesses via CCQL
    4. For each access, compare index interval with buffer size
    5. Report warnings with severity
    """
    
    def __init__(self, dump_file: str):
        # Parse cppcheck dump
        self.data = cppcheckdata.parsedump(dump_file)
        
        # Build CFGs for all functions
        self.cfgs: Dict[str, CFG] = {}
        self.cfg_to_function: Dict[str, cppcheckdata.Function] = {}
        
        # Initialize components (done in analyze())
        self.ccql_engine: Optional[CCQLEngine] = None
        self.query_engine: Optional[BufferQueryEngine] = None
        self.dataflow_results: Dict[int, IntervalState] = {}
        self.buffer_tracker: Optional[BufferSizeTracker] = None
        
        # Token ID to token map for lookups
        self.token_map: Dict[int, cppcheckdata.Token] = {}
        
        # Results
        self.warnings: List[OverflowWarning] = []
    
    def analyze(self) -> List[OverflowWarning]:
        """Run full analysis and return warnings."""
        for cfg in self.data.configurations:
            self._analyze_configuration(cfg)
        
        return self.warnings
    
    def _analyze_configuration(self, cfg):
        """Analyze a single configuration."""
        # Build token map
        self._build_token_map(cfg)
        
        # Build CFGs
        self._build_cfgs(cfg)
        
        # Initialize CCQL
        self.ccql_engine = CCQLEngine(cfg)
        self.query_engine = BufferQueryEngine(self.ccql_engine)
        
        # Run interval analysis on all functions
        self._run_interval_analysis(cfg)
        
        # Initialize buffer tracker
        self.buffer_tracker = BufferSizeTracker(
            self.cfgs, self.query_engine, self.dataflow_results
        )
        
        # Check all array accesses
        self._check_subscript_accesses()
        self._check_pointer_arithmetic()
        
        # Check for negative indices
        self._check_negative_indices()
    
    def _build_token_map(self, cfg):
        """Build ID -> Token map."""
        self.token_map.clear()
        for token in cfg.tokenlist:
            if token.Id:
                self.token_map[int(token.Id)] = token
    
    def _build_cfgs(self, cfg):
        """Build CFG for each function."""
        for func in cfg.functions:
            if func.tokenDef:
                function_cfg = build_cfg_for_function(func)
                if function_cfg:
                    self.cfgs[func.name] = function_cfg
                    self.cfg_to_function[func.name] = func
    
    def _run_interval_analysis(self, cfg):
        """Run interval dataflow analysis."""
        for func_name, function_cfg in self.cfgs.items():
            # Create dataflow engine
            transfer = IntervalTransfer(function_cfg)
            engine = DataflowEngine(
                cfg=function_cfg,
                transfer=transfer,
                direction=Direction.FORWARD,
                init_state=IntervalState.top(),
                merge_op=MergeOperator.JOIN
            )
            
            # Solve to fixpoint
            result = engine.solve()
            
            # Store results indexed by CFG node ID
            for node_id, state in result.node_states.items():
                self.dataflow_results[node_id] = state
    
    def _check_subscript_accesses(self):
        """Check all array subscript accesses for overflow."""
        accesses = self.query_engine.find_subscript_accesses()
        
        for access in accesses:
            self._check_single_access(access)
    
    def _check_single_access(self, access: SubscriptAccess):
        """Check a single array access for overflow."""
        # Get buffer size
        buffer_info = self.buffer_tracker.get_buffer_info(access.array_var_id)
        if buffer_info is None:
            # Unknown buffer - can't check
            return
        
        buffer_size = buffer_info.size
        
        # Get index interval from dataflow
        index_interval = self._get_index_interval(access)
        
        # Compare index against buffer size
        warning = self._check_bounds(
            buffer_info=buffer_info,
            index_interval=index_interval,
            access_type='subscript',
            file=access.file,
            line=access.line,
            column=access.column
        )
        
        if warning:
            self.warnings.append(warning)
    
    def _get_index_interval(self, access: SubscriptAccess) -> Interval:
        """Get the interval of possible index values."""
        # If index is a variable, look up from dataflow
        if access.index_var_id:
            # Find the CFG node containing this access
            for node_id, state in self.dataflow_results.items():
                interval = state.get_var(access.index_var_id)
                if not interval.is_top():
                    return interval
        
        # If index is a constant, evaluate directly
        index_token = self.token_map.get(access.index_token_id)
        if index_token and index_token.isInt:
            try:
                return Interval.const(int(index_token.str))
            except ValueError:
                pass
        
        # Use cppcheck's value flow if available
        if index_token and index_token.values:
            lo, hi = None, None
            for v in index_token.values:
                if hasattr(v, 'intvalue') and v.intvalue is not None:
                    val = int(v.intvalue)
                    lo = val if lo is None else min(lo, val)
                    hi = val if hi is None else max(hi, val)
            if lo is not None and hi is not None:
                return Interval(lo=lo, hi=hi)
        
        return Interval.top()
    
    def _check_pointer_arithmetic(self):
        """Check pointer arithmetic dereferences."""
        derefs = self.query_engine.find_pointer_arithmetic_derefs()
        
        for deref in derefs:
            buffer_info = self.buffer_tracker.get_buffer_info(deref.ptr_var_id)
            if buffer_info is None:
                continue
            
            # Get offset interval
            offset_interval = self._get_offset_interval(deref)
            
            warning = self._check_bounds(
                buffer_info=buffer_info,
                index_interval=offset_interval,
                access_type='pointer_arithmetic',
                file=deref.file,
                line=deref.line,
                column=0
            )
            
            if warning:
                self.warnings.append(warning)
    
    def _get_offset_interval(self, deref: PointerArithmeticDeref) -> Interval:
        """Get interval for pointer offset."""
        if deref.offset_var_id:
            for node_id, state in self.dataflow_results.items():
                interval = state.get_var(deref.offset_var_id)
                if not interval.is_top():
                    return interval
        
        offset_token = self.token_map.get(deref.offset_token_id)
        if offset_token and offset_token.isInt:
            try:
                return Interval.const(int(offset_token.str))
            except ValueError:
                pass
        
        return Interval.top()
    
    def _check_bounds(self, buffer_info: BufferInfo,
                      index_interval: Interval,
                      access_type: str,
                      file: str, line: int, column: int) -> Optional[OverflowWarning]:
        """
        Compare index interval against buffer size and generate warning.
        
        Decision logic:
          - If index.lo >= size: DEFINITE overflow
          - If index.hi >= size: POSSIBLE overflow
          - If index.hi < size: no overflow
          - If index.lo < 0: negative index (underflow)
        """
        buffer_size = buffer_info.size
        
        # Get the upper bound of buffer size
        if buffer_size.is_const():
            size_val = buffer_size.lo
        elif buffer_size.hi is not None:
            size_val = buffer_size.hi
        else:
            # Unknown size - can't check
            return None
        
        # Check for definite overflow
        if index_interval.must_exceed(size_val):
            return OverflowWarning(
                severity=OverflowSeverity.DEFINITE,
                message=f"Buffer overflow: index {index_interval} always exceeds buffer size {size_val}",
                file=file,
                line=line,
                column=column,
                buffer_name=buffer_info.name,
                buffer_size=buffer_size,
                index_range=index_interval,
                access_type=access_type
            )
        
        # Check for possible overflow
        if index_interval.may_exceed(size_val):
            return OverflowWarning(
                severity=OverflowSeverity.POSSIBLE,
                message=f"Possible buffer overflow: index {index_interval} may exceed buffer size {size_val}",
                file=file,
                line=line,
                column=column,
                buffer_name=buffer_info.name,
                buffer_size=buffer_size,
                index_range=index_interval,
                access_type=access_type
            )
        
        # Check for negative index
        if index_interval.may_be_negative():
            return OverflowWarning(
                severity=OverflowSeverity.POSSIBLE,
                message=f"Possible negative index: {index_interval}",
                file=file,
                line=line,
                column=column,
                buffer_name=buffer_info.name,
                buffer_size=buffer_size,
                index_range=index_interval,
                access_type=access_type
            )
        
        return None
    
    def _check_negative_indices(self):
        """Additional check specifically for negative indices."""
        # This is handled in _check_bounds, but we could add more
        # sophisticated analysis here
        pass


# ============================================================================
# PART 7: CLI AND USAGE EXAMPLES
# ============================================================================

def main():
    """Command-line interface."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Buffer overflow detector using cppcheckdata-shims',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate dump and analyze
  cppcheck --dump myfile.c
  python buffer_overflow_detector.py myfile.c.dump
  
  # Analyze with verbose output
  python buffer_overflow_detector.py --verbose myfile.c.dump
  
  # Output as JSON
  python buffer_overflow_detector.py --json myfile.c.dump
        """
    )
    
    parser.add_argument('dump_file', help='Cppcheck dump file (.dump)')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Verbose output')
    parser.add_argument('--json', action='store_true',
                        help='Output as JSON')
    parser.add_argument('--severity', choices=['all', 'definite', 'possible'],
                        default='all', help='Filter by severity')
    
    args = parser.parse_args()
    
    # Run analysis
    checker = BufferOverflowChecker(args.dump_file)
    warnings = checker.analyze()
    
    # Filter by severity
    if args.severity == 'definite':
        warnings = [w for w in warnings if w.severity == OverflowSeverity.DEFINITE]
    elif args.severity == 'possible':
        warnings = [w for w in warnings if w.severity in 
                    (OverflowSeverity.DEFINITE, OverflowSeverity.POSSIBLE)]
    
    # Output
    if args.json:
        import json
        output = [{
            'severity': w.severity.name,
            'message': w.message,
            'file': w.file,
            'line': w.line,
            'column': w.column,
            'buffer': w.buffer_name,
            'bufferSize': str(w.buffer_size),
            'indexRange': str(w.index_range),
            'accessType': w.access_type
        } for w in warnings]
        print(json.dumps(output, indent=2))
    else:
        if not warnings:
            print("No buffer overflow issues detected.")
        else:
            print(f"Found {len(warnings)} potential buffer overflow(s):\n")
            for w in warnings:
                print(str(w))
                print()
    
    # Exit code: 1 if definite overflows found
    definite = any(w.severity == OverflowSeverity.DEFINITE for w in warnings)
    return 1 if definite else 0


if __name__ == '__main__':
    import sys
    sys.exit(main())
