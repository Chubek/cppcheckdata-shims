#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
casl/builtins.py
================

Built-in domains, functions, and predicates for CASL.

This module provides the standard library that CASL specifications can
reference without explicit definition.

Built-in Domains
----------------
Based on Møller & Schwartzbach chapters 4-6:

- **Sign** — {⊥, -, 0, +, ⊤} for sign analysis
- **Parity** — {⊥, Even, Odd, ⊤} for parity analysis
- **Interval** — [l, h] intervals with widening
- **Nullness** — {⊥, Null, NonNull, ⊤} for null pointer analysis
- **Taint** — {⊥, Untainted, Tainted, ⊤} for taint tracking
- **Initialized** — {⊥, Uninitialized, Initialized, ⊤}
- **Constant** — constant propagation lattice

Built-in Functions
------------------
- **Lattice operations**: join, meet, widen, leq
- **Set operations**: union, intersect, difference, member
- **Arithmetic**: eval_arith, abstract_arith
- **Predicates**: is_null, is_tainted, is_initialized, may_alias

Built-in Patterns
-----------------
Common code patterns for C/C++:
- **malloc-free**: memory allocation/deallocation
- **fopen-fclose**: file handle management
- **lock-unlock**: mutex operations
- **array-access**: array indexing
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import (
    Any,
    Callable,
    Dict,
    FrozenSet,
    Generic,
    List,
    Optional,
    Set,
    Tuple,
    TypeVar,
    Union,
)

__all__ = [
    # Domain definitions
    "BUILTIN_DOMAINS",
    "BUILTIN_FUNCTIONS",
    "BUILTIN_PATTERNS",
    # Sign domain
    "Sign",
    "SignLattice",
    # Parity domain
    "Parity",
    "ParityLattice",
    # Interval domain
    "Interval",
    "IntervalLattice",
    # Nullness domain
    "Nullness",
    "NullnessLattice",
    # Taint domain
    "Taint",
    "TaintLattice",
    # Initialized domain
    "Initialized",
    "InitializedLattice",
]


# ═══════════════════════════════════════════════════════════════════════════
# SIGN DOMAIN (§4.1 in Møller & Schwartzbach)
# ═══════════════════════════════════════════════════════════════════════════

class Sign(Enum):
    """Sign abstract domain elements."""
    
    BOTTOM = auto()  # ⊥ — no values
    NEG = auto()     # - — negative
    ZERO = auto()    # 0 — zero
    POS = auto()     # + — positive
    TOP = auto()     # ⊤ — any value
    
    def __str__(self) -> str:
        return {
            Sign.BOTTOM: "⊥",
            Sign.NEG: "-",
            Sign.ZERO: "0",
            Sign.POS: "+",
            Sign.TOP: "⊤",
        }[self]


class SignLattice:
    """Sign lattice operations."""
    
    @staticmethod
    def bottom() -> Sign:
        return Sign.BOTTOM
    
    @staticmethod
    def top() -> Sign:
        return Sign.TOP
    
    @staticmethod
    def leq(a: Sign, b: Sign) -> bool:
        """Lattice ordering: a ⊑ b"""
        if a == Sign.BOTTOM:
            return True
        if b == Sign.TOP:
            return True
        return a == b
    
    @staticmethod
    def join(a: Sign, b: Sign) -> Sign:
        """Least upper bound: a ⊔ b"""
        if a == Sign.BOTTOM:
            return b
        if b == Sign.BOTTOM:
            return a
        if a == b:
            return a
        return Sign.TOP
    
    @staticmethod
    def meet(a: Sign, b: Sign) -> Sign:
        """Greatest lower bound: a ⊓ b"""
        if a == Sign.TOP:
            return b
        if b == Sign.TOP:
            return a
        if a == b:
            return a
        return Sign.BOTTOM
    
    @staticmethod
    def abstract(n: int) -> Sign:
        """Abstract a concrete integer."""
        if n < 0:
            return Sign.NEG
        elif n == 0:
            return Sign.ZERO
        else:
            return Sign.POS
    
    @staticmethod
    def add(a: Sign, b: Sign) -> Sign:
        """Abstract addition."""
        if a == Sign.BOTTOM or b == Sign.BOTTOM:
            return Sign.BOTTOM
        if a == Sign.TOP or b == Sign.TOP:
            return Sign.TOP
        
        # Addition table
        table = {
            (Sign.NEG, Sign.NEG): Sign.NEG,
            (Sign.NEG, Sign.ZERO): Sign.NEG,
            (Sign.NEG, Sign.POS): Sign.TOP,
            (Sign.ZERO, Sign.NEG): Sign.NEG,
            (Sign.ZERO, Sign.ZERO): Sign.ZERO,
            (Sign.ZERO, Sign.POS): Sign.POS,
            (Sign.POS, Sign.NEG): Sign.TOP,
            (Sign.POS, Sign.ZERO): Sign.POS,
            (Sign.POS, Sign.POS): Sign.POS,
        }
        return table.get((a, b), Sign.TOP)
    
    @staticmethod
    def multiply(a: Sign, b: Sign) -> Sign:
        """Abstract multiplication."""
        if a == Sign.BOTTOM or b == Sign.BOTTOM:
            return Sign.BOTTOM
        if a == Sign.ZERO or b == Sign.ZERO:
            return Sign.ZERO
        if a == Sign.TOP or b == Sign.TOP:
            return Sign.TOP
        
        # Same sign -> positive, different -> negative
        if a == b:
            return Sign.POS
        return Sign.NEG


# ═══════════════════════════════════════════════════════════════════════════
# PARITY DOMAIN
# ═══════════════════════════════════════════════════════════════════════════

class Parity(Enum):
    """Parity abstract domain elements."""
    
    BOTTOM = auto()
    EVEN = auto()
    ODD = auto()
    TOP = auto()
    
    def __str__(self) -> str:
        return {
            Parity.BOTTOM: "⊥",
            Parity.EVEN: "Even",
            Parity.ODD: "Odd",
            Parity.TOP: "⊤",
        }[self]


class ParityLattice:
    """Parity lattice operations."""
    
    @staticmethod
    def bottom() -> Parity:
        return Parity.BOTTOM
    
    @staticmethod
    def top() -> Parity:
        return Parity.TOP
    
    @staticmethod
    def leq(a: Parity, b: Parity) -> bool:
        if a == Parity.BOTTOM:
            return True
        if b == Parity.TOP:
            return True
        return a == b
    
    @staticmethod
    def join(a: Parity, b: Parity) -> Parity:
        if a == Parity.BOTTOM:
            return b
        if b == Parity.BOTTOM:
            return a
        if a == b:
            return a
        return Parity.TOP
    
    @staticmethod
    def abstract(n: int) -> Parity:
        return Parity.EVEN if n % 2 == 0 else Parity.ODD
    
    @staticmethod
    def add(a: Parity, b: Parity) -> Parity:
        if a == Parity.BOTTOM or b == Parity.BOTTOM:
            return Parity.BOTTOM
        if a == Parity.TOP or b == Parity.TOP:
            return Parity.TOP
        # Even + Even = Even, Odd + Odd = Even, else Odd
        if a == b:
            return Parity.EVEN
        return Parity.ODD
    
    @staticmethod
    def multiply(a: Parity, b: Parity) -> Parity:
        if a == Parity.BOTTOM or b == Parity.BOTTOM:
            return Parity.BOTTOM
        if a == Parity.EVEN or b == Parity.EVEN:
            return Parity.EVEN
        if a == Parity.TOP or b == Parity.TOP:
            return Parity.TOP
        return Parity.ODD


# ═══════════════════════════════════════════════════════════════════════════
# INTERVAL DOMAIN (§6.1)
# ═══════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class Interval:
    """Interval abstract domain: [low, high] or ⊥."""
    
    low: Optional[int]   # None means -∞
    high: Optional[int]  # None means +∞
    is_bottom: bool = False
    
    @classmethod
    def bottom(cls) -> "Interval":
        return cls(None, None, is_bottom=True)
    
    @classmethod
    def top(cls) -> "Interval":
        return cls(None, None, is_bottom=False)
    
    @classmethod
    def const(cls, n: int) -> "Interval":
        return cls(n, n)
    
    @classmethod
    def range(cls, low: Optional[int], high: Optional[int]) -> "Interval":
        if low is not None and high is not None and low > high:
            return cls.bottom()
        return cls(low, high)
    
    def __str__(self) -> str:
        if self.is_bottom:
            return "⊥"
        lo = str(self.low) if self.low is not None else "-∞"
        hi = str(self.high) if self.high is not None else "+∞"
        return f"[{lo}, {hi}]"
    
    def contains(self, n: int) -> bool:
        if self.is_bottom:
            return False
        lo_ok = self.low is None or n >= self.low
        hi_ok = self.high is None or n <= self.high
        return lo_ok and hi_ok


class IntervalLattice:
    """Interval lattice operations with widening."""
    
    # Widening thresholds
    THRESHOLDS: List[int] = [-1000, -100, -10, -1, 0, 1, 10, 100, 1000]
    
    @staticmethod
    def bottom() -> Interval:
        return Interval.bottom()
    
    @staticmethod
    def top() -> Interval:
        return Interval.top()
    
    @staticmethod
    def leq(a: Interval, b: Interval) -> bool:
        if a.is_bottom:
            return True
        if b.is_bottom:
            return False
        
        lo_ok = b.low is None or (a.low is not None and a.low >= b.low)
        hi_ok = b.high is None or (a.high is not None and a.high <= b.high)
        return lo_ok and hi_ok
    
    @staticmethod
    def join(a: Interval, b: Interval) -> Interval:
        if a.is_bottom:
            return b
        if b.is_bottom:
            return a
        
        low = None
        if a.low is not None and b.low is not None:
            low = min(a.low, b.low)
        
        high = None
        if a.high is not None and b.high is not None:
            high = max(a.high, b.high)
        
        return Interval.range(low, high)
    
    @staticmethod
    def widen(a: Interval, b: Interval) -> Interval:
        """Widening with thresholds."""
        if a.is_bottom:
            return b
        if b.is_bottom:
            return a
        
        # Widen low bound
        low = a.low
        if b.low is not None and (a.low is None or b.low < a.low):
            # Find next threshold below b.low
            low = None
            for t in reversed(IntervalLattice.THRESHOLDS):
                if b.low >= t:
                    low = t
                    break
        
        # Widen high bound
        high = a.high
        if b.high is not None and (a.high is None or b.high > a.high):
            high = None
            for t in IntervalLattice.THRESHOLDS:
                if b.high <= t:
                    high = t
                    break
        
        return Interval.range(low, high)
    
    @staticmethod
    def add(a: Interval, b: Interval) -> Interval:
        if a.is_bottom or b.is_bottom:
            return Interval.bottom()
        
        low = None
        if a.low is not None and b.low is not None:
            low = a.low + b.low
        
        high = None
        if a.high is not None and b.high is not None:
            high = a.high + b.high
        
        return Interval.range(low, high)
    
    @staticmethod
    def multiply(a: Interval, b: Interval) -> Interval:
        if a.is_bottom or b.is_bottom:
            return Interval.bottom()
        
        if a.low is None or a.high is None or b.low is None or b.high is None:
            return Interval.top()
        
        # Compute all corner products
        corners = [
            a.low * b.low,
            a.low * b.high,
            a.high * b.low,
            a.high * b.high,
        ]
        return Interval.range(min(corners), max(corners))


# ═══════════════════════════════════════════════════════════════════════════
# NULLNESS DOMAIN (for pointer analysis)
# ═══════════════════════════════════════════════════════════════════════════

class Nullness(Enum):
    """Nullness abstract domain."""
    
    BOTTOM = auto()    # unreachable
    NULL = auto()      # definitely null
    NON_NULL = auto()  # definitely non-null
    TOP = auto()       # may be null or non-null
    
    def __str__(self) -> str:
        return {
            Nullness.BOTTOM: "⊥",
            Nullness.NULL: "Null",
            Nullness.NON_NULL: "NonNull",
            Nullness.TOP: "⊤",
        }[self]


class NullnessLattice:
    """Nullness lattice operations."""
    
    @staticmethod
    def bottom() -> Nullness:
        return Nullness.BOTTOM
    
    @staticmethod
    def top() -> Nullness:
        return Nullness.TOP
    
    @staticmethod
    def leq(a: Nullness, b: Nullness) -> bool:
        if a == Nullness.BOTTOM:
            return True
        if b == Nullness.TOP:
            return True
        return a == b
    
    @staticmethod
    def join(a: Nullness, b: Nullness) -> Nullness:
        if a == Nullness.BOTTOM:
            return b
        if b == Nullness.BOTTOM:
            return a
        if a == b:
            return a
        return Nullness.TOP


# ═══════════════════════════════════════════════════════════════════════════
# TAINT DOMAIN (for security analysis)
# ═══════════════════════════════════════════════════════════════════════════

class Taint(Enum):
    """Taint abstract domain for tracking untrusted data."""
    
    BOTTOM = auto()
    UNTAINTED = auto()  # safe, trusted data
    TAINTED = auto()    # potentially malicious
    TOP = auto()
    
    def __str__(self) -> str:
        return {
            Taint.BOTTOM: "⊥",
            Taint.UNTAINTED: "Untainted",
            Taint.TAINTED: "Tainted",
            Taint.TOP: "⊤",
        }[self]


class TaintLattice:
    """Taint lattice operations."""
    
    @staticmethod
    def bottom() -> Taint:
        return Taint.BOTTOM
    
    @staticmethod
    def top() -> Taint:
        return Taint.TOP
    
    @staticmethod
    def leq(a: Taint, b: Taint) -> bool:
        if a == Taint.BOTTOM:
            return True
        if b == Taint.TOP:
            return True
        return a == b
    
    @staticmethod
    def join(a: Taint, b: Taint) -> Taint:
        if a == Taint.BOTTOM:
            return b
        if b == Taint.BOTTOM:
            return a
        if a == b:
            return a
        return Taint.TOP
    
    @staticmethod
    def propagate(a: Taint, b: Taint) -> Taint:
        """Taint propagation: any tainted input taints output."""
        if a == Taint.TAINTED or b == Taint.TAINTED:
            return Taint.TAINTED
        return TaintLattice.join(a, b)


# ═══════════════════════════════════════════════════════════════════════════
# INITIALIZED DOMAIN (for uninitialized variable detection)
# ═══════════════════════════════════════════════════════════════════════════

class Initialized(Enum):
    """Initialization status domain."""
    
    BOTTOM = auto()
    UNINITIALIZED = auto()
    INITIALIZED = auto()
    TOP = auto()  # may be either
    
    def __str__(self) -> str:
        return {
            Initialized.BOTTOM: "⊥",
            Initialized.UNINITIALIZED: "Uninit",
            Initialized.INITIALIZED: "Init",
            Initialized.TOP: "⊤",
        }[self]


class InitializedLattice:
    """Initialization lattice operations."""
    
    @staticmethod
    def bottom() -> Initialized:
        return Initialized.BOTTOM
    
    @staticmethod
    def top() -> Initialized:
        return Initialized.TOP
    
    @staticmethod
    def leq(a: Initialized, b: Initialized) -> bool:
        if a == Initialized.BOTTOM:
            return True
        if b == Initialized.TOP:
            return True
        return a == b
    
    @staticmethod
    def join(a: Initialized, b: Initialized) -> Initialized:
        if a == Initialized.BOTTOM:
            return b
        if b == Initialized.BOTTOM:
            return a
        if a == b:
            return a
        return Initialized.TOP


# ═══════════════════════════════════════════════════════════════════════════
# REGISTRY EXPORTS
# ═══════════════════════════════════════════════════════════════════════════

BUILTIN_DOMAINS: Dict[str, Dict[str, Any]] = {
    "Sign": {
        "enum": Sign,
        "lattice": SignLattice,
        "complete": True,
        "has_widening": False,
    },
    "Parity": {
        "enum": Parity,
        "lattice": ParityLattice,
        "complete": True,
        "has_widening": False,
    },
    "Interval": {
        "class": Interval,
        "lattice": IntervalLattice,
        "complete": True,
        "has_widening": True,
    },
    "Nullness": {
        "enum": Nullness,
        "lattice": NullnessLattice,
        "complete": True,
        "has_widening": False,
    },
    "Taint": {
        "enum": Taint,
        "lattice": TaintLattice,
        "complete": True,
        "has_widening": False,
    },
    "Initialized": {
        "enum": Initialized,
        "lattice": InitializedLattice,
        "complete": True,
        "has_widening": False,
    },
}

BUILTIN_FUNCTIONS: Dict[str, Dict[str, Any]] = {
    # Lattice operations
    "join": {"arity": 2, "description": "Lattice join (⊔)"},
    "meet": {"arity": 2, "description": "Lattice meet (⊓)"},
    "widen": {"arity": 2, "description": "Widening operator"},
    "leq": {"arity": 2, "description": "Lattice ordering (⊑)"},
    
    # Set operations
    "union": {"arity": 2, "description": "Set union"},
    "intersect": {"arity": 2, "description": "Set intersection"},
    "difference": {"arity": 2, "description": "Set difference"},
    "member": {"arity": 2, "description": "Set membership"},
    "empty-set": {"arity": 0, "description": "Empty set"},
    "singleton": {"arity": 1, "description": "Singleton set"},
    
    # Map operations
    "lookup": {"arity": 2, "description": "Map lookup"},
    "update": {"arity": 3, "description": "Map update"},
    "empty-map": {"arity": 0, "description": "Empty map"},
    
    # Predicates
    "is-null": {"arity": 1, "description": "Check if nullness is Null or Top"},
    "is-tainted": {"arity": 1, "description": "Check if taint is Tainted or Top"},
    "is-initialized": {"arity": 1, "description": "Check if initialized"},
    "may-alias": {"arity": 2, "description": "Check potential aliasing"},
    
    # Abstract evaluation
    "eval-const": {"arity": 1, "description": "Evaluate constant expression"},
    "abstract-int": {"arity": 1, "description": "Abstract integer to domain"},
}

BUILTIN_PATTERNS: Dict[str, Dict[str, Any]] = {
    # Memory patterns
    "malloc-call": {
        "match": "(call ?fn ?size)",
        "where": "(?fn.name in ['malloc', 'calloc', 'realloc'])",
        "binds": {"fn": "Function", "size": "Token"},
    },
    "free-call": {
        "match": "(call ?fn ?ptr)",
        "where": "(?fn.name == 'free')",
        "binds": {"fn": "Function", "ptr": "Token"},
    },
    
    # File patterns
    "fopen-call": {
        "match": "(call ?fn ?path ?mode)",
        "where": "(?fn.name == 'fopen')",
        "binds": {"fn": "Function", "path": "Token", "mode": "Token"},
    },
    "fclose-call": {
        "match": "(call ?fn ?handle)",
        "where": "(?fn.name == 'fclose')",
        "binds": {"fn": "Function", "handle": "Token"},
    },
    
    # Lock patterns
    "mutex-lock": {
        "match": "(call ?fn ?mutex)",
        "where": "(?fn.name in ['pthread_mutex_lock', 'mtx_lock'])",
        "binds": {"fn": "Function", "mutex": "Token"},
    },
    "mutex-unlock": {
        "match": "(call ?fn ?mutex)",
        "where": "(?fn.name in ['pthread_mutex_unlock', 'mtx_unlock'])",
        "binds": {"fn": "Function", "mutex": "Token"},
    },
    
    # Array access
    "array-subscript": {
        "match": "(subscript ?array ?index)",
        "binds": {"array": "Token", "index": "Token"},
    },
    
    # Null dereference
    "pointer-deref": {
        "match": "(deref ?ptr)",
        "binds": {"ptr": "Token"},
    },
}
