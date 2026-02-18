#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cppcheckdata_shims/taint_analysis.py
════════════════════════════════════

Taint analysis framework for tracking information flow in C/C++ programs.

Taint analysis is a form of information flow analysis that tracks how data
from untrusted sources (e.g., user input) propagates through a program to
sensitive sinks (e.g., system calls, SQL queries). This is fundamental for
detecting security vulnerabilities such as:

    • SQL Injection (CWE-89)
    • Command Injection (CWE-78)
    • Path Traversal (CWE-22)
    • Cross-Site Scripting (CWE-79)
    • Format String Vulnerabilities (CWE-134)
    • Buffer Overflows from untrusted sizes (CWE-120)

Architecture Overview
─────────────────────

    ┌─────────────────────────────────────────────────────────────────┐
    │                        TAINT LATTICE                            │
    │                                                                 │
    │                             ⊤                                   │
    │                        (Unknown)                                │
    │                        /       \                                │
    │                   Tainted    Untainted                          │
    │                        \       /                                │
    │                             ⊥                                   │
    │                       (Unreachable)                             │
    └─────────────────────────────────────────────────────────────────┘

    ┌─────────────────────────────────────────────────────────────────┐
    │                     ANALYSIS PIPELINE                           │
    │                                                                 │
    │   1. Configure sources, sinks, sanitizers, propagators          │
    │   2. Build CFG for each function                                │
    │   3. Run forward dataflow analysis                              │
    │   4. At each sink, check if reaching taint is unsanitized       │
    │   5. Report vulnerabilities with taint flow paths               │
    └─────────────────────────────────────────────────────────────────┘

Key Components
──────────────

TaintValue
    Represents the taint state of a single value (Tainted, Untainted,
    Unknown, or Bottom).

TaintState
    Maps variables/memory locations to their taint values. Represents
    the abstract state at a program point.

TaintSource
    Specification of where tainted data enters the program (e.g.,
    return value of `gets()`, parameters of `main()`).

TaintSink
    Specification of sensitive operations where tainted data is
    dangerous (e.g., arguments to `system()`, format strings).

TaintSanitizer
    Specification of operations that remove taint (e.g., validation
    functions, encoding functions).

TaintPropagator
    Specification of how taint flows through operations (e.g., taint
    propagates through string concatenation).

TaintConfig
    Complete configuration combining sources, sinks, sanitizers, and
    propagators.

TaintAnalyzer
    The main analysis engine that performs taint tracking.

TaintViolation
    A detected vulnerability: tainted data reaching a sink without
    proper sanitization.

Usage Example
─────────────

    from cppcheckdata_shims.taint_analysis import (
        TaintAnalyzer, TaintConfig, TaintSource, TaintSink,
        TaintSanitizer, SourceKind, SinkKind,
    )

    # Configure the analysis
    config = TaintConfig()

    # User input functions are sources
    config.add_source(TaintSource(
        function="gets",
        kind=SourceKind.RETURN_VALUE,
        description="User input from stdin"
    ))
    config.add_source(TaintSource(
        function="getenv",
        kind=SourceKind.RETURN_VALUE,
        description="Environment variable"
    ))

    # System functions are sinks
    config.add_sink(TaintSink(
        function="system",
        argument_index=0,
        kind=SinkKind.COMMAND_INJECTION,
        description="Command execution"
    ))
    config.add_sink(TaintSink(
        function="execve",
        argument_index=0,
        kind=SinkKind.COMMAND_INJECTION,
        description="Program execution"
    ))

    # Validation functions sanitize
    config.add_sanitizer(TaintSanitizer(
        function="validate_input",
        argument_index=0,
        sanitizes_return=True,
    ))

    # Run analysis
    analyzer = TaintAnalyzer(config)
    violations = analyzer.analyze(cppcheck_cfg)

    for v in violations:
        print(f"VULNERABILITY: {v.sink_kind.name}")
        print(f"  Location: {v.location}")
        print(f"  Flow: {' -> '.join(v.flow_path)}")

License: MIT
"""

from __future__ import annotations

import copy
from abc import ABC, abstractmethod
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import (
    Any,
    Callable,
    Dict,
    FrozenSet,
    Iterator,
    List,
    Mapping,
    Optional,
    Protocol,
    Sequence,
    Set,
    Tuple,
    Union,
)

# Import AST helper utilities
from .ast_helper import (
    tok_str, tok_op1, tok_op2, tok_parent, tok_var_id, tok_variable,
    tok_values, tok_file, tok_line, tok_column,
    iter_ast_preorder, find_ast_root,
    is_assignment, is_function_call, is_dereference, is_subscript,
    is_address_of, is_member_access, is_compound_assignment,
    get_called_function_name, get_call_arguments,
    get_variables_used, get_variables_written,
    is_identifier, is_literal, token_location, expr_to_string,
)


# ═══════════════════════════════════════════════════════════════════════════
#  TYPE ALIASES
# ═══════════════════════════════════════════════════════════════════════════

Token = Any
Scope = Any
Variable = Any
Function = Any
Configuration = Any

# A location identifier: either a variable ID or a symbolic location
LocationId = Union[int, str]


# ═══════════════════════════════════════════════════════════════════════════
#  PART 1 — TAINT LATTICE
# ═══════════════════════════════════════════════════════════════════════════

class TaintLevel(Enum):
    """
    The taint lattice elements.

    The lattice structure is:

            UNKNOWN (⊤)
           /         \
       TAINTED    UNTAINTED
           \         /
            BOTTOM (⊥)

    BOTTOM represents unreachable code or uninitialized state.
    TAINTED means definitely contains untrusted data.
    UNTAINTED means definitely safe (no untrusted data).
    UNKNOWN means might or might not be tainted (conservative).
    """
    BOTTOM = 0      # ⊥ - unreachable/uninitialized
    TAINTED = 1     # Definitely tainted
    UNTAINTED = 2   # Definitely untainted
    UNKNOWN = 3     # ⊤ - might be either


@dataclass(frozen=True, slots=True)
class TaintValue:
    """
    Represents the taint state of a single value.

    This is an element of the taint lattice with proper lattice operations.

    Attributes:
        level: The taint level
        sources: Set of source identifiers that contributed to this taint
                 (for tracking taint provenance)
    """
    level: TaintLevel
    sources: FrozenSet[str] = field(default_factory=frozenset)

    # ─────────────────────────────────────────────────────────────────
    #  Factory methods
    # ─────────────────────────────────────────────────────────────────

    @classmethod
    def bottom(cls) -> 'TaintValue':
        """Create the bottom element (⊥)."""
        return cls(TaintLevel.BOTTOM, frozenset())

    @classmethod
    def tainted(cls, source: Optional[str] = None) -> 'TaintValue':
        """Create a tainted value, optionally with a source identifier."""
        sources = frozenset({source}) if source else frozenset()
        return cls(TaintLevel.TAINTED, sources)

    @classmethod
    def untainted(cls) -> 'TaintValue':
        """Create an untainted (safe) value."""
        return cls(TaintLevel.UNTAINTED, frozenset())

    @classmethod
    def unknown(cls) -> 'TaintValue':
        """Create the top element (⊤) - unknown taint status."""
        return cls(TaintLevel.UNKNOWN, frozenset())

    # ─────────────────────────────────────────────────────────────────
    #  Lattice operations
    # ─────────────────────────────────────────────────────────────────

    def join(self, other: 'TaintValue') -> 'TaintValue':
        """
        Least upper bound (⊔) in the lattice.

        Used when merging taint states at control flow joins.

        Join table:
            ⊥ ⊔ x = x
            x ⊔ ⊤ = ⊤
            T ⊔ U = ⊤
            T ⊔ T = T
            U ⊔ U = U
        """
        # Bottom is identity
        if self.level == TaintLevel.BOTTOM:
            return other
        if other.level == TaintLevel.BOTTOM:
            return self

        # Unknown absorbs everything
        if self.level == TaintLevel.UNKNOWN or other.level == TaintLevel.UNKNOWN:
            return TaintValue(TaintLevel.UNKNOWN, self.sources | other.sources)

        # Same level: combine sources
        if self.level == other.level:
            return TaintValue(self.level, self.sources | other.sources)

        # Different levels (TAINTED vs UNTAINTED): result is UNKNOWN
        return TaintValue(TaintLevel.UNKNOWN, self.sources | other.sources)

    def meet(self, other: 'TaintValue') -> 'TaintValue':
        """
        Greatest lower bound (⊓) in the lattice.

        Used for computing definite taint (must-taint analysis).

        Meet table:
            ⊥ ⊓ x = ⊥
            x ⊓ ⊤ = x
            T ⊓ U = ⊥
            T ⊓ T = T
            U ⊓ U = U
        """
        # Bottom absorbs everything
        if self.level == TaintLevel.BOTTOM or other.level == TaintLevel.BOTTOM:
            return TaintValue.bottom()

        # Unknown is identity
        if self.level == TaintLevel.UNKNOWN:
            return other
        if other.level == TaintLevel.UNKNOWN:
            return self

        # Same level: intersect sources
        if self.level == other.level:
            return TaintValue(self.level, self.sources & other.sources)

        # Different levels: bottom
        return TaintValue.bottom()

    def leq(self, other: 'TaintValue') -> bool:
        """
        Partial order (⊑) in the lattice.

        self ⊑ other means self is "less than or equal to" other in
        the information ordering.
        """
        if self.level == TaintLevel.BOTTOM:
            return True
        if other.level == TaintLevel.UNKNOWN:
            return True
        if self.level == other.level:
            return self.sources <= other.sources
        return False

    # ─────────────────────────────────────────────────────────────────
    #  Predicates
    # ─────────────────────────────────────────────────────────────────

    def is_bottom(self) -> bool:
        """Check if this is the bottom element."""
        return self.level == TaintLevel.BOTTOM

    def is_top(self) -> bool:
        """Check if this is the top element (unknown)."""
        return self.level == TaintLevel.UNKNOWN

    def is_tainted(self) -> bool:
        """Check if this value is definitely tainted."""
        return self.level == TaintLevel.TAINTED

    def is_untainted(self) -> bool:
        """Check if this value is definitely untainted."""
        return self.level == TaintLevel.UNTAINTED

    def may_be_tainted(self) -> bool:
        """Check if this value might be tainted (tainted or unknown)."""
        return self.level in (TaintLevel.TAINTED, TaintLevel.UNKNOWN)

    def must_be_tainted(self) -> bool:
        """Check if this value must be tainted."""
        return self.level == TaintLevel.TAINTED

    def must_be_untainted(self) -> bool:
        """Check if this value must be untainted."""
        return self.level == TaintLevel.UNTAINTED

    # ─────────────────────────────────────────────────────────────────
    #  Operations
    # ─────────────────────────────────────────────────────────────────

    def with_source(self, source: str) -> 'TaintValue':
        """Add a source identifier to this taint value."""
        return TaintValue(self.level, self.sources | {source})

    def sanitize(self) -> 'TaintValue':
        """
        Remove taint (sanitize).

        Returns an untainted value, discarding source information.
        """
        return TaintValue.untainted()

    def __repr__(self) -> str:
        if self.sources:
            return f"TaintValue({self.level.name}, sources={set(self.sources)})"
        return f"TaintValue({self.level.name})"


# ═══════════════════════════════════════════════════════════════════════════
#  PART 2 — TAINT STATE
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class TaintState:
    """
    Abstract state mapping locations to taint values.

    A TaintState represents the taint information at a single program point.
    It maps variable IDs and symbolic memory locations to their taint values.

    The state supports:
    - Variable tracking (by varId)
    - Heap location tracking (by symbolic names)
    - Field-sensitive tracking (for struct members)
    - Array element tracking (with limited precision)

    Attributes:
        _mapping: Internal mapping from locations to taint values
        _default: Default taint value for unmapped locations
    """
    _mapping: Dict[LocationId, TaintValue] = field(default_factory=dict)
    _default: TaintValue = field(default_factory=TaintValue.unknown)

    # ─────────────────────────────────────────────────────────────────
    #  Factory methods
    # ─────────────────────────────────────────────────────────────────

    @classmethod
    def bottom(cls) -> 'TaintState':
        """Create the bottom state (unreachable)."""
        return cls(_mapping={}, _default=TaintValue.bottom())

    @classmethod
    def initial(cls) -> 'TaintState':
        """
        Create the initial state for analysis entry.

        All variables start as UNKNOWN (conservative).
        """
        return cls(_mapping={}, _default=TaintValue.unknown())

    @classmethod
    def empty(cls) -> 'TaintState':
        """
        Create an empty state where everything is untainted.

        Use this for trusted entry points.
        """
        return cls(_mapping={}, _default=TaintValue.untainted())

    # ─────────────────────────────────────────────────────────────────
    #  Accessors
    # ─────────────────────────────────────────────────────────────────

    def get(self, location: LocationId) -> TaintValue:
        """
        Get the taint value for a location.

        Args:
            location: Variable ID or symbolic location name

        Returns:
            The taint value (default if not explicitly mapped)
        """
        return self._mapping.get(location, self._default)

    def get_var(self, var_id: int) -> TaintValue:
        """
        Get the taint value for a variable by ID.

        Args:
            var_id: The variable ID

        Returns:
            The taint value for the variable
        """
        if var_id == 0:
            return self._default
        return self.get(var_id)

    def get_token(self, tok: Token) -> TaintValue:
        """
        Get the taint value for an expression represented by a token.

        This handles:
        - Simple variables (by varId)
        - Dereferences (*p gets taint of pointed-to location)
        - Member access (s.m, p->m)
        - Array access (a[i])

        Args:
            tok: The token representing the expression

        Returns:
            The taint value of the expression
        """
        if tok is None:
            return self._default

        # Simple variable
        var_id = tok_var_id(tok)
        if var_id != 0:
            return self.get_var(var_id)

        s = tok_str(tok)

        # Dereference: *p
        if is_dereference(tok):
            ptr_tok = tok_op1(tok)
            ptr_taint = self.get_token(ptr_tok)
            # Conservative: if pointer is tainted, dereferenced value is tainted
            # More precise analysis would track points-to information
            if ptr_taint.may_be_tainted():
                return TaintValue.unknown()
            # Look up symbolic location for the pointer
            ptr_var_id = tok_var_id(ptr_tok)
            if ptr_var_id:
                deref_loc = f"*{ptr_var_id}"
                return self.get(deref_loc)
            return self._default

        # Member access: s.m or p->m
        if is_member_access(tok):
            base_tok = tok_op1(tok)
            member_tok = tok_op2(tok)
            base_var_id = tok_var_id(base_tok)
            member_name = tok_str(member_tok) if member_tok else ""
            if base_var_id and member_name:
                field_loc = f"{base_var_id}.{member_name}"
                return self.get(field_loc)
            # Conservative: check base object taint
            return self.get_token(base_tok)

        # Array subscript: a[i]
        if is_subscript(tok):
            array_tok = tok_op1(tok)
            index_tok = tok_op2(tok)
            # If index is tainted, result might be controlled by attacker
            index_taint = self.get_token(index_tok)
            if index_taint.may_be_tainted():
                return TaintValue.unknown()
            # Otherwise, check array taint
            return self.get_token(array_tok)

        # Literals are untainted
        if is_literal(tok):
            return TaintValue.untainted()

        # For complex expressions, analyze recursively
        op1 = tok_op1(tok)
        op2 = tok_op2(tok)

        if op1 is not None:
            t1 = self.get_token(op1)
            if op2 is not None:
                t2 = self.get_token(op2)
                # Taint propagates through operations
                return t1.join(t2)
            return t1

        return self._default

    # ─────────────────────────────────────────────────────────────────
    #  Mutators (return new state)
    # ─────────────────────────────────────────────────────────────────

    def set(self, location: LocationId, value: TaintValue) -> 'TaintState':
        """
        Set the taint value for a location.

        Returns a new state (immutable update).

        Args:
            location: Variable ID or symbolic location
            value: The new taint value

        Returns:
            A new TaintState with the update applied
        """
        new_mapping = dict(self._mapping)
        new_mapping[location] = value
        return TaintState(_mapping=new_mapping, _default=self._default)

    def set_var(self, var_id: int, value: TaintValue) -> 'TaintState':
        """
        Set the taint value for a variable.

        Args:
            var_id: The variable ID
            value: The new taint value

        Returns:
            A new TaintState with the update applied
        """
        if var_id == 0:
            return self
        return self.set(var_id, value)

    def set_token(self, tok: Token, value: TaintValue) -> 'TaintState':
        """
        Set the taint value for an expression.

        Handles complex lvalues (dereferences, member access, etc.).

        Args:
            tok: The token representing the lvalue
            value: The new taint value

        Returns:
            A new TaintState with the update applied
        """
        if tok is None:
            return self

        # Simple variable
        var_id = tok_var_id(tok)
        if var_id != 0:
            return self.set_var(var_id, value)

        s = tok_str(tok)

        # Dereference: *p = ...
        if is_dereference(tok):
            ptr_tok = tok_op1(tok)
            ptr_var_id = tok_var_id(ptr_tok)
            if ptr_var_id:
                deref_loc = f"*{ptr_var_id}"
                return self.set(deref_loc, value)
            # Can't track precisely; be conservative
            return self

        # Member access: s.m = ... or p->m = ...
        if is_member_access(tok):
            base_tok = tok_op1(tok)
            member_tok = tok_op2(tok)
            base_var_id = tok_var_id(base_tok)
            member_name = tok_str(member_tok) if member_tok else ""
            if base_var_id and member_name:
                field_loc = f"{base_var_id}.{member_name}"
                return self.set(field_loc, value)
            return self

        # Array subscript: a[i] = ...
        if is_subscript(tok):
            array_tok = tok_op1(tok)
            array_var_id = tok_var_id(array_tok)
            if array_var_id:
                # Weak update: join with existing value
                # (we don't know which element is being written)
                existing = self.get_var(array_var_id)
                new_value = existing.join(value)
                return self.set_var(array_var_id, new_value)
            return self

        return self

    def remove(self, location: LocationId) -> 'TaintState':
        """
        Remove a location from the state (reset to default).

        Args:
            location: The location to remove

        Returns:
            A new TaintState with the location removed
        """
        if location not in self._mapping:
            return self
        new_mapping = dict(self._mapping)
        del new_mapping[location]
        return TaintState(_mapping=new_mapping, _default=self._default)

    def sanitize(self, location: LocationId) -> 'TaintState':
        """
        Sanitize a location (mark as untainted).

        Args:
            location: The location to sanitize

        Returns:
            A new TaintState with the location sanitized
        """
        return self.set(location, TaintValue.untainted())

    def taint(self, location: LocationId, source: Optional[str] = None) -> 'TaintState':
        """
        Mark a location as tainted.

        Args:
            location: The location to taint
            source: Optional source identifier

        Returns:
            A new TaintState with the location tainted
        """
        return self.set(location, TaintValue.tainted(source))

    # ─────────────────────────────────────────────────────────────────
    #  Lattice operations
    # ─────────────────────────────────────────────────────────────────

    def join(self, other: 'TaintState') -> 'TaintState':
        """
        Least upper bound of two states.

        Used at control flow merge points.

        Args:
            other: The other state to join with

        Returns:
            A new TaintState representing the join
        """
        # Collect all locations
        all_locations = set(self._mapping.keys()) | set(other._mapping.keys())

        new_mapping: Dict[LocationId, TaintValue] = {}
        new_default = self._default.join(other._default)

        for loc in all_locations:
            v1 = self.get(loc)
            v2 = other.get(loc)
            joined = v1.join(v2)
            # Only store if different from default
            if joined != new_default:
                new_mapping[loc] = joined

        return TaintState(_mapping=new_mapping, _default=new_default)

    def meet(self, other: 'TaintState') -> 'TaintState':
        """
        Greatest lower bound of two states.

        Args:
            other: The other state to meet with

        Returns:
            A new TaintState representing the meet
        """
        all_locations = set(self._mapping.keys()) | set(other._mapping.keys())

        new_mapping: Dict[LocationId, TaintValue] = {}
        new_default = self._default.meet(other._default)

        for loc in all_locations:
            v1 = self.get(loc)
            v2 = other.get(loc)
            met = v1.meet(v2)
            if met != new_default:
                new_mapping[loc] = met

        return TaintState(_mapping=new_mapping, _default=new_default)

    def leq(self, other: 'TaintState') -> bool:
        """
        Check if this state is less than or equal to other.

        Args:
            other: The other state to compare with

        Returns:
            True if self ⊑ other
        """
        # Check default
        if not self._default.leq(other._default):
            return False

        # Check all explicitly mapped locations
        all_locations = set(self._mapping.keys()) | set(other._mapping.keys())
        for loc in all_locations:
            if not self.get(loc).leq(other.get(loc)):
                return False

        return True

    def is_bottom(self) -> bool:
        """Check if this is the bottom state."""
        return self._default.is_bottom() and not self._mapping

    # ─────────────────────────────────────────────────────────────────
    #  Utilities
    # ─────────────────────────────────────────────────────────────────

    def tainted_locations(self) -> Iterator[LocationId]:
        """Iterate over locations that are definitely tainted."""
        for loc, val in self._mapping.items():
            if val.is_tainted():
                yield loc

    def possibly_tainted_locations(self) -> Iterator[LocationId]:
        """Iterate over locations that may be tainted."""
        for loc, val in self._mapping.items():
            if val.may_be_tainted():
                yield loc

    def copy(self) -> 'TaintState':
        """Create a shallow copy of this state."""
        return TaintState(
            _mapping=dict(self._mapping),
            _default=self._default
        )

    def __repr__(self) -> str:
        if not self._mapping:
            return f"TaintState(default={self._default.level.name})"
        items = ", ".join(f"{k}: {v.level.name}" for k,
                          v in self._mapping.items())
        return f"TaintState({{{items}}}, default={self._default.level.name})"


# ═══════════════════════════════════════════════════════════════════════════
#  PART 3 — CONFIGURATION TYPES
# ═══════════════════════════════════════════════════════════════════════════

class SourceKind(Enum):
    """Classification of taint sources."""
    RETURN_VALUE = auto()      # Function return value is tainted
    ARGUMENT_OUT = auto()      # Argument is tainted after call (output param)
    GLOBAL_READ = auto()       # Reading a global variable
    PARAMETER = auto()         # Function parameter is tainted
    ENVIRONMENT = auto()       # Environment variable
    FILE_READ = auto()         # Data read from file
    NETWORK_READ = auto()      # Data read from network
    USER_INPUT = auto()        # Direct user input


class SinkKind(Enum):
    """Classification of taint sinks (vulnerability types)."""
    COMMAND_INJECTION = auto()      # CWE-78
    SQL_INJECTION = auto()          # CWE-89
    PATH_TRAVERSAL = auto()         # CWE-22
    FORMAT_STRING = auto()          # CWE-134
    BUFFER_SIZE = auto()            # CWE-120, CWE-787
    MEMORY_ALLOCATION = auto()      # CWE-789
    LDAP_INJECTION = auto()         # CWE-90
    XML_INJECTION = auto()          # CWE-91
    XSS = auto()                    # CWE-79
    CODE_INJECTION = auto()         # CWE-94
    DESERIALIZATION = auto()        # CWE-502
    LOG_INJECTION = auto()          # CWE-117
    HEADER_INJECTION = auto()       # CWE-113
    REDIRECT = auto()               # CWE-601
    SSRF = auto()                   # CWE-918
    CUSTOM = auto()                 # User-defined sink


class PropagationKind(Enum):
    """How taint propagates through a function."""
    COPY = auto()           # Output has same taint as input
    MERGE = auto()          # Output has join of all input taints
    CONDITIONAL = auto()    # Taint depends on runtime conditions
    TRANSFORM = auto()      # Taint is transformed (may add/remove)
    NONE = auto()           # No propagation (output is untainted)


@dataclass(frozen=True)
class TaintSource:
    """
    Specification of a taint source.

    A taint source introduces untrusted data into the program.

    Attributes:
        function: Name of the function that produces tainted data
        kind: How the taint is introduced
        argument_index: For ARGUMENT_OUT, which argument becomes tainted
        description: Human-readable description
        cwe: Associated CWE identifier (optional)
        tags: Additional tags for filtering/grouping
    """
    function: str
    kind: SourceKind = SourceKind.RETURN_VALUE
    argument_index: int = -1
    description: str = ""
    cwe: Optional[int] = None
    tags: FrozenSet[str] = field(default_factory=frozenset)

    def source_id(self) -> str:
        """Get a unique identifier for this source."""
        return f"source:{self.function}:{self.kind.name}"


@dataclass(frozen=True)
class TaintSink:
    """
    Specification of a taint sink.

    A taint sink is a sensitive operation where tainted data is dangerous.

    Attributes:
        function: Name of the sensitive function
        argument_index: Which argument must not be tainted (-1 for any)
        kind: The type of vulnerability this represents
        description: Human-readable description
        cwe: Associated CWE identifier
        severity: Severity level (1-10, 10 being most severe)
        tags: Additional tags for filtering/grouping
    """
    function: str
    argument_index: int = 0
    kind: SinkKind = SinkKind.CUSTOM
    description: str = ""
    cwe: Optional[int] = None
    severity: int = 5
    tags: FrozenSet[str] = field(default_factory=frozenset)

    def sink_id(self) -> str:
        """Get a unique identifier for this sink."""
        return f"sink:{self.function}:{self.argument_index}:{self.kind.name}"


@dataclass(frozen=True)
class TaintSanitizer:
    """
    Specification of a taint sanitizer.

    A sanitizer is a function that removes or neutralizes taint,
    making data safe for use at sinks.

    Attributes:
        function: Name of the sanitizing function
        argument_index: Which argument is sanitized (-1 for all)
        sanitizes_return: Whether the return value is sanitized
        sanitizes_in_place: Whether the argument is sanitized in place
        valid_for_sinks: Set of sink kinds this sanitizer is valid for
                         (empty means valid for all)
        description: Human-readable description
        tags: Additional tags for filtering/grouping
    """
    function: str
    argument_index: int = 0
    sanitizes_return: bool = True
    sanitizes_in_place: bool = False
    valid_for_sinks: FrozenSet[SinkKind] = field(default_factory=frozenset)
    description: str = ""
    tags: FrozenSet[str] = field(default_factory=frozenset)

    def sanitizer_id(self) -> str:
        """Get a unique identifier for this sanitizer."""
        return f"sanitizer:{self.function}:{self.argument_index}"

    def is_valid_for_sink(self, sink_kind: SinkKind) -> bool:
        """Check if this sanitizer is valid for a given sink kind."""
        if not self.valid_for_sinks:
            return True  # Valid for all sinks
        return sink_kind in self.valid_for_sinks


@dataclass(frozen=True)
class TaintPropagator:
    """
    Specification of how taint propagates through a function.

    Propagators define the taint transfer semantics for library functions
    that the analyzer cannot inspect.

    Attributes:
        function: Name of the function
        propagation_kind: How taint flows through the function
        from_arguments: Which arguments contribute taint (indices)
        to_return: Whether taint propagates to return value
        to_arguments: Which arguments receive taint (output params)
        description: Human-readable description
        tags: Additional tags for filtering/grouping
    """
    function: str
    propagation_kind: PropagationKind = PropagationKind.MERGE
    from_arguments: FrozenSet[int] = field(default_factory=frozenset)
    to_return: bool = True
    to_arguments: FrozenSet[int] = field(default_factory=frozenset)
    description: str = ""
    tags: FrozenSet[str] = field(default_factory=frozenset)

    def propagator_id(self) -> str:
        """Get a unique identifier for this propagator."""
        return f"propagator:{self.function}"


@dataclass
class TaintConfig:
    """
    Complete configuration for taint analysis.

    This class aggregates all sources, sinks, sanitizers, and propagators
    that define the taint analysis behavior.

    Attributes:
        sources: Mapping from function name to list of sources
        sinks: Mapping from function name to list of sinks
        sanitizers: Mapping from function name to list of sanitizers
        propagators: Mapping from function name to propagator
        tainted_parameters: Set of (function_name, param_index) for tainted params
        tainted_globals: Set of global variable names that are tainted
        default_propagation: How to handle unknown functions
        track_strings: Whether to track string taint precisely
        track_containers: Whether to track container element taint
        max_path_length: Maximum taint flow path length to track
    """
    sources: Dict[str, List[TaintSource]] = field(default_factory=dict)
    sinks: Dict[str, List[TaintSink]] = field(default_factory=dict)
    sanitizers: Dict[str, List[TaintSanitizer]] = field(default_factory=dict)
    propagators: Dict[str, TaintPropagator] = field(default_factory=dict)
    tainted_parameters: Set[Tuple[str, int]] = field(default_factory=set)
    tainted_globals: Set[str] = field(default_factory=set)
    default_propagation: PropagationKind = PropagationKind.MERGE
    track_strings: bool = True
    track_containers: bool = False
    max_path_length: int = 50

    # ─────────────────────────────────────────────────────────────────
    #  Registration methods
    # ─────────────────────────────────────────────────────────────────

    def add_source(self, source: TaintSource) -> 'TaintConfig':
        """
        Add a taint source to the configuration.

        Args:
            source: The source specification

        Returns:
            self for method chaining
        """
        if source.function not in self.sources:
            self.sources[source.function] = []
        self.sources[source.function].append(source)
        return self

    def add_sink(self, sink: TaintSink) -> 'TaintConfig':
        """
        Add a taint sink to the configuration.

        Args:
            sink: The sink specification

        Returns:
            self for method chaining
        """
        if sink.function not in self.sinks:
            self.sinks[sink.function] = []
        self.sinks[sink.function].append(sink)
        return self

    def add_sanitizer(self, sanitizer: TaintSanitizer) -> 'TaintConfig':
        """
        Add a taint sanitizer to the configuration.

        Args:
            sanitizer: The sanitizer specification

        Returns:
            self for method chaining
        """
        if sanitizer.function not in self.sanitizers:
            self.sanitizers[sanitizer.function] = []
        self.sanitizers[sanitizer.function].append(sanitizer)
        return self

    def add_propagator(self, propagator: TaintPropagator) -> 'TaintConfig':
        """
        Add a taint propagator to the configuration.

        Args:
            propagator: The propagator specification

        Returns:
            self for method chaining
        """
        self.propagators[propagator.function] = propagator
        return self

    def add_tainted_parameter(self, function: str, param_index: int) -> 'TaintConfig':
        """
        Mark a function parameter as tainted.

        Args:
            function: Function name
            param_index: Parameter index (0-based)

        Returns:
            self for method chaining
        """
        self.tainted_parameters.add((function, param_index))
        return self

    def add_tainted_global(self, global_name: str) -> 'TaintConfig':
        """
        Mark a global variable as tainted.

        Args:
            global_name: Name of the global variable

        Returns:
            self for method chaining
        """
        self.tainted_globals.add(global_name)
        return self

    # ─────────────────────────────────────────────────────────────────
    #  Query methods
    # ─────────────────────────────────────────────────────────────────

    def get_sources(self, function: str) -> List[TaintSource]:
        """Get all sources for a function."""
        return self.sources.get(function, [])

    def get_sinks(self, function: str) -> List[TaintSink]:
        """Get all sinks for a function."""
        return self.sinks.get(function, [])

    def get_sanitizers(self, function: str) -> List[TaintSanitizer]:
        """Get all sanitizers for a function."""
        return self.sanitizers.get(function, [])

    def get_propagator(self, function: str) -> Optional[TaintPropagator]:
        """Get the propagator for a function."""
        return self.propagators.get(function)

    def is_source(self, function: str) -> bool:
        """Check if a function is a taint source."""
        return function in self.sources

    def is_sink(self, function: str) -> bool:
        """Check if a function is a taint sink."""
        return function in self.sinks

    def is_sanitizer(self, function: str) -> bool:
        """Check if a function is a sanitizer."""
        return function in self.sanitizers

    def has_propagator(self, function: str) -> bool:
        """Check if a function has a custom propagator."""
        return function in self.propagators

    def is_parameter_tainted(self, function: str, param_index: int) -> bool:
        """Check if a function parameter is marked as tainted."""
        return (function, param_index) in self.tainted_parameters

    def is_global_tainted(self, global_name: str) -> bool:
        """Check if a global variable is marked as tainted."""
        return global_name in self.tainted_globals

    # ─────────────────────────────────────────────────────────────────
    #  Bulk registration
    # ─────────────────────────────────────────────────────────────────

    def add_sources(self, sources: Sequence[TaintSource]) -> 'TaintConfig':
        """Add multiple sources."""
        for source in sources:
            self.add_source(source)
        return self

    def add_sinks(self, sinks: Sequence[TaintSink]) -> 'TaintConfig':
        """Add multiple sinks."""
        for sink in sinks:
            self.add_sink(sink)
        return self

    def add_sanitizers(self, sanitizers: Sequence[TaintSanitizer]) -> 'TaintConfig':
        """Add multiple sanitizers."""
        for sanitizer in sanitizers:
            self.add_sanitizer(sanitizer)
        return self

    def add_propagators(self, propagators: Sequence[TaintPropagator]) -> 'TaintConfig':
        """Add multiple propagators."""
        for propagator in propagators:
            self.add_propagator(propagator)
        return self

    def merge(self, other: 'TaintConfig') -> 'TaintConfig':
        """
        Merge another configuration into this one.

        Args:
            other: Configuration to merge

        Returns:
            self for method chaining
        """
        for func, sources in other.sources.items():
            for source in sources:
                self.add_source(source)
        for func, sinks in other.sinks.items():
            for sink in sinks:
                self.add_sink(sink)
        for func, sanitizers in other.sanitizers.items():
            for sanitizer in sanitizers:
                self.add_sanitizer(sanitizer)
        for func, propagator in other.propagators.items():
            self.add_propagator(propagator)
        self.tainted_parameters.update(other.tainted_parameters)
        self.tainted_globals.update(other.tainted_globals)
        return self


# ═══════════════════════════════════════════════════════════════════════════
#  PART 4 — TAINT FLOW TRACKING
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class TaintFlowStep:
    """
    A single step in a taint flow path.

    Represents how taint moved from one location to another.

    Attributes:
        location: Source file location (file:line:col)
        description: Human-readable description of this step
        token: The token at this step (optional)
        kind: Type of flow step
    """
    location: str
    description: str
    token: Optional[Token] = None
    kind: str = "flow"

    def __repr__(self) -> str:
        return f"{self.location}: {self.description}"


@dataclass
class TaintFlowPath:
    """
    A complete path from taint source to sink.

    Attributes:
        steps: Ordered list of flow steps
        source: The originating taint source
        sink: The destination sink
    """
    steps: List[TaintFlowStep] = field(default_factory=list)
    source: Optional[TaintSource] = None
    sink: Optional[TaintSink] = None

    def add_step(
        self,
        token: Token,
        description: str,
        kind: str = "flow"
    ) -> 'TaintFlowPath':
        """
        Add a step to the flow path.

        Args:
            token: The token at this step
            description: Description of the step
            kind: Type of step

        Returns:
            self for method chaining
        """
        loc = token_location(token) if token else "<unknown>"
        self.steps.append(TaintFlowStep(
            location=loc,
            description=description,
            token=token,
            kind=kind
        ))
        return self

    def add_source_step(self, token: Token, source: TaintSource) -> 'TaintFlowPath':
        """Add the source introduction step."""
        self.source = source
        desc = f"Taint introduced from {source.function}()"
        if source.description:
            desc += f" - {source.description}"
        return self.add_step(token, desc, kind="source")

    def add_sink_step(self, token: Token, sink: TaintSink) -> 'TaintFlowPath':
        """Add the sink consumption step."""
        self.sink = sink
        desc = f"Taint reaches sink {sink.function}() argument {sink.argument_index}"
        if sink.description:
            desc += f" - {sink.description}"
        return self.add_step(token, desc, kind="sink")

    def format_path(self) -> str:
        """Format the path as a human-readable string."""
        lines = []
        for i, step in enumerate(self.steps):
            prefix = "  " if i > 0 else ""
            arrow = "→ " if i > 0 else ""
            lines.append(f"{prefix}{arrow}{step}")
        return "\n".join(lines)

    def __len__(self) -> int:
        return len(self.steps)

    def __repr__(self) -> str:
        if self.source and self.sink:
            return f"TaintFlowPath({self.source.function} → {self.sink.function}, {len(self.steps)} steps)"
        return f"TaintFlowPath({len(self.steps)} steps)"


# ═══════════════════════════════════════════════════════════════════════════
#  PART 5 — TAINT VIOLATIONS
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class TaintViolation:
    """
    A detected taint violation (potential vulnerability).

    Represents tainted data reaching a sensitive sink without
    proper sanitization.

    Attributes:
        sink: The sink that was reached
        sink_token: The token at the sink location
        sink_kind: The type of vulnerability
        taint_sources: Sources that contributed to this violation
        flow_path: The path taint took from source to sink
        severity: Severity level (1-10)
        confidence: Confidence level (0.0-1.0)
        cwe: Associated CWE identifier
        message: Human-readable description
        suppressed: Whether this violation is suppressed
    """
    sink: TaintSink
    sink_token: Token
    sink_kind: SinkKind
    taint_sources: FrozenSet[str]
    flow_path: Optional[TaintFlowPath] = None
    severity: int = 5
    confidence: float = 0.8
    cwe: Optional[int] = None
    message: str = ""
    suppressed: bool = False

    @property
    def location(self) -> str:
        """Get the location of this violation."""
        return token_location(self.sink_token)

    @property
    def function(self) -> str:
        """Get the sink function name."""
        return self.sink.function

    @property
    def argument_index(self) -> int:
        """Get the affected argument index."""
        return self.sink.argument_index

    def format_message(self) -> str:
        """Format a complete message for this violation."""
        parts = [
            f"[{self.sink_kind.name}]",
            f"Tainted data reaches {self.sink.function}()",
        ]
        if self.sink.argument_index >= 0:
            parts.append(f"at argument {self.sink.argument_index}")
        if self.cwe:
            parts.append(f"(CWE-{self.cwe})")
        return " ".join(parts)

    def format_full_report(self) -> str:
        """Format a complete report including flow path."""
        lines = [
            f"═══ TAINT VIOLATION ═══",
            f"Location: {self.location}",
            f"Severity: {self.severity}/10",
            f"Confidence: {self.confidence:.0%}",
            f"Type: {self.sink_kind.name}",
        ]
        if self.cwe:
            lines.append(f"CWE: CWE-{self.cwe}")
        lines.append(f"Message: {self.format_message()}")

        if self.taint_sources:
            lines.append(f"Sources: {', '.join(self.taint_sources)}")

        if self.flow_path and self.flow_path.steps:
            lines.append("")
            lines.append("Flow path:")
            lines.append(self.flow_path.format_path())

        return "\n".join(lines)

    def __repr__(self) -> str:
        return f"TaintViolation({self.sink_kind.name} at {self.location})"


# ═══════════════════════════════════════════════════════════════════════════
#  PART 6 — TRANSFER FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════

class TaintTransfer:
    """
    Taint transfer function implementation.

    Computes how taint state changes after executing a statement.
    """

    def __init__(self, config: TaintConfig):
        """
        Initialize the transfer function.

        Args:
            config: Taint analysis configuration
        """
        self.config = config
        self._flow_tracker: Optional[TaintFlowPath] = None

    def set_flow_tracker(self, tracker: Optional[TaintFlowPath]) -> None:
        """Set the current flow path tracker."""
        self._flow_tracker = tracker

    def transfer(self, state: TaintState, token: Token) -> TaintState:
        """
        Compute the new taint state after a statement.

        Args:
            state: Current taint state
            token: The AST root of the statement

        Returns:
            New taint state after the statement
        """
        if token is None:
            return state

        s = tok_str(token)

        # Handle different statement types
        if is_assignment(token):
            return self._transfer_assignment(state, token)

        if is_function_call(token):
            return self._transfer_call(state, token)

        # For other expressions, propagate taint through the AST
        return self._transfer_expression(state, token)

    def _transfer_assignment(self, state: TaintState, token: Token) -> TaintState:
        """
        Transfer function for assignment statements.

        Handles: x = expr, x += expr, *p = expr, a[i] = expr, s.m = expr
        """
        lhs = tok_op1(token)
        rhs = tok_op2(token)

        if lhs is None or rhs is None:
            return state

        # Get taint of RHS
        rhs_taint = state.get_token(rhs)

        # For compound assignments, merge with LHS taint
        if is_compound_assignment(token):
            lhs_taint = state.get_token(lhs)
            rhs_taint = lhs_taint.join(rhs_taint)

        # Update LHS with RHS taint
        new_state = state.set_token(lhs, rhs_taint)

        # Track flow if enabled
        if self._flow_tracker and rhs_taint.may_be_tainted():
            lhs_str = expr_to_string(lhs)
            rhs_str = expr_to_string(rhs)
            self._flow_tracker.add_step(
                token,
                f"Taint flows: {rhs_str} → {lhs_str}",
                kind="assignment"
            )

        return new_state

    def _transfer_call(self, state: TaintState, token: Token) -> TaintState:
        """
        Transfer function for function calls.

        Handles sources, sinks, sanitizers, and propagators.
        """
        func_name = get_called_function_name(token)
        args = get_call_arguments(token)

        new_state = state

        # Check if this is a source
        if self.config.is_source(func_name):
            new_state = self._apply_sources(new_state, token, func_name, args)

        # Check if this is a sanitizer
        if self.config.is_sanitizer(func_name):
            new_state = self._apply_sanitizers(
                new_state, token, func_name, args)

        # Apply propagation rules
        propagator = self.config.get_propagator(func_name)
        if propagator:
            new_state = self._apply_propagator(
                new_state, token, propagator, args)
        else:
            # Default propagation: merge taint from all arguments
            new_state = self._apply_default_propagation(new_state, token, args)

        return new_state

    def _apply_sources(
        self,
        state: TaintState,
        call_token: Token,
        func_name: str,
        args: List[Token]
    ) -> TaintState:
        """Apply taint source specifications."""
        new_state = state

        for source in self.config.get_sources(func_name):
            source_id = source.source_id()

            if source.kind == SourceKind.RETURN_VALUE:
                # Return value is tainted - handled by caller assignment
                # We mark the call token itself
                pass  # Handled in assignment transfer

            elif source.kind == SourceKind.ARGUMENT_OUT:
                # Output parameter becomes tainted
                if 0 <= source.argument_index < len(args):
                    arg = args[source.argument_index]
                    new_state = new_state.set_token(
                        arg,
                        TaintValue.tainted(source_id)
                    )
                    if self._flow_tracker:
                        self._flow_tracker.add_source_step(call_token, source)

        return new_state

    def _apply_sanitizers(
        self,
        state: TaintState,
        call_token: Token,
        func_name: str,
        args: List[Token]
    ) -> TaintState:
        """Apply taint sanitizer specifications."""
        new_state = state

        for sanitizer in self.config.get_sanitizers(func_name):
            if sanitizer.sanitizes_in_place:
                # Argument is sanitized in place
                if 0 <= sanitizer.argument_index < len(args):
                    arg = args[sanitizer.argument_index]
                    new_state = new_state.set_token(
                        arg, TaintValue.untainted())
                elif sanitizer.argument_index == -1:
                    # Sanitize all arguments
                    for arg in args:
                        new_state = new_state.set_token(
                            arg, TaintValue.untainted())

            # Return value sanitization is handled by assignment transfer

        return new_state

    def _apply_propagator(
        self,
        state: TaintState,
        call_token: Token,
        propagator: TaintPropagator,
        args: List[Token]
    ) -> TaintState:
        """Apply custom taint propagation rules."""
        new_state = state

        # Collect taint from specified input arguments
        input_taint = TaintValue.untainted()
        for arg_idx in propagator.from_arguments:
            if 0 <= arg_idx < len(args):
                arg_taint = state.get_token(args[arg_idx])
                input_taint = input_taint.join(arg_taint)

        # If no specific arguments, use all arguments
        if not propagator.from_arguments:
            for arg in args:
                arg_taint = state.get_token(arg)
                input_taint = input_taint.join(arg_taint)

        # Apply propagation kind
        output_taint = input_taint
        if propagator.propagation_kind == PropagationKind.NONE:
            output_taint = TaintValue.untainted()
        elif propagator.propagation_kind == PropagationKind.CONDITIONAL:
            output_taint = TaintValue.unknown()

        # Propagate to output arguments
        for arg_idx in propagator.to_arguments:
            if 0 <= arg_idx < len(args):
                new_state = new_state.set_token(args[arg_idx], output_taint)

        return new_state

    def _apply_default_propagation(
        self,
        state: TaintState,
        call_token: Token,
        args: List[Token]
    ) -> TaintState:
        """Apply default taint propagation for unknown functions."""
        if self.config.default_propagation == PropagationKind.NONE:
            return state

        # Merge taint from all arguments
        merged_taint = TaintValue.untainted()
        for arg in args:
            arg_taint = state.get_token(arg)
            merged_taint = merged_taint.join(arg_taint)

        # For conservative analysis, assume output parameters may be tainted
        # if any input is tainted
        if merged_taint.may_be_tainted():
            # Mark pointer/reference arguments as potentially tainted
            for arg in args:
                if is_address_of(arg) or is_identifier(arg):
                    var = tok_variable(
                        tok_op1(arg) if is_address_of(arg) else arg)
                    if var and (getattr(var, "isPointer", False) or
                                getattr(var, "isReference", False)):
                        state = state.set_token(arg, merged_taint)

        return state

    def _transfer_expression(self, state: TaintState, token: Token) -> TaintState:
        """
        Transfer function for general expressions.

        Taint propagates through most operators.
        """
        # Most expressions don't modify state, just compute values
        # State modification happens through assignments
        return state

    def get_expression_taint(self, state: TaintState, token: Token) -> TaintValue:
        """
        Get the taint value of an expression.

        This is used for checking sinks.

        Args:
            state: Current taint state
            token: The expression token

        Returns:
            The taint value of the expression
        """
        if token is None:
            return TaintValue.unknown()

        # Check if this is a function call that's a source
        if is_function_call(token):
            func_name = get_called_function_name(token)
            for source in self.config.get_sources(func_name):
                if source.kind == SourceKind.RETURN_VALUE:
                    return TaintValue.tainted(source.source_id())

            # Check if sanitizer returns untainted
            for sanitizer in self.config.get_sanitizers(func_name):
                if sanitizer.sanitizes_return:
                    return TaintValue.untainted()

        # Otherwise, get from state
        return state.get_token(token)


# ═══════════════════════════════════════════════════════════════════════════
#  PART 7 — TAINT ANALYZER
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class TaintAnalysisResult:
    """
    Results of taint analysis on a function or program.

    Attributes:
        violations: List of detected taint violations
        state_at_exit: Taint state at function exit
        states: Mapping from token ID to taint state (optional)
        analyzed_functions: Set of function names that were analyzed
        analysis_time_ms: Time taken for analysis in milliseconds
    """
    violations: List[TaintViolation] = field(default_factory=list)
    state_at_exit: Optional[TaintState] = None
    states: Dict[int, TaintState] = field(default_factory=dict)
    analyzed_functions: Set[str] = field(default_factory=set)
    analysis_time_ms: float = 0.0

    def has_violations(self) -> bool:
        """Check if any violations were found."""
        return len(self.violations) > 0

    def get_violations_by_kind(self, kind: SinkKind) -> List[TaintViolation]:
        """Get violations of a specific kind."""
        return [v for v in self.violations if v.sink_kind == kind]

    def get_violations_by_cwe(self, cwe: int) -> List[TaintViolation]:
        """Get violations for a specific CWE."""
        return [v for v in self.violations if v.cwe == cwe]

    def get_high_severity_violations(self, threshold: int = 7) -> List[TaintViolation]:
        """Get violations above a severity threshold."""
        return [v for v in self.violations if v.severity >= threshold]


class TaintAnalyzer:
    """
    Main taint analysis engine.

    Performs forward dataflow analysis to track taint propagation
    from sources to sinks.

    Usage:
        config = TaintConfig()
        # ... configure sources, sinks, sanitizers ...

        analyzer = TaintAnalyzer(config)
        result = analyzer.analyze_function(scope)

        for violation in result.violations:
            print(violation.format_full_report())
    """

    def __init__(
        self,
        config: TaintConfig,
        *,
        track_flow_paths: bool = True,
        max_iterations: int = 1000,
        verbose: bool = False,
    ):
        """
        Initialize the taint analyzer.

        Args:
            config: Taint analysis configuration
            track_flow_paths: Whether to track detailed flow paths
            max_iterations: Maximum fixpoint iterations
            verbose: Enable verbose output
        """
        self.config = config
        self.track_flow_paths = track_flow_paths
        self.max_iterations = max_iterations
        self.verbose = verbose

        self._transfer = TaintTransfer(config)
        self._violations: List[TaintViolation] = []
        self._current_function: Optional[str] = None

    # ─────────────────────────────────────────────────────────────────
    #  Main analysis entry points
    # ─────────────────────────────────────────────────────────────────

    def analyze_function(
        self,
        scope: Scope,
        initial_state: Optional[TaintState] = None
    ) -> TaintAnalysisResult:
        """
        Analyze a single function for taint violations.

        Args:
            scope: The function scope to analyze
            initial_state: Initial taint state (default: based on config)

        Returns:
            Analysis results including violations
        """
        import time
        start_time = time.time()

        self._violations = []
        func_name = getattr(scope, "className", "<unknown>")
        self._current_function = func_name

        # Initialize state
        if initial_state is None:
            initial_state = self._create_initial_state(scope)

        # Get function body tokens
        body_start = getattr(scope, "bodyStart", None)
        body_end = getattr(scope, "bodyEnd", None)

        if body_start is None or body_end is None:
            return TaintAnalysisResult(analyzed_functions={func_name})

        # Perform forward analysis
        final_state = self._analyze_tokens(initial_state, body_start, body_end)

        elapsed_ms = (time.time() - start_time) * 1000

        return TaintAnalysisResult(
            violations=list(self._violations),
            state_at_exit=final_state,
            analyzed_functions={func_name},
            analysis_time_ms=elapsed_ms,
        )

    def analyze_configuration(self, cfg: Configuration) -> TaintAnalysisResult:
        """
        Analyze all functions in a Cppcheck configuration.

        Args:
            cfg: A cppcheckdata Configuration object

        Returns:
            Combined analysis results
        """
        import time
        start_time = time.time()

        all_violations: List[TaintViolation] = []
        analyzed_functions: Set[str] = set()

        scopes = getattr(cfg, "scopes", [])
        for scope in scopes:
            scope_type = getattr(scope, "type", "")
            if scope_type == "Function":
                result = self.analyze_function(scope)
                all_violations.extend(result.violations)
                analyzed_functions.update(result.analyzed_functions)

        elapsed_ms = (time.time() - start_time) * 1000

        return TaintAnalysisResult(
            violations=all_violations,
            analyzed_functions=analyzed_functions,
            analysis_time_ms=elapsed_ms,
        )

    # ─────────────────────────────────────────────────────────────────
    #  Internal analysis methods
    # ─────────────────────────────────────────────────────────────────

    def _create_initial_state(self, scope: Scope) -> TaintState:
        """
        Create the initial taint state for a function.

        Marks parameters and globals as tainted according to config.
        """
        state = TaintState.initial()
        func_name = getattr(scope, "className", "")

        # Mark tainted parameters
        func = getattr(scope, "function", None)
        if func:
            arg_list = getattr(func, "argument", {})
            for idx, arg in arg_list.items():
                arg_idx = int(idx) - 1  # Cppcheck uses 1-based indexing
                if self.config.is_parameter_tainted(func_name, arg_idx):
                    var_id = getattr(arg, "nameTokenId", 0)
                    if var_id:
                        source_id = f"param:{func_name}:{arg_idx}"
                        state = state.taint(var_id, source_id)

        # Mark tainted globals
        for global_name in self.config.tainted_globals:
            state = state.taint(
                f"global:{global_name}", f"global:{global_name}")

        return state

    def _analyze_tokens(
        self,
        initial_state: TaintState,
        start_token: Token,
        end_token: Token
    ) -> TaintState:
        """
        Analyze a sequence of tokens with forward dataflow.

        This is a simplified intraprocedural analysis that processes
        tokens in order. For more sophisticated analysis with proper
        CFG handling, use the dataflow_engine module.
        """
        state = initial_state
        current = start_token

        iterations = 0
        while current is not None and iterations < self.max_iterations:
            iterations += 1

            # Skip non-AST tokens
            if current is end_token:
                break

            # Process AST roots (top-level expressions/statements)
            ast_parent = tok_parent(current)
            if ast_parent is None and (tok_op1(current) is not None or tok_op2(current) is not None):
                # This is an AST root
                state = self._analyze_statement(state, current)

            # Check for sinks at this token
            self._check_sinks(state, current)

            current = getattr(current, "next", None)

        return state

    def _analyze_statement(self, state: TaintState, token: Token) -> TaintState:
        """Analyze a single statement and update taint state."""
        # Apply transfer function
        new_state = self._transfer.transfer(state, token)

        # Handle special cases
        s = tok_str(token)

        # Assignment: check if RHS is a source function call
        if is_assignment(token):
            rhs = tok_op2(token)
            lhs = tok_op1(token)
            if rhs and is_function_call(rhs):
                func_name = get_called_function_name(rhs)
                for source in self.config.get_sources(func_name):
                    if source.kind == SourceKind.RETURN_VALUE:
                        # LHS becomes tainted
                        new_state = new_state.set_token(
                            lhs,
                            TaintValue.tainted(source.source_id())
                        )
                        if self.verbose:
                            print(
                                f"  Source: {func_name}() taints {expr_to_string(lhs)}")

                # Check if RHS is a sanitizer
                for sanitizer in self.config.get_sanitizers(func_name):
                    if sanitizer.sanitizes_return:
                        new_state = new_state.set_token(
                            lhs, TaintValue.untainted())
                        if self.verbose:
                            print(
                                f"  Sanitizer: {func_name}() cleans {expr_to_string(lhs)}")

        return new_state

    def _check_sinks(self, state: TaintState, token: Token) -> None:
        """Check if any sinks are reached with tainted data."""
        if not is_function_call(token):
            return

        func_name = get_called_function_name(token)
        if not self.config.is_sink(func_name):
            return

        args = get_call_arguments(token)

        for sink in self.config.get_sinks(func_name):
            # Determine which argument to check
            if sink.argument_index == -1:
                # Check all arguments
                args_to_check = list(enumerate(args))
            elif 0 <= sink.argument_index < len(args):
                args_to_check = [
                    (sink.argument_index, args[sink.argument_index])]
            else:
                continue

            for arg_idx, arg in args_to_check:
                taint = self._transfer.get_expression_taint(state, arg)

                if taint.may_be_tainted():
                    # Check if there's a valid sanitizer in the path
                    # (This is a simplified check; full path analysis would be more precise)
                    is_sanitized = self._is_sanitized_for_sink(
                        state, arg, sink.kind)

                    if not is_sanitized:
                        # Create violation
                        flow_path = None
                        if self.track_flow_paths:
                            flow_path = self._build_flow_path(state, arg, sink)

                        violation = TaintViolation(
                            sink=sink,
                            sink_token=token,
                            sink_kind=sink.kind,
                            taint_sources=taint.sources,
                            flow_path=flow_path,
                            severity=sink.severity,
                            confidence=0.9 if taint.is_tainted() else 0.7,
                            cwe=sink.cwe,
                            message=f"Tainted data from {taint.sources} reaches {func_name}()"
                        )

                        self._violations.append(violation)

                        if self.verbose:
                            print(f"  VIOLATION: {violation.format_message()}")

    def _is_sanitized_for_sink(
        self,
        state: TaintState,
        arg: Token,
        sink_kind: SinkKind
    ) -> bool:
        """
        Check if an argument has been properly sanitized for a sink kind.

        This is a simplified check. A full implementation would track
        sanitization through the flow path.
        """
        # For now, we rely on the taint state being properly updated
        # when sanitizers are called. If the value is still tainted,
        # it wasn't sanitized.
        return False

    def _build_flow_path(
        self,
        state: TaintState,
        sink_arg: Token,
        sink: TaintSink
    ) -> TaintFlowPath:
        """
        Build a flow path from sources to sink.

        This is a simplified implementation that creates a basic path.
        A full implementation would perform backward slicing.
        """
        path = TaintFlowPath(sink=sink)

        # Add source information from taint
        taint = state.get_token(sink_arg)
        for source_id in taint.sources:
            path.add_step(
                sink_arg,
                f"Taint from {source_id}",
                kind="source"
            )

        # Add sink step
        path.add_sink_step(sink_arg, sink)

        return path


# ═══════════════════════════════════════════════════════════════════════════
#  PART 8 — PREDEFINED CONFIGURATIONS
# ═══════════════════════════════════════════════════════════════════════════

def create_default_config() -> TaintConfig:
    """
    Create a default taint configuration with common sources and sinks.

    This provides a reasonable starting point for security analysis.

    Returns:
        A TaintConfig with common security-relevant specifications
    """
    config = TaintConfig()

    # ─────────────────────────────────────────────────────────────────
    #  SOURCES: User input functions
    # ─────────────────────────────────────────────────────────────────

    # Standard input
    config.add_source(TaintSource(
        function="gets",
        kind=SourceKind.RETURN_VALUE,
        description="Reads line from stdin (DANGEROUS)",
        cwe=242,
    ))
    config.add_source(TaintSource(
        function="fgets",
        kind=SourceKind.ARGUMENT_OUT,
        argument_index=0,
        description="Reads line from stream",
    ))
    config.add_source(TaintSource(
        function="scanf",
        kind=SourceKind.ARGUMENT_OUT,
        argument_index=1,  # First variadic argument
        description="Formatted input from stdin",
    ))
    config.add_source(TaintSource(
        function="fscanf",
        kind=SourceKind.ARGUMENT_OUT,
        argument_index=2,
        description="Formatted input from stream",
    ))
    config.add_source(TaintSource(
        function="getchar",
        kind=SourceKind.RETURN_VALUE,
        description="Single character from stdin",
    ))
    config.add_source(TaintSource(
        function="fgetc",
        kind=SourceKind.RETURN_VALUE,
        description="Single character from stream",
    ))
    config.add_source(TaintSource(
        function="getc",
        kind=SourceKind.RETURN_VALUE,
        description="Single character from stream",
    ))
    config.add_source(TaintSource(
        function="fread",
        kind=SourceKind.ARGUMENT_OUT,
        argument_index=0,
        description="Binary read from stream",
    ))
    config.add_source(TaintSource(
        function="read",
        kind=SourceKind.ARGUMENT_OUT,
        argument_index=1,
        description="POSIX read from file descriptor",
    ))
    config.add_source(TaintSource(
        function="recv",
        kind=SourceKind.ARGUMENT_OUT,
        argument_index=1,
        description="Receive from socket",
    ))
    config.add_source(TaintSource(
        function="recvfrom",
        kind=SourceKind.ARGUMENT_OUT,
        argument_index=1,
        description="Receive from socket with address",
    ))
    config.add_source(TaintSource(
        function="recvmsg",
        kind=SourceKind.ARGUMENT_OUT,
        argument_index=1,
        description="Receive message from socket",
    ))

    # Environment
    config.add_source(TaintSource(
        function="getenv",
        kind=SourceKind.RETURN_VALUE,
        description="Environment variable",
        cwe=78,
    ))
    config.add_source(TaintSource(
        function="secure_getenv",
        kind=SourceKind.RETURN_VALUE,
        description="Secure environment variable access",
    ))

    # Command line (via main parameters)
    config.add_tainted_parameter("main", 1)  # argv

    # ─────────────────────────────────────────────────────────────────
    #  SINKS: Dangerous functions
    # ─────────────────────────────────────────────────────────────────

    # Command injection
    config.add_sink(TaintSink(
        function="system",
        argument_index=0,
        kind=SinkKind.COMMAND_INJECTION,
        description="Shell command execution",
        cwe=78,
        severity=10,
    ))
    config.add_sink(TaintSink(
        function="popen",
        argument_index=0,
        kind=SinkKind.COMMAND_INJECTION,
        description="Shell command with pipe",
        cwe=78,
        severity=10,
    ))
    config.add_sink(TaintSink(
        function="execl",
        argument_index=0,
        kind=SinkKind.COMMAND_INJECTION,
        description="Execute program",
        cwe=78,
        severity=9,
    ))
    config.add_sink(TaintSink(
        function="execle",
        argument_index=0,
        kind=SinkKind.COMMAND_INJECTION,
        cwe=78,
        severity=9,
    ))
    config.add_sink(TaintSink(
        function="execlp",
        argument_index=0,
        kind=SinkKind.COMMAND_INJECTION,
        cwe=78,
        severity=9,
    ))
    config.add_sink(TaintSink(
        function="execv",
        argument_index=0,
        kind=SinkKind.COMMAND_INJECTION,
        cwe=78,
        severity=9,
    ))
    config.add_sink(TaintSink(
        function="execve",
        argument_index=0,
        kind=SinkKind.COMMAND_INJECTION,
        cwe=78,
        severity=9,
    ))
    config.add_sink(TaintSink(
        function="execvp",
        argument_index=0,
        kind=SinkKind.COMMAND_INJECTION,
        cwe=78,
        severity=9,
    ))

    # Format string
    config.add_sink(TaintSink(
        function="printf",
        argument_index=0,
        kind=SinkKind.FORMAT_STRING,
        description="Format string vulnerability",
        cwe=134,
        severity=8,
    ))
    config.add_sink(TaintSink(
        function="fprintf",
        argument_index=1,
        kind=SinkKind.FORMAT_STRING,
        cwe=134,
        severity=8,
    ))
    config.add_sink(TaintSink(
        function="sprintf",
        argument_index=1,
        kind=SinkKind.FORMAT_STRING,
        cwe=134,
        severity=8,
    ))
    config.add_sink(TaintSink(
        function="snprintf",
        argument_index=2,
        kind=SinkKind.FORMAT_STRING,
        cwe=134,
        severity=8,
    ))
    config.add_sink(TaintSink(
        function="syslog",
        argument_index=1,
        kind=SinkKind.FORMAT_STRING,
        cwe=134,
        severity=8,
    ))

    # Path traversal
    config.add_sink(TaintSink(
        function="fopen",
        argument_index=0,
        kind=SinkKind.PATH_TRAVERSAL,
        description="File open with user path",
        cwe=22,
        severity=7,
    ))
    config.add_sink(TaintSink(
        function="open",
        argument_index=0,
        kind=SinkKind.PATH_TRAVERSAL,
        cwe=22,
        severity=7,
    ))
    config.add_sink(TaintSink(
        function="openat",
        argument_index=1,
        kind=SinkKind.PATH_TRAVERSAL,
        cwe=22,
        severity=7,
    ))
    config.add_sink(TaintSink(
        function="creat",
        argument_index=0,
        kind=SinkKind.PATH_TRAVERSAL,
        cwe=22,
        severity=7,
    ))
    config.add_sink(TaintSink(
        function="mkdir",
        argument_index=0,
        kind=SinkKind.PATH_TRAVERSAL,
        cwe=22,
        severity=6,
    ))
    config.add_sink(TaintSink(
        function="rmdir",
        argument_index=0,
        kind=SinkKind.PATH_TRAVERSAL,
        cwe=22,
        severity=7,
    ))
    config.add_sink(TaintSink(
        function="unlink",
        argument_index=0,
        kind=SinkKind.PATH_TRAVERSAL,
        cwe=22,
        severity=8,
    ))
    config.add_sink(TaintSink(
        function="remove",
        argument_index=0,
        kind=SinkKind.PATH_TRAVERSAL,
        cwe=22,
        severity=8,
    ))
    config.add_sink(TaintSink(
        function="rename",
        argument_index=0,
        kind=SinkKind.PATH_TRAVERSAL,
        cwe=22,
        severity=7,
    ))
    config.add_sink(TaintSink(
        function="rename",
        argument_index=1,
        kind=SinkKind.PATH_TRAVERSAL,
        cwe=22,
        severity=7,
    ))
    config.add_sink(TaintSink(
        function="chdir",
        argument_index=0,
        kind=SinkKind.PATH_TRAVERSAL,
        cwe=22,
        severity=5,
    ))
    config.add_sink(TaintSink(
        function="chroot",
        argument_index=0,
        kind=SinkKind.PATH_TRAVERSAL,
        cwe=22,
        severity=8,
    ))

    # Buffer overflow via tainted size
    config.add_sink(TaintSink(
        function="malloc",
        argument_index=0,
        kind=SinkKind.MEMORY_ALLOCATION,
        description="Allocation with tainted size",
        cwe=789,
        severity=6,
    ))
    config.add_sink(TaintSink(
        function="calloc",
        argument_index=0,
        kind=SinkKind.MEMORY_ALLOCATION,
        cwe=789,
        severity=6,
    ))
    config.add_sink(TaintSink(
        function="calloc",
        argument_index=1,
        kind=SinkKind.MEMORY_ALLOCATION,
        cwe=789,
        severity=6,
    ))
    config.add_sink(TaintSink(
        function="realloc",
        argument_index=1,
        kind=SinkKind.MEMORY_ALLOCATION,
        cwe=789,
        severity=6,
    ))
    config.add_sink(TaintSink(
        function="memcpy",
        argument_index=2,
        kind=SinkKind.BUFFER_SIZE,
        description="Copy with tainted size",
        cwe=120,
        severity=8,
    ))
    config.add_sink(TaintSink(
        function="memmove",
        argument_index=2,
        kind=SinkKind.BUFFER_SIZE,
        cwe=120,
        severity=8,
    ))
    config.add_sink(TaintSink(
        function="memset",
        argument_index=2,
        kind=SinkKind.BUFFER_SIZE,
        cwe=120,
        severity=7,
    ))
    config.add_sink(TaintSink(
        function="strncpy",
        argument_index=2,
        kind=SinkKind.BUFFER_SIZE,
        cwe=120,
        severity=7,
    ))
    config.add_sink(TaintSink(
        function="strncat",
        argument_index=2,
        kind=SinkKind.BUFFER_SIZE,
        cwe=120,
        severity=7,
    ))

    # ─────────────────────────────────────────────────────────────────
    #  SANITIZERS: Validation functions
    # ─────────────────────────────────────────────────────────────────

    # Note: These are examples; real sanitizers depend on the application
    config.add_sanitizer(TaintSanitizer(
        function="realpath",
        argument_index=0,
        sanitizes_return=True,
        valid_for_sinks=frozenset({SinkKind.PATH_TRAVERSAL}),
        description="Resolves to canonical path",
    ))
    config.add_sanitizer(TaintSanitizer(
        function="basename",
        argument_index=0,
        sanitizes_return=True,
        valid_for_sinks=frozenset({SinkKind.PATH_TRAVERSAL}),
        description="Extracts filename component",
    ))

    # ─────────────────────────────────────────────────────────────────
    #  PROPAGATORS: String functions
    # ─────────────────────────────────────────────────────────────────

    config.add_propagator(TaintPropagator(
        function="strcpy",
        propagation_kind=PropagationKind.COPY,
        from_arguments=frozenset({1}),
        to_return=False,
        to_arguments=frozenset({0}),
        description="Copies string, propagates taint to destination",
    ))
    config.add_propagator(TaintPropagator(
        function="strncpy",
        propagation_kind=PropagationKind.COPY,
        from_arguments=frozenset({1}),
        to_return=False,
        to_arguments=frozenset({0}),
    ))
    config.add_propagator(TaintPropagator(
        function="strcat",
        propagation_kind=PropagationKind.MERGE,
        from_arguments=frozenset({0, 1}),
        to_return=False,
        to_arguments=frozenset({0}),
        description="Concatenates strings, merges taint",
    ))
    config.add_propagator(TaintPropagator(
        function="strncat",
        propagation_kind=PropagationKind.MERGE,
        from_arguments=frozenset({0, 1}),
        to_return=False,
        to_arguments=frozenset({0}),
    ))
    config.add_propagator(TaintPropagator(
        function="strdup",
        propagation_kind=PropagationKind.COPY,
        from_arguments=frozenset({0}),
        to_return=True,
        description="Duplicates string with taint",
    ))
    config.add_propagator(TaintPropagator(
        function="strndup",
        propagation_kind=PropagationKind.COPY,
        from_arguments=frozenset({0}),
        to_return=True,
    ))
    config.add_propagator(TaintPropagator(
        function="sprintf",
        propagation_kind=PropagationKind.MERGE,
        from_arguments=frozenset(),  # All variadic args
        to_return=False,
        to_arguments=frozenset({0}),
        description="Formatted output to string",
    ))
    config.add_propagator(TaintPropagator(
        function="snprintf",
        propagation_kind=PropagationKind.MERGE,
        from_arguments=frozenset(),
        to_return=False,
        to_arguments=frozenset({0}),
    ))
    config.add_propagator(TaintPropagator(
        function="memcpy",
        propagation_kind=PropagationKind.COPY,
        from_arguments=frozenset({1}),
        to_return=False,
        to_arguments=frozenset({0}),
        description="Memory copy propagates taint",
    ))
    config.add_propagator(TaintPropagator(
        function="memmove",
        propagation_kind=PropagationKind.COPY,
        from_arguments=frozenset({1}),
        to_return=False,
        to_arguments=frozenset({0}),
    ))

    # Functions that don't propagate taint (return computed values)
    config.add_propagator(TaintPropagator(
        function="strlen",
        propagation_kind=PropagationKind.NONE,
        to_return=True,
        description="Returns length, not tainted content",
    ))
    config.add_propagator(TaintPropagator(
        function="strcmp",
        propagation_kind=PropagationKind.NONE,
        to_return=True,
    ))
    config.add_propagator(TaintPropagator(
        function="strncmp",
        propagation_kind=PropagationKind.NONE,
        to_return=True,
    ))
    config.add_propagator(TaintPropagator(
        function="memcmp",
        propagation_kind=PropagationKind.NONE,
        to_return=True,
    ))

    return config


def create_sql_injection_config() -> TaintConfig:
    """
    Create a taint configuration focused on SQL injection detection.

    Returns:
        A TaintConfig for SQL injection analysis
    """
    config = create_default_config()

    # Add SQL-specific sinks
    sql_functions = [
        "mysql_query", "mysql_real_query",
        "sqlite3_exec", "sqlite3_prepare", "sqlite3_prepare_v2",
        "PQexec", "PQexecParams",  # PostgreSQL
        "SQLExecDirect", "SQLExecute",  # ODBC
    ]

    for func in sql_functions:
        config.add_sink(TaintSink(
            function=func,
            argument_index=1 if "sqlite" in func else 0,
            kind=SinkKind.SQL_INJECTION,
            description=f"SQL query execution via {func}",
            cwe=89,
            severity=9,
        ))

    # SQL-specific sanitizers (parameterized queries)
    config.add_sanitizer(TaintSanitizer(
        function="mysql_real_escape_string",
        argument_index=1,
        sanitizes_return=False,
        sanitizes_in_place=True,
        valid_for_sinks=frozenset({SinkKind.SQL_INJECTION}),
        description="MySQL string escaping",
    ))
    config.add_sanitizer(TaintSanitizer(
        function="sqlite3_bind_text",
        argument_index=2,
        sanitizes_return=False,
        sanitizes_in_place=False,
        valid_for_sinks=frozenset({SinkKind.SQL_INJECTION}),
        description="SQLite parameterized binding",
    ))
    config.add_sanitizer(TaintSanitizer(
        function="PQescapeStringConn",
        argument_index=2,
        sanitizes_return=False,
        sanitizes_in_place=True,
        valid_for_sinks=frozenset({SinkKind.SQL_INJECTION}),
        description="PostgreSQL string escaping",
    ))

    return config


def create_xss_config() -> TaintConfig:
    """
    Create a taint configuration focused on XSS detection.

    Returns:
        A TaintConfig for XSS analysis
    """
    config = create_default_config()

    # Web output functions as sinks
    web_output_functions = [
        ("printf", 0),   # When used for web output
        ("fprintf", 1),
        ("fputs", 0),
        ("fwrite", 0),
        ("write", 1),
        ("send", 1),
    ]

    for func, arg_idx in web_output_functions:
        config.add_sink(TaintSink(
            function=func,
            argument_index=arg_idx,
            kind=SinkKind.XSS,
            description=f"Potential XSS via {func}",
            cwe=79,
            severity=7,
        ))

    # HTML encoding sanitizers
    config.add_sanitizer(TaintSanitizer(
        function="htmlspecialchars",
        argument_index=0,
        sanitizes_return=True,
        valid_for_sinks=frozenset({SinkKind.XSS}),
        description="HTML entity encoding",
    ))
    config.add_sanitizer(TaintSanitizer(
        function="html_encode",
        argument_index=0,
        sanitizes_return=True,
        valid_for_sinks=frozenset({SinkKind.XSS}),
    ))
    config.add_sanitizer(TaintSanitizer(
        function="escape_html",
        argument_index=0,
        sanitizes_return=True,
        valid_for_sinks=frozenset({SinkKind.XSS}),
    ))

    return config


# ═══════════════════════════════════════════════════════════════════════════
#  PART 9 — CONVENIENCE FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════

def analyze_for_command_injection(cfg: Configuration) -> List[TaintViolation]:
    """
    Convenience function to analyze for command injection vulnerabilities.

    Args:
        cfg: A cppcheckdata Configuration object

    Returns:
        List of command injection violations
    """
    config = create_default_config()
    analyzer = TaintAnalyzer(config)
    result = analyzer.analyze_configuration(cfg)
    return result.get_violations_by_kind(SinkKind.COMMAND_INJECTION)


def analyze_for_format_string(cfg: Configuration) -> List[TaintViolation]:
    """
    Convenience function to analyze for format string vulnerabilities.

    Args:
        cfg: A cppcheckdata Configuration object

    Returns:
        List of format string violations
    """
    config = create_default_config()
    analyzer = TaintAnalyzer(config)
    result = analyzer.analyze_configuration(cfg)
    return result.get_violations_by_kind(SinkKind.FORMAT_STRING)


def analyze_for_path_traversal(cfg: Configuration) -> List[TaintViolation]:
    """
    Convenience function to analyze for path traversal vulnerabilities.

    Args:
        cfg: A cppcheckdata Configuration object

    Returns:
        List of path traversal violations
    """
    config = create_default_config()
    analyzer = TaintAnalyzer(config)
    result = analyzer.analyze_configuration(cfg)
    return result.get_violations_by_kind(SinkKind.PATH_TRAVERSAL)


def analyze_for_sql_injection(cfg: Configuration) -> List[TaintViolation]:
    """
    Convenience function to analyze for SQL injection vulnerabilities.

    Args:
        cfg: A cppcheckdata Configuration object

    Returns:
        List of SQL injection violations
    """
    config = create_sql_injection_config()
    analyzer = TaintAnalyzer(config)
    result = analyzer.analyze_configuration(cfg)
    return result.get_violations_by_kind(SinkKind.SQL_INJECTION)


def analyze_for_buffer_overflow(cfg: Configuration) -> List[TaintViolation]:
    """
    Convenience function to analyze for buffer overflow via tainted sizes.

    Args:
        cfg: A cppcheckdata Configuration object

    Returns:
        List of buffer overflow violations
    """
    config = create_default_config()
    analyzer = TaintAnalyzer(config)
    result = analyzer.analyze_configuration(cfg)
    return (
        result.get_violations_by_kind(SinkKind.BUFFER_SIZE) +
        result.get_violations_by_kind(SinkKind.MEMORY_ALLOCATION)
    )


def analyze_all_vulnerabilities(cfg: Configuration) -> TaintAnalysisResult:
    """
    Analyze for all supported vulnerability types.

    Args:
        cfg: A cppcheckdata Configuration object

    Returns:
        Complete analysis result with all violations
    """
    config = create_default_config()
    analyzer = TaintAnalyzer(config, track_flow_paths=True)
    return analyzer.analyze_configuration(cfg)


# ═══════════════════════════════════════════════════════════════════════════
#  PART 10 — REPORTING UTILITIES
# ═══════════════════════════════════════════════════════════════════════════

class TaintReportFormat(Enum):
    """Output format for taint analysis reports."""
    TEXT = auto()
    JSON = auto()
    SARIF = auto()
    CSV = auto()


def format_violations_text(violations: List[TaintViolation]) -> str:
    """
    Format violations as human-readable text.

    Args:
        violations: List of violations to format

    Returns:
        Formatted text report
    """
    if not violations:
        return "No taint violations detected.\n"

    lines = [
        f"╔══════════════════════════════════════════════════════════════╗",
        f"║             TAINT ANALYSIS REPORT                            ║",
        f"║             {len(violations)} violation(s) detected                       ║",
        f"╚══════════════════════════════════════════════════════════════╝",
        "",
    ]

    # Group by severity
    by_severity: Dict[int, List[TaintViolation]] = defaultdict(list)
    for v in violations:
        by_severity[v.severity].append(v)

    for severity in sorted(by_severity.keys(), reverse=True):
        severity_violations = by_severity[severity]
        lines.append(
            f"═══ Severity {severity}/10 ({len(severity_violations)} issues) ═══")
        lines.append("")

        for i, v in enumerate(severity_violations, 1):
            lines.append(f"[{i}] {v.sink_kind.name}")
            lines.append(f"    Location: {v.location}")
            lines.append(f"    Function: {v.function}()")
            if v.cwe:
                lines.append(f"    CWE: CWE-{v.cwe}")
            lines.append(f"    Confidence: {v.confidence:.0%}")
            if v.taint_sources:
                lines.append(f"    Sources: {', '.join(v.taint_sources)}")
            if v.flow_path and v.flow_path.steps:
                lines.append(f"    Flow path:")
                for step in v.flow_path.steps:
                    lines.append(f"      → {step}")
            lines.append("")

    return "\n".join(lines)


def format_violations_json(violations: List[TaintViolation]) -> str:
    """
    Format violations as JSON.

    Args:
        violations: List of violations to format

    Returns:
        JSON string
    """
    import json

    data = {
        "version": "1.0",
        "total_violations": len(violations),
        "violations": []
    }

    for v in violations:
        violation_data = {
            "kind": v.sink_kind.name,
            "location": v.location,
            "function": v.function,
            "argument_index": v.argument_index,
            "severity": v.severity,
            "confidence": v.confidence,
            "cwe": v.cwe,
            "message": v.format_message(),
            "sources": list(v.taint_sources),
        }

        if v.flow_path and v.flow_path.steps:
            violation_data["flow_path"] = [
                {"location": s.location, "description": s.description, "kind": s.kind}
                for s in v.flow_path.steps
            ]

        data["violations"].append(violation_data)

    return json.dumps(data, indent=2)


def format_violations_csv(violations: List[TaintViolation]) -> str:
    """
    Format violations as CSV.

    Args:
        violations: List of violations to format

    Returns:
        CSV string
    """
    import csv
    import io

    output = io.StringIO()
    writer = csv.writer(output)

    # Header
    writer.writerow([
        "Kind", "Location", "Function", "Argument", "Severity",
        "Confidence", "CWE", "Sources", "Message"
    ])

    # Data rows
    for v in violations:
        writer.writerow([
            v.sink_kind.name,
            v.location,
            v.function,
            v.argument_index,
            v.severity,
            f"{v.confidence:.2f}",
            v.cwe or "",
            ";".join(v.taint_sources),
            v.format_message(),
        ])

    return output.getvalue()


def format_violations_sarif(
    violations: List[TaintViolation],
    tool_name: str = "cppcheckdata_shims.taint_analysis",
    tool_version: str = "1.0.0"
) -> str:
    """
    Format violations as SARIF (Static Analysis Results Interchange Format).

    SARIF is a standard format for static analysis tools, supported by
    GitHub, Azure DevOps, and many other platforms.

    Args:
        violations: List of violations to format
        tool_name: Name of the analysis tool
        tool_version: Version of the analysis tool

    Returns:
        SARIF JSON string
    """
    import json

    # Build rules from unique sink kinds
    rules = {}
    for v in violations:
        rule_id = f"TAINT-{v.sink_kind.name}"
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": v.sink_kind.name,
                "shortDescription": {
                    "text": f"Tainted data reaches {v.sink_kind.name} sink"
                },
                "fullDescription": {
                    "text": v.sink.description if v.sink.description else f"Potential {v.sink_kind.name} vulnerability"
                },
                "defaultConfiguration": {
                    "level": "error" if v.severity >= 7 else "warning" if v.severity >= 4 else "note"
                },
                "properties": {
                    "security-severity": str(v.severity),
                }
            }
            if v.cwe:
                rules[rule_id]["properties"]["cwe"] = f"CWE-{v.cwe}"

    # Build results
    results = []
    for v in violations:
        # Parse location
        loc_parts = v.location.split(":")
        file_path = loc_parts[0] if loc_parts else "unknown"
        line = int(loc_parts[1]) if len(loc_parts) > 1 else 1
        column = int(loc_parts[2]) if len(loc_parts) > 2 else 1

        result = {
            "ruleId": f"TAINT-{v.sink_kind.name}",
            "level": "error" if v.severity >= 7 else "warning" if v.severity >= 4 else "note",
            "message": {
                "text": v.format_message()
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": file_path
                        },
                        "region": {
                            "startLine": line,
                            "startColumn": column
                        }
                    }
                }
            ],
            "properties": {
                "confidence": v.confidence,
                "sources": list(v.taint_sources),
            }
        }

        # Add code flow if available
        if v.flow_path and v.flow_path.steps:
            thread_flow_locations = []
            for step in v.flow_path.steps:
                step_loc_parts = step.location.split(":")
                step_file = step_loc_parts[0] if step_loc_parts else "unknown"
                step_line = int(step_loc_parts[1]) if len(
                    step_loc_parts) > 1 else 1
                step_col = int(step_loc_parts[2]) if len(
                    step_loc_parts) > 2 else 1

                thread_flow_locations.append({
                    "location": {
                        "physicalLocation": {
                            "artifactLocation": {"uri": step_file},
                            "region": {"startLine": step_line, "startColumn": step_col}
                        },
                        "message": {"text": step.description}
                    }
                })

            result["codeFlows"] = [
                {
                    "threadFlows": [
                        {"locations": thread_flow_locations}
                    ]
                }
            ]

        results.append(result)

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "version": tool_version,
                        "informationUri": "https://github.com/your/repo",
                        "rules": list(rules.values())
                    }
                },
                "results": results
            }
        ]
    }

    return json.dumps(sarif, indent=2)


def format_violations(
    violations: List[TaintViolation],
    format: TaintReportFormat = TaintReportFormat.TEXT
) -> str:
    """
    Format violations in the specified format.

    Args:
        violations: List of violations to format
        format: Output format

    Returns:
        Formatted string
    """
    if format == TaintReportFormat.TEXT:
        return format_violations_text(violations)
    elif format == TaintReportFormat.JSON:
        return format_violations_json(violations)
    elif format == TaintReportFormat.CSV:
        return format_violations_csv(violations)
    elif format == TaintReportFormat.SARIF:
        return format_violations_sarif(violations)
    else:
        raise ValueError(f"Unknown format: {format}")


def print_violations(
    violations: List[TaintViolation],
    format: TaintReportFormat = TaintReportFormat.TEXT
) -> None:
    """
    Print violations to stdout.

    Args:
        violations: List of violations to print
        format: Output format
    """
    print(format_violations(violations, format))


# ═══════════════════════════════════════════════════════════════════════════
#  PART 11 — INTEGRATION WITH DATAFLOW ENGINE
# ═══════════════════════════════════════════════════════════════════════════

class TaintDataflowAnalysis:
    """
    Taint analysis as a dataflow analysis problem.

    This class provides the interface expected by the dataflow_engine module,
    allowing taint analysis to be performed using the generic dataflow solver.

    Usage with dataflow_engine:
        from cppcheckdata_shims.dataflow_engine import ForwardDataflowSolver
        from cppcheckdata_shims.taint_analysis import TaintDataflowAnalysis

        analysis = TaintDataflowAnalysis(config)
        solver = ForwardDataflowSolver(cfg, analysis)
        result = solver.solve()
    """

    def __init__(self, config: TaintConfig):
        """
        Initialize the dataflow analysis.

        Args:
            config: Taint analysis configuration
        """
        self.config = config
        self._transfer = TaintTransfer(config)

    @property
    def direction(self) -> str:
        """Analysis direction: forward."""
        return "forward"

    @property
    def domain(self) -> type:
        """The abstract domain type."""
        return TaintState

    def initial_value(self) -> TaintState:
        """Initial value for entry node."""
        return TaintState.initial()

    def boundary_value(self) -> TaintState:
        """Boundary value (bottom)."""
        return TaintState.bottom()

    def transfer(self, node: Any, in_state: TaintState) -> TaintState:
        """
        Transfer function for a CFG node.

        Args:
            node: CFG node (from ctrlflow_graph module)
            in_state: Input taint state

        Returns:
            Output taint state
        """
        state = in_state

        # Process all tokens in the node
        tokens = getattr(node, "tokens", [])
        for token in tokens:
            state = self._transfer.transfer(state, token)

        return state

    def merge(self, states: Iterable[TaintState]) -> TaintState:
        """
        Merge multiple states at a control flow join.

        Args:
            states: States to merge

        Returns:
            Merged state
        """
        result = TaintState.bottom()
        for state in states:
            result = result.join(state)
        return result

    def check_node(
        self,
        node: Any,
        state: TaintState
    ) -> List[TaintViolation]:
        """
        Check a CFG node for taint violations.

        Args:
            node: CFG node to check
            state: Taint state at this node

        Returns:
            List of violations found
        """
        violations = []
        tokens = getattr(node, "tokens", [])

        for token in tokens:
            if is_function_call(token):
                func_name = get_called_function_name(token)
                if self.config.is_sink(func_name):
                    args = get_call_arguments(token)
                    for sink in self.config.get_sinks(func_name):
                        if 0 <= sink.argument_index < len(args):
                            arg = args[sink.argument_index]
                            taint = self._transfer.get_expression_taint(
                                state, arg)
                            if taint.may_be_tainted():
                                violation = TaintViolation(
                                    sink=sink,
                                    sink_token=token,
                                    sink_kind=sink.kind,
                                    taint_sources=taint.sources,
                                    severity=sink.severity,
                                    confidence=0.9 if taint.is_tainted() else 0.7,
                                    cwe=sink.cwe,
                                )
                                violations.append(violation)

        return violations


# ═══════════════════════════════════════════════════════════════════════════
#  PART 12 — INTER-PROCEDURAL TAINT ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class FunctionTaintSummary:
    """
    Summary of taint behavior for a function.

    Used for inter-procedural analysis to avoid re-analyzing called functions.

    Attributes:
        function_name: Name of the function
        parameter_taints: Mapping from parameter index to whether it's a source
        return_taint_depends_on: Set of parameter indices that affect return taint
        modifies_parameters: Set of parameter indices that may be modified
        calls_sinks: Whether the function may call a sink
        is_sanitizer: Whether the function acts as a sanitizer
    """
    function_name: str
    parameter_taints: Dict[int, bool] = field(default_factory=dict)
    return_taint_depends_on: Set[int] = field(default_factory=set)
    modifies_parameters: Set[int] = field(default_factory=set)
    calls_sinks: bool = False
    is_sanitizer: bool = False
    sanitizes_parameters: Set[int] = field(default_factory=set)
    sanitizes_return: bool = False

    def propagates_taint(self, from_param: int, to_return: bool = True) -> bool:
        """Check if taint propagates from a parameter."""
        if to_return:
            return from_param in self.return_taint_depends_on
        return False


class InterproceduralTaintAnalyzer:
    """
    Inter-procedural taint analysis using function summaries.

    This analyzer computes taint summaries for each function and uses
    them to perform context-insensitive inter-procedural analysis.

    Usage:
        analyzer = InterproceduralTaintAnalyzer(config)

        # Analyze all functions to build summaries
        analyzer.build_summaries(all_scopes)

        # Then analyze for violations
        violations = analyzer.analyze(cfg)
    """

    def __init__(self, config: TaintConfig):
        """
        Initialize the inter-procedural analyzer.

        Args:
            config: Taint analysis configuration
        """
        self.config = config
        self._summaries: Dict[str, FunctionTaintSummary] = {}
        self._intra_analyzer = TaintAnalyzer(config, track_flow_paths=False)

    def get_summary(self, function_name: str) -> Optional[FunctionTaintSummary]:
        """
        Get the summary for a function.

        Args:
            function_name: Name of the function

        Returns:
            The function summary, or None if not analyzed
        """
        return self._summaries.get(function_name)

    def build_summaries(self, scopes: Sequence[Scope]) -> None:
        """
        Build taint summaries for all functions.

        This performs a bottom-up analysis of the call graph to compute
        summaries.

        Args:
            scopes: All function scopes to analyze
        """
        # First pass: compute local summaries
        for scope in scopes:
            scope_type = getattr(scope, "type", "")
            if scope_type != "Function":
                continue

            func_name = getattr(scope, "className", "")
            if not func_name:
                continue

            summary = self._compute_local_summary(scope)
            self._summaries[func_name] = summary

        # Second pass: propagate through call graph
        # (simplified: would need proper fixpoint for recursive calls)
        changed = True
        iterations = 0
        max_iterations = 100

        while changed and iterations < max_iterations:
            changed = False
            iterations += 1

            for func_name, summary in self._summaries.items():
                # Check if any called function affects our summary
                # This would require tracking call sites, simplified here
                pass

    def _compute_local_summary(self, scope: Scope) -> FunctionTaintSummary:
        """
        Compute the local taint summary for a function.

        Args:
            scope: The function scope

        Returns:
            The computed summary
        """
        func_name = getattr(scope, "className", "")
        summary = FunctionTaintSummary(function_name=func_name)

        # Analyze the function
        result = self._intra_analyzer.analyze_function(scope)

        # Check if it calls any sinks
        summary.calls_sinks = result.has_violations()

        # Analyze parameter flow (simplified)
        func = getattr(scope, "function", None)
        if func:
            arg_list = getattr(func, "argument", {})
            num_params = len(arg_list)

            # For each parameter, check if it flows to return
            for i in range(num_params):
                # This is a simplification; full analysis would trace flows
                summary.return_taint_depends_on.add(i)
                summary.modifies_parameters.add(i)

        return summary

    def analyze_with_summaries(
        self,
        scope: Scope,
        initial_state: Optional[TaintState] = None
    ) -> TaintAnalysisResult:
        """
        Analyze a function using pre-computed summaries.

        Args:
            scope: The function scope to analyze
            initial_state: Initial taint state

        Returns:
            Analysis results
        """
        # Create a modified config that uses summaries for called functions
        modified_config = copy.copy(self.config)

        # Add propagators based on summaries
        for func_name, summary in self._summaries.items():
            if not modified_config.has_propagator(func_name):
                propagator = TaintPropagator(
                    function=func_name,
                    propagation_kind=PropagationKind.MERGE,
                    from_arguments=frozenset(summary.return_taint_depends_on),
                    to_return=True,
                    to_arguments=frozenset(summary.modifies_parameters),
                )
                modified_config.add_propagator(propagator)

        # Run analysis with modified config
        analyzer = TaintAnalyzer(modified_config, track_flow_paths=True)
        return analyzer.analyze_function(scope, initial_state)


# ═══════════════════════════════════════════════════════════════════════════
#  MODULE EXPORTS
# ═══════════════════════════════════════════════════════════════════════════

__all__ = [
    # Taint lattice
    "TaintLevel",
    "TaintValue",

    # Taint state
    "TaintState",

    # Configuration types
    "SourceKind",
    "SinkKind",
    "PropagationKind",
    "TaintSource",
    "TaintSink",
    "TaintSanitizer",
    "TaintPropagator",
    "TaintConfig",

    # Flow tracking
    "TaintFlowStep",
    "TaintFlowPath",

    # Violations
    "TaintViolation",

    # Analysis results
    "TaintAnalysisResult",

    # Main analyzer
    "TaintTransfer",
    "TaintAnalyzer",

    # Predefined configurations
    "create_default_config",
    "create_sql_injection_config",
    "create_xss_config",

    # Convenience functions
    "analyze_for_command_injection",
    "analyze_for_format_string",
    "analyze_for_path_traversal",
    "analyze_for_sql_injection",
    "analyze_for_buffer_overflow",
    "analyze_all_vulnerabilities",

    # Reporting
    "TaintReportFormat",
    "format_violations_text",
    "format_violations_json",
    "format_violations_csv",
    "format_violations_sarif",
    "format_violations",
    "print_violations",

    # Dataflow integration
    "TaintDataflowAnalysis",

    # Inter-procedural analysis
    "FunctionTaintSummary",
    "InterproceduralTaintAnalyzer",
]
