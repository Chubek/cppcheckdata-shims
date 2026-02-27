"""
casl/property_compiler.py - CASL Property Compiler

Compiles CASL property specifications to executable checker code.
Transforms temporal formulas (LTL/CTL), safety properties, and pattern-based
properties into PropertyProtocol implementations and Checker subclasses.

Architecture:
    Property AST → PropertyCompiler → Generated Checker Code
                                   → PropertyProtocol instances
                                   → State machine monitors

Integration points:
    - PropertyProtocol: For BoundedExplorer/SafetyChecker integration
    - Checker base class: For diagnostic emission
    - EventSequenceMatcher: For temporal sequence monitoring
    - AbstractVM: For bytecode-level property checking
"""

from __future__ import annotations

import ast as python_ast
import textwrap
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum, auto
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
    Protocol,
    Sequence,
    Set,
    Tuple,
    TypeVar,
    Union,
)

# =============================================================================
# Property AST Node Definitions (mirroring casl/ast.py structure)
# =============================================================================

class PropertyKind(Enum):
    """Classification of property types."""
    SAFETY = auto()      # AG !bad (invariant)
    LIVENESS = auto()    # AF good (eventually)
    RESPONSE = auto()    # AG(p -> AF q)
    PRECEDENCE = auto()  # !q W p (p before q)
    ABSENCE = auto()     # AG !p (never p)
    EXISTENCE = auto()   # EF p (possibly p)
    UNIVERSALITY = auto() # AG p (always p)
    BOUNDED = auto()     # Bounded temporal property


class TemporalOp(Enum):
    """Temporal operators for LTL/CTL."""
    # LTL operators
    NEXT = "X"       # Next state
    FINALLY = "F"    # Eventually/Finally
    GLOBALLY = "G"   # Always/Globally
    UNTIL = "U"      # Until
    WEAK_UNTIL = "W" # Weak until
    RELEASE = "R"    # Release
    
    # CTL path quantifiers (combined with temporal)
    AX = "AX"  # All paths, next
    EX = "EX"  # Exists path, next
    AF = "AF"  # All paths, finally
    EF = "EF"  # Exists path, finally
    AG = "AG"  # All paths, globally
    EG = "EG"  # Exists path, globally
    AU = "AU"  # All paths, until
    EU = "EU"  # Exists path, until


@dataclass(frozen=True, slots=True)
class SourceLocation:
    """Source location for error reporting."""
    file: str
    line: int
    column: int = 0
    
    def __str__(self) -> str:
        return f"{self.file}:{self.line}:{self.column}"


@dataclass(slots=True)
class PropertyNode(ABC):
    """Base class for property AST nodes."""
    loc: Optional[SourceLocation] = None
    
    @abstractmethod
    def accept(self, visitor: PropertyVisitor[T]) -> T:
        """Accept a visitor."""
        ...


T = TypeVar('T')


class PropertyVisitor(ABC, Generic[T]):
    """Visitor interface for property AST traversal."""
    
    @abstractmethod
    def visit_atomic(self, node: AtomicProp) -> T: ...
    
    @abstractmethod
    def visit_not(self, node: NotProp) -> T: ...
    
    @abstractmethod
    def visit_and(self, node: AndProp) -> T: ...
    
    @abstractmethod
    def visit_or(self, node: OrProp) -> T: ...
    
    @abstractmethod
    def visit_implies(self, node: ImpliesProp) -> T: ...
    
    @abstractmethod
    def visit_temporal(self, node: TemporalProp) -> T: ...
    
    @abstractmethod
    def visit_binary_temporal(self, node: BinaryTemporalProp) -> T: ...
    
    @abstractmethod
    def visit_pattern(self, node: PatternProp) -> T: ...
    
    @abstractmethod
    def visit_query_ref(self, node: QueryRefProp) -> T: ...


# --- Atomic propositions ---

@dataclass(slots=True)
class AtomicProp(PropertyNode):
    """
    Atomic proposition - base predicate in temporal formula.
    
    Can reference:
    - State predicates: (at-label "loop_head")
    - Query results: (query-holds my-query)
    - Variable conditions: (var-is-null ptr)
    - Event occurrences: (event-occurred "free")
    """
    predicate: str
    args: Tuple[Any, ...] = ()
    
    def accept(self, visitor: PropertyVisitor[T]) -> T:
        return visitor.visit_atomic(self)


# --- Boolean connectives ---

@dataclass(slots=True)
class NotProp(PropertyNode):
    """Negation."""
    operand: PropertyNode
    
    def accept(self, visitor: PropertyVisitor[T]) -> T:
        return visitor.visit_not(self)


@dataclass(slots=True)
class AndProp(PropertyNode):
    """Conjunction."""
    operands: Tuple[PropertyNode, ...]
    
    def accept(self, visitor: PropertyVisitor[T]) -> T:
        return visitor.visit_and(self)


@dataclass(slots=True)
class OrProp(PropertyNode):
    """Disjunction."""
    operands: Tuple[PropertyNode, ...]
    
    def accept(self, visitor: PropertyVisitor[T]) -> T:
        return visitor.visit_or(self)


@dataclass(slots=True)
class ImpliesProp(PropertyNode):
    """Implication."""
    antecedent: PropertyNode
    consequent: PropertyNode
    
    def accept(self, visitor: PropertyVisitor[T]) -> T:
        return visitor.visit_implies(self)


# --- Temporal operators ---

@dataclass(slots=True)
class TemporalProp(PropertyNode):
    """
    Unary temporal operator application.
    
    Examples:
        (G safe)      - Globally safe
        (F done)      - Finally done
        (X next_step) - Next state
        (AG !error)   - All paths, globally no error
        (EF goal)     - Exists path to goal
    """
    op: TemporalOp
    operand: PropertyNode
    
    def accept(self, visitor: PropertyVisitor[T]) -> T:
        return visitor.visit_temporal(self)


@dataclass(slots=True)
class BinaryTemporalProp(PropertyNode):
    """
    Binary temporal operator application.
    
    Examples:
        (U !freed used)     - !freed Until used
        (W init accessed)   - init Weak-until accessed
        (AU p q)            - All paths: p Until q
    """
    op: TemporalOp
    left: PropertyNode
    right: PropertyNode
    
    def accept(self, visitor: PropertyVisitor[T]) -> T:
        return visitor.visit_binary_temporal(self)


# --- High-level patterns ---

@dataclass(slots=True)
class PatternProp(PropertyNode):
    """
    Property specification pattern (from pattern catalog).
    
    Patterns are high-level templates that expand to temporal formulas:
        (never p)           → AG !p
        (eventually p)      → AF p  (or EF p depending on semantics)
        (always p before q) → A[!q W p]
        (responds p q)      → AG(p -> AF q)
        (precedes p q)      → !q W p
    """
    pattern_name: str
    args: Tuple[PropertyNode, ...]
    scope: Optional[str] = None  # "global", "before q", "after p", etc.
    
    def accept(self, visitor: PropertyVisitor[T]) -> T:
        return visitor.visit_pattern(self)


@dataclass(slots=True)
class QueryRefProp(PropertyNode):
    """
    Reference to a CSQL query result as atomic proposition.
    
    Example:
        (property use-after-free
          (never (query-match uaf-query)))
    """
    query_name: str
    binding_constraint: Optional[Dict[str, Any]] = None
    
    def accept(self, visitor: PropertyVisitor[T]) -> T:
        return visitor.visit_query_ref(self)


# =============================================================================
# Property Classification and Analysis
# =============================================================================

@dataclass(slots=True)
class PropertyAnalysis:
    """Analysis results for a property."""
    kind: PropertyKind
    is_safety: bool
    is_liveness: bool
    temporal_depth: int
    atomic_predicates: FrozenSet[str]
    referenced_queries: FrozenSet[str]
    can_monitor_online: bool
    estimated_complexity: str  # "O(1)", "O(n)", "O(n^2)", etc.


class PropertyClassifier(PropertyVisitor[PropertyAnalysis]):
    """Classifies and analyzes properties."""
    
    def __init__(self):
        self._atomic_preds: Set[str] = set()
        self._query_refs: Set[str] = set()
        self._depth = 0
        self._max_depth = 0
    
    def classify(self, prop: PropertyNode) -> PropertyAnalysis:
        """Classify a property and compute analysis."""
        self._atomic_preds.clear()
        self._query_refs.clear()
        self._depth = 0
        self._max_depth = 0
        
        result = prop.accept(self)
        return result
    
    def visit_atomic(self, node: AtomicProp) -> PropertyAnalysis:
        self._atomic_preds.add(node.predicate)
        return PropertyAnalysis(
            kind=PropertyKind.SAFETY,
            is_safety=True,
            is_liveness=False,
            temporal_depth=0,
            atomic_predicates=frozenset(self._atomic_preds),
            referenced_queries=frozenset(self._query_refs),
            can_monitor_online=True,
            estimated_complexity="O(1)"
        )
    
    def visit_not(self, node: NotProp) -> PropertyAnalysis:
        inner = node.operand.accept(self)
        return PropertyAnalysis(
            kind=inner.kind,
            is_safety=inner.is_liveness,  # negation flips safety/liveness
            is_liveness=inner.is_safety,
            temporal_depth=inner.temporal_depth,
            atomic_predicates=inner.atomic_predicates,
            referenced_queries=inner.referenced_queries,
            can_monitor_online=inner.can_monitor_online,
            estimated_complexity=inner.estimated_complexity
        )
    
    def visit_and(self, node: AndProp) -> PropertyAnalysis:
        analyses = [op.accept(self) for op in node.operands]
        return self._combine_analyses(analyses, all_safety=True)
    
    def visit_or(self, node: OrProp) -> PropertyAnalysis:
        analyses = [op.accept(self) for op in node.operands]
        return self._combine_analyses(analyses, all_safety=False)
    
    def visit_implies(self, node: ImpliesProp) -> PropertyAnalysis:
        ant = node.antecedent.accept(self)
        cons = node.consequent.accept(self)
        return self._combine_analyses([ant, cons], all_safety=False)
    
    def visit_temporal(self, node: TemporalProp) -> PropertyAnalysis:
        self._depth += 1
        self._max_depth = max(self._max_depth, self._depth)
        
        inner = node.operand.accept(self)
        self._depth -= 1
        
        # Classify based on temporal operator
        kind, is_safety, is_liveness = self._classify_temporal_op(node.op, inner)
        
        # Online monitoring possible for safety, harder for liveness
        can_monitor = is_safety or node.op in (TemporalOp.NEXT, TemporalOp.AX, TemporalOp.EX)
        
        return PropertyAnalysis(
            kind=kind,
            is_safety=is_safety,
            is_liveness=is_liveness,
            temporal_depth=self._max_depth,
            atomic_predicates=inner.atomic_predicates | frozenset(self._atomic_preds),
            referenced_queries=inner.referenced_queries | frozenset(self._query_refs),
            can_monitor_online=can_monitor,
            estimated_complexity="O(n)" if can_monitor else "O(n^2)"
        )
    
    def visit_binary_temporal(self, node: BinaryTemporalProp) -> PropertyAnalysis:
        self._depth += 1
        self._max_depth = max(self._max_depth, self._depth)
        
        left = node.left.accept(self)
        right = node.right.accept(self)
        self._depth -= 1
        
        # Until/Weak-until classification
        if node.op in (TemporalOp.UNTIL, TemporalOp.AU, TemporalOp.EU):
            kind = PropertyKind.LIVENESS
            is_safety = False
            is_liveness = True
        elif node.op in (TemporalOp.WEAK_UNTIL,):
            kind = PropertyKind.SAFETY
            is_safety = True
            is_liveness = False
        else:
            kind = PropertyKind.SAFETY
            is_safety = True
            is_liveness = False
        
        combined = self._combine_analyses([left, right], all_safety=is_safety)
        return PropertyAnalysis(
            kind=kind,
            is_safety=is_safety,
            is_liveness=is_liveness,
            temporal_depth=self._max_depth,
            atomic_predicates=combined.atomic_predicates,
            referenced_queries=combined.referenced_queries,
            can_monitor_online=is_safety,
            estimated_complexity="O(n)"
        )
    
    def visit_pattern(self, node: PatternProp) -> PropertyAnalysis:
        # Analyze pattern arguments
        arg_analyses = [arg.accept(self) for arg in node.args]
        
        # Classify pattern
        pattern_info = PATTERN_CLASSIFICATIONS.get(node.pattern_name.lower(), {
            'kind': PropertyKind.SAFETY,
            'is_safety': True,
            'is_liveness': False
        })
        
        combined = self._combine_analyses(arg_analyses, all_safety=pattern_info['is_safety'])
        return PropertyAnalysis(
            kind=pattern_info['kind'],
            is_safety=pattern_info['is_safety'],
            is_liveness=pattern_info['is_liveness'],
            temporal_depth=combined.temporal_depth + 1,
            atomic_predicates=combined.atomic_predicates,
            referenced_queries=combined.referenced_queries,
            can_monitor_online=pattern_info['is_safety'],
            estimated_complexity="O(n)"
        )
    
    def visit_query_ref(self, node: QueryRefProp) -> PropertyAnalysis:
        self._query_refs.add(node.query_name)
        return PropertyAnalysis(
            kind=PropertyKind.SAFETY,
            is_safety=True,
            is_liveness=False,
            temporal_depth=0,
            atomic_predicates=frozenset(self._atomic_preds),
            referenced_queries=frozenset(self._query_refs),
            can_monitor_online=True,
            estimated_complexity="O(q)"  # depends on query complexity
        )
    
    def _classify_temporal_op(
        self, 
        op: TemporalOp, 
        inner: PropertyAnalysis
    ) -> Tuple[PropertyKind, bool, bool]:
        """Classify property based on temporal operator."""
        # Safety operators (can be violated in finite time)
        if op in (TemporalOp.GLOBALLY, TemporalOp.AG, TemporalOp.EG):
            return PropertyKind.SAFETY, True, False
        
        # Liveness operators (require infinite traces to verify)
        if op in (TemporalOp.FINALLY, TemporalOp.AF):
            return PropertyKind.LIVENESS, False, True
        
        # EF is existential liveness
        if op == TemporalOp.EF:
            return PropertyKind.EXISTENCE, False, True
        
        # Next is bounded, effectively safety
        if op in (TemporalOp.NEXT, TemporalOp.AX, TemporalOp.EX):
            return PropertyKind.BOUNDED, True, False
        
        return inner.kind, inner.is_safety, inner.is_liveness
    
    def _combine_analyses(
        self, 
        analyses: List[PropertyAnalysis],
        all_safety: bool
    ) -> PropertyAnalysis:
        """Combine multiple analyses."""
        if not analyses:
            return PropertyAnalysis(
                kind=PropertyKind.SAFETY,
                is_safety=True,
                is_liveness=False,
                temporal_depth=0,
                atomic_predicates=frozenset(),
                referenced_queries=frozenset(),
                can_monitor_online=True,
                estimated_complexity="O(1)"
            )
        
        return PropertyAnalysis(
            kind=analyses[0].kind,  # simplified
            is_safety=all(a.is_safety for a in analyses) if all_safety else any(a.is_safety for a in analyses),
            is_liveness=any(a.is_liveness for a in analyses),
            temporal_depth=max(a.temporal_depth for a in analyses),
            atomic_predicates=frozenset().union(*(a.atomic_predicates for a in analyses)),
            referenced_queries=frozenset().union(*(a.referenced_queries for a in analyses)),
            can_monitor_online=all(a.can_monitor_online for a in analyses),
            estimated_complexity="O(n)"
        )


# Pattern classification lookup
PATTERN_CLASSIFICATIONS: Dict[str, Dict[str, Any]] = {
    'never': {'kind': PropertyKind.ABSENCE, 'is_safety': True, 'is_liveness': False},
    'always': {'kind': PropertyKind.UNIVERSALITY, 'is_safety': True, 'is_liveness': False},
    'eventually': {'kind': PropertyKind.EXISTENCE, 'is_safety': False, 'is_liveness': True},
    'responds': {'kind': PropertyKind.RESPONSE, 'is_safety': False, 'is_liveness': True},
    'precedes': {'kind': PropertyKind.PRECEDENCE, 'is_safety': True, 'is_liveness': False},
    'before': {'kind': PropertyKind.PRECEDENCE, 'is_safety': True, 'is_liveness': False},
    'after': {'kind': PropertyKind.PRECEDENCE, 'is_safety': True, 'is_liveness': False},
    'between': {'kind': PropertyKind.BOUNDED, 'is_safety': True, 'is_liveness': False},
}


# =============================================================================
# Pattern Expansion - High-level patterns to CTL/LTL
# =============================================================================

class PatternExpander(PropertyVisitor[PropertyNode]):
    """
    Expands high-level property patterns to explicit temporal formulas.
    
    Based on property specification patterns from the literature:
    - Dwyer et al. "Patterns in Property Specifications for Finite-State Verification"
    - Direct mappings from sca-spec-lang-for-abstract-interp.pdf
    """
    
    def expand(self, prop: PropertyNode) -> PropertyNode:
        """Expand all patterns in a property."""
        return prop.accept(self)
    
    def visit_atomic(self, node: AtomicProp) -> PropertyNode:
        return node
    
    def visit_not(self, node: NotProp) -> PropertyNode:
        return NotProp(operand=node.operand.accept(self), loc=node.loc)
    
    def visit_and(self, node: AndProp) -> PropertyNode:
        return AndProp(
            operands=tuple(op.accept(self) for op in node.operands),
            loc=node.loc
        )
    
    def visit_or(self, node: OrProp) -> PropertyNode:
        return OrProp(
            operands=tuple(op.accept(self) for op in node.operands),
            loc=node.loc
        )
    
    def visit_implies(self, node: ImpliesProp) -> PropertyNode:
        return ImpliesProp(
            antecedent=node.antecedent.accept(self),
            consequent=node.consequent.accept(self),
            loc=node.loc
        )
    
    def visit_temporal(self, node: TemporalProp) -> PropertyNode:
        return TemporalProp(
            op=node.op,
            operand=node.operand.accept(self),
            loc=node.loc
        )
    
    def visit_binary_temporal(self, node: BinaryTemporalProp) -> PropertyNode:
        return BinaryTemporalProp(
            op=node.op,
            left=node.left.accept(self),
            right=node.right.accept(self),
            loc=node.loc
        )
    
    def visit_pattern(self, node: PatternProp) -> PropertyNode:
        """
        Expand pattern to explicit temporal formula.
        
        Mappings (from sca-spec-lang-for-abstract-interp.pdf p9):
            NEVER a         → AG !a
            EVENTUALLY a    → EF a (or AF a for universal)
            ALWAYS a BEFORE b → A[!b W a]
            RESPONDS p q    → AG(p -> AF q)
            PRECEDES p q    → !q W p
        """
        pattern = node.pattern_name.lower()
        expanded_args = [arg.accept(self) for arg in node.args]
        
        if pattern == 'never':
            # NEVER a → AG !a
            if len(expanded_args) != 1:
                raise PropertyCompilationError(
                    f"'never' pattern requires exactly 1 argument, got {len(expanded_args)}",
                    node.loc
                )
            return TemporalProp(
                op=TemporalOp.AG,
                operand=NotProp(operand=expanded_args[0], loc=node.loc),
                loc=node.loc
            )
        
        elif pattern == 'always':
            # ALWAYS a → AG a
            if len(expanded_args) != 1:
                raise PropertyCompilationError(
                    f"'always' pattern requires exactly 1 argument, got {len(expanded_args)}",
                    node.loc
                )
            return TemporalProp(
                op=TemporalOp.AG,
                operand=expanded_args[0],
                loc=node.loc
            )
        
        elif pattern == 'eventually':
            # EVENTUALLY a → EF a (existential) or AF a (universal)
            if len(expanded_args) != 1:
                raise PropertyCompilationError(
                    f"'eventually' pattern requires exactly 1 argument, got {len(expanded_args)}",
                    node.loc
                )
            # Default to existential (EF) for "eventually"
            return TemporalProp(
                op=TemporalOp.EF,
                operand=expanded_args[0],
                loc=node.loc
            )
        
        elif pattern in ('before', 'always-before'):
            # ALWAYS a BEFORE b → A[!b W a] 
            # Meaning: a must happen before b (or b never happens)
            if len(expanded_args) != 2:
                raise PropertyCompilationError(
                    f"'before' pattern requires exactly 2 arguments, got {len(expanded_args)}",
                    node.loc
                )
            a, b = expanded_args
            # A[!b W a] - "not b" weak-until "a"
            return BinaryTemporalProp(
                op=TemporalOp.WEAK_UNTIL,
                left=NotProp(operand=b, loc=node.loc),
                right=a,
                loc=node.loc
            )
        
        elif pattern == 'responds':
            # RESPONDS p q → AG(p -> AF q)
            # Every p is eventually followed by q
            if len(expanded_args) != 2:
                raise PropertyCompilationError(
                    f"'responds' pattern requires exactly 2 arguments, got {len(expanded_args)}",
                    node.loc
                )
            p, q = expanded_args
            return TemporalProp(
                op=TemporalOp.AG,
                operand=ImpliesProp(
                    antecedent=p,
                    consequent=TemporalProp(op=TemporalOp.AF, operand=q, loc=node.loc),
                    loc=node.loc
                ),
                loc=node.loc
            )
        
        elif pattern == 'precedes':
            # PRECEDES p q → !q W p
            # p must precede q (or q never happens)
            if len(expanded_args) != 2:
                raise PropertyCompilationError(
                    f"'precedes' pattern requires exactly 2 arguments, got {len(expanded_args)}",
                    node.loc
                )
            p, q = expanded_args
            return BinaryTemporalProp(
                op=TemporalOp.WEAK_UNTIL,
                left=NotProp(operand=q, loc=node.loc),
                right=p,
                loc=node.loc
            )
        
        elif pattern == 'until':
            # UNTIL p q → p U q
            if len(expanded_args) != 2:
                raise PropertyCompilationError(
                    f"'until' pattern requires exactly 2 arguments, got {len(expanded_args)}",
                    node.loc
                )
            return BinaryTemporalProp(
                op=TemporalOp.UNTIL,
                left=expanded_args[0],
                right=expanded_args[1],
                loc=node.loc
            )
        
        elif pattern == 'absence-after':
            # ABSENCE p AFTER q → AG(q -> AG !p)
            # After q occurs, p never occurs
            if len(expanded_args) != 2:
                raise PropertyCompilationError(
                    f"'absence-after' pattern requires exactly 2 arguments, got {len(expanded_args)}",
                    node.loc
                )
            p, q = expanded_args
            return TemporalProp(
                op=TemporalOp.AG,
                operand=ImpliesProp(
                    antecedent=q,
                    consequent=TemporalProp(
                        op=TemporalOp.AG,
                        operand=NotProp(operand=p, loc=node.loc),
                        loc=node.loc
                    ),
                    loc=node.loc
                ),
                loc=node.loc
            )
        
        elif pattern == 'existence-between':
            # EXISTENCE p BETWEEN q AND r → AG(q -> A[!r W (p & !r)])
            if len(expanded_args) != 3:
                raise PropertyCompilationError(
                    f"'existence-between' pattern requires exactly 3 arguments, got {len(expanded_args)}",
                    node.loc
                )
            p, q, r = expanded_args
            return TemporalProp(
                op=TemporalOp.AG,
                operand=ImpliesProp(
                    antecedent=q,
                    consequent=BinaryTemporalProp(
                        op=TemporalOp.WEAK_UNTIL,
                        left=NotProp(operand=r, loc=node.loc),
                        right=AndProp(
                            operands=(p, NotProp(operand=r, loc=node.loc)),
                            loc=node.loc
                        ),
                        loc=node.loc
                    ),
                    loc=node.loc
                ),
                loc=node.loc
            )
        
        else:
            raise PropertyCompilationError(
                f"Unknown pattern: '{node.pattern_name}'",
                node.loc
            )
    
    def visit_query_ref(self, node: QueryRefProp) -> PropertyNode:
        # Query references become atomic propositions
        return AtomicProp(
            predicate='query-match',
            args=(node.query_name, node.binding_constraint),
            loc=node.loc
        )


# =============================================================================
# Compilation Error Types
# =============================================================================

class PropertyCompilationError(Exception):
    """Error during property compilation."""
    
    def __init__(self, message: str, loc: Optional[SourceLocation] = None):
        self.message = message
        self.loc = loc
        super().__init__(f"{loc}: {message}" if loc else message)


# =============================================================================
# Code Generation - Property to Executable Checker
# =============================================================================

@dataclass(slots=True)
class CompiledProperty:
    """Result of property compilation."""
    property_name: str
    property_kind: PropertyKind
    analysis: PropertyAnalysis
    checker_code: str           # Generated Python code for Checker subclass
    monitor_code: Optional[str] # Generated state machine monitor (if applicable)
    predicate_code: str         # Generated predicate evaluation code
    metadata: Dict[str, Any] = field(default_factory=dict)


class PropertyCodeGenerator(PropertyVisitor[str]):
    """
    Generates Python code for property checking.
    
    Produces:
    1. Checker subclass implementing collect_evidence/diagnose
    2. State machine monitor for online checking
    3. Predicate evaluators for atomic propositions
    """
    
    def __init__(self, property_name: str, query_registry: Optional[Dict[str, str]] = None):
        self.property_name = property_name
        self.query_registry = query_registry or {}
        self._predicate_counter = 0
        self._generated_predicates: Dict[str, str] = {}
        self._indent_level = 0
    
    def generate(self, prop: PropertyNode, analysis: PropertyAnalysis) -> CompiledProperty:
        """Generate complete compiled property."""
        # Generate predicate evaluation code
        predicate_code = self._generate_predicate_evaluators(prop)
        
        # Generate checker class
        checker_code = self._generate_checker_class(prop, analysis)
        
        # Generate monitor if online monitoring is possible
        monitor_code = None
        if analysis.can_monitor_online:
            monitor_code = self._generate_state_machine_monitor(prop, analysis)
        
        return CompiledProperty(
            property_name=self.property_name,
            property_kind=analysis.kind,
            analysis=analysis,
            checker_code=checker_code,
            monitor_code=monitor_code,
            predicate_code=predicate_code,
            metadata={
                'generated_predicates': list(self._generated_predicates.keys()),
                'referenced_queries': list(analysis.referenced_queries),
            }
        )
    
    def _generate_predicate_evaluators(self, prop: PropertyNode) -> str:
        """Generate predicate evaluation functions."""
        # Collect all atomic predicates
        predicates = self._collect_atomic_predicates(prop)
        
        lines = [
            '"""Auto-generated predicate evaluators for property checking."""',
            '',
            'from typing import Any, Dict, Optional',
            'from dataclasses import dataclass',
            '',
        ]
        
        for pred_name, pred_args in predicates:
            func_name = self._predicate_func_name(pred_name)
            self._generated_predicates[pred_name] = func_name
            
            lines.append(f'def {func_name}(state: Dict[str, Any], ctx: Any) -> bool:')
            lines.append(f'    """Evaluate predicate: {pred_name}"""')
            
            # Generate evaluation based on predicate type
            if pred_name == 'at-label':
                label = pred_args[0] if pred_args else 'unknown'
                lines.append(f'    return state.get("current_label") == "{label}"')
            elif pred_name == 'var-is-null':
                var = pred_args[0] if pred_args else 'unknown'
                lines.append(f'    var_state = state.get("variables", {{}}).get("{var}")')
                lines.append(f'    return var_state is not None and var_state.get("is_null", False)')
            elif pred_name == 'var-is-freed':
                var = pred_args[0] if pred_args else 'unknown'
                lines.append(f'    var_state = state.get("variables", {{}}).get("{var}")')
                lines.append(f'    return var_state is not None and var_state.get("is_freed", False)')
            elif pred_name == 'event-occurred':
                event = pred_args[0] if pred_args else 'unknown'
                lines.append(f'    return "{event}" in state.get("occurred_events", set())')
            elif pred_name == 'query-match':
                query = pred_args[0] if pred_args else 'unknown'
                lines.append(f'    # Delegate to query executor')
                lines.append(f'    query_results = ctx.execute_query("{query}")')
                lines.append(f'    return len(query_results) > 0')
            elif pred_name == 'in-scope':
                scope = pred_args[0] if pred_args else 'unknown'
                lines.append(f'    return "{scope}" in state.get("scope_stack", [])')
            elif pred_name == 'after-call':
                func = pred_args[0] if pred_args else 'unknown'
                lines.append(f'    last_call = state.get("last_call")')
                lines.append(f'    return last_call is not None and last_call.get("name") == "{func}"')
            else:
                # Generic predicate - check state dict
                lines.append(f'    return state.get("{pred_name}", False)')
            
            lines.append('')
        
        return '\n'.join(lines)
    
    def _generate_checker_class(self, prop: PropertyNode, analysis: PropertyAnalysis) -> str:
        """Generate Checker subclass for property."""
        class_name = self._checker_class_name()
        
        # Generate the property check expression
        check_expr = prop.accept(self)
        
        code = f'''"""Auto-generated checker for property: {self.property_name}"""

from typing import Any, Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum

# Import base checker infrastructure (from cppcheckdata-shims)
# from .checker import Checker, CheckerContext, Diagnostic, DiagnosticSeverity, SourceLocation


class DiagnosticSeverity(Enum):
    """Diagnostic severity levels."""
    ERROR = "error"
    WARNING = "warning"
    STYLE = "style"
    PERFORMANCE = "performance"
    PORTABILITY = "portability"
    INFORMATION = "information"


@dataclass(slots=True)
class SourceLocation:
    """Source location for diagnostics."""
    file: str
    line: int
    column: int = 0


@dataclass(slots=True)
class Diagnostic:
    """A diagnostic message."""
    error_id: str
    message: str
    severity: DiagnosticSeverity
    location: Optional[SourceLocation] = None
    confidence: str = "normal"
    cwe: Optional[int] = None
    checker_name: str = ""
    secondary: Tuple[SourceLocation, ...] = ()
    evidence: Dict[str, Any] = field(default_factory=dict)
    
    def to_cppcheck_json(self) -> Dict[str, Any]:
        """Serialize to cppcheck JSON format."""
        result = {{
            "errorId": self.error_id,
            "message": self.message,
            "severity": self.severity.value,
            "confidence": self.confidence,
        }}
        if self.location:
            result["location"] = {{
                "file": self.location.file,
                "line": self.location.line,
                "column": self.location.column,
            }}
        if self.cwe:
            result["cwe"] = self.cwe
        if self.secondary:
            result["secondaryLocations"] = [
                {{"file": loc.file, "line": loc.line, "column": loc.column}}
                for loc in self.secondary
            ]
        return result


class {class_name}:
    """
    Auto-generated checker for property: {self.property_name}
    
    Property kind: {analysis.kind.name}
    Is safety property: {analysis.is_safety}
    Can monitor online: {analysis.can_monitor_online}
    Temporal depth: {analysis.temporal_depth}
    """
    
    name = "{self.property_name}"
    description = "Checks property: {self.property_name}"
    
    def __init__(self):
        self._diagnostics: List[Diagnostic] = []
        self._evidence: List[Dict[str, Any]] = []
        self._violation_traces: List[List[Dict[str, Any]]] = []
    
    def collect_evidence(self, ctx: Any) -> None:
        """
        Collect evidence for property violations.
        
        Iterates through program states and checks property.
        """
        # Import generated predicates
        from . import {self.property_name}_predicates as predicates
        
        for state in self._iterate_states(ctx):
            # Check if property is violated in this state
            if not self._check_property(state, ctx, predicates):
                self._evidence.append({{
                    "state": state,
                    "location": state.get("location"),
                    "violation_type": "{analysis.kind.name}",
                }})
    
    def diagnose(self, ctx: Any) -> None:
        """
        Generate diagnostics from collected evidence.
        """
        # Deduplicate by location
        seen: Set[Tuple[str, int]] = set()
        
        for ev in self._evidence:
            loc = ev.get("location")
            if loc:
                key = (loc.get("file", ""), loc.get("line", 0))
                if key in seen:
                    continue
                seen.add(key)
            
            self._emit(
                error_id="{self._error_id()}",
                message=self._format_violation_message(ev),
                severity={self._severity_for_kind(analysis.kind)},
                location=SourceLocation(
                    file=loc.get("file", "<unknown>") if loc else "<unknown>",
                    line=loc.get("line", 0) if loc else 0,
                    column=loc.get("column", 0) if loc else 0,
                ) if loc else None,
                confidence="high" if {analysis.is_safety} else "medium",
                evidence=ev,
            )
    
    def report(self, ctx: Any) -> List[Diagnostic]:
        """Return filtered diagnostics."""
        # Apply suppressions if available
        if hasattr(ctx, 'suppressions'):
            return ctx.suppressions.filter_diagnostics(self._diagnostics)
        return self._diagnostics
    
    def _emit(
        self,
        error_id: str,
        message: str,
        severity: DiagnosticSeverity,
        location: Optional[SourceLocation] = None,
        confidence: str = "normal",
        cwe: Optional[int] = None,
        secondary: Tuple[SourceLocation, ...] = (),
        evidence: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Emit a diagnostic."""
        self._diagnostics.append(Diagnostic(
            error_id=error_id,
            message=message,
            severity=severity,
            location=location,
            confidence=confidence,
            cwe=cwe,
            checker_name=self.name,
            secondary=secondary,
            evidence=evidence or {{}},
        ))
    
    def _check_property(self, state: Dict[str, Any], ctx: Any, predicates: Any) -> bool:
        """
        Check if property holds in given state.
        
        Generated from property formula:
        {check_expr}
        """
        {self._indent(self._generate_property_check(prop), 2)}
    
    def _iterate_states(self, ctx: Any):
        """Iterate through program states for checking."""
        # Use abstract interpreter if available
        if hasattr(ctx, 'abstract_interpreter'):
            yield from ctx.abstract_interpreter.iterate_reachable_states()
        # Fall back to CFG traversal
        elif hasattr(ctx, 'cfg'):
            for block in ctx.cfg.blocks:
                for instr in block.instructions:
                    yield self._extract_state(instr, ctx)
        # Fall back to token iteration
        elif hasattr(ctx, 'tokens'):
            for token in ctx.tokens:
                yield self._token_to_state(token)
        else:
            return
    
    def _extract_state(self, instr: Any, ctx: Any) -> Dict[str, Any]:
        """Extract state from instruction."""
        return {{
            "location": {{
                "file": getattr(instr, 'source_loc', (None,))[0],
                "line": getattr(instr, 'source_loc', (None, 0))[1] if getattr(instr, 'source_loc', None) else 0,
            }},
            "opcode": getattr(instr, 'opcode', None),
            "operands": getattr(instr, 'operands', ()),
        }}
    
    def _token_to_state(self, token: Any) -> Dict[str, Any]:
        """Convert cppcheck token to state dict."""
        return {{
            "location": {{
                "file": getattr(token, 'file', '<unknown>'),
                "line": getattr(token, 'linenr', 0),
                "column": getattr(token, 'column', 0),
            }},
            "token_str": getattr(token, 'str', ''),
            "token_type": getattr(token, 'type', ''),
            "scope": getattr(token, 'scope', None),
            "variable": getattr(token, 'variable', None),
        }}
    
    def _format_violation_message(self, evidence: Dict[str, Any]) -> str:
        """Format violation message from evidence."""
        loc = evidence.get("location", {{}})
        return (
            f"Property '{self.property_name}' violated at "
            f"{{loc.get('file', '<unknown>')}}:{{loc.get('line', '?')}}"
        )
'''
        return code
    
    def _generate_state_machine_monitor(self, prop: PropertyNode, analysis: PropertyAnalysis) -> str:
        """Generate state machine monitor for online property checking."""
        class_name = f"{self._to_pascal_case(self.property_name)}Monitor"
        
        # Generate state machine states based on property structure
        states, transitions = self._build_state_machine(prop)
        
        code = f'''"""Auto-generated state machine monitor for property: {self.property_name}"""

from typing import Any, Callable, Dict, List, Optional, Set
from dataclasses import dataclass, field
from enum import Enum, auto


class MonitorState(Enum):
    """Monitor states for property: {self.property_name}"""
    INITIAL = auto()
    {self._generate_state_enum_members(states)}
    ACCEPTING = auto()
    REJECTING = auto()


@dataclass(slots=True)
class MonitorTransition:
    """A transition in the property monitor."""
    source: MonitorState
    target: MonitorState
    guard: Callable[[Dict[str, Any]], bool]
    label: str


class {class_name}:
    """
    State machine monitor for property: {self.property_name}
    
    Monitors execution trace and reports violations in real-time.
    Based on EventSequenceMatcher pattern from shims infrastructure.
    """
    
    def __init__(self):
        self.current_state = MonitorState.INITIAL
        self.trace: List[Dict[str, Any]] = []
        self.violations: List[Dict[str, Any]] = []
        self._transitions = self._build_transitions()
    
    def _build_transitions(self) -> List[MonitorTransition]:
        """Build state machine transitions."""
        return [
            {self._generate_transition_list(transitions)}
        ]
    
    def step(self, event: Dict[str, Any]) -> bool:
        """
        Process an event and update monitor state.
        
        Returns True if property still holds, False if violated.
        """
        self.trace.append(event)
        
        # Find applicable transitions
        for trans in self._transitions:
            if trans.source == self.current_state and trans.guard(event):
                self.current_state = trans.target
                break
        
        # Check for violation
        if self.current_state == MonitorState.REJECTING:
            self.violations.append({{
                "trace": list(self.trace),
                "event": event,
                "state": self.current_state.name,
            }})
            return False
        
        return True
    
    def reset(self) -> None:
        """Reset monitor to initial state."""
        self.current_state = MonitorState.INITIAL
        self.trace.clear()
    
    def is_accepting(self) -> bool:
        """Check if monitor is in accepting state."""
        return self.current_state == MonitorState.ACCEPTING
    
    def is_rejecting(self) -> bool:
        """Check if monitor is in rejecting state."""
        return self.current_state == MonitorState.REJECTING


def create_monitor() -> {class_name}:
    """Factory function to create monitor instance."""
    return {class_name}()
'''
        return code
    
    # --- Visitor methods for code generation ---
    
    def visit_atomic(self, node: AtomicProp) -> str:
        func_name = self._predicate_func_name(node.predicate)
        return f'predicates.{func_name}(state, ctx)'
    
    def visit_not(self, node: NotProp) -> str:
        inner = node.operand.accept(self)
        return f'(not ({inner}))'
    
    def visit_and(self, node: AndProp) -> str:
        parts = [f'({op.accept(self)})' for op in node.operands]
        return ' and '.join(parts)
    
    def visit_or(self, node: OrProp) -> str:
        parts = [f'({op.accept(self)})' for op in node.operands]
        return ' or '.join(parts)
    
    def visit_implies(self, node: ImpliesProp) -> str:
        ant = node.antecedent.accept(self)
        cons = node.consequent.accept(self)
        return f'(not ({ant}) or ({cons}))'
    
    def visit_temporal(self, node: TemporalProp) -> str:
        inner = node.operand.accept(self)
        op_name = node.op.value
        return f'self._check_temporal("{op_name}", lambda s, c, p: {inner}, state, ctx, predicates)'
    
    def visit_binary_temporal(self, node: BinaryTemporalProp) -> str:
        left = node.left.accept(self)
        right = node.right.accept(self)
        op_name = node.op.value
        return f'self._check_binary_temporal("{op_name}", lambda s, c, p: {left}, lambda s, c, p: {right}, state, ctx, predicates)'
    
    def visit_pattern(self, node: PatternProp) -> str:
        # Patterns should be expanded before code generation
        raise PropertyCompilationError(
            f"Pattern '{node.pattern_name}' should be expanded before code generation",
            node.loc
        )
    
    def visit_query_ref(self, node: QueryRefProp) -> str:
        return f'len(ctx.execute_query("{node.query_name}")) > 0'
    
    # --- Helper methods ---
    
    def _collect_atomic_predicates(self, prop: PropertyNode) -> List[Tuple[str, Tuple[Any, ...]]]:
        """Collect all atomic predicates from property."""
        predicates: List[Tuple[str, Tuple[Any, ...]]] = []
        
        def collect(node: PropertyNode):
            if isinstance(node, AtomicProp):
                predicates.append((node.predicate, node.args))
            elif isinstance(node, NotProp):
                collect(node.operand)
            elif isinstance(node, (AndProp, OrProp)):
                for op in node.operands:
                    collect(op)
            elif isinstance(node, ImpliesProp):
                collect(node.antecedent)
                collect(node.consequent)
            elif isinstance(node, TemporalProp):
                collect(node.operand)
            elif isinstance(node, BinaryTemporalProp):
                collect(node.left)
                collect(node.right)
            elif isinstance(node, PatternProp):
                for arg in node.args:
                    collect(arg)
            elif isinstance(node, QueryRefProp):
                predicates.append(('query-match', (node.query_name,)))
        
        collect(prop)
        return list(set(predicates))  # deduplicate
    
    def _predicate_func_name(self, pred_name: str) -> str:
        """Generate function name for predicate."""
        clean = pred_name.replace('-', '_').replace(' ', '_')
        return f'check_{clean}'
    
    def _checker_class_name(self) -> str:
        """Generate checker class name."""
        return f'{self._to_pascal_case(self.property_name)}Checker'
    
    def _to_pascal_case(self, name: str) -> str:
        """Convert name to PascalCase."""
        parts = name.replace('-', '_').split('_')
        return ''.join(p.capitalize() for p in parts if p)
    
    def _error_id(self) -> str:
        """Generate error ID for property."""
        return self.property_name.replace('-', '_').replace(' ', '_')
    
    def _severity_for_kind(self, kind: PropertyKind) -> str:
        """Map property kind to diagnostic severity."""
        severity_map = {
            PropertyKind.SAFETY: 'DiagnosticSeverity.ERROR',
            PropertyKind.ABSENCE: 'DiagnosticSeverity.ERROR',
            PropertyKind.LIVENESS: 'DiagnosticSeverity.WARNING',
            PropertyKind.RESPONSE: 'DiagnosticSeverity.WARNING',
            PropertyKind.PRECEDENCE: 'DiagnosticSeverity.WARNING',
            PropertyKind.EXISTENCE: 'DiagnosticSeverity.STYLE',
            PropertyKind.UNIVERSALITY: 'DiagnosticSeverity.ERROR',
            PropertyKind.BOUNDED: 'DiagnosticSeverity.WARNING',
        }
        return severity_map.get(kind, 'DiagnosticSeverity.WARNING')
    
    def _indent(self, code: str, level: int) -> str:
        """Indent code by level."""
        indent = '    ' * level
        lines = code.split('\n')
        return '\n'.join(indent + line if line.strip() else line for line in lines)
    
    def _generate_property_check(self, prop: PropertyNode) -> str:
        """Generate property check code."""
        expr = prop.accept(self)
        return f'return {expr}'
    
    def _build_state_machine(self, prop: PropertyNode) -> Tuple[List[str], List[Dict[str, Any]]]:
        """Build state machine states and transitions from property."""
        # Simplified state machine construction
        states = ['CHECKING']
        transitions = [
            {'source': 'INITIAL', 'target': 'CHECKING', 'guard': 'True', 'label': 'start'},
            {'source': 'CHECKING', 'target': 'ACCEPTING', 'guard': 'property_holds', 'label': 'accept'},
            {'source': 'CHECKING', 'target': 'REJECTING', 'guard': 'property_violated', 'label': 'reject'},
        ]
        return states, transitions
    
    def _generate_state_enum_members(self, states: List[str]) -> str:
        """Generate state enum members."""
        return '\n    '.join(f'{s} = auto()' for s in states)
    
    def _generate_transition_list(self, transitions: List[Dict[str, Any]]) -> str:
        """Generate transition list code."""
        lines = []
        for t in transitions:
            guard = f'lambda e: {t["guard"]}' if t['guard'] != 'True' else 'lambda e: True'
            lines.append(
                f'MonitorTransition(MonitorState.{t["source"]}, MonitorState.{t["target"]}, '
                f'{guard}, "{t["label"]}"),'
            )
        return '\n            '.join(lines)


# =============================================================================
# Main Compiler Interface
# =============================================================================

class PropertyCompiler:
    """
    Main property compiler interface.
    
    Compiles CASL property specifications to executable checker code.
    
    Usage:
        compiler = PropertyCompiler()
        result = compiler.compile(property_ast, "my-property")
        
        # Write generated code
        with open("my_property_checker.py", "w") as f:
            f.write(result.checker_code)
    """
    
    def __init__(
        self,
        query_registry: Optional[Dict[str, str]] = None,
        expand_patterns: bool = True,
    ):
        """
        Initialize property compiler.
        
        Args:
            query_registry: Map of query names to compiled query modules
            expand_patterns: Whether to expand high-level patterns
        """
        self.query_registry = query_registry or {}
        self.expand_patterns = expand_patterns
        self._classifier = PropertyClassifier()
        self._expander = PatternExpander()
    
    def compile(
        self,
        prop: PropertyNode,
        name: str,
        options: Optional[Dict[str, Any]] = None,
    ) -> CompiledProperty:
        """
        Compile a property to executable checker code.
        
        Args:
            prop: Property AST node
            name: Property name (used for class/function naming)
            options: Compilation options
        
        Returns:
            CompiledProperty with generated code
        """
        options = options or {}
        
        # Step 1: Expand patterns if requested
        if self.expand_patterns:
            expanded = self._expander.expand(prop)
        else:
            expanded = prop
        
        # Step 2: Classify and analyze property
        analysis = self._classifier.classify(expanded)
        
        # Step 3: Generate code
        generator = PropertyCodeGenerator(name, self.query_registry)
        result = generator.generate(expanded, analysis)
        
        return result
    
    def compile_multiple(
        self,
        properties: Sequence[Tuple[PropertyNode, str]],
        options: Optional[Dict[str, Any]] = None,
    ) -> List[CompiledProperty]:
        """
        Compile multiple properties.
        
        Args:
            properties: List of (property_ast, name) tuples
            options: Compilation options
        
        Returns:
            List of compiled properties
        """
        return [self.compile(prop, name, options) for prop, name in properties]
    
    def compile_to_protocol(
        self,
        prop: PropertyNode,
        name: str,
    ) -> str:
        """
        Compile property to PropertyProtocol implementation.
        
        Generates code that integrates with BoundedExplorer and SafetyChecker.
        """
        if self.expand_patterns:
            expanded = self._expander.expand(prop)
        else:
            expanded = prop
        
        analysis = self._classifier.classify(expanded)
        
        if not analysis.is_safety:
            raise PropertyCompilationError(
                f"PropertyProtocol only supports safety properties, got {analysis.kind.name}",
                prop.loc
            )
        
        class_name = self._to_pascal_case(name)
        
        code = f'''"""PropertyProtocol implementation for: {name}"""

from typing import Any, Optional


class {class_name}PropertyProtocol:
    """
    PropertyProtocol implementation for property: {name}
    
    A safety property: an invariant that must hold at every reachable state.
    Compatible with BoundedExplorer.explore() and SafetyChecker.add_property().
    """
    
    name = "{name}"
    
    def check(self, state: Any) -> bool:
        """Check if property holds in state."""
        # TODO: Implement state checking based on expanded property
        return True
    
    def get_violation_message(self, state: Any) -> str:
        """Get violation message for state."""
        return f"Property '{name}' violated"
    
    def __repr__(self) -> str:
        return f"<PropertyProtocol:{self.name}>"
'''
        return code
    
    def _to_pascal_case(self, name: str) -> str:
        """Convert name to PascalCase."""
        parts = name.replace('-', '_').split('_')
        return ''.join(p.capitalize() for p in parts if p)


# =============================================================================
# Convenience Functions
# =============================================================================

def compile_property(
    prop: PropertyNode,
    name: str,
    **kwargs
) -> CompiledProperty:
    """Convenience function to compile a single property."""
    compiler = PropertyCompiler(**kwargs)
    return compiler.compile(prop, name)


def expand_pattern(prop: PropertyNode) -> PropertyNode:
    """Convenience function to expand patterns in a property."""
    return PatternExpander().expand(prop)


def classify_property(prop: PropertyNode) -> PropertyAnalysis:
    """Convenience function to classify a property."""
    return PropertyClassifier().classify(prop)


# =============================================================================
# Property DSL Builders (for programmatic construction)
# =============================================================================

def atomic(predicate: str, *args) -> AtomicProp:
    """Create atomic proposition."""
    return AtomicProp(predicate=predicate, args=args)


def NOT(prop: PropertyNode) -> NotProp:
    """Create negation."""
    return NotProp(operand=prop)


def AND(*props: PropertyNode) -> AndProp:
    """Create conjunction."""
    return AndProp(operands=props)


def OR(*props: PropertyNode) -> OrProp:
    """Create disjunction."""
    return OrProp(operands=props)


def IMPLIES(ant: PropertyNode, cons: PropertyNode) -> ImpliesProp:
    """Create implication."""
    return ImpliesProp(antecedent=ant, consequent=cons)


def AG(prop: PropertyNode) -> TemporalProp:
    """Create AG (all paths globally) temporal property."""
    return TemporalProp(op=TemporalOp.AG, operand=prop)


def EF(prop: PropertyNode) -> TemporalProp:
    """Create EF (exists path finally) temporal property."""
    return TemporalProp(op=TemporalOp.EF, operand=prop)


def AF(prop: PropertyNode) -> TemporalProp:
    """Create AF (all paths finally) temporal property."""
    return TemporalProp(op=TemporalOp.AF, operand=prop)


def AX(prop: PropertyNode) -> TemporalProp:
    """Create AX (all paths next) temporal property."""
    return TemporalProp(op=TemporalOp.AX, operand=prop)


def UNTIL(left: PropertyNode, right: PropertyNode) -> BinaryTemporalProp:
    """Create Until temporal property."""
    return BinaryTemporalProp(op=TemporalOp.UNTIL, left=left, right=right)


def WEAK_UNTIL(left: PropertyNode, right: PropertyNode) -> BinaryTemporalProp:
    """Create Weak Until temporal property."""
    return BinaryTemporalProp(op=TemporalOp.WEAK_UNTIL, left=left, right=right)


def never(prop: PropertyNode) -> PatternProp:
    """Create NEVER pattern (expands to AG !prop)."""
    return PatternProp(pattern_name='never', args=(prop,))


def always(prop: PropertyNode) -> PatternProp:
    """Create ALWAYS pattern (expands to AG prop)."""
    return PatternProp(pattern_name='always', args=(prop,))


def eventually(prop: PropertyNode) -> PatternProp:
    """Create EVENTUALLY pattern (expands to EF prop)."""
    return PatternProp(pattern_name='eventually', args=(prop,))


def responds(trigger: PropertyNode, response: PropertyNode) -> PatternProp:
    """Create RESPONDS pattern (expands to AG(trigger -> AF response))."""
    return PatternProp(pattern_name='responds', args=(trigger, response))


def precedes(first: PropertyNode, second: PropertyNode) -> PatternProp:
    """Create PRECEDES pattern (first must precede second)."""
    return PatternProp(pattern_name='precedes', args=(first, second))


def query_holds(query_name: str) -> QueryRefProp:
    """Create query reference proposition."""
    return QueryRefProp(query_name=query_name)


