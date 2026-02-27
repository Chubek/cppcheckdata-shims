"""
CASL/CSQL Semantic Analyzer

Performs semantic analysis on CASL AST nodes:
1. Name resolution - resolves references between queries, atoms, domains, properties
2. Type checking - validates domain compositions and transfer function compatibility
3. Scope management - tracks variable bindings and their visibility
4. Diagnostic accumulation - collects errors/warnings with suppression support

Design follows patterns from cppcheckdata-shims:
- Diagnostic dataclass with severity, confidence, location [cppcheckdata-shims:16654-16686]
- SuppressionManager for filtering diagnostics [cppcheckdata-shims:16717-16815]
- Two-phase validation: resolve → validate [cppcheckdata-shims:54796, 54873]
- Constraint/property diagnostics [cppcheckdata-shims:52305-52317]
"""

from __future__ import annotations

import fnmatch
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import (
    Any,
    Callable,
    Dict,
    FrozenSet,
    Generic,
    Iterable,
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
    cast,
)

# Import AST definitions (assumed from previous conversation)
# These would be in casl/ast.py
import casl.ast as A

# ============================================================================
# PART 1 — DIAGNOSTIC MODEL
# Pattern from cppcheckdata-shims-source-code.md:16614-16710
# ============================================================================


class DiagnosticSeverity(Enum):
    """
    Severity levels for semantic diagnostics.
    Compatible with cppcheck severity model [cppcheckdata-shims:16618-16626].
    """
    ERROR = "error"          # Fatal semantic error, analysis cannot proceed
    WARNING = "warning"      # Likely bug or problematic pattern
    STYLE = "style"          # Style/convention violation
    PERFORMANCE = "performance"  # Potential performance issue
    PORTABILITY = "portability"  # Portability concern
    INFORMATION = "information"  # Informational message
    DEBUG = "debug"          # Debug/internal information


class Confidence(Enum):
    """
    Confidence level in diagnostic accuracy [cppcheckdata-shims:16628-16638].
    """
    HIGH = auto()    # Very confident this is a real issue
    MEDIUM = auto()  # Reasonably confident
    LOW = auto()     # Possible false positive


@dataclass(frozen=True, slots=True)
class SourceLocation:
    """
    Immutable source location for diagnostics [cppcheckdata-shims:16641-16652].
    """
    file: str
    line: int
    column: int = 0

    def __str__(self) -> str:
        if self.column > 0:
            return f"{self.file}:{self.line}:{self.column}"
        return f"{self.file}:{self.line}"

    @classmethod
    def from_ast_loc(cls, loc: Optional[A.SourceLoc]) -> Optional[SourceLocation]:
        """Convert AST SourceLoc to diagnostic SourceLocation."""
        if loc is None:
            return None
        return cls(file=loc.filename, line=loc.line, column=loc.column)


@dataclass(frozen=True, slots=True)
class SecondaryLocation:
    """Additional location providing context for a diagnostic."""
    location: SourceLocation
    message: str


@dataclass(frozen=True, slots=True)
class Diagnostic:
    """
    Structured diagnostic/finding from semantic analysis.
    Pattern from cppcheckdata-shims-source-code.md:16654-16686.

    Attributes:
        error_id: Unique identifier for this diagnostic type (e.g., "undefined-reference")
        message: Human-readable description of the issue
        severity: How serious the issue is
        location: Primary source location
        confidence: How confident we are this is a real issue
        cwe: Optional CWE identifier
        checker_name: Name of the checker that produced this
        addon: Optional addon/phase name
        extra: Additional structured data
        secondary: Secondary locations providing context
        evidence: Supporting evidence string
    """
    error_id: str
    message: str
    severity: DiagnosticSeverity
    location: Optional[SourceLocation] = None
    confidence: Confidence = Confidence.HIGH
    cwe: Optional[int] = None
    checker_name: str = "casl-semantic"
    addon: str = "casl"
    extra: Tuple[Tuple[str, Any], ...] = ()
    secondary: Tuple[SecondaryLocation, ...] = ()
    evidence: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        result: Dict[str, Any] = {
            "errorId": self.error_id,
            "message": self.message,
            "severity": self.severity.value,
            "confidence": self.confidence.name.lower(),
            "checker": self.checker_name,
            "addon": self.addon,
        }
        if self.location:
            result["location"] = {
                "file": self.location.file,
                "line": self.location.line,
                "column": self.location.column,
            }
        if self.cwe:
            result["cwe"] = self.cwe
        if self.extra:
            result["extra"] = dict(self.extra)
        if self.secondary:
            result["secondary"] = [
                {"location": str(s.location), "message": s.message}
                for s in self.secondary
            ]
        if self.evidence:
            result["evidence"] = self.evidence
        return result

    def to_gcc_format(self) -> str:
        """Format as GCC-style diagnostic string."""
        loc_str = str(self.location) if self.location else "<unknown>"
        return f"{loc_str}: {self.severity.value}: [{self.error_id}] {self.message}"

    def with_location(self, loc: Optional[SourceLocation]) -> Diagnostic:
        """Return a copy with updated location."""
        return Diagnostic(
            error_id=self.error_id,
            message=self.message,
            severity=self.severity,
            location=loc,
            confidence=self.confidence,
            cwe=self.cwe,
            checker_name=self.checker_name,
            addon=self.addon,
            extra=self.extra,
            secondary=self.secondary,
            evidence=self.evidence,
        )


# ============================================================================
# PART 2 — SUPPRESSION MANAGER
# Pattern from cppcheckdata-shims-source-code.md:16713-16818
# ============================================================================


class SuppressionManager:
    """
    Manages diagnostic suppressions from multiple sources.
    Pattern from cppcheckdata-shims-source-code.md:16717-16815.

    Suppression sources:
    1. Inline comments: ;; casl-suppress error-id
    2. File-level suppressions: patterns matching file paths
    3. Global suppressions: error IDs suppressed everywhere
    """

    def __init__(self) -> None:
        # (file, line) -> set of suppressed error IDs ("*" for all)
        self._inline: Dict[Tuple[str, int], Set[str]] = {}
        # file pattern -> set of suppressed error IDs
        self._file_level: Dict[str, Set[str]] = {}
        # globally suppressed error IDs
        self._global: Set[str] = set()

    def add_inline_suppression(
        self, file: str, line: int, error_id: str
    ) -> None:
        """Add an inline suppression for a specific location."""
        key = (file, line)
        if key not in self._inline:
            self._inline[key] = set()
        self._inline[key].add(error_id)

    def add_file_suppression(self, pattern: str, error_id: str) -> None:
        """Add a file-level suppression for files matching pattern."""
        if pattern not in self._file_level:
            self._file_level[pattern] = set()
        self._file_level[pattern].add(error_id)

    def add_global_suppression(self, error_id: str) -> None:
        """Suppress an error ID globally."""
        self._global.add(error_id)

    def load_inline_suppressions_from_source(self, source: str, filename: str) -> None:
        """
        Scan source text for suppression comments.
        Format: ;; casl-suppress error-id [error-id ...]
        """
        suppress_pattern = re.compile(
            r';\s*casl-suppress\s+([\w-]+(?:\s+[\w-]+)*)',
            re.IGNORECASE
        )
        for line_num, line in enumerate(source.splitlines(), start=1):
            match = suppress_pattern.search(line)
            if match:
                error_ids = match.group(1).split()
                for error_id in error_ids:
                    # Suppression applies to this line and the next
                    self.add_inline_suppression(filename, line_num, error_id)
                    self.add_inline_suppression(filename, line_num + 1, error_id)

    def is_suppressed(self, diag: Diagnostic) -> bool:
        """
        Check if a diagnostic should be suppressed.
        Pattern from cppcheckdata-shims:16792-16815.
        """
        error_id = diag.error_id

        # Check global suppressions
        if error_id in self._global or "*" in self._global:
            return True

        if diag.location is None:
            return False

        file = diag.location.file
        line = diag.location.line

        # Check inline suppressions (current line and previous line)
        for check_line in (line, line - 1):
            key = (file, check_line)
            if key in self._inline:
                suppressed = self._inline[key]
                if error_id in suppressed or "*" in suppressed:
                    return True

        # Check file-level suppressions
        for pattern, suppressed in self._file_level.items():
            if error_id in suppressed or "*" in suppressed:
                if file.endswith(pattern) or fnmatch.fnmatch(file, pattern):
                    return True

        return False

    def filter_diagnostics(
        self, diagnostics: Iterable[Diagnostic]
    ) -> List[Diagnostic]:
        """Return diagnostics that are not suppressed."""
        return [d for d in diagnostics if not self.is_suppressed(d)]


# ============================================================================
# PART 3 — DIAGNOSTIC COLLECTOR
# Accumulates diagnostics during analysis with optional suppression
# ============================================================================


class DiagnosticCollector:
    """
    Collects diagnostics during semantic analysis.
    Supports severity filtering and suppression management.
    """

    def __init__(
        self,
        *,
        suppression_manager: Optional[SuppressionManager] = None,
        min_severity: DiagnosticSeverity = DiagnosticSeverity.INFORMATION,
    ) -> None:
        self._diagnostics: List[Diagnostic] = []
        self._suppression = suppression_manager or SuppressionManager()
        self._min_severity = min_severity
        self._severity_order = {
            DiagnosticSeverity.ERROR: 0,
            DiagnosticSeverity.WARNING: 1,
            DiagnosticSeverity.STYLE: 2,
            DiagnosticSeverity.PERFORMANCE: 3,
            DiagnosticSeverity.PORTABILITY: 4,
            DiagnosticSeverity.INFORMATION: 5,
            DiagnosticSeverity.DEBUG: 6,
        }

    def report(
        self,
        error_id: str,
        message: str,
        severity: DiagnosticSeverity = DiagnosticSeverity.ERROR,
        location: Optional[SourceLocation] = None,
        confidence: Confidence = Confidence.HIGH,
        **kwargs: Any,
    ) -> None:
        """
        Report a diagnostic finding.
        Respects severity filtering and suppression.
        """
        # Check severity filter
        if self._severity_order.get(severity, 99) > self._severity_order.get(
            self._min_severity, 99
        ):
            return

        diag = Diagnostic(
            error_id=error_id,
            message=message,
            severity=severity,
            location=location,
            confidence=confidence,
            **kwargs,
        )

        # Check suppression
        if not self._suppression.is_suppressed(diag):
            self._diagnostics.append(diag)

    def report_from_ast(
        self,
        error_id: str,
        message: str,
        node: Any,
        severity: DiagnosticSeverity = DiagnosticSeverity.ERROR,
        **kwargs: Any,
    ) -> None:
        """Report a diagnostic with location extracted from an AST node."""
        loc = None
        if hasattr(node, "loc") and node.loc is not None:
            loc = SourceLocation.from_ast_loc(node.loc)
        self.report(error_id, message, severity, loc, **kwargs)

    @property
    def diagnostics(self) -> List[Diagnostic]:
        """Get all collected diagnostics."""
        return list(self._diagnostics)

    @property
    def errors(self) -> List[Diagnostic]:
        """Get only ERROR severity diagnostics."""
        return [d for d in self._diagnostics if d.severity == DiagnosticSeverity.ERROR]

    @property
    def warnings(self) -> List[Diagnostic]:
        """Get WARNING severity diagnostics."""
        return [d for d in self._diagnostics if d.severity == DiagnosticSeverity.WARNING]

    def has_errors(self) -> bool:
        """Check if any ERROR diagnostics were collected."""
        return any(d.severity == DiagnosticSeverity.ERROR for d in self._diagnostics)

    def error_count(self) -> int:
        """Count ERROR severity diagnostics."""
        return sum(1 for d in self._diagnostics if d.severity == DiagnosticSeverity.ERROR)

    def clear(self) -> None:
        """Clear all collected diagnostics."""
        self._diagnostics.clear()


# ============================================================================
# PART 4 — TYPE SYSTEM FOR CASL DOMAINS
# Represents lattice types for abstract interpretation
# ============================================================================


class CaslType(ABC):
    """
    Base class for CASL types.
    Used to represent domain types for type checking.
    """

    @abstractmethod
    def pretty(self) -> str:
        """Return a human-readable representation."""
        ...

    @abstractmethod
    def __eq__(self, other: object) -> bool:
        ...

    @abstractmethod
    def __hash__(self) -> int:
        ...


@dataclass(frozen=True, slots=True)
class TUnknown(CaslType):
    """Unknown/unresolved type (type variable)."""
    name: Optional[str] = None

    def pretty(self) -> str:
        return f"?{self.name}" if self.name else "?"

    def __eq__(self, other: object) -> bool:
        return isinstance(other, TUnknown) and self.name == other.name

    def __hash__(self) -> int:
        return hash(("TUnknown", self.name))


@dataclass(frozen=True, slots=True)
class TEntity(CaslType):
    """Type representing a program entity (variable, function, token, etc.)."""
    kind: A.EntityKind

    def pretty(self) -> str:
        return f"Entity<{self.kind.value}>"

    def __eq__(self, other: object) -> bool:
        return isinstance(other, TEntity) and self.kind == other.kind

    def __hash__(self) -> int:
        return hash(("TEntity", self.kind))


@dataclass(frozen=True, slots=True)
class TBool(CaslType):
    """Boolean type."""

    def pretty(self) -> str:
        return "Bool"

    def __eq__(self, other: object) -> bool:
        return isinstance(other, TBool)

    def __hash__(self) -> int:
        return hash("TBool")


@dataclass(frozen=True, slots=True)
class TString(CaslType):
    """String type."""

    def pretty(self) -> str:
        return "String"

    def __eq__(self, other: object) -> bool:
        return isinstance(other, TString)

    def __hash__(self) -> int:
        return hash("TString")


@dataclass(frozen=True, slots=True)
class TInt(CaslType):
    """Integer type."""

    def pretty(self) -> str:
        return "Int"

    def __eq__(self, other: object) -> bool:
        return isinstance(other, TInt)

    def __hash__(self) -> int:
        return hash("TInt")


@dataclass(frozen=True, slots=True)
class TLattice(CaslType):
    """Type representing a lattice/abstract domain."""
    domain_name: str

    def pretty(self) -> str:
        return f"Lattice<{self.domain_name}>"

    def __eq__(self, other: object) -> bool:
        return isinstance(other, TLattice) and self.domain_name == other.domain_name

    def __hash__(self) -> int:
        return hash(("TLattice", self.domain_name))


@dataclass(frozen=True, slots=True)
class TProduct(CaslType):
    """Product of lattice types."""
    components: Tuple[CaslType, ...]

    def pretty(self) -> str:
        parts = " × ".join(c.pretty() for c in self.components)
        return f"({parts})"

    def __eq__(self, other: object) -> bool:
        return isinstance(other, TProduct) and self.components == other.components

    def __hash__(self) -> int:
        return hash(("TProduct", self.components))


@dataclass(frozen=True, slots=True)
class TPowerset(CaslType):
    """Powerset lattice type."""
    element: CaslType

    def pretty(self) -> str:
        return f"℘({self.element.pretty()})"

    def __eq__(self, other: object) -> bool:
        return isinstance(other, TPowerset) and self.element == other.element

    def __hash__(self) -> int:
        return hash(("TPowerset", self.element))


@dataclass(frozen=True, slots=True)
class TMap(CaslType):
    """Map/function lattice type."""
    key: CaslType
    value: CaslType

    def pretty(self) -> str:
        return f"Map<{self.key.pretty()}, {self.value.pretty()}>"

    def __eq__(self, other: object) -> bool:
        return (
            isinstance(other, TMap) and
            self.key == other.key and
            self.value == other.value
        )

    def __hash__(self) -> int:
        return hash(("TMap", self.key, self.value))


@dataclass(frozen=True, slots=True)
class TFlat(CaslType):
    """Flat lattice over a base type."""
    base: CaslType

    def pretty(self) -> str:
        return f"Flat<{self.base.pretty()}>"

    def __eq__(self, other: object) -> bool:
        return isinstance(other, TFlat) and self.base == other.base

    def __hash__(self) -> int:
        return hash(("TFlat", self.base))


@dataclass(frozen=True, slots=True)
class TTransfer(CaslType):
    """Transfer function type: Domain → Domain."""
    input_domain: CaslType
    output_domain: CaslType

    def pretty(self) -> str:
        return f"{self.input_domain.pretty()} → {self.output_domain.pretty()}"

    def __eq__(self, other: object) -> bool:
        return (
            isinstance(other, TTransfer) and
            self.input_domain == other.input_domain and
            self.output_domain == other.output_domain
        )

    def __hash__(self) -> int:
        return hash(("TTransfer", self.input_domain, self.output_domain))


@dataclass(frozen=True, slots=True)
class TPredicate(CaslType):
    """Predicate/proposition type."""

    def pretty(self) -> str:
        return "Predicate"

    def __eq__(self, other: object) -> bool:
        return isinstance(other, TPredicate)

    def __hash__(self) -> int:
        return hash("TPredicate")


@dataclass(frozen=True, slots=True)
class TFormula(CaslType):
    """Temporal formula type (LTL or CTL)."""
    kind: str  # "ltl" or "ctl"

    def pretty(self) -> str:
        return f"Formula<{self.kind.upper()}>"

    def __eq__(self, other: object) -> bool:
        return isinstance(other, TFormula) and self.kind == other.kind

    def __hash__(self) -> int:
        return hash(("TFormula", self.kind))


# ============================================================================
# PART 5 — SYMBOL TABLE AND SCOPE MANAGEMENT
# Tracks declarations and their visibility
# ============================================================================


@dataclass(frozen=True, slots=True)
class Symbol:
    """
    A symbol table entry representing a declared name.
    """
    name: str
    kind: str  # "domain", "query", "atom", "transfer", "property", "checker", "binding"
    type: CaslType
    location: Optional[SourceLocation]
    node: Any  # The AST node that declared this symbol


class Scope:
    """
    A lexical scope containing symbol bindings.
    Supports nested scopes with parent lookup.
    """

    def __init__(
        self,
        name: str,
        parent: Optional[Scope] = None,
        kind: str = "block",
    ) -> None:
        self.name = name
        self.parent = parent
        self.kind = kind  # "module", "query", "block", etc.
        self._symbols: Dict[str, Symbol] = {}
        self._children: List[Scope] = []

        if parent is not None:
            parent._children.append(self)

    def define(self, symbol: Symbol) -> Optional[Symbol]:
        """
        Define a symbol in this scope.
        Returns the previous definition if there was a conflict, None otherwise.
        """
        existing = self._symbols.get(symbol.name)
        self._symbols[symbol.name] = symbol
        return existing

    def lookup_local(self, name: str) -> Optional[Symbol]:
        """Look up a symbol in this scope only (no parent lookup)."""
        return self._symbols.get(name)

    def lookup(self, name: str) -> Optional[Symbol]:
        """Look up a symbol, searching parent scopes if not found locally."""
        local = self._symbols.get(name)
        if local is not None:
            return local
        if self.parent is not None:
            return self.parent.lookup(name)
        return None

    def all_symbols(self) -> Iterator[Symbol]:
        """Iterate over all symbols in this scope (not including parents)."""
        return iter(self._symbols.values())

    def symbols_of_kind(self, kind: str) -> Iterator[Symbol]:
        """Iterate over symbols of a specific kind."""
        return (s for s in self._symbols.values() if s.kind == kind)


class SymbolTable:
    """
    Symbol table managing scopes and symbol resolution.
    Handles scope entry/exit events similar to shims pattern [cppcheckdata-shims:3816-3828].
    """

    def __init__(self) -> None:
        self._global_scope = Scope("global", kind="module")
        self._current_scope = self._global_scope
        self._scope_stack: List[Scope] = [self._global_scope]

    @property
    def global_scope(self) -> Scope:
        """Get the global/module scope."""
        return self._global_scope

    @property
    def current_scope(self) -> Scope:
        """Get the current active scope."""
        return self._current_scope

    def enter_scope(self, name: str, kind: str = "block") -> Scope:
        """Enter a new nested scope."""
        new_scope = Scope(name, parent=self._current_scope, kind=kind)
        self._scope_stack.append(new_scope)
        self._current_scope = new_scope
        return new_scope

    def exit_scope(self) -> Scope:
        """Exit the current scope and return to parent."""
        if len(self._scope_stack) <= 1:
            raise RuntimeError("Cannot exit global scope")
        exited = self._scope_stack.pop()
        self._current_scope = self._scope_stack[-1]
        return exited

    def define(self, symbol: Symbol) -> Optional[Symbol]:
        """Define a symbol in the current scope."""
        return self._current_scope.define(symbol)

    def define_global(self, symbol: Symbol) -> Optional[Symbol]:
        """Define a symbol in the global scope."""
        return self._global_scope.define(symbol)

    def lookup(self, name: str) -> Optional[Symbol]:
        """Look up a symbol starting from current scope."""
        return self._current_scope.lookup(name)

    def lookup_global(self, name: str) -> Optional[Symbol]:
        """Look up a symbol in global scope only."""
        return self._global_scope.lookup_local(name)


# ============================================================================
# PART 6 — SEMANTIC ANALYZER
# Two-phase analysis: resolve → validate
# Pattern from cppcheckdata-shims:54796, 54873
# ============================================================================


@dataclass
class SemanticContext:
    """
    Context maintained during semantic analysis.
    """
    module: A.Module
    symbols: SymbolTable
    diagnostics: DiagnosticCollector
    # Track what has been resolved
    resolved_domains: Dict[str, CaslType] = field(default_factory=dict)
    resolved_queries: Dict[str, A.CsqlQuery] = field(default_factory=dict)
    resolved_atoms: Dict[str, A.PropAtom] = field(default_factory=dict)
    resolved_transfers: Dict[str, A.TransferDecl] = field(default_factory=dict)
    resolved_properties: Dict[str, A.PropertyDecl] = field(default_factory=dict)
    # Pending references to resolve
    pending_references: List[Tuple[str, str, Any]] = field(default_factory=list)


class SemanticAnalyzer:
    """
    Semantic analyzer for CASL modules.

    Performs two-phase analysis [cppcheckdata-shims:54796, 54873]:
    1. Phase 1 (resolve): Collect all declarations and build symbol table
    2. Phase 2 (validate): Validate references, types, and constraints
    """

    def __init__(
        self,
        *,
        suppression_manager: Optional[SuppressionManager] = None,
    ) -> None:
        self._suppression = suppression_manager or SuppressionManager()

    def analyze(self, module: A.Module) -> SemanticResult:
        """
        Perform semantic analysis on a CASL module.
        Returns a SemanticResult containing the analyzed module and diagnostics.
        """
        collector = DiagnosticCollector(suppression_manager=self._suppression)
        symbols = SymbolTable()

        ctx = SemanticContext(
            module=module,
            symbols=symbols,
            diagnostics=collector,
        )

        # Phase 1: Resolve - collect all declarations
        self._phase1_resolve(ctx)

        # Phase 2: Validate - check references and types
        self._phase2_validate(ctx)

        return SemanticResult(
            module=module,
            symbols=symbols,
            diagnostics=collector.diagnostics,
            has_errors=collector.has_errors(),
        )

    # ========================================================================
    # Phase 1: Resolution - Collect declarations
    # ========================================================================

    def _phase1_resolve(self, ctx: SemanticContext) -> None:
        """
        Phase 1: Collect all declarations and build symbol table.
        """
        # Process imports first
        for item in ctx.module.items:
            if isinstance(item, A.Import):
                self._resolve_import(ctx, item)

        # Process domain declarations
        for item in ctx.module.items:
            if isinstance(item, A.DomainDecl):
                self._resolve_domain(ctx, item)

        # Process query declarations
        for item in ctx.module.items:
            if isinstance(item, A.CsqlQuery):
                self._resolve_query(ctx, item)

        # Process atom declarations
        for item in ctx.module.items:
            if isinstance(item, A.PropAtom):
                self._resolve_atom(ctx, item)

        # Process transfer declarations
        for item in ctx.module.items:
            if isinstance(item, A.TransferDecl):
                self._resolve_transfer(ctx, item)

        # Process property declarations
        for item in ctx.module.items:
            if isinstance(item, A.PropertyDecl):
                self._resolve_property(ctx, item)

        # Process checker declarations
        for item in ctx.module.items:
            if isinstance(item, A.CheckerDecl):
                self._resolve_checker(ctx, item)

    def _resolve_import(self, ctx: SemanticContext, imp: A.Import) -> None:
        """Process an import declaration."""
        # For now, just record the import
        # In a full implementation, we would load the imported module
        loc = SourceLocation.from_ast_loc(imp.loc)
        ctx.diagnostics.report(
            "unresolved-import",
            f"Import '{imp.module_path}' not resolved (module loading not implemented)",
            DiagnosticSeverity.WARNING,
            loc,
            confidence=Confidence.HIGH,
        )

    def _resolve_domain(self, ctx: SemanticContext, domain: A.DomainDecl) -> None:
        """Process a domain declaration."""
        loc = SourceLocation.from_ast_loc(domain.loc)

        # Check for duplicate domain name
        existing = ctx.symbols.lookup_global(domain.name)
        if existing is not None:
            ctx.diagnostics.report(
                "duplicate-domain",
                f"Domain '{domain.name}' already defined at {existing.location}",
                DiagnosticSeverity.ERROR,
                loc,
                secondary=(
                    SecondaryLocation(existing.location, "previous definition here")
                    if existing.location else ()
                ),
            )
            return

        # Compute the domain type
        domain_type = self._lattice_expr_to_type(ctx, domain.lattice)

        # Register the symbol
        symbol = Symbol(
            name=domain.name,
            kind="domain",
            type=domain_type,
            location=loc,
            node=domain,
        )
        ctx.symbols.define_global(symbol)
        ctx.resolved_domains[domain.name] = domain_type

    def _lattice_expr_to_type(
        self, ctx: SemanticContext, expr: A.LatticeExpr
    ) -> CaslType:
        """Convert a lattice expression AST to a CaslType."""
        if isinstance(expr, A.LatticeName):
            # Reference to another domain
            return TLattice(expr.name)

        elif isinstance(expr, A.LatticeProduct):
            components = tuple(
                self._lattice_expr_to_type(ctx, comp) for comp in expr.components
            )
            return TProduct(components)

        elif isinstance(expr, A.LatticePowerset):
            element = self._lattice_expr_to_type(ctx, expr.element)
            return TPowerset(element)

        elif isinstance(expr, A.LatticeMap):
            key = self._lattice_expr_to_type(ctx, expr.key)
            value = self._lattice_expr_to_type(ctx, expr.value)
            return TMap(key, value)

        elif isinstance(expr, A.LatticeFlat):
            base = self._lattice_expr_to_type(ctx, expr.base)
            return TFlat(base)

        else:
            ctx.diagnostics.report_from_ast(
                "unknown-lattice-expr",
                f"Unknown lattice expression type: {type(expr).__name__}",
                expr,
                DiagnosticSeverity.ERROR,
            )
            return TUnknown()

    def _resolve_query(self, ctx: SemanticContext, query: A.CsqlQuery) -> None:
        """Process a CSQL query declaration."""
        loc = SourceLocation.from_ast_loc(query.loc)

        # Check for duplicate query name
        existing = ctx.symbols.lookup_global(query.name)
        if existing is not None:
            ctx.diagnostics.report(
                "duplicate-query",
                f"Query '{query.name}' already defined at {existing.location}",
                DiagnosticSeverity.ERROR,
                loc,
            )
            return

        # Register the symbol (queries produce sets of entities)
        # The result type depends on the source entity kind
        result_type: CaslType
        if query.source is not None:
            result_type = TPowerset(TEntity(query.source.kind))
        else:
            result_type = TPowerset(TEntity(A.EntityKind.TOKEN))

        symbol = Symbol(
            name=query.name,
            kind="query",
            type=result_type,
            location=loc,
            node=query,
        )
        ctx.symbols.define_global(symbol)
        ctx.resolved_queries[query.name] = query

        # Enter query scope for bindings
        ctx.symbols.enter_scope(f"query:{query.name}", kind="query")

        # Register bindings
        for binding in query.bindings:
            self._resolve_binding(ctx, binding)

        # Exit query scope
        ctx.symbols.exit_scope()

    def _resolve_binding(self, ctx: SemanticContext, binding: A.Binding) -> None:
        """Process a query variable binding."""
        loc = SourceLocation.from_ast_loc(binding.loc)

        # Determine the type from the binding's type annotation
        bind_type = self._type_name_to_type(binding.type_name)

        symbol = Symbol(
            name=binding.name,
            kind="binding",
            type=bind_type,
            location=loc,
            node=binding,
        )

        existing = ctx.symbols.define(symbol)
        if existing is not None:
            ctx.diagnostics.report(
                "duplicate-binding",
                f"Binding '{binding.name}' already defined in this scope",
                DiagnosticSeverity.ERROR,
                loc,
            )

    def _type_name_to_type(self, type_name: str) -> CaslType:
        """Convert a type name string to a CaslType."""
        type_map: Dict[str, CaslType] = {
            "variable": TEntity(A.EntityKind.VARIABLE),
            "function": TEntity(A.EntityKind.FUNCTION),
            "token": TEntity(A.EntityKind.TOKEN),
            "scope": TEntity(A.EntityKind.SCOPE),
            "type": TEntity(A.EntityKind.TYPE),
            "expr": TEntity(A.EntityKind.EXPR),
            "stmt": TEntity(A.EntityKind.STMT),
            "string": TString(),
            "int": TInt(),
            "bool": TBool(),
        }
        return type_map.get(type_name.lower(), TUnknown(type_name))

    def _resolve_atom(self, ctx: SemanticContext, atom: A.PropAtom) -> None:
        """Process a proposition atom declaration."""
        loc = SourceLocation.from_ast_loc(atom.loc)

        # Check for duplicate atom name
        existing = ctx.symbols.lookup_global(atom.name)
        if existing is not None:
            ctx.diagnostics.report(
                "duplicate-atom",
                f"Atom '{atom.name}' already defined at {existing.location}",
                DiagnosticSeverity.ERROR,
                loc,
            )
            return

        symbol = Symbol(
            name=atom.name,
            kind="atom",
            type=TPredicate(),
            location=loc,
            node=atom,
        )
        ctx.symbols.define_global(symbol)
        ctx.resolved_atoms[atom.name] = atom

        # Record reference to query for phase 2 validation
        ctx.pending_references.append(("query", atom.query_name, atom))

    def _resolve_transfer(self, ctx: SemanticContext, transfer: A.TransferDecl) -> None:
        """Process a transfer function declaration."""
        loc = SourceLocation.from_ast_loc(transfer.loc)

        existing = ctx.symbols.lookup_global(transfer.name)
        if existing is not None:
            ctx.diagnostics.report(
                "duplicate-transfer",
                f"Transfer '{transfer.name}' already defined at {existing.location}",
                DiagnosticSeverity.ERROR,
                loc,
            )
            return

        # Transfer functions have type Domain → Domain
        # We'll resolve the actual domain types in phase 2
        transfer_type = TTransfer(TUnknown("input"), TUnknown("output"))

        symbol = Symbol(
            name=transfer.name,
            kind="transfer",
            type=transfer_type,
            location=loc,
            node=transfer,
        )
        ctx.symbols.define_global(symbol)
        ctx.resolved_transfers[transfer.name] = transfer

        # Record domain reference for phase 2
        ctx.pending_references.append(("domain", transfer.domain, transfer))

    def _resolve_property(self, ctx: SemanticContext, prop: A.PropertyDecl) -> None:
        """Process a property declaration."""
        loc = SourceLocation.from_ast_loc(prop.loc)

        existing = ctx.symbols.lookup_global(prop.name)
        if existing is not None:
            ctx.diagnostics.report(
                "duplicate-property",
                f"Property '{prop.name}' already defined at {existing.location}",
                DiagnosticSeverity.ERROR,
                loc,
            )
            return

        # Determine formula type
        formula_type: CaslType
        if isinstance(prop.formula, A.LTLFormula):
            formula_type = TFormula("ltl")
        elif isinstance(prop.formula, A.CTLFormula):
            formula_type = TFormula("ctl")
        else:
            formula_type = TFormula("unknown")

        symbol = Symbol(
            name=prop.name,
            kind="property",
            type=formula_type,
            location=loc,
            node=prop,
        )
        ctx.symbols.define_global(symbol)
        ctx.resolved_properties[prop.name] = prop

    def _resolve_checker(self, ctx: SemanticContext, checker: A.CheckerDecl) -> None:
        """Process a checker declaration."""
        loc = SourceLocation.from_ast_loc(checker.loc)

        existing = ctx.symbols.lookup_global(checker.name)
        if existing is not None:
            ctx.diagnostics.report(
                "duplicate-checker",
                f"Checker '{checker.name}' already defined at {existing.location}",
                DiagnosticSeverity.ERROR,
                loc,
            )
            return

        symbol = Symbol(
            name=checker.name,
            kind="checker",
            type=TUnknown("checker"),
            location=loc,
            node=checker,
        )
        ctx.symbols.define_global(symbol)

        # Record references to properties for phase 2
        for prop_name in checker.properties:
            ctx.pending_references.append(("property", prop_name, checker))

    # ========================================================================
    # Phase 2: Validation - Check references and types
    # ========================================================================

    def _phase2_validate(self, ctx: SemanticContext) -> None:
        """
        Phase 2: Post-resolution validation.
        Pattern from cppcheckdata-shims:54873 (_phase2_postchecks).
        """
        # Validate all pending references
        self._validate_references(ctx)

        # Validate CSQL predicates
        for query in ctx.resolved_queries.values():
            self._validate_csql_predicate(ctx, query.predicate)

        # Validate temporal formulas
        for prop in ctx.resolved_properties.values():
            self._validate_temporal_formula(ctx, prop.formula)

        # Validate transfer functions
        for transfer in ctx.resolved_transfers.values():
            self._validate_transfer_effects(ctx, transfer)

        # Check for unused declarations
        self._check_unused_declarations(ctx)

    def _validate_references(self, ctx: SemanticContext) -> None:
        """Validate all pending name references."""
        for ref_kind, ref_name, node in ctx.pending_references:
            if ref_kind == "query":
                if ref_name not in ctx.resolved_queries:
                    ctx.diagnostics.report_from_ast(
                        "undefined-query",
                        f"Reference to undefined query '{ref_name}'",
                        node,
                        DiagnosticSeverity.ERROR,
                    )
            elif ref_kind == "domain":
                if ref_name not in ctx.resolved_domains:
                    # Check if it's a built-in domain
                    if ref_name not in self._builtin_domains():
                        ctx.diagnostics.report_from_ast(
                            "undefined-domain",
                            f"Reference to undefined domain '{ref_name}'",
                            node,
                            DiagnosticSeverity.ERROR,
                        )
            elif ref_kind == "property":
                if ref_name not in ctx.resolved_properties:
                    ctx.diagnostics.report_from_ast(
                        "undefined-property",
                        f"Reference to undefined property '{ref_name}'",
                        node,
                        DiagnosticSeverity.ERROR,
                    )
            elif ref_kind == "atom":
                if ref_name not in ctx.resolved_atoms:
                    ctx.diagnostics.report_from_ast(
                        "undefined-atom",
                        f"Reference to undefined atom '{ref_name}'",
                        node,
                        DiagnosticSeverity.ERROR,
                    )

    def _builtin_domains(self) -> Set[str]:
        """Return set of built-in domain names."""
        return {
            "Sign",           # Sign domain: {neg, zero, pos}
            "Interval",       # Integer intervals
            "Parity",         # Even/odd
            "Bool3",          # Three-valued boolean
            "Const",          # Constant propagation
            "Taint",          # Taint tracking
            "PointsTo",       # Points-to analysis
            "LiveVars",       # Live variables
            "ReachingDefs",   # Reaching definitions
            "AvailExprs",     # Available expressions
        }

    def _validate_csql_predicate(
        self, ctx: SemanticContext, pred: A.CsqlPredicate
    ) -> None:
        """Validate a CSQL predicate recursively."""
        if isinstance(pred, A.CsqlAnd):
            for child in pred.children:
                self._validate_csql_predicate(ctx, child)

        elif isinstance(pred, A.CsqlOr):
            for child in pred.children:
                self._validate_csql_predicate(ctx, child)

        elif isinstance(pred, A.CsqlNot):
            self._validate_csql_predicate(ctx, pred.child)

        elif isinstance(pred, A.CsqlHasAttr):
            # Validate attribute name is sensible
            valid_attrs = {
                "name", "type", "value", "scope", "line", "column",
                "file", "isConst", "isStatic", "isGlobal", "isLocal",
                "isParameter", "isSigned", "isUnsigned", "isPointer",
            }
            if pred.attr not in valid_attrs:
                ctx.diagnostics.report_from_ast(
                    "unknown-attribute",
                    f"Unknown attribute '{pred.attr}' in has-attr predicate",
                    pred,
                    DiagnosticSeverity.WARNING,
                    confidence=Confidence.MEDIUM,
                )

        elif isinstance(pred, A.CsqlAttrEq):
            pass  # Attribute equality is always valid if it parses

        elif isinstance(pred, A.CsqlAttrMatch):
            # Validate regex pattern
            try:
                re.compile(pred.pattern)
            except re.error as e:
                ctx.diagnostics.report_from_ast(
                    "invalid-regex",
                    f"Invalid regex pattern in attr-match: {e}",
                    pred,
                    DiagnosticSeverity.ERROR,
                )

        elif isinstance(pred, A.CsqlTypeIs):
            pass  # Type checking is runtime

        elif isinstance(pred, A.CsqlFlows):
            pass  # Flow predicates are runtime

        elif isinstance(pred, A.CsqlReaches):
            pass  # Reachability is runtime

        elif isinstance(pred, A.CsqlCall):
            # Validate referenced query exists
            if pred.query_name not in ctx.resolved_queries:
                ctx.diagnostics.report_from_ast(
                    "undefined-query-call",
                    f"Call to undefined query '{pred.query_name}'",
                    pred,
                    DiagnosticSeverity.ERROR,
                )

        elif isinstance(pred, A.CsqlTrue) or isinstance(pred, A.CsqlFalse):
            pass  # Literals are always valid

        elif isinstance(pred, A.CsqlVarRef):
            # Variable references will be checked within query scope
            pass

    def _validate_temporal_formula(
        self, ctx: SemanticContext, formula: Union[A.LTLFormula, A.CTLFormula]
    ) -> None:
        """Validate a temporal logic formula."""
        if isinstance(formula, A.LTLFormula):
            self._validate_ltl_formula(ctx, formula)
        elif isinstance(formula, A.CTLFormula):
            self._validate_ctl_formula(ctx, formula)

    def _validate_ltl_formula(self, ctx: SemanticContext, formula: A.LTLFormula) -> None:
        """Validate an LTL formula recursively."""
        if isinstance(formula, A.LTLProp):
            # Check that referenced atom exists
            if formula.atom_name not in ctx.resolved_atoms:
                ctx.diagnostics.report_from_ast(
                    "undefined-atom-ref",
                    f"LTL formula references undefined atom '{formula.atom_name}'",
                    formula,
                    DiagnosticSeverity.ERROR,
                )

        elif isinstance(formula, A.LTLTrue) or isinstance(formula, A.LTLFalse):
            pass  # Literals are valid

        elif isinstance(formula, A.LTLNot):
            self._validate_ltl_formula(ctx, formula.child)

        elif isinstance(formula, A.LTLAnd):
            self._validate_ltl_formula(ctx, formula.left)
            self._validate_ltl_formula(ctx, formula.right)

        elif isinstance(formula, A.LTLOr):
            self._validate_ltl_formula(ctx, formula.left)
            self._validate_ltl_formula(ctx, formula.right)

        elif isinstance(formula, A.LTLImplies):
            self._validate_ltl_formula(ctx, formula.left)
            self._validate_ltl_formula(ctx, formula.right)

        elif isinstance(formula, A.LTLNext):
            self._validate_ltl_formula(ctx, formula.child)

        elif isinstance(formula, A.LTLFinally):
            self._validate_ltl_formula(ctx, formula.child)

        elif isinstance(formula, A.LTLGlobally):
            self._validate_ltl_formula(ctx, formula.child)

        elif isinstance(formula, A.LTLUntil):
            self._validate_ltl_formula(ctx, formula.left)
            self._validate_ltl_formula(ctx, formula.right)

        elif isinstance(formula, A.LTLRelease):
            self._validate_ltl_formula(ctx, formula.left)
            self._validate_ltl_formula(ctx, formula.right)

        elif isinstance(formula, A.LTLWeakUntil):
            self._validate_ltl_formula(ctx, formula.left)
            self._validate_ltl_formula(ctx, formula.right)

    def _validate_ctl_formula(self, ctx: SemanticContext, formula: A.CTLFormula) -> None:
        """Validate a CTL formula recursively."""
        if isinstance(formula, A.CTLProp):
            if formula.atom_name not in ctx.resolved_atoms:
                ctx.diagnostics.report_from_ast(
                    "undefined-atom-ref",
                    f"CTL formula references undefined atom '{formula.atom_name}'",
                    formula,
                    DiagnosticSeverity.ERROR,
                )

        elif isinstance(formula, A.CTLTrue) or isinstance(formula, A.CTLFalse):
            pass

        elif isinstance(formula, A.CTLNot):
            self._validate_ctl_formula(ctx, formula.child)

        elif isinstance(formula, A.CTLAnd):
            self._validate_ctl_formula(ctx, formula.left)
            self._validate_ctl_formula(ctx, formula.right)

        elif isinstance(formula, A.CTLOr):
            self._validate_ctl_formula(ctx, formula.left)
            self._validate_ctl_formula(ctx, formula.right)

        elif isinstance(formula, (A.CTLAX, A.CTLEX, A.CTLAF, A.CTLEF, A.CTLAG, A.CTLEG)):
            self._validate_ctl_formula(ctx, formula.child)

        elif isinstance(formula, (A.CTLAU, A.CTLEU)):
            self._validate_ctl_formula(ctx, formula.left)
            self._validate_ctl_formula(ctx, formula.right)

    def _validate_transfer_effects(
        self, ctx: SemanticContext, transfer: A.TransferDecl
    ) -> None:
        """Validate transfer function effects."""
        # Check domain reference
        domain_name = transfer.domain
        if domain_name not in ctx.resolved_domains and domain_name not in self._builtin_domains():
            # Already reported in reference validation
            return

        # Validate effects reference appropriate things
        for effect in transfer.effects:
            self._validate_effect(ctx, effect, transfer)

    def _validate_effect(
        self, ctx: SemanticContext, effect: A.AbstractEffect, transfer: A.TransferDecl
    ) -> None:
        """Validate an abstract effect."""
        if isinstance(effect, A.EffectAssign):
            # Variable should be sensible
            pass

        elif isinstance(effect, A.EffectJoin):
            # Recursively validate children
            for child in effect.effects:
                self._validate_effect(ctx, child, transfer)

        elif isinstance(effect, A.EffectSeq):
            for child in effect.effects:
                self._validate_effect(ctx, child, transfer)

        elif isinstance(effect, A.EffectCall):
            # Check referenced transfer exists
            if effect.transfer_name not in ctx.resolved_transfers:
                if effect.transfer_name != transfer.name:  # Allow recursion
                    ctx.diagnostics.report_from_ast(
                        "undefined-transfer-call",
                        f"Effect calls undefined transfer '{effect.transfer_name}'",
                        effect,
                        DiagnosticSeverity.ERROR,
                    )

        elif isinstance(effect, A.EffectIdentity):
            pass  # Identity is always valid

    def _check_unused_declarations(self, ctx: SemanticContext) -> None:
        """Check for declarations that are never referenced."""
        # Track which atoms are used in properties
        used_atoms: Set[str] = set()
        for prop in ctx.resolved_properties.values():
            used_atoms.update(self._collect_atom_refs(prop.formula))

        # Report unused atoms
        for atom_name, atom in ctx.resolved_atoms.items():
            if atom_name not in used_atoms:
                ctx.diagnostics.report_from_ast(
                    "unused-atom",
                    f"Atom '{atom_name}' is declared but never used in any property",
                    atom,
                    DiagnosticSeverity.STYLE,
                    confidence=Confidence.HIGH,
                )

        # Track which queries are used
        used_queries: Set[str] = set()
        for atom in ctx.resolved_atoms.values():
            used_queries.add(atom.query_name)
        # Also check for query calls in predicates
        for query in ctx.resolved_queries.values():
            used_queries.update(self._collect_query_calls(query.predicate))

        # Report unused queries
        for query_name, query in ctx.resolved_queries.items():
            if query_name not in used_queries:
                ctx.diagnostics.report_from_ast(
                    "unused-query",
                    f"Query '{query_name}' is declared but never used",
                    query,
                    DiagnosticSeverity.STYLE,
                    confidence=Confidence.HIGH,
                )

    def _collect_atom_refs(
        self, formula: Union[A.LTLFormula, A.CTLFormula]
    ) -> Set[str]:
        """Collect all atom references in a temporal formula."""
        refs: Set[str] = set()

        if isinstance(formula, (A.LTLProp, A.CTLProp)):
            refs.add(formula.atom_name)
        elif hasattr(formula, "child"):
            refs.update(self._collect_atom_refs(formula.child))
        elif hasattr(formula, "left") and hasattr(formula, "right"):
            refs.update(self._collect_atom_refs(formula.left))
            refs.update(self._collect_atom_refs(formula.right))

        return refs

    def _collect_query_calls(self, pred: A.CsqlPredicate) -> Set[str]:
        """Collect all query calls in a predicate."""
        calls: Set[str] = set()

        if isinstance(pred, A.CsqlCall):
            calls.add(pred.query_name)
        elif isinstance(pred, (A.CsqlAnd, A.CsqlOr)):
            for child in pred.children:
                calls.update(self._collect_query_calls(child))
        elif isinstance(pred, A.CsqlNot):
            calls.update(self._collect_query_calls(pred.child))

        return calls


# ============================================================================
# PART 7 — SEMANTIC RESULT AND PUBLIC API
# ============================================================================


@dataclass(frozen=True)
class SemanticResult:
    """
    Result of semantic analysis.
    """
    module: A.Module
    symbols: SymbolTable
    diagnostics: List[Diagnostic]
    has_errors: bool

    def format_diagnostics(self, *, format: str = "gcc") -> str:
        """
        Format all diagnostics as a string.

        Args:
            format: Output format - "gcc" for GCC-style, "json" for JSON
        """
        if format == "json":
            import json
            return json.dumps([d.to_dict() for d in self.diagnostics], indent=2)
        else:
            return "\n".join(d.to_gcc_format() for d in self.diagnostics)

    def errors_only(self) -> List[Diagnostic]:
        """Get only ERROR severity diagnostics."""
        return [d for d in self.diagnostics if d.severity == DiagnosticSeverity.ERROR]

    def warnings_only(self) -> List[Diagnostic]:
        """Get only WARNING severity diagnostics."""
        return [d for d in self.diagnostics if d.severity == DiagnosticSeverity.WARNING]


def analyze_module(
    module: A.Module,
    *,
    suppression_manager: Optional[SuppressionManager] = None,
) -> SemanticResult:
    """
    Perform semantic analysis on a CASL module.

    This is the main entry point for semantic analysis.

    Args:
        module: The parsed CASL module AST
        suppression_manager: Optional suppression manager for filtering diagnostics

    Returns:
        SemanticResult containing the analyzed module, symbol table, and diagnostics
    """
    analyzer = SemanticAnalyzer(suppression_manager=suppression_manager)
    return analyzer.analyze(module)


def analyze_file(
    path: str,
    *,
    suppression_manager: Optional[SuppressionManager] = None,
) -> SemanticResult:
    """
    Parse and analyze a CASL file.

    Args:
        path: Path to the CASL source file
        suppression_manager: Optional suppression manager

    Returns:
        SemanticResult containing analysis results
    """
    # Import parser (assumed from previous conversation)
    from casl.parser import parse_file

    module = parse_file(path)
    return analyze_module(module, suppression_manager=suppression_manager)


# ============================================================================
# PART 8 — TYPE CHECKER (Additional validation for domain types)
# ============================================================================


class TypeChecker:
    """
    Type checker for CASL domain expressions and transfer functions.
    Validates type compatibility and domain composition rules.
    """

    def __init__(self, ctx: SemanticContext) -> None:
        self._ctx = ctx

    def check_domain_composition(
        self, domain_type: CaslType, loc: Optional[SourceLocation] = None
    ) -> bool:
        """
        Check that a domain composition is valid.
        Returns True if valid, False otherwise (with diagnostics reported).
        """
        if isinstance(domain_type, TLattice):
            # Check referenced domain exists
            if domain_type.domain_name not in self._ctx.resolved_domains:
                if domain_type.domain_name not in self._builtin_domains():
                    self._ctx.diagnostics.report(
                        "undefined-domain-ref",
                        f"Domain composition references undefined domain '{domain_type.domain_name}'",
                        DiagnosticSeverity.ERROR,
                        loc,
                    )
                    return False
            return True

        elif isinstance(domain_type, TProduct):
            # All components must be valid
            return all(
                self.check_domain_composition(comp, loc)
                for comp in domain_type.components
            )

        elif isinstance(domain_type, TPowerset):
            return self.check_domain_composition(domain_type.element, loc)

        elif isinstance(domain_type, TMap):
            return (
                self.check_domain_composition(domain_type.key, loc) and
                self.check_domain_composition(domain_type.value, loc)
            )

        elif isinstance(domain_type, TFlat):
            return self.check_domain_composition(domain_type.base, loc)

        elif isinstance(domain_type, TUnknown):
            # Unknown types are placeholders - warning only
            self._ctx.diagnostics.report(
                "unresolved-type",
                f"Type could not be fully resolved: {domain_type.pretty()}",
                DiagnosticSeverity.WARNING,
                loc,
                confidence=Confidence.LOW,
            )
            return True

        else:
            # Primitive types are always valid
            return True

    def _