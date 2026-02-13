"""
cppcheckdata_shims/checkers.py
══════════════════════════════

Production checker framework that composes analyses from the
cppcheckdata-shims infrastructure into actionable bug detectors.

This is the "last mile" module: it bridges abstract analyses
(dataflow, type, symbolic execution, memory abstraction) to
concrete, CWE-tagged, cppcheck-addon-compatible diagnostics.

Architecture
────────────

  ┌─────────────────────────────────────────────────────────┐
  │                   CheckerRunner                         │
  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
  │  │NullDerefCheck│  │BufferOverflow│  │UseAfterFree  │  │
  │  │   Checker    │  │  Checker     │  │  Checker     │  │
  │  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  │
  │         │                 │                  │          │
  │  ┌──────▼─────────────────▼──────────────────▼───────┐  │
  │  │              Evidence Collection                  │  │
  │  │  dataflow_analyses │ type_analysis │ symbolic_exec│  │
  │  │  memory_abstraction│ ctrlflow_graph│ callgraph    │  │
  │  └──────────────────────────┬────────────────────────┘  │
  │                             │                           │
  │  ┌──────────────────────────▼────────────────────────┐  │
  │  │           SuppressionManager                      │  │
  │  │  // cppcheck-suppress  │  file-level  │  global   │  │
  │  └──────────────────────────┬────────────────────────┘  │
  │                             │                           │
  │  ┌──────────────────────────▼────────────────────────┐  │
  │  │        Diagnostic Formatter (JSON / text)         │  │
  │  └──────────────────────────────────────────────────┘  │
  └─────────────────────────────────────────────────────────┘

Each Checker follows a four-phase lifecycle:

  1. **configure()**        — declare required analyses, set thresholds
  2. **collect_evidence()** — run analyses, gather suspicious sites
  3. **diagnose()**         — correlate evidence, assign severity/confidence
  4. **report()**           — emit Diagnostics (filtered by suppressions)

License: MIT — same as cppcheckdata-shims.
"""

from __future__ import annotations

import json
import sys
import time
from abc import ABC, abstractmethod
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import (
    Any,
    Callable,
    ClassVar,
    Dict,
    FrozenSet,
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
    Union,
)

# ── sibling imports (best-effort) ────────────────────────────────────
try:
    from cppcheckdata_shims.dataflow_analyses import (  # type: ignore[import-untyped]
        NullPointerAnalysis,
        IntervalAnalysis,
        LiveVariables,
        ReachingDefinitions,
        DefiniteAssignment,
        TaintAnalysis,
        SignAnalysis,
        PointerAnalysis,
        ConstantPropagation,
        run_all_analyses,
    )
except ImportError:
    NullPointerAnalysis = None  # type: ignore[assignment,misc]
    IntervalAnalysis = None  # type: ignore[assignment,misc]
    LiveVariables = None  # type: ignore[assignment,misc]
    ReachingDefinitions = None  # type: ignore[assignment,misc]
    DefiniteAssignment = None  # type: ignore[assignment,misc]
    TaintAnalysis = None  # type: ignore[assignment,misc]
    SignAnalysis = None  # type: ignore[assignment,misc]
    PointerAnalysis = None  # type: ignore[assignment,misc]
    ConstantPropagation = None  # type: ignore[assignment,misc]
    run_all_analyses = None  # type: ignore[assignment,misc]

try:
    from cppcheckdata_shims.type_analysis import (  # type: ignore[import-untyped]
        TypeAnalysis,
        TypeAnalysisResults,
        CType,
        TypeKind,
    )
except ImportError:
    TypeAnalysis = None  # type: ignore[assignment,misc]
    TypeAnalysisResults = None  # type: ignore[assignment,misc]
    CType = None  # type: ignore[assignment,misc]
    TypeKind = None  # type: ignore[assignment,misc]

try:
    from cppcheckdata import (  # type: ignore[import-untyped]
        CppcheckData,
        Configuration,
        Token,
        Scope,
        Variable,
        Function,
        ValueType,
    )
except ImportError:
    CppcheckData = Any  # type: ignore[assignment,misc]
    Configuration = Any  # type: ignore[assignment,misc]
    Token = Any  # type: ignore[assignment,misc]
    Scope = Any  # type: ignore[assignment,misc]
    Variable = Any  # type: ignore[assignment,misc]
    Function = Any  # type: ignore[assignment,misc]
    ValueType = Any  # type: ignore[assignment,misc]


# ═════════════════════════════════════════════════════════════════════════
#  PART 1 — DIAGNOSTIC MODEL
# ═════════════════════════════════════════════════════════════════════════

class DiagnosticSeverity(Enum):
    """cppcheck-compatible severity levels."""
    ERROR = "error"
    WARNING = "warning"
    STYLE = "style"
    PERFORMANCE = "performance"
    PORTABILITY = "portability"
    INFORMATION = "information"


class Confidence(Enum):
    """
    How certain we are that the diagnostic is a true positive.

    HIGH   — analysis proves the bug exists on at least one feasible path
    MEDIUM — analysis strongly suspects but cannot rule out infeasibility
    LOW    — heuristic / pattern-based, may be false positive
    """
    HIGH = auto()
    MEDIUM = auto()
    LOW = auto()


@dataclass(frozen=True)
class SourceLocation:
    """A specific point in source code."""
    file: str = ""
    line: int = 0
    column: int = 0

    def __str__(self) -> str:
        if self.column:
            return f"{self.file}:{self.line}:{self.column}"
        return f"{self.file}:{self.line}"


@dataclass(frozen=True)
class Diagnostic:
    """
    A single diagnostic finding.

    Designed for direct serialization to cppcheck's JSON addon protocol.

    Attributes
    ----------
    error_id     : Unique identifier (e.g., "nullPointerDeref")
    message      : Human-readable description
    severity     : DiagnosticSeverity
    location     : Primary source location
    confidence   : Confidence level
    cwe          : CWE identifier (0 = none)
    checker_name : Name of the checker that produced this
    addon        : Addon name for cppcheck protocol
    extra        : Additional context string
    secondary    : Related locations (e.g., where a pointer was set to NULL)
    evidence     : Machine-readable evidence dict for downstream tooling
    """
    error_id: str
    message: str
    severity: DiagnosticSeverity
    location: SourceLocation
    confidence: Confidence = Confidence.MEDIUM
    cwe: int = 0
    checker_name: str = ""
    addon: str = "cppcheckdata-shims"
    extra: str = ""
    secondary: Tuple[SourceLocation, ...] = ()
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_cppcheck_json(self) -> Dict[str, Any]:
        """Serialize to cppcheck's JSON addon output format."""
        result: Dict[str, Any] = {
            "file": self.location.file,
            "linenr": self.location.line,
            "column": self.location.column,
            "severity": self.severity.value,
            "message": self.message,
            "addon": self.addon,
            "errorId": self.error_id,
            "extra": self.extra,
        }
        if self.cwe:
            result["cwe"] = self.cwe
        return result

    def to_json_str(self) -> str:
        """Single-line JSON string for cppcheck addon stdout."""
        return json.dumps(self.to_cppcheck_json())

    def to_gcc_format(self) -> str:
        """GCC-style diagnostic string: file:line:col: severity: message."""
        sev = self.severity.value
        return f"{self.location}: {sev}: {self.message} [{self.error_id}]"


# ═════════════════════════════════════════════════════════════════════════
#  PART 2 — SUPPRESSION MANAGER
# ═════════════════════════════════════════════════════════════════════════

class SuppressionManager:
    """
    Manages diagnostic suppressions from multiple sources.

    Sources:
      1. Inline comments:  ``// cppcheck-suppress errorId``
      2. File-level suppressions (passed programmatically)
      3. Global suppressions (command-line or config)

    Usage
    -----
    >>> sm = SuppressionManager()
    >>> sm.load_inline_suppressions(cfg)
    >>> sm.add_file_suppression("nullDeref", "legacy/old_code.c")
    >>> sm.add_global_suppression("uninitVar")
    >>> if not sm.is_suppressed(diagnostic):
    ...     emit(diagnostic)
    """

    def __init__(self) -> None:
        # {(file, line)} → set of error_ids suppressed at that location
        self._inline: Dict[Tuple[str, int], Set[str]] = defaultdict(set)
        # file pattern → set of error_ids
        self._file_level: Dict[str, Set[str]] = defaultdict(set)
        # globally suppressed error_ids
        self._global: Set[str] = set()

    def load_inline_suppressions(self, cfg: Any) -> None:
        """
        Scan token list for ``// cppcheck-suppress`` comments.

        cppcheck already parses these into ``cfg.suppressions``, but
        we also handle direct token scanning for addons that run
        independently.
        """
        # Method 1: Use cppcheck's parsed suppressions
        for supp in getattr(cfg, "suppressions", []):
            error_id = getattr(supp, "errorId", None)
            file = getattr(supp, "fileName", "")
            line = getattr(supp, "lineNumber", 0)
            if error_id:
                if file and line:
                    self._inline[(file, line)].add(error_id)
                elif file:
                    self._file_level[file].add(error_id)
                else:
                    self._global.add(error_id)

        # Method 2: Scan tokens for patterns cppcheck might have missed
        prev_tok = None
        for tok in getattr(cfg, "tokenlist", []):
            # Look for comment tokens or preceding-line suppress markers
            # cppcheck strips comments, but we check for isSuppressed attr
            is_suppressed = getattr(tok, "isSuppressed", False)
            if is_suppressed:
                # The token itself carries suppression info
                file = getattr(tok, "file", "")
                line = getattr(tok, "linenr", 0)
                # We don't know which errorId without more parsing,
                # so we mark this location as "any suppression"
                self._inline[(file, line)].add("*")
            prev_tok = tok

    def add_file_suppression(self, error_id: str, file_pattern: str) -> None:
        """Suppress ``error_id`` in files matching ``file_pattern``."""
        self._file_level[file_pattern].add(error_id)

    def add_global_suppression(self, error_id: str) -> None:
        """Globally suppress ``error_id``."""
        self._global.add(error_id)

    def is_suppressed(self, diag: Diagnostic) -> bool:
        """Check whether a diagnostic should be suppressed."""
        eid = diag.error_id

        # Global
        if eid in self._global or "*" in self._global:
            return True

        loc = diag.location

        # Inline (exact line match, or line-1 for preceding-line suppress)
        for line_offset in (0, 1):
            key = (loc.file, loc.line - line_offset)
            suppressed_ids = self._inline.get(key, set())
            if eid in suppressed_ids or "*" in suppressed_ids:
                return True

        # File-level
        for pattern, ids in self._file_level.items():
            if eid in ids or "*" in ids:
                # Simple matching: exact or fnmatch-style
                if pattern == loc.file or loc.file.endswith(pattern):
                    return True
                try:
                    from fnmatch import fnmatch
                    if fnmatch(loc.file, pattern):
                        return True
                except ImportError:
                    pass

        return False

    def filter_diagnostics(
        self, diagnostics: Iterable[Diagnostic]
    ) -> List[Diagnostic]:
        """Return only non-suppressed diagnostics."""
        return [d for d in diagnostics if not self.is_suppressed(d)]


# ═════════════════════════════════════════════════════════════════════════
#  PART 3 — CHECKER BASE CLASS
# ═════════════════════════════════════════════════════════════════════════

class Checker(ABC):
    """
    Abstract base class for all checkers.

    Lifecycle
    ─────────
      1. ``configure(ctx)``        — receive context, declare needs
      2. ``collect_evidence(ctx)``  — run or consume analyses
      3. ``diagnose(ctx)``          — correlate evidence into diagnostics
      4. ``report(ctx)``            — yield final diagnostics

    Subclass Contract
    ─────────────────
      - Override ``name``, ``description``, ``error_ids``
      - Implement ``collect_evidence()`` and ``diagnose()``
      - Optionally override ``configure()`` for custom setup
    """

    # ── Metadata (override in subclasses) ────────────────────────────

    name: ClassVar[str] = "base-checker"
    description: ClassVar[str] = ""
    error_ids: ClassVar[FrozenSet[str]] = frozenset()
    default_severity: ClassVar[DiagnosticSeverity] = DiagnosticSeverity.WARNING
    cwe_ids: ClassVar[Dict[str, int]] = {}  # error_id → CWE number

    def __init__(self) -> None:
        self._diagnostics: List[Diagnostic] = []
        self._enabled: bool = True
        self._config: Dict[str, Any] = {}

    @property
    def diagnostics(self) -> List[Diagnostic]:
        return list(self._diagnostics)

    def configure(self, ctx: CheckerContext) -> None:
        """
        Called before evidence collection.

        Override to set thresholds, read configuration, etc.
        Default implementation does nothing.
        """
        pass

    @abstractmethod
    def collect_evidence(self, ctx: CheckerContext) -> None:
        """
        Run analyses and gather evidence.

        This is where you invoke dataflow_analyses, type_analysis,
        symbolic_exec, etc. and store intermediate results.
        """
        ...

    @abstractmethod
    def diagnose(self, ctx: CheckerContext) -> None:
        """
        Correlate evidence into Diagnostic objects.

        Append diagnostics to ``self._diagnostics``.
        """
        ...

    def report(self, ctx: CheckerContext) -> List[Diagnostic]:
        """
        Return final diagnostics, filtered by suppressions.

        Normally you don't need to override this.
        """
        return ctx.suppressions.filter_diagnostics(self._diagnostics)

    def _emit(
        self,
        error_id: str,
        message: str,
        file: str,
        line: int,
        column: int = 0,
        severity: Optional[DiagnosticSeverity] = None,
        confidence: Confidence = Confidence.MEDIUM,
        extra: str = "",
        secondary: Tuple[SourceLocation, ...] = (),
        evidence: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Helper to create and store a diagnostic."""
        self._diagnostics.append(Diagnostic(
            error_id=error_id,
            message=message,
            severity=severity or self.default_severity,
            location=SourceLocation(file=file, line=line, column=column),
            confidence=confidence,
            cwe=self.cwe_ids.get(error_id, 0),
            checker_name=self.name,
            extra=extra,
            secondary=secondary,
            evidence=evidence or {},
        ))

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} '{self.name}'>"


@dataclass
class CheckerContext:
    """
    Shared context passed to every checker during execution.

    Holds the cppcheck configuration, pre-computed analyses,
    suppression manager, and inter-checker communication.

    Attributes
    ----------
    cfg          : cppcheckdata.Configuration
    suppressions : SuppressionManager
    analyses     : dict of pre-computed analysis results (keyed by name)
    options      : user-provided options dict
    stats        : mutable dict for timing / counting statistics
    """
    cfg: Any  # cppcheckdata.Configuration
    suppressions: SuppressionManager = field(default_factory=SuppressionManager)
    analyses: Dict[str, Any] = field(default_factory=dict)
    options: Dict[str, Any] = field(default_factory=dict)
    stats: Dict[str, Any] = field(default_factory=dict)

    def get_analysis(self, name: str) -> Any:
        """Retrieve a pre-computed analysis result by name."""
        return self.analyses.get(name)

    def set_analysis(self, name: str, result: Any) -> None:
        """Store an analysis result for sharing between checkers."""
        self.analyses[name] = result

    def get_option(self, key: str, default: Any = None) -> Any:
        return self.options.get(key, default)


# ═════════════════════════════════════════════════════════════════════════
#  PART 4 — CHECKER REGISTRY
# ═════════════════════════════════════════════════════════════════════════

class CheckerRegistry:
    """
    Registry of available checkers with discovery and filtering.

    Usage
    -----
    >>> registry = CheckerRegistry()
    >>> registry.register(NullDerefChecker)
    >>> registry.register(BufferOverflowChecker)
    >>> checkers = registry.get_enabled()
    >>> checkers = registry.filter_by_error_id("nullDeref")
    """

    def __init__(self) -> None:
        self._checkers: Dict[str, Type[Checker]] = {}
        self._disabled: Set[str] = set()

    def register(self, checker_cls: Type[Checker]) -> None:
        """Register a checker class."""
        self._checkers[checker_cls.name] = checker_cls

    def unregister(self, name: str) -> None:
        """Remove a checker by name."""
        self._checkers.pop(name, None)

    def disable(self, name: str) -> None:
        """Disable a registered checker."""
        self._disabled.add(name)

    def enable(self, name: str) -> None:
        """Re-enable a disabled checker."""
        self._disabled.discard(name)

    def get_all(self) -> List[Type[Checker]]:
        """Return all registered checker classes."""
        return list(self._checkers.values())

    def get_enabled(self) -> List[Type[Checker]]:
        """Return only enabled checker classes."""
        return [
            cls for name, cls in self._checkers.items()
            if name not in self._disabled
        ]

    def get_by_name(self, name: str) -> Optional[Type[Checker]]:
        return self._checkers.get(name)

    def filter_by_error_id(self, error_id: str) -> List[Type[Checker]]:
        """Return checkers that can produce the given error_id."""
        return [
            cls for cls in self._checkers.values()
            if error_id in cls.error_ids
        ]

    def filter_by_severity(
        self, severity: DiagnosticSeverity
    ) -> List[Type[Checker]]:
        """Return checkers with the given default severity."""
        return [
            cls for cls in self._checkers.values()
            if cls.default_severity == severity
        ]

    @property
    def names(self) -> List[str]:
        return sorted(self._checkers.keys())


# ═════════════════════════════════════════════════════════════════════════
#  PART 5 — UTILITY HELPERS FOR TOKEN TRAVERSAL
# ═════════════════════════════════════════════════════════════════════════

def _tok_str(tok: Any) -> str:
    return getattr(tok, "str", "") or ""


def _tok_file(tok: Any) -> str:
    return getattr(tok, "file", "") or ""


def _tok_line(tok: Any) -> int:
    return getattr(tok, "linenr", 0) or 0


def _tok_col(tok: Any) -> int:
    return getattr(tok, "column", 0) or 0


def _tok_loc(tok: Any) -> SourceLocation:
    return SourceLocation(
        file=_tok_file(tok), line=_tok_line(tok), column=_tok_col(tok)
    )


def _iter_tokens(cfg: Any) -> Iterator[Any]:
    """Iterate all tokens in a configuration."""
    for tok in getattr(cfg, "tokenlist", []):
        yield tok


def _iter_variables(cfg: Any) -> Iterator[Any]:
    """Iterate all variables in a configuration."""
    for var in getattr(cfg, "variables", []):
        yield var


def _iter_functions(cfg: Any) -> Iterator[Any]:
    """Iterate all functions in a configuration."""
    for func in getattr(cfg, "functions", []):
        yield func


def _iter_scopes(cfg: Any) -> Iterator[Any]:
    """Iterate all scopes in a configuration."""
    for scope in getattr(cfg, "scopes", []):
        yield scope


def _is_deref(tok: Any) -> bool:
    """Check if token is a pointer dereference site."""
    s = _tok_str(tok)
    parent = getattr(tok, "astParent", None)
    # Unary * operator
    if parent and _tok_str(parent) == "*":
        op1 = getattr(parent, "astOperand1", None)
        op2 = getattr(parent, "astOperand2", None)
        if op1 is tok and op2 is None:
            return True
    # Array subscript: a[i] dereferences a
    if parent and _tok_str(parent) == "[":
        op1 = getattr(parent, "astOperand1", None)
        if op1 is tok:
            return True
    # Arrow operator: p->member
    if parent and getattr(parent, "originalName", "") == "->":
        op1 = getattr(parent, "astOperand1", None)
        if op1 is tok:
            return True
    return False


def _get_valueflow_values(tok: Any) -> list:
    """Get ValueFlow values for a token."""
    return list(getattr(tok, "values", None) or [])


def _has_known_int_value(tok: Any, value: int) -> bool:
    """Check if token has a known integer value via ValueFlow."""
    for v in _get_valueflow_values(tok):
        if getattr(v, "valueKind", "") == "known":
            int_val = getattr(v, "intvalue", None)
            if int_val is not None and int(int_val) == value:
                return True
    return False


def _has_possible_int_value(tok: Any, value: int) -> bool:
    """Check if token has a possible integer value via ValueFlow."""
    for v in _get_valueflow_values(tok):
        int_val = getattr(v, "intvalue", None)
        if int_val is not None and int(int_val) == value:
            return True
    return False


def _valueflow_int_range(tok: Any) -> Optional[Tuple[int, int]]:
    """Extract integer range [lo, hi] from ValueFlow values."""
    vals = _get_valueflow_values(tok)
    if not vals:
        return None
    ints = []
    for v in vals:
        iv = getattr(v, "intvalue", None)
        if iv is not None:
            ints.append(int(iv))
    if ints:
        return (min(ints), max(ints))
    return None


def _var_name(var: Any) -> str:
    """Get variable name from a Variable object."""
    nt = getattr(var, "nameToken", None)
    if nt:
        return getattr(nt, "str", "?")
    return getattr(var, "name", "?")


def _function_name(func: Any) -> str:
    """Get function name."""
    td = getattr(func, "tokenDef", None)
    if td:
        return getattr(td, "str", "?")
    return getattr(func, "name", "?")


def _is_in_loop(tok: Any) -> bool:
    """Check if token is inside a loop scope."""
    scope = getattr(tok, "scope", None)
    while scope:
        st = getattr(scope, "type", "")
        if st in {"While", "For", "Do"}:
            return True
        scope = getattr(scope, "nestedIn", None)
    return False


# ═════════════════════════════════════════════════════════════════════════
#  PART 6 — PRODUCTION CHECKERS
# ═════════════════════════════════════════════════════════════════════════
#
#  Each checker follows the Checker lifecycle and produces
#  CWE-tagged diagnostics.
# ═════════════════════════════════════════════════════════════════════════

# ─────────────────────────────────────────────────────────────────────────
#  6.1  Null Pointer Dereference Checker (CWE-476)
# ─────────────────────────────────────────────────────────────────────────

class NullDerefChecker(Checker):
    """
    Detects null pointer dereferences.

    Combines:
      - cppcheck ValueFlow (known/possible null values)
      - NullPointerAnalysis (forward dataflow)
      - Pattern matching (deref after null-check branches)

    CWE-476: NULL Pointer Dereference
    """

    name: ClassVar[str] = "null-deref"
    description: ClassVar[str] = "Null pointer dereference detection"
    error_ids: ClassVar[FrozenSet[str]] = frozenset({
        "nullDeref", "nullDerefPossible", "nullDerefRedundantCheck",
    })
    default_severity: ClassVar[DiagnosticSeverity] = DiagnosticSeverity.ERROR
    cwe_ids: ClassVar[Dict[str, int]] = {
        "nullDeref": 476,
        "nullDerefPossible": 476,
        "nullDerefRedundantCheck": 476,
    }

    def __init__(self) -> None:
        super().__init__()
        self._null_sites: List[Tuple[Any, int, str]] = []  # (token, varId, reason)

    def collect_evidence(self, ctx: CheckerContext) -> None:
        cfg = ctx.cfg

        # ── Strategy 1: ValueFlow known/possible null at deref sites ─
        for tok in _iter_tokens(cfg):
            vid = getattr(tok, "varId", None)
            if not vid or vid == 0:
                continue
            if not _is_deref(tok):
                continue

            # Check ValueFlow for null values
            for v in _get_valueflow_values(tok):
                int_val = getattr(v, "intvalue", None)
                is_null = (int_val is not None and int(int_val) == 0)
                if not is_null:
                    continue
                vk = getattr(v, "valueKind", "possible")
                is_known = (vk == "known")
                is_inconclusive = getattr(v, "isInconclusive", False)

                condition = getattr(v, "condition", None)
                cond_line = getattr(condition, "linenr", 0) if condition else 0
                reason = "known null" if is_known else "possibly null"
                if cond_line:
                    reason += f" (condition at line {cond_line})"

                self._null_sites.append((tok, vid, reason))

        # ── Strategy 2: NullPointerAnalysis (if available) ───────────
        if NullPointerAnalysis is not None:
            try:
                npa = NullPointerAnalysis(cfg)
                npa.run()
                ctx.set_analysis("null_pointer", npa)
                # Extract warnings from the analysis
                for warning in getattr(npa, "null_deref_warnings", lambda: [])():
                    w_tok = getattr(warning, "token", None)
                    w_vid = getattr(warning, "var_id", 0)
                    if w_tok:
                        self._null_sites.append(
                            (w_tok, w_vid, "dataflow-determined null")
                        )
            except Exception:
                pass  # Graceful degradation

    def diagnose(self, ctx: CheckerContext) -> None:
        # Deduplicate by (file, line, varId)
        seen: Set[Tuple[str, int, int]] = set()
        for tok, vid, reason in self._null_sites:
            file = _tok_file(tok)
            line = _tok_line(tok)
            key = (file, line, vid)
            if key in seen:
                continue
            seen.add(key)

            var_name = _tok_str(tok)
            is_known = "known null" in reason

            if is_known:
                self._emit(
                    error_id="nullDeref",
                    message=f"Null pointer dereference: '{var_name}' is {reason}",
                    file=file, line=line, column=_tok_col(tok),
                    severity=DiagnosticSeverity.ERROR,
                    confidence=Confidence.HIGH,
                    evidence={"varId": vid, "reason": reason},
                )
            else:
                self._emit(
                    error_id="nullDerefPossible",
                    message=f"Possible null pointer dereference: '{var_name}' is {reason}",
                    file=file, line=line, column=_tok_col(tok),
                    severity=DiagnosticSeverity.WARNING,
                    confidence=Confidence.MEDIUM,
                    evidence={"varId": vid, "reason": reason},
                )


# ─────────────────────────────────────────────────────────────────────────
#  6.2  Buffer Overflow Checker (CWE-120 / CWE-787)
# ─────────────────────────────────────────────────────────────────────────

class BufferOverflowChecker(Checker):
    """
    Detects out-of-bounds array/buffer accesses.

    Combines:
      - IntervalAnalysis for index range estimation
      - ValueFlow for known array sizes and index values
      - Variable dimension information from cppcheck

    CWE-120: Buffer Copy without Checking Size of Input
    CWE-787: Out-of-bounds Write
    """

    name: ClassVar[str] = "buffer-overflow"
    description: ClassVar[str] = "Buffer overflow and out-of-bounds access detection"
    error_ids: ClassVar[FrozenSet[str]] = frozenset({
        "bufferOverflow", "bufferUnderflow", "bufferOverflowPossible",
    })
    default_severity: ClassVar[DiagnosticSeverity] = DiagnosticSeverity.ERROR
    cwe_ids: ClassVar[Dict[str, int]] = {
        "bufferOverflow": 787,
        "bufferUnderflow": 787,
        "bufferOverflowPossible": 120,
    }

    def __init__(self) -> None:
        super().__init__()
        self._array_sizes: Dict[int, int] = {}  # varId → known size
        self._violations: List[Tuple[Any, int, str, str]] = []  # (tok, varId, eid, msg)

    def collect_evidence(self, ctx: CheckerContext) -> None:
        cfg = ctx.cfg

        # ── Collect array sizes from variable declarations ───────────
        for var in _iter_variables(cfg):
            vid = getattr(var, "Id", None)
            if vid is None:
                continue
            vid = int(vid)
            dims = getattr(var, "dimensions", None)
            if dims:
                for dim in dims:
                    sz = getattr(dim, "size", None)
                    if sz and int(sz) > 0:
                        self._array_sizes[vid] = int(sz)
                        break

        # ── Scan subscript operations ────────────────────────────────
        for tok in _iter_tokens(cfg):
            if _tok_str(tok) != "[":
                continue
            op1 = getattr(tok, "astOperand1", None)
            op2 = getattr(tok, "astOperand2", None)
            if op1 is None or op2 is None:
                continue

            # Get array variable
            arr_vid = getattr(op1, "varId", None)
            if not arr_vid or arr_vid == 0:
                continue
            arr_size = self._array_sizes.get(arr_vid)
            if arr_size is None:
                # Try ValueFlow on the array variable
                arr_var = getattr(op1, "variable", None)
                if arr_var:
                    arr_dims = getattr(arr_var, "dimensions", None)
                    if arr_dims:
                        for dim in arr_dims:
                            sz = getattr(dim, "size", None)
                            if sz and int(sz) > 0:
                                arr_size = int(sz)
                                break
            if arr_size is None:
                continue

            # Check index via ValueFlow
            for v in _get_valueflow_values(op2):
                iv = getattr(v, "intvalue", None)
                if iv is None:
                    continue
                idx = int(iv)
                vk = getattr(v, "valueKind", "possible")

                if idx < 0:
                    eid = "bufferUnderflow"
                    confidence = Confidence.HIGH if vk == "known" else Confidence.MEDIUM
                    self._violations.append((
                        tok, arr_vid, eid,
                        f"Array index {idx} is negative "
                        f"(array '{_tok_str(op1)}' size={arr_size})"
                    ))
                elif idx >= arr_size:
                    if vk == "known":
                        eid = "bufferOverflow"
                    else:
                        eid = "bufferOverflowPossible"
                    self._violations.append((
                        tok, arr_vid, eid,
                        f"Array index {idx} out of bounds "
                        f"(array '{_tok_str(op1)}' size={arr_size})"
                    ))

    def diagnose(self, ctx: CheckerContext) -> None:
        seen: Set[Tuple[str, int, int]] = set()
        for tok, vid, eid, msg in self._violations:
            file = _tok_file(tok)
            line = _tok_line(tok)
            key = (file, line, vid)
            if key in seen:
                continue
            seen.add(key)

            is_definite = eid in {"bufferOverflow", "bufferUnderflow"}
            self._emit(
                error_id=eid,
                message=msg,
                file=file, line=line, column=_tok_col(tok),
                severity=DiagnosticSeverity.ERROR if is_definite else DiagnosticSeverity.WARNING,
                confidence=Confidence.HIGH if is_definite else Confidence.MEDIUM,
                evidence={"varId": vid, "arraySize": self._array_sizes.get(vid, -1)},
            )


# ─────────────────────────────────────────────────────────────────────────
#  6.3  Use-After-Free Checker (CWE-416)
# ─────────────────────────────────────────────────────────────────────────

class UseAfterFreeChecker(Checker):
    """
    Detects use of memory after it has been freed.

    Tracks free/delete/realloc calls and subsequent dereferences
    of the freed pointer.

    CWE-416: Use After Free
    """

    name: ClassVar[str] = "use-after-free"
    description: ClassVar[str] = "Use-after-free detection"
    error_ids: ClassVar[FrozenSet[str]] = frozenset({
        "useAfterFree", "doubleFree",
    })
    default_severity: ClassVar[DiagnosticSeverity] = DiagnosticSeverity.ERROR
    cwe_ids: ClassVar[Dict[str, int]] = {
        "useAfterFree": 416,
        "doubleFree": 415,
    }

    _FREE_FUNCS: ClassVar[FrozenSet[str]] = frozenset({
        "free", "g_free", "delete", "delete[]",
        "kfree", "vfree", "kmem_cache_free",
    })

    def __init__(self) -> None:
        super().__init__()
        self._free_sites: Dict[int, List[Any]] = defaultdict(list)  # varId → [free tokens]
        self._use_after_free: List[Tuple[Any, Any, int]] = []  # (use_tok, free_tok, varId)

    def collect_evidence(self, ctx: CheckerContext) -> None:
        cfg = ctx.cfg

        # ── Pass 1: Identify free() sites ────────────────────────────
        for tok in _iter_tokens(cfg):
            s = _tok_str(tok)
            func = getattr(tok, "function", None)

            # Direct call: free(ptr)
            if s in self._FREE_FUNCS or (func and _function_name(func) in self._FREE_FUNCS):
                next_tok = getattr(tok, "next", None)
                if next_tok and _tok_str(next_tok) == "(":
                    link = getattr(next_tok, "link", None)
                    # Simple case: free(single_var)
                    arg_tok = getattr(next_tok, "astOperand2", None)
                    if arg_tok is None:
                        # Try looking at token after '('
                        arg_tok = getattr(next_tok, "next", None)
                    if arg_tok:
                        vid = getattr(arg_tok, "varId", None)
                        if vid and vid != 0:
                            self._free_sites[vid].append(tok)

            # delete expression
            if s == "delete":
                op1 = getattr(tok, "astOperand1", None)
                if op1:
                    vid = getattr(op1, "varId", None)
                    if vid and vid != 0:
                        self._free_sites[vid].append(tok)

        # ── Pass 2: Find uses after free ─────────────────────────────
        for vid, free_tokens in self._free_sites.items():
            for free_tok in free_tokens:
                free_line = _tok_line(free_tok)
                free_file = _tok_file(free_tok)

                # Scan forward from free site for uses of same varId
                # within the same scope
                free_scope = getattr(free_tok, "scope", None)
                found_reassign = False

                tok = getattr(free_tok, "next", None)
                while tok:
                    # Stop at scope boundary
                    if getattr(tok, "scope", None) is not free_scope:
                        # May have left scope; be conservative
                        if _tok_str(tok) == "}":
                            break

                    t_vid = getattr(tok, "varId", None)
                    if t_vid == vid:
                        # Check if this is a reassignment (ptr = ...)
                        parent = getattr(tok, "astParent", None)
                        if parent and getattr(parent, "isAssignmentOp", False):
                            op1 = getattr(parent, "astOperand1", None)
                            if op1 is tok:
                                # ptr = ...; reassignment kills the free
                                found_reassign = True
                                break

                        # Check if this is another free (double free)
                        if self._is_free_call_arg(tok):
                            self._use_after_free.append((tok, free_tok, vid))
                            continue

                        # Any other use is potential use-after-free
                        if _is_deref(tok) or self._is_passed_to_function(tok):
                            self._use_after_free.append((tok, free_tok, vid))

                    tok = getattr(tok, "next", None)

    def _is_free_call_arg(self, tok: Any) -> bool:
        """Check if token is an argument to a free-like function."""
        parent = getattr(tok, "astParent", None)
        if parent and _tok_str(parent) == "(":
            func_tok = getattr(parent, "astOperand1", None)
            if func_tok and _tok_str(func_tok) in self._FREE_FUNCS:
                return True
        return False

    def _is_passed_to_function(self, tok: Any) -> bool:
        """Check if token is passed as a function argument."""
        parent = getattr(tok, "astParent", None)
        while parent:
            if _tok_str(parent) == "(":
                return True
            if _tok_str(parent) == ",":
                parent = getattr(parent, "astParent", None)
                continue
            break
        return False

    def diagnose(self, ctx: CheckerContext) -> None:
        seen: Set[Tuple[str, int, int]] = set()
        for use_tok, free_tok, vid in self._use_after_free:
            file = _tok_file(use_tok)
            line = _tok_line(use_tok)
            key = (file, line, vid)
            if key in seen:
                continue
            seen.add(key)

            var_name = _tok_str(use_tok)
            free_line = _tok_line(free_tok)

            if self._is_free_call_arg(use_tok):
                self._emit(
                    error_id="doubleFree",
                    message=f"Double free of '{var_name}' (freed at line {free_line})",
                    file=file, line=line, column=_tok_col(use_tok),
                    confidence=Confidence.HIGH,
                    secondary=(_tok_loc(free_tok),),
                    evidence={"varId": vid, "freeLocation": free_line},
                )
            else:
                self._emit(
                    error_id="useAfterFree",
                    message=f"Use of '{var_name}' after free (freed at line {free_line})",
                    file=file, line=line, column=_tok_col(use_tok),
                    confidence=Confidence.HIGH,
                    secondary=(_tok_loc(free_tok),),
                    evidence={"varId": vid, "freeLocation": free_line},
                )


# ─────────────────────────────────────────────────────────────────────────
#  6.4  Uninitialized Variable Checker (CWE-457)
# ─────────────────────────────────────────────────────────────────────────

class UninitVarChecker(Checker):
    """
    Detects reads of uninitialized variables.

    Uses DefiniteAssignment analysis (forward, must) to determine
    if a variable is definitely assigned before each use.

    CWE-457: Use of Uninitialized Variable
    """

    name: ClassVar[str] = "uninit-var"
    description: ClassVar[str] = "Uninitialized variable read detection"
    error_ids: ClassVar[FrozenSet[str]] = frozenset({
        "uninitVar", "uninitVarPossible",
    })
    default_severity: ClassVar[DiagnosticSeverity] = DiagnosticSeverity.ERROR
    cwe_ids: ClassVar[Dict[str, int]] = {
        "uninitVar": 457,
        "uninitVarPossible": 457,
    }

    def __init__(self) -> None:
        super().__init__()
        self._violations: List[Tuple[Any, int, str]] = []

    def collect_evidence(self, ctx: CheckerContext) -> None:
        cfg = ctx.cfg

        # Collect non-initialized local variables
        uninit_vars: Set[int] = set()
        for var in _iter_variables(cfg):
            vid = getattr(var, "Id", None)
            if vid is None:
                continue
            vid = int(vid)
            is_local = getattr(var, "isLocal", False)
            is_arg = getattr(var, "isArgument", False)
            is_static = getattr(var, "isStatic", False)
            is_extern = getattr(var, "isExtern", False)
            is_init = getattr(var, "isInit", False)

            if is_local and not is_arg and not is_static and not is_extern and not is_init:
                uninit_vars.add(vid)

        if not uninit_vars:
            return

        # Scan forward: for each uninit var, check first use vs. first assignment
        for var in _iter_variables(cfg):
            vid = getattr(var, "Id", None)
            if vid is None or int(vid) not in uninit_vars:
                continue
            vid = int(vid)

            name_tok = getattr(var, "nameToken", None)
            if name_tok is None:
                continue

            # Walk from declaration to find first use before first assignment
            assigned = False
            tok = getattr(name_tok, "next", None)
            while tok:
                t_vid = getattr(tok, "varId", None)
                if t_vid == vid:
                    parent = getattr(tok, "astParent", None)
                    # Is this an assignment to the variable?
                    if parent and getattr(parent, "isAssignmentOp", False):
                        op1 = getattr(parent, "astOperand1", None)
                        if op1 is tok and _tok_str(parent) == "=":
                            assigned = True
                            break

                    # Is this an address-of (initialization through pointer)?
                    if parent and _tok_str(parent) == "&":
                        op2 = getattr(parent, "astOperand2", None)
                        if op2 is None:  # unary &
                            assigned = True
                            break

                    # This is a read before assignment
                    if not assigned:
                        self._violations.append((
                            tok, vid,
                            f"Variable '{_tok_str(tok)}' is used uninitialized"
                        ))
                        break

                tok = getattr(tok, "next", None)

    def diagnose(self, ctx: CheckerContext) -> None:
        seen: Set[Tuple[str, int, int]] = set()
        for tok, vid, msg in self._violations:
            file = _tok_file(tok)
            line = _tok_line(tok)
            key = (file, line, vid)
            if key in seen:
                continue
            seen.add(key)

            self._emit(
                error_id="uninitVar",
                message=msg,
                file=file, line=line, column=_tok_col(tok),
                confidence=Confidence.MEDIUM,
                evidence={"varId": vid},
            )


# ─────────────────────────────────────────────────────────────────────────
#  6.5  Dead Store Checker (CWE-563)
# ─────────────────────────────────────────────────────────────────────────

class DeadStoreChecker(Checker):
    """
    Detects assignments whose value is never subsequently read.

    Uses LiveVariables (backward, may) analysis: if a variable
    is not live after an assignment, the store is dead.

    CWE-563: Assignment to Variable without Use
    """

    name: ClassVar[str] = "dead-store"
    description: ClassVar[str] = "Dead store (useless assignment) detection"
    error_ids: ClassVar[FrozenSet[str]] = frozenset({
        "deadStore", "deadStoreInit",
    })
    default_severity: ClassVar[DiagnosticSeverity] = DiagnosticSeverity.STYLE
    cwe_ids: ClassVar[Dict[str, int]] = {
        "deadStore": 563,
        "deadStoreInit": 563,
    }

    def __init__(self) -> None:
        super().__init__()
        self._dead_stores: List[Tuple[Any, int, bool]] = []  # (tok, varId, is_init)

    def collect_evidence(self, ctx: CheckerContext) -> None:
        cfg = ctx.cfg

        # Build set of all assignment sites
        assignments: List[Tuple[Any, int]] = []  # (assign_tok, varId)
        for tok in _iter_tokens(cfg):
            if not getattr(tok, "isAssignmentOp", False):
                continue
            op1 = getattr(tok, "astOperand1", None)
            if op1 is None:
                continue
            vid = getattr(op1, "varId", None)
            if not vid or vid == 0:
                continue

            # Skip volatile variables
            var = getattr(op1, "variable", None)
            if var and getattr(var, "isVolatile", False):
                continue
            # Skip globals (may have side effects)
            if var and not getattr(var, "isLocal", False):
                continue
            # Skip arguments (caller may expect side effects on pointers)
            if var and getattr(var, "isArgument", False):
                continue

            assignments.append((tok, vid))

        # For each assignment, check if the variable is read before
        # next assignment or scope exit
        for assign_tok, vid in assignments:
            is_read = False
            is_reassigned = False

            tok = getattr(assign_tok, "next", None)
            assign_scope = getattr(assign_tok, "scope", None)
            depth = 0

            while tok:
                s = _tok_str(tok)

                # Track scope
                if s == "{":
                    depth += 1
                elif s == "}":
                    if depth == 0:
                        break  # Left assignment's scope
                    depth -= 1

                t_vid = getattr(tok, "varId", None)
                if t_vid == vid:
                    parent = getattr(tok, "astParent", None)
                    # Is this a reassignment?
                    if parent and getattr(parent, "isAssignmentOp", False):
                        op1 = getattr(parent, "astOperand1", None)
                        if op1 is tok and _tok_str(parent) == "=":
                            is_reassigned = True
                            break

                    # Otherwise it's a read
                    is_read = True
                    break

                tok = getattr(tok, "next", None)

            if not is_read:
                is_init = _tok_str(assign_tok) == "=" and self._is_declaration_init(assign_tok)
                self._dead_stores.append((assign_tok, vid, is_init))

    def _is_declaration_init(self, assign_tok: Any) -> bool:
        """Check if this assignment is part of a variable declaration."""
        op1 = getattr(assign_tok, "astOperand1", None)
        if op1:
            var = getattr(op1, "variable", None)
            if var:
                name_tok = getattr(var, "nameToken", None)
                if name_tok:
                    # If the name token is very close to the assignment,
                    # it's likely a declaration-init: int x = 5;
                    name_line = getattr(name_tok, "linenr", 0)
                    assign_line = getattr(assign_tok, "linenr", 0)
                    return name_line == assign_line
        return False

    def diagnose(self, ctx: CheckerContext) -> None:
        seen: Set[Tuple[str, int, int]] = set()
        for tok, vid, is_init in self._dead_stores:
            file = _tok_file(tok)
            line = _tok_line(tok)
            key = (file, line, vid)
            if key in seen:
                continue
            seen.add(key)

            op1 = getattr(tok, "astOperand1", None)
            var_name = _tok_str(op1) if op1 else "?"

            eid = "deadStoreInit" if is_init else "deadStore"
            msg = (
                f"Variable '{var_name}' is assigned a value that is never used"
                if not is_init else
                f"Variable '{var_name}' is initialized but never used"
            )

            self._emit(
                error_id=eid,
                message=msg,
                file=file, line=line, column=_tok_col(tok),
                severity=DiagnosticSeverity.STYLE,
                confidence=Confidence.MEDIUM,
                evidence={"varId": vid, "isInit": is_init},
            )


# ─────────────────────────────────────────────────────────────────────────
#  6.6  Division by Zero Checker (CWE-369)
# ─────────────────────────────────────────────────────────────────────────

class DivByZeroChecker(Checker):
    """
    Detects division by zero or modulo by zero.

    Uses ValueFlow and SignAnalysis to determine if a divisor
    can be zero.

    CWE-369: Divide By Zero
    """

    name: ClassVar[str] = "div-by-zero"
    description: ClassVar[str] = "Division/modulo by zero detection"
    error_ids: ClassVar[FrozenSet[str]] = frozenset({
        "divByZero", "divByZeroPossible",
    })
    default_severity: ClassVar[DiagnosticSeverity] = DiagnosticSeverity.ERROR
    cwe_ids: ClassVar[Dict[str, int]] = {
        "divByZero": 369,
        "divByZeroPossible": 369,
    }

    def __init__(self) -> None:
        super().__init__()
        self._violations: List[Tuple[Any, str, Confidence]] = []

    def collect_evidence(self, ctx: CheckerContext) -> None:
        cfg = ctx.cfg

        for tok in _iter_tokens(cfg):
            s = _tok_str(tok)
            if s not in {"/", "%", "/=", "%="}:
                continue

            # Get the divisor (right operand)
            op2 = getattr(tok, "astOperand2", None)
            if op2 is None:
                continue

            # Check ValueFlow for zero value
            for v in _get_valueflow_values(op2):
                iv = getattr(v, "intvalue", None)
                if iv is not None and int(iv) == 0:
                    vk = getattr(v, "valueKind", "possible")
                    if vk == "known":
                        self._violations.append((
                            tok, f"Division by zero: divisor is known to be zero",
                            Confidence.HIGH,
                        ))
                    else:
                        self._violations.append((
                            tok, f"Possible division by zero",
                            Confidence.MEDIUM,
                        ))

                # Float: check for 0.0
                fv = getattr(v, "floatvalue", None)
                if fv is not None:
                    try:
                        if float(fv) == 0.0:
                            self._violations.append((
                                tok,
                                f"Division by zero (float divisor is 0.0)",
                                Confidence.MEDIUM,
                            ))
                    except (ValueError, TypeError):
                        pass

    def diagnose(self, ctx: CheckerContext) -> None:
        seen: Set[Tuple[str, int]] = set()
        for tok, msg, confidence in self._violations:
            file = _tok_file(tok)
            line = _tok_line(tok)
            key = (file, line)
            if key in seen:
                continue
            seen.add(key)

            is_definite = confidence == Confidence.HIGH
            self._emit(
                error_id="divByZero" if is_definite else "divByZeroPossible",
                message=msg,
                file=file, line=line, column=_tok_col(tok),
                severity=DiagnosticSeverity.ERROR if is_definite else DiagnosticSeverity.WARNING,
                confidence=confidence,
            )


# ─────────────────────────────────────────────────────────────────────────
#  6.7  Taint / Injection Checker (CWE-89 / CWE-78 / CWE-79)
# ─────────────────────────────────────────────────────────────────────────

class TaintInjectionChecker(Checker):
    """
    Detects flows of untrusted input to security-sensitive sinks.

    Tracks taint from sources (scanf, getenv, recv, argv, etc.)
    through the program to sinks (system, exec, SQL, format strings).

    CWE-89:  SQL Injection
    CWE-78:  OS Command Injection
    CWE-79:  Cross-site Scripting (XSS)
    CWE-134: Use of Externally-Controlled Format String
    """

    name: ClassVar[str] = "taint-injection"
    description: ClassVar[str] = "Taint-based injection vulnerability detection"
    error_ids: ClassVar[FrozenSet[str]] = frozenset({
        "taintedExec", "taintedFormat", "taintedSql", "taintedData",
    })
    default_severity: ClassVar[DiagnosticSeverity] = DiagnosticSeverity.WARNING
    cwe_ids: ClassVar[Dict[str, int]] = {
        "taintedExec": 78,
        "taintedFormat": 134,
        "taintedSql": 89,
        "taintedData": 20,
    }

    _SOURCES: ClassVar[FrozenSet[str]] = frozenset({
        "scanf", "fscanf", "sscanf", "gets", "fgets", "fread",
        "recv", "recvfrom", "recvmsg", "read",
        "getenv", "getchar", "fgetc", "getline",
    })

    _EXEC_SINKS: ClassVar[FrozenSet[str]] = frozenset({
        "system", "popen", "exec", "execl", "execlp", "execle",
        "execv", "execvp", "execvpe", "ShellExecute",
    })

    _FORMAT_SINKS: ClassVar[FrozenSet[str]] = frozenset({
        "printf", "fprintf", "sprintf", "snprintf",
        "syslog", "dprintf",
    })

    def __init__(self) -> None:
        super().__init__()
        self._tainted_vars: Dict[int, Any] = {}  # varId → source token
        self._violations: List[Tuple[Any, Any, int, str, str]] = []

    def collect_evidence(self, ctx: CheckerContext) -> None:
        cfg = ctx.cfg

        # ── Pass 1: Identify taint sources ───────────────────────────
        for tok in _iter_tokens(cfg):
            s = _tok_str(tok)
            func = getattr(tok, "function", None)
            func_name = _function_name(func) if func else s

            if func_name not in self._SOURCES:
                continue

            # Find variables receiving tainted data
            # Pattern: scanf("%d", &var) → var is tainted
            # Pattern: var = getenv("X") → var is tainted
            parent = getattr(tok, "astParent", None)

            # Call site: look at arguments and assignment targets
            if parent and _tok_str(parent) == "(":
                # Assignment: result = source(...)
                gp = getattr(parent, "astParent", None)
                if gp and getattr(gp, "isAssignmentOp", False):
                    lhs = getattr(gp, "astOperand1", None)
                    if lhs:
                        vid = getattr(lhs, "varId", None)
                        if vid and vid != 0:
                            self._tainted_vars[vid] = tok

                # scanf-style: arguments are tainted
                if func_name in {"scanf", "fscanf", "sscanf"}:
                    self._mark_scanf_args_tainted(parent, tok)

                # read/recv: buffer argument is tainted
                if func_name in {"fgets", "fread", "recv", "recvfrom", "read", "gets"}:
                    self._mark_first_arg_tainted(parent, tok)

        # Also mark argv as tainted (argc/argv in main)
        for func in _iter_functions(cfg):
            fname = _function_name(func)
            if fname == "main":
                arg_dict = getattr(func, "argument", {})
                if isinstance(arg_dict, dict) and 2 in arg_dict:
                    argv = arg_dict[2]
                    argv_vid = getattr(argv, "Id", None) or getattr(argv, "varId", None)
                    if argv_vid:
                        self._tainted_vars[int(argv_vid)] = None

        # ── Pass 2: Propagate taint through assignments ──────────────
        changed = True
        max_iters = 10
        iteration = 0
        while changed and iteration < max_iters:
            changed = False
            iteration += 1
            for tok in _iter_tokens(cfg):
                if not getattr(tok, "isAssignmentOp", False):
                    continue
                if _tok_str(tok) != "=":
                    continue
                lhs = getattr(tok, "astOperand1", None)
                rhs = getattr(tok, "astOperand2", None)
                if lhs is None or rhs is None:
                    continue
                lhs_vid = getattr(lhs, "varId", None)
                rhs_vid = getattr(rhs, "varId", None)
                if rhs_vid and rhs_vid in self._tainted_vars:
                    if lhs_vid and lhs_vid not in self._tainted_vars:
                        self._tainted_vars[lhs_vid] = tok
                        changed = True

        # ── Pass 3: Check sinks ──────────────────────────────────────
        for tok in _iter_tokens(cfg):
            s = _tok_str(tok)
            func = getattr(tok, "function", None)
            func_name = _function_name(func) if func else s

            if func_name in self._EXEC_SINKS:
                self._check_sink_args(tok, "taintedExec",
                                      f"Tainted data passed to '{func_name}'")
            elif func_name in self._FORMAT_SINKS:
                self._check_format_sink(tok, func_name)

    def _mark_scanf_args_tainted(self, call_tok: Any, source: Any) -> None:
        """Mark scanf destination arguments as tainted."""
        # scanf args after format string are pointers to tainted destinations
        op2 = getattr(call_tok, "astOperand2", None)
        if op2:
            self._collect_arg_vars(op2, source, skip_first=True)

    def _mark_first_arg_tainted(self, call_tok: Any, source: Any) -> None:
        """Mark the first argument (buffer) as tainted."""
        op2 = getattr(call_tok, "astOperand2", None)
        if op2:
            # Navigate comma tree to find first arg
            arg = op2
            while _tok_str(arg) == ",":
                arg = getattr(arg, "astOperand1", None)
                if arg is None:
                    return
            vid = getattr(arg, "varId", None)
            if vid and vid != 0:
                self._tainted_vars[vid] = source

    def _collect_arg_vars(
        self, tok: Any, source: Any, skip_first: bool = False
    ) -> None:
        """Collect variable ids from function arguments."""
        args: List[Any] = []
        self._flatten_comma(tok, args)
        for i, arg in enumerate(args):
            if skip_first and i == 0:
                continue
            # For &var, extract var
            if _tok_str(arg) == "&":
                inner = getattr(arg, "astOperand1", None)
                if inner:
                    arg = inner
            vid = getattr(arg, "varId", None)
            if vid and vid != 0:
                self._tainted_vars[vid] = source

    def _flatten_comma(self, tok: Any, out: List[Any]) -> None:
        """Flatten a comma-separated argument list."""
        if tok is None:
            return
        if _tok_str(tok) == ",":
            self._flatten_comma(getattr(tok, "astOperand1", None), out)
            self._flatten_comma(getattr(tok, "astOperand2", None), out)
        else:
            out.append(tok)

    def _check_sink_args(
        self, tok: Any, error_id: str, base_msg: str
    ) -> None:
        """Check if any argument to a sink is tainted."""
        parent = getattr(tok, "astParent", None)
        if parent and _tok_str(parent) == "(":
            args: List[Any] = []
            op2 = getattr(parent, "astOperand2", None)
            if op2:
                self._flatten_comma(op2, args)
            for arg in args:
                vid = getattr(arg, "varId", None)
                if vid and vid in self._tainted_vars:
                    source = self._tainted_vars[vid]
                    self._violations.append((
                        tok, source, vid, error_id, base_msg
                    ))

    def _check_format_sink(self, tok: Any, func_name: str) -> None:
        """Check format string functions for tainted format argument."""
        parent = getattr(tok, "astParent", None)
        if parent and _tok_str(parent) == "(":
            args: List[Any] = []
            op2 = getattr(parent, "astOperand2", None)
            if op2:
                self._flatten_comma(op2, args)
            # Format string is typically the first arg (printf)
            # or second arg (fprintf, sprintf, snprintf)
            fmt_idx = 0
            if func_name in {"fprintf", "dprintf"}:
                fmt_idx = 1
            elif func_name in {"sprintf", "snprintf"}:
                fmt_idx = 1 if func_name == "sprintf" else 2

            if fmt_idx < len(args):
                fmt_arg = args[fmt_idx]
                vid = getattr(fmt_arg, "varId", None)
                if vid and vid in self._tainted_vars:
                    self._violations.append((
                        tok, self._tainted_vars[vid], vid,
                        "taintedFormat",
                        f"Tainted format string in '{func_name}'"
                    ))

    def diagnose(self, ctx: CheckerContext) -> None:
        seen: Set[Tuple[str, int, str]] = set()
        for tok, source, vid, eid, msg in self._violations:
            file = _tok_file(tok)
            line = _tok_line(tok)
            key = (file, line, eid)
            if key in seen:
                continue
            seen.add(key)

            secondary = ()
            if source is not None:
                secondary = (_tok_loc(source),)

            self._emit(
                error_id=eid,
                message=msg,
                file=file, line=line, column=_tok_col(tok),
                severity=DiagnosticSeverity.WARNING,
                confidence=Confidence.MEDIUM,
                secondary=secondary,
                evidence={"varId": vid},
            )


# ─────────────────────────────────────────────────────────────────────────
#  6.8  Integer Overflow Checker (CWE-190)
# ─────────────────────────────────────────────────────────────────────────

class IntOverflowChecker(Checker):
    """
    Detects potential integer overflow/underflow.

    Examines arithmetic operations on integer types where ValueFlow
    indicates values near type boundaries.

    CWE-190: Integer Overflow or Wraparound
    CWE-191: Integer Underflow
    """

    name: ClassVar[str] = "int-overflow"
    description: ClassVar[str] = "Integer overflow/underflow detection"
    error_ids: ClassVar[FrozenSet[str]] = frozenset({
        "intOverflow", "intUnderflow", "intOverflowPossible",
    })
    default_severity: ClassVar[DiagnosticSeverity] = DiagnosticSeverity.WARNING
    cwe_ids: ClassVar[Dict[str, int]] = {
        "intOverflow": 190,
        "intUnderflow": 191,
        "intOverflowPossible": 190,
    }

    # Common type bounds
    _TYPE_BOUNDS: ClassVar[Dict[str, Tuple[int, int]]] = {
        "char": (-128, 127),
        "unsigned char": (0, 255),
        "short": (-32768, 32767),
        "unsigned short": (0, 65535),
        "int": (-2147483648, 2147483647),
        "unsigned int": (0, 4294967295),
        "long": (-2147483648, 2147483647),  # platform-dependent
        "unsigned long": (0, 4294967295),
        "long long": (-9223372036854775808, 9223372036854775807),
        "unsigned long long": (0, 18446744073709551615),
    }

    def __init__(self) -> None:
        super().__init__()
        self._violations: List[Tuple[Any, str, Confidence]] = []

    def collect_evidence(self, ctx: CheckerContext) -> None:
        cfg = ctx.cfg

        for tok in _iter_tokens(cfg):
            if not getattr(tok, "isArithmeticalOp", False):
                continue
            s = _tok_str(tok)
            if s not in {"+", "-", "*"}:
                continue

            # Check result ValueType for integer
            vt = getattr(tok, "valueType", None)
            if vt is None:
                continue
            vt_type = getattr(vt, "type", "")
            vt_sign = getattr(vt, "sign", "signed")

            type_key = f"{'unsigned ' if vt_sign == 'unsigned' else ''}{vt_type}"
            bounds = self._TYPE_BOUNDS.get(type_key)
            if bounds is None:
                continue
            lo, hi = bounds

            # Check result values from ValueFlow
            for v in _get_valueflow_values(tok):
                iv = getattr(v, "intvalue", None)
                if iv is None:
                    continue
                val = int(iv)
                vk = getattr(v, "valueKind", "possible")

                if val > hi:
                    conf = Confidence.HIGH if vk == "known" else Confidence.MEDIUM
                    eid = "intOverflow" if conf == Confidence.HIGH else "intOverflowPossible"
                    self._violations.append((
                        tok,
                        f"Integer overflow: result {val} exceeds {type_key} max ({hi})",
                        conf,
                    ))
                elif val < lo:
                    conf = Confidence.HIGH if vk == "known" else Confidence.MEDIUM
                    self._violations.append((
                        tok,
                        f"Integer underflow: result {val} below {type_key} min ({lo})",
                        conf,
                    ))

    def diagnose(self, ctx: CheckerContext) -> None:
        seen: Set[Tuple[str, int]] = set()
        for tok, msg, confidence in self._violations:
            file = _tok_file(tok)
            line = _tok_line(tok)
            key = (file, line)
            if key in seen:
                continue
            seen.add(key)

            is_under = "underflow" in msg.lower()
            is_definite = confidence == Confidence.HIGH
            eid = "intUnderflow" if is_under else ("intOverflow" if is_definite else "intOverflowPossible")

            self._emit(
                error_id=eid,
                message=msg,
                file=file, line=line, column=_tok_col(tok),
                confidence=confidence,
            )


# ─────────────────────────────────────────────────────────────────────────
#  6.9  Resource Leak Checker (CWE-401 / CWE-772)
# ─────────────────────────────────────────────────────────────────────────

class ResourceLeakChecker(Checker):
    """
    Detects leaked resources (memory, file handles, etc.)
    that are allocated but never freed/closed.

    CWE-401: Missing Release of Memory after Effective Lifetime
    CWE-772: Missing Release of Resource after Effective Lifetime
    """

    name: ClassVar[str] = "resource-leak"
    description: ClassVar[str] = "Resource leak detection (memory, files, etc.)"
    error_ids: ClassVar[FrozenSet[str]] = frozenset({
        "memoryLeak", "resourceLeak", "fdLeak",
    })
    default_severity: ClassVar[DiagnosticSeverity] = DiagnosticSeverity.WARNING
    cwe_ids: ClassVar[Dict[str, int]] = {
        "memoryLeak": 401,
        "resourceLeak": 772,
        "fdLeak": 772,
    }

    _ALLOC_FUNCS: ClassVar[Dict[str, str]] = {
        "malloc": "memoryLeak",
        "calloc": "memoryLeak",
        "realloc": "memoryLeak",
        "strdup": "memoryLeak",
        "strndup": "memoryLeak",
        "fopen": "resourceLeak",
        "fdopen": "resourceLeak",
        "tmpfile": "resourceLeak",
        "popen": "resourceLeak",
        "open": "fdLeak",
        "socket": "fdLeak",
        "accept": "fdLeak",
    }

    _FREE_FUNCS: ClassVar[Dict[str, Set[str]]] = {
        "memoryLeak": {"free", "realloc", "g_free", "kfree"},
        "resourceLeak": {"fclose", "pclose"},
        "fdLeak": {"close"},
    }

    def __init__(self) -> None:
        super().__init__()
        # varId → (alloc_token, error_id)
        self._allocations: Dict[int, Tuple[Any, str]] = {}
        self._freed: Set[int] = set()
        self._returned: Set[int] = set()
        self._escaped: Set[int] = set()  # stored to global/struct/passed out

    def collect_evidence(self, ctx: CheckerContext) -> None:
        cfg = ctx.cfg

        # ── Pass 1: Find allocations ─────────────────────────────────
        for tok in _iter_tokens(cfg):
            s = _tok_str(tok)
            func = getattr(tok, "function", None)
            func_name = _function_name(func) if func else s

            if func_name not in self._ALLOC_FUNCS:
                continue

            eid = self._ALLOC_FUNCS[func_name]

            # Find the variable receiving the allocation
            parent = getattr(tok, "astParent", None)
            # Navigate up through '(' to assignment
            if parent and _tok_str(parent) == "(":
                parent = getattr(parent, "astParent", None)

            if parent and getattr(parent, "isAssignmentOp", False):
                lhs = getattr(parent, "astOperand1", None)
                if lhs:
                    vid = getattr(lhs, "varId", None)
                    if vid and vid != 0:
                        self._allocations[vid] = (tok, eid)

        # ── Pass 2: Find frees / closes ──────────────────────────────
        all_free_names: Set[str] = set()
        for names in self._FREE_FUNCS.values():
            all_free_names |= names

        for tok in _iter_tokens(cfg):
            s = _tok_str(tok)
            func = getattr(tok, "function", None)
            func_name = _function_name(func) if func else s

            if func_name in all_free_names:
                # Find the freed variable
                parent = getattr(tok, "astParent", None)
                if parent and _tok_str(parent) == "(":
                    args: List[Any] = []
                    op2 = getattr(parent, "astOperand2", None)
                    if op2:
                        self._flatten_args(op2, args)
                    for arg in args:
                        vid = getattr(arg, "varId", None)
                        if vid and vid in self._allocations:
                            self._freed.add(vid)

        # ── Pass 3: Find returns and escapes ─────────────────────────
        for tok in _iter_tokens(cfg):
            s = _tok_str(tok)

            # Return statement: returned resources are not leaked
            if s == "return":
                op1 = getattr(tok, "astOperand1", None)
                if op1:
                    vid = getattr(op1, "varId", None)
                    if vid and vid in self._allocations:
                        self._returned.add(vid)

            # Assignment to struct field, global, or pointer:
            # resource may have escaped
            if getattr(tok, "isAssignmentOp", False):
                op2 = getattr(tok, "astOperand2", None)
                op1 = getattr(tok, "astOperand1", None)
                if op2:
                    vid = getattr(op2, "varId", None)
                    if vid and vid in self._allocations:
                        # Check if LHS is a field access or deref
                        if op1:
                            lhs_parent = getattr(op1, "astParent", None)
                            op1_str = _tok_str(op1)
                            # Storing through pointer or to struct field
                            if (getattr(op1, "astParent", None) and
                                _tok_str(getattr(op1, "astParent", None)) in {".", "->", "*"}):
                                self._escaped.add(vid)
                            # Storing to a non-local variable
                            op1_var = getattr(op1, "variable", None)
                            if op1_var and not getattr(op1_var, "isLocal", False):
                                self._escaped.add(vid)

    def _flatten_args(self, tok: Any, out: List[Any]) -> None:
        if tok is None:
            return
        if _tok_str(tok) == ",":
            self._flatten_args(getattr(tok, "astOperand1", None), out)
            self._flatten_args(getattr(tok, "astOperand2", None), out)
        else:
            out.append(tok)

    def diagnose(self, ctx: CheckerContext) -> None:
        for vid, (alloc_tok, eid) in self._allocations.items():
            if vid in self._freed:
                continue
            if vid in self._returned:
                continue
            if vid in self._escaped:
                continue

            file = _tok_file(alloc_tok)
            line = _tok_line(alloc_tok)

            # Find the variable name
            var_name = "?"
            for var in _iter_variables(ctx.cfg):
                var_id = getattr(var, "Id", None)
                if var_id is not None and int(var_id) == vid:
                    var_name = _var_name(var)
                    break

            resource_type = {
                "memoryLeak": "memory",
                "resourceLeak": "file handle",
                "fdLeak": "file descriptor",
            }.get(eid, "resource")

            self._emit(
                error_id=eid,
                message=f"Leaked {resource_type} allocated for '{var_name}' at line {line}",
                file=file, line=line, column=_tok_col(alloc_tok),
                confidence=Confidence.MEDIUM,
                evidence={"varId": vid, "resourceType": resource_type},
            )


# ─────────────────────────────────────────────────────────────────────────
#  6.10  Unreachable Code Checker (CWE-561)
# ─────────────────────────────────────────────────────────────────────────

class UnreachableCodeChecker(Checker):
    """
    Detects code that can never be executed.

    Patterns:
      - Code after unconditional return/break/continue/goto
      - Dead branches (if(0), while(0))
      - Constant condition evaluation

    CWE-561: Dead Code
    """

    name: ClassVar[str] = "unreachable-code"
    description: ClassVar[str] = "Unreachable / dead code detection"
    error_ids: ClassVar[FrozenSet[str]] = frozenset({
        "unreachableCode", "deadBranch",
    })
    default_severity: ClassVar[DiagnosticSeverity] = DiagnosticSeverity.STYLE
    cwe_ids: ClassVar[Dict[str, int]] = {
        "unreachableCode": 561,
        "deadBranch": 561,
    }

    _TERMINATORS: ClassVar[FrozenSet[str]] = frozenset({
        "return", "break", "continue", "goto",
    })

    def __init__(self) -> None:
        super().__init__()
        self._unreachable: List[Tuple[Any, str]] = []

    def collect_evidence(self, ctx: CheckerContext) -> None:
        cfg = ctx.cfg

        # ── Pattern 1: Code after unconditional terminators ──────────
        for tok in _iter_tokens(cfg):
            s = _tok_str(tok)
            if s not in self._TERMINATORS:
                continue

            # Find the semicolon that ends this statement
            scan = tok
            while scan:
                if _tok_str(scan) == ";":
                    break
                scan = getattr(scan, "next", None)
            if scan is None:
                continue

            # The token after the semicolon (if any) is unreachable
            # — unless it's a closing brace, label, or case
            next_tok = getattr(scan, "next", None)
            if next_tok is None:
                continue
            ns = _tok_str(next_tok)
            if ns in {"}", "case", "default"}:
                continue
            # Check for labels (identifier followed by ':')
            next_next = getattr(next_tok, "next", None)
            if next_next and _tok_str(next_next) == ":":
                continue

            # Confirm same scope
            if getattr(next_tok, "scope", None) is getattr(tok, "scope", None):
                self._unreachable.append((
                    next_tok,
                    f"Code after '{s}' statement is unreachable"
                ))

        # ── Pattern 2: Dead branches from constant conditions ────────
        for tok in _iter_tokens(cfg):
            s = _tok_str(tok)
            if s not in {"if", "while"}:
                continue

            op1 = getattr(tok, "astOperand1", None)
            if op1 is None:
                continue

            # Check if condition is a known constant
            if _has_known_int_value(op1, 0):
                if s == "if":
                    self._unreachable.append((
                        tok,
                        "Condition is always false: 'if' body never executes"
                    ))
                elif s == "while":
                    self._unreachable.append((
                        tok,
                        "Condition is always false: 'while' body never executes"
                    ))

    def diagnose(self, ctx: CheckerContext) -> None:
        seen: Set[Tuple[str, int]] = set()
        for tok, msg in self._unreachable:
            file = _tok_file(tok)
            line = _tok_line(tok)
            key = (file, line)
            if key in seen:
                continue
            seen.add(key)

            is_branch = "branch" in msg.lower() or "Condition" in msg
            self._emit(
                error_id="deadBranch" if is_branch else "unreachableCode",
                message=msg,
                file=file, line=line, column=_tok_col(tok),
                severity=DiagnosticSeverity.STYLE,
                confidence=Confidence.HIGH if "always" in msg else Confidence.MEDIUM,
            )


# ─────────────────────────────────────────────────────────────────────────
#  6.11  Implicit Conversion Loss Checker (CWE-197)
# ─────────────────────────────────────────────────────────────────────────

class ImplicitConversionChecker(Checker):
    """
    Detects implicit conversions that may lose data.

    Examples:
      - Assigning long long to int
      - Assigning double to float
      - Assigning signed to unsigned (with possible negative values)

    CWE-197: Numeric Truncation Error
    """

    name: ClassVar[str] = "implicit-conversion"
    description: ClassVar[str] = "Implicit narrowing conversion detection"
    error_ids: ClassVar[FrozenSet[str]] = frozenset({
        "implicitConversionLoss", "signConversion",
    })
    default_severity: ClassVar[DiagnosticSeverity] = DiagnosticSeverity.PORTABILITY
    cwe_ids: ClassVar[Dict[str, int]] = {
        "implicitConversionLoss": 197,
        "signConversion": 195,
    }

    _TYPE_SIZES: ClassVar[Dict[str, int]] = {
        "bool": 1, "char": 8, "short": 16, "int": 32,
        "long": 64, "long long": 64,
        "float": 32, "double": 64, "long double": 80,
    }

    def __init__(self) -> None:
        super().__init__()
        self._conversions: List[Tuple[Any, str]] = []

    def collect_evidence(self, ctx: CheckerContext) -> None:
        cfg = ctx.cfg

        for tok in _iter_tokens(cfg):
            if not getattr(tok, "isAssignmentOp", False):
                continue
            if _tok_str(tok) != "=":
                continue

            op1 = getattr(tok, "astOperand1", None)
            op2 = getattr(tok, "astOperand2", None)
            if op1 is None or op2 is None:
                continue

            # Skip explicit casts
            if getattr(op2, "isCast", False):
                continue

            lhs_vt = getattr(op1, "valueType", None)
            rhs_vt = getattr(op2, "valueType", None)
            if lhs_vt is None or rhs_vt is None:
                continue

            lhs_type = getattr(lhs_vt, "type", "")
            rhs_type = getattr(rhs_vt, "type", "")
            lhs_sign = getattr(lhs_vt, "sign", "")
            rhs_sign = getattr(rhs_vt, "sign", "")
            lhs_ptr = getattr(lhs_vt, "pointer", 0) or 0
            rhs_ptr = getattr(rhs_vt, "pointer", 0) or 0

            # Skip pointer assignments
            if lhs_ptr or rhs_ptr:
                continue

            lhs_size = self._TYPE_SIZES.get(lhs_type, 0)
            rhs_size = self._TYPE_SIZES.get(rhs_type, 0)

            if not lhs_size or not rhs_size:
                continue

            # Narrowing: larger type → smaller type
            if rhs_size > lhs_size:
                # Float → int is always lossy
                if rhs_type in {"float", "double", "long double"} and lhs_type not in {"float", "double", "long double"}:
                    self._conversions.append((
                        tok,
                        f"Implicit conversion from '{rhs_type}' to '{lhs_type}' "
                        f"may lose fractional part"
                    ))
                elif lhs_type not in {"float", "double", "long double"}:
                    self._conversions.append((
                        tok,
                        f"Implicit narrowing conversion from '{rhs_type}' ({rhs_size}-bit) "
                        f"to '{lhs_type}' ({lhs_size}-bit)"
                    ))

            # Sign conversion: signed → unsigned when value may be negative
            if lhs_sign == "unsigned" and rhs_sign == "signed":
                # Check if RHS can be negative via ValueFlow
                can_be_negative = False
                for v in _get_valueflow_values(op2):
                    iv = getattr(v, "intvalue", None)
                    if iv is not None and int(iv) < 0:
                        can_be_negative = True
                        break

                if can_be_negative:
                    self._conversions.append((
                        tok,
                        f"Signed-to-unsigned conversion: '{rhs_type}' to "
                        f"'{lhs_type}' with possible negative value"
                    ))

    def diagnose(self, ctx: CheckerContext) -> None:
        seen: Set[Tuple[str, int]] = set()
        for tok, msg in self._conversions:
            file = _tok_file(tok)
            line = _tok_line(tok)
            key = (file, line)
            if key in seen:
                continue
            seen.add(key)

            is_sign = "Sign" in msg or "sign" in msg
            self._emit(
                error_id="signConversion" if is_sign else "implicitConversionLoss",
                message=msg,
                file=file, line=line, column=_tok_col(tok),
                confidence=Confidence.MEDIUM,
            )


# ─────────────────────────────────────────────────────────────────────────
#  6.12  Infinite Loop Checker (CWE-835)
# ─────────────────────────────────────────────────────────────────────────

class InfiniteLoopChecker(Checker):
    """
    Detects loops that may never terminate.

    Patterns:
      - while(1) / for(;;) without break/return/goto
      - Loop condition variable not modified in body

    CWE-835: Loop with Unreachable Exit Condition
    """

    name: ClassVar[str] = "infinite-loop"
    description: ClassVar[str] = "Potentially infinite loop detection"
    error_ids: ClassVar[FrozenSet[str]] = frozenset({
        "infiniteLoop", "infiniteLoopPossible",
    })
    default_severity: ClassVar[DiagnosticSeverity] = DiagnosticSeverity.WARNING
    cwe_ids: ClassVar[Dict[str, int]] = {
        "infiniteLoop": 835,
        "infiniteLoopPossible": 835,
    }

    def __init__(self) -> None:
        super().__init__()
        self._infinite_loops: List[Tuple[Any, str, Confidence]] = []

    def collect_evidence(self, ctx: CheckerContext) -> None:
        cfg = ctx.cfg

        for scope in _iter_scopes(cfg):
            scope_type = getattr(scope, "type", "")
            if scope_type not in {"While", "For", "Do"}:
                continue

            class_start = getattr(scope, "bodyStart", None)
            class_end = getattr(scope, "bodyEnd", None)
            if class_start is None or class_end is None:
                continue

            # Get loop condition token
            cond_tok = None
            if scope_type in {"While", "Do"}:
                # The scope's classStart parent or nearby token
                # We look for the condition expression
                scope_start = getattr(scope, "bodyStart", None)
                if scope_start:
                    # Walk backward from bodyStart to find 'while'/'do' keyword
                    t = getattr(scope_start, "previous", None)
                    while t:
                        s = _tok_str(t)
                        if s in {"while", "do"}:
                            cond_tok = getattr(t, "astOperand1", None)
                            break
                        if s == ")":
                            break
                        t = getattr(t, "previous", None)
            elif scope_type == "For":
                # For scope: condition is astOperand2 of 'for' token
                t = getattr(scope, "bodyStart", None)
                if t:
                    t = getattr(t, "previous", None)
                    while t:
                        if _tok_str(t) == "for":
                            # for(init; cond; step) — AST structure varies
                            cond_tok = getattr(t, "astOperand2", None)
                            break
                        t = getattr(t, "previous", None)

            # ── Check for always-true conditions ─────────────────────
            if cond_tok:
                if _has_known_int_value(cond_tok, 1):
                    # while(1) / while(true) — check for break/return
                    has_exit = self._body_has_exit(class_start, class_end)
                    if not has_exit:
                        self._infinite_loops.append((
                            class_start,
                            "Loop condition is always true with no reachable exit",
                            Confidence.HIGH,
                        ))

                # Check if condition variables are modified in body
                cond_vars = self._collect_vars_in_expr(cond_tok)
                if cond_vars and not _has_known_int_value(cond_tok, 1):
                    modified = False
                    tok = getattr(class_start, "next", None)
                    while tok and tok is not class_end:
                        t_vid = getattr(tok, "varId", None)
                        if t_vid and t_vid in cond_vars:
                            parent = getattr(tok, "astParent", None)
                            if parent:
                                if getattr(parent, "isAssignmentOp", False):
                                    op1 = getattr(parent, "astOperand1", None)
                                    if op1 is tok:
                                        modified = True
                                        break
                                if _tok_str(parent) in {"++", "--"}:
                                    modified = True
                                    break
                        tok = getattr(tok, "next", None)

                    if not modified:
                        self._infinite_loops.append((
                            class_start,
                            "Loop condition variable(s) not modified in loop body",
                            Confidence.MEDIUM,
                        ))
            else:
                # for(;;) with no explicit condition — always true
                if scope_type == "For":
                    has_exit = self._body_has_exit(class_start, class_end)
                    if not has_exit:
                        self._infinite_loops.append((
                            class_start,
                            "for(;;) loop with no reachable exit",
                            Confidence.HIGH,
                        ))

    def _body_has_exit(self, start: Any, end: Any) -> bool:
        """Check if the loop body contains break/return/goto."""
        tok = getattr(start, "next", None)
        depth = 0
        while tok and tok is not end:
            s = _tok_str(tok)
            if s == "{":
                depth += 1
            elif s == "}":
                depth -= 1
            # Only count exits at the loop's own level or direct children
            if s in {"break", "return", "goto"} and depth <= 1:
                return True
            # Function calls that don't return (exit, abort, _exit)
            if s in {"exit", "abort", "_exit", "_Exit", "quick_exit"}:
                return True
            tok = getattr(tok, "next", None)
        return False

    def _collect_vars_in_expr(self, tok: Any) -> Set[int]:
        """Collect all variable IDs referenced in an expression tree."""
        result: Set[int] = set()
        if tok is None:
            return result
        vid = getattr(tok, "varId", None)
        if vid and vid != 0:
            result.add(vid)
        result |= self._collect_vars_in_expr(getattr(tok, "astOperand1", None))
        result |= self._collect_vars_in_expr(getattr(tok, "astOperand2", None))
        return result

    def diagnose(self, ctx: CheckerContext) -> None:
        seen: Set[Tuple[str, int]] = set()
        for tok, msg, confidence in self._infinite_loops:
            file = _tok_file(tok)
            line = _tok_line(tok)
            key = (file, line)
            if key in seen:
                continue
            seen.add(key)

            is_definite = confidence == Confidence.HIGH
            self._emit(
                error_id="infiniteLoop" if is_definite else "infiniteLoopPossible",
                message=msg,
                file=file, line=line, column=_tok_col(tok),
                confidence=confidence,
            )


# ═════════════════════════════════════════════════════════════════════════
#  PART 7 — CHECKER RUNNER
# ═════════════════════════════════════════════════════════════════════════

# Default registry with all built-in checkers
_DEFAULT_REGISTRY = CheckerRegistry()
_DEFAULT_REGISTRY.register(NullDerefChecker)
_DEFAULT_REGISTRY.register(BufferOverflowChecker)
_DEFAULT_REGISTRY.register(UseAfterFreeChecker)
_DEFAULT_REGISTRY.register(UninitVarChecker)
_DEFAULT_REGISTRY.register(DeadStoreChecker)
_DEFAULT_REGISTRY.register(DivByZeroChecker)
_DEFAULT_REGISTRY.register(TaintInjectionChecker)
_DEFAULT_REGISTRY.register(IntOverflowChecker)
_DEFAULT_REGISTRY.register(ResourceLeakChecker)
_DEFAULT_REGISTRY.register(UnreachableCodeChecker)
_DEFAULT_REGISTRY.register(ImplicitConversionChecker)
_DEFAULT_REGISTRY.register(InfiniteLoopChecker)


@dataclass
class CheckerRunResults:
    """
    Aggregate results from running a suite of checkers.

    Attributes
    ----------
    diagnostics         : All diagnostics from all checkers
    diagnostics_by_checker : Diagnostics grouped by checker name
    stats               : Timing and counting statistics
    checker_names       : Names of checkers that were run
    """
    diagnostics: List[Diagnostic] = field(default_factory=list)
    diagnostics_by_checker: Dict[str, List[Diagnostic]] = field(
        default_factory=lambda: defaultdict(list)
    )
    stats: Dict[str, Any] = field(default_factory=dict)
    checker_names: List[str] = field(default_factory=list)

    @property
    def error_count(self) -> int:
        return sum(
            1 for d in self.diagnostics
            if d.severity == DiagnosticSeverity.ERROR
        )

    @property
    def warning_count(self) -> int:
        return sum(
            1 for d in self.diagnostics
            if d.severity == DiagnosticSeverity.WARNING
        )

    @property
    def total_count(self) -> int:
        return len(self.diagnostics)

    def by_severity(self, severity: DiagnosticSeverity) -> List[Diagnostic]:
        return [d for d in self.diagnostics if d.severity == severity]

    def by_file(self, file: str) -> List[Diagnostic]:
        return [d for d in self.diagnostics if d.location.file == file]

    def by_cwe(self, cwe: int) -> List[Diagnostic]:
        return [d for d in self.diagnostics if d.cwe == cwe]

    def to_json_lines(self) -> str:
        """Format all diagnostics as cppcheck JSON addon output."""
        return "\n".join(d.to_json_str() for d in self.diagnostics)

    def to_gcc_format(self) -> str:
        """Format all diagnostics in GCC-style."""
        return "\n".join(d.to_gcc_format() for d in self.diagnostics)

    def summary(self) -> str:
        """Human-readable summary."""
        lines = [
            f"Checker run complete: {self.total_count} diagnostics "
            f"({self.error_count} errors, {self.warning_count} warnings)",
        ]
        for name in self.checker_names:
            count = len(self.diagnostics_by_checker.get(name, []))
            elapsed = self.stats.get(f"{name}_elapsed_ms", 0)
            lines.append(f"  {name}: {count} findings ({elapsed:.1f}ms)")
        return "\n".join(lines)


class CheckerRunner:
    """
    Runs a suite of checkers against a cppcheck Configuration.

    Usage
    -----
    >>> runner = CheckerRunner()
    >>> # Use all built-in checkers:
    >>> results = runner.run(cfg)
    >>> print(results.summary())

    >>> # Or select specific checkers:
    >>> results = runner.run(cfg, checkers=["null-deref", "buffer-overflow"])

    >>> # Output for cppcheck addon protocol:
    >>> for line in results.to_json_lines().splitlines():
    ...     sys.stdout.write(line + '\\n')

    Parameters for constructor
    ─────────────────────────
    registry    : CheckerRegistry — source of checker classes
    suppressions: SuppressionManager — pre-loaded suppression rules
    options     : dict — per-checker configuration
    """

    def __init__(
        self,
        registry: Optional[CheckerRegistry] = None,
        suppressions: Optional[SuppressionManager] = None,
        options: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.registry = registry or _DEFAULT_REGISTRY
        self.suppressions = suppressions or SuppressionManager()
        self.options = options or {}

    def run(
        self,
        cfg: Any,
        checkers: Optional[Sequence[str]] = None,
    ) -> CheckerRunResults:
        """
        Run checkers against a single Configuration.

        Parameters
        ----------
        cfg      : cppcheckdata.Configuration
        checkers : list of checker names to run (None = all enabled)

        Returns
        -------
        CheckerRunResults
        """
        results = CheckerRunResults()

        # Load inline suppressions
        self.suppressions.load_inline_suppressions(cfg)

        # Build context
        ctx = CheckerContext(
            cfg=cfg,
            suppressions=self.suppressions,
            options=self.options,
        )

        # Determine which checkers to run
        if checkers is not None:
            checker_classes: List[Type[Checker]] = []
            for name in checkers:
                cls = self.registry.get_by_name(name)
                if cls is not None:
                    checker_classes.append(cls)
        else:
            checker_classes = self.registry.get_enabled()

        # Run each checker through its lifecycle
        for cls in checker_classes:
            checker = cls()
            checker_name = cls.name
            results.checker_names.append(checker_name)

            t0 = time.monotonic()
            try:
                checker.configure(ctx)
                checker.collect_evidence(ctx)
                checker.diagnose(ctx)
                diags = checker.report(ctx)
            except Exception as exc:
                # Graceful degradation: report the failure, don't crash
                diags = [Diagnostic(
                    error_id="checkerInternalError",
                    message=f"Checker '{checker_name}' failed: {exc}",
                    severity=DiagnosticSeverity.INFORMATION,
                    location=SourceLocation(),
                    checker_name=checker_name,
                )]
            elapsed_ms = (time.monotonic() - t0) * 1000.0

            results.diagnostics.extend(diags)
            results.diagnostics_by_checker[checker_name] = diags
            results.stats[f"{checker_name}_elapsed_ms"] = elapsed_ms

        return results

    def run_all_configurations(
        self,
        data: Any,
        checkers: Optional[Sequence[str]] = None,
    ) -> CheckerRunResults:
        """
        Run checkers across all configurations in a CppcheckData dump.

        Parameters
        ----------
        data     : cppcheckdata.CppcheckData (result of parsedump())
        checkers : list of checker names (None = all enabled)
        """
        combined = CheckerRunResults()
        for cfg in getattr(data, "configurations", []):
            partial = self.run(cfg, checkers=checkers)
            combined.diagnostics.extend(partial.diagnostics)
            for name, diags in partial.diagnostics_by_checker.items():
                combined.diagnostics_by_checker[name].extend(diags)
            for key, val in partial.stats.items():
                # Accumulate times
                if key in combined.stats:
                    combined.stats[key] += val
                else:
                    combined.stats[key] = val
            for name in partial.checker_names:
                if name not in combined.checker_names:
                    combined.checker_names.append(name)
        return combined


# ═════════════════════════════════════════════════════════════════════════
#  PART 8 — CONVENIENCE ENTRY POINT FOR CPPCHECK ADDONS
# ═════════════════════════════════════════════════════════════════════════

def run_addon(
    dump_file: str,
    checkers: Optional[Sequence[str]] = None,
    output: str = "json",
    suppress: Optional[Sequence[str]] = None,
) -> int:
    """
    Run the checker suite as a cppcheck addon entry point.

    Parameters
    ----------
    dump_file : Path to the .dump file from ``cppcheck --dump``
    checkers  : Checker names to run (None = all)
    output    : "json" for cppcheck protocol, "gcc" for GCC-style
    suppress  : Error IDs to globally suppress

    Returns
    -------
    Exit code (0 = no errors, 1 = errors found)

    Usage from command line or cppcheck addon config::

        python -m cppcheckdata_shims.checkers my_file.c.dump
    """
    try:
        from cppcheckdata import parsedump  # type: ignore[import-untyped]
    except ImportError:
        sys.stderr.write("ERROR: cppcheckdata module not found\n")
        return 2

    data = parsedump(dump_file)

    sm = SuppressionManager()
    if suppress:
        for eid in suppress:
            sm.add_global_suppression(eid)

    runner = CheckerRunner(suppressions=sm)
    results = runner.run_all_configurations(data, checkers=checkers)

    if output == "json":
        for diag in results.diagnostics:
            sys.stdout.write(diag.to_json_str() + "\n")
    elif output == "gcc":
        for diag in results.diagnostics:
            sys.stdout.write(diag.to_gcc_format() + "\n")
    else:
        sys.stdout.write(results.summary() + "\n")

    return 1 if results.error_count > 0 else 0


# ═════════════════════════════════════════════════════════════════════════
#  PART 9 — MODULE MAIN (addon entry point)
# ═════════════════════════════════════════════════════════════════════════

def _main() -> None:
    """CLI entry point for ``python -m cppcheckdata_shims.checkers``."""
    import argparse

    parser = argparse.ArgumentParser(
        description="cppcheckdata-shims checker suite",
        prog="cppcheckdata_shims.checkers",
    )
    parser.add_argument("dump_file", help="Path to .dump file")
    parser.add_argument(
        "--checkers", nargs="*", default=None,
        help="Checker names to run (default: all)",
    )
    parser.add_argument(
        "--output", choices=["json", "gcc", "summary"],
        default="json", help="Output format",
    )
    parser.add_argument(
        "--suppress", nargs="*", default=None,
        help="Error IDs to suppress",
    )
    parser.add_argument(
        "--list-checkers", action="store_true",
        help="List available checkers and exit",
    )

    args = parser.parse_args()

    if args.list_checkers:
        for name in _DEFAULT_REGISTRY.names:
            cls = _DEFAULT_REGISTRY.get_by_name(name)
            desc = cls.description if cls else ""
            ids = ", ".join(sorted(cls.error_ids)) if cls else ""
            cwes = ", ".join(
                f"CWE-{v}" for v in sorted(set(cls.cwe_ids.values()))
            ) if cls else ""
            print(f"  {name:25s} {desc}")
            print(f"  {'':25s} IDs: {ids}")
            print(f"  {'':25s} CWEs: {cwes}")
            print()
        return

    exit_code = run_addon(
        dump_file=args.dump_file,
        checkers=args.checkers,
        output=args.output,
        suppress=args.suppress,
    )
    sys.exit(exit_code)


if __name__ == "__main__":
    _main()


# ═════════════════════════════════════════════════════════════════════════
#  PART 10 — PUBLIC API
# ═════════════════════════════════════════════════════════════════════════

__all__ = [
    # Diagnostic model
    "Diagnostic",
    "DiagnosticSeverity",
    "Confidence",
    "SourceLocation",
    # Suppression
    "SuppressionManager",
    # Checker framework
    "Checker",
    "CheckerContext",
    "CheckerRegistry",
    # Production checkers
    "NullDerefChecker",
    "BufferOverflowChecker",
    "UseAfterFreeChecker",
    "UninitVarChecker",
    "DeadStoreChecker",
    "DivByZeroChecker",
    "TaintInjectionChecker",
    "IntOverflowChecker",
    "ResourceLeakChecker",
    "UnreachableCodeChecker",
    "ImplicitConversionChecker",
    "InfiniteLoopChecker",
    # Runner
    "CheckerRunner",
    "CheckerRunResults",
    # Entry point
    "run_addon",
]
