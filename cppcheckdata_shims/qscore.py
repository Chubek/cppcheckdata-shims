"""
qscore.py — Quality Score Metric for Cppcheck Code Analysis
================================================================

Computes a comprehensive quality score (0-100) for C code by analyzing:
  - Safety & Reliability (pointer issues, memory errors, undefined behavior)
  - Maintainability (complexity, coupling, naming consistency)
  - Style & Conventions (indentation, brace style, line length)
  - Performance (inefficient patterns, redundant operations)
  - Portability (non-portable constructs, compiler extensions)
  - Documentation (comment coverage, completeness)

Usage::

    import cppcheckdata
    from qscore import QualityScorer

    data = cppcheckdata.parsedump("example.c.dump")
    scorer = QualityScorer()
    result = scorer.score_tu(data.configurations[0])

    print(f"Quality Score: {result.overall_score:.1f}/100")
    for fb in result.feedbacks:
        print(f"  {fb.priority.value}: {fb.message}")

The score is computed at two levels:
  1. Translation Unit Level — single Cppcheck Configuration
  2. Global/Project Level — aggregated across multiple Configurations

Each metric provides specific feedback explaining why points were deducted.
"""

from __future__ import annotations

import enum
import math
import re
import statistics
from abc import ABC, abstractmethod
from collections import defaultdict, Counter
from dataclasses import dataclass, field
from typing import (
    Any,
    Dict,
    Iterable,
    List,
    Optional,
    Set,
    Tuple,
    Union,
)

# ---------------------------------------------------------------------------
# Optional shim imports — degrade gracefully when unavailable
# ---------------------------------------------------------------------------
try:
    from . import memory_abstraction  # type: ignore
    _HAS_MEMORY = True
except Exception:
    _HAS_MEMORY = False

try:
    from . import constraint_engine  # type: ignore
    _HAS_CONSTRAINT = True
except Exception:
    _HAS_CONSTRAINT = False

try:
    from . import symbolic_exec  # type: ignore
    _HAS_SYMEXEC = True
except Exception:
    _HAS_SYMEXEC = False

try:
    from . import controlflow_graph  # type: ignore
    _HAS_CFG = True
except Exception:
    _HAS_CFG = False

try:
    from . import callgraph  # type: ignore
    _HAS_CALLGRAPH = True
except Exception:
    _HAS_CALLGRAPH = False

try:
    from . import dataflow_engine  # type: ignore
    _HAS_DATAFLOW = True
except Exception:
    _HAS_DATAFLOW = False


# ===================================================================
# 1.  Core Enums and Data Structures
# ===================================================================

class QualityDimension(enum.Enum):
    """Categories of code quality being measured."""
    SAFETY = "safety"
    MAINTAINABILITY = "maintainability"
    STYLE = "style"
    PERFORMANCE = "performance"
    PORTABILITY = "portability"
    DOCUMENTATION = "documentation"


class Priority(enum.Enum):
    """Severity of a feedback item."""
    CRITICAL = "critical"
    WARNING = "warning"
    SUGGESTION = "suggestion"
    INFO = "info"


# Canonical ordering so we can sort feedbacks deterministically.
_PRIORITY_ORDER = {
    Priority.CRITICAL: 0,
    Priority.WARNING: 1,
    Priority.SUGGESTION: 2,
    Priority.INFO: 3,
}


@dataclass
class QualityFeedback:
    """One piece of feedback explaining a score deduction or boost."""
    dimension: QualityDimension
    priority: Priority
    message: str
    location: Optional[Tuple[str, int]] = None   # (file, line)
    metric_name: str = ""
    score_impact: float = 0.0                     # negative = penalty

    # Sorting: critical first, then by dimension name, then message
    def _sort_key(self):
        return (
            _PRIORITY_ORDER.get(self.priority, 99),
            self.dimension.value,
            self.location[0] if self.location else "",
            self.location[1] if self.location else 0,
            self.message,
        )

    def __lt__(self, other):
        if not isinstance(other, QualityFeedback):
            return NotImplemented
        return self._sort_key() < other._sort_key()

    def __repr__(self) -> str:
        loc = ""
        if self.location:
            loc = f" @ {self.location[0]}:{self.location[1]}"
        return (
            f"[{self.dimension.value}/{self.priority.value}]"
            f"{loc}: {self.message}"
        )


@dataclass
class DimensionScore:
    """Score breakdown for one quality dimension."""
    dimension: QualityDimension
    raw_score: float          # 0-100
    weighted_score: float     # raw_score * weight
    weight: float
    feedbacks: List[QualityFeedback] = field(default_factory=list)

    @property
    def penalty(self) -> float:
        return sum(
            fb.score_impact for fb in self.feedbacks if fb.score_impact < 0
        )


@dataclass
class ScoringResult:
    """Complete scoring result for a translation unit or project."""
    overall_score: float
    dimension_scores: Dict[QualityDimension, DimensionScore]
    feedbacks: List[QualityFeedback]
    config_name: Optional[str] = None
    file_count: int = 1

    # -- convenience accessors ------------------------------------------------

    @property
    def critical_issues(self) -> List[QualityFeedback]:
        return [f for f in self.feedbacks if f.priority == Priority.CRITICAL]

    @property
    def warnings(self) -> List[QualityFeedback]:
        return [f for f in self.feedbacks if f.priority == Priority.WARNING]

    @property
    def suggestions(self) -> List[QualityFeedback]:
        return [f for f in self.feedbacks if f.priority == Priority.SUGGESTION]

    # -- serialization --------------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        """Dictionary suitable for ``json.dumps``."""
        return {
            "overall_score": round(self.overall_score, 2),
            "dimensions": {
                dim.value: {
                    "score": round(ds.raw_score, 2),
                    "weighted_score": round(ds.weighted_score, 2),
                    "weight": ds.weight,
                    "penalty": round(ds.penalty, 2),
                    "feedback_count": len(ds.feedbacks),
                }
                for dim, ds in self.dimension_scores.items()
            },
            "feedback_count": len(self.feedbacks),
            "critical_count": len(self.critical_issues),
            "warning_count": len(self.warnings),
            "config_name": self.config_name,
            "file_count": self.file_count,
        }

    # -- human-readable report ------------------------------------------------

    def generate_report(self, max_feedbacks: int = 30) -> str:
        """Return a multi-line human-readable quality report."""
        sep = "=" * 72
        lines: List[str] = [
            sep,
            "QUALITY SCORE REPORT",
        ]
        if self.config_name:
            lines.append(f"Configuration : {self.config_name}")
        lines += [
            f"Overall Score : {self.overall_score:.1f} / 100",
            f"Files Analyzed: {self.file_count}",
            sep,
            "",
            "DIMENSION BREAKDOWN:",
        ]
        for dim in QualityDimension:
            ds = self.dimension_scores.get(dim)
            if ds is None:
                continue
            bar_len = int(ds.raw_score / 5)
            bar = "#" * bar_len + "." * (20 - bar_len)
            lines.append(
                f"  {dim.value:17s} [{bar}] "
                f"{ds.raw_score:5.1f}/100  "
                f"(w={ds.weight:.2f}  => {ds.weighted_score:5.1f})"
            )

        n_show = min(max_feedbacks, len(self.feedbacks))
        lines += [
            "",
            f"FEEDBACK ({n_show} of {len(self.feedbacks)} shown):",
        ]
        for fb in self.feedbacks[:n_show]:
            loc = (
                f"{fb.location[0]}:{fb.location[1]}"
                if fb.location
                else "global"
            )
            imp = f" ({fb.score_impact:+.1f})" if fb.score_impact else ""
            lines.append(
                f"  [{fb.priority.value.upper():10s}] "
                f"[{fb.dimension.value:15s}] "
                f"{loc:28s} {fb.message}{imp}"
            )
        if len(self.feedbacks) > n_show:
            lines.append(
                f"  ... and {len(self.feedbacks) - n_show} more items"
            )
        lines.append(sep)
        return "\n".join(lines)


# ===================================================================
# 2.  Abstract Metric Base
# ===================================================================

class QualityMetric(ABC):
    """
    Abstract base for every quality metric.

    Sub-classes must implement ``compute(cfg)`` which returns a raw score
    in [0, 100] together with a list of ``QualityFeedback`` instances.
    """

    def __init__(
        self,
        dimension: QualityDimension,
        weight: float = 1.0,
        priority: Priority = Priority.WARNING,
    ):
        self.dimension = dimension
        self.weight = weight
        self.default_priority = priority
        self.name: str = self.__class__.__name__.replace("Metric", "")
        self.description: str = ""

    # -- helpers for sub-classes ----------------------------------------------

    def fb(
        self,
        message: str,
        *,
        priority: Optional[Priority] = None,
        location: Optional[Tuple[str, int]] = None,
        impact: float = 0.0,
    ) -> QualityFeedback:
        """Shorthand factory for ``QualityFeedback``."""
        return QualityFeedback(
            dimension=self.dimension,
            priority=priority or self.default_priority,
            message=message,
            location=location,
            metric_name=self.name,
            score_impact=impact,
        )

    # -- contract -------------------------------------------------------------

    @abstractmethod
    def compute(self, cfg) -> Tuple[float, List[QualityFeedback]]:
        """
        Analyse *cfg* (a ``cppcheckdata.Configuration``) and return
        ``(score_0_100, [feedback, …])``.
        """
        ...


# ===================================================================
# 3.  Utility Helpers (token/scope walking)
# ===================================================================

def _iter_tokens(cfg) -> Iterable:
    """Yield every token in *cfg*.tokenlist."""
    tok = cfg.tokenlist
    # cfg.tokenlist may be a list or the first Token with .next links
    if isinstance(tok, list):
        yield from tok
    else:
        t = tok
        while t is not None:
            yield t
            t = t.next


def _iter_scopes(cfg) -> Iterable:
    """Yield every Scope object."""
    return cfg.scopes if hasattr(cfg, "scopes") and cfg.scopes else []


def _iter_functions(cfg) -> Iterable:
    """Yield every Function object."""
    return cfg.functions if hasattr(cfg, "functions") and cfg.functions else []


def _iter_variables(cfg) -> Iterable:
    """Yield every Variable object."""
    return cfg.variables if hasattr(cfg, "variables") and cfg.variables else []


def _function_body_tokens(func) -> List:
    """Return all tokens belonging to a function body."""
    tokens: List = []
    if not hasattr(func, "tokenDef") or func.tokenDef is None:
        return tokens
    # Walk forward from the function definition token until we find
    # the opening '{', then collect until the matching '}'.
    tok = func.tokenDef
    # Advance to '{'
    while tok is not None and tok.str != "{":
        tok = tok.next
    if tok is None:
        return tokens
    open_brace = tok
    close_brace = tok.link if tok.link else None
    if close_brace is None:
        return tokens
    tok = open_brace.next
    while tok is not None and tok != close_brace:
        tokens.append(tok)
        tok = tok.next
    return tokens


def _function_name(func) -> str:
    """Best-effort extraction of the function's name."""
    if hasattr(func, "name") and func.name:
        return func.name
    if hasattr(func, "tokenDef") and func.tokenDef:
        return func.tokenDef.str
    return "<unknown>"


def _tok_loc(tok) -> Optional[Tuple[str, int]]:
    """Return (file, linenr) from a token, or None."""
    f = getattr(tok, "file", None)
    ln = getattr(tok, "linenr", None)
    if f and ln:
        return (f, int(ln))
    return None


def _scope_line_count(scope) -> int:
    """Estimate the number of source lines spanned by *scope*."""
    body_start = getattr(scope, "bodyStart", None)
    body_end = getattr(scope, "bodyEnd", None)
    if body_start and body_end:
        s = getattr(body_start, "linenr", 0) or 0
        e = getattr(body_end, "linenr", 0) or 0
        return max(0, int(e) - int(s))
    return 0


def _clamp(val: float, lo: float = 0.0, hi: float = 100.0) -> float:
    return max(lo, min(hi, val))


# ===================================================================
# 4.  SAFETY Metrics
# ===================================================================

class NullDerefMetric(QualityMetric):
    """Detect potential null-pointer dereferences via Cppcheck value flow."""

    def __init__(self):
        super().__init__(QualityDimension.SAFETY, weight=1.0,
                         priority=Priority.CRITICAL)
        self.description = "Null-pointer dereference risk"

    def compute(self, cfg) -> Tuple[float, List[QualityFeedback]]:
        issues: List[QualityFeedback] = []
        deref_count = 0

        for tok in _iter_tokens(cfg):
            # Look for pointer dereferences where the value-flow includes 0
            if not (getattr(tok, "astParent", None) and
                    getattr(tok, "variable", None)):
                continue
            var = tok.variable
            vt = getattr(var, "typeStartToken", None)
            is_ptr = getattr(var, "isPointer", False)
            if not is_ptr:
                continue

            # Check if token is being dereferenced
            parent = tok.astParent
            is_deref = False
            if parent and parent.str == "*" and parent.astOperand1 == tok:
                is_deref = True
            if parent and parent.str == "[" and parent.astOperand1 == tok:
                is_deref = True
            if parent and parent.str == "->" and parent.astOperand1 == tok:
                is_deref = True

            if not is_deref:
                continue

            # Check value flow for possible null
            values = getattr(tok, "values", None) or []
            for v in values:
                int_val = getattr(v, "intvalue", None)
                if int_val is not None and int_val == 0:
                    cond = getattr(v, "condition", None)
                    deref_count += 1
                    var_name = getattr(var, "nameToken", None)
                    vn = var_name.str if var_name else "?"
                    msg = (
                        f"Possible null dereference of `{vn}` "
                        f"(value-flow shows intvalue=0)"
                    )
                    if cond:
                        msg += " [conditional]"
                    issues.append(self.fb(
                        msg,
                        priority=Priority.CRITICAL,
                        location=_tok_loc(tok),
                        impact=-8.0,
                    ))
                    break  # one report per dereference site

        # Score: start at 100, lose 8 per issue, floor at 0
        score = _clamp(100.0 - deref_count * 8.0)
        return score, issues


class UninitializedUseMetric(QualityMetric):
    """Detect use of variables before initialization."""

    def __init__(self):
        super().__init__(QualityDimension.SAFETY, weight=1.0,
                         priority=Priority.CRITICAL)
        self.description = "Use of uninitialized variables"

    def compute(self, cfg) -> Tuple[float, List[QualityFeedback]]:
        issues: List[QualityFeedback] = []
        count = 0

        for tok in _iter_tokens(cfg):
            values = getattr(tok, "values", None) or []
            for v in values:
                if getattr(v, "uninit", False) or getattr(v, "isUninitValue", False):
                    var = getattr(tok, "variable", None)
                    vn = tok.str
                    if var:
                        nt = getattr(var, "nameToken", None)
                        if nt:
                            vn = nt.str
                    count += 1
                    issues.append(self.fb(
                        f"Variable `{vn}` may be used uninitialized",
                        priority=Priority.CRITICAL,
                        location=_tok_loc(tok),
                        impact=-10.0,
                    ))
                    break  # one per token

        score = _clamp(100.0 - count * 10.0)
        return score, issues


class MemoryLeakMetric(QualityMetric):
    """
    Heuristic detection of potential memory leaks.

    Looks for malloc/calloc/realloc calls whose result is stored in a
    local pointer that is never passed to free() within the same scope.
    """

    _ALLOC_FUNCS = {"malloc", "calloc", "realloc", "strdup", "strndup"}
    _FREE_FUNCS = {"free", "realloc"}  # realloc frees old ptr

    def __init__(self):
        super().__init__(QualityDimension.SAFETY, weight=1.0,
                         priority=Priority.CRITICAL)
        self.description = "Potential memory leaks"

    def compute(self, cfg) -> Tuple[float, List[QualityFeedback]]:
        issues: List[QualityFeedback] = []
        # Track: varId -> (alloc_token, freed: bool)
        alloc_vars: Dict[int, Any] = {}
        freed_vars: Set[int] = set()

        for tok in _iter_tokens(cfg):
            # Detect allocation: tok is the function name like 'malloc'
            if (tok.str in self._ALLOC_FUNCS and
                    getattr(tok, "next", None) and
                    tok.next.str == "("):
                # Walk backwards to find assignment target:  ptr = malloc(…)
                parent = getattr(tok, "astParent", None)
                # The AST parent of the call might be '(' ; grandparent '='
                while parent and parent.str == "(":
                    parent = getattr(parent, "astParent", None)
                if parent and parent.str == "=" and parent.astOperand1:
                    lhs = parent.astOperand1
                    vid = getattr(lhs, "varId", None)
                    if vid and vid != 0:
                        alloc_vars[vid] = tok

            # Detect free
            if (tok.str in self._FREE_FUNCS and
                    getattr(tok, "next", None) and
                    tok.next.str == "("):
                # Argument is the token after '('
                arg_tok = tok.next.next if tok.next else None
                # Could also walk astOperand
                if arg_tok:
                    vid = getattr(arg_tok, "varId", None)
                    if vid:
                        freed_vars.add(vid)

        leak_count = 0
        for vid, alloc_tok in alloc_vars.items():
            if vid not in freed_vars:
                leak_count += 1
                issues.append(self.fb(
                    f"Memory allocated via `{alloc_tok.str}()` may not be freed "
                    f"(varId={vid})",
                    priority=Priority.CRITICAL,
                    location=_tok_loc(alloc_tok),
                    impact=-10.0,
                ))

        score = _clamp(100.0 - leak_count * 10.0)
        return score, issues


class BufferOverflowMetric(QualityMetric):
    """
    Heuristic detection of obvious buffer overflows.

    Looks for array subscripts where the index value-flow exceeds declared
    array dimensions.
    """

    def __init__(self):
        super().__init__(QualityDimension.SAFETY, weight=1.0,
                         priority=Priority.CRITICAL)
        self.description = "Potential buffer overflows"

    def compute(self, cfg) -> Tuple[float, List[QualityFeedback]]:
        issues: List[QualityFeedback] = []
        count = 0

        for tok in _iter_tokens(cfg):
            if tok.str != "[":
                continue
            arr_tok = getattr(tok, "astOperand1", None)
            idx_tok = getattr(tok, "astOperand2", None)
            if arr_tok is None or idx_tok is None:
                continue
            var = getattr(arr_tok, "variable", None)
            if var is None:
                continue
            # Get array dimension
            dims = getattr(var, "dimensions", None) or []
            if not dims:
                continue
            dim_size = None
            for d in dims:
                num = getattr(d, "num", None)
                if num and int(num) > 0:
                    dim_size = int(num)
                    break
            if dim_size is None:
                continue

            # Check index value-flow
            idx_values = getattr(idx_tok, "values", None) or []
            for v in idx_values:
                iv = getattr(v, "intvalue", None)
                if iv is not None and iv >= dim_size:
                    count += 1
                    vn = arr_tok.str
                    issues.append(self.fb(
                        f"Array `{vn}[{dim_size}]` accessed with index "
                        f"value {iv} (out of bounds)",
                        priority=Priority.CRITICAL,
                        location=_tok_loc(tok),
                        impact=-10.0,
                    ))
                    break

        score = _clamp(100.0 - count * 10.0)
        return score, issues


class DivisionByZeroMetric(QualityMetric):
    """Detect potential division by zero via value flow."""

    def __init__(self):
        super().__init__(QualityDimension.SAFETY, weight=0.8,
                         priority=Priority.CRITICAL)
        self.description = "Potential division by zero"

    def compute(self, cfg) -> Tuple[float, List[QualityFeedback]]:
        issues: List[QualityFeedback] = []
        count = 0

        for tok in _iter_tokens(cfg):
            if tok.str not in ("/", "%", "/=", "%="):
                continue
            divisor = getattr(tok, "astOperand2", None)
            if divisor is None:
                continue
            values = getattr(divisor, "values", None) or []
            for v in values:
                iv = getattr(v, "intvalue", None)
                if iv is not None and iv == 0:
                    count += 1
                    issues.append(self.fb(
                        f"Potential division by zero at "
                        f"`{tok.str}` operation",
                        priority=Priority.CRITICAL,
                        location=_tok_loc(tok),
                        impact=-10.0,
                    ))
                    break

        score = _clamp(100.0 - count * 10.0)
        return score, issues


class IntegerOverflowMetric(QualityMetric):
    """Flag arithmetic on narrow integer types without overflow checks."""

    _NARROW_TYPES = {"char", "short", "int"}

    def __init__(self):
        super().__init__(QualityDimension.SAFETY, weight=0.6,
                         priority=Priority.WARNING)
        self.description = "Potential integer overflow"

    def compute(self, cfg) -> Tuple[float, List[QualityFeedback]]:
        issues: List[QualityFeedback] = []
        count = 0

        for tok in _iter_tokens(cfg):
            if tok.str not in ("+", "-", "*", "<<"):
                continue
            vt = getattr(tok, "valueType", None)
            if vt is None:
                continue
            if getattr(vt, "type", None) not in self._NARROW_TYPES:
                continue
            if getattr(vt, "sign", None) == "unsigned":
                continue  # unsigned wraps by definition

            # Check if operand values suggest large magnitude
            op1 = getattr(tok, "astOperand1", None)
            op2 = getattr(tok, "astOperand2", None)
            large = False
            for operand in (op1, op2):
                if operand is None:
                    continue
                for v in (getattr(operand, "values", None) or []):
                    iv = getattr(v, "intvalue", None)
                    if iv is not None and abs(iv) > 30000:
                        large = True
                        break
            if large:
                count += 1
                issues.append(self.fb(
                    f"Arithmetic `{tok.str}` on signed `{vt.type}` with "
                    f"large operand values — risk of overflow",
                    location=_tok_loc(tok),
                    impact=-4.0,
                ))

        score = _clamp(100.0 - count * 4.0)
        return score, issues


# ===================================================================
# 5.  MAINTAINABILITY Metrics
# ===================================================================

class FunctionLengthMetric(QualityMetric):
    """Penalize functions that exceed a line-count threshold."""

    def __init__(self, threshold: int = 60):
        super().__init__(QualityDimension.MAINTAINABILITY, weight=1.0,
                         priority=Priority.WARNING)
        self.threshold = threshold
        self.description = f"Functions longer than {threshold} lines"

    def compute(self, cfg) -> Tuple[float, List[QualityFeedback]]:
        issues: List[QualityFeedback] = []
        penalties = 0.0

        for scope in _iter_scopes(cfg):
            stype = getattr(scope, "type", "")
            if stype != "Function":
                continue
            lines = _scope_line_count(scope)
            if lines <= self.threshold:
                continue
            fname = ""
            func = getattr(scope, "function", None)
            if func:
                fname = _function_name(func)
            else:
                bs = getattr(scope, "bodyStart", None)
                if bs:
                    fname = f"<scope at line {getattr(bs, 'linenr', '?')}>"

            excess = lines - self.threshold
            pen = min(5.0, 1.0 + excess * 0.1)
            penalties += pen
            issues.append(self.fb(
                f"Function `{fname}` is {lines} lines long "
                f"(threshold: {self.threshold})",
                location=_tok_loc(getattr(scope, "bodyStart", None)),
                impact=-pen,
            ))

        score = _clamp(100.0 - penalties)
        return score, issues


class CyclomaticComplexityMetric(QualityMetric):
    """
    Estimate cyclomatic complexity per function.

    CC ≈ 1 + number of decision points (if, while, for, case, &&, ||, ?:).
    """

    _DECISION_KEYWORDS = {"if", "while", "for", "case"}
    _DECISION_OPS = {"&&", "||", "?"}

    def __init__(self, threshold: int = 10):
        super().__init__(QualityDimension.MAINTAINABILITY, weight=1.0,
                         priority=Priority.WARNING)
        self.threshold = threshold
        self.description = f"Cyclomatic complexity > {threshold}"

    def compute(self, cfg) -> Tuple[float, List[QualityFeedback]]:
        issues: List[QualityFeedback] = []
        penalties = 0.0

        for scope in _iter_scopes(cfg):
            if getattr(scope, "type", "") != "Function":
                continue
            cc = 1
            tok = getattr(scope, "bodyStart", None)
            end = getattr(scope, "bodyEnd", None)
            if tok is None or end is None:
                continue
            tok = tok.next
            while tok is not None and tok != end:
                if tok.str in self._DECISION_KEYWORDS:
                    cc += 1
                elif tok.str in self._DECISION_OPS:
                    cc += 1
                tok = tok.next

            if cc <= self.threshold:
                continue

            func = getattr(scope, "function", None)
            fname = _function_name(func) if func else "?"
            excess = cc - self.threshold
            pen = min(8.0, 2.0 + excess * 0.5)
            penalties += pen
            issues.append(self.fb(
                f"Function `{fname}` has cyclomatic complexity {cc} "
                f"(threshold: {self.threshold})",
                location=_tok_loc(getattr(scope, "bodyStart", None)),
                impact=-pen,
            ))

        score = _clamp(100.0 - penalties)
        return score, issues


class NameConsistencyMetric(QualityMetric):
    """
    Check naming consistency across the translation unit.

    Detects mixing of naming conventions (e.g. camelCase vs snake_case)
    among variable names.
    """

    _RE_SNAKE = re.compile(r"^[a-z][a-z0-9]*(_[a-z0-9]+)*$")
    _RE_CAMEL = re.compile(r"^[a-z][a-zA-Z0-9]*$")
    _RE_UPPER = re.compile(r"^[A-Z][A-Z0-9]*(_[A-Z0-9]+)*$")
    _RE_PASCAL = re.compile(r"^[A-Z][a-zA-Z0-9]*$")

    def __init__(self):
        super().__init__(QualityDimension.MAINTAINABILITY, weight=0.7,
                         priority=Priority.SUGGESTION)
        self.description = "Naming convention consistency"

    @staticmethod
    def _classify(name: str) -> str:
        if NameConsistencyMetric._RE_UPPER.match(name):
            return "UPPER_SNAKE"
        if NameConsistencyMetric._RE_SNAKE.match(name):
            return "snake_case"
        if NameConsistencyMetric._RE_PASCAL.match(name):
            return "PascalCase"
        if NameConsistencyMetric._RE_CAMEL.match(name):
            return "camelCase"
        return "other"

    def compute(self, cfg) -> Tuple[float, List[QualityFeedback]]:
        issues: List[QualityFeedback] = []
        style_counts: Dict[str, int] = defaultdict(int)
        examples: Dict[str, List[str]] = defaultdict(list)

        for var in _iter_variables(cfg):
            nt = getattr(var, "nameToken", None)
            if nt is None:
                continue
            name = nt.str
            if len(name) <= 1:
                continue  # skip single-char names
            is_const = getattr(var, "isConst", False)
            if is_const:
                continue  # constants are often UPPER, skip
            cls = self._classify(name)
            style_counts[cls] += 1
            if len(examples[cls]) < 5:
                examples[cls].append(name)

        if not style_counts:
            return 100.0, []

        total = sum(style_counts.values())
        if total <= 2:
            return 100.0, []

        # The dominant style is the one with the most names
        dominant = max(style_counts, key=style_counts.get)  # type: ignore
        dominant_pct = style_counts[dominant] / total

        # Penalize for inconsistency
        penalty = 0.0
        for style, cnt in style_counts.items():
            if style == dominant or style == "other":
                continue
            pct = cnt / total
            if pct > 0.15:  # minor styles > 15%
                pen = min(15.0, pct * 30.0)
                penalty += pen
                exs = ", ".join(f"`{e}`" for e in examples[style][:3])
                issues.append(self.fb(
                    f"Naming inconsistency: {cnt} names use {style} "
                    f"(dominant: {dominant}). Examples: {exs}",
                    impact=-pen,
                ))

        score = _clamp(100.0 - penalty)
        return score, issues


class NestingDepthMetric(QualityMetric):
    """Penalize deeply nested code blocks."""

    def __init__(self, threshold: int = 4):
        super().__init__(QualityDimension.MAINTAINABILITY, weight=0.8,
                         priority=Priority.WARNING)
        self.threshold = threshold
        self.description = f"Nesting depth > {threshold}"

    def compute(self, cfg) -> Tuple[float, List[QualityFeedback]]:
        issues: List[QualityFeedback] = []
        max_depth = 0
        current_depth = 0

        for tok in _iter_tokens(cfg):
            if tok.str == "{":
                current_depth += 1
                if current_depth > max_depth:
                    max_depth = current_depth
                if current_depth > self.threshold:
                    issues.append(self.fb(
                        f"Nesting depth {current_depth} exceeds "
                        f"threshold {self.threshold}",
                        location=_tok_loc(tok),
                        impact=-3.0,
                    ))
            elif tok.str == "}":
                current_depth = max(0, current_depth - 1)

        # Deduplicate: keep one per distinct depth level
        seen_depths: Set[str] = set()
        unique_issues: List[QualityFeedback] = []
        for fb_item in issues:
            key = fb_item.message
            if key not in seen_depths:
                seen_depths.add(key)
                unique_issues.append(fb_item)

        penalty = len(unique_issues) * 3.0
        score = _clamp(100.0 - penalty)
        return score, unique_issues


class ParameterCountMetric(QualityMetric):
    """Penalize functions with too many parameters."""

    def __init__(self, threshold: int = 5):
        super().__init__(QualityDimension.MAINTAINABILITY, weight=0.6,
                         priority=Priority.SUGGESTION)
        self.threshold = threshold
        self.description = f"Functions with > {threshold} parameters"

    def compute(self, cfg) -> Tuple[float, List[QualityFeedback]]:
        issues: List[QualityFeedback] = []
        penalty = 0.0

        for scope in _iter_scopes(cfg):
            if getattr(scope, "type", "") != "Function":
                continue
            func = getattr(scope, "function", None)
            if func is None:
                continue
            arg_count = 0
            arg_list = getattr(func, "argument", None)
            if isinstance(arg_list, dict):
                arg_count = len(arg_list)
            elif isinstance(arg_list, (list, tuple)):
                arg_count = len(arg_list)
            elif arg_list is not None:
                arg_count = 1

            if arg_count > self.threshold:
                fname = _function_name(func)
                pen = min(5.0, (arg_count - self.threshold) * 1.5)
                penalty += pen
                issues.append(self.fb(
                    f"Function `{fname}` has {arg_count} parameters "
                    f"(threshold: {self.threshold})",
                    location=_tok_loc(getattr(func, "tokenDef", None)),
                    impact=-pen,
                ))

        score = _clamp(100.0 - penalty)
        return score, issues


# ===================================================================
# 6.  STYLE Metrics
# ===================================================================

class LineLengthMetric(QualityMetric):
    """Penalize lines exceeding a maximum column width."""

    def __init__(self, max_length: int = 100):
        super().__init__(QualityDimension.STYLE, weight=0.5,
                         priority=Priority.SUGGESTION)
        self.max_length = max_length
        self.description = f"Lines longer than {max_length} columns"

    def compute(self, cfg) -> Tuple[float, List[QualityFeedback]]:
        issues: List[QualityFeedback] = []
        # Reconstruct approximate line lengths from token positions
        line_max_col: Dict[Tuple[str, int], int] = {}

        for tok in _iter_tokens(cfg):
            f = getattr(tok, "file", None)
            ln = getattr(tok, "linenr", None)
            col = getattr(tok, "column", 0) or 0
            tlen = len(tok.str) if tok.str else 0
            end_col = int(col) + tlen
            if f and ln:
                key = (f, int(ln))
                if key not in line_max_col or end_col > line_max_col[key]:
                    line_max_col[key] = end_col

        long_lines = 0
        reported_files: Dict[str, int] = defaultdict(int)
        for (fname, linenr), end_col in line_max_col.items():
            if end_col > self.max_length:
                long_lines += 1
                reported_files[fname] += 1

        # Report per-file summary instead of per-line
        penalty = 0.0
        for fname, cnt in reported_files.items():
            pen = min(5.0, cnt * 0.3)
            penalty += pen
            issues.append(self.fb(
                f"File `{fname}` has {cnt} line(s) exceeding "
                f"{self.max_length} columns",
                priority=Priority.SUGGESTION,
                location=(fname, 0),
                impact=-pen,
            ))

        score = _clamp(100.0 - penalty)
        return score, issues


class BraceStyleMetric(QualityMetric):
    """
    Detect inconsistent brace placement style (K&R vs Allman).

    K&R:   ``if (...) {``   (opening brace on same line)
    Allman: brace on its own line.
    """

    def __init__(self):
        super().__init__(QualityDimension.STYLE, weight=0.5,
                         priority=Priority.SUGGESTION)
        self.description = "Brace placement consistency"

    def compute(self, cfg) -> Tuple[float, List[QualityFeedback]]:
        issues: List[QualityFeedback] = []
        same_line = 0   # K&R style
        next_line = 0   # Allman style
        _CONTROL = {"if", "else", "for", "while", "do", "switch"}

        for tok in _iter_tokens(cfg):
            if tok.str != "{":
                continue
            prev = getattr(tok, "previous", None)
            if prev is None:
                continue
            # Walk back past ')' to find the control keyword
            p = prev
            while p and p.str == ")":
                p = getattr(p, "link", None)
                if p:
                    p = getattr(p, "previous", None)
            if p is None:
                continue
            if p.str not in _CONTROL:
                continue

            # Compare line numbers
            ctrl_line = getattr(p, "linenr", 0) or 0
            brace_line = getattr(tok, "linenr", 0) or 0
            if brace_line == ctrl_line:
                same_line += 1
            elif brace_line > ctrl_line:
                next_line += 1

        total = same_line + next_line
        if total < 3:
            return 100.0, []

        dominant_cnt = max(same_line, next_line)
        dominant_style = "K&R" if same_line >= next_line else "Allman"
        minor_cnt = total - dominant_cnt
        consistency = dominant_cnt / total

        if consistency < 0.85:
            pen = min(15.0, (1.0 - consistency) * 40.0)
            issues.append(self.fb(
                f"Inconsistent brace style: {same_line} K&R vs "
                f"{next_line} Allman (dominant: {dominant_style})",
                impact=-pen,
            ))
            score = _clamp(100.0 - pen)
        else:
            score = 100.0

        return score, issues


class IndentationConsistencyMetric(QualityMetric):
    """
    Check whether the code uses a consistent indentation unit
    (tabs vs spaces, and the number of spaces).
    """

    def __init__(self):
        super().__init__(QualityDimension.STYLE, weight=0.5,
                         priority=Priority.SUGGESTION)
        self.description = "Indentation consistency"

    def compute(self, cfg) -> Tuple[float, List[QualityFeedback]]:
        issues: List[QualityFeedback] = []
        # Heuristic: look at the column offsets of '{' tokens.
        # Consistent code has columns that are multiples of a fixed indent.
        indent_sizes: List[int] = []
        prev_col_by_line: Dict[Tuple[str, int], int] = {}

        for tok in _iter_tokens(cfg):
            col = getattr(tok, "column", None)
            if col is None or int(col) <= 1:
                continue
            f = getattr(tok, "file", "")
            ln = getattr(tok, "linenr", 0)
            key = (f, int(ln))
            if key not in prev_col_by_line:
                prev_col_by_line[key] = int(col)

        # Collect indent levels (first-token column per line)
        col_values = sorted(set(prev_col_by_line.values()))
        if len(col_values) < 3:
            return 100.0, []

        # Compute deltas between successive indent levels
        deltas: List[int] = []
        for i in range(1, len(col_values)):
            d = col_values[i] - col_values[i - 1]
            if 0 < d <= 16:
                deltas.append(d)

        if not deltas:
            return 100.0, []

        # Check consistency of deltas
        counter = Counter(deltas)
        dominant_indent, dom_count = counter.most_common(1)[0]
        total_d = sum(counter.values())
        consistency = dom_count / total_d if total_d else 1.0

        if consistency < 0.7:
            pen = min(10.0, (1.0 - consistency) * 25.0)
            dist_str = ", ".join(f"{k}sp:{v}" for k,
                                 v in counter.most_common(4))
            issues.append(self.fb(
                f"Inconsistent indentation widths: {dist_str} "
                f"(dominant: {dominant_indent} spaces)",
                impact=-pen,
            ))
            score = _clamp(100.0 - pen)
        else:
            score = 100.0

        return score, issues


class NamingConventionMetric(QualityMetric):
    """
    Check that functions follow a naming convention
    (default expectation: snake_case for C functions).
    """

    _RE_SNAKE = re.compile(r"^[a-z_][a-z0-9_]*$")

    def __init__(self, pattern: Optional[re.Pattern] = None):
        super().__init__(QualityDimension.STYLE, weight=0.6,
                         priority=Priority.SUGGESTION)
        self.pattern = pattern or self._RE_SNAKE
        self.description = "Function naming conventions"

    def compute(self, cfg) -> Tuple[float, List[QualityFeedback]]:
        issues: List[QualityFeedback] = []
        total = 0
        violations = 0

        for scope in _iter_scopes(cfg):
            if getattr(scope, "type", "") != "Function":
                continue
            func = getattr(scope, "function", None)
            if func is None:
                continue
            fname = _function_name(func)
            if fname.startswith("<"):
                continue
            # Skip 'main'
            if fname == "main":
                continue
            total += 1
            if not self.pattern.match(fname):
                violations += 1
                issues.append(self.fb(
                    f"Function name `{fname}` does not match expected "
                    f"pattern `{self.pattern.pattern}`",
                    location=_tok_loc(getattr(func, "tokenDef", None)),
                    impact=-2.0,
                ))

        if total == 0:
            return 100.0, []
        score = _clamp(100.0 - (violations / total) * 50.0)
        return score, issues


class MagicNumberMetric(QualityMetric):
    """Detect hard-coded "magic numbers" outside of obvious contexts."""

    _IGNORE = {0, 1, 2, -1, 10, 100, 0.0, 1.0}

    def __init__(self):
        super().__init__(QualityDimension.STYLE, weight=0.4,
                         priority=Priority.SUGGESTION)
        self.description = "Magic number usage"

    def compute(self, cfg) -> Tuple[float, List[QualityFeedback]]:
        issues: List[QualityFeedback] = []
        count = 0

        for tok in _iter_tokens(cfg):
            if not (getattr(tok, "isNumber", False) or
                    getattr(tok, "isInt", False) or
                    getattr(tok, "isFloat", False)):
                continue

            # Skip numbers in array dimensions, enum values,
            # #define, and initializers of const vars
            parent = getattr(tok, "astParent", None)

            # Try to parse the number
            try:
                val = int(tok.str, 0)
            except (ValueError, TypeError):
                try:
                    val = float(tok.str)
                except (ValueError, TypeError):
                    continue

            if val in self._IGNORE:
                continue

            # Skip if inside an enum scope or #define
            scope = getattr(tok, "scope", None)
            if scope and getattr(scope, "type", "") == "Enum":
                continue

            # Skip if the parent is an array dimension [N]
            if parent and parent.str == "[":
                continue

            # Skip if this is the RHS of a const variable init
            if parent and parent.str in ("=", "{"):
                lhs = getattr(parent, "astOperand1", None)
                if lhs:
                    var = getattr(lhs, "variable", None)
                    if var and getattr(var, "isConst", False):
                        continue

            count += 1
            if count <= 10:  # Cap reports
                issues.append(self.fb(
                    f"Magic number `{tok.str}` — consider using a "
                    f"named constant",
                    location=_tok_loc(tok),
                    impact=-1.0,
                ))

        penalty = min(20.0, count * 1.0)
        score = _clamp(100.0 - penalty)
        return score, issues


class TrailingWhitespaceMetric(QualityMetric):
    """
    Flag evidence of trailing whitespace / mixed line endings.

    Since we only have tokens (not raw source), this is a best-effort
    heuristic: we flag string literals containing trailing spaces/tabs
    and note it as a general reminder.
    """

    def __init__(self):
        super().__init__(QualityDimension.STYLE, weight=0.2,
                         priority=Priority.INFO)
        self.description = "Trailing whitespace hints"

    def compute(self, cfg) -> Tuple[float, List[QualityFeedback]]:
        # Without raw source access we can't truly check this,
        # so just return perfect score with an info note.
        issues: List[QualityFeedback] = []
        issues.append(self.fb(
            "Trailing whitespace detection requires raw source access; "
            "skipped in token-only mode",
            priority=Priority.INFO,
            impact=0.0,
        ))
        return 100.0, issues


# ===================================================================
# 7.  PERFORMANCE Metrics
# ===================================================================

class LoopPerformanceMetric(QualityMetric):
    """
    Detect common loop inefficiencies:
    - strlen() / function calls in loop conditions
    - Repeated identical expressions inside loops
    """

    _EXPENSIVE_FUNCS = {
        "strlen", "strcmp", "strncmp", "atoi", "atof",
        "pow", "sqrt", "log", "exp",
    }

    def __init__(self):
        super().__init__(QualityDimension.PERFORMANCE, weight=0.8,
                         priority=Priority.WARNING)
        self.description = "Loop efficiency"

    def compute(self, cfg) -> Tuple[float, List[QualityFeedback]]:
        issues: List[QualityFeedback] = []
        count = 0

        for tok in _iter_tokens(cfg):
            # Detect: for (...; <condition involving expensive call>; ...)
            if tok.str not in ("for", "while"):
                continue

            # Find the condition tokens
            paren = getattr(tok, "next", None)
            if paren is None or paren.str != "(":
                continue
            close_paren = getattr(paren, "link", None)
            if close_paren is None:
                continue

            # Walk tokens inside the condition
            # For 'for', the condition is between the first and second ';'
            t = paren.next
            semicolons = 0
            in_condition = tok.str == "while"
            while t is not None and t != close_paren:
                if t.str == ";" and tok.str == "for":
                    semicolons += 1
                    if semicolons == 1:
                        in_condition = True
                    elif semicolons == 2:
                        in_condition = False
                if in_condition and t.str in self._EXPENSIVE_FUNCS:
                    nt = getattr(t, "next", None)
                    if nt and nt.str == "(":
                        count += 1
                        issues.append(self.fb(
                            f"Expensive function `{t.str}()` called in "
                            f"loop condition — consider hoisting",
                            location=_tok_loc(t),
                            impact=-3.0,
                        ))
                t = t.next

        penalty = min(20.0, count * 3.0)
        score = _clamp(100.0 - penalty)
        return score, issues


class RedundantOpMetric(QualityMetric):
    """
    Detect obviously redundant operations:
    - x = x (self-assignment)
    - x * 1, x + 0, x | 0, x & ~0
    - Double negation !!x used non-idiomatically
    """

    def __init__(self):
        super().__init__(QualityDimension.PERFORMANCE, weight=0.5,
                         priority=Priority.SUGGESTION)
        self.description = "Redundant operations"

    def compute(self, cfg) -> Tuple[float, List[QualityFeedback]]:
        issues: List[QualityFeedback] = []
        count = 0

        for tok in _iter_tokens(cfg):
            # Self-assignment: a = a
            if tok.str == "=" and not getattr(tok, "isComparisonOp", False):
                op1 = getattr(tok, "astOperand1", None)
                op2 = getattr(tok, "astOperand2", None)
                if (op1 and op2 and
                        getattr(op1, "varId", None) and
                        op1.varId == getattr(op2, "varId", None) and
                        op1.varId != 0):
                    count += 1
                    issues.append(self.fb(
                        f"Self-assignment of `{op1.str}`",
                        location=_tok_loc(tok),
                        impact=-2.0,
                    ))

            # Multiply by 1, add 0
            if tok.str in ("*", "/") and getattr(tok, "isArithmeticalOp", False):
                for operand in (getattr(tok, "astOperand1", None),
                                getattr(tok, "astOperand2", None)):
                    if operand and getattr(operand, "isInt", False):
                        try:
                            val = int(operand.str, 0)
                        except (ValueError, TypeError):
                            continue
                        if val == 1 and tok.str in ("*", "/"):
                            count += 1
                            issues.append(self.fb(
                                f"Redundant `{tok.str} 1` operation",
                                location=_tok_loc(tok),
                                impact=-1.0,
                            ))
                        elif val == 0 and tok.str == "*":
                            count += 1
                            issues.append(self.fb(
                                f"Multiplication by zero — result always 0",
                                location=_tok_loc(tok),
                                impact=-1.0,
                            ))

            if tok.str in ("+", "-") and getattr(tok, "isArithmeticalOp", False):
                for operand in (getattr(tok, "astOperand1", None),
                                getattr(tok, "astOperand2", None)):
                    if operand and getattr(operand, "isInt", False):
                        try:
                            val = int(operand.str, 0)
                        except (ValueError, TypeError):
                            continue
                        if val == 0:
                            count += 1
                            issues.append(self.fb(
                                f"Redundant `{tok.str} 0` operation",
                                location=_tok_loc(tok),
                                impact=-1.0,
                            ))

        penalty = min(15.0, count * 1.5)
        score = _clamp(100.0 - penalty)
        return score, issues


class UnusedVariableMetric(QualityMetric):
    """Flag variables that are declared but never read."""

    def __init__(self):
        super().__init__(QualityDimension.PERFORMANCE, weight=0.5,
                         priority=Priority.WARNING)
        self.description = "Unused variables"

    def compute(self, cfg) -> Tuple[float, List[QualityFeedback]]:
        issues: List[QualityFeedback] = []
        # Collect all varIds that appear as assignments (writes)
        # vs those that appear as reads
        written: Set[int] = set()
        read: Set[int] = set()
        var_names: Dict[int, str] = {}
        var_locs: Dict[int, Optional[Tuple[str, int]]] = {}

        for var in _iter_variables(cfg):
            vid = getattr(var, "Id", None)
            if vid is None:
                continue
            nt = getattr(var, "nameToken", None)
            if nt:
                var_names[vid] = nt.str
                var_locs[vid] = _tok_loc(nt)
            # Skip global/extern variables
            if getattr(var, "isGlobal", False) or getattr(var, "isExtern", False):
                continue

        for tok in _iter_tokens(cfg):
            vid = getattr(tok, "varId", None)
            if not vid or vid == 0:
                continue
            parent = getattr(tok, "astParent", None)
            if parent and parent.str in ("=", "+=", "-=", "*=", "/=",
                                         "%=", "&=", "|=", "^=", "<<=", ">>="):
                if getattr(parent, "astOperand1", None) == tok:
                    written.add(vid)
                    continue
            read.add(vid)

        # Variables written but never read
        count = 0
        for vid in written - read:
            name = var_names.get(vid, f"varId={vid}")
            count += 1
            issues.append(self.fb(
                f"Variable `{name}` is assigned but never read",
                location=var_locs.get(vid),
                impact=-2.0,
            ))

        penalty = min(20.0, count * 2.0)
        score = _clamp(100.0 - penalty)
        return score, issues


class ResourceLeakMetric(QualityMetric):
    """
    Detect potential resource leaks (fopen without fclose, etc.).
    """

    _OPEN_CLOSE_PAIRS = {
        "fopen": "fclose",
        "fdopen": "fclose",
        "tmpfile": "fclose",
        "socket": "close",
        "open": "close",
        "opendir": "closedir",
        "popen": "pclose",
    }

    def __init__(self):
        super().__init__(QualityDimension.PERFORMANCE, weight=0.7,
                         priority=Priority.WARNING)
        self.description = "Resource leak detection"

    def compute(self, cfg) -> Tuple[float, List[QualityFeedback]]:
        issues: List[QualityFeedback] = []
        # Similar approach to MemoryLeakMetric
        opened: Dict[int, Tuple[str, Any]] = {}  # varId -> (open_func, token)
        closed: Set[int] = set()

        close_funcs = set(self._OPEN_CLOSE_PAIRS.values())

        for tok in _iter_tokens(cfg):
            if tok.str in self._OPEN_CLOSE_PAIRS:
                nt = getattr(tok, "next", None)
                if nt and nt.str == "(":
                    parent = getattr(tok, "astParent", None)
                    while parent and parent.str == "(":
                        parent = getattr(parent, "astParent", None)
                    if parent and parent.str == "=":
                        lhs = getattr(parent, "astOperand1", None)
                        if lhs:
                            vid = getattr(lhs, "varId", None)
                            if vid:
                                opened[vid] = (tok.str, tok)

            if tok.str in close_funcs:
                nt = getattr(tok, "next", None)
                if nt and nt.str == "(":
                    arg = nt.next
                    if arg:
                        vid = getattr(arg, "varId", None)
                        if vid:
                            closed.add(vid)

        count = 0
        for vid, (func_name, open_tok) in opened.items():
            if vid not in closed:
                expected_close = self._OPEN_CLOSE_PAIRS.get(func_name, "?")
                count += 1
                issues.append(self.fb(
                    f"Resource opened via `{func_name}()` may not be "
                    f"closed with `{expected_close}()` (varId={vid})",
                    location=_tok_loc(open_tok),
                    impact=-5.0,
                ))

        penalty = min(25.0, count * 5.0)
        score = _clamp(100.0 - penalty)
        return score, issues


# ===================================================================
# 8.  PORTABILITY Metrics
# ===================================================================

class CompilerExtensionMetric(QualityMetric):
    """Detect use of common compiler-specific extensions."""

    _GCC_BUILTINS = {
        "__builtin_expect", "__builtin_clz", "__builtin_ctz",
        "__builtin_popcount", "__builtin_unreachable",
        "__builtin_bswap16", "__builtin_bswap32", "__builtin_bswap64",
        "__builtin_types_compatible_p", "__builtin_choose_expr",
        "__builtin_constant_p",
    }

    _GCC_ATTRIBUTES = {
        "__attribute__", "__asm__", "__volatile__",
        "__extension__", "__typeof__", "__alignof__",
    }

    _MSVC_EXTENSIONS = {
        "__declspec", "__forceinline", "__pragma",
        "__int8", "__int16", "__int32", "__int64",
    }

    def __init__(self):
        super().__init__(QualityDimension.PORTABILITY, weight=0.8,
                         priority=Priority.WARNING)
        self.description = "Compiler-specific extensions"

    def compute(self, cfg) -> Tuple[float, List[QualityFeedback]]:
        issues: List[QualityFeedback] = []
        count = 0
        all_ext = self._GCC_BUILTINS | self._GCC_ATTRIBUTES | self._MSVC_EXTENSIONS

        for tok in _iter_tokens(cfg):
            if tok.str in all_ext:
                count += 1
                if tok.str in self._GCC_BUILTINS:
                    kind = "GCC builtin"
                elif tok.str in self._GCC_ATTRIBUTES:
                    kind = "GCC extension"
                else:
                    kind = "MSVC extension"
                issues.append(self.fb(
                    f"Non-portable {kind} `{tok.str}` used",
                    location=_tok_loc(tok),
                    impact=-3.0,
                ))

        penalty = min(25.0, count * 3.0)
        score = _clamp(100.0 - penalty)
        return score, issues


class PlatformDependencyMetric(QualityMetric):
    """
    Detect platform-dependent constructs:
    - Assumption about ``sizeof(int)`` etc.
    - Use of platform-specific headers (windows.h, unistd.h)
    - Hard-coded path separators
    """

    _PLATFORM_HEADERS = {
        "windows.h", "unistd.h", "sys/socket.h", "winsock2.h",
        "dlfcn.h", "pthread.h", "mach/mach.h",
    }

    def __init__(self):
        super().__init__(QualityDimension.PORTABILITY, weight=0.6,
                         priority=Priority.SUGGESTION)
        self.description = "Platform-dependent constructs"

    def compute(self, cfg) -> Tuple[float, List[QualityFeedback]]:
        issues: List[QualityFeedback] = []
        count = 0

        # Check directives for platform-specific includes
        directives = getattr(cfg, "directives", []) or []
        for d in directives:
            d_str = getattr(d, "str", "") or ""
            for hdr in self._PLATFORM_HEADERS:
                if hdr in d_str:
                    count += 1
                    issues.append(self.fb(
                        f"Platform-specific header `{hdr}` included",
                        location=(
                            getattr(d, "file", "?"),
                            getattr(d, "linenr", 0) or 0,
                        ),
                        impact=-3.0,
                    ))
                    break

        # Detect hard-coded Windows paths in string literals
        for tok in _iter_tokens(cfg):
            if getattr(tok, "isString", False) and tok.str:
                s = tok.str
                if "\\\\" in s and ("C:" in s or "D:" in s):
                    count += 1
                    issues.append(self.fb(
                        f"Hard-coded Windows path in string literal",
                        location=_tok_loc(tok),
                        impact=-2.0,
                    ))

        penalty = min(20.0, count * 3.0)
        score = _clamp(100.0 - penalty)
        return score, issues


class TypeSizeAssumptionMetric(QualityMetric):
    """
    Detect code that assumes specific sizes for basic types,
    e.g. casting between ``int`` and pointer, or using ``int``
    where ``size_t``/``ptrdiff_t`` should be used.
    """

    def __init__(self):
        super().__init__(QualityDimension.PORTABILITY, weight=0.5,
                         priority=Priority.WARNING)
        self.description = "Type-size assumptions"

    def compute(self, cfg) -> Tuple[float, List[QualityFeedback]]:
        issues: List[QualityFeedback] = []
        count = 0

        for tok in _iter_tokens(cfg):
            # Detect pointer-to-int casts (loss of data on 64-bit)
            if getattr(tok, "isCast", False):
                vt = getattr(tok, "valueType", None)
                if vt and getattr(vt, "type", "") == "int" and \
                        getattr(vt, "pointer", 0) == 0:
                    # Check if operand is a pointer
                    op1 = getattr(tok, "astOperand1", None)
                    if op1:
                        op1_vt = getattr(op1, "valueType", None)
                        if op1_vt and getattr(op1_vt, "pointer", 0) > 0:
                            count += 1
                            issues.append(self.fb(
                                f"Pointer cast to `int` — use "
                                f"`intptr_t`/`uintptr_t` for portability",
                                location=_tok_loc(tok),
                                impact=-5.0,
                            ))

        penalty = min(20.0, count * 5.0)
        score = _clamp(100.0 - penalty)
        return score, issues


class NonStandardFunctionMetric(QualityMetric):
    """Detect use of non-standard C library functions."""

    _NON_STANDARD = {
        "stricmp", "strnicmp", "itoa", "ltoa", "ultoa",
        "strlcpy", "strlcat",  # BSD
        "asprintf", "vasprintf",  # GNU
        "alloca",  # not in C standard
        "bzero", "bcopy", "bcmp",  # BSD legacy
        "index", "rindex",  # BSD legacy
        "getline",  # POSIX, not C standard
    }

    def __init__(self):
        super().__init__(QualityDimension.PORTABILITY, weight=0.5,
                         priority=Priority.SUGGESTION)
        self.description = "Non-standard function usage"

    def compute(self, cfg) -> Tuple[float, List[QualityFeedback]]:
        issues: List[QualityFeedback] = []
        count = 0

        for tok in _iter_tokens(cfg):
            if tok.str in self._NON_STANDARD:
                nt = getattr(tok, "next", None)
                if nt and nt.str == "(":
                    count += 1
                    issues.append(self.fb(
                        f"Non-standard function `{tok.str}()` — "
                        f"may not be available on all platforms",
                        location=_tok_loc(tok),
                        impact=-2.0,
                    ))

        penalty = min(15.0, count * 2.0)
        score = _clamp(100.0 - penalty)
        return score, issues


# ===================================================================
# 9.  DOCUMENTATION Metrics
# ===================================================================

class CommentDensityMetric(QualityMetric):
    """
    Estimate comment-to-code ratio.

    Since Cppcheck strips comments from the token stream, we inspect
    directives and rely on heuristics.  If raw source is unavailable,
    we look at whether functions have any preceding comment-like tokens
    or documentation directives.
    """

    def __init__(self, min_density: float = 0.10):
        super().__init__(QualityDimension.DOCUMENTATION, weight=0.8,
                         priority=Priority.SUGGESTION)
        self.min_density = min_density
        self.description = f"Comment density (target >= {min_density:.0%})"

    def compute(self, cfg) -> Tuple[float, List[QualityFeedback]]:
        issues: List[QualityFeedback] = []

        # Count total tokens and total lines as a proxy for code size
        total_tokens = 0
        lines: Set[Tuple[str, int]] = set()
        for tok in _iter_tokens(cfg):
            total_tokens += 1
            f = getattr(tok, "file", None)
            ln = getattr(tok, "linenr", None)
            if f and ln:
                lines.add((f, int(ln)))

        total_lines = len(lines)
        if total_lines == 0:
            return 100.0, []

        # Check directives for comment-related macros (e.g. Doxygen)
        # This is a rough proxy — proper comment analysis requires source.
        comment_hints = 0
        directives = getattr(cfg, "directives", []) or []
        for d in directives:
            d_str = getattr(d, "str", "") or ""
            # Doxygen-style /** or /*! markers sometimes survive in preprocessor
            if "/**" in d_str or "/*!" in d_str or "@brief" in d_str:
                comment_hints += 1

        # Without raw source, we estimate comment density based on
        # the ratio of blank lines (lines in range not in token set).
        # This is very approximate.
        if total_lines < 10:
            return 100.0, [self.fb(
                "Too few lines to assess comment density",
                priority=Priority.INFO,
                impact=0.0,
            )]

        # Rough heuristic: if there are no comment hints and the code
        # is substantial, flag it.
        estimated_density = comment_hints / \
            (total_lines / 10.0) if total_lines > 0 else 0
        estimated_density = min(1.0, estimated_density)

        if estimated_density < self.min_density:
            deficit = self.min_density - estimated_density
            pen = min(20.0, deficit * 100.0)
            issues.append(self.fb(
                f"Estimated comment density {estimated_density:.1%} is below "
                f"target {self.min_density:.0%} "
                f"(note: analysis is approximate without raw source)",
                impact=-pen,
            ))
            score = _clamp(100.0 - pen)
        else:
            score = 100.0

        return score, issues


class DoxygenCoverageMetric(QualityMetric):
    """
    Check whether functions have Doxygen-style documentation.

    Looks for ``@brief`` / ``\\brief`` / ``/**`` patterns in directives
    preceding each function definition.
    """

    def __init__(self):
        super().__init__(QualityDimension.DOCUMENTATION, weight=0.7,
                         priority=Priority.SUGGESTION)
        self.description = "Doxygen documentation coverage"

    def compute(self, cfg) -> Tuple[float, List[QualityFeedback]]:
        issues: List[QualityFeedback] = []

        # Build set of documented line regions from directives
        # (This is a heuristic since Cppcheck doesn't preserve comments.)
        doc_lines: Set[Tuple[str, int]] = set()
        directives = getattr(cfg, "directives", []) or []
        for d in directives:
            d_str = getattr(d, "str", "") or ""
            if any(kw in d_str for kw in ("/**", "/*!", "@brief", "\\brief",
                                          "@param", "\\param", "@return",
                                          "\\return")):
                f = getattr(d, "file", "")
                ln = getattr(d, "linenr", 0) or 0
                # Mark a range of lines as "documented"
                for offset in range(0, 10):
                    doc_lines.add((f, ln + offset))

        total_funcs = 0
        documented_funcs = 0

        for scope in _iter_scopes(cfg):
            if getattr(scope, "type", "") != "Function":
                continue
            func = getattr(scope, "function", None)
            if func is None:
                continue
            total_funcs += 1
            fname = _function_name(func)
            td = getattr(func, "tokenDef", None)
            if td:
                f = getattr(td, "file", "")
                ln = getattr(td, "linenr", 0) or 0
                # Check if any of the few lines before the function are documented
                found = False
                for offset in range(0, 8):
                    if (f, ln - offset) in doc_lines:
                        found = True
                        break
                if found:
                    documented_funcs += 1
                else:
                    issues.append(self.fb(
                        f"Function `{fname}` lacks Doxygen documentation",
                        location=_tok_loc(td),
                        impact=-3.0,
                    ))

        if total_funcs == 0:
            return 100.0, []

        coverage = documented_funcs / total_funcs
        # Score scales linearly: 100% coverage = 100, 0% = 0
        score = _clamp(coverage * 100.0)
        return score, issues


class TodoFixmeMetric(QualityMetric):
    """
    Detect TODO / FIXME / HACK / XXX markers in string literals
    and directives as indicators of incomplete work.
    """

    _MARKERS = re.compile(r"\b(TODO|FIXME|HACK|XXX|BUG|TEMP)\b", re.IGNORECASE)

    def __init__(self):
        super().__init__(QualityDimension.DOCUMENTATION, weight=0.4,
                         priority=Priority.INFO)
        self.description = "TODO/FIXME markers"

    def compute(self, cfg) -> Tuple[float, List[QualityFeedback]]:
        issues: List[QualityFeedback] = []
        count = 0

        # Check directives (some comment-like preprocessor stuff)
        directives = getattr(cfg, "directives", []) or []
        for d in directives:
            d_str = getattr(d, "str", "") or ""
            if self._MARKERS.search(d_str):
                count += 1
                issues.append(self.fb(
                    f"Marker found in directive: `{d_str.strip()[:60]}`",
                    priority=Priority.INFO,
                    location=(
                        getattr(d, "file", "?"),
                        getattr(d, "linenr", 0) or 0,
                    ),
                    impact=-1.0,
                ))

        # Check string literals
        for tok in _iter_tokens(cfg):
            if getattr(tok, "isString", False) and tok.str:
                if self._MARKERS.search(tok.str):
                    count += 1
                    issues.append(self.fb(
                        f"Marker found in string literal: "
                        f"`{tok.str[:40]}`",
                        priority=Priority.INFO,
                        location=_tok_loc(tok),
                        impact=-1.0,
                    ))

        penalty = min(15.0, count * 1.0)
        score = _clamp(100.0 - penalty)
        return score, issues


# ===================================================================
# 10.  Weight Profiles
# ===================================================================

#: Default balanced weight profile — all dimensions weighted equally.
DEFAULT_WEIGHTS: Dict[QualityDimension, float] = {
    QualityDimension.SAFETY: 0.30,
    QualityDimension.MAINTAINABILITY: 0.25,
    QualityDimension.STYLE: 0.15,
    QualityDimension.PERFORMANCE: 0.15,
    QualityDimension.PORTABILITY: 0.08,
    QualityDimension.DOCUMENTATION: 0.07,
}

#: Safety-focused profile (e.g. for embedded / safety-critical code).
SAFETY_WEIGHTS: Dict[QualityDimension, float] = {
    QualityDimension.SAFETY: 0.50,
    QualityDimension.MAINTAINABILITY: 0.20,
    QualityDimension.STYLE: 0.05,
    QualityDimension.PERFORMANCE: 0.10,
    QualityDimension.PORTABILITY: 0.10,
    QualityDimension.DOCUMENTATION: 0.05,
}

#: Style-focused profile (e.g. for open-source / team style enforcement).
STYLE_WEIGHTS: Dict[QualityDimension, float] = {
    QualityDimension.SAFETY: 0.20,
    QualityDimension.MAINTAINABILITY: 0.20,
    QualityDimension.STYLE: 0.30,
    QualityDimension.PERFORMANCE: 0.10,
    QualityDimension.PORTABILITY: 0.05,
    QualityDimension.DOCUMENTATION: 0.15,
}

#: Performance-focused profile (e.g. for HPC / real-time code).
PERFORMANCE_WEIGHTS: Dict[QualityDimension, float] = {
    QualityDimension.SAFETY: 0.20,
    QualityDimension.MAINTAINABILITY: 0.15,
    QualityDimension.STYLE: 0.05,
    QualityDimension.PERFORMANCE: 0.40,
    QualityDimension.PORTABILITY: 0.10,
    QualityDimension.DOCUMENTATION: 0.10,
}


def _normalize_weights(
    weights: Dict[QualityDimension, float],
) -> Dict[QualityDimension, float]:
    """Ensure weights sum to 1.0."""
    total = sum(weights.values())
    if total == 0:
        n = len(QualityDimension)
        return {d: 1.0 / n for d in QualityDimension}
    return {d: w / total for d, w in weights.items()}


# ===================================================================
# 11.  Default Metric Registry
# ===================================================================

def _default_metrics() -> List[QualityMetric]:
    """Return the full set of built-in metrics."""
    return [
        # Safety (6)
        NullDerefMetric(),
        UninitializedUseMetric(),
        MemoryLeakMetric(),
        BufferOverflowMetric(),
        DivisionByZeroMetric(),
        IntegerOverflowMetric(),

        # Maintainability (5)
        FunctionLengthMetric(),
        CyclomaticComplexityMetric(),
        NameConsistencyMetric(),
        NestingDepthMetric(),
        ParameterCountMetric(),

        # Style (6)
        LineLengthMetric(),
        BraceStyleMetric(),
        IndentationConsistencyMetric(),
        NamingConventionMetric(),
        MagicNumberMetric(),
        TrailingWhitespaceMetric(),

        # Performance (4)
        LoopPerformanceMetric(),
        RedundantOpMetric(),
        UnusedVariableMetric(),
        ResourceLeakMetric(),

        # Portability (4)
        CompilerExtensionMetric(),
        PlatformDependencyMetric(),
        TypeSizeAssumptionMetric(),
        NonStandardFunctionMetric(),

        # Documentation (3)
        CommentDensityMetric(),
        DoxygenCoverageMetric(),
        TodoFixmeMetric(),
    ]


# ===================================================================
# 12.  Quality Scorer (main orchestrator)
# ===================================================================

class QualityScorer:
    """
    Orchestrates metric computation and produces a ``ScoringResult``.

    Parameters
    ----------
    weight_profile : dict, optional
        Mapping of ``QualityDimension`` → float weight.  Defaults to
        ``DEFAULT_WEIGHTS``.
    metrics : list of QualityMetric, optional
        Custom metric list.  Defaults to all built-in metrics.
    exclude_metrics : set of str, optional
        Metric names (class names without 'Metric') to exclude.
    exclude_files : set of str, optional
        Glob patterns of files to ignore.
    """

    def __init__(
        self,
        weight_profile: Optional[Dict[QualityDimension, float]] = None,
        metrics: Optional[List[QualityMetric]] = None,
        exclude_metrics: Optional[Set[str]] = None,
        exclude_files: Optional[Set[str]] = None,
    ):
        raw_weights = weight_profile or DEFAULT_WEIGHTS
        # Fill in missing dimensions with zero
        for dim in QualityDimension:
            raw_weights.setdefault(dim, 0.0)
        self.weights = _normalize_weights(raw_weights)

        all_metrics = metrics if metrics is not None else _default_metrics()
        excl = exclude_metrics or set()
        self.metrics = [m for m in all_metrics if m.name not in excl]
        self.exclude_files = exclude_files or set()

    # ------------------------------------------------------------------
    # Translation-unit level scoring
    # ------------------------------------------------------------------

    def score_tu(self, cfg) -> ScoringResult:
        """
        Score a single Cppcheck ``Configuration`` (translation unit).

        Parameters
        ----------
        cfg : cppcheckdata.Configuration
            A parsed dump configuration.

        Returns
        -------
        ScoringResult
        """
        # Group metrics by dimension
        dim_metrics: Dict[QualityDimension,
                          List[QualityMetric]] = defaultdict(list)
        for m in self.metrics:
            dim_metrics[m.dimension].append(m)

        all_feedbacks: List[QualityFeedback] = []
        dimension_scores: Dict[QualityDimension, DimensionScore] = {}

        for dim in QualityDimension:
            metrics_for_dim = dim_metrics.get(dim, [])
            weight = self.weights.get(dim, 0.0)

            if not metrics_for_dim:
                dimension_scores[dim] = DimensionScore(
                    dimension=dim,
                    raw_score=100.0,
                    weighted_score=100.0 * weight,
                    weight=weight,
                )
                continue

            # Compute each metric and aggregate
            dim_feedbacks: List[QualityFeedback] = []
            metric_scores: List[float] = []
            metric_weights: List[float] = []

            for m in metrics_for_dim:
                try:
                    raw, fbs = m.compute(cfg)
                except Exception as exc:
                    # Metric crashed — record and continue
                    raw = 100.0
                    fbs = [QualityFeedback(
                        dimension=dim,
                        priority=Priority.INFO,
                        message=f"Metric {m.name} failed: {exc}",
                        metric_name=m.name,
                    )]

                raw = _clamp(raw)
                metric_scores.append(raw)
                metric_weights.append(m.weight)

                # Filter feedbacks by excluded files
                for fb_item in fbs:
                    if fb_item.location and self.exclude_files:
                        fname = fb_item.location[0]
                        from fnmatch import fnmatch as _fm
                        if any(_fm(fname, pat) for pat in self.exclude_files):
                            continue
                    dim_feedbacks.append(fb_item)

            # Weighted average within the dimension
            total_w = sum(metric_weights)
            if total_w > 0:
                dim_score = sum(
                    s * w for s, w in zip(metric_scores, metric_weights)
                ) / total_w
            else:
                dim_score = 100.0

            dim_score = _clamp(dim_score)
            dimension_scores[dim] = DimensionScore(
                dimension=dim,
                raw_score=dim_score,
                weighted_score=dim_score * weight,
                weight=weight,
                feedbacks=sorted(dim_feedbacks),
            )
            all_feedbacks.extend(dim_feedbacks)

        # Overall score
        overall = sum(ds.weighted_score for ds in dimension_scores.values())
        overall = _clamp(overall)

        # Sort all feedbacks: critical first
        all_feedbacks.sort()

        config_name = getattr(cfg, "name", None)
        return ScoringResult(
            overall_score=overall,
            dimension_scores=dimension_scores,
            feedbacks=all_feedbacks,
            config_name=config_name,
            file_count=self._count_files(cfg),
        )

    # ------------------------------------------------------------------
    # Global / project-level scoring
    # ------------------------------------------------------------------

    def score_global(
        self,
        configs: List,
        aggregation: str = "weighted_mean",
    ) -> ScoringResult:
        """
        Score multiple configurations and aggregate into a single result.

        Parameters
        ----------
        configs : list of Configuration
            Parsed configurations (possibly from different dumps).
        aggregation : str
            ``"weighted_mean"`` (default), ``"min"``, or ``"median"``.

        Returns
        -------
        ScoringResult
        """
        if not configs:
            empty_dims = {
                dim: DimensionScore(
                    dim, 100.0, 100.0 * self.weights.get(dim, 0), self.weights.get(dim, 0))
                for dim in QualityDimension
            }
            return ScoringResult(100.0, empty_dims, [], file_count=0)

        results = [self.score_tu(cfg) for cfg in configs]

        # Aggregate dimension scores
        agg_dims: Dict[QualityDimension, DimensionScore] = {}
        all_fbs: List[QualityFeedback] = []

        for dim in QualityDimension:
            raw_scores = [r.dimension_scores[dim].raw_score for r in results]
            weight = self.weights.get(dim, 0.0)

            if aggregation == "min":
                agg_raw = min(raw_scores)
            elif aggregation == "median":
                agg_raw = statistics.median(raw_scores)
            else:  # weighted_mean by file count
                file_counts = [r.file_count for r in results]
                total_files = sum(file_counts)
                if total_files > 0:
                    agg_raw = sum(
                        s * fc for s, fc in zip(raw_scores, file_counts)
                    ) / total_files
                else:
                    agg_raw = statistics.mean(raw_scores)

            agg_raw = _clamp(agg_raw)
            dim_fbs: List[QualityFeedback] = []
            for r in results:
                dim_fbs.extend(r.dimension_scores[dim].feedbacks)
            dim_fbs.sort()

            agg_dims[dim] = DimensionScore(
                dimension=dim,
                raw_score=agg_raw,
                weighted_score=agg_raw * weight,
                weight=weight,
                feedbacks=dim_fbs,
            )
            all_fbs.extend(dim_fbs)

        overall = sum(ds.weighted_score for ds in agg_dims.values())
        overall = _clamp(overall)
        all_fbs.sort()

        total_files = sum(r.file_count for r in results)
        return ScoringResult(
            overall_score=overall,
            dimension_scores=agg_dims,
            feedbacks=all_fbs,
            config_name="<project>",
            file_count=total_files,
        )

    # ------------------------------------------------------------------
    # Convenience: generate report from a cfg directly
    # ------------------------------------------------------------------

    def report(self, cfg, max_feedbacks: int = 30) -> str:
        """Score *cfg* and return a human-readable report string."""
        return self.score_tu(cfg).generate_report(max_feedbacks)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    @staticmethod
    def _count_files(cfg) -> int:
        files: Set[str] = set()
        for tok in _iter_tokens(cfg):
            f = getattr(tok, "file", None)
            if f:
                files.add(f)
        return max(1, len(files))


# ===================================================================
# 13.  Convenience Functions
# ===================================================================

def score(cfg, **kwargs) -> ScoringResult:
    """
    One-shot convenience: score a configuration with default settings.

    Any *kwargs* are forwarded to ``QualityScorer.__init__``.
    """
    return QualityScorer(**kwargs).score_tu(cfg)


def score_project(configs: List, **kwargs) -> ScoringResult:
    """
    One-shot convenience: score a list of configurations globally.
    """
    return QualityScorer(**kwargs).score_global(configs)


def report(cfg, **kwargs) -> str:
    """
    One-shot convenience: produce a human-readable quality report.
    """
    return QualityScorer(**kwargs).report(cfg)


# ===================================================================
# 14.  CLI entry-point (when run as ``python -m qscore``)
# ===================================================================

def _cli_main() -> None:
    """Minimal CLI: ``python qscore.py <dumpfile> [--profile safety|style|performance]``"""
    import argparse
    import json as _json

    parser = argparse.ArgumentParser(
        description="Compute a quality score from a Cppcheck dump file."
    )
    parser.add_argument("dumpfile", help="Path to .dump file")
    parser.add_argument(
        "--profile",
        choices=["default", "safety", "style", "performance"],
        default="default",
        help="Weight profile (default: %(default)s)",
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Output machine-readable JSON instead of a report",
    )
    parser.add_argument(
        "--max-feedback", type=int, default=30,
        help="Maximum feedback items in report (default: 30)",
    )
    parser.add_argument(
        "--threshold", type=float, default=None,
        help="Exit with code 1 if score < threshold",
    )
    args = parser.parse_args()

    # Select weight profile
    profiles = {
        "default": DEFAULT_WEIGHTS,
        "safety": SAFETY_WEIGHTS,
        "style": STYLE_WEIGHTS,
        "performance": PERFORMANCE_WEIGHTS,
    }
    weights = profiles[args.profile]

    # Parse the dump file
    try:
        import cppcheckdata
    except ImportError:
        print("ERROR: cppcheckdata module not found on sys.path",
              file=__import__("sys").stderr)
        raise SystemExit(1)

    data = cppcheckdata.parsedump(args.dumpfile)
    scorer = QualityScorer(weight_profile=weights)

    configs = data.configurations if hasattr(
        data, "configurations") else [data]
    if len(configs) == 1:
        result = scorer.score_tu(configs[0])
    else:
        result = scorer.score_global(configs)

    if args.json:
        print(_json.dumps(result.to_dict(), indent=2))
    else:
        print(result.generate_report(max_feedbacks=args.max_feedback))

    if args.threshold is not None and result.overall_score < args.threshold:
        raise SystemExit(1)


if __name__ == "__main__":
    _cli_main()
