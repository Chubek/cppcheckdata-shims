# casl/errors.py
"""
CASL/CSQL Error Types and Reporting Module

This module provides a comprehensive error handling infrastructure for the CASL
(Cppcheck Abstract Specification Language) and CSQL (Code Structure Query Language)
compiler pipeline. It integrates with the existing cppcheckdata-shims diagnostic
model while providing specialized error types for each compilation phase.

Architecture Overview:
─────────────────────
┌─────────────────────────────────────────────────────────────────────────────┐
│                          Error Hierarchy                                     │
├─────────────────────────────────────────────────────────────────────────────┤
│  CaslError (base)                                                           │
│  ├── LexicalError      - Tokenization failures                              │
│  ├── SyntaxError       - Parse-time grammar violations                      │
│  ├── SemanticError     - Type/scope/binding errors                          │
│  │   ├── TypeError     - Type mismatch/inference failure                    │
│  │   ├── ScopeError    - Undefined/redefined symbols                        │
│  │   └── BindingError  - Pattern binding failures                           │
│  ├── CodeGenError      - Bytecode emission failures                         │
│  ├── RuntimeError      - Execution-time errors                              │
│  └── InternalError     - Compiler bugs (should never happen)                │
└─────────────────────────────────────────────────────────────────────────────┘

Error Codes:
────────────
Each error has a unique code following the pattern: CASL-XXXX or CSQL-XXXX
where XXXX is a 4-digit number in ranges:
  - 0001-0999: Lexical errors
  - 1000-1999: Syntax errors
  - 2000-2999: Semantic errors (type)
  - 3000-3999: Semantic errors (scope/binding)
  - 4000-4999: Code generation errors
  - 5000-5999: Runtime errors
  - 9000-9999: Internal compiler errors

Integration:
────────────
This module integrates with:
  - DiagnosticSeverity, Confidence, SourceLocation from cppcheckdata-shims
  - Diagnostic dataclass for unified error reporting
  - Checker infrastructure for error emission

Example Usage:
──────────────
    from casl.errors import (
        CaslError, SyntaxError, TypeError, ErrorReporter,
        ErrorCode, SourceSpan
    )
    
    # Create an error reporter
    reporter = ErrorReporter(source_file="check.casl")
    
    # Report a syntax error
    reporter.error(
        ErrorCode.UNEXPECTED_TOKEN,
        span=SourceSpan(line=10, column=5, end_column=12),
        message="Expected 'then' after condition",
        hint="Did you mean to write 'if cond then action'?"
    )
    
    # Check if compilation can continue
    if reporter.has_fatal_errors():
        raise reporter.as_exception()
    
    # Get all diagnostics for cppcheck integration
    diagnostics = reporter.to_diagnostics()

Author: CASL Compiler Team
Version: 1.0.0
"""

from __future__ import annotations

import json
import sys
import traceback
from dataclasses import dataclass, field
from enum import Enum, auto, unique
from pathlib import Path
from typing import (
    Any,
    Callable,
    ClassVar,
    Dict,
    FrozenSet,
    Iterator,
    List,
    Mapping,
    NamedTuple,
    Optional,
    Protocol,
    Sequence,
    Set,
    Tuple,
    Type,
    TypeVar,
    Union,
    runtime_checkable,
)

# ═══════════════════════════════════════════════════════════════════════════════
# TYPE ALIASES AND FORWARD REFERENCES
# ═══════════════════════════════════════════════════════════════════════════════

# For integration with cppcheckdata-shims (forward references)
# These will be imported at runtime if available
DiagnosticSeverity: Any = None
Confidence: Any = None
SourceLocation: Any = None
Diagnostic: Any = None

def _try_import_diagnostics() -> bool:
    """Attempt to import diagnostic types from cppcheckdata-shims."""
    global DiagnosticSeverity, Confidence, SourceLocation, Diagnostic
    try:
        # Try importing from the main module
        from cppcheckdata_shims import (
            DiagnosticSeverity as DS,
            Confidence as C,
            SourceLocation as SL,
            Diagnostic as D,
        )
        DiagnosticSeverity = DS
        Confidence = C
        SourceLocation = SL
        Diagnostic = D
        return True
    except ImportError:
        return False

# Try import at module load time
_DIAGNOSTICS_AVAILABLE = _try_import_diagnostics()


# ═══════════════════════════════════════════════════════════════════════════════
# ERROR SEVERITY AND CLASSIFICATION
# ═══════════════════════════════════════════════════════════════════════════════

@unique
class ErrorSeverity(Enum):
    """
    Severity levels for CASL/CSQL errors.
    
    Maps to cppcheck DiagnosticSeverity when available, otherwise provides
    standalone severity classification.
    """
    
    # Fatal errors that prevent compilation
    FATAL = "fatal"
    
    # Standard errors that must be fixed
    ERROR = "error"
    
    # Warnings that indicate potential issues
    WARNING = "warning"
    
    # Style suggestions for better code
    STYLE = "style"
    
    # Informational messages
    INFO = "info"
    
    # Debug/internal messages
    DEBUG = "debug"
    
    def __lt__(self, other: "ErrorSeverity") -> bool:
        """Allow severity comparison (FATAL > ERROR > WARNING > ...)."""
        order = [
            ErrorSeverity.DEBUG,
            ErrorSeverity.INFO,
            ErrorSeverity.STYLE,
            ErrorSeverity.WARNING,
            ErrorSeverity.ERROR,
            ErrorSeverity.FATAL,
        ]
        return order.index(self) < order.index(other)
    
    def is_error(self) -> bool:
        """Check if this severity represents an error (not warning/info)."""
        return self in (ErrorSeverity.FATAL, ErrorSeverity.ERROR)
    
    def to_diagnostic_severity(self) -> Any:
        """Convert to cppcheck DiagnosticSeverity if available."""
        if not _DIAGNOSTICS_AVAILABLE:
            return self.value
        
        mapping = {
            ErrorSeverity.FATAL: DiagnosticSeverity.ERROR,
            ErrorSeverity.ERROR: DiagnosticSeverity.ERROR,
            ErrorSeverity.WARNING: DiagnosticSeverity.WARNING,
            ErrorSeverity.STYLE: DiagnosticSeverity.STYLE,
            ErrorSeverity.INFO: DiagnosticSeverity.INFORMATION,
            ErrorSeverity.DEBUG: DiagnosticSeverity.INFORMATION,
        }
        return mapping.get(self, DiagnosticSeverity.ERROR)


@unique
class ErrorPhase(Enum):
    """
    Compilation phase where the error occurred.
    
    This helps with error categorization and debugging.
    """
    
    LEXICAL = "lexical"        # Tokenization
    SYNTAX = "syntax"          # Parsing
    SEMANTIC = "semantic"      # Type checking, scope resolution
    CODEGEN = "codegen"        # Bytecode generation
    RUNTIME = "runtime"        # Execution
    INTERNAL = "internal"      # Compiler internals


@unique
class ErrorCategory(Enum):
    """
    Fine-grained error categories for filtering and statistics.
    """
    
    # Lexical categories
    INVALID_CHARACTER = auto()
    UNTERMINATED_STRING = auto()
    UNTERMINATED_COMMENT = auto()
    INVALID_ESCAPE = auto()
    INVALID_NUMBER = auto()
    
    # Syntax categories
    UNEXPECTED_TOKEN = auto()
    MISSING_TOKEN = auto()
    UNEXPECTED_EOF = auto()
    INVALID_EXPRESSION = auto()
    INVALID_STATEMENT = auto()
    INVALID_DECLARATION = auto()
    INVALID_PATTERN = auto()
    
    # Semantic categories - Type
    TYPE_MISMATCH = auto()
    INCOMPATIBLE_TYPES = auto()
    INVALID_CAST = auto()
    INFERENCE_FAILURE = auto()
    RECURSIVE_TYPE = auto()
    
    # Semantic categories - Scope
    UNDEFINED_SYMBOL = auto()
    REDEFINED_SYMBOL = auto()
    INVALID_SCOPE = auto()
    FORWARD_REFERENCE = auto()
    CIRCULAR_DEPENDENCY = auto()
    
    # Semantic categories - Binding
    BINDING_FAILURE = auto()
    PATTERN_MISMATCH = auto()
    ARITY_MISMATCH = auto()
    
    # Semantic categories - Property
    INVALID_PROPERTY = auto()
    UNSATISFIABLE_PROPERTY = auto()
    AMBIGUOUS_PROPERTY = auto()
    
    # Code generation categories
    INVALID_TARGET = auto()
    REGISTER_OVERFLOW = auto()
    STACK_OVERFLOW = auto()
    INVALID_INSTRUCTION = auto()
    UNSUPPORTED_FEATURE = auto()
    
    # Runtime categories
    EXECUTION_ERROR = auto()
    ASSERTION_FAILURE = auto()
    TIMEOUT = auto()
    MEMORY_ERROR = auto()
    
    # Internal categories
    INTERNAL_ERROR = auto()
    ASSERTION_VIOLATED = auto()
    INVARIANT_BROKEN = auto()


# ═══════════════════════════════════════════════════════════════════════════════
# ERROR CODES
# ═══════════════════════════════════════════════════════════════════════════════

class ErrorCode:
    """
    Structured error codes for CASL/CSQL errors.
    
    Error codes follow the pattern PREFIX-NNNN where:
      - PREFIX is CASL or CSQL
      - NNNN is a 4-digit number
    
    Ranges:
      - 0001-0999: Lexical errors
      - 1000-1999: Syntax errors  
      - 2000-2999: Type errors
      - 3000-3999: Scope/binding errors
      - 4000-4999: Code generation errors
      - 5000-5999: Runtime errors
      - 9000-9999: Internal errors
    """
    
    __slots__ = ("prefix", "number", "category", "phase", "default_severity", "cwe")
    
    def __init__(
        self,
        prefix: str,
        number: int,
        category: ErrorCategory,
        phase: ErrorPhase,
        default_severity: ErrorSeverity = ErrorSeverity.ERROR,
        cwe: int = 0,
    ) -> None:
        self.prefix = prefix
        self.number = number
        self.category = category
        self.phase = phase
        self.default_severity = default_severity
        self.cwe = cwe
    
    @property
    def code(self) -> str:
        """Get the full error code string."""
        return f"{self.prefix}-{self.number:04d}"
    
    def __str__(self) -> str:
        return self.code
    
    def __repr__(self) -> str:
        return f"ErrorCode({self.code!r}, {self.category.name})"
    
    def __hash__(self) -> int:
        return hash((self.prefix, self.number))
    
    def __eq__(self, other: object) -> bool:
        if isinstance(other, ErrorCode):
            return self.prefix == other.prefix and self.number == other.number
        if isinstance(other, str):
            return self.code == other
        return False


# ───────────────────────────────────────────────────────────────────────────────
# PREDEFINED ERROR CODES
# ───────────────────────────────────────────────────────────────────────────────

class CaslErrorCodes:
    """Predefined error codes for CASL language."""
    
    # ═══════════════════════════════════════════════════════════════════════════
    # LEXICAL ERRORS (0001-0999)
    # ═══════════════════════════════════════════════════════════════════════════
    
    INVALID_CHARACTER = ErrorCode(
        "CASL", 1, ErrorCategory.INVALID_CHARACTER, ErrorPhase.LEXICAL
    )
    UNTERMINATED_STRING = ErrorCode(
        "CASL", 2, ErrorCategory.UNTERMINATED_STRING, ErrorPhase.LEXICAL
    )
    UNTERMINATED_COMMENT = ErrorCode(
        "CASL", 3, ErrorCategory.UNTERMINATED_COMMENT, ErrorPhase.LEXICAL
    )
    INVALID_ESCAPE_SEQUENCE = ErrorCode(
        "CASL", 4, ErrorCategory.INVALID_ESCAPE, ErrorPhase.LEXICAL
    )
    INVALID_NUMBER_LITERAL = ErrorCode(
        "CASL", 5, ErrorCategory.INVALID_NUMBER, ErrorPhase.LEXICAL
    )
    INVALID_IDENTIFIER = ErrorCode(
        "CASL", 6, ErrorCategory.INVALID_CHARACTER, ErrorPhase.LEXICAL
    )
    UNTERMINATED_REGEX = ErrorCode(
        "CASL", 7, ErrorCategory.UNTERMINATED_STRING, ErrorPhase.LEXICAL
    )
    
    # ═══════════════════════════════════════════════════════════════════════════
    # SYNTAX ERRORS (1000-1999)
    # ═══════════════════════════════════════════════════════════════════════════
    
    UNEXPECTED_TOKEN = ErrorCode(
        "CASL", 1000, ErrorCategory.UNEXPECTED_TOKEN, ErrorPhase.SYNTAX
    )
    MISSING_TOKEN = ErrorCode(
        "CASL", 1001, ErrorCategory.MISSING_TOKEN, ErrorPhase.SYNTAX
    )
    UNEXPECTED_EOF = ErrorCode(
        "CASL", 1002, ErrorCategory.UNEXPECTED_EOF, ErrorPhase.SYNTAX
    )
    INVALID_EXPRESSION = ErrorCode(
        "CASL", 1003, ErrorCategory.INVALID_EXPRESSION, ErrorPhase.SYNTAX
    )
    INVALID_STATEMENT = ErrorCode(
        "CASL", 1004, ErrorCategory.INVALID_STATEMENT, ErrorPhase.SYNTAX
    )
    INVALID_DECLARATION = ErrorCode(
        "CASL", 1005, ErrorCategory.INVALID_DECLARATION, ErrorPhase.SYNTAX
    )
    INVALID_PATTERN = ErrorCode(
        "CASL", 1006, ErrorCategory.INVALID_PATTERN, ErrorPhase.SYNTAX
    )
    INVALID_PROPERTY_SYNTAX = ErrorCode(
        "CASL", 1007, ErrorCategory.INVALID_STATEMENT, ErrorPhase.SYNTAX
    )
    INVALID_TEMPORAL_OPERATOR = ErrorCode(
        "CASL", 1008, ErrorCategory.INVALID_EXPRESSION, ErrorPhase.SYNTAX
    )
    MISSING_PROPERTY_BODY = ErrorCode(
        "CASL", 1009, ErrorCategory.MISSING_TOKEN, ErrorPhase.SYNTAX
    )
    DUPLICATE_MODIFIER = ErrorCode(
        "CASL", 1010, ErrorCategory.INVALID_DECLARATION, ErrorPhase.SYNTAX,
        ErrorSeverity.WARNING
    )
    INVALID_ANNOTATION = ErrorCode(
        "CASL", 1011, ErrorCategory.INVALID_DECLARATION, ErrorPhase.SYNTAX
    )
    UNBALANCED_BRACKETS = ErrorCode(
        "CASL", 1012, ErrorCategory.MISSING_TOKEN, ErrorPhase.SYNTAX
    )
    INVALID_OPERATOR = ErrorCode(
        "CASL", 1013, ErrorCategory.INVALID_EXPRESSION, ErrorPhase.SYNTAX
    )
    
    # ═══════════════════════════════════════════════════════════════════════════
    # TYPE ERRORS (2000-2999)
    # ═══════════════════════════════════════════════════════════════════════════
    
    TYPE_MISMATCH = ErrorCode(
        "CASL", 2000, ErrorCategory.TYPE_MISMATCH, ErrorPhase.SEMANTIC
    )
    INCOMPATIBLE_OPERAND_TYPES = ErrorCode(
        "CASL", 2001, ErrorCategory.INCOMPATIBLE_TYPES, ErrorPhase.SEMANTIC
    )
    INVALID_TYPE_CAST = ErrorCode(
        "CASL", 2002, ErrorCategory.INVALID_CAST, ErrorPhase.SEMANTIC
    )
    TYPE_INFERENCE_FAILURE = ErrorCode(
        "CASL", 2003, ErrorCategory.INFERENCE_FAILURE, ErrorPhase.SEMANTIC
    )
    RECURSIVE_TYPE_DETECTED = ErrorCode(
        "CASL", 2004, ErrorCategory.RECURSIVE_TYPE, ErrorPhase.SEMANTIC
    )
    INVALID_PROPERTY_TYPE = ErrorCode(
        "CASL", 2005, ErrorCategory.TYPE_MISMATCH, ErrorPhase.SEMANTIC
    )
    EXPECTED_BOOLEAN = ErrorCode(
        "CASL", 2006, ErrorCategory.TYPE_MISMATCH, ErrorPhase.SEMANTIC
    )
    EXPECTED_PREDICATE = ErrorCode(
        "CASL", 2007, ErrorCategory.TYPE_MISMATCH, ErrorPhase.SEMANTIC
    )
    INVALID_EVENT_TYPE = ErrorCode(
        "CASL", 2008, ErrorCategory.TYPE_MISMATCH, ErrorPhase.SEMANTIC
    )
    MISSING_TYPE_ANNOTATION = ErrorCode(
        "CASL", 2009, ErrorCategory.INFERENCE_FAILURE, ErrorPhase.SEMANTIC
    )
    CONFLICTING_TYPES = ErrorCode(
        "CASL", 2010, ErrorCategory.INCOMPATIBLE_TYPES, ErrorPhase.SEMANTIC
    )
    
    # ═══════════════════════════════════════════════════════════════════════════
    # SCOPE/BINDING ERRORS (3000-3999)
    # ═══════════════════════════════════════════════════════════════════════════
    
    UNDEFINED_SYMBOL = ErrorCode(
        "CASL", 3000, ErrorCategory.UNDEFINED_SYMBOL, ErrorPhase.SEMANTIC
    )
    UNDEFINED_PROPERTY = ErrorCode(
        "CASL", 3001, ErrorCategory.UNDEFINED_SYMBOL, ErrorPhase.SEMANTIC
    )
    UNDEFINED_EVENT = ErrorCode(
        "CASL", 3002, ErrorCategory.UNDEFINED_SYMBOL, ErrorPhase.SEMANTIC
    )
    UNDEFINED_OBSERVER = ErrorCode(
        "CASL", 3003, ErrorCategory.UNDEFINED_SYMBOL, ErrorPhase.SEMANTIC
    )
    REDEFINED_SYMBOL = ErrorCode(
        "CASL", 3004, ErrorCategory.REDEFINED_SYMBOL, ErrorPhase.SEMANTIC
    )
    REDEFINED_PROPERTY = ErrorCode(
        "CASL", 3005, ErrorCategory.REDEFINED_SYMBOL, ErrorPhase.SEMANTIC
    )
    INVALID_SCOPE_ACCESS = ErrorCode(
        "CASL", 3006, ErrorCategory.INVALID_SCOPE, ErrorPhase.SEMANTIC
    )
    FORWARD_REFERENCE = ErrorCode(
        "CASL", 3007, ErrorCategory.FORWARD_REFERENCE, ErrorPhase.SEMANTIC,
        ErrorSeverity.WARNING
    )
    CIRCULAR_DEPENDENCY = ErrorCode(
        "CASL", 3008, ErrorCategory.CIRCULAR_DEPENDENCY, ErrorPhase.SEMANTIC
    )
    BINDING_FAILURE = ErrorCode(
        "CASL", 3009, ErrorCategory.BINDING_FAILURE, ErrorPhase.SEMANTIC
    )
    PATTERN_BINDING_FAILURE = ErrorCode(
        "CASL", 3010, ErrorCategory.PATTERN_MISMATCH, ErrorPhase.SEMANTIC
    )
    ARITY_MISMATCH = ErrorCode(
        "CASL", 3011, ErrorCategory.ARITY_MISMATCH, ErrorPhase.SEMANTIC
    )
    SHADOWED_BINDING = ErrorCode(
        "CASL", 3012, ErrorCategory.REDEFINED_SYMBOL, ErrorPhase.SEMANTIC,
        ErrorSeverity.WARNING
    )
    
    # ═══════════════════════════════════════════════════════════════════════════
    # PROPERTY ERRORS (3500-3999)
    # ═══════════════════════════════════════════════════════════════════════════
    
    INVALID_PROPERTY_SPEC = ErrorCode(
        "CASL", 3500, ErrorCategory.INVALID_PROPERTY, ErrorPhase.SEMANTIC
    )
    UNSATISFIABLE_PROPERTY = ErrorCode(
        "CASL", 3501, ErrorCategory.UNSATISFIABLE_PROPERTY, ErrorPhase.SEMANTIC
    )
    AMBIGUOUS_PROPERTY = ErrorCode(
        "CASL", 3502, ErrorCategory.AMBIGUOUS_PROPERTY, ErrorPhase.SEMANTIC,
        ErrorSeverity.WARNING
    )
    CONFLICTING_PROPERTIES = ErrorCode(
        "CASL", 3503, ErrorCategory.INVALID_PROPERTY, ErrorPhase.SEMANTIC
    )
    INVALID_TEMPORAL_SCOPE = ErrorCode(
        "CASL", 3504, ErrorCategory.INVALID_PROPERTY, ErrorPhase.SEMANTIC
    )
    MISSING_TRIGGER = ErrorCode(
        "CASL", 3505, ErrorCategory.INVALID_PROPERTY, ErrorPhase.SEMANTIC
    )
    INVALID_RESPONSE = ErrorCode(
        "CASL", 3506, ErrorCategory.INVALID_PROPERTY, ErrorPhase.SEMANTIC
    )
    
    # ═══════════════════════════════════════════════════════════════════════════
    # CODE GENERATION ERRORS (4000-4999)
    # ═══════════════════════════════════════════════════════════════════════════
    
    CODEGEN_FAILURE = ErrorCode(
        "CASL", 4000, ErrorCategory.INVALID_TARGET, ErrorPhase.CODEGEN
    )
    REGISTER_EXHAUSTION = ErrorCode(
        "CASL", 4001, ErrorCategory.REGISTER_OVERFLOW, ErrorPhase.CODEGEN
    )
    STACK_LIMIT_EXCEEDED = ErrorCode(
        "CASL", 4002, ErrorCategory.STACK_OVERFLOW, ErrorPhase.CODEGEN
    )
    INVALID_INSTRUCTION_ENCODING = ErrorCode(
        "CASL", 4003, ErrorCategory.INVALID_INSTRUCTION, ErrorPhase.CODEGEN
    )
    UNSUPPORTED_FEATURE = ErrorCode(
        "CASL", 4004, ErrorCategory.UNSUPPORTED_FEATURE, ErrorPhase.CODEGEN
    )
    LABEL_RESOLUTION_FAILURE = ErrorCode(
        "CASL", 4005, ErrorCategory.INVALID_TARGET, ErrorPhase.CODEGEN
    )
    INVALID_JUMP_TARGET = ErrorCode(
        "CASL", 4006, ErrorCategory.INVALID_TARGET, ErrorPhase.CODEGEN
    )
    STATE_MACHINE_ERROR = ErrorCode(
        "CASL", 4007, ErrorCategory.INVALID_TARGET, ErrorPhase.CODEGEN
    )
    BYTECODE_VALIDATION_FAILURE = ErrorCode(
        "CASL", 4008, ErrorCategory.INVALID_INSTRUCTION, ErrorPhase.CODEGEN
    )
    
    # ═══════════════════════════════════════════════════════════════════════════
    # RUNTIME ERRORS (5000-5999)
    # ═══════════════════════════════════════════════════════════════════════════
    
    RUNTIME_ERROR = ErrorCode(
        "CASL", 5000, ErrorCategory.EXECUTION_ERROR, ErrorPhase.RUNTIME
    )
    ASSERTION_FAILURE = ErrorCode(
        "CASL", 5001, ErrorCategory.ASSERTION_FAILURE, ErrorPhase.RUNTIME,
        cwe=617  # CWE-617: Reachable Assertion
    )
    PROPERTY_VIOLATION = ErrorCode(
        "CASL", 5002, ErrorCategory.ASSERTION_FAILURE, ErrorPhase.RUNTIME
    )
    TIMEOUT_EXCEEDED = ErrorCode(
        "CASL", 5003, ErrorCategory.TIMEOUT, ErrorPhase.RUNTIME
    )
    MEMORY_LIMIT_EXCEEDED = ErrorCode(
        "CASL", 5004, ErrorCategory.MEMORY_ERROR, ErrorPhase.RUNTIME
    )
    OBSERVER_ERROR = ErrorCode(
        "CASL", 5005, ErrorCategory.EXECUTION_ERROR, ErrorPhase.RUNTIME
    )
    EVENT_DISPATCH_ERROR = ErrorCode(
        "CASL", 5006, ErrorCategory.EXECUTION_ERROR, ErrorPhase.RUNTIME
    )
    
    # ═══════════════════════════════════════════════════════════════════════════
    # INTERNAL ERRORS (9000-9999)
    # ═══════════════════════════════════════════════════════════════════════════
    
    INTERNAL_ERROR = ErrorCode(
        "CASL", 9000, ErrorCategory.INTERNAL_ERROR, ErrorPhase.INTERNAL,
        ErrorSeverity.FATAL
    )
    INTERNAL_ASSERTION = ErrorCode(
        "CASL", 9001, ErrorCategory.ASSERTION_VIOLATED, ErrorPhase.INTERNAL,
        ErrorSeverity.FATAL
    )
    INVARIANT_VIOLATION = ErrorCode(
        "CASL", 9002, ErrorCategory.INVARIANT_BROKEN, ErrorPhase.INTERNAL,
        ErrorSeverity.FATAL
    )
    UNREACHABLE_CODE = ErrorCode(
        "CASL", 9003, ErrorCategory.INTERNAL_ERROR, ErrorPhase.INTERNAL,
        ErrorSeverity.FATAL
    )
    NOT_IMPLEMENTED = ErrorCode(
        "CASL", 9004, ErrorCategory.UNSUPPORTED_FEATURE, ErrorPhase.INTERNAL,
        ErrorSeverity.FATAL
    )


class CsqlErrorCodes:
    """Predefined error codes for CSQL language."""
    
    # ═══════════════════════════════════════════════════════════════════════════
    # LEXICAL ERRORS (0001-0999)
    # ═══════════════════════════════════════════════════════════════════════════
    
    INVALID_CHARACTER = ErrorCode(
        "CSQL", 1, ErrorCategory.INVALID_CHARACTER, ErrorPhase.LEXICAL
    )
    UNTERMINATED_STRING = ErrorCode(
        "CSQL", 2, ErrorCategory.UNTERMINATED_STRING, ErrorPhase.LEXICAL
    )
    INVALID_PATTERN_LITERAL = ErrorCode(
        "CSQL", 3, ErrorCategory.INVALID_CHARACTER, ErrorPhase.LEXICAL
    )
    
    # ═══════════════════════════════════════════════════════════════════════════
    # SYNTAX ERRORS (1000-1999)
    # ═══════════════════════════════════════════════════════════════════════════
    
    UNEXPECTED_TOKEN = ErrorCode(
        "CSQL", 1000, ErrorCategory.UNEXPECTED_TOKEN, ErrorPhase.SYNTAX
    )
    MISSING_TOKEN = ErrorCode(
        "CSQL", 1001, ErrorCategory.MISSING_TOKEN, ErrorPhase.SYNTAX
    )
    UNEXPECTED_EOF = ErrorCode(
        "CSQL", 1002, ErrorCategory.UNEXPECTED_EOF, ErrorPhase.SYNTAX
    )
    INVALID_QUERY_SYNTAX = ErrorCode(
        "CSQL", 1003, ErrorCategory.INVALID_EXPRESSION, ErrorPhase.SYNTAX
    )
    INVALID_PATH_PATTERN = ErrorCode(
        "CSQL", 1004, ErrorCategory.INVALID_PATTERN, ErrorPhase.SYNTAX
    )
    INVALID_NODE_PATTERN = ErrorCode(
        "CSQL", 1005, ErrorCategory.INVALID_PATTERN, ErrorPhase.SYNTAX
    )
    INVALID_EDGE_PATTERN = ErrorCode(
        "CSQL", 1006, ErrorCategory.INVALID_PATTERN, ErrorPhase.SYNTAX
    )
    INVALID_QUANTIFIER = ErrorCode(
        "CSQL", 1007, ErrorCategory.INVALID_EXPRESSION, ErrorPhase.SYNTAX
    )
    INVALID_FILTER = ErrorCode(
        "CSQL", 1008, ErrorCategory.INVALID_EXPRESSION, ErrorPhase.SYNTAX
    )
    MISSING_MATCH_CLAUSE = ErrorCode(
        "CSQL", 1009, ErrorCategory.MISSING_TOKEN, ErrorPhase.SYNTAX
    )
    
    # ═══════════════════════════════════════════════════════════════════════════
    # TYPE ERRORS (2000-2999)
    # ═══════════════════════════════════════════════════════════════════════════
    
    TYPE_MISMATCH = ErrorCode(
        "CSQL", 2000, ErrorCategory.TYPE_MISMATCH, ErrorPhase.SEMANTIC
    )
    INVALID_NODE_TYPE = ErrorCode(
        "CSQL", 2001, ErrorCategory.TYPE_MISMATCH, ErrorPhase.SEMANTIC
    )
    INVALID_EDGE_TYPE = ErrorCode(
        "CSQL", 2002, ErrorCategory.TYPE_MISMATCH, ErrorPhase.SEMANTIC
    )
    INVALID_PROPERTY_ACCESS = ErrorCode(
        "CSQL", 2003, ErrorCategory.TYPE_MISMATCH, ErrorPhase.SEMANTIC
    )
    INVALID_AGGREGATION = ErrorCode(
        "CSQL", 2004, ErrorCategory.TYPE_MISMATCH, ErrorPhase.SEMANTIC
    )
    
    # ═══════════════════════════════════════════════════════════════════════════
    # SCOPE/BINDING ERRORS (3000-3999)
    # ═══════════════════════════════════════════════════════════════════════════
    
    UNDEFINED_VARIABLE = ErrorCode(
        "CSQL", 3000, ErrorCategory.UNDEFINED_SYMBOL, ErrorPhase.SEMANTIC
    )
    UNDEFINED_LABEL = ErrorCode(
        "CSQL", 3001, ErrorCategory.UNDEFINED_SYMBOL, ErrorPhase.SEMANTIC
    )
    UNDEFINED_PROPERTY = ErrorCode(
        "CSQL", 3002, ErrorCategory.UNDEFINED_SYMBOL, ErrorPhase.SEMANTIC
    )
    REDEFINED_VARIABLE = ErrorCode(
        "CSQL", 3003, ErrorCategory.REDEFINED_SYMBOL, ErrorPhase.SEMANTIC
    )
    BINDING_AMBIGUITY = ErrorCode(
        "CSQL", 3004, ErrorCategory.BINDING_FAILURE, ErrorPhase.SEMANTIC
    )
    UNBOUND_VARIABLE = ErrorCode(
        "CSQL", 3005, ErrorCategory.BINDING_FAILURE, ErrorPhase.SEMANTIC
    )
    
    # ═══════════════════════════════════════════════════════════════════════════
    # CODE GENERATION ERRORS (4000-4999)
    # ═══════════════════════════════════════════════════════════════════════════
    
    CODEGEN_FAILURE = ErrorCode(
        "CSQL", 4000, ErrorCategory.INVALID_TARGET, ErrorPhase.CODEGEN
    )
    PATTERN_COMPILATION_FAILURE = ErrorCode(
        "CSQL", 4001, ErrorCategory.INVALID_TARGET, ErrorPhase.CODEGEN
    )
    QUERY_OPTIMIZATION_FAILURE = ErrorCode(
        "CSQL", 4002, ErrorCategory.INVALID_TARGET, ErrorPhase.CODEGEN,
        ErrorSeverity.WARNING
    )
    
    # ═══════════════════════════════════════════════════════════════════════════
    # RUNTIME ERRORS (5000-5999)
    # ═══════════════════════════════════════════════════════════════════════════
    
    RUNTIME_ERROR = ErrorCode(
        "CSQL", 5000, ErrorCategory.EXECUTION_ERROR, ErrorPhase.RUNTIME
    )
    QUERY_EXECUTION_ERROR = ErrorCode(
        "CSQL", 5001, ErrorCategory.EXECUTION_ERROR, ErrorPhase.RUNTIME
    )
    RESULT_LIMIT_EXCEEDED = ErrorCode(
        "CSQL", 5002, ErrorCategory.MEMORY_ERROR, ErrorPhase.RUNTIME
    )
    TIMEOUT_EXCEEDED = ErrorCode(
        "CSQL", 5003, ErrorCategory.TIMEOUT, ErrorPhase.RUNTIME
    )
    
    # ═══════════════════════════════════════════════════════════════════════════
    # INTERNAL ERRORS (9000-9999)
    # ═══════════════════════════════════════════════════════════════════════════
    
    INTERNAL_ERROR = ErrorCode(
        "CSQL", 9000, ErrorCategory.INTERNAL_ERROR, ErrorPhase.INTERNAL,
        ErrorSeverity.FATAL
    )


# Convenient access to error codes
E = CaslErrorCodes
Q = CsqlErrorCodes


# ═══════════════════════════════════════════════════════════════════════════════
# SOURCE LOCATION TYPES
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class SourceSpan:
    """
    A span of source code with start and end positions.
    
    This is richer than SourceLocation as it captures a range,
    which is useful for highlighting error locations in editors.
    """
    
    file: str = ""
    line: int = 0
    column: int = 0
    end_line: int = 0
    end_column: int = 0
    
    def __post_init__(self) -> None:
        # Normalize: if end not specified, use start
        if self.end_line == 0:
            object.__setattr__(self, "end_line", self.line)
        if self.end_column == 0:
            object.__setattr__(self, "end_column", self.column)
    
    @classmethod
    def from_token(cls, token: Any) -> "SourceSpan":
        """Create a SourceSpan from a token object."""
        if hasattr(token, "file"):
            file = token.file
        elif hasattr(token, "filename"):
            file = token.filename
        else:
            file = ""
        
        line = getattr(token, "line", 0) or getattr(token, "linenr", 0) or 0
        col = getattr(token, "column", 0) or getattr(token, "col", 0) or 0
        
        # Try to get end position
        end_line = getattr(token, "end_line", line)
        end_col = getattr(token, "end_column", col)
        
        return cls(file=file, line=line, column=col, 
                   end_line=end_line, end_column=end_col)
    
    @classmethod
    def from_node(cls, node: Any) -> "SourceSpan":
        """Create a SourceSpan from an AST node."""
        if hasattr(node, "span"):
            return node.span
        if hasattr(node, "loc"):
            loc = node.loc
            return cls(
                file=getattr(loc, "file", ""),
                line=getattr(loc, "line", 0),
                column=getattr(loc, "column", 0),
            )
        if hasattr(node, "token"):
            return cls.from_token(node.token)
        return cls()
    
    @classmethod
    def merge(cls, *spans: "SourceSpan") -> "SourceSpan":
        """Merge multiple spans into one that covers all of them."""
        if not spans:
            return cls()
        
        # Get the file from the first non-empty span
        file = next((s.file for s in spans if s.file), "")
        
        # Find min start and max end
        min_line = min(s.line for s in spans if s.line > 0) if any(s.line > 0 for s in spans) else 0
        max_end_line = max(s.end_line for s in spans)
        
        # For columns, find the column at the min line
        min_col = 0
        max_end_col = 0
        
        for s in spans:
            if s.line == min_line and (min_col == 0 or s.column < min_col):
                min_col = s.column
            if s.end_line == max_end_line and s.end_column > max_end_col:
                max_end_col = s.end_column
        
        return cls(
            file=file,
            line=min_line,
            column=min_col,
            end_line=max_end_line,
            end_column=max_end_col,
        )
    
    def to_source_location(self) -> Any:
        """Convert to cppcheckdata-shims SourceLocation if available."""
        if _DIAGNOSTICS_AVAILABLE:
            return SourceLocation(
                file=self.file,
                line=self.line,
                column=self.column,
            )
        return self
    
    def __str__(self) -> str:
        if not self.file and self.line == 0:
            return "<unknown location>"
        
        parts = []
        if self.file:
            parts.append(self.file)
        if self.line > 0:
            parts.append(str(self.line))
            if self.column > 0:
                parts.append(str(self.column))
        
        return ":".join(parts)
    
    def to_range_string(self) -> str:
        """Get a string representation showing the full range."""
        start = str(self)
        if self.end_line > self.line or (self.end_line == self.line and self.end_column > self.column):
            return f"{start}-{self.end_line}:{self.end_column}"
        return start


# ═══════════════════════════════════════════════════════════════════════════════
# ERROR MESSAGE FORMATTING
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class ErrorNote:
    """
    Additional note attached to an error.
    
    Notes provide extra context, such as where a symbol was originally defined,
    or what the expected type was.
    """
    
    message: str
    span: Optional[SourceSpan] = None
    label: str = ""  # e.g., "note", "help", "see also"
    
    def __str__(self) -> str:
        prefix = f"{self.label}: " if self.label else ""
        if self.span:
            return f"{self.span}: {prefix}{self.message}"
        return f"{prefix}{self.message}"


@dataclass
class ErrorMessage:
    """
    A complete error message with all context.
    
    This is the internal representation of an error before it's converted
    to a Diagnostic or printed.
    """
    
    code: ErrorCode
    message: str
    span: SourceSpan = field(default_factory=SourceSpan)
    severity: Optional[ErrorSeverity] = None  # None means use code's default
    notes: List[ErrorNote] = field(default_factory=list)
    hint: str = ""
    source_line: str = ""  # The actual source code line, if available
    labels: Dict[str, str] = field(default_factory=dict)  # Span labels for rich display
    
    def __post_init__(self) -> None:
        if self.severity is None:
            self.severity = self.code.default_severity
    
    def add_note(
        self,
        message: str,
        span: Optional[SourceSpan] = None,
        label: str = "note",
    ) -> "ErrorMessage":
        """Add a note to this error message."""
        self.notes.append(ErrorNote(message=message, span=span, label=label))
        return self
    
    def with_hint(self, hint: str) -> "ErrorMessage":
        """Add a hint to this error message."""
        self.hint = hint
        return self
    
    def with_source(self, line: str) -> "ErrorMessage":
        """Add the source line for display."""
        self.source_line = line
        return self
    
    def to_diagnostic(self) -> Any:
        """Convert to a cppcheckdata-shims Diagnostic."""
        if not _DIAGNOSTICS_AVAILABLE:
            raise RuntimeError("Diagnostic types not available")
        
        # Build secondary locations from notes
        secondary = tuple(
            note.span.to_source_location()
            for note in self.notes
            if note.span is not None
        )
        
        # Build extra info
        extra_parts = []
        if self.hint:
            extra_parts.append(f"hint: {self.hint}")
        for note in self.notes:
            if note.span is None:
                extra_parts.append(f"{note.label}: {note.message}")
        extra = "; ".join(extra_parts)
        
        return Diagnostic(
            error_id=self.code.code,
            message=self.message,
            severity=self.severity.to_diagnostic_severity(),
            location=self.span.to_source_location(),
            cwe=self.code.cwe,
            checker_name="casl",
            extra=extra,
            secondary=secondary,
        )
    
    def to_gcc_format(self) -> str:
        """Format as a GCC-style error message."""
        severity = self.severity.value if self.severity else "error"
        main = f"{self.span}: {severity}: {self.message} [{self.code}]"
        
        lines = [main]
        
        # Add source line with caret if available
        if self.source_line:
            lines.append(f"    {self.source_line}")
            if self.span.column > 0:
                caret_pos = self.span.column - 1
                caret_len = max(1, self.span.end_column - self.span.column)
                lines.append(f"    {' ' * caret_pos}{'^' * caret_len}")
        
        # Add notes
        for note in self.notes:
            lines.append(str(note))
        
        # Add hint
        if self.hint:
            lines.append(f"hint: {self.hint}")
        
        return "\n".join(lines)
    
    def to_json(self) -> Dict[str, Any]:
        """Convert to JSON-serializable dict."""
        return {
            "code": self.code.code,
            "message": self.message,
            "severity": self.severity.value if self.severity else "error",
            "location": {
                "file": self.span.file,
                "line": self.span.line,
                "column": self.span.column,
                "end_line": self.span.end_line,
                "end_column": self.span.end_column,
            },
            "phase": self.code.phase.value,
            "category": self.code.category.name,
            "cwe": self.code.cwe,
            "notes": [
                {
                    "message": note.message,
                    "label": note.label,
                    "location": {
                        "file": note.span.file,
                        "line": note.span.line,
                        "column": note.span.column,
                    } if note.span else None,
                }
                for note in self.notes
            ],
            "hint": self.hint,
        }
    
    def __str__(self) -> str:
        return self.to_gcc_format()


# ═══════════════════════════════════════════════════════════════════════════════
# EXCEPTION CLASSES
# ═══════════════════════════════════════════════════════════════════════════════

class CaslError(Exception):
    """
    Base exception for all CASL/CSQL errors.
    
    This exception carries structured error information that can be
    converted to diagnostics or pretty-printed.
    """
    
    def __init__(
        self,
        message: str,
        code: Optional[ErrorCode] = None,
        span: Optional[SourceSpan] = None,
        severity: Optional[ErrorSeverity] = None,
        cause: Optional[Exception] = None,
        notes: Optional[List[ErrorNote]] = None,
        hint: str = "",
    ) -> None:
        super().__init__(message)
        self.error_message = ErrorMessage(
            code=code or CaslErrorCodes.INTERNAL_ERROR,
            message=message,
            span=span or SourceSpan(),
            severity=severity,
            notes=notes or [],
            hint=hint,
        )
        self.cause = cause
    
    @property
    def code(self) -> ErrorCode:
        return self.error_message.code
    
    @property
    def span(self) -> SourceSpan:
        return self.error_message.span
    
    @property
    def severity(self) -> ErrorSeverity:
        return self.error_message.severity or ErrorSeverity.ERROR
    
    def add_note(
        self,
        message: str,
        span: Optional[SourceSpan] = None,
        label: str = "note",
    ) -> "CaslError":
        """Add a note to this error."""
        self.error_message.add_note(message, span, label)
        return self
    
    def with_hint(self, hint: str) -> "CaslError":
        """Add a hint to this error."""
        self.error_message.with_hint(hint)
        return self
    
    def to_diagnostic(self) -> Any:
        """Convert to a cppcheckdata-shims Diagnostic."""
        return self.error_message.to_diagnostic()
    
    def to_gcc_format(self) -> str:
        """Format as a GCC-style error message."""
        return self.error_message.to_gcc_format()
    
    def __str__(self) -> str:
        return self.to_gcc_format()


# ───────────────────────────────────────────────────────────────────────────────
# LEXICAL ERRORS
# ───────────────────────────────────────────────────────────────────────────────

class LexicalError(CaslError):
    """Error during tokenization/lexical analysis."""
    
    def __init__(
        self,
        message: str,
        code: Optional[ErrorCode] = None,
        span: Optional[SourceSpan] = None,
        character: str = "",
        **kwargs: Any,
    ) -> None:
        super().__init__(
            message=message,
            code=code or CaslErrorCodes.INVALID_CHARACTER,
            span=span,
            **kwargs,
        )
        self.character = character


class InvalidCharacterError(LexicalError):
    """Invalid character in source code."""
    
    def __init__(
        self,
        char: str,
        span: Optional[SourceSpan] = None,
        **kwargs: Any,
    ) -> None:
        if len(char) == 1 and not char.isprintable():
            char_desc = f"U+{ord(char):04X}"
        else:
            char_desc = repr(char)
        
        super().__init__(
            message=f"Invalid character {char_desc}",
            code=CaslErrorCodes.INVALID_CHARACTER,
            span=span,
            character=char,
            **kwargs,
        )


class UnterminatedStringError(LexicalError):
    """String literal not properly closed."""
    
    def __init__(
        self,
        span: Optional[SourceSpan] = None,
        quote_char: str = '"',
        **kwargs: Any,
    ) -> None:
        super().__init__(
            message=f"Unterminated string literal (missing closing {quote_char})",
            code=CaslErrorCodes.UNTERMINATED_STRING,
            span=span,
            hint="Add the closing quote character",
            **kwargs,
        )


class UnterminatedCommentError(LexicalError):
    """Block comment not properly closed."""
    
    def __init__(
        self,
        span: Optional[SourceSpan] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(
            message="Unterminated block comment (missing closing */)",
            code=CaslErrorCodes.UNTERMINATED_COMMENT,
            span=span,
            hint="Add */ to close the comment",
            **kwargs,
        )


# ───────────────────────────────────────────────────────────────────────────────
# SYNTAX ERRORS
# ───────────────────────────────────────────────────────────────────────────────

class SyntaxError(CaslError):
    """Error during parsing."""
    
    def __init__(
        self,
        message: str,
        code: Optional[ErrorCode] = None,
        span: Optional[SourceSpan] = None,
        expected: Optional[Sequence[str]] = None,
        got: str = "",
        **kwargs: Any,
    ) -> None:
        super().__init__(
            message=message,
            code=code or CaslErrorCodes.UNEXPECTED_TOKEN,
            span=span,
            **kwargs,
        )
        self.expected = list(expected) if expected else []
        self.got = got
        
        # Auto-generate hint if expected tokens provided
        if self.expected and not self.error_message.hint:
            if len(self.expected) == 1:
                self.error_message.hint = f"Expected {self.expected[0]}"
            elif len(self.expected) <= 3:
                self.error_message.hint = f"Expected one of: {', '.join(self.expected)}"
            else:
                self.error_message.hint = f"Expected one of: {', '.join(self.expected[:3])}, ..."


class UnexpectedTokenError(SyntaxError):
    """Unexpected token encountered during parsing."""
    
    def __init__(
        self,
        got: str,
        expected: Optional[Sequence[str]] = None,
        span: Optional[SourceSpan] = None,
        **kwargs: Any,
    ) -> None:
        expected_msg = ""
        if expected:
            if len(expected) == 1:
                expected_msg = f", expected {expected[0]}"
            else:
                expected_msg = f", expected one of: {', '.join(expected[:5])}"
        
        super().__init__(
            message=f"Unexpected token {got!r}{expected_msg}",
            code=CaslErrorCodes.UNEXPECTED_TOKEN,
            span=span,
            expected=expected,
            got=got,
            **kwargs,
        )


class MissingTokenError(SyntaxError):
    """Required token is missing."""
    
    def __init__(
        self,
        expected: str,
        span: Optional[SourceSpan] = None,
        context: str = "",
        **kwargs: Any,
    ) -> None:
        ctx_msg = f" {context}" if context else ""
        super().__init__(
            message=f"Missing {expected!r}{ctx_msg}",
            code=CaslErrorCodes.MISSING_TOKEN,
            span=span,
            expected=[expected],
            hint=f"Add {expected!r} here",
            **kwargs,
        )


class UnexpectedEOFError(SyntaxError):
    """Unexpected end of file."""
    
    def __init__(
        self,
        expected: Optional[Sequence[str]] = None,
        span: Optional[SourceSpan] = None,
        **kwargs: Any,
    ) -> None:
        msg = "Unexpected end of file"
        if expected:
            msg += f", expected {expected[0]}" if len(expected) == 1 else f", expected one of: {', '.join(expected)}"
        
        super().__init__(
            message=msg,
            code=CaslErrorCodes.UNEXPECTED_EOF,
            span=span,
            expected=expected,
            **kwargs,
        )


class InvalidPropertySyntaxError(SyntaxError):
    """Invalid property specification syntax."""
    
    def __init__(
        self,
        message: str,
        span: Optional[SourceSpan] = None,
        property_kind: str = "",
        **kwargs: Any,
    ) -> None:
        full_msg = message
        if property_kind:
            full_msg = f"Invalid {property_kind} property: {message}"
        
        super().__init__(
            message=full_msg,
            code=CaslErrorCodes.INVALID_PROPERTY_SYNTAX,
            span=span,
            **kwargs,
        )


# ───────────────────────────────────────────────────────────────────────────────
# SEMANTIC ERRORS - TYPE
# ───────────────────────────────────────────────────────────────────────────────

class SemanticError(CaslError):
    """Error during semantic analysis."""
    
    def __init__(
        self,
        message: str,
        code: Optional[ErrorCode] = None,
        span: Optional[SourceSpan] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(
            message=message,
            code=code or CaslErrorCodes.TYPE_MISMATCH,
            span=span,
            **kwargs,
        )


class TypeError(SemanticError):
    """Type-related semantic error."""
    
    def __init__(
        self,
        message: str,
        code: Optional[ErrorCode] = None,
        span: Optional[SourceSpan] = None,
        expected_type: str = "",
        actual_type: str = "",
        **kwargs: Any,
    ) -> None:
        super().__init__(
            message=message,
            code=code or CaslErrorCodes.TYPE_MISMATCH,
            span=span,
            **kwargs,
        )
        self.expected_type = expected_type
        self.actual_type = actual_type
        
        # Add note about the type mismatch
        if expected_type and actual_type:
            self.add_note(f"Expected type: {expected_type}")
            self.add_note(f"Actual type: {actual_type}")


class TypeMismatchError(TypeError):
    """Type mismatch in expression or assignment."""
    
    def __init__(
        self,
        expected: str,
        actual: str,
        span: Optional[SourceSpan] = None,
        context: str = "",
        **kwargs: Any,
    ) -> None:
        ctx = f" in {context}" if context else ""
        super().__init__(
            message=f"Type mismatch{ctx}: expected '{expected}', got '{actual}'",
            code=CaslErrorCodes.TYPE_MISMATCH,
            span=span,
            expected_type=expected,
            actual_type=actual,
            **kwargs,
        )


class TypeInferenceError(TypeError):
    """Failed to infer type."""
    
    def __init__(
        self,
        expression: str = "",
        span: Optional[SourceSpan] = None,
        reason: str = "",
        **kwargs: Any,
    ) -> None:
        msg = "Failed to infer type"
        if expression:
            msg = f"Failed to infer type for '{expression}'"
        if reason:
            msg += f": {reason}"
        
        super().__init__(
            message=msg,
            code=CaslErrorCodes.TYPE_INFERENCE_FAILURE,
            span=span,
            **kwargs,
        )


# ───────────────────────────────────────────────────────────────────────────────
# SEMANTIC ERRORS - SCOPE
# ───────────────────────────────────────────────────────────────────────────────

class ScopeError(SemanticError):
    """Scope-related semantic error."""
    
    def __init__(
        self,
        message: str,
        code: Optional[ErrorCode] = None,
        span: Optional[SourceSpan] = None,
        symbol: str = "",
        **kwargs: Any,
    ) -> None:
        super().__init__(
            message=message,
            code=code or CaslErrorCodes.UNDEFINED_SYMBOL,
            span=span,
            **kwargs,
        )
        self.symbol = symbol


class UndefinedSymbolError(ScopeError):
    """Reference to undefined symbol."""
    
    def __init__(
        self,
        name: str,
        span: Optional[SourceSpan] = None,
        kind: str = "symbol",
        suggestions: Optional[Sequence[str]] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(
            message=f"Undefined {kind} '{name}'",
            code=CaslErrorCodes.UNDEFINED_SYMBOL,
            span=span,
            symbol=name,
            **kwargs,
        )
        
        if suggestions:
            if len(suggestions) == 1:
                self.with_hint(f"Did you mean '{suggestions[0]}'?")
            else:
                self.add_note(f"Similar names: {', '.join(suggestions[:5])}")


class RedefinedSymbolError(ScopeError):
    """Symbol is already defined."""
    
    def __init__(
        self,
        name: str,
        span: Optional[SourceSpan] = None,
        original_span: Optional[SourceSpan] = None,
        kind: str = "symbol",
        **kwargs: Any,
    ) -> None:
        super().__init__(
            message=f"Redefinition of {kind} '{name}'",
            code=CaslErrorCodes.REDEFINED_SYMBOL,
            span=span,
            symbol=name,
            **kwargs,
        )
        
        if original_span:
            self.add_note(f"Previously defined here", span=original_span)


class CircularDependencyError(ScopeError):
    """Circular dependency detected."""
    
    def __init__(
        self,
        cycle: Sequence[str],
        span: Optional[SourceSpan] = None,
        **kwargs: Any,
    ) -> None:
        cycle_str = " -> ".join(cycle)
        super().__init__(
            message=f"Circular dependency detected: {cycle_str}",
            code=CaslErrorCodes.CIRCULAR_DEPENDENCY,
            span=span,
            **kwargs,
        )
        self.cycle = list(cycle)


# ───────────────────────────────────────────────────────────────────────────────
# SEMANTIC ERRORS - BINDING
# ───────────────────────────────────────────────────────────────────────────────

class BindingError(SemanticError):
    """Pattern binding error."""
    
    def __init__(
        self,
        message: str,
        code: Optional[ErrorCode] = None,
        span: Optional[SourceSpan] = None,
        pattern: str = "",
        **kwargs: Any,
    ) -> None:
        super().__init__(
            message=message,
            code=code or CaslErrorCodes.BINDING_FAILURE,
            span=span,
            **kwargs,
        )
        self.pattern = pattern


class PatternMismatchError(BindingError):
    """Pattern does not match value."""
    
    def __init__(
        self,
        pattern: str,
        value_type: str = "",
        span: Optional[SourceSpan] = None,
        **kwargs: Any,
    ) -> None:
        msg = f"Pattern '{pattern}' cannot match"
        if value_type:
            msg += f" value of type '{value_type}'"
        
        super().__init__(
            message=msg,
            code=CaslErrorCodes.PATTERN_BINDING_FAILURE,
            span=span,
            pattern=pattern,
            **kwargs,
        )


class ArityMismatchError(BindingError):
    """Wrong number of arguments."""
    
    def __init__(
        self,
        name: str,
        expected: int,
        actual: int,
        span: Optional[SourceSpan] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(
            message=f"'{name}' expects {expected} argument(s), got {actual}",
            code=CaslErrorCodes.ARITY_MISMATCH,
            span=span,
            **kwargs,
        )
        self.expected_arity = expected
        self.actual_arity = actual


# ───────────────────────────────────────────────────────────────────────────────
# SEMANTIC ERRORS - PROPERTY
# ───────────────────────────────────────────────────────────────────────────────

class PropertyError(SemanticError):
    """Property specification error."""
    
    def __init__(
        self,
        message: str,
        code: Optional[ErrorCode] = None,
        span: Optional[SourceSpan] = None,
        property_name: str = "",
        **kwargs: Any,
    ) -> None:
        super().__init__(
            message=message,
            code=code or CaslErrorCodes.INVALID_PROPERTY_SPEC,
            span=span,
            **kwargs,
        )
        self.property_name = property_name


class UnsatisfiablePropertyError(PropertyError):
    """Property can never be satisfied."""
    
    def __init__(
        self,
        property_name: str = "",
        reason: str = "",
        span: Optional[SourceSpan] = None,
        **kwargs: Any,
    ) -> None:
        msg = "Property is unsatisfiable"
        if property_name:
            msg = f"Property '{property_name}' is unsatisfiable"
        if reason:
            msg += f": {reason}"
        
        super().__init__(
            message=msg,
            code=CaslErrorCodes.UNSATISFIABLE_PROPERTY,
            span=span,
            property_name=property_name,
            **kwargs,
        )


class ConflictingPropertiesError(PropertyError):
    """Properties conflict with each other."""
    
    def __init__(
        self,
        properties: Sequence[str],
        span: Optional[SourceSpan] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(
