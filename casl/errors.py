#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
casl/errors.py
==============

Exception hierarchy for CASL parsing, semantic analysis, and code generation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional, Sequence, Tuple


@dataclass
class SourceLocation:
    """Location in CASL source for error reporting."""
    
    line: int = 0
    column: int = 0
    filename: Optional[str] = None
    context: Optional[str] = None  # snippet of source
    
    def __str__(self) -> str:
        loc = f"{self.filename or '<input>'}:{self.line}:{self.column}"
        if self.context:
            loc += f"\n  | {self.context}"
        return loc


class CASLError(Exception):
    """Base class for all CASL errors."""
    
    def __init__(
        self,
        message: str,
        location: Optional[SourceLocation] = None,
        hints: Optional[Sequence[str]] = None,
    ) -> None:
        self.message = message
        self.location = location
        self.hints = list(hints) if hints else []
        super().__init__(self._format())
    
    def _format(self) -> str:
        parts = [f"CASL Error: {self.message}"]
        if self.location:
            parts.append(f"  at {self.location}")
        for hint in self.hints:
            parts.append(f"  hint: {hint}")
        return "\n".join(parts)


class ParseError(CASLError):
    """Raised when S-expression parsing fails."""
    pass


class SyntaxError_(CASLError):
    """Raised when CASL syntax is invalid (well-formed S-expr but bad CASL)."""
    pass


class SemanticError(CASLError):
    """Raised during semantic analysis (undefined references, type errors)."""
    pass


class CodeGenError(CASLError):
    """Raised during Python code generation."""
    pass


class RuntimeError_(CASLError):
    """Raised during execution of generated addon."""
    pass


# ---------------------------------------------------------------------------
# Diagnostic accumulator
# ---------------------------------------------------------------------------

@dataclass
class Diagnostic:
    """A single diagnostic message (error, warning, note)."""
    
    level: str  # "error", "warning", "note"
    message: str
    location: Optional[SourceLocation] = None
    code: Optional[str] = None  # e.g., "CASL001"
    
    def __str__(self) -> str:
        prefix = f"[{self.code}] " if self.code else ""
        loc = f" at {self.location}" if self.location else ""
        return f"{self.level}: {prefix}{self.message}{loc}"


class DiagnosticCollector:
    """Accumulates diagnostics without immediately raising."""
    
    def __init__(self) -> None:
        self._diagnostics: list[Diagnostic] = []
    
    def error(
        self,
        message: str,
        location: Optional[SourceLocation] = None,
        code: Optional[str] = None,
    ) -> None:
        self._diagnostics.append(
            Diagnostic("error", message, location, code)
        )
    
    def warning(
        self,
        message: str,
        location: Optional[SourceLocation] = None,
        code: Optional[str] = None,
    ) -> None:
        self._diagnostics.append(
            Diagnostic("warning", message, location, code)
        )
    
    def note(
        self,
        message: str,
        location: Optional[SourceLocation] = None,
        code: Optional[str] = None,
    ) -> None:
        self._diagnostics.append(
            Diagnostic("note", message, location, code)
        )
    
    def has_errors(self) -> bool:
        return any(d.level == "error" for d in self._diagnostics)
    
    def all(self) -> list[Diagnostic]:
        return list(self._diagnostics)
    
    def errors(self) -> list[Diagnostic]:
        return [d for d in self._diagnostics if d.level == "error"]
    
    def raise_if_errors(self) -> None:
        if self.has_errors():
            msgs = "\n".join(str(d) for d in self.errors())
            raise SemanticError(f"Analysis failed with errors:\n{msgs}")
    
    def clear(self) -> None:
        self._diagnostics.clear()
