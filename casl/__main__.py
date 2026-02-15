#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
casl/__main__.py
================

Entry point for the CASL (Cppcheck Addon Specification Language) toolchain.

Usage
-----
    python -m casl <command> [options] <spec-file>

Commands
--------
    compile     Compile a CASL specification to a standalone Cppcheck addon
    check       Parse and validate a CASL specification (no code generation)
    dump-ast    Parse a specification and dump the AST
    dump-sexp   Parse a specification and dump the canonical S-expression form
    run         Compile and immediately execute against a Cppcheck dump file
    info        Display metadata and summary of a CASL specification
    init        Generate a skeleton CASL specification file

Pipeline
--------
The full compilation pipeline is:

    .casl source
        │
        ▼
    ┌──────────┐
    │  Parser   │   sexpdata → CASL AST
    └────┬─────┘
         │
         ▼
    ┌──────────────┐
    │  Semantic     │   Multi-pass validation
    │  Analyzer     │   (symbols, types, soundness)
    └────┬─────────┘
         │
         ▼
    ┌──────────────┐
    │  Code         │   AST → Python source
    │  Generator    │   (standalone Cppcheck addon)
    └────┬─────────┘
         │
         ▼
    generated_addon.py
        │
        ▼  (optional: --run)
    ┌──────────────┐
    │  Cppcheck     │   Execute against dump files
    │  Runtime      │
    └──────────────┘

References
----------
- PQL (Program Query Language) — compilation model
- Møller & Schwartzbach — static analysis theory
- Cppcheck addon conventions (cppcheckdata.py API)
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import traceback
from pathlib import Path
from typing import (
    Any,
    Dict,
    List,
    NoReturn,
    Optional,
    Sequence,
    TextIO,
    Tuple,
)

# ═══════════════════════════════════════════════════════════════════════════
# VERSION AND METADATA
# ═══════════════════════════════════════════════════════════════════════════

__version__ = "0.1.0"
__description__ = "CASL — Cppcheck Addon Specification Language"

# ═══════════════════════════════════════════════════════════════════════════
# LAZY IMPORTS (avoid heavy imports for --help)
# ═══════════════════════════════════════════════════════════════════════════

def _import_parser():
    from casl.parser import parse, parse_file
    return parse, parse_file

def _import_semantic():
    from casl.semantic import SemanticAnalyzer
    return SemanticAnalyzer

def _import_codegen():
    from casl.codegen import CodeGenerator, GeneratedAddon
    return CodeGenerator, GeneratedAddon

def _import_runtime():
    from casl.runtime import CASLRuntime
    return CASLRuntime

def _import_errors():
    from casl.errors import (
        CASLError,
        ParseError,
        SyntaxError_,
        SemanticError,
        CodeGenError,
        RuntimeError_,
        DiagnosticCollector,
        SourceLocation,
    )
    return (
        CASLError, ParseError, SyntaxError_, SemanticError,
        CodeGenError, RuntimeError_, DiagnosticCollector, SourceLocation,
    )

def _import_ast():
    from casl import ast as A
    return A

def _import_visitor():
    from casl.visitor import DepthFirstVisitor
    return DepthFirstVisitor


# ═══════════════════════════════════════════════════════════════════════════
# TERMINAL COLORS
# ═══════════════════════════════════════════════════════════════════════════

class _Colors:
    """ANSI color codes, disabled when not writing to a TTY."""

    def __init__(self, enabled: bool = True) -> None:
        self.enabled = enabled

    def _code(self, code: str) -> str:
        return code if self.enabled else ""

    @property
    def RESET(self) -> str:
        return self._code("\033[0m")

    @property
    def BOLD(self) -> str:
        return self._code("\033[1m")

    @property
    def DIM(self) -> str:
        return self._code("\033[2m")

    @property
    def RED(self) -> str:
        return self._code("\033[31m")

    @property
    def GREEN(self) -> str:
        return self._code("\033[32m")

    @property
    def YELLOW(self) -> str:
        return self._code("\033[33m")

    @property
    def BLUE(self) -> str:
        return self._code("\033[34m")

    @property
    def MAGENTA(self) -> str:
        return self._code("\033[35m")

    @property
    def CYAN(self) -> str:
        return self._code("\033[36m")

    @property
    def WHITE(self) -> str:
        return self._code("\033[37m")


def _get_colors(stream: TextIO = sys.stderr) -> _Colors:
    """Get color codes appropriate for the given stream."""
    try:
        is_tty = hasattr(stream, "isatty") and stream.isatty()
    except Exception:
        is_tty = False
    return _Colors(enabled=is_tty and os.environ.get("NO_COLOR") is None)


# ═══════════════════════════════════════════════════════════════════════════
# DIAGNOSTIC FORMATTER
# ═══════════════════════════════════════════════════════════════════════════

class DiagnosticFormatter:
    """Format diagnostics for terminal output.

    Produces GCC/Clang-style diagnostic messages:

        spec.casl:12:5: error: undefined pattern 'malloc-free'
          (query leak-check
               ^~~~~~~~~~~
    """

    def __init__(self, colors: _Colors, stream: TextIO = sys.stderr) -> None:
        self.colors = colors
        self.stream = stream
        self._error_count = 0
        self._warning_count = 0
        self._note_count = 0

    def error(self, message: str, location: Optional[Any] = None,
              source_line: Optional[str] = None) -> None:
        """Emit an error diagnostic."""
        self._error_count += 1
        c = self.colors
        loc = self._format_location(location)
        self.stream.write(
            f"{c.BOLD}{loc}{c.RED}error:{c.RESET}{c.BOLD} {message}{c.RESET}\n"
        )
        if source_line:
            self._print_source_context(source_line, location)

    def warning(self, message: str, location: Optional[Any] = None,
                source_line: Optional[str] = None) -> None:
        """Emit a warning diagnostic."""
        self._warning_count += 1
        c = self.colors
        loc = self._format_location(location)
        self.stream.write(
            f"{c.BOLD}{loc}{c.MAGENTA}warning:{c.RESET}{c.BOLD} {message}{c.RESET}\n"
        )
        if source_line:
            self._print_source_context(source_line, location)

    def note(self, message: str, location: Optional[Any] = None,
             source_line: Optional[str] = None) -> None:
        """Emit a note diagnostic."""
        self._note_count += 1
        c = self.colors
        loc = self._format_location(location)
        self.stream.write(
            f"{c.BOLD}{loc}{c.CYAN}note:{c.RESET} {message}\n"
        )
        if source_line:
            self._print_source_context(source_line, location)

    def summary(self) -> None:
        """Print a summary of all diagnostics."""
        parts = []
        c = self.colors
        if self._error_count:
            parts.append(f"{c.RED}{self._error_count} error(s){c.RESET}")
        if self._warning_count:
            parts.append(f"{c.MAGENTA}{self._warning_count} warning(s){c.RESET}")
        if self._note_count:
            parts.append(f"{c.CYAN}{self._note_count} note(s){c.RESET}")
        if parts:
            self.stream.write(", ".join(parts) + " generated.\n")

    @property
    def has_errors(self) -> bool:
        return self._error_count > 0

    def _format_location(self, location: Optional[Any]) -> str:
        """Format a source location prefix."""
        if location is None:
            return ""
        file_ = getattr(location, "file", None) or "<input>"
        line = getattr(location, "line", None)
        col = getattr(location, "column", None)
        if line is not None and col is not None:
            return f"{file_}:{line}:{col}: "
        elif line is not None:
            return f"{file_}:{line}: "
        else:
            return f"{file_}: "

    def _print_source_context(self, source_line: str, location: Optional[Any]) -> None:
        """Print source context with a caret."""
        c = self.colors
        # Print the source line
        self.stream.write(f"  {source_line.rstrip()}\n")
        # Print caret
        col = getattr(location, "column", None)
        if col is not None and col > 0:
            padding = " " * (col - 1 + 2)  # +2 for leading indent
            self.stream.write(f"{c.GREEN}{padding}^{c.RESET}\n")


# ═══════════════════════════════════════════════════════════════════════════
# SOURCE FILE MANAGER
# ═══════════════════════════════════════════════════════════════════════════

class SourceManager:
    """Manage loading and caching of CASL source files."""

    def __init__(self) -> None:
        self._cache: Dict[str, str] = {}
        self._lines_cache: Dict[str, List[str]] = {}

    def load(self, path: str) -> str:
        """Load a source file, returning its content."""
        path = os.path.abspath(path)
        if path not in self._cache:
            try:
                with open(path, "r", encoding="utf-8") as f:
                    content = f.read()
            except FileNotFoundError:
                raise FileNotFoundError(f"CASL specification not found: {path}")
            except PermissionError:
                raise PermissionError(f"Cannot read CASL specification: {path}")
            except UnicodeDecodeError as e:
                raise ValueError(
                    f"CASL specification is not valid UTF-8: {path} ({e})"
                )
            self._cache[path] = content
            self._lines_cache[path] = content.splitlines()
        return self._cache[path]

    def load_stdin(self) -> str:
        """Load source from stdin."""
        content = sys.stdin.read()
        self._cache["<stdin>"] = content
        self._lines_cache["<stdin>"] = content.splitlines()
        return content

    def get_line(self, path: str, line_number: int) -> Optional[str]:
        """Get a specific line from a loaded file."""
        path = os.path.abspath(path) if path != "<stdin>" else path
        lines = self._lines_cache.get(path)
        if lines and 0 < line_number <= len(lines):
            return lines[line_number - 1]
        return None

    def get_source_name(self, path: str) -> str:
        """Get a display name for a source path."""
        if path == "<stdin>":
            return "<stdin>"
        return os.path.relpath(path)


# ═══════════════════════════════════════════════════════════════════════════
# AST DUMPER
# ═══════════════════════════════════════════════════════════════════════════

class ASTDumper:
    """Dump a CASL AST in a human-readable tree format."""

    def __init__(self, stream: TextIO = sys.stdout,
                 colors: Optional[_Colors] = None,
                 show_locations: bool = False) -> None:
        self.stream = stream
        self.colors = colors or _Colors(enabled=False)
        self.show_locations = show_locations

    def dump(self, node: Any, indent: int = 0) -> None:
        """Recursively dump an AST node."""
        A = _import_ast()

        prefix = "  " * indent
        c = self.colors
        node_name = type(node).__name__

        # Format the node header
        header = f"{c.CYAN}{node_name}{c.RESET}"

        # Add key attributes inline
        attrs = self._get_display_attrs(node)
        if attrs:
            attr_str = " ".join(
                f"{c.DIM}{k}={c.RESET}{c.YELLOW}{repr(v)}{c.RESET}"
                for k, v in attrs
            )
            header = f"{header} {attr_str}"

        # Add location if requested
        loc = getattr(node, "location", None)
        if self.show_locations and loc is not None:
            loc_str = f"{c.DIM}[{loc.file}:{loc.line}:{loc.column}]{c.RESET}"
            header = f"{header} {loc_str}"

        self.stream.write(f"{prefix}{header}\n")

        # Recurse into child nodes
        children = self._get_children(node)
        for child_name, child_value in children:
            if child_value is None:
                continue
            if isinstance(child_value, list):
                if not child_value:
                    continue
                self.stream.write(
                    f"{prefix}  {c.DIM}{child_name}:{c.RESET}\n"
                )
                for item in child_value:
                    if hasattr(item, "__class__") and hasattr(item, "__dict__"):
                        self.dump(item, indent + 2)
                    else:
                        self.stream.write(f"{prefix}    {repr(item)}\n")
            elif isinstance(child_value, dict):
                if not child_value:
                    continue
                self.stream.write(
                    f"{prefix}  {c.DIM}{child_name}:{c.RESET}\n"
                )
                for k, v in child_value.items():
                    self.stream.write(f"{prefix}    {repr(k)}:\n")
                    if hasattr(v, "__class__") and hasattr(v, "__dict__"):
                        self.dump(v, indent + 3)
                    else:
                        self.stream.write(f"{prefix}      {repr(v)}\n")
            elif hasattr(child_value, "__class__") and hasattr(child_value, "__dict__"):
                self.stream.write(
                    f"{prefix}  {c.DIM}{child_name}:{c.RESET}\n"
                )
                self.dump(child_value, indent + 2)

    def _get_display_attrs(self, node: Any) -> List[Tuple[str, Any]]:
        """Get attributes to display inline with the node name."""
        # Attributes that identify a node (displayed inline)
        identity_attrs = {
            "name", "kind", "severity", "operator", "direction",
            "value", "type_name", "field",
        }
        result = []
        for attr in identity_attrs:
            val = getattr(node, attr, None)
            if val is not None:
                result.append((attr, val))
        return result

    def _get_children(self, node: Any) -> List[Tuple[str, Any]]:
        """Get child nodes/collections for recursive dumping."""
        # Attributes that are structural children (not identity)
        skip = {
            "name", "kind", "severity", "operator", "direction",
            "value", "type_name", "field", "location",
        }
        result = []
        for attr_name, attr_val in sorted(vars(node).items()):
            if attr_name.startswith("_") or attr_name in skip:
                continue
            result.append((attr_name, attr_val))
        return result


# ═══════════════════════════════════════════════════════════════════════════
# SEXP ROUND-TRIP DUMPER
# ═══════════════════════════════════════════════════════════════════════════

class SexpDumper:
    """Dump a CASL AST back into canonical S-expression form.

    This enables round-tripping: parse → AST → sexp → parse → ...
    Useful for normalization, formatting, and diff.
    """

    def __init__(self, stream: TextIO = sys.stdout,
                 indent: int = 2,
                 line_width: int = 80) -> None:
        self.stream = stream
        self.indent = indent
        self.line_width = line_width

    def dump(self, node: Any) -> None:
        """Dump a node as S-expressions."""
        A = _import_ast()
        sexp = self._to_sexp(node)
        formatted = self._format_sexp(sexp, 0)
        self.stream.write(formatted)
        self.stream.write("\n")

    def _to_sexp(self, node: Any) -> Any:
        """Convert an AST node to a nested list (S-expression structure)."""
        A = _import_ast()

        if node is None:
            return "nil"
        if isinstance(node, (str, int, float, bool)):
            return node
        if isinstance(node, list):
            return [self._to_sexp(item) for item in node]

        node_type = type(node).__name__

        # Map AST node types to their S-expression form
        if isinstance(node, A.AddonSpec):
            parts = ["addon-spec", node.name]
            if node.metadata:
                parts.append(self._to_sexp(node.metadata))
            for imp in (node.imports or []):
                parts.append(self._to_sexp(imp))
            for decl in (node.declarations or []):
                parts.append(self._to_sexp(decl))
            return parts

        if isinstance(node, A.Metadata):
            parts = ["metadata"]
            if node.version:
                parts.append(["version", node.version])
            if node.description:
                parts.append(["description", node.description])
            if node.author:
                parts.append(["author", node.author])
            if node.tags:
                parts.append(["tags"] + list(node.tags))
            return parts

        if isinstance(node, A.Import):
            parts = ["import", node.module]
            if node.names:
                parts.append(["only"] + list(node.names))
            return parts

        if isinstance(node, A.DomainDecl):
            parts = ["domain", node.name]
            if node.values:
                parts.append(["values"] + [self._to_sexp(v) for v in node.values])
            if node.bottom:
                parts.append(["bottom", self._to_sexp(node.bottom)])
            if node.top:
                parts.append(["top", self._to_sexp(node.top)])
            if node.join:
                parts.append(["join", self._to_sexp(node.join)])
            if node.meet:
                parts.append(["meet", self._to_sexp(node.meet)])
            if node.widen:
                parts.append(["widen", self._to_sexp(node.widen)])
            if node.leq:
                parts.append(["leq", self._to_sexp(node.leq)])
            return parts

        if isinstance(node, A.PatternDecl):
            parts = ["pattern", node.name]
            if node.pattern:
                parts.append(self._to_sexp(node.pattern))
            return parts

        if isinstance(node, A.QueryDecl):
            parts = ["query", node.name]
            if node.uses:
                parts.append(["uses"] + list(node.uses))
            if node.matches:
                parts.append(["matches"] + [self._to_sexp(m) for m in node.matches])
            if node.where:
                parts.append(["where", self._to_sexp(node.where)])
            if node.actions:
                parts.append(["actions"] + [self._to_sexp(a) for a in node.actions])
            return parts

        if isinstance(node, A.CheckerDecl):
            parts = ["checker", node.name]
            if node.queries:
                parts.append(["queries"] + list(node.queries))
            if node.severity:
                parts.append(["severity", node.severity])
            if node.message:
                parts.append(["message", self._to_sexp(node.message)])
            return parts

        if isinstance(node, A.TransferDecl):
            parts = ["transfer", node.name]
            if node.domain:
                parts.append(["domain", node.domain])
            if node.pattern:
                parts.append(["pattern", self._to_sexp(node.pattern)])
            if node.pre_state:
                parts.append(["pre", self._to_sexp(node.pre_state)])
            if node.post_state:
                parts.append(["post", self._to_sexp(node.post_state)])
            return parts

        if isinstance(node, A.ReportAction):
            parts = ["report"]
            if node.severity:
                parts.append(node.severity)
            if node.message:
                parts.append(self._to_sexp(node.message))
            return parts

        if isinstance(node, A.SetFactAction):
            parts = ["set-fact"]
            if node.target:
                parts.append(self._to_sexp(node.target))
            if node.value:
                parts.append(self._to_sexp(node.value))
            if node.domain:
                parts.append(["domain", node.domain])
            return parts

        if isinstance(node, A.LogAction):
            parts = ["log"]
            if node.level:
                parts.append(node.level)
            if node.message:
                parts.append(self._to_sexp(node.message))
            return parts

        # Patterns
        if isinstance(node, A.NodePattern):
            parts = ["node", node.kind]
            for child in (node.children or []):
                parts.append(self._to_sexp(child))
            for attr_name, attr_pat in (node.attributes or {}).items():
                parts.append([f":{attr_name}", self._to_sexp(attr_pat)])
            return parts

        if isinstance(node, A.BindingPattern):
            s = f"?{node.name}"
            if node.type_constraint:
                s = f"?{node.name}:{node.type_constraint}"
            if node.nested:
                return [s, self._to_sexp(node.nested)]
            return s

        if isinstance(node, A.WildcardPattern):
            return "_"

        if isinstance(node, A.LiteralPattern):
            return node.value

        if isinstance(node, A.CallPattern):
            parts = ["call"]
            if node.function:
                parts.append(self._to_sexp(node.function))
            for arg in (node.arguments or []):
                parts.append(self._to_sexp(arg))
            return parts

        if isinstance(node, A.AssignPattern):
            parts = ["assign"]
            if node.lhs:
                parts.append(self._to_sexp(node.lhs))
            if node.rhs:
                parts.append(self._to_sexp(node.rhs))
            return parts

        if isinstance(node, A.SequencePattern):
            parts = ["seq"]
            for elem in (node.elements or []):
                parts.append(self._to_sexp(elem))
            return parts

        # Expressions
        if isinstance(node, A.Identifier):
            return node.name

        if isinstance(node, A.IntegerLit):
            return node.value

        if isinstance(node, A.FloatLit):
            return node.value

        if isinstance(node, A.StringLit):
            return node.value

        if isinstance(node, A.BoolLit):
            return node.value

        if isinstance(node, A.NilLit):
            return "nil"

        if isinstance(node, A.BinaryExpr):
            return [node.operator, self._to_sexp(node.left), self._to_sexp(node.right)]

        if isinstance(node, A.UnaryExpr):
            return [node.operator, self._to_sexp(node.operand)]

        if isinstance(node, A.CallExpr):
            parts = [self._to_sexp(node.function)]
            for arg in (node.arguments or []):
                parts.append(self._to_sexp(arg))
            return parts

        if isinstance(node, A.FieldAccess):
            return [".", self._to_sexp(node.object), node.field]

        if isinstance(node, A.CondExpr):
            return [
                "if",
                self._to_sexp(node.condition),
                self._to_sexp(node.then_expr),
                self._to_sexp(node.else_expr),
            ]

        if isinstance(node, A.LetExpr):
            bindings = [
                [name, self._to_sexp(val)]
                for name, val in (node.bindings or [])
            ]
            return ["let", bindings, self._to_sexp(node.body)]

        if isinstance(node, A.LambdaExpr):
            params = [p.name for p in (node.params or [])]
            return ["lambda", params, self._to_sexp(node.body)]

        # Constraints
        if isinstance(node, A.FlowsTo):
            parts = ["flows-to", self._to_sexp(node.source), self._to_sexp(node.sink)]
            if node.domain:
                parts.append(["domain", node.domain])
            return parts

        if isinstance(node, A.Reaches):
            return ["reaches", self._to_sexp(node.source), self._to_sexp(node.target)]

        if isinstance(node, A.Dominates):
            return ["dominates", self._to_sexp(node.dominator), self._to_sexp(node.dominated)]

        if isinstance(node, A.SameValue):
            return ["same-value", self._to_sexp(node.left), self._to_sexp(node.right)]

        if isinstance(node, A.MayAlias):
            return ["may-alias", self._to_sexp(node.ptr1), self._to_sexp(node.ptr2)]

        if isinstance(node, A.AndConstraint):
            return ["and"] + [self._to_sexp(c) for c in node.constraints]

        if isinstance(node, A.OrConstraint):
            return ["or"] + [self._to_sexp(c) for c in node.constraints]

        if isinstance(node, A.NotConstraint):
            return ["not", self._to_sexp(node.constraint)]

        # Fallback: represent as tagged list with all attributes
        parts = [node_type]
        for attr_name in sorted(vars(node)):
            if attr_name.startswith("_") or attr_name == "location":
                continue
            val = getattr(node, attr_name)
            if val is not None:
                parts.append([f":{attr_name}", self._to_sexp(val)])
        return parts

    def _format_sexp(self, sexp: Any, depth: int) -> str:
        """Format an S-expression with indentation."""
        indent_str = " " * (self.indent * depth)

        if isinstance(sexp, bool):
            return f"{indent_str}{'#t' if sexp else '#f'}"
        if isinstance(sexp, (int, float)):
            return f"{indent_str}{sexp}"
        if isinstance(sexp, str):
            # Determine if quoting is needed
            if any(c in sexp for c in ' ()"\'') or not sexp:
                return f'{indent_str}"{sexp}"'
            return f"{indent_str}{sexp}"
        if not isinstance(sexp, list):
            return f"{indent_str}{repr(sexp)}"

        if not sexp:
            return f"{indent_str}()"

        # Try single-line first
        single = self._format_sexp_flat(sexp)
        if len(single) + len(indent_str) <= self.line_width:
            return f"{indent_str}{single}"

        # Multi-line
        lines = [f"{indent_str}({self._format_sexp_flat(sexp[0])}"]
        for item in sexp[1:]:
            lines.append(self._format_sexp(item, depth + 1))
        lines[-1] += ")"
        return "\n".join(lines)

    def _format_sexp_flat(self, sexp: Any) -> str:
        """Format an S-expression on a single line."""
        if isinstance(sexp, bool):
            return "#t" if sexp else "#f"
        if isinstance(sexp, (int, float)):
            return str(sexp)
        if isinstance(sexp, str):
            if any(c in sexp for c in ' ()"\'') or not sexp:
                return f'"{sexp}"'
            return sexp
        if not isinstance(sexp, list):
            return repr(sexp)
        if not sexp:
            return "()"
        inner = " ".join(self._format_sexp_flat(item) for item in sexp)
        return f"({inner})"


# ═══════════════════════════════════════════════════════════════════════════
# SKELETON GENERATOR
# ═══════════════════════════════════════════════════════════════════════════

SKELETON_TEMPLATE = '''\
;;; {name}.casl — CASL Specification
;;;
;;; Generated by: casl init
;;; Description: {description}

(addon-spec {name}
  (metadata
    (version "0.1.0")
    (description "{description}")
    (author "{author}")
    (tags "custom"))

  ;; ─── Imports ───────────────────────────────────────────────
  ;; Import built-in abstract domains
  ;; (import builtins (only Nullness Taint Sign))

  ;; ─── Domains ──────────────────────────────────────────────
  ;; Define custom abstract domains if needed
  ;;
  ;; (domain MyDomain
  ;;   (values Safe Unsafe Unknown)
  ;;   (bottom Unknown)
  ;;   (top Unsafe)
  ;;   (leq (lambda (a b)
  ;;     (or (== a Unknown)
  ;;         (== a b)
  ;;         (== b Unsafe)))))

  ;; ─── Patterns ─────────────────────────────────────────────
  ;; PQL-style code patterns
  ;;
  (pattern example-call
    (call (name "example_function") ?arg))

  ;; ─── Queries ──────────────────────────────────────────────
  ;; Queries bind patterns to constraints and actions
  ;;
  (query example-check
    (uses example-call)
    (matches
      (call (name "example_function") ?arg))
    (where
      (and
        (type-of ?arg "int")
        (not (in-range ?arg 0 100))))
    (actions
      (report "warning"
        (format "Argument to example_function may be out of range: ~a" ?arg))))

  ;; ─── Checkers ─────────────────────────────────────────────
  ;; Top-level checkers group queries
  ;;
  (checker example-checker
    (queries example-check)
    (severity "warning")
    (message "Example checker found issues"))

) ;; end addon-spec
'''


def _generate_skeleton(name: str, description: str, author: str) -> str:
    """Generate a skeleton CASL specification."""
    return SKELETON_TEMPLATE.format(
        name=name,
        description=description,
        author=author,
    )


# ═══════════════════════════════════════════════════════════════════════════
# PIPELINE EXECUTION
# ═══════════════════════════════════════════════════════════════════════════

class Pipeline:
    """Orchestrates the CASL compilation pipeline.

    Handles:
    - Source loading
    - Parsing
    - Semantic analysis
    - Code generation
    - Error collection and reporting
    """

    def __init__(self, formatter: DiagnosticFormatter,
                 source_mgr: SourceManager,
                 verbose: bool = False) -> None:
        self.formatter = formatter
        self.source_mgr = source_mgr
        self.verbose = verbose
        self._timings: Dict[str, float] = {}

    def _timed(self, phase_name: str):
        """Context manager to time a pipeline phase."""
        class _Timer:
            def __init__(self_, name: str, pipeline: "Pipeline"):
                self_.name = name
                self_.pipeline = pipeline

            def __enter__(self_):
                self_.start = time.perf_counter()
                if self_.pipeline.verbose:
                    sys.stderr.write(f"  [{self_.name}] starting...\n")
                return self_

            def __exit__(self_, *args: Any):
                elapsed = time.perf_counter() - self_.start
                self_.pipeline._timings[self_.name] = elapsed
                if self_.pipeline.verbose:
                    sys.stderr.write(
                        f"  [{self_.name}] completed in {elapsed:.3f}s\n"
                    )

        return _Timer(phase_name, self)

    def parse(self, source: str, filename: str = "<input>") -> Any:
        """Parse phase: S-expression text → CASL AST."""
        (CASLError, ParseError, SyntaxError_, SemanticError,
         CodeGenError, RuntimeError_, DiagnosticCollector, SourceLocation) = _import_errors()
        parse, _ = _import_parser()

        with self._timed("parse"):
            try:
                spec = parse(source)
                if self.verbose:
                    sys.stderr.write(f"  Parsed specification: {spec.name}\n")
                return spec
            except ParseError as e:
                self.formatter.error(
                    str(e),
                    getattr(e, "location", None),
                    self._get_source_line(filename, e),
                )
                return None
            except SyntaxError_ as e:
                self.formatter.error(
                    str(e),
                    getattr(e, "location", None),
                    self._get_source_line(filename, e),
                )
                return None

    def analyze(self, spec: Any) -> Any:
        """Semantic analysis phase: validated AST + context."""
        (CASLError, ParseError, SyntaxError_, SemanticError,
         CodeGenError, RuntimeError_, DiagnosticCollector, SourceLocation) = _import_errors()
        SemanticAnalyzer = _import_semantic()

        with self._timed("semantic-analysis"):
            try:
                analyzer = SemanticAnalyzer()
                ctx = analyzer.analyze(spec)

                # Report diagnostics from the analyzer
                if hasattr(analyzer, "diagnostics"):
                    for diag in analyzer.diagnostics:
                        severity = getattr(diag, "severity", "error")
                        message = getattr(diag, "message", str(diag))
                        location = getattr(diag, "location", None)
                        if severity == "error":
                            self.formatter.error(message, location)
                        elif severity == "warning":
                            self.formatter.warning(message, location)
                        else:
                            self.formatter.note(message, location)

                if self.verbose:
                    sym_count = len(ctx.symbols) if hasattr(ctx, "symbols") else 0
                    sys.stderr.write(
                        f"  Semantic analysis complete: "
                        f"{sym_count} symbols resolved\n"
                    )

                return ctx
            except SemanticError as e:
                self.formatter.error(
                    str(e),
                    getattr(e, "location", None),
                )
                return None

    def generate(self, spec: Any, ctx: Any, output_path: Optional[str] = None) -> Any:
        """Code generation phase: AST + context → Python addon."""
        (CASLError, ParseError, SyntaxError_, SemanticError,
         CodeGenError, RuntimeError_, DiagnosticCollector, SourceLocation) = _import_errors()
        CodeGenerator, GeneratedAddon = _import_codegen()

        with self._timed("code-generation"):
            try:
                generator = CodeGenerator(ctx)
                addon = generator.generate(spec)

                if self.verbose:
                    code_lines = addon.code.count("\n")
                    sys.stderr.write(
                        f"  Generated {code_lines} lines of Python code\n"
                    )
                    sys.stderr.write(
                        f"  Checkers: {', '.join(addon.checkers)}\n"
                    )
                    sys.stderr.write(
                        f"  Domains: {', '.join(addon.domains)}\n"
                    )

                return addon
            except CodeGenError as e:
                self.formatter.error(
                    str(e),
                    getattr(e, "location", None),
                )
                return None

    def print_timings(self) -> None:
        """Print pipeline phase timings."""
        if not self._timings:
            return
        total = sum(self._timings.values())
        colors = _get_colors()
        sys.stderr.write(f"\n{colors.BOLD}Pipeline timings:{colors.RESET}\n")
        for phase, elapsed in self._timings.items():
            pct = (elapsed / total * 100) if total > 0 else 0
            bar_len = int(pct / 2)
            bar = "█" * bar_len + "░" * (50 - bar_len)
            sys.stderr.write(
                f"  {phase:<25s} {elapsed:7.3f}s  {bar} {pct:5.1f}%\n"
            )
        sys.stderr.write(
            f"  {'TOTAL':<25s} {total:7.3f}s\n"
        )

    def _get_source_line(self, filename: str, exc: Exception) -> Optional[str]:
        """Try to extract a source line for diagnostic context."""
        loc = getattr(exc, "location", None)
        if loc is None:
            return None
        file_ = getattr(loc, "file", filename)
        line = getattr(loc, "line", None)
        if line is not None:
            return self.source_mgr.get_line(file_, line)
        return None


# ═══════════════════════════════════════════════════════════════════════════
# COMMAND HANDLERS
# ═══════════════════════════════════════════════════════════════════════════

def cmd_compile(args: argparse.Namespace) -> int:
    """Handle the 'compile' command."""
    colors = _get_colors()
    formatter = DiagnosticFormatter(colors)
    source_mgr = SourceManager()

    # Load source
    try:
        if args.input == "-":
            source = source_mgr.load_stdin()
            filename = "<stdin>"
        else:
            source = source_mgr.load(args.input)
            filename = args.input
    except (FileNotFoundError, PermissionError, ValueError) as e:
        formatter.error(str(e))
        return 1

    pipeline = Pipeline(formatter, source_mgr, verbose=args.verbose)

    # Phase 1: Parse
    spec = pipeline.parse(source, filename)
    if spec is None:
        formatter.summary()
        return 1

    # Phase 2: Semantic analysis
    ctx = pipeline.analyze(spec)
    if ctx is None or formatter.has_errors:
        formatter.summary()
        return 1

    # Phase 3: Code generation
    addon = pipeline.generate(spec, ctx)
    if addon is None:
        formatter.summary()
        return 1

    # Determine output path
    if args.output:
        output_path = args.output
    elif args.input != "-":
        base = os.path.splitext(args.input)[0]
        output_path = base + ".py"
    else:
        output_path = None

    # Write output
    if output_path:
        try:
            addon.write_to_file(output_path)
            if not args.quiet:
                sys.stderr.write(
                    f"{colors.GREEN}✓{colors.RESET} "
                    f"Generated addon: {colors.BOLD}{output_path}{colors.RESET}\n"
                )
        except (IOError, OSError) as e:
            formatter.error(f"Cannot write output: {e}")
            return 1
    else:
        # Write to stdout
        sys.stdout.write(addon.code)

    # Write source map if requested
    if args.source_map:
        map_path = (output_path or "addon") + ".map.json"
        try:
            source_map_data = {
                str(gen_line): {
                    "file": loc.file,
                    "line": loc.line,
                    "column": loc.column,
                }
                for gen_line, loc in addon.source_map.items()
                if loc is not None
            }
            with open(map_path, "w") as f:
                json.dump(source_map_data, f, indent=2)
            if not args.quiet:
                sys.stderr.write(
                    f"{colors.GREEN}✓{colors.RESET} "
                    f"Source map: {colors.BOLD}{map_path}{colors.RESET}\n"
                )
        except (IOError, OSError) as e:
            formatter.warning(f"Cannot write source map: {e}")

    if args.verbose:
        pipeline.print_timings()

    formatter.summary()
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    """Handle the 'check' command (parse + validate, no codegen)."""
    colors = _get_colors()
    formatter = DiagnosticFormatter(colors)
    source_mgr = SourceManager()

    try:
        if args.input == "-":
            source = source_mgr.load_stdin()
            filename = "<stdin>"
        else:
            source = source_mgr.load(args.input)
            filename = args.input
    except (FileNotFoundError, PermissionError, ValueError) as e:
        formatter.error(str(e))
        return 1

    pipeline = Pipeline(formatter, source_mgr, verbose=args.verbose)

    # Phase 1: Parse
    spec = pipeline.parse(source, filename)
    if spec is None:
        formatter.summary()
        return 1

    # Phase 2: Semantic analysis
    ctx = pipeline.analyze(spec)
    if ctx is None or formatter.has_errors:
        formatter.summary()
        return 1

    # Success
    if not args.quiet:
        sys.stderr.write(
            f"{colors.GREEN}✓{colors.RESET} "
            f"Specification {colors.BOLD}{spec.name}{colors.RESET} "
            f"is valid.\n"
        )

    if args.verbose:
        pipeline.print_timings()

    formatter.summary()
    return 0


def cmd_dump_ast(args: argparse.Namespace) -> int:
    """Handle the 'dump-ast' command."""
    colors = _get_colors()
    formatter = DiagnosticFormatter(colors)
    source_mgr = SourceManager()

    try:
        if args.input == "-":
            source = source_mgr.load_stdin()
            filename = "<stdin>"
        else:
            source = source_mgr.load(args.input)
            filename = args.input
    except (FileNotFoundError, PermissionError, ValueError) as e:
        formatter.error(str(e))
        return 1

    pipeline = Pipeline(formatter, source_mgr, verbose=args.verbose)

    # Parse only
    spec = pipeline.parse(source, filename)
    if spec is None:
        formatter.summary()
        return 1

    # Dump
    output_colors = _get_colors(sys.stdout)
    dumper = ASTDumper(
        stream=sys.stdout,
        colors=output_colors,
        show_locations=args.show_locations,
    )
    dumper.dump(spec)

    return 0


def cmd_dump_sexp(args: argparse.Namespace) -> int:
    """Handle the 'dump-sexp' command."""
    colors = _get_colors()
    formatter = DiagnosticFormatter(colors)
    source_mgr = SourceManager()

    try:
        if args.input == "-":
            source = source_mgr.load_stdin()
            filename = "<stdin>"
        else:
            source = source_mgr.load(args.input)
            filename = args.input
    except (FileNotFoundError, PermissionError, ValueError) as e:
        formatter.error(str(e))
        return 1

    pipeline = Pipeline(formatter, source_mgr, verbose=args.verbose)

    # Parse only
    spec = pipeline.parse(source, filename)
    if spec is None:
        formatter.summary()
        return 1

    # Dump as S-expression
    dumper = SexpDumper(
        stream=sys.stdout,
        indent=args.indent if hasattr(args, "indent") else 2,
        line_width=args.width if hasattr(args, "width") else 80,
    )
    dumper.dump(spec)

    return 0


def cmd_run(args: argparse.Namespace) -> int:
    """Handle the 'run' command (compile + execute)."""
    colors = _get_colors()
    formatter = DiagnosticFormatter(colors)
    source_mgr = SourceManager()

    try:
        if args.input == "-":
            source = source_mgr.load_stdin()
            filename = "<stdin>"
        else:
            source = source_mgr.load(args.input)
            filename = args.input
    except (FileNotFoundError, PermissionError, ValueError) as e:
        formatter.error(str(e))
        return 1

    # Validate dump file(s)
    dump_files = args.dump_files
    if not dump_files:
        formatter.error("No dump files specified. Use --dump <file.dump>")
        return 1

    for df in dump_files:
        if not os.path.isfile(df):
            formatter.error(f"Dump file not found: {df}")
            return 1

    pipeline = Pipeline(formatter, source_mgr, verbose=args.verbose)

    # Phase 1: Parse
    spec = pipeline.parse(source, filename)
    if spec is None:
        formatter.summary()
        return 1

    # Phase 2: Semantic analysis
    ctx = pipeline.analyze(spec)
    if ctx is None or formatter.has_errors:
        formatter.summary()
        return 1

    # Phase 3: Code generation
    addon = pipeline.generate(spec, ctx)
    if addon is None:
        formatter.summary()
        return 1

    # Phase 4: Execute
    (CASLError, ParseError, SyntaxError_, SemanticError,
     CodeGenError, RuntimeError_, DiagnosticCollector, SourceLocation) = _import_errors()

    with pipeline._timed("execution"):
        try:
            # Compile the generated code into a module
            code_obj = compile(addon.code, f"<casl:{spec.name}>", "exec")
            module_ns: Dict[str, Any] = {"__name__": f"casl_addon_{spec.name}"}
            exec(code_obj, module_ns)

            # Find and call the check() entry point
            check_fn = module_ns.get("check")
            if check_fn is None:
                formatter.error("Generated addon has no check() function")
                return 1

            # Process each dump file
            import cppcheckdata
            for dump_path in dump_files:
                if args.verbose:
                    sys.stderr.write(f"  Processing: {dump_path}\n")

                data = cppcheckdata.parsedump(dump_path)
                for cfg in data.configurations:
                    check_fn(cfg)

        except ImportError as e:
            formatter.error(
                f"Cannot import cppcheckdata: {e}. "
                f"Ensure cppcheckdata.py is on your Python path."
            )
            return 1
        except RuntimeError_ as e:
            formatter.error(f"Runtime error: {e}", getattr(e, "location", None))
            return 1
        except Exception as e:
            formatter.error(f"Execution failed: {e}")
            if args.verbose:
                traceback.print_exc()
            return 1

    if args.verbose:
        pipeline.print_timings()

    formatter.summary()
    return 0 if not formatter.has_errors else 1


def cmd_info(args: argparse.Namespace) -> int:
    """Handle the 'info' command."""
    colors = _get_colors()
    formatter = DiagnosticFormatter(colors)
    source_mgr = SourceManager()

    try:
        if args.input == "-":
            source = source_mgr.load_stdin()
            filename = "<stdin>"
        else:
            source = source_mgr.load(args.input)
            filename = args.input
    except (FileNotFoundError, PermissionError, ValueError) as e:
        formatter.error(str(e))
        return 1

    pipeline = Pipeline(formatter, source_mgr, verbose=False)

    # Parse
    spec = pipeline.parse(source, filename)
    if spec is None:
        formatter.summary()
        return 1

    # Display info
    c = colors
    out = sys.stdout

    out.write(f"\n{c.BOLD}CASL Specification Info{c.RESET}\n")
    out.write(f"{'─' * 50}\n")
    out.write(f"  {c.CYAN}Name:{c.RESET}        {spec.name}\n")

    if spec.metadata:
        m = spec.metadata
        if m.version:
            out.write(f"  {c.CYAN}Version:{c.RESET}     {m.version}\n")
        if m.description:
            out.write(f"  {c.CYAN}Description:{c.RESET} {m.description}\n")
        if m.author:
            out.write(f"  {c.CYAN}Author:{c.RESET}      {m.author}\n")
        if m.tags:
            out.write(f"  {c.CYAN}Tags:{c.RESET}        {', '.join(m.tags)}\n")

    # Count declarations by type
    A = _import_ast()
    decl_counts: Dict[str, int] = {}
    decl_names: Dict[str, List[str]] = {}

    for decl in (spec.declarations or []):
        type_name = type(decl).__name__.replace("Decl", "")
        decl_counts[type_name] = decl_counts.get(type_name, 0) + 1
        name = getattr(decl, "name", None)
        if name:
            decl_names.setdefault(type_name, []).append(name)

    out.write(f"\n  {c.BOLD}Declarations:{c.RESET}\n")
    for dtype, count in sorted(decl_counts.items()):
        names = decl_names.get(dtype, [])
        names_str = ", ".join(names[:5])
        if len(names) > 5:
            names_str += f", ... (+{len(names) - 5} more)"
        out.write(
            f"    {c.YELLOW}{dtype:<12s}{c.RESET} "
            f"{count:>3d}  {c.DIM}{names_str}{c.RESET}\n"
        )

    imports = spec.imports or []
    if imports:
        out.write(f"\n  {c.BOLD}Imports:{c.RESET}\n")
        for imp in imports:
            names = f" ({', '.join(imp.names)})" if imp.names else ""
            out.write(f"    {c.GREEN}{imp.module}{c.RESET}{names}\n")

    out.write(f"\n  {c.CYAN}Source:{c.RESET}      {source_mgr.get_source_name(filename)}\n")
    out.write(f"  {c.CYAN}Size:{c.RESET}        {len(source)} bytes, "
              f"{source.count(chr(10)) + 1} lines\n")
    out.write(f"{'─' * 50}\n\n")

    return 0


def cmd_init(args: argparse.Namespace) -> int:
    """Handle the 'init' command (generate skeleton)."""
    colors = _get_colors()

    name = args.name or "my-addon"
    description = args.description or "A custom Cppcheck addon"
    author = args.author or os.environ.get("USER", os.environ.get("USERNAME", "unknown"))

    skeleton = _generate_skeleton(name, description, author)

    if args.output:
        output_path = args.output
    else:
        output_path = f"{name}.casl"

    if os.path.exists(output_path) and not args.force:
        sys.stderr.write(
            f"{colors.RED}Error:{colors.RESET} "
            f"File already exists: {output_path}\n"
            f"Use --force to overwrite.\n"
        )
        return 1

    try:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(skeleton)
        sys.stderr.write(
            f"{colors.GREEN}✓{colors.RESET} "
            f"Created: {colors.BOLD}{output_path}{colors.RESET}\n"
        )
        return 0
    except (IOError, OSError) as e:
        sys.stderr.write(
            f"{colors.RED}Error:{colors.RESET} Cannot write file: {e}\n"
        )
        return 1


# ═══════════════════════════════════════════════════════════════════════════
# ARGUMENT PARSER
# ═══════════════════════════════════════════════════════════════════════════

def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser for the CASL CLI."""

    # Top-level parser
    parser = argparse.ArgumentParser(
        prog="casl",
        description=__description__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            examples:
              %(prog)s compile my-addon.casl
              %(prog)s compile my-addon.casl -o output.py
              %(prog)s check my-addon.casl
              %(prog)s dump-ast my-addon.casl
              %(prog)s dump-sexp my-addon.casl
              %(prog)s run my-addon.casl --dump project.dump
              %(prog)s info my-addon.casl
              %(prog)s init --name my-addon

            For more information, see: https://github.com/example/casl
        """),
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    # Subcommands
    subparsers = parser.add_subparsers(
        dest="command",
        title="commands",
        description="available commands",
        metavar="<command>",
    )

    # ── compile ──────────────────────────────────────────────────────────

    p_compile = subparsers.add_parser(
        "compile",
        help="Compile a CASL spec to a standalone Cppcheck addon",
        description=(
            "Compile a CASL specification file into a standalone Python "
            "Cppcheck addon. The generated addon can be used directly "
            "with cppcheck --addon=<generated.py>."
        ),
    )
    p_compile.add_argument(
        "input",
        help="Input CASL specification file (use '-' for stdin)",
    )
    p_compile.add_argument(
        "-o", "--output",
        help="Output Python file (default: <input>.py)",
    )
    p_compile.add_argument(
        "--source-map",
        action="store_true",
        default=False,
        help="Generate a source map file (.map.json)",
    )
    p_compile.add_argument(
        "-v", "--verbose",
        action="store_true",
        default=False,
        help="Show detailed compilation progress",
    )
    p_compile.add_argument(
        "-q", "--quiet",
        action="store_true",
        default=False,
        help="Suppress non-error output",
    )
    p_compile.add_argument(
        "--no-optimize",
        action="store_true",
        default=False,
        help="Disable code generation optimizations",
    )
    p_compile.set_defaults(func=cmd_compile)

    # ── check ────────────────────────────────────────────────────────────

    p_check = subparsers.add_parser(
        "check",
        help="Validate a CASL specification without generating code",
        description=(
            "Parse and validate a CASL specification file. Reports "
            "all syntax errors, semantic errors, and warnings without "
            "generating any output code."
        ),
    )
    p_check.add_argument(
        "input",
        help="Input CASL specification file (use '-' for stdin)",
    )
    p_check.add_argument(
        "-v", "--verbose",
        action="store_true",
        default=False,
        help="Show detailed validation progress",
    )
    p_check.add_argument(
        "-q", "--quiet",
        action="store_true",
        default=False,
        help="Suppress non-error output",
    )
    p_check.set_defaults(func=cmd_check)

    # ── dump-ast ─────────────────────────────────────────────────────────

    p_dump_ast = subparsers.add_parser(
        "dump-ast",
        help="Parse a spec and dump the AST in tree form",
        description=(
            "Parse a CASL specification and display its Abstract Syntax "
            "Tree in a human-readable tree format. Useful for debugging "
            "and understanding how CASL parses your specification."
        ),
    )
    p_dump_ast.add_argument(
        "input",
        help="Input CASL specification file (use '-' for stdin)",
    )
    p_dump_ast.add_argument(
        "--show-locations",
        action="store_true",
        default=False,
        help="Show source locations on each AST node",
    )
    p_dump_ast.add_argument(
        "-v", "--verbose",
        action="store_true",
        default=False,
        help="Show detailed progress",
    )
    p_dump_ast.set_defaults(func=cmd_dump_ast)

    # ── dump-sexp ────────────────────────────────────────────────────────

    p_dump_sexp = subparsers.add_parser(
        "dump-sexp",
        help="Parse a spec and dump canonical S-expression form",
        description=(
            "Parse a CASL specification and emit it in canonical, "
            "pretty-printed S-expression form. Useful for normalization, "
            "diff, and round-trip testing."
        ),
    )
    p_dump_sexp.add_argument(
        "input",
        help="Input CASL specification file (use '-' for stdin)",
    )
    p_dump_sexp.add_argument(
        "--indent",
        type=int,
        default=2,
        help="Indentation width (default: 2)",
    )
    p_dump_sexp.add_argument(
        "--width",
        type=int,
        default=80,
        help="Line width for wrapping (default: 80)",
    )
    p_dump_sexp.add_argument(
        "-v", "--verbose",
        action="store_true",
        default=False,
        help="Show detailed progress",
    )
    p_dump_sexp.set_defaults(func=cmd_dump_sexp)

    # ── run ──────────────────────────────────────────────────────────────

    p_run = subparsers.add_parser(
        "run",
        help="Compile and execute against Cppcheck dump file(s)",
        description=(
            "Compile a CASL specification and immediately execute the "
            "generated addon against one or more Cppcheck dump files. "
            "This is equivalent to 'compile' followed by running the "
            "generated addon, but without writing an intermediate file."
        ),
    )
    p_run.add_argument(
        "input",
        help="Input CASL specification file",
    )
    p_run.add_argument(
        "--dump",
        dest="dump_files",
        nargs="+",
        required=True,
        metavar="DUMPFILE",
        help="Cppcheck dump file(s) to analyze",
    )
    p_run.add_argument(
        "--cli",
        action="store_true",
        default=False,
        help="Output results in Cppcheck CLI JSON format",
    )
    p_run.add_argument(
        "-v", "--verbose",
        action="store_true",
        default=False,
        help="Show detailed execution progress",
    )
    p_run.add_argument(
        "-q", "--quiet",
        action="store_true",
        default=False,
        help="Suppress non-error output",
    )
    p_run.set_defaults(func=cmd_run)

    # ── info ─────────────────────────────────────────────────────────────

    p_info = subparsers.add_parser(
        "info",
        help="Display metadata and summary of a CASL specification",
        description=(
            "Parse a CASL specification and display its metadata, "
            "declaration counts, imports, and other summary information."
        ),
    )
    p_info.add_argument(
        "input",
        help="Input CASL specification file (use '-' for stdin)",
    )
    p_info.add_argument(
        "-v", "--verbose",
        action="store_true",
        default=False,
        help="Show detailed progress",
    )
    p_info.set_defaults(func=cmd_info)

    # ── init ─────────────────────────────────────────────────────────────

    p_init = subparsers.add_parser(
        "init",
        help="Generate a skeleton CASL specification file",
        description=(
            "Generate a new CASL specification file with a skeleton "
            "structure including metadata, example patterns, queries, "
            "and checkers. A good starting point for new addons."
        ),
    )
    p_init.add_argument(
        "--name",
        default=None,
        help="Addon name (default: my-addon)",
    )
    p_init.add_argument(
        "--description",
        default=None,
        help="Addon description",
    )
    p_init.add_argument(
        "--author",
        default=None,
        help="Author name",
    )
    p_init.add_argument(
        "-o", "--output",
        default=None,
        help="Output file path (default: <name>.casl)",
    )
    p_init.add_argument(
        "-f", "--force",
        action="store_true",
        default=False,
        help="Overwrite existing file",
    )
    p_init.set_defaults(func=cmd_init)

    return parser


# ═══════════════════════════════════════════════════════════════════════════
# TEXTWRAP IMPORT (for epilog)
# ═══════════════════════════════════════════════════════════════════════════

import textwrap


# ═══════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════

def main(argv: Optional[Sequence[str]] = None) -> int:
    """Main entry point for the CASL CLI.

    Parameters
    ----------
    argv : sequence of str, optional
        Command-line arguments. Defaults to sys.argv[1:].

    Returns
    -------
    int
        Exit code (0 = success, non-zero = failure).
    """
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return 0

    # Dispatch to the appropriate command handler
    try:
        return args.func(args)
    except KeyboardInterrupt:
        sys.stderr.write("\nInterrupted.\n")
        return 130
    except BrokenPipeError:
        # Handle piping to head, etc.
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
        return 0
    except Exception as e:
        colors = _get_colors()
        sys.stderr.write(
            f"\n{colors.RED}{colors.BOLD}"
            f"Internal error:{colors.RESET} {e}\n"
        )
        sys.stderr.write(
            f"{colors.DIM}This is a bug in CASL. Please report it.{colors.RESET}\n\n"
        )
        traceback.print_exc()
        return 2


if __name__ == "__main__":
    sys.exit(main())
