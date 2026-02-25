#!/usr/bin/env python3
"""
docs/extract_docs.py
====================

Documentation extractor for cppcheckdata_shims modules.

Parses Python source files and extracts:
  - Module-level docstrings
  - Class docstrings and method signatures
  - Function docstrings and signatures
  - Type hints
  - Constants and their annotations

Usage:
    python extract_docs.py <module_path> [--output <output_path>] [--format md|json|rst]

Example:
    python extract_docs.py ../cppcheckdata_shims/abstract_domains.py --output api/abstract_domains.md
"""

from __future__ import annotations

import ast
import argparse
import inspect
import json
import re
import sys
import textwrap
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union


# ═══════════════════════════════════════════════════════════════════════════
#  DATA STRUCTURES
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class ParameterInfo:
    """Information about a function/method parameter."""
    name: str
    annotation: Optional[str] = None
    default: Optional[str] = None
    
    def signature_str(self) -> str:
        """Return parameter as it would appear in a signature."""
        parts = [self.name]
        if self.annotation:
            parts.append(f": {self.annotation}")
        if self.default:
            parts.append(f" = {self.default}")
        return "".join(parts)


@dataclass
class FunctionDoc:
    """Documentation for a function or method."""
    name: str
    docstring: Optional[str]
    parameters: List[ParameterInfo] = field(default_factory=list)
    return_annotation: Optional[str] = None
    decorators: List[str] = field(default_factory=list)
    is_async: bool = False
    is_classmethod: bool = False
    is_staticmethod: bool = False
    is_property: bool = False
    lineno: int = 0
    
    def signature(self) -> str:
        """Generate the function signature string."""
        params = ", ".join(p.signature_str() for p in self.parameters)
        ret = f" -> {self.return_annotation}" if self.return_annotation else ""
        prefix = "async " if self.is_async else ""
        return f"{prefix}def {self.name}({params}){ret}"


@dataclass
class ClassDoc:
    """Documentation for a class."""
    name: str
    docstring: Optional[str]
    bases: List[str] = field(default_factory=list)
    methods: List[FunctionDoc] = field(default_factory=list)
    class_variables: Dict[str, str] = field(default_factory=dict)
    decorators: List[str] = field(default_factory=list)
    lineno: int = 0
    
    def signature(self) -> str:
        """Generate the class signature string."""
        bases_str = f"({', '.join(self.bases)})" if self.bases else ""
        return f"class {self.name}{bases_str}"


@dataclass
class ConstantDoc:
    """Documentation for a module-level constant."""
    name: str
    value: Optional[str]
    annotation: Optional[str] = None
    lineno: int = 0


@dataclass
class ModuleDoc:
    """Complete documentation for a module."""
    name: str
    filepath: str
    docstring: Optional[str]
    classes: List[ClassDoc] = field(default_factory=list)
    functions: List[FunctionDoc] = field(default_factory=list)
    constants: List[ConstantDoc] = field(default_factory=list)
    imports: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "name": self.name,
            "filepath": self.filepath,
            "docstring": self.docstring,
            "classes": [
                {
                    "name": c.name,
                    "signature": c.signature(),
                    "docstring": c.docstring,
                    "bases": c.bases,
                    "decorators": c.decorators,
                    "lineno": c.lineno,
                    "methods": [
                        {
                            "name": m.name,
                            "signature": m.signature(),
                            "docstring": m.docstring,
                            "decorators": m.decorators,
                            "lineno": m.lineno,
                        }
                        for m in c.methods
                    ],
                    "class_variables": c.class_variables,
                }
                for c in self.classes
            ],
            "functions": [
                {
                    "name": f.name,
                    "signature": f.signature(),
                    "docstring": f.docstring,
                    "decorators": f.decorators,
                    "lineno": f.lineno,
                }
                for f in self.functions
            ],
            "constants": [
                {
                    "name": c.name,
                    "value": c.value,
                    "annotation": c.annotation,
                    "lineno": c.lineno,
                }
                for c in self.constants
            ],
        }


# ═══════════════════════════════════════════════════════════════════════════
#  AST EXTRACTION
# ═══════════════════════════════════════════════════════════════════════════

class DocExtractor(ast.NodeVisitor):
    """
    AST visitor that extracts documentation from Python source code.
    """
    
    def __init__(self, source: str, filepath: str):
        self.source = source
        self.source_lines = source.splitlines()
        self.filepath = filepath
        self.module_doc = ModuleDoc(
            name=Path(filepath).stem,
            filepath=filepath,
            docstring=None,
        )
        self._current_class: Optional[ClassDoc] = None
    
    def extract(self) -> ModuleDoc:
        """Parse the source and extract documentation."""
        tree = ast.parse(self.source, filename=self.filepath)
        
        # Get module docstring
        self.module_doc.docstring = ast.get_docstring(tree)
        
        # Visit all nodes
        self.visit(tree)
        
        return self.module_doc
    
    def _get_annotation_str(self, node: Optional[ast.expr]) -> Optional[str]:
        """Convert an annotation AST node to string."""
        if node is None:
            return None
        return ast.unparse(node)
    
    def _get_decorator_str(self, decorator: ast.expr) -> str:
        """Convert a decorator AST node to string."""
        return ast.unparse(decorator)
    
    def _get_value_str(self, node: ast.expr, max_length: int = 100) -> str:
        """Convert a value AST node to string, truncating if too long."""
        try:
            value = ast.unparse(node)
            if len(value) > max_length:
                return value[:max_length] + "..."
            return value
        except Exception:
            return "<complex expression>"
    
    def _extract_parameters(self, args: ast.arguments) -> List[ParameterInfo]:
        """Extract parameter information from function arguments."""
        params = []
        
        # Positional-only args (Python 3.8+)
        defaults_offset = len(args.posonlyargs) + len(args.args) - len(args.defaults)
        
        all_positional = args.posonlyargs + args.args
        for i, arg in enumerate(all_positional):
            default_idx = i - defaults_offset
            default = None
            if default_idx >= 0 and default_idx < len(args.defaults):
                default = self._get_value_str(args.defaults[default_idx])
            
            params.append(ParameterInfo(
                name=arg.arg,
                annotation=self._get_annotation_str(arg.annotation),
                default=default,
            ))
        
        # *args
        if args.vararg:
            params.append(ParameterInfo(
                name=f"*{args.vararg.arg}",
                annotation=self._get_annotation_str(args.vararg.annotation),
            ))
        
        # Keyword-only args
        kw_defaults_map = {
            i: d for i, d in enumerate(args.kw_defaults) if d is not None
        }
        for i, arg in enumerate(args.kwonlyargs):
            default = None
            if i in kw_defaults_map:
                default = self._get_value_str(kw_defaults_map[i])
            params.append(ParameterInfo(
                name=arg.arg,
                annotation=self._get_annotation_str(arg.annotation),
                default=default,
            ))
        
        # **kwargs
        if args.kwarg:
            params.append(ParameterInfo(
                name=f"**{args.kwarg.arg}",
                annotation=self._get_annotation_str(args.kwarg.annotation),
            ))
        
        return params
    
    def _extract_function(self, node: Union[ast.FunctionDef, ast.AsyncFunctionDef]) -> FunctionDoc:
        """Extract documentation from a function definition."""
        decorators = [self._get_decorator_str(d) for d in node.decorator_list]
        
        return FunctionDoc(
            name=node.name,
            docstring=ast.get_docstring(node),
            parameters=self._extract_parameters(node.args),
            return_annotation=self._get_annotation_str(node.returns),
            decorators=decorators,
            is_async=isinstance(node, ast.AsyncFunctionDef),
            is_classmethod="classmethod" in decorators,
            is_staticmethod="staticmethod" in decorators,
            is_property="property" in decorators,
            lineno=node.lineno,
        )
    
    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Visit a class definition."""
        bases = [ast.unparse(base) for base in node.bases]
        decorators = [self._get_decorator_str(d) for d in node.decorator_list]
        
        class_doc = ClassDoc(
            name=node.name,
            docstring=ast.get_docstring(node),
            bases=bases,
            decorators=decorators,
            lineno=node.lineno,
        )
        
        # Extract methods and class variables
        for item in node.body:
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                method_doc = self._extract_function(item)
                class_doc.methods.append(method_doc)
            elif isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name):
                # Class variable with annotation
                var_name = item.target.id
                annotation = self._get_annotation_str(item.annotation)
                class_doc.class_variables[var_name] = annotation or "Any"
            elif isinstance(item, ast.Assign):
                # Class variable without annotation
                for target in item.targets:
                    if isinstance(target, ast.Name):
                        class_doc.class_variables[target.id] = "Any"
        
        self.module_doc.classes.append(class_doc)
    
    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Visit a top-level function definition."""
        if self._current_class is None:
            func_doc = self._extract_function(node)
            self.module_doc.functions.append(func_doc)
    
    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """Visit a top-level async function definition."""
        if self._current_class is None:
            func_doc = self._extract_function(node)
            self.module_doc.functions.append(func_doc)
    
    def visit_Assign(self, node: ast.Assign) -> None:
        """Visit a top-level assignment (potential constant)."""
        for target in node.targets:
            if isinstance(target, ast.Name):
                name = target.id
                # Heuristic: UPPER_CASE names are constants
                if name.isupper() or name.startswith("_") and name[1:].isupper():
                    self.module_doc.constants.append(ConstantDoc(
                        name=name,
                        value=self._get_value_str(node.value),
                        lineno=node.lineno,
                    ))
    
    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        """Visit a top-level annotated assignment."""
        if isinstance(node.target, ast.Name):
            name = node.target.id
            if name.isupper() or (name.startswith("_") and len(name) > 1 and name[1:].isupper()):
                value = self._get_value_str(node.value) if node.value else None
                self.module_doc.constants.append(ConstantDoc(
                    name=name,
                    value=value,
                    annotation=self._get_annotation_str(node.annotation),
                    lineno=node.lineno,
                ))
    
    def visit_Import(self, node: ast.Import) -> None:
        """Track imports."""
        for alias in node.names:
            self.module_doc.imports.append(alias.name)
    
    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Track from imports."""
        module = node.module or ""
        for alias in node.names:
            self.module_doc.imports.append(f"{module}.{alias.name}")


# ═══════════════════════════════════════════════════════════════════════════
#  FORMATTERS
# ═══════════════════════════════════════════════════════════════════════════

class MarkdownFormatter:
    """Format extracted documentation as Markdown."""
    
    def __init__(self, module_doc: ModuleDoc):
        self.doc = module_doc
    
    def format(self) -> str:
        """Generate complete Markdown documentation."""
        sections = []
        
        # Title
        sections.append(f"# `{self.doc.name}` Module\n")
        sections.append(f"**Source:** `{self.doc.filepath}`\n")
        
        # Module docstring
        if self.doc.docstring:
            sections.append("## Overview\n")
            sections.append(self._format_docstring(self.doc.docstring))
            sections.append("")
        
        # Table of Contents
        sections.append(self._generate_toc())
        
        # Constants
        if self.doc.constants:
            sections.append("## Constants\n")
            for const in self.doc.constants:
                sections.append(self._format_constant(const))
        
        # Functions
        if self.doc.functions:
            sections.append("## Functions\n")
            for func in self.doc.functions:
                sections.append(self._format_function(func))
        
        # Classes
        if self.doc.classes:
            sections.append("## Classes\n")
            for cls in self.doc.classes:
                sections.append(self._format_class(cls))
        
        return "\n".join(sections)
    
    def _generate_toc(self) -> str:
        """Generate table of contents."""
        lines = ["## Table of Contents\n"]
        
        if self.doc.constants:
            lines.append("### Constants")
            for const in self.doc.constants:
                anchor = const.name.lower().replace("_", "-")
                lines.append(f"- [`{const.name}`](#{anchor})")
            lines.append("")
        
        if self.doc.functions:
            lines.append("### Functions")
            for func in self.doc.functions:
                anchor = func.name.lower().replace("_", "-")
                lines.append(f"- [`{func.name}()`](#{anchor})")
            lines.append("")
        
        if self.doc.classes:
            lines.append("### Classes")
            for cls in self.doc.classes:
                anchor = cls.name.lower().replace("_", "-")
                lines.append(f"- [`{cls.name}`](#{anchor})")
                # List important methods
                public_methods = [m for m in cls.methods if not m.name.startswith("_")]
                if public_methods:
                    for method in public_methods[:5]:  # Limit to first 5
                        method_anchor = f"{cls.name.lower()}-{method.name.lower()}".replace("_", "-")
                        lines.append(f"  - [`{method.name}()`](#{method_anchor})")
                    if len(public_methods) > 5:
                        lines.append(f"  - *...and {len(public_methods) - 5} more*")
            lines.append("")
        
        return "\n".join(lines)
    
    def _format_docstring(self, docstring: str) -> str:
        """Format a docstring, preserving code blocks and structure."""
        # Preserve ASCII art and code blocks
        lines = docstring.split("\n")
        result = []
        in_code_block = False
        
        for line in lines:
            # Detect code block markers
            if line.strip().startswith("```") or line.strip().startswith(">>>"):
                if not in_code_block and line.strip().startswith(">>>"):
                    result.append("```python")
                    in_code_block = True
                elif line.strip().startswith("```"):
                    in_code_block = not in_code_block
            
            # Detect ASCII art (lines with box-drawing characters or multiple special chars)
            if any(c in line for c in "═─│┌┐└┘├┤┬┴┼╔╗╚╝╠╣╦╩╬"):
                if not in_code_block:
                    result.append("```")
                    in_code_block = True
            
            result.append(line)
        
        # Close any unclosed code block
        if in_code_block:
            result.append("```")
        
        return "\n".join(result)
    
    def _format_constant(self, const: ConstantDoc) -> str:
        """Format a constant definition."""
        lines = [f"### `{const.name}`\n"]
        
        if const.annotation:
            lines.append(f"**Type:** `{const.annotation}`\n")
        if const.value:
            lines.append(f"**Value:** `{const.value}`\n")
        
        lines.append(f"*Defined at line {const.lineno}*\n")
        lines.append("---\n")
        
        return "\n".join(lines)
    
    def _format_function(self, func: FunctionDoc, heading_level: int = 3) -> str:
        """Format a function definition."""
        heading = "#" * heading_level
        lines = [f"{heading} `{func.name}`\n"]
        
        # Decorators
        if func.decorators:
            lines.append("**Decorators:**")
            for dec in func.decorators:
                lines.append(f"- `@{dec}`")
            lines.append("")
        
        # Signature
        lines.append("```python")
        lines.append(func.signature())
        lines.append("```\n")
        
        # Docstring
        if func.docstring:
            lines.append(self._format_docstring(func.docstring))
            lines.append("")
        
        lines.append(f"*Defined at line {func.lineno}*\n")
        lines.append("---\n")
        
        return "\n".join(lines)
    
    def _format_class(self, cls: ClassDoc) -> str:
        """Format a class definition."""
        lines = [f"### `{cls.name}`\n"]
        
        # Decorators
        if cls.decorators:
            lines.append("**Decorators:**")
            for dec in cls.decorators:
                lines.append(f"- `@{dec}`")
            lines.append("")
        
        # Signature
        lines.append("```python")
        lines.append(cls.signature())
        lines.append("```\n")
        
        # Bases
        if cls.bases:
            lines.append(f"**Inherits from:** {', '.join(f'`{b}`' for b in cls.bases)}\n")
        
        # Docstring
        if cls.docstring:
            lines.append(self._format_docstring(cls.docstring))
            lines.append("")
        
        # Class variables
        if cls.class_variables:
            lines.append("#### Class Variables\n")
            lines.append("| Name | Type |")
            lines.append("|------|------|")
            for name, type_hint in cls.class_variables.items():
                lines.append(f"| `{name}` | `{type_hint}` |")
            lines.append("")
        
        # Methods
        if cls.methods:
            lines.append("#### Methods\n")
            
            # Group methods
            special_methods = [m for m in cls.methods if m.name.startswith("__")]
            class_methods = [m for m in cls.methods if m.is_classmethod and not m.name.startswith("__")]
            static_methods = [m for m in cls.methods if m.is_staticmethod and not m.name.startswith("__")]
            properties = [m for m in cls.methods if m.is_property]
            regular_methods = [
                m for m in cls.methods 
                if not m.name.startswith("__") 
                and not m.is_classmethod 
                and not m.is_staticmethod 
                and not m.is_property
            ]
            
            if class_methods:
                lines.append("##### Class Methods\n")
                for method in class_methods:
                    lines.append(self._format_function(method, heading_level=6))
            
            if static_methods:
                lines.append("##### Static Methods\n")
                for method in static_methods:
                    lines.append(self._format_function(method, heading_level=6))
            
            if properties:
                lines.append("##### Properties\n")
                for method in properties:
                    lines.append(self._format_function(method, heading_level=6))
            
            if regular_methods:
                lines.append("##### Instance Methods\n")
                for method in regular_methods:
                    lines.append(self._format_function(method, heading_level=6))
            
            if special_methods:
                lines.append("<details>\n<summary><strong>Special Methods</strong></summary>\n")
                for method in special_methods:
                    lines.append(self._format_function(method, heading_level=6))
                lines.append("</details>\n")
        
        lines.append(f"*Defined at line {cls.lineno}*\n")
        lines.append("---\n")
        
        return "\n".join(lines)


class RstFormatter:
    """Format extracted documentation as reStructuredText."""
    
    def __init__(self, module_doc: ModuleDoc):
        self.doc = module_doc
    
    def format(self) -> str:
        """Generate complete RST documentation."""
        sections = []
        
        # Title
        title = f"``{self.doc.name}`` Module"
        sections.append(title)
        sections.append("=" * len(title))
        sections.append("")
        sections.append(f".. module:: {self.doc.name}")
        sections.append(f"   :synopsis: {self._get_synopsis()}")
        sections.append("")
        
        # Module docstring
        if self.doc.docstring:
            sections.append("Overview")
            sections.append("-" * 8)
            sections.append("")
            sections.append(self.doc.docstring)
            sections.append("")
        
        # Constants
        if self.doc.constants:
            sections.append("Constants")
            sections.append("-" * 9)
            sections.append("")
            for const in self.doc.constants:
                sections.append(f".. data:: {const.name}")
                if const.annotation:
                    sections.append(f"   :type: {const.annotation}")
                if const.value:
                    sections.append(f"   :value: {const.value}")
                sections.append("")
        
        # Functions
        if self.doc.functions:
            sections.append("Functions")
            sections.append("-" * 9)
            sections.append("")
            for func in self.doc.functions:
                sections.append(self._format_function_rst(func))
        
        # Classes
        if self.doc.classes:
            sections.append("Classes")
            sections.append("-" * 7)
            sections.append("")
            for cls in self.doc.classes:
                sections.append(self._format_class_rst(cls))
        
        return "\n".join(sections)
    
    def _get_synopsis(self) -> str:
        """Extract a one-line synopsis from the module docstring."""
        if not self.doc.docstring:
            return "No description available."
        first_line = self.doc.docstring.split("\n")[0].strip()
        return first_line[:80] if len(first_line) > 80 else first_line
    
    def _format_function_rst(self, func: FunctionDoc) -> str:
        """Format a function in RST."""
        lines = []
        sig = func.signature().replace("def ", "")
        lines.append(f".. function:: {sig}")
        lines.append("")
        if func.docstring:
            for line in func.docstring.split("\n"):
                lines.append(f"   {line}")
        lines.append("")
        return "\n".join(lines)
    
    def _format_class_rst(self, cls: ClassDoc) -> str:
        """Format a class in RST."""
        lines = []
        lines.append(f".. class:: {cls.signature().replace('class ', '')}")
        lines.append("")
        if cls.docstring:
            for line in cls.docstring.split("\n"):
                lines.append(f"   {line}")
            lines.append("")
        
        for method in cls.methods:
            sig = method.signature().replace("def ", "")
            lines.append(f"   .. method:: {sig}")
            lines.append("")
            if method.docstring:
                for line in method.docstring.split("\n"):
                    lines.append(f"      {line}")
            lines.append("")
        
        return "\n".join(lines)


class JsonFormatter:
    """Format extracted documentation as JSON."""
    
    def __init__(self, module_doc: ModuleDoc):
        self.doc = module_doc
    
    def format(self) -> str:
        """Generate JSON documentation."""
        return json.dumps(self.doc.to_dict(), indent=2, ensure_ascii=False)


# ═══════════════════════════════════════════════════════════════════════════
#  MAIN ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════

def extract_module_docs(filepath: str) -> ModuleDoc:
    """Extract documentation from a Python module file."""
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"Module file not found: {filepath}")
    
    source = path.read_text(encoding="utf-8")
    extractor = DocExtractor(source, filepath)
    return extractor.extract()


def format_docs(module_doc: ModuleDoc, fmt: str = "md") -> str:
    """Format extracted documentation in the specified format."""
    formatters = {
        "md": MarkdownFormatter,
        "markdown": MarkdownFormatter,
        "rst": RstFormatter,
        "json": JsonFormatter,
    }
    
    formatter_cls = formatters.get(fmt.lower())
    if not formatter_cls:
        raise ValueError(f"Unknown format: {fmt}. Supported: {list(formatters.keys())}")
    
    return formatter_cls(module_doc).format()


def main():
    parser = argparse.ArgumentParser(
        description="Extract documentation from Python modules.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s ../cppcheckdata_shims/abstract_domains.py
  %(prog)s ../cppcheckdata_shims/abstract_domains.py --output api/abstract_domains.md
  %(prog)s ../cppcheckdata_shims/abstract_domains.py --format json
        """,
    )
    parser.add_argument("module", help="Path to the Python module file")
    parser.add_argument(
        "--output", "-o",
        help="Output file path (default: stdout)",
    )
    parser.add_argument(
        "--format", "-f",
        choices=["md", "markdown", "rst", "json"],
        default="md",
        help="Output format (default: md)",
    )
    
    args = parser.parse_args()
    
    try:
        module_doc = extract_module_docs(args.module)
        output = format_docs(module_doc, args.format)
        
        if args.output:
            output_path = Path(args.output)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(output, encoding="utf-8")
            print(f"Documentation written to: {args.output}", file=sys.stderr)
        else:
            print(output)
    
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()