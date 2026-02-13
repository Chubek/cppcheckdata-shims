#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
casl/codegen.py
===============

Code generator for CASL specifications.

This module transforms validated CASL ASTs into executable Python code
that implements Cppcheck addons. The generated code:

1. Imports necessary runtime support from `casl.runtime`
2. Defines pattern matchers as Python functions
3. Compiles constraints to Python predicates
4. Generates dataflow analysis configurations
5. Produces the `check(data)` entry point expected by Cppcheck

Architecture
------------
The code generator uses a multi-pass approach:

1. **Prologue generation** — imports, constants, domain setup
2. **Domain compilation** — abstract domain definitions
3. **Pattern compilation** — pattern matching functions
4. **Dataflow compilation** — transfer functions, analysis setup
5. **Query compilation** — constraint checking, action execution
6. **Checker compilation** — main checker orchestration
7. **Epilogue generation** — check() entry point, CLI support

Design Principles
-----------------
- **Readability**: Generated code is formatted and commented
- **Debuggability**: Line mappings back to CASL source
- **Efficiency**: Avoid unnecessary allocations in hot paths
- **Correctness**: Preserve CASL semantics exactly

References
----------
- PQL code generation strategy
- Møller & Schwartzbach interprocedural analysis
- Cppcheck addon API conventions
"""

from __future__ import annotations

import hashlib
import keyword
import re
import textwrap
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from io import StringIO
from typing import (
    Any,
    Callable,
    Dict,
    FrozenSet,
    Iterator,
    List,
    Mapping,
    Optional,
    Sequence,
    Set,
    Tuple,
    Union,
)

from casl import ast as A
from casl.visitor import ASTVisitor, DepthFirstVisitor
from casl.semantic import SemanticContext, Symbol, SymbolKind
from casl.errors import CodeGenError, SourceLocation

__all__ = [
    "generate",
    "CodeGenerator",
    "CodeEmitter",
    "GeneratedAddon",
]


# ═══════════════════════════════════════════════════════════════════════════
# CODE EMITTER
# ═══════════════════════════════════════════════════════════════════════════

class CodeEmitter:
    """Low-level code emission with indentation management.
    
    Provides a structured way to emit Python code with:
    - Automatic indentation tracking
    - Block context managers
    - Line and source mapping
    - String literal escaping
    """
    
    def __init__(self, indent_str: str = "    ") -> None:
        self._buffer = StringIO()
        self._indent_str = indent_str
        self._indent_level = 0
        self._line_number = 1
        self._source_map: Dict[int, SourceLocation] = {}
        self._current_source: Optional[SourceLocation] = None
    
    def emit(self, code: str) -> None:
        """Emit a line of code at the current indentation."""
        if code.strip():  # Non-empty line
            self._buffer.write(self._indent_str * self._indent_level)
            self._buffer.write(code)
            if self._current_source:
                self._source_map[self._line_number] = self._current_source
        self._buffer.write("\n")
        self._line_number += 1
    
    def emit_raw(self, code: str) -> None:
        """Emit code without indentation (for multi-line strings)."""
        for line in code.split("\n"):
            self._buffer.write(line)
            self._buffer.write("\n")
            self._line_number += 1
    
    def emit_blank(self, count: int = 1) -> None:
        """Emit blank lines."""
        for _ in range(count):
            self._buffer.write("\n")
            self._line_number += 1
    
    def emit_comment(self, text: str) -> None:
        """Emit a comment."""
        for line in text.split("\n"):
            self.emit(f"# {line}")
    
    def emit_docstring(self, text: str) -> None:
        """Emit a docstring."""
        lines = text.strip().split("\n")
        if len(lines) == 1:
            self.emit(f'"""{lines[0]}"""')
        else:
            self.emit('"""')
            for line in lines:
                self.emit(line)
            self.emit('"""')
    
    def indent(self) -> None:
        """Increase indentation level."""
        self._indent_level += 1
    
    def dedent(self) -> None:
        """Decrease indentation level."""
        self._indent_level = max(0, self._indent_level - 1)
    
    def block(self, header: str) -> "CodeEmitter._BlockContext":
        """Context manager for indented blocks."""
        return self._BlockContext(self, header)
    
    class _BlockContext:
        """Context manager for code blocks."""
        
        def __init__(self, emitter: "CodeEmitter", header: str) -> None:
            self._emitter = emitter
            self._header = header
        
        def __enter__(self) -> "CodeEmitter":
            self._emitter.emit(self._header)
            self._emitter.indent()
            return self._emitter
        
        def __exit__(self, *args: Any) -> None:
            self._emitter.dedent()
    
    def set_source(self, location: Optional[SourceLocation]) -> None:
        """Set current source location for mapping."""
        self._current_source = location
    
    def get_code(self) -> str:
        """Get the generated code."""
        return self._buffer.getvalue()
    
    def get_source_map(self) -> Dict[int, SourceLocation]:
        """Get the source map (generated line -> CASL location)."""
        return dict(self._source_map)
    
    @staticmethod
    def escape_string(s: str) -> str:
        """Escape a string for Python code."""
        return repr(s)
    
    @staticmethod
    def make_identifier(name: str) -> str:
        """Convert a name to a valid Python identifier."""
        # Replace hyphens with underscores
        result = name.replace("-", "_")
        # Remove invalid characters
        result = re.sub(r"[^a-zA-Z0-9_]", "", result)
        # Ensure doesn't start with digit
        if result and result[0].isdigit():
            result = "_" + result
        # Handle Python keywords
        if keyword.iskeyword(result):
            result = result + "_"
        return result or "_unnamed"


# ═══════════════════════════════════════════════════════════════════════════
# GENERATED ADDON CONTAINER
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class GeneratedAddon:
    """Container for generated addon code and metadata."""
    
    code: str
    source_map: Dict[int, SourceLocation]
    spec_name: str
    spec_version: str
    generation_time: str
    checkers: List[str]
    domains: List[str]
    patterns: List[str]
    
    def write_to_file(self, path: str) -> None:
        """Write the generated code to a file."""
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.code)
    
    def get_metadata_comment(self) -> str:
        """Get a metadata comment for the generated file."""
        return f"""\
# Generated by CASL Code Generator
# Specification: {self.spec_name} v{self.spec_version}
# Generated: {self.generation_time}
# Checkers: {', '.join(self.checkers)}
# Domains: {', '.join(self.domains)}
# Patterns: {', '.join(self.patterns)}
"""


# ═══════════════════════════════════════════════════════════════════════════
# EXPRESSION COMPILER
# ═══════════════════════════════════════════════════════════════════════════

class ExpressionCompiler(ASTVisitor):
    """Compile CASL expressions to Python expressions."""
    
    def __init__(self, context: "CompilationContext") -> None:
        self.ctx = context
    
    def compile(self, expr: A.Expr) -> str:
        """Compile an expression to Python code."""
        return self.visit(expr)
    
    def visit_integer_lit(self, node: A.IntegerLit) -> str:
        return str(node.value)
    
    def visit_float_lit(self, node: A.FloatLit) -> str:
        return repr(node.value)
    
    def visit_string_lit(self, node: A.StringLit) -> str:
        return repr(node.value)
    
    def visit_bool_lit(self, node: A.BoolLit) -> str:
        return "True" if node.value else "False"
    
    def visit_nil_lit(self, node: A.NilLit) -> str:
        return "None"
    
    def visit_symbol_lit(self, node: A.SymbolLit) -> str:
        # Symbols become Python strings with a prefix
        return f"Symbol({repr(node.name)})"
    
    def visit_identifier(self, node: A.Identifier) -> str:
        name = CodeEmitter.make_identifier(node.name)
        # Check if it's a pattern variable
        if name in self.ctx.pattern_variables:
            return f"bindings[{repr(node.name)}]"
        # Check if it's a local variable
        if name in self.ctx.local_variables:
            return name
        # Check if it's a domain value
        if node.name in self.ctx.domain_values:
            domain, value = self.ctx.domain_values[node.name]
            return f"{domain}.{value}"
        # Default to identifier
        return name
    
    def visit_list_expr(self, node: A.ListExpr) -> str:
        elements = ", ".join(self.visit(e) for e in node.elements)
        return f"[{elements}]"
    
    def visit_set_expr(self, node: A.SetExpr) -> str:
        if not node.elements:
            return "frozenset()"
        elements = ", ".join(self.visit(e) for e in node.elements)
        return f"frozenset({{{elements}}})"
    
    def visit_map_expr(self, node: A.MapExpr) -> str:
        if not node.entries:
            return "{}"
        entries = ", ".join(
            f"{self.visit(k)}: {self.visit(v)}"
            for k, v in node.entries
        )
        return f"{{{entries}}}"
    
    def visit_tuple_expr(self, node: A.TupleExpr) -> str:
        elements = ", ".join(self.visit(e) for e in node.elements)
        if len(node.elements) == 1:
            return f"({elements},)"
        return f"({elements})"
    
    def visit_call_expr(self, node: A.CallExpr) -> str:
        func = self.visit(node.function)
        args = ", ".join(self.visit(a) for a in node.arguments)
        
        # Handle special built-in functions
        if isinstance(node.function, A.Identifier):
            fname = node.function.name
            if fname == "join":
                return f"_lattice_join({args})"
            elif fname == "meet":
                return f"_lattice_meet({args})"
            elif fname == "widen":
                return f"_lattice_widen({args})"
            elif fname == "leq":
                return f"_lattice_leq({args})"
            elif fname == "lookup":
                return f"_map_lookup({args})"
            elif fname == "update":
                return f"_map_update({args})"
            elif fname == "union":
                return f"_set_union({args})"
            elif fname == "intersect":
                return f"_set_intersect({args})"
            elif fname == "member":
                return f"_set_member({args})"
            elif fname == "empty-set":
                return "frozenset()"
            elif fname == "empty-map":
                return "{}"
            elif fname == "singleton":
                return f"frozenset({{{args}}})"
        
        return f"{func}({args})"
    
    def visit_field_access(self, node: A.FieldAccess) -> str:
        obj = self.visit(node.object)
        field = CodeEmitter.make_identifier(node.field)
        return f"{obj}.{field}"
    
    def visit_index_access(self, node: A.IndexAccess) -> str:
        obj = self.visit(node.object)
        index = self.visit(node.index)
        return f"{obj}[{index}]"
    
    def visit_unary_expr(self, node: A.UnaryExpr) -> str:
        operand = self.visit(node.operand)
        op_map = {
            "not": "not ",
            "-": "-",
            "+": "+",
            "~": "~",
        }
        op = op_map.get(node.operator, node.operator)
        return f"({op}{operand})"
    
    def visit_binary_expr(self, node: A.BinaryExpr) -> str:
        left = self.visit(node.left)
        right = self.visit(node.right)
        
        op_map = {
            "and": "and",
            "or": "or",
            "==": "==",
            "!=": "!=",
            "<": "<",
            "<=": "<=",
            ">": ">",
            ">=": ">=",
            "+": "+",
            "-": "-",
            "*": "*",
            "/": "/",
            "%": "%",
            "in": "in",
        }
        op = op_map.get(node.operator, node.operator)
        return f"({left} {op} {right})"
    
    def visit_cond_expr(self, node: A.CondExpr) -> str:
        cond = self.visit(node.condition)
        then = self.visit(node.then_expr)
        else_ = self.visit(node.else_expr)
        return f"({then} if {cond} else {else_})"
    
    def visit_let_expr(self, node: A.LetExpr) -> str:
        # Let expressions become immediately-invoked lambdas
        bindings = []
        for name, value in node.bindings:
            bindings.append(f"{CodeEmitter.make_identifier(name)}={self.visit(value)}")
        body = self.visit(node.body)
        params = ", ".join(CodeEmitter.make_identifier(n) for n, _ in node.bindings)
        args = ", ".join(bindings)
        return f"(lambda {params}: {body})({args})"
    
    def visit_lambda_expr(self, node: A.LambdaExpr) -> str:
        params = ", ".join(CodeEmitter.make_identifier(p.name) for p in node.params)
        body = self.visit(node.body)
        return f"(lambda {params}: {body})"
    
    def generic_visit(self, node: A.ASTNode) -> str:
        raise CodeGenError(
            f"Cannot compile expression of type {type(node).__name__}",
            getattr(node, "location", None),
        )


# ═══════════════════════════════════════════════════════════════════════════
# PATTERN COMPILER
# ═══════════════════════════════════════════════════════════════════════════

class PatternCompiler(ASTVisitor):
    """Compile CASL code patterns to Python pattern matching code."""
    
    def __init__(self, context: "CompilationContext") -> None:
        self.ctx = context
        self._var_counter = 0
    
    def compile(self, pattern: A.CodePattern, func_name: str) -> str:
        """Compile a pattern to a Python matching function."""
        emitter = CodeEmitter()
        
        with emitter.block(f"def {func_name}(token, binding):"):
            emitter.emit_docstring(f"Match pattern: {pattern}")
            emitter.emit("bindings = dict(binding)")
            emitter.emit_blank()
            
            # Generate matching code
            match_code = self._compile_pattern(pattern, "token")
            for line in match_code:
                emitter.emit(line)
            
            emitter.emit_blank()
            emitter.emit("return bindings")
        
        return emitter.get_code()
    
    def _compile_pattern(self, pattern: A.CodePattern, target: str) -> List[str]:
        """Compile a pattern, returning lines of matching code."""
        return self.visit(pattern, target)
    
    def _fresh_var(self, prefix: str = "tmp") -> str:
        """Generate a fresh variable name."""
        self._var_counter += 1
        return f"_{prefix}_{self._var_counter}"
    
    def visit_wildcard_pattern(self, node: A.WildcardPattern, target: str) -> List[str]:
        # Wildcard matches anything
        return ["# wildcard - matches anything"]
    
    def visit_binding_pattern(self, node: A.BindingPattern, target: str) -> List[str]:
        lines = []
        var_name = node.name
        
        if node.type_constraint:
            # Type check
            type_check = self._compile_type_check(target, node.type_constraint)
            lines.append(f"if not {type_check}:")
            lines.append(f"    return None")
        
        lines.append(f"bindings[{repr(var_name)}] = {target}")
        
        if node.nested:
            nested_lines = self._compile_pattern(node.nested, target)
            lines.extend(nested_lines)
        
        return lines
    
    def visit_literal_pattern(self, node: A.LiteralPattern, target: str) -> List[str]:
        value = repr(node.value)
        return [
            f"if not _match_literal({target}, {value}):",
            f"    return None",
        ]
    
    def visit_type_pattern(self, node: A.TypePattern, target: str) -> List[str]:
        type_check = self._compile_type_check(target, node.type_name)
        lines = [
            f"if not {type_check}:",
            f"    return None",
        ]
        
        if node.nested:
            nested_lines = self._compile_pattern(node.nested, target)
            lines.extend(nested_lines)
        
        return lines
    
    def visit_node_pattern(self, node: A.NodePattern, target: str) -> List[str]:
        lines = []
        
        # Check node kind
        kind = node.kind
        lines.append(f"if not _check_node_kind({target}, {repr(kind)}):")
        lines.append(f"    return None")
        
        # Match children
        for i, child in enumerate(node.children):
            child_var = self._fresh_var("child")
            lines.append(f"{child_var} = _get_child({target}, {i})")
            lines.append(f"if {child_var} is None:")
            lines.append(f"    return None")
            child_lines = self._compile_pattern(child, child_var)
            lines.extend(child_lines)
        
        # Match attributes
        for attr_name, attr_pattern in node.attributes.items():
            attr_var = self._fresh_var("attr")
            lines.append(f"{attr_var} = _get_attr({target}, {repr(attr_name)})")
            lines.append(f"if {attr_var} is None:")
            lines.append(f"    return None")
            attr_lines = self._compile_pattern(attr_pattern, attr_var)
            lines.extend(attr_lines)
        
        return lines
    
    def visit_sequence_pattern(self, node: A.SequencePattern, target: str) -> List[str]:
        """Compile PQL-style sequence patterns."""
        lines = []
        lines.append(f"# Sequence pattern with {len(node.elements)} elements")
        lines.append(f"_seq_state = _init_sequence_match({target})")
        
        for i, elem in enumerate(node.elements):
            if isinstance(elem, A.SequenceWildcard):
                # Match zero or more tokens
                if elem.binding:
                    lines.append(f"_seq_state, bindings[{repr(elem.binding)}] = "
                                f"_match_sequence_wildcard(_seq_state, greedy={elem.greedy})")
                else:
                    lines.append(f"_seq_state, _ = _match_sequence_wildcard(_seq_state, greedy={elem.greedy})")
            else:
                elem_var = self._fresh_var("seq_elem")
                lines.append(f"{elem_var} = _seq_advance(_seq_state)")
                lines.append(f"if {elem_var} is None:")
                lines.append(f"    return None")
                elem_lines = self._compile_pattern(elem, elem_var)
                lines.extend(elem_lines)
                lines.append(f"_seq_state = _seq_state._replace(pos=_seq_state.pos + 1)")
        
        return lines
    
    def visit_call_pattern(self, node: A.CallPattern, target: str) -> List[str]:
        """Compile function call patterns."""
        lines = []
        lines.append(f"if not _is_call({target}):")
        lines.append(f"    return None")
        
        if node.function:
            func_var = self._fresh_var("callee")
            lines.append(f"{func_var} = _get_callee({target})")
            func_lines = self._compile_pattern(node.function, func_var)
            lines.extend(func_lines)
        
        for i, arg in enumerate(node.arguments):
            arg_var = self._fresh_var("arg")
            lines.append(f"{arg_var} = _get_call_arg({target}, {i})")
            lines.append(f"if {arg_var} is None:")
            lines.append(f"    return None")
            arg_lines = self._compile_pattern(arg, arg_var)
            lines.extend(arg_lines)
        
        return lines
    
    def visit_assign_pattern(self, node: A.AssignPattern, target: str) -> List[str]:
        """Compile assignment patterns."""
        lines = []
        lines.append(f"if not _is_assignment({target}):")
        lines.append(f"    return None")
        
        if node.lhs:
            lhs_var = self._fresh_var("lhs")
            lines.append(f"{lhs_var} = _get_assign_lhs({target})")
            lhs_lines = self._compile_pattern(node.lhs, lhs_var)
            lines.extend(lhs_lines)
        
        if node.rhs:
            rhs_var = self._fresh_var("rhs")
            lines.append(f"{rhs_var} = _get_assign_rhs({target})")
            rhs_lines = self._compile_pattern(node.rhs, rhs_var)
            lines.extend(rhs_lines)
        
        return lines
    
    def visit_deref_pattern(self, node: A.DerefPattern, target: str) -> List[str]:
        """Compile dereference patterns."""
        lines = []
        lines.append(f"if not _is_deref({target}):")
        lines.append(f"    return None")
        
        if node.operand:
            op_var = self._fresh_var("deref_op")
            lines.append(f"{op_var} = _get_deref_operand({target})")
            op_lines = self._compile_pattern(node.operand, op_var)
            lines.extend(op_lines)
        
        return lines
    
    def _compile_type_check(self, target: str, type_name: str) -> str:
        """Generate type checking code."""
        type_map = {
            "Token": "_is_token",
            "Variable": "_is_variable",
            "Function": "_is_function",
            "Scope": "_is_scope",
            "Number": "_is_number",
            "Name": "_is_name",
            "Op": "_is_op",
        }
        check_func = type_map.get(type_name, "_is_node_type")
        if type_name in type_map:
            return f"{check_func}({target})"
        return f"{check_func}({target}, {repr(type_name)})"
    
    def generic_visit(self, node: A.ASTNode, target: str = "") -> List[str]:
        return [f"# Unhandled pattern type: {type(node).__name__}"]


# ═══════════════════════════════════════════════════════════════════════════
# CONSTRAINT COMPILER
# ═══════════════════════════════════════════════════════════════════════════

class ConstraintCompiler(ASTVisitor):
    """Compile CASL constraints to Python predicates."""
    
    def __init__(self, context: "CompilationContext") -> None:
        self.ctx = context
        self.expr_compiler = ExpressionCompiler(context)
    
    def compile(self, constraint: A.Constraint) -> str:
        """Compile a constraint to a Python expression."""
        return self.visit(constraint)
    
    def visit_expr_constraint(self, node: A.ExprConstraint) -> str:
        return self.expr_compiler.compile(node.expr)
    
    def visit_type_constraint(self, node: A.TypeConstraint) -> str:
        target = self.expr_compiler.compile(node.target)
        type_name = node.type_name
        return f"_check_type({target}, {repr(type_name)})"
    
    def visit_flows_to(self, node: A.FlowsTo) -> str:
        source = self.expr_compiler.compile(node.source)
        sink = self.expr_compiler.compile(node.sink)
        domain = repr(node.domain) if node.domain else "None"
        return f"_flows_to({source}, {sink}, domain={domain}, state=_analysis_state)"
    
    def visit_reaches(self, node: A.Reaches) -> str:
        source = self.expr_compiler.compile(node.source)
        target = self.expr_compiler.compile(node.target)
        return f"_reaches({source}, {target}, cfg=_cfg)"
    
    def visit_dominates(self, node: A.Dominates) -> str:
        dominator = self.expr_compiler.compile(node.dominator)
        dominated = self.expr_compiler.compile(node.dominated)
        return f"_dominates({dominator}, {dominated}, dominators=_dominators)"
    
    def visit_same_value(self, node: A.SameValue) -> str:
        left = self.expr_compiler.compile(node.left)
        right = self.expr_compiler.compile(node.right)
        return f"_same_value({left}, {right})"
    
    def visit_may_alias(self, node: A.MayAlias) -> str:
        ptr1 = self.expr_compiler.compile(node.ptr1)
        ptr2 = self.expr_compiler.compile(node.ptr2)
        return f"_may_alias({ptr1}, {ptr2}, alias_info=_alias_info)"
    
    def visit_dataflow_fact(self, node: A.DataflowFact) -> str:
        target = self.expr_compiler.compile(node.target)
        fact = repr(node.fact)
        domain = repr(node.domain) if node.domain else "None"
        return f"_check_fact({target}, {fact}, domain={domain}, state=_analysis_state)"
    
    def visit_and_constraint(self, node: A.AndConstraint) -> str:
        parts = [f"({self.visit(c)})" for c in node.constraints]
        return " and ".join(parts)
    
    def visit_or_constraint(self, node: A.OrConstraint) -> str:
        parts = [f"({self.visit(c)})" for c in node.constraints]
        return " or ".join(parts)
    
    def visit_not_constraint(self, node: A.NotConstraint) -> str:
        inner = self.visit(node.constraint)
        return f"(not ({inner}))"
    
    def visit_forall_constraint(self, node: A.ForallConstraint) -> str:
        var = CodeEmitter.make_identifier(node.variable)
        collection = self.expr_compiler.compile(node.collection)
        body = self.visit(node.body)
        return f"all({body} for {var} in {collection})"
    
    def visit_exists_constraint(self, node: A.ExistsConstraint) -> str:
        var = CodeEmitter.make_identifier(node.variable)
        collection = self.expr_compiler.compile(node.collection)
        body = self.visit(node.body)
        return f"any({body} for {var} in {collection})"
    
    def generic_visit(self, node: A.ASTNode) -> str:
        return "True  # unhandled constraint"


# ═══════════════════════════════════════════════════════════════════════════
# ACTION COMPILER
# ═══════════════════════════════════════════════════════════════════════════

class ActionCompiler(ASTVisitor):
    """Compile CASL actions to Python code."""
    
    def __init__(self, context: "CompilationContext") -> None:
        self.ctx = context
        self.expr_compiler = ExpressionCompiler(context)
    
    def compile(self, action: A.Action) -> List[str]:
        """Compile an action to Python statements."""
        return self.visit(action)
    
    def visit_report_action(self, node: A.ReportAction) -> List[str]:
        severity = node.severity or "warning"
        message = self.expr_compiler.compile(node.message)
        
        lines = []
        if node.location:
            location = self.expr_compiler.compile(node.location)
            lines.append(f"_report({repr(severity)}, {message}, {location})")
        else:
            lines.append(f"_report({repr(severity)}, {message}, _current_token)")
        
        return lines
    
    def visit_set_fact_action(self, node: A.SetFactAction) -> List[str]:
        target = self.expr_compiler.compile(node.target)
        value = self.expr_compiler.compile(node.value)
        domain = repr(node.domain) if node.domain else "None"
        return [f"_set_fact({target}, {value}, domain={domain}, state=_analysis_state)"]
    
    def visit_log_action(self, node: A.LogAction) -> List[str]:
        level = node.level or "debug"
        message = self.expr_compiler.compile(node.message)
        return [f"_log({repr(level)}, {message})"]
    
    def visit_store_action(self, node: A.StoreAction) -> List[str]:
        key = self.expr_compiler.compile(node.key)
        value = self.expr_compiler.compile(node.value)
        return [f"_store[{key}] = {value}"]
    
    def visit_sequence_action(self, node: A.SequenceAction) -> List[str]:
        lines = []
        for action in node.actions:
            lines.extend(self.visit(action))
        return lines
    
    def visit_cond_action(self, node: A.CondAction) -> List[str]:
        cond = self.expr_compiler.compile(node.condition)
        lines = [f"if {cond}:"]
        
        then_lines = self.visit(node.then_action)
        for line in then_lines:
            lines.append(f"    {line}")
        
        if node.else_action:
            lines.append("else:")
            else_lines = self.visit(node.else_action)
            for line in else_lines:
                lines.append(f"    {line}")
        
        return lines
    
    def visit_foreach_action(self, node: A.ForeachAction) -> List[str]:
        var = CodeEmitter.make_identifier(node.variable)
        collection = self.expr_compiler.compile(node.collection)
        
        lines = [f"for {var} in {collection}:"]
        body_lines = self.visit(node.body)
        for line in body_lines:
            lines.append(f"    {line}")
        
        return lines
    
    def generic_visit(self, node: A.ASTNode) -> List[str]:
        return [f"pass  # unhandled action: {type(node).__name__}"]


# ═══════════════════════════════════════════════════════════════════════════
# COMPILATION CONTEXT
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class CompilationContext:
    """Context for code generation."""
    
    semantic_ctx: SemanticContext
    emitter: CodeEmitter
    
    # Tracked state
    pattern_variables: Set[str] = field(default_factory=set)
    local_variables: Set[str] = field(default_factory=set)
    domain_values: Dict[str, Tuple[str, str]] = field(default_factory=dict)
    generated_functions: Dict[str, str] = field(default_factory=dict)
    
    # Collected information
    required_imports: Set[str] = field(default_factory=set)
    required_domains: Set[str] = field(default_factory=set)
    required_analyses: Set[str] = field(default_factory=set)


# ═══════════════════════════════════════════════════════════════════════════
# MAIN CODE GENERATOR
# ═══════════════════════════════════════