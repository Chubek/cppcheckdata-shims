# casl/codegen.py
"""
CASL Code Generator — AST → Python addon source code

The generated addon follows the cppcheck addon protocol:
  - Reads a .dump file path from sys.argv
  - Parses it with cppcheckdata.parsedump()
  - Runs checkers using cppcheckdata_shims
  - Outputs JSON diagnostics to stdout (--cli mode) or stderr
"""

from __future__ import annotations

import textwrap
from typing import Optional

from casl.ast_nodes import (
    Program, AddonDecl, ImportStmt, CheckerDecl, FnDecl, ConstDecl,
    TypeAliasDecl, PatternDecl, QueryDecl, OnBlock, SuppressDecl,
    LetStmt, AssignStmt, IfStmt, ForStmt, WhileStmt, ReturnStmt,
    EmitStmt, BreakStmt, ContinueStmt, ExprStmt,
    Identifier, IntLiteral, FloatLiteral, StringLiteral, BoolLiteral,
    NullLiteral, ListLiteral, MapLiteral, SetLiteral,
    UnaryExpr, BinaryExpr, TernaryExpr, CallExpr, IndexExpr,
    MemberExpr, MethodCallExpr, LambdaExpr, MatchExpr, MatchArm,
    TokenPattern, ScopePattern, CallPattern, AssignPattern,
    DerefPattern, BinopPattern, WildcardPattern,
    PatternClauseMatch, PatternClauseWhere, PatternClauseEnsures,
    OnEvent, Severity, Confidence, AssignOp, UnaryOp, BinOp,
    Param, TypeName, TypeGeneric,
)


class CodeGenError(Exception):
    """Error during code generation."""
    pass


class _Emitter:
    """Builds Python source incrementally with indentation tracking."""

    def __init__(self):
        self._lines: list[str] = []
        self._indent: int = 0

    def line(self, code: str = ""):
        if code:
            self._lines.append("    " * self._indent + code)
        else:
            self._lines.append("")

    def indent(self):
        self._indent += 1

    def dedent(self):
        self._indent = max(0, self._indent - 1)

    def blank(self):
        self._lines.append("")

    def comment(self, text: str):
        for ln in text.split("\n"):
            self.line(f"# {ln}")

    def docstring(self, text: str):
        self.line(f'"""{text}"""')

    def result(self) -> str:
        return "\n".join(self._lines) + "\n"


def _py_op(op: BinOp) -> str:
    """Map CASL binary operator to Python."""
    mapping = {
        BinOp.OR: "or", BinOp.AND: "and",
        BinOp.BIT_OR: "|", BinOp.BIT_XOR: "^", BinOp.BIT_AND: "&",
        BinOp.EQ: "==", BinOp.NE: "!=",
        BinOp.LT: "<", BinOp.GT: ">", BinOp.LE: "<=", BinOp.GE: ">=",
        BinOp.ADD: "+", BinOp.SUB: "-",
        BinOp.MUL: "*", BinOp.DIV: "/", BinOp.MOD: "%",
    }
    return mapping[op]


def _py_unary(op: UnaryOp) -> str:
    mapping = {UnaryOp.NOT: "not ", UnaryOp.NEG: "-", UnaryOp.BITNOT: "~"}
    return mapping[op]


def _py_assign_op(op: AssignOp) -> str:
    return op.value


def _severity_str(sev: Optional[Severity]) -> str:
    if sev is None:
        return "'warning'"
    return repr(sev.value)


def _confidence_str(conf: Optional[Confidence]) -> str:
    if conf is None:
        return "'probable'"
    return repr(conf.value)


class CodeGenerator:
    """
    Generates a complete Python cppcheck addon from a CASL AST.

    The generated code:
    1. Imports cppcheckdata and cppcheckdata_shims
    2. Defines helper functions for pattern matching
    3. Defines each checker as a class inheriting from a base
    4. Has a main() that parses the dump and runs all checkers
    """

    def __init__(self, program: Program, source_filename: str = "<casl>"):
        self.program = program
        self.source_filename = source_filename
        self.e = _Emitter()
        self._checker_names: list[str] = []
        self._fn_names: list[str] = []

    def generate(self) -> str:
        """Generate and return complete Python source."""
        self._emit_header()
        self._emit_imports()
        self._emit_runtime_helpers()
        self._emit_constants()
        self._emit_functions()
        self._emit_checkers()
        self._emit_main()
        return self.e.result()

    # ── Header ───────────────────────────────────────────────────

    def _emit_header(self):
        e = self.e
        e.comment("=" * 70)
        e.comment(f"Auto-generated cppcheck addon from CASL source")
        if self.program.addon:
            e.comment(f"Addon: {self.program.addon.name}")
            if self.program.addon.description:
                e.comment(f"Description: {self.program.addon.description}")
        e.comment(f"Source: {self.source_filename}")
        e.comment("DO NOT EDIT — regenerate from the .casl source file")
        e.comment("=" * 70)
        e.blank()

    # ── Imports ──────────────────────────────────────────────────

    def _emit_imports(self):
        e = self.e
        e.line("from __future__ import annotations")
        e.blank()
        e.line("import sys")
        e.line("import os")
        e.line("import json")
        e.line("import argparse")
        e.line("from typing import Any, Optional")
        e.blank()
        e.comment("cppcheck data access")
        e.line("try:")
        e.indent()
        e.line("import cppcheckdata")
        e.line("from cppcheckdata import parsedump, CppcheckData")
        e.dedent()
        e.line("except ImportError:")
        e.indent()
        e.line("# Allow the module to be found via deps/ in typical addon layout")
        e.line("sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'deps'))")
        e.line("import cppcheckdata")
        e.line("from cppcheckdata import parsedump, CppcheckData")
        e.dedent()
        e.blank()
        e.comment("cppcheckdata-shims analyses")
        e.line("try:")
        e.indent()
        e.line("from cppcheckdata_shims.dataflow_analyses import (")
        e.line("    ReachingDefinitions, LiveVariables, IntervalAnalysis,")
        e.line("    NullPointerAnalysis, TaintAnalysis, SignAnalysis,")
        e.line("    ConstantPropagation, PointerAnalysis, run_all_analyses,")
        e.line(")")
        e.line("from cppcheckdata_shims.ctrlflow_graph import build_cfg")
        e.line("from cppcheckdata_shims.callgraph import build_callgraph")
        e.line("from cppcheckdata_shims.checkers import (")
        e.line("    Checker, CheckerContext, CheckerRunner, CheckerRunResults,")
        e.line("    DiagnosticSeverity, Confidence as ShimConfidence,")
        e.line(")")
        e.dedent()
        e.line("except ImportError:")
        e.indent()
        e.line("sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))")
        e.line("from cppcheckdata_shims.dataflow_analyses import (")
        e.line("    ReachingDefinitions, LiveVariables, IntervalAnalysis,")
        e.line("    NullPointerAnalysis, TaintAnalysis, SignAnalysis,")
        e.line("    ConstantPropagation, PointerAnalysis, run_all_analyses,")
        e.line(")")
        e.line("from cppcheckdata_shims.ctrlflow_graph import build_cfg")
        e.line("from cppcheckdata_shims.callgraph import build_callgraph")
        e.line("from cppcheckdata_shims.checkers import (")
        e.line("    Checker, CheckerContext, CheckerRunner, CheckerRunResults,")
        e.line("    DiagnosticSeverity, Confidence as ShimConfidence,")
        e.line(")")
        e.dedent()
        e.blank()

        # Emit CASL imports (other CASL modules)
        for item in self.program.items:
            if isinstance(item, ImportStmt):
                mod_path = ".".join(item.path)
                e.line(f"import {mod_path}")
        e.blank()

    # ── Runtime Helpers ──────────────────────────────────────────

    def _emit_runtime_helpers(self):
        e = self.e
        e.comment("─── CASL Runtime Helpers ─────────────────────────────")
        e.blank()

        # Diagnostic emitter
        e.line("_CLI_MODE = '--cli' in sys.argv")
        e.blank()
        e.line("def _casl_emit(error_id: str, message: str, file: str,")
        e.line("               linenr: int, column: int = 0,")
        e.line("               severity: str = 'warning',")
        e.line("               cwe: int = 0, addon: str = '',")
        e.line("               confidence: str = 'probable'):")
        e.indent()
        e.line('"""Emit a diagnostic in cppcheck addon protocol."""')
        e.line("if _CLI_MODE:")
        e.indent()
        e.line("msg = {")
        e.indent()
        e.line("'file': str(file or ''),")
        e.line("'linenr': int(linenr or 0),")
        e.line("'column': int(column or 0),")
        e.line("'severity': severity,")
        e.line("'message': message,")
        e.line("'addon': addon,")
        e.line("'errorId': error_id,")
        e.line("'extra': '',")
        e.dedent()
        e.line("}")
        e.line("if cwe:")
        e.indent()
        e.line("msg['cwe'] = cwe")
        e.dedent()
        e.line("sys.stdout.write(json.dumps(msg) + '\\n')")
        e.dedent()
        e.line("else:")
        e.indent()
        e.line("cwe_str = f' [CWE-{cwe}]' if cwe else ''")
        e.line("sys.stderr.write(")
        e.line("    f'{file}:{linenr}:{column}: {severity}: {message} "
               "[{error_id}]{cwe_str}\\n'")
        e.line(")")
        e.dedent()
        e.dedent()
        e.blank()

        # Token iteration helper
        e.line("def _iter_tokens(cfg):")
        e.indent()
        e.line('"""Iterate all tokens in a configuration."""')
        e.line("for tok in getattr(cfg, 'tokenlist', []):")
        e.indent()
        e.line("yield tok")
        e.dedent()
        e.dedent()
        e.blank()

        # Scope iteration helper
        e.line("def _iter_scopes(cfg):")
        e.indent()
        e.line('"""Iterate all scopes in a configuration."""')
        e.line("for scope in getattr(cfg, 'scopes', []):")
        e.indent()
        e.line("yield scope")
        e.dedent()
        e.dedent()
        e.blank()

        # Function iteration helper
        e.line("def _iter_functions(cfg):")
        e.indent()
        e.line('"""Iterate all functions in a configuration."""')
        e.line("for func in getattr(cfg, 'functions', []):")
        e.indent()
        e.line("yield func")
        e.dedent()
        e.dedent()
        e.blank()

        # Variable iteration helper
        e.line("def _iter_variables(cfg):")
        e.indent()
        e.line('"""Iterate all variables in a configuration."""')
        e.line("for var in getattr(cfg, 'variables', []):")
        e.indent()
        e.line("yield var")
        e.dedent()
        e.dedent()
        e.blank()

        # Token pattern matcher
        e.line("def _match_token(tok, **constraints) -> bool:")
        e.indent()
        e.line('"""Check if a token matches all given constraints."""')
        e.line("for key, val in constraints.items():")
        e.indent()
        e.line("actual = getattr(tok, key, None)")
        e.line("if callable(val):")
        e.indent()
        e.line("if not val(actual):")
        e.indent()
        e.line("return False")
        e.dedent()
        e.dedent()
        e.line("elif actual != val:")
        e.indent()
        e.line("return False")
        e.dedent()
        e.dedent()
        e.line("return True")
        e.dedent()
        e.blank()

        # Pattern matching: call site detector
        e.line("def _is_call_to(tok, func_name: str) -> bool:")
        e.indent()
        e.line('"""Check if token is a call to the named function."""')
        e.line("if getattr(tok, 'str', None) != '(':")
        e.indent()
        e.line("return False")
        e.dedent()
        e.line("prev = getattr(tok, 'previous', None)")
        e.line("if prev and getattr(prev, 'str', None) == func_name:")
        e.indent()
        e.line("return True")
        e.dedent()
        e.line("# Also check astOperand1 for function pointer calls")
        e.line("op1 = getattr(tok, 'astOperand1', None)")
        e.line("if op1 and getattr(op1, 'str', None) == func_name:")
        e.indent()
        e.line("return True")
        e.dedent()
        e.line("return False")
        e.dedent()
        e.blank()

        # Suppression check
        e.line("_SUPPRESSIONS = set()")
        e.line("_FILE_SUPPRESSIONS = {}")
        e.blank()
        e.line("def _is_suppressed(error_id: str, file: str = '') -> bool:")
        e.indent()
        e.line("if error_id in _SUPPRESSIONS:")
        e.indent()
        e.line("return True")
        e.dedent()
        e.line("from fnmatch import fnmatch")
        e.line("for eid, pattern in _FILE_SUPPRESSIONS.items():")
        e.indent()
        e.line("if eid == error_id and fnmatch(file, pattern):")
        e.indent()
        e.line("return True")
        e.dedent()
        e.dedent()
        e.line("return False")
        e.dedent()
        e.blank()

    # ── Constants ────────────────────────────────────────────────

    def _emit_constants(self):
        e = self.e
        for item in self.program.items:
            if isinstance(item, ConstDecl):
                val = self._expr(item.value)
                e.line(f"{item.name} = {val}")
        e.blank()

    # ── Top-level Functions ──────────────────────────────────────

    def _emit_functions(self):
        for item in self.program.items:
            if isinstance(item, FnDecl):
                self._emit_fn(item, indent=0)
                self._fn_names.append(item.name)

    def _emit_fn(self, fn: FnDecl, indent: int = 0):
        e = self.e
        params_str = ", ".join(p.name for p in fn.params)
        e.line(f"def {fn.name}({params_str}):")
        e.indent()
        if fn.docstring:
            e.docstring(fn.docstring)
        if not fn.body:
            e.line("pass")
        else:
            for stmt in fn.body:
                self._emit_stmt(stmt)
        e.dedent()
        e.blank()

    # ── Checkers ─────────────────────────────────────────────────

    def _emit_checkers(self):
        e = self.e
        for item in self.program.items:
            if isinstance(item, CheckerDecl):
                self._emit_checker(item)

    def _emit_checker(self, checker: CheckerDecl):
        e = self.e
        class_name = f"_CASLChecker_{checker.name}"
        self._checker_names.append(class_name)

        addon_name = ""
        if self.program.addon:
            addon_name = self.program.addon.name

        e.line(f"class {class_name}:")
        e.indent()

        if checker.docstring:
            e.docstring(checker.docstring)

        # Metadata
        e.line(f"name = {repr(checker.name)}")
        e.line(f"error_id = {repr(checker.error_id or checker.name)}")
        e.line(f"severity = {_severity_str(checker.severity)}")
        e.line(f"cwe = {checker.cwe or 0}")
        e.line(f"confidence = {_confidence_str(checker.confidence)}")
        e.line(f"addon_name = {repr(addon_name)}")
        e.blank()

        # __init__
        e.line("def __init__(self):")
        e.indent()
        e.line("self._diagnostics = []")
        for let in checker.lets:
            val = self._expr(let.value)
            e.line(f"self.{let.name} = {val}")
        e.dedent()
        e.blank()

        # Helper: emit diagnostic
        e.line("def _emit(self, error_id, message, file, linenr, column=0):")
        e.indent()
        e.line("if not _is_suppressed(error_id, file):")
        e.indent()
        e.line("_casl_emit(")
        e.line("    error_id=error_id, message=message,")
        e.line("    file=file, linenr=linenr, column=column,")
        e.line("    severity=self.severity, cwe=self.cwe,")
        e.line("    addon=self.addon_name, confidence=self.confidence,")
        e.line(")")
        e.line("self._diagnostics.append({")
        e.line("    'errorId': error_id, 'message': message,")
        e.line("    'file': file, 'linenr': linenr, 'column': column,")
        e.line("})")
        e.dedent()
        e.dedent()
        e.blank()

        # Emit suppressions registration
        for sup in checker.suppressions:
            if sup.file_glob:
                e.line(f"_FILE_SUPPRESSIONS[{repr(sup.error_id)}] = {repr(sup.file_glob)}")
            else:
                e.line(f"_SUPPRESSIONS.add({repr(sup.error_id)})")

        # Emit internal functions
        for fn in checker.functions:
            self._emit_method(fn)

        # Emit pattern matching functions
        for pat in checker.patterns:
            self._emit_pattern_method(pat, checker)

        # Emit query functions
        for query in checker.queries:
            self._emit_query_method(query)

        # run() method — orchestrates everything
        e.line("def run(self, data):")
        e.indent()
        e.line('"""Run this checker on parsed cppcheck data."""')
        e.line("for cfg in data.configurations:")
        e.indent()

        # init event
        for ob in checker.on_blocks:
            if ob.event == OnEvent.INIT:
                e.comment(f"on init")
                for stmt in ob.body:
                    self._emit_stmt(stmt, receiver="self")

        # cfg event
        for ob in checker.on_blocks:
            if ob.event == OnEvent.CFG:
                e.comment(f"on cfg")
                e.line("_cfg = cfg")
                for stmt in ob.body:
                    self._emit_stmt(stmt, receiver="self")

        # token iteration
        token_blocks = [ob for ob in checker.on_blocks if ob.event == OnEvent.TOKEN]
        token_patterns = checker.patterns
        if token_blocks or token_patterns:
            e.line("for tok in _iter_tokens(cfg):")
            e.indent()
            for ob in token_blocks:
                for stmt in ob.body:
                    self._emit_stmt(stmt, receiver="self")
            for pat in token_patterns:
                e.line(f"self._pattern_{pat.name}(tok)")
            e.dedent()

        # scope iteration
        scope_blocks = [ob for ob in checker.on_blocks if ob.event == OnEvent.SCOPE]
        if scope_blocks:
            e.line("for scope in _iter_scopes(cfg):")
            e.indent()
            for ob in scope_blocks:
                for stmt in ob.body:
                    self._emit_stmt(stmt, receiver="self")
            e.dedent()

        # function iteration
        fn_blocks = [ob for ob in checker.on_blocks if ob.event == OnEvent.FUNCTION]
        if fn_blocks:
            e.line("for func in _iter_functions(cfg):")
            e.indent()
            for ob in fn_blocks:
                for stmt in ob.body:
                    self._emit_stmt(stmt, receiver="self")
            e.dedent()

        # variable iteration
        var_blocks = [ob for ob in checker.on_blocks if ob.event == OnEvent.VARIABLE]
        if var_blocks:
            e.line("for var in _iter_variables(cfg):")
            e.indent()
            for ob in var_blocks:
                for stmt in ob.body:
                    self._emit_stmt(stmt, receiver="self")
            e.dedent()

        # finish event
        for ob in checker.on_blocks:
            if ob.event == OnEvent.FINISH:
                e.comment(f"on finish")
                for stmt in ob.body:
                    self._emit_stmt(stmt, receiver="self")

        e.dedent()  # for cfg
        e.line("return self._diagnostics")
        e.dedent()  # def run

        e.dedent()  # class
        e.blank()

    def _emit_method(self, fn: FnDecl):
        e = self.e
        params = ["self"] + [p.name for p in fn.params]
        params_str = ", ".join(params)
        e.line(f"def {fn.name}({params_str}):")
        e.indent()
        if fn.docstring:
            e.docstring(fn.docstring)
        if not fn.body:
            e.line("pass")
        else:
            for stmt in fn.body:
                self._emit_stmt(stmt, receiver="self")
        e.dedent()
        e.blank()

    def _emit_pattern_method(self, pat: PatternDecl, checker: CheckerDecl):
        e = self.e
        params = ["self", "tok"] + [p.name for p in pat.params]
        params_str = ", ".join(params)
        e.line(f"def _pattern_{pat.name}({params_str}):")
        e.indent()
        if pat.docstring:
            e.docstring(pat.docstring)

        # Generate match conditions
        match_conditions = []
        where_conditions = []
        ensures_conditions = []

        for clause in pat.clauses:
            if isinstance(clause, PatternClauseMatch):
                cond = self._pattern_expr_to_condition(clause.pattern, "tok")
                match_conditions.append(cond)
            elif isinstance(clause, PatternClauseWhere):
                where_conditions.append(self._expr(clause.condition))
            elif isinstance(clause, PatternClauseEnsures):
                ensures_conditions.append(self._expr(clause.condition))

        # Build combined condition
        all_conds = match_conditions + where_conditions
        if all_conds:
            combined = " and ".join(f"({c})" for c in all_conds)
            e.line(f"if {combined}:")
            e.indent()
            # Default action: emit diagnostic
            eid = checker.error_id or checker.name
            e.line(f"self._emit(")
            e.line(f"    {repr(eid)},")
            e.line(f"    f'Pattern {repr(pat.name)} matched at {{getattr(tok, \"file\", \"?\")}}:{{getattr(tok, \"linenr\", 0)}}',")
            e.line(f"    getattr(tok, 'file', ''),")
            e.line(f"    getattr(tok, 'linenr', 0),")
            e.line(f"    getattr(tok, 'column', 0),")
            e.line(f")")
            e.dedent()
        else:
            e.line("pass")
        e.dedent()
        e.blank()

    def _emit_query_method(self, query: QueryDecl):
        e = self.e
        params = ["self"] + [p.name for p in query.params]
        params_str = ", ".join(params)
        e.line(f"def _query_{query.name}({params_str}):")
        e.indent()
        if query.docstring:
            e.docstring(query.docstring)
        if not query.body:
            e.line("return None")
        else:
            for stmt in query.body:
                self._emit_stmt(stmt, receiver="self")
        e.dedent()
        e.blank()

    # ── Pattern → Python condition ───────────────────────────────

    def _pattern_expr_to_condition(self, pat, var_name: str) -> str:
        if isinstance(pat, TokenPattern):
            parts = []
            for key, val in pat.constraints.items():
                val_str = self._expr(val)
                parts.append(f"getattr({var_name}, {repr(key)}, None) == {val_str}")
            return " and ".join(parts) if parts else "True"

        elif isinstance(pat, ScopePattern):
            return (f"getattr(getattr({var_name}, 'scope', None), "
                    f"'type', None) == {repr(pat.name)}")

        elif isinstance(pat, CallPattern):
            callee_str = self._expr(pat.callee)
            return f"_is_call_to({var_name}, {callee_str})"

        elif isinstance(pat, AssignPattern):
            lhs_cond = self._pattern_expr_to_condition(pat.lhs, var_name)
            return (f"getattr({var_name}, 'isAssignmentOp', False) "
                    f"and {lhs_cond}")

        elif isinstance(pat, DerefPattern):
            inner = self._pattern_expr_to_condition(pat.operand, var_name)
            return (f"getattr({var_name}, 'str', None) == '*' "
                    f"and getattr({var_name}, 'isOp', False) "
                    f"and {inner}")

        elif isinstance(pat, BinopPattern):
            return (f"getattr({var_name}, 'str', None) == {repr(pat.op)} "
                    f"and getattr({var_name}, 'isBinaryOp', lambda: False)()")

        elif isinstance(pat, WildcardPattern):
            return "True"

        return "True"

    # ── Statement emission ───────────────────────────────────────

    def _emit_stmt(self, stmt, receiver: Optional[str] = None):
        e = self.e

        if isinstance(stmt, LetStmt):
            val = self._expr(stmt.value)
            e.line(f"{stmt.name} = {val}")

        elif isinstance(stmt, AssignStmt):
            target = self._expr(stmt.target)
            val = self._expr(stmt.value)
            e.line(f"{target} {_py_assign_op(stmt.op)} {val}")

        elif isinstance(stmt, IfStmt):
            cond = self._expr(stmt.condition)
            e.line(f"if {cond}:")
            e.indent()
            if not stmt.then_body:
                e.line("pass")
            for s in stmt.then_body:
                self._emit_stmt(s, receiver)
            e.dedent()
            for elif_cond, elif_body in stmt.elif_clauses:
                ec = self._expr(elif_cond)
                e.line(f"elif {ec}:")
                e.indent()
                if not elif_body:
                    e.line("pass")
                for s in elif_body:
                    self._emit_stmt(s, receiver)
                e.dedent()
            if stmt.else_body is not None:
                e.line("else:")
                e.indent()
                if not stmt.else_body:
                    e.line("pass")
                for s in stmt.else_body:
                    self._emit_stmt(s, receiver)
                e.dedent()

        elif isinstance(stmt, ForStmt):
            it = self._expr(stmt.iterable)
            e.line(f"for {stmt.var} in {it}:")
            e.indent()
            if not stmt.body:
                e.line("pass")
            for s in stmt.body:
                self._emit_stmt(s, receiver)
            e.dedent()

        elif isinstance(stmt, WhileStmt):
            cond = self._expr(stmt.condition)
            e.line(f"while {cond}:")
            e.indent()
            if not stmt.body:
                e.line("pass")
            for s in stmt.body:
                self._emit_stmt(s, receiver)
            e.dedent()

        elif isinstance(stmt, ReturnStmt):
            if stmt.value is not None:
                val = self._expr(stmt.value)
                e.line(f"return {val}")
            else:
                e.line("return")

        elif isinstance(stmt, EmitStmt):
            # emit errorId(message, file, linenr, column)
            args_str = ", ".join(self._expr(a) for a in stmt.args)
            if receiver:
                e.line(f"{receiver}._emit({repr(stmt.error_id)}, {args_str})")
            else:
                e.line(f"_casl_emit({repr(stmt.error_id)}, {args_str})")

        elif isinstance(stmt, BreakStmt):
            e.line("break")

        elif isinstance(stmt, ContinueStmt):
            e.line("continue")

        elif isinstance(stmt, ExprStmt):
            val = self._expr(stmt.expr)
            e.line(val)

    # ── Expression emission ──────────────────────────────────────

    def _expr(self, expr) -> str:
        if expr is None:
            return "None"

        if isinstance(expr, Identifier):
            return expr.name

        if isinstance(expr, IntLiteral):
            return repr(expr.value)

        if isinstance(expr, FloatLiteral):
            return repr(expr.value)

        if isinstance(expr, StringLiteral):
            return repr(expr.value)

        if isinstance(expr, BoolLiteral):
            return "True" if expr.value else "False"

        if isinstance(expr, NullLiteral):
            return "None"

        if isinstance(expr, ListLiteral):
            elems = ", ".join(self._expr(e) for e in expr.elements)
            return f"[{elems}]"

        if isinstance(expr, MapLiteral):
            entries = ", ".join(
                f"{self._expr(k)}: {self._expr(v)}" for k, v in expr.entries
            )
            return f"{{{entries}}}"

        if isinstance(expr, SetLiteral):
            elems = ", ".join(self._expr(e) for e in expr.elements)
            return f"set([{elems}])" if elems else "set()"

        if isinstance(expr, UnaryExpr):
            operand = self._expr(expr.operand)
            return f"({_py_unary(expr.op)}{operand})"

        if isinstance(expr, BinaryExpr):
            left = self._expr(expr.left)
            right = self._expr(expr.right)
            return f"({left} {_py_op(expr.op)} {right})"

        if isinstance(expr, TernaryExpr):
            then = self._expr(expr.then_expr)
            cond = self._expr(expr.condition)
            els = self._expr(expr.else_expr)
            return f"({then} if {cond} else {els})"

        if isinstance(expr, CallExpr):
            callee = self._expr(expr.callee)
            args = ", ".join(self._expr(a) for a in expr.args)
            return f"{callee}({args})"

        if isinstance(expr, IndexExpr):
            obj = self._expr(expr.obj)
            idx = self._expr(expr.index)
            return f"{obj}[{idx}]"

        if isinstance(expr, MemberExpr):
            obj = self._expr(expr.obj)
            return f"{obj}.{expr.member}"

        if isinstance(expr, MethodCallExpr):
            obj = self._expr(expr.obj)
            args = ", ".join(self._expr(a) for a in expr.args)
            return f"{obj}.{expr.method}({args})"

        if isinstance(expr, LambdaExpr):
            params = ", ".join(p.name for p in expr.params)
            # For simple lambdas (single return), use Python lambda
            if len(expr.body) == 1 and isinstance(expr.body[0], ReturnStmt):
                val = self._expr(expr.body[0].value)
                return f"(lambda {params}: {val})"
            # For complex lambdas, we need a local function
            # This is a simplification — full implementation would use
            # a generated function name
            if len(expr.body) == 1 and isinstance(expr.body[0], ExprStmt):
                val = self._expr(expr.body[0].expr)
                return f"(lambda {params}: {val})"
            return f"(lambda {params}: None)  # complex lambda — see source"

        if isinstance(expr, MatchExpr):
            # Compile to a series of if/elif
            subject = self._expr(expr.subject)
            # Use a helper
            return f"_casl_match({subject}, {self._match_arms_dict(expr.arms)})"

        # Fallback
        return repr(str(expr))

    def _match_arms_dict(self, arms: list[MatchArm]) -> str:
        entries = []
        default = "None"
        for arm in arms:
            pat = arm.pattern
            body = self._expr(arm.body)
            if isinstance(pat, Identifier) and pat.name == "_":
                default = body
            else:
                key = self._expr(pat)
                entries.append(f"{key}: (lambda: {body})")
        dict_str = "{" + ", ".join(entries) + "}"
        return f"({dict_str}.get({self._expr(arms[0].pattern) if arms else 'None'}, lambda: {default})())"

    # ── Main entry point ─────────────────────────────────────────

    def _emit_main(self):
        e = self.e

        # match helper
        e.line("def _casl_match(subject, dispatch):")
        e.indent()
        e.line('"""Runtime match expression helper."""')
        e.line("if isinstance(dispatch, dict):")
        e.indent()
        e.line("fn = dispatch.get(subject)")
        e.line("if fn is not None:")
        e.indent()
        e.line("return fn() if callable(fn) else fn")
        e.dedent()
        e.line("# Try wildcard")
        e.line("fn = dispatch.get('_')")
        e.line("if fn is not None:")
        e.indent()
        e.line("return fn() if callable(fn) else fn")
        e.dedent()
        e.dedent()
        e.line("return None")
        e.dedent()
        e.blank()

        # main
        e.line("def main():")
        e.indent()
        addon_name = self.program.addon.name if self.program.addon else "casl_addon"
        e.docstring(f"Entry point for {addon_name} cppcheck addon.")
        e.blank()

        e.line("parser = argparse.ArgumentParser(")
        e.line(f"    description={repr(addon_name + ' - CASL-generated cppcheck addon')}")
        e.line(")")
        e.line("parser.add_argument('dumpfile', help='Path to cppcheck .dump file')")
        e.line("parser.add_argument('--cli', action='store_true',")
        e.line("                    help='Output in cppcheck JSON protocol')")
        e.line("parser.add_argument('--suppress', nargs='*', default=[],")
        e.line("                    help='Error IDs to suppress')")
        e.line("args, unknown = parser.parse_known_args()")
        e.blank()
        e.line("global _CLI_MODE")
        e.line("_CLI_MODE = args.cli or _CLI_MODE")
        e.blank()
        e.line("for s in args.suppress:")
        e.indent()
        e.line("_SUPPRESSIONS.add(s)")
        e.dedent()
        e.blank()

        e.line("data = parsedump(args.dumpfile)")
        e.blank()

        e.line("all_diagnostics = []")
        for cn in self._checker_names:
            e.line(f"checker = {cn}()")
            e.line(f"diags = checker.run(data)")
            e.line(f"all_diagnostics.extend(diags)")
        e.blank()

        e.line("if not _CLI_MODE and all_diagnostics:")
        e.indent()
        e.line(f"sys.stderr.write(f'\\n{repr(addon_name)}: "
               f"{{len(all_diagnostics)}} issue(s) found.\\n')")
        e.dedent()
        e.blank()
        e.line("sys.exit(1 if all_diagnostics else 0)")
        e.dedent()
        e.blank()
        e.blank()
        e.line("if __name__ == '__main__':")
        e.indent()
        e.line("main()")
        e.dedent()


def generate(program: Program, source_filename: str = "<casl>") -> str:
    """Generate Python addon source from a CASL AST."""
    gen = CodeGenerator(program, source_filename)
    return gen.generate()
