# tests/test_casl.py
"""
Comprehensive tests for the CASL compiler pipeline:
  parse → AST → codegen → valid Python
"""

import pytest
import textwrap
import sys
import os

# Ensure casl package is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from casl.parser import parse, CASLParseError
from casl.codegen import generate
from casl.ast_nodes import (
    Program, AddonDecl, CheckerDecl, FnDecl, ConstDecl,
    LetStmt, IfStmt, ForStmt, EmitStmt,
    Identifier, IntLiteral, StringLiteral, BoolLiteral,
    BinaryExpr, BinOp, Severity, Confidence, OnEvent,
    TokenPattern, PatternClauseMatch, PatternClauseWhere,
)


class TestParser:
    """Test CASL parsing into AST nodes."""

    def test_empty_program(self):
        ast = parse("")
        assert isinstance(ast, Program)
        assert ast.addon is None
        assert ast.items == []

    def test_addon_declaration(self):
        src = textwrap.dedent('''\
            addon MyAddon "A test addon" {
                cwe = 123;
                severity = "error";
            }
        ''')
        ast = parse(src)
        assert ast.addon is not None
        assert ast.addon.name == "MyAddon"
        assert ast.addon.description == "A test addon"
        assert len(ast.addon.fields) == 2

    def test_const_declaration(self):
        src = 'const MAX_SIZE = 1024;'
        ast = parse(src)
        assert len(ast.items) == 1
        c = ast.items[0]
        assert isinstance(c, ConstDecl)
        assert c.name == "MAX_SIZE"
        assert isinstance(c.value, IntLiteral)
        assert c.value.value == 1024

    def test_function_declaration(self):
        src = textwrap.dedent('''\
            fn add(a, b) {
                return a + b;
            }
        ''')
        ast = parse(src)
        assert len(ast.items) == 1
        fn = ast.items[0]
        assert isinstance(fn, FnDecl)
        assert fn.name == "add"
        assert len(fn.params) == 2
        assert fn.params[0].name == "a"
        assert fn.params[1].name == "b"

    def test_checker_basic(self):
        src = textwrap.dedent('''\
            checker my_check {
                error_id = "myError";
                severity = warning;
                cwe = 999;
                confidence = certain;

                on token {
                    if tok.isName {
                        emit myError("found name", tok.file, tok.linenr, 0);
                    }
                }
            }
        ''')
        ast = parse(src)
        assert len(ast.items) == 1
        ch = ast.items[0]
        assert isinstance(ch, CheckerDecl)
        assert ch.name == "my_check"
        assert ch.error_id == "myError"
        assert ch.severity == Severity.WARNING
        assert ch.cwe == 999
        assert ch.confidence == Confidence.CERTAIN
        assert len(ch.on_blocks) == 1
        assert ch.on_blocks[0].event == OnEvent.TOKEN

    def test_pattern_declaration(self):
        src = textwrap.dedent('''\
            checker pat_check {
                error_id = "patErr";
                severity = error;

                pattern null_deref(tok) {
                    match token(str = "*", isOp = true);
                    where tok.astOperand1 != null;
                }

                on token {
                    let x = 1;
                }
            }
        ''')
        ast = parse(src)
        ch = ast.items[0]
        assert len(ch.patterns) == 1
        pat = ch.patterns[0]
        assert pat.name == "null_deref"
        assert len(pat.clauses) == 2
        assert isinstance(pat.clauses[0], PatternClauseMatch)
        assert isinstance(pat.clauses[0].pattern, TokenPattern)
        assert isinstance(pat.clauses[1], PatternClauseWhere)

    def test_docstring_on_checker(self):
        src = textwrap.dedent('''\
            """This is a docstring"""
            checker documented {
                error_id = "doc";
                severity = style;
                on token {
                    let x = 1;
                }
            }
        ''')
        ast = parse(src)
        ch = ast.items[0]
        assert ch.docstring == "This is a docstring"

    def test_import_statement(self):
        src = 'import utils.taint_helpers;'
        ast = parse(src)
        assert len(ast.items) == 1
        imp = ast.items[0]
        assert isinstance(imp, ImportStmt)
        assert imp.path == ["utils", "taint_helpers"]

    def test_if_elif_else(self):
        src = textwrap.dedent('''\
            fn test() {
                if x == 1 {
                    let a = 1;
                } elif x == 2 {
                    let a = 2;
                } else {
                    let a = 3;
                }
            }
        ''')
        ast = parse(src)
        fn = ast.items[0]
        stmt = fn.body[0]
        assert isinstance(stmt, IfStmt)
        assert len(stmt.elif_clauses) == 1
        assert stmt.else_body is not None

    def test_for_loop(self):
        src = textwrap.dedent('''\
            fn test() {
                for item in items {
                    let x = item;
                }
            }
        ''')
        ast = parse(src)
        fn = ast.items[0]
        stmt = fn.body[0]
        assert isinstance(stmt, ForStmt)
        assert stmt.var == "item"

    def test_binary_expressions(self):
        src = textwrap.dedent('''\
            fn test() {
                let x = 1 + 2 * 3;
            }
        ''')
        ast = parse(src)
        fn = ast.items[0]
        let = fn.body[0]
        assert isinstance(let, LetStmt)
        # Should parse as 1 + (2 * 3) due to precedence
        expr = let.value
        assert isinstance(expr, BinaryExpr)
        assert expr.op == BinOp.ADD

    def test_list_literal(self):
        src = 'const ITEMS = [1, 2, 3];'
        ast = parse(src)
        c = ast.items[0]
        from casl.ast_nodes import ListLiteral
        assert isinstance(c.value, ListLiteral)
        assert len(c.value.elements) == 3

    def test_string_literal_escapes(self):
        src = r'const MSG = "hello\nworld";'
        ast = parse(src)
        c = ast.items[0]
        assert c.value.value == "hello\nworld"

    def test_parse_error(self):
        src = "checker { broken"
        with pytest.raises(CASLParseError):
            parse(src)


class TestCodeGen:
    """Test that generated Python code is syntactically valid."""

    def _gen(self, casl_src: str) -> str:
        ast = parse(casl_src)
        return generate(ast)

    def test_empty_generates_valid_python(self):
        code = self._gen("")
        # Should be parseable Python
        compile(code, "<test>", "exec")

    def test_addon_with_checker_generates_main(self):
        src = textwrap.dedent('''\
            addon TestAddon {
                severity = "warning";
            }
            checker test_check {
                error_id = "testErr";
                severity = warning;
                on token {
                    let x = tok.str;
                }
            }
        ''')
        code = self._gen(src)
        compile(code, "<test>", "exec")
        assert "class _CASLChecker_test_check" in code
        assert "def main():" in code
        assert "parsedump" in code

    def test_function_generates_def(self):
        src = textwrap.dedent('''\
            fn helper(x, y) {
                return x + y;
            }
        ''')
        code = self._gen(src)
        compile(code, "<test>", "exec")
        assert "def helper(x, y):" in code

    def test_emit_generates_diagnostic(self):
        src = textwrap.dedent('''\
            checker emitter {
                error_id = "testEmit";
                severity = error;
                on token {
                    emit testEmit("message", tok.file, tok.linenr, 0);
                }
            }
        ''')
        code = self._gen(src)
        compile(code, "<test>", "exec")
        assert "_casl_emit" in code or "self._emit" in code

    def test_pattern_generates_matcher(self):
        src = textwrap.dedent('''\
            checker patter {
                error_id = "patErr";
                severity = style;
                pattern check_op(tok) {
                    match token(str = "+", isOp = true);
                    where tok.astOperand1 != null;
                }
                on token {
                    let x = 1;
                }
            }
        ''')
        code = self._gen(src)
        compile(code, "<test>", "exec")
        assert "_pattern_check_op" in code

    def test_suppress_generates_suppression(self):
        src = textwrap.dedent('''\
            checker suppressed {
                error_id = "supErr";
                severity = style;
                suppress "supErr" "test/*.c";
                on token {
                    let x = 1;
                }
            }
        ''')
        code = self._gen(src)
        compile(code, "<test>", "exec")
        assert "_FILE_SUPPRESSIONS" in code

    def test_for_loop_generates_for(self):
        src = textwrap.dedent('''\
            fn loop_test() {
                for i in items {
                    let x = i;
                }
            }
        ''')
        code = self._gen(src)
        compile(code, "<test>", "exec")
        assert "for i in items:" in code

    def test_if_else_generates_correctly(self):
        src = textwrap.dedent('''\
            fn branch_test(x) {
                if x == 1 {
                    return true;
                } else {
                    return false;
                }
            }
        ''')
        code = self._gen(src)
        compile(code, "<test>", "exec")
        assert "if (x == 1):" in code or "if x == 1:" in code

    def test_complex_addon_compiles(self):
        """Full realistic CASL addon compiles to valid Python."""
        src = textwrap.dedent('''\
            addon FullAddon "Complete test" {
                cwe = 476;
                severity = "error";
            }

            const MAX = 100;

            fn helper(tok) {
                if tok.isName {
                    return true;
                }
                return false;
            }

            checker full_check {
                error_id = "fullErr";
                severity = error;
                cwe = 476;
                confidence = probable;

                let mut count = 0;

                on init {
                    count = 0;
                }

                on token {
                    if helper(tok) {
                        count = count + 1;
                        if count > MAX {
                            emit fullErr(
                                "Too many names",
                                tok.file,
                                tok.linenr,
                                tok.column
                            );
                        }
                    }
                }

                on finish {
                    let x = count;
                }
            }
        ''')
        code = self._gen(src)
        compile(code, "<test>", "exec")
        assert "class _CASLChecker_full_check" in code
        assert "MAX = 100" in code
        assert "def helper(tok):" in code
        assert "def main():" in code


class TestRuntime:
    """Test runtime helper classes."""

    def test_pattern_matcher_token(self):
        from casl.runtime import PatternMatcher

        class FakeToken:
            str = "+"
            isOp = True
            isArithmeticalOp = True

        pm = PatternMatcher()
        assert pm.match_token(FakeToken(), str="+", isOp=True)
        assert not pm.match_token(FakeToken(), str="-")

    def test_pattern_matcher_callable_constraint(self):
        from casl.runtime import PatternMatcher

        class FakeToken:
            str = "x"
            linenr = 42

        pm = PatternMatcher()
        assert pm.match_token(
            FakeToken(), linenr=lambda n: n > 10
        )
        assert not pm.match_token(
            FakeToken(), linenr=lambda n: n > 100
        )

    def test_trace_analyzer_subsequence(self):
        from casl.runtime import TraceAnalyzer

        ta = TraceAnalyzer(None)
        actions = ["alloc", "use", "free", "use"]
        tokens = ["t1", "t2", "t3", "t4"]
        result = ta._subsequence_match(actions, tokens, ["free", "use"])
        assert result == ["t3", "t4"]

    def test_trace_analyzer_no_match(self):
        from casl.runtime import TraceAnalyzer

        ta = TraceAnalyzer(None)
        actions = ["alloc", "use", "use"]
        tokens = ["t1", "t2", "t3"]
        result = ta._subsequence_match(actions, tokens, ["free", "use"])
        assert result is None

    def test_environment_suppression(self):
        from casl.runtime import CASLEnvironment

        env = CASLEnvironment()
        env.suppress("deadStore")
        env.suppress("magicNumber", "test/*.c")

        assert env.is_suppressed("deadStore")
        assert not env.is_suppressed("nullDeref")
        assert env.is_suppressed("magicNumber", "test/foo.c")
        assert not env.is_suppressed("magicNumber", "src/main.c")


class TestEndToEnd:
    """End-to-end tests: CASL source → Python code → execution."""

    def test_generated_code_defines_main(self):
        src = textwrap.dedent('''\
            addon E2E {
                severity = "style";
            }
            checker trivial {
                error_id = "trivial";
                severity = style;
                on token {
                    let x = 1;
                }
            }
        ''')
        ast = parse(src)
        code = generate(ast)

        # Execute the generated code in an isolated namespace
        ns = {}
        # We can't actually call main() without a dump file,
        # but we can verify the code loads
        exec(compile(code, "<e2e>", "exec"), ns)
        assert "main" in ns
        assert "_CASLChecker_trivial" in ns

    def test_checker_class_has_run_method(self):
        src = textwrap.dedent('''\
            checker runner {
                error_id = "runErr";
                severity = warning;
                on token {
                    let x = tok.str;
                }
            }
        ''')
        ast = parse(src)
        code = generate(ast)
        ns = {}
        exec(compile(code, "<e2e>", "exec"), ns)
        checker_cls = ns["_CASLChecker_runner"]
        instance = checker_cls()
        assert hasattr(instance, "run")
        assert hasattr(instance, "_emit")
        assert hasattr(instance, "_diagnostics")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
