# tests/test_codegen.py
"""
Tests for CASL code generation: AST → Python source.
Verifies the output is syntactically valid Python and structurally correct.
"""

import pytest

from casl.parser import parse
from casl.codegen import generate
from tests.conftest import (
    MINIMAL_CASL, ADDON_ONLY_CASL, CHECKER_MINIMAL_CASL,
    CHECKER_FULL_CASL, FN_CASL, CONST_CASL, PATTERN_CASL,
    SUPPRESS_CASL, FOR_LOOP_CASL, IF_ELIF_ELSE_CASL,
    IMPORT_CASL, QUERY_CASL,
)


def _gen(casl_src: str) -> str:
    """Parse + generate, return Python source."""
    return generate(parse(casl_src))


def _compile_check(code: str):
    """Assert code is valid Python."""
    compile(code, "<test>", "exec")


class TestCodeGenValidity:
    """All generated code must be syntactically valid Python."""

    @pytest.mark.parametrize("src", [
        MINIMAL_CASL,
        ADDON_ONLY_CASL,
        CHECKER_MINIMAL_CASL,
        CHECKER_FULL_CASL,
        FN_CASL,
        CONST_CASL,
        PATTERN_CASL,
        SUPPRESS_CASL,
        FOR_LOOP_CASL,
        IF_ELIF_ELSE_CASL,
        IMPORT_CASL,
        QUERY_CASL,
    ], ids=[
        "empty", "addon_only", "checker_minimal", "checker_full",
        "fn", "const", "pattern", "suppress", "for_loop",
        "if_elif_else", "import", "query",
    ])
    def test_generates_valid_python(self, src):
        code = _gen(src)
        _compile_check(code)


class TestCodeGenStructure:

    def test_has_main(self):
        code = _gen(CHECKER_MINIMAL_CASL)
        assert "def main():" in code

    def test_has_checker_class(self):
        code = _gen(CHECKER_MINIMAL_CASL)
        assert "class _CASLChecker_minimal:" in code

    def test_has_run_method(self):
        code = _gen(CHECKER_MINIMAL_CASL)
        assert "def run(self, data):" in code

    def test_has_emit_method(self):
        code = _gen(CHECKER_MINIMAL_CASL)
        assert "def _emit(self" in code

    def test_has_parsedump_import(self):
        code = _gen(CHECKER_MINIMAL_CASL)
        assert "parsedump" in code

    def test_has_argparse(self):
        code = _gen(CHECKER_MINIMAL_CASL)
        assert "argparse" in code

    def test_has_cli_mode(self):
        code = _gen(CHECKER_MINIMAL_CASL)
        assert "_CLI_MODE" in code

    def test_if_name_main(self):
        code = _gen(CHECKER_MINIMAL_CASL)
        assert "if __name__" in code

    def test_fn_becomes_def(self):
        code = _gen(FN_CASL)
        assert "def helper(x, y):" in code

    def test_const_becomes_assignment(self):
        code = _gen(CONST_CASL)
        assert "MAX_VAL = 42" in code

    def test_pattern_becomes_method(self):
        code = _gen(PATTERN_CASL)
        assert "_pattern_deref_op" in code

    def test_suppression_registered(self):
        code = _gen(SUPPRESS_CASL)
        assert "_FILE_SUPPRESSIONS" in code or "_SUPPRESSIONS" in code

    def test_for_generates_python_for(self):
        code = _gen(FOR_LOOP_CASL)
        assert "for item in items:" in code

    def test_if_generates_python_if(self):
        code = _gen(IF_ELIF_ELSE_CASL)
        assert "if " in code
        assert "elif " in code
        assert "else:" in code

    def test_import_generates_python_import(self):
        code = _gen(IMPORT_CASL)
        assert "import utils.helpers" in code

    def test_multiple_checkers(self):
        src = '''
            checker alpha {
                error_id = "alphaErr";
                severity = style;
                on token { let x = 1; }
            }
            checker beta {
                error_id = "betaErr";
                severity = warning;
                on token { let y = 2; }
            }
        '''
        code = _gen(src)
        assert "_CASLChecker_alpha" in code
        assert "_CASLChecker_beta" in code
        # main runs both
        assert "_CASLChecker_alpha().run(data)" in code
        assert "_CASLChecker_beta().run(data)" in code


class TestCodeGenExpressions:

    def test_binary_ops(self):
        code = _gen('fn test() { let x = a + b; }')
        assert "(a + b)" in code

    def test_comparison(self):
        code = _gen('fn test() { let x = a > 0; }')
        assert "(a > 0)" in code

    def test_logical_and(self):
        code = _gen('fn test() { let x = a && b; }')
        assert "and" in code

    def test_logical_or(self):
        code = _gen('fn test() { let x = a || b; }')
        assert "or" in code

    def test_unary_not(self):
        code = _gen('fn test() { let x = !y; }')
        assert "not " in code

    def test_list_literal(self):
        code = _gen('fn test() { let x = [1, 2, 3]; }')
        assert "[1, 2, 3]" in code

    def test_string_literal(self):
        code = _gen('fn test() { let x = "hello"; }')
        assert "'hello'" in code

    def test_bool_true(self):
        code = _gen('fn test() { let x = true; }')
        assert "True" in code

    def test_bool_false(self):
        code = _gen('fn test() { let x = false; }')
        assert "False" in code

    def test_null_becomes_none(self):
        code = _gen('fn test() { let x = null; }')
        assert "None" in code


class TestCodeGenExecutability:
    """Generated code can be exec'd (minus cppcheck deps)."""

    def test_exec_checker_class(self):
        code = _gen(CHECKER_MINIMAL_CASL)
        ns = {}
        exec(compile(code, "<test>", "exec"), ns)
        assert "_CASLChecker_minimal" in ns

    def test_exec_creates_instance(self):
        code = _gen(CHECKER_MINIMAL_CASL)
        ns = {}
        exec(compile(code, "<test>", "exec"), ns)
        inst = ns["_CASLChecker_minimal"]()
        assert hasattr(inst, "run")
        assert hasattr(inst, "_diagnostics")
        assert inst._diagnostics == []

    def test_exec_fn_callable(self):
        code = _gen(FN_CASL)
        ns = {}
        exec(compile(code, "<test>", "exec"), ns)
        assert "helper" in ns
