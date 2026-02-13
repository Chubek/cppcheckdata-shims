# tests/test_end_to_end.py
"""
End-to-end tests: CASL source → parse → generate → exec → run checker
on mock data → collect diagnostics.
"""

import pytest

from casl.parser import parse
from casl.codegen import generate
from tests.conftest import (
    MockToken, MockConfiguration, MockCppcheckData, MockValue,
    make_token_chain, make_cfg, make_data,
    CHECKER_MINIMAL_CASL, CHECKER_FULL_CASL,
)


def _build_and_exec(casl_src: str) -> dict:
    """Parse + generate + exec, return the namespace."""
    code = generate(parse(casl_src))
    ns = {}
    exec(compile(code, "<e2e>", "exec"), ns)
    return ns


class TestE2ECheckerExecution:

    def test_checker_runs_on_empty_data(self):
        ns = _build_and_exec(CHECKER_MINIMAL_CASL)
        cls = ns["_CASLChecker_minimal"]
        inst = cls()
        data = make_data([make_cfg([])])
        diags = inst.run(data)
        assert isinstance(diags, list)
        assert len(diags) == 0

    def test_checker_iterates_tokens(self):
        """Verify on token block fires for each token."""
        src = '''
            checker counter {
                error_id = "countErr";
                severity = style;
                on token {
                    emit countErr("found", tok.file, tok.linenr, tok.column);
                }
            }
        '''
        ns = _build_and_exec(src)
        tokens = make_token_chain([
            {"str": "a", "file": "t.c", "linenr": 1, "column": 1},
            {"str": "b", "file": "t.c", "linenr": 2, "column": 1},
            {"str": "c", "file": "t.c", "linenr": 3, "column": 1},
        ])
        data = make_data([make_cfg(tokens)])
        inst = ns["_CASLChecker_counter"]()
        diags = inst.run(data)
        assert len(diags) == 3

    def test_checker_conditional_emit(self):
        """Checker that only emits for assignment ops."""
        src = '''
            checker assign_finder {
                error_id = "assignFound";
                severity = warning;
                on token {
                    if tok.isAssignmentOp {
                        emit assignFound("assign", tok.file, tok.linenr, 0);
                    }
                }
            }
        '''
        ns = _build_and_exec(src)
        tokens = make_token_chain([
            {"str": "x", "isName": True},
            {"str": "=", "isAssignmentOp": True},
            {"str": "0", "isNumber": True},
            {"str": ";"},
            {"str": "y", "isName": True},
            {"str": "+", "isOp": True},
            {"str": "1", "isNumber": True},
        ])
        data = make_data([make_cfg(tokens)])
        diags = ns["_CASLChecker_assign_finder"]().run(data)
        assert len(diags) == 1

    def test_checker_uses_helper_fn(self):
        """Checker that calls a top-level function."""
        src = '''
            fn is_name_tok(tok) {
                return tok.isName;
            }

            checker name_finder {
                error_id = "nameFound";
                severity = style;
                on token {
                    if is_name_tok(tok) {
                        emit nameFound("name", tok.file, tok.linenr, 0);
                    }
                }
            }
        '''
        ns = _build_and_exec(src)
        tokens = make_token_chain([
            {"str": "x", "isName": True},
            {"str": "="},
            {"str": "y", "isName": True},
        ])
        data = make_data([make_cfg(tokens)])
        diags = ns["_CASLChecker_name_finder"]().run(data)
        assert len(diags) == 2

    def test_checker_multiple_configurations(self):
        """Checker runs across all configurations."""
        src = '''
            checker multi_cfg {
                error_id = "mc";
                severity = style;
                on token {
                    emit mc("t", tok.file, tok.linenr, 0);
                }
            }
        '''
        ns = _build_and_exec(src)
        cfg1 = make_cfg(make_token_chain([{"str": "a"}]))
        cfg2 = make_cfg(make_token_chain([{"str": "b"}, {"str": "c"}]))
        data = make_data([cfg1, cfg2])
        diags = ns["_CASLChecker_multi_cfg"]().run(data)
        assert len(diags) == 3  # 1 from cfg1 + 2 from cfg2

    def test_suppression_prevents_emit(self):
        src = '''
            checker supp_test {
                error_id = "suppMe";
                severity = style;
                suppress "suppMe";
                on token {
                    emit suppMe("msg", tok.file, tok.linenr, 0);
                }
            }
        '''
        ns = _build_and_exec(src)
        tokens = make_token_chain([{"str": "a"}])
        data = make_data([make_cfg(tokens)])
        diags = ns["_CASLChecker_supp_test"]().run(data)
        assert len(diags) == 0

    def test_main_function_exists(self):
        ns = _build_and_exec(CHECKER_MINIMAL_CASL)
        assert callable(ns["main"])

    def test_multiple_checkers_run(self):
        src = '''
            checker chk_a {
                error_id = "a";
                severity = style;
                on token {
                    if tok.isName {
                        emit a("name", tok.file, tok.linenr, 0);
                    }
                }
            }
            checker chk_b {
                error_id = "b";
                severity = style;
                on token {
                    if tok.isOp {
                        emit b("op", tok.file, tok.linenr, 0);
                    }
                }
            }
        '''
        ns = _build_and_exec(src)
        tokens = make_token_chain([
            {"str": "x", "isName": True},
            {"str": "+", "isOp": True},
            {"str": "y", "isName": True},
        ])
        data = make_data([make_cfg(tokens)])
        diags_a = ns["_CASLChecker_chk_a"]().run(data)
        diags_b = ns["_CASLChecker_chk_b"]().run(data)
        assert len(diags_a) == 2  # x and y
        assert len(diags_b) == 1  # +
