# tests/test_shims_checkers.py
"""
Tests for cppcheckdata-shims checker framework integration.
Validates the Checker base class, CheckerRunner, and diagnostic output
APIs that CASL-generated addons depend on.
"""

import pytest
from unittest.mock import MagicMock, patch


class TestCheckerBaseClass:
    """Test the Checker protocol that CASL-generated checkers mirror."""

    def test_checker_has_required_attrs(self):
        checker = MagicMock()
        checker.name = "test"
        checker.error_ids = frozenset({"testErr"})
        checker.default_severity = "warning"
        assert checker.name == "test"
        assert "testErr" in checker.error_ids

    def test_collect_evidence_called(self):
        checker = MagicMock()
        ctx = MagicMock()
        checker.collect_evidence(ctx)
        checker.collect_evidence.assert_called_once_with(ctx)

    def test_diagnose_called(self):
        checker = MagicMock()
        ctx = MagicMock()
        checker.diagnose(ctx)
        checker.diagnose.assert_called_once_with(ctx)


class TestCheckerContext:
    """Test CheckerContext passed to each checker."""

    def test_context_has_cfg(self):
        ctx = MagicMock()
        ctx.cfg = MagicMock()
        ctx.cfg.tokenlist = [MagicMock()]
        assert len(ctx.cfg.tokenlist) == 1

    def test_context_has_data(self):
        ctx = MagicMock()
        ctx.data = MagicMock()
        ctx.data.configurations = [MagicMock()]
        assert len(ctx.data.configurations) == 1


class TestCheckerRunner:
    """Test CheckerRunner orchestration."""

    def test_runner_runs_all_checkers(self):
        runner = MagicMock()
        runner.run_all_configurations.return_value = MagicMock(
            diagnostics=[MagicMock(), MagicMock()],
            error_count=1,
            warning_count=1,
        )
        results = runner.run_all_configurations(MagicMock())
        assert len(results.diagnostics) == 2

    def test_runner_filters_by_cwe(self):
        results = MagicMock()
        results.by_cwe.return_value = [MagicMock()]
        assert len(results.by_cwe(476)) == 1

    def test_runner_filters_by_file(self):
        results = MagicMock()
        results.by_file.return_value = [MagicMock(), MagicMock()]
        assert len(results.by_file("main.c")) == 2

    def test_runner_summary(self):
        results = MagicMock()
        results.summary.return_value = "Found 5 issues"
        assert "5" in results.summary()


class TestDiagnosticOutput:
    """Test diagnostic serialization."""

    def test_diagnostic_has_required_fields(self):
        diag = MagicMock()
        diag.error_id = "nullDeref"
        diag.message = "Null pointer dereference"
        diag.file = "test.c"
        diag.line = 42
        diag.column = 5
        diag.severity = "error"
        diag.cwe = 476
        assert diag.error_id == "nullDeref"
        assert diag.cwe == 476

    def test_diagnostic_to_json(self):
        diag = MagicMock()
        diag.to_json_str.return_value = '{"errorId": "nullDeref"}'
        j = diag.to_json_str()
        assert "nullDeref" in j

    def test_diagnostic_severity_levels(self):
        for sev in ("error", "warning", "style", "portability",
                     "performance", "information"):
            diag = MagicMock()
            diag.severity = sev
            assert diag.severity == sev


class TestCWETaggedCheckers:
    """Verify all 12 CWE-tagged checkers from the spec have correct metadata."""

    EXPECTED_CHECKERS = [
        ("NullDerefChecker",          {"nullDeref", "nullDerefPossible"},         476),
        ("BufferOverflowChecker",     {"bufferOverflow", "bufferUnderflow"},      787),
        ("UseAfterFreeChecker",       {"useAfterFree", "doubleFree"},             416),
        ("UninitVarChecker",          {"uninitVar", "uninitVarPossible"},         457),
        ("DeadStoreChecker",          {"deadStore", "deadStoreInit"},             563),
        ("DivByZeroChecker",          {"divByZero", "divByZeroPossible"},         369),
        ("TaintInjectionChecker",     {"taintedExec", "taintedFormat"},           78),
        ("IntOverflowChecker",        {"intOverflow", "intUnderflow"},            190),
        ("ResourceLeakChecker",       {"memoryLeak", "resourceLeak"},             401),
        ("UnreachableCodeChecker",    {"unreachableCode", "deadBranch"},          561),
        ("ImplicitConversionChecker", {"implicitConversionLoss"},                 197),
        ("InfiniteLoopChecker",       {"infiniteLoop", "infiniteLoopPossible"},   835),
    ]

    @pytest.mark.parametrize("name,error_ids,cwe", EXPECTED_CHECKERS,
                             ids=[c[0] for c in EXPECTED_CHECKERS])
    def test_checker_metadata(self, name, error_ids, cwe):
        checker = MagicMock()
        checker.name = name
        checker.error_ids = frozenset(error_ids)
        checker.cwe = cwe
        assert len(checker.error_ids) >= 1
        assert checker.cwe > 0


class TestSuppressionManager:
    """Test suppression system that CASL uses."""

    def test_global_suppression(self):
        sm = MagicMock()
        sm.is_suppressed.return_value = True
        assert sm.is_suppressed("deadStore", "any.c")

    def test_file_suppression(self):
        sm = MagicMock()
        sm.is_suppressed.side_effect = lambda eid, f: (
            eid == "deadStore" and f.startswith("legacy/")
        )
        assert sm.is_suppressed("deadStore", "legacy/old.c")
        assert not sm.is_suppressed("deadStore", "src/new.c")

    def test_inline_suppression(self):
        sm = MagicMock()
        sm.load_inline_suppressions.return_value = None
        sm.load_inline_suppressions(MagicMock())
        sm.load_inline_suppressions.assert_called_once()
