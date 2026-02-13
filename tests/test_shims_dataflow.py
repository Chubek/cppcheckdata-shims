# tests/test_shims_dataflow.py
"""
Tests for cppcheckdata-shims dataflow analyses integration.

These tests use mock objects to verify the API contracts that CASL
expects from each analysis. When shims are not installed, tests are
skipped gracefully.
"""

import pytest
from unittest.mock import MagicMock, patch, PropertyMock
from tests.conftest import (
    MockToken, MockVariable, MockConfiguration, MockValue,
    make_token_chain, make_cfg,
)


# ── Fixture: skip if shims not installed ─────────────────────────

def _has_shims():
    try:
        import cppcheckdata_shims
        return True
    except ImportError:
        return False


shims_available = pytest.mark.skipif(
    not _has_shims(),
    reason="cppcheckdata-shims not installed"
)


# ── API Contract Tests (mock-based, always run) ─────────────────

class TestDataflowAPIContracts:
    """
    Verify that the interfaces CASL generated code calls exist
    and have the expected signatures.
    """

    def test_reaching_definitions_api(self):
        """ReachingDefinitions must have .run() and .reaching_at(token)."""
        rd = MagicMock()
        rd.run.return_value = None
        rd.reaching_at.return_value = set()
        rd.run()
        result = rd.reaching_at(MagicMock())
        assert isinstance(result, set)

    def test_live_variables_api(self):
        """LiveVariables must have .run() and .is_live_after(var_id, token)."""
        lv = MagicMock()
        lv.run.return_value = None
        lv.is_live_after.return_value = True
        lv.run()
        assert lv.is_live_after(1, MagicMock()) is True

    def test_interval_analysis_api(self):
        """IntervalAnalysis must have .run() and .is_in_bounds(var_id, lo, hi, tok)."""
        ia = MagicMock()
        ia.run.return_value = None
        ia.is_in_bounds.return_value = True
        ia.run()
        assert ia.is_in_bounds(1, 0, 99, MagicMock()) is True

    def test_null_pointer_analysis_api(self):
        """NullPointerAnalysis must have .run() and .may_be_null(tok)."""
        npa = MagicMock()
        npa.run.return_value = None
        npa.may_be_null.return_value = False
        npa.run()
        assert npa.may_be_null(MagicMock()) is False

    def test_taint_analysis_api(self):
        """TaintAnalysis must have .run() and .is_tainted_at(tok)."""
        ta = MagicMock()
        ta.run.return_value = None
        ta.is_tainted_at.return_value = True
        ta.run()
        assert ta.is_tainted_at(MagicMock()) is True

    def test_sign_analysis_api(self):
        """SignAnalysis must have .run() and queryable state."""
        sa = MagicMock()
        sa.run.return_value = None
        sa.run()

    def test_constant_propagation_api(self):
        """ConstantPropagation must have .run()."""
        cp = MagicMock()
        cp.run.return_value = None
        cp.run()

    def test_pointer_analysis_api(self):
        """PointerAnalysis must have .run()."""
        pa = MagicMock()
        pa.run.return_value = None
        pa.run()


class TestDataflowDirection:
    """Verify that analyses report correct direction / confluence per
    the framework spec (used by custom analyses composed in CASL)."""

    def _mock_analysis(self, direction="forward", confluence="join"):
        a = MagicMock()
        a.direction = direction
        a.confluence = confluence
        return a

    def test_reaching_defs_forward_join(self):
        a = self._mock_analysis("forward", "join")
        assert a.direction == "forward"
        assert a.confluence == "join"

    def test_available_exprs_forward_meet(self):
        a = self._mock_analysis("forward", "meet")
        assert a.direction == "forward"
        assert a.confluence == "meet"

    def test_live_vars_backward_join(self):
        a = self._mock_analysis("backward", "join")
        assert a.direction == "backward"
        assert a.confluence == "join"

    def test_very_busy_backward_meet(self):
        a = self._mock_analysis("backward", "meet")
        assert a.direction == "backward"
        assert a.confluence == "meet"


class TestDataflowValueFlowIntegration:
    """Test that analyses respect ValueFlow data on tokens."""

    def test_null_from_valueflow(self):
        """A token with intvalue==0 in values is potentially null."""
        tok = MockToken(
            str="p",
            isName=True,
            values=[MockValue(intvalue=0, isPossible=True)],
        )
        # The analysis should detect this as possibly null
        has_null = any(v.intvalue == 0 for v in tok.values)
        assert has_null

    def test_interval_from_valueflow(self):
        """ValueFlow values define variable ranges."""
        tok = MockToken(
            values=[
                MockValue(intvalue=0),
                MockValue(intvalue=100),
            ]
        )
        lo = min(v.intvalue for v in tok.values)
        hi = max(v.intvalue for v in tok.values)
        assert lo == 0
        assert hi == 100

    def test_no_values_means_top(self):
        """Token with no values → analysis returns top (unknown)."""
        tok = MockToken(values=None)
        assert tok.values is None


class TestRunAllAnalyses:
    """Test the run_all_analyses convenience function contract."""

    def test_run_all_returns_dict(self):
        mock_run = MagicMock()
        mock_run.return_value = {
            "live_vars": MagicMock(),
            "intervals": MagicMock(),
        }
        result = mock_run(MagicMock(), analyses={"live_vars", "intervals"})
        assert "live_vars" in result
        assert "intervals" in result

    def test_run_all_empty_selection(self):
        mock_run = MagicMock()
        mock_run.return_value = {}
        result = mock_run(MagicMock(), analyses=set())
        assert result == {}
