# tests/test_shims_bridge.py
"""
Tests for the ShimsBridge: lazy analysis management and query wrappers.
"""

import pytest
from unittest.mock import MagicMock, patch

from casl.shims_bridge import ShimsBridge


class TestShimsBridgeCache:

    def test_same_analysis_cached(self):
        bridge = ShimsBridge()
        cfg = MagicMock()
        cfg_id = id(cfg)

        with patch("casl.shims_bridge.ShimsBridge._build") as mock_build:
            mock_analysis = MagicMock()
            mock_build.return_value = mock_analysis

            a1 = bridge.get("intervals", cfg)
            a2 = bridge.get("intervals", cfg)

            assert a1 is a2
            assert mock_build.call_count == 1

    def test_different_analyses_separate(self):
        bridge = ShimsBridge()
        cfg = MagicMock()

        with patch("casl.shims_bridge.ShimsBridge._build") as mock_build:
            mock_build.side_effect = [MagicMock(), MagicMock()]

            a1 = bridge.get("intervals", cfg)
            a2 = bridge.get("taint", cfg)

            assert a1 is not a2
            assert mock_build.call_count == 2

    def test_different_cfgs_separate(self):
        bridge = ShimsBridge()
        cfg1 = MagicMock()
        cfg2 = MagicMock()

        with patch("casl.shims_bridge.ShimsBridge._build") as mock_build:
            mock_build.side_effect = [MagicMock(), MagicMock()]

            a1 = bridge.get("intervals", cfg1)
            a2 = bridge.get("intervals", cfg2)

            assert a1 is not a2

    def test_invalidate_all(self):
        bridge = ShimsBridge()
        cfg = MagicMock()

        with patch("casl.shims_bridge.ShimsBridge._build") as mock_build:
            mock_build.return_value = MagicMock()
            bridge.get("intervals", cfg)
            bridge.invalidate()
            bridge.get("intervals", cfg)
            assert mock_build.call_count == 2

    def test_invalidate_specific_cfg(self):
        bridge = ShimsBridge()
        cfg1 = MagicMock()
        cfg2 = MagicMock()

        with patch("casl.shims_bridge.ShimsBridge._build") as mock_build:
            mock_build.return_value = MagicMock()
            bridge.get("intervals", cfg1)
            bridge.get("intervals", cfg2)
            bridge.invalidate(cfg1)
            # cfg2 still cached
            bridge.get("intervals", cfg2)
            assert mock_build.call_count == 2  # cfg1 + cfg2 initially


class TestShimsBridgeUnknownAnalysis:

    def test_unknown_analysis_raises(self):
        bridge = ShimsBridge()
        cfg = MagicMock()
        with pytest.raises(ValueError, match="Unknown analysis"):
            bridge._build("nonexistent_analysis", cfg)


class TestShimsBridgeQueryWrappers:

    def test_null_check_returns_none_on_error(self):
        bridge = ShimsBridge()
        cfg = MagicMock()
        tok = MagicMock()

        with patch.object(bridge, "get", side_effect=Exception("no shims")):
            result = bridge.null_check(cfg, tok)
            assert result is None

    def test_interval_check_returns_none_on_error(self):
        bridge = ShimsBridge()
        result = bridge.interval_check(MagicMock(), 1, 0, 100, MagicMock())
        # Will fail because shims not installed — should return None
        assert result is None

    def test_is_tainted_returns_none_on_error(self):
        bridge = ShimsBridge()
        result = bridge.is_tainted(MagicMock(), MagicMock())
        assert result is None

    def test_is_live_returns_none_on_error(self):
        bridge = ShimsBridge()
        result = bridge.is_live(MagicMock(), 1, MagicMock())
        assert result is None

    def test_null_check_delegates(self):
        bridge = ShimsBridge()
        mock_npa = MagicMock()
        mock_npa.may_be_null.return_value = True

        with patch.object(bridge, "get", return_value=mock_npa):
            assert bridge.null_check(MagicMock(), MagicMock()) is True
            mock_npa.may_be_null.assert_called_once()

    def test_interval_check_delegates(self):
        bridge = ShimsBridge()
        mock_ia = MagicMock()
        mock_ia.is_in_bounds.return_value = True

        with patch.object(bridge, "get", return_value=mock_ia):
            result = bridge.interval_check(MagicMock(), 1, 0, 100, MagicMock())
            assert result is True

    def test_taint_check_delegates(self):
        bridge = ShimsBridge()
        mock_ta = MagicMock()
        mock_ta.is_tainted_at.return_value = False

        with patch.object(bridge, "get", return_value=mock_ta):
            assert bridge.is_tainted(MagicMock(), MagicMock()) is False

    def test_liveness_check_delegates(self):
        bridge = ShimsBridge()
        mock_lv = MagicMock()
        mock_lv.is_live_after.return_value = False

        with patch.object(bridge, "get", return_value=mock_lv):
            assert bridge.is_live(MagicMock(), 1, MagicMock()) is False
