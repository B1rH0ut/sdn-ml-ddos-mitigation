"""Tests for sdn_ddos_detector.ml.drift_detector."""

import sys
from unittest.mock import patch

import pytest

from sdn_ddos_detector.ml.drift_detector import DriftResult, DriftMonitor


class TestDriftResult:
    def test_drift_result_fields(self):
        r = DriftResult(detected=True, stats={"drift_count": 1})
        assert r.detected is True
        assert isinstance(r.stats, dict)
        assert r.stats["drift_count"] == 1


class TestDriftMonitorZScore:
    """Test z-score fallback by hiding the river library."""

    def _make_zscore_monitor(self):
        """Create a DriftMonitor that always uses z-score fallback."""
        # Temporarily hide river from imports
        saved = {}
        for mod_name in list(sys.modules):
            if mod_name == "river" or mod_name.startswith("river."):
                saved[mod_name] = sys.modules.pop(mod_name)
        try:
            with patch.dict("sys.modules", {"river": None, "river.drift": None}):
                monitor = DriftMonitor(window_size=200)
        finally:
            sys.modules.update(saved)
        return monitor

    def test_initial_stats_zero_drift_count(self):
        monitor = self._make_zscore_monitor()
        assert monitor.get_stats()["drift_count"] == 0

    def test_method_is_zscore_fallback(self):
        monitor = self._make_zscore_monitor()
        assert monitor.get_stats()["method"] == "zscore_fallback"

    def test_no_drift_with_uniform_errors(self):
        monitor = self._make_zscore_monitor()
        for _ in range(200):
            result = monitor.update(0.0)
        assert result.detected is False

    def test_no_drift_below_100_samples(self):
        monitor = self._make_zscore_monitor()
        detected_any = False
        for _ in range(99):
            result = monitor.update(1.0)
            if result.detected:
                detected_any = True
        assert detected_any is False

    def test_drift_detected_with_spike(self):
        monitor = self._make_zscore_monitor()
        # Feed 150 zeros to build baseline
        for _ in range(150):
            monitor.update(0.0)
        # A spike of 1.0 should be > mean + 3*std when std ≈ 0
        result = monitor.update(1.0)
        assert result.detected is True

    def test_drift_count_increments(self):
        monitor = self._make_zscore_monitor()
        for _ in range(150):
            monitor.update(0.0)
        monitor.update(1.0)
        assert monitor.get_stats()["drift_count"] >= 1


class TestDriftMonitorADWIN:
    def test_method_is_adwin(self):
        try:
            import river.drift  # noqa: F401
        except ImportError:
            pytest.skip("river library not installed")
        monitor = DriftMonitor()
        assert monitor.get_stats()["method"] == "adwin"
