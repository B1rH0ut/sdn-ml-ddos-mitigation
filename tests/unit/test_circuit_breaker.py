"""Tests for sdn_ddos_detector.ml.circuit_breaker."""

import time
from unittest.mock import patch

import numpy as np
import pytest

from sdn_ddos_detector.ml.circuit_breaker import (
    MLCircuitBreaker,
    ThresholdFallbackDetector,
)


# ── MLCircuitBreaker ─────────────────────────────────────────────────────────

class TestMLCircuitBreaker:
    def test_initial_state_is_closed(self):
        cb = MLCircuitBreaker()
        assert cb.state == "closed"

    def test_successful_call_returns_result(self):
        cb = MLCircuitBreaker()
        result = cb.call(lambda: 42)
        assert result == 42

    def test_closed_to_open_after_fail_max(self):
        cb = MLCircuitBreaker(fail_max=5)
        for _ in range(5):
            with pytest.raises(ValueError):
                cb.call(lambda: (_ for _ in ()).throw(ValueError("boom")))
        assert cb.state == "open"

    def test_open_state_uses_fallback(self):
        cb = MLCircuitBreaker(fail_max=2)
        # Trip the breaker
        for _ in range(2):
            with pytest.raises(ValueError):
                cb.call(lambda: (_ for _ in ()).throw(ValueError("fail")))
        assert cb.state == "open"

        fallback = lambda: "fallback_result"
        result = cb.call(lambda: None, fallback=fallback)
        assert result == "fallback_result"

    def test_open_state_no_fallback_raises(self):
        cb = MLCircuitBreaker(fail_max=1)
        with pytest.raises(ValueError):
            cb.call(lambda: (_ for _ in ()).throw(ValueError("fail")))
        assert cb.state == "open"

        with pytest.raises(RuntimeError, match="OPEN"):
            cb.call(lambda: "should not run")

    def test_open_to_half_open_after_timeout(self):
        cb = MLCircuitBreaker(fail_max=1, reset_timeout=0.1)
        with pytest.raises(ValueError):
            cb.call(lambda: (_ for _ in ()).throw(ValueError("fail")))
        assert cb.state == "open"
        time.sleep(0.15)
        assert cb.state == "half_open"

    def test_half_open_success_closes_circuit(self):
        cb = MLCircuitBreaker(fail_max=1, reset_timeout=0.1, success_threshold=2)
        # Trip it
        with pytest.raises(ValueError):
            cb.call(lambda: (_ for _ in ()).throw(ValueError("fail")))
        time.sleep(0.15)
        assert cb.state == "half_open"
        # Two successes should close it
        cb.call(lambda: "ok")
        cb.call(lambda: "ok")
        assert cb.state == "closed"

    def test_half_open_failure_reopens_circuit(self):
        cb = MLCircuitBreaker(fail_max=1, reset_timeout=0.1)
        with pytest.raises(ValueError):
            cb.call(lambda: (_ for _ in ()).throw(ValueError("fail")))
        time.sleep(0.15)
        assert cb.state == "half_open"
        with pytest.raises(ValueError):
            cb.call(lambda: (_ for _ in ()).throw(ValueError("fail again")))
        assert cb.state == "open"

    def test_get_stats_tracks_totals(self):
        cb = MLCircuitBreaker(fail_max=3)
        cb.call(lambda: "ok")
        for _ in range(2):
            cb.call(
                lambda: (_ for _ in ()).throw(ValueError("x")),
                fallback=lambda: "fb",
            )
        stats = cb.get_stats()
        assert stats["total_failures"] == 2
        assert stats["total_fallbacks"] == 2


# ── ThresholdFallbackDetector ────────────────────────────────────────────────

class TestThresholdFallbackDetector:
    def test_detect_normal_flow(self):
        det = ThresholdFallbackDetector()
        result = det.detect({"packet_count_per_second": 50, "byte_count_per_second": 1000})
        assert result["is_attack"] is False

    def test_detect_attack_high_pps(self):
        det = ThresholdFallbackDetector(pps_threshold=10000)
        result = det.detect({"packet_count_per_second": 20000, "byte_count_per_second": 0})
        assert result["is_attack"] is True

    def test_detect_attack_high_bps(self):
        det = ThresholdFallbackDetector(bps_threshold=50_000_000)
        result = det.detect({"packet_count_per_second": 0, "byte_count_per_second": 100_000_000})
        assert result["is_attack"] is True

    def test_detect_batch_shape(self, normal_feature_vector, attack_feature_vector):
        det = ThresholdFallbackDetector()
        batch = np.vstack([normal_feature_vector, attack_feature_vector])
        probs = det.detect_batch(batch)
        assert probs.shape == (2, 2)

    def test_detect_batch_values(self, normal_feature_vector, attack_feature_vector):
        det = ThresholdFallbackDetector()
        batch = np.vstack([normal_feature_vector, attack_feature_vector])
        probs = det.detect_batch(batch)
        # Normal row: [0.9, 0.1]
        assert probs[0, 0] == pytest.approx(0.9)
        assert probs[0, 1] == pytest.approx(0.1)
        # Attack row: [0.5, 0.5]
        assert probs[1, 0] == pytest.approx(0.5)
        assert probs[1, 1] == pytest.approx(0.5)
