"""
Circuit breaker for ML inference in the SDN controller.

Prevents silent detection failures (audit 8.3) by tracking consecutive
ML prediction failures and switching to a heuristic fallback detector
when the model is consistently failing.

States:
    CLOSED  - Normal operation, ML model is used for predictions.
    OPEN    - ML model has failed too many times, fallback is used.
    HALF_OPEN - Testing whether ML model has recovered.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Callable

import numpy as np

logger = logging.getLogger(__name__)


class MLCircuitBreaker:
    """
    Circuit breaker pattern for ML model inference.

    Transitions:
        CLOSED  -> OPEN      after fail_max consecutive failures
        OPEN    -> HALF_OPEN  after reset_timeout seconds
        HALF_OPEN -> CLOSED   after success_threshold consecutive successes
        HALF_OPEN -> OPEN     on any failure

    Args:
        fail_max: Failures before opening the circuit.
        reset_timeout: Seconds to wait before attempting recovery.
        success_threshold: Successes needed in HALF_OPEN to close circuit.
    """

    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"

    def __init__(self, fail_max=5, reset_timeout=30, success_threshold=2):
        self.fail_max = fail_max
        self.reset_timeout = reset_timeout
        self.success_threshold = success_threshold
        self._state = self.CLOSED
        self._fail_count = 0
        self._success_count = 0
        self._last_failure_time = None
        self._total_failures = 0
        self._total_fallbacks = 0

    @property
    def state(self):
        """Current circuit breaker state."""
        if self._state == self.OPEN and self._last_failure_time is not None:
            if time.time() - self._last_failure_time >= self.reset_timeout:
                self._state = self.HALF_OPEN
                self._success_count = 0
                logger.warning(
                    "Circuit breaker HALF_OPEN: testing ML model recovery"
                )
        return self._state

    def call(self, func: Callable, *args: Any, fallback: Callable | None = None, **kwargs: Any) -> Any:
        """
        Call func with circuit breaker protection.

        If the circuit is OPEN, the fallback is used immediately.
        If func raises an exception, failures are tracked.

        Args:
            func: The ML function to call (e.g., model.predict_proba).
            *args: Positional arguments for func.
            fallback: Callable to use when circuit is open. Receives
                the same *args and **kwargs.
            **kwargs: Keyword arguments for func.

        Returns:
            Result from func or fallback.

        Raises:
            Exception: Re-raises if no fallback is provided and circuit
                is closed/half-open.
        """
        current_state = self.state

        if current_state == self.OPEN:
            self._total_fallbacks += 1
            if fallback is not None:
                logger.info("Circuit OPEN: using fallback detector")
                return fallback(*args, **kwargs)
            raise RuntimeError(
                "ML circuit breaker is OPEN and no fallback provided"
            )

        try:
            result = func(*args, **kwargs)
            self._on_success()
            return result
        except Exception as e:
            self._on_failure()
            if fallback is not None:
                self._total_fallbacks += 1
                logger.warning(
                    "ML prediction failed (%s), using fallback: %s",
                    self._state, str(e)
                )
                return fallback(*args, **kwargs)
            raise

    def _on_success(self):
        """Record a successful ML call."""
        if self._state == self.HALF_OPEN:
            self._success_count += 1
            if self._success_count >= self.success_threshold:
                self._state = self.CLOSED
                self._fail_count = 0
                self._success_count = 0
                logger.warning("Circuit breaker CLOSED: ML model recovered")
        else:
            self._fail_count = 0

    def _on_failure(self):
        """Record a failed ML call."""
        self._fail_count += 1
        self._total_failures += 1
        self._last_failure_time = time.time()

        if self._state == self.HALF_OPEN:
            self._state = self.OPEN
            logger.warning(
                "Circuit breaker OPEN: ML model failed during recovery test"
            )
        elif self._fail_count >= self.fail_max:
            self._state = self.OPEN
            logger.critical(
                "Circuit breaker OPEN: %d consecutive ML failures. "
                "Detection is using fallback heuristics.",
                self._fail_count
            )

    def get_stats(self) -> dict[str, Any]:
        """Return circuit breaker statistics."""
        return {
            "state": self.state,
            "fail_count": self._fail_count,
            "total_failures": self._total_failures,
            "total_fallbacks": self._total_fallbacks,
        }


class ThresholdFallbackDetector:
    """
    Simple heuristic DDoS detector used when the ML model is unavailable.

    Uses static thresholds on raw traffic features as a last resort.
    Less accurate than the ML model but provides non-zero detection
    capability during model failures.
    """

    def __init__(self, pps_threshold=10000, bps_threshold=50_000_000):
        self.pps_threshold = pps_threshold
        self.bps_threshold = bps_threshold

    def detect(self, features_dict: dict[str, float]) -> dict[str, Any]:
        """Detect a single flow using threshold heuristics.

        Args:
            features_dict: Dict with at least packet_count_per_second
                and byte_count_per_second keys.

        Returns:
            dict: {"is_attack": bool, "confidence": float, "method": str}
        """
        pps = features_dict.get('packet_count_per_second', 0)
        bps = features_dict.get('byte_count_per_second', 0)
        is_attack = pps > self.pps_threshold or bps > self.bps_threshold
        return {
            "is_attack": is_attack,
            "confidence": 0.5 if is_attack else 0.1,
            "method": "threshold_fallback",
        }

    def detect_batch(self, features_array: np.ndarray) -> np.ndarray:
        """Detect a batch of flows, returning probabilities array.

        Mimics model.predict_proba() output shape: (n_samples, 2).

        Args:
            features_array: numpy array of shape (n_samples, 12).

        Returns:
            numpy.ndarray: Shape (n_samples, 2) with [P(normal), P(attack)].
        """
        from sdn_ddos_detector.ml.feature_engineering import FEATURE_NAMES

        pps_idx = FEATURE_NAMES.index('packet_count_per_second')
        bps_idx = FEATURE_NAMES.index('byte_count_per_second')

        n_samples = features_array.shape[0]
        probabilities = np.zeros((n_samples, 2))

        for i in range(n_samples):
            pps = features_array[i, pps_idx]
            bps = features_array[i, bps_idx]
            is_attack = pps > self.pps_threshold or bps > self.bps_threshold
            if is_attack:
                probabilities[i] = [0.5, 0.5]
            else:
                probabilities[i] = [0.9, 0.1]

        return probabilities
