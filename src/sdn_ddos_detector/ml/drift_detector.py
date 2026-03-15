"""
Concept drift detection for the ML classifier.

Replaces the EMA-based drift detection (audit 4.7) which slowly adapted
its baseline, masking gradual attacks. Uses ADWIN (Adaptive Windowing)
from the river library when available, with a z-score fallback.

ADWIN uses Hoeffding bounds to detect distribution changes without
adapting away the signal it should detect.
"""

import math
import time
from collections import deque
from dataclasses import dataclass, field


@dataclass
class DriftResult:
    """Result from a single drift monitor update."""
    detected: bool
    stats: dict = field(default_factory=dict)


class DriftMonitor:
    """
    Concept drift monitor for ML prediction error rates.

    Uses ADWIN (river library) when available, otherwise falls back
    to z-score detection over a sliding window.

    Args:
        delta: ADWIN sensitivity parameter (lower = more sensitive).
        window_size: Fallback sliding window size for z-score method.
    """

    def __init__(self, delta=0.002, window_size=1000):
        try:
            from river.drift import ADWIN
            self._detector = ADWIN(delta=delta)
            self._method = "adwin"
        except ImportError:
            self._method = "zscore_fallback"
            self._window = deque(maxlen=window_size)
        self._drift_count = 0
        self._last_drift_time = None

    def update(self, prediction_error):
        """Feed a prediction error value (0.0 = correct, 1.0 = incorrect).

        Args:
            prediction_error: Error signal, typically 0.0 or 1.0.

        Returns:
            DriftResult with detected flag and current stats.
        """
        detected = False

        if self._method == "adwin":
            self._detector.update(prediction_error)
            detected = self._detector.drift_detected
        else:
            self._window.append(prediction_error)
            if len(self._window) >= 100:
                mean = sum(self._window) / len(self._window)
                variance = sum((x - mean) ** 2 for x in self._window) / len(self._window)
                std = math.sqrt(variance) if variance > 0 else 0
                if std > 0:
                    detected = prediction_error > mean + 3 * std
                else:
                    detected = False

        if detected:
            self._drift_count += 1
            self._last_drift_time = time.time()

        return DriftResult(detected=detected, stats=self.get_stats())

    def get_stats(self):
        """Return current drift detection statistics."""
        return {
            "method": self._method,
            "drift_count": self._drift_count,
            "last_drift_time": self._last_drift_time,
        }
