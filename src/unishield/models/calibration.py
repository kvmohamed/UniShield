"""
UniShield — Probability Calibration

Isotonic calibration maps a model's raw attack score to an empirical
probability that the window is an attack, fitted on held-out labelled
windows (never the training windows). The fitted step function is stored as
plain JSON points so it can be inspected and versioned with the model.

A score is only called a probability in UniShield after this calibration;
rule confidences are rule scores.
"""

from __future__ import annotations

from typing import Any, Sequence

import numpy as np


class IsotonicCalibrator:
    """Monotone mapping raw score → P(attack), stored as interpolation points."""

    def __init__(self, x: Sequence[float], y: Sequence[float]):
        if len(x) != len(y) or not len(x):
            raise ValueError("Calibration points must be non-empty and of equal length")
        self.x = np.asarray(x, dtype=float)
        self.y = np.clip(np.asarray(y, dtype=float), 0.0, 1.0)

    @classmethod
    def fit(cls, scores: Sequence[float], labels: Sequence[int]) -> "IsotonicCalibrator":
        from sklearn.isotonic import IsotonicRegression

        scores = np.asarray(scores, dtype=float)
        labels = np.asarray(labels, dtype=float)
        if len(np.unique(labels)) < 2:
            raise ValueError("Calibration needs both benign and attack windows")
        iso = IsotonicRegression(y_min=0.0, y_max=1.0, out_of_bounds="clip").fit(scores, labels)
        return cls(iso.X_thresholds_.tolist(), iso.y_thresholds_.tolist())

    def __call__(self, scores) -> np.ndarray:
        return np.interp(np.asarray(scores, dtype=float), self.x, self.y)

    def to_dict(self) -> dict[str, Any]:
        # Full precision: rounding the step edges would move scores across steps.
        return {"method": "isotonic", "x": [float(v) for v in self.x], "y": [float(v) for v in self.y]}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "IsotonicCalibrator":
        if data.get("method") != "isotonic":
            raise ValueError(f"Unsupported calibration method {data.get('method')!r}")
        return cls(data["x"], data["y"])


def brier_score(probabilities: Sequence[float], labels: Sequence[int]) -> float:
    p = np.asarray(probabilities, dtype=float)
    y = np.asarray(labels, dtype=float)
    return float(np.mean((p - y) ** 2)) if len(p) else 0.0


def expected_calibration_error(probabilities: Sequence[float], labels: Sequence[int], bins: int = 10) -> float:
    """Average |observed attack rate - mean predicted probability| over equal-width bins, weighted by size."""
    p = np.asarray(probabilities, dtype=float)
    y = np.asarray(labels, dtype=float)
    if not len(p):
        return 0.0
    edges = np.linspace(0.0, 1.0, bins + 1)
    idx = np.clip(np.digitize(p, edges[1:-1]), 0, bins - 1)
    error = 0.0
    for b in range(bins):
        mask = idx == b
        if mask.any():
            error += mask.mean() * abs(y[mask].mean() - p[mask].mean())
    return float(error)
