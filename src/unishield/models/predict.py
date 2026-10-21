"""
UniShield — Window Model Inference

Wraps a trained bundle (``models.train``) for use on live windows: builds the
feature vector from a window's feature dictionary, computes the raw attack
score, applies the stored isotonic calibration and names the most likely
attack class (supervised models only).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

import numpy as np

from unishield.models.calibration import IsotonicCalibrator
from unishield.models.dataset import BENIGN
from unishield.models.features import model_vector
from unishield.models.registry import ModelRegistry
from unishield.models.train import raw_attack_scores


@dataclass
class WindowPrediction:
    raw_score: float
    probability: Optional[float]          # calibrated P(attack); None without calibration
    predicted_class: Optional[str]        # most likely attack class (supervised models)
    class_probability: Optional[float]    # uncalibrated share of that class


class WindowModel:
    """A trained window model ready for inference."""

    def __init__(self, bundle: dict[str, Any], metadata: dict[str, Any] | None = None):
        self.bundle = bundle
        self.metadata = metadata or {}
        self.algorithm: str = bundle["algorithm"]
        self.feature_keys: list[str] = list(bundle["feature_keys"])
        cal = bundle.get("calibrator")
        self.calibrator = IsotonicCalibrator.from_dict(cal) if cal else None

    @classmethod
    def load(cls, name: str, version: int | None = None, registry: ModelRegistry | None = None) -> "WindowModel":
        bundle, meta = (registry or ModelRegistry()).load(name, version)
        return cls(bundle, meta)

    @property
    def version(self) -> str:
        v = self.metadata.get("version")
        return f"{self.metadata.get('name', self.algorithm)}-v{v}" if v else self.algorithm

    @property
    def calibrated(self) -> bool:
        return self.calibrator is not None

    def vector(self, features: dict[str, Any]) -> np.ndarray:
        return np.asarray([model_vector(features, self.feature_keys)], dtype=float)

    def scores(self, X: np.ndarray) -> tuple[np.ndarray, Optional[np.ndarray]]:
        """(raw scores, calibrated probabilities or None) for a feature matrix."""
        raw = raw_attack_scores(self.bundle, X)
        return raw, (self.calibrator(raw) if self.calibrator else None)

    def predict(self, features: dict[str, Any]) -> WindowPrediction:
        X = self.vector(features)
        raw, prob = self.scores(X)
        predicted = share = None
        if self.bundle["kind"] == "supervised":
            estimator = self.bundle["estimator"]
            proba = estimator.predict_proba(X)[0]
            classes = [str(c) for c in estimator.classes_]
            attack = [(p, c) for p, c in zip(proba, classes) if c != BENIGN]
            if attack:
                share, predicted = max(attack)
                share = float(share)
        return WindowPrediction(
            raw_score=float(raw[0]),
            probability=float(prob[0]) if prob is not None else None,
            predicted_class=predicted,
            class_probability=share,
        )
