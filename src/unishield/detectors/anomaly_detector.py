"""
UniShield — Isolation Forest Anomaly Detector

Uses scikit-learn's Isolation Forest to detect statistical anomalies
in network traffic that don't match known rule-based patterns.

DESIGN:
    - Online learning: the model is fit on an initial baseline of
      normal-looking windows, then used to score new windows.
    - Feature vector is constructed from volume, scan, and statistical
      feature extractors.
    - Anomaly scores are mapped to confidence values in [0, 1].

SECURITY CONSTRAINTS:
    - Read-only: no packets sent, no decryption.
    - Model operates only on extracted feature vectors.

MITRE ATT&CK:
    - T1071: Application Layer Protocol (generic anomaly)
"""

from __future__ import annotations

import logging
import time
import json
from pathlib import Path
from typing import Any, Optional

import numpy as np

from unishield.config import get_thresholds
from unishield.detectors.base import BaseDetector
from unishield.schemas.alert import Alert, Severity, ThreatClass
from unishield.schemas.flow import NormalisedFlow

logger = logging.getLogger("unishield.detectors.anomaly")

# Feature keys used to build the feature vector for the model
_FEATURE_KEYS = [
    "total_packets",
    "total_bytes",
    "total_flows",
    "packets_per_second",
    "bytes_per_second",
    "flows_per_second",
    "unique_source_ips",
    "unique_dest_ips",
    "unique_dest_ports",
    "source_ip_entropy",
    "dest_ip_entropy",
    "tcp_ratio",
    "udp_ratio",
    "syn_count",
    "syn_ack_ratio",
    "dest_concentration",
    "connection_rate",
    "failed_connection_ratio",
    "fanout_score",
    "max_vertical_ports",
    "max_horizontal_hosts",
    "burst_connections",
]


class AnomalyDetector(BaseDetector):
    """
    Isolation-Forest-based anomaly detector.

    The model learns "normal" traffic patterns from an initial set
    of windows and then flags windows whose feature vector is
    anomalous. This catches novel attacks not covered by rule-based
    detectors.
    """

    def __init__(
        self,
        thresholds: dict[str, Any] | None = None,
        contamination: float = 0.05,
        n_estimators: int = 100,
        min_training_windows: int = 10,
    ):
        if thresholds is None:
            all_thresholds = get_thresholds()
            thresholds = all_thresholds.get("statistical", {})
        super().__init__(thresholds)

        self._contamination = contamination
        self._n_estimators = n_estimators
        self._min_training_windows = min_training_windows
        self._model = None  # Lazy import to avoid slow startup
        self._is_fitted = False
        self._training_data: list[list[float]] = []
        self._feature_keys = _FEATURE_KEYS

    @property
    def name(self) -> str:
        return "anomaly_detector"

    @property
    def threat_classes(self) -> list[ThreatClass]:
        return [ThreatClass.STATISTICAL_ANOMALY]

    @property
    def mitre_techniques(self) -> list[str]:
        return ["T1071"]

    @property
    def is_fitted(self) -> bool:
        return self._is_fitted

    def _build_feature_vector(self, features: dict[str, Any]) -> list[float]:
        """Extract numeric values in a fixed order for the model."""
        return [float(features.get(k, 0)) for k in self._feature_keys]

    def _ensure_model(self) -> None:
        """Lazy-init the Isolation Forest model."""
        if self._model is None:
            from sklearn.ensemble import IsolationForest
            self._model = IsolationForest(
                n_estimators=self._n_estimators,
                contamination=self._contamination,
                random_state=42,
                n_jobs=1,
            )

    def fit(self, feature_matrix: list[list[float]]) -> None:
        """
        Fit the model on a baseline of feature vectors.

        Args:
            feature_matrix: List of feature vectors (one per window).
        """
        self._ensure_model()
        X = np.array(feature_matrix)
        self._model.fit(X)
        self._is_fitted = True
        logger.info("Anomaly detector fitted on %d windows", len(feature_matrix))

    def detect(
        self,
        flows: list[NormalisedFlow],
        features: dict[str, Any],
        window_start: Any,
        window_end: Any,
    ) -> list[Alert]:
        start_time = time.time()
        self._windows_analysed += 1
        alerts: list[Alert] = []

        if not flows or not features:
            return alerts

        vec = self._build_feature_vector(features)

        # Phase 1: Collect training data
        if not self._is_fitted:
            self._training_data.append(vec)
            if len(self._training_data) >= self._min_training_windows:
                self.fit(self._training_data)
                self._training_data.clear()
            return alerts

        # Phase 2: Score the window
        self._ensure_model()
        X = np.array([vec])
        prediction = self._model.predict(X)[0]        # -1 = anomaly, 1 = normal
        raw_score = self._model.decision_function(X)[0]  # More negative = more anomalous

        if prediction == -1:
            # Convert raw score to confidence in [0, 1]
            # decision_function returns negative for anomalies; more negative = stronger
            z_threshold = self._thresholds.get("z_score_threshold", 3.0)
            confidence = min(1.0, max(0.0, -raw_score / z_threshold))

            # Determine severity
            if confidence >= 0.8:
                severity = Severity.HIGH
            elif confidence >= 0.5:
                severity = Severity.MEDIUM
            else:
                severity = Severity.LOW

            # Build evidence with top anomalous features
            evidence = {
                "anomaly_score": round(float(raw_score), 4),
                "confidence": round(confidence, 4),
                "prediction": int(prediction),
                "model_type": "IsolationForest",
                "n_estimators": self._n_estimators,
                "contamination": self._contamination,
            }

            # Add the most extreme feature values
            for key in self._feature_keys[:8]:
                evidence[f"feat_{key}"] = features.get(key, 0)

            alert = Alert(
                window_start=window_start,
                window_end=window_end,
                threat_class=ThreatClass.STATISTICAL_ANOMALY,
                severity=severity,
                confidence=round(confidence, 4),
                detector_name=self.name,
                model_version=f"v1.0.0-IF{self._n_estimators}",
                evidence=evidence,
                mitre_techniques=["T1071"],
                detection_latency_ms=self._measure_latency(start_time),
            )
            alerts.append(alert)
            self._alerts_generated += 1

        return alerts

    def save_model(self, path: Path | str) -> None:
        """Save the fitted model to disk."""
        import joblib
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        if self._is_fitted and self._model is not None:
            joblib.dump(self._model, str(path))
            logger.info("Model saved to %s", path)

    def load_model(self, path: Path | str) -> None:
        """Load a previously fitted model from disk."""
        import joblib
        path = Path(path)
        if path.exists():
            self._model = joblib.load(str(path))
            self._is_fitted = True
            logger.info("Model loaded from %s", path)
        else:
            raise FileNotFoundError(f"Model file not found: {path}")
