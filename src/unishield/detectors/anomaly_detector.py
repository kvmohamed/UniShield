"""
UniShield — Isolation Forest Anomaly Detector

Flags windows whose overall traffic profile is unlike the windows the model
was trained on, to catch activity no rule describes.

DESIGN:
    - Runs after the rule detectors and reports only windows no rule alert
      explained; explained windows are also never used for training.
      Windows with fewer than ``min_window_flows`` flows are skipped.
    - Model source: a saved model (``load_model`` / ``models/saved``), or —
      if none is loaded — online warm-up on the first
      ``min_training_windows`` unexplained windows of the run.
    - Features: ~25 window-level counts and rates, log-scaled (log1p) so
      that a few huge values do not dominate.
    - One ``score_samples`` call per window. The anomaly score is
      ``-score_samples`` (≈0.5 typical, → 1 isolated). An alert needs the
      score to be at least ``min_score`` and above the ``quantile`` of the
      training scores.
    - Confidence is the window's percentile among the training scores — how
      unusual it is relative to the baseline — not a probability of attack.
    - Evidence lists the features furthest from their training medians.

SECURITY CONSTRAINTS:
    - Read-only: no packets sent, no decryption.
"""

from __future__ import annotations

import logging
import math
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import numpy as np

from unishield.config import get_thresholds
from unishield.correlation.mitre_mapping import techniques_for
from unishield.detectors.base import BaseDetector
from unishield.schemas.alert import Alert, Severity, ThreatClass
from unishield.schemas.flow import NormalisedFlow

logger = logging.getLogger("unishield.detectors.anomaly")

ANOMALY_FEATURE_KEYS = [
    "total_packets", "total_bytes", "total_flows",
    "packets_per_second", "bytes_per_second", "flows_per_second",
    "unique_source_ips", "unique_dest_ips", "unique_dest_ports",
    "source_ip_entropy", "dest_ip_entropy", "dest_port_entropy",
    "tcp_ratio", "udp_ratio", "icmp_ratio",
    "syn_count", "syn_ack_ratio", "dest_concentration", "peak_flows_per_second",
    "connection_rate", "failed_connection_ratio", "max_vertical_ports", "max_horizontal_hosts",
    "burst_connections", "total_outbound_bytes", "dns_query_count",
]


def anomaly_vector(features: dict[str, Any], keys: list[str] = ANOMALY_FEATURE_KEYS) -> list[float]:
    """Log-scaled numeric feature vector for the model."""
    values = []
    for key in keys:
        try:
            v = float(features.get(key) or 0.0)
        except (TypeError, ValueError):
            v = 0.0
        values.append(math.log1p(max(v, 0.0)))
    return values


class AnomalyDetector(BaseDetector):
    """Isolation-Forest detector for windows no rule explains."""

    runs_after_rules = True

    def __init__(
        self,
        thresholds: dict[str, Any] | None = None,
        n_estimators: int = 100,
        min_training_windows: int | None = None,
        model_path: Path | str | None = None,
        random_state: int = 42,
        contamination: Any = None,          # accepted for backward compatibility; unused
    ):
        if thresholds is None:
            thresholds = get_thresholds().get("anomaly", {})
        super().__init__(thresholds)
        self._n_estimators = n_estimators
        self._min_training_windows = min_training_windows or thresholds.get("min_training_windows", 30)
        self._random_state = random_state
        self._feature_keys = list(ANOMALY_FEATURE_KEYS)
        self._model = None
        self._train_scores: Optional[np.ndarray] = None
        self._medians: Optional[np.ndarray] = None
        self._scales: Optional[np.ndarray] = None
        self._training: list[list[float]] = []
        self._fit_rows: list[list[float]] = []      # online warm-up windows the model was fitted on
        self._is_fitted = False
        #: Anomaly score of the last window scored (None if not scored); recorded by learning mode.
        self.last_score: Optional[float] = None
        self.model_info: dict[str, Any] = {"source": "online warm-up"}
        if model_path is not None:
            self.load_model(model_path)

    @property
    def name(self) -> str:
        return "anomaly_detector"

    @property
    def threat_classes(self) -> list[ThreatClass]:
        return [ThreatClass.STATISTICAL_ANOMALY]

    @property
    def mitre_techniques(self) -> list[str]:
        return techniques_for(ThreatClass.STATISTICAL_ANOMALY)

    @property
    def is_fitted(self) -> bool:
        return self._is_fitted

    @property
    def version(self) -> str:
        return self.model_info.get("version", f"v1.1.0-IF{self._n_estimators}-online")

    # ------------------------------------------------------------- training

    def fit(self, feature_matrix: list[list[float]]) -> None:
        """Fit on log-scaled feature vectors (one per window)."""
        from sklearn.ensemble import IsolationForest

        X = np.asarray(feature_matrix, dtype=float)
        self._model = IsolationForest(n_estimators=self._n_estimators, contamination="auto",
                                      random_state=self._random_state, n_jobs=1)
        self._model.fit(X)
        self._train_scores = np.sort(-self._model.score_samples(X))
        self._medians = np.median(X, axis=0)
        mad = np.median(np.abs(X - self._medians), axis=0)
        self._scales = np.maximum(1.4826 * mad, 0.1)
        self._is_fitted = True
        logger.info("Anomaly detector fitted on %d windows", len(X))

    def save_model(self, path: Path | str, extra: dict[str, Any] | None = None) -> None:
        """Save the fitted model with its score distribution and feature statistics."""
        import joblib

        if not self._is_fitted:
            raise RuntimeError("model is not fitted")
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({
            "model": self._model,
            "train_scores": self._train_scores,
            "medians": self._medians,
            "scales": self._scales,
            "feature_keys": self._feature_keys,
            "info": {"trained_at": datetime.now(timezone.utc).isoformat(),
                     "n_training": int(len(self._train_scores)), **(extra or {})},
        }, str(path))
        logger.info("Anomaly model saved to %s", path)

    def load_model(self, path: Path | str) -> None:
        import joblib

        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Model file not found: {path}")
        bundle = joblib.load(str(path))
        if bundle.get("feature_keys") != self._feature_keys:
            raise ValueError(f"Model {path} was trained on different features")
        self._model = bundle["model"]
        self._train_scores = bundle["train_scores"]
        self._medians, self._scales = bundle["medians"], bundle["scales"]
        self._is_fitted = True
        self.model_info = {"source": str(path), **bundle.get("info", {})}
        logger.info("Anomaly model loaded from %s", path)

    # ---------------------------------------------------------- persistence

    @property
    def online(self) -> bool:
        """True unless a saved model was loaded."""
        return self.model_info.get("source") == "online warm-up"

    def state_dict(self) -> dict[str, Any]:
        """
        Online model: its warm-up windows (fitted or still collecting). Refitting
        on the same windows with the same random_state rebuilds the same
        forest, so no model object is serialised. A saved model is referenced
        by path only; it is loaded from its file as at start-up.
        """
        if not self.online:
            return {"mode": "saved_model", "source": self.model_info.get("source")}
        return {
            "mode": "online",
            "feature_keys": self._feature_keys,
            "n_estimators": self._n_estimators,
            "random_state": self._random_state,
            "fitted": self._is_fitted,
            "rows": self._fit_rows if self._is_fitted else self._training,
        }

    def load_state_dict(self, state: dict[str, Any]) -> None:
        if state["mode"] != "online" or not self.online:
            return                          # saved models are loaded from their files, not from snapshots
        if state["feature_keys"] != self._feature_keys:
            raise ValueError("snapshot was taken with different anomaly features")
        rows = [[float(v) for v in row] for row in state["rows"]]
        self._n_estimators, self._random_state = int(state["n_estimators"]), int(state["random_state"])
        if state["fitted"]:
            self.fit(rows)
            self._fit_rows, self._training = rows, []
        else:
            self._training = rows

    # ------------------------------------------------------------ detection

    def score(self, vector: list[float]) -> tuple[float, float]:
        """(anomaly score, percentile among training scores) for one window."""
        s = float(-self._model.score_samples(np.asarray([vector], dtype=float))[0])
        percentile = float(np.searchsorted(self._train_scores, s, side="right") / len(self._train_scores))
        return s, percentile

    def detect(
        self,
        flows: list[NormalisedFlow],
        features: dict[str, Any],
        window_start: Any,
        window_end: Any,
    ) -> list[Alert]:
        start_time = time.time()
        self._windows_analysed += 1
        self.last_score = None
        if not flows or not features or features.get("rule_alert_classes"):
            return []
        if len(flows) < self._thresholds.get("min_window_flows", 10):
            return []          # too few flows for a meaningful traffic profile

        vec = anomaly_vector(features, self._feature_keys)
        if not self._is_fitted:
            self._training.append(vec)
            if len(self._training) >= self._min_training_windows:
                self.fit(self._training)
                self._fit_rows, self._training = self._training, []
            return []

        quantile = self._thresholds.get("quantile", 0.995)
        min_score = self._thresholds.get("min_score", 0.6)
        s, percentile = self.score(vec)
        self.last_score = s
        if percentile < quantile or s < min_score:
            return []

        deviation = (np.asarray(vec) - self._medians) / self._scales
        top = np.argsort(-np.abs(deviation))[:3]
        alert = Alert(
            window_start=window_start,
            window_end=window_end,
            threat_class=ThreatClass.STATISTICAL_ANOMALY,
            severity=Severity.MEDIUM if s >= self._thresholds.get("medium_score", 0.7) else Severity.LOW,
            confidence=round(percentile, 4),
            detector_name=self.name,
            model_version=self.version,
            evidence={
                "anomaly_score": round(s, 4),
                "training_percentile": round(percentile, 4),
                "min_score": min_score,
                "quantile": quantile,
                "training_windows": int(len(self._train_scores)),
                "model_source": self.model_info.get("source"),
                "most_unusual_features": {
                    self._feature_keys[i]: {"value": features.get(self._feature_keys[i]),
                                            "deviation": round(float(deviation[i]), 2)}
                    for i in top
                },
            },
            mitre_techniques=techniques_for(ThreatClass.STATISTICAL_ANOMALY),
            detection_latency_ms=self._measure_latency(start_time),
        )
        self._alerts_generated += 1
        return [alert]
