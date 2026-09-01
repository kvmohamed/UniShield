"""
UniShield — C2 Beaconing Detector

Detects command-and-control beaconing via periodic communication patterns:
    - Regular inter-arrival intervals (low coefficient of variation)
    - Consistent packet sizes
    - Sustained connections to same destination

Uses features from the BeaconingFeatureExtractor.

MITRE ATT&CK:
    - T1071: Application Layer Protocol
    - T1573: Encrypted Channel
    - T1095: Non-Application Layer Protocol
"""

from __future__ import annotations

import time
from typing import Any

from unishield.config import get_thresholds
from unishield.detectors.base import BaseDetector
from unishield.schemas.alert import Alert, Severity, ThreatClass
from unishield.schemas.flow import NormalisedFlow


class BeaconingDetector(BaseDetector):
    """
    Detect C2 beaconing patterns based on timing regularity.
    """

    def __init__(self, thresholds: dict[str, Any] | None = None):
        if thresholds is None:
            all_thresholds = get_thresholds()
            thresholds = all_thresholds.get("beaconing", {})
        super().__init__(thresholds)

    @property
    def name(self) -> str:
        return "beaconing_detector"

    @property
    def threat_classes(self) -> list[ThreatClass]:
        return [ThreatClass.C2_BEACONING]

    @property
    def mitre_techniques(self) -> list[str]:
        return ["T1071", "T1573"]

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

        t = self._thresholds
        severity_levels = t.get("severity_levels", {})

        candidates = features.get("candidate_beacon_pairs", 0)
        if candidates == 0:
            return alerts

        # Top beacon metrics
        cv = features.get("top_beacon_interval_cv", float("inf"))
        periodicity = features.get("top_beacon_periodicity_score", 0)
        size_reg = features.get("top_beacon_size_regularity", 0)
        conn_count = features.get("top_beacon_connection_count", 0)

        cv_threshold = t.get("regularity_cv_threshold", 0.3)
        periodicity_threshold = t.get("periodicity_score", 0.7)
        size_threshold = t.get("packet_size_regularity", 0.8)
        min_connections = t.get("min_connections", 10)

        # Detection logic: low CV + high periodicity + enough connections
        is_beacon = (
            cv <= cv_threshold
            and periodicity >= periodicity_threshold
            and conn_count >= min_connections
        )

        if is_beacon:
            severity = self._determine_severity(
                cv_threshold - cv,  # How much below threshold (inverted)
                severity_levels,
                "regularity_cv_threshold",
            )
            # For beaconing, use inverted comparison
            if cv <= 0.1:
                severity = Severity.CRITICAL
            elif cv <= 0.2:
                severity = Severity.HIGH
            else:
                severity = Severity.MEDIUM

            # Confidence from multiple signals
            cv_score = max(0, 1.0 - cv / cv_threshold)
            period_score = periodicity / max(periodicity_threshold, 0.01)
            size_score = size_reg
            confidence = min(1.0, (cv_score * 0.5 + period_score * 0.3 + size_score * 0.2))

            alert = Alert(
                window_start=window_start,
                window_end=window_end,
                source_ip=features.get("top_beacon_src_ip"),
                destination_ip=features.get("top_beacon_dst_ip"),
                threat_class=ThreatClass.C2_BEACONING,
                severity=severity,
                confidence=round(confidence, 4),
                detector_name=self.name,
                model_version=self.version,
                evidence={
                    "interval_cv": cv,
                    "cv_threshold": cv_threshold,
                    "periodicity_score": periodicity,
                    "periodicity_threshold": periodicity_threshold,
                    "size_regularity": size_reg,
                    "connection_count": conn_count,
                    "interval_mean_sec": features.get("top_beacon_interval_mean", 0),
                    "interval_std_sec": features.get("top_beacon_interval_std", 0),
                    "candidate_pairs": candidates,
                },
                mitre_techniques=["T1071", "T1573"],
                detection_latency_ms=self._measure_latency(start_time),
            )
            alerts.append(alert)

        # Also check for less confident candidates
        elif cv <= cv_threshold * 1.5 and periodicity >= periodicity_threshold * 0.7:
            alert = Alert(
                window_start=window_start,
                window_end=window_end,
                source_ip=features.get("top_beacon_src_ip"),
                destination_ip=features.get("top_beacon_dst_ip"),
                threat_class=ThreatClass.C2_BEACONING,
                severity=Severity.LOW,
                confidence=round(min(1.0, periodicity * 0.4), 4),
                detector_name=self.name,
                model_version=self.version,
                evidence={
                    "interval_cv": cv,
                    "periodicity_score": periodicity,
                    "connection_count": conn_count,
                    "note": "Below primary threshold; possible beacon candidate",
                },
                mitre_techniques=["T1071"],
                detection_latency_ms=self._measure_latency(start_time),
            )
            alerts.append(alert)

        self._alerts_generated += len(alerts)
        return alerts
