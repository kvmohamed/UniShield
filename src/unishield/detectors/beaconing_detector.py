"""
UniShield — C2 Beaconing Detector

Applies beaconing rules to the candidates of BeaconingFeatureExtractor,
which profiles each (source, destination, port) over a rolling history:

    C2_BEACONING when
      - at least ``min_connections`` connections,
      - mean interval between ``min_interval_sec`` and ``max_interval_sec``
        (sub-second machine traffic such as scans, floods or page loads is
        excluded),
      - regular timing: CV <= ``regularity_cv_threshold`` and periodicity
        >= ``periodicity_score``,
      - a rare destination: contacted by at most ``max_destination_sources``
        internal hosts (popular services polled by many hosts are excluded).

Severity: HIGH for very regular beacons (CV <= 0.1 and periodicity >= 0.9),
MEDIUM for CV <= 0.2, otherwise LOW. Regular timing alone does not prove
command-and-control (update checkers and monitoring agents also poll), so
severity stops at HIGH. A pair is re-reported only after
``realert_after_sec`` of traffic time or when its severity rises.

Confidence is a rule score, not a calibrated probability.

MITRE ATT&CK: T1071, plus T1573 when the pair used TLS.
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta
from typing import Any

from unishield.config import get_thresholds
from unishield.correlation.mitre_mapping import ENCRYPTED_CHANNEL, techniques_for
from unishield.correlation.severity import RANK
from unishield.detectors.base import BaseDetector
from unishield.schemas.alert import Alert, Severity, ThreatClass
from unishield.schemas.flow import NormalisedFlow


class BeaconingDetector(BaseDetector):
    """Detect C2 beaconing from long-horizon timing regularity."""

    def __init__(self, thresholds: dict[str, Any] | None = None):
        if thresholds is None:
            thresholds = get_thresholds().get("beaconing", {})
        super().__init__(thresholds)
        self._last_reported: dict[tuple, tuple[datetime, Severity]] = {}

    @property
    def name(self) -> str:
        return "beaconing_detector"

    @property
    def threat_classes(self) -> list[ThreatClass]:
        return [ThreatClass.C2_BEACONING]

    @property
    def mitre_techniques(self) -> list[str]:
        return techniques_for(ThreatClass.C2_BEACONING, ENCRYPTED_CHANNEL)

    def detect(
        self,
        flows: list[NormalisedFlow],
        features: dict[str, Any],
        window_start: Any,
        window_end: Any,
    ) -> list[Alert]:
        start_time = time.time()
        self._windows_analysed += 1
        if not flows or not features:
            return []

        t = self._thresholds
        min_conn = t.get("min_connections", 10)
        min_interval = t.get("min_interval_sec", 5)
        max_interval = t.get("max_interval_sec", 3600)
        cv_thr = t.get("regularity_cv_threshold", 0.3)
        periodicity_thr = t.get("periodicity_score", 0.7)
        max_sources = t.get("max_destination_sources", 3)
        realert = timedelta(seconds=t.get("realert_after_sec", 900))
        alerts: list[Alert] = []

        for c in features.get("beacon_candidates", []):
            if not (
                c["connection_count"] >= min_conn
                and min_interval <= c["interval_mean_sec"] <= max_interval
                and c["interval_cv"] <= cv_thr
                and c["periodicity"] >= periodicity_thr
                and c["destination_sources"] <= max_sources
            ):
                continue

            cv = c["interval_cv"]
            if cv <= 0.1 and c["periodicity"] >= 0.9:
                severity = Severity.HIGH
            elif cv <= 0.2:
                severity = Severity.MEDIUM
            else:
                severity = Severity.LOW

            key = (c["source_ip"], c["destination_ip"], c["destination_port"])
            previous = self._last_reported.get(key)
            if previous is not None and window_end - previous[0] < realert \
                    and RANK[severity] <= RANK[previous[1]]:
                continue
            self._last_reported[key] = (window_end, severity)

            confidence = (0.5 * max(0.0, 1.0 - cv / cv_thr) + 0.3 * c["periodicity"]
                          + 0.2 * c["size_regularity"])
            extra = (ENCRYPTED_CHANNEL,) if c["uses_tls"] else ()
            alerts.append(Alert(
                window_start=window_start,
                window_end=window_end,
                source_ip=c["source_ip"],
                destination_ip=c["destination_ip"],
                threat_class=ThreatClass.C2_BEACONING,
                severity=severity,
                confidence=round(min(1.0, confidence), 4),
                detector_name=self.name,
                model_version=self.version,
                evidence={
                    "destination_port": c["destination_port"],
                    "connection_count": c["connection_count"],
                    "interval_mean_sec": round(c["interval_mean_sec"], 3),
                    "interval_std_sec": round(c["interval_std_sec"], 3),
                    "interval_cv": round(cv, 4),
                    "periodicity": round(c["periodicity"], 4),
                    "size_regularity": round(c["size_regularity"], 4),
                    "observed_span_sec": round(c["span_sec"], 1),
                    "destination_sources": c["destination_sources"],
                    "uses_tls": c["uses_tls"],
                    "cv_threshold": cv_thr,
                    "periodicity_threshold": periodicity_thr,
                },
                mitre_techniques=techniques_for(ThreatClass.C2_BEACONING, *extra),
                detection_latency_ms=self._measure_latency(start_time),
            ))

        self._alerts_generated += len(alerts)
        return alerts
