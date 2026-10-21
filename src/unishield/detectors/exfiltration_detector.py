"""
UniShield — Data Exfiltration Detector

Applies exfiltration rules to the per-pair upload candidates of
ExfiltrationFeatureExtractor (internal source → external destination,
bytes the internal host uploaded on connections it initiated):

    volume     — upload >= ``min_upload_mb`` in the window and upload/download
                 >= ``upload_download_ratio``
    baseline   — the source's window upload is >= ``baseline_deviation_sigma``
                 robust standard deviations above its own history (after
                 ``min_baseline_windows`` windows), at least
                 ``baseline_min_upload_mb``, and upload-dominated
    long session — an outbound session of >= ``long_session_duration_sec`` that
                 uploaded >= ``long_session_min_upload_mb``, upload-dominated

A rare destination (uploaded to by <= ``max_destination_sources`` internal
hosts) raises severity by one level; an unusual destination port is reported
as evidence only. A pair is re-reported after ``realert_after_sec`` of
traffic time or when its severity rises.

Confidence is a rule score, not a calibrated probability.

MITRE ATT&CK: T1041, T1048 (+ T1573 over TLS, T1571 on an unusual port).
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta
from typing import Any

from unishield.config import get_thresholds
from unishield.correlation import severity as sev
from unishield.correlation.mitre_mapping import ENCRYPTED_CHANNEL, NON_STANDARD_PORT, techniques_for
from unishield.detectors.base import BaseDetector
from unishield.schemas.alert import Alert, Severity, ThreatClass
from unishield.schemas.flow import NormalisedFlow

_MB = 1_000_000


class ExfiltrationDetector(BaseDetector):
    """Detect data exfiltration from upload volume, per-source baselines and session length."""

    def __init__(self, thresholds: dict[str, Any] | None = None):
        if thresholds is None:
            thresholds = get_thresholds().get("exfiltration", {})
        super().__init__(thresholds)
        self._last_reported: dict[tuple[str, str], tuple[datetime, Severity]] = {}

    @property
    def name(self) -> str:
        return "exfiltration_detector"

    @property
    def threat_classes(self) -> list[ThreatClass]:
        return [ThreatClass.DATA_EXFILTRATION]

    @property
    def mitre_techniques(self) -> list[str]:
        return techniques_for(ThreatClass.DATA_EXFILTRATION, ENCRYPTED_CHANNEL, NON_STANDARD_PORT)

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
        min_upload = t.get("min_upload_mb", 5) * _MB
        ratio_thr = t.get("upload_download_ratio", 5.0)
        sigma = t.get("baseline_deviation_sigma", 3.5)
        min_windows = t.get("min_baseline_windows", 10)
        baseline_min = t.get("baseline_min_upload_mb", 1) * _MB
        long_sec = t.get("long_session_duration_sec", 3600)
        long_min = t.get("long_session_min_upload_mb", 1) * _MB
        max_sources = t.get("max_destination_sources", 3)
        realert = timedelta(seconds=t.get("realert_after_sec", 600))
        levels = t.get("severity_levels", {})
        alerts: list[Alert] = []

        for c in features.get("exfil_candidates", []):
            upload = c["upload_bytes"]
            upload_dominated = c["upload_download_ratio"] >= ratio_thr
            if not upload_dominated:
                continue

            rules = []
            if upload >= min_upload:
                rules.append("volume")
            z = c["robust_z"]
            if (z is not None and c["baseline_windows"] >= min_windows and z >= sigma
                    and c["source_window_upload"] >= baseline_min):
                rules.append("baseline")
            if c["max_duration_sec"] >= long_sec and c["long_session_upload_bytes"] >= long_min:
                rules.append("long_session")
            if not rules:
                continue

            if "volume" in rules:
                severity = sev.from_levels(upload / _MB, levels, "upload_mb", default=Severity.MEDIUM)
            else:
                severity = Severity.LOW
            rare = c["destination_sources"] <= max_sources
            if rare:
                severity = sev.escalate(severity)

            key = (c["source_ip"], c["destination_ip"])
            previous = self._last_reported.get(key)
            if previous is not None and window_end - previous[0] < realert \
                    and sev.RANK[severity] <= sev.RANK[previous[1]]:
                continue
            self._last_reported[key] = (window_end, severity)

            confidence = 0.4 + 0.1 * len(rules) + (0.15 if rare else 0.0)
            if "volume" in rules:
                confidence += min(0.2, 0.1 * upload / min_upload)
            extra = []
            if c["uses_tls"]:
                extra.append(ENCRYPTED_CHANNEL)
            if c["unusual_port"]:
                extra.append(NON_STANDARD_PORT)

            alerts.append(Alert(
                window_start=window_start,
                window_end=window_end,
                source_ip=c["source_ip"],
                destination_ip=c["destination_ip"],
                threat_class=ThreatClass.DATA_EXFILTRATION,
                severity=severity,
                confidence=round(min(1.0, confidence), 4),
                detector_name=self.name,
                model_version=self.version,
                evidence={
                    "rules": rules,
                    "upload_bytes": upload,
                    "download_bytes": c["download_bytes"],
                    "upload_download_ratio": c["upload_download_ratio"],
                    "destination_ports": c["destination_ports"],
                    "unusual_port": c["unusual_port"],
                    "rare_destination": rare,
                    "destination_sources": c["destination_sources"],
                    "source_window_upload": c["source_window_upload"],
                    "baseline_median_bytes": c["baseline_median_bytes"],
                    "baseline_windows": c["baseline_windows"],
                    "robust_z": z,
                    "max_session_sec": c["max_duration_sec"],
                    "min_upload_mb": min_upload / _MB,
                    "ratio_threshold": ratio_thr,
                },
                mitre_techniques=techniques_for(ThreatClass.DATA_EXFILTRATION, *extra),
                detection_latency_ms=self._measure_latency(start_time),
            ))

        self._alerts_generated += len(alerts)
        return alerts
