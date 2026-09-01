"""
UniShield — Data Exfiltration Detector

Detects data exfiltration patterns:
    - Abnormally high outbound/inbound byte ratios
    - Large sustained outbound transfers
    - Traffic to unusual ports
    - Long-duration sessions with high byte counts

Uses features from the ExfiltrationFeatureExtractor.

MITRE ATT&CK:
    - T1041: Exfiltration Over C2 Channel
    - T1048: Exfiltration Over Alternative Protocol
"""

from __future__ import annotations

import time
from typing import Any

from unishield.config import get_thresholds
from unishield.detectors.base import BaseDetector
from unishield.schemas.alert import Alert, Severity, ThreatClass
from unishield.schemas.flow import NormalisedFlow


class ExfiltrationDetector(BaseDetector):
    """
    Detect data exfiltration based on volume asymmetry and session patterns.
    """

    def __init__(self, thresholds: dict[str, Any] | None = None):
        if thresholds is None:
            all_thresholds = get_thresholds()
            thresholds = all_thresholds.get("exfiltration", {})
        super().__init__(thresholds)

    @property
    def name(self) -> str:
        return "exfiltration_detector"

    @property
    def threat_classes(self) -> list[ThreatClass]:
        return [ThreatClass.DATA_EXFILTRATION]

    @property
    def mitre_techniques(self) -> list[str]:
        return ["T1041", "T1048"]

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

        # --- Outbound/Inbound Ratio Check ---
        ob_ratio = features.get("outbound_inbound_ratio", 0)
        ratio_threshold = t.get("outbound_inbound_byte_ratio", 5.0)
        outbound_bytes = features.get("total_outbound_bytes", 0)

        if ob_ratio > ratio_threshold and outbound_bytes > 1_000_000:  # > 1 MB
            severity = self._determine_severity(
                ob_ratio, severity_levels, "outbound_inbound_byte_ratio"
            )

            confidence = min(1.0, ob_ratio / ratio_threshold * 0.4)

            alert = Alert(
                window_start=window_start,
                window_end=window_end,
                destination_ip=features.get("top_dest_ip"),
                threat_class=ThreatClass.DATA_EXFILTRATION,
                severity=severity,
                confidence=round(confidence, 4),
                detector_name=self.name,
                model_version=self.version,
                evidence={
                    "outbound_inbound_ratio": ob_ratio,
                    "ratio_threshold": ratio_threshold,
                    "total_outbound_bytes": outbound_bytes,
                    "total_inbound_bytes": features.get("total_inbound_bytes", 0),
                    "top_dest_ip": features.get("top_dest_ip"),
                    "top_dest_bytes": features.get("top_dest_bytes", 0),
                },
                mitre_techniques=["T1041"],
                detection_latency_ms=self._measure_latency(start_time),
            )
            alerts.append(alert)

        # --- High-Volume Transfer to Single Destination ---
        top_dest_bytes = features.get("top_dest_bytes", 0)
        volume_threshold_bytes = t.get("unusual_outbound_volume_mb", 100) * 1_000_000

        if top_dest_bytes > volume_threshold_bytes:
            severity = self._determine_severity(
                top_dest_bytes / 1_000_000,
                severity_levels,
                "unusual_outbound_volume_mb",
            )

            alert = Alert(
                window_start=window_start,
                window_end=window_end,
                destination_ip=features.get("top_dest_ip"),
                threat_class=ThreatClass.DATA_EXFILTRATION,
                severity=severity,
                confidence=min(1.0, top_dest_bytes / volume_threshold_bytes * 0.5),
                detector_name=self.name,
                model_version=self.version,
                evidence={
                    "top_dest_bytes": top_dest_bytes,
                    "volume_threshold_bytes": volume_threshold_bytes,
                    "top_dest_ip": features.get("top_dest_ip"),
                    "avg_bytes_per_dest": features.get("avg_bytes_per_dest", 0),
                },
                mitre_techniques=["T1048"],
                detection_latency_ms=self._measure_latency(start_time),
            )
            alerts.append(alert)

        # --- Unusual Port Usage ---
        port_rarity = features.get("dest_port_rarity", 0)
        unusual_flows = features.get("unusual_port_flows", 0)
        rarity_threshold = t.get("port_rarity_threshold", 0.95)

        if port_rarity > rarity_threshold and unusual_flows > 5:
            alert = Alert(
                window_start=window_start,
                window_end=window_end,
                threat_class=ThreatClass.DATA_EXFILTRATION,
                severity=Severity.MEDIUM,
                confidence=min(1.0, port_rarity * 0.6),
                detector_name=self.name,
                model_version=self.version,
                evidence={
                    "dest_port_rarity": port_rarity,
                    "rarity_threshold": rarity_threshold,
                    "unusual_port_flows": unusual_flows,
                    "note": "High ratio of traffic on uncommon ports",
                },
                mitre_techniques=["T1048"],
                detection_latency_ms=self._measure_latency(start_time),
            )
            alerts.append(alert)

        # --- Long-Duration Sessions ---
        max_duration = features.get("max_session_duration_sec", 0)
        long_sessions = features.get("long_sessions_count", 0)
        duration_threshold = t.get("long_session_duration_sec", 3600)

        if max_duration > duration_threshold and long_sessions > 0:
            alert = Alert(
                window_start=window_start,
                window_end=window_end,
                threat_class=ThreatClass.DATA_EXFILTRATION,
                severity=Severity.LOW,
                confidence=min(1.0, max_duration / duration_threshold * 0.3),
                detector_name=self.name,
                model_version=self.version,
                evidence={
                    "max_session_duration_sec": max_duration,
                    "duration_threshold": duration_threshold,
                    "long_sessions_count": long_sessions,
                    "max_session_bytes": features.get("max_session_bytes", 0),
                },
                mitre_techniques=["T1041"],
                detection_latency_ms=self._measure_latency(start_time),
            )
            alerts.append(alert)

        self._alerts_generated += len(alerts)
        return alerts
