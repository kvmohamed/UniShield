"""
UniShield — DDoS / Flood Detector

Detects volumetric DDoS attacks and protocol-level floods:
    - Volumetric: high packet/byte rates
    - SYN flood: high SYN rate with SYN/ACK imbalance
    - UDP flood: high UDP packet rate
    - Destination concentration: traffic focused on single target

Uses features from the VolumeFeatureExtractor.

MITRE ATT&CK:
    - T1498: Network Denial of Service
    - T1498.001: Direct Network Flood
"""

from __future__ import annotations

import time
from datetime import datetime
from typing import Any

from unishield.config import get_thresholds
from unishield.detectors.base import BaseDetector
from unishield.schemas.alert import Alert, Severity, ThreatClass
from unishield.schemas.flow import NormalisedFlow


class DDoSDetector(BaseDetector):
    """
    Detect DDoS/flood attacks based on volume and rate features.
    """

    def __init__(self, thresholds: dict[str, Any] | None = None):
        if thresholds is None:
            all_thresholds = get_thresholds()
            thresholds = all_thresholds.get("ddos", {})
        super().__init__(thresholds)

    @property
    def name(self) -> str:
        return "ddos_detector"

    @property
    def threat_classes(self) -> list[ThreatClass]:
        return [
            ThreatClass.DDOS_VOLUMETRIC,
            ThreatClass.DDOS_PROTOCOL,
            ThreatClass.SYN_FLOOD,
            ThreatClass.UDP_FLOOD,
        ]

    @property
    def mitre_techniques(self) -> list[str]:
        return ["T1498", "T1498.001"]

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

        # --- Volumetric DDoS ---
        pps = features.get("packets_per_second", 0)
        bps = features.get("bytes_per_second", 0)
        pps_threshold = t.get("packets_per_second", 10000)
        bps_threshold = t.get("bytes_per_second", 50_000_000)

        if pps > pps_threshold or bps > bps_threshold:
            severity = self._determine_severity(
                pps, severity_levels, "packets_per_second"
            )
            alert = Alert(
                window_start=window_start,
                window_end=window_end,
                threat_class=ThreatClass.DDOS_VOLUMETRIC,
                severity=severity,
                confidence=min(1.0, max(pps / pps_threshold, bps / bps_threshold) * 0.5),
                detector_name=self.name,
                model_version=self.version,
                evidence={
                    "packets_per_second": pps,
                    "bytes_per_second": bps,
                    "pps_threshold": pps_threshold,
                    "bps_threshold": bps_threshold,
                    "total_packets": features.get("total_packets", 0),
                    "total_bytes": features.get("total_bytes", 0),
                    "unique_source_ips": features.get("unique_source_ips", 0),
                    "source_ip_entropy": features.get("source_ip_entropy", 0),
                    "dest_concentration": features.get("dest_concentration", 0),
                },
                mitre_techniques=["T1498", "T1498.001"],
                detection_latency_ms=self._measure_latency(start_time),
            )
            alerts.append(alert)

        # --- SYN Flood ---
        syn_count = features.get("syn_count", 0)
        syn_ack_ratio = features.get("syn_ack_ratio", 0)
        syn_threshold = t.get("syn_rate_threshold", 5000)
        ratio_threshold = t.get("syn_ack_imbalance_ratio", 5.0)

        if syn_count > syn_threshold and syn_ack_ratio > ratio_threshold:
            severity = self._determine_severity(
                syn_count, severity_levels, "packets_per_second"
            )
            # Bump to at least HIGH for SYN floods
            if severity == Severity.LOW or severity == Severity.MEDIUM:
                severity = Severity.HIGH

            alert = Alert(
                window_start=window_start,
                window_end=window_end,
                threat_class=ThreatClass.SYN_FLOOD,
                severity=severity,
                confidence=min(1.0, (syn_ack_ratio / ratio_threshold) * 0.6),
                detector_name=self.name,
                model_version=self.version,
                evidence={
                    "syn_count": syn_count,
                    "syn_ack_count": features.get("syn_ack_count", 0),
                    "syn_ack_ratio": syn_ack_ratio,
                    "syn_threshold": syn_threshold,
                    "ratio_threshold": ratio_threshold,
                },
                mitre_techniques=["T1498", "T1498.001"],
                detection_latency_ms=self._measure_latency(start_time),
            )
            alerts.append(alert)

        # --- UDP Flood ---
        udp_ratio = features.get("udp_ratio", 0)
        udp_flood_pps = t.get("udp_flood_pps", 8000)

        if udp_ratio > 0.7 and pps > udp_flood_pps:
            alert = Alert(
                window_start=window_start,
                window_end=window_end,
                threat_class=ThreatClass.UDP_FLOOD,
                severity=Severity.HIGH,
                confidence=min(1.0, udp_ratio * 0.8),
                detector_name=self.name,
                model_version=self.version,
                evidence={
                    "udp_ratio": udp_ratio,
                    "packets_per_second": pps,
                    "udp_flood_pps_threshold": udp_flood_pps,
                },
                mitre_techniques=["T1498", "T1498.001"],
                detection_latency_ms=self._measure_latency(start_time),
            )
            alerts.append(alert)

        self._alerts_generated += len(alerts)
        return alerts
