"""
UniShield — Port/Host Scan Detector

Detects network reconnaissance via port scanning and host sweeping:
    - Port scan: single source probing many ports on one or more targets
    - Host scan: single source probing same port across many hosts
    - Burst scanning: rapid connection attempts in short intervals

Uses features from the ScanFeatureExtractor.

MITRE ATT&CK:
    - T1046: Network Service Scanning
    - T1595: Active Scanning (detected passively via observed patterns)
"""

from __future__ import annotations

import time
from datetime import datetime
from typing import Any

from unishield.config import get_thresholds
from unishield.detectors.base import BaseDetector
from unishield.schemas.alert import Alert, Severity, ThreatClass
from unishield.schemas.flow import NormalisedFlow


class ScanDetector(BaseDetector):
    """
    Detect port scanning and host scanning activity.
    """

    def __init__(self, thresholds: dict[str, Any] | None = None):
        if thresholds is None:
            all_thresholds = get_thresholds()
            thresholds = all_thresholds.get("scanning", {})
        super().__init__(thresholds)

    @property
    def name(self) -> str:
        return "scan_detector"

    @property
    def threat_classes(self) -> list[ThreatClass]:
        return [
            ThreatClass.PORT_SCAN,
            ThreatClass.HOST_SCAN,
            ThreatClass.RECONNAISSANCE,
        ]

    @property
    def mitre_techniques(self) -> list[str]:
        return ["T1046"]

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

        # --- Port Scan Detection ---
        top_port_count = features.get("top_scanner_port_count", 0)
        port_threshold = t.get("unique_dest_ports", 25)
        failed_ratio = features.get("failed_connection_ratio", 0)
        failed_threshold = t.get("failed_connection_ratio", 0.7)
        fanout = features.get("fanout_score", 0)
        fanout_threshold = t.get("fanout_score", 0.8)

        if top_port_count >= port_threshold:
            severity = self._determine_severity(
                top_port_count, severity_levels, "unique_dest_ports"
            )

            # Boost confidence if failure ratio is high
            base_conf = min(1.0, top_port_count / port_threshold * 0.5)
            if failed_ratio > failed_threshold:
                base_conf = min(1.0, base_conf + 0.2)

            alert = Alert(
                window_start=window_start,
                window_end=window_end,
                source_ip=features.get("top_scanner_ip"),
                threat_class=ThreatClass.PORT_SCAN,
                severity=severity,
                confidence=round(base_conf, 4),
                detector_name=self.name,
                model_version=self.version,
                evidence={
                    "unique_dest_ports": top_port_count,
                    "port_threshold": port_threshold,
                    "failed_connection_ratio": failed_ratio,
                    "fanout_score": fanout,
                    "connection_rate": features.get("connection_rate", 0),
                    "max_vertical_ports": features.get("max_vertical_ports", 0),
                    "scanner_source_ip": features.get("top_scanner_ip"),
                },
                mitre_techniques=["T1046"],
                detection_latency_ms=self._measure_latency(start_time),
            )
            alerts.append(alert)

        # --- Host Scan Detection ---
        top_host_count = features.get("top_scanner_host_count", 0)
        host_threshold = t.get("unique_dest_hosts", 10)
        max_horizontal = features.get("max_horizontal_hosts", 0)
        horiz_threshold = t.get("horizontal_scan_hosts", 20)

        if top_host_count >= host_threshold or max_horizontal >= horiz_threshold:
            severity = self._determine_severity(
                max(top_host_count, max_horizontal),
                severity_levels,
                "unique_dest_hosts",
            )

            alert = Alert(
                window_start=window_start,
                window_end=window_end,
                source_ip=features.get("top_scanner_ip"),
                threat_class=ThreatClass.HOST_SCAN,
                severity=severity,
                confidence=min(1.0, max(
                    top_host_count / host_threshold,
                    max_horizontal / horiz_threshold,
                ) * 0.5),
                detector_name=self.name,
                model_version=self.version,
                evidence={
                    "unique_dest_hosts": top_host_count,
                    "host_threshold": host_threshold,
                    "max_horizontal_hosts": max_horizontal,
                    "horiz_threshold": horiz_threshold,
                    "scanner_source_ip": features.get("top_scanner_ip"),
                },
                mitre_techniques=["T1046"],
                detection_latency_ms=self._measure_latency(start_time),
            )
            alerts.append(alert)

        # --- Burst Scan Detection ---
        burst = features.get("burst_connections", 0)
        burst_threshold = t.get("burst_connections", 30)

        if burst >= burst_threshold and (top_port_count >= port_threshold // 2 or top_host_count >= host_threshold // 2):
            alert = Alert(
                window_start=window_start,
                window_end=window_end,
                source_ip=features.get("top_scanner_ip"),
                threat_class=ThreatClass.RECONNAISSANCE,
                severity=Severity.MEDIUM,
                confidence=min(1.0, burst / burst_threshold * 0.5),
                detector_name=self.name,
                model_version=self.version,
                evidence={
                    "burst_connections": burst,
                    "burst_threshold": burst_threshold,
                    "unique_ports": top_port_count,
                    "unique_hosts": top_host_count,
                },
                mitre_techniques=["T1046"],
                detection_latency_ms=self._measure_latency(start_time),
            )
            alerts.append(alert)

        self._alerts_generated += len(alerts)
        return alerts
