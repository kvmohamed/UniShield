"""
UniShield — Port/Host Scan Detector

Applies reconnaissance rules to every candidate source from
ScanFeatureExtractor (connection attempts only), so each scanner in a
window is reported and attributed to the right source:

    PORT_SCAN       — many ports on one host (vertical), or many ports on any
                      hosts with a high share of failed attempts
    HOST_SCAN       — many hosts probed on the same port with a high share of
                      failed attempts, or a very wide sweep regardless of failures
    RECONNAISSANCE  — a burst of mostly failed attempts from one source that
                      stays below the port/host scan thresholds

Requiring failures (or a single-host / single-port pattern) keeps busy but
normal clients — e.g. a browser opening connections to many CDN hosts on
port 443 — from being reported.

Confidence is a rule score (0.5 at the threshold, 1.0 at twice it, +0.2 for
a high failure ratio), not a calibrated probability.

MITRE ATT&CK: see correlation/mitre_mapping.py (T1046, T1595.001).
"""

from __future__ import annotations

import time
from typing import Any

from unishield.config import get_thresholds
from unishield.correlation.mitre_mapping import techniques_for
from unishield.detectors.base import BaseDetector
from unishield.schemas.alert import Alert, Severity, ThreatClass
from unishield.schemas.flow import NormalisedFlow



class ScanDetector(BaseDetector):
    """Detect port scanning, host sweeps and reconnaissance bursts."""

    def __init__(self, thresholds: dict[str, Any] | None = None):
        if thresholds is None:
            thresholds = get_thresholds().get("scanning", {})
        super().__init__(thresholds)

    @property
    def name(self) -> str:
        return "scan_detector"

    @property
    def threat_classes(self) -> list[ThreatClass]:
        return [ThreatClass.PORT_SCAN, ThreatClass.HOST_SCAN, ThreatClass.RECONNAISSANCE]

    @property
    def mitre_techniques(self) -> list[str]:
        return sorted({t for c in self.threat_classes for t in techniques_for(c)})

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
        levels = t.get("severity_levels", {})
        port_thr = t.get("unique_dest_ports", 25)
        failed_thr = t.get("failed_connection_ratio", 0.5)
        horiz_thr = t.get("horizontal_scan_hosts", 20)
        horiz_any_thr = t.get("horizontal_scan_hosts_any", 50)
        burst_thr = t.get("burst_connections", 30)
        alerts: list[Alert] = []

        def alert(threat: ThreatClass, c: dict[str, Any], severity: Severity, confidence: float,
                  destination: str | None, evidence: dict[str, Any]) -> Alert:
            return Alert(
                window_start=window_start,
                window_end=window_end,
                source_ip=c["source_ip"],
                destination_ip=destination,
                threat_class=threat,
                severity=severity,
                confidence=round(min(1.0, confidence), 4),
                detector_name=self.name,
                model_version=self.version,
                evidence={
                    "scanner_source_ip": c["source_ip"],
                    "attempts": c["attempts"],
                    "failed_attempts": c["failed"],
                    "failed_connection_ratio": c["failed_ratio"],
                    "attempts_per_second": c["attempts_per_second"],
                    **evidence,
                },
                mitre_techniques=techniques_for(threat),
                detection_latency_ms=self._measure_latency(start_time),
            )

        for c in features.get("scan_candidates", []):
            failing = c["failed_ratio"] >= failed_thr
            bonus = 0.2 if failing else 0.0
            reported = False

            vertical = c["vertical_ports"] >= port_thr
            if vertical or (c["unique_ports"] >= port_thr and failing):
                ports = max(c["vertical_ports"], c["unique_ports"])
                severity = self._determine_severity(ports, levels, "unique_dest_ports")
                alerts.append(alert(
                    ThreatClass.PORT_SCAN, c, severity, 0.5 * ports / port_thr + bonus,
                    c["vertical_host"] if vertical else None,
                    {
                        "unique_dest_ports": c["unique_ports"],
                        "unique_dest_hosts": c["unique_hosts"],
                        "max_ports_on_one_host": c["vertical_ports"],
                        "most_probed_host": c["vertical_host"],
                        "port_threshold": port_thr,
                    },
                ))
                reported = True

            horizontal = c["horizontal_hosts"]
            if (horizontal >= horiz_thr and failing) or horizontal >= horiz_any_thr:
                severity = self._determine_severity(horizontal, levels, "unique_dest_hosts")
                alerts.append(alert(
                    ThreatClass.HOST_SCAN, c, severity, 0.5 * horizontal / horiz_thr + bonus, None,
                    {
                        "hosts_on_one_port": horizontal,
                        "swept_port": c["horizontal_port"],
                        "unique_dest_hosts": c["unique_hosts"],
                        "horizontal_threshold": horiz_thr,
                    },
                ))
                reported = True

            if not reported and c["burst"] >= burst_thr and failing:
                alerts.append(alert(
                    ThreatClass.RECONNAISSANCE, c, Severity.MEDIUM, 0.5 * c["burst"] / burst_thr + bonus,
                    None,
                    {
                        "burst_attempts": c["burst"],
                        "burst_threshold": burst_thr,
                        "unique_dest_ports": c["unique_ports"],
                        "unique_dest_hosts": c["unique_hosts"],
                    },
                ))

        self._alerts_generated += len(alerts)
        return alerts
