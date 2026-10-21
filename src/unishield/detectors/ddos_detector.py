"""
UniShield — DDoS / Flood Detector

Detects floods against a single destination, using the per-target
features of VolumeFeatureExtractor:

    DDOS_VOLUMETRIC — peak packets/s or bytes/s to one destination above threshold
    SYN_FLOOD       — peak half-open connection attempts/s to one destination above
                      threshold, and most TCP attempts to it left half-open
    UDP_FLOOD       — peak UDP packets/s to one destination above threshold, and
                      most of its traffic UDP

Peak rates are the busiest 1-second interval of the window. The number of
distinct sources is reported as evidence ("distributed" when it reaches
``min_unique_sources``); a single-source flood is still reported.

Confidence is a rule score (0.5 at the threshold, 1.0 at twice it), not a
calibrated probability.

MITRE ATT&CK: see correlation/mitre_mapping.py (T1498, T1498.001, T1499.001).
"""

from __future__ import annotations

import time
from typing import Any

from unishield.config import get_thresholds
from unishield.correlation.mitre_mapping import techniques_for
from unishield.correlation.severity import at_least as _at_least
from unishield.detectors.base import BaseDetector
from unishield.schemas.alert import Alert, Severity, ThreatClass
from unishield.schemas.flow import NormalisedFlow


class DDoSDetector(BaseDetector):
    """Detect DDoS/flood attacks against a single destination."""

    def __init__(self, thresholds: dict[str, Any] | None = None):
        if thresholds is None:
            thresholds = get_thresholds().get("ddos", {})
        super().__init__(thresholds)

    @property
    def name(self) -> str:
        return "ddos_detector"

    @property
    def threat_classes(self) -> list[ThreatClass]:
        return [ThreatClass.DDOS_VOLUMETRIC, ThreatClass.SYN_FLOOD, ThreatClass.UDP_FLOOD]

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
        min_sources = t.get("min_unique_sources", 20)
        window_sec = features.get("window_duration_sec")
        alerts: list[Alert] = []

        def alert(threat: ThreatClass, target: str, sources: int, ratio: float,
                  severity: Severity, evidence: dict[str, Any]) -> Alert:
            return Alert(
                window_start=window_start,
                window_end=window_end,
                destination_ip=target,
                threat_class=threat,
                severity=severity,
                confidence=round(min(1.0, 0.5 * ratio), 4),
                detector_name=self.name,
                model_version=self.version,
                evidence={
                    "target_ip": target,
                    "unique_sources": sources,
                    "distributed": sources >= min_sources,
                    "window_observed_sec": window_sec,
                    **evidence,
                },
                mitre_techniques=techniques_for(threat),
                detection_latency_ms=self._measure_latency(start_time),
            )

        # --- Volumetric -----------------------------------------------------
        pps_thr = t.get("packets_per_second", 10000)
        bps_thr = t.get("bytes_per_second", 50_000_000)
        pps = features.get("vol_target_pps_peak", 0) or 0
        bps = features.get("vol_target_bps_peak", 0) or 0
        target = features.get("vol_target_ip")
        if target and (pps > pps_thr or bps > bps_thr):
            sources = features.get("vol_target_unique_sources", 0)
            severity = _at_least(self._determine_severity(pps, levels, "packets_per_second"), Severity.MEDIUM)
            alerts.append(alert(
                ThreatClass.DDOS_VOLUMETRIC, target, sources, max(pps / pps_thr, bps / bps_thr), severity,
                {
                    "peak_packets_per_second": pps,
                    "avg_packets_per_second": features.get("vol_target_pps_avg", 0),
                    "peak_bytes_per_second": bps,
                    "pps_threshold": pps_thr,
                    "bps_threshold": bps_thr,
                    "target_packets": features.get("vol_target_packets", 0),
                    "source_ip_entropy": features.get("vol_target_source_entropy", 0),
                },
            ))

        # --- SYN flood ------------------------------------------------------
        syn_thr = t.get("syn_rate_threshold", 1000)
        ratio_thr = t.get("syn_only_ratio", 0.8)
        syn_rate = features.get("syn_target_rate_peak", 0) or 0
        syn_ratio = features.get("syn_target_syn_only_ratio", 0) or 0
        target = features.get("syn_target_ip")
        if target and syn_rate > syn_thr and syn_ratio >= ratio_thr:
            sources = features.get("syn_target_unique_sources", 0)
            severity = _at_least(self._determine_severity(syn_rate, levels, "syn_rate_threshold"), Severity.MEDIUM)
            alerts.append(alert(
                ThreatClass.SYN_FLOOD, target, sources, syn_rate / syn_thr, severity,
                {
                    "peak_half_open_per_second": syn_rate,
                    "half_open_attempts": features.get("syn_target_attempts", 0),
                    "half_open_ratio": syn_ratio,
                    "syn_rate_threshold": syn_thr,
                    "syn_only_ratio_threshold": ratio_thr,
                },
            ))

        # --- UDP flood ------------------------------------------------------
        udp_thr = t.get("udp_flood_pps", 8000)
        udp_ratio_thr = t.get("udp_ratio", 0.7)
        udp_pps = features.get("udp_target_pps_peak", 0) or 0
        udp_ratio = features.get("udp_target_udp_ratio", 0) or 0
        target = features.get("udp_target_ip")
        if target and udp_pps > udp_thr and udp_ratio >= udp_ratio_thr:
            sources = features.get("udp_target_unique_sources", 0)
            severity = _at_least(self._determine_severity(udp_pps, levels, "packets_per_second"), Severity.MEDIUM)
            alerts.append(alert(
                ThreatClass.UDP_FLOOD, target, sources, udp_pps / udp_thr, severity,
                {
                    "peak_udp_packets_per_second": udp_pps,
                    "udp_share_of_target_packets": udp_ratio,
                    "udp_flood_pps_threshold": udp_thr,
                    "udp_ratio_threshold": udp_ratio_thr,
                },
            ))

        self._alerts_generated += len(alerts)
        return alerts
