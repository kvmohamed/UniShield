"""
UniShield — DNS Tunnelling & DGA Detector

Detects DNS-based threats:
    - DNS Tunnelling: data exfiltration/C2 via encoded DNS queries
      (long queries, high entropy, TXT record abuse)
    - DGA (Domain Generation Algorithm): malware-generated domains
      with high character entropy, unusual character distributions

Uses features from the DNSFeatureExtractor.

MITRE ATT&CK:
    - T1071.004: Application Layer Protocol: DNS
    - T1568.002: Dynamic Resolution: Domain Generation Algorithms
    - T1048.003: Exfiltration Over Alternative Protocol: DNS
"""

from __future__ import annotations

import time
from typing import Any

from unishield.config import get_thresholds
from unishield.detectors.base import BaseDetector
from unishield.schemas.alert import Alert, Severity, ThreatClass
from unishield.schemas.flow import NormalisedFlow


class DNSDetector(BaseDetector):
    """
    Detect DNS tunnelling and DGA activity.
    """

    def __init__(self, thresholds: dict[str, Any] | None = None):
        if thresholds is None:
            all_thresholds = get_thresholds()
            thresholds = all_thresholds.get("dns", {})
        super().__init__(thresholds)

    @property
    def name(self) -> str:
        return "dns_detector"

    @property
    def threat_classes(self) -> list[ThreatClass]:
        return [ThreatClass.DNS_TUNNELLING, ThreatClass.DGA_DETECTED]

    @property
    def mitre_techniques(self) -> list[str]:
        return ["T1071.004", "T1568.002", "T1048.003"]

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
        dns_count = features.get("dns_query_count", 0)

        if dns_count == 0:
            return alerts

        # --- DNS Tunnelling Detection ---
        avg_query_len = features.get("avg_query_length", 0)
        max_query_len = features.get("max_query_length", 0)
        txt_ratio = features.get("txt_record_ratio", 0)
        long_queries = features.get("long_query_domains", 0)
        avg_entropy = features.get("avg_domain_entropy", 0)

        len_threshold = t.get("query_length_threshold", 50)
        txt_threshold = t.get("txt_record_frequency", 0.1)
        entropy_threshold = t.get("domain_entropy_threshold", 3.5)

        # Tunnelling indicators: long queries + high TXT ratio + high entropy
        tunnelling_score = 0.0
        if avg_query_len > len_threshold * 0.7:
            tunnelling_score += 0.3
        if max_query_len > len_threshold:
            tunnelling_score += 0.2
        if txt_ratio > txt_threshold:
            tunnelling_score += 0.3
        if avg_entropy > entropy_threshold:
            tunnelling_score += 0.2

        if tunnelling_score >= 0.5:
            severity = Severity.HIGH if tunnelling_score >= 0.8 else Severity.MEDIUM

            alert = Alert(
                window_start=window_start,
                window_end=window_end,
                threat_class=ThreatClass.DNS_TUNNELLING,
                severity=severity,
                confidence=round(min(1.0, tunnelling_score), 4),
                detector_name=self.name,
                model_version=self.version,
                evidence={
                    "avg_query_length": avg_query_len,
                    "max_query_length": max_query_len,
                    "txt_record_ratio": txt_ratio,
                    "long_query_domains": long_queries,
                    "avg_domain_entropy": avg_entropy,
                    "dns_query_count": dns_count,
                    "tunnelling_score": round(tunnelling_score, 4),
                },
                mitre_techniques=["T1071.004", "T1048.003"],
                detection_latency_ms=self._measure_latency(start_time),
            )
            alerts.append(alert)

        # --- DGA Detection ---
        high_entropy_domains = features.get("high_entropy_domains", 0)
        unique_subdomain_ratio = features.get("unique_subdomain_ratio", 0)
        avg_consonant = features.get("avg_consonant_ratio", 0)
        nxdomain_ratio = features.get("nxdomain_ratio", 0)
        nxdomain_threshold = t.get("nxdomain_ratio", 0.3)
        subdomain_threshold = t.get("subdomain_uniqueness", 0.8)

        # DGA indicators: high entropy + many unique subdomains + high NXDOMAIN
        dga_score = 0.0
        if high_entropy_domains > 5:
            dga_score += 0.3
        if unique_subdomain_ratio > subdomain_threshold:
            dga_score += 0.25
        if nxdomain_ratio > nxdomain_threshold:
            dga_score += 0.25
        if avg_consonant > 0.75:
            dga_score += 0.2

        if dga_score >= 0.5:
            severity = Severity.HIGH if dga_score >= 0.8 else Severity.MEDIUM

            alert = Alert(
                window_start=window_start,
                window_end=window_end,
                threat_class=ThreatClass.DGA_DETECTED,
                severity=severity,
                confidence=round(min(1.0, dga_score), 4),
                detector_name=self.name,
                model_version=self.version,
                evidence={
                    "high_entropy_domains": high_entropy_domains,
                    "unique_subdomain_ratio": unique_subdomain_ratio,
                    "avg_consonant_ratio": avg_consonant,
                    "nxdomain_ratio": nxdomain_ratio,
                    "avg_domain_entropy": avg_entropy,
                    "dga_score": round(dga_score, 4),
                },
                mitre_techniques=["T1568.002"],
                detection_latency_ms=self._measure_latency(start_time),
            )
            alerts.append(alert)

        self._alerts_generated += len(alerts)
        return alerts
