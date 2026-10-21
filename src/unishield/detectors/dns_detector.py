"""
UniShield — DNS Tunnelling & DGA Detector (optional advanced module)

Applies rules to the candidates of DNSFeatureExtractor:

    DGA_DETECTED   — one client queried at least ``dga_min_domains`` distinct
                     registrable domains that look machine-generated, and
                     either at least ``nxdomain_ratio`` of its answers were
                     NXDOMAIN or (without response codes) at least
                     ``dga_generated_share`` of its domains look generated
    DNS_TUNNELLING — one base domain received at least ``tunnel_min_queries``
                     queries with mostly unique subdomains
                     (>= ``subdomain_uniqueness``) that are long
                     (>= ``query_length_threshold`` characters on average) or
                     high-entropy (>= ``domain_entropy_threshold`` bits/char)

Name-based heuristics are probabilistic: CDNs and some services use
generated-looking names, so findings are leads for investigation.
Confidence is a rule score, not a calibrated probability.

MITRE ATT&CK: T1568.002 (DGA); T1071.004, T1572 (tunnelling).
"""

from __future__ import annotations

import time
from typing import Any

from unishield.config import get_thresholds
from unishield.correlation.mitre_mapping import techniques_for
from unishield.detectors.base import BaseDetector
from unishield.schemas.alert import Alert, Severity, ThreatClass
from unishield.schemas.flow import NormalisedFlow


class DNSDetector(BaseDetector):
    """Detect DGA activity per client and DNS tunnelling per base domain."""

    def __init__(self, thresholds: dict[str, Any] | None = None):
        if thresholds is None:
            thresholds = get_thresholds().get("dns", {})
        super().__init__(thresholds)

    @property
    def name(self) -> str:
        return "dns_detector"

    @property
    def threat_classes(self) -> list[ThreatClass]:
        return [ThreatClass.DNS_TUNNELLING, ThreatClass.DGA_DETECTED]

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
        if not flows or not features or not features.get("dns_query_count"):
            return []

        t = self._thresholds
        alerts: list[Alert] = []

        min_domains = t.get("dga_min_domains", 10)
        nx_thr = t.get("nxdomain_ratio", 0.3)
        share_thr = t.get("dga_generated_share", 0.5)
        for c in features.get("dga_candidates", []):
            if c["generated_looking_domains"] < min_domains:
                continue
            nx = c["nxdomain_ratio"]
            if nx is not None:
                if nx < nx_thr:
                    continue
            elif c["generated_share"] < share_thr:
                continue
            strong = nx is not None and c["generated_looking_domains"] >= 2 * min_domains
            confidence = 0.5 + 0.2 * min(1.0, c["generated_looking_domains"] / (2 * min_domains)) \
                + (0.2 * nx if nx is not None else 0.1 * c["generated_share"])
            alerts.append(self._alert(
                ThreatClass.DGA_DETECTED, Severity.HIGH if strong else Severity.MEDIUM, confidence,
                window_start, window_end, start_time,
                source_ip=c["source_ip"], destination_ip=c["resolver_ip"],
                evidence={
                    "generated_looking_domains": c["generated_looking_domains"],
                    "distinct_domains": c["distinct_domains"],
                    "generated_share": c["generated_share"],
                    "nxdomain_ratio": nx,
                    "examples": c["examples"],
                    "min_domains": min_domains,
                },
            ))

        min_queries = t.get("tunnel_min_queries", 20)
        unique_thr = t.get("subdomain_uniqueness", 0.8)
        length_thr = t.get("query_length_threshold", 30)
        entropy_thr = t.get("domain_entropy_threshold", 3.8)
        txt_thr = t.get("txt_record_frequency", 0.5)
        for c in features.get("tunnel_candidates", []):
            encoded = c["avg_subdomain_length"] >= length_thr or c["avg_subdomain_entropy"] >= entropy_thr
            if not (c["queries"] >= min_queries and c["unique_subdomain_ratio"] >= unique_thr and encoded):
                continue
            heavy = c["tunnel_record_ratio"] >= txt_thr or c["encoded_bytes"] >= 5000
            confidence = 0.5 + 0.2 * min(1.0, c["avg_subdomain_length"] / (2 * length_thr)) \
                + (0.2 if heavy else 0.0)
            clients = c["clients"]
            alerts.append(self._alert(
                ThreatClass.DNS_TUNNELLING, Severity.HIGH if heavy else Severity.MEDIUM, confidence,
                window_start, window_end, start_time,
                source_ip=clients[0] if len(clients) == 1 else None, destination_ip=None,
                evidence={
                    "base_domain": c["base_domain"],
                    "queries": c["queries"],
                    "unique_subdomain_ratio": c["unique_subdomain_ratio"],
                    "avg_subdomain_length": c["avg_subdomain_length"],
                    "avg_subdomain_entropy": c["avg_subdomain_entropy"],
                    "txt_or_null_ratio": c["tunnel_record_ratio"],
                    "encoded_bytes": c["encoded_bytes"],
                    "clients": clients,
                },
            ))

        self._alerts_generated += len(alerts)
        return alerts

    def _alert(self, threat, severity, confidence, window_start, window_end, start_time, *,
               source_ip, destination_ip, evidence) -> Alert:
        return Alert(
            window_start=window_start,
            window_end=window_end,
            source_ip=source_ip,
            destination_ip=destination_ip,
            threat_class=threat,
            severity=severity,
            confidence=round(min(1.0, confidence), 4),
            detector_name=self.name,
            model_version=self.version,
            evidence=evidence,
            mitre_techniques=techniques_for(threat),
            detection_latency_ms=self._measure_latency(start_time),
        )
