"""
UniShield — Threat-Intelligence Match Detector

Raises INTEL_MATCH for traffic involving an indicator the operator imported
(IntelFeatureExtractor groups the matches):

    a monitored host contacting a listed address      ``outbound_severity`` (HIGH)
    a monitored host resolving a listed domain        ``dns_severity`` (HIGH)
    a listed address contacting the monitored network ``inbound_severity`` (MEDIUM)
    anything else (internal, direction unknown)       ``other_severity`` (MEDIUM)

A severity listed with the indicator (CSV ``severity`` column) overrides
these. Confidence reflects a list match, not observed behaviour: the
evidence names every list, so analysts can judge its reliability. A match
is re-reported after ``realert_after_sec`` of traffic time or when its
severity rises.

MITRE ATT&CK: none by default; techniques listed with the indicator are added.
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta
from typing import Any

from unishield.config import get_thresholds
from unishield.correlation import severity as sev
from unishield.correlation.mitre_mapping import techniques_for
from unishield.detectors.base import BaseDetector
from unishield.schemas.alert import Alert, Severity, ThreatClass
from unishield.schemas.flow import NormalisedFlow

_SUMMARY = {
    "destination_ip": "traffic to an address on an imported threat-intelligence list",
    "source_ip": "traffic from an address on an imported threat-intelligence list",
    "dns_query": "DNS lookup of a domain on an imported threat-intelligence list",
}


class IntelDetector(BaseDetector):
    """Report flows that involve an imported known-bad indicator."""

    def __init__(self, thresholds: dict[str, Any] | None = None):
        if thresholds is None:
            thresholds = get_thresholds().get("intel", {})
        super().__init__(thresholds)
        self._last_reported: dict[tuple[str, str, str], tuple[datetime, Severity]] = {}

    @property
    def name(self) -> str:
        return "intel_detector"

    @property
    def threat_classes(self) -> list[ThreatClass]:
        return [ThreatClass.INTEL_MATCH]

    @property
    def mitre_techniques(self) -> list[str]:
        return techniques_for(ThreatClass.INTEL_MATCH)

    def _base_severity(self, match: dict[str, Any]) -> Severity:
        t = self._thresholds
        if match["severities"]:
            return sev.max_severity(Severity(s) for s in match["severities"])
        if match["field"] == "dns_query":
            return Severity(t.get("dns_severity", "HIGH"))
        if match["field"] == "destination_ip" and match["direction"] == "outbound":
            return Severity(t.get("outbound_severity", "HIGH"))
        if match["field"] == "source_ip" and match["direction"] == "inbound":
            return Severity(t.get("inbound_severity", "MEDIUM"))
        return Severity(t.get("other_severity", "MEDIUM"))

    def detect(
        self,
        flows: list[NormalisedFlow],
        features: dict[str, Any],
        window_start: Any,
        window_end: Any,
    ) -> list[Alert]:
        start_time = time.time()
        self._windows_analysed += 1
        self.suppressed_classes = set()
        if not flows or not features or not features.get("intel_match_count"):
            return []

        t = self._thresholds
        realert = timedelta(seconds=t.get("realert_after_sec", 900))
        base_confidence = float(t.get("base_confidence", 0.7))
        alerts: list[Alert] = []
        for m in features.get("intel_matches", []):
            field, observed, peers = m["field"], m["observed"], m["peers"]
            single_peer = peers[0] if m["peer_count"] == 1 else None
            if field == "source_ip":
                source_ip, destination_ip = observed, single_peer
            elif field == "destination_ip":
                source_ip, destination_ip = single_peer, observed
            else:                                              # dns_query: the client resolving the name
                source_ip, destination_ip = single_peer, None

            severity = self._base_severity(m)
            key = (field, observed, single_peer or "*")
            previous = self._last_reported.get(key)
            if previous is not None and window_end - previous[0] < realert \
                    and sev.RANK[severity] <= sev.RANK[previous[1]]:
                self.suppressed_classes.add(ThreatClass.INTEL_MATCH)
                continue
            self._last_reported[key] = (window_end, severity)

            confidence = min(0.9, base_confidence + 0.1 * (len(m["sources"]) - 1))
            evidence = {
                "summary": _SUMMARY[field],
                "matched_field": field,
                "observed": observed,
                "intel_matches": m["intel_matches"],
                "sources": m["sources"],
                "flows": m["flows"],
                "bytes": m["bytes"],
                "direction": m["direction"],
                "peers": peers,
                "peer_count": m["peer_count"],
                "destination_ports": m["destination_ports"],
                "confidence_basis": "list match; reliability depends on the listed sources",
            }
            if m["query_names"]:
                evidence["query_names"] = m["query_names"]
            alerts.append(Alert(
                window_start=window_start,
                window_end=window_end,
                source_ip=source_ip,
                destination_ip=destination_ip,
                threat_class=ThreatClass.INTEL_MATCH,
                severity=severity,
                confidence=round(confidence, 4),
                detector_name=self.name,
                model_version=self.version,
                evidence=evidence,
                mitre_techniques=techniques_for(ThreatClass.INTEL_MATCH, *m["techniques"]),
                detection_latency_ms=self._measure_latency(start_time),
            ))

        self._alerts_generated += len(alerts)
        return alerts
