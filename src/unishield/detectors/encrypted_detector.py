"""
UniShield — Encrypted-Session Anomaly Detector (optional advanced module)

Raises ENCRYPTED_SESSION_ANOMALY ("suspicious encrypted-session behaviour")
from TLS handshake metadata of EncryptedSessionFeatureExtractor:

    blocklisted_fingerprint — the client's JA3 is on the operator-supplied
                              ``ja3_blocklist`` (HIGH)
    outdated_protocol       — the session used a version in
                              ``outdated_tls_versions`` (MEDIUM)
    long_low_rate_session   — a session lasting >= ``long_session_sec`` at
                              <= ``low_rate_bytes_per_sec`` on a port where TLS
                              is unusual (LOW)

These findings describe how a session looks, not what it carries: nothing
is decrypted, and outdated clients or long-lived keep-alive connections are
often benign. A client → server → port triple is re-reported after
``realert_after_sec`` of traffic time or when its severity rises.

Confidence is a rule score, not a calibrated probability.

MITRE ATT&CK: T1573 (+ T1571 on an unusual port).
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta
from typing import Any

from unishield.config import get_thresholds
from unishield.correlation import severity as sev
from unishield.correlation.mitre_mapping import NON_STANDARD_PORT, techniques_for
from unishield.detectors.base import BaseDetector
from unishield.schemas.alert import Alert, Severity, ThreatClass
from unishield.schemas.flow import NormalisedFlow

_RULE_SEVERITY = {
    "blocklisted_fingerprint": Severity.HIGH,
    "outdated_protocol": Severity.MEDIUM,
    "long_low_rate_session": Severity.LOW,
}


class EncryptedSessionDetector(BaseDetector):
    """Flag suspicious encrypted-session behaviour from handshake metadata."""

    def __init__(self, thresholds: dict[str, Any] | None = None):
        if thresholds is None:
            thresholds = get_thresholds().get("encrypted", {})
        super().__init__(thresholds)
        self._last_reported: dict[tuple, tuple[datetime, Severity]] = {}

    @property
    def name(self) -> str:
        return "encrypted_session_detector"

    @property
    def threat_classes(self) -> list[ThreatClass]:
        return [ThreatClass.ENCRYPTED_SESSION_ANOMALY]

    @property
    def mitre_techniques(self) -> list[str]:
        return techniques_for(ThreatClass.ENCRYPTED_SESSION_ANOMALY, NON_STANDARD_PORT)

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
        if not flows or not features or not features.get("tls_flow_count"):
            return []

        t = self._thresholds
        long_sec = t.get("long_session_sec", 1800)
        low_rate = t.get("low_rate_bytes_per_sec", 200)
        realert = timedelta(seconds=t.get("realert_after_sec", 900))
        alerts: list[Alert] = []

        for c in features.get("tls_candidates", []):
            rules = []
            if c["blocklisted_ja3"]:
                rules.append("blocklisted_fingerprint")
            if c["outdated_versions"]:
                rules.append("outdated_protocol")
            rate = c["max_session_bytes_per_sec"]
            if c["unusual_port"] and c["max_duration_sec"] >= long_sec and rate is not None and rate <= low_rate:
                rules.append("long_low_rate_session")
            if not rules:
                continue

            severity = sev.max_severity(_RULE_SEVERITY[r] for r in rules)
            key = (c["source_ip"], c["destination_ip"], c["destination_port"])
            previous = self._last_reported.get(key)
            if previous is not None and window_end - previous[0] < realert \
                    and sev.RANK[severity] <= sev.RANK[previous[1]]:
                self.suppressed_classes.add(ThreatClass.ENCRYPTED_SESSION_ANOMALY)
                continue
            self._last_reported[key] = (window_end, severity)

            confidence = {Severity.HIGH: 0.8, Severity.MEDIUM: 0.6}.get(severity, 0.45) + 0.05 * (len(rules) - 1)
            extra = (NON_STANDARD_PORT,) if c["unusual_port"] else ()
            alerts.append(Alert(
                window_start=window_start,
                window_end=window_end,
                source_ip=c["source_ip"],
                destination_ip=c["destination_ip"],
                threat_class=ThreatClass.ENCRYPTED_SESSION_ANOMALY,
                severity=severity,
                confidence=round(min(1.0, confidence), 4),
                detector_name=self.name,
                model_version=self.version,
                evidence={
                    "summary": "suspicious encrypted-session behaviour (metadata only, not decrypted)",
                    "rules": rules,
                    "destination_port": c["destination_port"],
                    "tls_versions": c["tls_versions"],
                    "outdated_versions": c["outdated_versions"],
                    "ja3": c["ja3"],
                    "blocklisted_ja3": c["blocklisted_ja3"],
                    "unusual_port": c["unusual_port"],
                    "max_session_sec": c["max_duration_sec"],
                    "max_session_bytes_per_sec": rate,
                    "flows": c["flows"],
                },
                mitre_techniques=techniques_for(ThreatClass.ENCRYPTED_SESSION_ANOMALY, *extra),
                detection_latency_ms=self._measure_latency(start_time),
            ))

        self._alerts_generated += len(alerts)
        return alerts
