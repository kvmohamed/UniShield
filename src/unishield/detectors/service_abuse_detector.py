"""
UniShield — Brute-Force and Spam Detector

Rules over the rolling profiles of ServiceAbuseFeatureExtractor:

    BRUTE_FORCE    one source made at least ``brute_force.min_attempts``
                   short, small connections to the same login port on one
                   host within ``brute_force.horizon_sec``, and at most
                   ``max_failed_ratio`` of them failed to connect (a login
                   attempt reaches the service; a SYN flood does not).
                   HIGH from ``high_attempts`` attempts. MITRE T1110.
    SPAM_ACTIVITY  one internal host opened SMTP connections to at least
                   ``spam.min_destinations`` different external mail servers
                   within ``spam.horizon_sec``. HIGH from ``high_destinations``.
                   ATT&CK has no technique for sending spam, so none is
                   attached. Real mail servers deliver this way: give them the
                   ``mail_server`` asset role.

Whether a login succeeded, or what a message contained, is never known:
nothing is decrypted or inspected. A pair or source is re-reported after
``realert_after_sec`` of traffic time or when its severity rises.
Confidence is a rule score, not a calibrated probability.
"""

from __future__ import annotations

import time
from datetime import timedelta
from typing import Any

from unishield.config import get_thresholds
from unishield.correlation.mitre_mapping import techniques_for
from unishield.detectors.base import BaseDetector, ReportMemory
from unishield.schemas.alert import Alert, Severity, ThreatClass
from unishield.schemas.flow import NormalisedFlow


class ServiceAbuseDetector(BaseDetector):
    """Detect password guessing against login services and spam sending."""

    def __init__(self, thresholds: dict[str, Any] | None = None):
        t = thresholds if thresholds is not None else get_thresholds()
        super().__init__(t)
        self._bf = t.get("brute_force", {})
        self._spam = t.get("spam", {})
        self._reported_bf = ReportMemory(timedelta(seconds=self._bf.get("realert_after_sec", 600)))
        self._reported_spam = ReportMemory(timedelta(seconds=self._spam.get("realert_after_sec", 900)))

    @property
    def name(self) -> str:
        return "service_abuse_detector"

    @property
    def threat_classes(self) -> list[ThreatClass]:
        return [ThreatClass.BRUTE_FORCE, ThreatClass.SPAM_ACTIVITY]

    @property
    def mitre_techniques(self) -> list[str]:
        return techniques_for(ThreatClass.BRUTE_FORCE)

    def state_dict(self) -> dict[str, Any]:
        return {"brute_force": self._reported_bf.state_dict(), "spam": self._reported_spam.state_dict()}

    def load_state_dict(self, state: dict[str, Any]) -> None:
        self._reported_bf.load_state_dict(state["brute_force"])
        self._reported_spam.load_state_dict(state["spam"])

    def detect(self, flows: list[NormalisedFlow], features: dict[str, Any], window_start: Any,
               window_end: Any) -> list[Alert]:
        start_time = time.time()
        self._windows_analysed += 1
        self.suppressed_classes = set()
        if not flows or not features:
            return []
        alerts = self._brute_force(features, window_start, window_end, start_time)
        alerts += self._spam_activity(features, window_start, window_end, start_time)
        self._alerts_generated += len(alerts)
        return alerts

    def _brute_force(self, features, window_start, window_end, start_time) -> list[Alert]:
        t = self._bf
        min_attempts = t.get("min_attempts", 30)
        high = t.get("high_attempts", 150)
        max_failed = t.get("max_failed_ratio", 0.5)
        out = []
        for c in features.get("bruteforce_candidates", []):
            attempts = c["attempts"]
            if attempts < min_attempts or c["failed"] / attempts > max_failed:
                continue
            severity = Severity.HIGH if attempts >= high else Severity.MEDIUM
            key = (c["source_ip"], c["destination_ip"], c["destination_port"])
            if not self._reported_bf.should_report(key, window_end, severity):
                self.suppressed_classes.add(ThreatClass.BRUTE_FORCE)
                continue
            out.append(self._alert(
                ThreatClass.BRUTE_FORCE, severity, 0.5 + 0.4 * min(1.0, attempts / high),
                window_start, window_end, start_time, c["source_ip"], c["destination_ip"],
                {
                    "summary": "repeated short connections to one login service (credential guessing pattern; "
                               "login success is not visible)",
                    "destination_port": c["destination_port"], "attempts": attempts,
                    "failed_to_connect": c["failed"], "span_sec": c["span_sec"],
                    "attempts_per_min": c["rate_per_min"], "horizon_sec": t.get("horizon_sec", 60),
                    "min_attempts": min_attempts,
                },
            ))
        return out

    def _spam_activity(self, features, window_start, window_end, start_time) -> list[Alert]:
        t = self._spam
        min_dest = t.get("min_destinations", 20)
        high = t.get("high_destinations", 100)
        out = []
        for c in features.get("spam_candidates", []):
            n = c["smtp_destinations"]
            if n < min_dest:
                continue
            severity = Severity.HIGH if n >= high else Severity.MEDIUM
            if not self._reported_spam.should_report((c["source_ip"],), window_end, severity):
                self.suppressed_classes.add(ThreatClass.SPAM_ACTIVITY)
                continue
            out.append(self._alert(
                ThreatClass.SPAM_ACTIVITY, severity, 0.5 + 0.4 * min(1.0, n / high),
                window_start, window_end, start_time, c["source_ip"], None,
                {
                    "summary": "direct SMTP delivery to many external mail servers (spam-sending pattern; "
                               "message content is not visible)",
                    "smtp_destinations": n, "smtp_connections": c["smtp_connections"],
                    "failed_to_connect": c["failed"], "examples": c["examples"],
                    "horizon_sec": t.get("horizon_sec", 300), "min_destinations": min_dest,
                },
            ))
        return out

    def _alert(self, threat, severity, confidence, window_start, window_end, start_time, src, dst, evidence):
        return Alert(
            window_start=window_start, window_end=window_end, source_ip=src, destination_ip=dst,
            threat_class=threat, severity=severity, confidence=round(min(1.0, confidence), 4),
            detector_name=self.name, model_version=self.version, evidence=evidence,
            mitre_techniques=techniques_for(threat), detection_latency_ms=self._measure_latency(start_time),
        )
