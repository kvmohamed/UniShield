"""
UniShield — Supervised Window-Model Detector (hybrid / ml detection modes)

Scores each window with a trained window model (``models.predict``) and
raises an alert when the calibrated probability that the window is an
attack reaches ``models.ml_alert_probability``.

    - In hybrid mode (``require_unexplained=True``) it runs after the rule
      detectors and only reports windows no rule explained, so it adds
      coverage rather than duplicate alerts.
    - A model without calibration never alerts: an uncalibrated score is not
      a probability.
    - The threat class is the model's most likely attack class when it is a
      UniShield class; otherwise (Isolation Forest, unknown "ATTACK" labels)
      STATISTICAL_ANOMALY. Source and destination are the strongest entity
      the matching feature extractor reported, which is a lead, not proof.
    - Confidence is the calibrated probability.

SECURITY CONSTRAINTS:
    - Read-only: no packets sent, no decryption. Models load only from the
      local registry after a SHA-256 check.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Optional

from unishield.config import get_config
from unishield.correlation.mitre_mapping import techniques_for
from unishield.detectors.base import BaseDetector
from unishield.schemas.alert import Alert, Severity, ThreatClass
from unishield.schemas.flow import NormalisedFlow

logger = logging.getLogger("unishield.detectors.ml")

_CANDIDATE_LISTS = {
    ThreatClass.DATA_EXFILTRATION: ("exfil_candidates", "source_ip", "destination_ip"),
    ThreatClass.DGA_DETECTED: ("dga_candidates", "source_ip", "resolver_ip"),
    ThreatClass.ENCRYPTED_SESSION_ANOMALY: ("tls_candidates", "source_ip", "destination_ip"),
}
_SCALAR_KEYS = {
    ThreatClass.SYN_FLOOD: (None, "syn_target_ip"),
    ThreatClass.UDP_FLOOD: (None, "udp_target_ip"),
    ThreatClass.DDOS_VOLUMETRIC: (None, "vol_target_ip"),
    ThreatClass.DDOS_PROTOCOL: (None, "vol_target_ip"),
    ThreatClass.PORT_SCAN: ("top_scanner_ip", None),
    ThreatClass.HOST_SCAN: ("top_host_scanner_ip", None),
    ThreatClass.RECONNAISSANCE: ("top_scanner_ip", None),
    ThreatClass.C2_BEACONING: ("top_beacon_src_ip", "top_beacon_dst_ip"),
}


def likely_entities(threat: ThreatClass, features: dict[str, Any]) -> tuple[Optional[str], Optional[str]]:
    """(source, destination) the feature extractor for ``threat`` ranked highest, if any."""
    if threat in _CANDIDATE_LISTS:
        key, src, dst = _CANDIDATE_LISTS[threat]
        items = features.get(key) or []
        return (items[0].get(src), items[0].get(dst)) if items else (None, None)
    if threat == ThreatClass.DNS_TUNNELLING:
        items = features.get("tunnel_candidates") or []
        clients = items[0].get("clients", []) if items else []
        return (clients[0] if len(clients) == 1 else None), None
    src_key, dst_key = _SCALAR_KEYS.get(threat, (None, None))
    return (features.get(src_key) if src_key else None), (features.get(dst_key) if dst_key else None)


class MLDetector(BaseDetector):
    """Alert on windows a calibrated window model scores as likely attacks."""

    runs_after_rules = True

    def __init__(self, model, threshold: float | None = None, require_unexplained: bool = True):
        super().__init__({})
        self.model = model
        self.threshold = threshold if threshold is not None else get_config().models.ml_alert_probability
        self.require_unexplained = require_unexplained
        if not model.calibrated:
            logger.warning("Window model %s has no calibration; MLDetector will not alert", model.version)

    @classmethod
    def from_registry(cls, name: str | None = None, require_unexplained: bool = True,
                      registry=None) -> Optional["MLDetector"]:
        """Detector for the latest saved model ``name`` (config default), or None if none is saved."""
        from unishield.models.predict import WindowModel
        from unishield.models.registry import ModelRegistry

        name = name or get_config().models.window_model
        registry = registry or ModelRegistry()
        if registry.metadata(name) is None:
            return None
        try:
            model = WindowModel.load(name, registry=registry)
        except FileNotFoundError as e:
            logger.warning("Window model unavailable: %s", e)
            return None
        return cls(model, require_unexplained=require_unexplained)

    @property
    def name(self) -> str:
        return "ml_detector"

    @property
    def version(self) -> str:
        return self.model.version

    @property
    def threat_classes(self) -> list[ThreatClass]:
        return list(ThreatClass)

    @property
    def mitre_techniques(self) -> list[str]:
        return []

    def detect(
        self,
        flows: list[NormalisedFlow],
        features: dict[str, Any],
        window_start: Any,
        window_end: Any,
    ) -> list[Alert]:
        start_time = time.time()
        self._windows_analysed += 1
        if not flows or not features or not self.model.calibrated:
            return []
        if self.require_unexplained and features.get("rule_alert_classes"):
            return []

        prediction = self.model.predict(features)
        if prediction.probability is None or prediction.probability < self.threshold:
            return []

        try:
            threat = ThreatClass(prediction.predicted_class)
        except (TypeError, ValueError):
            threat = ThreatClass.STATISTICAL_ANOMALY
        source, destination = likely_entities(threat, features)
        severity = Severity.HIGH if prediction.probability >= 0.99 else Severity.MEDIUM
        alert = Alert(
            window_start=window_start,
            window_end=window_end,
            source_ip=source,
            destination_ip=destination,
            threat_class=threat,
            severity=severity,
            confidence=round(prediction.probability, 4),
            detector_name=self.name,
            model_version=self.version,
            evidence={
                "summary": f"window model ({self.model.algorithm}) scored this window as a likely attack",
                "calibrated_probability": round(prediction.probability, 4),
                "raw_score": round(prediction.raw_score, 4),
                "predicted_class": prediction.predicted_class,
                "class_share": round(prediction.class_probability, 4)
                if prediction.class_probability is not None else None,
                "threshold": self.threshold,
                "entities_from_features": source is not None or destination is not None,
                "flows_in_window": len(flows),
            },
            mitre_techniques=techniques_for(threat),
            detection_latency_ms=self._measure_latency(start_time),
        )
        self._alerts_generated += 1
        return [alert]
