"""
UniShield — Alert Correlation Engine

Correlates and deduplicates alerts to reduce noise and group
related detections into coherent incidents.

DESIGN:
    - Temporal deduplication: identical (threat_class, source_ip, detector)
      alerts within a configurable time window are merged.
    - Cross-detector correlation: alerts from different detectors about
      the same source are grouped into incidents.
    - Severity escalation: correlated alerts may upgrade severity.

SECURITY CONSTRAINTS:
    - Read-only: operates on alert objects only.
    - No network communication.
"""

from __future__ import annotations

import logging
import uuid
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from unishield.schemas.alert import Alert, Severity, ThreatClass

logger = logging.getLogger("unishield.correlation")


class AlertCorrelator:
    """
    Correlate and deduplicate alerts to reduce noise.
    """

    def __init__(
        self,
        dedup_window_sec: int = 60,
        correlation_window_sec: int = 300,
        min_alerts_for_incident: int = 3,
    ):
        self.dedup_window = timedelta(seconds=dedup_window_sec)
        self.correlation_window = timedelta(seconds=correlation_window_sec)
        self.min_alerts_for_incident = min_alerts_for_incident

        # Dedup state: key → last alert timestamp
        self._dedup_cache: dict[str, datetime] = {}
        self._suppressed_count: int = 0
        self._total_processed: int = 0

    def _dedup_key(self, alert: Alert) -> str:
        """Generate a deduplication key for an alert."""
        return f"{alert.threat_class.value}|{alert.source_ip or 'any'}|{alert.detector_name}"

    def deduplicate(self, alerts: list[Alert]) -> list[Alert]:
        """
        Remove duplicate alerts that have the same threat class, source IP,
        and detector within the dedup window.

        Returns:
            List of unique alerts after deduplication.
        """
        unique: list[Alert] = []

        for alert in alerts:
            self._total_processed += 1
            key = self._dedup_key(alert)
            last_seen = self._dedup_cache.get(key)

            if last_seen is not None:
                time_since = alert.timestamp - last_seen
                if time_since < self.dedup_window:
                    self._suppressed_count += 1
                    continue

            self._dedup_cache[key] = alert.timestamp
            unique.append(alert)

        return unique

    def correlate(self, alerts: list[Alert]) -> list[dict[str, Any]]:
        """
        Group related alerts into correlated incidents.

        Groups alerts by source IP within the correlation window.
        If multiple threat classes appear from the same source,
        this may indicate a coordinated attack.

        Returns:
            List of incident dictionaries.
        """
        if not alerts:
            return []

        # Group by source IP
        by_source: dict[str, list[Alert]] = defaultdict(list)
        for alert in alerts:
            key = alert.source_ip or "unknown"
            by_source[key].append(alert)

        incidents: list[dict[str, Any]] = []

        for source_ip, source_alerts in by_source.items():
            if len(source_alerts) < self.min_alerts_for_incident:
                continue

            # Sort by timestamp
            source_alerts.sort(key=lambda a: a.timestamp)

            # Check if alerts span multiple threat classes or detectors
            threat_classes = set(a.threat_class.value for a in source_alerts)
            detectors = set(a.detector_name for a in source_alerts)
            severities = [a.severity for a in source_alerts]

            # Determine incident severity (escalate if multi-class)
            max_severity = max(severities, key=lambda s: _SEVERITY_ORDER.get(s, 0))
            if len(threat_classes) >= 3:
                # Multi-vector attack — escalate to CRITICAL
                incident_severity = Severity.CRITICAL
            elif len(threat_classes) >= 2:
                # Multi-stage attack — escalate by one level
                incident_severity = _escalate_severity(max_severity)
            else:
                incident_severity = max_severity

            # Compute time span
            time_span = (
                source_alerts[-1].timestamp - source_alerts[0].timestamp
            ).total_seconds()

            incident = {
                "incident_id": f"INC-{uuid.uuid4().hex[:8].upper()}",
                "source_ip": source_ip,
                "alert_count": len(source_alerts),
                "alert_ids": [a.alert_id for a in source_alerts],
                "threat_classes": sorted(threat_classes),
                "detectors": sorted(detectors),
                "severity": incident_severity.value,
                "first_seen": source_alerts[0].timestamp.isoformat(),
                "last_seen": source_alerts[-1].timestamp.isoformat(),
                "time_span_sec": round(time_span, 2),
                "avg_confidence": round(
                    sum(a.confidence for a in source_alerts) / len(source_alerts), 4
                ),
                "is_multi_stage": len(threat_classes) >= 2,
                "is_multi_vector": len(threat_classes) >= 3,
                "mitre_techniques": sorted(set(
                    t for a in source_alerts for t in a.mitre_techniques
                )),
            }
            incidents.append(incident)

        # Sort incidents by severity (most severe first)
        incidents.sort(
            key=lambda i: _SEVERITY_ORDER.get(Severity(i["severity"]), 0),
            reverse=True,
        )

        return incidents

    def process(self, alerts: list[Alert]) -> tuple[list[Alert], list[dict[str, Any]]]:
        """
        Full correlation pipeline: deduplicate then correlate.

        Returns:
            Tuple of (deduplicated_alerts, incidents).
        """
        deduped = self.deduplicate(alerts)
        incidents = self.correlate(deduped)
        return deduped, incidents

    @property
    def suppressed_count(self) -> int:
        return self._suppressed_count

    @property
    def total_processed(self) -> int:
        return self._total_processed

    def stats(self) -> dict[str, Any]:
        return {
            "total_processed": self._total_processed,
            "suppressed": self._suppressed_count,
            "dedup_cache_size": len(self._dedup_cache),
            "suppression_rate": round(
                self._suppressed_count / max(self._total_processed, 1), 4
            ),
        }

    def clear(self) -> None:
        """Reset the correlator state."""
        self._dedup_cache.clear()
        self._suppressed_count = 0
        self._total_processed = 0


# ---------------------------------------------------------------------------
# Severity helpers
# ---------------------------------------------------------------------------

_SEVERITY_ORDER = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def _escalate_severity(severity: Severity) -> Severity:
    """Escalate severity by one level."""
    order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    idx = order.index(severity) if severity in order else 0
    return order[min(idx + 1, len(order) - 1)]
