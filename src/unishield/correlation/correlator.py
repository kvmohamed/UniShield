"""
UniShield — Alert Correlation Engine

Deduplicates alerts and groups related alerts into incidents.

DESIGN:
    - Deduplication runs in traffic (event) time: an alert is suppressed when
      an alert with the same threat class, source, destination and detector
      ended within ``dedup_window_sec`` before it (window end times). This
      gives the same result whether traffic is replayed fast or arrives live.
    - Incidents group alerts by the entity involved — the source, or the
      destination for alerts without a single source (e.g. a distributed
      flood) — within ``correlation_window_sec``. Several threat classes for
      one entity escalate the incident's severity.

SECURITY CONSTRAINTS:
    - Read-only: operates on alert objects only.
    - No network communication.
"""

from __future__ import annotations

import hashlib
import logging
from collections import OrderedDict, defaultdict
from datetime import datetime, timedelta
from typing import Any, Iterable

from unishield.correlation import severity as sev
from unishield.schemas.alert import Alert, Severity
from unishield.schemas.timeutil import from_epoch_us, to_epoch_us

logger = logging.getLogger("unishield.correlation")

_DEDUP_CACHE_LIMIT = 100_000


class AlertCorrelator:
    """Correlate and deduplicate alerts to reduce noise."""

    def __init__(
        self,
        dedup_window_sec: int = 60,
        correlation_window_sec: int = 300,
        min_alerts_for_incident: int = 2,
    ):
        self.dedup_window = timedelta(seconds=dedup_window_sec)
        self.correlation_window = timedelta(seconds=correlation_window_sec)
        self.min_alerts_for_incident = min_alerts_for_incident

        # Dedup state: key → window_end of the last alert kept (bounded LRU)
        self._dedup_cache: OrderedDict[str, datetime] = OrderedDict()
        self._suppressed_count: int = 0
        self._total_processed: int = 0

    @staticmethod
    def dedup_key(alert: Alert) -> str:
        return "|".join((
            alert.threat_class.value,
            alert.source_ip or "*",
            alert.destination_ip or "*",
            alert.detector_name,
        ))

    def deduplicate(self, alerts: Iterable[Alert]) -> list[Alert]:
        """Drop alerts repeating an alert kept within the dedup window (event time)."""
        unique: list[Alert] = []
        for alert in alerts:
            self._total_processed += 1
            key = self.dedup_key(alert)
            last_end = self._dedup_cache.get(key)
            if last_end is not None and timedelta(0) <= alert.window_end - last_end < self.dedup_window:
                self._suppressed_count += 1
                continue
            self._dedup_cache[key] = alert.window_end
            self._dedup_cache.move_to_end(key)
            if len(self._dedup_cache) > _DEDUP_CACHE_LIMIT:
                self._dedup_cache.popitem(last=False)
            unique.append(alert)
        return unique

    def state_dict(self) -> dict[str, Any]:
        return {"dedup": [[key, to_epoch_us(t)] for key, t in self._dedup_cache.items()]}

    def load_state_dict(self, state: dict[str, Any]) -> None:
        self._dedup_cache = OrderedDict((key, from_epoch_us(t)) for key, t in state["dedup"][-_DEDUP_CACHE_LIMIT:])

    def correlate(self, alerts: Iterable[Alert]) -> list[dict[str, Any]]:
        """
        Group alerts into incidents per entity, splitting an entity's alerts
        wherever consecutive alerts are more than ``correlation_window`` apart.
        """
        by_entity: dict[str, list[Alert]] = defaultdict(list)
        for alert in alerts:
            entity = alert.source_ip or alert.destination_ip or "unknown"
            by_entity[entity].append(alert)

        incidents: list[dict[str, Any]] = []
        for entity, entity_alerts in by_entity.items():
            entity_alerts.sort(key=lambda a: a.window_end)
            group: list[Alert] = []
            for alert in entity_alerts:
                if group and alert.window_start - group[-1].window_end > self.correlation_window:
                    self._emit_incident(entity, group, incidents)
                    group = []
                group.append(alert)
            self._emit_incident(entity, group, incidents)

        incidents.sort(key=lambda i: (sev.RANK[Severity(i["severity"])], i["last_seen"]), reverse=True)
        return incidents

    def _emit_incident(self, entity: str, group: list[Alert], out: list[dict[str, Any]]) -> None:
        if len(group) < self.min_alerts_for_incident:
            return
        classes = sorted({a.threat_class.value for a in group})
        highest = sev.max_severity(a.severity for a in group)
        if len(classes) >= 3:
            incident_severity = Severity.CRITICAL          # multi-vector
        elif len(classes) == 2:
            incident_severity = sev.escalate(highest)      # multi-stage
        else:
            incident_severity = highest
        first, last = group[0], group[-1]
        digest = hashlib.sha1(f"{entity}|{first.window_start.isoformat()}".encode()).hexdigest()[:8]
        out.append({
            "incident_id": f"INC-{digest.upper()}",
            "entity": entity,
            "source_ip": entity if any(a.source_ip == entity for a in group) else None,
            "alert_count": len(group),
            "alert_ids": [a.alert_id for a in group],
            "threat_classes": classes,
            "detectors": sorted({a.detector_name for a in group}),
            "severity": incident_severity.value,
            "first_seen": first.window_start.isoformat(),
            "last_seen": last.window_end.isoformat(),
            "time_span_sec": round((last.window_end - first.window_start).total_seconds(), 2),
            "avg_confidence": round(sum(a.confidence for a in group) / len(group), 4),
            "is_multi_stage": len(classes) >= 2,
            "is_multi_vector": len(classes) >= 3,
            "mitre_techniques": sorted({t for a in group for t in a.mitre_techniques}),
        })

    def process(self, alerts: list[Alert]) -> tuple[list[Alert], list[dict[str, Any]]]:
        """Deduplicate then correlate."""
        deduped = self.deduplicate(alerts)
        return deduped, self.correlate(deduped)

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
            "suppression_rate": round(self._suppressed_count / max(self._total_processed, 1), 4),
        }

    def clear(self) -> None:
        """Reset the correlator state."""
        self._dedup_cache.clear()
        self._suppressed_count = 0
        self._total_processed = 0
