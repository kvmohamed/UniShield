"""
UniShield — Incremental incident tracking for continuous outputs

Incidents are normally computed on request from the stored alerts
(``GET /incidents``). Continuous exports and forwarding need them as they
form, so IncidentTracker keeps the recent alerts (bounded by traffic time
and count), re-correlates them when new alerts arrive and returns the
incidents that are new or changed (more alerts or a different severity).

SECURITY CONSTRAINTS:
    - Pure computation over alerts in memory. No network I/O.
"""

from __future__ import annotations

from collections import deque
from datetime import timedelta
from typing import Any, Iterable

from unishield.correlation.correlator import AlertCorrelator
from unishield.schemas.alert import Alert


class IncidentTracker:
    def __init__(self, gap_sec: int = 300, min_alerts: int = 2, horizon_sec: int = 3600, max_alerts: int = 5000):
        self._correlator = AlertCorrelator(correlation_window_sec=gap_sec, min_alerts_for_incident=min_alerts)
        self._horizon = timedelta(seconds=horizon_sec)
        self._alerts: deque[Alert] = deque(maxlen=max_alerts)
        self._reported: dict[str, tuple[int, str]] = {}

    def update(self, alerts: Iterable[Alert]) -> list[dict[str, Any]]:
        """Add alerts; return incidents that are new or changed since the last call."""
        added = list(alerts)
        if not added:
            return []
        self._alerts.extend(added)
        newest = max(a.window_end for a in self._alerts)
        while self._alerts and newest - self._alerts[0].window_end > self._horizon:
            self._alerts.popleft()
        current = self._correlator.correlate(list(self._alerts))
        changed = []
        for incident in current:
            state = (incident["alert_count"], incident["severity"])
            if self._reported.get(incident["incident_id"]) != state:
                changed.append(incident)
        self._reported = {i["incident_id"]: (i["alert_count"], i["severity"]) for i in current}
        return changed

    def alerts(self) -> dict[str, Alert]:
        return {a.alert_id: a for a in self._alerts}
