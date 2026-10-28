"""
UniShield — Retention and Housekeeping

``housekeeping`` deletes alerts stored more than ``retention.alert_days``
ago (and finished runs older than that) and expired login sessions, and
records an audit entry when it deleted alerts or runs. The audit log itself
is never purged. ``MaintenanceWorker`` runs it in a background thread every
``retention.interval_minutes`` while the API is up; ``unishield-admin
retention run`` runs it once (e.g. from cron or a scheduled task).
"""

from __future__ import annotations

import logging
import threading
import time
from datetime import timedelta
from typing import Any, Callable, Optional

from unishield.schemas.timeutil import utc_now

logger = logging.getLogger("unishield.storage.retention")


def housekeeping(repository, accounts, audit, alert_days: Optional[int], session_idle_minutes: int, *,
                 actor: str = "system", actor_type: str = "system") -> dict[str, Any]:
    """One housekeeping pass; returns what was deleted."""
    result: dict[str, Any] = {"alerts": 0, "runs": 0, "sessions": 0, "cutoff": None}
    if alert_days:
        cutoff = utc_now() - timedelta(days=alert_days)
        result["alerts"], result["runs"] = repository.delete_stored_before(cutoff)
        result["cutoff"] = cutoff.isoformat()
        if result["alerts"] or result["runs"]:
            audit.record("retention.purge", actor=actor, actor_type=actor_type, target="alerts",
                         details={"alert_days": alert_days, **result})
            logger.info("Retention: deleted %d alerts and %d runs stored before %s",
                        result["alerts"], result["runs"], result["cutoff"])
    result["sessions"] = accounts.purge_expired_sessions(session_idle_minutes)
    return result


class MaintenanceWorker:
    """Calls ``task`` now and then every ``interval_sec`` in a daemon thread until stopped."""

    def __init__(self, task: Callable[[], dict[str, Any]], interval_sec: float):
        self.task, self.interval = task, interval_sec
        self.last_run: Optional[float] = None
        self.last_result: Optional[dict[str, Any]] = None
        self.last_error: Optional[str] = None
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def run_once(self) -> None:
        try:
            self.last_result = self.task()
            self.last_error = None
        except Exception as exc:                            # reported by /health, retried next interval
            logger.error("Housekeeping failed: %s", exc, exc_info=True)
            self.last_error = f"{type(exc).__name__}: {exc}"
        self.last_run = time.time()

    def _loop(self) -> None:
        while not self._stop.is_set():
            self.run_once()
            self._stop.wait(self.interval)

    def start(self) -> None:
        self._thread = threading.Thread(target=self._loop, name="unishield-maintenance", daemon=True)
        self._thread.start()

    @property
    def alive(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout)
