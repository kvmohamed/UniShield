"""
UniShield — Output service

Delivers stored alerts to the configured analyst-side outputs without
slowing detection: the pipeline thread only puts alerts on a bounded queue
(``outbound.queue_size``; alerts beyond it are counted as dropped, never
blocking), and one worker thread

    1. groups recent alerts into incidents (new or changed ones),
    2. appends alerts/incidents to the continuous export files,
    3. forwards them to each syslog destination,
    4. offers alerts to the email/webhook channels and sends any message
       their rate limits allow (single alerts or digests).

With every output off (the default) the service is inactive and starts no
thread. ``status()`` reports configuration and counters without secrets
(webhook URLs are reduced to scheme, host and port).
"""

from __future__ import annotations

import logging
import queue
import threading
import time
from typing import Any, Callable, Optional

from unishield.export.files import ContinuousFileExporter
from unishield.export.incidents import IncidentTracker
from unishield.export.notify import NotificationChannel, email_channel, webhook_channel
from unishield.export.policy import DestinationPolicy
from unishield.export.syslog import SyslogForwarder
from unishield.schemas.alert import Alert

logger = logging.getLogger("unishield.export.service")

_BATCH = 500
_TICK_SEC = 1.0


class OutputService:
    def __init__(self, config, clock: Callable[[], float] = time.monotonic):
        self.config = config
        out, exp = config.outbound, config.export
        self.files: Optional[ContinuousFileExporter] = None
        if exp.continuous:
            try:
                self.files = ContinuousFileExporter.from_config(config)
            except OSError as exc:
                logger.error("Continuous export disabled: cannot use %s: %s", exp.directory, exc)
        network = out.syslog.enabled or out.email.enabled or out.webhook.enabled
        self.policy: Optional[DestinationPolicy] = DestinationPolicy.from_config(config) if network else None
        timeout = out.connect_timeout_sec
        self.syslog: list[SyslogForwarder] = [
            SyslogForwarder(d, out.syslog, self.policy, timeout) for d in out.syslog.destinations
        ] if out.syslog.enabled else []
        self.channels: list[NotificationChannel] = []
        if out.email.enabled:
            self.channels.append(email_channel(out.email, self.policy, timeout, clock))
        if out.webhook.enabled:
            self.channels += [webhook_channel(d, self.policy, timeout, clock) for d in out.webhook.destinations]
        wants_incidents = (self.files is not None and exp.include_incidents) or any(
            f.include_incidents for f in self.syslog)
        self.tracker = IncidentTracker(exp.incident_gap_sec, exp.incident_min_alerts) if wants_incidents else None
        self._queue: queue.Queue = queue.Queue(maxsize=out.queue_size)
        self._thread: Optional[threading.Thread] = None
        self._stopping = threading.Event()
        self.received = 0
        self.dropped = 0
        self.processed = 0
        self.errors = 0

    @property
    def active(self) -> bool:
        return bool(self.files or self.syslog or self.channels)

    # --- lifecycle -------------------------------------------------------------

    def start(self) -> None:
        if not self.active or (self._thread is not None and self._thread.is_alive()):
            return
        self._stopping.clear()
        self._thread = threading.Thread(target=self._run, name="unishield-outputs", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 10.0) -> None:
        if self._thread is None:
            return
        self._stopping.set()
        self._thread.join(timeout)
        self._thread = None

    def submit(self, alert: Alert) -> None:
        """Called from the pipeline thread after an alert is stored. Never blocks."""
        if not self.active:
            return
        self.received += 1
        try:
            self._queue.put_nowait(alert)
        except queue.Full:
            self.dropped += 1

    def drain(self, timeout: float = 10.0) -> bool:
        """Wait until every submitted alert has been processed (tests, shutdown). True if drained."""
        deadline = time.monotonic() + timeout
        while self._queue.unfinished_tasks and time.monotonic() < deadline:
            time.sleep(0.01)
        return not self._queue.unfinished_tasks

    # --- worker ----------------------------------------------------------------

    def _run(self) -> None:
        while not self._stopping.is_set() or not self._queue.empty():
            batch: list[Alert] = []
            try:
                batch.append(self._queue.get(timeout=_TICK_SEC))
                while len(batch) < _BATCH:
                    batch.append(self._queue.get_nowait())
            except queue.Empty:
                pass
            try:
                self.process(batch)
            except Exception as exc:                      # pragma: no cover - defensive: keep the worker alive
                self.errors += 1
                logger.error("Output processing failed: %s", exc, exc_info=True)
            finally:
                for _ in batch:
                    self._queue.task_done()

    def process(self, alerts: list[Alert]) -> None:
        """Deliver one batch to every output (also callable directly, without the thread)."""
        incidents = self.tracker.update(alerts) if self.tracker is not None and alerts else []
        if self.files is not None and alerts:
            self.files.write(alerts, incidents if self.config.export.include_incidents else [],
                             self.tracker.alerts() if self.tracker is not None else None)
        for forwarder in self.syslog:
            if alerts or incidents:
                forwarder.forward(alerts, incidents)
        for channel in self.channels:
            for alert in alerts:
                channel.offer(alert)
            channel.flush()
        self.processed += len(alerts)

    # --- status ----------------------------------------------------------------

    def status(self) -> dict[str, Any]:
        out, exp = self.config.outbound, self.config.export
        return {
            "active": self.active,
            "worker_running": self._thread is not None and self._thread.is_alive(),
            "queue": {"size": self._queue.qsize(), "capacity": out.queue_size, "received": self.received,
                      "processed": self.processed, "dropped": self.dropped, "errors": self.errors},
            "allowed_destinations": list(out.allowed_destinations),
            "monitored_networks": list(self.config.network.home_networks),
            "files": self.files.status() if self.files is not None else {
                "enabled": False, "directory": exp.directory, "formats": list(exp.formats)},
            "syslog": {"enabled": out.syslog.enabled, "facility": out.syslog.facility,
                       "destinations": [f.status() for f in self.syslog]},
            "notifications": [c.status() for c in self.channels],
            "email_enabled": out.email.enabled,
            "webhook_enabled": out.webhook.enabled,
        }
