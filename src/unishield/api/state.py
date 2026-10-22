"""
UniShield — API Application State

One AppContext per FastAPI app: the alert repository (created lazily from
``database.url`` on first use), the threat-intel store in the same
database, the output service (exports, syslog, notifications; started on
first use, inactive unless configured), the replay worker thread and its
status, and the live pipeline whose metrics the API reports.

Replays run the pipeline in a background thread with the imported
indicators loaded at start; alerts are written to the repository as the
pipeline emits them, so they are visible through the API while the replay
is still running, and then handed to the output service.
"""

from __future__ import annotations

import logging
import threading
import time
import uuid
from typing import Any, Optional

from unishield.config import get_config
from unishield.export.service import OutputService
from unishield.intel.matcher import IntelMatcher
from unishield.intel.store import IntelStore
from unishield.processing.pipeline import Pipeline
from unishield.schemas.alert import Alert
from unishield.storage import AlertRepository

logger = logging.getLogger("unishield.api.state")

_IDLE = {
    "status": "idle",
    "run_id": None,
    "source": None,
    "format": None,
    "detection_mode": None,
    "started_at": None,
    "finished_at": None,
    "records_processed": 0,
    "alerts_generated": 0,
    "error": None,
    "result": None,
}


class AppContext:
    """State shared by the API routes of one application instance."""

    def __init__(self, repository: AlertRepository | None = None):
        self._repository = repository
        self._intel: Optional[IntelStore] = None
        self._outputs: Optional[OutputService] = None
        self._lock = threading.Lock()
        self.started = time.time()
        self.replay: dict[str, Any] = dict(_IDLE)
        self.pipeline: Optional[Pipeline] = None
        self.thread: Optional[threading.Thread] = None

    # --- storage ------------------------------------------------------------

    @property
    def repository(self) -> AlertRepository:
        if self._repository is None:
            with self._lock:
                if self._repository is None:
                    cfg = get_config().database
                    self._repository = AlertRepository.from_url(cfg.url, cfg.echo)
        return self._repository

    def use_repository(self, repository: AlertRepository) -> None:
        self._repository = repository
        self._intel = None

    @property
    def intel(self) -> IntelStore:
        if self._intel is None:
            self._intel = IntelStore(self.repository.engine)
        return self._intel

    def intel_matcher(self) -> IntelMatcher:
        """Active indicators for a new run (hashed like the flows when IPs are anonymised)."""
        config = get_config()
        if not config.intel.enabled:
            return IntelMatcher()
        salt = config.security.ip_hash_salt if config.security.anonymize_ips else None
        return self.intel.matcher(anonymize_salt=salt)

    # --- outputs --------------------------------------------------------------

    @property
    def outputs(self) -> OutputService:
        if self._outputs is None:
            with self._lock:
                if self._outputs is None:
                    service = OutputService(get_config())
                    service.start()
                    self._outputs = service
        return self._outputs

    def stop_outputs(self) -> None:
        if self._outputs is not None:
            self._outputs.drain(5)
            self._outputs.stop()
            self._outputs = None

    # --- replay -------------------------------------------------------------

    @property
    def running(self) -> bool:
        return self.replay["status"] == "running"

    def start_replay(self, reader, source: str, fmt: str, clear: bool = True,
                     detection_mode: str | None = None) -> dict[str, Any]:
        """Start the pipeline on ``reader`` in a background thread. Raises RuntimeError if one is running."""
        intel = self.intel_matcher()                    # outside the lock: may create the repository
        with self._lock:
            if self.running:
                raise RuntimeError("Replay already running")
            pipeline = Pipeline(alert_callback=self._store_alert, detection_mode=detection_mode, intel=intel)
            run_id = f"run-{time.strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"
            self.pipeline = pipeline
            self.replay = dict(_IDLE, status="running", run_id=run_id, source=source, format=fmt,
                               detection_mode=pipeline.detection_mode, started_at=time.time())
        if clear:
            self.repository.delete_all()
        self.repository.start_run(run_id, source, pipeline.detection_mode)
        self.thread = threading.Thread(target=self._run, args=(pipeline, reader, run_id),
                                       name=f"replay-{run_id}", daemon=True)
        self.thread.start()
        return {"status": "started", "run_id": run_id, "source": source, "format": fmt,
                "detection_mode": pipeline.detection_mode}

    def _store_alert(self, alert: Alert) -> None:
        alert.run_id = self.replay.get("run_id")
        self.repository.add(alert)
        self.replay["alerts_generated"] += 1
        self.outputs.submit(alert)

    def _run(self, pipeline: Pipeline, reader, run_id: str) -> None:
        status, summary = "completed", None
        try:
            result = pipeline.run(reader)
            summary = result.summary()
            self.replay["records_processed"] = result.total_records
            if pipeline._should_stop:
                status = "stopped"
            elif result.errors:
                status = "failed"
                self.replay["error"] = "pipeline error (see server log)"
        except Exception as e:                            # pragma: no cover - defensive
            logger.error("Replay failed: %s", e, exc_info=True)
            status = "failed"
            self.replay["error"] = str(e)
        self.replay.update(status=status, finished_at=time.time(), result=summary)
        try:
            self.repository.finish_run(run_id, status, summary)
        except Exception as e:                            # pragma: no cover - defensive
            logger.error("Could not record run %s: %s", run_id, e)

    def stop_replay(self) -> bool:
        if self.pipeline is not None and self.running:
            self.pipeline.stop()
            return True
        return False

    def wait(self, timeout: float) -> None:
        thread = self.thread
        if thread is not None:
            thread.join(timeout)

    def status(self) -> dict[str, Any]:
        state = dict(self.replay)
        if self.pipeline is not None and self.running:
            state["records_processed"] = self.pipeline.get_metrics().total_records_ingested
        start, end = state.get("started_at"), state.get("finished_at")
        state["elapsed_seconds"] = round((end or time.time()) - start, 3) if start else 0.0
        return state

    def reset(self) -> None:
        """Wait for any replay to finish and return to idle (tests)."""
        self.stop_replay()
        self.wait(30)
        self.stop_outputs()
        self.replay = dict(_IDLE)
        self.pipeline = None
        self.thread = None
