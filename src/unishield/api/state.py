"""
UniShield — API Application State

One AppContext per FastAPI app: the alert repository (created lazily from
``database.url`` on first use), the threat-intel store, the account store
and the audit log in the same database, the login rate limiter, the output
service (exports, syslog, notifications; started on first use, inactive
unless configured), the replay worker thread and its
status, and the live pipeline whose metrics the API reports.

Replays run the pipeline in a background thread with the imported
indicators loaded at start; alerts are written to the repository as the
pipeline emits them, so they are visible through the API while the replay
is still running, and then handed to the output service.

Lifecycle (driven by the application's lifespan): ``start_services``
records ``system.start`` with the security-relevant configuration and
starts housekeeping; ``shutdown`` (SIGTERM / Ctrl+C under uvicorn) stops
housekeeping and any replay, waits for the replay to record its state,
drains the output service, records ``system.stop`` and releases the
database connections.
"""

from __future__ import annotations

import logging
import threading
import time
import uuid
from typing import Any, Optional

from unishield.accounts import AccountStore, Role
from unishield.accounts.ratelimit import LoginRateLimiter
from unishield.config import UnishieldConfig, get_config
from unishield.export.service import OutputService
from unishield.intel.matcher import IntelMatcher
from unishield.intel.store import IntelStore
from unishield.processing.pipeline import Pipeline
from unishield.schemas.alert import Alert
from unishield.storage import AlertRepository, AuditLog, AuditQuery, migrate
from unishield.storage.retention import MaintenanceWorker, housekeeping

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


def config_summary(config: UnishieldConfig) -> dict[str, Any]:
    """Configuration that affects security and data handling (no secrets, no database credentials)."""
    return {
        "environment": config.environment,
        "auth_mode": config.auth.mode,
        "cookie_secure": config.auth.cookie_secure,
        "session_ttl_minutes": config.auth.session_ttl_minutes,
        "session_idle_minutes": config.auth.session_idle_minutes,
        "max_failed_logins": config.auth.max_failed_logins,
        "static_api_key": bool(config.api.admin_api_key),
        "static_api_key_role": config.api.api_key_role if config.api.admin_api_key else None,
        "docs_enabled": config.api.docs_enabled,
        "tls": config.tls.enabled,
        "forwarded_allow_ips": config.api.forwarded_allow_ips,
        "cors_origins": list(config.api.cors_origins),
        "database_backend": config.database.url.split(":", 1)[0].split("+", 1)[0],
        "alert_retention_days": config.retention.alert_days,
        "detection_mode": config.models.detection_mode,
        "anonymize_ips": config.security.anonymize_ips,
    }


class AppContext:
    """State shared by the API routes of one application instance."""

    def __init__(self, repository: AlertRepository | None = None):
        self._repository = repository
        self._intel: Optional[IntelStore] = None
        self._outputs: Optional[OutputService] = None
        self._accounts: Optional[AccountStore] = None
        self._audit: Optional[AuditLog] = None
        self._limiter: Optional[LoginRateLimiter] = None
        self._lock = threading.Lock()
        self.started = time.time()
        self.replay: dict[str, Any] = dict(_IDLE)
        self.pipeline: Optional[Pipeline] = None
        self.thread: Optional[threading.Thread] = None
        self.maintenance: Optional[MaintenanceWorker] = None
        self._model_status: Optional[str] = None

    # --- storage ------------------------------------------------------------

    @property
    def repository(self) -> AlertRepository:
        if self._repository is None:
            with self._lock:
                if self._repository is None:
                    cfg = get_config().database
                    self._repository = AlertRepository.from_url(cfg.url, cfg.echo, cfg.auto_migrate)
        return self._repository

    def use_repository(self, repository: AlertRepository) -> None:
        self._repository = repository
        self._intel = None
        self._accounts = self._audit = None

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

    @property
    def accounts(self) -> AccountStore:
        if self._accounts is None:
            self._accounts = AccountStore(self.repository.engine)
        return self._accounts

    @property
    def audit(self) -> AuditLog:
        if self._audit is None:
            self._audit = AuditLog(self.repository.engine)
        return self._audit

    @property
    def limiter(self) -> LoginRateLimiter:
        if self._limiter is None:
            cfg = get_config().auth
            self._limiter = LoginRateLimiter(cfg.login_rate_limit, cfg.login_rate_window_sec)
        return self._limiter

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
        deleted = self.repository.delete_all() if clear else 0
        self.repository.start_run(run_id, source, pipeline.detection_mode)
        self.thread = threading.Thread(target=self._run, args=(pipeline, reader, run_id),
                                       name=f"replay-{run_id}", daemon=True)
        self.thread.start()
        return {"status": "started", "run_id": run_id, "source": source, "format": fmt,
                "detection_mode": pipeline.detection_mode, "alerts_deleted": deleted}

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

    # --- service lifecycle ----------------------------------------------------------

    def start_services(self) -> None:
        config = get_config()
        summary = config_summary(config)
        previous, _ = self.audit.list(AuditQuery(action="system.start", limit=1))
        changed = sorted(k for k, v in summary.items()
                         if previous and previous[0]["details"].get(k, v) != v) if previous else []
        from unishield import __version__

        self.audit.record("system.start", details=dict(summary, version=__version__, changed_since_last_start=changed))
        self._model_status = self._check_models()
        self.maintenance = MaintenanceWorker(self.housekeeping, config.retention.interval_minutes * 60)
        self.maintenance.start()

    def housekeeping(self) -> dict[str, Any]:
        config = get_config()
        return housekeeping(self.repository, self.accounts, self.audit, config.retention.alert_days,
                            config.auth.session_idle_minutes)

    def shutdown(self, timeout: float) -> dict[str, Any]:
        """Stop housekeeping and any replay (waiting up to ``timeout`` s), record the stop, release the database."""
        if self.maintenance is not None:
            self.maintenance.stop()
        run_id = self.replay.get("run_id") if self.running else None
        clean = True
        if run_id:
            logger.info("Shutting down: stopping replay %s", run_id)
            self.stop_replay()
            self.wait(timeout)
            if self.thread is not None and self.thread.is_alive():
                clean = False
                logger.warning("Replay %s did not stop within %.0f s; recording it as interrupted", run_id, timeout)
                self.replay.update(status="interrupted", finished_at=time.time())
                try:
                    self.repository.finish_run(run_id, "interrupted", None)
                except Exception as e:                    # pragma: no cover - defensive
                    logger.error("Could not record run %s: %s", run_id, e)
        self.stop_outputs()                               # deliver queued exports/notifications, then stop
        result = {"replay_stopped": run_id, "replay_finished_cleanly": clean}
        try:
            self.audit.record("system.stop", details=result)
        except Exception as e:                            # pragma: no cover - database already gone
            logger.error("Could not record the shutdown: %s", e)
        self.repository.engine.dispose()
        return result

    # --- health ------------------------------------------------------------------------

    def _check_models(self) -> str:
        models = get_config().models
        if models.detection_mode == "rules":
            return "not used (rules mode)"
        from unishield.models.registry import ModelRegistry

        try:
            results = ModelRegistry().verify(models.window_model)
        except Exception as e:                            # pragma: no cover - unreadable registry
            return f"error: {e}"
        if not results:
            return "missing (falls back to rules)"
        return {"ok": "ok", "missing": "artifact missing", "mismatch": "SHA-256 mismatch"}[results[0]["status"]]

    def health(self) -> dict[str, Any]:
        """Component states; ``degraded`` lists the components that need attention."""
        config = get_config()
        components: dict[str, str] = {}
        degraded: list[str] = []

        storage_ok = self.repository.ping()
        components["storage"] = "connected" if storage_ok else "unavailable"
        if storage_ok:
            current = migrate.is_current(self.repository.engine)
            components["schema"] = "current" if current else "outdated (run unishield-admin db upgrade)"
            if not current:
                degraded.append("schema")
            if config.auth.mode == "open":
                components["accounts"] = "open mode (lab only)"
            elif any(u.role == Role.ADMIN and not u.disabled for u in self.accounts.list_users()) or (
                    config.api.admin_api_key and config.api.api_key_role == "admin"):
                components["accounts"] = "ok"
            else:
                components["accounts"] = "no active administrator (unishield-admin user create)"
                degraded.append("accounts")
        else:
            degraded.append("storage")

        worker = self.maintenance
        if worker is None:
            components["housekeeping"] = "not started"
        elif not worker.alive:
            components["housekeeping"] = "stopped"
            degraded.append("housekeeping")
        elif worker.last_error:
            components["housekeeping"] = f"failing: {worker.last_error}"
            degraded.append("housekeeping")
        else:
            components["housekeeping"] = "ok" + ("" if config.retention.alert_days else " (alert retention off)")

        replay = self.replay["status"]
        components["replay"] = replay
        if replay in ("failed", "interrupted"):
            degraded.append("replay")

        if self._model_status is None:
            self._model_status = self._check_models()
        components["models"] = self._model_status
        if config.models.detection_mode != "rules" and self._model_status != "ok":
            degraded.append("models")

        running = self.running
        components.update(ingest="running" if running else "idle", processing="running" if running else "idle",
                          detection="running" if running else "idle", api="running")
        status = "unhealthy" if not storage_ok else "degraded" if degraded else "healthy"
        return {"status": status, "storage_ok": storage_ok, "components": components, "degraded": degraded}

    def reset(self) -> None:
        """Wait for any replay to finish and return to idle (tests)."""
        self.stop_replay()
        self.wait(30)
        self.stop_outputs()
        self.replay = dict(_IDLE)
        self.pipeline = None
        self.thread = None
