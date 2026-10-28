"""Service operation: retention and housekeeping, start/stop audit, graceful shutdown, component health."""

from __future__ import annotations

import threading
import time
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import update

from unishield import cli
from unishield.accounts import AccountStore
from unishield.api.app import create_app
from unishield.config import get_config, reset_config
from unishield.data.sample_generator import SimulatedReader, build_scenario
from unishield.schemas.timeutil import utc_now
from unishield.storage import AlertRepository, AuditLog, AuditQuery
from unishield.storage.database import alerts_table, runs_table, users_table
from unishield.storage.retention import MaintenanceWorker, housekeeping
from tests.unit.test_api import _alert


@pytest.fixture
def file_repo(tmp_path):
    return AlertRepository.from_url(f"sqlite:///{(tmp_path / 'service.db').as_posix()}")


@pytest.fixture(autouse=True)
def _fresh_config(monkeypatch):
    for var in ("UNISHIELD_AUTH_MODE", "UNISHIELD_ADMIN_API_KEY", "UNISHIELD_ALERT_RETENTION_DAYS"):
        monkeypatch.delenv(var, raising=False)
    reset_config()
    yield
    reset_config()


def _age(repo, alert_ids, days):
    with repo.engine.begin() as conn:
        conn.execute(update(alerts_table).where(alerts_table.c.alert_id.in_(alert_ids))
                     .values(stored_at=(utc_now() - timedelta(days=days)).replace(tzinfo=None)))


# --- retention ------------------------------------------------------------------

def test_housekeeping_deletes_only_expired_alerts_runs_and_sessions(file_repo):
    alerts = [_alert(i) for i in range(5)]
    file_repo.add_many(alerts)
    _age(file_repo, [a.alert_id for a in alerts[:3]], days=40)
    file_repo.start_run("run-old", "x", "rules")
    file_repo.finish_run("run-old", "completed")
    file_repo.start_run("run-new", "x", "rules")
    with file_repo.engine.begin() as conn:
        conn.execute(update(runs_table).where(runs_table.c.run_id == "run-old")
                     .values(finished_at=(utc_now() - timedelta(days=40)).replace(tzinfo=None)))
    accounts, audit = AccountStore(file_repo.engine), AuditLog(file_repo.engine)

    result = housekeeping(file_repo, accounts, audit, alert_days=30, session_idle_minutes=30)
    assert (result["alerts"], result["runs"]) == (3, 1)
    assert file_repo.count() == 2 and [r["run_id"] for r in file_repo.runs()] == ["run-new"]
    (entry,), _ = audit.list(AuditQuery(action="retention.purge"))
    assert entry["actor"] == "system" and entry["details"]["alerts"] == 3 and entry["details"]["alert_days"] == 30

    again = housekeeping(file_repo, accounts, audit, alert_days=30, session_idle_minutes=30)
    assert again["alerts"] == 0 and audit.list(AuditQuery(action="retention.purge"))[1] == 1   # no empty entries
    off = housekeeping(file_repo, accounts, audit, alert_days=None, session_idle_minutes=30)
    assert off["alerts"] == 0 and file_repo.count() == 2


def test_cli_retention_run(tmp_path, file_repo, monkeypatch, capsys):
    url = str(file_repo.engine.url)
    alerts = [_alert(i) for i in range(4)]
    file_repo.add_many(alerts)
    _age(file_repo, [alerts[0].alert_id], days=10)
    assert cli.main(["--db-url", url, "retention", "run"]) == 1                 # no period configured
    assert "retention.alert_days" in capsys.readouterr().err
    assert cli.main(["--db-url", url, "retention", "run", "--days", "7"]) == 0
    assert "Deleted 1 alerts" in capsys.readouterr().out
    monkeypatch.setenv("UNISHIELD_ALERT_RETENTION_DAYS", "1")
    reset_config()
    _age(file_repo, [alerts[1].alert_id], days=2)
    assert cli.main(["--db-url", url, "retention", "run"]) == 0
    assert file_repo.count() == 2
    actors = {e["actor"] for e in AuditLog(file_repo.engine).list(AuditQuery(action="retention.purge"))[0]}
    assert len(actors) == 1 and actors.pop().startswith("cli:")
    assert cli.main(["--db-url", url, "retention", "run", "--days", "0"]) == 1


def test_maintenance_worker_runs_periodically_and_reports_errors():
    calls = []

    def task():
        calls.append(time.time())
        if len(calls) == 2:
            raise RuntimeError("disk full")
        return {"alerts": 0}

    worker = MaintenanceWorker(task, interval_sec=0.05)
    worker.start()
    deadline = time.time() + 5
    while len(calls) < 2 and time.time() < deadline:
        time.sleep(0.01)
    time.sleep(0.02)
    assert worker.alive and worker.last_error == "RuntimeError: disk full"
    while len(calls) < 3 and time.time() < deadline:
        time.sleep(0.01)
    time.sleep(0.02)
    assert worker.last_error is None and worker.last_result == {"alerts": 0}
    worker.stop()
    assert not worker.alive


# --- lifecycle --------------------------------------------------------------------

def test_lifespan_records_start_stop_and_configuration_changes(file_repo, monkeypatch):
    with TestClient(create_app(file_repo)) as client:
        assert client.app.state.ctx.maintenance.alive
        assert client.get("/health").json()["components"]["housekeeping"].startswith("ok")
    entries, _ = AuditLog(file_repo.engine).list(AuditQuery(action="system."))
    assert [e["action"] for e in entries] == ["system.stop", "system.start"]
    start = entries[1]["details"]
    assert start["auth_mode"] == "accounts" and start["alert_retention_days"] is None
    assert start["changed_since_last_start"] == [] and "url" not in str(start).lower()
    assert entries[0]["details"] == {"replay_stopped": None, "replay_finished_cleanly": True}

    monkeypatch.setenv("UNISHIELD_ALERT_RETENTION_DAYS", "90")
    monkeypatch.setenv("UNISHIELD_ADMIN_API_KEY", "a-static-key-for-the-test")
    reset_config()
    with TestClient(create_app(file_repo)):
        pass
    latest = AuditLog(file_repo.engine).list(AuditQuery(action="system.start", limit=1))[0][0]["details"]
    assert latest["changed_since_last_start"] == ["alert_retention_days", "static_api_key", "static_api_key_role"]
    assert "a-static-key-for-the-test" not in str(latest)


class SlowReader(SimulatedReader):
    """Yields flows slowly so a run is still going when the service stops; optionally gets stuck."""

    def __init__(self, flows, delay=0.005, stuck: threading.Event | None = None):
        super().__init__(flows)
        self.delay, self.stuck = delay, stuck

    def read(self):
        for i, flow in enumerate(super().read()):
            if self.stuck is not None and i == 5:
                self.stuck.wait(10)
            time.sleep(self.delay)
            yield flow


def test_shutdown_stops_a_running_replay_and_records_it(file_repo):
    app = create_app(file_repo)
    ctx = app.state.ctx
    started = ctx.start_replay(SlowReader(build_scenario("dga", 1).flows), "test", "simulated")
    time.sleep(0.1)
    assert ctx.outputs is not None                       # the run hands alerts to the output service
    result = ctx.shutdown(timeout=10)
    assert result == {"replay_stopped": started["run_id"], "replay_finished_cleanly": True}
    assert ctx._outputs is None                           # drained and stopped
    (run,) = file_repo.runs()
    assert run["run_id"] == started["run_id"] and run["status"] == "stopped" and run["finished_at"]
    (entry,), _ = AuditLog(file_repo.engine).list(AuditQuery(action="system.stop"))
    assert entry["details"]["replay_stopped"] == started["run_id"]


def test_shutdown_records_a_replay_that_does_not_stop_in_time_as_interrupted(file_repo):
    app = create_app(file_repo)
    ctx = app.state.ctx
    stuck = threading.Event()
    started = ctx.start_replay(SlowReader(build_scenario("dga", 1).flows, stuck=stuck), "test", "simulated")
    time.sleep(0.1)
    try:
        result = ctx.shutdown(timeout=0.2)
        assert result["replay_finished_cleanly"] is False
        assert file_repo.runs()[0]["status"] == "interrupted"
        assert ctx.health()["degraded"] == ["accounts", "replay"]
    finally:
        stuck.set()
        ctx.wait(10)
    assert started["run_id"] == result["replay_stopped"]


# --- health -------------------------------------------------------------------------

def _health(client):
    response = client.get("/health")
    return response.status_code, response.json()


def test_health_is_healthy_with_an_administrator(api_client):
    client, _ = api_client
    code, body = _health(client)
    assert code == 200 and body["status"] == "healthy" and body["degraded_components"] == []
    components = body["components"]
    assert components["storage"] == "connected" and components["schema"] == "current"
    assert components["accounts"] == "ok" and components["models"] == "not used (rules mode)"
    assert body["auth_mode"] == "accounts"


def test_health_reports_degraded_components(api_client, monkeypatch, tmp_path):
    client, _ = api_client
    ctx = client.app.state.ctx
    with ctx.repository.engine.begin() as conn:                           # the API refuses this; the DB does not
        conn.execute(update(users_table).values(disabled=True))
    code, body = _health(client)
    assert code == 200 and body["status"] == "degraded" and body["degraded_components"] == ["accounts"]
    assert "unishield-admin user create" in body["components"]["accounts"]

    monkeypatch.setattr("unishield.api.state.migrate.is_current", lambda engine: False)
    ctx.replay["status"] = "failed"
    monkeypatch.setattr(get_config().models, "detection_mode", "hybrid")
    monkeypatch.setattr(get_config().models, "metadata_dir", str(tmp_path / "no-models"))
    ctx._model_status = None
    ctx.maintenance = MaintenanceWorker(lambda: {}, 3600)                 # created but its thread is not running
    body = _health(client)[1]
    assert body["degraded_components"] == ["schema", "accounts", "housekeeping", "replay", "models"]
    assert body["components"]["models"] == "missing (falls back to rules)"
    assert body["components"]["housekeeping"] == "stopped"


def test_health_is_unhealthy_with_503_when_storage_is_unavailable(api_client, monkeypatch):
    client, _ = api_client
    monkeypatch.setattr(client.app.state.ctx.repository, "ping", lambda: False)
    code, body = _health(client)
    assert code == 503 and body["status"] == "unhealthy" and body["database_connected"] is False
    assert body["components"]["storage"] == "unavailable" and "storage" in body["degraded_components"]


def test_registry_verify_reports_ok_missing_and_mismatch(tmp_path):
    from unishield.models.registry import ModelRegistry

    registry = ModelRegistry(tmp_path / "saved", tmp_path / "meta")
    registry.save("window_rf", {"weights": [1, 2, 3]}, {"algorithm": "test"})
    registry.save("window_rf", {"weights": [4, 5, 6]}, {"algorithm": "test"})
    assert [r["status"] for r in registry.verify()] == ["ok", "ok"]
    assert registry.verify("window_rf") == [{"name": "window_rf", "version": 2, "artifact": "window_rf-v2.joblib",
                                             "status": "ok"}]
    (tmp_path / "saved" / "window_rf-v1.joblib").write_bytes(b"tampered")
    (tmp_path / "saved" / "window_rf-v2.joblib").unlink()
    assert [r["status"] for r in registry.verify()] == ["mismatch", "missing"]
    assert registry.verify("other_model") == []


def test_cli_models_verify(tmp_path, capsys):
    from unishield.models.registry import ModelRegistry

    saved, meta = tmp_path / "saved", tmp_path / "meta"
    args = ["models", "verify", "--saved-dir", str(saved), "--metadata-dir", str(meta)]
    assert cli.main(args) == 0 and "No saved models" in capsys.readouterr().out
    ModelRegistry(saved, meta).save("window_rf", {"w": 1}, {"algorithm": "test"})
    assert cli.main(args) == 0 and "ok        window_rf v1" in capsys.readouterr().out
    (saved / "window_rf-v1.joblib").write_bytes(b"tampered")
    assert cli.main(args) == 1
    captured = capsys.readouterr()
    assert "mismatch  window_rf v1" in captured.out and "1 of 1" in captured.err
