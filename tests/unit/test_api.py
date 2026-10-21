"""API tests: alerts storage and queries, replay lifecycle, metrics, architecture, reports."""

from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

import pytest

from unishield.schemas.alert import Alert, Severity, ThreatClass
from unishield.storage import AlertQuery, AlertRepository

T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _alert(i, cls=ThreatClass.PORT_SCAN, sev=Severity.HIGH, src="198.18.0.100", conf=0.9):
    return Alert(window_start=T0 + timedelta(seconds=10 * i), window_end=T0 + timedelta(seconds=10 * i + 10),
                 source_ip=src, destination_ip="10.0.1.5", threat_class=cls, severity=sev, confidence=conf,
                 detector_name="scan_detector", evidence={"ports": i, "nested": {"k": [1, 2]}},
                 mitre_techniques=["T1046"])


def wait_idle(client, timeout=60):
    deadline = time.time() + timeout
    while time.time() < deadline:
        status = client.get("/replay/status").json()
        if status["status"] != "running":
            return status
        time.sleep(0.05)
    raise AssertionError("replay did not finish")


def repo_of(client) -> AlertRepository:
    return client.app.state.ctx.repository


# --- repository -------------------------------------------------------------

def test_repository_roundtrip_preserves_fields():
    repo = AlertRepository.from_url("sqlite://")
    original = _alert(1)
    repo.add(original)
    stored = repo.get(original.alert_id)
    assert stored.evidence == original.evidence and stored.mitre_techniques == ["T1046"]
    assert stored.window_end == original.window_end and stored.window_end.tzinfo is not None
    assert stored.stored_at is not None


def test_repository_filters_sort_and_count():
    repo = AlertRepository.from_url("sqlite://")
    repo.add_many([_alert(i, sev=Severity.LOW if i % 2 else Severity.CRITICAL, conf=i / 10) for i in range(10)])
    repo.add(_alert(20, cls=ThreatClass.SYN_FLOOD, src="198.18.0.101"))
    items, total = repo.list(AlertQuery(threat_class="PORT_SCAN", limit=3))
    assert total == 10 and len(items) == 3
    assert items[0].window_end > items[1].window_end                      # newest first
    items, _ = repo.list(AlertQuery(sort="severity", limit=11))
    assert items[0].severity == Severity.CRITICAL and items[-1].severity == Severity.LOW
    _, total = repo.list(AlertQuery(min_confidence=0.5))
    assert total == 6                                                     # 0.5..0.9 plus the SYN alert
    _, total = repo.list(AlertQuery(since=T0 + timedelta(seconds=50), until=T0 + timedelta(seconds=80)))
    assert total == 3
    assert repo.summary().by_threat_class == {"PORT_SCAN": 10, "SYN_FLOOD": 1}
    assert repo.top_entities("source_ip")[0] == {"ip": "198.18.0.100", "alerts": 10, "max_confidence": 0.9}
    with pytest.raises(ValueError):
        repo.list(AlertQuery(sort="evidence"))


def test_repository_timeline_buckets():
    repo = AlertRepository.from_url("sqlite://")
    repo.add_many([_alert(i) for i in range(12)])                         # window ends 10..120 s
    buckets = repo.timeline(60)
    assert [b["total"] for b in buckets] == [5, 6, 1]


def test_repository_on_disk_sqlite(tmp_path):
    url = f"sqlite:///{(tmp_path / 'sub' / 'alerts.db').as_posix()}"
    AlertRepository.from_url(url).add(_alert(1))
    assert AlertRepository.from_url(url).count() == 1                     # persisted across engines


def test_runs_are_recorded():
    repo = AlertRepository.from_url("sqlite://")
    repo.start_run("run-1", "synthetic", "rules")
    repo.finish_run("run-1", "completed", {"total_records": 5, "total_windows": 2, "total_alerts": 1,
                                          "when": T0})
    (run,) = repo.runs()
    assert run["status"] == "completed" and run["records"] == 5 and run["summary"]["when"].startswith("2026")


# --- API: alerts --------------------------------------------------------------

def test_alerts_pagination_header_and_filters(api_client):
    client, _ = api_client
    repo_of(client).add_many([_alert(i) for i in range(25)])
    r = client.get("/alerts", params={"limit": 10, "offset": 20})
    assert r.status_code == 200 and r.headers["X-Total-Count"] == "25" and len(r.json()) == 5
    r = client.get("/alerts", params={"threat_class": "SYN_FLOOD"})
    assert r.json() == [] and r.headers["X-Total-Count"] == "0"
    assert client.get("/alerts", params={"source_ip": "198.18.0.100", "limit": 1}).headers["X-Total-Count"] == "25"
    assert client.get("/alerts", params={"limit": 0}).status_code == 422
    assert client.get("/alerts", params={"sort": "nope"}).status_code == 422


def test_alert_detail_summary_timeline_incidents(api_client):
    client, _ = api_client
    alerts = [_alert(i) for i in range(3)] + [_alert(3, cls=ThreatClass.HOST_SCAN)]
    repo_of(client).add_many(alerts)
    assert client.get(f"/alerts/{alerts[0].alert_id}").json()["evidence"]["nested"] == {"k": [1, 2]}
    assert client.get("/alerts/US-NOPE0000").status_code == 404
    assert client.get("/alerts/summary").json()["total_alerts"] == 4
    assert client.get("/alerts/timeline", params={"bucket_sec": 3600}).json()["buckets"][0]["total"] == 4
    (incident,) = client.get("/incidents").json()["incidents"]
    assert incident["alert_count"] == 4 and incident["is_multi_stage"]
    assert len(client.get("/threats/HOST_SCAN").json()) == 1


def test_delete_alerts(api_client):
    client, _ = api_client
    repo_of(client).add_many([_alert(i) for i in range(3)])
    assert client.delete("/alerts").json() == {"deleted": 3}
    assert client.get("/alerts").json() == []


# --- API: replay --------------------------------------------------------------

def test_demo_runs_in_background_and_stores_alerts(api_client):
    client, _ = api_client
    body = client.post("/replay/demo", params={"scenario": "port_scan", "seed": 3}).json()
    assert body["status"] == "started" and body["expected_classes"] == ["PORT_SCAN"]
    status = wait_idle(client)
    assert status["status"] == "completed" and status["run_id"] == body["run_id"]
    alerts = client.get("/alerts").json()
    assert {a["threat_class"] for a in alerts} == {"PORT_SCAN"}
    a = alerts[0]
    assert a["run_id"] == body["run_id"] and a["flow_id"]
    for stage in ("window_closed_at", "emitted_at", "stored_at"):
        assert a[stage] is not None
    assert a["window_closed_at"] <= a["emitted_at"] <= a["stored_at"]
    (run,) = client.get("/replay/runs").json()
    assert run["status"] == "completed" and run["alerts"] == len(alerts)


def test_demo_wait_and_unknown_scenario(api_client):
    client, _ = api_client
    body = client.post("/replay/demo", params={"scenario": "dga", "wait": True}).json()
    assert body["status"] == "completed" and body["alerts_count"] >= 1
    assert client.post("/replay/demo", params={"scenario": "nope"}).status_code == 422


def test_second_replay_while_running_is_409(api_client):
    client, _ = api_client
    client.post("/replay/demo", params={"scenario": "exfil_episodes"})
    second = client.post("/replay/demo", params={"scenario": "dga"})
    if client.get("/replay/status").json()["status"] == "running":
        assert second.status_code == 409
        assert client.delete("/alerts").status_code == 409
    assert client.post("/replay/stop").json()["status"] in ("stopping", "idle")
    assert wait_idle(client)["status"] in ("stopped", "completed")


def test_replay_keeps_alerts_when_clear_false(api_client):
    client, _ = api_client
    client.post("/replay/demo", params={"scenario": "port_scan", "wait": True})
    first = int(client.get("/alerts").headers["X-Total-Count"])
    client.post("/replay/demo", params={"scenario": "dga", "wait": True, "clear": False})
    assert int(client.get("/alerts").headers["X-Total-Count"]) > first


# --- API: system ----------------------------------------------------------------

def test_health_reports_database(api_client):
    client, _ = api_client
    body = client.get("/health").json()
    assert body["status"] == "healthy" and body["database_connected"] is True
    assert body["components"]["storage"] == "connected"


def test_metrics_include_process_and_traffic(api_client):
    client, _ = api_client
    client.post("/replay/demo", params={"scenario": "ddos_syn", "wait": True})
    m = client.get("/metrics").json()
    assert m["memory_mb"] > 0 and m["total_records_ingested"] > 0 and m["records_per_second"] > 0
    t = client.get("/metrics/traffic").json()
    assert t["totals"]["windows"] > 0 and t["series"][0]["flows"] >= 1
    assert sum(w["alerts"] for w in t["series"]) >= 1
    assert t["top_destinations"]


def test_architecture_lists_stages_and_notice(api_client):
    client, _ = api_client
    body = client.get("/system/architecture").json()
    assert "does not probe, block, decrypt, or send commands" in body["notice"]
    assert [s["name"] for s in body["stages"]][:3] == ["ingest", "sessionizer", "windowing"]
    assert any(d["name"] == "encrypted_session_detector" for d in body["detectors"])
    assert body["security"]["read_only_mode"] is True


def test_reports_endpoints(api_client, monkeypatch, tmp_path):
    client, _ = api_client
    from unishield.config import get_config

    monkeypatch.setattr(get_config().paths, "reports_dir", str(tmp_path))
    assert client.get("/benchmark/latest").json()["status"] == "no_benchmark_available"
    assert client.get("/evaluation/latest").json()["status"] == "no_evaluation_available"
    (tmp_path / "benchmark.json").write_text(json.dumps({"records_per_second": 1234.5}))
    (tmp_path / "model_evaluation.json").write_text(json.dumps(
        {"context": {"dataset": "x"}, "results": {"windows": {"test": 3}, "threshold": 0.9,
                                                  "approaches": {"rules": {"f1": 0.5, "extra": 1}}}}))
    assert client.get("/benchmark/latest").json() == {"records_per_second": 1234.5, "status": "ok"}
    ev = client.get("/evaluation/latest").json()
    assert ev["approaches"]["rules"]["f1"] == 0.5 and "extra" not in ev["approaches"]["rules"]


def test_dashboard_served_with_csp(api_client):
    client, _ = api_client
    r = client.get("/dashboard")
    assert r.status_code == 200 and "text/html" in r.headers["content-type"]
    assert "default-src 'self'" in r.headers["Content-Security-Policy"]
    assert r.headers["X-Frame-Options"] == "DENY"
