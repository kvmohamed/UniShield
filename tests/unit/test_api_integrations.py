"""API: threat-intel import and status, on-demand export, output status and replay → outputs."""

from __future__ import annotations

import json

from tests.stix21 import validate_bundle
from unishield.data.sample_generator import C2_SERVER


def _demo(client, scenario="beacon_30s"):
    body = client.post("/replay/demo", params={"scenario": scenario, "seed": 1, "wait": True}).json()
    assert body["status"] == "completed", body
    return body


def test_intel_import_status_and_detection(api_client):
    client, _ = api_client
    feed = f"indicator,type,label\n{C2_SERVER},ip,QakBot C2\nbad[.]example,domain,phishing\nhttp://x/,url,no\n"
    r = client.post("/intel/import", params={"source": "feodo", "filename": "feodo.csv"}, content=feed)
    assert r.status_code == 200, r.text
    summary = r.json()
    assert summary["accepted"] == 2 and summary["rejected"] == 1 and summary["format"] == "csv"

    status = client.get("/intel/status").json()
    assert status["active_total"] == 2 and status["sources"][0]["source"] == "feodo" and status["enabled"]

    _demo(client)
    alerts = client.get("/alerts", params={"threat_class": "INTEL_MATCH"}).json()
    assert alerts and alerts[0]["destination_ip"] == C2_SERVER
    assert alerts[0]["evidence"]["intel_matches"][0]["label"] == "QakBot C2"
    beacon = client.get("/alerts", params={"threat_class": "C2_BEACONING"}).json()[0]
    assert beacon["evidence"]["intel_matches"][0]["source"] == "feodo"

    assert client.delete("/intel/sources/feodo").json()["removed"] == 2
    assert client.get("/intel/status").json()["active_total"] == 0


def test_intel_import_rejects_bad_requests(api_client):
    client, _ = api_client
    assert client.post("/intel/import", params={"source": "x"}, content=b"").status_code == 400
    assert client.post("/intel/import", params={"source": "../x"}, content=b"198.51.100.1").status_code == 422
    r = client.post("/intel/import", params={"source": "x", "format": "stix"}, content=b"{not json")
    assert r.status_code == 400 and "JSON" in r.json()["detail"]
    r = client.post("/intel/import", params={"source": "x", "expires": "soon"}, content=b"198.51.100.1")
    assert r.status_code == 400 and "expiry" in r.json()["detail"]


def test_intel_import_size_limit(api_client, monkeypatch):
    from unishield.config import get_config

    client, _ = api_client
    monkeypatch.setattr(get_config().intel, "max_file_mb", 1)
    r = client.post("/intel/import", params={"source": "big"}, content=b"198.51.100.1\n" * 90_000)
    assert r.status_code == 413


def test_on_demand_export_writes_valid_files(api_client, tmp_path):
    client, _ = api_client
    _demo(client, "port_scan")
    r = client.post("/export")
    assert r.status_code == 200, r.text
    summary = r.json()
    assert summary["alerts"] >= 1 and len(summary["files"]) == 4
    out = tmp_path / "exports" / "on-demand"
    stix = json.loads(next(out.glob("*.stix.json")).read_text(encoding="utf-8"))
    assert validate_bundle(stix) == []
    only_cef = client.post("/export", params={"formats": ["cef"]}).json()
    assert [f["name"].endswith(".cef") for f in only_cef["files"]] == [True]
    assert client.post("/export", params={"formats": ["xml"]}).status_code == 422


def test_output_and_architecture_status_without_outputs(api_client):
    client, _ = api_client
    status = client.get("/outputs/status").json()
    assert status["active"] is False and status["syslog"]["destinations"] == []
    arch = client.get("/system/architecture").json()
    stages = {s["name"]: s for s in arch["stages"]}
    assert stages["analyst-side outputs"]["status"] == "disabled"
    assert "nothing is sent anywhere" in stages["analyst-side outputs"]["detail"]
    assert stages["exports"]["status"] == "on demand" and "intel" in arch and "outputs" in arch
    assert "intel_detector" in {d["name"] for d in arch["detectors"]}


def test_replayed_alerts_reach_syslog_and_continuous_export(api_client, monkeypatch, tmp_path):
    """Alerts stored by a replay are handed to the output service (syslog to a loopback receiver)."""
    from unishield.config import SyslogDestination, get_config
    from unishield.evaluation.receivers import UdpSyslogReceiver

    client, _ = api_client
    cfg = get_config()
    with UdpSyslogReceiver() as rx:
        monkeypatch.setattr(cfg.export, "continuous", True)
        monkeypatch.setattr(cfg.outbound, "allowed_destinations", ["127.0.0.1"])
        monkeypatch.setattr(cfg.outbound.syslog, "enabled", True)
        monkeypatch.setattr(cfg.outbound.syslog, "destinations",
                            [SyslogDestination(name="siem", host="127.0.0.1", port=rx.port)])
        body = _demo(client, "port_scan")
        ctx = client.app.state.ctx
        assert ctx.outputs.drain(10)
        status = client.get("/outputs/status").json()
        assert status["active"] and status["queue"]["processed"] == body["alerts_count"]
        assert status["syslog"]["destinations"][0]["sent"] >= body["alerts_count"]
        assert len(rx.messages) >= body["alerts_count"]
    lines = (tmp_path / "exports" / "alerts.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == body["alerts_count"] and json.loads(lines[0])["run_id"] == body["run_id"]
