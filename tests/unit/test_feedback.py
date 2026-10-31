"""Analyst feedback: explanations, verdicts, suppression rules, labelled export and the API around them."""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timedelta, timezone

import pytest

from unishield.data.sample_generator import SCENARIO_NAMES, SimulatedReader, build_scenario
from unishield.evaluation.passive import sample_intel
from unishield.explain import BENIGN_CAUSES, RULES, explain
from unishield.processing.pipeline import Pipeline
from unishield.schemas.alert import Alert, Severity, ThreatClass
from unishield.storage import AlertRepository
from unishield.storage.feedback import FeedbackStore, SuppressionStore

T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _alert(threat=ThreatClass.PORT_SCAN, src="10.0.0.5", dst="10.0.1.9", detector="scan_detector", **evidence):
    return Alert(window_start=T0, window_end=T0 + timedelta(seconds=10), threat_class=threat,
                 severity=Severity.MEDIUM, confidence=0.8, detector_name=detector, source_ip=src,
                 destination_ip=dst, evidence=evidence)


@pytest.fixture(scope="module")
def scenario_alerts():
    alerts = []
    for name in SCENARIO_NAMES:
        for mode in ("rules", "hybrid"):
            alerts += Pipeline(intel=sample_intel(), detection_mode=mode).run(
                SimulatedReader(build_scenario(name, 1).flows)).alerts
    return alerts


# --- explanations ----------------------------------------------------------------------------------------------------

def test_every_threat_class_has_a_rule_and_benign_causes():
    assert set(RULES) == set(ThreatClass) and set(BENIGN_CAUSES) == set(ThreatClass)


def test_explanations_cover_every_scenario_alert(scenario_alerts):
    classes = set()
    for alert in scenario_alerts:
        e = explain(alert)
        classes.add(alert.threat_class)
        assert e["headline"] and e["rule"] and e["observed"], (alert.threat_class, alert.evidence)
        assert e["context"][0].startswith(f"Detector {alert.detector_name}")
        assert [t["id"] for t in e["techniques"]] == alert.mitre_techniques
        assert all(t["name"] for t in e["techniques"])                  # every mapped technique has a name
    assert len(classes) >= 12


def test_explanation_reports_observed_values_against_thresholds(scenario_alerts):
    scan = next(a for a in scenario_alerts if a.threat_class == ThreatClass.PORT_SCAN
                and a.detector_name == "scan_detector")
    e = explain(scan)
    assert any(f"{scan.evidence['unique_dest_ports']} observed, threshold {scan.evidence['port_threshold']}" in t
               for t in e["thresholds"])
    encrypted = next(a for a in scenario_alerts if a.threat_class == ThreatClass.ENCRYPTED_SESSION_ANOMALY)
    assert any("not decrypted" in c for c in explain(encrypted)["caveats"])
    # trained models are not in the repository, so the model alert is built here
    model = _alert(detector="ml_detector", calibrated_probability=0.97, threshold=0.9, predicted_class="PORT_SCAN",
                   flows_in_window=12)
    model_explained = explain(model)
    assert any("synthetic traffic" in c for c in model_explained["caveats"])
    assert model_explained["observed"][0].startswith("The window model scored this window 0.97 (threshold 0.9)")
    intel = next(a for a in scenario_alerts if a.evidence.get("intel_matches")
                 and a.threat_class != ThreatClass.INTEL_MATCH)
    assert any("threat intelligence" in c for c in explain(intel)["context"])


def test_explanation_never_guesses_missing_evidence():
    e = explain(_alert(attempts=40))                                   # most scan fields missing
    assert e["observed"] == ["10.0.0.5 made 40 connection attempts in the window."]
    assert e["thresholds"] == []
    bare = explain(_alert(ThreatClass.C2_BEACONING, detector="beaconing_detector"))
    assert bare["observed"] == [] and bare["headline"] == RULES[ThreatClass.C2_BEACONING]
    odd = explain(_alert(ThreatClass.DDOS_PROTOCOL, detector="custom", weird_metric=3.14159))
    assert "weird metric: 3.142" in odd["observed"]


def test_asset_policy_and_known_assets_are_explained():
    alert = _alert(asset_policy={"action": "downgrade", "original_severity": "HIGH",
                                 "matches": [{"role": "vulnerability_scanner"}]},
                   assets={"source": [{"address": "10.0.0.5", "asset": "nessus", "roles": ["vulnerability_scanner"]}]})
    alert.severity = Severity.INFO
    context = " ".join(explain(alert)["context"])
    assert "severity lowered to INFO from HIGH" in context and "10.0.0.5 is nessus" in context


# --- verdicts ----------------------------------------------------------------------------------------------------

@pytest.fixture
def stores():
    repo = AlertRepository.from_url("sqlite://")
    return repo, FeedbackStore(repo.engine), SuppressionStore(repo.engine, max_days=90)


def test_verdicts_are_set_updated_cleared_and_deleted_with_the_alert(stores):
    repo, feedback, _ = stores
    a, b = repo.add(_alert()), repo.add(_alert(ThreatClass.HOST_SCAN))
    with pytest.raises(ValueError):
        feedback.set_verdict(a.alert_id, "maybe", "ana")
    with pytest.raises(KeyError):
        feedback.set_verdict("US-NOPE", "false_positive", "ana")
    first = feedback.set_verdict(a.alert_id, "false_positive", "ana", "nessus scan")
    assert first["verdict"] == "false_positive" and first["note"] == "nessus scan" and first["analyst"] == "ana"
    second = feedback.set_verdict(a.alert_id, "benign_true_positive", "bob")
    assert second["created_at"] == first["created_at"] and second["analyst"] == "bob" and second["note"] is None
    feedback.set_verdict(b.alert_id, "true_positive", "ana")
    assert set(feedback.get_many([a.alert_id, b.alert_id, "x"])) == {a.alert_id, b.alert_id}
    assert feedback.clear(b.alert_id) and not feedback.clear(b.alert_id)
    repo.delete_all()
    assert feedback.get(a.alert_id) is None                            # cascades with the alert


def test_review_summary_and_labelled_export(stores):
    repo, feedback, _ = stores
    scans = [repo.add(_alert()) for _ in range(4)]
    beacon = repo.add(_alert(ThreatClass.C2_BEACONING, detector="beaconing_detector"))
    for alert, verdict in zip(scans, ("true_positive", "benign_true_positive", "false_positive")):
        feedback.set_verdict(alert.alert_id, verdict, "ana")
    summary = feedback.summary()
    scan_row = next(r for r in summary["by_detector"] if r["detector"] == "scan_detector")
    assert scan_row["alerts"] == 4 and scan_row["reviewed"] == 3 and scan_row["reviewed_precision"] == 0.667
    beacon_row = next(r for r in summary["by_detector"] if r["detector"] == "beaconing_detector")
    assert beacon_row["reviewed"] == 0 and beacon_row["reviewed_precision"] is None
    assert summary["alerts"] == 5 and summary["false_positive"] == 1 and "biased" in summary["note"]
    rows = feedback.labelled()
    assert [r["verdict"] for r in rows].count("false_positive") == 1 and len(rows) == 3
    assert rows[0]["reviewed_at"].endswith("+00:00") and beacon.alert_id not in {r["alert_id"] for r in rows}
    assert [r["verdict"] for r in feedback.labelled("true_positive")] == ["true_positive"]


# --- suppression rules -------------------------------------------------------------------------------------------

@pytest.mark.parametrize("kwargs, message", [
    ({}, "source or a destination"),
    ({"source": "10.0.0.5", "threat_class": "INTEL_MATCH"}, "threat-intel"),
    ({"source": "not-an-ip"}, "not an IP address"),
    ({"source": "10.0.0.5", "days": 91}, "between 1 and 90"),
    ({"source": "10.0.0.5", "reason": "ok"}, "reason"),
])
def test_suppression_rules_are_validated(stores, kwargs, message):
    _, _, rules = stores
    args = {"threat_class": "PORT_SCAN", "reason": "authorised scanner", "created_by": "ana", "days": 30, **kwargs}
    with pytest.raises(ValueError, match=message):
        rules.create(**args)


def test_suppression_matching_scope(stores):
    _, _, rules = stores
    net = rules.create(threat_class="PORT_SCAN", source="10.0.0.0/24", reason="scanner subnet", created_by="ana",
                       days=30)
    assert net["source"] == "10.0.0.0/24" and net["expires_at"] > datetime.now(timezone.utc).isoformat()
    assert rules.match(_alert(src="10.0.0.77")) == net["id"]
    assert rules.match(_alert(src="10.0.1.77")) is None                 # outside the range
    assert rules.match(_alert(ThreatClass.HOST_SCAN, src="10.0.0.77")) is None   # other class
    assert rules.match(_alert(src="10.0.0.77", intel_matches=[{"label": "x"}])) is None   # intel is never hidden
    rules.create(threat_class="C2_BEACONING", destination="a1b2c3d4e5f60718", detector_name="beaconing_detector",
                 reason="hashed NTP server", created_by="ana", days=7)
    beacon = _alert(ThreatClass.C2_BEACONING, src="ffff0000", dst="a1b2c3d4e5f60718", detector="beaconing_detector")
    assert rules.match(beacon) is not None
    assert rules.match(beacon.model_copy(update={"detector_name": "ml_detector"})) is None
    rules.set_enabled(net["id"], False)
    assert rules.match(_alert(src="10.0.0.77")) is None
    rules.set_enabled(net["id"], True)
    rules.record_hit(net["id"])
    assert rules.get(net["id"])["hits"] == 1 and rules.get(net["id"])["last_hit_at"]
    assert rules.delete(net["id"]) and rules.match(_alert(src="10.0.0.77")) is None


def test_expired_rules_stop_matching(stores):
    from sqlalchemy import update

    from unishield.storage.database import suppression_rules_table as t

    repo, _, rules = stores
    rule = rules.create(threat_class="PORT_SCAN", source="10.0.0.5", reason="one-off test", created_by="ana", days=1)
    with repo.engine.begin() as conn:
        conn.execute(update(t).where(t.c.id == rule["id"]).values(expires_at=datetime(2020, 1, 1)))
    rules._invalidate()
    assert rules.match(_alert()) is None
    assert [r["active"] for r in rules.list()] == [False] and rules.list(include_expired=False) == []


# --- API ---------------------------------------------------------------------------------------------------------

def _demo(client, scenario="port_scan"):
    body = client.post("/replay/demo", params={"scenario": scenario, "seed": 1, "wait": True}).json()
    assert body["status"] == "completed", body


def test_verdict_and_explanation_api(api_client, client_as):
    client, _ = api_client
    _demo(client)
    alert = client.get("/alerts", params={"threat_class": "PORT_SCAN"}).json()[0]
    aid = alert["alert_id"]
    viewer, analyst = client_as("viewer"), client_as("analyst")
    explanation = viewer.get(f"/alerts/{aid}/explanation").json()
    assert explanation["threat_class"] == "PORT_SCAN" and explanation["thresholds"]
    assert viewer.get(f"/alerts/{aid}/verdict").json() == {"alert_id": aid, "verdict": None}
    assert viewer.put(f"/alerts/{aid}/verdict", json={"verdict": "true_positive"}).status_code == 403
    assert analyst.put(f"/alerts/{aid}/verdict", json={"verdict": "nope"}).status_code == 422
    assert analyst.put("/alerts/US-NOPE/verdict", json={"verdict": "true_positive"}).status_code == 404
    saved = analyst.put(f"/alerts/{aid}/verdict", json={"verdict": "false_positive", "note": "lab scanner"}).json()
    assert saved["verdict"] == "false_positive" and saved["analyst"].startswith("analyst")
    assert viewer.get("/feedback/verdicts", params={"alert_id": [aid, "other"]}).json() == {aid: "false_positive"}
    summary = viewer.get("/feedback/summary").json()
    assert summary["false_positive"] == 1 and summary["reviewed_precision"] == 0.0

    assert viewer.get("/feedback/export").status_code == 403
    rows = list(csv.DictReader(io.StringIO(analyst.get("/feedback/export").text)))
    assert [(r["alert_id"], r["verdict"], r["note"]) for r in rows] == [(aid, "false_positive", "lab scanner")]
    lines = analyst.get("/feedback/export", params={"format": "jsonl"}).text.splitlines()
    assert json.loads(lines[0])["evidence"]["port_threshold"] == 25

    assert analyst.delete(f"/alerts/{aid}/verdict").json()["removed"] is True
    actions = [e["action"] for e in client.get("/audit").json()]
    assert {"alert.verdict", "alert.verdict.clear", "feedback.export"} <= set(actions)


def test_suppression_hides_new_alerts_from_lists_and_outputs(api_client, client_as):
    client, _ = api_client
    _demo(client)
    scan = client.get("/alerts", params={"threat_class": "PORT_SCAN"}).json()[0]
    analyst = client_as("analyst")
    bad = analyst.post("/suppressions", json={"threat_class": "PORT_SCAN", "reason": "lab scanner", "days": 30})
    assert bad.status_code == 422 and "source or a destination" in bad.text
    too_long = analyst.post("/suppressions", json={"threat_class": "PORT_SCAN", "source": scan["source_ip"],
                                                   "reason": "lab scanner", "days": 365})
    assert too_long.status_code == 422
    rule = analyst.post("/suppressions", json={"threat_class": "PORT_SCAN", "source": scan["source_ip"],
                                               "reason": "authorised lab scanner", "days": 14,
                                               "from_alert_id": scan["alert_id"]}).json()
    assert rule["created_by"].startswith("analyst") and rule["from_alert_id"] == scan["alert_id"]

    client.delete("/alerts")
    _demo(client)
    assert client.get("/alerts", params={"threat_class": "PORT_SCAN"}).json() == []
    hidden = client.get("/alerts", params={"threat_class": "PORT_SCAN", "suppressed": "only"}).json()
    assert hidden and all(a["suppressed_by"] == rule["id"] for a in hidden)
    assert client.get("/alerts/summary").json()["suppressed_alerts"] == len(hidden)
    assert client.get("/replay/status").json()["alerts_suppressed"] == len(hidden)
    assert client.get("/suppressions").json()[0]["hits"] == len(hidden)
    explanation = client.get(f"/alerts/{hidden[0]['alert_id']}/explanation").json()
    assert any("authorised lab scanner" in c for c in explanation["context"])

    assert analyst.patch(f"/suppressions/{rule['id']}", json={"enabled": False}).json()["enabled"] is False
    assert analyst.delete(f"/suppressions/{rule['id']}").status_code == 403
    assert client.delete(f"/suppressions/{rule['id']}").json() == {"deleted": rule["id"]}
    assert client.delete(f"/suppressions/{rule['id']}").status_code == 404
    actions = [e["action"] for e in client.get("/audit").json()]
    assert {"suppression.create", "suppression.update", "suppression.delete"} <= set(actions)


def test_analyst_role_still_cannot_administer(api_client, client_as):
    analyst = client_as("analyst")
    assert analyst.post("/replay/demo", params={"scenario": "port_scan"}).status_code == 403
    assert analyst.delete("/alerts").status_code == 403
