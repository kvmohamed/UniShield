"""File exports: JSON lines, CEF, STIX 2.1 (validated against the spec structure), rotation, on-demand export."""

from __future__ import annotations

import json
import runpy
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from tests.stix21 import validate_bundle
from unishield.correlation.correlator import AlertCorrelator
from unishield.export.files import ContinuousFileExporter, RotatingLineFile, export_snapshot, export_stored
from unishield.export.formats import alert_record, alert_to_cef, incident_to_cef, json_line
from unishield.export.incidents import IncidentTracker
from unishield.export.stix import SCO_NAMESPACE, build_bundle, sco_id, stix_time
from unishield.schemas.alert import Alert, Severity, ThreatClass
from unishield.storage import AlertRepository

T0 = datetime(2026, 10, 22, 10, 0, tzinfo=timezone.utc)
HOME = ["10.0.0.0/8", "fc00::/7"]
SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "export_alerts.py"


def make(cls, src, dst, sec=0, severity=Severity.HIGH, techniques=(), evidence=None, detector="rule_detector",
         alert_id=None):
    end = T0 + timedelta(seconds=sec + 10)
    extra = {"alert_id": alert_id} if alert_id else {}
    return Alert(window_start=end - timedelta(seconds=10), window_end=end, timestamp=end + timedelta(seconds=1),
                 source_ip=src, destination_ip=dst, threat_class=cls, severity=severity, confidence=0.83,
                 detector_name=detector, mitre_techniques=list(techniques), evidence=evidence or {}, **extra)


@pytest.fixture
def alerts():
    return [
        make(ThreatClass.PORT_SCAN, "198.51.100.66", "10.0.1.5", 0, techniques=["T1046"],
             evidence={"summary": "vertical scan | 85 ports", "destination_port": 22}),
        make(ThreatClass.C2_BEACONING, "10.0.1.50", "198.51.100.42", 20, techniques=["T1071", "T1573"],
             evidence={"flows": 12, "intel_matches": [{"source": "feodo", "kind": "ip", "indicator": "198.51.100.42"}]}),
        make(ThreatClass.HOST_SCAN, "198.51.100.66", "10.0.1.6", 30, techniques=["T1046", "T1595.001"]),
        make(ThreatClass.SYN_FLOOD, None, "10.0.1.100", 40, Severity.CRITICAL, ["T1498.001", "T1499.001"]),
        make(ThreatClass.DNS_TUNNELLING, "10.0.1.70", None, 50, techniques=["T1071.004", "T1572"],
             evidence={"base_domain": "t.bad.example"}),
        make(ThreatClass.INTEL_MATCH, "10.0.1.50", "203.0.113.9", 60, detector="intel_detector",
             evidence={"matched_field": "destination_ip", "observed": "203.0.113.9", "flows": 3,
                       "intel_matches": [{"source": "hosting", "kind": "cidr", "indicator": "203.0.113.0/24"}]}),
        make(ThreatClass.INTEL_MATCH, "10.0.1.71", None, 70, detector="intel_detector",
             evidence={"matched_field": "dns_query", "observed": "bad.example",
                       "intel_matches": [{"source": "phish", "kind": "domain", "indicator": "bad.example"}]}),
        make(ThreatClass.STATISTICAL_ANOMALY, "3f2a9c01d4e5b6a7", "0123456789abcdef", 80, Severity.LOW),
        make(ThreatClass.DATA_EXFILTRATION, "fd00::5", "2001:db8::77", 90, techniques=["T1041", "T1048"]),
    ]


def incidents_for(alerts):
    return AlertCorrelator(min_alerts_for_incident=2).correlate(alerts)


class TestJsonAndCef:
    def test_json_line_round_trips_and_redacts(self, alerts):
        line = json_line(alert_record(alerts[0]))
        assert "\n" not in line and Alert.model_validate(json.loads(line)).alert_id == alerts[0].alert_id
        redacted = alert_record(alerts[1], redact_ips=True)
        assert redacted["source_ip"] == redacted["destination_ip"] == "redacted"
        assert redacted["evidence"] == {"summary": "Command-and-control beaconing"}

    def test_cef_header_extension_and_escaping(self, alerts):
        line = alert_to_cef(alerts[0])
        header = line.split("|")
        assert header[:7] == ["CEF:0", "UniShield", "UniShield", header[3], "PORT_SCAN", "Port scan", "8"]
        assert "src=198.51.100.66" in line and "dst=10.0.1.5" in line and "dpt=22" in line
        assert f"externalId={alerts[0].alert_id}" in line and "cs1Label=mitreTechniques cs1=T1046" in line
        assert "msg=vertical scan | 85 ports" in line                 # '|' needs no escape in extensions
        assert f"rt={int(alerts[0].timestamp.timestamp() * 1000)}" in line
        tricky = make(ThreatClass.PORT_SCAN, "198.51.100.1", None, evidence={"summary": "a=b\\c\nnext"})
        assert "msg=a\\=b\\\\c\\nnext" in alert_to_cef(tricky) and "\n" not in alert_to_cef(tricky)

    def test_cef_intel_sources_anonymised_hashes_and_redaction(self, alerts):
        assert "cs4Label=intelSources cs4=feodo" in alert_to_cef(alerts[1])
        anon = alert_to_cef(alerts[7])
        assert "src=" not in anon and "cs5Label=sourceAnonymised cs5=3f2a9c01d4e5b6a7" in anon
        assert "cs1Label" not in anon                                   # no techniques → no orphan label
        redacted = alert_to_cef(alerts[0], redact_ips=True)
        assert "198.51.100.66" not in redacted and "dpt=" not in redacted

    def test_incident_cef(self, alerts):
        (incident,) = [i for i in incidents_for(alerts) if i["entity"] == "198.51.100.66"]
        line = incident_to_cef(incident)
        assert "|INCIDENT|Correlated incident (2 alerts)|" in line
        assert "src=198.51.100.66" in line and "cnt=2" in line and "cs2=HOST_SCAN,PORT_SCAN" in line


class TestStix:
    def test_bundle_is_valid_stix_2_1(self, alerts):
        bundle = build_bundle(alerts, incidents_for(alerts), HOME)
        assert validate_bundle(bundle) == []
        types = {o["type"] for o in bundle["objects"]}
        assert {"identity", "attack-pattern", "indicator", "sighting", "observed-data", "relationship", "incident",
                "ipv4-addr", "ipv6-addr", "domain-name"} <= types

    def test_validator_catches_broken_bundles(self, alerts):
        bundle = build_bundle(alerts[:1], [], HOME)
        indicator = next(o for o in bundle["objects"] if o["type"] == "indicator")
        indicator["pattern"] = "ipv4-addr:value = '1.2.3.4'"           # missing brackets
        indicator["confidence"] = 120
        indicator["labels"] = []
        sighting = next(o for o in bundle["objects"] if o["type"] == "sighting")
        sighting["sighting_of_ref"] = "indicator--00000000-0000-4000-8000-000000000000"
        problems = validate_bundle(bundle)
        assert any("pattern" in p for p in problems) and any("confidence" in p for p in problems)
        assert any("empty list" in p for p in problems) and any("not in bundle" in p for p in problems)

    def test_attack_patterns_carry_mitre_references(self, alerts):
        bundle = build_bundle(alerts, [], HOME)
        patterns = {o["external_references"][0]["external_id"]: o for o in bundle["objects"]
                    if o["type"] == "attack-pattern"}
        assert {"T1046", "T1071", "T1573", "T1595.001", "T1498.001"} <= set(patterns)
        sub = patterns["T1595.001"]
        assert sub["name"] == "Active Scanning: Scanning IP Blocks"
        assert sub["external_references"][0] == {"source_name": "mitre-attack", "external_id": "T1595.001",
                                                 "url": "https://attack.mitre.org/techniques/T1595/001/"}
        rels = [o for o in bundle["objects"] if o["type"] == "relationship" and o["relationship_type"] == "indicates"]
        assert {r["target_ref"] for r in rels} <= {p["id"] for p in patterns.values()}

    def test_indicator_patterns_describe_the_adversary_side(self, alerts):
        bundle = build_bundle(alerts, [], HOME)
        by_alert = {o["x_unishield_alert_id"]: o for o in bundle["objects"] if o["type"] == "indicator"}
        assert by_alert[alerts[0].alert_id]["pattern"] == "[ipv4-addr:value = '198.51.100.66']"
        c2 = by_alert[alerts[1].alert_id]
        assert c2["pattern"] == "[ipv4-addr:value = '198.51.100.42']"            # external C2, not the host
        assert c2["indicator_types"] == ["anomalous-activity"] and c2["confidence"] == 83
        assert c2["x_unishield_intel_sources"] == ["feodo"]
        assert c2["valid_until"] == stix_time(alerts[1].window_end + timedelta(days=30))
        assert alerts[3].alert_id not in by_alert                                # flood victim is no indicator
        assert by_alert[alerts[4].alert_id]["pattern"] == "[domain-name:value = 't.bad.example']"
        intel_ip = by_alert[alerts[5].alert_id]
        assert intel_ip["pattern"] == "[ipv4-addr:value = '203.0.113.9']"
        assert intel_ip["indicator_types"] == ["malicious-activity"]
        assert by_alert[alerts[6].alert_id]["pattern"] == "[domain-name:value = 'bad.example']"
        assert by_alert[alerts[8].alert_id]["pattern"] == "[ipv6-addr:value = '2001:db8::77']"

    def test_sightings_observed_data_and_unexportable_alerts(self, alerts):
        bundle = build_bundle(alerts, [], HOME)
        objects = {o["id"]: o for o in bundle["objects"]}
        sightings = {o["x_unishield_alert_id"]: o for o in bundle["objects"] if o["type"] == "sighting"}
        flood = sightings[alerts[3].alert_id]
        assert objects[flood["sighting_of_ref"]]["type"] == "attack-pattern"
        c2 = sightings[alerts[1].alert_id]
        observed = objects[c2["observed_data_refs"][0]]
        assert observed["number_observed"] == 12 and len(observed["object_refs"]) == 2
        assert c2["first_seen"] == stix_time(alerts[1].window_start) and c2["count"] == 1
        assert c2["where_sighted_refs"] == [next(o["id"] for o in bundle["objects"] if o["type"] == "identity")]
        assert alerts[7].alert_id not in sightings            # hashed addresses, no technique: nothing to sight

    def test_ids_are_deterministic_and_observables_follow_the_spec(self, alerts):
        first, second = build_bundle(alerts, [], HOME), build_bundle(alerts, [], HOME)
        assert first["objects"] == second["objects"] and first["id"] != second["id"]
        import uuid
        assert sco_id("ipv4-addr", "198.51.100.3") == \
            f"ipv4-addr--{uuid.uuid5(SCO_NAMESPACE, json.dumps({'value': '198.51.100.3'}, separators=(',', ':')))}"

    def test_incident_object_links_member_indicators(self, alerts):
        incidents = incidents_for(alerts)
        bundle = build_bundle(alerts, incidents, HOME)
        (incident,) = [o for o in bundle["objects"] if o["type"] == "incident" and "PORT_SCAN" in o["name"]]
        assert incident["x_unishield_alert_count"] == 2 and incident["x_unishield_severity"] == "CRITICAL"
        related = {o["target_ref"] for o in bundle["objects"]
                   if o["type"] == "relationship" and o["source_ref"] == incident["id"]}
        indicator_ids = {o["id"] for o in bundle["objects"] if o["type"] == "indicator"
                         and o["x_unishield_alert_id"] in (alerts[0].alert_id, alerts[2].alert_id)}
        assert indicator_ids <= related


class TestFiles:
    def test_rotation_and_retention(self, tmp_path):
        f = RotatingLineFile(tmp_path, "alerts", ".jsonl", max_bytes=100, backup_count=2)
        for i in range(8):
            f.write_lines(["x" * 60 + str(i)])
        rotated = sorted(p.name for p in tmp_path.glob("alerts-*.jsonl"))
        assert f.rotations == 7 and len(rotated) == 2
        assert (tmp_path / "alerts.jsonl").read_text(encoding="utf-8").strip().endswith("7")

    def test_continuous_exporter_writes_all_formats_and_rotates_stix(self, tmp_path, alerts):
        exporter = ContinuousFileExporter(tmp_path / "exports", home_networks=HOME, rotate_max_stix_objects=10,
                                          backup_count=0)
        tracker = IncidentTracker()
        for alert in alerts:
            exporter.write([alert], tracker.update([alert]), tracker.alerts())
        out = tmp_path / "exports"
        lines = (out / "alerts.jsonl").read_text(encoding="utf-8").splitlines()
        assert [json.loads(line)["alert_id"] for line in lines] == [a.alert_id for a in alerts]
        assert (out / "incidents.jsonl").exists()
        assert len((out / "unishield.cef").read_text(encoding="utf-8").splitlines()) >= len(alerts)
        bundles = [out / "unishield.stix.json", *out.glob("unishield-*.stix.json")]
        assert len(bundles) >= 2                                                  # rotated at 10 objects
        for path in bundles:
            assert validate_bundle(json.loads(path.read_text(encoding="utf-8"))) == []
        status = exporter.status()
        assert status["alerts_written"] == len(alerts) and status["errors"] == 0 and status["rotations"] >= 1

    def test_snapshot_writes_one_set_of_files(self, tmp_path, alerts):
        summary = export_snapshot(alerts, incidents_for(alerts), tmp_path, home_networks=HOME)
        names = [f["name"] for f in summary["files"]]
        assert len(names) == 4 and summary["alerts"] == len(alerts)
        assert any(n.endswith("-bundle.stix.json") for n in names)
        stix = json.loads(next(tmp_path.glob("*.stix.json")).read_text(encoding="utf-8"))
        assert validate_bundle(stix) == [] and len(stix["objects"]) == summary["stix"]["objects"]

    def test_incident_tracker_reports_new_and_changed_incidents(self, alerts):
        tracker = IncidentTracker()
        assert tracker.update([alerts[0]]) == []
        (first,) = tracker.update([alerts[2]])
        assert first["alert_count"] == 2
        assert tracker.update([alerts[4]]) == []                                    # unrelated entity
        later = make(ThreatClass.PORT_SCAN, "198.51.100.66", "10.0.1.9", 35, techniques=["T1046"])
        (grown,) = tracker.update([later])
        assert grown["incident_id"] == first["incident_id"] and grown["alert_count"] == 3


def test_export_stored_and_cli(tmp_path, alerts, monkeypatch, capsys):
    from unishield.config import get_config

    db = f"sqlite:///{tmp_path / 'alerts.db'}"
    repo = AlertRepository.from_url(db)
    repo.add_many(alerts)
    summary = export_stored(repo, get_config(), formats=["stix"], since=T0 + timedelta(seconds=45),
                            directory=tmp_path / "out")
    assert summary["alerts"] == 6 and [f["name"].endswith(".stix.json") for f in summary["files"]] == [True]

    monkeypatch.setattr(sys, "argv", ["export_alerts.py", "--db", db, "--out", str(tmp_path / "cli")])
    with pytest.raises(SystemExit) as exit_info:
        runpy.run_path(str(SCRIPT), run_name="__main__")
    assert exit_info.value.code == 0
    assert f"Exported {len(alerts)} alerts" in capsys.readouterr().out
    assert len(list((tmp_path / "cli").iterdir())) == 4
