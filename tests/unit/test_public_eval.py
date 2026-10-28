"""Public-dataset evaluation: host-level and window-level scoring on a small CTU-13-style file."""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from unishield.evaluation.public import FileRun, host_metrics, render_markdown, run_file, window_metrics

HEADER = "StartTime,Dur,Proto,SrcAddr,Sport,Dir,DstAddr,Dport,State,sTos,dTos,TotPkts,TotBytes,SrcBytes,Label\n"
T0 = datetime(2011, 8, 18, 10, 0, 0)


def _row(t: float, src, sport, dst, dport, state, pkts, total, srcb, label, proto="tcp"):
    ts = (T0 + timedelta(seconds=t)).strftime("%Y/%m/%d %H:%M:%S.%f")
    return f"{ts},0.01,{proto},{src},{sport},   ->,{dst},{dport},{state},0,0,{pkts},{total},{srcb},{label}\n"


@pytest.fixture
def capture(tmp_path):
    rows = []
    for i in range(120):                                  # background traffic, two minutes
        rows.append(_row(i, f"147.32.84.{10 + i % 20}", 40000 + i, "93.184.216.34", 443, "FSPA_FSPA",
                         12, 9000, 1200, "flow=Background-TCP-Established"))
    for i in range(60):                                   # infected host scans 60 ports of one server
        rows.append(_row(30 + i * 0.05, "147.32.84.165", 50000 + i, "147.32.96.69", 1000 + i, "S_",
                         1, 62, 62, "flow=From-Botnet-V51-TCP-Attempt"))
    rows.sort(key=lambda r: r.split(",")[0])
    path = tmp_path / "scenario_test.binetflow"
    path.write_text(HEADER + "".join(rows), encoding="utf-8")
    return path


def test_run_file_scores_hosts_and_windows(capture):
    run = run_file(capture, ["147.32.0.0/16"])
    assert run.records == 180 and run.reader_errors == 0
    assert run.labels == {"BENIGN": 120, "BOTNET": 60}
    assert run.attack_hosts == ["147.32.84.165"] and run.attack_targets == ["147.32.96.69"]

    h = host_metrics(run)
    assert h["attack_hosts_detected"] == 1
    assert h["alerts_by_class"]["PORT_SCAN"]["involving_attack_hosts"] >= 1
    assert h["first_alert_delay_sec"] and 0 <= h["first_alert_delay_sec"][0] <= 20
    assert h["alert_precision_host_level"] == pytest.approx(h["alerts_involving_attack_hosts"] / h["alerts"])

    w = window_metrics(run.windows)
    assert w["attack_windows"] >= 1 and w["rules"]["recall"] > 0


def test_flood_victim_alert_counts_as_attack_related():
    run = FileRun(name="x", path="x", fmt="flow_csv", records=0, reader_errors=0, labels={}, traffic_hours=0,
                  alerts=[{"threat_class": "DDOS_VOLUMETRIC", "severity": "HIGH", "source_ip": None,
                           "destination_ip": "198.51.100.9", "window_end": T0, "detector": "ddos_detector"},
                          {"threat_class": "C2_BEACONING", "severity": "LOW", "source_ip": "10.0.0.5",
                           "destination_ip": "198.51.100.9", "window_end": T0, "detector": "beaconing_detector"}],
                  attack_hosts=["10.0.0.66"], attack_targets=["198.51.100.9"], first_attack={})
    h = host_metrics(run)
    assert h["alerts_involving_attack_hosts"] == 1          # the flood alert, not the benign host's beacon
    assert h["other_hosts_named"] == 1                      # 10.0.0.5


def test_markdown_report_renders(capture):
    run = run_file(capture, ["147.32.0.0/16"])
    report = {"generated_at": "now", "datasets": [{
        "dataset": "CTU-13 test", "description": "d", "home_networks": ["147.32.0.0/16"], "caveats": ["c"],
        "files": [{"name": run.name, "records": run.records, "traffic_hours": run.traffic_hours,
                   "labels": run.labels, "window": window_metrics(run.windows), "host": host_metrics(run)}],
        "cross_domain": None, "leave_one_file_out": {}}]}
    text = render_markdown(report)
    assert "## CTU-13 test" in text and "| scenario_test.binetflow |" in text and "PORT_SCAN" in text
