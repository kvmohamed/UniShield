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


def test_minute_resolution_flows_are_spread_over_their_minute(tmp_path):
    from unishield.evaluation.public import _MinuteSpreader

    header = (" Source IP, Source Port, Destination IP, Destination Port, Protocol, Timestamp, Flow Duration,"
              " Total Fwd Packets, Total Backward Packets, Label\n")
    rows = [f"192.168.10.5,{50000 + i},192.168.10.3,80,6,7/7/2017 9:{15 + i // 4},1000,1,1,BENIGN\n" for i in range(8)]
    path = tmp_path / "minutes.csv"
    path.write_text(header + "".join(rows), encoding="utf-8")
    reader = _MinuteSpreader(path)
    times = [f.timestamp for f in reader.read()]
    assert reader.spread and reader.records_read == 8
    assert [t.second for t in times] == [0, 15, 30, 45, 0, 15, 30, 45]
    assert times == sorted(times)


def test_out_of_order_file_is_analysed_without_late_drops(tmp_path):
    from unishield.evaluation.public import run_file, time_sorted_copy

    header = (" Source IP, Source Port, Destination IP, Destination Port, Protocol, Timestamp, Flow Duration,"
              " Total Fwd Packets, Total Backward Packets, Label\n")
    # afternoon rows written first (as 1:xx without PM), morning rows after: not in time order
    rows = [f"192.168.10.5,{50000 + i},192.168.10.3,80,6,5/7/2017 1:{10 + i},1000,1,1,BENIGN\n" for i in range(5)]
    rows += [f"192.168.10.5,{51000 + i},192.168.10.3,80,6,5/7/2017 9:{10 + i},1000,1,1,BENIGN\n" for i in range(5)]
    path = tmp_path / "unordered.csv"
    path.write_text(header + "".join(rows), encoding="utf-8")

    unsorted = run_file(path, ["192.168.10.0/24"])
    assert unsorted.late_dropped == 5                      # the morning rows arrive after the afternoon ones

    (tmp_path / "sorted").mkdir()
    copy = time_sorted_copy(path, tmp_path / "sorted")
    lines = copy.read_text(encoding="utf-8").splitlines()
    assert "9:10" in lines[1] and "1:14" in lines[-1]      # 09:10 first, 13:14 last
    fixed = run_file(path, ["192.168.10.0/24"], sort_by_time=True)
    assert fixed.late_dropped == 0 and fixed.records == 10 and fixed.path == str(path)


def test_asset_inventory_is_applied_and_counted(capture, tmp_path):
    from unishield.evaluation.public import load_inventory

    inventory_file = tmp_path / "assets.yaml"
    inventory_file.write_text("version: 1\nassets:\n  - name: audit\n    addresses: [\"147.32.84.165\"]\n"
                              "    roles: [vulnerability_scanner]\n", encoding="utf-8")
    plain = run_file(capture, ["147.32.0.0/16"])
    audited = run_file(capture, ["147.32.0.0/16"], assets=load_inventory(inventory_file))
    assert any(a["threat_class"] == "PORT_SCAN" and a["severity"] != "INFO" for a in plain.alerts)
    scans = [a for a in audited.alerts if a["threat_class"] == "PORT_SCAN"]
    assert scans and all(a["severity"] == "INFO" for a in scans)
    assert any(k.startswith("info PORT_SCAN (vulnerability_scanner)") for k in audited.asset_actions)
