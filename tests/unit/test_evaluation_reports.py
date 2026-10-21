"""Unit tests for the benchmark and real-time replay report builders (small, fast workloads)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from unishield.data.sample_generator import build_scenario
from unishield.evaluation.benchmark import build_workload, describe, render_markdown, run_benchmark
from unishield.evaluation.realtime import PacedReader, paced_run, render_verdict


def test_describe():
    assert describe([1, 2, 3, 4]) == {"mean": 2.5, "median": 2.5, "stdev": 1.291, "min": 1, "max": 4}
    assert describe([5])["stdev"] == 0.0


def test_workload_is_deterministic_and_sized():
    a, b = build_workload(3000, 4), build_workload(3000, 4)
    assert [f.timestamp for f in a] == [f.timestamp for f in b]
    assert 2500 < len(a) < 3500
    assert {f.label for f in a} >= {"BENIGN", "DDOS_SYN_FLOOD", "PORT_SCAN"}


def test_benchmark_report_and_markdown():
    report = run_benchmark(records=2000, runs=2, seed=50, pcap_packets=0)
    assert report["runs"] == 2 and len(report["per_run"]) == 2 and report["pcap"] is None
    for run in report["per_run"]:
        assert run["records_per_second"] > 0 and run["alerts"] > 0 and run["errors"] == 0
    assert set(report["targets"]) == {"throughput", "alert_latency"}
    text = render_markdown(report)
    assert "| Throughput (records/s) |" in text and "## Per run" in text


def test_paced_reader_respects_speed():
    t0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
    flows = [f.model_copy(update={"timestamp": t0 + timedelta(seconds=i)})
             for i, f in enumerate(build_scenario("benign_hard", 1).flows[:3])]
    reader = PacedReader(flows, speed=20)
    import time

    started = time.time()
    assert len(list(reader.read())) == 3
    assert time.time() - started >= 0.09                     # 2 s of traffic at 20x


def test_paced_run_measures_every_stage():
    flows = build_scenario("port_scan", 2).flows
    run = paced_run(flows, speed=1000, poll_interval=0.02)
    assert run["alerts"] >= 1
    alert = run["alerts_detail"][0]
    assert alert["threat_class"] == "PORT_SCAN"
    assert alert["processing_ms"] >= 0 and alert["end_to_end_ms"] is not None
    report = {"generated_at": "now", "machine": {"platform": "p", "logical_cpus": 1, "python": "3.12"},
              "runs": 1, "speed": 1000, "poll_interval_sec": 0.02, "workload": "w",
              "statistics_ms": {k: describe([alert[k]]) for k in ("close_delay_ms", "processing_ms",
                                                                  "api_visibility_ms", "end_to_end_ms")},
              "end_to_end_p95_per_run_ms": None, "alerts_not_seen_by_api": 0,
              "per_run": [dict({k: v for k, v in run.items() if k != "alerts_detail"}, seed=2)]}
    text = render_verdict(report)
    assert "Near-real-time" in text and "End to end" in text and "not claimed to be a live network sensor" in text
