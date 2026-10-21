"""
Performance tests (run with: pytest -m performance).

They check the brief's targets on this machine with smaller workloads than
scripts/benchmark_pipeline.py: >= 1,000 records/s and P95 alert latency
after window close < 2 s, plus bounded memory on a long benign stream.
"""

from __future__ import annotations

import pytest

from unishield.data.sample_generator import SimulatedReader, generate_normal_traffic
from unishield.evaluation.benchmark import (
    TARGET_P95_ALERT_LATENCY_MS,
    TARGET_RECORDS_PER_SEC,
    build_workload,
    run_once,
    run_pcap_benchmark,
)
from unishield.evaluation.realtime import paced_run, realtime_workload
from unishield.processing.pipeline import Pipeline

pytestmark = pytest.mark.performance


@pytest.mark.parametrize("seed", [1, 2, 3])
def test_throughput_and_alert_latency_targets(seed):
    run = run_once(build_workload(10_000, seed))
    assert run["errors"] == 0 and run["alerts"] > 0
    assert run["records_per_second"] >= TARGET_RECORDS_PER_SEC
    assert run["alert_latency_after_close_ms"]["p95"] < TARGET_P95_ALERT_LATENCY_MS


def test_pcap_path_detects_and_keeps_up():
    report = run_pcap_benchmark(3000, 1)
    assert report["alerts_by_class"].get("SYN_FLOOD") == 1
    assert report["packets_per_second"]["min"] > 500


def test_memory_stays_bounded_on_a_long_stream():
    import psutil

    process = psutil.Process()
    flows = generate_normal_traffic(60_000, gap_ms=(5, 30), seed=9)
    before = process.memory_info().rss
    result = Pipeline().run(SimulatedReader(flows))
    grown_mb = (process.memory_info().rss - before) / 1_048_576
    assert result.total_records == 60_000 and result.errors == 0
    assert grown_mb < 300


def test_paced_replay_alerts_reach_the_api_quickly():
    run = paced_run(realtime_workload(5), speed=100, poll_interval=0.05)
    assert run["alerts"] > 0
    seen = [a for a in run["alerts_detail"] if a["end_to_end_ms"] is not None]
    assert len(seen) == run["alerts"]
    assert max(a["processing_ms"] for a in seen) < TARGET_P95_ALERT_LATENCY_MS
