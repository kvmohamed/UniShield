"""
UniShield — Pipeline Performance Benchmark

Runs the real pipeline (default ``rules`` detectors, alerts written to an
in-memory SQLite repository) over a deterministic synthetic workload several
times and reports, per run and across runs (mean, median, standard
deviation, min, max):

    - throughput: records / wall-clock seconds for the whole run
    - window processing time (feature extraction + detection) p50 / p95 / max
    - alert latency after window close: stored_at - window_closed_at
      (detection, correlation and storage of each alert)
    - peak resident memory (sampled every 50 ms) and CPU use of the process

Targets checked: >= 1,000 records/s and P95 alert latency < 2 s after the
window closes. Results depend on the machine; the report records it.
"""

from __future__ import annotations

import os
import platform
import statistics
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Any

import psutil

from unishield.data.sample_generator import (
    SimulatedReader,
    generate_beacon_traffic,
    generate_ddos_traffic,
    generate_dga_traffic,
    generate_dns_tunnel_traffic,
    generate_exfil_traffic,
    generate_normal_traffic,
    generate_scan_traffic,
)
from unishield.processing.pipeline import Pipeline
from unishield.schemas.flow import NormalisedFlow
from unishield.storage import AlertRepository

TARGET_RECORDS_PER_SEC = 1000.0
TARGET_P95_ALERT_LATENCY_MS = 2000.0
T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)


def build_workload(records: int, seed: int) -> list[NormalisedFlow]:
    """About ``records`` flows: dense benign traffic (~100 flows/s of traffic time) with embedded attacks."""
    import random

    rng = random.Random(seed)
    normal = int(records * 0.70)
    flows = generate_normal_traffic(normal, T0, gap_ms=(2, 18), rng=rng)
    span = (flows[-1].timestamp - T0).total_seconds() if flows else 60
    at = lambda frac: T0 + timedelta(seconds=span * frac)              # noqa: E731
    flows += generate_ddos_traffic(int(records * 0.15), at(0.2), rng=rng)
    flows += generate_scan_traffic(int(records * 0.05), at(0.4), rng=rng)
    flows += generate_dga_traffic(max(20, int(records * 0.03)), at(0.5), rng=rng)
    flows += generate_dns_tunnel_traffic(max(30, int(records * 0.03)), at(0.6), rng=rng)
    flows += generate_exfil_traffic(max(10, int(records * 0.02)), at(0.7), rng=rng)
    flows += generate_beacon_traffic(max(10, int(span / 30)), T0, interval_sec=30, rng=rng)
    flows.sort(key=lambda f: f.timestamp)
    return flows


def _pct(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    return ordered[min(int(len(ordered) * p / 100), len(ordered) - 1)]


def describe(values: list[float]) -> dict[str, float]:
    return {
        "mean": round(statistics.fmean(values), 3),
        "median": round(statistics.median(values), 3),
        "stdev": round(statistics.stdev(values), 3) if len(values) > 1 else 0.0,
        "min": round(min(values), 3),
        "max": round(max(values), 3),
    }


class _MemorySampler(threading.Thread):
    def __init__(self, interval: float = 0.05):
        super().__init__(daemon=True)
        self.interval, self.peak, self._stop_event = interval, 0, threading.Event()
        self.process = psutil.Process()

    def run(self) -> None:
        while not self._stop_event.is_set():
            self.peak = max(self.peak, self.process.memory_info().rss)
            self._stop_event.wait(self.interval)

    def stop(self) -> int:
        self._stop_event.set()
        self.join()
        return max(self.peak, self.process.memory_info().rss)


def run_once(flows: list[NormalisedFlow]) -> dict[str, Any]:
    """One measured pipeline run over ``flows``."""
    repo = AlertRepository.from_url("sqlite://")
    pipeline = Pipeline(alert_callback=repo.add, detection_mode="rules")
    process = psutil.Process()
    sampler = _MemorySampler()
    sampler.start()
    cpu_before = process.cpu_times()
    started = time.perf_counter()
    result = pipeline.run(SimulatedReader(flows))
    wall = time.perf_counter() - started
    cpu_after = process.cpu_times()
    peak_rss = sampler.stop()

    stored = repo.all()
    latencies = [(a.stored_at - a.window_closed_at).total_seconds() * 1000 for a in stored
                 if a.stored_at and a.window_closed_at]
    windows = list(result.window_latencies_ms)
    cpu = (cpu_after.user - cpu_before.user) + (cpu_after.system - cpu_before.system)
    return {
        "records": result.total_records,
        "windows": result.total_windows,
        "alerts": len(stored),
        "alerts_by_class": result.summary()["alerts_by_class"],
        "wall_seconds": round(wall, 4),
        "records_per_second": round(result.total_records / wall, 1) if wall else 0.0,
        "window_processing_ms": {"p50": round(_pct(windows, 50), 3), "p95": round(_pct(windows, 95), 3),
                                 "max": round(max(windows, default=0.0), 3)},
        "alert_latency_after_close_ms": {"p50": round(_pct(latencies, 50), 3),
                                         "p95": round(_pct(latencies, 95), 3),
                                         "max": round(max(latencies, default=0.0), 3)},
        "peak_rss_mb": round(peak_rss / 1_048_576, 1),
        "cpu_percent_of_one_core": round(100 * cpu / wall, 1) if wall else 0.0,
        "errors": result.errors,
    }


def machine_info() -> dict[str, Any]:
    vm = psutil.virtual_memory()
    return {
        "platform": platform.platform(),
        "python": platform.python_version(),
        "processor": platform.processor() or platform.machine(),
        "logical_cpus": os.cpu_count(),
        "memory_gb": round(vm.total / 1_073_741_824, 1),
    }


def run_pcap_benchmark(packets: int, runs: int) -> dict[str, Any]:
    """Throughput of the PCAP path (scapy offline parsing + sessionizer + pipeline) on a written SYN-flood capture."""
    import tempfile
    from pathlib import Path

    from unishield.data.sample_files import write_syn_flood_pcap
    from unishield.ingest.pcap_reader import PcapReader

    with tempfile.TemporaryDirectory() as tmp:
        path = write_syn_flood_pcap(Path(tmp) / "bench.pcap", packets=packets, rate_per_sec=2500)
        rates = []
        for _ in range(runs):
            started = time.perf_counter()
            result = Pipeline(detection_mode="rules").run(PcapReader(path))
            wall = time.perf_counter() - started
            rates.append(packets / wall)
            alerts = result.summary()["alerts_by_class"]
    return {"packets": packets, "runs": runs, "packets_per_second": describe(rates), "alerts_by_class": alerts}


def run_benchmark(records: int = 20_000, runs: int = 5, seed: int = 1000,
                  pcap_packets: int = 10_000) -> dict[str, Any]:
    """``runs`` measured runs (seeds seed..seed+runs-1) after one unmeasured warm-up run."""
    run_once(build_workload(min(records, 2000), seed - 1))                 # warm-up (imports, caches)
    per_run = []
    for i in range(runs):
        flows = build_workload(records, seed + i)
        per_run.append(dict(run_once(flows), seed=seed + i))

    stats = {
        "throughput_records_per_sec": describe([r["records_per_second"] for r in per_run]),
        "window_processing_p95_ms": describe([r["window_processing_ms"]["p95"] for r in per_run]),
        "alert_latency_after_close_p95_ms": describe([r["alert_latency_after_close_ms"]["p95"] for r in per_run]),
        "peak_rss_mb": describe([r["peak_rss_mb"] for r in per_run]),
        "cpu_percent_of_one_core": describe([r["cpu_percent_of_one_core"] for r in per_run]),
    }
    worst_throughput = stats["throughput_records_per_sec"]["min"]
    worst_latency = stats["alert_latency_after_close_p95_ms"]["max"]
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "machine": machine_info(),
        "workload": "synthetic: dense benign (~100 flows/s traffic time) + SYN/UDP flood, port scan, DGA, "
                    "DNS tunnel, exfiltration, 30 s beacon; default rules detectors; alerts stored in "
                    "in-memory SQLite",
        "records": records,
        "runs": runs,
        "per_run": per_run,
        "statistics": stats,
        "pcap": run_pcap_benchmark(pcap_packets, min(runs, 3)) if pcap_packets else None,
        "targets": {
            "throughput": {"description": f">= {TARGET_RECORDS_PER_SEC:.0f} records/s in every run",
                           "worst": worst_throughput, "met": worst_throughput >= TARGET_RECORDS_PER_SEC},
            "alert_latency": {"description": f"P95 alert latency after window close < {TARGET_P95_ALERT_LATENCY_MS:.0f} ms "
                                             "in every run",
                              "worst": worst_latency, "met": worst_latency < TARGET_P95_ALERT_LATENCY_MS},
        },
    }


def render_markdown(report: dict[str, Any]) -> str:
    m = report["machine"]
    lines = [
        "# UniShield — Pipeline Benchmark", "",
        f"Generated {report['generated_at']} by `scripts/benchmark_pipeline.py`.", "",
        f"- Machine: {m['platform']}, {m['processor']}, {m['logical_cpus']} logical CPUs, {m['memory_gb']} GB RAM",
        f"- Python {m['python']}",
        f"- Workload: {report['workload']}",
        f"- {report['runs']} measured runs of ~{report['records']:,} records each (after one warm-up run)", "",
        "## Results across runs", "",
        "| Measure | Mean | Median | SD | Min | Max |", "|---|---|---|---|---|---|",
    ]
    labels = {
        "throughput_records_per_sec": "Throughput (records/s)",
        "window_processing_p95_ms": "Window processing P95 (ms)",
        "alert_latency_after_close_p95_ms": "Alert latency after window close, P95 (ms)",
        "peak_rss_mb": "Peak resident memory (MB)",
        "cpu_percent_of_one_core": "CPU (% of one core)",
    }
    for key, label in labels.items():
        s = report["statistics"][key]
        lines.append(f"| {label} | {s['mean']} | {s['median']} | {s['stdev']} | {s['min']} | {s['max']} |")
    lines += ["", "## Targets", ""]
    for t in report["targets"].values():
        lines.append(f"- {'Met' if t['met'] else 'NOT met'}: {t['description']} (worst run: {t['worst']})")
    lines += ["", "## Per run", "", "| Seed | Records | Windows | Alerts | Wall (s) | Records/s | Window P95 (ms) | "
              "Alert latency P95 (ms) | Peak RSS (MB) |", "|---|---|---|---|---|---|---|---|---|"]
    for r in report["per_run"]:
        lines.append(f"| {r['seed']} | {r['records']:,} | {r['windows']} | {r['alerts']} | {r['wall_seconds']} | "
                     f"{r['records_per_second']:,} | {r['window_processing_ms']['p95']} | "
                     f"{r['alert_latency_after_close_ms']['p95']} | {r['peak_rss_mb']} |")
    if report.get("pcap"):
        pc = report["pcap"]["packets_per_second"]
        lines += ["", "## PCAP path", "",
                  f"Offline parsing of a written {report['pcap']['packets']:,}-packet SYN-flood capture with scapy, "
                  f"sessionization and detection ({report['pcap']['runs']} runs): "
                  f"mean {pc['mean']:,} packets/s (median {pc['median']:,}, min {pc['min']:,}, max {pc['max']:,}). "
                  "Packet parsing in Python is the slowest stage; for high-rate captures, convert to Zeek logs "
                  "first and replay those."]
    lines += ["", "## Notes", "",
              "- Throughput covers the whole pipeline run over records already in memory (generating the "
              "workload is excluded): normalisation, windowing, feature extraction, detection, deduplication "
              "and storage. File parsing costs extra; the PCAP section measures the slowest input path.",
              "- Alert latency after window close is measured per alert from the wall-clock moment its window "
              "was closed to the moment it was stored. It does not include the wait for the window to end in "
              "traffic time (up to the window length) — see the real-time replay report for that.",
              "- The workload is synthetic and replayed as fast as possible; live traffic would arrive at its own "
              "rate."]
    return "\n".join(lines) + "\n"
