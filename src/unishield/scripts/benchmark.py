"""
UniShield — Benchmarking & Ablation Study Runner

Runs systematic benchmarks and ablation studies to measure:
    - Pipeline throughput (records/second)
    - Detection latency (P50, P95, P99)
    - Alert quality by threat class
    - Detector contribution (ablation)

Produces structured JSON reports.

Usage:
    python -m unishield.scripts.benchmark
"""

from __future__ import annotations

import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Ensure src is on path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from unishield.config import reset_config, reset_thresholds
from unishield.data.sample_generator import (
    SimulatedReader,
    generate_mixed_scenario,
    generate_normal_traffic,
    generate_ddos_traffic,
    generate_scan_traffic,
    generate_beacon_traffic,
    generate_exfil_traffic,
)
from unishield.detectors.base import BaseDetector
from unishield.detectors.ddos_detector import DDoSDetector
from unishield.detectors.scan_detector import ScanDetector
from unishield.detectors.beaconing_detector import BeaconingDetector
from unishield.detectors.exfiltration_detector import ExfiltrationDetector
from unishield.detectors.anomaly_detector import AnomalyDetector
from unishield.features.volume import VolumeFeatureExtractor
from unishield.features.scan import ScanFeatureExtractor
from unishield.features.beaconing import BeaconingFeatureExtractor
from unishield.features.exfiltration import ExfiltrationFeatureExtractor
from unishield.features.statistical import StatisticalFeatureExtractor
from unishield.processing.pipeline import Pipeline, PipelineResult
from unishield.correlation.correlator import AlertCorrelator


def _run_pipeline(
    flows,
    detectors: list | None = None,
    label: str = "benchmark",
) -> dict[str, Any]:
    """Run pipeline and return result summary."""
    reader = SimulatedReader(flows)
    kwargs = {}
    if detectors is not None:
        kwargs["detectors"] = detectors
    pipeline = Pipeline(window_size_sec=10, slide_interval_sec=5, **kwargs)
    result = pipeline.run(reader)
    summary = result.summary()
    summary["label"] = label
    return summary


def run_throughput_benchmark() -> dict[str, Any]:
    """Benchmark pipeline throughput at different data sizes."""
    print("\n" + "=" * 60)
    print("THROUGHPUT BENCHMARK")
    print("=" * 60)

    results = []
    for size in [500, 1000, 2000, 5000]:
        flows = generate_mixed_scenario(
            normal_count=size,
            ddos_count=size // 2,
            scan_count=size // 5,
            beacon_count=min(size // 20, 50),
            exfil_count=size // 10,
        )
        summary = _run_pipeline(flows, label=f"throughput_{size}")
        results.append(summary)

        total = summary["total_records"]
        rps = summary["records_per_second"]
        alerts = summary["total_alerts"]
        p95 = summary["latency_p95_ms"]
        print(f"  Records: {total:>6} | Throughput: {rps:>10,.0f} rec/s | "
              f"Alerts: {alerts:>4} | P95 latency: {p95:.2f}ms")

    return {"benchmark": "throughput", "results": results}


def run_detection_quality_benchmark() -> dict[str, Any]:
    """Benchmark detection quality per attack scenario."""
    print("\n" + "=" * 60)
    print("DETECTION QUALITY BENCHMARK")
    print("=" * 60)

    scenarios = {
        "normal_only": generate_normal_traffic(500),
        "ddos_attack": generate_ddos_traffic(500) + generate_normal_traffic(200),
        "port_scan": generate_scan_traffic(200) + generate_normal_traffic(200),
        "c2_beacon": generate_beacon_traffic(40, interval_sec=30, jitter_percent=3)
                     + generate_normal_traffic(200),
        "exfiltration": generate_exfil_traffic(50) + generate_normal_traffic(200),
        "mixed_attack": generate_mixed_scenario(200, 300, 100, 25, 30),
    }

    results = {}
    for name, flows in scenarios.items():
        flows.sort(key=lambda f: f.timestamp)
        summary = _run_pipeline(flows, label=name)
        classes = summary.get("alerts_by_class", {})
        results[name] = {
            "total_records": summary["total_records"],
            "total_alerts": summary["total_alerts"],
            "alerts_by_class": classes,
            "latency_avg_ms": summary["latency_avg_ms"],
        }
        print(f"  {name:20s} | Records: {summary['total_records']:>5} | "
              f"Alerts: {summary['total_alerts']:>3} | Classes: {classes}")

    return {"benchmark": "detection_quality", "results": results}


def run_ablation_study() -> dict[str, Any]:
    """
    Ablation study: measure detection performance with each
    detector removed one at a time.
    """
    print("\n" + "=" * 60)
    print("ABLATION STUDY")
    print("=" * 60)

    flows = generate_mixed_scenario(300, 400, 150, 30, 40)

    all_detectors = [
        ("ddos", DDoSDetector()),
        ("scan", ScanDetector()),
        ("beaconing", BeaconingDetector()),
        ("exfiltration", ExfiltrationDetector()),
    ]

    # Baseline: all detectors
    baseline = _run_pipeline(flows, label="all_detectors")
    print(f"\n  ALL DETECTORS (baseline):")
    print(f"    Alerts: {baseline['total_alerts']} | Classes: {baseline['alerts_by_class']}")

    results = {"baseline": baseline, "ablations": {}}

    # Remove each detector one at a time
    for remove_name, _ in all_detectors:
        remaining = [d for name, d in all_detectors if name != remove_name]
        summary = _run_pipeline(flows, detectors=remaining, label=f"without_{remove_name}")

        delta = baseline["total_alerts"] - summary["total_alerts"]
        lost_classes = set(baseline.get("alerts_by_class", {}).keys()) - set(summary.get("alerts_by_class", {}).keys())

        results["ablations"][remove_name] = {
            "alerts_with": baseline["total_alerts"],
            "alerts_without": summary["total_alerts"],
            "delta": delta,
            "lost_threat_classes": sorted(lost_classes),
            "alerts_by_class": summary.get("alerts_by_class", {}),
        }

        print(f"\n  WITHOUT {remove_name.upper():15s}:")
        print(f"    Alerts: {summary['total_alerts']} (delta {delta:+d}) | "
              f"Lost classes: {lost_classes or 'none'}")

    return {"benchmark": "ablation", "results": results}


def run_correlation_benchmark() -> dict[str, Any]:
    """Benchmark the alert correlation engine."""
    print("\n" + "=" * 60)
    print("CORRELATION BENCHMARK")
    print("=" * 60)

    flows = generate_mixed_scenario(300, 400, 150, 30, 40)
    reader = SimulatedReader(flows)
    pipeline = Pipeline(window_size_sec=10, slide_interval_sec=5)
    result = pipeline.run(reader)

    correlator = AlertCorrelator(
        dedup_window_sec=30,
        correlation_window_sec=300,
        min_alerts_for_incident=2,
    )

    deduped, incidents = correlator.process(result.alerts)

    print(f"  Raw alerts:         {len(result.alerts)}")
    print(f"  After dedup:        {len(deduped)}")
    print(f"  Suppressed:         {correlator.suppressed_count}")
    print(f"  Incidents:          {len(incidents)}")

    for inc in incidents[:5]:
        print(f"    {inc['incident_id']}: {inc['source_ip']} | "
              f"Severity: {inc['severity']} | "
              f"Alerts: {inc['alert_count']} | "
              f"Classes: {inc['threat_classes']}")

    return {
        "benchmark": "correlation",
        "raw_alerts": len(result.alerts),
        "deduped_alerts": len(deduped),
        "suppressed": correlator.suppressed_count,
        "incidents": incidents[:10],
        "correlator_stats": correlator.stats(),
    }


def main():
    """Run all benchmarks and save results."""
    print("=" * 60)
    print(" UniShield — Benchmark & Ablation Study")
    print("=" * 60)

    reset_config()
    reset_thresholds()

    start = time.time()

    all_results = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "benchmarks": [],
    }

    # Run benchmarks
    all_results["benchmarks"].append(run_throughput_benchmark())
    all_results["benchmarks"].append(run_detection_quality_benchmark())
    all_results["benchmarks"].append(run_ablation_study())
    all_results["benchmarks"].append(run_correlation_benchmark())

    elapsed = time.time() - start

    all_results["total_duration_sec"] = round(elapsed, 2)

    # Save report
    report_dir = Path(__file__).resolve().parent.parent.parent.parent / "reports"
    report_dir.mkdir(parents=True, exist_ok=True)
    report_path = report_dir / "benchmark_report.json"

    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(all_results, f, indent=2, default=str)

    print(f"\n{'=' * 60}")
    print(f" All benchmarks complete in {elapsed:.2f}s")
    print(f" Report saved to: {report_path}")
    print(f"{'=' * 60}")

    return all_results


if __name__ == "__main__":
    main()
