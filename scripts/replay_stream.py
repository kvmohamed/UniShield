"""
UniShield — Replay Stream with End-to-End Timestamping

Replays flow records through the pipeline with configurable speed,
measuring timestamps at every stage of processing.

Usage:
    python scripts/replay_stream.py --scenario ddos --speed 1.0
    python scripts/replay_stream.py --input data/test_scenarios/ddos-100/flows.jsonl --speed 10.0
    python scripts/replay_stream.py --all --runs 5

SAFETY:
    - No packets are sent on any network interface.
    - All processing is local, read-only, and passive.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import sys
import time
import statistics
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Ensure src is on the path
_script_dir = Path(__file__).resolve().parent
_project_root = _script_dir.parent
sys.path.insert(0, str(_project_root / "src"))

import psutil  # type: ignore

from unishield.config import load_config, reset_config, reset_thresholds
from unishield.processing.pipeline import Pipeline, PipelineResult
from unishield.features.base import WindowContext
from unishield.processing.window import SlidingWindow
from unishield.features.volume import VolumeFeatureExtractor
from unishield.features.scan import ScanFeatureExtractor
from unishield.features.beaconing import BeaconingFeatureExtractor
from unishield.features.exfiltration import ExfiltrationFeatureExtractor
from unishield.features.dns import DNSFeatureExtractor
from unishield.features.statistical import StatisticalFeatureExtractor
from unishield.detectors.ddos_detector import DDoSDetector
from unishield.detectors.scan_detector import ScanDetector
from unishield.detectors.beaconing_detector import BeaconingDetector
from unishield.detectors.exfiltration_detector import ExfiltrationDetector
from unishield.detectors.dns_detector import DNSDetector
from unishield.detectors.anomaly_detector import AnomalyDetector
from unishield.correlation.correlator import AlertCorrelator
from unishield.schemas.alert import Alert
from unishield.schemas.flow import NormalisedFlow


def _utcnow_ms() -> float:
    """Current UTC time as float with ms precision."""
    return time.time()


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_flows_from_jsonl(path: Path) -> list[NormalisedFlow]:
    """Load flows from a JSONL file."""
    flows = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                data = json.loads(line)
                flows.append(NormalisedFlow(**data))
    return flows


def get_system_info() -> dict:
    """Collect system information."""
    return {
        "platform": platform.platform(),
        "processor": platform.processor(),
        "python_version": platform.python_version(),
        "cpu_count": os.cpu_count(),
        "total_memory_gb": round(psutil.virtual_memory().total / (1024**3), 2),
        "hostname": platform.node(),
    }


def run_pipeline_with_timestamps(
    flows: list[NormalisedFlow],
    speed: float = 1.0,
    window_size: int = 10,
    slide_interval: int = 5,
) -> dict:
    """
    Run the pipeline with end-to-end timestamping at every stage.

    Returns a comprehensive result dictionary with all metrics.
    """
    reset_config()
    reset_thresholds()

    # Initialise components
    extractors = [
        VolumeFeatureExtractor(),
        ScanFeatureExtractor(),
        BeaconingFeatureExtractor(),
        ExfiltrationFeatureExtractor(),
    ]
    detectors = [
        DDoSDetector(),
        ScanDetector(),
        BeaconingDetector(),
        ExfiltrationDetector(),
    ]
    correlator = AlertCorrelator()

    window = SlidingWindow(
        window_size_sec=window_size,
        slide_interval_sec=slide_interval,
        max_records=50000,
    )

    # Result collection
    all_alerts: list[dict] = []
    processing_events: list[dict] = []
    latencies: list[float] = []
    ingest_latencies: list[float] = []
    feature_latencies: list[float] = []
    detection_latencies: list[float] = []
    storage_latencies: list[float] = []
    e2e_latencies: list[float] = []

    records_processed = 0
    records_dropped = 0
    records_malformed = 0
    windows_emitted = 0
    errors = 0

    # System metrics
    process = psutil.Process()
    cpu_samples = []
    mem_samples = []

    def analyse_window(closed, flow, record_wall_start, ingest_timestamp, ingest_delay_ms):
        nonlocal windows_emitted, errors
        windows_emitted += 1
        window_flows, w_start, w_end = closed.records, closed.start, closed.end
        context = WindowContext(start=w_start, end=w_end, observed_seconds=closed.observed_seconds)

        # Stage 2: Feature extraction
        feat_start = _utcnow_ms()
        all_features = {}
        for ext in extractors:
            try:
                features = ext.extract(window_flows, context)
                all_features.update(features)
            except Exception as e:
                errors += 1
        feat_end = _utcnow_ms()
        feature_latency_ms = (feat_end - feat_start) * 1000.0
        feature_latencies.append(feature_latency_ms)

        # Stage 3: Detection
        det_start = _utcnow_ms()
        window_alerts = []
        for det in detectors:
            try:
                alerts = det.detect(window_flows, all_features, w_start, w_end)
                window_alerts.extend(alerts)
            except Exception as e:
                errors += 1
        det_end = _utcnow_ms()
        detection_latency_ms = (det_end - det_start) * 1000.0
        detection_latencies.append(detection_latency_ms)

        # Stage 4: Storage (in-memory)
        store_start = _utcnow_ms()
        for alert in window_alerts:
            storage_timestamp = _utcnow_ms()
            alert_record = {
                **json.loads(alert.model_dump_json()),
                "_timestamps": {
                    "event_timestamp": flow.timestamp.isoformat(),
                    "ingest_timestamp": datetime.fromtimestamp(ingest_timestamp, tz=timezone.utc).isoformat(),
                    "window_start": w_start.isoformat() if w_start else None,
                    "window_end": w_end.isoformat() if w_end else None,
                    "feature_completion_timestamp": datetime.fromtimestamp(feat_end, tz=timezone.utc).isoformat(),
                    "detection_timestamp": datetime.fromtimestamp(det_end, tz=timezone.utc).isoformat(),
                    "storage_timestamp": datetime.fromtimestamp(storage_timestamp, tz=timezone.utc).isoformat(),
                },
                "_latencies_ms": {
                    "ingest_delay": round(ingest_delay_ms, 3),
                    "feature_processing": round(feature_latency_ms, 3),
                    "detection": round(detection_latency_ms, 3),
                    "storage": round((_utcnow_ms() - store_start) * 1000.0, 3),
                    "end_to_end": round((_utcnow_ms() - record_wall_start) * 1000.0, 3),
                },
            }
            all_alerts.append(alert_record)
            e2e_ms = (_utcnow_ms() - record_wall_start) * 1000.0
            e2e_latencies.append(e2e_ms)

        store_end = _utcnow_ms()
        storage_latencies.append((store_end - store_start) * 1000.0)

        # Processing event log
        processing_events.append({
            "window_id": windows_emitted,
            "window_start": w_start.isoformat() if w_start else None,
            "window_end": w_end.isoformat() if w_end else None,
            "records_in_window": len(window_flows),
            "features_extracted": len(all_features),
            "alerts_generated": len(window_alerts),
            "feature_latency_ms": round(feature_latency_ms, 3),
            "detection_latency_ms": round(detection_latency_ms, 3),
            "wall_clock": _iso_now(),
        })

    pipeline_start_time = _utcnow_ms()
    prev_event_time = None

    for idx, flow in enumerate(flows):
        record_wall_start = _utcnow_ms()

        # Speed-controlled delay
        if speed > 0 and speed != float("inf") and prev_event_time is not None:
            event_delta = (flow.timestamp - prev_event_time).total_seconds()
            if event_delta > 0:
                sleep_time = event_delta / speed
                if sleep_time > 0.0001:  # Don't sleep for sub-100µs
                    time.sleep(sleep_time)
        prev_event_time = flow.timestamp

        # Stage 1: Ingest
        ingest_timestamp = _utcnow_ms()
        ingest_delay_ms = (ingest_timestamp - record_wall_start) * 1000.0
        ingest_latencies.append(ingest_delay_ms)

        # Add to window; analyse every window this record closes
        records_processed += 1
        for closed in window.add(flow):
            analyse_window(closed, flow, record_wall_start, ingest_timestamp, ingest_delay_ms)

        # Track per-record latency
        record_latency_ms = (_utcnow_ms() - record_wall_start) * 1000.0
        latencies.append(record_latency_ms)

        # Sample system metrics every 100 records
        if idx % 100 == 0:
            try:
                cpu_samples.append(process.cpu_percent(interval=None))
                mem_samples.append(process.memory_info().rss / (1024 * 1024))
            except Exception:
                pass

    # End of input: analyse the windows that are still open
    flush_start = _utcnow_ms()
    for closed in window.flush():
        analyse_window(closed, flows[-1], flush_start, flush_start, 0.0)

    pipeline_end_time = _utcnow_ms()
    total_duration = pipeline_end_time - pipeline_start_time

    # Correlate alerts
    raw_alerts = []
    for a_dict in all_alerts:
        try:
            clean = {k: v for k, v in a_dict.items() if not k.startswith("_")}
            raw_alerts.append(Alert(**clean))
        except Exception:
            pass
    deduped_alerts, incidents = correlator.process(raw_alerts)

    # Compute statistics
    def _stats(values: list[float]) -> dict:
        if not values:
            return {"mean": 0, "median": 0, "std": 0, "min": 0, "max": 0,
                    "p50": 0, "p95": 0, "p99": 0}
        sorted_v = sorted(values)
        n = len(sorted_v)
        return {
            "mean": round(statistics.mean(values), 4),
            "median": round(statistics.median(values), 4),
            "std": round(statistics.stdev(values), 4) if n > 1 else 0,
            "min": round(min(values), 4),
            "max": round(max(values), 4),
            "p50": round(sorted_v[int(n * 0.50)], 4),
            "p95": round(sorted_v[min(int(n * 0.95), n - 1)], 4),
            "p99": round(sorted_v[min(int(n * 0.99), n - 1)], 4),
        }

    return {
        "run_summary": {
            "total_records": len(flows),
            "records_processed": records_processed,
            "records_dropped": records_dropped,
            "records_malformed": records_malformed,
            "windows_emitted": windows_emitted,
            "total_alerts": len(all_alerts),
            "unique_threat_classes": list(set(
                a.get("threat_class", "") for a in all_alerts
            )),
            "total_incidents": len(incidents),
            "total_duration_sec": round(total_duration, 4),
            "throughput_rps": round(records_processed / max(total_duration, 0.001), 2),
            "speed_factor": speed,
            "window_size_sec": window_size,
            "slide_interval_sec": slide_interval,
            "errors": errors,
        },
        "latency_metrics": {
            "per_record": _stats(latencies),
            "ingest": _stats(ingest_latencies),
            "feature_extraction": _stats(feature_latencies),
            "detection": _stats(detection_latencies),
            "storage": _stats(storage_latencies),
            "end_to_end_alert": _stats(e2e_latencies),
        },
        "throughput_metrics": {
            "records_per_second": round(records_processed / max(total_duration, 0.001), 2),
            "alerts_per_second": round(len(all_alerts) / max(total_duration, 0.001), 4),
            "windows_per_second": round(windows_emitted / max(total_duration, 0.001), 4),
        },
        "system_metrics": {
            "cpu_percent": _stats(cpu_samples),
            "memory_mb": _stats(mem_samples),
            "system_info": get_system_info(),
        },
        "alerts": all_alerts,
        "processing_events": processing_events,
        "incidents": incidents,
    }


def evaluate_detection_quality(
    alerts: list[dict],
    expected_labels: list[str],
    is_benign: bool = False,
) -> dict:
    """Evaluate detection quality against ground truth."""
    detected_classes = set(a.get("threat_class", "") for a in alerts)
    expected_set = set(expected_labels)

    if is_benign:
        # For benign: any high-severity alert is a false positive
        high_sev_alerts = [
            a for a in alerts
            if a.get("severity") in ("CRITICAL", "HIGH")
        ]
        return {
            "scenario_type": "benign",
            "total_alerts": len(alerts),
            "high_severity_false_positives": len(high_sev_alerts),
            "false_positive_rate": round(len(high_sev_alerts) / max(len(alerts), 1), 4),
            "pass": len(high_sev_alerts) <= 2,  # Allow up to 2 FP
        }

    # For threat scenarios
    true_positives = len(expected_set & detected_classes)
    false_negatives = len(expected_set - detected_classes)
    # False positives: detected classes NOT in expected (but exclude LOW severity)
    unexpected = detected_classes - expected_set
    false_positives = len([
        a for a in alerts
        if a.get("threat_class") in unexpected
        and a.get("severity") in ("CRITICAL", "HIGH", "MEDIUM")
    ])

    precision = true_positives / max(true_positives + false_positives, 1)
    recall = true_positives / max(true_positives + false_negatives, 1)
    f1 = 2 * precision * recall / max(precision + recall, 0.001)

    return {
        "scenario_type": "threat",
        "expected_labels": list(expected_set),
        "detected_labels": list(detected_classes),
        "true_positives": true_positives,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "total_alerts": len(alerts),
        "pass": recall >= 0.5,  # At least 50% of expected classes detected
    }


def run_scenario(
    scenario_name: str,
    seed: int,
    speed: float = 0.0,
    window_size: int = 10,
    slide_interval: int = 5,
) -> dict:
    """Run a single scenario end-to-end."""
    # Import generator
    from scripts.test_traffic_generator import SCENARIO_GENERATORS

    if scenario_name not in SCENARIO_GENERATORS:
        raise ValueError(f"Unknown scenario: {scenario_name}")

    generator = SCENARIO_GENERATORS[scenario_name]
    flows, meta = generator(seed=seed)

    print(f"  Running {meta.scenario_id}: {meta.total_records} records, speed={speed}")

    result = run_pipeline_with_timestamps(
        flows, speed=speed, window_size=window_size, slide_interval=slide_interval,
    )

    quality = evaluate_detection_quality(
        result["alerts"],
        meta.expected_threat_labels,
        is_benign=(scenario_name == "benign"),
    )

    return {
        "scenario_metadata": {
            "scenario_name": meta.scenario_name,
            "scenario_id": meta.scenario_id,
            "seed": meta.seed,
            "total_records": meta.total_records,
            "expected_labels": meta.expected_threat_labels,
            "description": meta.description,
        },
        "run_summary": result["run_summary"],
        "latency_metrics": result["latency_metrics"],
        "throughput_metrics": result["throughput_metrics"],
        "system_metrics": result["system_metrics"],
        "detection_quality": quality,
        "alerts_count": len(result["alerts"]),
        "incidents_count": len(result["incidents"]),
    }


def save_run_results(results: dict, run_id: str, output_dir: Path) -> Path:
    """Save all run results to the output directory."""
    run_dir = output_dir / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    # Save individual files
    for key in ["run_summary", "latency_metrics", "throughput_metrics", "system_metrics"]:
        if key in results:
            with open(run_dir / f"{key}.json", "w") as f:
                json.dump(results[key], f, indent=2, default=str)

    if "alerts" in results:
        with open(run_dir / "alerts.jsonl", "w") as f:
            for alert in results["alerts"]:
                f.write(json.dumps(alert, default=str) + "\n")

    if "processing_events" in results:
        with open(run_dir / "processing_events.jsonl", "w") as f:
            for event in results["processing_events"]:
                f.write(json.dumps(event, default=str) + "\n")

    if "scenario_metadata" in results:
        with open(run_dir / "scenario_metadata.json", "w") as f:
            json.dump(results.get("scenario_metadata", {}), f, indent=2, default=str)

    return run_dir


def main():
    parser = argparse.ArgumentParser(description="UniShield Replay Stream")
    parser.add_argument("--scenario", type=str, help="Scenario name: benign, ddos, scan, beacon, exfil")
    parser.add_argument("--input", type=str, help="Path to flows.jsonl file")
    parser.add_argument("--speed", type=float, default=0.0, help="Replay speed (0=max speed, 1.0=real-time)")
    parser.add_argument("--window-size", type=int, default=10, help="Window size in seconds")
    parser.add_argument("--slide-interval", type=int, default=5, help="Slide interval in seconds")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    parser.add_argument("--all", action="store_true", help="Run all scenarios")
    parser.add_argument("--runs", type=int, default=5, help="Number of runs per scenario")
    args = parser.parse_args()

    output_base = _project_root / "reports" / "realtime_runs"
    output_base.mkdir(parents=True, exist_ok=True)

    timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    if args.all:
        print("=" * 60)
        print("UniShield Full Real-Time Verification Suite")
        print("=" * 60)

        all_results = []
        scenarios = ["benign", "ddos", "scan", "beacon", "exfil"]

        for scenario in scenarios:
            print(f"\n--- Scenario: {scenario} ---")
            for run_idx in range(args.runs):
                seed = hash(f"{scenario}-{run_idx}") % (2**31)
                try:
                    result = run_scenario(
                        scenario, seed=seed,
                        speed=args.speed,
                        window_size=args.window_size,
                        slide_interval=args.slide_interval,
                    )
                    run_id = f"run_{timestamp_str}_{scenario}_{run_idx}"
                    save_run_results(result, run_id, output_base)
                    all_results.append(result)
                    status = "PASS" if result["detection_quality"].get("pass", False) else "FAIL"
                    print(f"    Run {run_idx}: {status} | "
                          f"Alerts={result['alerts_count']} | "
                          f"Throughput={result['throughput_metrics']['records_per_second']} rps")
                except Exception as e:
                    print(f"    Run {run_idx}: ERROR — {e}")

        # Generate aggregate report
        _generate_aggregate_report(all_results, output_base / f"aggregate_{timestamp_str}.json")
        print(f"\nResults saved to: {output_base}")

    elif args.scenario:
        result = run_scenario(
            args.scenario, seed=args.seed,
            speed=args.speed,
            window_size=args.window_size,
            slide_interval=args.slide_interval,
        )
        run_id = f"run_{timestamp_str}_{args.scenario}"
        run_dir = save_run_results(result, run_id, output_base)
        print(f"\nResults saved to: {run_dir}")
        print(json.dumps(result["run_summary"], indent=2))

    elif args.input:
        flows = load_flows_from_jsonl(Path(args.input))
        print(f"Loaded {len(flows)} flows from {args.input}")
        result = run_pipeline_with_timestamps(
            flows, speed=args.speed,
            window_size=args.window_size,
            slide_interval=args.slide_interval,
        )
        run_id = f"run_{timestamp_str}_custom"
        run_dir = save_run_results(result, run_id, output_base)
        print(f"\nResults saved to: {run_dir}")
        print(json.dumps(result["run_summary"], indent=2))

    else:
        parser.print_help()


def _generate_aggregate_report(all_results: list[dict], output_path: Path) -> None:
    """Generate aggregate report across all runs."""
    by_scenario: dict[str, list[dict]] = {}
    for r in all_results:
        name = r.get("scenario_metadata", {}).get("scenario_name", "unknown")
        by_scenario.setdefault(name, []).append(r)

    aggregate = {}
    for scenario, runs in by_scenario.items():
        throughputs = [r["throughput_metrics"]["records_per_second"] for r in runs]
        p95s = [r["latency_metrics"]["per_record"]["p95"] for r in runs]
        passes = sum(1 for r in runs if r["detection_quality"].get("pass", False))
        total_alerts = [r["alerts_count"] for r in runs]

        aggregate[scenario] = {
            "runs": len(runs),
            "passes": passes,
            "pass_rate": round(passes / len(runs), 2),
            "throughput_rps": {
                "mean": round(statistics.mean(throughputs), 2),
                "median": round(statistics.median(throughputs), 2),
                "min": round(min(throughputs), 2),
                "max": round(max(throughputs), 2),
            },
            "p95_latency_ms": {
                "mean": round(statistics.mean(p95s), 4),
                "median": round(statistics.median(p95s), 4),
                "min": round(min(p95s), 4),
                "max": round(max(p95s), 4),
            },
            "alerts": {
                "mean": round(statistics.mean(total_alerts), 2),
                "min": min(total_alerts),
                "max": max(total_alerts),
            },
        }

    with open(output_path, "w") as f:
        json.dump(aggregate, f, indent=2)


if __name__ == "__main__":
    main()
