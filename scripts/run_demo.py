"""
UniShield - One-command offline demo

Runs everything on this machine with synthetic or locally written data;
nothing is downloaded and nothing is sent on any network:

  1. writes sample input files to data/samples/
  2. runs every labelled scenario and compares raised vs expected classes
  3. builds a window dataset, trains and calibrates the models, compares
     rules / statistics / RF / XGBoost / Isolation Forest / hybrid
  4. benchmarks throughput and alert latency (5 runs)
  5. paced real-time replay with end-to-end timestamps (5 runs)
  6. verifies passive operation (static scan + runtime tripwire)
  7. draws charts (if matplotlib is installed)

Every number it prints is measured in this run and written to reports/.

Usage:
    python scripts/run_demo.py            # full (several minutes)
    python scripts/run_demo.py --quick    # fewer seeds/runs (about a minute)
    python scripts/run_demo.py --serve    # then start the dashboard on http://127.0.0.1:8000
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REPORTS = ROOT / "reports"
NOTICE = ("This system is a passive defensive research prototype. It does not probe, block, decrypt, "
          "or send commands to monitored systems.")


def step(n: int, title: str) -> float:
    print(f"\n[{n}/7] {title}")
    return time.time()


def done(started: float) -> None:
    print(f"      done in {time.time() - started:.1f} s")


def run_scenarios(seed: int) -> dict:
    from unishield.data.sample_generator import SCENARIO_NAMES, SimulatedReader, build_scenario
    from unishield.processing.pipeline import Pipeline

    rows = []
    for name in SCENARIO_NAMES:
        scenario = build_scenario(name, seed)
        result = Pipeline().run(SimulatedReader(scenario.flows))
        detected = sorted({a.threat_class.value for a in result.alerts})
        expected = sorted(scenario.expected_classes)
        unexpected = sorted(set(detected) - set(expected) - {"STATISTICAL_ANOMALY"})
        ok = set(expected) <= set(detected) and not unexpected
        rows.append({"scenario": name, "expected": expected, "detected": detected, "alerts": len(result.alerts),
                     "records": result.total_records, "ok": ok})
        print(f"      {'PASS' if ok else 'FAIL'}  {name:18s} expected {expected or ['none']}  raised {detected or ['none']}")
    return {"seed": seed, "scenarios": rows, "passed": sum(r["ok"] for r in rows), "total": len(rows)}


def run_script(args: list[str]) -> int:
    """Run one of the project scripts with the current interpreter (local subprocess, no network)."""
    return subprocess.call([sys.executable, *args], cwd=ROOT)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument("--quick", action="store_true", help="fewer seeds and runs")
    parser.add_argument("--serve", action="store_true", help="start the API + dashboard afterwards")
    args = parser.parse_args()
    quick = args.quick

    print("=" * 72)
    print("UniShield - AI security for one-way networks: offline demo")
    print(NOTICE)
    print("=" * 72)
    REPORTS.mkdir(exist_ok=True)
    statuses: dict[str, str] = {}

    t = step(1, "Writing sample input files to data/samples/")
    statuses["samples"] = "ok" if run_script(["scripts/make_samples.py", "--out", "data/samples"]) == 0 else "failed"
    done(t)

    t = step(2, "Running labelled scenarios through the pipeline")
    demo = run_scenarios(seed=11)
    demo["generated_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    (REPORTS / "demo_detection.json").write_text(json.dumps(demo, indent=2), encoding="utf-8")
    statuses["scenarios"] = f"{demo['passed']}/{demo['total']} passed"
    done(t)

    t = step(3, "Dataset, model training, calibration and comparison")
    seeds = "1-6" if quick else "1-20"
    dataset = "data/processed/windows_synthetic.csv"
    rc = run_script(["scripts/prepare_dataset.py", "--synthetic", "--seeds", seeds, "--out", dataset])
    rc = rc or run_script(["scripts/train_models.py", "--dataset", dataset])
    rc = rc or run_script(["scripts/evaluate_models.py", "--dataset", dataset] + (["--no-ablations"] if quick else []))
    statuses["models"] = "ok" if rc == 0 else "failed"
    done(t)

    t = step(4, "Throughput and latency benchmark")
    bench_args = ["--records", "10000", "--runs", "2", "--pcap-packets", "3000"] if quick else []
    rc = run_script(["scripts/benchmark_pipeline.py", *bench_args])
    statuses["benchmark"] = "targets met" if rc == 0 else "targets NOT met or failed"
    done(t)

    t = step(5, "Paced real-time replay with end-to-end timestamps")
    replay_args = ["--runs", "2", "--speed", "60"] if quick else []
    statuses["realtime"] = "ok" if run_script(["scripts/replay_stream.py", *replay_args]) == 0 else "failed"
    done(t)

    t = step(6, "Passive-mode verification")
    statuses["passive"] = "PASSED" if run_script(["scripts/verify_passive_mode.py"]) == 0 else "FAILED"
    done(t)

    t = step(7, "Charts")
    statuses["charts"] = "ok" if run_script(["scripts/generate_charts.py"]) == 0 else "skipped"
    done(t)

    print("\n" + "=" * 72)
    print("Summary")
    for k, v in statuses.items():
        print(f"  {k:10s} {v}")
    print("Reports: reports/model_evaluation.md, reports/benchmark.md, reports/realtime_verdict.md,")
    print("         reports/passive_mode_verification.md, reports/figures/")
    print("=" * 72)

    if args.serve:
        print("\nStarting the API and dashboard on http://127.0.0.1:8000/dashboard (Ctrl+C to stop)")
        return subprocess.call([sys.executable, "-m", "uvicorn", "unishield.api.app:app",
                                "--host", "127.0.0.1", "--port", "8000"], cwd=ROOT)
    print("\nStart the dashboard with:  python -m unishield.main   (http://127.0.0.1:8000/dashboard)")
    failed = statuses["passive"] != "PASSED" or demo["passed"] != demo["total"] or "failed" in statuses.values()
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
