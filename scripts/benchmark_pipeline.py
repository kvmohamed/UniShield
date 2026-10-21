"""
UniShield - Pipeline performance benchmark

Runs the real pipeline over a deterministic synthetic workload several times
(after a warm-up run) and over a written PCAP, then writes
reports/benchmark.json, reports/benchmark.md and an archived copy under
reports/benchmark_results/. Nothing is sent on any network.

Usage:
    python scripts/benchmark_pipeline.py                 # 5 runs x 20,000 records
    python scripts/benchmark_pipeline.py --records 50000 --runs 5
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

from unishield.evaluation.benchmark import render_markdown, run_benchmark


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument("--records", type=int, default=20_000)
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--seed", type=int, default=1000)
    parser.add_argument("--pcap-packets", type=int, default=10_000, help="0 to skip the PCAP measurement")
    parser.add_argument("--out", type=Path, default=Path("reports"))
    args = parser.parse_args()

    report = run_benchmark(args.records, args.runs, args.seed, args.pcap_packets)
    args.out.mkdir(parents=True, exist_ok=True)
    text = json.dumps(report, indent=2)
    (args.out / "benchmark.json").write_text(text, encoding="utf-8")
    archive = args.out / "benchmark_results"
    archive.mkdir(exist_ok=True)
    (archive / f"benchmark_{time.strftime('%Y%m%d_%H%M%S')}.json").write_text(text, encoding="utf-8")
    (args.out / "benchmark.md").write_text(render_markdown(report), encoding="utf-8")

    s = report["statistics"]
    print(f"Throughput: mean {s['throughput_records_per_sec']['mean']:,} records/s "
          f"(min {s['throughput_records_per_sec']['min']:,}) over {args.runs} runs")
    print(f"Alert latency after window close, P95: mean {s['alert_latency_after_close_p95_ms']['mean']} ms "
          f"(max {s['alert_latency_after_close_p95_ms']['max']} ms)")
    for name, t in report["targets"].items():
        print(f"Target {name}: {'met' if t['met'] else 'NOT met'} - {t['description']}")
    print(f"Wrote {args.out / 'benchmark.md'} and {args.out / 'benchmark.json'}")
    return 0 if all(t["met"] for t in report["targets"].values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
