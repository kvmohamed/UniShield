"""
UniShield - Paced real-time replay with end-to-end timestamps

Replays synthetic traffic at a multiple of its original pace through the
real pipeline while the API is polled for new alerts, and measures for each
alert: window end -> window closed -> stored -> visible in the API.
Writes reports/realtime_report.json and reports/realtime_verdict.md.
Nothing is sent on any network.

Usage:
    python scripts/replay_stream.py                  # 5 runs at 20x
    python scripts/replay_stream.py --runs 2 --speed 50
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from unishield.evaluation.realtime import render_verdict, run_realtime


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--speed", type=float, default=20.0, help="replay speed (x real time)")
    parser.add_argument("--seed", type=int, default=2000)
    parser.add_argument("--poll", type=float, default=0.1, help="API poll interval in seconds")
    parser.add_argument("--out", type=Path, default=Path("reports"))
    args = parser.parse_args()

    report = run_realtime(args.runs, args.speed, args.seed, args.poll)
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "realtime_report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    bench_path = args.out / "benchmark.json"
    benchmark = json.loads(bench_path.read_text(encoding="utf-8")) if bench_path.is_file() else None
    (args.out / "realtime_verdict.md").write_text(render_verdict(report, benchmark), encoding="utf-8")

    s = report["statistics_ms"]
    for key in ("close_delay_ms", "processing_ms", "api_visibility_ms", "end_to_end_ms"):
        if key in s:
            print(f"{key:20s} median {s[key]['median']:>9} ms   max {s[key]['max']:>9} ms")
    print(f"Alerts not seen by the API: {report['alerts_not_seen_by_api']}")
    print(f"Wrote {args.out / 'realtime_verdict.md'}")


if __name__ == "__main__":
    main()
