"""
UniShield - Soak test

Streams continuous synthetic site traffic through one pipeline for a
wall-clock duration at a chosen record rate, sampling memory, CPU, lag,
window latency, alert rate and state size at a fixed interval, and writes
reports/soak_test.{json,md}.

Usage:
    python scripts/soak_test.py --duration 24h --rate 1000             # full soak
    python scripts/soak_test.py --duration 30m --rate 1000 --speedup 8  # 30 min covering 4 h of traffic
    python scripts/soak_test.py --quick                                 # 2 min, samples every 10 s (CI-like)
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

from unishield.evaluation.soak import SoakConfig, render_markdown, run_soak


def parse_duration(text: str) -> float:
    match = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*([smh]?)\s*", text)
    if not match:
        raise argparse.ArgumentTypeError(f"invalid duration {text!r} (e.g. 90s, 30m, 24h)")
    value, unit = float(match.group(1)), match.group(2) or "s"
    return value * {"s": 1, "m": 60, "h": 3600}[unit]


def git_commit() -> str | None:
    try:
        out = subprocess.run(["git", "rev-parse", "--short", "HEAD"], capture_output=True, text=True,
                             timeout=10, check=True)
        dirty = subprocess.run(["git", "status", "--porcelain", "--untracked-files=no"], capture_output=True,
                               text=True, timeout=10).stdout.strip()
        return out.stdout.strip() + ("+uncommitted changes" if dirty else "")
    except (OSError, subprocess.SubprocessError):
        return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument("--duration", type=parse_duration, default=parse_duration("30m"))
    parser.add_argument("--rate", type=float, default=1000.0, help="records per wall-clock second")
    parser.add_argument("--speedup", type=float, default=1.0, help="traffic seconds per wall-clock second")
    parser.add_argument("--sample-every", type=parse_duration, default=60.0)
    parser.add_argument("--profile", choices=["site", "plain"], default="site")
    parser.add_argument("--attack-every", type=parse_duration, default=900.0,
                        help="traffic time between injected attacks (0: none)")
    parser.add_argument("--no-assets", action="store_true", help="do not apply the site's asset inventory")
    parser.add_argument("--no-state", action="store_true", help="do not snapshot pipeline state")
    parser.add_argument("--snapshot-every", type=parse_duration, default=60.0)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--quick", action="store_true", help="2 minutes, samples every 10 s")
    parser.add_argument("--notes", default="", help="text added to the report's Notes section")
    parser.add_argument("--out", type=Path, default=Path("reports"))
    args = parser.parse_args()
    if args.quick:
        args.duration, args.sample_every = 120.0, 10.0

    state_dir = Path(tempfile.mkdtemp(prefix="unishield-soak-"))
    cfg = SoakConfig(
        duration_sec=args.duration, rate=args.rate, speedup=args.speedup, sample_every_sec=args.sample_every,
        profile=args.profile, attack_every_sec=args.attack_every or None, use_assets=not args.no_assets,
        state_path=None if args.no_state else str(state_dir / "pipeline_state.json"),
        snapshot_interval_sec=args.snapshot_every, seed=args.seed,
    )

    def progress(sample):
        print(f"[{sample['elapsed_sec']:>8.0f}s] {sample['records']:>10,} records  "
              f"{sample['records_per_sec']:>7,.0f}/s  lag {sample['max_lag_sec']:.3f}s  "
              f"RSS {sample['rss_mb']:>6.1f} MB  window p95 {sample['window_p95_ms']:>7.2f} ms  "
              f"alerts {sample['alerts']}", flush=True)

    commit = git_commit()                            # the code under test, before the run starts
    print(f"Soak test: {args.duration:.0f} s at {args.rate:,.0f} records/s, speedup {args.speedup:g}", flush=True)
    report = run_soak(cfg, progress)
    report["commit"] = commit
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "soak_test.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    (args.out / "soak_test.md").write_text(render_markdown(report, commit=commit, notes=args.notes),
                                           encoding="utf-8")
    s = report["summary"]
    print(f"Done: {s['records']:,} records, {s['errors']} errors, RSS {s['rss_first_mb']} -> {s['rss_last_mb']} MB "
          f"(max {s['rss_max_mb']}), window p95 {s['window_p95_ms_overall']} ms, max lag {s['max_lag_sec']} s")
    print(f"Wrote {args.out / 'soak_test.md'}")
    return 0 if s["errors"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
