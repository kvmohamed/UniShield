"""
UniShield - Evaluate on public labelled datasets

Runs the default rules pipeline over CTU-13 binetflow files and/or CIC-IDS2017
TrafficLabelling CSVs, then scores host-level and window-level detection, the
synthetic-trained model on the real windows, and leave-one-file-out models.
Writes reports/public_dataset_evaluation.{json,md}. Files are only read.

Usage:
    python scripts/evaluate_public_datasets.py --ctu13 data/raw/ctu13/*.binetflow
    python scripts/evaluate_public_datasets.py --cicids data/raw/cicids2017/*.csv
"""

from __future__ import annotations

import argparse
import glob
import json
import time
from datetime import datetime, timezone
from pathlib import Path

from unishield.evaluation.public import (
    cross_domain,
    host_metrics,
    leave_one_file_out,
    render_markdown,
    run_file,
    window_metrics,
)

DATASETS = {
    "ctu13": {
        "title": "CTU-13 (Stratosphere Lab, CTU Prague, 2011)",
        "description": "Botnet captures in a university network, as Argus bidirectional flows with labels "
                       "Botnet / Normal / Background.",
        "home_networks": ["147.32.0.0/16"],
        "caveats": [
            "Background flows are unverified university traffic and are counted as benign; some may be "
            "malicious or misconfigured, so 'other hosts named' is an upper bound on false positives.",
            "Botnet flows mix C2, spam, scanning and DDoS and are labelled BOTNET; window labels are binary "
            "here, so class-level accuracy is not measured.",
            "Argus exports have no DNS names or TLS fields, so the DNS and encrypted-session detectors cannot fire.",
            "Timestamps are local capture time read as UTC (consistent within a file).",
            "Findings from inspecting the 2026-10 run: scenario 6's bot sends spam (4,398 failed SMTP "
            "attempts to at most 15 mail servers per 10 s, under the 20-host HOST_SCAN threshold; UniShield has "
            "no spam rule) and was caught only by its C2 beacon after about 6,300 s; scenario 7's bot made 63 "
            "flows in 21 minutes, too few for any rule; scenario 11's ICMP flood reaches only about 60 packets/s "
            "at the capture point, far below the 10,000 packets/s volumetric threshold.",
            "Most other alerts name hosts inside 147.32.0.0/16: regular polling and peer-to-peer traffic "
            "(HTTP, SSH attempts, BitTorrent, POP3 were seen behind beacon alerts) raises C2_BEACONING, large "
            "uploads raise DATA_EXFILTRATION, and failed connection bursts raise PORT_SCAN. Default thresholds "
            "were tuned on synthetic traffic; the asset inventory and learning mode exist for this, but were not "
            "applied here.",
        ],
    },
    "cicids2017": {
        "title": "CIC-IDS2017 (Canadian Institute for Cybersecurity)",
        "description": "Five days of benign and attack traffic in a lab network, as CICFlowMeter flows "
                       "(TrafficLabelling CSVs).",
        "home_networks": [],
        "caveats": [
            "Published analyses report labelling and flow-construction errors in CIC-IDS2017.",
            "CICFlowMeter timestamps are local lab time with minute resolution in some files.",
            "CICFlowMeter flows carry no DNS names or TLS fields.",
        ],
    },
}


def _expand(patterns: list[str]) -> list[Path]:
    files: list[Path] = []
    for p in patterns:
        matches = glob.glob(p)
        files += [Path(m) for m in sorted(matches)] if matches else [Path(p)]
    return [f for f in files if f.is_file()]


def evaluate_dataset(key: str, files: list[Path], synthetic: Path) -> dict:
    spec = DATASETS[key]
    runs = []
    for f in files:
        started = time.time()
        run = run_file(f, spec["home_networks"] or None)
        print(f"  {f.name}: {run.records:,} records, {len(run.windows):,} windows, {len(run.alerts)} alerts "
              f"({time.time() - started:.0f} s)")
        runs.append(run)
    all_windows = [w for r in runs for w in r.windows]
    return {
        "dataset": spec["title"],
        "key": key,
        "description": spec["description"],
        "home_networks": spec["home_networks"],
        "caveats": spec["caveats"],
        "files": [{
            "name": r.name, "format": r.fmt, "records": r.records, "reader_errors": r.reader_errors,
            "traffic_hours": r.traffic_hours, "labels": r.labels,
            "window": window_metrics(r.windows), "host": host_metrics(r),
        } for r in runs],
        "cross_domain": cross_domain(synthetic, all_windows),
        "leave_one_file_out": leave_one_file_out(runs),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument("--ctu13", nargs="*", default=[], help="CTU-13 .binetflow files (globs allowed)")
    parser.add_argument("--cicids", nargs="*", default=[], help="CIC-IDS2017 TrafficLabelling CSVs (globs allowed)")
    parser.add_argument("--synthetic", type=Path, default=Path("data/processed/windows_synthetic.csv"),
                        help="synthetic window dataset for the cross-domain model")
    parser.add_argument("--out", type=Path, default=Path("reports"))
    args = parser.parse_args()

    report = {"generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"), "datasets": []}
    for key, patterns in (("ctu13", args.ctu13), ("cicids2017", args.cicids)):
        files = _expand(patterns)
        if not files:
            continue
        print(f"{DATASETS[key]['title']}: {len(files)} files")
        report["datasets"].append(evaluate_dataset(key, files, args.synthetic))
    if not report["datasets"]:
        parser.error("no input files found")

    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "public_dataset_evaluation.json").write_text(json.dumps(report, indent=2, default=str),
                                                           encoding="utf-8")
    (args.out / "public_dataset_evaluation.md").write_text(render_markdown(report), encoding="utf-8")
    print(f"Wrote {args.out / 'public_dataset_evaluation.md'}")


if __name__ == "__main__":
    main()
