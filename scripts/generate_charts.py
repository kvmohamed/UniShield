"""
UniShield - Charts from the measured reports

Reads reports/benchmark.json, reports/realtime_report.json,
reports/model_evaluation.json and reports/demo_detection.json (whichever
exist) and writes PNG charts to reports/figures/. Requires matplotlib
(pip install -e .[reports]).

Usage:
    python scripts/generate_charts.py [--reports reports]
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def _load(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def throughput_chart(plt, bench, out: Path) -> Path:
    runs = bench["per_run"]
    fig, ax = plt.subplots(figsize=(7, 3.8))
    ax.bar([str(r["seed"]) for r in runs], [r["records_per_second"] for r in runs], color="#4ea1ff")
    ax.axhline(1000, color="#ff4d6d", linestyle="--", label="target 1,000 records/s")
    ax.set_xlabel("run (seed)")
    ax.set_ylabel("records / second")
    ax.set_title(f"Pipeline throughput, {bench['records']:,} records per run")
    ax.legend(loc="lower right")
    fig.tight_layout()
    path = out / "throughput_per_run.png"
    fig.savefig(path, dpi=130)
    plt.close(fig)
    return path


def latency_chart(plt, realtime, out: Path) -> Path:
    keys = [("close_delay_ms", "window close\ndelay"), ("processing_ms", "processing\n(close -> stored)"),
            ("api_visibility_ms", "API visibility\n(stored -> seen)"), ("end_to_end_ms", "end to end\n(window end -> seen)")]
    data = [[a[k] for a in realtime["alerts"] if a[k] is not None] for k, _ in keys]
    fig, ax = plt.subplots(figsize=(8, 4))
    ax.boxplot(data, showfliers=True)
    ax.set_xticks(range(1, len(keys) + 1), [label for _, label in keys])
    ax.set_ylabel("milliseconds (wall time)")
    ax.set_title(f"Per-alert latency, {realtime['runs']} paced replays at {realtime['speed']}x")
    fig.tight_layout()
    path = out / "latency_breakdown.png"
    fig.savefig(path, dpi=130)
    plt.close(fig)
    return path


def model_chart(plt, evaluation, out: Path) -> Path:
    approaches = evaluation["results"]["approaches"]
    names = list(approaches)
    metrics = ["precision", "recall", "f1"]
    width = 0.26
    fig, ax = plt.subplots(figsize=(9, 4))
    for i, m in enumerate(metrics):
        ax.bar([x + (i - 1) * width for x in range(len(names))], [approaches[n][m] for n in names], width, label=m)
    ax.set_xticks(range(len(names)), names, rotation=15)
    ax.set_ylim(0, 1.05)
    ax.set_title("Window-level detection on held-out runs (synthetic data)")
    ax.legend(loc="lower right")
    fig.tight_layout()
    path = out / "model_comparison.png"
    fig.savefig(path, dpi=130)
    plt.close(fig)
    return path


def detection_chart(plt, demo, out: Path) -> Path:
    rows = demo["scenarios"]
    classes = sorted({c for r in rows for c in r["expected"] + r["detected"]})
    fig, ax = plt.subplots(figsize=(max(7, len(classes) * 0.9), 0.45 * len(rows) + 1.8))
    for y, r in enumerate(rows):
        for x, c in enumerate(classes):
            expected, found = c in r["expected"], c in r["detected"]
            color = "#3fb950" if expected and found else "#ff4d6d" if expected or found else "#e6e9ee"
            ax.add_patch(plt.Rectangle((x, y), 0.95, 0.9, color=color))
    ax.set_xlim(0, len(classes))
    ax.set_ylim(0, len(rows))
    ax.set_xticks([x + 0.45 for x in range(len(classes))], classes, rotation=40, ha="right", fontsize=8)
    ax.set_yticks([y + 0.45 for y in range(len(rows))], [r["scenario"] for r in rows], fontsize=8)
    ax.invert_yaxis()
    ax.set_title("Scenario detection (green: expected and raised; red: missed or unexpected)")
    fig.tight_layout()
    path = out / "detection_matrix.png"
    fig.savefig(path, dpi=130)
    plt.close(fig)
    return path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument("--reports", type=Path, default=Path("reports"))
    args = parser.parse_args()
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("matplotlib is not installed; skipping charts (pip install -e .[reports])")
        return 1

    out = args.reports / "figures"
    out.mkdir(parents=True, exist_ok=True)
    written = []
    sources = [("benchmark.json", throughput_chart), ("realtime_report.json", latency_chart),
               ("model_evaluation.json", model_chart), ("demo_detection.json", detection_chart)]
    for name, chart in sources:
        data = _load(args.reports / name)
        if data is None:
            print(f"skip {name}: not found")
            continue
        written.append(chart(plt, data, out))
    for path in written:
        print(f"wrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
