"""
UniShield — Chart Generation for Visual Evidence

Generates charts from verification run data:
- Latency distribution histograms
- Throughput over scenarios
- Detection quality by threat class
- System resource usage
- End-to-end latency timeline

Saves charts as PNG images under reports/realtime_runs/<run_id>/figures/

Usage:
    python scripts/generate_charts.py --results reports/realtime_raw_results.json
    python scripts/generate_charts.py --auto  # Uses latest raw results

SAFETY: No network connections. Read-only analysis of JSON result files.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

_script_dir = Path(__file__).resolve().parent
_project_root = _script_dir.parent
sys.path.insert(0, str(_project_root / "src"))

try:
    import matplotlib
    matplotlib.use("Agg")  # Non-interactive backend
    import matplotlib.pyplot as plt
    import matplotlib.ticker as ticker
    HAS_MPL = True
except ImportError:
    HAS_MPL = False


# ==================================================================
# Colour palette
# ==================================================================
COLORS = {
    "primary": "#6366f1",
    "secondary": "#818cf8",
    "success": "#10b981",
    "warning": "#eab308",
    "danger": "#ef4444",
    "info": "#3b82f6",
    "muted": "#64748b",
    "bg": "#0a0e1a",
    "card": "#1a1f36",
    "text": "#e2e8f0",
    "grid": "#2a3055",
}

SCENARIO_COLORS = {
    "benign": "#10b981",
    "ddos": "#ef4444",
    "scan": "#f97316",
    "beacon": "#eab308",
    "exfil": "#a855f7",
}


def _style_chart(ax, title: str) -> None:
    """Apply consistent dark-theme styling to a chart axis."""
    ax.set_facecolor(COLORS["card"])
    ax.figure.set_facecolor(COLORS["bg"])
    ax.set_title(title, color=COLORS["text"], fontsize=13, fontweight="bold", pad=12)
    ax.tick_params(colors=COLORS["text"], labelsize=9)
    ax.xaxis.label.set_color(COLORS["text"])
    ax.yaxis.label.set_color(COLORS["text"])
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.spines["bottom"].set_color(COLORS["grid"])
    ax.spines["left"].set_color(COLORS["grid"])
    ax.grid(True, alpha=0.15, color=COLORS["grid"])


def chart_latency_distribution(all_results: dict, output_dir: Path) -> Path:
    """Generate latency distribution chart across all scenarios."""
    fig, axes = plt.subplots(1, 2, figsize=(14, 5))

    # P95 latencies by scenario
    ax = axes[0]
    scenarios = []
    p95_values = []
    for scenario, runs in all_results.items():
        for r in runs:
            if "error" in r:
                continue
            p95 = r.get("latency", {}).get("per_record", {}).get("p95", 0)
            scenarios.append(scenario)
            p95_values.append(p95)

    if scenarios:
        unique_scenarios = sorted(set(scenarios))
        by_scenario = {s: [] for s in unique_scenarios}
        for s, v in zip(scenarios, p95_values):
            by_scenario[s].append(v)

        positions = range(len(unique_scenarios))
        box_data = [by_scenario[s] for s in unique_scenarios]
        bp = ax.boxplot(box_data, positions=positions, patch_artist=True,
                       widths=0.6, showmeans=True)

        for i, (patch, s) in enumerate(zip(bp["boxes"], unique_scenarios)):
            patch.set_facecolor(SCENARIO_COLORS.get(s, COLORS["primary"]))
            patch.set_alpha(0.7)
        for element in ["whiskers", "caps", "medians", "means"]:
            for item in bp[element]:
                item.set_color(COLORS["text"])

        ax.set_xticks(positions)
        ax.set_xticklabels([s.upper() for s in unique_scenarios])
    _style_chart(ax, "P95 Latency by Scenario")
    ax.set_ylabel("Latency (ms)")

    # Overall latency percentiles
    ax2 = axes[1]
    percentile_keys = ["p50", "p95", "p99"]
    percentile_labels = ["P50", "P95", "P99"]
    all_percentiles = {k: [] for k in percentile_keys}

    for runs in all_results.values():
        for r in runs:
            if "error" in r:
                continue
            lat = r.get("latency", {}).get("per_record", {})
            for k in percentile_keys:
                v = lat.get(k, 0)
                if v > 0:
                    all_percentiles[k].append(v)

    if any(all_percentiles.values()):
        means = [sum(all_percentiles[k]) / max(len(all_percentiles[k]), 1)
                 for k in percentile_keys]
        bars = ax2.bar(percentile_labels, means,
                       color=[COLORS["success"], COLORS["warning"], COLORS["danger"]],
                       alpha=0.8, width=0.5)
        for bar, val in zip(bars, means):
            ax2.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.01,
                     f"{val:.3f}", ha="center", va="bottom",
                     color=COLORS["text"], fontsize=10, fontweight="bold")

    _style_chart(ax2, "Average Latency Percentiles")
    ax2.set_ylabel("Latency (ms)")

    fig.tight_layout(pad=2.0)
    out = output_dir / "latency_distribution.png"
    fig.savefig(out, dpi=150, bbox_inches="tight")
    plt.close(fig)
    return out


def chart_throughput(all_results: dict, output_dir: Path) -> Path:
    """Generate throughput comparison chart."""
    fig, ax = plt.subplots(figsize=(10, 5))

    scenarios = []
    rps_values = []
    colors = []

    for scenario in ["benign", "ddos", "scan", "beacon", "exfil"]:
        runs = all_results.get(scenario, [])
        for r in runs:
            if "error" in r:
                continue
            rps = r.get("throughput", {}).get("records_per_second", 0)
            scenarios.append(scenario.upper())
            rps_values.append(rps)
            colors.append(SCENARIO_COLORS.get(scenario, COLORS["primary"]))

    if scenarios:
        unique = sorted(set(scenarios), key=lambda s: ["BENIGN", "DDOS", "SCAN", "BEACON", "EXFIL"].index(s) if s in ["BENIGN", "DDOS", "SCAN", "BEACON", "EXFIL"] else 99)
        by_scenario = {s: [] for s in unique}
        for s, v in zip(scenarios, rps_values):
            by_scenario[s].append(v)

        means = [sum(by_scenario[s]) / max(len(by_scenario[s]), 1) for s in unique]
        bar_colors = [SCENARIO_COLORS.get(s.lower(), COLORS["primary"]) for s in unique]

        bars = ax.bar(unique, means, color=bar_colors, alpha=0.85, width=0.6)

        for bar, val in zip(bars, means):
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 50,
                    f"{val:,.0f}", ha="center", va="bottom",
                    color=COLORS["text"], fontsize=11, fontweight="bold")

        # Threshold line at 1000 rps
        ax.axhline(y=1000, color=COLORS["warning"], linestyle="--", alpha=0.5, label="1000 rps threshold")
        ax.legend(facecolor=COLORS["card"], edgecolor=COLORS["grid"],
                  labelcolor=COLORS["text"])

    _style_chart(ax, "Throughput by Scenario (records/sec)")
    ax.set_ylabel("Records per Second")

    fig.tight_layout(pad=2.0)
    out = output_dir / "throughput_comparison.png"
    fig.savefig(out, dpi=150, bbox_inches="tight")
    plt.close(fig)
    return out


def chart_detection_quality(all_results: dict, output_dir: Path) -> Path:
    """Generate detection quality metrics chart."""
    fig, axes = plt.subplots(1, 2, figsize=(14, 5))

    # Pass rate by scenario
    ax = axes[0]
    scenario_names = []
    pass_rates = []
    bar_colors = []

    for scenario in ["benign", "ddos", "scan", "beacon", "exfil"]:
        runs = all_results.get(scenario, [])
        valid_runs = [r for r in runs if "error" not in r]
        if not valid_runs:
            continue
        passes = sum(1 for r in valid_runs if r.get("quality", {}).get("pass", False))
        rate = passes / len(valid_runs) * 100
        scenario_names.append(scenario.upper())
        pass_rates.append(rate)
        bar_colors.append(SCENARIO_COLORS.get(scenario, COLORS["primary"]))

    if scenario_names:
        bars = ax.bar(scenario_names, pass_rates, color=bar_colors, alpha=0.85, width=0.6)
        for bar, val in zip(bars, pass_rates):
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 1,
                    f"{val:.0f}%", ha="center", va="bottom",
                    color=COLORS["text"], fontsize=11, fontweight="bold")
        ax.set_ylim(0, 110)

    _style_chart(ax, "Detection Pass Rate by Scenario")
    ax.set_ylabel("Pass Rate (%)")

    # Alert counts by scenario
    ax2 = axes[1]
    alert_counts = []
    alert_names = []
    alert_colors = []

    for scenario in ["benign", "ddos", "scan", "beacon", "exfil"]:
        runs = all_results.get(scenario, [])
        valid_runs = [r for r in runs if "error" not in r]
        if not valid_runs:
            continue
        avg_alerts = sum(r.get("alerts_count", 0) for r in valid_runs) / len(valid_runs)
        alert_names.append(scenario.upper())
        alert_counts.append(avg_alerts)
        alert_colors.append(SCENARIO_COLORS.get(scenario, COLORS["primary"]))

    if alert_names:
        bars = ax2.bar(alert_names, alert_counts, color=alert_colors, alpha=0.85, width=0.6)
        for bar, val in zip(bars, alert_counts):
            ax2.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.5,
                     f"{val:.1f}", ha="center", va="bottom",
                     color=COLORS["text"], fontsize=11, fontweight="bold")

    _style_chart(ax2, "Average Alerts per Run")
    ax2.set_ylabel("Alert Count")

    fig.tight_layout(pad=2.0)
    out = output_dir / "detection_quality.png"
    fig.savefig(out, dpi=150, bbox_inches="tight")
    plt.close(fig)
    return out


def chart_system_resources(all_results: dict, output_dir: Path) -> Path:
    """Generate system resource usage chart."""
    fig, axes = plt.subplots(1, 2, figsize=(14, 5))

    cpu_values = []
    mem_values = []
    labels = []

    for scenario in ["benign", "ddos", "scan", "beacon", "exfil"]:
        runs = all_results.get(scenario, [])
        for r in runs:
            if "error" in r:
                continue
            sys_metrics = r.get("system", {})
            cpu = sys_metrics.get("cpu_percent", {}).get("mean", 0)
            mem = sys_metrics.get("memory_mb", {}).get("mean", 0)
            if cpu > 0 or mem > 0:
                cpu_values.append(cpu)
                mem_values.append(mem)
                labels.append(scenario.upper())

    # CPU usage
    ax = axes[0]
    if cpu_values:
        unique = sorted(set(labels), key=lambda s: ["BENIGN", "DDOS", "SCAN", "BEACON", "EXFIL"].index(s) if s in ["BENIGN", "DDOS", "SCAN", "BEACON", "EXFIL"] else 99)
        by_scenario = {s: [] for s in unique}
        for l, v in zip(labels, cpu_values):
            by_scenario[l].append(v)
        means = [sum(by_scenario[s]) / max(len(by_scenario[s]), 1) for s in unique]
        bar_colors = [SCENARIO_COLORS.get(s.lower(), COLORS["primary"]) for s in unique]
        ax.bar(unique, means, color=bar_colors, alpha=0.85, width=0.6)

    _style_chart(ax, "CPU Usage by Scenario (%)")
    ax.set_ylabel("CPU %")

    # Memory usage
    ax2 = axes[1]
    if mem_values:
        unique = sorted(set(labels), key=lambda s: ["BENIGN", "DDOS", "SCAN", "BEACON", "EXFIL"].index(s) if s in ["BENIGN", "DDOS", "SCAN", "BEACON", "EXFIL"] else 99)
        by_scenario = {s: [] for s in unique}
        for l, v in zip(labels, mem_values):
            by_scenario[l].append(v)
        means = [sum(by_scenario[s]) / max(len(by_scenario[s]), 1) for s in unique]
        bar_colors = [SCENARIO_COLORS.get(s.lower(), COLORS["primary"]) for s in unique]
        ax2.bar(unique, means, color=bar_colors, alpha=0.85, width=0.6)

    _style_chart(ax2, "Memory Usage by Scenario (MB)")
    ax2.set_ylabel("Memory (MB)")

    fig.tight_layout(pad=2.0)
    out = output_dir / "system_resources.png"
    fig.savefig(out, dpi=150, bbox_inches="tight")
    plt.close(fig)
    return out


def chart_acceptance_criteria(criteria: list[dict], output_dir: Path) -> Path:
    """Generate acceptance criteria pass/fail visual."""
    fig, ax = plt.subplots(figsize=(12, 4))

    names = [c["name"][:40] for c in criteria]
    passes = [1 if c["pass"] else 0 for c in criteria]
    colors_list = [COLORS["success"] if p else COLORS["danger"] for p in passes]

    y_pos = range(len(names))
    bars = ax.barh(y_pos, [1] * len(names), color=colors_list, alpha=0.8, height=0.6)

    for i, (name, c) in enumerate(zip(names, criteria)):
        icon = "✓" if c["pass"] else "✗"
        ax.text(0.02, i, f"  {icon}  {name}", va="center",
                color="white", fontsize=9, fontweight="bold")
        ax.text(0.98, i, c.get("actual", ""), va="center", ha="right",
                color="white", fontsize=8, fontfamily="monospace")

    ax.set_xlim(0, 1)
    ax.set_yticks([])
    ax.set_xticks([])

    _style_chart(ax, f"Acceptance Criteria ({sum(passes)}/{len(passes)} passed)")

    fig.tight_layout(pad=1.5)
    out = output_dir / "acceptance_criteria.png"
    fig.savefig(out, dpi=150, bbox_inches="tight")
    plt.close(fig)
    return out


def generate_all_charts(
    results_path: Path,
    output_dir: Path,
    criteria: list[dict] | None = None,
) -> list[Path]:
    """Generate all charts from raw results."""
    if not HAS_MPL:
        print("WARNING: matplotlib not installed. Skipping chart generation.")
        print("  Install with: pip install matplotlib")
        return []

    with open(results_path, "r") as f:
        all_results = json.load(f)

    output_dir.mkdir(parents=True, exist_ok=True)

    generated = []

    print("Generating charts...")

    try:
        p = chart_latency_distribution(all_results, output_dir)
        generated.append(p)
        print(f"  ✓ {p.name}")
    except Exception as e:
        print(f"  ✗ latency_distribution: {e}")

    try:
        p = chart_throughput(all_results, output_dir)
        generated.append(p)
        print(f"  ✓ {p.name}")
    except Exception as e:
        print(f"  ✗ throughput: {e}")

    try:
        p = chart_detection_quality(all_results, output_dir)
        generated.append(p)
        print(f"  ✓ {p.name}")
    except Exception as e:
        print(f"  ✗ detection_quality: {e}")

    try:
        p = chart_system_resources(all_results, output_dir)
        generated.append(p)
        print(f"  ✓ {p.name}")
    except Exception as e:
        print(f"  ✗ system_resources: {e}")

    if criteria:
        try:
            p = chart_acceptance_criteria(criteria, output_dir)
            generated.append(p)
            print(f"  ✓ {p.name}")
        except Exception as e:
            print(f"  ✗ acceptance_criteria: {e}")

    print(f"\n{len(generated)} charts saved to: {output_dir}")
    return generated


def main():
    parser = argparse.ArgumentParser(description="UniShield Chart Generator")
    parser.add_argument("--results", type=str, help="Path to raw results JSON")
    parser.add_argument("--output", type=str, help="Output directory for charts")
    parser.add_argument("--auto", action="store_true", help="Auto-detect latest results")
    args = parser.parse_args()

    if args.auto:
        default_path = _project_root / "reports" / "realtime_raw_results.json"
        if default_path.exists():
            args.results = str(default_path)
        else:
            print(f"No results file found at {default_path}")
            print("Run the verification suite first: python scripts/run_demo.py")
            sys.exit(1)

    if not args.results:
        parser.print_help()
        sys.exit(1)

    results_path = Path(args.results)
    if not results_path.exists():
        print(f"Results file not found: {results_path}")
        sys.exit(1)

    output_dir = Path(args.output) if args.output else (_project_root / "reports" / "figures")

    generate_all_charts(results_path, output_dir)


if __name__ == "__main__":
    main()
