"""
UniShield - Learning mode: suggest site thresholds from a site's own traffic

Runs the pipeline over days of the site's traffic (Zeek log directories or
files, flow CSV/JSON, PCAP) without reporting alerts, records how close
benign traffic came to each threshold, and writes:

    - a suggested thresholds overlay (default configs/thresholds.site.yaml)
      with the percentile, observed value and default behind every value
    - a Markdown report (default reports/learning_report.md)

configs/thresholds.yaml is never written. Select the overlay, after review,
with site.thresholds_file in config.yaml or UNISHIELD_THRESHOLDS_FILE.
Learning compares against thresholds.yaml alone (an active overlay is
ignored) and uses the asset inventory, so list scanners, backup targets,
resolvers, update servers and monitoring hosts in assets.yaml first.

Usage:
    python scripts/learn_baseline.py data/zeek/2026-10-01 data/zeek/2026-10-02 ...
    python scripts/learn_baseline.py flows_week.csv --percentile 99.5 --margin 1.3
    python scripts/learn_baseline.py --synthetic-hours 24      # demonstration on generated traffic
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

from unishield.assets import AssetInventory
from unishield.config import (
    config_dir,
    get_thresholds,
    load_thresholds,
    reset_thresholds,
    threshold_sources,
)
from unishield.data.sample_generator import SimulatedReader
from unishield.data.site_traffic import SiteTraffic, site_assets
from unishield.evaluation.learning import learn, render_report, render_site_thresholds
from unishield.ingest.detect import open_reader
from unishield.processing.state_store import PipelineStateStore


def synthetic_inputs(hours: float, rate: float, seed: int):
    """Generated site traffic in one-hour readers (records are produced lazily)."""
    traffic = SiteTraffic(rate_per_sec=rate, seed=seed)

    def hour(end):
        while traffic.now < end:
            yield from traffic.next_chunk(5.0)

    class _Hour(SimulatedReader):
        def __init__(self, end):
            super().__init__([])
            self._end = end

        def read(self):
            for f in hour(self._end):
                self._records_read += 1
                yield f

    for h in range(int(hours)):
        yield f"synthetic:site:{seed}:hour{h + 1}", _Hour(traffic.start + timedelta(hours=h + 1))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument("inputs", nargs="*", type=Path, help="traffic files or Zeek directories, oldest first")
    parser.add_argument("--out", type=Path, default=config_dir() / "thresholds.site.yaml")
    parser.add_argument("--report", type=Path, default=Path("reports") / "learning_report.md")
    parser.add_argument("--percentile", type=float, default=99.9)
    parser.add_argument("--margin", type=float, default=None,
                        help="headroom over the observed value for volume thresholds (default 1.5)")
    parser.add_argument("--allow-tighten", action="store_true",
                        help="also suggest stricter values where the site stayed far below a threshold")
    parser.add_argument("--state-out", type=Path, default=None,
                        help="also save the learned detector state (warm start with state.path)")
    parser.add_argument("--force", action="store_true", help="overwrite an existing --out file")
    parser.add_argument("--synthetic-hours", type=float, default=0,
                        help="learn from generated site traffic instead of inputs (demonstration)")
    parser.add_argument("--synthetic-rate", type=float, default=10.0, help="records per traffic second")
    parser.add_argument("--synthetic-assets", action="store_true",
                        help="apply the generated site's asset inventory instead of assets.yaml")
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--home-networks", default=None,
                        help="comma-separated CIDRs of the monitored network (default: network.home_networks)")
    args = parser.parse_args()

    if not args.inputs and not args.synthetic_hours:
        parser.error("give traffic inputs or --synthetic-hours")
    if not 50 <= args.percentile < 100:
        parser.error("--percentile must be in [50, 100)")
    base = (config_dir() / "thresholds.yaml").resolve()
    out = args.out.resolve()
    if out == base or out.name == "thresholds.yaml":
        parser.error("refusing to write thresholds.yaml: learning only writes an overlay (e.g. thresholds.site.yaml)")
    if out.exists() and not args.force:
        parser.error(f"{args.out} exists; review it, move it away or pass --force")

    reset_thresholds()
    current = load_thresholds(use_site=False)                     # learn against thresholds.yaml alone
    defaults = yaml.safe_load(base.read_text(encoding="utf-8")) if base.is_file() else current
    if args.synthetic_hours:
        inputs = synthetic_inputs(args.synthetic_hours, args.synthetic_rate, args.seed)
        assets = AssetInventory(site_assets()) if args.synthetic_assets else AssetInventory.from_config()
    else:
        inputs = ((str(p), open_reader(p)[0]) for p in args.inputs)
        assets = AssetInventory.from_config()
    store = PipelineStateStore(args.state_out) if args.state_out else None

    def progress(name, result):
        print(f"  {name}: {result.total_records:,} records, {result.total_windows:,} windows", flush=True)

    print(f"Learning (no alerts are stored or sent); asset inventory: {len(assets)} entries", flush=True)
    normalizer = None
    if args.home_networks:
        from unishield.processing.normalization import Normalizer

        normalizer = Normalizer(home_networks=args.home_networks.split(","))
    run = learn(inputs, thresholds=get_thresholds(), threshold_sources=threshold_sources(), assets=assets,
                state_store=store, progress=progress, normalizer=normalizer)
    suggestions = run.learner.suggest(defaults, percentile=args.percentile, margin=args.margin,
                                      allow_tighten=args.allow_tighten)
    meta = run.meta(datetime.now(timezone.utc).isoformat(timespec="seconds"), args.percentile, args.allow_tighten)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(render_site_thresholds(suggestions, defaults, current, meta), encoding="utf-8")
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(render_report(run.learner, suggestions, meta), encoding="utf-8")

    changed = [s for s in suggestions if s.changed]
    print(f"{run.records:,} records, {run.learner.windows:,} windows; {len(changed)} thresholds differ from defaults")
    for s in changed:
        print(f"  {s.key}: {s.default} -> {s.suggested}  ({s.reason})")
    print(f"Wrote {args.out} (not active until selected) and {args.report}")
    if store is not None:
        print(f"Detector state saved to {args.state_out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
