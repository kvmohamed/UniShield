"""
UniShield — Build a labelled window dataset

Runs the real pipeline over labelled input and writes one row per analysed
window (model features, label, what the rule and statistical stages
concluded) plus a manifest with the file's SHA-256.

Usage:
    python scripts/prepare_dataset.py --synthetic --seeds 1-20
    python scripts/prepare_dataset.py --input data/raw/cicids_subset.csv --out data/processed/windows_cicids.csv

Input files need a label column (e.g. CICIDS2017 "Label", CTU-13 binetflow
"Label"); unlabelled flows count as benign. Nothing is sent on any network.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from unishield.data.sample_generator import SCENARIO_NAMES
from unishield.models.workflow import parse_seeds, prepare_files, prepare_synthetic


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--synthetic", action="store_true", help="use the seeded scenario generator")
    source.add_argument("--input", type=Path, nargs="+", help="labelled PCAP / Zeek / flow files")
    parser.add_argument("--scenarios", default="all", help="comma-separated scenario names (synthetic)")
    parser.add_argument("--seeds", default="1-20", help="seed list, e.g. 1-20 or 1,2,5 (synthetic)")
    parser.add_argument("--out", type=Path, default=None, help="output CSV")
    args = parser.parse_args()

    if args.synthetic:
        scenarios = list(SCENARIO_NAMES) if args.scenarios == "all" else args.scenarios.split(",")
        out = args.out or Path("data/processed/windows_synthetic.csv")
        manifest = prepare_synthetic(out, scenarios, parse_seeds(args.seeds))
    else:
        out = args.out or Path("data/processed/windows_files.csv")
        manifest = prepare_files(out, args.input)

    print(f"Wrote {manifest['windows']} windows from {manifest['runs']} runs to {out}")
    print(json.dumps(manifest["labels"], indent=2))


if __name__ == "__main__":
    main()
