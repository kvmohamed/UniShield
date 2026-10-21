"""
UniShield — Compare detection approaches on a window dataset

Rules, rules + statistics, random forest, XGBoost, Isolation Forest and the
hybrid are evaluated on the same held-out windows, with calibration,
feature-group ablation and leave-one-attack-out results. Writes
reports/model_evaluation.json and reports/model_evaluation.md.

Usage:
    python scripts/evaluate_models.py --dataset data/processed/windows_synthetic.csv
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from unishield.evaluation.models import compare_approaches
from unishield.evaluation.report import SYNTHETIC_LIMITATIONS, write_model_report
from unishield.models.workflow import load_split


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument("--dataset", type=Path, default=Path("data/processed/windows_synthetic.csv"))
    parser.add_argument("--out", type=Path, default=Path("reports"))
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--threshold", type=float, default=0.9)
    parser.add_argument("--no-ablations", action="store_true")
    args = parser.parse_args()
    if not args.dataset.is_file():
        parser.error(f"{args.dataset} not found; run scripts/prepare_dataset.py first")

    (train, calibration, test), keys = load_split(args.dataset, args.seed)
    results, _ = compare_approaches(train, calibration, test, keys, args.threshold, args.seed,
                                    ablations=not args.no_ablations)
    manifest_path = args.dataset.with_suffix(".manifest.json")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.is_file() else {}
    source = manifest.get("source", {})
    synthetic = source.get("type") == "synthetic"
    context = {
        "dataset": args.dataset.name,
        "sha256": manifest.get("sha256"),
        "source_description": (f"seeded generator, {len(source.get('scenarios', []))} scenarios × "
                               f"{len(source.get('seeds', []))} seeds") if synthetic else "labelled input files",
        "limitations": SYNTHETIC_LIMITATIONS if synthetic else [
            "Probabilities are calibrated on the calibration split of this dataset only."],
    }
    json_path, md_path = write_model_report(results, args.out, context)
    for name, m in results["approaches"].items():
        print(f"{name:18s} P={m['precision']:.3f} R={m['recall']:.3f} F1={m['f1']:.3f} "
              f"FPR={m['false_positive_rate']:.4f} episodes={m['episodes_detected']}/{m['episodes']}")
    print(f"Wrote {json_path} and {md_path}")


if __name__ == "__main__":
    main()
