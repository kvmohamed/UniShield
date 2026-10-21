"""
UniShield — Train and register window models

Trains the random forest, Isolation Forest and (if installed) XGBoost window
models on the train split of a window dataset, calibrates each on the
calibration split and stores them in the model registry (models/saved,
models/metadata) with test-split metrics.

Usage:
    python scripts/prepare_dataset.py --synthetic --seeds 1-20
    python scripts/train_models.py --dataset data/processed/windows_synthetic.csv

Then run the pipeline with UNISHIELD_DETECTION_MODE=hybrid to use window_rf.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from unishield.models.registry import ModelRegistry
from unishield.models.workflow import train_and_register


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument("--dataset", type=Path, default=Path("data/processed/windows_synthetic.csv"))
    parser.add_argument("--algorithms", default=None,
                        help="comma-separated: random_forest,xgboost,isolation_forest (default: all available)")
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--threshold", type=float, default=0.9)
    args = parser.parse_args()
    if not args.dataset.is_file():
        parser.error(f"{args.dataset} not found; run scripts/prepare_dataset.py first")

    algorithms = args.algorithms.split(",") if args.algorithms else None
    for meta in train_and_register(args.dataset, ModelRegistry(), algorithms, args.seed, args.threshold):
        m = meta["test_metrics"]
        print(f"{meta['name']}-v{meta['version']} ({meta['algorithm']}): "
              f"precision={m.get('precision')} recall={m.get('recall')} f1={m.get('f1')} "
              f"pr_auc={m.get('pr_auc')}  -> {meta['artifact']}")


if __name__ == "__main__":
    main()
