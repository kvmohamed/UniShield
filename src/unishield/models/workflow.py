"""
UniShield — Dataset / Training / Evaluation Workflow

The functions behind scripts/prepare_dataset.py, scripts/train_models.py and
scripts/evaluate_models.py, kept here so they are importable and tested.
"""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence

from unishield.models.dataset import (
    WindowRecord,
    load_windows,
    save_windows,
    synthetic_windows,
    windows_from_reader,
)
from unishield.models.features import MODEL_FEATURE_KEYS
from unishield.models.registry import ModelRegistry
from unishield.models.train import (
    binary_labels,
    feature_importance,
    split_by_run,
    train_bundle,
    xgboost_available,
)

SPLIT = (0.6, 0.2, 0.2)          # train / calibration / test, by run
REGISTRY_NAMES = {"random_forest": "window_rf", "xgboost": "window_xgb", "isolation_forest": "window_if"}


def parse_seeds(text: str) -> list[int]:
    """'1-5,8,10-11' → [1, 2, 3, 4, 5, 8, 10, 11]."""
    seeds: list[int] = []
    for part in text.split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = part.split("-", 1)
            seeds.extend(range(int(lo), int(hi) + 1))
        elif part:
            seeds.append(int(part))
    return seeds


def prepare_synthetic(out: Path, scenarios: Sequence[str], seeds: Sequence[int]) -> dict[str, Any]:
    records = synthetic_windows(scenarios, seeds)
    return _write_dataset(records, out, source={"type": "synthetic", "scenarios": list(scenarios),
                                                 "seeds": list(seeds)})


def prepare_files(out: Path, inputs: Iterable[Path]) -> dict[str, Any]:
    from unishield.ingest.detect import open_reader

    records: list[WindowRecord] = []
    names = []
    for path in inputs:
        reader, fmt = open_reader(path)
        records += windows_from_reader(reader, run=Path(path).name)
        names.append({"file": str(path), "format": fmt})
    return _write_dataset(records, out, source={"type": "files", "inputs": names})


def _write_dataset(records: list[WindowRecord], out: Path, source: dict[str, Any]) -> dict[str, Any]:
    if not records:
        raise ValueError("No windows were produced; check the inputs")
    sha = save_windows(records, out)
    manifest = {
        "dataset": out.name,
        "sha256": sha,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "windows": len(records),
        "runs": len({r.run for r in records}),
        "labels": dict(Counter(r.label for r in records).most_common()),
        "feature_keys": len(MODEL_FEATURE_KEYS),
        "source": source,
    }
    out.with_suffix(".manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def quick_metrics(bundle: dict[str, Any], test: Sequence[WindowRecord], threshold: float) -> dict[str, Any]:
    """Window-level metrics of a bundle on the test split at ``threshold``."""
    from unishield.evaluation.metrics import binary_metrics, ranking_metrics
    from unishield.models.predict import WindowModel
    from unishield.models.train import matrix

    if not test:
        return {}
    raw, prob = WindowModel(bundle).scores(matrix(test))
    score = prob if prob is not None else raw
    y = binary_labels(test)
    out = binary_metrics(y, (score >= threshold).astype(int) if prob is not None else [0] * len(test))
    out.update(ranking_metrics(y, score), threshold=threshold)
    return out


def load_split(dataset: Path, seed: int = 7):
    records, keys = load_windows(dataset)
    if keys != MODEL_FEATURE_KEYS:
        raise ValueError(f"{dataset} was built with a different feature set; rebuild it with prepare_dataset.py")
    return split_by_run(records, SPLIT, seed=seed), keys


def train_and_register(dataset: Path, registry: ModelRegistry, algorithms: Sequence[str] | None = None,
                       seed: int = 7, threshold: float = 0.9) -> list[dict[str, Any]]:
    """Train each algorithm on the train split, calibrate on the calibration split, register it."""
    (train, calibration, test), keys = load_split(dataset, seed)
    if algorithms is None:
        algorithms = ["random_forest", "isolation_forest"] + (["xgboost"] if xgboost_available() else [])
    sha = json.loads(dataset.with_suffix(".manifest.json").read_text(encoding="utf-8"))["sha256"] \
        if dataset.with_suffix(".manifest.json").is_file() else None
    saved = []
    for algorithm in algorithms:
        bundle = train_bundle(algorithm, train, calibration, keys, seed=seed)
        metadata = {
            "algorithm": algorithm,
            "kind": bundle["kind"],
            "feature_keys": bundle["feature_keys"],
            "classes": bundle["classes"],
            "calibration": bundle["calibrator"],
            "dataset": {"file": dataset.name, "sha256": sha},
            "split": {"method": "by run", "fractions": list(SPLIT), "seed": seed,
                      "train_windows": len(train), "calibration_windows": len(calibration),
                      "test_windows": len(test),
                      "train_attack_windows": int(binary_labels(train).sum())},
            "test_metrics": quick_metrics(bundle, test, threshold),
            "feature_importance": feature_importance(bundle),
        }
        saved.append(registry.save(REGISTRY_NAMES[algorithm], bundle, metadata))
    return saved
