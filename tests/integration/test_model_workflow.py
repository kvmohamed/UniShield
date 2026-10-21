"""Integration test: dataset preparation → training/registration → evaluation report."""

from __future__ import annotations

import json

from unishield.evaluation.models import compare_approaches
from unishield.evaluation.report import SYNTHETIC_LIMITATIONS, write_model_report
from unishield.models.registry import ModelRegistry
from unishield.models.workflow import load_split, parse_seeds, prepare_synthetic, train_and_register


def test_parse_seeds():
    assert parse_seeds("1-3,7, 9-10") == [1, 2, 3, 7, 9, 10]


def test_prepare_train_evaluate(tmp_path):
    dataset = tmp_path / "windows.csv"
    manifest = prepare_synthetic(dataset, ["benign_hard", "port_scan", "dga"], range(1, 6))
    assert manifest["runs"] == 15 and manifest["labels"]["BENIGN"] > 0
    saved_manifest = json.loads(dataset.with_suffix(".manifest.json").read_text())
    assert saved_manifest["sha256"] == manifest["sha256"]

    registry = ModelRegistry(tmp_path / "saved", tmp_path / "meta")
    metas = train_and_register(dataset, registry, ["random_forest", "isolation_forest"])
    assert [m["name"] for m in metas] == ["window_rf", "window_if"]
    rf = metas[0]
    assert rf["dataset"]["sha256"] == manifest["sha256"]
    assert rf["calibration"]["method"] == "isotonic"
    assert rf["test_metrics"]["precision"] >= 0.9
    assert rf["split"]["train_windows"] > rf["split"]["test_windows"] > 0

    (train, cal, test), keys = load_split(dataset)
    results, _ = compare_approaches(train, cal, test, keys, ablations=False)
    assert {"rules", "rules_statistical", "random_forest", "isolation_forest", "hybrid"} <= set(results["approaches"])
    json_path, md_path = write_model_report(results, tmp_path / "reports",
                                            {"dataset": dataset.name, "sha256": manifest["sha256"],
                                             "limitations": SYNTHETIC_LIMITATIONS})
    text = md_path.read_text(encoding="utf-8")
    assert "| rules |" in text and "Limitations" in text
    assert json.loads(json_path.read_text())["results"]["windows"]["test"] == len(test)
