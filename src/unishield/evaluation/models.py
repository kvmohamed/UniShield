"""
UniShield — Detection Approach Comparison

Compares, on the same held-out windows:

    rules             rule detectors only (a window counts as detected when a
                      rule raised or suppressed a class in it)
    rules_statistical the default ``rules`` mode: rules + robust-z statistics
                      + online Isolation Forest
    random_forest     calibrated P(attack) >= threshold
    xgboost           calibrated P(attack) >= threshold (when installed)
    isolation_forest  IF trained on benign windows, score calibrated on labels
    hybrid            rules OR random forest (what ``hybrid`` mode reports)

plus ablations (random forest without each feature group) and a
leave-one-attack-out test that trains without one attack class and measures
how much of it the model still flags as an attack.

Splits are by run (``models.train.split_by_run``): train / calibration /
test never share a run.
"""

from __future__ import annotations

from typing import Any, Sequence

import numpy as np

from unishield.evaluation.metrics import (
    benign_false_alarm_windows,
    binary_metrics,
    confusion_matrix,
    episode_metrics,
    per_class_recall,
    ranking_metrics,
)
from unishield.models.calibration import brier_score, expected_calibration_error
from unishield.models.dataset import BENIGN, WindowRecord
from unishield.models.features import FEATURE_GROUPS, MODEL_FEATURE_KEYS
from unishield.models.predict import WindowModel
from unishield.models.train import (
    binary_labels,
    feature_importance,
    matrix,
    train_bundle,
    xgboost_available,
)


def _approach(records, y_true, y_pred, scores=None) -> dict[str, Any]:
    y_pred = np.asarray(y_pred, dtype=int)
    out = binary_metrics(y_true, y_pred)
    out.update(ranking_metrics(y_true, scores if scores is not None else y_pred))
    out["recall_by_class"] = per_class_recall(records, y_pred)
    out["benign_false_alarm_windows"] = benign_false_alarm_windows(records, y_pred)
    out.update(episode_metrics(records, y_pred))
    return out


def _model_scores(bundle, test, columns=None):
    model = WindowModel(bundle)
    raw, prob = model.scores(matrix(test, columns))
    return raw, prob


def _calibration_report(raw, prob, y_true, algorithm) -> dict[str, Any]:
    report = {"calibrated": prob is not None}
    if prob is not None:
        report.update(brier_after=round(brier_score(prob, y_true), 4),
                      ece_after=round(expected_calibration_error(prob, y_true), 4))
    if algorithm != "isolation_forest":          # raw IF scores are not probabilities
        report.update(brier_before=round(brier_score(raw, y_true), 4),
                      ece_before=round(expected_calibration_error(raw, y_true), 4))
    return report


def compare_approaches(
    train: Sequence[WindowRecord],
    calibration: Sequence[WindowRecord],
    test: Sequence[WindowRecord],
    feature_keys: Sequence[str] = MODEL_FEATURE_KEYS,
    threshold: float = 0.9,
    seed: int = 0,
    ablations: bool = True,
) -> dict[str, Any]:
    y_true = binary_labels(test)
    results: dict[str, Any] = {
        "threshold": threshold,
        "windows": {"train": len(train), "calibration": len(calibration), "test": len(test)},
        "attack_windows": {"train": int(binary_labels(train).sum()),
                           "calibration": int(binary_labels(calibration).sum()),
                           "test": int(y_true.sum())},
        "approaches": {},
        "calibration": {},
    }
    approaches = results["approaches"]

    rules = np.array([int(bool(r.rule_classes)) for r in test])
    approaches["rules"] = _approach(test, y_true, rules)
    rules_stat = np.array([int(bool(r.rule_classes or r.post_rule_classes)) for r in test])
    approaches["rules_statistical"] = _approach(test, y_true, rules_stat)

    algorithms = ["random_forest", "isolation_forest"]
    if xgboost_available():
        algorithms.insert(1, "xgboost")
    bundles = {}
    for algorithm in algorithms:
        bundle = train_bundle(algorithm, train, calibration, feature_keys, seed=seed)
        bundles[algorithm] = bundle
        raw, prob = _model_scores(bundle, test)
        score = prob if prob is not None else raw
        pred = (prob >= threshold).astype(int) if prob is not None else np.zeros(len(test), dtype=int)
        approaches[algorithm] = _approach(test, y_true, pred, score)
        results["calibration"][algorithm] = _calibration_report(raw, prob, y_true, algorithm)
        if algorithm == "random_forest":
            rf_pred, rf_score = pred, score
            results["feature_importance"] = feature_importance(bundle)
            estimator = bundle["estimator"]
            attack_idx = [i for i, r in enumerate(test) if r.is_attack]
            if attack_idx:
                predicted = estimator.predict(matrix([test[i] for i in attack_idx]))
                results["random_forest_confusion"] = confusion_matrix(
                    [test[i].label for i in attack_idx], [str(p) for p in predicted])

    hybrid = np.maximum(rules, rf_pred)
    approaches["hybrid"] = _approach(test, y_true, hybrid, np.maximum(rules, rf_score))
    if not xgboost_available():
        results["notes"] = ["xgboost not installed (pip install -e .[ml]); XGBoost skipped"]

    if ablations:
        results["ablations"] = feature_ablation(train, calibration, test, feature_keys, threshold, seed)
        results["leave_one_attack_out"] = leave_one_attack_out(train, calibration, test, feature_keys,
                                                               threshold, seed)
    return results, bundles


def feature_ablation(train, calibration, test, feature_keys, threshold=0.9, seed=0) -> dict[str, Any]:
    """Random forest F1 / PR-AUC / recall with each feature group removed."""
    y_true = binary_labels(test)
    out = {}
    index = {k: i for i, k in enumerate(feature_keys)}
    for group, keys in [("none", [])] + list(FEATURE_GROUPS.items()):
        drop = {index[k] for k in keys if k in index}
        columns = [i for i in range(len(feature_keys)) if i not in drop]
        bundle = train_bundle("random_forest", train, calibration, feature_keys, columns=columns, seed=seed)
        raw, prob = _model_scores(bundle, test, columns)
        score = prob if prob is not None else raw
        pred = (score >= threshold).astype(int)
        m = binary_metrics(y_true, pred)
        r = ranking_metrics(y_true, score)
        out[f"without_{group}" if group != "none" else "all_features"] = {
            "f1": m["f1"], "recall": m["recall"], "precision": m["precision"],
            "false_positive_rate": m["false_positive_rate"], "pr_auc": r["pr_auc"],
            "recall_by_class": per_class_recall(test, pred),
        }
    return out


def leave_one_attack_out(train, calibration, test, feature_keys, threshold=0.9, seed=0) -> dict[str, Any]:
    """For each attack class: train/calibrate without it, report how much of it is still flagged."""
    out = {}
    classes = sorted({r.label for r in test if r.is_attack})
    for held_out in classes:
        tr = [r for r in train if r.label != held_out]
        cal = [r for r in calibration if r.label != held_out]
        if not any(r.is_attack for r in tr):
            continue
        bundle = train_bundle("random_forest", tr, cal, feature_keys, seed=seed)
        target = [r for r in test if r.label == held_out]
        raw, prob = _model_scores(bundle, target)
        score = prob if prob is not None else raw
        benign = [r for r in test if r.label == BENIGN]
        b_raw, b_prob = _model_scores(bundle, benign) if benign else (np.array([]), None)
        b_score = b_prob if b_prob is not None else b_raw
        out[held_out] = {
            "windows": len(target),
            "flagged_as_attack": round(float((score >= threshold).mean()), 4) if len(target) else None,
            "benign_false_positive_rate": round(float((b_score >= threshold).mean()), 4) if len(benign) else None,
        }
    return out
