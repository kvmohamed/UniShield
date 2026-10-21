"""
UniShield — Window Model Training

Trains window-level models on WindowRecords (``models.dataset``):

    random_forest     — supervised, multi-class (BENIGN + threat classes)
    xgboost           — supervised, multi-class (optional ``ml`` extra)
    isolation_forest  — unsupervised, trained on benign windows only

Supervised models report P(attack) = 1 - P(BENIGN) and the most likely
attack class. Every model's attack score is calibrated with isotonic
regression on a held-out calibration split, so the stored probability is
an empirical one. Splits are made by run (scenario + seed, or input file)
because windows overlap: windows of one run never appear on both sides.
"""

from __future__ import annotations

import random
from collections import defaultdict
from typing import Any, Iterable, Sequence

import numpy as np

from unishield.models.calibration import IsotonicCalibrator
from unishield.models.dataset import BENIGN, WindowRecord

ALGORITHMS = ("random_forest", "xgboost", "isolation_forest")


def matrix(records: Sequence[WindowRecord], columns: Sequence[int] | None = None) -> np.ndarray:
    X = np.asarray([r.features for r in records], dtype=float)
    if X.ndim != 2:
        X = X.reshape(len(records), -1)
    return X[:, list(columns)] if columns is not None else X


def binary_labels(records: Iterable[WindowRecord]) -> np.ndarray:
    return np.asarray([int(r.is_attack) for r in records])


def split_by_run(records: Sequence[WindowRecord], fractions: Sequence[float], seed: int = 0
                 ) -> list[list[WindowRecord]]:
    """
    Split records into len(fractions) parts by run, stratified by each run's
    dominant label so every part sees every scenario type where possible.
    """
    by_run: dict[str, list[WindowRecord]] = defaultdict(list)
    for r in records:
        by_run[r.run].append(r)
    kinds: dict[str, list[str]] = defaultdict(list)
    for run, rs in by_run.items():
        attack = [r.label for r in rs if r.is_attack]
        kinds[max(set(attack), key=attack.count) if attack else BENIGN].append(run)

    rng = random.Random(seed)
    parts: list[list[WindowRecord]] = [[] for _ in fractions]
    total = sum(fractions)
    for kind in sorted(kinds):
        runs = sorted(kinds[kind])
        rng.shuffle(runs)
        bounds, acc = [], 0.0
        for f in fractions:
            acc += f / total
            bounds.append(round(acc * len(runs)))
        start = 0
        for i, end in enumerate(bounds):
            for run in runs[start:end]:
                parts[i].extend(by_run[run])
            start = end
    return parts


# ---------------------------------------------------------------------------
# Estimators
# ---------------------------------------------------------------------------

def fit_random_forest(X: np.ndarray, labels: Sequence[str], seed: int = 0, n_estimators: int = 200):
    from sklearn.ensemble import RandomForestClassifier

    model = RandomForestClassifier(
        n_estimators=n_estimators, min_samples_leaf=2, class_weight="balanced_subsample",
        random_state=seed, n_jobs=-1,
    )
    return model.fit(X, list(labels))


class XGBoostWindowClassifier:
    """XGBoost multi-class classifier with string labels (sklearn-like interface)."""

    def __init__(self, seed: int = 0, n_estimators: int = 200, max_depth: int = 6):
        self.seed, self.n_estimators, self.max_depth = seed, n_estimators, max_depth
        self.classes_: np.ndarray = np.array([])
        self.model = None

    def fit(self, X: np.ndarray, labels: Sequence[str]) -> "XGBoostWindowClassifier":
        from xgboost import XGBClassifier

        self.classes_ = np.array(sorted(set(labels)))
        index = {c: i for i, c in enumerate(self.classes_)}
        y = np.array([index[label] for label in labels])
        counts = np.bincount(y, minlength=len(self.classes_))
        weights = (len(y) / (len(self.classes_) * counts))[y]       # balanced classes
        objective = "binary:logistic" if len(self.classes_) == 2 else "multi:softprob"
        self.model = XGBClassifier(
            n_estimators=self.n_estimators, max_depth=self.max_depth, learning_rate=0.1,
            subsample=0.9, colsample_bytree=0.9, objective=objective, tree_method="hist",
            random_state=self.seed, n_jobs=-1, verbosity=0,
        )
        self.model.fit(X, y, sample_weight=weights)
        return self

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        proba = self.model.predict_proba(X)
        return proba if proba.ndim == 2 else np.column_stack([1 - proba, proba])

    @property
    def feature_importances_(self) -> np.ndarray:
        return self.model.feature_importances_


def fit_isolation_forest(X_benign: np.ndarray, seed: int = 0, n_estimators: int = 200):
    from sklearn.ensemble import IsolationForest

    return IsolationForest(n_estimators=n_estimators, contamination="auto", random_state=seed).fit(X_benign)


def xgboost_available() -> bool:
    try:
        import xgboost  # noqa: F401
    except ImportError:
        return False
    return True


# ---------------------------------------------------------------------------
# Bundles
# ---------------------------------------------------------------------------

def raw_attack_scores(bundle: dict[str, Any], X: np.ndarray) -> np.ndarray:
    """Uncalibrated attack score per row: 1 - P(BENIGN), or the IF anomaly score."""
    estimator = bundle["estimator"]
    if bundle["algorithm"] == "isolation_forest":
        return -estimator.score_samples(X)
    classes = list(estimator.classes_)
    proba = estimator.predict_proba(X)
    if BENIGN not in classes:
        return np.ones(len(X))
    return 1.0 - proba[:, classes.index(BENIGN)]


def train_bundle(
    algorithm: str,
    train: Sequence[WindowRecord],
    calibration: Sequence[WindowRecord],
    feature_keys: Sequence[str],
    columns: Sequence[int] | None = None,
    seed: int = 0,
) -> dict[str, Any]:
    """Fit one algorithm on ``train`` and calibrate its attack score on ``calibration``."""
    if algorithm not in ALGORITHMS:
        raise ValueError(f"Unknown algorithm {algorithm!r}; choose from {ALGORITHMS}")
    X = matrix(train, columns)
    labels = [r.label for r in train]
    if algorithm == "random_forest":
        estimator = fit_random_forest(X, labels, seed)
    elif algorithm == "xgboost":
        estimator = XGBoostWindowClassifier(seed).fit(X, labels)
    else:
        benign = X[binary_labels(train) == 0]
        if len(benign) < 10:
            raise ValueError("Isolation Forest needs at least 10 benign training windows")
        estimator = fit_isolation_forest(benign, seed)

    keys = list(feature_keys) if columns is None else [feature_keys[i] for i in columns]
    bundle: dict[str, Any] = {
        "algorithm": algorithm,
        "kind": "unsupervised" if algorithm == "isolation_forest" else "supervised",
        "estimator": estimator,
        "feature_keys": keys,
        "classes": [str(c) for c in getattr(estimator, "classes_", [])],
        "calibrator": None,
    }
    if calibration:
        Xc = matrix(calibration, columns)
        try:
            bundle["calibrator"] = IsotonicCalibrator.fit(raw_attack_scores(bundle, Xc),
                                                          binary_labels(calibration)).to_dict()
        except ValueError:
            bundle["calibrator"] = None
    return bundle


def feature_importance(bundle: dict[str, Any], top: int = 15) -> list[tuple[str, float]]:
    values = getattr(bundle["estimator"], "feature_importances_", None)
    if values is None:
        return []
    pairs = sorted(zip(bundle["feature_keys"], (float(v) for v in values)), key=lambda p: -p[1])
    return [(k, round(v, 4)) for k, v in pairs[:top]]
