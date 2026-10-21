"""
UniShield — Detection Metrics

Window-level metrics (precision, recall, F1, false-positive rate, PR-AUC,
confusion matrices) and episode-level metrics (was each attack episode
detected, and how long after the first window containing attack traffic
closed).

Detection delay is measured in traffic time from the close of the first
window that contains attack traffic — the earliest moment a window-based
detector can report it — to the close of the first window in which the
approach detected the episode.
"""

from __future__ import annotations

import statistics
from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Sequence

import numpy as np

from unishield.models.dataset import BENIGN, WindowRecord

EPISODE_GAP_SEC = 300


def _ratio(a: float, b: float) -> float:
    return round(a / b, 4) if b else 0.0


def binary_metrics(y_true: Sequence[int], y_pred: Sequence[int]) -> dict[str, Any]:
    y_true = np.asarray(y_true, dtype=int)
    y_pred = np.asarray(y_pred, dtype=int)
    tp = int(((y_true == 1) & (y_pred == 1)).sum())
    fp = int(((y_true == 0) & (y_pred == 1)).sum())
    tn = int(((y_true == 0) & (y_pred == 0)).sum())
    fn = int(((y_true == 1) & (y_pred == 0)).sum())
    precision = _ratio(tp, tp + fp)
    recall = _ratio(tp, tp + fn)
    return {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": _ratio(2 * precision * recall, precision + recall),
        "false_positive_rate": _ratio(fp, fp + tn),
        "accuracy": _ratio(tp + tn, len(y_true)),
    }


def ranking_metrics(y_true: Sequence[int], scores: Sequence[float]) -> dict[str, Any]:
    """PR-AUC (average precision) and ROC-AUC; None when only one class is present."""
    from sklearn.metrics import average_precision_score, roc_auc_score

    y_true = np.asarray(y_true, dtype=int)
    if len(np.unique(y_true)) < 2:
        return {"pr_auc": None, "roc_auc": None}
    return {"pr_auc": round(float(average_precision_score(y_true, scores)), 4),
            "roc_auc": round(float(roc_auc_score(y_true, scores)), 4)}


def confusion_matrix(true_labels: Sequence[str], predicted: Sequence[str]) -> dict[str, dict[str, int]]:
    """{true label: {predicted label: count}}."""
    matrix: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for t, p in zip(true_labels, predicted):
        matrix[t][p] += 1
    return {t: dict(row) for t, row in sorted(matrix.items())}


def per_class_recall(records: Sequence[WindowRecord], y_pred: Sequence[int]) -> dict[str, float]:
    hits: dict[str, list[int]] = defaultdict(list)
    for r, p in zip(records, y_pred):
        if r.is_attack:
            hits[r.label].append(int(p))
    return {label: _ratio(sum(v), len(v)) for label, v in sorted(hits.items())}


@dataclass
class Episode:
    run: str
    label: str
    indices: list[int]          # positions in the evaluated record list


def episodes(records: Sequence[WindowRecord], gap_sec: float = EPISODE_GAP_SEC) -> list[Episode]:
    """Attack episodes: windows of one run and label, split where attack windows are > gap_sec apart."""
    by_key: dict[tuple[str, str], list[int]] = defaultdict(list)
    for i, r in enumerate(records):
        if r.is_attack:
            by_key[(r.run, r.label)].append(i)
    out = []
    for (run, label), idx in sorted(by_key.items()):
        idx.sort(key=lambda i: records[i].window_start)
        current = [idx[0]]
        for i in idx[1:]:
            gap = (records[i].window_start - records[current[-1]].window_end).total_seconds()
            if gap > gap_sec:
                out.append(Episode(run, label, current))
                current = []
            current.append(i)
        out.append(Episode(run, label, current))
    return out


def episode_metrics(records: Sequence[WindowRecord], y_pred: Sequence[int],
                    gap_sec: float = EPISODE_GAP_SEC) -> dict[str, Any]:
    """Share of attack episodes detected and detection delays (seconds of traffic time)."""
    eps = episodes(records, gap_sec)
    delays: list[float] = []
    by_label: dict[str, list[int]] = defaultdict(list)
    for ep in eps:
        first_close = records[ep.indices[0]].window_end
        detected = [records[i].window_end for i in ep.indices if y_pred[i]]
        by_label[ep.label].append(int(bool(detected)))
        if detected:
            delays.append(max(0.0, (min(detected) - first_close).total_seconds()))
    return {
        "episodes": len(eps),
        "episodes_detected": sum(sum(v) for v in by_label.values()),
        "episode_recall": _ratio(sum(sum(v) for v in by_label.values()), len(eps)),
        "episode_recall_by_class": {k: _ratio(sum(v), len(v)) for k, v in sorted(by_label.items())},
        "delay_median_sec": round(statistics.median(delays), 1) if delays else None,
        "delay_max_sec": round(max(delays), 1) if delays else None,
    }


def benign_false_alarm_windows(records: Sequence[WindowRecord], y_pred: Sequence[int]) -> int:
    return sum(1 for r, p in zip(records, y_pred) if p and r.label == BENIGN)
