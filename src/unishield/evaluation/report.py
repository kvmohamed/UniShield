"""
UniShield — Evaluation Report Writer

Renders the results of ``evaluation.models.compare_approaches`` as JSON and
as a Markdown report. Every number in the report comes from the results
dictionary; nothing is typed in by hand.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_APPROACH_NOTES = {
    "rules": "rule detectors only",
    "rules_statistical": "default `rules` mode: rules + robust-z + online Isolation Forest",
    "random_forest": "supervised, calibrated P(attack) ≥ threshold",
    "xgboost": "supervised, calibrated P(attack) ≥ threshold",
    "isolation_forest": "unsupervised (benign-only training), score calibrated on labels",
    "hybrid": "rules OR random forest (what `hybrid` mode reports)",
}


def _fmt(v: Any) -> str:
    if v is None:
        return "–"
    if isinstance(v, float):
        return f"{v:.3f}"
    return str(v)


def render_markdown(results: dict[str, Any], context: dict[str, Any]) -> str:
    lines = [
        "# UniShield — Model Evaluation",
        "",
        f"Generated {context.get('generated_at')} by `scripts/evaluate_models.py`.",
        "",
        "## Data",
        "",
        f"- Dataset: `{context.get('dataset')}` (SHA-256 `{str(context.get('sha256'))[:16]}…`)",
        f"- Source: {context.get('source_description', 'see manifest')}",
        f"- Split by run (train / calibration / test never share a run): "
        f"{results['windows']['train']} / {results['windows']['calibration']} / {results['windows']['test']} windows, "
        f"of which {results['attack_windows']['train']} / {results['attack_windows']['calibration']} / "
        f"{results['attack_windows']['test']} contain attack traffic.",
        f"- Model alert threshold: calibrated P(attack) ≥ {results['threshold']}.",
        "",
        "A window is an attack window if it contains at least one attack-labelled flow.",
        "Window-level recall therefore penalises detectors that need several windows of",
        "evidence (beaconing, exfiltration baselines); episode recall and delay show",
        "whether, and how quickly, each attack episode was reported at all.",
        "",
        "## Window-level and episode-level results (test split)",
        "",
        "| Approach | Precision | Recall | F1 | FPR | PR-AUC | Episodes detected | Median delay (s) | Max delay (s) |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for name, m in results["approaches"].items():
        lines.append(
            f"| {name} | {_fmt(m['precision'])} | {_fmt(m['recall'])} | {_fmt(m['f1'])} | "
            f"{_fmt(m['false_positive_rate'])} | {_fmt(m['pr_auc'])} | "
            f"{m['episodes_detected']}/{m['episodes']} | {_fmt(m['delay_median_sec'])} | {_fmt(m['delay_max_sec'])} |"
        )
    lines += ["", "Approaches:", ""]
    lines += [f"- **{k}** — {v}" for k, v in _APPROACH_NOTES.items() if k in results["approaches"]]

    classes = sorted({c for m in results["approaches"].values() for c in m["recall_by_class"]})
    lines += ["", "## Window recall by attack class", "",
              "| Approach | " + " | ".join(classes) + " |",
              "|---|" + "---|" * len(classes)]
    for name, m in results["approaches"].items():
        lines.append(f"| {name} | " + " | ".join(_fmt(m["recall_by_class"].get(c)) for c in classes) + " |")

    lines += ["", "## Calibration (test split)", "",
              "Brier score and expected calibration error (10 bins) of the attack probability.",
              "Raw Isolation Forest scores are not probabilities, so only the calibrated values are shown.", "",
              "| Model | Brier before | ECE before | Brier after | ECE after |", "|---|---|---|---|---|"]
    for name, c in results["calibration"].items():
        lines.append(f"| {name} | {_fmt(c.get('brier_before'))} | {_fmt(c.get('ece_before'))} | "
                     f"{_fmt(c.get('brier_after'))} | {_fmt(c.get('ece_after'))} |")

    if results.get("ablations"):
        lines += ["", "## Feature-group ablation (random forest)", "",
                  "| Variant | Precision | Recall | F1 | FPR | PR-AUC |", "|---|---|---|---|---|---|"]
        for name, m in results["ablations"].items():
            lines.append(f"| {name} | {_fmt(m['precision'])} | {_fmt(m['recall'])} | {_fmt(m['f1'])} | "
                         f"{_fmt(m['false_positive_rate'])} | {_fmt(m['pr_auc'])} |")

    if results.get("leave_one_attack_out"):
        lines += ["", "## Leave-one-attack-out (random forest)", "",
                  "Trained and calibrated without one attack class; share of that class's test windows",
                  "still scored as attacks. This measures generalisation to attack types the model",
                  "has not seen, which is what matters for novel threats.", "",
                  "| Held-out class | Test windows | Flagged as attack | Benign FPR |", "|---|---|---|---|"]
        for name, m in results["leave_one_attack_out"].items():
            lines.append(f"| {name} | {m['windows']} | {_fmt(m['flagged_as_attack'])} | "
                         f"{_fmt(m['benign_false_positive_rate'])} |")

    if results.get("random_forest_confusion"):
        lines += ["", "## Random forest class confusion (attack windows of the test split)", ""]
        for true_label, row in results["random_forest_confusion"].items():
            cells = ", ".join(f"{p}: {n}" for p, n in sorted(row.items(), key=lambda x: -x[1]))
            lines.append(f"- {true_label} → {cells}")

    if results.get("feature_importance"):
        lines += ["", "## Most important features (random forest, impurity based)", ""]
        lines += [f"- `{k}` — {v}" for k, v in results["feature_importance"]]

    lines += ["", "## Limitations", ""]
    lines += [f"- {n}" for n in context.get("limitations", [])]
    lines += [f"- {n}" for n in results.get("notes", [])]
    return "\n".join(lines) + "\n"


SYNTHETIC_LIMITATIONS = [
    "The data is produced by UniShield's own seeded generator. Train and test come from the "
    "same generator, so supervised scores are optimistic; the leave-one-attack-out table is a "
    "better guide to behaviour on unfamiliar attacks.",
    "Results on real traffic (e.g. CICIDS2017, CTU-13) require running "
    "`scripts/prepare_dataset.py --input <files>` on those datasets; they are not included.",
    "Probabilities are calibrated on the calibration split of the same distribution and may be "
    "miscalibrated on other networks.",
]


def write_model_report(results: dict[str, Any], out_dir: Path, context: dict[str, Any]) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    context = dict(context)
    context.setdefault("generated_at", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"))
    json_path = out_dir / "model_evaluation.json"
    md_path = out_dir / "model_evaluation.md"
    json_path.write_text(json.dumps({"context": context, "results": results}, indent=2, default=str),
                         encoding="utf-8")
    md_path.write_text(render_markdown(results, context), encoding="utf-8")
    return json_path, md_path
