# UniShield — Model Card

## Models

| Registry name | Algorithm | Role | Output |
|---|---|---|---|
| `window_rf` | Random forest, 200 trees, `min_samples_leaf=2`, balanced class weights | Supervised window classifier; used by `hybrid` and `ml` modes | P(attack) = 1 − P(BENIGN), calibrated; most likely attack class |
| `window_xgb` | XGBoost, 200 trees, depth 6, balanced sample weights (optional `ml` extra) | Supervised comparison model | as above |
| `window_if` | Isolation Forest, 200 trees, trained on benign windows only | Unsupervised comparison model | anomaly score, calibrated on labelled windows |
| (online) | Isolation Forest inside `AnomalyDetector` | Default `rules` mode: anomaly leads on windows no rule explained | percentile of the window among training windows (not a probability) |

Artifacts: `models/saved/<name>-v<N>.joblib` with
`models/metadata/<name>-v<N>.json` (algorithm, feature keys, classes,
calibration points, dataset SHA-256, split, test metrics, feature importance,
library versions, artifact SHA-256). Loading checks the SHA-256; joblib files
are pickles, so load only artifacts this installation trained.

## Intended use

Ranking and flagging 10-second traffic windows, from metadata only, in a
research setting, alongside the rule detectors. In `hybrid` mode the model
only reports windows that no rule explained, at calibrated P(attack) ≥ 0.9
(`models.ml_alert_probability`).

Not intended for automated response, for deciding guilt, for traffic it was
not trained on without re-evaluation, or as evidence of malware in encrypted
sessions.

## Training data

18,444 windows from 220 runs of UniShield's seeded generator (11 scenarios ×
20 seeds; [dataset.md](dataset.md)). Split by run: 11,099 train / 3,635
calibration / 3,710 test windows (1,900 / 651 / 653 with attack traffic).

## Features

75 window features in six groups (volume, scan, beaconing, exfiltration,
DNS, TLS) from `unishield.models.features`: scalar window statistics plus the
strongest beaconing, exfiltration, DGA and tunnelling candidate, each
log1p-scaled. No payload, no IP addresses as features.

## Calibration

Isotonic regression fitted on the calibration split (never the training
split), stored as JSON interpolation points. Test-split Brier score / ECE
before → after: random forest 0.027 / 0.027 → 0.025 / 0.010; XGBoost 0.021 /
0.015 → 0.019 / 0.009 (`reports/model_evaluation.md`).

## Performance (held-out runs of the same generator)

| Model | Precision | Recall | F1 | PR-AUC | Episodes detected |
|---|---|---|---|---|---|
| random forest | 1.000 | 0.684 | 0.813 | 0.961 | 48/48 |
| XGBoost | 0.998 | 0.753 | 0.859 | 0.975 | 48/48 |
| Isolation Forest (calibrated) | 0.000 | 0.000 | 0.000 | 0.421 | 0/48 |
| rules only (reference) | 1.000 | 0.423 | 0.594 | 0.524 | 48/48 |
| hybrid (rules OR random forest) | 1.000 | 0.697 | 0.821 | 0.962 | 48/48 |

Window recall is limited mainly by beaconing windows, which contain a single
small check-in flow each.

## Performance on real traffic (CTU-13)

Scored on 3,263 analysed windows from five CTU-13 scenarios
(`reports/public_dataset_evaluation.md`):

- trained on the synthetic dataset: ROC-AUC 0.53, PR-AUC 0.57 — about chance;
  it flags almost every window (recall 1.00 at precision 0.56, the attack
  share), so it does not transfer from the generator to a real network;
- trained on four CTU-13 scenarios and tested on the fifth: ROC-AUC 0.33–0.72
  depending on the held-out botnet.

Do not enable `hybrid` mode on a real network on the strength of the
synthetic scores.

## Known weaknesses

- **Generalisation.** Trained without a class, the random forest flags none
  of that class's windows for beaconing, exfiltration, DGA, DNS tunnelling,
  encrypted-session anomalies and UDP floods (it still flags host scans,
  port scans and SYN floods, which resemble other trained attacks). The
  supervised models recognise what they were shown; the rules remain the
  primary detectors.
- **Synthetic distribution.** Train and test share the generator, so the
  scores above are optimistic for real networks.
- **Isolation Forest.** On this data its calibrated scores never reach 0.9,
  and it cannot score points beyond its training range higher than the edge.
- **Class prediction** for ML alerts is a model guess, and the reported
  source/destination is the strongest entity the matching extractor found.

## Reproduce

```bash
python scripts/prepare_dataset.py --synthetic --seeds 1-20
python scripts/train_models.py
python scripts/evaluate_models.py
```
