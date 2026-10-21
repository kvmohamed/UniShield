# UniShield — Model Evaluation

Generated 2026-10-21 18:36 UTC by `scripts/evaluate_models.py`.

## Data

- Dataset: `windows_synthetic.csv` (SHA-256 `a78c70776e6560b5…`)
- Source: seeded generator, 11 scenarios × 20 seeds
- Split by run (train / calibration / test never share a run): 11099 / 3635 / 3710 windows, of which 1900 / 651 / 653 contain attack traffic.
- Model alert threshold: calibrated P(attack) ≥ 0.9.

A window is an attack window if it contains at least one attack-labelled flow.
Window-level recall therefore penalises detectors that need several windows of
evidence (beaconing, exfiltration baselines); episode recall and delay show
whether, and how quickly, each attack episode was reported at all.

## Window-level and episode-level results (test split)

| Approach | Precision | Recall | F1 | FPR | PR-AUC | Episodes detected | Median delay (s) | Max delay (s) |
|---|---|---|---|---|---|---|---|---|
| rules | 1.000 | 0.423 | 0.594 | 0.000 | 0.524 | 48/48 | 0.000 | 550.000 |
| rules_statistical | 1.000 | 0.495 | 0.662 | 0.000 | 0.584 | 48/48 | 0.000 | 550.000 |
| random_forest | 1.000 | 0.684 | 0.813 | 0.000 | 0.961 | 48/48 | 0.000 | 545.000 |
| xgboost | 0.998 | 0.753 | 0.859 | 0.000 | 0.975 | 48/48 | 0.000 | 90.000 |
| isolation_forest | 0.000 | 0.000 | 0.000 | 0.000 | 0.421 | 0/48 | – | – |
| hybrid | 1.000 | 0.697 | 0.821 | 0.000 | 0.962 | 48/48 | 0.000 | 545.000 |

Approaches:

- **rules** — rule detectors only
- **rules_statistical** — default `rules` mode: rules + robust-z + online Isolation Forest
- **random_forest** — supervised, calibrated P(attack) ≥ threshold
- **xgboost** — supervised, calibrated P(attack) ≥ threshold
- **isolation_forest** — unsupervised (benign-only training), score calibrated on labels
- **hybrid** — rules OR random forest (what `hybrid` mode reports)

## Window recall by attack class

| Approach | C2_BEACONING | DATA_EXFILTRATION | DGA_DETECTED | DNS_TUNNELLING | ENCRYPTED_SESSION_ANOMALY | HOST_SCAN | PORT_SCAN | SYN_FLOOD | UDP_FLOOD |
|---|---|---|---|---|---|---|---|---|---|
| rules | 0.291 | 0.300 | 0.750 | 1.000 | 1.000 | 1.000 | 0.906 | 1.000 | 1.000 |
| rules_statistical | 0.291 | 0.561 | 0.750 | 1.000 | 1.000 | 1.000 | 0.906 | 1.000 | 1.000 |
| random_forest | 0.424 | 1.000 | 1.000 | 1.000 | 0.758 | 1.000 | 1.000 | 1.000 | 1.000 |
| xgboost | 0.541 | 1.000 | 0.875 | 1.000 | 1.000 | 1.000 | 0.969 | 1.000 | 1.000 |
| isolation_forest | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 |
| hybrid | 0.424 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 |

## Calibration (test split)

Brier score and expected calibration error (10 bins) of the attack probability.
Raw Isolation Forest scores are not probabilities, so only the calibrated values are shown.

| Model | Brier before | ECE before | Brier after | ECE after |
|---|---|---|---|---|
| random_forest | 0.027 | 0.027 | 0.025 | 0.010 |
| xgboost | 0.021 | 0.015 | 0.019 | 0.009 |
| isolation_forest | – | – | 0.117 | 0.015 |

## Feature-group ablation (random forest)

| Variant | Precision | Recall | F1 | FPR | PR-AUC |
|---|---|---|---|---|---|
| all_features | 1.000 | 0.684 | 0.813 | 0.000 | 0.961 |
| without_volume | 0.993 | 0.692 | 0.816 | 0.001 | 0.928 |
| without_scan | 1.000 | 0.691 | 0.817 | 0.000 | 0.959 |
| without_beaconing | 0.987 | 0.678 | 0.804 | 0.002 | 0.947 |
| without_exfiltration | 0.998 | 0.680 | 0.809 | 0.000 | 0.959 |
| without_dns | 0.998 | 0.695 | 0.820 | 0.000 | 0.960 |
| without_tls | 0.986 | 0.732 | 0.840 | 0.002 | 0.943 |

## Leave-one-attack-out (random forest)

Trained and calibrated without one attack class; share of that class's test windows
still scored as attacks. This measures generalisation to attack types the model
has not seen, which is what matters for novel threats.

| Held-out class | Test windows | Flagged as attack | Benign FPR |
|---|---|---|---|
| C2_BEACONING | 344 | 0.000 | 0.000 |
| DATA_EXFILTRATION | 180 | 0.000 | 0.000 |
| DGA_DETECTED | 16 | 0.000 | 0.000 |
| DNS_TUNNELLING | 16 | 0.000 | 0.000 |
| ENCRYPTED_SESSION_ANOMALY | 33 | 0.000 | 0.000 |
| HOST_SCAN | 12 | 1.000 | 0.000 |
| PORT_SCAN | 32 | 0.969 | 0.000 |
| SYN_FLOOD | 8 | 1.000 | 0.000 |
| UDP_FLOOD | 12 | 0.000 | 0.000 |

## Random forest class confusion (attack windows of the test split)

- C2_BEACONING → C2_BEACONING: 253, BENIGN: 91
- DATA_EXFILTRATION → DATA_EXFILTRATION: 180
- DGA_DETECTED → DGA_DETECTED: 16
- DNS_TUNNELLING → DNS_TUNNELLING: 16
- ENCRYPTED_SESSION_ANOMALY → ENCRYPTED_SESSION_ANOMALY: 30, BENIGN: 3
- HOST_SCAN → HOST_SCAN: 12
- PORT_SCAN → PORT_SCAN: 32
- SYN_FLOOD → SYN_FLOOD: 8
- UDP_FLOOD → UDP_FLOOD: 12

## Most important features (random forest, impurity based)

- `flows_per_second` — 0.0323
- `failed_connection_ratio` — 0.0318
- `total_flows` — 0.0307
- `connection_rate` — 0.03
- `outbound_inbound_ratio` — 0.0298
- `max_query_length` — 0.0288
- `total_outbound_bytes` — 0.0274
- `unique_source_ips` — 0.0269
- `peak_flows_per_second` — 0.0258
- `nxdomain_ratio` — 0.0251
- `max_domain_entropy` — 0.025
- `dest_ip_entropy` — 0.0248
- `syn_target_attempts` — 0.0238
- `max_pair_upload` — 0.0237
- `avg_domain_entropy` — 0.0235

## Limitations

- The data is produced by UniShield's own seeded generator. Train and test come from the same generator, so supervised scores are optimistic; the leave-one-attack-out table is a better guide to behaviour on unfamiliar attacks.
- Results on real traffic (e.g. CICIDS2017, CTU-13) require running `scripts/prepare_dataset.py --input <files>` on those datasets; they are not included.
- Probabilities are calibrated on the calibration split of the same distribution and may be miscalibrated on other networks.
