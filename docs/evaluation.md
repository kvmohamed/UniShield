# UniShield — Evaluation Methodology

## Metrics
- Confusion Matrix (per threat class)
- Precision, Recall, F1-Score (per threat class + macro)
- PR-AUC
- False Positive Rate
- Detection Delay (time from first malicious record to alert)
- Confidence Calibration (reliability diagram)
- Throughput (records/sec)
- Latency (P50, P95, P99)

## Baselines
1. Threshold-only detector
2. Random Forest
3. XGBoost
4. Isolation Forest
5. Hybrid detector (rules + stats + ML)

## Ablation Study
- Without entropy features
- Without timing features
- Without byte-ratio features
- Without destination-rarity features
- Rule-only vs ML-only vs Hybrid

## Methodology
- To be populated during Phase 5 and Phase 9
