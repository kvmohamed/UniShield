# UniShield — Evaluation

Four scripts produce every number reported for UniShield. Each writes JSON
and Markdown to `reports/` and records the machine it ran on;
`scripts/run_demo.py` runs them all.

| Question | Script | Report |
|---|---|---|
| Does each labelled scenario raise the right classes? | `run_demo.py` (step 2) | `demo_detection.json` |
| How do rules, statistics and ML compare? | `evaluate_models.py` | `model_evaluation.md` |
| Is it fast enough? | `benchmark_pipeline.py` | `benchmark.md` |
| How long from window end to an alert in the API? | `replay_stream.py` | `realtime_verdict.md` |
| Is it passive? | `verify_passive_mode.py` | `passive_mode_verification.md` |

## 1. Scenario detection

Each of the 11 scenarios ([dataset.md](dataset.md)) runs through the default
pipeline and the raised classes are compared with the expected ones. A
scenario passes when every expected class is raised and no other rule class
is (STATISTICAL_ANOMALY is allowed because it names no technique). The
integration tests check seeds 1–5 for each scenario; the demo uses seed 11.
Result on the development machine: 11/11.

## 2. Detection approaches

**Unit of evaluation.** Each analysed 10 s window (sliding every 5 s). A
window is an attack window if it holds at least one attack-labelled flow.

**Data and splits.** 220 runs of the generator (11 scenarios × 20 seeds),
split by run into train / calibration / test (60/20/20, stratified by
scenario type) so overlapping windows never cross sets.

**Approaches**, all scored on the same test windows:

| Approach | A window is flagged when |
|---|---|
| rules | a rule detector raised or suppressed (re-alert) a class in it |
| rules + statistics | as above, or the robust-z / online Isolation Forest detectors raised an alert (the default `rules` mode) |
| random forest / XGBoost | calibrated P(attack) ≥ 0.9 |
| Isolation Forest | its anomaly score, isotonically calibrated on labels, ≥ 0.9 |
| hybrid | rules, or random forest ≥ 0.9 (what `hybrid` mode reports) |

**Metrics.** Precision, recall, F1, false-positive rate, PR-AUC and ROC-AUC
(scores where the approach has one), per-class recall, a random-forest
confusion matrix over attack windows, and episode metrics: an episode is a
run's attack windows of one class, split at gaps over 300 s; it is detected
if any of its windows is flagged, and its **detection delay** is the time
from the close of its first window containing attack traffic to the close of
the first flagged window (traffic time).

**Calibration.** Brier score and expected calibration error (10 bins)
before and after isotonic calibration.

**Ablations.** Random forest retrained without each feature group (volume,
scan, beaconing, exfiltration, DNS, TLS), and **leave-one-attack-out**:
trained and calibrated without one attack class, how much of that class it
still flags.

**Headline results** (`reports/model_evaluation.md`): window F1 rules 0.594,
rules + statistics 0.662, random forest 0.813, XGBoost 0.859, hybrid 0.821;
every approach except the Isolation Forest detected all 48 test episodes,
with a median delay of 0 s (beaconing needs up to ~9 minutes of check-ins
before the rules fire). Rules had no false positives on test windows. The
leave-one-attack-out table shows the supervised model does not recognise
unseen classes except scans and SYN floods.

**How to read it.** Window recall penalises evidence-accumulating detectors
(a beacon window holds one small check-in), so episode recall and delay
matter more for beaconing and exfiltration. Supervised scores are optimistic
because train and test share the generator.

## 3. Performance

`benchmark_pipeline.py`: a deterministic workload of ~20,000 records (dense
benign traffic plus floods, scan, DGA, tunnel, exfiltration and a beacon),
the default detectors, alerts written to in-memory SQLite; one warm-up run,
then 5 measured runs with mean / median / SD / min / max of throughput,
window-processing P95, alert latency after window close (stored −
window closed), peak RSS and CPU. Targets: ≥ 1,000 records/s and P95 alert
latency < 2 s after the window closes, in every run. A separate measurement
covers the PCAP path (scapy parsing + sessionization + detection).

Result on the development machine: 25,829 records/s mean (min 25,214);
alert-latency P95 51.8 ms mean (max 55.0); PCAP path 3,881 packets/s.
`pytest -m performance` checks the same targets on smaller workloads.

## 4. Real-time verification

`replay_stream.py` replays an ~8-minute mixed scenario at 20× real time
through the real pipeline (5 runs) while the real API is polled every 0.1 s
through an in-process client. Per alert it measures the window-close delay
(window end in replayed time → window closed), processing (closed → stored),
API visibility (stored → first returned) and end to end (window end →
visible). Result: median end to end 90.5 ms of wall time, max 218 ms, all 27
alerts seen. In traffic time an alert follows its activity by at most one
window length plus the close delay; evidence-accumulating detectors take
longer by design.

## 5. Passive operation

`verify_passive_mode.py` parses every module for network, capture, process
and crypto capabilities and runs every input format, all scenarios and the
API under a tripwire that refuses any non-loopback socket operation, name
resolution and scapy send/receive/sniff. Result: no static findings and no
runtime attempts.

## Reproducibility

Seeds are fixed in every script; the dataset manifest records the CSV's
SHA-256 and the model metadata records it again. Timing results depend on
the machine and its load.
