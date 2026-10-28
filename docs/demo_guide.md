# UniShield — Demo Guide

Everything below runs offline on synthetic or locally written data. Nothing
is downloaded and nothing is sent on any network.

## 1. One command

```bash
python scripts/run_demo.py            # full: about 5 minutes
python scripts/run_demo.py --quick    # shorter seeds/runs: about 1 minute
```

(`scripts/run_demo.bat` on Windows and `scripts/run_demo.sh` on Linux/macOS
use the project's `.venv` when it exists.)

It runs seven steps and writes every result to `reports/`:

| Step | Output |
|---|---|
| Sample input files (PCAP, PCAPNG, Zeek JSON/TSV, flow CSV/JSONL, CICIDS-style CSV) | `data/samples/` |
| Every labelled scenario through the pipeline, raised vs expected classes | `reports/demo_detection.json` |
| Window dataset, training, calibration, comparison of approaches | `reports/model_evaluation.md`, `models/saved/` |
| Throughput and alert-latency benchmark (5 runs) + PCAP path | `reports/benchmark.md` |
| Paced real-time replay with end-to-end timestamps (5 runs) | `reports/realtime_verdict.md` |
| Passive-mode verification (static + runtime) | `reports/passive_mode_verification.md` |
| Charts | `reports/figures/*.png` |

## 2. Dashboard

```bash
unishield-admin user create admin --role admin   # once: there are no default accounts
python -m unishield.main              # http://127.0.0.1:8000/dashboard, then sign in
```

- **Overview**: pick a scenario (e.g. `ddos_syn`, `beacon_30s`,
  `encrypted_anomaly`, or `mixed`) and press *Run demo*, or enter a file under
  `data/` (e.g. `data/samples/attack_portscan.pcap`) and press *Analyse file*.
- **Alerts & timeline**: filter alerts, page through them and open one to see
  its evidence, MITRE ATT&CK links and stage timestamps (window closed →
  stored).
- **Traffic analytics**: flows and bytes per analysis window, top alert
  sources and destinations.
- **Benchmark & evaluation**: the measured benchmark, live pipeline metrics
  and the model comparison table.
- **Architecture status**: pipeline stages, safety constraints, trained
  models and per-detector counters.

- **Admin** (administrators): users and roles, password resets, unlocking,
  and the audit log of everything done in the session above.
- **Account**: your session and a password change.

Run controls appear for administrators only; a viewer account sees the
same data without them. For a classroom machine where nobody should need to
sign in to look, `UNISHIELD_AUTH_MODE=open` (lab only) lets anyone read;
running demos still needs an administrator.

## 3. Hybrid detection

```bash
python scripts/prepare_dataset.py --synthetic --seeds 1-20
python scripts/train_models.py
UNISHIELD_DETECTION_MODE=hybrid python -m unishield.main
```

or `POST /replay/demo?scenario=beacon_30s&mode=hybrid`. Alerts from the
window model have `detector_name = ml_detector` and a calibrated probability
as confidence.

## 4. Command line

```bash
python scripts/replay_pcap.py --input data/samples/attack_synflood.pcap
python scripts/replay_pcap.py --input data/samples/zeek --json
python scripts/verify_passive_mode.py
python scripts/import_intel.py --source demo-c2 my_blocklist.txt   # offline threat intel
python scripts/export_alerts.py --formats stix                     # JSON lines / CEF / STIX files
pytest                       # unit, integration and security tests
pytest -m performance        # performance targets on this machine
```

## Talking points

- Detection is metadata only; TLS is never decrypted.
- Nothing goes back into the monitored network. Optional exports, syslog,
  email and webhooks reach only allow-listed analyst-side destinations, and
  the passive-mode report shows the refused probes.
- Rule confidences are scores; only the ML detector reports calibrated
  probabilities.
- Every number in the reports is produced by the scripts on the machine that
  ran them, with the machine recorded in the report.
- The models are trained on synthetic data from UniShield's own generator;
  read the leave-one-attack-out table before trusting the high scores.
