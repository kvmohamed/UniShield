# 🛡️ UniShield: AI Security for One-Way Networks

> **Passive, read-only cybersecurity monitoring for unidirectional IP traffic.**

[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![tests](https://github.com/kvmohamed/UniShield/actions/workflows/tests.yml/badge.svg)](https://github.com/kvmohamed/UniShield/actions/workflows/tests.yml)

> **Status:** research prototype under phased repair. The audit in
> [reports/realtime_readiness_report.md](reports/realtime_readiness_report.md) records what
> currently works, what does not, and the repair plan. Where this README and the audit
> disagree, the audit is authoritative.

---

## ⚠️ Security Notice

> **This system is a passive defensive research prototype. It does NOT probe, block, decrypt, or send commands to monitored systems.**

UniShield operates in **read-only mode only**. It:
- ✅ Reads PCAP files, Zeek JSON logs, and flow records
- ✅ Analyses traffic metadata (timestamps, sizes, ports, protocols)
- ✅ Detects threats using rules, statistics, and machine learning
- ❌ **Never** sends packets to monitored networks
- ❌ **Never** decrypts TLS, QUIC, or VPN payloads
- ❌ **Never** performs active scanning or endpoint discovery
- ❌ **Never** issues blocking or remediation commands

---

## 🎯 Features

### Threat Detection
| Threat Class | Indicators | MITRE ATT&CK | Detector |
|---|---|---|---|
| **DDoS / Volumetric** | SYN flood, UDP flood, PPS/BPS rates, SYN/ACK imbalance | T1498, T1498.001 | Rule-based |
| **Port Scanning** | Unique ports, host fan-out, failure ratio, burst detection | T1046 | Rule-based |
| **Host Scanning** | Horizontal sweep, port-host spread, fan-out score | T1046 | Rule-based |
| **C2 Beaconing** | Inter-arrival timing CV, periodicity score, size regularity | T1071, T1573 | Rule-based |
| **Data Exfiltration** | Outbound/inbound ratio, long sessions, port rarity | T1041, T1048 | Rule-based |
| **DNS Tunnelling** | Long queries, TXT record ratio, domain entropy | T1071.004, T1048.003 | Rule-based |
| **DGA Detection** | Character entropy, consonant ratio, NXDOMAIN ratio | T1568.002 | Rule-based |
| **Statistical Anomaly** | Z-score deviation, Isolation Forest anomaly scoring | T1071 | ML (scikit-learn) |

### Detection Architecture
```
PCAP / Zeek / CSV ─→ Input Adapters ─→ Sessionizer (PCAP only) ─→ Normaliser
                     (format detected     (packets → bidirectional   (direction,
                      from content)        flows, conn state)         naming, optional
                                                                       IP hashing)
                                              │
                                    ┌─────────▼─────────┐
                                    │  Sliding Windows   │
                                    │  (configurable)    │
                                    └─────────┬─────────┘
                                              │
                              ┌───────────────┼───────────────┐
                              │               │               │
                       Volume Features  Scan Features  Beacon Features
                       Exfil Features   DNS Features   Statistical Features
                              │               │               │
                              └───────────────┼───────────────┘
                                              │
                              ┌───────────────┼───────────────┐
                              │               │               │
                        DDoS Detector   Scan Detector   Beacon Detector
                        Exfil Detector  DNS Detector    Anomaly Detector (IF)
                              │               │               │
                              └───────────────┼───────────────┘
                                              │
                                    ┌─────────▼─────────┐
                                    │  Alert Correlator  │
                                    │  (dedup + group)   │
                                    └─────────┬─────────┘
                                              │
                                    ┌─────────▼─────────┐
                                    │   REST API + UI    │
                                    └───────────────────┘
```

### Key Capabilities
- **Streaming processing** with configurable rolling windows
- **Incremental detection** — alerts generated without waiting for full dataset
- **Bounded detection latency** — sub-millisecond per record
- **Alert correlation** — deduplication, multi-stage attack grouping, severity escalation
- **Isolation Forest** anomaly detection with online learning
- **Real-time dashboard** at `http://127.0.0.1:8000/dashboard`
- **Benchmark & ablation study** tooling

---

## 🚀 Quick Start

### Prerequisites
- Python 3.12 (the pinned dependencies require 3.12 or newer; Docker uses 3.12)
- pip

### Installation

```bash
# Clone the repository
git clone https://github.com/kvmohamed/UniShield.git
cd UniShield

# Create a Python 3.12 virtual environment
#   Windows:     py -3.12 -m venv .venv
#   Linux/macOS: python3.12 -m venv .venv

# Activate
#   Windows:     .venv\Scripts\activate
#   Linux/macOS: source .venv/bin/activate

# Install pinned dependencies, then UniShield itself
pip install -r requirements-dev.txt    # runtime + tests + charts (use requirements.txt for runtime only)
pip install --no-deps -e .
```

All commands below are run from the project root (no `cd src` needed).

### Start the API + Dashboard

```bash
python -m unishield.main
# or: uvicorn unishield.api.app:app --host 127.0.0.1 --port 8000
```

Settings come from `configs/config.yaml`; the variables in `.env.example` override them
(copy it to `.env`). Logs go to the console and `logs/unishield.log`.

Then open:
- **Dashboard**: http://127.0.0.1:8000/dashboard
- **API Docs**: http://127.0.0.1:8000/docs
- **Health Check**: http://127.0.0.1:8000/health

### Run a Demo Analysis

```bash
# Via API (generates synthetic traffic with embedded attacks)
curl -X POST "http://127.0.0.1:8000/replay/demo?normal=300&ddos=400&scan=150&beacon=30&exfil=40"

# View alerts
curl http://127.0.0.1:8000/alerts/summary
```

Or click **"Run Demo Analysis"** on the dashboard.

### Replay a Traffic File

`POST /replay/start` analyses a file or Zeek log directory located under the data
directory (`paths.data_dir`, default `./data`; extra folders via `ingest.allowed_dirs`).
The format is detected from the content:

| Input | Notes |
|---|---|
| PCAP / PCAPNG | One record per IPv4/IPv6 packet, then grouped into bidirectional flows (per-direction counts, connection state S0/REJ/S1/SF/RST/OTH). TLS version/cipher from plaintext handshake fields; DNS question and response code. |
| Zeek logs | JSON lines, JSON array or default TSV. A directory with `conn.log` (+ optional `dns.log`, `ssl.log`) is joined on `uid`. |
| Flow CSV / JSON | Flexible column names; CIC-IDS2017 CSVs detected automatically (µs durations, forward/backward counts, labels). |

Sample files with known contents:

```bash
python scripts/make_samples.py          # writes data/samples/
curl -X POST "http://127.0.0.1:8000/replay/start?file_path=data/samples/sample.pcap"
curl http://127.0.0.1:8000/replay/status
```

Paths outside the data directory are refused (HTTP 403). Inputs over
`ingest.max_file_size_mb` are refused (413). Direction (inbound/outbound/internal) is
inferred from `network.home_networks`.

### Run Tests

```bash
# All tests
python -m pytest tests/ -v

# With coverage
python -m pytest tests/ --cov=unishield --cov-report=term-missing
```

The same tests run on GitHub Actions (Ubuntu and Windows, Python 3.12) for every push.

### Run Benchmarks & Ablation Study

```bash
python -m unishield.scripts.benchmark
# Report saved to reports/benchmark_report.json
```

### Updating dependencies

`pyproject.toml` lists the dependency ranges; `requirements.txt` and `requirements-dev.txt`
pin exact versions for reproducible installs. After changing `pyproject.toml`, regenerate
the pins in a fresh Python 3.12 venv:

```bash
pip install -e .                                  # runtime only
pip freeze --exclude-editable > runtime.txt       # becomes requirements.txt
pip install -e ".[dev,reports]"
pip freeze --exclude-editable > all.txt           # all.txt minus runtime.txt becomes requirements-dev.txt
```

---

## 🐳 Docker

```bash
docker compose up -d --build    # build and start
docker compose logs -f          # follow logs
docker compose down             # stop
```

The container serves the API and dashboard at http://127.0.0.1:8000/dashboard. The port is
bound to loopback only because the API has no authentication yet. Configs and data are
mounted read-only. (The Docker setup has not yet been verified on a machine with Docker
installed.)

---

## 📁 Project Structure

```
unishield/
├── configs/                # YAML configuration files
│   ├── config.yaml         # Main application config
│   ├── thresholds.yaml     # Detection thresholds (tunable)
│   └── logging.yaml        # Logging configuration
├── data/                   # Traffic data (raw, processed, samples)
├── models/                 # Saved ML models (Isolation Forest)
├── src/unishield/          # Main source code
│   ├── api/                # FastAPI endpoints + dashboard serving
│   │   └── app.py          # Health, alerts, replay, demo endpoints
│   ├── ingest/             # Input adapters
│   │   ├── base.py         # Abstract reader interface
│   │   ├── pcap_reader.py  # PCAP/PCAPNG file reader
│   │   ├── zeek_reader.py  # Zeek JSON log reader
│   │   └── flow_reader.py  # CSV/JSON flow record reader
│   ├── processing/         # Streaming pipeline
│   │   ├── window.py       # Sliding window manager
│   │   └── pipeline.py     # Pipeline orchestrator
│   ├── features/           # Feature extractors
│   │   ├── base.py         # Abstract extractor interface
│   │   ├── volume.py       # Volume/rate features (25 features)
│   │   ├── scan.py         # Scan pattern features (12 features)
│   │   ├── beaconing.py    # Beacon timing features (11 features)
│   │   ├── exfiltration.py # Exfil indicator features (12 features)
│   │   ├── dns.py          # DNS query features (14 features)
│   │   └── statistical.py  # Z-score/baseline features (11 features)
│   ├── detectors/          # Threat detectors
│   │   ├── base.py         # Abstract detector interface
│   │   ├── ddos_detector.py       # DDoS/SYN/UDP flood
│   │   ├── scan_detector.py       # Port scan/host scan
│   │   ├── beaconing_detector.py  # C2 beaconing
│   │   ├── exfiltration_detector.py  # Data exfiltration
│   │   ├── dns_detector.py        # DNS tunnelling/DGA
│   │   └── anomaly_detector.py    # Isolation Forest ML
│   ├── correlation/        # Alert processing
│   │   └── correlator.py   # Dedup + incident grouping
│   ├── data/               # Sample data generation
│   │   └── sample_generator.py  # Synthetic traffic (5 scenarios)
│   ├── dashboard/          # Web UI
│   │   └── index.html      # Real-time monitoring dashboard
│   ├── schemas/            # Pydantic models
│   │   ├── flow.py         # NormalisedFlow schema
│   │   ├── alert.py        # Alert + AlertSummary schemas
│   │   └── metrics.py      # PipelineMetrics, HealthStatus
│   └── scripts/            # Utilities
│       └── benchmark.py    # Benchmarking + ablation study
├── tests/                  # Test suite (100+ tests)
│   ├── unit/               # Unit tests
│   ├── integration/        # Integration tests
│   └── performance/        # Performance tests
├── reports/                # Benchmark reports
└── docs/                   # Documentation
```

---

## 📡 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Dashboard (HTML) |
| GET | `/dashboard` | Dashboard (HTML) |
| GET | `/health` | System health + security constraints |
| GET | `/metrics` | Pipeline processing statistics |
| GET | `/alerts` | List alerts (filter by threat_class, severity, limit, offset) |
| GET | `/alerts/{id}` | Get alert by ID |
| GET | `/alerts/summary` | Alert summary statistics |
| GET | `/threats/{class}` | Alerts by threat class |
| POST | `/replay/start` | Analyse a PCAP/PCAPNG, Zeek or flow file under the data directory |
| POST | `/replay/demo` | Run demo with synthetic attack traffic |
| POST | `/replay/stop` | Stop active replay |
| GET | `/replay/status` | Replay progress + results |
| GET | `/benchmark/latest` | Latest benchmark results |
| GET | `/docs` | OpenAPI documentation |
| GET | `/redoc` | ReDoc documentation |

---

## ⚙️ Configuration

Edit `configs/config.yaml` for general settings and `configs/thresholds.yaml` for detection thresholds.

### Key Settings

```yaml
# Security (always enforced — cannot be disabled)
security:
  read_only_mode: true
  no_payload_decryption: true
  no_active_scanning: true
  no_response_path: true

# Processing windows
processing:
  window_size_sec: 10
  slide_interval_sec: 5
  max_queue_size: 10000

# Thresholds (configs/thresholds.yaml)
ddos:
  packets_per_second: 10000
  syn_rate_threshold: 5000
scanning:
  unique_dest_ports: 25
  unique_dest_hosts: 10
beaconing:
  regularity_cv_threshold: 0.3
  periodicity_score: 0.7
```

---

## 📊 Performance

Figures previously listed here (40,000+ records/sec, sub-millisecond latency) did not
reflect the current pipeline. Measured on 2026-10-14 (synthetic mixed traffic, 5 runs; see
audit §8):

| Metric | Value |
|--------|-------|
| Throughput (default pipeline, 6 detectors) | ~706 records/sec (σ 1.4) |
| Throughput without the Isolation Forest | ~30,000 records/sec |
| Per-window analysis time, P95 | ~14 ms |
| Threat classes that can be emitted | 11 (6 detectors) |

Throughput is being repaired in Phase 6 of the plan; this table will be regenerated from
benchmark output, not edited by hand.

---

## 📋 Limitations

- This system is **not a complete SOC** (Security Operations Centre).
- It does **not guarantee** attack detection — false negatives are possible.
- Metadata-based detection has **blind spots** — payload content is never inspected.
- Encrypted traffic classification is **probabilistic**, not deterministic.
- Public datasets may **not represent** real production infrastructure.
- **No mitigation** is performed — the environment is unidirectional by design.
- Detection thresholds require **tuning** per deployment environment.
- The Isolation Forest model requires a **warm-up period** (10+ windows) before anomaly detection activates.
- Confidence scores from rule-based detectors are **not calibrated probabilities** unless explicitly stated.
- DNS-based detectors require DNS metadata fields to be present in input data.

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

This software is intended for use only with authorised datasets and isolated laboratory traffic.
