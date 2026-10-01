# 🛡️ UniShield: AI Security for One-Way Networks

> **Passive, read-only cybersecurity monitoring for unidirectional IP traffic.**

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-passing-brightgreen.svg)]()

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
PCAP / Zeek / CSV ─→ Input Adapters ─→ NormalisedFlow Records
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
- Python 3.11+
- pip

### Installation

```bash
# Clone the repository
git clone <your-repo-url>
cd unishield

# Create virtual environment
python -m venv .venv

# Activate (Windows)
.venv\Scripts\activate

# Activate (Linux/macOS)
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
pip install -e .
```

### Start the API + Dashboard

```bash
cd src
python -m uvicorn unishield.api.app:app --host 127.0.0.1 --port 8000
```

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

### Run Tests

```bash
# All tests
python -m pytest tests/ -v

# With coverage
python -m pytest tests/ --cov=src/unishield --cov-report=term-missing
```

### Run Benchmarks & Ablation Study

```bash
cd src
python -m unishield.scripts.benchmark
# Report saved to reports/benchmark_report.json
```

---

## 🐳 Docker

```bash
# Build and start
docker-compose up -d

# View logs
docker-compose logs -f

# Stop
docker-compose down
```

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
| POST | `/replay/start` | Replay a PCAP/JSON/CSV file |
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

Benchmarked on synthetic traffic (mixed attack scenarios):

| Metric | Value |
|--------|-------|
| Throughput | 40,000+ records/sec |
| P50 Latency | < 0.01 ms |
| P95 Latency | < 0.2 ms |
| P99 Latency | < 0.3 ms |
| Threat Classes | 7+ (DDoS, scan, beacon, exfil, DNS, DGA, anomaly) |

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
