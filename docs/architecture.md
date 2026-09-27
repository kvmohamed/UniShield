# UniShield Architecture

## System Overview

UniShield is a passive, read-only cybersecurity monitoring platform for
unidirectional IP traffic. It detects threats using only traffic metadata
— never decrypting payloads, probing endpoints, or sending commands.

## Pipeline Architecture

```
┌─────────────────┐
│  Input Adapter   │  PCAP, Zeek JSON, Flow CSV/JSON
│  (Read-Only)     │
└────────┬────────┘
         │
┌────────▼────────┐
│  Normalisation   │  Standardise all inputs to NormalisedFlow
│  Layer           │
└────────┬────────┘
         │
┌────────▼────────┐
│  Flow            │  Group packets into sessions
│  Sessionisation  │
└────────┬────────┘
         │
┌────────▼────────┐
│  Rolling Window  │  10s window, 5s slide (configurable)
│  Manager         │
└────────┬────────┘
         │
┌────────▼────────┐
│  Feature         │  Per-threat-class feature extraction
│  Extraction      │
└────────┬────────┘
         │
┌────────▼────────────────────────────────┐
│  Detection Layers                        │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ │
│  │  Rules   │ │  Stats   │ │   ML     │ │
│  └──────────┘ └──────────┘ └──────────┘ │
└────────┬────────────────────────────────┘
         │
┌────────▼────────┐
│  Confidence      │  Calibrate and normalise scores
│  Calibration     │
└────────┬────────┘
         │
┌────────▼────────┐
│  Correlation &   │  Deduplicate, assign severity,
│  Deduplication   │  map MITRE ATT&CK
└────────┬────────┘
         │
┌────────▼────────┐
│  Alert Store     │  SQLite / PostgreSQL
└────────┬────────┘
         │
┌────────▼────────┐
│  REST API        │  FastAPI endpoints
└────────┬────────┘
         │
┌────────▼────────┐
│  Dashboard       │  Streamlit + Plotly
└─────────────────┘
```

## Security Architecture

All security constraints are **immutable** — they cannot be disabled at runtime:

| Constraint | Status | Description |
|---|---|---|
| Read-only mode | ✅ Always ON | No packets sent to monitored networks |
| No payload decryption | ✅ Always ON | TLS/QUIC/VPN payloads are never decrypted |
| No active scanning | ✅ Always ON | No probing or endpoint discovery |
| No response path | ✅ Always ON | No commands sent to monitored systems |

## Technology Stack

- **Backend**: Python 3.11+, FastAPI, Pydantic, SQLAlchemy
- **Processing**: Pandas, NumPy, SciPy
- **ML**: scikit-learn, XGBoost, Isolation Forest
- **Database**: SQLite (dev) / PostgreSQL (production)
- **Dashboard**: Streamlit, Plotly
- **Infrastructure**: Docker, Docker Compose
