# UniShield: AI Security for One-Way Networks

> Passive, metadata-only threat detection for unidirectional IP traffic.

[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![tests](https://github.com/kvmohamed/UniShield/actions/workflows/tests.yml/badge.svg)](https://github.com/kvmohamed/UniShield/actions/workflows/tests.yml)

> **This system is a passive defensive research prototype. It does not probe, block, decrypt, or send commands to monitored systems.**

UniShield reads capture files, Zeek logs and flow exports (or a replayed
stream), analyses them in 10-second sliding windows of traffic time, and
reports DDoS, scanning, C2 beaconing, data exfiltration, DGA, DNS tunnelling,
suspicious encrypted-session behaviour and contact with known-bad
infrastructure (offline threat-intel lists) through a REST API and a
dashboard. It has no packet-sending, capture, decryption or response path
towards the monitored network; `scripts/verify_passive_mode.py` checks this
statically and at runtime.

It fits into a security team's workflow on the **analyst side** of the
one-way link: alerts and incidents can be exported as JSON lines, CEF and
STIX 2.1 files, forwarded to a SIEM over syslog, and announced by email or
webhook. All of that is off by default, and outbound traffic can only reach
destinations you allow-list on the analyst network — never the monitored
network ([docs/deployment.md](docs/deployment.md)).

The project went through a phased audit and repair; the audit and the repair
log are in [reports/realtime_readiness_report.md](reports/realtime_readiness_report.md).

---

## Quick start

```bash
git clone https://github.com/kvmohamed/UniShield.git
cd UniShield
python3.12 -m venv .venv            # Windows: py -3.12 -m venv .venv
source .venv/bin/activate           # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt # runtime + tests + charts
pip install --no-deps -e .
pip install -r requirements-ml.txt  # optional: XGBoost comparison model
```

### One-command offline demo

```bash
python scripts/run_demo.py           # about 5 minutes; --quick for about 1 minute
```

It writes sample inputs, runs every labelled scenario, trains and evaluates
the models, benchmarks throughput and latency, replays traffic at a fixed
pace with end-to-end timestamps, verifies passive operation and draws charts.
Everything it reports is measured in that run and written to `reports/`.
See [docs/demo_guide.md](docs/demo_guide.md).

### Dashboard and API

```bash
python -m unishield.main             # http://127.0.0.1:8000/dashboard  (API docs: /docs)
```

Pick a scenario and press **Run demo**, or analyse a file under `data/`
(e.g. `data/samples/attack_portscan.pcap` after `python scripts/make_samples.py`).

---

## What it detects

| Class | Evidence (metadata only) | ATT&CK |
|---|---|---|
| SYN_FLOOD, UDP_FLOOD, DDOS_VOLUMETRIC | per-destination peak packet / half-open / UDP rates, number of sources | T1498, T1498.001, T1499.001 |
| PORT_SCAN, HOST_SCAN | per-source connection attempts across ports and hosts, failure ratio | T1046, T1595.001 |
| C2_BEACONING | regular inter-arrival times to one destination across windows | T1071 (+T1573 over TLS) |
| DATA_EXFILTRATION | upload volume and ratio, deviation from the source's own baseline, long upload sessions, rare destinations | T1041, T1048 (+T1573, T1571) |
| DGA_DETECTED | many generated-looking domains from one client, NXDOMAIN share | T1568.002 |
| DNS_TUNNELLING | many unique long / high-entropy subdomains of one base domain | T1071.004, T1572 |
| ENCRYPTED_SESSION_ANOMALY | outdated TLS versions, operator JA3 blocklist, long low-rate sessions on unusual ports — never decrypted | T1573 (+T1571) |
| STATISTICAL_ANOMALY | robust z-scores and Isolation Forest on windows no rule explained | — |
| INTEL_MATCH | an address, network or domain from an imported threat-intel list in a flow or DNS query (other alerts involving one get the match as evidence and one level more severity) | techniques listed with the indicator |

Detection modes (`UNISHIELD_DETECTION_MODE` or `mode=` on a replay):
`rules` (default: rules + robust z + Isolation Forest), `hybrid` (adds the
calibrated random-forest window model for windows no rule explained) and
`ml` (the model alone, for evaluation). Rule confidences are scores; only the
ML detector reports calibrated probabilities.

Architecture, stage by stage: [docs/architecture.md](docs/architecture.md).

## Inputs

| Input | Notes |
|---|---|
| PCAP / PCAPNG | read offline with scapy; packets grouped into bidirectional flows; DNS question/rcode, TLS version/cipher and JA3 from plaintext handshakes |
| Zeek logs | JSON lines/array or TSV; a directory with `conn.log` (+`dns.log`, `ssl.log`) is joined on `uid` |
| Flow CSV / JSON | flexible column names; CIC-IDS2017 CSVs detected automatically |
| Synthetic | seeded, labelled scenarios (`build_scenario(name, seed)`) |

The format is detected from file content. The replay API reads only under
`paths.data_dir` / `ingest.allowed_dirs`.

---

## Analyst-side integrations

Everything below is local files or traffic to the **analyst network**; none
of it touches the monitored network, and nothing is fetched from the internet.

| Feature | How | Details |
|---|---|---|
| Threat intelligence | `python scripts/import_intel.py --source feodo feodo.csv` or `POST /intel/import` | Known-bad IPs/CIDRs, domains and JA3 hashes from text, CSV or STIX 2.1 indicator files, with source and expiry; matches raise INTEL_MATCH, enrich other alerts and feed the JA3 blocklist |
| File exports | `python scripts/export_alerts.py`, `POST /export`, or `export.continuous: true` | Alerts and incidents as JSON lines, CEF and a STIX 2.1 bundle (indicators, sightings, observed data, incidents, ATT&CK attack-patterns); continuous files rotate |
| SIEM forwarding | `outbound.syslog` | RFC 5424 syslog over UDP, TCP or TLS with CEF or JSON payloads |
| Notifications | `outbound.email`, `outbound.webhook` | Alerts at or above a severity; rate limit and digests; only the configured fields; optional IP redaction |

Outbound rules: every destination must be listed in
`outbound.allowed_destinations` and lie outside `network.home_networks`.
This is checked when the configuration loads and again before every
connection (names are resolved and every address checked; the connection
goes to the checked address). Only `unishield/export/transport.py` can open
connections, which the passive-mode verification checks statically and at
runtime. With the default `home_networks` (all private ranges), private
analyst addresses are refused, so set it to the monitored network's real
ranges before enabling outputs. Placement, firewalling, TLS and secrets:
[docs/deployment.md](docs/deployment.md); threats and mitigations:
[docs/threat_model.md](docs/threat_model.md).

---

## Measured results

From the reports produced by `scripts/run_demo.py` on the development machine
(Windows 10, 12 logical CPUs, Python 3.12.10). Rerun the scripts to measure
your own machine.

**Scenarios** — all 11 labelled scenarios raise their expected classes with
the default `rules` mode and no other rule class (`reports/demo_detection.json`;
`exfil_episodes` also raises STATISTICAL_ANOMALY inside the upload episodes).
`benign_hard`, built to trip naive rules, raises nothing.

**Throughput and latency** (`reports/benchmark.md`, 5 runs × 19,610 records):

| Measure | Mean | Min | Max |
|---|---|---|---|
| Throughput, records/s (target ≥ 1,000) | 25,829 | 25,214 | 26,480 |
| P95 alert latency after window close, ms (target < 2,000) | 51.8 | 50.0 | 55.0 |
| Window processing P95, ms | 13.5 | 13.2 | 14.2 |
| Peak resident memory, MB | 131 | 125 | 137 |
| PCAP path (scapy parsing + sessionizer), packets/s | 3,881 | 3,721 | 3,963 |

**Real-time replay** (`reports/realtime_verdict.md`, 5 paced replays at 20×,
API polled every 0.1 s): from the end of an alert's window in replayed time to
the alert being returned by the API took a median of 90.5 ms of wall time
(max 218 ms; per-run P95 mean 110 ms), of which window-close wait 40 ms,
detection + storage 26 ms and API polling 16 ms (medians). All 27 alerts
reached the API. Classification: near-real-time event-time processing of
replayed traffic — not a live capture sensor.

**Detection approaches** (`reports/model_evaluation.md`, held-out runs, window level):

| Approach | Precision | Recall | F1 | Episodes detected |
|---|---|---|---|---|
| rules | 1.000 | 0.423 | 0.594 | 48/48 |
| rules + statistics (default) | 1.000 | 0.495 | 0.662 | 48/48 |
| random forest (calibrated, ≥ 0.9) | 1.000 | 0.684 | 0.813 | 48/48 |
| XGBoost | 0.998 | 0.753 | 0.859 | 48/48 |
| Isolation Forest | 0.000 | 0.000 | 0.000 | 0/48 |
| hybrid | 1.000 | 0.697 | 0.821 | 48/48 |

These use synthetic data from UniShield's own generator, so the supervised
scores are optimistic: trained without a class, the random forest misses
most unseen attack types (leave-one-attack-out table in the report). See
[docs/model_card.md](docs/model_card.md) and [docs/evaluation.md](docs/evaluation.md).

**Passive operation** (`reports/passive_mode_verification.md`): the static
scan finds no network, capture, process or crypto capability outside the
analyst-side transport (whose allowed lines the report lists); under the
runtime tripwire readers, pipeline and detectors make no socket call at all
across every input format, the API makes only loopback calls, the outputs
reach only allow-listed loopback receivers, and a monitored-network
destination is refused at config load, at send time and at socket level.

---

## API

| Method | Endpoint | Description |
|---|---|---|
| GET | `/dashboard` | dashboard |
| GET | `/health` | health, database status, security flags |
| GET | `/metrics` | pipeline metrics, process CPU and memory |
| GET | `/metrics/traffic` | per-window flows/bytes/alerts, top alert entities |
| GET | `/alerts` | filters (class, severity, IPs, detector, run, time, confidence), sort, pagination (`X-Total-Count`) |
| GET | `/alerts/summary`, `/alerts/timeline`, `/alerts/{id}` | summary, severity timeline, detail |
| GET | `/incidents` | alerts grouped by entity and time |
| GET | `/threats/{class}` | alerts of one class |
| GET | `/replay/status`, `/replay/runs` | current run, recent runs |
| GET | `/system/architecture` | stage, detector, model, output, intel and safety status |
| GET | `/outputs/status` | export, syslog and notification status (no secrets) |
| GET | `/intel/status` | imported indicators per kind and source |
| GET | `/benchmark/latest`, `/evaluation/latest` | measured reports |
| POST | `/replay/start` | admin: analyse a file under the data directory |
| POST | `/replay/demo` | admin: analyse a synthetic scenario (`wait=true` to block) |
| POST | `/replay/stop` | admin: stop the run |
| DELETE | `/alerts` | admin: delete stored alerts |
| POST | `/export` | admin: write JSON lines / CEF / STIX files of stored alerts and incidents |
| POST | `/intel/import` | admin: import an indicator file (request body) |
| DELETE | `/intel/sources/{source}` | admin: remove a source's indicators |
| POST | `/intel/purge-expired` | admin: delete expired indicators |

Admin endpoints need `X-API-Key` matching `UNISHIELD_ADMIN_API_KEY`; when no
key is set they accept loopback clients only. Read endpoints have no side
effects.

## Configuration

`configs/config.yaml` (general, including the `intel`, `export` and
`outbound` sections), `configs/thresholds.yaml` (detection thresholds) and
environment variables listed in `.env.example` (`UNISHIELD_DB_URL`,
`UNISHIELD_ADMIN_API_KEY`, `UNISHIELD_DETECTION_MODE`, `UNISHIELD_EXPORT_DIR`,
`UNISHIELD_SMTP_PASSWORD`, ...). The four security flags cannot be disabled;
outbound secrets are read only from the environment.

Alerts are stored in SQLite (`data/unishield.db`) by default; PostgreSQL
works with `UNISHIELD_DB_URL=postgresql+psycopg://...` and its driver.

## Models

```bash
python scripts/prepare_dataset.py --synthetic --seeds 1-20   # or --input <labelled files>
python scripts/train_models.py                               # window_rf, window_xgb, window_if
python scripts/evaluate_models.py                            # reports/model_evaluation.md
```

## Tests

```bash
pytest                    # unit, integration and security tests
pytest -m performance     # throughput / latency / memory targets on this machine
```

CI runs the default suite on Ubuntu and Windows with Python 3.12.

## Docker

```bash
echo "UNISHIELD_ADMIN_API_KEY=$(python -c 'import secrets; print(secrets.token_urlsafe(32))')" > .env
docker compose up -d --build   # http://127.0.0.1:8000/dashboard
```

The container runs unprivileged with a read-only root filesystem and no
capabilities; configs, data, reports and models are mounted read-only and
alerts live in a named volume. Requests reach it from the Docker bridge, so
admin actions need the key (enter it in the dashboard header). The Docker
files have not been built on the development machine (Docker was not
installed there).

## Updating dependencies

`pyproject.toml` holds the ranges; `requirements*.txt` pin exact versions.
After changing `pyproject.toml`, regenerate the pins in a fresh Python 3.12
venv (`pip install -e .` → `pip freeze --exclude-editable` for
`requirements.txt`; add `.[dev,reports]` for `requirements-dev.txt`).

## Documentation

[architecture](docs/architecture.md) ·
[deployment](docs/deployment.md) ·
[threat model](docs/threat_model.md) ·
[datasets](docs/dataset.md) ·
[model card](docs/model_card.md) ·
[evaluation](docs/evaluation.md) ·
[limitations](docs/limitations.md) ·
[demo guide](docs/demo_guide.md)

## Limitations

Not a live sensor (files and replayed streams only), not a SOC or IPS, no
payload inspection; thresholds tuned on synthetic data; models trained on
synthetic data and weak on unseen attack types; single process; threat-intel
matching only as good as the imported lists; outputs tested against
UniShield's own loopback receivers, not specific SIEM products. Full list:
[docs/limitations.md](docs/limitations.md).

## License

MIT — see [LICENSE](LICENSE). Use only with authorised datasets or isolated
laboratory traffic.
