# UniShield — Architecture

UniShield is a single-process Python service: a streaming detection pipeline,
an alert store and a FastAPI application that also serves the dashboard.
Everything it analyses comes from local files or a replayed stream; it has no
packet-sending, capture or response path towards the monitored network (see
[threat_model.md](threat_model.md) and `reports/passive_mode_verification.md`).
Optional outputs deliver alerts to the analyst network only: export files,
syslog, email and webhooks, all through one allow-listed transport
([deployment.md](deployment.md)).

```
 PCAP/PCAPNG ─┐                                   ┌─ Volume ─────┐   ┌─ DDoS ─────────┐
 Zeek JSON/TSV├─ readers ─ sessionizer ─ normaliser ─ windows ─┤─ Scan ───────┤──┤─ Scan ─────────┤
 Flow CSV/JSON│   (format     (PCAP only:   (direction,  (event time, │─ Beaconing* ──│  │─ Beaconing ────│
 Synthetic   ─┘   detected)    packets →     TLS names,   10 s every  │─ Exfiltration*│  │─ Exfiltration ─│── rule stage
                               flows)        hashing)     5 s)        │─ DNS ─────────│  │─ DNS (DGA,     │
                                                                      │─ TLS/JA3 ─────│  │  tunnelling)   │
                                                                      └─ Threat intel ┘  │─ Encrypted ────┤
                                                                                         │─ Intel match ──┘
                                                                     * keep bounded      │
                                                                       cross-window      ├─ Statistical (robust z) ┐
                                                                       history           ├─ Isolation Forest       ├─ post-rule stage
                                                                                         └─ ML window model ───────┘  (unexplained windows)
                                                                                                   │
                                                       intel enrichment (evidence, +1 severity)
                                                                                                   │
                              dashboard ◄── FastAPI ◄── SQLite / PostgreSQL ◄── correlator (dedup in traffic time)
                                               │               │ ▲ imported indicators (files → intel store)
                                               │               ▼
                                               │        output service (queue + worker, analyst side only)
                                               │          ├─ export files: JSON lines, CEF, STIX 2.1 (rotating)
                                               │          └─ export/transport.py ── policy: allow-listed, never
                                               │               ├─ syslog RFC 5424 (UDP/TCP/TLS)    home_networks
                                               │               ├─ email (SMTP relay)
                                               │               └─ webhook (JSON POST)
                                               └─ POST /export, /intel/import (admin)
```

## Stages

| Stage | Module | What it does |
|---|---|---|
| Ingest | `ingest/` | `detect.open_reader` picks the reader from file content. `PcapReader` streams packets with scapy's offline reader (one record per IP packet, DNS question/rcode, plaintext TLS ClientHello/ServerHello fields and JA3). `ZeekReader` reads JSON lines/arrays or TSV, joining `conn`, `dns` and `ssl` logs on `uid`. `FlowReader` maps flexible CSV/JSON columns, including CIC-IDS2017. Live readers: `FlowExportCollector` (`ingest/collector.py`, receive-only UDP; decoding in `ingest/netflow.py`: NetFlow v5, v9 and IPFIX templates per exporter and domain, RFC 5103 biflows) and `ZeekFollowReader` (`ingest/zeek_follow.py`, tails `conn.log`, joins `dns.log`/`ssl.log` by `uid`, follows rotation). While idle they yield `ClockTick`s so windows close on the wall clock. |
| Sessionizer | `processing/sessionizer.py` | Packet records → bidirectional flows with per-direction counts, connection state (S0/REJ/S1/SF/RST/OTH), idle/active timeouts and a bound on active flows. Flows are released in start-time order. |
| Normaliser | `processing/normalization.py` | Direction from `network.home_networks`, TLS version names, optional salted IP hashing. |
| Windows | `processing/window.py` | Grid-aligned sliding windows in traffic (event) time: a window closes when the first record past its end arrives, with configurable allowed lateness; the last windows are flushed at end of input. |
| Features | `features/` | One extractor per threat family (table below). Beaconing and exfiltration keep bounded state across windows (per-pair inter-arrival history; per-source upload baselines and destination rarity). |
| Detectors | `detectors/` | Rule detectors first; then detectors with `runs_after_rules` see which classes the rules raised or suppressed, so statistical, anomaly and ML alerts only describe windows nothing else explained. |
| Correlation | `correlation/` | Deduplication in traffic time (class, source, destination, detector); incident grouping per entity with multi-stage / multi-vector escalation; one table for severities and MITRE ATT&CK mappings. |
| Asset policy | `assets.py` | Role policies from `configs/assets.yaml` applied after deduplication: an alert is kept, reported as INFO (original severity and matching asset in evidence) or suppressed (counted, latest kept for review). |
| State | `processing/state_store.py` | Versioned JSON snapshot (SHA-256 checked, atomic) of every stateful extractor, detector and the correlator; restored before a run, written periodically and at the end. |
| Threat intel | `intel/` | Offline indicator files (text, CSV, STIX 2.1 indicators) parsed and validated, stored per source with expiry in the alert database; an in-memory matcher (exact addresses, networks, parent domains, JA3) is built for each run. Matches become INTEL_MATCH alerts, evidence on other alerts (with one level more severity) and JA3 blocklist entries. Nothing is fetched. |
| Storage | `storage/` | SQLAlchemy tables for alerts, runs, intel indicators, accounts and the append-only audit log (SQLite default, PostgreSQL by URL); schema owned by Alembic revisions (`storage/migrations`); retention and housekeeping; bound-parameter queries only. |
| Outputs | `export/` | Record formats (JSON lines, CEF, STIX 2.1), rotating and on-demand export files, an incident tracker for continuous outputs, RFC 5424 syslog forwarding, email/webhook notifications with rate limits and digests, the destination policy and the output service (bounded queue, one worker). `export/transport.py` is the only module that opens connections, only to allow-listed analyst-side destinations outside `network.home_networks`. |
| Accounts | `accounts/` | Roles (viewer < analyst < admin), Argon2id password hashing and policy, users with lockout, server-side login sessions, service tokens, login rate limiter. |
| API | `api/` | Routers for auth, users, audit, system, alerts, replay, exports and intel; one role guard per route (enforced when the app is built); session cookie + CSRF token or `X-API-Key` service token; Origin check, hardening headers, HSTS over HTTPS; dashboard with a same-origin CSP. |
| Administration | `cli.py` | `unishield-admin`: schema migrations, users, service tokens, retention, model verification. |

## Detection families

| Family | Extractor | Detector | Classes | Method |
|---|---|---|---|---|
| DDoS | `volume.py` | `ddos_detector.py` | SYN_FLOOD, UDP_FLOOD, DDOS_VOLUMETRIC | Per-destination peak 1 s rates, SYN-only ratio, source counts |
| Scanning | `scan.py` | `scan_detector.py` | PORT_SCAN, HOST_SCAN | Per-source connection attempts: vertical ports, horizontal hosts, failures |
| C2 beaconing | `beaconing.py` | `beaconing_detector.py` | C2_BEACONING | Rolling inter-arrival history per (src, dst, port): count, mean, CV, periodicity, destination fan-in |
| Exfiltration | `exfiltration.py` | `exfiltration_detector.py` | DATA_EXFILTRATION | Upload volume, robust z vs the source's own baseline, long upload sessions, destination rarity |
| DNS | `dns.py` | `dns_detector.py` | DGA_DETECTED, DNS_TUNNELLING | Per-client generated-looking names + NXDOMAIN; per-base-domain unique long/high-entropy subdomains |
| Encrypted sessions | `encrypted.py` | `encrypted_detector.py` | ENCRYPTED_SESSION_ANOMALY | Outdated TLS versions, operator JA3 blocklist (plus imported JA3 indicators), long low-rate sessions on unusual ports (metadata only) |
| Threat intel | `intel.py` | `intel_detector.py` | INTEL_MATCH | Flow addresses and DNS query names looked up in imported indicators; severity by direction (outbound/DNS HIGH, inbound MEDIUM) unless the indicator sets one |
| Brute force, spam | `service_abuse.py` | `service_abuse_detector.py` | BRUTE_FORCE, SPAM_ACTIVITY | Rolling per-(source, destination, login port) attempt counts over 60 s; per-source distinct external SMTP servers over 5 min |
| Statistical | (window metrics) | `statistical_detector.py` | STATISTICAL_ANOMALY | Median/MAD robust z-scores against a baseline of unexplained windows |
| Anomaly | (window metrics) | `anomaly_detector.py` | STATISTICAL_ANOMALY | Isolation Forest on log-scaled window features, online warm-up or saved model |
| ML window model | `models/features.py` | `ml_detector.py` | any class above | Random forest (or XGBoost/IF) with isotonic calibration; hybrid mode only |

## Site configuration

Three site files sit beside the defaults (see [deployment.md](deployment.md)):

- `configs/assets.yaml`: roles of known hosts (scanner, backup server,
  resolver, update server, proxy, monitoring, server), validated at load.
  Uploads to expected destinations stay out of the exfiltration baselines.
  All other role effects are applied to alerts after detection, so every
  detector keeps seeing all traffic, and classes a policy handled still
  count as explained for the post-rule stages.
- `thresholds.site.yaml`: an overlay merged over `thresholds.yaml` key by
  key. Unknown keys and wrong types are errors.
- the state snapshot (`state.path`).

`scripts/learn_baseline.py` (and `POST /replay/start?learning=true`) runs
the pipeline with a window observer (`evaluation/learning.py`) that records
the metric behind each threshold and writes a suggested overlay plus a
report; it never writes `thresholds.yaml`. `scripts/soak_test.py`
(`evaluation/soak.py`) streams generated site traffic
(`data/site_traffic.py`) for a long run and samples memory, latency, lag
and state size.

## Detection modes

`models.detection_mode` (or `UNISHIELD_DETECTION_MODE`, or `mode=` on a replay):

- `rules` (default): rule detectors + statistical + Isolation Forest.
- `hybrid`: `rules` plus the registered window model for windows no rule
  explained; falls back to `rules` if no model is saved.
- `ml`: the window model alone (for evaluation).

## Models

`models/` holds the window feature vector, labelled dataset builder (runs the
real pipeline and records each window's label and what each stage concluded),
training (split by run so overlapping windows never cross train/calibration/
test), isotonic calibration stored as JSON points, a versioned registry with
SHA-256 integrity checks, and inference. See [model_card.md](model_card.md).

## Timing and latency

Each alert carries `window_closed_at`, `emitted_at` and `stored_at` (wall
clock) besides its traffic-time window. `scripts/benchmark_pipeline.py`
measures throughput and close-to-storage latency; `scripts/replay_stream.py`
replays traffic at a fixed pace and adds the delay until the window closes
and until the API returns the alert ([evaluation.md](evaluation.md)).

Live inputs have no end of stream: a reader that receives nothing yields a
`ClockTick` carrying its estimate of the current traffic time (last record
time plus the wall-clock time since it arrived), and the pipeline closes the
windows that are due. Live runs use `live.allowed_lateness_sec` (default
120 s) instead of `processing.allowed_lateness_sec`, because flow exporters
report a flow only when it ends or hits its active timeout.

## Deployment

`python -m unishield.main` serves the API and dashboard on
`127.0.0.1:8000`, over HTTPS when `tls.certfile` is set, trusting
forwarded headers only from `api.forwarded_allow_ips`. On start the
application checks the schema revision, records `system.start` and starts
housekeeping (retention, expired sessions); on SIGTERM/Ctrl+C it stops a
running replay, records its state and `system.stop`, and closes the
database. `/health` reports degraded components and answers 503 when
storage is unavailable. With `state.enabled`, file replays continue from the
last state snapshot, and a replay stopped by shutdown writes its final snapshot
before the application exits.

The systemd unit (`deploy/systemd`) and the Docker image run as an
unprivileged user with no capabilities and a read-only system; nginx and
Caddy examples (`deploy/`) terminate TLS in front. Placement on the analyst
side of a diode, firewalling, outputs and operations — accounts, HTTPS,
migrations, backups, monitoring — are described in
[deployment.md](deployment.md).
