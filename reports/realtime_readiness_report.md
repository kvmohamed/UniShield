# UniShield — Phase 1 Audit & Real-Time Readiness Report

| | |
|---|---|
| **Date** | 2026-10-14 |
| **Code audited** | commit `1f82e47` **plus** uncommitted working-tree changes to `api/app.py`, `config.py`, `dashboard/index.html`, `processing/pipeline.py`, and untracked `scripts/*`, `reports/*` |
| **Environment** | Windows 10 (19045), Python 3.14.7 (`.venv`), AMD 12-core, 7.4 GB RAM. Docker **not installed** |
| **Method** | Every source file read; full test suite executed; scripted runs on synthetic and locally-written sample files (PCAP, Zeek JSON/TSV, CSV, JSON); API exercised in-process with FastAPI `TestClient`. For the PCAP test only, `scapy==2.6.1` was installed into an isolated scratch folder (the project venv was not modified). No packets were sent; no network access was used by any test. |
| **Supersedes** | The auto-generated version of this file dated 2026-10-05 (several of its statements are no longer true for the current working tree). |

Status vocabulary used throughout:

- **Implemented** — exists, runs, and does what it claims in tests or a scripted run.
- **Partial** — exists and runs, but is incomplete or has a confirmed defect that affects its purpose.
- **Placeholder** — file exists but contains only a docstring/comment.
- **Missing** — required by the target architecture, no file or equivalent exists.
- **Unverified** — exists but could not be executed in this environment.

---

## 0. Executive summary

1. **A working end-to-end path exists, but only for synthetic data.** `POST /replay/demo` → synthetic flows → sliding window → 6 extractors → 6 detectors → dedup → in-memory store → `/alerts` → HTML dashboard. Measured: 920 synthetic flows produced **3 alerts** (PORT_SCAN, HOST_SCAN, DATA_EXFILTRATION). No DDoS or beaconing alert appears in the demo.
2. **Real-file ingestion is weak.** PCAP reading **cannot run** in the current venv (`scapy` not installed) and `/replay/start` rejects `.pcap`. Flow-format JSON through the API parses **0 records**. Zeek's default TSV format parses 0 records. CICIDS2017-style CSV rows fail on timestamp format, and when they parse, units and columns are wrong.
3. **Detectors are connected to the pipeline** (all 6), but several are **functionally broken in the pipeline context** (DDoS false-alarms after quiet periods, port-scan false positives on normal two-way traffic, beaconing blind to intervals ≥ ~5 s, Isolation Forest confidence capped at ~0.03). See §10.
4. **No ML model is trained, saved or loaded.** The only model is an Isolation Forest fitted in memory on the first 10 windows of each run, then discarded. No supervised model, no dataset, no registry, no calibration.
5. **Headline performance claims are not supported by the current code.** Measured throughput is **~706 records/s** (5 runs, σ = 1.4), not "40,000+". 97% of CPU time is the Isolation Forest's two per-window scikit-learn calls; without it, ~30,000 records/s. "Sub-millisecond latency" is the time to append a record to a queue, not detection latency.
6. **No persistence, no auth, no sessionization, no statistical detector, no encrypted-session module, no Streamlit dashboard, no integration/performance tests, no CI.**
7. **Passive-operation constraint holds in code:** no socket/send/HTTP-client/subprocess calls anywhere in `src/`; readers only open local files; the security-flag validator rejects disabling read-only mode. Two adjacent risks: the API has no authentication and `/replay/start` opens any path on disk; the dashboard has a stored-XSS sink.
8. **Tests: 96 collected, 95 pass, 1 fails** (`test_pipeline_metrics` expects 4 detectors; the uncommitted change registers 6). There are no tests for any reader or replay endpoint.
9. **Existing reports are not reliable evidence.** `realtime_verdict.md` was produced by a harness that re-implements the pipeline loop with 4 of 6 detectors, contains hard-coded pass marks and limitation text, and uses non-reproducible seeds.

**Honest classification today: _Accelerated replay (offline)_.** It is not near-real-time replay (no end-of-stream flush, record-driven window emission, no paced replay through the real pipeline, no end-to-end timestamps stored with alerts). It is not live passive monitoring (no live input).

---

## 1. Claims vs. measured evidence

| Claim (source) | Measured / found | Verdict |
|---|---|---|
| "7 detectors" / "7+ threat classes" (README) | **6** detector classes. Threat-class enum has 13 values; **11** can be emitted; `DDOS_PROTOCOL` and `ENCRYPTED_SESSION_ANOMALY` are never produced. | Overstated |
| "85+ features" (README per-module counts) | **84** named feature outputs (volume 24, scan 12, beaconing 11, exfiltration 12, DNS 14, statistical 11); 4 of them are IP strings, so **80 numeric**. The 11 statistical features are computed every window but **no detector reads them**. | Overstated |
| "40,000+ records/sec" (README) | Current default pipeline, 9,050-record mixed synthetic scenario, 5 runs: **mean 706.5 rec/s, median 706.6, σ 1.4, min 704.5, max 708.3**. Same data without `AnomalyDetector`: ~30,000 rec/s. The 34k figure in `benchmark_report.json` predates adding the Isolation Forest to the default pipeline. | **Not supported** (and below the 1,000 rec/s target) |
| "P50 < 0.01 ms, P95 < 0.2 ms, P99 < 0.3 ms" (README) | The metric is wall time per record for `window.add()` plus, occasionally, a whole window's analysis. Measured now: per-record **P50 0.002 ms, P95 13.7 ms, P99 13.9 ms**. True per-window analysis time: **P50 13.6 ms, P95 14.1 ms, max 88–102 ms**. Event-to-alert time in traffic terms is bounded below by the window/slide (≥ seconds), and is not measured anywhere. | Mislabelled metric |
| "15+ API endpoints" (README table) | **13 routes** (11 API + `/` and `/dashboard`), plus auto-generated `/docs`, `/redoc`, `/openapi.json`. | Overstated (counts docs) |
| "100+ tests" (README) | **96** tests collected, **95 pass, 1 fails**. `tests/integration/` and `tests/performance/` contain only `__init__.py`. | Overstated |
| "Isolation Forest with online learning" (README) | Fitted **once**, after the first 10 windows of a run, on whatever those windows contain (attacks included); never refitted; never saved; discarded at end of run. | False |
| "Real-time dashboard" (README) | HTML page polls `/alerts`, `/alerts/summary`, `/replay/status`, `/health`, `/metrics` every 4 s (uncommitted change). No push (WebSocket/SSE). | Polling, near-real-time display only |
| "POST /replay/start — Replay a PCAP/JSON/CSV file" (README) | `.pcap` → `"Unsupported format: .pcap"`. Flow `.json` → 0 records (wrong reader chosen). `.csv` works. | Partially false |
| "Docker deployment" (README) | Not executable here (Docker absent). Static review: compose `dashboard` service runs non-existent `streamlit_app.py`; no `.dockerignore`, so `.venv/` and `.git/` are copied into the image. | Unverified, known defects |
| `pytest --cov` (README, Makefile) | `pytest-cov` is not installed in the venv; command fails. | Broken |
| Commit `c2a054e` "storage layer with migrations support and ML model package" | `storage/` and `models/` contain only `__init__.py`; `migrations/` is empty. | False |
| Commit `1f82e47` "utility scripts for dataset prep, model training, and PCAP replay" | All four scripts are one-line placeholders. | False |
| Commit `da38d76` "unit, integration, and performance tests" | Integration and performance test folders are empty. | False |

---

## 2. Module status: required structure vs. current repository

### 2.1 Top level, configuration, data

| Required item | Current equivalent | Status | Evidence / notes |
|---|---|---|---|
| `README.md` | present | Partial | Overstates capability (§1). Quick-start works for synthetic demo. |
| `LICENSE` | present | Implemented | MIT. |
| `.env.example` | present | Partial | `AppSettings` (config.py:129) is defined but never instantiated; none of the `UNISHIELD_*` variables except `UNISHIELD_CONFIG_DIR` are read. |
| `.gitignore` | present | Implemented | No `.dockerignore` exists. |
| `docker-compose.yml` | present | Partial | `dashboard` service command points at a missing file → restart loop. Obsolete `version:` key. |
| `Dockerfile` | present | Unverified | Python 3.11 base vs local 3.14 venv (environment drift). Copies whole tree. |
| `Makefile` | present | Partial | `dashboard` target → missing file; `test-cov` needs pytest-cov; `clean` uses POSIX `find` (fails in cmd.exe). |
| `requirements.txt` | present | Partial | 15 declared packages never imported (pandas, pyarrow, scipy, xgboost, shap, streamlit, plotly, sqlalchemy, aiosqlite, alembic, psycopg2-binary, structlog, rich, python-dotenv, click). `psutil`, `matplotlib` used by scripts but undeclared. The venv does **not** match it (scapy, pandas, sqlalchemy, xgboost, streamlit, plotly, pytest-cov … not installed). |
| `pyproject.toml` | present | Implemented | Editable install verified. |
| `configs/config.yaml` | present | Partial | Read, but most keys are never used: `max_queue_size`, `max_alert_batch`, `max_file_size_mb`, `supported_formats`, `anonymize_ips`, `ip_hash_salt`, `database.*`, `models.*`, `paths.*`. Only `processing.window_size_sec`, `slide_interval_sec`, `max_records_in_memory` and `security.*` have effect. |
| `configs/thresholds.yaml` | present | Partial | Read by detectors. `encrypted.*` unused (no module); several keys unused (`destination_rarity`, `burst_size_bytes`, `baseline_deviation_sigma`, `min_interval_sec`, `max_interval_sec`, `mad_threshold`, `ngram_anomaly_score`, …). |
| `configs/logging.yaml` | present | Partial | Applied only via `python -m unishield.main`; launching with `uvicorn …` (README, Dockerfile) skips it. |
| `data/raw`, `processed`, `samples` | present (empty) | Missing content | No sample PCAP/Zeek/CSV file ships with the repo. |
| `data/test_scenarios/` | generated on demand | Partial | Created by `scripts/test_traffic_generator.py`; not present now. |
| `models/saved`, `models/metadata` | present (empty) | Missing content | No model artifact exists. |
| `notebooks/` | empty | Missing content | — |
| `.github/workflows` (CI) | — | Missing | — |

### 2.2 Scripts

| Required | Current | Status | Notes |
|---|---|---|---|
| `scripts/prepare_dataset.py` | present | Placeholder | `# Implemented in Phase 5` |
| `scripts/train_models.py` | present | Placeholder | `# Implemented in Phase 5` |
| `scripts/replay_pcap.py` | present | Placeholder | `# Implemented in Phase 2` |
| `scripts/replay_stream.py` | present (untracked) | Partial | Has speed-factor pacing and stage timestamps, but **re-implements the pipeline loop** with 4 extractors/4 detectors instead of calling `Pipeline`; same no-flush bug; seeds from `hash()` (randomised per process). |
| `scripts/benchmark_pipeline.py` | present | Placeholder | A working (flawed) benchmark exists at `src/unishield/scripts/benchmark.py`: ablation compares a 6-detector baseline against 3-detector subsets (confounded), no ground truth. |
| `scripts/run_demo.py` | present (untracked) | Partial | Criteria 8 and 10 hard-coded `pass: True`; network check is a string literal; static scan uses Windows `findstr` and passes silently on error; "Limitations" and dashboard text are hard-coded and already inaccurate. |
| `scripts/verify_passive_mode.py` | — | Missing | Logic partly embedded in `run_demo.verify_passive_operation()`. |
| `scripts/generate_charts.py` | present (untracked) | Implemented | Needs undeclared `matplotlib`. |
| `scripts/test_traffic_generator.py` | present (untracked) | Partial | Labelled scenarios with metadata; seeds non-reproducible; labels are per-scenario, not per-flow; edited after the reports were generated. |
| `scripts/run_demo.bat` | present (untracked) | Implemented | Windows only; `run_demo.sh` missing. |

### 2.3 Source package `src/unishield/`

| Required module | Current equivalent | Status | Evidence / notes |
|---|---|---|---|
| `main.py` | `main.py` | Implemented | Starts uvicorn with config host/port; `reload=debug` (True by default). |
| `config.py` | `config.py` | Partial | YAML + security validator work; env settings unused; configs located via `__file__` (works only for editable install). |
| `logging_config.py` | `logging_config.py` | Partial | See logging.yaml note. |
| `schemas/flow.py` | `schemas/flow.py` | Partial | Field `source` (spec: `source_type`); IPs are unvalidated strings; epoch input becomes a **naive** datetime while readers emit aware ones; no `event_id` for flows/sessions beyond random UUID. |
| `schemas/alert.py` | `schemas/alert.py` | Partial | Validation, confidence clamp and MITRE format check work. `flow_id`, `source_ip_hash`, `destination_ip_hash` are **never populated** by any detector. `timestamp` is wall-clock `utcnow` (deprecated). |
| `schemas/metrics.py` | `schemas/metrics.py` | Partial | `cpu_percent`, `memory_mb`, `queue_size`, `dropped_records`, `malformed_records` are always 0 (verified via `/metrics`). |
| `ingest/base.py` | `ingest/base.py` | Implemented | — |
| `ingest/pcap_reader.py` | `ingest/pcap_reader.py` | Partial / not runnable here | `ImportError` in current venv. With scapy: 6 packets → 6 records (one record **per packet**, `packet_count=1`, `duration=0`); DNS name/type extracted correctly; direction always `unknown`. TLS version is read from the **record-layer header**, which modern TLS 1.2/1.3 ClientHellos set to `0x0301`, so it reports `TLSv1.0` for modern clients — a planned "old TLS version" rule would fire on normal traffic. |
| `ingest/zeek_reader.py` | `ingest/zeek_reader.py` | Partial | conn.log JSON: 20/20 records, counts correct. Zeek default **TSV: 0 records** (2 errors). dns.log `rcode_name: NXDOMAIN` is dropped. ssl.log `version` kept as `TLSv12` (Zeek naming) vs `TLSv1.2` elsewhere. Each log line becomes a separate flow (dns/ssl lines with `byte_count=0`, `packet_count=1`), no join on `uid`. Missing IPs filled with `0.0.0.0` (violates "never fabricate"). Loads the **entire file into memory** before yielding. |
| `ingest/flow_reader.py` | `ingest/flow_reader.py` | Partial | Project's own CSV/JSON: 50/50 records, but `direction` (and DNS type, TLS fields, label) are **discarded** — all become `unknown`. CICIDS2017-style CSV: timestamps without seconds → **0/2 records**; with seconds: `Flow Duration` (µs) read as seconds (5,000,000 s), packet/byte columns unmapped (`packet_count=1`, `byte_count=0`), `Label` dropped. JSON mode loads whole file. |
| `processing/normalization.py` | inside readers | Missing | No home-network/CIDR config, so direction is never inferred; no IP anonymisation applied (`to_anonymised()` is never called). |
| `processing/sessionizer.py` | — | **Missing** | Packet-level PCAP records go straight into windows. This is the root cause of the two-way-traffic port-scan false positive. |
| `processing/window_manager.py` | `processing/window.py` | Partial | Global sliding window works. Emission is **record-driven** (a window only closes when a later record arrives), **no end-of-stream flush**, per-source windows are filled but never read (retained **all 60,000 records** of a 60k-record test while the global window held 13), "LRU" eviction is FIFO. |
| `processing/pipeline.py` | `processing/pipeline.py` | Partial | All 6 extractors/detectors wired; dedup wired. Defects: no flush; `latencies_ms`, `features_history`, `alerts` grow unbounded; `_lock` unused; Isolation Forest dominates runtime. |
| `features/base.py` | `features/base.py` | Implemented | — |
| `features/traffic_features.py` + `ddos_features.py` | `features/volume.py` | Partial | Rates divided by first-to-last timestamp span clamped to 1 ms, not the window length → one 20-packet flow after 30 s silence = "20,000 pps". |
| `features/scan_features.py` | `features/scan.py` | Partial | Counts reply traffic's ephemeral ports as scan fan-out; host-scan values taken from the top *port* scanner. |
| `features/beacon_features.py` | `features/beaconing.py` | Partial | Needs ≥ 5 connections per pair inside one 10 s window → blind to intervals ≥ ~5 s. "FFT periodicity" is actually median-clustering. Destination rarity not implemented. |
| `features/exfil_features.py` | `features/exfiltration.py` | Partial | Direction is always unknown, so it falls back to a port-number heuristic. No per-source baseline, no destination rarity. |
| `features/dns_features.py` | `features/dns.py` | Partial | Entropy, length, depth, TXT ratio work. NXDOMAIN read from record type (never populated). No n-gram features. |
| `features/encrypted_features.py` | — | Missing | — |
| (extra) | `features/statistical.py` | Partial | Rolling z-scores computed; baseline absorbs attack windows; **output consumed by no detector**. |
| `detectors/base.py` | `detectors/base.py` | Implemented | — |
| `detectors/rule_detector.py` | — | Missing (as generic) | Rules are embedded in each detector. |
| `detectors/statistical_detector.py` | — | **Missing** | Statistical layer has no detector. |
| `detectors/ml_detector.py` | `detectors/anomaly_detector.py` | Partial | Isolation Forest only. Confidence = `−decision_function/3.0` → measured max **0.035**, always LOW. Fitted once on first 10 windows; 91% of windows flagged on benign traffic with one rate change. `save_model`/`load_model` exist but are never called. ~14 ms per window. |
| `detectors/ddos_detector.py` | same | Partial | Logic runs; with the project's own synthetic DDoS generator it **never fires** (peak ~290 pps vs 10,000 threshold); fires falsely after traffic gaps (via volume bug). |
| `detectors/scan_detector.py` | same | Partial | Fires on synthetic scans; false positives on normal bidirectional traffic. |
| `detectors/beacon_detector.py` | `beaconing_detector.py` | Partial | 2 s beacons detected (13 alerts); 30 s and 60 s beacons: 0. |
| `detectors/exfil_detector.py` | `exfiltration_detector.py` | Partial | Fires on synthetic exfil; "unusual port" rule also fires on port scans (cross-class FP). |
| `detectors/dns_detector.py` | same | Partial | Tunnelling score works on synthetic DNS; DGA NXDOMAIN signal dead. |
| `detectors/encrypted_detector.py` | — | Missing | — |
| `models/train.py`, `predict.py`, `calibration.py`, `registry.py` | `models/__init__.py` only | **Missing** | — |
| `correlation/deduplication.py` | `correlation/correlator.py::deduplicate` | Partial | Uses wall-clock alert time → collapses a whole replay to ~1 alert per key (3 episodes 20 min apart → 1 alert). Key ignores destination, so all DDoS/exfil alerts (no source IP) share one key. |
| `correlation/severity.py` | per-detector code; `correlator.correlate()` | Partial | Incident grouping/escalation exists but is **never called** by the pipeline or API. |
| `correlation/mitre_mapping.py` | hard-coded per detector | Partial | IDs format-validated; no central mapping. |
| `storage/database.py`, `repositories.py`, `migrations/` | `storage/__init__.py` only | **Missing** | Alerts live in a Python list; lost on restart. |
| `api/app.py` | `api/app.py` | Partial | See §6. |
| `api/routes_alerts.py`, `routes_metrics.py`, `routes_replay.py` | all inside `app.py` | Missing (as split) | — |
| `dashboard/streamlit_app.py` | — | Missing | Referenced by Makefile, compose, docs. |
| (extra) | `dashboard/index.html` | Partial | Overview tiles, severity bars, threat list, pipeline-performance panel, alert table, status panel with passive flags, 4 s polling. Missing: timeline, alert-detail/evidence view, traffic analytics, benchmark page, the exact required notice text. "Clear" only clears the browser view (next poll refills it). Stored XSS via `innerHTML`. Loads Google Fonts (falls back offline). |
| (extra) | `data/sample_generator.py` | Partial | Synthetic scenarios; DDoS too weak for thresholds; benign TCP always `SYN,ACK` (cannot trip SYN-ratio rules); unseeded. |

### 2.4 Tests

| File | Tests | Covers | Gaps / notes |
|---|---|---|---|
| `test_alert_schema.py` | 17 | Alert validation, confidence bounds, MITRE format, IDs, JSON round-trip | — |
| `test_flow_schema.py` | 18 | Flow fields, timestamp parsing, anonymisation helper | Naive-datetime behaviour not asserted |
| `test_config.py` | 11 | YAML loading, security validator | — |
| `test_api_health.py` | 10 | `/health`, `/metrics`, `/alerts` basic, `/benchmark/latest` | No `/replay/*` tests |
| `test_pipeline.py` | 25 | Window, volume/scan/beacon/exfil features, 4 detectors, pipeline smoke | **1 failing.** Detector tests feed a whole scenario as one window and lower DDoS thresholds 100×; they don't test default-config behaviour in the pipeline. |
| `test_advanced.py` | 15 | Statistical, anomaly, DNS, correlator | Anomaly "detection" test asserts only `windows_analysed >= 11`. |
| **Readers (PCAP/Zeek/Flow)** | **0** | — | No tests at all |
| `tests/integration/` | 0 | — | Empty |
| `tests/performance/` | 0 | — | Empty |
| Security tests | 0 | — | No malformed-input, path-traversal, auth, oversize tests |

Run: `.venv/Scripts/python.exe -m pytest tests/ -q` → **95 passed, 1 failed, 216 warnings** (mostly `datetime.utcnow()` deprecation on Python 3.14).

### 2.5 Documentation and reports

| Item | Status | Notes |
|---|---|---|
| `docs/architecture.md` | Partial | Describes calibration, SQLite/PostgreSQL store, Streamlit + Plotly, XGBoost — none exist. |
| `docs/threat_model.md` | Implemented | Reasonable; not re-verified line by line. |
| `docs/dataset.md` | Partial | Recommends CICIDS2017 / CTU-13 / UNSW-NB15; none downloaded or supported by readers. |
| `docs/model_card.md` | Placeholder | "to be trained in Phase 5". |
| `docs/evaluation.md` | Placeholder | "To be populated during Phase 5 and Phase 9". |
| `docs/limitations.md` | Implemented | Honest and useful. |
| `docs/demo_guide.md` | Partial | Points the dashboard at `localhost:8501` (Streamlit); real dashboard is `127.0.0.1:8000/dashboard`. |
| `reports/benchmark_report.json` | Stale | 2026-10-01, before the Isolation Forest joined the default pipeline. |
| `reports/realtime_verdict.md`, `realtime_demo_report.json`, `realtime_raw_results.json`, `figures/*` | Not reliable | See §8.3. |

---

## 3. Ingestion — functional status (answers checklist item 6)

| Input | Works? | Evidence |
|---|---|---|
| **PCAP** | **No (current venv)** / Partial (with scapy) | `ImportError: Scapy is required…`. With scapy in an isolated folder: a 6-packet PCAP → 6 per-packet records; DNS fields correct; TLS ClientHello with record version `0x0301` → `TLSv1.0`; 0.6 s capture → **0 windows, 0 alerts** (no flush). Not reachable from the API. |
| **Zeek JSON conn.log** | Yes | 20/20 records, bytes/packets summed correctly, direction `unknown`. Via API: works only if the file is `.json`/`.jsonl` (Zeek's default name `conn.log` → "Unsupported format"). |
| **Zeek dns.log / ssl.log JSON** | Partial | Parsed as stand-alone flows; NXDOMAIN dropped; TLS version naming inconsistent. |
| **Zeek TSV (default format)** | **No** | 0 records, 2 errors. |
| **CSV (project format)** | Yes (lossy) | 50/50 records; direction discarded. API path works. |
| **JSON flows (project format)** | Reader yes / **API no** | Direct `FlowReader`: 50/50. `POST /replay/start` picks `ZeekReader` → **0 records**, status "completed". |
| **Public-dataset CSV (CICIDS2017-style)** | **No** | 0/2 rows (timestamp format); when forced, duration unit wrong by 10⁶, packet/byte counts lost, labels dropped. |
| **Live input** | Missing | No live capture or tail-follow of Zeek logs. |

## 4. Are detectors connected to the pipeline? (item 7)

Yes. With the current working tree, `Pipeline()` registers extractors `volume, scan, beaconing, exfiltration, dns, statistical` and detectors `ddos, scan, beaconing, exfiltration, dns, anomaly`, and runs `AlertCorrelator.deduplicate()` on each window's alerts. Caveats:

- The statistical extractor's 11 features are not read by any detector.
- `AlertCorrelator.correlate()` (incident grouping, escalation) is never called.
- Windows close only when a later record arrives, and the final partial window is never processed.
- `replay_stream.py` / `run_demo.py` (the source of the realtime reports) do **not** use this pipeline.

## 5. ML models (item 9)

| Question | Answer |
|---|---|
| Any trained model artifact on disk? | **No** (`models/saved/` empty). |
| Supervised model (RF/XGBoost)? | **No.** `xgboost` not installed; no training code. |
| Isolation Forest | Fitted in-process on the first 10 windows of each run; never refitted, saved or reloaded; confidence mis-scaled (max 0.035); dominates runtime (~14 ms/window, 97% of CPU). |
| Datasets | None present; readers cannot ingest the recommended public datasets correctly. |
| Calibration, registry, versioning, preprocessing persistence | Missing. |

## 6. Do the API and dashboard receive real alerts? (item 8)

Yes, for pipeline runs started through the API. Measured via `TestClient`: `POST /replay/demo` (920 flows, 2.55 s) → `/alerts` returned the same 3 alerts; `/metrics` showed 920 records, 3 alerts, P95 13.5 ms. The dashboard polls these endpoints every 4 s. Limitations:

- Store is an in-memory list: lost on restart; grows without bound; no pagination beyond offset/limit.
- `/health` reports `models_loaded=1` whenever a pipeline object exists, even if the forest is unfitted; `database_connected` is always false.
- `/benchmark/latest` never returns data (`_benchmark` is never set).
- `/replay/demo` is `async` but blocks on `thread.join(timeout=30)` → the server cannot answer other requests during a demo.
- `/replay/stop` reports "stopped", then the worker overwrites it with "completed".
- No authentication on any endpoint; `/replay/start` accepted a CSV outside the project directory (path not restricted); CORS `*`.
- Dashboard renders alert fields with `innerHTML` (stored XSS if a crafted Zeek/CSV file supplies a non-IP string as an IP).

## 7. Passive-operation verification

| Check | Result | Evidence |
|---|---|---|
| Packet-sending / network-client primitives in `src/` | **None found** | grep for `socket.`, `send(`, `sendp(`, `sr(`, `sr1(`, `requests.`, `urllib`, `httpx.`, `subprocess`, `os.system`: 0 matches. |
| Readers only read local files | Yes | All readers open files read-only; PCAP uses scapy's offline reader. |
| Security flags cannot be disabled | Yes | `SecurityConfig(read_only_mode=False)` raises a validation error (tested). |
| Payload decryption | None | Only plaintext header/metadata fields are read. |
| Dashboard outbound requests | Google Fonts CSS only | Cosmetic; page works offline with fallback fonts. |
| Runtime network monitoring during tests | **Not performed by the project** | The "no outbound connections" line in existing reports is a hard-coded string. |
| Admin endpoint protection | **Missing** | Unauthenticated replay control and arbitrary-path file reads. |

---

## 8. Performance — measured on this machine

### 8.1 Throughput and latency (current default pipeline, 5 runs, 9,050 records each, seeds 1000–1004)

| Metric | Mean | Median | σ | Min | Max |
|---|---|---|---|---|---|
| Throughput (records/s) | 706.5 | 706.6 | 1.4 | 704.5 | 708.3 |
| Per-record wall time P50 (ms) | 0.002 | 0.002 | 0.000 | 0.002 | 0.003 |
| Per-record wall time P95 (ms) | 13.66 | 13.67 | 0.02 | 13.64 | 13.68 |
| Per-record wall time P99 (ms) | 13.92 | 13.92 | 0.04 | 13.87 | 13.98 |
| **Per-window analysis P50 (ms)** | 13.64 | 13.65 | 0.02 | 13.61 | 13.66 |
| **Per-window analysis P95 (ms)** | 14.15 | 14.16 | 0.04 | 14.09 | 14.18 |
| Per-window analysis max (ms) | 91.2 | 88.4 | 5.9 | 87.9 | 101.6 |
| Alerts per run (after dedup) | 5.4 | 6 | 0.9 | 4 | 6 |

Cost breakdown of one run (934 windows, 13.66 s): `anomaly_detector` 13.29 s (14.2 ms/window); all other extractors and detectors combined < 0.4 s. Without the anomaly detector: ~30,000 records/s.

Interpretation:

- Throughput depends on traffic density, because cost is per window, not per record. Sparse traffic (few records per 5 s slide) gives low records/s.
- Per-window analysis (P95 ≈ 14 ms) is the honest "latency after the window closes". It meets the < 2 s target **if** windows close on time, which they don't when traffic pauses (record-driven emission).

### 8.2 Memory retention (60,000-record benign stream)

| Structure | Retained after run |
|---|---|
| `Pipeline._latencies` | 60,000 floats (unbounded) |
| Per-source windows | 771 windows holding **60,000** flow objects (never read) |
| Global window | 13 records |

A long-running stream will therefore grow linearly in memory.

### 8.3 Reliability of existing reports

- `realtime_verdict.md` is generated by `replay_stream.py`, which does not use `Pipeline` and runs 4 of 6 detectors.
- Acceptance criteria 8 and 10 are hard-coded `pass: True`. Criteria 2 and 3 read flags that the validator forces to `True`. Criterion 6 uses per-record append time as "detection latency".
- "Limitations" and the dashboard description are hard-coded strings. When generated (2026-10-12 22:34), they already contradicted the code changed at 16:46 the same day.
- Seeds come from `hash(str)`, which Python randomises per process, so the 25 runs cannot be reproduced. Start times are `datetime.now()`.
- Precision mixes units (true positives counted per class, false positives per alert). There is no per-flow ground truth.
- `test_traffic_generator.py` was modified at 2026-10-13 00:08, after the reports.

---

## 9. Real-time classification

| Level | Met? | Why |
|---|---|---|
| Offline batch only | Exceeded | Records are processed incrementally through windows. |
| **Accelerated replay** | **Yes — current level** | Files/synthetic streams are replayed as fast as possible through incremental windows. |
| Near-real-time replay | No | Needs: end-of-stream flush and clock-driven window closing; paced replay through the **real** pipeline; per-alert event/ingest/window/detection/storage timestamps; measured event-to-alert latency. |
| Live passive monitoring | No | No live input (no interface capture, no Zeek log tailing). |
| Real-time passive detection | No | — |

---

## 10. Confirmed functional defects (reproduced by script)

| ID | Defect | Location | Reproduction result |
|---|---|---|---|
| D1 | No end-of-stream flush | `processing/pipeline.py:229` | 8 s, 20,000-record SYN flood → 0 windows, 0 alerts. With a manual flush the current DDoS scenario goes from 3/5 to 5/5 seeds detected. |
| D2 | Rate denominator is timestamp span clamped to 1 ms | `features/volume.py:85` (same pattern in `scan.py`, `statistical.py`) | One 20-packet flow after 30 s silence → `DDOS_VOLUMETRIC` HIGH at "20,000 pps". |
| D3 | Dedup on wall-clock time; key ignores destination | `correlation/correlator.py:54,72` | 3 exfil episodes 20 min apart → 1 alert (39 without dedup). |
| D4 | Beaconing needs ≥ 5 connections inside one 10 s window | `features/beaconing.py:67`, window config | 2 s interval → 13 alerts; 30 s → 0; 60 s → 0. |
| D5 | Isolation Forest confidence mis-scaled; fit-once on unvetted windows | `detectors/anomaly_detector.py:157-174` | Max confidence 0.035, all LOW; 91% of benign windows flagged after one rate change. |
| D6 | Isolation Forest per-window cost | `detectors/anomaly_detector.py:167-168` | 14.2 ms/window, 97% of runtime; throughput 706 rec/s. |
| D7 | Reply traffic counted as scan fan-out; host-scan misattributed | `features/scan.py:109` | 40 normal HTTPS connections → PORT_SCAN + RECONNAISSANCE against the web server (+2 C2_BEACONING). |
| D8 | API picks Zeek reader for every `.json` | `api/app.py:305-314` | Flow JSON → 0 records, 50 errors, status "completed". |
| D9 | `/replay/start` rejects PCAP; scapy not installed | `api/app.py:317`, venv | "Unsupported format: .pcap"; `ImportError`. |
| D10 | Synthetic DDoS generator cannot reach thresholds | `data/sample_generator.py:132` | Peak ~290 pps and 1,451 SYN vs 10,000 / 5,000 thresholds, even at API maximum. |
| D11 | Per-source windows retain everything | `processing/window.py:213-231`, `pipeline.py:153` | 60,000 of 60,000 records retained. |
| D12 | Unbounded latency/feature/alert lists | `processing/pipeline.py:253,278-279` | 60,000 latency entries after 60k records. |
| D13 | Readers discard direction/labels; units/formats wrong for public CSV | `ingest/flow_reader.py` | See §3. |
| D14 | Zeek TSV unsupported; rcode dropped | `ingest/zeek_reader.py` | 0 records; NXDOMAIN lost. |
| D15 | TLS version from record layer | `ingest/pcap_reader.py:222-245` | Modern ClientHello → `TLSv1.0`. |
| D16 | `/replay/demo` blocks event loop | `api/app.py:375` | Server unresponsive for the duration of the demo (≈2.5 s for 920 flows; up to 30 s). |
| D17 | Stored XSS in alert table | `dashboard/index.html:1222` | Unescaped `innerHTML` interpolation of alert fields. |
| D18 | Failing unit test | `tests/unit/test_pipeline.py:464` | Expects 4 detectors, pipeline has 6. |

---

## 11. Prioritized repair plan

Each phase ends with an **exit test** that must pass before the next phase starts. Effort: S ≈ ½ day, M ≈ 1–2 days, L ≈ 3+ days.

### Phase 2 — Baseline, environment, structure (S–M)
1. Commit the current working tree to a branch (e.g. `audit-baseline`) so all repairs are reviewable diffs.
2. Create a Python 3.11 or 3.12 venv matching the Dockerfile; split `requirements.txt` into core / ml / dev; remove unused packages; declare `psutil`, `matplotlib`, `scapy`, `pytest-cov`.
3. Fix the failing test (D18); move `datetime.utcnow()` / `utcfromtimestamp()` to timezone-aware UTC everywhere.
4. Wire `logging.yaml` into app startup; make config path resolution work outside editable installs; either use or delete `AppSettings`/env vars.
5. Add `.dockerignore`; remove or fix the compose `dashboard` service and Makefile target.
6. Add GitHub Actions running `pytest` on push.

**Exit test:** clean venv from `requirements*.txt` → `pytest` 100% green; `uvicorn unishield.api.app:app` serves `/health`.

### Phase 3 — Ingestion, normalisation, sessionization (M–L)
1. `processing/normalization.py`: home-network CIDRs in config → direction inference; IP validation (`ipaddress`); optional salted hashing applied centrally; `source_type` naming.
2. `processing/sessionizer.py`: aggregate packet records into bidirectional flows (5-tuple + idle/active timeouts) with per-direction bytes/packets; emit on timeout or FIN/RST (fixes the root of D7).
3. Readers: Zeek TSV support and `uid` join of conn/dns/ssl; keep `rcode`; stream JSON line by line; flow reader keeps direction/DNS/TLS fields/labels; dataset profiles for CICIDS2017 (column names, µs durations, timestamp formats) (D13, D14). PCAP TLS version from handshake/`supported_versions` (D15).
4. API: reader selection by content sniffing; accept `.pcap/.pcapng` and Zeek `.log`; restrict `file_path` to an allow-listed data directory (D8, D9).
5. Ship small fixtures in `tests/fixtures/` (tiny PCAP, Zeek JSON + TSV, CSV, JSON).

**Exit test:** reader unit tests per format + integration test "fixture PCAP → sessionized flows → expected counts", all passing.

### Phase 4 — Windowing + DDoS and scan (M)
1. Window: end-of-stream flush; clock-driven closing (watermark: close a window when event time passes its end, or after an idle timeout); drop or actually use per-source windows; bounded metric buffers (D1, D11, D12).
2. Volume/scan features divide by window length (D2); scan features use sessionized flows and count only client-initiated connections; separate top host-scanner (D7).
3. Synthetic generator: DDoS scenario that is genuinely volumetric, seeded RNG, **per-flow labels** (D10).

**Exit test:** labelled DDoS and scan scenarios detected in ≥ 5/5 seeded runs; benign scenario with traffic gaps and bidirectional HTTPS raises 0 DDoS/scan alerts.

### Phase 5 — Beaconing and exfiltration (M)
1. Beaconing: per-pair long-horizon state (rolling connection timestamps per src→dst over e.g. 30–60 min, bounded), so intervals of seconds to minutes are measurable; destination rarity (D4).
2. Exfiltration: use real direction; per-source rolling baseline; destination rarity; remove port-rarity-only cross-firing on scans.
3. Dedup on window/event time with destination in key (D3).

**Exit test:** 30 s and 60 s beacons with 5% jitter detected; three separate exfil episodes → three alerts; scan scenario raises no exfil alert.

### Phase 6 — Dataset preparation and baseline models (L)
1. `scripts/prepare_dataset.py`: public dataset subset (decision needed, §12) → normalised, sessionized, windowed feature table with dataset version metadata.
2. `models/train.py`, `registry.py`: seeded, session/time-aware split; Random Forest, XGBoost, Isolation Forest; saved with preprocessing and version metadata.
3. Fix Isolation Forest scoring (one `score_samples` call, proper confidence mapping, fit on vetted baseline, persisted) (D5, D6).

**Exit test:** `train_models.py` produces versioned artifacts and a metrics JSON (precision/recall/F1/PR-AUC/FPR/confusion matrix) on a held-out split.

### Phase 7 — Hybrid detection, calibration, correlation (M)
`statistical_detector.py` (robust z/MAD using the existing features), `ml_detector.py` inference from the registry, calibration (Platt/isotonic on validation), central severity and MITRE mapping, incident correlation actually called.

**Exit test:** hybrid vs rule-only vs ML-only comparison table produced from one command.

### Phase 8 — Persistence and API (M)
SQLAlchemy store (SQLite default, PostgreSQL by URL) with repositories; alerts carry `flow_id` and stage timestamps; split routers; API-key auth on replay/admin endpoints; non-blocking demo endpoint; pagination; populated `/metrics` (CPU, RSS, queue, drops) and `/benchmark/latest` (D16).

**Exit test:** restart server → alerts still served; replay endpoints reject missing key; integration test "replay → DB → API".

### Phase 9 — Dashboard (M)
Escape all rendered fields (D17); add timeline, alert-detail/evidence view, traffic analytics, benchmark page, the required notice text; bundle fonts locally for offline use; real server-side clear.

**Exit test:** offline browser run of the demo shows alerts, details and benchmark page; XSS fixture renders as text.

### Phase 10 — Tests, Docker, benchmarking, real-time verification, docs (M–L)
Integration, security and performance tests; Docker build verified; `benchmark_pipeline.py` and `verify_passive_mode.py` that call the real pipeline with fixed seeds, five runs, mean/median/σ/min/max; paced replay with end-to-end timestamps; regenerate all reports from measurements only; rewrite README/docs to match.

**Exit test:** the acceptance criteria in the project brief, each backed by a generated artifact rather than a literal.

### First end-to-end path to restore (before any new feature)
`fixture PCAP / Zeek JSON / CSV` → normalisation (direction, validation) → sessionizer → window with flush → volume + scan features → DDoS + scan detectors → dedup on event time → in-memory store (DB arrives in Phase 8) → `/alerts` → dashboard. This is Phases 2–4 above.

---

## 12. Decisions needed before Phase 2

| # | Decision | Options | Recommendation |
|---|---|---|---|
| 1 | Dashboard technology | (a) keep the FastAPI-served HTML dashboard and extend it; (b) Streamlit as the brief suggests; (c) both | **(a)** — already wired, single process, works offline; Streamlit adds a second service and dependency without new capability. |
| 2 | Database | SQLite only; SQLite + PostgreSQL via URL | **SQLite default, PostgreSQL by connection URL** (same SQLAlchemy code). |
| 3 | PCAP processing | scapy + own sessionizer; PyShark/TShark (needs Wireshark install); Zeek (Linux/WSL/Docker) | **scapy + sessionizer for demo-sized PCAPs; Zeek JSON for large datasets** (offline, no extra installs for the demo). |
| 4 | Public dataset for supervised baselines | CICIDS2017 (DDoS, PortScan; PCAP + labelled CSV); CTU-13 (botnet C2); UNSW-NB15 | **CICIDS2017 subset (one or two days) + CTU-13 scenario for beaconing**, sized for 7.4 GB RAM. |
| 5 | Python version | stay on 3.14; move to 3.11/3.12 | **3.11 or 3.12**, matching Docker and the brief; several required packages are not installed in the 3.14 venv. |
| 6 | Uncommitted work | commit as baseline; discard; keep uncommitted | **Commit to a baseline branch first.** |

---

## 13. Repair log

### Phase 2 — Baseline, environment, structure (2026-10-14) — exit test passed

Baseline committed as `ec4663e` on branch `audit-baseline`; Phase 2 is the next commit on that branch.

| Item | Change | Evidence |
|---|---|---|
| Python version | Python 3.12.10 installed per-user; new `.venv` on 3.12. Old 3.14 venv kept at `.venv-py314-old` (git-ignored). `requires-python >=3.12` (numpy 2.5 / scipy 1.18 need it). | `py list` |
| Dependencies | `pyproject.toml` is the source of truth: runtime deps are only what `src/` imports (+ scapy, psutil); extras `dev`, `reports`. `requirements.txt` / `requirements-dev.txt` are generated exact pins. Removed 15 unused packages and `pydantic-settings`. Phase 6 (ML) and Phase 8 (DB) packages will be added when used. | clean venv `pip check`: no broken requirements |
| D18 failing test | Asserts the exact default detector set and that the metric matches it. | 115/115 pass |
| Timezones | New `schemas/timeutil.py`; flows and alerts normalise every timestamp to aware UTC (naive → UTC, offsets converted); `utcnow`/`utcfromtimestamp` removed from `src/` and tests. Pydantic class-based `Config` replaced with `ConfigDict`. | 7 new tests; suite passes with `-W error::DeprecationWarning` |
| Config | `AppSettings` removed; explicit `ENV_OVERRIDES` table (+ `.env` loading, process env wins); config dir lookup `UNISHIELD_CONFIG_DIR` → `./configs` → source checkout; warnings when config/thresholds files are missing; Streamlit `dashboard:` section removed; unused keys marked "(planned)". Security flags have no override. | 9 new tests |
| Logging | Configured once in the API startup hook (works under plain `uvicorn` and reload); file handlers follow `paths.logs_dir` / `UNISHIELD_LOGS_DIR`. | 3 new tests; packaged-server run wrote `logs/unishield.log` |
| Packaging | Dashboard HTML declared as package data (needed for non-editable installs). | non-editable install served `/dashboard` |
| Docker | Python 3.12 image, pinned install, non-editable package, non-root user, stdlib health check, `.dockerignore`; compose reduced to the API service, port bound to 127.0.0.1, configs/data mounted read-only; Streamlit service removed. | **Not built** — Docker is not installed on this machine |
| Makefile | Streamlit target removed; install targets use the lock files; coverage target fixed. | — |
| CI | `.github/workflows/tests.yml`: pytest on Ubuntu + Windows, Python 3.12, pinned deps. | **Not run yet** — runs after the branch is pushed |
| Docs | README install/run/test/Docker/dependency sections and performance table corrected; `docs/demo_guide.md` dashboard URL fixed. Full documentation rewrite remains Phase 10. | — |

Exit test results:

1. Fresh Python 3.12 venv from `requirements-dev.txt` + `pip install --no-deps -e .` → `pytest tests/` **115 passed** (no warnings with deprecations as errors); coverage command works (69% line coverage).
2. Fresh venv from `requirements.txt` + non-editable `pip install --no-deps .`, server started with `uvicorn unishield.api.app:app` from a directory containing only `configs/` → `/health` 200 (security flags true), `/dashboard` 200, `/docs` 200, `/replay/demo` 200 (4 alerts), `/alerts` 200, log file created.

New observation for Phase 6: under a real uvicorn server, `/replay/demo` took 8.7 s for 920 records (87 windows, ~100 ms per window) versus ~14 ms per window in-process, so the Isolation Forest bottleneck (D6) is worse in deployment than in §8.1.

Not changed in Phase 2 (by plan): all detection defects D1–D17 except D18.

### Phase 3 — Ingestion, normalisation, sessionization (2026-10-14) — exit test passed

Branch `phase-3-ingestion` (on top of `audit-baseline`).

| Item | Change | Evidence |
|---|---|---|
| Flow schema | Strict IP validation (IPv4/IPv6 canonicalised, or 16-hex anonymised hash) — also closes the IP-field route to the dashboard XSS (D17 remains for other fields until Phase 9). New optional fields: `flow_id`, `orig/resp_packets`, `orig/resp_bytes`, `conn_state`, `dns_rcode`, `label` (evaluation only). `source` renamed `source_type` per spec (old name still accepted). `end_time` property. | `test_flow_schema.py` |
| Normalisation (`processing/normalization.py`) | Direction from `network.home_networks` (default RFC 1918 + ULA) unless the source gave one; TLS version names unified; DNS query length filled; optional salted IP hashing applied last (after direction inference). | `test_normalization.py` (25 tests) |
| Sessionizer (`processing/sessionizer.py`) | Packet → bidirectional flow aggregation: originator detection, per-direction counts, Zeek-style `conn_state`, originator-only `tcp_flags`, idle/active timeouts, FIN/RST closing grace, `max_active_flows` memory bound. Output released in start-time order (lag = active + idle + 1 s of traffic time). | `test_sessionizer.py` (13 tests), 99% line coverage |
| PCAP reader (D9, D15) | IPv6; TLS version/cipher parsed from ClientHello/ServerHello `supported_versions` (`ingest/tls.py`) instead of the record header; no port-443 assumption; DNS rcode from responses; `wirelen` used for byte counts. scapy now installed. | sample capture: 26 packets → exactly the 10 ground-truth flows (PCAP and PCAPNG) |
| Zeek reader (D14) | TSV format; JSON lines streamed; directory mode joins `conn.log` with `dns.log`/`ssl.log` on `uid`; rcode, labels, per-direction counts, `local_orig/local_resp` direction kept; records without IPs counted as errors (no `0.0.0.0`); port 0 kept. | `test_readers.py` |
| Flow reader (D13) | Keeps direction, DNS/TLS fields, flow id, per-direction counts, labels; JSON lines streamed; CIC-IDS2017 profile auto-detected (µs → s, forward/backward counts, dd/mm/yyyy timestamps without seconds); invalid rows counted, never fabricated; negative durations → null. | `test_readers.py` |
| Format detection (D8) | `ingest/detect.py` picks the reader from file content (magic bytes / headers / JSON keys), independent of extension. | `test_detect.py` |
| Replay API (D8, D9) | Accepts PCAP/PCAPNG/Zeek file or directory/flow files; only under `paths.data_dir` + `ingest.allowed_dirs` (403 otherwise, checked before existence); 404/413/400/409 status codes; status reports reader/sessionizer/normaliser counts; "stopped" no longer overwritten by "completed". | `tests/integration/test_ingest_pipeline.py`; live server run below |
| Pipeline | Stages reader → sessionizer (packet-level readers) → normaliser → window; alerts carry the real input source (`source_type`); `/metrics` `malformed_records` reports reader errors. | integration tests |
| Samples | `unishield/data/sample_files.py` + `scripts/make_samples.py` write deterministic PCAP/PCAPNG, Zeek JSON dir, Zeek TSV, flow CSV/JSONL and CIC-IDS2017-style files to `data/samples/` (git-ignored). | — |

Exit test results:

- `pytest tests/` → **222 passed** (107 new), no warnings with deprecations as errors; line coverage 88% (sessionizer 99%, detection 97%, TLS 95%, readers 86–93%).
- Integration: sample PCAP → reader → sessionizer → normaliser matches every ground-truth flow (counts, bytes, connection state, direction, TLS, DNS rcode); output in timestamp order.
- Live uvicorn server, `POST /replay/start` on each generated sample: `sample.pcap` and `sample.pcapng` → 26 packets → 10 flows; Zeek directory → 4; Zeek TSV → 4; `flows.jsonl` → 3 (was 0, D8); `README.md` and `data/samples/../../README.md` → 403; missing file → 404.

Notes and remaining limitations:

- The sample PCAP spans < 3 s, so it fills no 10-second window and yields no alerts — D1 (no end-of-stream flush) is Phase 4 work.
- Sessionized flows reach the window 16 s (traffic time) after they start; Phase 4 window rework should account for this when measuring detection delay.
- Detectors still use their pre-Phase-3 features: e.g. the scan features do not yet use `conn_state`, so D7 is not fixed until Phase 4.
- TLS hellos split across TCP segments are not reassembled (version left empty); JA3/JA4 are not computed from PCAP (Phase F).
- CIC-IDS2017 timestamps are local lab time and some files use 12-hour times without AM/PM; they are read as UTC as-is.

### Phase 4 — Windowing, DDoS and scan detection (2026-10-14) — exit test passed

Branch `phase-4-windowing-ddos-scan` (on top of `main` @ `803a106`).

| Item | Change | Evidence |
|---|---|---|
| Window (D1, D11) | `processing/window.py` rewritten: grid-aligned event-time windows (close when the watermark passes their end), `flush()` at end of input, `advance()` for clock-driven closing, `allowed_lateness_sec` (default 0) with late records counted, `observed_seconds` per window (1 s floor), empty windows skipped. Unused per-source windows removed. | `test_window.py` (12 tests), 97% coverage |
| Rates (D2) | All extractors receive a `WindowContext`; rates divide by the observed window duration. New `peak_per_second` spreads each flow over its duration. | one 20-packet flow after 30 s silence: no alert (was HIGH DDoS at "20,000 pps") |
| DDoS features/detector (D10) | Per-target profiles (most packets / most half-open attempts / most UDP); peak 1-s rates; half-open = S0/REJ or SYN-only. Rules: VOLUMETRIC (peak pps or bps), SYN_FLOOD (peak half-open/s and ≥ 80% half-open), UDP_FLOOD (peak UDP pps and ≥ 70% UDP). Alerts name the target and whether the attack is distributed. Thresholds redefined and documented in `thresholds.yaml`. | `test_ddos.py` (19 tests) |
| Scan features/detector (D7) | Connection attempts only (replies from service ports ignored); failed = S0/REJ/RST ≤ 4 packets; per-source profiles; every candidate source evaluated. PORT_SCAN = ≥ 25 ports on one host, or ≥ 25 ports with ≥ 50% failures; HOST_SCAN = ≥ 20 hosts on one port with failures, or ≥ 50 regardless; RECONNAISSANCE = failed burst below those. | `test_scan.py` (24 tests); CDN browsing and per-packet HTTPS raise nothing |
| Pipeline (D12) | Uses the new window and flushes at end; latency/feature histories bounded (100k records / 10k windows / 1k feature sets); window processing P50/P95 and window stats in `/replay/status`; `/metrics` reports queue size and dropped records. Unused lock and "thread-safe" claim removed. | — |
| Generator (D10) | `sample_generator.py`: every generator seedable, every flow labelled; flows carry per-direction counts and connection state; DDoS = SYN flood ~3,000 attempts/s + UDP botnet ~24,000 pps; new host sweep; `build_scenario(name, seed)` with expected classes (`benign_hard`, `ddos_syn`, `ddos_udp`, `port_scan`, `host_sweep`). Demo default DDoS volume 6,000 records; demo endpoint takes `seed`. | `test_generator.py` (14 tests) |
| Exfiltration byte attribution | Uses per-direction counts: uploads on internally initiated connections vs bytes received; downloads and server replies are no longer counted as exfiltration. Full exfiltration rework remains Phase 5. | `benign_hard`: 3–4 false exfiltration alerts → 0 |
| Samples | `attack_portscan.pcap` (200-port SYN scan) and `attack_synflood.pcap` (3,000-packet spoofed SYN flood) added to `scripts/make_samples.py`. | — |

Exit test results (`tests/integration/test_detection_scenarios.py`, full pipeline, default config):

| Scenario | Seeds | Expected DDoS/scan classes | Result |
|---|---|---|---|
| `ddos_syn` | 1–5 | SYN_FLOOD | 5/5 exact match |
| `ddos_udp` | 1–5 | UDP_FLOOD + DDOS_VOLUMETRIC | 5/5 exact match |
| `port_scan` | 1–5 | PORT_SCAN | 5/5 exact match (no spurious HOST_SCAN) |
| `host_sweep` | 1–5 | HOST_SCAN | 5/5 exact match |
| `benign_hard` | 1–5 | none | 5/5 — zero DDoS/scan alerts |
| `attack_portscan.pcap` | — | PORT_SCAN from 198.51.100.66 → 192.168.1.20 | ✔ (also via API, source `pcap_file`) |
| `attack_synflood.pcap` | — | SYN_FLOOD on 192.168.1.100, distributed | ✔ (3,000 packets → 3,000 flows) |
| `sample.pcap` (benign) | — | none; short capture analysed | ✔ (D1 fixed) |

`pytest tests/` → **314 passed** (99 new), no warnings with deprecations as errors; coverage 89% (scan features 99%, volume 99%, window 97%, detectors 95%).

Live server: `attack_portscan.pcap` via `/replay/start` → CRITICAL PORT_SCAN (200 ports on one host, 100% failed); dashboard demo → DDOS_VOLUMETRIC (peak 25,229 pps), SYN_FLOOD (3,070 half-open/s), UDP_FLOOD (24,572 pps), PORT_SCAN, DATA_EXFILTRATION.

Performance (5 runs, 12,550-record mixed scenario, seeds 1000–1004):

| Pipeline | Records/s mean (σ, min–max) | Window processing P95 |
|---|---|---|
| Default (6 detectors) | 937 (29, 888–957) | 12.8 ms |
| Without Isolation Forest | 22,389 (1,023, 21,248–23,214) | 0.4 ms |

Remaining issues observed (not Phase 4 scope):

- Beaconing false positives: machine-regular sub-second sequences (scan probes 10 ms apart, a client's 40 connections 200 ms apart, DNS bursts, UDP bot flows) are reported as C2 beaconing; the configured `min_interval_sec` is not applied (D4, Phase 5).
- DGA false positives on many unique benign subdomains (optional DNS module, Phase E).
- Isolation Forest: 4–14 anomaly alerts per benign scenario and still the throughput bottleneck (D5, D6 — Phase 6); throughput remains just under the 1,000 records/s target.
- Deduplication still uses wall-clock time (D3, Phase 5), so repeated alerts for one attack collapse during fast replay.

### Phases 5–10 and optional modules E/F (2026-10-21/22) — completed in one run

Branch `complete-phases-5-10` (on top of `main`). Detailed results live in the generated reports; this log records what changed and where the evidence is.

| Phase | Change | Evidence |
|---|---|---|
| 5 — Beaconing, exfiltration, correlation (D3, D4) | Deduplication in traffic time keyed on class/source/destination/detector; one module for severities and one for MITRE mappings. Beaconing keeps a bounded rolling inter-arrival history per (src, dst, port) across windows (≥ 10 connections, 5 s–1 h mean, CV ≤ 0.3, destination fan-in ≤ 3, re-alert after 900 s). Exfiltration uses per-source upload baselines (robust z), upload/download ratio, long upload sessions and destination rarity. | `test_beaconing.py`, `test_exfiltration.py`, `test_correlation.py`, `test_phase5_scenarios.py`; beacons at 30/60 s detected for every seed, three exfiltration episodes → three alerts, no beacon/exfiltration false positives |
| 5/6 — Anomaly (D5, D6) | Isolation Forest runs after the rules, trains and reports only on unexplained windows with ≥ 10 flows, one `score_samples` call per window, percentile confidence; new robust-z statistical detector over a vetted baseline (≥ 5 flows per reported window). | `test_anomaly.py`; throughput 937 → ~25,800 records/s |
| E — DNS | DGA per client (generated-looking registrable domains + NXDOMAIN), tunnelling per base domain (unique long/high-entropy subdomains, TXT share). | `test_dns.py`; `benign_hard` DGA false positives gone |
| F — Encrypted sessions | JA3 from ClientHello carried through the sessionizer; ENCRYPTED_SESSION_ANOMALY for outdated TLS, operator JA3 blocklist and long low-rate sessions on unusual ports; cautious wording. | `test_encrypted.py`, `test_tls.py` |
| 6 — Datasets and models | Window dataset built by the real pipeline (labels + what each stage concluded), run-level splits, random forest / XGBoost / benign-only Isolation Forest, isotonic calibration, SHA-256-checked registry. A label leak (only attack flows carried TLS metadata) was found by ablation and fixed in the generator. | `test_models.py`, `test_model_workflow.py`; `reports/model_evaluation.md` |
| 7 — Hybrid and evaluation | `rules` / `hybrid` / `ml` detection modes; ML detector alerts only on unexplained windows at calibrated P ≥ 0.9; comparison of all approaches with episode recall, detection delay, calibration, feature-group ablation and leave-one-attack-out. | `reports/model_evaluation.md` (window F1: rules 0.594, rules+stats 0.662, RF 0.813, XGBoost 0.859, hybrid 0.821; 48/48 episodes except IF) |
| 8 — Persistence and API (D16) | SQLAlchemy storage (SQLite default, PostgreSQL by URL), alert stage timestamps and related flow id, split routers, admin key / loopback-only admin endpoints, non-blocking demo, pagination with `X-Total-Count`, process metrics, traffic analytics, incidents, architecture and report endpoints, hardening headers. | `test_api.py`, `tests/security/test_api_security.py` |
| 9 — Dashboard (D17) | Rewritten offline page with overview, alerts + timeline + details, traffic, benchmark/evaluation and architecture tabs and the required notice; all data inserted with `textContent`; CSP. | `tests/security/test_dashboard.py`; live check: hostile alert fields rendered as text, no script executed |
| 10 — Verification and docs | `evaluation/benchmark.py`, `realtime.py` (paced replay, window end → API), `passive.py` (AST scan + runtime tripwire); scripts `benchmark_pipeline.py`, `replay_stream.py`, `verify_passive_mode.py`, `run_demo.py` (+ `.sh`/`.bat`), `generate_charts.py`; performance tests (`pytest -m performance`); Docker hardening and state volume; documentation rewritten. Stale reports from the pre-audit scripts removed. | `reports/benchmark.md`, `reports/realtime_verdict.md`, `reports/passive_mode_verification.md`, `reports/demo_detection.json` |

Exit results on the development machine (Windows 10, 12 logical CPUs, Python 3.12.10):

- `pytest` → **525 passed** (6 performance tests deselected); `pytest -m performance` → 6 passed.
- `python scripts/run_demo.py` → scenarios 11/11, models ok, benchmark targets met, real-time ok, passive PASSED, charts ok.
- Throughput 25,829 records/s mean (min 25,214) over 5 runs; P95 alert latency after window close 51.8 ms mean (max 55.0); PCAP path 3,881 packets/s.
- Paced replay at 20×: median 90.5 ms from window end to the alert being returned by the API (max 218 ms), 27/27 alerts seen.

Not verified: Docker build (Docker not installed on this machine); evaluation on public datasets (not downloaded); CI on the new commits until they are pushed.

### Deployment hardening (2026-10-22 to 2026-10-28)

Branch `claude/heuristic-stonebraker-eec873`, rebased onto `main` @ `3eede09` (threat intel, exports and analyst-side outputs). Goal: make UniShield safe to deploy and operate as a service. Operating guide: `docs/deployment.md`.

| Area | Change | Evidence |
|---|---|---|
| Schema | Alembic owns the schema: `0001_initial` (alerts, runs, as before), `0002_intel_indicators`, `0003_audit_log`, `0004_accounts`, `0005_alert_retention_index`. Pre-migration databases (with or without the intel tables) are stamped at 0001 and keep their data. `unishield-admin db upgrade / current`; the API refuses an outdated schema when auto-migration is off. | `test_migrations.py` (empty DB, legacy DB, schema = metadata, downgrade, CLI); `test_postgres.py` passed against a local PostgreSQL |
| Accounts | Roles viewer < analyst < admin; Argon2id (argon2-cffi 25.1.0); lockout after 5 failures; per-address throttling; server-side sessions (SHA-256 ids, idle 30 min / absolute 8 h) in HttpOnly, SameSite=Strict, Secure-over-HTTPS cookies; CSRF token; Origin check; service tokens with role, expiry, revocation; no default credentials (`unishield-admin user create`). Loopback is no longer trusted. | `test_accounts.py`, `tests/security/test_auth.py` |
| Route protection | Every route declares one guard; the app refuses to build otherwise and publishes `x-unishield-role` in OpenAPI; tests call every operation as anonymous, each role and service tokens. Intel and output status need a viewer; intel import/removal/purge and exports need an administrator and are audited. Lab-only `auth.mode: open`, refused in production. | `tests/security/test_route_guards.py`, `test_api_security.py` |
| Audit log | Append-only table and `GET /audit` (admin): logins, lockouts, denials, CSRF rejections, replays, deletion, retention, user/token changes, service start (configuration and changes) and stop. Triggers refuse UPDATE/DELETE (and TRUNCATE on PostgreSQL). | `test_audit_log.py`, `test_auth.py`, `test_service.py`, `test_postgres.py` |
| Dashboard | Sign-in view, user pill and sign-out, admin-only run controls, Admin tab (users, audit log), Account tab (password change); CSRF header; no browser storage; still `textContent` only. | `test_dashboard.py`; checked in a browser against a live server (sign-in, demo, user creation, audit view, viewer without admin controls getting 403) |
| HTTPS | `tls.certfile/keyfile` passed to uvicorn by `python -m unishield.main`; HSTS on HTTPS responses; trusted proxies (`api.forwarded_allow_ips`); nginx and Caddy examples. | `test_tls.py`; live: self-signed cert → HTTPS health with HSTS, Secure cookie, plain HTTP refused |
| Operations | Alert retention + housekeeping thread and `unishield-admin retention run`; graceful shutdown stops and records a running replay; `/health` with degraded components and 503 when storage is down; systemd unit, NSSM instructions, container fixes (state directory ownership, entry point, stop grace). | `test_service.py`, `test_packaging.py`; live: Ctrl+Break during a demo replay → run recorded `stopped` with its 14 alerts, `system.stop` audited |
| Supply chain | CI: ruff F/E9, passive-mode verification, `unishield-admin models verify`, PostgreSQL job, `systemd-analyze verify` + `nginx -t`, pip-audit, CycloneDX SBOM artifacts. pip-audit found vulnerabilities only in development pins (pillow 12.3.0, certifi 2026.7.22) → bumped to 13.0.0 / 2026.10.19. Release procedure: `docs/releasing.md`. | local pip-audit: no known vulnerabilities after the bump; local SBOM: 36 runtime components |

Exit results on the development machine (Windows 10, Python 3.12.10): `pytest -q -W error::DeprecationWarning` → **754 passed, 5 skipped** (the PostgreSQL tests, which skip without `UNISHIELD_TEST_POSTGRES_URL`; they passed separately against PostgreSQL), 6 performance tests deselected; `scripts/verify_passive_mode.py` → PASSED (0 static findings outside the outbound transport's scoped allowance, 0 unexpected attempts, login flow included).

Not verified here: the new CI jobs and the Ubuntu/Windows matrix on these commits (not pushed); `systemd-analyze verify` and `nginx -t` (CI only; no systemd or nginx on this machine); the Caddy example and the NSSM instructions; the Docker build.

### Public-dataset evaluation: CTU-13 (2026-10-29)

| Item | Change | Evidence |
|---|---|---|
| CTU-13 reader | `ctu13` flow-reader profile for Argus `.binetflow`: column mapping, reply bytes from TotBytes − SrcBytes, Argus states → S0/REJ/SF/S1/RST/OTH with originator TCP flags. | `tests/unit/test_ctu13.py` |
| Labels | CTU-13 botnet flows labelled BOTNET instead of C2_BEACONING (they mix C2, spam, scans and floods); `prepare_dataset.py --home-networks`. | `tests/unit/test_models.py` |
| Evaluation | `evaluation/public.py` + `scripts/evaluate_public_datasets.py`: host-level, window-level, cross-domain and leave-one-file-out scoring. | `tests/unit/test_public_eval.py` |
| Volume features | Volumetric target chosen among the top 5 destinations by packets by peak rate, so long transfers to a busy host cannot hide a short flood elsewhere. | `tests/unit/test_ddos.py` |

Run on five scenarios (5, 6, 7, 11, 12; 1,235,536 flows, ~5 h of traffic), default thresholds: infected hosts flagged in 4/5 scenarios (8/15 hosts), but 1–5 % of alerts name an infected host. False alerts come mainly from beaconing (regular polling, P2P), exfiltration (uploads) and scan rules on internal hosts. Misses: scenario 6 spam (no spam rule; under the HOST_SCAN fan-out threshold), scenario 7 (63 botnet flows), scenario 11's ICMP flood (~60 packets/s at the capture point). Synthetic-trained window model on real windows: ROC-AUC 0.53; leave-one-scenario-out: 0.33–0.72.

Not done: CIC-IDS2017 (download needs the user's registration), site tuning (asset inventory, learning mode) on CTU-13, the remaining eight CTU-13 scenarios.

### Public-dataset evaluation: CIC-IDS2017 and site tuning (2026-10-29)

| Item | Change | Evidence |
|---|---|---|
| CIC-IDS2017 times | Afternoon times written without AM/PM read as PM (lab hours 08:00-17:00). | `tests/unit/test_readers.py` |
| Out-of-order files | Evaluation analyses a stable time-sorted copy and reports late-dropped records (before the fix Wednesday yielded 946 windows instead of 6,088). | `tests/unit/test_public_eval.py` |
| Minute timestamps | Evaluation spreads each minute's flows over the minute in file order. | `tests/unit/test_public_eval.py` |
| Site tuning | `learn()` takes other home networks; `evaluate_public_datasets.py --site-tuning` learns thresholds without assets (attack flows removed from learning traffic) leave one file out or from a named attack-free file, and compares default vs tuned. | `reports/public_dataset_evaluation.md` |
| Host metric | An alert counts for an attack host only from that host's first attack flow on. | `tests/unit/test_public_eval.py` |

CIC-IDS2017 (8 files, 2,830,743 flows, 0 late drops; 288,602 empty rows in the web-attacks file counted as reader errors): default rules flag 18/23 attack hosts at host-level precision 0.07-0.35; with thresholds learned from Monday, precision 0.72-0.97 on five of seven attack days with almost all hosts kept, botnet day 7/10 -> 2/10, web attacks 1/2 -> 0/2. CTU-13 with thresholds learned from the other scenarios' background traffic: 8/15 -> 1/15 hosts. Synthetic-trained window model: ROC-AUC 0.56 on CIC-IDS2017 windows.

### Brute-force and spam rules (2026-10-29)

| Item | Change | Evidence |
|---|---|---|
| Rules | `features/service_abuse.py` + `detectors/service_abuse_detector.py`: BRUTE_FORCE (T1110) for >= 30 short, small connections from one source to one login port on one host within 60 s with at most half failing to connect; SPAM_ACTIVITY for direct SMTP delivery to >= 20 external mail servers within 5 minutes. Thresholds from tool and client behaviour, not fitted to the datasets. Re-alert memory and restart-safe state. | `tests/unit/test_service_abuse.py` (16 tests) |
| Asset roles | `mail_server` (SPAM_ACTIVITY -> info); vulnerability scanners' BRUTE_FORCE -> info. | same |
| Scenarios and labels | `ssh_bruteforce`, `spam_bot`; CIC-IDS2017 FTP-/SSH-Patator -> BRUTE_FORCE. | scenario check, 5 seeds each |

Rerun of the public-dataset evaluation: 47 new alerts, 45 on attack hosts. CIC-IDS2017 Tuesday 1/2 -> 2/2 attack hosts (first alert 116 s); CTU-13 scenario 6 spam bot first alert 6,266 s -> 491 s; no new alerts on the attack-free Monday; 2 BRUTE_FORCE alerts on CTU-13 background hosts.
