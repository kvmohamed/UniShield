# UniShield Real-Time Verification Verdict

**Generated**: 2026-10-12T17:04:07.937503+00:00  
**System**: Windows-10-10.0.19045-SP0  
**Python**: 3.14.7  
**CPU**: AMD64 Family 25 Model 80 Stepping 0, AuthenticAMD (12 cores)

---

## Overall Classification

**Near-real-time replay**

UniShield processes network flow records incrementally through a sliding-window
pipeline with configurable window sizes. Records are consumed one at a time,
accumulated into time-based windows, and analysed by rule-based and ML detectors
when windows slide. The system does not perform live interface capture.

---

## Evidence

- Pipeline processes records **incrementally** (not batch-load-then-analyse)
- Sliding window with configurable size (10s) and slide interval (5s)
- Each record is timestamped at ingestion, feature extraction, detection, and storage
- 25 test runs completed across 5 scenario types
- All security constraints enforced (read-only, no decryption, no active scanning)
- No prohibited network connections detected

---

## Detection Latency (per-record, across all runs)

| Metric | Value |
|---|---|
| Mean | 0.0405 ms |
| Median | 0.0036 ms |
| P95 | 0.1799 ms |
| P99 | 0.3909 ms |
| Maximum | 10.3099 ms |

---

## Throughput

| Metric | Value |
|---|---|
| Mean | 34901 records/sec |
| Median | 29186 records/sec |
| Minimum | 10815 records/sec |
| Maximum | 104697 records/sec |

---

## Detection Quality

| Scenario | Runs | Passes | Pass Rate | Avg Alerts | Detected Classes |
|---|---|---|---|---|---|
| benign | 5 | 5 | 100% | 0.0 | — |
| ddos | 5 | 0 | 0% | 0.0 | — |
| scan | 5 | 5 | 100% | 11.0 | DATA_EXFILTRATION, HOST_SCAN, PORT_SCAN, RECONNAISSANCE |
| beacon | 5 | 5 | 100% | 27.4 | C2_BEACONING |
| exfil | 5 | 5 | 100% | 161.0 | C2_BEACONING, DATA_EXFILTRATION |

---

## Passive-Operation Verification

| Check | Result |
|---|---|
| Security config enforced | True |
| read_only_mode | True |
| no_payload_decryption | True |
| no_active_scanning | True |
| no_response_path | True |
| Can disable read-only | False |
| Static analysis clean | True |
| Outbound connections | None (localhost only) |

The system generated **no prohibited network activity** during testing.

---

## Dashboard Verification

- **Refresh mechanism**: HTTP polling (health every 10s, alerts on user action only)
- **No WebSocket or SSE** — alerts do not push to the dashboard automatically
- **Alert display delay**: Depends on manual refresh or demo button click
- **Limitation**: The dashboard is a replay visualiser; for continuous monitoring, the polling interval must be shortened and applied to the `/alerts` endpoint

---

## Acceptance Criteria

| # | Criterion | Expected | Actual | Result |
|---|---|---|---|---|
| 1 | Record processing rate ≥ 95% | ≥ 95% | 100.0% | ✅ |
| 2 | No payload decryption | True | True | ✅ |
| 3 | No outbound monitoring command | True | True | ✅ |
| 4 | ≥ 4 threat scenarios generate alerts | ≥ 4 | 3 | ❌ |
| 5 | Benign: low false positives | ≤ 10 high-severity FP across all runs | 0 | ✅ |
| 6 | P95 detection latency < 2000ms | < 2000ms | 0.335ms | ✅ |
| 7 | Throughput ≥ 1000 rps | ≥ 1000 | 10815 | ✅ |
| 8 | Alert schema has required fields | timestamp, threat_class, confidence, severity, evidence, flow_id | All fields present in Alert schema | ✅ |
| 9 | ≥ 5 repeated runs per scenario | ≥ 5 | 25 total runs | ✅ |
| 10 | Dashboard/API alerts correspond to stored alerts | Consistent | In-memory store — API serves same list | ✅ |

**Result: 9/10 criteria passed.**

---

## Limitations

1. **No live capture**: The system replays files or synthetic flows — it does not capture from a live network interface.
2. **Dashboard is not push-based**: Alerts must be manually refreshed or fetched via API polling.
3. **DNS and Anomaly detectors not in default pipeline**: These must be explicitly enabled.
4. **Alert correlation not integrated**: The `AlertCorrelator` exists but is not called by the default pipeline.
5. **No persistent storage**: Alerts are stored in-memory and lost on restart.
6. **Placeholder scripts**: `replay_pcap.py`, `benchmark_pipeline.py`, `train_models.py`, `prepare_dataset.py` are stubs.
7. **Single-threaded pipeline**: No async/concurrent processing.
8. **Dashboard loads Google Fonts**: Requires internet for full styling (does not affect security).

---

## Required Fixes (Priority Order)

1. Add continuous alert polling to the dashboard (3-5 second interval)
2. Register DNS and Anomaly detectors in the default pipeline
3. Integrate AlertCorrelator into the pipeline flow
4. Add persistent alert storage (SQLite or file-based)
5. Implement the replay_pcap.py and benchmark_pipeline.py scripts
6. Add live capture support (tshark/Zeek live feed) for true live monitoring
7. Remove Google Fonts dependency for offline operation

---

## Final Statement

Based on the controlled replay experiment with 25 test runs across
5 scenario types (benign, DDoS, scanning, beaconing, exfiltration), UniShield
demonstrates **near-real-time replay** passive threat detection under the
tested conditions. The system processes flow records incrementally through a
sliding-window pipeline with sub-millisecond per-record latency and detects
embedded attack patterns with measurable precision.

This result does not prove production readiness or generalisation to all
critical-infrastructure networks. The system is a research prototype operating
on synthetic test traffic in an isolated laboratory environment.
