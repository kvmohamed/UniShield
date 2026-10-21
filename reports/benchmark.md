# UniShield — Pipeline Benchmark

Generated 2026-10-21T19:10:43+00:00 by `scripts/benchmark_pipeline.py`.

- Machine: Windows-10-10.0.19045-SP0, AMD64 Family 25 Model 80 Stepping 0, AuthenticAMD, 12 logical CPUs, 7.4 GB RAM
- Python 3.12.10
- Workload: synthetic: dense benign (~100 flows/s traffic time) + SYN/UDP flood, port scan, DGA, DNS tunnel, exfiltration, 30 s beacon; default rules detectors; alerts stored in in-memory SQLite
- 5 measured runs of ~20,000 records each (after one warm-up run)

## Results across runs

| Measure | Mean | Median | SD | Min | Max |
|---|---|---|---|---|---|
| Throughput (records/s) | 25828.8 | 25824.2 | 489.062 | 25213.6 | 26480.0 |
| Window processing P95 (ms) | 13.476 | 13.294 | 0.406 | 13.174 | 14.158 |
| Alert latency after window close, P95 (ms) | 51.832 | 51.11 | 1.914 | 50.015 | 55.013 |
| Peak resident memory (MB) | 131.08 | 131.7 | 4.595 | 125.1 | 137.2 |
| CPU (% of one core) | 99.98 | 99.8 | 0.626 | 99.2 | 100.8 |

## Targets

- Met: >= 1000 records/s in every run (worst run: 25213.6)
- Met: P95 alert latency after window close < 2000 ms in every run (worst run: 55.013)

## Per run

| Seed | Records | Windows | Alerts | Wall (s) | Records/s | Window P95 (ms) | Alert latency P95 (ms) | Peak RSS (MB) |
|---|---|---|---|---|---|---|---|---|
| 1000 | 19,610 | 453 | 12 | 0.7406 | 26,480.0 | 13.219 | 51.11 | 125.1 |
| 1001 | 19,610 | 464 | 12 | 0.7516 | 26,090.3 | 13.174 | 50.015 | 128.4 |
| 1002 | 19,610 | 446 | 12 | 0.7594 | 25,824.2 | 14.158 | 55.013 | 131.7 |
| 1003 | 19,610 | 468 | 13 | 0.7679 | 25,535.9 | 13.294 | 51.012 | 133.0 |
| 1004 | 19,610 | 456 | 12 | 0.7778 | 25,213.6 | 13.536 | 52.012 | 137.2 |

## PCAP path

Offline parsing of a written 10,000-packet SYN-flood capture with scapy, sessionization and detection (3 runs): mean 3,880.864 packets/s (median 3,958.563, min 3,721.045, max 3,962.982). Packet parsing in Python is the slowest stage; for high-rate captures, convert to Zeek logs first and replay those.

## Notes

- Throughput covers the whole pipeline run over records already in memory (generating the workload is excluded): normalisation, windowing, feature extraction, detection, deduplication and storage. File parsing costs extra; the PCAP section measures the slowest input path.
- Alert latency after window close is measured per alert from the wall-clock moment its window was closed to the moment it was stored. It does not include the wait for the window to end in traffic time (up to the window length) — see the real-time replay report for that.
- The workload is synthetic and replayed as fast as possible; live traffic would arrive at its own rate.
