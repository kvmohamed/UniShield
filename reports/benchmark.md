# UniShield — Pipeline Benchmark

Generated 2026-10-31T11:20:03+00:00 by `scripts/benchmark_pipeline.py`.

- Machine: Windows-10-10.0.19045-SP0, AMD64 Family 25 Model 80 Stepping 0, AuthenticAMD, 12 logical CPUs, 7.4 GB RAM
- Python 3.12.10
- Workload: synthetic: dense benign (~100 flows/s traffic time) + SYN/UDP flood, port scan, DGA, DNS tunnel, exfiltration, 30 s beacon; default rules detectors; alerts stored in in-memory SQLite
- 5 measured runs of ~20,000 records each (after one warm-up run)

## Results across runs

| Measure | Mean | Median | SD | Min | Max |
|---|---|---|---|---|---|
| Throughput (records/s) | 23696.06 | 24155.4 | 1101.407 | 21775.6 | 24410.4 |
| Window processing P95 (ms) | 14.49 | 14.513 | 0.085 | 14.348 | 14.572 |
| Alert latency after window close, P95 (ms) | 63.518 | 62.015 | 9.549 | 51.012 | 73.52 |
| Peak resident memory (MB) | 143.68 | 143.5 | 4.128 | 138.4 | 148.5 |
| CPU (% of one core) | 100.24 | 100.4 | 0.783 | 99.0 | 101.1 |

## Targets

- Met: >= 1000 records/s in every run (worst run: 21775.6)
- Met: P95 alert latency after window close < 2000 ms in every run (worst run: 73.52)

## Per run

| Seed | Records | Windows | Alerts | Wall (s) | Records/s | Window P95 (ms) | Alert latency P95 (ms) | Peak RSS (MB) |
|---|---|---|---|---|---|---|---|---|
| 1000 | 19,610 | 453 | 12 | 0.8051 | 24,355.9 | 14.572 | 51.012 | 138.4 |
| 1001 | 19,610 | 464 | 12 | 0.8033 | 24,410.4 | 14.348 | 73.52 | 141.1 |
| 1002 | 19,610 | 446 | 12 | 0.9006 | 21,775.6 | 14.488 | 62.015 | 143.5 |
| 1003 | 19,610 | 468 | 13 | 0.8118 | 24,155.4 | 14.513 | 72.522 | 146.9 |
| 1004 | 19,610 | 456 | 12 | 0.8245 | 23,783.0 | 14.53 | 58.522 | 148.5 |

## PCAP path

Offline parsing of a written 10,000-packet SYN-flood capture with scapy, sessionization and detection (3 runs): mean 3,856.251 packets/s (median 3,897.313, min 3,756.353, max 3,915.088). Packet parsing in Python is the slowest stage; for high-rate captures, convert to Zeek logs first and replay those.

## Notes

- Throughput covers the whole pipeline run over records already in memory (generating the workload is excluded): normalisation, windowing, feature extraction, detection, deduplication and storage. File parsing costs extra; the PCAP section measures the slowest input path.
- Alert latency after window close is measured per alert from the wall-clock moment its window was closed to the moment it was stored. It does not include the wait for the window to end in traffic time (up to the window length) — see the real-time replay report for that.
- The workload is synthetic and replayed as fast as possible; live traffic would arrive at its own rate.
