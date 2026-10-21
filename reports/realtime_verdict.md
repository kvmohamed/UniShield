# UniShield — Real-Time Verification

Generated 2026-10-21T19:12:57+00:00 by `scripts/replay_stream.py`.

## Classification

**Near-real-time, event-time stream processing of replayed traffic.**

Records are processed one at a time as they arrive; each 10 s window (sliding every 5 s) is analysed as soon as it closes, and alerts are stored and served by the API immediately. UniShield does not capture from a live interface: input is a file or a replayed stream, so it is not claimed to be a live network sensor.

## Method

- 5 paced replays at 20.0x real time (generate_mixed_scenario(normal 200, SYN/UDP flood 3000, port scan 120, beacon 8, exfiltration 20), ~8 min of traffic per run).
- The API was polled every 0.1 s through an in-process client; an alert counts as visible at the first poll that returned it.
- Machine: Windows-10-10.0.19045-SP0, 12 logical CPUs, Python 3.12.10.
- Delays measured in wall time. Close delay is converted from traffic time; at 20.0x, 1 s of wall time is 20.0 s of traffic.

## Per-alert latency across all runs (ms of wall time)

| Stage | Mean | Median | SD | Min | Max |
|---|---|---|---|---|---|
| Window close delay (window end → window closed) | 40.137 | 40.2 | 27.925 | 2.5 | 135.9 |
| Processing (window closed → alert stored) | 21.185 | 26.4 | 19.461 | 0.0 | 42.02 |
| API visibility (stored → first returned by API) | 30.578 | 16.0 | 26.023 | 4.0 | 106.0 |
| End to end (window end → visible in API) | 91.896 | 90.5 | 44.837 | 13.7 | 218.1 |

P95 end-to-end latency per run: mean 109.7 ms, median 101.2 ms, SD 23.65, min 82.2, max 143.8 (n = 5 runs).

Alerts never returned by the API: 0.

## Per run

| Seed | Records | Windows | Alerts | Traffic (s) | Wall (s) |
|---|---|---|---|---|---|
| 2000 | 3,348 | 57 | 5 | 483.3 | 24.17 |
| 2001 | 3,348 | 58 | 5 | 479.0 | 23.95 |
| 2002 | 3,348 | 55 | 5 | 483.7 | 24.19 |
| 2003 | 3,348 | 56 | 6 | 480.4 | 24.02 |
| 2004 | 3,348 | 58 | 6 | 485.8 | 24.3 |

## Throughput headroom (from reports/benchmark.md)

Unpaced, the pipeline processed 25,828.8 records/s on average (min 25,213.6) with P95 alert latency after window close of 51.832 ms, so at these replay rates it is idle most of the time.

## Interpretation

- The dominant delay is waiting for a window to close. A window closes when the first record after its end arrives, so in quiet traffic the delay grows with the gap between records; `processing.allowed_lateness_sec` adds to it by design.
- Detection, correlation and storage take milliseconds per window.
- API visibility is bounded by the poll interval; the dashboard polls every 3 s.
- In traffic time, an alert can be raised at most one window length plus the close delay after the activity starts; slow behaviours (beaconing, exfiltration baselines) need several windows of evidence by design.
