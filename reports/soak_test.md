# UniShield — Soak Test

Generated 2026-10-28T06:39:05+00:00 by `scripts/soak_test.py` at commit `d65bcfe`.

Everything below was measured in this run on the machine listed. The traffic is UniShield's own synthetic site profile (`unishield.data.site_traffic`), not traffic from a real network.

## Setup

| Setting | Value |
|---|---|
| Wall-clock duration | 30 min |
| Record rate | 1,000 records/s (wall clock) |
| Traffic time per wall second | 8 s, so the run covered 4.0 h of traffic |
| Profile | `site`; asset inventory on; attack every 15 min of traffic |
| State snapshots | every 60 s to `pipeline_state.json` |
| Sampling | every 60 s |
| Machine | Windows-10-10.0.19045-SP0, 12 logical CPUs, 7.9 GB, Python 3.12.10 |

## Summary

| Measure | Value |
|---|---|
| Records processed | 1,818,250 (1,010/s) in 2,881 windows |
| Pipeline errors | 0 |
| Largest lag behind schedule | 1.034 s |
| RSS first / last / max | 88.9 / 243.0 / 243.0 MB |
| RSS trend over the second half | +113.7 MB/h (range 27.4 MB) |
| Window processing p50 / p95 (all windows) | 73.75 / 127.15 ms |
| Worst per-interval p95 / slowest window | 198.31 / 392.95 ms |
| Alerts | 366 (732.0 per wall-clock hour) |
| Alerts by class | C2_BEACONING 349, DATA_EXFILTRATION 2, DGA_DETECTED 2, DNS_TUNNELLING 2, HOST_SCAN 2, PORT_SCAN 7, SYN_FLOOD 2 |
| Alerts by severity | CRITICAL 2, HIGH 8, INFO 352, MEDIUM 4 |
| Attacks injected | c2_beacon 3, dga 2, dns_tunnel 2, exfiltration 2, host_sweep 2, port_scan 3, syn_flood 2 |
| Asset policy | 352 alerts downgraded to INFO, 1 suppressed |
| State snapshots | 30 written, 0 failed; last 19.65 MB in 715.0 ms |
| Final state sizes | beacon_pairs 41,924, beacon_seen_ids 523, upload_baselines 762, upload_destinations 12, beaconing_detector_memory 23, exfiltration_detector_memory 2, encrypted_session_detector_memory 0, statistical_baseline 55, dedup_cache 37 |

## Samples

One row per sample; window latencies are for the windows closed in that interval, alerts are those emitted in it.

| Elapsed | Traffic time | Records/s | Lag s | RSS MB | CPU % | Window p50 / p95 / max ms | Alerts | Beacon pairs | Baselines | Snapshot MB / ms |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 min | 00:07:59 | 1,006 | 0.117 | 88.9 | 8.3 | 30.29 / 55.25 / 111.43 | 20 | 23,736 | 762 | - |
| 2 min | 00:16:00 | 1,010 | 0.202 | 110.3 | 10.2 | 36.54 / 85.66 / 182.19 | 1 | 33,378 | 762 | 3.17 / 152.2 |
| 3 min | 00:24:00 | 1,003 | 0.269 | 124.8 | 11.2 | 42.26 / 91.76 / 242.42 | 22 | 37,620 | 762 | 4.97 / 219.5 |
| 4 min | 00:31:59 | 1,017 | 0.333 | 136.7 | 11.2 | 41.97 / 64.91 / 114.7 | 4 | 40,293 | 762 | 6.51 / 275.2 |
| 5 min | 00:40:00 | 1,006 | 0.402 | 146.3 | 12.1 | 47.78 / 108.9 / 186.56 | 23 | 41,271 | 762 | 7.75 / 332.8 |
| 6 min | 00:48:00 | 1,007 | 0.447 | 156.8 | 12.4 | 48.26 / 115.42 / 125.26 | 1 | 41,828 | 762 | 8.77 / 378.7 |
| 7 min | 00:55:59 | 1,006 | 0.522 | 164.7 | 14.9 | 58.64 / 124.79 / 180.64 | 22 | 42,122 | 762 | 9.79 / 419.2 |
| 8 min | 01:03:59 | 1,008 | 0.538 | 171.2 | 15.3 | 59.48 / 149.25 / 179.48 | 1 | 42,294 | 762 | 10.78 / 454.6 |
| 9 min | 01:12:00 | 1,005 | 0.617 | 178.2 | 14.2 | 57.56 / 146.26 / 156.98 | 22 | 42,386 | 762 | 11.78 / 524.3 |
| 10 min | 01:20:00 | 1,010 | 0.599 | 187.0 | 13.9 | 59.01 / 98.69 / 155.85 | 21 | 42,448 | 762 | 12.77 / 514.4 |
| 11 min | 01:28:00 | 1,006 | 0.651 | 194.6 | 14.9 | 61.85 / 155.09 / 168.77 | 2 | 42,480 | 762 | 13.77 / 523.6 |
| 12 min | 01:36:00 | 1,010 | 0.673 | 200.0 | 14.9 | 65.39 / 97.4 / 164.65 | 21 | 42,501 | 762 | 14.76 / 578.7 |
| 13 min | 01:43:59 | 1,008 | 0.686 | 199.6 | 17.0 | 74.59 / 163.09 / 214.66 | 2 | 42,511 | 762 | 15.75 / 583.0 |
| 14 min | 01:52:00 | 1,054 | 1.034 | 204.9 | 19.5 | 77.29 / 190.98 / 247.71 | 21 | 42,525 | 762 | 16.73 / 861.9 |
| 15 min | 02:00:00 | 1,006 | 0.789 | 210.5 | 17.3 | 73.93 / 172.99 / 301.23 | 2 | 42,529 | 762 | 17.73 / 681.7 |
| 16 min | 02:08:00 | 1,007 | 0.920 | 215.6 | 18.1 | 76.17 / 176.8 / 195.8 | 21 | 42,529 | 762 | 18.72 / 812.1 |
| 17 min | 02:15:59 | 1,007 | 0.963 | 218.2 | 19.1 | 78.52 / 156.78 / 392.95 | 2 | 42,531 | 762 | 19.26 / 823.6 |
| 18 min | 02:24:00 | 1,003 | 0.864 | 219.7 | 19.0 | 77.84 / 131.82 / 262.51 | 20 | 42,534 | 762 | 19.48 / 736.9 |
| 19 min | 02:32:00 | 1,006 | 0.961 | 221.6 | 20.2 | 82.02 / 192.02 / 282.86 | 3 | 41,932 | 762 | 19.58 / 830.8 |
| 20 min | 02:40:00 | 1,005 | 0.980 | 223.6 | 18.7 | 74.85 / 91.79 / 182.76 | 20 | 41,931 | 762 | 19.60 / 857.1 |
| 21 min | 02:48:00 | 1,007 | 0.844 | 225.8 | 18.2 | 75.67 / 185.54 / 246.82 | 3 | 41,926 | 762 | 19.63 / 731.7 |
| 22 min | 02:56:00 | 1,005 | 0.861 | 228.2 | 17.4 | 75.3 / 88.99 / 197.94 | 20 | 41,927 | 762 | 19.64 / 749.0 |
| 23 min | 03:04:00 | 1,010 | 0.865 | 229.4 | 17.7 | 75.86 / 89.98 / 196.14 | 3 | 41,923 | 762 | 19.66 / 752.4 |
| 24 min | 03:12:00 | 1,006 | 0.955 | 230.0 | 19.3 | 80.51 / 196.83 / 252.89 | 20 | 41,924 | 762 | 19.66 / 824.2 |
| 25 min | 03:20:00 | 1,006 | 0.974 | 233.9 | 18.2 | 75.3 / 182.17 / 240.29 | 23 | 41,926 | 762 | 19.66 / 849.1 |
| 26 min | 03:28:00 | 1,006 | 0.847 | 235.8 | 17.9 | 75.32 / 102.56 / 187.91 | 0 | 41,921 | 762 | 19.65 / 734.9 |
| 27 min | 03:36:00 | 1,055 | 0.861 | 237.1 | 18.3 | 77.5 / 189.6 / 207.52 | 23 | 41,923 | 762 | 19.65 / 746.0 |
| 28 min | 03:44:00 | 1,005 | 1.014 | 237.5 | 18.2 | 76.54 / 189.3 / 212.83 | 0 | 41,925 | 762 | 19.65 / 762.6 |
| 29 min | 03:52:00 | 1,008 | 0.946 | 240.4 | 19.5 | 79.35 / 198.31 / 298.07 | 23 | 41,927 | 762 | 19.65 / 805.6 |
| 30 min | 04:00:00 | 1,005 | 0.852 | 243.0 | 19.0 | 75.85 / 90.41 / 200.7 | 0 | 41,924 | 762 | 19.65 / 715.0 |

## Notes

Run on the development machine while documentation was being edited in parallel, so latency figures are an upper bound for an otherwise idle machine. A 24-hour run was not performed.

Reading the run (analysis added after it finished):

- **Throughput and lag.** Every record was processed at the requested rate. The largest lag per interval
  rose to about 1 s while the state filled, then stayed between 0.84 and 1.03 s; it tracks the state
  snapshot write time (0.7-0.86 s once the state was full), during which the pipeline pauses. Processing
  did not fall progressively behind.
- **State.** Beacon pairs grew to about 42,500 over the first 2 h of traffic (the beacon history length),
  then stayed flat at about 41,900 as idle pairs were pruned; the snapshot stayed at 19.6 MB. Re-alert
  memories, dedup cache and seen-record ids stayed small.
- **Memory.** RSS was still rising at the end, by about 1 MB per wall-clock minute (219.7 to 243.0 MB over
  the last 13 minutes), while every state size was flat. A separate `tracemalloc` run on the same profile
  (30 records/s, no snapshots) found the Python heap at 112.4 MB at traffic hour 3 and 116.4 MB at hour 6,
  so the growth is probably memory the allocator keeps rather than live objects, but this run does not
  show that RSS levels off. A 24-hour run is needed to settle it.
- **Detections.** Every injected attack type raised its class above INFO except C2 beaconing: the three
  beacon episodes reuse one pair, the third started at the very end, and the second resumed 93 minutes
  after the first, while the first episode's connections were still in the pair's 2-hour history, so the
  gap made the intervals irregular. A follow-up check reproduced it (same pair, 93-minute gap: not
  re-detected; 150-minute gap: re-detected). This is a limit of the beaconing rule, not of the soak.
  *Since this run* the beaconing profile uses the pair's newest run of connections, and the same
  check re-detects the 93-minute case at the resumed episode's 10th connection; the soak itself has
  not been re-run, so the table above is unchanged.
- **Benign site behaviour.** 352 alerts from the monitoring poller, update checks and vulnerability scanner
  were reported as INFO and one backup upload was suppressed, all counted by the asset policy.
