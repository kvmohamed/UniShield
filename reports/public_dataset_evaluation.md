# UniShield — Evaluation on Public Datasets

Generated 2026-10-28 19:58 UTC by `scripts/evaluate_public_datasets.py` with the default `rules` detection mode and default thresholds (no tuning to these datasets).

## CTU-13 (Stratosphere Lab, CTU Prague, 2011)

Botnet captures in a university network, as Argus bidirectional flows with labels Botnet / Normal / Background.

Home networks used for direction: 147.32.0.0/16.

| File | Records | Hours | Attack flows | Windows (attack) | Attack hosts detected | Alerts (involving attack hosts) | Other hosts named | First-alert delay (s) |
|---|---|---|---|---|---|---|---|---|
| scenario11_capture20110818-2.binetflow | 107,248 | 0.27 | 8,164 | 196 (37) | 3/3 | 61 (3) | 70 | 37.5, 77.0, 80.8 |
| scenario12_capture20110819.binetflow | 325,468 | 1.72 | 2,168 | 894 (394) | 3/9 | 313 (5) | 199 | 118.6, 140.1, 179.9 |
| scenario5_capture20110815-2.binetflow | 129,831 | 0.5 | 901 | 363 (223) | 1/1 | 46 (1) | 40 | 719.1 |
| scenario6_capture20110816.binetflow | 558,914 | 2.15 | 4,630 | 1,552 (1,142) | 1/1 | 557 (4) | 197 | 6266.3 |
| scenario7_capture20110816-2.binetflow | 114,075 | 0.35 | 63 | 258 (17) | 0/1 | 84 (0) | 69 | – |

### Window level (default rules)

| File | Approach | Precision | Recall | F1 | FPR |
|---|---|---|---|---|---|
| scenario11_capture20110818-2.binetflow | rules | 0.210 | 0.919 | 0.342 | 0.805 |
| scenario11_capture20110818-2.binetflow | rules_statistical | 0.210 | 0.919 | 0.342 | 0.805 |
| scenario12_capture20110819.binetflow | rules | 0.454 | 0.987 | 0.622 | 0.936 |
| scenario12_capture20110819.binetflow | rules_statistical | 0.454 | 0.987 | 0.622 | 0.936 |
| scenario5_capture20110815-2.binetflow | rules | 0.641 | 0.978 | 0.774 | 0.871 |
| scenario5_capture20110815-2.binetflow | rules_statistical | 0.641 | 0.978 | 0.774 | 0.871 |
| scenario6_capture20110816.binetflow | rules | 0.740 | 0.984 | 0.845 | 0.961 |
| scenario6_capture20110816.binetflow | rules_statistical | 0.740 | 0.984 | 0.845 | 0.961 |
| scenario7_capture20110816-2.binetflow | rules | 0.064 | 0.941 | 0.120 | 0.967 |
| scenario7_capture20110816-2.binetflow | rules_statistical | 0.064 | 0.941 | 0.120 | 0.967 |

### Alerts by class

- scenario11_capture20110818-2.binetflow: C2_BEACONING 54 (0 on attack hosts); DATA_EXFILTRATION 2 (0 on attack hosts); DDOS_VOLUMETRIC 2 (0 on attack hosts); PORT_SCAN 3 (3 on attack hosts)
- scenario12_capture20110819.binetflow: C2_BEACONING 208 (0 on attack hosts); DATA_EXFILTRATION 88 (0 on attack hosts); HOST_SCAN 3 (2 on attack hosts); PORT_SCAN 14 (3 on attack hosts)
- scenario5_capture20110815-2.binetflow: C2_BEACONING 40 (0 on attack hosts); DATA_EXFILTRATION 4 (1 on attack hosts); HOST_SCAN 2 (0 on attack hosts)
- scenario6_capture20110816.binetflow: C2_BEACONING 396 (4 on attack hosts); DATA_EXFILTRATION 81 (0 on attack hosts); DDOS_VOLUMETRIC 1 (0 on attack hosts); HOST_SCAN 10 (0 on attack hosts); PORT_SCAN 69 (0 on attack hosts)
- scenario7_capture20110816-2.binetflow: C2_BEACONING 30 (0 on attack hosts); DATA_EXFILTRATION 28 (0 on attack hosts); DDOS_VOLUMETRIC 5 (0 on attack hosts); HOST_SCAN 3 (0 on attack hosts); PORT_SCAN 18 (0 on attack hosts)

### Synthetic-trained random forest on these windows (cross-domain)

PR-AUC 0.569, ROC-AUC 0.526; at P ≥ 0.5: precision 0.557, recall 1.000; at P ≥ 0.9: precision 0.557, recall 0.999.

### Random forest trained on the other files, tested on each (unseen attack)

| Held-out file | PR-AUC | ROC-AUC | Precision@0.5 | Recall@0.5 | FPR@0.5 | Recall@0.9 |
|---|---|---|---|---|---|---|
| scenario11_capture20110818-2.binetflow | 0.304 | 0.723 | 0.292 | 0.892 | 0.503 | 0.000 |
| scenario12_capture20110819.binetflow | 0.465 | 0.532 | 0.440 | 0.447 | 0.448 | 0.102 |
| scenario5_capture20110815-2.binetflow | 0.704 | 0.661 | 0.663 | 0.996 | 0.807 | 0.000 |
| scenario6_capture20110816.binetflow | 0.744 | 0.524 | 0.752 | 0.950 | 0.871 | 0.068 |
| scenario7_capture20110816-2.binetflow | 0.054 | 0.330 | 0.000 | 0.000 | 0.216 | 0.000 |

### Caveats

- Background flows are unverified university traffic and are counted as benign; some may be malicious or misconfigured, so 'other hosts named' is an upper bound on false positives.
- Botnet flows mix C2, spam, scanning and DDoS and are labelled BOTNET; window labels are binary here, so class-level accuracy is not measured.
- Argus exports have no DNS names or TLS fields, so the DNS and encrypted-session detectors cannot fire.
- Timestamps are local capture time read as UTC (consistent within a file).
- Findings from inspecting the 2026-10 run: scenario 6's bot sends spam (4,398 failed SMTP attempts to at most 15 mail servers per 10 s, under the 20-host HOST_SCAN threshold; UniShield has no spam rule) and was caught only by its C2 beacon after about 6,300 s; scenario 7's bot made 63 flows in 21 minutes, too few for any rule; scenario 11's ICMP flood reaches only about 60 packets/s at the capture point, far below the 10,000 packets/s volumetric threshold.
- Most other alerts name hosts inside 147.32.0.0/16: regular polling and peer-to-peer traffic (HTTP, SSH attempts, BitTorrent, POP3 were seen behind beacon alerts) raises C2_BEACONING, large uploads raise DATA_EXFILTRATION, and failed connection bursts raise PORT_SCAN. Default thresholds were tuned on synthetic traffic; the asset inventory and learning mode exist for this, but were not applied here.

