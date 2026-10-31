# UniShield — Evaluation on Public Datasets

Generated 2026-10-29 07:41 UTC by `scripts/evaluate_public_datasets.py` with the default `rules` detection mode and default thresholds (no tuning to these datasets).

## CTU-13 (Stratosphere Lab, CTU Prague, 2011)

Botnet captures in a university network, as Argus bidirectional flows with labels Botnet / Normal / Background.

Home networks used for direction: 147.32.0.0/16.

| File | Records (late-dropped) | Hours | Attack flows | Windows (attack) | Attack hosts detected | Alerts (involving attack hosts) | Other hosts named | First-alert delay (s) |
|---|---|---|---|---|---|---|---|---|
| scenario11_capture20110818-2.binetflow | 107,248 (0) | 0.27 | 8,164 | 196 (37) | 3/3 | 61 (3) | 70 | 37.5, 77.0, 80.8 |
| scenario12_capture20110819.binetflow | 325,468 (0) | 1.72 | 2,168 | 894 (394) | 3/9 | 313 (5) | 199 | 118.6, 140.1, 179.9 |
| scenario5_capture20110815-2.binetflow | 129,831 (0) | 0.5 | 901 | 363 (223) | 1/1 | 46 (1) | 40 | 719.1 |
| scenario6_capture20110816.binetflow | 558,914 (0) | 2.15 | 4,630 | 1,552 (1,142) | 1/1 | 567 (13) | 197 | 491.3 |
| scenario7_capture20110816-2.binetflow | 114,075 (0) | 0.35 | 63 | 258 (17) | 0/1 | 85 (0) | 71 | – |

### Window level (default rules)

| File | Approach | Precision | Recall | F1 | FPR |
|---|---|---|---|---|---|
| scenario11_capture20110818-2.binetflow | rules | 0.210 | 0.919 | 0.342 | 0.805 |
| scenario11_capture20110818-2.binetflow | rules_statistical | 0.210 | 0.919 | 0.342 | 0.805 |
| scenario12_capture20110819.binetflow | rules | 0.454 | 0.987 | 0.622 | 0.936 |
| scenario12_capture20110819.binetflow | rules_statistical | 0.454 | 0.987 | 0.622 | 0.936 |
| scenario5_capture20110815-2.binetflow | rules | 0.641 | 0.978 | 0.774 | 0.871 |
| scenario5_capture20110815-2.binetflow | rules_statistical | 0.641 | 0.978 | 0.774 | 0.871 |
| scenario6_capture20110816.binetflow | rules | 0.743 | 0.998 | 0.852 | 0.961 |
| scenario6_capture20110816.binetflow | rules_statistical | 0.743 | 0.998 | 0.852 | 0.961 |
| scenario7_capture20110816-2.binetflow | rules | 0.063 | 0.941 | 0.118 | 0.992 |
| scenario7_capture20110816-2.binetflow | rules_statistical | 0.063 | 0.941 | 0.118 | 0.992 |

### Alerts by class

- scenario11_capture20110818-2.binetflow: C2_BEACONING 54 (0 on attack hosts); DATA_EXFILTRATION 2 (0 on attack hosts); DDOS_VOLUMETRIC 2 (0 on attack hosts); PORT_SCAN 3 (3 on attack hosts)
- scenario12_capture20110819.binetflow: C2_BEACONING 208 (0 on attack hosts); DATA_EXFILTRATION 88 (0 on attack hosts); HOST_SCAN 3 (2 on attack hosts); PORT_SCAN 14 (3 on attack hosts)
- scenario5_capture20110815-2.binetflow: C2_BEACONING 40 (0 on attack hosts); DATA_EXFILTRATION 4 (1 on attack hosts); HOST_SCAN 2 (0 on attack hosts)
- scenario6_capture20110816.binetflow: BRUTE_FORCE 1 (0 on attack hosts); C2_BEACONING 396 (4 on attack hosts); DATA_EXFILTRATION 81 (0 on attack hosts); DDOS_VOLUMETRIC 1 (0 on attack hosts); HOST_SCAN 10 (0 on attack hosts); PORT_SCAN 69 (0 on attack hosts); SPAM_ACTIVITY 9 (9 on attack hosts)
- scenario7_capture20110816-2.binetflow: BRUTE_FORCE 1 (0 on attack hosts); C2_BEACONING 30 (0 on attack hosts); DATA_EXFILTRATION 28 (0 on attack hosts); DDOS_VOLUMETRIC 5 (0 on attack hosts); HOST_SCAN 3 (0 on attack hosts); PORT_SCAN 18 (0 on attack hosts)

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

### Site tuning (leave one file out, percentile 99.9)

Learning mode, without an asset inventory, with attack-labelled flows removed from the learning traffic (standing in for an attack-free learning period); an evaluated file never influences its own thresholds.

| File | Hosts detected (default → tuned) | Alerts | Alerts on attack hosts | Host-level precision | Other hosts named |
|---|---|---|---|---|---|
| scenario11_capture20110818-2.binetflow | 3/3 → 0/3 | 61 → 18 | 3 → 0 | 0.049 → 0.000 | 70 → 30 |
| scenario12_capture20110819.binetflow | 3/9 → 0/9 | 313 → 139 | 5 → 0 | 0.016 → 0.000 | 199 → 84 |
| scenario5_capture20110815-2.binetflow | 1/1 → 0/1 | 46 → 28 | 1 → 0 | 0.022 → 0.000 | 40 → 27 |
| scenario6_capture20110816.binetflow | 1/1 → 1/1 | 567 → 199 | 13 → 11 | 0.023 → 0.055 | 197 → 103 |
| scenario7_capture20110816-2.binetflow | 0/1 → 0/1 | 85 → 23 | 0 → 0 | 0.000 → 0.000 | 71 → 33 |

Thresholds changed by learning (held-out file: key default → learned):

- scenario11_capture20110818-2.binetflow: ddos.packets_per_second 10000 → 18374; scanning.unique_dest_ports 25 → 425; scanning.horizontal_scan_hosts 20 → 87; scanning.horizontal_scan_hosts_any 50 → 152; scanning.burst_connections 30 → 300; exfiltration.min_upload_mb 5 → 89.3; exfiltration.baseline_deviation_sigma 3.5 → 1550.0; beaconing.regularity_cv_threshold 0.3 → 0.05; statistical.mad_threshold 3.5 → 2670.0
- scenario12_capture20110819.binetflow: ddos.packets_per_second 10000 → 20719; scanning.unique_dest_ports 25 → 428; scanning.horizontal_scan_hosts 20 → 96; scanning.horizontal_scan_hosts_any 50 → 156; scanning.burst_connections 30 → 104; exfiltration.min_upload_mb 5 → 57.2; exfiltration.baseline_deviation_sigma 3.5 → 1210.0; beaconing.regularity_cv_threshold 0.3 → 0.05; statistical.mad_threshold 3.5 → 819.0
- scenario5_capture20110815-2.binetflow: ddos.packets_per_second 10000 → 20719; scanning.unique_dest_ports 25 → 428; scanning.horizontal_scan_hosts 20 → 96; scanning.horizontal_scan_hosts_any 50 → 156; scanning.burst_connections 30 → 300; exfiltration.min_upload_mb 5 → 89.3; exfiltration.baseline_deviation_sigma 3.5 → 2340.0; beaconing.regularity_cv_threshold 0.3 → 0.05; statistical.mad_threshold 3.5 → 1440.0
- scenario6_capture20110816.binetflow: ddos.packets_per_second 10000 → 23387; scanning.unique_dest_ports 25 → 300; scanning.horizontal_scan_hosts 20 → 29; scanning.horizontal_scan_hosts_any 50 → 159; scanning.burst_connections 30 → 300; exfiltration.min_upload_mb 5 → 518; exfiltration.baseline_deviation_sigma 3.5 → 6990.0; beaconing.regularity_cv_threshold 0.3 → 0.05; statistical.mad_threshold 3.5 → 220.0
- scenario7_capture20110816-2.binetflow: ddos.packets_per_second 10000 → 19788; scanning.unique_dest_ports 25 → 425; scanning.horizontal_scan_hosts 20 → 87; scanning.horizontal_scan_hosts_any 50 → 141; scanning.burst_connections 30 → 300; exfiltration.min_upload_mb 5 → 89.3; exfiltration.baseline_deviation_sigma 3.5 → 1550.0; beaconing.regularity_cv_threshold 0.3 → 0.05; statistical.mad_threshold 3.5 → 2260.0

### With an asset inventory (`configs/evaluation/ctu13_assets.yaml`)

Roles taken from the dataset's published description (CIC-IDS2017) or seen in the traffic (CTU-13); only roles an operator would know. With site tuning the inventory is also used while learning.

| File | Hosts: default / +assets / tuned / tuned+assets | Alerts: default / +assets / tuned / tuned+assets | Host-level precision: default / +assets / tuned / tuned+assets |
|---|---|---|---|
| scenario11_capture20110818-2.binetflow | 3/3 / 3/3 / 0/3 / 0/3 | 61 / 61 / 18 / 18 | 0.049 / 0.049 / 0.000 / 0.000 |
| scenario12_capture20110819.binetflow | 3/9 / 3/9 / 0/9 / 0/9 | 313 / 313 / 139 / 139 | 0.016 / 0.016 / 0.000 / 0.000 |
| scenario5_capture20110815-2.binetflow | 1/1 / 1/1 / 0/1 / 0/1 | 46 / 46 / 28 / 28 | 0.022 / 0.022 / 0.000 / 0.000 |
| scenario6_capture20110816.binetflow | 1/1 / 1/1 / 1/1 / 1/1 | 567 / 567 / 199 / 199 | 0.023 / 0.023 / 0.055 / 0.055 |
| scenario7_capture20110816-2.binetflow | 0/1 / 0/1 / 0/1 / 0/1 | 85 / 85 / 23 / 23 | 0.000 / 0.000 / 0.000 / 0.000 |

No alert was changed by the inventory's roles: the listed roles (DNS resolver, server) only act on DNS-based alerts, and these flow records carry no DNS names.

### Caveats

- Background flows are unverified university traffic and are counted as benign; some may be malicious or misconfigured, so 'other hosts named' is an upper bound on false positives.
- Botnet flows mix C2, spam, scanning and DDoS and are labelled BOTNET; window labels are binary here, so class-level accuracy is not measured.
- Argus exports have no DNS names or TLS fields, so the DNS and encrypted-session detectors cannot fire.
- Timestamps are local capture time read as UTC (consistent within a file).
- Findings from inspecting the first 2026-10 run (before the spam and brute-force rules were added): scenario 6's bot sends spam (4,398 failed SMTP attempts to at most 15 mail servers per 10 s, under the 20-host HOST_SCAN threshold; UniShield has no spam rule) and was caught only by its C2 beacon after about 6,300 s; scenario 7's bot made 63 flows in 21 minutes, too few for any rule; scenario 11's ICMP flood reaches only about 60 packets/s at the capture point, far below the 10,000 packets/s volumetric threshold.
- Most other alerts name hosts inside 147.32.0.0/16: regular polling and peer-to-peer traffic (HTTP, SSH attempts, BitTorrent, POP3 were seen behind beacon alerts) raises C2_BEACONING, large uploads raise DATA_EXFILTRATION, and failed connection bursts raise PORT_SCAN. Default thresholds were tuned on synthetic traffic. Learning mode is evaluated below (no asset inventory); CTU-13 background traffic is not a clean learning baseline.

## CIC-IDS2017 (Canadian Institute for Cybersecurity)

Five days of benign and attack traffic in a lab network, as CICFlowMeter flows (TrafficLabelling CSVs).

Home networks used for direction: 192.168.10.0/24.

| File | Records (late-dropped) | Hours | Attack flows | Windows (attack) | Attack hosts detected | Alerts (involving attack hosts) | Other hosts named | First-alert delay (s) |
|---|---|---|---|---|---|---|---|---|
| Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv | 225,745 (0) | 1.55 | 128,027 | 1,117 (211) | 2/2 | 155 (40) | 8 | 59.8, 59.8 |
| Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv | 286,467 (0) | 2.5 | 158,930 | 1,801 (214) | 2/2 | 173 (48) | 14 | 2471.1, 3311.1 |
| Friday-WorkingHours-Morning.pcap_ISCX.csv | 191,033 (0) | 4.02 | 1,966 | 2,885 (892) | 7/10 | 469 (162) | 23 | 169.2, 220.2, 569.4, 1643.9, 2923.8 |
| Monday-WorkingHours.pcap_ISCX.csv | 529,918 (0) | 8.09 | 0 | 5,824 (0) | 0/0 | 1093 (0) | 139 | – |
| Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv | 288,602 (0) | 4.08 | 36 | 2,941 (70) | 2/2 | 325 (69) | 11 | 589.9, 589.9 |
| Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv | 170,366 (0) | 4.02 | 2,180 | 2,893 (688) | 1/2 | 513 (34) | 52 | 1448.1 |
| Tuesday-WorkingHours.pcap_ISCX.csv | 445,909 (0) | 8.13 | 13,835 | 5,847 (391) | 2/2 | 1163 (159) | 66 | 115.9, 115.9 |
| Wednesday-workingHours.pcap_ISCX.csv | 692,703 (0) | 8.47 | 252,672 | 6,088 (519) | 3/3 | 939 (170) | 65 | 1797.1, 2729.4, 2882.1 |

### Window level (default rules)

| File | Approach | Precision | Recall | F1 | FPR |
|---|---|---|---|---|---|
| Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv | rules | 0.374 | 0.332 | 0.352 | 0.129 |
| Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv | rules_statistical | 0.412 | 1.000 | 0.584 | 0.332 |
| Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv | rules | 0.449 | 0.692 | 0.544 | 0.115 |
| Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv | rules_statistical | 0.226 | 0.818 | 0.355 | 0.377 |
| Friday-WorkingHours-Morning.pcap_ISCX.csv | rules | 0.401 | 0.396 | 0.398 | 0.265 |
| Friday-WorkingHours-Morning.pcap_ISCX.csv | rules_statistical | 0.337 | 0.475 | 0.394 | 0.419 |
| Monday-WorkingHours.pcap_ISCX.csv | rules | 0.000 | 0.000 | 0.000 | 0.370 |
| Monday-WorkingHours.pcap_ISCX.csv | rules_statistical | 0.000 | 0.000 | 0.000 | 0.587 |
| Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv | rules | 0.080 | 0.700 | 0.144 | 0.195 |
| Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv | rules_statistical | 0.047 | 0.857 | 0.088 | 0.428 |
| Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv | rules | 0.522 | 0.565 | 0.543 | 0.162 |
| Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv | rules_statistical | 0.315 | 0.666 | 0.427 | 0.453 |
| Tuesday-WorkingHours.pcap_ISCX.csv | rules | 0.338 | 0.987 | 0.504 | 0.139 |
| Tuesday-WorkingHours.pcap_ISCX.csv | rules_statistical | 0.126 | 0.992 | 0.223 | 0.495 |
| Wednesday-workingHours.pcap_ISCX.csv | rules | 0.147 | 0.235 | 0.181 | 0.128 |
| Wednesday-workingHours.pcap_ISCX.csv | rules_statistical | 0.160 | 0.807 | 0.268 | 0.394 |

### Alerts by class

- Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv: C2_BEACONING 31 (19 on attack hosts); DATA_EXFILTRATION 3 (3 on attack hosts); HOST_SCAN 10 (0 on attack hosts); RECONNAISSANCE 20 (18 on attack hosts); STATISTICAL_ANOMALY 91 (0 on attack hosts)
- Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv: BRUTE_FORCE 2 (2 on attack hosts); C2_BEACONING 55 (32 on attack hosts); DATA_EXFILTRATION 1 (0 on attack hosts); HOST_SCAN 14 (0 on attack hosts); PORT_SCAN 14 (14 on attack hosts); RECONNAISSANCE 1 (0 on attack hosts); STATISTICAL_ANOMALY 86 (0 on attack hosts)
- Friday-WorkingHours-Morning.pcap_ISCX.csv: C2_BEACONING 340 (146 on attack hosts); HOST_SCAN 16 (14 on attack hosts); PORT_SCAN 1 (0 on attack hosts); RECONNAISSANCE 3 (2 on attack hosts); STATISTICAL_ANOMALY 109 (0 on attack hosts)
- Monday-WorkingHours.pcap_ISCX.csv: C2_BEACONING 570 (0 on attack hosts); DATA_EXFILTRATION 5 (0 on attack hosts); HOST_SCAN 210 (0 on attack hosts); PORT_SCAN 1 (0 on attack hosts); RECONNAISSANCE 7 (0 on attack hosts); STATISTICAL_ANOMALY 300 (0 on attack hosts)
- Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv: BRUTE_FORCE 12 (12 on attack hosts); C2_BEACONING 64 (1 on attack hosts); DATA_EXFILTRATION 3 (2 on attack hosts); HOST_SCAN 30 (4 on attack hosts); PORT_SCAN 51 (50 on attack hosts); RECONNAISSANCE 1 (0 on attack hosts); STATISTICAL_ANOMALY 164 (0 on attack hosts)
- Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv: C2_BEACONING 309 (34 on attack hosts); HOST_SCAN 21 (0 on attack hosts); PORT_SCAN 1 (0 on attack hosts); STATISTICAL_ANOMALY 182 (0 on attack hosts)
- Tuesday-WorkingHours.pcap_ISCX.csv: BRUTE_FORCE 13 (13 on attack hosts); C2_BEACONING 373 (146 on attack hosts); DATA_EXFILTRATION 7 (0 on attack hosts); DDOS_VOLUMETRIC 2 (0 on attack hosts); HOST_SCAN 109 (0 on attack hosts); PORT_SCAN 1 (0 on attack hosts); RECONNAISSANCE 1 (0 on attack hosts); STATISTICAL_ANOMALY 657 (0 on attack hosts)
- Wednesday-workingHours.pcap_ISCX.csv: C2_BEACONING 376 (140 on attack hosts); DATA_EXFILTRATION 10 (2 on attack hosts); HOST_SCAN 103 (5 on attack hosts); PORT_SCAN 1 (1 on attack hosts); RECONNAISSANCE 29 (22 on attack hosts); STATISTICAL_ANOMALY 420 (0 on attack hosts)

### Synthetic-trained random forest on these windows (cross-domain)

PR-AUC 0.142, ROC-AUC 0.563; at P ≥ 0.5: precision 0.137, recall 0.309; at P ≥ 0.9: precision 0.333, recall 0.060.

### Random forest trained on the other files, tested on each (unseen attack)

| Held-out file | PR-AUC | ROC-AUC | Precision@0.5 | Recall@0.5 | FPR@0.5 | Recall@0.9 |
|---|---|---|---|---|---|---|
| Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv | 0.971 | 0.986 | 0.851 | 0.891 | 0.036 | 0.446 |
| Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv | 0.486 | 0.782 | 0.844 | 0.252 | 0.006 | 0.000 |
| Friday-WorkingHours-Morning.pcap_ISCX.csv | 0.327 | 0.524 | 0.067 | 0.002 | 0.014 | 0.000 |
| Monday-WorkingHours.pcap_ISCX.csv | – | – | 0.000 | 0.000 | 0.015 | 0.000 |
| Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv | 0.045 | 0.693 | 0.054 | 0.229 | 0.098 | 0.014 |
| Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv | 0.332 | 0.666 | 0.000 | 0.000 | 0.002 | 0.000 |
| Tuesday-WorkingHours.pcap_ISCX.csv | 0.562 | 0.841 | 0.958 | 0.235 | 0.001 | 0.000 |
| Wednesday-workingHours.pcap_ISCX.csv | 0.853 | 0.957 | 0.980 | 0.568 | 0.001 | 0.006 |

### Site tuning (learned once from Monday-WorkingHours.pcap_ISCX.csv, percentile 99.9)

Learning mode, without an asset inventory, with attack-labelled flows removed from the learning traffic (standing in for an attack-free learning period); an evaluated file never influences its own thresholds.

| File | Hosts detected (default → tuned) | Alerts | Alerts on attack hosts | Host-level precision | Other hosts named |
|---|---|---|---|---|---|
| Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv | 2/2 → 2/2 | 155 → 24 | 40 → 23 | 0.258 → 0.958 | 8 → 0 |
| Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv | 2/2 → 2/2 | 173 → 35 | 48 → 34 | 0.278 → 0.971 | 14 → 2 |
| Friday-WorkingHours-Morning.pcap_ISCX.csv | 7/10 → 2/10 | 469 → 30 | 162 → 15 | 0.345 → 0.500 | 23 → 5 |
| Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv | 2/2 → 2/2 | 325 → 84 | 69 → 64 | 0.212 → 0.762 | 11 → 2 |
| Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv | 1/2 → 0/2 | 513 → 13 | 34 → 0 | 0.066 → 0.000 | 52 → 9 |
| Tuesday-WorkingHours.pcap_ISCX.csv | 2/2 → 2/2 | 1163 → 115 | 159 → 96 | 0.137 → 0.835 | 66 → 20 |
| Wednesday-workingHours.pcap_ISCX.csv | 3/3 → 3/3 | 939 → 111 | 170 → 87 | 0.181 → 0.784 | 65 → 15 |

Thresholds changed by learning (held-out file: key default → learned):

- Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv: scanning.horizontal_scan_hosts 20 → 50; scanning.horizontal_scan_hosts_any 50 → 185; scanning.burst_connections 30 → 89; beaconing.regularity_cv_threshold 0.3 → 0.05; statistical.mad_threshold 3.5 → 2330.0; anomaly.min_score 0.6 → 0.676
- Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv: scanning.horizontal_scan_hosts 20 → 50; scanning.horizontal_scan_hosts_any 50 → 185; scanning.burst_connections 30 → 89; beaconing.regularity_cv_threshold 0.3 → 0.05; statistical.mad_threshold 3.5 → 2330.0; anomaly.min_score 0.6 → 0.676
- Friday-WorkingHours-Morning.pcap_ISCX.csv: scanning.horizontal_scan_hosts 20 → 50; scanning.horizontal_scan_hosts_any 50 → 185; scanning.burst_connections 30 → 89; beaconing.regularity_cv_threshold 0.3 → 0.05; statistical.mad_threshold 3.5 → 2330.0; anomaly.min_score 0.6 → 0.676
- Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv: scanning.horizontal_scan_hosts 20 → 50; scanning.horizontal_scan_hosts_any 50 → 185; scanning.burst_connections 30 → 89; beaconing.regularity_cv_threshold 0.3 → 0.05; statistical.mad_threshold 3.5 → 2330.0; anomaly.min_score 0.6 → 0.676
- Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv: scanning.horizontal_scan_hosts 20 → 50; scanning.horizontal_scan_hosts_any 50 → 185; scanning.burst_connections 30 → 89; beaconing.regularity_cv_threshold 0.3 → 0.05; statistical.mad_threshold 3.5 → 2330.0; anomaly.min_score 0.6 → 0.676
- Tuesday-WorkingHours.pcap_ISCX.csv: scanning.horizontal_scan_hosts 20 → 50; scanning.horizontal_scan_hosts_any 50 → 185; scanning.burst_connections 30 → 89; beaconing.regularity_cv_threshold 0.3 → 0.05; statistical.mad_threshold 3.5 → 2330.0; anomaly.min_score 0.6 → 0.676
- Wednesday-workingHours.pcap_ISCX.csv: scanning.horizontal_scan_hosts 20 → 50; scanning.horizontal_scan_hosts_any 50 → 185; scanning.burst_connections 30 → 89; beaconing.regularity_cv_threshold 0.3 → 0.05; statistical.mad_threshold 3.5 → 2330.0; anomaly.min_score 0.6 → 0.676

### With an asset inventory (`configs/evaluation/cicids2017_assets.yaml`)

Roles taken from the dataset's published description (CIC-IDS2017) or seen in the traffic (CTU-13); only roles an operator would know. With site tuning the inventory is also used while learning.

| File | Hosts: default / +assets / tuned / tuned+assets | Alerts: default / +assets / tuned / tuned+assets | Host-level precision: default / +assets / tuned / tuned+assets |
|---|---|---|---|
| Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv | 2/2 / 2/2 / 2/2 / 2/2 | 155 / 155 / 24 / 24 | 0.258 / 0.258 / 0.958 / 0.958 |
| Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv | 2/2 / 2/2 / 2/2 / 2/2 | 173 / 173 / 35 / 35 | 0.278 / 0.278 / 0.971 / 0.971 |
| Friday-WorkingHours-Morning.pcap_ISCX.csv | 7/10 / 7/10 / 2/10 / 2/10 | 469 / 469 / 30 / 30 | 0.345 / 0.345 / 0.500 / 0.500 |
| Monday-WorkingHours.pcap_ISCX.csv | 0/0 / 0/0 / – / – | 1093 / 1093 / – / – | 0.000 / 0.000 / – / – |
| Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv | 2/2 / 2/2 / 2/2 / 2/2 | 325 / 325 / 84 / 84 | 0.212 / 0.212 / 0.762 / 0.762 |
| Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv | 1/2 / 1/2 / 0/2 / 0/2 | 513 / 513 / 13 / 13 | 0.066 / 0.066 / 0.000 / 0.000 |
| Tuesday-WorkingHours.pcap_ISCX.csv | 2/2 / 2/2 / 2/2 / 2/2 | 1163 / 1163 / 115 / 115 | 0.137 / 0.137 / 0.835 / 0.835 |
| Wednesday-workingHours.pcap_ISCX.csv | 3/3 / 3/3 / 3/3 / 3/3 | 939 / 939 / 111 / 111 | 0.181 / 0.181 / 0.784 / 0.784 |

No alert was changed by the inventory's roles: the listed roles (DNS resolver, server) only act on DNS-based alerts, and these flow records carry no DNS names.

### Caveats

- Published analyses report labelling and flow-construction errors in CIC-IDS2017.
- Timestamps are local lab time. Some files write afternoon times as 1:00-5:00 without AM/PM; hours before 08:00 are read as PM (lab hours 08:00-17:00).
- Seven of the eight files have minute-resolution timestamps; for this evaluation each minute's flows are spread evenly over the minute in file order, so they are not analysed as one burst. Rates inside a minute are therefore approximate.
- CICFlowMeter flows carry no DNS names or TLS fields, so the DNS and encrypted-session detectors cannot fire.
- Attack hosts are both ends of every attack-labelled flow (attackers and victims); an alert counts for an attack host only from that host's first attack flow on.
- Several files are not written in time order; each is analysed as a time-sorted copy (stable within a minute), so event-time windows do not drop out-of-order rows.

