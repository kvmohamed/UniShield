# UniShield — Datasets

## What was used

All results in `reports/` come from **synthetic, labelled traffic generated
locally** by `unishield.data.sample_generator`. No public dataset was
downloaded for this prototype, and no production or unauthorised traffic was
used.

### Seeded scenario generator

`build_scenario(name, seed)` returns deterministic flows with a per-flow
`label` and the threat classes the scenario should raise:

| Scenario | Content | Expected classes |
|---|---|---|
| `benign_hard` | benign traffic built to trip naive rules: quiet gaps, a 20 MB download, 25 CDN connections, 40 connections to one server, a 60-lookup DNS burst, a 300-client flash crowd | none |
| `ddos_syn` | background + distributed SYN flood | SYN_FLOOD |
| `ddos_udp` | background + UDP botnet flood | UDP_FLOOD, DDOS_VOLUMETRIC |
| `port_scan` | background + TCP SYN port scan | PORT_SCAN |
| `host_sweep` | background + SSH sweep of a /24 | HOST_SCAN |
| `beacon_30s`, `beacon_60s` | 15/20 minutes of background + HTTPS beacon with 5 % jitter | C2_BEACONING |
| `exfil_episodes` | 30 minutes of background + three upload episodes 12 minutes apart | DATA_EXFILTRATION |
| `dga` | background + a host resolving random-looking domains (mostly NXDOMAIN) | DGA_DETECTED |
| `dns_tunnel` | background + base32-like data in subdomains of one domain, mostly TXT | DNS_TUNNELLING |
| `encrypted_anomaly` | background + a TLS 1.0 client and a one-hour low-rate TLS session on port 4443 | ENCRYPTED_SESSION_ANOMALY |

Benign and attack sessions on TLS ports carry TLS 1.2/1.3 metadata and one of
a few client JA3 values, so that TLS presence alone does not separate the
classes (an earlier version leaked the label this way; the ablation exposed
it).

### Window dataset

`scripts/prepare_dataset.py --synthetic --seeds 1-20` runs the real pipeline
over 11 scenarios × 20 seeds (220 runs) and writes one row per analysed
window to `data/processed/windows_synthetic.csv` with a manifest containing
its SHA-256:

- 18,444 windows; 15,240 benign, 3,204 containing attack traffic
  (C2_BEACONING 1,720, DATA_EXFILTRATION 847, PORT_SCAN 159,
  ENCRYPTED_SESSION_ANOMALY 158, DGA_DETECTED 80, DNS_TUNNELLING 80,
  UDP_FLOOD 60, HOST_SCAN 60, SYN_FLOOD 40)
- 75 model features (log1p-scaled) in six extractor groups
- label = most common attack label among the window's flows, else BENIGN
- what the rule stage raised or suppressed and what the post-rule detectors
  raised, so rules can be evaluated on exactly the same windows

Splits are made **by run** (60 % train / 20 % calibration / 20 % test,
stratified by scenario type), because windows overlap and windows of one run
must not appear on both sides.

### Sample input files

`scripts/make_samples.py` writes small files with known contents to
`data/samples/` (benign PCAP/PCAPNG with ground-truth flows, a 200-port scan
PCAP, a 3,000-packet SYN-flood PCAP, Zeek JSON and TSV logs, flow CSV/JSONL
and a CICIDS2017-style CSV). Packets are written to files with scapy; none is
sent.

## Public datasets (supported, not evaluated)

The readers accept the formats of common research datasets, and
`normalise_label` maps their labels to UniShield classes:

| Dataset | Input | Label mapping |
|---|---|---|
| CICIDS2017 / CSE-CIC-IDS2018 | flow CSV (detected automatically) | DDoS → DDOS_VOLUMETRIC, DoS * → DDOS_PROTOCOL, PortScan → PORT_SCAN, Bot → C2_BEACONING, Infiltration → DATA_EXFILTRATION, others → ATTACK |
| CTU-13 | binetflow labels | `flow=From-Botnet…` → C2_BEACONING, background/normal → BENIGN |
| Any Zeek deployment | `conn.log` (+`dns.log`, `ssl.log`) | needs a `label` field for evaluation |

```bash
python scripts/prepare_dataset.py --input data/raw/Friday-WorkingHours.csv --out data/processed/windows_cic.csv
python scripts/evaluate_models.py --dataset data/processed/windows_cic.csv
```

Download such datasets only from their official sources and under their
licences, and keep them in `data/raw/` (git-ignored).
