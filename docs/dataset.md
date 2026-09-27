# UniShield — Dataset Documentation

## Recommended Public Datasets

| Dataset | Source | Attacks | License |
|---|---|---|---|
| CICIDS 2017 | Canadian Institute for Cybersecurity | DDoS, Port Scan, Brute Force | Research |
| CTU-13 | Czech Technical University | Botnets, C2 | Research |
| UNSW-NB15 | UNSW Sydney | Multiple | Research |
| CIC-DDoS2019 | CIC | DDoS variants | Research |

## Data Format Requirements

All input data must be in one of:
- PCAP / PCAPNG files
- Zeek JSON logs
- Flow CSV with standard columns
- Flow JSON records

## Anonymisation

When `anonymize_ips: true` is set, IP addresses are hashed with a
configurable salt. This affects correlation accuracy and must be
documented in experiment reports.
