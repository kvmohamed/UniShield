# UniShield — Data Directory

This directory holds traffic data for analysis.

## Structure

```
data/
├── raw/          # Original PCAP files, Zeek logs, flow records
├── processed/    # Normalised flow records (Parquet, JSON)
├── samples/      # Small sample files for testing and demos
└── README.md     # This file
```

## Security

- Only use **authorised datasets** and **isolated lab traffic**.
- Public datasets (e.g. CICIDS, CTU-13, UNSW-NB15) are acceptable.
- Never include live production traffic without authorisation.
- Never include malware samples or credential dumps.

## Supported Formats

| Format      | Extension      | Reader            |
|-------------|----------------|-------------------|
| PCAP        | `.pcap`        | `pcap_reader.py`  |
| PCAPNG      | `.pcapng`      | `pcap_reader.py`  |
| Zeek JSON   | `.json`        | `zeek_reader.py`  |
| Flow CSV    | `.csv`         | `flow_reader.py`  |
| Flow JSON   | `.json`        | `flow_reader.py`  |

## Anonymisation

When `anonymize_ips: true` is set in `configs/config.yaml`, IP addresses
are hashed before processing. This affects correlation and evaluation
accuracy — document this in experiment reports.
