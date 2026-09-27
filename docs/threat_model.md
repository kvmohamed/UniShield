# UniShield — Threat Model

## Scope

UniShield detects threats in unidirectional IP traffic using metadata-only
analysis. The system monitors passively and never interacts with the network.

## MVP Threat Classes

### A. Volumetric / Protocol DDoS
- **MITRE**: T1498 (Network Denial of Service), T1499 (Endpoint DoS)
- **Indicators**: SYN flood, UDP flood, high PPS/BPS, SYN/ACK imbalance,
  source-IP entropy, destination concentration, unique source count
- **Detection layers**: Rules + Statistical + ML

### B. Reconnaissance / Port Scanning
- **MITRE**: T1046 (Network Service Scanning)
- **Indicators**: Unique destination ports, unique destination hosts,
  fan-out score, failed connection ratio, connection bursts
- **Detection layers**: Rules + Statistical + ML

### C. C2 Beaconing
- **MITRE**: T1071 (Application Layer Protocol), T1573 (Encrypted Channel)
- **Indicators**: Repeated connections, inter-arrival time regularity,
  coefficient of variation, periodicity score, destination rarity,
  packet size patterns
- **Detection layers**: Statistical + ML

### D. Data Exfiltration
- **MITRE**: T1048 (Exfiltration Over Alternative Protocol), T1041 (Exfiltration Over C2)
- **Indicators**: Outbound/inbound byte ratio, long sessions, unusual volume,
  destination rarity, burst size, protocol/port rarity, baseline deviation
- **Detection layers**: Statistical + ML

## Advanced Threat Classes (Post-MVP)

### E. DGA / DNS Tunnelling
- **MITRE**: T1568.002 (Domain Generation Algorithms), T1071.004 (DNS)
- **Indicators**: Query length, domain entropy, n-gram analysis, NXDOMAIN ratio

### F. Encrypted Session Anomaly
- **Note**: Analysis is probabilistic. Does NOT prove malware.
- **Indicators**: TLS version, cipher metadata, JA3/JA4, packet sequences

## Limitations

- Metadata-only analysis cannot detect threats visible only in payload content
- Encrypted traffic analysis is indicative, not definitive
- Threshold-based detection requires per-environment tuning
- No active response or mitigation capability
