# UniShield — Threat Model

## Setting

UniShield monitors a one-way (unidirectional) network from its receiving
side. It sees copies of traffic — capture files, Zeek logs or flow exports —
and can only report. It must never probe, send packets into, complete
handshakes with, connect back into, block, or decrypt anything in the
monitored network.

## Assets and adversaries

- **Monitored network**: hosts behind the one-way link. Adversaries are
  external attackers (floods, scans) and compromised internal hosts
  (beaconing to command-and-control, exfiltration, DGA, DNS tunnelling,
  unusual encrypted sessions).
- **UniShield itself**: its API, stored alerts and models. Adversaries are
  anyone who can reach the API or tamper with its files.

## Detected behaviours

| Class | ATT&CK | Evidence used | Not seen |
|---|---|---|---|
| SYN_FLOOD, UDP_FLOOD, DDOS_VOLUMETRIC | T1498, T1498.001, T1499.001 | per-destination peak packet/SYN/UDP rates, SYN-only ratio, number of sources | application-layer floods that look like normal requests |
| PORT_SCAN, HOST_SCAN | T1046, T1595.001 | per-source connection attempts across ports/hosts, failure ratio | very slow scans spread over more than the tracked history |
| C2_BEACONING | T1071 (+T1573 over TLS) | regular inter-arrival times to one destination over many windows | beacons with heavy jitter or long sleep times |
| DATA_EXFILTRATION | T1041, T1048 (+T1573, T1571) | upload volume and ratio, deviation from the source's own baseline, long upload sessions, rare destinations | slow "low and slow" uploads below the baseline noise |
| DGA_DETECTED | T1568.002 | many generated-looking registrable domains from one client, NXDOMAIN share | dictionary-word DGAs |
| DNS_TUNNELLING | T1071.004, T1572 | many unique long/high-entropy subdomains of one base domain, TXT/NULL share | low-rate tunnels with short labels |
| ENCRYPTED_SESSION_ANOMALY | T1573 (+T1571) | outdated TLS versions, JA3 on an operator blocklist, long low-rate sessions on unusual ports | anything inside the encrypted payload (never decrypted) |
| STATISTICAL_ANOMALY | — | window metrics far from a vetted baseline; Isolation Forest | the cause: these are leads, not attributions |

Wording for encrypted traffic is deliberately cautious: "suspicious
encrypted-session behaviour", never a claim of malware.

## Threats to UniShield and mitigations

| Threat | Mitigation |
|---|---|
| Unauthorised use of state-changing endpoints | `X-API-Key` (constant-time compare) when `UNISHIELD_ADMIN_API_KEY` is set; loopback-only otherwise; read endpoints are side-effect free (tested) |
| Reading arbitrary files through replay | Allow-list of data directories checked before existence; NUL bytes and over-long paths rejected; size limit |
| SQL injection | All queries are SQLAlchemy expressions with bound parameters; filters are validated (patterns, enums, ranges) |
| Stored XSS via alert fields | Dashboard inserts all data with `textContent`; strict same-origin CSP; static test for HTML sinks |
| Tampered model files (joblib is pickle) | Registry refuses artifacts whose SHA-256 differs from the training metadata; only load models this installation trained |
| Resource exhaustion from input | Bounded windows, sessionizer active-flow cap, bounded per-pair and per-source state, file size limit |
| Leaking the admin key | Key only from the environment, excluded from `repr`, never returned by any endpoint (tested) |
| Accidental active behaviour in code | `scripts/verify_passive_mode.py`: AST scan for network/process/crypto capabilities and a runtime tripwire around sockets and scapy send/capture |

## Out of scope

Live capture from interfaces, payload inspection, response or blocking,
multi-tenant access control, and protection against an attacker with write
access to the host.
