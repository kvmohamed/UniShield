# UniShield — Threat Model

## Setting

UniShield monitors a one-way (unidirectional) network from its receiving
side. It sees copies of traffic — capture files, Zeek logs or flow exports —
and can only report. It must never probe, send packets into, complete
handshakes with, connect back into, block, or decrypt anything in the
monitored network.

Analysts work on a separate **analyst network**. UniShield can optionally
deliver alerts there (syslog to a SIEM, email to a relay, JSON webhooks) and
write export files. That outbound path is described in its own section
below; it never points at the monitored network.

## Assets and adversaries

- **Monitored network**: hosts behind the one-way link. Adversaries are
  external attackers (floods, scans) and compromised internal hosts
  (beaconing to command-and-control, exfiltration, DGA, DNS tunnelling,
  unusual encrypted sessions, contact with known-bad infrastructure).
- **UniShield itself**: its API, stored alerts, imported threat
  intelligence, models and outbound credentials. Adversaries are anyone who
  can reach the API, tamper with its files or input, or sit on the analyst
  network between UniShield and its destinations.
- **The one-way property**: an attacker who controls monitored traffic must
  not be able to make UniShield send anything back into the monitored
  network.

## Detected behaviours

| Class | ATT&CK | Evidence used | Not seen |
|---|---|---|---|
| SYN_FLOOD, UDP_FLOOD, DDOS_VOLUMETRIC | T1498, T1498.001, T1499.001 | per-destination peak packet/SYN/UDP rates, SYN-only ratio, number of sources | application-layer floods that look like normal requests |
| PORT_SCAN, HOST_SCAN | T1046, T1595.001 | per-source connection attempts across ports/hosts, failure ratio | very slow scans spread over more than the tracked history |
| C2_BEACONING | T1071 (+T1573 over TLS) | regular inter-arrival times to one destination over many windows | beacons with heavy jitter or long sleep times |
| DATA_EXFILTRATION | T1041, T1048 (+T1573, T1571) | upload volume and ratio, deviation from the source's own baseline, long upload sessions, rare destinations | slow "low and slow" uploads below the baseline noise |
| DGA_DETECTED | T1568.002 | many generated-looking registrable domains from one client, NXDOMAIN share | dictionary-word DGAs |
| DNS_TUNNELLING | T1071.004, T1572 | many unique long/high-entropy subdomains of one base domain, TXT/NULL share | low-rate tunnels with short labels |
| ENCRYPTED_SESSION_ANOMALY | T1573 (+T1571) | outdated TLS versions, JA3 on an operator blocklist or imported list, long low-rate sessions on unusual ports | anything inside the encrypted payload (never decrypted) |
| INTEL_MATCH | none by default; techniques listed with the indicator | an address, network, domain (or subdomain) on an imported list in a flow or DNS query | infrastructure not on the lists; stale or wrong list entries |
| STATISTICAL_ANOMALY | — | window metrics far from a vetted baseline; Isolation Forest | the cause: these are leads, not attributions |

Wording for encrypted traffic is deliberately cautious: "suspicious
encrypted-session behaviour", never a claim of malware. Intel matches state
which list named the indicator; their confidence is a list-match score.

## Outbound path (analyst side)

**What can leave the host**: alert and incident records — as files in
`export.directory`, as syslog messages, as notification emails or webhook
JSON. For notifications only the configured fields (never raw evidence);
optionally with addresses redacted. Nothing else: no packets, no captures,
no payloads, no requests to the monitored network, no internet lookups.

**Where it may go**: only to destinations listed in
`outbound.allowed_destinations` that lie outside `network.home_networks`.

**How this is enforced**

1. *One module.* `unishield/export/transport.py` is the only module with
   network capability. The static scan allows exactly its
   socket/ssl/smtplib/http.client imports and connect/send calls and flags
   anything else, there or anywhere else.
2. *Config load.* Allow-list entries overlapping the monitored network,
   destinations not on the allow-list and destinations inside the monitored
   network stop the configuration from loading. Outbound delivery requires
   `home_networks` to be set; with the default (all private ranges) private
   analyst addresses are refused, so the safe failure is "nothing is sent".
3. *Send time.* Before any lookup the host is checked again; listed names
   are resolved and every returned address must be outside the monitored
   network (IPv4-mapped IPv6 included); the connection goes to the checked
   address, so a later DNS answer cannot redirect it. No proxies (environment
   variables are not consulted) and no HTTP redirects.
4. *Runtime verification.* `scripts/verify_passive_mode.py` runs the
   transport against loopback receivers under a socket tripwire that lets
   only code inside the transport reach only policy-permitted addresses,
   refuses all socket use by readers, pipeline and detectors, and checks that
   a monitored destination is refused at load time, at send time, and at
   socket level with the policy check bypassed.

### Threats on the outbound path and mitigations

| Threat | Mitigation |
|---|---|
| Configuration (or a mistake) points delivery at the monitored network | Refused at load, at send time and by the tripwire; overlapping allow-list entries refused; independent egress firewall recommended ([deployment.md](deployment.md)) |
| DNS answer redirects a listed name into the monitored network (rebinding) | Every resolved address checked; connection pinned to the checked address |
| Webhook/SMTP configuration used as an SSRF primitive | Hosts must be listed by name or address; URL credentials refused; no redirects, no proxies; only POST of UniShield's own JSON |
| Attacker-controlled traffic fields injected into the SIEM (log forging) | CEF header/extension escaping (no raw newlines, `\|`, `=` escaped), RFC 5424 structured-data escaping, octet-counted framing on TCP/TLS, header fields restricted to printable ASCII |
| Eavesdropping or tampering on the analyst network | Syslog over TLS (min TLS 1.2, certificate and host-name verification, pinned CA via `tls.ca_file`, optional client certificate); SMTP STARTTLS or implicit TLS; HTTPS webhooks. Disabling verification is possible but shown in the status |
| Sensitive alert content reaching too many people | Per-channel severity floor, field allow-list, IP redaction; raw evidence never sent in notifications |
| Notification flooding during an attack | Per-channel minimum interval and hourly cap; bursts become one digest listing the most severe alerts |
| Credential leakage | SMTP password and webhook tokens only from environment variables; never logged or returned; webhook URLs reduced to scheme, host and port in status |
| Slow or dead destination degrading detection | Bounded queue and a separate worker; overflow counted as dropped; TCP/TLS syslog retries a bounded backlog |
| Export files read or altered on the host | Written only to `export.directory` on the analyst side; protect the directory with file permissions or a dedicated volume; STIX bundle rewritten atomically |

### Threat intelligence imports

| Threat | Mitigation |
|---|---|
| Poisoned or careless list flags whole networks or every domain | Networks broader than /8 (IPv4) or /32 (IPv6) rejected (configurable); single-label names and public suffixes rejected; URLs rejected (they name paths on shared hosts); every rejection reported |
| Oversized file exhausts memory or disk | `intel.max_file_mb` and `intel.max_indicators` per import; request body limit on the API |
| Stale indicators raise alerts forever | Per-indicator expiry (file column, STIX `valid_until`, `--expires`, `intel.default_ttl_days`); expired entries never match |
| Stored XSS through labels | Labels stored as text and rendered with `textContent` (live-checked with an HTML-like label) |
| Unauthorised import or removal | Admin key / loopback-only, like other state-changing endpoints |
| Fetching feeds opens a path to the internet | UniShield never fetches; files are carried across by the operator |

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
| Accidental active behaviour in code | `scripts/verify_passive_mode.py`: AST scan for network/process/crypto capabilities (scoped allowance for the transport only) and a runtime tripwire around sockets and scapy send/capture |

## Out of scope

Live capture from interfaces, payload inspection, response or blocking,
multi-tenant access control, fetching threat intelligence, encryption of
export files at rest, and protection against an attacker with write access
to the host or its configuration.
