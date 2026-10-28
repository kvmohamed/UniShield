# UniShield — Passive-Mode Verification

Generated 2026-10-28T18:44:29+00:00 by `scripts/verify_passive_mode.py`.

**Result: PASSED**

UniShield never sends anything into the monitored network. Its only outbound path is the optional export/notifier transport, which may reach analyst-side destinations listed in `outbound.allowed_destinations` that lie outside `network.home_networks`.

## Static scan

121 Python modules under `src/unishield` were parsed. Forbidden imports: Crypto, aiohttp, asyncssh, cryptography, ftplib, http.client, httpx, nmap, paramiko, pexpect, requests, smtplib, ssl, subprocess, telnetlib, urllib.request. Forbidden calls: AsyncSniffer, Popen, arping, connect, connect_ex, create_connection, execv, execve, popen, send, send_raw, sendall, sendp, sendpfast, sendto, sniff, spawnl, sr, sr1, srloop, srp, srp1, srploop, system, traceroute, urlopen (allowed: engine.connect, self.engine.connect — the local alert database).

No findings.

### Scoped allowance: the analyst-side transport

`unishield/export/transport.py` is the only module allowed network capability: imports `http.client`, `smtplib`, `socket`, `ssl` and calls `connect`, `create_connection`, `sendall`, `sendto`. Every function in it checks the destination against the policy before resolving or connecting and connects only to the checked address. Any other forbidden name in that file, or any of these names elsewhere, is a finding. Allowed occurrences:

| Line | Kind | Name |
|---|---|---|
| 25 | import | `http.client` |
| 27 | import | `smtplib` |
| 28 | import | `socket` |
| 29 | import | `ssl` |
| 87 | call | `socket.create_connection` |
| 101 | call | `sock.sendto` |
| 115 | call | `sock.sendall` |
| 137 | call | `socket.create_connection` |
| 149 | call | `socket.create_connection` |
| 167 | call | `smtp.connect` |
| 187 | call | `socket.create_connection` |
| 197 | call | `socket.create_connection` |

## Runtime tripwire

Socket connect/send and name-resolution functions and scapy's send/receive/sniff functions were replaced by recorders. Calls from inside the outbound transport are allowed only to addresses the destination policy permits (allow-listed, outside `network.home_networks`); readers, pipeline and detectors ran with every socket operation refused, loopback included; the API ran with loopback allowed (asyncio's event loop uses an internal loopback socket pair on Windows). Exercised under the tripwire:

- pipeline:pcap:pcap (with threat intel)
- pipeline:pcapng:pcapng (with threat intel)
- pipeline:port_scan_pcap:pcap (with threat intel)
- pipeline:syn_flood_pcap:pcap (with threat intel)
- pipeline:zeek_dir:zeek_dir (with threat intel)
- pipeline:zeek_tsv:zeek_tsv (with threat intel)
- pipeline:flow_csv:flow_csv (with threat intel)
- pipeline:flow_jsonl:flow_json (with threat intel)
- pipeline:cicids_csv:flow_csv (with threat intel)
- pipeline:scenario:benign_hard (5 INTEL_MATCH alerts from the sample indicators)
- pipeline:scenario:ddos_syn (0 INTEL_MATCH alerts from the sample indicators)
- pipeline:scenario:ddos_udp (0 INTEL_MATCH alerts from the sample indicators)
- pipeline:scenario:port_scan (0 INTEL_MATCH alerts from the sample indicators)
- pipeline:scenario:host_sweep (0 INTEL_MATCH alerts from the sample indicators)
- pipeline:scenario:beacon_30s (1 INTEL_MATCH alerts from the sample indicators)
- pipeline:scenario:exfil_episodes (0 INTEL_MATCH alerts from the sample indicators)
- pipeline:scenario:dga (0 INTEL_MATCH alerts from the sample indicators)
- pipeline:scenario:dns_tunnel (0 INTEL_MATCH alerts from the sample indicators)
- pipeline:scenario:encrypted_anomaly (1 INTEL_MATCH alerts from the sample indicators)
- pipeline:scenario:beacon_60s (2 INTEL_MATCH alerts from the sample indicators)
- readers, pipeline and detectors: 0 socket operations of any kind (loopback refused too)
- api:/auth/login:200
- api:/replay/demo:completed
- api:/health
- api:/alerts
- api:/incidents
- api:/metrics
- api:/metrics/traffic
- api:/system/architecture
- api:/intel/status
- api:/outputs/status
- api:/auth/me
- api:/audit
- api:/system/assets
- loopback socket operations allowed (event-loop internals): 103
- outbound:syslog/udp → 127.0.0.1:56679 (allow-listed): 4 messages
- outbound:syslog/tcp → 127.0.0.1:55873 (allow-listed): 4 messages
- outbound:email → 127.0.0.1:55874 (allow-listed): 1 message(s)
- outbound:webhook → http://127.0.0.1:55875 (allow-listed): 1 message(s)
- export files (local): 3 alerts written to 4 rotating files

Outbound socket operations allowed for the transport (loopback receivers standing in for the analyst-side SIEM, mail relay and webhook):

- socket.connect(127.0.0.1) × 3
- socket.create_connection(127.0.0.1) × 3
- socket.getaddrinfo(127.0.0.1) × 3
- socket.sendall(127.0.0.1) × 9
- socket.sendto(127.0.0.1) × 4

Refusals that must happen (a destination inside the monitored network):

- config load: syslog destination 10.0.0.5 refused (inside network.home_networks)
- send time: delivery to 10.0.0.5 refused by the destination policy before any socket use
- socket level: with the policy check bypassed, the tripwire refused sendto(10.0.0.5, 514)

Recorded unexpected network attempts: 0

## Scope

The API itself listens on a socket when served by uvicorn (it receives requests); that is inbound. Outbound traffic is off by default and, when configured, goes only to the analyst network through the transport above. The checks cover UniShield's own code; they cannot exclude every behaviour of third-party libraries.
