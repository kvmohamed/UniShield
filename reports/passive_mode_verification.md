# UniShield — Passive-Mode Verification

Generated 2026-10-21T19:13:02+00:00 by `scripts/verify_passive_mode.py`.

**Result: PASSED**

## Static scan

76 Python modules under `src/unishield` were parsed. Forbidden imports: Crypto, aiohttp, asyncssh, cryptography, ftplib, http.client, httpx, nmap, paramiko, pexpect, requests, smtplib, ssl, subprocess, telnetlib, urllib.request. Forbidden calls: AsyncSniffer, Popen, arping, connect, connect_ex, create_connection, execv, execve, popen, send, send_raw, sendall, sendp, sendpfast, sendto, sniff, spawnl, sr, sr1, srloop, srp, srp1, srploop, system, traceroute, urlopen (allowed: engine.connect, self.engine.connect — the local alert database).

No findings.

## Runtime tripwire

Socket connect/send and name-resolution functions and scapy's send/receive/sniff functions were replaced by recorders that refuse any non-loopback peer (loopback is allowed because asyncio's event loop uses an internal loopback socket pair on Windows). Exercised under the tripwire:

- pipeline:pcap:pcap
- pipeline:pcapng:pcapng
- pipeline:port_scan_pcap:pcap
- pipeline:syn_flood_pcap:pcap
- pipeline:zeek_dir:zeek_dir
- pipeline:zeek_tsv:zeek_tsv
- pipeline:flow_csv:flow_csv
- pipeline:flow_jsonl:flow_json
- pipeline:cicids_csv:flow_csv
- pipeline:scenario:benign_hard
- pipeline:scenario:ddos_syn
- pipeline:scenario:ddos_udp
- pipeline:scenario:port_scan
- pipeline:scenario:host_sweep
- pipeline:scenario:beacon_30s
- pipeline:scenario:exfil_episodes
- pipeline:scenario:dga
- pipeline:scenario:dns_tunnel
- pipeline:scenario:encrypted_anomaly
- pipeline:scenario:beacon_60s
- api:/replay/demo:completed
- api:/health
- api:/alerts
- api:/incidents
- api:/metrics
- api:/metrics/traffic
- api:/system/architecture
- loopback socket operations allowed (event-loop internals): 49

Recorded network attempts: 0

## Scope

The API itself listens on a socket when served by uvicorn (it receives requests); that is the only network use and it is inbound. The checks cover UniShield's own code; they cannot exclude every behaviour of third-party libraries.
