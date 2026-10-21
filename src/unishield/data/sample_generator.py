"""
UniShield — Synthetic Traffic Generator

Generates labelled, reproducible synthetic flow records for testing and
demonstration. Records look like sessionized flows: the originator is the
source, per-direction packet/byte counts and a connection state are set, and
``tcp_flags`` holds the originator's flags.

IMPORTANT: This generates SIMULATED flow records only. It does not create
packets, generate real attacks, or interact with any network. Addresses come
from private (RFC 1918) and documentation/benchmark ranges (RFC 5737, RFC 2544).

Reproducibility: every generator accepts ``rng`` (a ``random.Random``) or
``seed``; with neither, results are random. ``build_scenario(name, seed)``
returns a labelled scenario plus the threat classes it is expected to raise.

Labels (``NormalisedFlow.label``): BENIGN, DDOS_SYN_FLOOD, DDOS_UDP_FLOOD,
PORT_SCAN, HOST_SCAN, C2_BEACONING, DATA_EXFILTRATION, DGA, DNS_TUNNELLING. Detectors never read
labels; they are ground truth for evaluation.
"""

from __future__ import annotations

import hashlib
import json
import random
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Iterator

from unishield.schemas.flow import (
    FlowDirection,
    InputSource,
    NormalisedFlow,
    ProtocolType,
)

# ---------------------------------------------------------------------------
# Address plan
# ---------------------------------------------------------------------------

INTERNAL_SUBNETS = ["10.0.1.", "10.0.2.", "192.168.1."]
EXTERNAL_IPS = [
    "203.0.113.50", "198.51.100.100", "198.51.100.200",
    "203.0.113.75", "93.184.216.34", "172.217.14.206",
    "151.101.1.140", "104.16.132.229", "13.107.42.14",
]
ATTACKER_IPS = ["198.18.0.100", "198.18.0.101", "198.18.0.102"]
C2_SERVER = "198.51.100.42"
EXFIL_DEST = "203.0.113.99"
DNS_RESOLVER = "10.0.1.53"

LABEL_BENIGN = "BENIGN"
LABEL_DDOS_SYN = "DDOS_SYN_FLOOD"
LABEL_DDOS_UDP = "DDOS_UDP_FLOOD"
LABEL_PORT_SCAN = "PORT_SCAN"
LABEL_HOST_SCAN = "HOST_SCAN"
LABEL_BEACON = "C2_BEACONING"
LABEL_EXFIL = "DATA_EXFILTRATION"

_COMPLETED_TCP_FLAGS = "ACK,FIN,PSH,SYN"

# TLS metadata for simulated HTTPS/IMAPS sessions, so that TLS presence alone
# does not separate benign from attack traffic. The JA3 values are MD5s of
# made-up ClientHello strings standing in for a few common client stacks.
_TLS_PORTS = frozenset({443, 465, 993, 995, 8443})
_CLIENT_JA3 = tuple(
    hashlib.md5(text.encode()).hexdigest()
    for text in ("771,4865-4866-4867,0-23-65281-10-11-35-16-5-13-43-45-51,29-23-24,0",
                 "771,4865-4867-4866,0-23-65281-10-11-16-5-34-51-43-13-45,29-23-24-25,0",
                 "771,49195-49199-52393,0-23-65281-10-11-35-13,29-23-24,0")
)


def _tls_fields(rng: random.Random, dport: int | None) -> dict:
    """tls_version / tls_cipher / ja3 for a TLS port, else nothing."""
    if dport not in _TLS_PORTS:
        return {}
    if rng.random() < 0.7:
        return {"tls_version": "TLSv1.3", "tls_cipher": "TLS_AES_128_GCM_SHA256", "ja3": rng.choice(_CLIENT_JA3)}
    return {"tls_version": "TLSv1.2", "tls_cipher": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "ja3": rng.choice(_CLIENT_JA3)}


def _rng(rng: random.Random | None, seed: int | None) -> random.Random:
    return rng if rng is not None else random.Random(seed)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _random_internal_ip(rng: random.Random) -> str:
    return f"{rng.choice(INTERNAL_SUBNETS)}{rng.randint(1, 254)}"


def _flow(
    *,
    timestamp: datetime,
    src: str,
    dst: str,
    sport: int | None,
    dport: int | None,
    protocol: ProtocolType,
    orig_packets: int,
    resp_packets: int,
    orig_bytes: int,
    resp_bytes: int,
    duration: float,
    conn_state: str,
    direction: FlowDirection,
    label: str,
    tcp_flags: str | None = None,
    **extra,
) -> NormalisedFlow:
    return NormalisedFlow(
        timestamp=timestamp,
        source_ip=src,
        destination_ip=dst,
        source_port=sport,
        destination_port=dport,
        protocol=protocol,
        packet_count=orig_packets + resp_packets,
        byte_count=orig_bytes + resp_bytes,
        orig_packets=orig_packets,
        resp_packets=resp_packets,
        orig_bytes=orig_bytes,
        resp_bytes=resp_bytes,
        duration=duration,
        tcp_flags=tcp_flags if protocol == ProtocolType.TCP else None,
        conn_state=conn_state,
        direction=direction,
        label=label,
        source_type=InputSource.SIMULATED,
        **extra,
    )


def _completed_tcp(rng, t, src, dst, dport, direction, label=LABEL_BENIGN,
                   up=(300, 3000), down=(2000, 60000)) -> NormalisedFlow:
    """A normal client connection: handshake, data both ways, FIN close."""
    orig_pkts, resp_pkts = rng.randint(4, 20), rng.randint(4, 60)
    return _flow(
        timestamp=t, src=src, dst=dst, sport=rng.randint(49152, 65535), dport=dport,
        protocol=ProtocolType.TCP, orig_packets=orig_pkts, resp_packets=resp_pkts,
        orig_bytes=rng.randint(*up), resp_bytes=rng.randint(*down),
        duration=round(rng.uniform(0.05, 5.0), 3), conn_state="SF",
        direction=direction, label=label, tcp_flags=_COMPLETED_TCP_FLAGS, **_tls_fields(rng, dport),
    )


# ---------------------------------------------------------------------------
# Normal traffic
# ---------------------------------------------------------------------------

def generate_normal_traffic(
    count: int = 500,
    start_time: datetime | None = None,
    *,
    gap_ms: tuple[int, int] = (100, 2000),
    rng: random.Random | None = None,
    seed: int | None = None,
) -> list[NormalisedFlow]:
    """Normal baseline traffic (by default about one completed flow per second)."""
    rng = _rng(rng, seed)
    current_time = start_time or _now()
    flows = []

    for _ in range(count):
        current_time += timedelta(milliseconds=rng.randint(*gap_ms))
        kind = rng.choices(["out_tcp", "in_tcp", "dns", "icmp"], weights=[0.55, 0.15, 0.25, 0.05])[0]

        if kind == "out_tcp":
            flows.append(_completed_tcp(rng, current_time, _random_internal_ip(rng),
                                        rng.choice(EXTERNAL_IPS), rng.choice([80, 443, 443, 22, 993, 587]),
                                        FlowDirection.OUTBOUND))
        elif kind == "in_tcp":
            flows.append(_completed_tcp(rng, current_time, rng.choice(EXTERNAL_IPS),
                                        _random_internal_ip(rng), rng.choice([80, 443, 8080]),
                                        FlowDirection.INBOUND, up=(300, 2000), down=(1000, 20000)))
        elif kind == "dns":
            flows.append(_flow(
                timestamp=current_time, src=_random_internal_ip(rng), dst=DNS_RESOLVER,
                sport=rng.randint(1024, 65535), dport=53, protocol=ProtocolType.UDP,
                orig_packets=1, resp_packets=1, orig_bytes=rng.randint(60, 90),
                resp_bytes=rng.randint(90, 300), duration=round(rng.uniform(0.001, 0.05), 3),
                conn_state="SF", direction=FlowDirection.INTERNAL, label=LABEL_BENIGN,
            ))
        else:
            flows.append(_flow(
                timestamp=current_time, src=_random_internal_ip(rng), dst=rng.choice(EXTERNAL_IPS),
                sport=None, dport=None, protocol=ProtocolType.ICMP, orig_packets=1, resp_packets=1,
                orig_bytes=84, resp_bytes=84, duration=round(rng.uniform(0.005, 0.1), 3),
                conn_state="SF", direction=FlowDirection.OUTBOUND, label=LABEL_BENIGN,
            ))
    return flows


# ---------------------------------------------------------------------------
# DDoS
# ---------------------------------------------------------------------------

def generate_ddos_traffic(
    count: int = 6000,
    start_time: datetime | None = None,
    target_ip: str = "10.0.1.100",
    *,
    syn_fraction: float = 0.8,
    rng: random.Random | None = None,
    seed: int | None = None,
) -> list[NormalisedFlow]:
    """
    Distributed flood against ``target_ip``.

    ``syn_fraction`` of the records are a SYN flood from spoofed sources
    (~3,000 half-open attempts per second, one record each); the rest are a
    UDP flood from a botnet, each record being one second of 80–160 packets
    from one bot (~200 bots active at once, ~24,000 packets per second).
    """
    rng = _rng(rng, seed)
    start = start_time or _now()
    flows = []

    t = start
    for _ in range(int(count * syn_fraction)):
        t += timedelta(microseconds=rng.randint(150, 500))
        flows.append(_flow(
            timestamp=t, src=f"198.18.{rng.randint(0, 255)}.{rng.randint(1, 254)}", dst=target_ip,
            sport=rng.randint(1024, 65535), dport=rng.choice([80, 443]), protocol=ProtocolType.TCP,
            orig_packets=1, resp_packets=0, orig_bytes=60, resp_bytes=0, duration=0.0,
            conn_state="S0", direction=FlowDirection.INBOUND, label=LABEL_DDOS_SYN, tcp_flags="SYN",
        ))

    t = start
    bots = [f"198.19.{rng.randint(0, 255)}.{rng.randint(1, 254)}" for _ in range(300)]
    for _ in range(count - int(count * syn_fraction)):
        t += timedelta(microseconds=rng.randint(2000, 8000))
        packets, size = rng.randint(80, 160), rng.randint(512, 1400)
        flows.append(_flow(
            timestamp=t, src=rng.choice(bots), dst=target_ip, sport=rng.randint(1024, 65535),
            dport=rng.choice([53, 123, 1900]), protocol=ProtocolType.UDP,
            orig_packets=packets, resp_packets=0, orig_bytes=packets * size, resp_bytes=0,
            duration=1.0, conn_state="S0", direction=FlowDirection.INBOUND, label=LABEL_DDOS_UDP,
        ))

    flows.sort(key=lambda f: f.timestamp)
    return flows


# ---------------------------------------------------------------------------
# Reconnaissance
# ---------------------------------------------------------------------------

def generate_scan_traffic(
    count: int = 200,
    start_time: datetime | None = None,
    scanner_ip: str | None = None,
    target_ip: str | None = None,
    *,
    rng: random.Random | None = None,
    seed: int | None = None,
) -> list[NormalisedFlow]:
    """
    TCP SYN port scan: 70% of probes against one target, 30% against other
    hosts. Closed ports reject (REJ), filtered ports stay silent (S0), open
    ports answer and are reset by the scanner (RST).
    """
    rng = _rng(rng, seed)
    current_time = start_time or _now()
    scanner_ip = scanner_ip or rng.choice(ATTACKER_IPS)
    target_ip = target_ip or _random_internal_ip(rng)
    scanned_ports = rng.sample(range(1, 65536), min(count, 1000))
    sport = rng.randint(1024, 65535)
    flows = []

    for i in range(count):
        current_time += timedelta(milliseconds=rng.randint(10, 200))
        outcome = rng.choices(["REJ", "S0", "RST"], weights=[0.8, 0.15, 0.05])[0]
        orig_pkts, resp_pkts = {"REJ": (1, 1), "S0": (1, 0), "RST": (2, 1)}[outcome]
        flows.append(_flow(
            timestamp=current_time, src=scanner_ip,
            dst=target_ip if rng.random() < 0.7 else _random_internal_ip(rng),
            sport=sport, dport=scanned_ports[i % len(scanned_ports)], protocol=ProtocolType.TCP,
            orig_packets=orig_pkts, resp_packets=resp_pkts, orig_bytes=44 * orig_pkts,
            resp_bytes=40 * resp_pkts, duration=round(rng.uniform(0.0, 0.05), 3),
            conn_state=outcome, direction=FlowDirection.INBOUND, label=LABEL_PORT_SCAN,
            tcp_flags="RST,SYN" if outcome == "RST" else "SYN",
        ))
    return flows


def generate_host_sweep_traffic(
    count: int = 254,
    start_time: datetime | None = None,
    scanner_ip: str | None = None,
    subnet: str = "10.0.2.",
    port: int = 22,
    *,
    live_fraction: float = 0.1,
    rng: random.Random | None = None,
    seed: int | None = None,
) -> list[NormalisedFlow]:
    """Horizontal sweep of one port across a /24; most addresses do not answer."""
    rng = _rng(rng, seed)
    current_time = start_time or _now()
    scanner_ip = scanner_ip or rng.choice(ATTACKER_IPS)
    flows = []
    for i in range(count):
        current_time += timedelta(milliseconds=rng.randint(5, 40))
        live = rng.random() < live_fraction
        flows.append(_flow(
            timestamp=current_time, src=scanner_ip, dst=f"{subnet}{i % 254 + 1}",
            sport=rng.randint(1024, 65535), dport=port, protocol=ProtocolType.TCP,
            orig_packets=2 if live else 1, resp_packets=1 if live else 0,
            orig_bytes=88 if live else 44, resp_bytes=44 if live else 0,
            duration=0.002 if live else 0.0, conn_state="RST" if live else "S0",
            direction=FlowDirection.INBOUND, label=LABEL_HOST_SCAN,
            tcp_flags="RST,SYN" if live else "SYN",
        ))
    return flows


# ---------------------------------------------------------------------------
# C2 beaconing and exfiltration
# ---------------------------------------------------------------------------

def generate_beacon_traffic(
    beacon_count: int = 50,
    start_time: datetime | None = None,
    interval_sec: float = 60.0,
    jitter_percent: float = 5.0,
    internal_ip: str | None = None,
    *,
    rng: random.Random | None = None,
    seed: int | None = None,
) -> list[NormalisedFlow]:
    """C2 beaconing: small periodic HTTPS check-ins to one server."""
    rng = _rng(rng, seed)
    current_time = start_time or _now()
    internal_ip = internal_ip or "10.0.1.50"
    flows = []
    for _ in range(beacon_count):
        jitter = interval_sec * jitter_percent / 100.0
        current_time += timedelta(seconds=max(1.0, interval_sec + rng.uniform(-jitter, jitter)))
        orig_pkts, resp_pkts = rng.randint(3, 5), rng.randint(3, 5)
        flows.append(_flow(
            timestamp=current_time, src=internal_ip, dst=C2_SERVER,
            sport=rng.randint(49152, 65535), dport=443, protocol=ProtocolType.TCP,
            orig_packets=orig_pkts, resp_packets=resp_pkts, orig_bytes=rng.randint(120, 260),
            resp_bytes=rng.randint(80, 240), duration=round(rng.uniform(0.1, 2.0), 3),
            conn_state="SF", direction=FlowDirection.OUTBOUND, label=LABEL_BEACON,
            tcp_flags=_COMPLETED_TCP_FLAGS, **_tls_fields(rng, 443),
        ))
    return flows


def generate_exfil_traffic(
    count: int = 100,
    start_time: datetime | None = None,
    internal_ip: str | None = None,
    *,
    rng: random.Random | None = None,
    seed: int | None = None,
) -> list[NormalisedFlow]:
    """Data exfiltration: large uploads from one internal host to one external host."""
    rng = _rng(rng, seed)
    current_time = start_time or _now()
    internal_ip = internal_ip or "10.0.2.200"
    flows = []
    for _ in range(count):
        current_time += timedelta(seconds=rng.uniform(1, 10))
        up = rng.randint(500_000, 5_000_000)
        orig_pkts = max(up // 1400, 1)
        dport = rng.choice([443, 8443, 4444, 9090])
        flows.append(_flow(
            timestamp=current_time, src=internal_ip, dst=EXFIL_DEST,
            sport=rng.randint(49152, 65535), dport=dport,
            protocol=ProtocolType.TCP, orig_packets=orig_pkts, resp_packets=max(orig_pkts // 2, 1),
            orig_bytes=up, resp_bytes=rng.randint(5_000, 40_000),
            duration=round(rng.uniform(5.0, 120.0), 3), conn_state="SF",
            direction=FlowDirection.OUTBOUND, label=LABEL_EXFIL, tcp_flags=_COMPLETED_TCP_FLAGS,
            **_tls_fields(rng, dport),
        ))
    return flows


# ---------------------------------------------------------------------------
# DNS: DGA and tunnelling (optional advanced module)
# ---------------------------------------------------------------------------

LABEL_DGA = "DGA"
LABEL_DNS_TUNNEL = "DNS_TUNNELLING"


def _dns_flow(rng, t, src, query, qtype, rcode, label, resp=True):
    return _flow(
        timestamp=t, src=src, dst=DNS_RESOLVER, sport=rng.randint(1024, 65535), dport=53,
        protocol=ProtocolType.UDP, orig_packets=1, resp_packets=1 if resp else 0,
        orig_bytes=40 + len(query), resp_bytes=(60 + len(query)) if resp else 0,
        duration=0.01, conn_state="SF" if resp else "S0", direction=FlowDirection.INTERNAL,
        label=label, dns_query=query, dns_record_type=qtype, dns_rcode=rcode if resp else None,
    )


def generate_dga_traffic(
    count: int = 120,
    start_time: datetime | None = None,
    infected_ip: str = "10.0.1.66",
    *,
    nxdomain_fraction: float = 0.9,
    rng: random.Random | None = None,
    seed: int | None = None,
) -> list[NormalisedFlow]:
    """An infected host resolving random-looking domains, most of which do not exist."""
    rng = _rng(rng, seed)
    current_time = start_time or _now()
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    flows = []
    for _ in range(count):
        current_time += timedelta(milliseconds=rng.randint(30, 150))
        name = "".join(rng.choice(alphabet) for _ in range(rng.randint(10, 16)))
        query = f"{name}.{rng.choice(['com', 'net', 'org', 'info', 'biz'])}"
        rcode = "NXDOMAIN" if rng.random() < nxdomain_fraction else "NOERROR"
        flows.append(_dns_flow(rng, current_time, infected_ip, query, "A", rcode, LABEL_DGA))
    return flows


def generate_dns_tunnel_traffic(
    count: int = 150,
    start_time: datetime | None = None,
    client_ip: str = "10.0.1.77",
    base_domain: str = "t.exfil-tunnel.example",
    *,
    rng: random.Random | None = None,
    seed: int | None = None,
) -> list[NormalisedFlow]:
    """Data encoded as base32-like subdomains of one base domain, mostly TXT queries."""
    rng = _rng(rng, seed)
    current_time = start_time or _now()
    alphabet = "abcdefghijklmnopqrstuvwxyz234567"
    flows = []
    for i in range(count):
        current_time += timedelta(milliseconds=rng.randint(40, 120))
        chunk = "".join(rng.choice(alphabet) for _ in range(rng.randint(40, 60)))
        query = f"{chunk}.{i:05d}.{base_domain}"
        qtype = "TXT" if rng.random() < 0.8 else "A"
        flows.append(_dns_flow(rng, current_time, client_ip, query, qtype, "NOERROR", LABEL_DNS_TUNNEL))
    return flows


# ---------------------------------------------------------------------------
# Encrypted sessions (optional advanced module; handshake metadata only)
# ---------------------------------------------------------------------------

LABEL_ENCRYPTED = "ENCRYPTED_SESSION_ANOMALY"
LEGACY_TLS_SERVER = "198.51.100.77"
TUNNEL_TLS_SERVER = "203.0.113.150"


def generate_encrypted_anomaly_traffic(
    count: int = 12,
    start_time: datetime | None = None,
    client_ip: str = "10.0.2.31",
    *,
    rng: random.Random | None = None,
    seed: int | None = None,
) -> list[NormalisedFlow]:
    """
    A client negotiating TLS 1.0 with one external server, plus a one-hour
    TLS session at a few bytes per second on port 4443 (a pattern typical of
    tunnels and keep-alive channels).
    """
    rng = _rng(rng, seed)
    current_time = start_time or _now()
    flows = []
    for _ in range(count):
        current_time += timedelta(seconds=rng.uniform(1, 4))
        flows.append(_flow(
            timestamp=current_time, src=client_ip, dst=LEGACY_TLS_SERVER,
            sport=rng.randint(49152, 65535), dport=443, protocol=ProtocolType.TCP,
            orig_packets=rng.randint(6, 12), resp_packets=rng.randint(8, 20),
            orig_bytes=rng.randint(600, 2000), resp_bytes=rng.randint(3000, 20000),
            duration=round(rng.uniform(0.2, 3.0), 3), conn_state="SF",
            direction=FlowDirection.OUTBOUND, label=LABEL_ENCRYPTED, tcp_flags=_COMPLETED_TCP_FLAGS,
            tls_version="TLSv1.0", tls_cipher="TLS_RSA_WITH_AES_128_CBC_SHA",
        ))
    current_time += timedelta(seconds=2)
    flows.append(_flow(
        timestamp=current_time, src=client_ip, dst=TUNNEL_TLS_SERVER,
        sport=rng.randint(49152, 65535), dport=4443, protocol=ProtocolType.TCP,
        orig_packets=900, resp_packets=900, orig_bytes=rng.randint(90_000, 140_000),
        resp_bytes=rng.randint(90_000, 140_000), duration=3600.0, conn_state="SF",
        direction=FlowDirection.OUTBOUND, label=LABEL_ENCRYPTED, tcp_flags=_COMPLETED_TCP_FLAGS,
        tls_version="TLSv1.3", tls_cipher="TLS_AES_128_GCM_SHA256",
    ))
    return flows


# ---------------------------------------------------------------------------
# Mixed scenario (baseline + attacks)
# ---------------------------------------------------------------------------

def generate_mixed_scenario(
    normal_count: int = 500,
    ddos_count: int = 6000,
    scan_count: int = 100,
    beacon_count: int = 30,
    exfil_count: int = 50,
    start_time: datetime | None = None,
    *,
    seed: int | None = None,
) -> list[NormalisedFlow]:
    """
    Normal traffic with embedded attacks, sorted by time:
    DDoS at +30 s, port scan at +60 s, exfiltration at +120 s, beaconing throughout.
    """
    rng = random.Random(seed)
    start_time = start_time or _now()
    flows = generate_normal_traffic(normal_count, start_time, rng=rng)
    flows += generate_ddos_traffic(ddos_count, start_time + timedelta(seconds=30), rng=rng)
    flows += generate_scan_traffic(scan_count, start_time + timedelta(seconds=60), rng=rng)
    flows += generate_beacon_traffic(beacon_count, start_time, rng=rng)
    flows += generate_exfil_traffic(exfil_count, start_time + timedelta(seconds=120), rng=rng)
    flows.sort(key=lambda f: f.timestamp)
    return flows


# ---------------------------------------------------------------------------
# Named, labelled scenarios
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Scenario:
    name: str
    seed: int
    flows: list[NormalisedFlow]
    expected_classes: frozenset[str]     # threat classes the scenario should raise
    description: str


def _benign_hard(rng: random.Random, t0: datetime) -> list[NormalisedFlow]:
    """
    Benign traffic built to trip naive detectors: long quiet gaps, a large
    download right after a gap, a client opening 25 CDN connections on 443,
    a client opening 40 connections to one server, a burst of 60 DNS lookups
    and a flash crowd of 300 clients on one web server.
    """
    flows = generate_normal_traffic(60, t0, rng=rng)
    t = flows[-1].timestamp + timedelta(seconds=45)                     # quiet gap > window

    client = "192.168.1.25"
    flows.append(_flow(                                                 # 20 MB download over 30 s
        timestamp=t, src=client, dst="151.101.1.140", sport=51000, dport=443,
        protocol=ProtocolType.TCP, orig_packets=4000, resp_packets=14000, orig_bytes=240_000,
        resp_bytes=20_000_000, duration=30.0, conn_state="SF", direction=FlowDirection.OUTBOUND,
        label=LABEL_BENIGN, tcp_flags=_COMPLETED_TCP_FLAGS, **_tls_fields(rng, 443),
    ))
    for i in range(25):                                                 # page load from 25 CDN hosts
        flows.append(_completed_tcp(rng, t + timedelta(milliseconds=120 * i), client,
                                    f"203.0.113.{100 + i}", 443, FlowDirection.OUTBOUND))
    t += timedelta(seconds=12)
    for i in range(40):                                                 # 40 connections, one server
        flows.append(_completed_tcp(rng, t + timedelta(milliseconds=200 * i), "10.0.1.77",
                                    "93.184.216.34", 443, FlowDirection.OUTBOUND))
    t += timedelta(seconds=12)
    for i in range(60):                                                 # DNS burst
        flows.append(_flow(
            timestamp=t + timedelta(milliseconds=80 * i), src="10.0.1.77", dst=DNS_RESOLVER,
            sport=rng.randint(1024, 65535), dport=53, protocol=ProtocolType.UDP, orig_packets=1,
            resp_packets=1, orig_bytes=70, resp_bytes=180, duration=0.01, conn_state="SF",
            direction=FlowDirection.INTERNAL, label=LABEL_BENIGN, dns_query=f"img{i}.example.com",
        ))
    t += timedelta(seconds=12)
    for i in range(300):                                                # flash crowd
        flows.append(_completed_tcp(rng, t + timedelta(milliseconds=30 * i),
                                    f"198.51.100.{i % 250 + 1}", "10.0.2.10", 443,
                                    FlowDirection.INBOUND, up=(400, 1500), down=(5000, 50000)))
    t += timedelta(seconds=45)                                          # second quiet gap
    flows += generate_normal_traffic(60, t, rng=rng)
    flows.sort(key=lambda f: f.timestamp)
    return flows


_SCENARIOS: dict[str, tuple[frozenset[str], str, Callable[[random.Random, datetime], list[NormalisedFlow]]]] = {
    "benign_hard": (frozenset(), "Benign traffic designed to trigger naive DDoS/scan rules", _benign_hard),
    "ddos_syn": (
        frozenset({"SYN_FLOOD"}), "Background traffic plus a distributed SYN flood",
        lambda rng, t0: generate_normal_traffic(60, t0, rng=rng)
        + generate_ddos_traffic(6000, t0 + timedelta(seconds=20), syn_fraction=1.0, rng=rng),
    ),
    "ddos_udp": (
        frozenset({"UDP_FLOOD", "DDOS_VOLUMETRIC"}), "Background traffic plus a UDP botnet flood",
        lambda rng, t0: generate_normal_traffic(60, t0, rng=rng)
        + generate_ddos_traffic(1500, t0 + timedelta(seconds=20), syn_fraction=0.0, rng=rng),
    ),
    "port_scan": (
        frozenset({"PORT_SCAN"}), "Background traffic plus a TCP SYN port scan",
        lambda rng, t0: generate_normal_traffic(60, t0, rng=rng)
        + generate_scan_traffic(300, t0 + timedelta(seconds=20), rng=rng),
    ),
    "host_sweep": (
        frozenset({"HOST_SCAN"}), "Background traffic plus an SSH sweep of a /24",
        lambda rng, t0: generate_normal_traffic(60, t0, rng=rng)
        + generate_host_sweep_traffic(254, t0 + timedelta(seconds=20), rng=rng),
    ),
    "beacon_30s": (
        frozenset({"C2_BEACONING"}), "15 minutes of background traffic plus a 30 s HTTPS beacon (5% jitter)",
        lambda rng, t0: generate_normal_traffic(300, t0, gap_ms=(1000, 5000), rng=rng)
        + generate_beacon_traffic(25, t0 + timedelta(seconds=30), interval_sec=30, jitter_percent=5, rng=rng),
    ),
    "exfil_episodes": (
        frozenset({"DATA_EXFILTRATION"}),
        "30 minutes of background traffic plus three exfiltration episodes 12 minutes apart",
        lambda rng, t0: generate_normal_traffic(600, t0, gap_ms=(1000, 5000), rng=rng)
        + [f for k in range(3)
           for f in generate_exfil_traffic(12, t0 + timedelta(minutes=2 + 12 * k), rng=rng)],
    ),
    "dga": (
        frozenset({"DGA_DETECTED"}), "Background traffic plus a host resolving random-looking domains (mostly NXDOMAIN)",
        lambda rng, t0: generate_normal_traffic(60, t0, rng=rng)
        + generate_dga_traffic(120, t0 + timedelta(seconds=20), rng=rng),
    ),
    "dns_tunnel": (
        frozenset({"DNS_TUNNELLING"}), "Background traffic plus data encoded in DNS subdomains",
        lambda rng, t0: generate_normal_traffic(60, t0, rng=rng)
        + generate_dns_tunnel_traffic(150, t0 + timedelta(seconds=20), rng=rng),
    ),
    "encrypted_anomaly": (
        frozenset({"ENCRYPTED_SESSION_ANOMALY"}),
        "Background traffic plus a TLS 1.0 client and a long low-rate TLS session on port 4443",
        lambda rng, t0: generate_normal_traffic(60, t0, rng=rng)
        + generate_encrypted_anomaly_traffic(12, t0 + timedelta(seconds=20), rng=rng),
    ),
    "beacon_60s": (
        frozenset({"C2_BEACONING"}), "20 minutes of background traffic plus a 60 s HTTPS beacon (5% jitter)",
        lambda rng, t0: generate_normal_traffic(400, t0, gap_ms=(1000, 5000), rng=rng)
        + generate_beacon_traffic(18, t0 + timedelta(seconds=30), interval_sec=60, jitter_percent=5, rng=rng),
    ),
}

SCENARIO_NAMES = tuple(_SCENARIOS)


def build_scenario(name: str, seed: int, start_time: datetime | None = None) -> Scenario:
    """Build a named, labelled scenario deterministically from ``seed``."""
    if name not in _SCENARIOS:
        raise ValueError(f"Unknown scenario {name!r}; choose from {SCENARIO_NAMES}")
    expected, description, builder = _SCENARIOS[name]
    rng = random.Random(seed)
    t0 = start_time or datetime(2026, 1, 1, tzinfo=timezone.utc)
    flows = sorted(builder(rng, t0), key=lambda f: f.timestamp)
    return Scenario(name=name, seed=seed, flows=flows, expected_classes=expected, description=description)


# ---------------------------------------------------------------------------
# File writer for sample data
# ---------------------------------------------------------------------------

def save_sample_flows(
    flows: list[NormalisedFlow],
    output_path: Path | str,
    format: str = "json",
) -> Path:
    """
    Save flows to a file: "json" writes JSON lines, "csv" a CSV with the
    main fields (readable by FlowReader).
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if format == "json":
        with open(output_path, "w", encoding="utf-8") as f:
            for flow in flows:
                f.write(flow.model_dump_json() + "\n")
    elif format == "csv":
        import csv
        columns = ["timestamp", "source_ip", "destination_ip", "source_port", "destination_port",
                   "protocol", "packet_count", "byte_count", "orig_packets", "resp_packets",
                   "orig_bytes", "resp_bytes", "duration", "tcp_flags", "conn_state", "direction",
                   "label"]
        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=columns)
            writer.writeheader()
            for flow in flows:
                row = json.loads(flow.model_dump_json(include=set(columns)))
                writer.writerow({k: ("" if row.get(k) is None else row[k]) for k in columns})
    else:
        raise ValueError(f"Unknown format: {format!r}")

    return output_path


# ---------------------------------------------------------------------------
# SimulatedReader — a reader that wraps pre-generated flows
# ---------------------------------------------------------------------------

class SimulatedReader:
    """
    A reader adapter for pre-generated flow lists.
    Implements the same interface as BaseReader for pipeline compatibility.
    """

    def __init__(self, flows: list[NormalisedFlow]):
        self._flows = flows
        self._records_read = 0
        self._errors = 0
        self.source_path = None

    def read(self) -> Iterator[NormalisedFlow]:
        for flow in self._flows:
            self._records_read += 1
            yield flow

    def validate_source(self) -> bool:
        return len(self._flows) > 0

    @property
    def records_read(self) -> int:
        return self._records_read

    @property
    def errors(self) -> int:
        return self._errors
