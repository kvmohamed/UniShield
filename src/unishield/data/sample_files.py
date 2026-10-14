"""
UniShield — Deterministic sample input files

Writes small PCAP, Zeek and flow files with known contents, used by the
test suite and by ``scripts/make_samples.py`` (which puts them in
``data/samples/`` so they can be replayed through the API).

All traffic is synthetic and written straight to local files with Scapy's
writer; nothing is sent on any network. Addresses come from private
(RFC 1918 / ULA) and documentation (RFC 5737 / RFC 3849) ranges.
"""

from __future__ import annotations

import csv
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from unishield.ingest.pcap_reader import quiet_scapy_import_warnings
from unishield.ingest.tls import build_client_hello, build_server_hello

quiet_scapy_import_warnings()

BASE_TIME = datetime(2026, 1, 1, tzinfo=timezone.utc)
BASE_EPOCH = BASE_TIME.timestamp()

CLIENT = "192.168.1.10"
WEB_SERVER = "93.184.216.34"
DNS_SERVER = "192.168.1.53"
SCANNER = "198.51.100.66"
SCAN_TARGET = "192.168.1.20"


@dataclass(frozen=True)
class ExpectedFlow:
    """Ground truth for one flow in the sample capture."""
    name: str
    protocol: str
    source_ip: str
    destination_ip: str
    source_port: int | None
    destination_port: int | None
    orig_packets: int
    resp_packets: int
    orig_bytes: int
    resp_bytes: int
    conn_state: str
    direction: str
    tcp_flags: str | None = None
    dns_query: str | None = None
    dns_rcode: str | None = None
    tls_version: str | None = None
    tls_cipher: str | None = None


@dataclass(frozen=True)
class SampleCapture:
    path: Path
    ip_packets: int
    non_ip_frames: int
    flows: tuple[ExpectedFlow, ...]


def write_sample_pcap(path: Path | str, pcapng: bool = False) -> SampleCapture:
    """
    Write the sample capture and return its ground truth.

    Contents (offsets in seconds from 2026-01-01T00:00:00Z):
      0.00–0.24  HTTPS 192.168.1.10 → 93.184.216.34:443, TLS 1.3 handshake, FIN close
      0.30       DNS A query, NOERROR (internal resolver)
      0.40       DNS A query, NXDOMAIN
      1.00–1.04  scan 198.51.100.66 → 192.168.1.20 ports 21/22/23/80/8080
      2.00       ICMP echo request + reply to 8.8.8.8
      2.50       one-way IPv6 UDP fd00::10 → 2001:db8::1:123
      2.60       one ARP frame (non-IP, skipped)
    """
    from scapy.layers.dns import DNS, DNSQR, DNSRR
    from scapy.layers.inet import ICMP, IP, TCP, UDP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.l2 import ARP, Ether
    from scapy.packet import Raw

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    packets = []
    flows: dict[str, dict] = {}

    def add(name, pkt, offset, from_orig):
        pkt.time = BASE_EPOCH + offset
        packets.append(pkt)
        if name is None:
            return
        f = flows[name]
        side = "orig" if from_orig else "resp"
        f[f"{side}_packets"] += 1
        f[f"{side}_bytes"] += len(pkt)

    def flow(name, **spec):
        flows[name] = {"orig_packets": 0, "resp_packets": 0, "orig_bytes": 0, "resp_bytes": 0, **spec}

    eth = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")

    # --- HTTPS with TLS 1.3 handshake -----------------------------------
    flow("https", protocol="TCP", source_ip=CLIENT, destination_ip=WEB_SERVER, source_port=50000,
         destination_port=443, conn_state="SF", direction="outbound", tcp_flags="ACK,FIN,PSH,SYN",
         tls_version="TLSv1.3", tls_cipher="TLS_AES_128_GCM_SHA256")
    c2s = eth / IP(src=CLIENT, dst=WEB_SERVER)
    s2c = eth / IP(src=WEB_SERVER, dst=CLIENT)
    add("https", c2s / TCP(sport=50000, dport=443, flags="S", seq=1000), 0.000, True)
    add("https", s2c / TCP(sport=443, dport=50000, flags="SA", seq=5000, ack=1001), 0.020, False)
    add("https", c2s / TCP(sport=50000, dport=443, flags="A", seq=1001, ack=5001), 0.040, True)
    hello = build_client_hello([0x1A1A, 0x0304, 0x0303])
    add("https", c2s / TCP(sport=50000, dport=443, flags="PA") / Raw(hello), 0.050, True)
    add("https", s2c / TCP(sport=443, dport=50000, flags="PA") / Raw(build_server_hello(0x0304, 0x1301)),
        0.080, False)
    add("https", c2s / TCP(sport=50000, dport=443, flags="PA") / Raw(b"\x17\x03\x03" + bytes(497)), 0.100, True)
    add("https", s2c / TCP(sport=443, dport=50000, flags="PA") / Raw(b"\x17\x03\x03" + bytes(1197)), 0.150, False)
    add("https", c2s / TCP(sport=50000, dport=443, flags="FA"), 0.200, True)
    add("https", s2c / TCP(sport=443, dport=50000, flags="FA"), 0.220, False)
    add("https", c2s / TCP(sport=50000, dport=443, flags="A"), 0.240, True)

    # --- DNS --------------------------------------------------------------
    for name, sport, qname, rcode, offset in (
        ("dns_ok", 40000, "www.example.com", 0, 0.300),
        ("dns_nx", 40001, "q7x9z2kd.example", 3, 0.400),
    ):
        flow(name, protocol="UDP", source_ip=CLIENT, destination_ip=DNS_SERVER, source_port=sport,
             destination_port=53, conn_state="SF", direction="internal", dns_query=qname,
             dns_rcode="NOERROR" if rcode == 0 else "NXDOMAIN")
        add(name, eth / IP(src=CLIENT, dst=DNS_SERVER) / UDP(sport=sport, dport=53)
            / DNS(id=sport, rd=1, qd=[DNSQR(qname=qname, qtype="A")]), offset, True)
        answers = [DNSRR(rrname=qname, type="A", rdata=WEB_SERVER)] if rcode == 0 else []
        add(name, eth / IP(src=DNS_SERVER, dst=CLIENT) / UDP(sport=53, dport=sport)
            / DNS(id=sport, qr=1, rd=1, ra=1, rcode=rcode, qd=[DNSQR(qname=qname, qtype="A")], an=answers),
            offset + 0.010, False)

    # --- Port scan (same scanner source port, as nmap does) --------------
    s_out = eth / IP(src=SCANNER, dst=SCAN_TARGET)
    s_in = eth / IP(src=SCAN_TARGET, dst=SCANNER)
    for i, (port, state) in enumerate(((21, "REJ"), (22, "RST"), (23, "REJ"), (80, "S0"), (8080, "S0"))):
        name = f"scan_{port}"
        flags = "RST,SYN" if state == "RST" else "SYN"
        flow(name, protocol="TCP", source_ip=SCANNER, destination_ip=SCAN_TARGET, source_port=61000,
             destination_port=port, conn_state=state, direction="inbound", tcp_flags=flags)
        t = 1.0 + i * 0.010
        add(name, s_out / TCP(sport=61000, dport=port, flags="S"), t, True)
        if state == "REJ":
            add(name, s_in / TCP(sport=port, dport=61000, flags="RA"), t + 0.001, False)
        elif state == "RST":
            add(name, s_in / TCP(sport=port, dport=61000, flags="SA"), t + 0.001, False)
            add(name, s_out / TCP(sport=61000, dport=port, flags="R"), t + 0.002, True)

    # --- ICMP echo --------------------------------------------------------
    flow("icmp", protocol="ICMP", source_ip=CLIENT, destination_ip="8.8.8.8", source_port=None,
         destination_port=None, conn_state="SF", direction="outbound")
    add("icmp", eth / IP(src=CLIENT, dst="8.8.8.8") / ICMP(type=8, id=1, seq=1), 2.000, True)
    add("icmp", eth / IP(src="8.8.8.8", dst=CLIENT) / ICMP(type=0, id=1, seq=1), 2.030, False)

    # --- One-way IPv6 UDP -------------------------------------------------
    flow("ipv6", protocol="UDP", source_ip="fd00::10", destination_ip="2001:db8::1", source_port=50010,
         destination_port=123, conn_state="S0", direction="outbound")
    add("ipv6", eth / IPv6(src="fd00::10", dst="2001:db8::1") / UDP(sport=50010, dport=123)
        / Raw(bytes(48)), 2.500, True)

    # --- Non-IP frame -----------------------------------------------------
    add(None, Ether(src="02:00:00:00:00:01", dst="ff:ff:ff:ff:ff:ff") / ARP(psrc=CLIENT, pdst=DNS_SERVER),
        2.600, True)

    if pcapng:
        from scapy.utils import PcapNgWriter
        with PcapNgWriter(str(path)) as writer:
            for pkt in packets:
                writer.write(pkt)
    else:
        from scapy.utils import wrpcap
        wrpcap(str(path), packets)

    expected = tuple(ExpectedFlow(name=n, **spec) for n, spec in flows.items())
    return SampleCapture(path=path, ip_packets=len(packets) - 1, non_ip_frames=1, flows=expected)


# ---------------------------------------------------------------------------
# Zeek logs
# ---------------------------------------------------------------------------

def _zeek_conn_records() -> list[dict]:
    t = BASE_EPOCH
    return [
        {"ts": t + 0.0, "uid": "CTLS0001", "id.orig_h": CLIENT, "id.orig_p": 50000,
         "id.resp_h": WEB_SERVER, "id.resp_p": 443, "proto": "tcp", "service": "ssl",
         "duration": 0.24, "orig_bytes": 820, "resp_bytes": 1560, "conn_state": "SF",
         "history": "ShADadFf", "orig_pkts": 6, "resp_pkts": 4},
        {"ts": t + 0.4, "uid": "CDNS0001", "id.orig_h": CLIENT, "id.orig_p": 40001,
         "id.resp_h": DNS_SERVER, "id.resp_p": 53, "proto": "udp", "service": "dns",
         "duration": 0.01, "orig_bytes": 34, "resp_bytes": 34, "conn_state": "SF",
         "history": "Dd", "orig_pkts": 1, "resp_pkts": 1},
        {"ts": t + 1.0, "uid": "CSCN0001", "id.orig_h": SCANNER, "id.orig_p": 61000,
         "id.resp_h": SCAN_TARGET, "id.resp_p": 21, "proto": "tcp", "conn_state": "REJ",
         "history": "Sr", "orig_bytes": 0, "resp_bytes": 0, "orig_pkts": 1, "resp_pkts": 1},
        {"ts": t + 1.03, "uid": "CSCN0004", "id.orig_h": SCANNER, "id.orig_p": 61000,
         "id.resp_h": SCAN_TARGET, "id.resp_p": 80, "proto": "tcp", "conn_state": "S0",
         "history": "S", "orig_bytes": 0, "resp_bytes": 0, "orig_pkts": 1, "resp_pkts": 0,
         "duration": None},
    ]


def write_sample_zeek_dir(directory: Path | str) -> Path:
    """Write conn.log, dns.log and ssl.log (JSON lines) sharing uids."""
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    t = BASE_EPOCH
    conn = [{k: v for k, v in r.items() if v is not None} for r in _zeek_conn_records()]
    dns = [{"ts": t + 0.4, "uid": "CDNS0001", "id.orig_h": CLIENT, "id.orig_p": 40001,
            "id.resp_h": DNS_SERVER, "id.resp_p": 53, "proto": "udp",
            "query": "q7x9z2kd.example", "qtype_name": "A", "rcode_name": "NXDOMAIN"}]
    ssl = [{"ts": t + 0.05, "uid": "CTLS0001", "id.orig_h": CLIENT, "id.orig_p": 50000,
            "id.resp_h": WEB_SERVER, "id.resp_p": 443, "version": "TLSv13",
            "cipher": "TLS_AES_128_GCM_SHA256", "server_name": "www.example.com"}]
    for name, records in (("conn.log", conn), ("dns.log", dns), ("ssl.log", ssl)):
        (directory / name).write_text("".join(json.dumps(r) + "\n" for r in records), encoding="utf-8")
    return directory


def write_sample_zeek_tsv(path: Path | str) -> Path:
    """Write the same conn records in Zeek's default tab-separated format."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "duration",
              "orig_bytes", "resp_bytes", "conn_state", "history", "orig_pkts", "resp_pkts"]
    types = ["time", "string", "addr", "port", "addr", "port", "enum", "interval",
             "count", "count", "string", "string", "count", "count"]
    lines = [
        "#separator \\x09", "#set_separator\t,", "#empty_field\t(empty)", "#unset_field\t-",
        "#path\tconn", "#fields\t" + "\t".join(fields), "#types\t" + "\t".join(types),
    ]
    for rec in _zeek_conn_records():
        row = []
        for name in fields:
            value = rec.get(name)
            row.append("-" if value is None else (f"{value:.6f}" if name == "ts" else str(value)))
        lines.append("\t".join(row))
    lines.append("#close\t2026-01-01-00-00-05")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# Flow files
# ---------------------------------------------------------------------------

_FLOW_ROWS = [
    {"timestamp": "2026-01-01T00:00:00Z", "src_ip": CLIENT, "dst_ip": WEB_SERVER, "src_port": 50000,
     "dst_port": 443, "proto": "TCP", "orig_bytes": 820, "resp_bytes": 1560, "orig_pkts": 6,
     "resp_pkts": 4, "duration": 0.24, "tcp_flags": "ACK,FIN,PSH,SYN", "direction": "outbound",
     "label": "BENIGN"},
    {"timestamp": "2026-01-01T00:00:01Z", "src_ip": SCANNER, "dst_ip": SCAN_TARGET, "src_port": 61000,
     "dst_port": 22, "proto": "6", "orig_bytes": 40, "resp_bytes": 0, "orig_pkts": 1,
     "resp_pkts": 0, "duration": 0, "tcp_flags": "SYN", "direction": "inbound", "label": "PortScan"},
    {"timestamp": "2026-01-01T00:00:02Z", "src_ip": CLIENT, "dst_ip": DNS_SERVER, "src_port": 40001,
     "dst_port": 53, "proto": "UDP", "bytes": 68, "packets": 2, "duration": 0.01,
     "query": "q7x9z2kd.example", "dns_rcode": "NXDOMAIN", "label": "BENIGN"},
]


def write_sample_flow_csv(path: Path | str) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    columns = sorted({k for row in _FLOW_ROWS for k in row})
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=columns)
        writer.writeheader()
        writer.writerows(_FLOW_ROWS)
    return path


def write_sample_flow_jsonl(path: Path | str) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(r) + "\n" for r in _FLOW_ROWS), encoding="utf-8")
    return path


def write_cicids_style_csv(path: Path | str) -> Path:
    """A few rows in CIC-IDS2017 'TrafficLabelling' layout (subset of columns)."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    header = ("Flow ID, Source IP, Source Port, Destination IP, Destination Port, Protocol, Timestamp,"
              " Flow Duration, Total Fwd Packets, Total Backward Packets,Total Length of Fwd Packets,"
              " Total Length of Bwd Packets, Flow Bytes/s, Label")
    rows = [
        "192.168.10.5-192.168.10.3-51000-80-6,192.168.10.5,51000,192.168.10.3,80,6,7/7/2017 3:30,"
        "5000000,10,8,1200,6400,1520.0,BENIGN",
        "172.16.0.1-192.168.10.50-40000-80-6,172.16.0.1,40000,192.168.10.50,80,6,7/7/2017 3:31:15,"
        "120,2,0,0,0,Infinity,DDoS",
        "bad-row,not-an-ip,1,192.168.10.50,80,6,7/7/2017 3:32,1,1,0,0,0,0,DDoS",
    ]
    path.write_text(header + "\n" + "\n".join(rows) + "\n", encoding="utf-8")
    return path
