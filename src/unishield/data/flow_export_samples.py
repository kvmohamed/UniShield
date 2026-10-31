"""
UniShield — Flow-Export Encoders (tests and the loopback demo exporter)

Builds NetFlow v5 and IPFIX datagrams from NormalisedFlow records, as bytes.
Nothing here sends anything; ``scripts/demo_flow_exporter.py`` sends the
datagrams to a collector on the loopback interface only.
"""

from __future__ import annotations

import ipaddress
import struct
from datetime import datetime
from typing import Iterable

from unishield.ingest.netflow import (
    DST_PORT, DST_V4, END_MS, OCTETS, PACKETS, PROTOCOL, REVERSE_PEN, SRC_PORT, SRC_V4, START_MS, TCP_FLAGS,
)
from unishield.schemas.flow import NormalisedFlow, ProtocolType

_PROTO_NUM = {ProtocolType.TCP: 6, ProtocolType.UDP: 17, ProtocolType.ICMP: 1}
_FLAG_BITS = {"FIN": 0x01, "SYN": 0x02, "RST": 0x04, "PSH": 0x08, "ACK": 0x10, "URG": 0x20, "ECE": 0x40, "CWR": 0x80}


def _flags(flow: NormalisedFlow) -> int:
    return sum(_FLAG_BITS.get(name.strip().upper(), 0) for name in (flow.tcp_flags or "").split(",") if name)


def _v4(ip: str) -> bytes:
    return ipaddress.IPv4Address(ip).packed


def _ms(ts: datetime) -> int:
    return int(ts.timestamp() * 1000)


def encode_v5(flows: list[NormalisedFlow], export_time: datetime, sequence: int = 0) -> bytes:
    """One NetFlow v5 datagram (at most 30 IPv4 flows). Uptime is chosen so every flow starts after boot."""
    if not 1 <= len(flows) <= 30:
        raise ValueError("a v5 datagram holds 1 to 30 flows")
    boot_ms = min(_ms(f.timestamp) for f in flows) - 60_000
    uptime = _ms(export_time) - boot_ms
    header = struct.pack("!HHIIIIBBH", 5, len(flows), uptime, int(export_time.timestamp()),
                         int((export_time.timestamp() % 1) * 1e9), sequence, 0, 0, 0)
    body = b""
    for f in flows:
        first = _ms(f.timestamp) - boot_ms
        last = first + int((f.duration or 0) * 1000)
        body += struct.pack("!4s4s4sHHIIIIHHxBBBHHBBxx", _v4(f.source_ip), _v4(f.destination_ip), bytes(4), 0, 0,
                            max(f.packet_count, 1), f.byte_count, first, last, f.source_port or 0,
                            f.destination_port or 0, _flags(f), _PROTO_NUM.get(f.protocol, 0), 0, 0, 0, 0, 0)
    return header + body


def ipfix_template(template_id: int = 256, biflow: bool = False) -> list[tuple[int, int, int]]:
    """(information element, enterprise number, length) of the IPv4 template used by ``encode_ipfix``."""
    fields = [(SRC_V4, 0, 4), (DST_V4, 0, 4), (SRC_PORT, 0, 2), (DST_PORT, 0, 2), (PROTOCOL, 0, 1),
              (TCP_FLAGS, 0, 1), (PACKETS, 0, 8), (OCTETS, 0, 8), (START_MS, 0, 8), (END_MS, 0, 8)]
    if biflow:
        fields += [(PACKETS, REVERSE_PEN, 8), (OCTETS, REVERSE_PEN, 8)]
    return fields


def encode_ipfix(flows: Iterable[NormalisedFlow], export_time: datetime, *, template_id: int = 256,
                 biflow: bool = False, include_template: bool = True, domain: int = 1, sequence: int = 0) -> bytes:
    """One IPFIX message with (optionally) the template set and a data set of IPv4 flows."""
    fields = ipfix_template(template_id, biflow)
    sets = b""
    if include_template:
        tpl = struct.pack("!HH", template_id, len(fields))
        for ie, pen, length in fields:
            tpl += struct.pack("!HH", ie | (0x8000 if pen else 0), length) + (struct.pack("!I", pen) if pen else b"")
        sets += struct.pack("!HH", 2, 4 + len(tpl)) + tpl
    data = b""
    for f in flows:
        split = biflow and f.orig_bytes is not None and f.resp_bytes is not None
        fwd_pkts = (f.orig_packets or 0) if split else max(f.packet_count, 1)
        fwd_bytes = f.orig_bytes if split else f.byte_count
        start = _ms(f.timestamp)
        data += struct.pack("!4s4sHHBBQQQQ", _v4(f.source_ip), _v4(f.destination_ip), f.source_port or 0,
                            f.destination_port or 0, _PROTO_NUM.get(f.protocol, 0), _flags(f), fwd_pkts, fwd_bytes,
                            start, start + int((f.duration or 0) * 1000))
        if biflow:
            data += struct.pack("!QQ", (f.resp_packets or 0) if split else 0, (f.resp_bytes or 0) if split else 0)
    if data:
        sets += struct.pack("!HH", template_id, 4 + len(data)) + data
    header = struct.pack("!HHIII", 10, 16 + len(sets), int(export_time.timestamp()), sequence, domain)
    return header + sets
