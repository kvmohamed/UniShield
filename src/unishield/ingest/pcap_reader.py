"""
UniShield — PCAP Reader

Reads PCAP/PCAPNG files using Scapy and produces NormalisedFlow records.

SECURITY CONSTRAINTS:
    - READ-ONLY: Only reads from local files. Never sends packets.
    - NO DECRYPTION: Extracts metadata only (IPs, ports, sizes, flags).
    - NO ACTIVE SCANNING: Never probes any address found in captures.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from unishield.ingest.base import BaseReader
from unishield.schemas.flow import (
    FlowDirection,
    InputSource,
    NormalisedFlow,
    ProtocolType,
)

logger = logging.getLogger("unishield.ingest.pcap")


# ---------------------------------------------------------------------------
# TCP flag helpers
# ---------------------------------------------------------------------------

_TCP_FLAGS = {
    0x01: "FIN",
    0x02: "SYN",
    0x04: "RST",
    0x08: "PSH",
    0x10: "ACK",
    0x20: "URG",
    0x40: "ECE",
    0x80: "CWR",
}


def _flags_to_str(flags_int: int) -> str:
    """Convert a TCP flags integer to a comma-separated string."""
    parts = [name for bit, name in _TCP_FLAGS.items() if flags_int & bit]
    return ",".join(parts) if parts else ""


def _protocol_from_number(proto_num: int) -> ProtocolType:
    """Map IP protocol number to ProtocolType enum."""
    if proto_num == 6:
        return ProtocolType.TCP
    elif proto_num == 17:
        return ProtocolType.UDP
    elif proto_num == 1:
        return ProtocolType.ICMP
    return ProtocolType.OTHER


class PcapReader(BaseReader):
    """
    Read-only PCAP/PCAPNG file reader.

    Uses Scapy's PcapReader for memory-efficient streaming.
    Extracts only metadata — never inspects or decrypts payload content.
    """

    def __init__(self, source_path: Path | str):
        super().__init__(source_path)

    def validate_source(self) -> bool:
        """Check that the PCAP file exists and is readable."""
        if self.source_path is None:
            return False
        p = Path(self.source_path)
        if not p.exists():
            logger.error("PCAP file not found: %s", p)
            return False
        if not p.is_file():
            logger.error("Path is not a file: %s", p)
            return False
        suffix = p.suffix.lower()
        if suffix not in (".pcap", ".pcapng", ".cap"):
            logger.warning("Unexpected file extension: %s", suffix)
        return True

    def read(self) -> Iterator[NormalisedFlow]:
        """
        Stream packets from a PCAP file, yielding NormalisedFlow records.

        Each IP-layer packet is converted to one flow record.
        Non-IP packets are skipped with a warning counter.

        SECURITY: This method only READS. It never sends packets,
        performs lookups, or contacts external systems.
        """
        if not self.validate_source():
            raise FileNotFoundError(f"Invalid PCAP source: {self.source_path}")

        try:
            from scapy.all import PcapReader as ScapyPcapReader, IP, TCP, UDP, ICMP, DNS
        except ImportError:
            raise ImportError(
                "Scapy is required for PCAP reading. "
                "Install it with: pip install scapy"
            )

        logger.info("Reading PCAP file: %s", self.source_path)
        skipped = 0

        with ScapyPcapReader(str(self.source_path)) as reader:
            for pkt in reader:
                try:
                    # Only process IP packets
                    if not pkt.haslayer(IP):
                        skipped += 1
                        continue

                    ip_layer = pkt[IP]
                    timestamp = datetime.fromtimestamp(
                        float(pkt.time), tz=timezone.utc
                    )

                    # Base fields
                    src_ip = ip_layer.src
                    dst_ip = ip_layer.dst
                    protocol = _protocol_from_number(ip_layer.proto)
                    byte_count = len(pkt)

                    # Transport-layer metadata
                    src_port = None
                    dst_port = None
                    tcp_flags = None

                    if pkt.haslayer(TCP):
                        tcp_layer = pkt[TCP]
                        src_port = tcp_layer.sport
                        dst_port = tcp_layer.dport
                        tcp_flags = _flags_to_str(int(tcp_layer.flags))
                    elif pkt.haslayer(UDP):
                        udp_layer = pkt[UDP]
                        src_port = udp_layer.sport
                        dst_port = udp_layer.dport

                    # DNS metadata (from query name only — no payload decryption)
                    dns_query = None
                    dns_query_length = None
                    dns_record_type = None

                    if pkt.haslayer(DNS):
                        dns_layer = pkt[DNS]
                        if dns_layer.qd:  # DNS question section
                            qname = dns_layer.qd.qname
                            if isinstance(qname, bytes):
                                qname = qname.decode("utf-8", errors="replace")
                            # Remove trailing dot
                            dns_query = qname.rstrip(".")
                            dns_query_length = len(dns_query)
                            # Map qtype number to string
                            dns_record_type = _dns_type_str(dns_layer.qd.qtype)

                    # TLS metadata — extract from ClientHello if present
                    # We do NOT decrypt. We only read the version from the
                    # TLS record header if it's visible in plaintext.
                    tls_version = None
                    if dst_port == 443 or src_port == 443:
                        tls_version = _extract_tls_version(pkt)

                    flow = NormalisedFlow(
                        timestamp=timestamp,
                        source_ip=src_ip,
                        destination_ip=dst_ip,
                        source_port=src_port,
                        destination_port=dst_port,
                        protocol=protocol,
                        packet_count=1,
                        byte_count=byte_count,
                        duration=0.0,
                        tcp_flags=tcp_flags,
                        direction=FlowDirection.UNKNOWN,
                        dns_query=dns_query,
                        dns_query_length=dns_query_length,
                        dns_record_type=dns_record_type,
                        tls_version=tls_version,
                        source=InputSource.PCAP,
                    )

                    self._records_read += 1
                    yield flow

                except Exception as e:
                    self._errors += 1
                    logger.debug("Error processing packet: %s", e)
                    continue

        logger.info(
            "PCAP read complete: %d records, %d errors, %d non-IP skipped",
            self._records_read,
            self._errors,
            skipped,
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_DNS_TYPES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR",
    15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY",
}


def _dns_type_str(qtype: int) -> str:
    """Convert DNS query type number to string."""
    return _DNS_TYPES.get(qtype, f"TYPE{qtype}")


def _extract_tls_version(pkt) -> str | None:
    """
    Attempt to extract TLS version from the record header.
    This reads ONLY the unencrypted TLS record header — no decryption.
    Returns None if TLS layer is not present or not parseable.
    """
    try:
        # Check raw payload for TLS record header (type 0x16 = Handshake)
        raw = bytes(pkt.payload.payload.payload) if hasattr(pkt, 'payload') else b""
        if len(raw) < 5:
            return None
        if raw[0] == 0x16:  # TLS Handshake
            major, minor = raw[1], raw[2]
            versions = {
                (3, 0): "SSLv3",
                (3, 1): "TLSv1.0",
                (3, 2): "TLSv1.1",
                (3, 3): "TLSv1.2",
                (3, 4): "TLSv1.3",
            }
            return versions.get((major, minor))
    except Exception:
        pass
    return None
