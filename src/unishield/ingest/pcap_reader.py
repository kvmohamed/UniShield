"""
UniShield — PCAP Reader

Reads PCAP/PCAPNG files using Scapy and produces one NormalisedFlow record
per IP packet. These packet-level records are aggregated into
bidirectional flows by ``processing.sessionizer`` (the pipeline does this
automatically because ``packet_level`` is True).

SECURITY CONSTRAINTS:
    - READ-ONLY: Only reads from local files with Scapy's offline reader.
      Never sends packets.
    - NO DECRYPTION: Extracts metadata only (IPs, ports, sizes, flags, DNS
      question/response code, plaintext TLS hello fields).
    - NO ACTIVE SCANNING: Never probes any address found in captures.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from unishield.ingest.base import BaseReader
from unishield.ingest.tls import parse_tls_hello
from unishield.schemas.flow import (
    FlowDirection,
    InputSource,
    NormalisedFlow,
    ProtocolType,
)

logger = logging.getLogger("unishield.ingest.pcap")


def quiet_scapy_import_warnings() -> None:
    """Scapy warns at import when no live-capture driver (Npcap/libpcap) is
    installed. Reading files offline does not need one, so hide the notice."""
    for name in ("scapy.loading", "scapy.runtime"):
        logging.getLogger(name).setLevel(logging.ERROR)


quiet_scapy_import_warnings()


# ---------------------------------------------------------------------------
# Field helpers
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

_DNS_TYPES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR",
    15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 65: "HTTPS", 255: "ANY",
}

_DNS_RCODES = {
    0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED",
}


def _flags_to_str(flags_int: int) -> str:
    """Convert a TCP flags integer to a comma-separated string."""
    parts = [name for bit, name in _TCP_FLAGS.items() if flags_int & bit]
    return ",".join(parts)


def _dns_type_str(qtype: int) -> str:
    """Convert DNS query type number to string."""
    return _DNS_TYPES.get(qtype, f"TYPE{qtype}")


class PcapReader(BaseReader):
    """
    Read-only PCAP/PCAPNG file reader.

    Streams packets with Scapy (memory use does not grow with file size).
    Non-IP frames are skipped and counted in ``skipped``.
    """

    #: Records are individual packets; the pipeline sessionizes them.
    packet_level = True

    def __init__(self, source_path: Path | str):
        super().__init__(source_path)
        self.skipped: int = 0

    def validate_source(self) -> bool:
        """Check that the PCAP file exists and is readable."""
        if self.source_path is None:
            return False
        p = Path(self.source_path)
        if not p.is_file():
            logger.error("PCAP file not found: %s", p)
            return False
        return True

    def read(self) -> Iterator[NormalisedFlow]:
        """
        Stream packets from a PCAP/PCAPNG file, yielding one record per
        IPv4/IPv6 packet.

        SECURITY: This method only READS. It never sends packets,
        performs lookups, or contacts external systems.
        """
        if not self.validate_source():
            raise FileNotFoundError(f"Invalid PCAP source: {self.source_path}")

        try:
            from scapy.layers.dns import DNS
            from scapy.layers.inet import ICMP, IP, TCP, UDP
            from scapy.layers.inet6 import IPv6
            from scapy.utils import PcapReader as ScapyPcapReader
        except ImportError as exc:
            raise ImportError(
                "Scapy is required for PCAP reading. Install it with: pip install scapy"
            ) from exc

        logger.info("Reading PCAP file: %s", self.source_path)

        with ScapyPcapReader(str(self.source_path)) as reader:
            for pkt in reader:
                try:
                    if pkt.haslayer(IP):
                        ip_layer = pkt[IP]
                    elif pkt.haslayer(IPv6):
                        ip_layer = pkt[IPv6]
                    else:
                        self.skipped += 1
                        continue

                    flow = self._packet_to_flow(pkt, ip_layer, TCP, UDP, ICMP, DNS)
                    self._records_read += 1
                    yield flow
                except Exception as e:
                    self._errors += 1
                    logger.debug("Error processing packet: %s", e)

        logger.info(
            "PCAP read complete: %d records, %d errors, %d non-IP skipped",
            self._records_read,
            self._errors,
            self.skipped,
        )

    @staticmethod
    def _packet_to_flow(pkt, ip_layer, TCP, UDP, ICMP, DNS) -> NormalisedFlow:
        """Convert one IP packet to a packet-level NormalisedFlow."""
        src_port = dst_port = None
        tcp_flags = None
        tls_version = tls_cipher = ja3 = None

        if pkt.haslayer(TCP):
            protocol = ProtocolType.TCP
            tcp_layer = pkt[TCP]
            src_port, dst_port = int(tcp_layer.sport), int(tcp_layer.dport)
            tcp_flags = _flags_to_str(int(tcp_layer.flags))
            payload = bytes(tcp_layer.payload)
            if len(payload) > 5 and payload[0] == 0x16 and payload[1] == 0x03:
                hello = parse_tls_hello(payload)
                if hello is not None:
                    tls_version, tls_cipher, ja3 = hello.version, hello.cipher, hello.ja3
        elif pkt.haslayer(UDP):
            protocol = ProtocolType.UDP
            src_port, dst_port = int(pkt[UDP].sport), int(pkt[UDP].dport)
        elif pkt.haslayer(ICMP) or getattr(ip_layer, "nh", None) == 58:
            protocol = ProtocolType.ICMP
        else:
            protocol = ProtocolType.OTHER

        # DNS metadata: question name/type and, for responses, the rcode.
        dns_query = dns_record_type = dns_rcode = None
        if pkt.haslayer(DNS):
            dns_layer = pkt[DNS]
            qd = dns_layer.qd
            question = (qd[0] if qd else None) if isinstance(qd, list) else qd
            if question is not None:
                qname = question.qname
                if isinstance(qname, bytes):
                    qname = qname.decode("utf-8", errors="replace")
                dns_query = qname.rstrip(".") or None
                dns_record_type = _dns_type_str(int(question.qtype))
            if int(dns_layer.qr) == 1:
                dns_rcode = _DNS_RCODES.get(int(dns_layer.rcode), f"RCODE{int(dns_layer.rcode)}")

        return NormalisedFlow(
            timestamp=datetime.fromtimestamp(float(pkt.time), tz=timezone.utc),
            source_ip=ip_layer.src,
            destination_ip=ip_layer.dst,
            source_port=src_port,
            destination_port=dst_port,
            protocol=protocol,
            packet_count=1,
            byte_count=int(getattr(pkt, "wirelen", None) or len(pkt)),
            duration=0.0,
            tcp_flags=tcp_flags,
            direction=FlowDirection.UNKNOWN,
            dns_query=dns_query,
            dns_query_length=len(dns_query) if dns_query else None,
            dns_record_type=dns_record_type,
            dns_rcode=dns_rcode,
            tls_version=tls_version,
            tls_cipher=tls_cipher,
            ja3=ja3,
            source_type=InputSource.PCAP,
        )
