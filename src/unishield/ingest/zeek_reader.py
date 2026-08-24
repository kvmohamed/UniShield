"""
UniShield — Zeek JSON Reader

Reads Zeek conn.log JSON format and produces NormalisedFlow records.

Supports both:
- JSON lines format (one JSON object per line, standard Zeek JSON output)
- Array format (a JSON array of objects)

SECURITY CONSTRAINTS:
    - READ-ONLY: Only reads from local files.
    - NO DECRYPTION: Extracts metadata fields only.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from unishield.ingest.base import BaseReader
from unishield.schemas.flow import (
    FlowDirection,
    InputSource,
    NormalisedFlow,
    ProtocolType,
)

logger = logging.getLogger("unishield.ingest.zeek")


# ---------------------------------------------------------------------------
# Zeek protocol mapping
# ---------------------------------------------------------------------------

_ZEEK_PROTO_MAP = {
    "tcp": ProtocolType.TCP,
    "udp": ProtocolType.UDP,
    "icmp": ProtocolType.ICMP,
}


def _map_protocol(proto_str: str | None) -> ProtocolType:
    """Map Zeek protocol string to ProtocolType."""
    if proto_str is None:
        return ProtocolType.OTHER
    return _ZEEK_PROTO_MAP.get(proto_str.lower(), ProtocolType.OTHER)


def _parse_zeek_timestamp(ts_value: Any) -> datetime:
    """
    Parse Zeek timestamp.
    Zeek uses epoch floats (e.g. 1695050400.123456) or ISO strings.
    """
    if isinstance(ts_value, (int, float)):
        return datetime.fromtimestamp(ts_value, tz=timezone.utc)
    if isinstance(ts_value, str):
        # Try epoch float in string form
        try:
            return datetime.fromtimestamp(float(ts_value), tz=timezone.utc)
        except ValueError:
            return datetime.fromisoformat(ts_value.replace("Z", "+00:00"))
    raise ValueError(f"Cannot parse Zeek timestamp: {ts_value}")


def _parse_direction(conn_state: str | None, orig_bytes: int, resp_bytes: int) -> FlowDirection:
    """Infer direction from Zeek connection state and byte counts."""
    # Zeek doesn't directly tell us direction relative to a monitored network,
    # but we can use heuristics or default to UNKNOWN
    return FlowDirection.UNKNOWN


def _parse_tcp_flags(history: str | None) -> str | None:
    """
    Convert Zeek connection history to TCP flags summary.
    Zeek history: S=SYN, H=SYN+ACK, A=ACK, D=data, F=FIN, R=RST, etc.
    Lowercase = responder, uppercase = originator.
    """
    if not history:
        return None

    flags = set()
    flag_map = {
        "S": "SYN", "s": "SYN",
        "H": "SYN,ACK", "h": "SYN,ACK",
        "A": "ACK", "a": "ACK",
        "F": "FIN", "f": "FIN",
        "R": "RST", "r": "RST",
    }
    for ch in history:
        if ch in flag_map:
            flags.add(flag_map[ch])

    return ",".join(sorted(flags)) if flags else None


class ZeekReader(BaseReader):
    """
    Read-only Zeek JSON conn.log reader.

    Parses Zeek's JSON log format and normalises each connection
    record to NormalisedFlow. Supports JSON lines and array formats.
    """

    def __init__(self, source_path: Path | str):
        super().__init__(source_path)

    def validate_source(self) -> bool:
        """Validate the Zeek JSON file exists and is readable."""
        if self.source_path is None:
            return False
        p = Path(self.source_path)
        if not p.exists():
            logger.error("Zeek file not found: %s", p)
            return False
        if not p.is_file():
            logger.error("Path is not a file: %s", p)
            return False
        return True

    def read(self) -> Iterator[NormalisedFlow]:
        """
        Read Zeek JSON records and yield NormalisedFlow objects.

        Handles both JSON-lines (one object per line) and JSON array formats.
        Fields not present in a record are set to None.
        """
        if not self.validate_source():
            raise FileNotFoundError(f"Invalid Zeek source: {self.source_path}")

        logger.info("Reading Zeek JSON file: %s", self.source_path)

        path = Path(self.source_path)
        content = path.read_text(encoding="utf-8").strip()

        # Detect format: JSON array or JSON lines
        if content.startswith("["):
            records = json.loads(content)
        else:
            records = []
            for line_num, line in enumerate(content.splitlines(), 1):
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("//"):
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError as e:
                    self._errors += 1
                    logger.debug("Skipping malformed JSON at line %d: %s", line_num, e)

        for record in records:
            try:
                flow = self._parse_record(record)
                self._records_read += 1
                yield flow
            except Exception as e:
                self._errors += 1
                logger.debug("Error parsing Zeek record: %s", e)

        logger.info(
            "Zeek read complete: %d records, %d errors",
            self._records_read,
            self._errors,
        )

    def _parse_record(self, rec: dict[str, Any]) -> NormalisedFlow:
        """Parse a single Zeek conn.log JSON record into a NormalisedFlow."""

        # Timestamp — Zeek uses 'ts' field
        ts_raw = rec.get("ts")
        if ts_raw is None:
            raise ValueError("Missing 'ts' field in Zeek record")
        timestamp = _parse_zeek_timestamp(ts_raw)

        # IPs
        src_ip = rec.get("id.orig_h") or rec.get("id_orig_h") or rec.get("src_ip", "0.0.0.0")
        dst_ip = rec.get("id.resp_h") or rec.get("id_resp_h") or rec.get("dst_ip", "0.0.0.0")

        # Ports
        src_port = rec.get("id.orig_p") or rec.get("id_orig_p") or rec.get("src_port")
        dst_port = rec.get("id.resp_p") or rec.get("id_resp_p") or rec.get("dst_port")

        if src_port is not None:
            src_port = int(src_port)
        if dst_port is not None:
            dst_port = int(dst_port)

        # Protocol
        protocol = _map_protocol(rec.get("proto"))

        # Byte and packet counts
        orig_bytes = int(rec.get("orig_bytes", 0) or 0)
        resp_bytes = int(rec.get("resp_bytes", 0) or 0)
        orig_pkts = int(rec.get("orig_pkts", 0) or 0)
        resp_pkts = int(rec.get("resp_pkts", 0) or 0)

        byte_count = orig_bytes + resp_bytes
        packet_count = orig_pkts + resp_pkts
        if packet_count == 0:
            packet_count = 1  # At least one packet created this record

        # Duration
        duration = rec.get("duration")
        if duration is not None:
            try:
                duration = float(duration)
            except (ValueError, TypeError):
                duration = None

        # TCP flags from connection history
        tcp_flags = _parse_tcp_flags(rec.get("history"))

        # Direction
        direction = _parse_direction(
            rec.get("conn_state"), orig_bytes, resp_bytes
        )

        # DNS metadata (from Zeek dns.log fields if present)
        dns_query = rec.get("query")
        dns_query_length = len(dns_query) if dns_query else None
        dns_record_type = rec.get("qtype_name") or rec.get("qtype")
        if dns_record_type is not None:
            dns_record_type = str(dns_record_type)

        # TLS metadata (from Zeek ssl.log fields if present)
        tls_version = rec.get("version") or rec.get("tls_version")
        tls_cipher = rec.get("cipher")
        ja3_hash = rec.get("ja3")
        ja4_hash = rec.get("ja4")

        return NormalisedFlow(
            timestamp=timestamp,
            source_ip=src_ip,
            destination_ip=dst_ip,
            source_port=src_port,
            destination_port=dst_port,
            protocol=protocol,
            packet_count=packet_count,
            byte_count=byte_count,
            duration=duration,
            tcp_flags=tcp_flags,
            direction=direction,
            dns_query=dns_query,
            dns_query_length=dns_query_length,
            dns_record_type=dns_record_type,
            tls_version=tls_version,
            tls_cipher=tls_cipher,
            ja3=ja3_hash,
            ja4=ja4_hash,
            source=InputSource.ZEEK_JSON,
        )
