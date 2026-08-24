"""
UniShield — Flow CSV/JSON Reader

Reads generic flow records from CSV or JSON files and produces
NormalisedFlow records. Supports flexible column/field mapping.

SECURITY CONSTRAINTS:
    - READ-ONLY: Only reads from local files.
    - NO DECRYPTION: Metadata fields only.
"""

from __future__ import annotations

import csv
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

logger = logging.getLogger("unishield.ingest.flow")


# ---------------------------------------------------------------------------
# Default column mappings — maps common CSV/JSON field names to our schema
# ---------------------------------------------------------------------------

DEFAULT_FIELD_MAP = {
    # timestamp variants
    "timestamp": "timestamp",
    "ts": "timestamp",
    "time": "timestamp",
    "start_time": "timestamp",
    "flow_start": "timestamp",

    # IP fields
    "source_ip": "source_ip",
    "src_ip": "source_ip",
    "src": "source_ip",
    "src_addr": "source_ip",
    "ip.src": "source_ip",

    "destination_ip": "destination_ip",
    "dst_ip": "destination_ip",
    "dst": "destination_ip",
    "dst_addr": "destination_ip",
    "ip.dst": "destination_ip",

    # Port fields
    "source_port": "source_port",
    "src_port": "source_port",
    "sport": "source_port",

    "destination_port": "destination_port",
    "dst_port": "destination_port",
    "dport": "destination_port",

    # Protocol
    "protocol": "protocol",
    "proto": "protocol",
    "ip_protocol": "protocol",

    # Counts
    "packet_count": "packet_count",
    "packets": "packet_count",
    "pkts": "packet_count",
    "in_pkts": "packet_count",
    "tot_pkts": "packet_count",

    "byte_count": "byte_count",
    "bytes": "byte_count",
    "in_bytes": "byte_count",
    "tot_bytes": "byte_count",
    "octets": "byte_count",

    # Duration
    "duration": "duration",
    "flow_duration": "duration",

    # TCP
    "tcp_flags": "tcp_flags",
    "flags": "tcp_flags",

    # Direction
    "direction": "direction",
    "dir": "direction",

    # DNS
    "dns_query": "dns_query",
    "query": "dns_query",

    # Label (for labelled datasets)
    "label": "label",
    "attack_type": "label",
    "class": "label",
}


def _map_protocol_str(proto: str | int | None) -> ProtocolType:
    """Map various protocol representations to ProtocolType."""
    if proto is None:
        return ProtocolType.OTHER
    if isinstance(proto, int):
        if proto == 6:
            return ProtocolType.TCP
        elif proto == 17:
            return ProtocolType.UDP
        elif proto == 1:
            return ProtocolType.ICMP
        return ProtocolType.OTHER
    proto_str = str(proto).upper().strip()
    if proto_str in ("TCP", "6"):
        return ProtocolType.TCP
    elif proto_str in ("UDP", "17"):
        return ProtocolType.UDP
    elif proto_str in ("ICMP", "1"):
        return ProtocolType.ICMP
    return ProtocolType.OTHER


def _safe_int(value: Any) -> int | None:
    """Safely convert a value to int, returning None on failure."""
    if value is None or value == "" or value == "-":
        return None
    try:
        return int(float(value))
    except (ValueError, TypeError):
        return None


def _safe_float(value: Any) -> float | None:
    """Safely convert a value to float, returning None on failure."""
    if value is None or value == "" or value == "-":
        return None
    try:
        return float(value)
    except (ValueError, TypeError):
        return None


def _parse_flow_timestamp(value: Any) -> datetime:
    """Parse a timestamp from various flow record formats."""
    if isinstance(value, datetime):
        return value
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc)
    if isinstance(value, str):
        value = value.strip()
        # Try epoch float
        try:
            return datetime.fromtimestamp(float(value), tz=timezone.utc)
        except ValueError:
            pass
        # Try ISO format
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            pass
        # Try common date formats
        for fmt in ("%Y-%m-%d %H:%M:%S", "%d/%m/%Y %H:%M:%S", "%m/%d/%Y %H:%M:%S"):
            try:
                return datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
            except ValueError:
                continue
    raise ValueError(f"Cannot parse timestamp: {value}")


class FlowReader(BaseReader):
    """
    Read-only flow CSV/JSON reader with flexible field mapping.

    Supports:
    - CSV files with headers
    - JSON files (array or JSON-lines)
    - Custom field mapping via constructor
    """

    def __init__(
        self,
        source_path: Path | str,
        field_map: dict[str, str] | None = None,
        delimiter: str = ",",
    ):
        super().__init__(source_path)
        self.field_map = {**DEFAULT_FIELD_MAP, **(field_map or {})}
        self.delimiter = delimiter
        self._format: str | None = None  # "csv" or "json"

    def validate_source(self) -> bool:
        """Validate the flow file exists."""
        if self.source_path is None:
            return False
        p = Path(self.source_path)
        if not p.exists() or not p.is_file():
            logger.error("Flow file not found: %s", p)
            return False

        suffix = p.suffix.lower()
        if suffix == ".csv":
            self._format = "csv"
        elif suffix == ".json":
            self._format = "json"
        else:
            # Try to detect from content
            self._format = "csv"
            logger.warning("Unknown extension %s, assuming CSV", suffix)

        return True

    def read(self) -> Iterator[NormalisedFlow]:
        """Read flow records and yield NormalisedFlow objects."""
        if not self.validate_source():
            raise FileNotFoundError(f"Invalid flow source: {self.source_path}")

        logger.info("Reading flow file: %s (format=%s)", self.source_path, self._format)

        if self._format == "csv":
            yield from self._read_csv()
        elif self._format == "json":
            yield from self._read_json()
        else:
            yield from self._read_csv()  # Default fallback

        logger.info(
            "Flow read complete: %d records, %d errors",
            self._records_read,
            self._errors,
        )

    def _read_csv(self) -> Iterator[NormalisedFlow]:
        """Read CSV file with automatic field mapping."""
        with open(self.source_path, "r", encoding="utf-8", newline="") as f:
            reader = csv.DictReader(f, delimiter=self.delimiter)
            for row_num, row in enumerate(reader, 1):
                try:
                    mapped = self._map_fields(row)
                    flow = self._dict_to_flow(mapped, InputSource.FLOW_CSV)
                    self._records_read += 1
                    yield flow
                except Exception as e:
                    self._errors += 1
                    logger.debug("Error at CSV row %d: %s", row_num, e)

    def _read_json(self) -> Iterator[NormalisedFlow]:
        """Read JSON file (array or JSON-lines)."""
        content = Path(self.source_path).read_text(encoding="utf-8").strip()

        if content.startswith("["):
            records = json.loads(content)
        else:
            records = []
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError as e:
                    self._errors += 1
                    logger.debug("Skipping malformed JSON line: %s", e)

        for rec in records:
            try:
                mapped = self._map_fields(rec)
                flow = self._dict_to_flow(mapped, InputSource.FLOW_JSON)
                self._records_read += 1
                yield flow
            except Exception as e:
                self._errors += 1
                logger.debug("Error parsing flow JSON record: %s", e)

    def _map_fields(self, record: dict[str, Any]) -> dict[str, Any]:
        """Map input field names to our normalised schema names."""
        mapped: dict[str, Any] = {}
        for input_key, value in record.items():
            # Clean key (strip whitespace, lowercase for matching)
            clean_key = input_key.strip().lower().replace(" ", "_")
            schema_key = self.field_map.get(clean_key)
            if schema_key:
                mapped[schema_key] = value
            elif input_key.strip().lower() in self.field_map:
                mapped[self.field_map[input_key.strip().lower()]] = value

        # Also try exact match (case-sensitive)
        for input_key, value in record.items():
            if input_key in self.field_map:
                mapped[self.field_map[input_key]] = value

        return mapped

    def _dict_to_flow(
        self, data: dict[str, Any], source: InputSource
    ) -> NormalisedFlow:
        """Convert a mapped dictionary to a NormalisedFlow."""
        timestamp = _parse_flow_timestamp(data.get("timestamp"))

        src_ip = str(data.get("source_ip", "0.0.0.0"))
        dst_ip = str(data.get("destination_ip", "0.0.0.0"))

        src_port = _safe_int(data.get("source_port"))
        dst_port = _safe_int(data.get("destination_port"))

        # Clamp ports to valid range
        if src_port is not None and (src_port < 0 or src_port > 65535):
            src_port = None
        if dst_port is not None and (dst_port < 0 or dst_port > 65535):
            dst_port = None

        protocol = _map_protocol_str(data.get("protocol"))

        packet_count = _safe_int(data.get("packet_count")) or 1
        byte_count = _safe_int(data.get("byte_count")) or 0
        duration = _safe_float(data.get("duration"))

        tcp_flags = data.get("tcp_flags")
        if tcp_flags is not None:
            tcp_flags = str(tcp_flags)

        dns_query = data.get("dns_query")
        dns_query_length = len(dns_query) if dns_query else None

        return NormalisedFlow(
            timestamp=timestamp,
            source_ip=src_ip,
            destination_ip=dst_ip,
            source_port=src_port,
            destination_port=dst_port,
            protocol=protocol,
            packet_count=max(packet_count, 0),
            byte_count=max(byte_count, 0),
            duration=max(duration, 0.0) if duration is not None else None,
            tcp_flags=tcp_flags,
            direction=FlowDirection.UNKNOWN,
            dns_query=dns_query,
            dns_query_length=dns_query_length,
            source=source,
        )
