"""
UniShield — Flow CSV/JSON Reader

Reads flow records from CSV or JSON files and produces NormalisedFlow
records. Column names are matched case-insensitively after trimming and
replacing spaces with underscores, via ``DEFAULT_FIELD_MAP`` plus an
optional dataset profile.

Dataset profiles (auto-detected from the header, or chosen explicitly):
    cicids2017 — CICFlowMeter CSVs from CIC-IDS2017 ("TrafficLabelling"
                 files): forward/backward packet and byte columns, Flow
                 Duration in microseconds, dd/mm/yyyy timestamps that may
                 lack seconds. Timestamps in that dataset are local lab
                 time and are interpreted as UTC here. Some files write
                 afternoon times as 1:00-5:00 without AM/PM; the lab worked
                 roughly 08:00-17:00, so hours before 08 are read as PM.
    ctu13      — Argus bidirectional flows (".binetflow") from CTU-13:
                 StartTime/Dur/SrcAddr/Sport/DstAddr/Dport/State/TotPkts/
                 TotBytes/SrcBytes/Label. Reply bytes are TotBytes - SrcBytes;
                 Argus states ("S_RA", "FSPA_FSPA", "INT", "CON", ...) are
                 translated to the Zeek-style states the detectors use, and
                 the originator's TCP flags come from the state's source
                 half. Per-direction packet counts are not in the export.

Fields absent from a file stay None; rows without a timestamp or both IP
addresses are skipped and counted in ``errors`` (never fabricated).

SECURITY CONSTRAINTS:
    - READ-ONLY: Only reads from local files.
    - NO DECRYPTION: Metadata fields only.
"""

from __future__ import annotations

import csv
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterator, Optional

from unishield.ingest.base import BaseReader, chain_first
from unishield.schemas.flow import (
    FlowDirection,
    InputSource,
    NormalisedFlow,
    ProtocolType,
)

logger = logging.getLogger("unishield.ingest.flow")


# ---------------------------------------------------------------------------
# Column mappings — cleaned input name → schema field
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
    "tot_pkts": "packet_count",

    "byte_count": "byte_count",
    "bytes": "byte_count",
    "tot_bytes": "byte_count",
    "octets": "byte_count",

    "orig_packets": "orig_packets",
    "orig_pkts": "orig_packets",
    "resp_packets": "resp_packets",
    "resp_pkts": "resp_packets",
    "orig_bytes": "orig_bytes",
    "resp_bytes": "resp_bytes",

    # Duration (seconds unless a profile says otherwise)
    "duration": "duration",
    "flow_duration": "duration",

    # TCP / connection
    "tcp_flags": "tcp_flags",
    "flags": "tcp_flags",
    "conn_state": "conn_state",
    "flow_id": "flow_id",
    "uid": "flow_id",

    # Direction
    "direction": "direction",
    "dir": "direction",

    # DNS
    "dns_query": "dns_query",
    "query": "dns_query",
    "dns_record_type": "dns_record_type",
    "qtype_name": "dns_record_type",
    "dns_rcode": "dns_rcode",
    "rcode_name": "dns_rcode",

    # TLS
    "tls_version": "tls_version",
    "tls_cipher": "tls_cipher",
    "cipher": "tls_cipher",
    "ja3": "ja3",
    "ja4": "ja4",

    # Label (for labelled datasets; evaluation only)
    "label": "label",
    "attack_type": "label",
    "class": "label",
}

_DEFAULT_TIMESTAMP_FORMATS = (
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S",
    "%d/%m/%Y %H:%M:%S",
    "%d/%m/%Y %H:%M",
    "%m/%d/%Y %H:%M:%S",
    "%m/%d/%Y %H:%M",
)

_DIRECTIONS = {
    "inbound": FlowDirection.INBOUND, "in": FlowDirection.INBOUND, "ingress": FlowDirection.INBOUND,
    "outbound": FlowDirection.OUTBOUND, "out": FlowDirection.OUTBOUND, "egress": FlowDirection.OUTBOUND,
    "internal": FlowDirection.INTERNAL, "local": FlowDirection.INTERNAL,
}


@dataclass(frozen=True)
class DatasetProfile:
    """Column mapping and unit conventions of one dataset's flow export."""
    name: str
    field_map: dict[str, str]
    signature: frozenset[str]                      # cleaned columns that identify it
    duration_scale: float = 1.0                    # multiply to get seconds
    timestamp_formats: tuple[str, ...] = field(default=_DEFAULT_TIMESTAMP_FORMATS)
    row_hook: Optional[Callable[[dict[str, Any]], dict[str, Any]]] = None   # fix up mapped fields


_ARGUS_FLAGS = {"S": "SYN", "A": "ACK", "F": "FIN", "R": "RST", "P": "PSH", "U": "URG", "E": "ECE", "C": "CWR"}


def argus_conn_state(state: Optional[str], protocol: Optional[str]) -> tuple[Optional[str], Optional[str]]:
    """
    (Zeek-style conn_state, originator TCP flags) from an Argus state.

    TCP states are "<originator flags>_<responder flags>": "S_" is an
    unanswered SYN (S0), "S_RA" a SYN answered by a reset (REJ), FIN from both
    sides a completed connection (SF), a reset after the handshake RST, an
    answered handshake without FIN S1. Other protocols: INT (no reply) → S0,
    CON (both directions) → SF, anything else OTH.
    """
    text = (state or "").strip().upper()
    proto = (protocol or "").strip().upper()
    if not text:
        return None, None
    if proto == "TCP" and "_" in text:
        orig, resp = text.split("_", 1)
        flags = ",".join(sorted({_ARGUS_FLAGS[c] for c in orig if c in _ARGUS_FLAGS})) or None
        if not resp:
            conn = "S0" if "S" in orig else "OTH"
        elif "R" in resp and "S" not in resp:
            conn = "REJ" if "S" in orig and "A" not in orig else "RST"
        elif "F" in orig and "F" in resp:
            conn = "SF"
        elif "R" in orig or "R" in resp:
            conn = "RST"
        elif "S" in orig and "S" in resp:
            conn = "S1"
        else:
            conn = "OTH"
        return conn, flags
    if text == "INT":
        return "S0", None
    if text == "CON":
        return "SF", None
    return "OTH", None


_CICIDS_FORMATS = ("%d/%m/%Y %H:%M:%S", "%d/%m/%Y %H:%M", "%d/%m/%Y %I:%M:%S %p", "%d/%m/%Y %I:%M %p")


def _cicids_row(data: dict[str, Any]) -> dict[str, Any]:
    """CIC-IDS2017 writes afternoon times without AM/PM: hours before 08:00 are PM (lab hours 08-17)."""
    raw = _text(data.get("timestamp"))
    if raw and not raw.upper().endswith(("AM", "PM")):
        for fmt in _CICIDS_FORMATS[:2]:
            try:
                ts = datetime.strptime(raw, fmt).replace(tzinfo=timezone.utc)
            except ValueError:
                continue
            data["timestamp"] = ts + timedelta(hours=12) if ts.hour < 8 else ts
            break
    return data


def _ctu13_row(data: dict[str, Any]) -> dict[str, Any]:
    total, orig = _safe_int(data.get("byte_count")), _safe_int(data.get("orig_bytes"))
    if total is not None and orig is not None and 0 <= orig <= total:
        data["resp_bytes"] = total - orig
    data["conn_state"], flags = argus_conn_state(data.get("conn_state"), data.get("protocol"))
    if flags:
        data["tcp_flags"] = flags
    data.pop("direction", None)                    # Argus "->"/"<->" is not a network direction
    return data


PROFILES: dict[str, DatasetProfile] = {
    "cicids2017": DatasetProfile(
        name="cicids2017",
        field_map={
            "flow_id": "flow_id",
            "flow_duration": "duration",
            "total_fwd_packets": "orig_packets",
            "total_backward_packets": "resp_packets",
            "total_length_of_fwd_packets": "orig_bytes",
            "total_length_of_bwd_packets": "resp_bytes",
        },
        signature=frozenset({"flow_duration", "total_fwd_packets", "total_backward_packets"}),
        duration_scale=1e-6,
        timestamp_formats=_CICIDS_FORMATS,
        row_hook=_cicids_row,
    ),
    "ctu13": DatasetProfile(
        name="ctu13",
        field_map={
            "starttime": "timestamp",
            "dur": "duration",
            "srcaddr": "source_ip",
            "dstaddr": "destination_ip",
            "state": "conn_state",
            "totpkts": "packet_count",
            "totbytes": "byte_count",
            "srcbytes": "orig_bytes",
        },
        signature=frozenset({"starttime", "srcaddr", "dstaddr", "totbytes", "srcbytes"}),
        timestamp_formats=("%Y/%m/%d %H:%M:%S.%f", "%Y/%m/%d %H:%M:%S"),
        row_hook=_ctu13_row,
    ),
}


# ---------------------------------------------------------------------------
# Value helpers
# ---------------------------------------------------------------------------

def _clean_key(key: str) -> str:
    return key.strip().lower().replace(" ", "_")


def _map_protocol_str(proto: str | int | None) -> ProtocolType:
    """Map various protocol representations to ProtocolType."""
    if proto is None:
        return ProtocolType.OTHER
    proto_str = str(proto).upper().strip()
    if proto_str in ("TCP", "6"):
        return ProtocolType.TCP
    if proto_str in ("UDP", "17"):
        return ProtocolType.UDP
    if proto_str in ("ICMP", "1", "ICMPV6", "58"):
        return ProtocolType.ICMP
    return ProtocolType.OTHER


def _safe_int(value: Any) -> int | None:
    """Convert to int, returning None for missing or invalid values."""
    if value is None or value == "" or value == "-":
        return None
    try:
        return int(float(value))
    except (ValueError, TypeError, OverflowError):
        return None


def _safe_float(value: Any) -> float | None:
    """Convert to a finite float, returning None for missing or invalid values."""
    if value is None or value == "" or value == "-":
        return None
    try:
        result = float(value)
    except (ValueError, TypeError):
        return None
    return result if result == result and result not in (float("inf"), float("-inf")) else None


def _non_negative(value: int | None) -> int | None:
    return value if value is None or value >= 0 else None


def _text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _parse_flow_timestamp(value: Any, formats: tuple[str, ...] = _DEFAULT_TIMESTAMP_FORMATS) -> datetime:
    """Parse a timestamp from epoch seconds, ISO 8601 or one of ``formats``."""
    if isinstance(value, datetime):
        return value
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc)
    if isinstance(value, str):
        value = value.strip()
        try:
            return datetime.fromtimestamp(float(value), tz=timezone.utc)
        except ValueError:
            pass
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            pass
        for fmt in formats:
            try:
                return datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
            except ValueError:
                continue
    raise ValueError(f"Cannot parse timestamp: {value!r}")


# ---------------------------------------------------------------------------
# Reader
# ---------------------------------------------------------------------------

class FlowReader(BaseReader):
    """
    Read-only flow CSV/JSON reader with flexible field mapping.

    Supports CSV with headers, JSON lines (streamed) and JSON arrays.
    """

    def __init__(
        self,
        source_path: Path | str,
        field_map: dict[str, str] | None = None,
        delimiter: str = ",",
        profile: str = "auto",
    ):
        super().__init__(source_path)
        self._user_map = {_clean_key(k): v for k, v in (field_map or {}).items()}
        self.delimiter = delimiter
        if profile not in ("auto", "none") and profile not in PROFILES:
            raise ValueError(f"Unknown dataset profile: {profile!r} (known: {sorted(PROFILES)})")
        self._profile_choice = profile
        self.profile: Optional[DatasetProfile] = PROFILES.get(profile)
        self._format: str | None = None  # "csv" or "json"

    @property
    def field_map(self) -> dict[str, str]:
        mapping = dict(DEFAULT_FIELD_MAP)
        if self.profile:
            mapping.update(self.profile.field_map)
        mapping.update(self._user_map)
        return mapping

    def validate_source(self) -> bool:
        """Validate the flow file exists and decide CSV vs JSON."""
        if self.source_path is None:
            return False
        p = Path(self.source_path)
        if not p.is_file():
            logger.error("Flow file not found: %s", p)
            return False

        suffix = p.suffix.lower()
        if suffix in (".csv", ".tsv"):
            self._format = "csv"
        elif suffix in (".json", ".jsonl", ".ndjson"):
            self._format = "json"
        else:
            with open(p, "r", encoding="utf-8", errors="replace") as f:
                head = f.read(4096).lstrip()
            self._format = "json" if head[:1] in ("{", "[") else "csv"
        return True

    def read(self) -> Iterator[NormalisedFlow]:
        """Read flow records and yield NormalisedFlow objects."""
        if not self.validate_source():
            raise FileNotFoundError(f"Invalid flow source: {self.source_path}")

        logger.info("Reading flow file: %s (format=%s)", self.source_path, self._format)
        if self._format == "json":
            yield from self._read_json()
        else:
            yield from self._read_csv()

        logger.info(
            "Flow read complete: %d records, %d errors (profile=%s)",
            self._records_read,
            self._errors,
            self.profile.name if self.profile else "none",
        )

    # -------------------------------------------------------------- formats

    def _select_profile(self, cleaned_keys: set[str]) -> None:
        if self._profile_choice != "auto":
            return
        for profile in PROFILES.values():
            if profile.signature <= cleaned_keys:
                self.profile = profile
                logger.info("Detected dataset profile: %s", profile.name)
                return

    def _read_csv(self) -> Iterator[NormalisedFlow]:
        """Read a CSV file; the header-to-field mapping is computed once."""
        # errors="replace": public datasets contain stray non-UTF-8 bytes in labels.
        with open(self.source_path, "r", encoding="utf-8", errors="replace", newline="") as f:
            reader = csv.DictReader(f, delimiter=self.delimiter)
            if not reader.fieldnames:
                return
            self._select_profile({_clean_key(k) for k in reader.fieldnames})
            mapping = self.field_map
            header_map = {k: mapping[_clean_key(k)] for k in reader.fieldnames if _clean_key(k) in mapping}
            for row_num, row in enumerate(reader, 1):
                try:
                    mapped = {schema: row[raw] for raw, schema in header_map.items()}
                    flow = self._dict_to_flow(mapped, InputSource.FLOW_CSV)
                    self._records_read += 1
                    yield flow
                except Exception as e:
                    self._errors += 1
                    logger.debug("Error at CSV row %d: %s", row_num, e)

    def _read_json(self) -> Iterator[NormalisedFlow]:
        """Read JSON lines (streamed) or a JSON array."""
        with open(self.source_path, "r", encoding="utf-8", errors="replace") as f:
            first = ""
            for line in f:
                if line.strip():
                    first = line
                    break
            if not first:
                return
            if first.lstrip().startswith("["):
                records: Iterator[Any] = iter(json.loads(first + f.read()))
            else:
                records = self._json_lines(first, f)
            for rec in records:
                try:
                    if self.profile is None and self._profile_choice == "auto":
                        self._select_profile({_clean_key(k) for k in rec})
                    flow = self._dict_to_flow(self._map_fields(rec), InputSource.FLOW_JSON)
                    self._records_read += 1
                    yield flow
                except Exception as e:
                    self._errors += 1
                    logger.debug("Error parsing flow JSON record: %s", e)

    def _json_lines(self, first: str, f) -> Iterator[dict[str, Any]]:
        for line in chain_first(first, f):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError as e:
                self._errors += 1
                logger.debug("Skipping malformed JSON line: %s", e)

    def _map_fields(self, record: dict[str, Any]) -> dict[str, Any]:
        """Map input field names to normalised schema names."""
        mapping = self.field_map
        return {mapping[_clean_key(k)]: v for k, v in record.items() if _clean_key(k) in mapping}

    # -------------------------------------------------------------- record

    def _dict_to_flow(self, data: dict[str, Any], source: InputSource) -> NormalisedFlow:
        """Convert a mapped dictionary to a NormalisedFlow."""
        formats = self.profile.timestamp_formats if self.profile else _DEFAULT_TIMESTAMP_FORMATS
        if self.profile and self.profile.row_hook:
            data = self.profile.row_hook(data)
        if data.get("timestamp") in (None, ""):
            raise ValueError("missing timestamp")
        timestamp = _parse_flow_timestamp(data["timestamp"], formats)

        src_ip, dst_ip = _text(data.get("source_ip")), _text(data.get("destination_ip"))
        if src_ip is None or dst_ip is None:
            raise ValueError("missing source or destination IP")

        def port(key: str) -> int | None:
            value = _safe_int(data.get(key))
            return value if value is not None and 0 <= value <= 65535 else None

        orig_pkts = _non_negative(_safe_int(data.get("orig_packets")))
        resp_pkts = _non_negative(_safe_int(data.get("resp_packets")))
        orig_bytes = _non_negative(_safe_int(data.get("orig_bytes")))
        resp_bytes = _non_negative(_safe_int(data.get("resp_bytes")))

        if orig_pkts is not None or resp_pkts is not None:
            packet_count = (orig_pkts or 0) + (resp_pkts or 0)
        else:
            packet_count = _non_negative(_safe_int(data.get("packet_count")))
            packet_count = 1 if packet_count is None else packet_count
        if orig_bytes is not None or resp_bytes is not None:
            byte_count = (orig_bytes or 0) + (resp_bytes or 0)
        else:
            byte_count = _non_negative(_safe_int(data.get("byte_count"))) or 0

        duration = _safe_float(data.get("duration"))
        if duration is not None:
            duration *= self.profile.duration_scale if self.profile else 1.0
            if duration < 0:
                duration = None   # invalid in source; not clamped

        dns_query = _text(data.get("dns_query"))
        direction = _DIRECTIONS.get(str(data.get("direction", "")).strip().lower(),
                                    FlowDirection.UNKNOWN)

        return NormalisedFlow(
            flow_id=_text(data.get("flow_id")),
            timestamp=timestamp,
            source_ip=src_ip,
            destination_ip=dst_ip,
            source_port=port("source_port"),
            destination_port=port("destination_port"),
            protocol=_map_protocol_str(data.get("protocol")),
            packet_count=packet_count,
            byte_count=byte_count,
            orig_packets=orig_pkts,
            resp_packets=resp_pkts,
            orig_bytes=orig_bytes,
            resp_bytes=resp_bytes,
            duration=duration,
            tcp_flags=_text(data.get("tcp_flags")),
            conn_state=_text(data.get("conn_state")),
            direction=direction,
            dns_query=dns_query,
            dns_query_length=len(dns_query) if dns_query else None,
            dns_record_type=_text(data.get("dns_record_type")),
            dns_rcode=_text(data.get("dns_rcode")),
            tls_version=_text(data.get("tls_version")),
            tls_cipher=_text(data.get("tls_cipher")),
            ja3=_text(data.get("ja3")),
            ja4=_text(data.get("ja4")),
            label=_text(data.get("label")),
            source_type=source,
        )
