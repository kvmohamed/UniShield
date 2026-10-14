"""
UniShield — Zeek Log Reader

Reads Zeek logs and produces NormalisedFlow records.

Supported inputs:
    - JSON lines (Zeek with ``LogAscii::use_json=T``), streamed line by line
    - a JSON array of records
    - Zeek's default tab-separated (TSV) format with ``#fields``/``#types`` headers
    - a directory containing ``conn.log`` and optionally ``dns.log`` / ``ssl.log``:
      conn records are enriched with DNS and TLS fields joined on ``uid``

A single conn.log gives full flow metadata; a single dns.log or ssl.log
gives one record per log line with only the fields that log carries
(packet/byte counts unknown).

SECURITY CONSTRAINTS:
    - READ-ONLY: Only reads from local files.
    - NO DECRYPTION: Extracts metadata fields only.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Optional

from unishield.ingest.base import BaseReader, chain_first
from unishield.processing.normalization import normalize_tls_version
from unishield.schemas.flow import (
    FlowDirection,
    InputSource,
    NormalisedFlow,
    ProtocolType,
)

logger = logging.getLogger("unishield.ingest.zeek")


# ---------------------------------------------------------------------------
# Field helpers
# ---------------------------------------------------------------------------

_ZEEK_PROTO_MAP = {
    "tcp": ProtocolType.TCP,
    "udp": ProtocolType.UDP,
    "icmp": ProtocolType.ICMP,
}

# Uppercase history letters are originator events (lowercase: responder).
_HISTORY_ORIG_FLAGS = {
    "S": ("SYN",),
    "H": ("SYN", "ACK"),
    "A": ("ACK",),
    "F": ("FIN",),
    "R": ("RST",),
}


def _map_protocol(proto_str: str | None) -> ProtocolType:
    """Map Zeek protocol string to ProtocolType."""
    if proto_str is None:
        return ProtocolType.OTHER
    return _ZEEK_PROTO_MAP.get(str(proto_str).lower(), ProtocolType.OTHER)


def _parse_zeek_timestamp(ts_value: Any) -> datetime:
    """Zeek uses epoch floats (e.g. 1695050400.123456) or ISO 8601 strings."""
    if isinstance(ts_value, (int, float)):
        return datetime.fromtimestamp(ts_value, tz=timezone.utc)
    if isinstance(ts_value, str):
        try:
            return datetime.fromtimestamp(float(ts_value), tz=timezone.utc)
        except ValueError:
            return datetime.fromisoformat(ts_value.replace("Z", "+00:00"))
    raise ValueError(f"Cannot parse Zeek timestamp: {ts_value!r}")


def _history_to_orig_flags(history: str | None) -> str | None:
    """TCP flags sent by the originator, from Zeek's connection history."""
    if not history:
        return None
    flags: set[str] = set()
    for ch in history:
        flags.update(_HISTORY_ORIG_FLAGS.get(ch, ()))
    return ",".join(sorted(flags)) if flags else None


def _first(rec: dict[str, Any], *keys: str) -> Any:
    """First key present with a non-None value (0 counts as present)."""
    for key in keys:
        value = rec.get(key)
        if value is not None:
            return value
    return None


def _opt_int(value: Any) -> Optional[int]:
    return None if value is None or value == "" else int(value)


def _direction(rec: dict[str, Any]) -> FlowDirection:
    """Use Zeek's local_orig/local_resp when Site::local_nets was configured."""
    local_orig, local_resp = rec.get("local_orig"), rec.get("local_resp")
    if local_orig is None or local_resp is None:
        return FlowDirection.UNKNOWN
    if local_orig and local_resp:
        return FlowDirection.INTERNAL
    if local_orig:
        return FlowDirection.OUTBOUND
    if local_resp:
        return FlowDirection.INBOUND
    return FlowDirection.UNKNOWN


def _convert_tsv_value(raw: str, zeek_type: str, unset: str, empty: str, set_sep: str) -> Any:
    if raw == unset:
        return None
    is_container = zeek_type.startswith(("set[", "vector["))
    if raw == empty:
        return [] if is_container else ""
    if is_container:
        return raw.split(set_sep)
    if zeek_type in ("time", "interval", "double"):
        return float(raw)
    if zeek_type in ("count", "int", "port"):
        return int(raw)
    if zeek_type == "bool":
        return raw == "T"
    return raw


# ---------------------------------------------------------------------------
# Reader
# ---------------------------------------------------------------------------

class ZeekReader(BaseReader):
    """
    Read-only Zeek log reader (file or directory).

    Malformed lines and records without a timestamp or IP addresses are
    skipped and counted in ``errors``; nothing is fabricated.
    """

    def __init__(self, source_path: Path | str):
        super().__init__(source_path)

    def validate_source(self) -> bool:
        """A readable file, or a directory containing conn.log."""
        if self.source_path is None:
            return False
        p = Path(self.source_path)
        if p.is_dir():
            if not (p / "conn.log").is_file():
                logger.error("Zeek directory has no conn.log: %s", p)
                return False
            return True
        if not p.is_file():
            logger.error("Zeek file not found: %s", p)
            return False
        return True

    def read(self) -> Iterator[NormalisedFlow]:
        """Yield NormalisedFlow records, streaming the input."""
        if not self.validate_source():
            raise FileNotFoundError(f"Invalid Zeek source: {self.source_path}")

        path = Path(self.source_path)
        logger.info("Reading Zeek logs: %s", path)

        if path.is_dir():
            dns_by_uid = self._index_by_uid(path / "dns.log")
            ssl_by_uid = self._index_by_uid(path / "ssl.log")
            records = self._iter_records(path / "conn.log")
        else:
            dns_by_uid, ssl_by_uid = {}, {}
            records = self._iter_records(path)

        for rec, source_type in records:
            try:
                uid = rec.get("uid")
                if uid is not None:
                    rec = {**dns_by_uid.get(uid, {}), **ssl_by_uid.get(uid, {}), **rec}
                flow = self._parse_record(rec, source_type)
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

    # -------------------------------------------------------------- parsing

    def _index_by_uid(self, path: Path) -> dict[str, dict[str, Any]]:
        """Load the enrichment fields of a dns.log / ssl.log, keyed by uid."""
        if not path.is_file():
            return {}
        keep = ("query", "qtype_name", "qtype", "rcode_name", "rcode",
                "version", "cipher", "ja3", "ja4")
        index: dict[str, dict[str, Any]] = {}
        for rec, _ in self._iter_records(path):
            uid = rec.get("uid")
            if uid is not None and uid not in index:
                index[uid] = {k: rec[k] for k in keep if rec.get(k) is not None}
        return index

    def _iter_records(self, path: Path) -> Iterator[tuple[dict[str, Any], InputSource]]:
        """Yield raw records from one log file, detecting JSON vs TSV."""
        with open(path, "r", encoding="utf-8") as f:
            first = ""
            for line in f:
                if line.strip():
                    first = line
                    break
            if not first:
                return
            stripped = first.lstrip()
            if stripped.startswith("["):
                for rec in json.loads(first + f.read()):
                    yield rec, InputSource.ZEEK_JSON
            elif stripped.startswith("{"):
                yield from self._iter_json_lines(first, f)
            elif stripped.startswith("#"):
                yield from self._iter_tsv(first, f)
            else:
                raise ValueError(f"Unrecognised Zeek log format: {path}")

    def _iter_json_lines(self, first: str, f) -> Iterator[tuple[dict[str, Any], InputSource]]:
        for line_num, line in enumerate(chain_first(first, f), 1):
            line = line.strip()
            if not line or line.startswith(("#", "//")):
                continue
            try:
                yield json.loads(line), InputSource.ZEEK_JSON
            except json.JSONDecodeError as e:
                self._errors += 1
                logger.debug("Skipping malformed JSON at line %d: %s", line_num, e)

    def _iter_tsv(self, first: str, f) -> Iterator[tuple[dict[str, Any], InputSource]]:
        separator, set_sep, empty, unset = "\t", ",", "(empty)", "-"
        fields: list[str] = []
        types: list[str] = []
        for line in chain_first(first, f):
            line = line.rstrip("\r\n")
            if not line:
                continue
            if line.startswith("#separator "):
                # The separator itself is written escaped, e.g. "#separator \x09"
                separator = line[len("#separator "):].strip().encode().decode("unicode_escape")
                continue
            if line.startswith("#"):
                key, _, value = line[1:].partition(separator)
                if key == "set_separator":
                    set_sep = value
                elif key == "empty_field":
                    empty = value
                elif key == "unset_field":
                    unset = value
                elif key == "fields":
                    fields = value.split(separator)
                elif key == "types":
                    types = value.split(separator)
                continue
            if not fields:
                self._errors += 1
                continue
            values = line.split(separator)
            if len(values) != len(fields):
                self._errors += 1
                continue
            try:
                rec = {
                    name: _convert_tsv_value(raw, types[i] if i < len(types) else "string",
                                             unset, empty, set_sep)
                    for i, (name, raw) in enumerate(zip(fields, values))
                }
            except ValueError as e:
                self._errors += 1
                logger.debug("Skipping malformed TSV row: %s", e)
                continue
            yield rec, InputSource.ZEEK_TSV

    @staticmethod
    def _parse_record(rec: dict[str, Any], source_type: InputSource = InputSource.ZEEK_JSON) -> NormalisedFlow:
        """Parse one Zeek record (conn, dns or ssl fields) into a NormalisedFlow."""
        ts_raw = rec.get("ts")
        if ts_raw is None:
            raise ValueError("Missing 'ts' field in Zeek record")

        src_ip = _first(rec, "id.orig_h", "id_orig_h", "src_ip")
        dst_ip = _first(rec, "id.resp_h", "id_resp_h", "dst_ip")
        if src_ip is None or dst_ip is None:
            raise ValueError("Missing originator/responder address in Zeek record")

        src_port = _opt_int(_first(rec, "id.orig_p", "id_orig_p", "src_port"))
        dst_port = _opt_int(_first(rec, "id.resp_p", "id_resp_p", "dst_port"))
        protocol = _map_protocol(rec.get("proto"))

        orig_bytes = _opt_int(rec.get("orig_bytes"))
        resp_bytes = _opt_int(rec.get("resp_bytes"))
        orig_pkts = _opt_int(rec.get("orig_pkts"))
        resp_pkts = _opt_int(rec.get("resp_pkts"))
        has_pkts = orig_pkts is not None or resp_pkts is not None

        duration = rec.get("duration")
        duration = float(duration) if duration not in (None, "") else None

        dns_query = rec.get("query") or None
        qtype = _first(rec, "qtype_name", "qtype")
        rcode = _first(rec, "rcode_name", "rcode")

        return NormalisedFlow(
            flow_id=rec.get("uid"),
            timestamp=_parse_zeek_timestamp(ts_raw),
            source_ip=str(src_ip),
            destination_ip=str(dst_ip),
            source_port=src_port,
            destination_port=dst_port,
            protocol=protocol,
            # Without packet counts (dns.log/ssl.log alone) the record stands for >= 1 packet.
            packet_count=(orig_pkts or 0) + (resp_pkts or 0) if has_pkts else 1,
            byte_count=(orig_bytes or 0) + (resp_bytes or 0),
            orig_packets=orig_pkts,
            resp_packets=resp_pkts,
            orig_bytes=orig_bytes,
            resp_bytes=resp_bytes,
            duration=duration,
            tcp_flags=_history_to_orig_flags(rec.get("history")) if protocol == ProtocolType.TCP else None,
            conn_state=rec.get("conn_state"),
            direction=_direction(rec),
            dns_query=dns_query,
            dns_query_length=len(dns_query) if dns_query else None,
            dns_record_type=str(qtype) if qtype is not None else None,
            dns_rcode=str(rcode) if rcode is not None else None,
            tls_version=normalize_tls_version(_first(rec, "version", "tls_version")),
            tls_cipher=rec.get("cipher"),
            ja3=rec.get("ja3"),
            ja4=rec.get("ja4"),
            label=rec.get("label"),
            source_type=source_type,
        )
