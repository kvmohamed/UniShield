"""
UniShield — Input format detection

Chooses a reader from file content rather than trusting the extension:

    pcap / pcapng  — magic bytes
    zeek_dir       — a directory containing conn.log
    zeek_tsv       — text starting with Zeek's '#separator' / '#fields' header
    zeek_json      — JSON records with 'ts' and 'id.orig_h' (or 'uid')
    flow_json      — any other JSON object / array of objects
    flow_csv       — delimited text with a header row

SECURITY CONSTRAINTS:
    - Reads at most the first 64 KiB of a local file. No network I/O.
"""

from __future__ import annotations

import json
from pathlib import Path

from unishield.ingest.base import BaseReader

_PCAP_MAGICS = (
    b"\xd4\xc3\xb2\xa1",  # little-endian, microsecond
    b"\xa1\xb2\xc3\xd4",  # big-endian, microsecond
    b"\x4d\x3c\xb2\xa1",  # little-endian, nanosecond
    b"\xa1\xb2\x3c\x4d",  # big-endian, nanosecond
)
_PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
_SNIFF_BYTES = 65_536


class UnsupportedFormatError(ValueError):
    """The input could not be matched to a supported reader."""


def _looks_like_zeek(record: object) -> bool:
    return isinstance(record, dict) and "ts" in record and (
        "id.orig_h" in record or "uid" in record
    )


def detect_format(path: Path | str) -> str:
    """Return one of: pcap, pcapng, zeek_dir, zeek_tsv, zeek_json, flow_json, flow_csv."""
    p = Path(path)
    if p.is_dir():
        if (p / "conn.log").is_file():
            return "zeek_dir"
        raise UnsupportedFormatError(f"Directory has no Zeek conn.log: {p}")
    if not p.is_file():
        raise FileNotFoundError(f"No such file: {p}")

    with open(p, "rb") as f:
        head = f.read(_SNIFF_BYTES)
    if head[:4] in _PCAP_MAGICS:
        return "pcap"
    if head[:4] == _PCAPNG_MAGIC:
        return "pcapng"

    text = head.decode("utf-8", errors="replace").lstrip("﻿")
    first_line = next((line.strip() for line in text.splitlines() if line.strip()), "")
    if not first_line:
        raise UnsupportedFormatError(f"Empty file: {p}")
    if first_line.startswith(("#separator", "#fields")):
        return "zeek_tsv"
    if first_line.startswith("{"):
        try:
            record = json.loads(first_line)
        except json.JSONDecodeError as exc:
            raise UnsupportedFormatError(f"First line is not valid JSON: {p}") from exc
        return "zeek_json" if _looks_like_zeek(record) else "flow_json"
    if first_line.startswith("["):
        body = text.lstrip()[1:].lstrip()
        try:
            record, _ = json.JSONDecoder().raw_decode(body)
        except json.JSONDecodeError:
            record = None
        return "zeek_json" if _looks_like_zeek(record) else "flow_json"
    if "," in first_line or "\t" in first_line:
        return "flow_csv"
    raise UnsupportedFormatError(f"Unrecognised input format: {p}")


def open_reader(path: Path | str) -> tuple[BaseReader, str]:
    """Detect the format and return ``(reader, format_name)``."""
    from unishield.ingest.flow_reader import FlowReader
    from unishield.ingest.pcap_reader import PcapReader
    from unishield.ingest.zeek_reader import ZeekReader

    fmt = detect_format(path)
    if fmt in ("pcap", "pcapng"):
        return PcapReader(path), fmt
    if fmt.startswith("zeek"):
        return ZeekReader(path), fmt
    if fmt == "flow_csv":
        delimiter = "\t" if Path(path).suffix.lower() == ".tsv" else ","
        return FlowReader(path, delimiter=delimiter), fmt
    return FlowReader(path), fmt
