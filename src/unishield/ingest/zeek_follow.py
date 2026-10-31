"""
UniShield — Zeek Follow Mode (live tail of conn.log, with dns.log / ssl.log)

Reads Zeek logs while Zeek writes them, like ``tail -F``: new lines of
conn.log become flows as they appear; recent dns.log and ssl.log entries are
kept in a bounded cache and joined to connections by ``uid`` (Zeek writes the
DNS/TLS entry before the connection entry closes). JSON and TSV logs are
supported; for TSV the header is read even when following from the end.

Rotation: files are not held open between polls (Windows does not let Zeek
rename an open file). A file whose identity changed, or that shrank, has
been rotated: the remainder of the old file is read from its new name in the
same directory if it can be found, then the new file is followed from its
start. Lines appended between the last poll and a rotation that cannot be
found are lost, and counted as a rotation without remainder.

While no line arrives the reader yields ClockTick objects so windows close on
wall-clock time. Read-only: files are only opened for reading.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from collections import OrderedDict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Iterator, Optional

from unishield.ingest.base import BaseReader, ClockTick
from unishield.ingest.zeek_reader import ZeekReader, _convert_tsv_value
from unishield.schemas.flow import InputSource

logger = logging.getLogger("unishield.ingest.zeek_follow")

_ENRICH_FIELDS = ("query", "qtype_name", "qtype", "rcode_name", "rcode", "version", "cipher", "ja3", "ja4")
_MAX_HEADER_LINES = 200


class _LogTail:
    """Incremental reader of one Zeek log file (JSON lines or TSV)."""

    def __init__(self, path: Path, from_start: bool):
        self.path = path
        self.from_start = from_start
        self._key: Optional[tuple[int, int]] = None
        self._pos = 0
        self._partial = ""
        self.separator, self.set_sep, self.empty, self.unset = "\t", ",", "(empty)", "-"
        self.fields: list[str] = []
        self.types: list[str] = []
        self.errors = 0
        self.rotations = 0
        self.lost_rotations = 0

    @staticmethod
    def _identity(st: os.stat_result) -> tuple[int, int]:
        return st.st_ino, st.st_dev

    def _read_from(self, path: Path, pos: int) -> tuple[str, int]:
        with open(path, "r", encoding="utf-8", errors="replace", newline="") as f:
            f.seek(pos)
            data = f.read()
            return data, f.tell()

    def _skip_to_end(self) -> None:
        """Start following at the end, after reading a TSV header if there is one."""
        with open(self.path, "r", encoding="utf-8", errors="replace", newline="") as f:
            for _ in range(_MAX_HEADER_LINES):
                line = f.readline()
                if not line.startswith("#"):
                    break
                self._header(line.rstrip("\r\n"))
            f.seek(0, os.SEEK_END)
            self._pos = f.tell()

    def _find_rotated(self, old_key: tuple[int, int]) -> Optional[Path]:
        try:
            for candidate in self.path.parent.iterdir():
                if candidate != self.path and candidate.is_file() and self._identity(candidate.stat()) == old_key:
                    return candidate
        except OSError:
            return None
        return None

    def poll(self) -> list[dict[str, Any]]:
        try:
            st = self.path.stat()
        except FileNotFoundError:
            if self._key is None:
                self.from_start = True                               # created after following began: all new
            return []
        key = self._identity(st)
        records: list[dict[str, Any]] = []
        if self._key is None:                                        # first time the file is seen
            self._key = key
            if self.from_start:
                self._pos = 0
            else:
                self._skip_to_end()
                return []
        elif key != self._key or st.st_size < self._pos:            # rotated or truncated
            self.rotations += 1
            rotated = self._find_rotated(self._key) if key != self._key else None
            if rotated is not None:                                  # the old file's remainder, old header
                remainder, _ = self._read_from(rotated, self._pos)
                records += self._parse_text(self._partial + remainder, final=True)
            elif self._pos and key != self._key:
                self.lost_rotations += 1
            self._key, self._pos, self._partial = key, 0, ""
            self.fields, self.types = [], []                       # a new TSV file writes a new header
        data, self._pos = self._read_from(self.path, self._pos)
        return records + self._parse_text(self._partial + data)

    def _parse_text(self, text: str, final: bool = False) -> list[dict[str, Any]]:
        """Parse complete lines; keep an incomplete last line for the next poll unless ``final``."""
        lines = text.split("\n")
        self._partial = "" if final else lines.pop()
        records = []
        for line in lines:
            rec = self._parse_line(line.rstrip("\r"))
            if rec is not None:
                records.append(rec)
        return records

    def _header(self, line: str) -> None:
        if line.startswith("#separator "):
            self.separator = line[len("#separator "):].strip().encode().decode("unicode_escape")
            return
        key, _, value = line[1:].partition(self.separator)
        if key == "set_separator":
            self.set_sep = value
        elif key == "empty_field":
            self.empty = value
        elif key == "unset_field":
            self.unset = value
        elif key == "fields":
            self.fields = value.split(self.separator)
        elif key == "types":
            self.types = value.split(self.separator)

    def _parse_line(self, line: str) -> Optional[dict[str, Any]]:
        if not line.strip():
            return None
        if line.startswith("#"):
            self._header(line)
            return None
        if line.lstrip().startswith("{"):
            try:
                rec = json.loads(line)
                rec["_source"] = InputSource.ZEEK_JSON
                return rec
            except json.JSONDecodeError:
                self.errors += 1
                return None
        values = line.split(self.separator)
        if not self.fields or len(values) != len(self.fields):
            self.errors += 1
            return None
        try:
            rec = {name: _convert_tsv_value(raw, self.types[i] if i < len(self.types) else "string",
                                            self.unset, self.empty, self.set_sep)
                   for i, (name, raw) in enumerate(zip(self.fields, values))}
        except ValueError:
            self.errors += 1
            return None
        rec["_source"] = InputSource.ZEEK_TSV
        return rec


class ZeekFollowReader(BaseReader):
    """Live reader that follows a Zeek log directory (or a single conn.log)."""

    packet_level = False
    live = True

    def __init__(self, source_path: Path | str, *, from_start: bool = False, poll_interval: float = 1.0,
                 max_enrichment: int = 200_000):
        super().__init__(source_path)
        path = Path(source_path)
        self.directory = path if path.is_dir() else path.parent
        conn = path / "conn.log" if path.is_dir() else path
        self.poll_interval = poll_interval
        self.max_enrichment = max_enrichment
        self._conn = _LogTail(conn, from_start)
        self._enrich_tails = [_LogTail(self.directory / name, from_start) for name in ("dns.log", "ssl.log")] \
            if path.is_dir() else []
        self._enrichment: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self._stop = threading.Event()
        self._last_event: Optional[datetime] = None
        self._last_wall = 0.0

    def validate_source(self) -> bool:
        return self.directory.is_dir()

    def stop(self) -> None:
        self._stop.set()

    def _remember(self, rec: dict[str, Any]) -> None:
        uid = rec.get("uid")
        if uid is None:
            return
        fields = {k: rec[k] for k in _ENRICH_FIELDS if rec.get(k) is not None}
        if fields:
            self._enrichment.setdefault(uid, {}).update(fields)
            self._enrichment.move_to_end(uid)
            while len(self._enrichment) > self.max_enrichment:
                self._enrichment.popitem(last=False)

    def read(self) -> Iterator:
        if not self.validate_source():
            raise FileNotFoundError(f"Zeek log directory not found: {self.directory}")
        logger.info("Following Zeek logs in %s", self.directory)
        while not self._stop.is_set():
            for tail in self._enrich_tails:
                for rec in tail.poll():
                    self._remember(rec)
            produced = 0
            for rec in self._conn.poll():
                source = rec.pop("_source", InputSource.ZEEK_JSON)
                uid = rec.get("uid")
                if uid is not None and uid in self._enrichment:
                    rec = {**self._enrichment[uid], **rec}
                try:
                    flow = ZeekReader._parse_record(rec, source)
                except Exception as exc:                            # malformed record: count, never fabricate
                    self._errors += 1
                    logger.debug("Skipping Zeek record: %s", exc)
                    continue
                self._records_read += 1
                produced += 1
                if self._last_event is None or flow.timestamp > self._last_event:
                    self._last_event = flow.timestamp
                    self._last_wall = time.monotonic()
                yield flow
            if produced == 0:
                yield ClockTick(None if self._last_event is None else
                                self._last_event + timedelta(seconds=time.monotonic() - self._last_wall))
                self._stop.wait(self.poll_interval)

    @property
    def errors(self) -> int:
        return self._errors + self._conn.errors + sum(t.errors for t in self._enrich_tails)

    def stats(self) -> dict[str, Any]:
        return {
            "following": str(self.directory),
            "records": self._records_read,
            "errors": self.errors,
            "rotations": self._conn.rotations,
            "rotations_without_remainder": self._conn.lost_rotations,
            "enrichment_cached": len(self._enrichment),
            "last_record_time": self._last_event.isoformat() if self._last_event else None,
        }
