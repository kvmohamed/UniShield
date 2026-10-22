"""
UniShield — File exports (continuous and on demand)

Continuous export (``export.continuous``) appends new alerts and incidents
to files in ``export.directory`` as they are stored:

    alerts.jsonl, incidents.jsonl   JSON lines
    unishield.cef                   CEF lines (alerts and incidents)
    unishield.stix.json             a STIX 2.1 bundle, rewritten atomically so
                                    it is always a complete, valid bundle

A file is rotated (renamed to ``<name>-<UTC time>.<ext>``) when it reaches
``rotate_max_mb`` (STIX: ``rotate_max_stix_objects`` objects), and only the
newest ``backup_count`` rotated files of each stream are kept (0 keeps all).
SIEM file collectors can follow the active files or pick up rotated ones.

On-demand export (``export_snapshot``; ``POST /export``,
``scripts/export_alerts.py``) writes one set of timestamped files to
``<directory>/on-demand``.

SECURITY CONSTRAINTS:
    - Local files on the analyst side only. No network I/O.
"""

from __future__ import annotations

import json
import logging
import os
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Optional

from unishield.export.formats import alert_record, alert_to_cef, incident_record, incident_to_cef, json_line
from unishield.export.stix import StixBundleBuilder, build_bundle
from unishield.schemas.alert import Alert
from unishield.schemas.timeutil import utc_now

logger = logging.getLogger("unishield.export.files")

FORMATS = ("jsonl", "cef", "stix")


def _stamp(now: Optional[datetime] = None) -> str:
    now = now or utc_now()
    return now.strftime("%Y%m%dT%H%M%S") + f"{now.microsecond // 1000:03d}Z"


def _free_name(directory: Path, stem: str, suffix: str) -> Path:
    path = directory / f"{stem}{suffix}"
    n = 1
    while path.exists():
        path = directory / f"{stem}-{n}{suffix}"
        n += 1
    return path


def _atomic_write(path: Path, text: str) -> None:
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


class _Rotating:
    """Active file plus rotated files ``<stem>-<time><suffix>`` with retention."""

    def __init__(self, directory: Path, stem: str, suffix: str, backup_count: int):
        self.directory = directory
        self.stem = stem
        self.suffix = suffix
        self.backup_count = backup_count
        self.path = directory / f"{stem}{suffix}"
        self.rotations = 0

    def rotate(self) -> Optional[Path]:
        if not self.path.exists():
            return None
        target = _free_name(self.directory, f"{self.stem}-{_stamp()}", self.suffix)
        os.replace(self.path, target)
        self.rotations += 1
        self._prune()
        return target

    def _prune(self) -> None:
        if self.backup_count <= 0:
            return
        rotated = sorted(p for p in self.directory.glob(f"{self.stem}-*{self.suffix}") if p != self.path)
        for old in rotated[:-self.backup_count]:
            try:
                old.unlink()
            except OSError as exc:                              # pragma: no cover - file in use
                logger.warning("Could not remove rotated export %s: %s", old.name, exc)


class RotatingLineFile(_Rotating):
    """Appends lines; rotates before a write would take the file past ``max_bytes``."""

    def __init__(self, directory: Path, stem: str, suffix: str, max_bytes: int, backup_count: int):
        super().__init__(directory, stem, suffix, backup_count)
        self.max_bytes = max_bytes
        self.lines_written = 0

    def write_lines(self, lines: Iterable[str]) -> int:
        data = "".join(line.replace("\n", " ") + "\n" for line in lines)
        if not data:
            return 0
        size = self.path.stat().st_size if self.path.exists() else 0
        if size and size + len(data.encode("utf-8")) > self.max_bytes:
            self.rotate()
        with open(self.path, "a", encoding="utf-8", newline="\n") as f:
            f.write(data)
        written = data.count("\n")
        self.lines_written += written
        return written


class RotatingStixFile(_Rotating):
    """A STIX bundle rewritten atomically on every update; rotated after ``max_objects`` objects."""

    def __init__(self, directory: Path, home_networks: Iterable[str], max_objects: int, backup_count: int,
                 indicator_valid_days: int = 30):
        super().__init__(directory, "unishield", ".stix.json", backup_count)
        self.home_networks = list(home_networks)
        self.max_objects = max_objects
        self.indicator_valid_days = indicator_valid_days
        self.builder = self._new_builder()
        self.bundle_id: Optional[str] = None

    def _new_builder(self) -> StixBundleBuilder:
        return StixBundleBuilder(self.home_networks, self.indicator_valid_days)

    def add(self, alerts: list[Alert], incidents: list[dict[str, Any]], alerts_by_id: dict[str, Alert]) -> None:
        if not alerts and not incidents:
            return
        if len(self.builder) >= self.max_objects:
            self.rotate()
            self.builder = self._new_builder()
            self.bundle_id = None
        for alert in alerts:
            self.builder.add_alert(alert)
        for incident in incidents:
            self.builder.add_incident(incident, alerts_by_id)
        bundle = self.builder.bundle()
        if self.bundle_id is None:
            self.bundle_id = bundle["id"]
        bundle["id"] = self.bundle_id
        _atomic_write(self.path, json.dumps(bundle, ensure_ascii=False, indent=1))


class ContinuousFileExporter:
    """Writes alerts and incidents to the rotating export files (used by the output service)."""

    def __init__(self, directory: str | Path, formats: Iterable[str] = FORMATS, home_networks: Iterable[str] = (),
                 rotate_max_mb: float = 10.0, rotate_max_stix_objects: int = 5000, backup_count: int = 20,
                 indicator_valid_days: int = 30):
        self.directory = Path(directory).expanduser()
        self.directory.mkdir(parents=True, exist_ok=True)
        self.formats = [f for f in FORMATS if f in set(formats)]
        max_bytes = int(rotate_max_mb * 1024 * 1024)
        self._lock = threading.Lock()
        self.alerts_jsonl = RotatingLineFile(self.directory, "alerts", ".jsonl", max_bytes, backup_count)
        self.incidents_jsonl = RotatingLineFile(self.directory, "incidents", ".jsonl", max_bytes, backup_count)
        self.cef = RotatingLineFile(self.directory, "unishield", ".cef", max_bytes, backup_count)
        self.stix = RotatingStixFile(self.directory, home_networks, rotate_max_stix_objects, backup_count,
                                     indicator_valid_days)
        self.alerts_written = 0
        self.incidents_written = 0
        self.last_write: Optional[str] = None
        self.errors = 0
        self.last_error: Optional[str] = None

    @classmethod
    def from_config(cls, config) -> "ContinuousFileExporter":
        e = config.export
        return cls(e.directory, e.formats, config.network.home_networks, e.rotate_max_mb,
                   e.rotate_max_stix_objects, e.backup_count, e.stix_indicator_valid_days)

    def write(self, alerts: list[Alert], incidents: list[dict[str, Any]],
              alerts_by_id: Optional[dict[str, Alert]] = None) -> None:
        if not alerts and not incidents:
            return
        with self._lock:
            try:
                if "jsonl" in self.formats:
                    self.alerts_jsonl.write_lines(json_line(alert_record(a)) for a in alerts)
                    self.incidents_jsonl.write_lines(json_line(incident_record(i)) for i in incidents)
                if "cef" in self.formats:
                    self.cef.write_lines([alert_to_cef(a) for a in alerts] + [incident_to_cef(i) for i in incidents])
                if "stix" in self.formats:
                    self.stix.add(alerts, incidents, alerts_by_id or {a.alert_id: a for a in alerts})
                self.alerts_written += len(alerts)
                self.incidents_written += len(incidents)
                self.last_write = utc_now().isoformat()
            except OSError as exc:
                self.errors += 1
                self.last_error = f"{type(exc).__name__}: {exc.strerror or exc}"
                logger.error("Export write failed: %s", exc)

    def status(self) -> dict[str, Any]:
        files = [p for p in (self.alerts_jsonl.path, self.incidents_jsonl.path, self.cef.path, self.stix.path)
                 if p.exists()]
        return {
            "enabled": True,
            "directory": str(self.directory),
            "formats": self.formats,
            "alerts_written": self.alerts_written,
            "incidents_written": self.incidents_written,
            "active_files": [{"name": p.name, "bytes": p.stat().st_size} for p in files],
            "rotations": self.alerts_jsonl.rotations + self.incidents_jsonl.rotations + self.cef.rotations
            + self.stix.rotations,
            "last_write": self.last_write,
            "errors": self.errors,
            "last_error": self.last_error,
        }


def export_snapshot(alerts: list[Alert], incidents: list[dict[str, Any]], directory: str | Path,
                    formats: Iterable[str] = FORMATS, home_networks: Iterable[str] = (),
                    indicator_valid_days: int = 30, prefix: str = "unishield") -> dict[str, Any]:
    """Write one set of export files for the given alerts and incidents; returns what was written."""
    out_dir = Path(directory).expanduser()
    out_dir.mkdir(parents=True, exist_ok=True)
    formats = [f for f in FORMATS if f in set(formats)]
    stamp = _stamp()
    written: list[Path] = []
    stix_info: dict[str, Any] = {}

    def put(stem: str, suffix: str, text: str) -> None:
        path = _free_name(out_dir, f"{prefix}-{stamp}-{stem}", suffix)
        _atomic_write(path, text)
        written.append(path)

    if "jsonl" in formats:
        put("alerts", ".jsonl", "".join(json_line(alert_record(a)) + "\n" for a in alerts))
        put("incidents", ".jsonl", "".join(json_line(incident_record(i)) + "\n" for i in incidents))
    if "cef" in formats:
        put("events", ".cef", "".join(line + "\n" for line in
                                      [alert_to_cef(a) for a in alerts] + [incident_to_cef(i) for i in incidents]))
    if "stix" in formats:
        bundle = build_bundle(alerts, incidents, home_networks, indicator_valid_days)
        put("bundle", ".stix.json", json.dumps(bundle, ensure_ascii=False, indent=1))
        stix_info = {"objects": len(bundle["objects"]), "bundle_id": bundle["id"]}
    return {
        "directory": str(out_dir),
        "alerts": len(alerts),
        "incidents": len(incidents),
        "files": [{"name": p.name, "bytes": p.stat().st_size} for p in written],
        "stix": stix_info,
        "generated_at": utc_now().isoformat(),
    }


def export_stored(repository, config, *, formats: Optional[Iterable[str]] = None, since: Optional[datetime] = None,
                  until: Optional[datetime] = None, run_id: Optional[str] = None,
                  include_incidents: Optional[bool] = None, max_alerts: int = 100_000,
                  directory: Optional[str | Path] = None) -> dict[str, Any]:
    """
    On-demand export of stored alerts (window end in [since, until), optionally
    one run) and the incidents they form, to ``<export.directory>/on-demand``.
    """
    from unishield.correlation.correlator import AlertCorrelator
    from unishield.storage import AlertQuery

    e = config.export
    alerts, total = repository.list(AlertQuery(since=since, until=until, run_id=run_id, sort="window_end",
                                               descending=False, limit=max_alerts))
    incidents: list[dict[str, Any]] = []
    if e.include_incidents if include_incidents is None else include_incidents:
        incidents = AlertCorrelator(correlation_window_sec=e.incident_gap_sec,
                                    min_alerts_for_incident=e.incident_min_alerts).correlate(alerts)
    out = Path(directory) if directory is not None else Path(e.directory) / "on-demand"
    summary = export_snapshot(alerts, incidents, out, formats or e.formats, config.network.home_networks,
                              e.stix_indicator_valid_days)
    summary["alerts_matching"] = total
    summary["truncated"] = total > len(alerts)
    return summary
