"""
UniShield — Threat-intelligence store

Keeps imported indicators in the alert database (``intel_indicators``,
with an ``intel_imports`` history), grouped by source. Re-importing a
source replaces its indicators unless ``mode="append"``. Expired indicators
stay stored (and visible in the status) until purged, but are never
matched.

SECURITY CONSTRAINTS:
    - Local database only; indicators come from files the operator supplies.
"""

from __future__ import annotations

import hashlib
import threading
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy import delete, func, insert, select
from sqlalchemy.engine import Engine

from unishield.intel.indicators import (
    Indicator,
    IndicatorError,
    ParseOptions,
    ParseResult,
    parse,
    valid_source_name,
)
from unishield.intel.matcher import IntelEntry, IntelMatcher
from unishield.schemas.timeutil import utc_now
from unishield.storage.database import intel_imports_table, intel_table, make_engine

_BATCH = 5_000
IMPORT_MODES = ("replace", "append")


def _naive(value: Optional[datetime]) -> Optional[datetime]:
    return value.astimezone(timezone.utc).replace(tzinfo=None) if value and value.tzinfo else value


def _aware(value: Optional[datetime]) -> Optional[datetime]:
    return value.replace(tzinfo=timezone.utc) if value is not None and value.tzinfo is None else value


def parse_options(config=None, expires_at: Optional[datetime] = None) -> ParseOptions:
    """Parse limits and the default expiry from ``intel`` in the config."""
    if config is None:
        from unishield.config import get_config
        config = get_config()
    cfg = config.intel
    if expires_at is None and cfg.default_ttl_days:
        expires_at = utc_now() + timedelta(days=cfg.default_ttl_days)
    return ParseOptions(min_prefix_v4=cfg.min_cidr_prefix_v4, min_prefix_v6=cfg.min_cidr_prefix_v6,
                        max_indicators=cfg.max_indicators, default_expires_at=expires_at)


class IntelStore:
    """Indicator persistence on a SQLAlchemy engine (usually the alert database)."""

    def __init__(self, engine: Engine):
        self.engine = engine
        self._lock = threading.Lock()

    @classmethod
    def from_url(cls, url: str, echo: bool = False) -> "IntelStore":
        return cls(make_engine(url, echo))

    # --- imports -------------------------------------------------------------

    def import_text(self, text: str, source: str, *, fmt: str = "auto", filename: Optional[str] = None,
                    mode: str = "replace", options: Optional[ParseOptions] = None,
                    kind_hint: Optional[str] = None) -> dict[str, Any]:
        """Parse file content and store its indicators under ``source``; returns the import summary."""
        result = parse(text, fmt, filename, options or parse_options(), kind_hint)
        digest = hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()
        return self.store(result, source, mode=mode, filename=filename, sha256=digest)

    def store(self, result: ParseResult, source: str, *, mode: str = "replace", filename: Optional[str] = None,
              sha256: Optional[str] = None) -> dict[str, Any]:
        if not valid_source_name(source):
            raise IndicatorError("source names use letters, digits, space and . _ : - (max 128 characters)")
        if mode not in IMPORT_MODES:
            raise IndicatorError(f"unknown import mode {mode!r}; choose from {IMPORT_MODES}")
        now = utc_now()
        with self._lock, self.engine.begin() as conn:
            existing: set[tuple[str, str]] = set()
            if mode == "replace":
                replaced = conn.execute(delete(intel_table).where(intel_table.c.source == source)).rowcount or 0
            else:
                replaced = 0
                existing = {(k, v) for k, v in conn.execute(
                    select(intel_table.c.kind, intel_table.c.value).where(intel_table.c.source == source))}
            rows = [self._row(source, ind, now) for ind in result.indicators if (ind.kind, ind.value) not in existing]
            for i in range(0, len(rows), _BATCH):
                conn.execute(insert(intel_table), rows[i:i + _BATCH])
            conn.execute(insert(intel_imports_table).values(
                source=source, filename=(filename or "")[:256] or None, format=result.format, mode=mode,
                sha256=sha256, accepted=len(rows), rejected=result.rejected_total, imported_at=_naive(now)))
        return {
            "source": source,
            "format": result.format,
            "mode": mode,
            "accepted": len(rows),
            "already_present": len(result.indicators) - len(rows),
            "replaced": replaced,
            "duplicates_in_file": result.duplicates,
            "rejected": result.rejected_total,
            "rejected_examples": result.rejected,
            "by_kind": result.counts(),
            "sha256": sha256,
            "imported_at": now.isoformat(),
        }

    @staticmethod
    def _row(source: str, ind: Indicator, now: datetime) -> dict[str, Any]:
        return {"source": source, "kind": ind.kind, "value": ind.value, "label": ind.label or None,
                "severity": ind.severity, "techniques": list(ind.techniques) or None,
                "expires_at": _naive(ind.expires_at), "imported_at": _naive(now)}

    def remove_source(self, source: str) -> int:
        with self._lock, self.engine.begin() as conn:
            return conn.execute(delete(intel_table).where(intel_table.c.source == source)).rowcount or 0

    def purge_expired(self, now: Optional[datetime] = None) -> int:
        now = now or utc_now()
        with self._lock, self.engine.begin() as conn:
            return conn.execute(delete(intel_table).where(
                intel_table.c.expires_at.is_not(None), intel_table.c.expires_at <= _naive(now))).rowcount or 0

    # --- reads ----------------------------------------------------------------

    def entries(self, now: Optional[datetime] = None, include_expired: bool = False) -> list[IntelEntry]:
        now = now or utc_now()
        c = intel_table.c
        stmt = select(c.source, c.kind, c.value, c.label, c.severity, c.techniques, c.expires_at)
        if not include_expired:
            stmt = stmt.where((c.expires_at.is_(None)) | (c.expires_at > _naive(now)))
        with self.engine.connect() as conn:
            return [IntelEntry(source=s, kind=k, value=v, label=label or "", expires_at=_aware(exp),
                               severity=severity, techniques=tuple(techniques or ()))
                    for s, k, v, label, severity, techniques, exp in conn.execute(stmt)]

    def matcher(self, now: Optional[datetime] = None, anonymize_salt: Optional[str] = None) -> IntelMatcher:
        return IntelMatcher(self.entries(now), anonymize_salt=anonymize_salt)

    def status(self, now: Optional[datetime] = None) -> dict[str, Any]:
        """Counts per kind and per source (active / expired) and the most recent imports."""
        now = now or utc_now()
        c = intel_table.c
        active = (c.expires_at.is_(None)) | (c.expires_at > _naive(now))
        with self.engine.connect() as conn:
            by_kind = {k: {"active": 0, "expired": 0} for k in ("ip", "cidr", "domain", "ja3")}
            for kind, is_active, n in conn.execute(
                    select(c.kind, active.label("active"), func.count()).group_by(c.kind, active)):
                by_kind.setdefault(kind, {"active": 0, "expired": 0})["active" if is_active else "expired"] += int(n)
            sources: dict[str, dict[str, Any]] = {}
            for source, is_active, n, imported, soonest in conn.execute(
                    select(c.source, active.label("active"), func.count(), func.max(c.imported_at),
                           func.min(c.expires_at)).group_by(c.source, active)):
                entry = sources.setdefault(source, {"source": source, "active": 0, "expired": 0,
                                                    "imported_at": None, "next_expiry": None})
                entry["active" if is_active else "expired"] += int(n)
                imported = _aware(imported)
                if imported and (entry["imported_at"] is None or imported.isoformat() > entry["imported_at"]):
                    entry["imported_at"] = imported.isoformat()
                if is_active and soonest is not None:
                    entry["next_expiry"] = _aware(soonest).isoformat()
            imports = [
                {"source": r.source, "filename": r.filename, "format": r.format, "mode": r.mode,
                 "accepted": r.accepted, "rejected": r.rejected, "imported_at": _aware(r.imported_at).isoformat()}
                for r in conn.execute(select(intel_imports_table)
                                      .order_by(intel_imports_table.c.imported_at.desc(), intel_imports_table.c.id.desc())
                                      .limit(10))
            ]
        return {
            "active_total": sum(v["active"] for v in by_kind.values()),
            "expired_total": sum(v["expired"] for v in by_kind.values()),
            "by_kind": by_kind,
            "sources": sorted(sources.values(), key=lambda s: s["source"]),
            "recent_imports": imports,
        }


def read_indicator_file(path, max_bytes: int) -> str:
    """Read an indicator file as text (UTF-8, BOM tolerated), refusing files over ``max_bytes``."""
    from pathlib import Path

    p = Path(path)
    size = p.stat().st_size
    if size > max_bytes:
        raise IndicatorError(f"{p.name} is {size} bytes; the limit is {max_bytes} (intel.max_file_mb)")
    return p.read_text(encoding="utf-8-sig", errors="replace")

