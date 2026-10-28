"""
UniShield — Alert Repository

Persists alerts and analysis runs, and answers the queries the API and
dashboard need: filtered/paginated listing with a total count, summaries,
timelines and top entities. Writes are serialised with a lock so the
pipeline thread and API requests can share one SQLite database.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable, Optional

from sqlalchemy import case, delete, func, insert, select, update
from sqlalchemy.engine import Engine

from unishield.schemas.alert import Alert, AlertSummary
from unishield.schemas.timeutil import utc_now
from unishield.storage.database import alerts_table, make_engine, runs_table, write_lock

_ALERT_COLUMNS = [c.name for c in alerts_table.columns]
_TIME_COLUMNS = {"timestamp", "window_start", "window_end", "window_closed_at", "emitted_at", "stored_at"}
SORTABLE = {"window_end", "timestamp", "severity", "confidence", "threat_class"}
_SEVERITY_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _to_db(value: Any) -> Any:
    """Aware datetimes → naive UTC for storage."""
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).replace(tzinfo=None) if value.tzinfo else value
    return value


def _from_db(name: str, value: Any) -> Any:
    if name in _TIME_COLUMNS and isinstance(value, datetime) and value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


@dataclass
class AlertQuery:
    threat_class: Optional[str] = None
    severity: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    detector_name: Optional[str] = None
    run_id: Optional[str] = None
    since: Optional[datetime] = None          # window_end >= since (traffic time)
    until: Optional[datetime] = None          # window_end < until
    min_confidence: Optional[float] = None
    sort: str = "window_end"
    descending: bool = True
    limit: int = 100
    offset: int = 0


class AlertRepository:
    """Alert and run storage on a SQLAlchemy engine."""

    def __init__(self, engine: Engine):
        self.engine = engine
        self._lock = write_lock(engine)

    @classmethod
    def from_url(cls, url: str, echo: bool = False, migrate: bool = True) -> "AlertRepository":
        return cls(make_engine(url, echo, migrate))

    @property
    def backend(self) -> str:
        return self.engine.dialect.name

    def ping(self) -> bool:
        try:
            with self.engine.connect() as conn:
                conn.execute(select(1))
            return True
        except Exception:
            return False

    # --- alerts ------------------------------------------------------------

    def add(self, alert: Alert) -> Alert:
        return self.add_many([alert])[0]

    def add_many(self, alerts: Iterable[Alert]) -> list[Alert]:
        alerts = list(alerts)
        if not alerts:
            return alerts
        now = utc_now()
        rows = []
        for alert in alerts:
            alert.stored_at = now
            data = alert.model_dump(mode="python")
            row = {k: _to_db(data.get(k)) for k in _ALERT_COLUMNS}
            for key in ("threat_class", "severity", "source_type"):
                row[key] = getattr(row[key], "value", row[key])
            row["evidence"] = alert.model_dump(mode="json")["evidence"]
            rows.append(row)
        with self._lock, self.engine.begin() as conn:
            conn.execute(insert(alerts_table), rows)
        return alerts

    def _row_to_alert(self, row) -> Alert:
        data = {name: _from_db(name, value) for name, value in row._mapping.items()}
        data["evidence"] = data.get("evidence") or {}
        data["mitre_techniques"] = data.get("mitre_techniques") or []
        return Alert.model_validate(data)

    def get(self, alert_id: str) -> Optional[Alert]:
        with self.engine.connect() as conn:
            row = conn.execute(select(alerts_table).where(alerts_table.c.alert_id == alert_id)).first()
        return self._row_to_alert(row) if row is not None else None

    def _filters(self, q: AlertQuery) -> list:
        c = alerts_table.c
        conditions = []
        for name in ("threat_class", "severity", "source_ip", "destination_ip", "detector_name", "run_id"):
            value = getattr(q, name)
            if value is not None:
                conditions.append(c[name] == getattr(value, "value", value))
        if q.since is not None:
            conditions.append(c.window_end >= _to_db(q.since))
        if q.until is not None:
            conditions.append(c.window_end < _to_db(q.until))
        if q.min_confidence is not None:
            conditions.append(c.confidence >= q.min_confidence)
        return conditions

    def list(self, q: AlertQuery | None = None) -> tuple[list[Alert], int]:
        """(alerts of the requested page, total number matching the filters)."""
        q = q or AlertQuery()
        if q.sort not in SORTABLE:
            raise ValueError(f"Cannot sort by {q.sort!r}; choose from {sorted(SORTABLE)}")
        conditions = self._filters(q)
        column = alerts_table.c[q.sort]
        if q.sort == "severity":
            column = case(_SEVERITY_RANK, value=alerts_table.c.severity, else_=-1)
        order = [column.desc() if q.descending else column.asc(), alerts_table.c.alert_id]
        stmt = select(alerts_table).where(*conditions).order_by(*order).limit(q.limit).offset(q.offset)
        count = select(func.count()).select_from(alerts_table).where(*conditions)
        with self.engine.connect() as conn:
            rows = conn.execute(stmt).all()
            total = conn.execute(count).scalar_one()
        return [self._row_to_alert(r) for r in rows], int(total)

    def all(self, run_id: Optional[str] = None, limit: int = 100_000) -> list[Alert]:
        alerts, _ = self.list(AlertQuery(run_id=run_id, sort="window_end", descending=False, limit=limit))
        return alerts

    def count(self) -> int:
        with self.engine.connect() as conn:
            return int(conn.execute(select(func.count()).select_from(alerts_table)).scalar_one())

    def delete_all(self) -> int:
        with self._lock, self.engine.begin() as conn:
            return conn.execute(delete(alerts_table)).rowcount or 0

    def summary(self, run_id: Optional[str] = None) -> AlertSummary:
        c = alerts_table.c
        where = [c.run_id == run_id] if run_id else []
        with self.engine.connect() as conn:
            total, avg_conf, avg_lat, first, last = conn.execute(
                select(func.count(), func.avg(c.confidence), func.avg(c.detection_latency_ms),
                       func.min(c.timestamp), func.max(c.timestamp)).where(*where)
            ).one()
            groups = {}
            for name in ("threat_class", "severity", "detector_name"):
                rows = conn.execute(select(c[name], func.count()).where(*where).group_by(c[name])).all()
                groups[name] = {k: int(v) for k, v in rows}
        if not total:
            return AlertSummary()
        return AlertSummary(
            total_alerts=int(total),
            by_threat_class=groups["threat_class"],
            by_severity=groups["severity"],
            by_detector=groups["detector_name"],
            avg_confidence=round(float(avg_conf or 0.0), 4),
            avg_detection_latency_ms=round(float(avg_lat or 0.0), 2),
            time_range_start=_from_db("timestamp", first),
            time_range_end=_from_db("timestamp", last),
        )

    def timeline(self, bucket_sec: int = 60, run_id: Optional[str] = None,
                 limit: int = 100_000) -> list[dict[str, Any]]:
        """Alert counts per severity in buckets of traffic time (by window end)."""
        c = alerts_table.c
        stmt = select(c.window_end, c.severity).where(*([c.run_id == run_id] if run_id else []))             .order_by(c.window_end).limit(limit)
        buckets: dict[int, dict[str, Any]] = {}
        with self.engine.connect() as conn:
            for window_end, severity in conn.execute(stmt).all():
                ts = _from_db("window_end", window_end).timestamp()
                key = int(ts // bucket_sec) * bucket_sec
                b = buckets.setdefault(key, {"bucket_start": datetime.fromtimestamp(key, tz=timezone.utc),
                                             "total": 0})
                b[severity] = b.get(severity, 0) + 1
                b["total"] += 1
        return [buckets[k] for k in sorted(buckets)]

    def top_entities(self, column: str, limit: int = 10) -> list[dict[str, Any]]:
        if column not in ("source_ip", "destination_ip"):
            raise ValueError("column must be source_ip or destination_ip")
        c = alerts_table.c
        stmt = (select(c[column], func.count().label("alerts"), func.max(c.confidence))
                .where(c[column].is_not(None)).group_by(c[column])
                .order_by(func.count().desc(), c[column]).limit(limit))
        with self.engine.connect() as conn:
            return [{"ip": ip, "alerts": int(n), "max_confidence": round(float(mc or 0), 4)}
                    for ip, n, mc in conn.execute(stmt).all()]

    # --- runs ----------------------------------------------------------------

    def start_run(self, run_id: str, source: str, detection_mode: str) -> None:
        with self._lock, self.engine.begin() as conn:
            conn.execute(insert(runs_table).values(run_id=run_id, source=source, detection_mode=detection_mode,
                                                   status="running", started_at=_to_db(utc_now())))

    def finish_run(self, run_id: str, status: str, summary: dict[str, Any] | None = None) -> None:
        summary = summary or {}
        with self._lock, self.engine.begin() as conn:
            conn.execute(update(runs_table).where(runs_table.c.run_id == run_id).values(
                status=status, finished_at=_to_db(utc_now()), records=summary.get("total_records"),
                windows=summary.get("total_windows"), alerts=summary.get("total_alerts"),
                summary=_jsonable(summary)))

    def runs(self, limit: int = 20) -> list[dict[str, Any]]:
        stmt = select(runs_table).order_by(runs_table.c.started_at.desc()).limit(limit)
        with self.engine.connect() as conn:
            out = []
            for row in conn.execute(stmt).all():
                data = dict(row._mapping)
                for key in ("started_at", "finished_at"):
                    if isinstance(data[key], datetime):
                        data[key] = data[key].replace(tzinfo=timezone.utc).isoformat()
                out.append(data)
            return out


def _jsonable(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    if isinstance(value, datetime):
        return value.isoformat()
    return value
