"""
UniShield — Audit Log

Who did what and when: logins, replays, data deletion, account changes,
service start/stop. The store has no update or delete method and the API
has no route that changes entries; on SQLite and PostgreSQL the database
also refuses UPDATE/DELETE on the table (migration ``0003_audit_log``).

Actors are recorded as strings so entries outlive the accounts they name:
a username, ``token:<name>`` for service tokens, ``cli:<os user>`` for
``unishield-admin``, ``system`` for the service itself, or ``anonymous``.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import func, insert, select
from sqlalchemy.engine import Engine

from unishield.schemas.timeutil import utc_now
from unishield.storage.database import audit_log_table, write_lock

OUTCOMES = ("success", "failure", "denied")
_TEXT_LIMITS = {"actor": 128, "actor_type": 16, "role": 16, "action": 64, "outcome": 16, "target": 256,
                "client_ip": 64}


def _naive_utc(value: datetime) -> datetime:
    return value.astimezone(timezone.utc).replace(tzinfo=None) if value.tzinfo else value


@dataclass
class AuditQuery:
    action: Optional[str] = None          # exact action, or a prefix ending in "." (e.g. "auth.")
    actor: Optional[str] = None
    outcome: Optional[str] = None
    since: Optional[datetime] = None
    until: Optional[datetime] = None
    limit: int = 100
    offset: int = 0


class AuditLog:
    """Append-only audit entries on a SQLAlchemy engine."""

    def __init__(self, engine: Engine):
        self.engine = engine
        self._lock = write_lock(engine)

    def record(self, action: str, outcome: str = "success", *, actor: str = "system", actor_type: str = "system",
               role: Optional[str] = None, target: Optional[str] = None, client_ip: Optional[str] = None,
               details: Optional[dict[str, Any]] = None) -> None:
        if outcome not in OUTCOMES:
            raise ValueError(f"outcome must be one of {OUTCOMES}")
        row = {"timestamp": _naive_utc(utc_now()), "actor": actor, "actor_type": actor_type, "role": role,
               "action": action, "outcome": outcome, "target": target, "client_ip": client_ip,
               "details": details or None}
        for key, limit in _TEXT_LIMITS.items():
            if isinstance(row[key], str):
                row[key] = row[key][:limit]
        with self._lock, self.engine.begin() as conn:
            conn.execute(insert(audit_log_table).values(**row))

    def list(self, q: AuditQuery | None = None) -> tuple[list[dict[str, Any]], int]:
        """(entries of the requested page, newest first; total matching the filters)."""
        q = q or AuditQuery()
        c = audit_log_table.c
        conditions = []
        if q.action:
            conditions.append(c.action.startswith(q.action, autoescape=True) if q.action.endswith(".")
                              else c.action == q.action)
        if q.actor:
            conditions.append(c.actor == q.actor)
        if q.outcome:
            conditions.append(c.outcome == q.outcome)
        if q.since is not None:
            conditions.append(c.timestamp >= _naive_utc(q.since))
        if q.until is not None:
            conditions.append(c.timestamp < _naive_utc(q.until))
        stmt = select(audit_log_table).where(*conditions).order_by(c.id.desc()).limit(q.limit).offset(q.offset)
        count = select(func.count()).select_from(audit_log_table).where(*conditions)
        with self.engine.connect() as conn:
            rows = conn.execute(stmt).all()
            total = conn.execute(count).scalar_one()
        entries = []
        for row in rows:
            data = dict(row._mapping)
            data["timestamp"] = data["timestamp"].replace(tzinfo=timezone.utc).isoformat()
            data["details"] = data["details"] or {}
            entries.append(data)
        return entries, int(total)
