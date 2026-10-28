"""
UniShield — Database

SQLAlchemy engine and schema for alert storage. SQLite is the default
(``sqlite:///./data/unishield.db``); PostgreSQL works by URL
(``postgresql+psycopg://user:pass@host/db``, driver installed separately).
The URL comes from ``database.url`` or ``UNISHIELD_DB_URL``.

The tables below describe the schema for queries; the schema itself is
created and changed by the Alembic revisions in ``migrations/versions``
(see ``storage/migrate.py``), and a test checks that the two agree.

All queries go through SQLAlchemy expressions with bound parameters; no SQL
is built from request strings. Times are stored as naive UTC and returned
as timezone-aware UTC.
"""

from __future__ import annotations

import threading
import weakref
from pathlib import Path

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    MetaData,
    String,
    Table,
    create_engine,
    event,
    false,
)
from sqlalchemy.engine import Engine
from sqlalchemy.pool import StaticPool

metadata = MetaData()

alerts_table = Table(
    "alerts",
    metadata,
    Column("alert_id", String(32), primary_key=True),
    Column("timestamp", DateTime, nullable=False),
    Column("window_start", DateTime, nullable=False),
    Column("window_end", DateTime, nullable=False),
    Column("source_ip", String(64)),
    Column("destination_ip", String(64)),
    Column("source_ip_hash", String(128)),
    Column("destination_ip_hash", String(128)),
    Column("flow_id", String(128)),
    Column("threat_class", String(48), nullable=False),
    Column("severity", String(16), nullable=False),
    Column("confidence", Float, nullable=False),
    Column("detector_name", String(64), nullable=False),
    Column("model_version", String(64)),
    Column("evidence", JSON),
    Column("mitre_techniques", JSON),
    Column("detection_latency_ms", Float),
    Column("source_type", String(32)),
    Column("window_closed_at", DateTime),
    Column("emitted_at", DateTime),
    Column("stored_at", DateTime),
    Column("run_id", String(64)),
    Index("ix_alerts_window_end", "window_end"),
    Index("ix_alerts_threat_class", "threat_class"),
    Index("ix_alerts_severity", "severity"),
    Index("ix_alerts_source_ip", "source_ip"),
    Index("ix_alerts_stored_at", "stored_at"),
)

runs_table = Table(
    "runs",
    metadata,
    Column("run_id", String(64), primary_key=True),
    Column("source", String(512)),
    Column("detection_mode", String(16)),
    Column("status", String(32)),
    Column("started_at", DateTime),
    Column("finished_at", DateTime),
    Column("records", Integer),
    Column("windows", Integer),
    Column("alerts", Integer),
    Column("summary", JSON),
)

# Operator-imported threat-intelligence indicators (see unishield.intel)
intel_table = Table(
    "intel_indicators",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("source", String(128), nullable=False),
    Column("kind", String(16), nullable=False),
    Column("value", String(256), nullable=False),
    Column("label", String(256)),
    Column("severity", String(16)),
    Column("techniques", JSON),
    Column("expires_at", DateTime),
    Column("imported_at", DateTime, nullable=False),
    Index("ux_intel_source_kind_value", "source", "kind", "value", unique=True),
    Index("ix_intel_kind", "kind"),
)

intel_imports_table = Table(
    "intel_imports",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("source", String(128), nullable=False),
    Column("filename", String(256)),
    Column("format", String(16)),
    Column("mode", String(16)),
    Column("sha256", String(64)),
    Column("accepted", Integer),
    Column("rejected", Integer),
    Column("imported_at", DateTime, nullable=False),
)

audit_log_table = Table(
    "audit_log",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("timestamp", DateTime, nullable=False),
    Column("actor", String(128), nullable=False),
    Column("actor_type", String(16), nullable=False),
    Column("role", String(16)),
    Column("action", String(64), nullable=False),
    Column("outcome", String(16), nullable=False),
    Column("target", String(256)),
    Column("client_ip", String(64)),
    Column("details", JSON),
    Index("ix_audit_log_timestamp", "timestamp"),
    Index("ix_audit_log_action", "action"),
    Index("ix_audit_log_actor", "actor"),
)

users_table = Table(
    "users",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("username", String(64), nullable=False, unique=True),
    Column("password_hash", String(255), nullable=False),
    Column("role", String(16), nullable=False),
    Column("disabled", Boolean, nullable=False, server_default=false()),
    Column("failed_logins", Integer, nullable=False, server_default="0"),
    Column("locked_until", DateTime),
    Column("created_at", DateTime, nullable=False),
    Column("created_by", String(128)),
    Column("updated_at", DateTime),
    Column("password_changed_at", DateTime),
    Column("last_login_at", DateTime),
)

sessions_table = Table(
    "sessions",
    metadata,
    Column("id", String(64), primary_key=True),                 # SHA-256 of the cookie value
    Column("user_id", Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
    Column("csrf_token", String(64), nullable=False),
    Column("created_at", DateTime, nullable=False),
    Column("expires_at", DateTime, nullable=False),
    Column("last_seen_at", DateTime, nullable=False),
    Column("client_ip", String(64)),
    Column("user_agent", String(256)),
    Index("ix_sessions_user_id", "user_id"),
    Index("ix_sessions_expires_at", "expires_at"),
)

api_tokens_table = Table(
    "api_tokens",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("name", String(64), nullable=False, unique=True),
    Column("token_hash", String(64), nullable=False, unique=True),   # SHA-256 of the token
    Column("role", String(16), nullable=False),
    Column("created_at", DateTime, nullable=False),
    Column("created_by", String(128)),
    Column("expires_at", DateTime),
    Column("last_used_at", DateTime),
    Column("revoked_at", DateTime),
)

_WRITE_LOCKS: "weakref.WeakKeyDictionary[Engine, threading.Lock]" = weakref.WeakKeyDictionary()
_WRITE_LOCKS_GUARD = threading.Lock()


def write_lock(engine: Engine) -> threading.Lock:
    """One lock per engine, shared by every store writing through it (the pipeline thread and API
    requests share one SQLite database, and in-memory SQLite shares a single connection)."""
    with _WRITE_LOCKS_GUARD:
        lock = _WRITE_LOCKS.get(engine)
        if lock is None:
            lock = _WRITE_LOCKS[engine] = threading.Lock()
        return lock


def make_engine(url: str, echo: bool = False, migrate: bool = True) -> Engine:
    """
    Engine for ``url``. In-memory SQLite shares one connection. With
    ``migrate`` the database is upgraded to the latest schema revision.
    """
    kwargs: dict = {"echo": echo, "future": True}
    if url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
        if url in ("sqlite://", "sqlite:///:memory:"):
            kwargs["poolclass"] = StaticPool
        else:
            db_path = url.split("sqlite:///", 1)[-1]
            if db_path:
                Path(db_path).expanduser().parent.mkdir(parents=True, exist_ok=True)
    engine = create_engine(url, **kwargs)
    if url.startswith("sqlite"):
        @event.listens_for(engine, "connect")
        def _sqlite_pragmas(dbapi_connection, _record):       # pragma: no cover - driver hook
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA busy_timeout=5000")
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()
    if migrate:
        from unishield.storage import migrate as migrations

        migrations.upgrade(engine)
    return engine
