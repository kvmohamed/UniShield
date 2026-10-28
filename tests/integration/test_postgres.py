"""
Migrations, the audit log's append-only triggers and the stores on PostgreSQL.

Skipped unless UNISHIELD_TEST_POSTGRES_URL names an empty database the tests
may drop and recreate tables in, e.g.
postgresql+psycopg://postgres:postgres@127.0.0.1:5432/unishield_test
(CI runs them against a PostgreSQL service container).
"""

from __future__ import annotations

import os

import pytest
from alembic.autogenerate import compare_metadata
from alembic.runtime.migration import MigrationContext
from sqlalchemy import delete, inspect, text, update
from sqlalchemy.exc import DBAPIError

from unishield.accounts import AccountStore
from unishield.storage import AlertRepository, AuditLog, migrate
from unishield.storage.database import audit_log_table, make_engine, metadata

URL = os.environ.get("UNISHIELD_TEST_POSTGRES_URL")
pytestmark = [pytest.mark.integration,
              pytest.mark.skipif(not URL, reason="set UNISHIELD_TEST_POSTGRES_URL to run PostgreSQL tests")]


@pytest.fixture
def engine():
    engine = make_engine(URL, migrate=False)
    if migrate.current_revision(engine):                 # left over from an interrupted run
        migrate.downgrade(engine, "base")
    with engine.begin() as conn:
        conn.execute(text("DROP TABLE IF EXISTS alembic_version"))
    yield engine
    migrate.downgrade(engine, "base")
    engine.dispose()


def test_upgrade_from_empty_matches_metadata(engine):
    assert set(inspect(engine).get_table_names()) == set()
    migrate.upgrade(engine)
    assert migrate.is_current(engine)
    assert {"alerts", "runs", "audit_log", "users", "sessions", "api_tokens"} <= set(inspect(engine).get_table_names())
    with engine.connect() as conn:
        assert compare_metadata(MigrationContext.configure(conn, opts={"compare_type": True}), metadata) == []


@pytest.mark.parametrize("statement", [
    update(audit_log_table).values(actor="someone-else"),
    delete(audit_log_table),
    text("TRUNCATE audit_log"),
])
def test_audit_log_is_append_only_in_postgres(engine, statement):
    migrate.upgrade(engine)
    audit = AuditLog(engine)
    audit.record("alerts.delete", actor="alice", actor_type="user", details={"deleted": 3})
    with pytest.raises(DBAPIError, match="append-only"):
        with engine.begin() as conn:
            conn.execute(statement)
    (entry,), total = audit.list()
    assert total == 1 and entry["actor"] == "alice" and entry["details"] == {"deleted": 3}


def test_stores_work_on_postgres(engine):
    migrate.upgrade(engine)
    repo = AlertRepository(engine)
    from tests.unit.test_api import _alert

    repo.add_many([_alert(i) for i in range(3)])
    assert repo.count() == 3 and repo.summary().total_alerts == 3
    accounts = AccountStore(engine)
    accounts.create_user("pgadmin", "postgres test password", "admin")
    assert accounts.authenticate("pgadmin", "postgres test password", 5, 15).ok
    raw, session = accounts.create_session(accounts.get_user("pgadmin"), 60)
    assert accounts.resolve_session(raw, 30).user.username == "pgadmin"
    token, _ = accounts.create_token("ci", "viewer")
    assert accounts.resolve_token(token).name == "ci"
