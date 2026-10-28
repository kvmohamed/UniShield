"""Audit log store: recording, filtering, and append-only enforcement in the database."""

from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy import delete, text, update
from sqlalchemy.exc import DatabaseError

from unishield.schemas.timeutil import utc_now
from unishield.storage.audit import AuditLog, AuditQuery
from unishield.storage.database import audit_log_table, make_engine


@pytest.fixture
def audit(tmp_path):
    return AuditLog(make_engine(f"sqlite:///{(tmp_path / 'audit.db').as_posix()}"))


def test_record_and_list_newest_first(audit):
    audit.record("auth.login", actor="alice", actor_type="user", role="admin", client_ip="10.0.0.5")
    audit.record("auth.login", "failure", actor="mallory", actor_type="anonymous", details={"reason": "bad_password"})
    audit.record("replay.start", actor="alice", actor_type="user", role="admin", target="synthetic:dga:7")
    entries, total = audit.list()
    assert total == 3 and [e["action"] for e in entries] == ["replay.start", "auth.login", "auth.login"]
    assert entries[1]["details"] == {"reason": "bad_password"} and entries[0]["details"] == {}
    assert entries[0]["timestamp"].endswith("+00:00")


def test_filters_and_pagination(audit):
    for i in range(5):
        audit.record("auth.login", "failure" if i % 2 else "success", actor=f"u{i}", actor_type="user")
    audit.record("user.create", actor="admin", actor_type="user", target="u9")
    assert audit.list(AuditQuery(action="auth.login"))[1] == 5
    assert audit.list(AuditQuery(action="auth."))[1] == 5
    assert audit.list(AuditQuery(action="user."))[1] == 1
    assert audit.list(AuditQuery(outcome="failure"))[1] == 2
    assert audit.list(AuditQuery(actor="u3"))[0][0]["outcome"] == "failure"
    page, total = audit.list(AuditQuery(limit=2, offset=2))
    assert total == 6 and len(page) == 2
    assert audit.list(AuditQuery(since=utc_now() + timedelta(minutes=1)))[1] == 0
    assert audit.list(AuditQuery(until=utc_now() + timedelta(minutes=1)))[1] == 6


def test_prefix_filter_escapes_wildcards(audit):
    audit.record("auth_login", actor="x", actor_type="user")
    assert audit.list(AuditQuery(action="auth%."))[1] == 0


def test_rejects_unknown_outcome_and_truncates_long_values(audit):
    with pytest.raises(ValueError):
        audit.record("auth.login", "maybe")
    audit.record("auth.login", "failure", actor="x" * 500, actor_type="anonymous", target="t" * 1000)
    entry = audit.list()[0][0]
    assert len(entry["actor"]) == 128 and len(entry["target"]) == 256


@pytest.mark.parametrize("statement", [
    update(audit_log_table).values(actor="someone-else"),
    delete(audit_log_table),
    text("UPDATE audit_log SET outcome = 'success'"),
    text("DELETE FROM audit_log"),
])
def test_database_refuses_changes_to_entries(audit, statement):
    audit.record("alerts.delete", actor="alice", actor_type="user", details={"deleted": 3})
    with pytest.raises(DatabaseError, match="append-only"):
        with audit.engine.begin() as conn:
            conn.execute(statement)
    (entry,), total = audit.list()
    assert total == 1 and entry["actor"] == "alice" and entry["outcome"] == "success"


def test_store_has_no_mutating_methods():
    public = {name for name in dir(AuditLog) if not name.startswith("_")}
    assert public == {"record", "list"}
