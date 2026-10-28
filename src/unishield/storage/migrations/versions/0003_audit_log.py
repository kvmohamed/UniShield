"""Append-only audit log.

Revision ID: 0003_audit_log
Revises: 0002_intel_indicators
Create Date: 2026-10-22

UniShield only ever inserts into ``audit_log``. On SQLite and PostgreSQL,
triggers additionally make the database refuse UPDATE and DELETE (and
TRUNCATE on PostgreSQL), so a bug or an injected statement in the
application cannot rewrite history; someone with administrative access to
the database itself can still drop the triggers. A later migration that
alters this table in SQLite batch mode must recreate the triggers.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0003_audit_log"
down_revision = "0002_intel_indicators"
branch_labels = None
depends_on = None

_MESSAGE = "audit_log is append-only"


def upgrade() -> None:
    op.create_table(
        "audit_log",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("timestamp", sa.DateTime(), nullable=False),
        sa.Column("actor", sa.String(128), nullable=False),
        sa.Column("actor_type", sa.String(16), nullable=False),
        sa.Column("role", sa.String(16)),
        sa.Column("action", sa.String(64), nullable=False),
        sa.Column("outcome", sa.String(16), nullable=False),
        sa.Column("target", sa.String(256)),
        sa.Column("client_ip", sa.String(64)),
        sa.Column("details", sa.JSON()),
    )
    op.create_index("ix_audit_log_timestamp", "audit_log", ["timestamp"])
    op.create_index("ix_audit_log_action", "audit_log", ["action"])
    op.create_index("ix_audit_log_actor", "audit_log", ["actor"])

    dialect = op.get_bind().dialect.name
    if dialect == "sqlite":
        for event in ("UPDATE", "DELETE"):
            op.execute(f"CREATE TRIGGER audit_log_no_{event.lower()} BEFORE {event} ON audit_log "
                       f"BEGIN SELECT RAISE(ABORT, '{_MESSAGE}'); END")
    elif dialect == "postgresql":
        op.execute("CREATE FUNCTION unishield_audit_append_only() RETURNS trigger LANGUAGE plpgsql AS "
                   f"$$ BEGIN RAISE EXCEPTION '{_MESSAGE}'; END $$")
        op.execute("CREATE TRIGGER audit_log_no_change BEFORE UPDATE OR DELETE ON audit_log "
                   "FOR EACH ROW EXECUTE FUNCTION unishield_audit_append_only()")
        op.execute("CREATE TRIGGER audit_log_no_truncate BEFORE TRUNCATE ON audit_log "
                   "FOR EACH STATEMENT EXECUTE FUNCTION unishield_audit_append_only()")


def downgrade() -> None:
    dialect = op.get_bind().dialect.name
    if dialect == "sqlite":
        op.execute("DROP TRIGGER IF EXISTS audit_log_no_update")
        op.execute("DROP TRIGGER IF EXISTS audit_log_no_delete")
    elif dialect == "postgresql":
        op.execute("DROP TRIGGER IF EXISTS audit_log_no_truncate ON audit_log")
        op.execute("DROP TRIGGER IF EXISTS audit_log_no_change ON audit_log")
        op.execute("DROP FUNCTION IF EXISTS unishield_audit_append_only()")
    op.drop_index("ix_audit_log_actor", table_name="audit_log")
    op.drop_index("ix_audit_log_action", table_name="audit_log")
    op.drop_index("ix_audit_log_timestamp", table_name="audit_log")
    op.drop_table("audit_log")
