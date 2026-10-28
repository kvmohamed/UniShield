"""User accounts, login sessions and service tokens.

Revision ID: 0004_accounts
Revises: 0003_audit_log
Create Date: 2026-10-22

Passwords are stored as Argon2id hashes. Session ids and service tokens are
stored as SHA-256 digests of the random values handed to clients, so a copy
of the database does not contain usable credentials.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0004_accounts"
down_revision = "0003_audit_log"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("username", sa.String(64), nullable=False, unique=True),
        sa.Column("password_hash", sa.String(255), nullable=False),
        sa.Column("role", sa.String(16), nullable=False),
        sa.Column("disabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("failed_logins", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("locked_until", sa.DateTime()),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("created_by", sa.String(128)),
        sa.Column("updated_at", sa.DateTime()),
        sa.Column("password_changed_at", sa.DateTime()),
        sa.Column("last_login_at", sa.DateTime()),
    )
    op.create_table(
        "sessions",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("csrf_token", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(), nullable=False),
        sa.Column("client_ip", sa.String(64)),
        sa.Column("user_agent", sa.String(256)),
    )
    op.create_index("ix_sessions_user_id", "sessions", ["user_id"])
    op.create_index("ix_sessions_expires_at", "sessions", ["expires_at"])
    op.create_table(
        "api_tokens",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("name", sa.String(64), nullable=False, unique=True),
        sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("role", sa.String(16), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("created_by", sa.String(128)),
        sa.Column("expires_at", sa.DateTime()),
        sa.Column("last_used_at", sa.DateTime()),
        sa.Column("revoked_at", sa.DateTime()),
    )


def downgrade() -> None:
    op.drop_table("api_tokens")
    op.drop_index("ix_sessions_expires_at", table_name="sessions")
    op.drop_index("ix_sessions_user_id", table_name="sessions")
    op.drop_table("sessions")
    op.drop_table("users")
