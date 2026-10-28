"""Threat-intelligence indicators and their import history.

Revision ID: 0002_intel_indicators
Revises: 0001_initial
Create Date: 2026-10-28

Databases created with ``metadata.create_all`` after threat-intel imports
were added already have these tables; they are stamped at 0001 like older
databases, and this revision then leaves existing tables untouched.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0002_intel_indicators"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    existing = set(sa.inspect(op.get_bind()).get_table_names())
    if "intel_indicators" not in existing:
        op.create_table(
            "intel_indicators",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("source", sa.String(128), nullable=False),
            sa.Column("kind", sa.String(16), nullable=False),
            sa.Column("value", sa.String(256), nullable=False),
            sa.Column("label", sa.String(256)),
            sa.Column("severity", sa.String(16)),
            sa.Column("techniques", sa.JSON()),
            sa.Column("expires_at", sa.DateTime()),
            sa.Column("imported_at", sa.DateTime(), nullable=False),
        )
        op.create_index("ux_intel_source_kind_value", "intel_indicators", ["source", "kind", "value"], unique=True)
        op.create_index("ix_intel_kind", "intel_indicators", ["kind"])
    if "intel_imports" not in existing:
        op.create_table(
            "intel_imports",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("source", sa.String(128), nullable=False),
            sa.Column("filename", sa.String(256)),
            sa.Column("format", sa.String(16)),
            sa.Column("mode", sa.String(16)),
            sa.Column("sha256", sa.String(64)),
            sa.Column("accepted", sa.Integer()),
            sa.Column("rejected", sa.Integer()),
            sa.Column("imported_at", sa.DateTime(), nullable=False),
        )


def downgrade() -> None:
    op.drop_table("intel_imports")
    op.drop_index("ix_intel_kind", table_name="intel_indicators")
    op.drop_index("ux_intel_source_kind_value", table_name="intel_indicators")
    op.drop_table("intel_indicators")
