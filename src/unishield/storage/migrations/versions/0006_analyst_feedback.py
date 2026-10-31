"""Analyst verdicts on alerts and suppression rules.

Revision ID: 0006_analyst_feedback
Revises: 0005_alert_retention_index
Create Date: 2026-10-31

A verdict belongs to one alert and is deleted with it (retention, DELETE
/alerts). Suppression rules are scoped (threat class plus a source or
destination) and expire; alerts they match are still stored, marked with
``suppressed_by``, and kept out of notifications and exports.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0006_analyst_feedback"
down_revision = "0005_alert_retention_index"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "alert_feedback",
        sa.Column("alert_id", sa.String(32), sa.ForeignKey("alerts.alert_id", ondelete="CASCADE"),
                  primary_key=True),
        sa.Column("verdict", sa.String(24), nullable=False),
        sa.Column("note", sa.String(2000)),
        sa.Column("analyst", sa.String(128), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_alert_feedback_verdict", "alert_feedback", ["verdict"])
    op.create_table(
        "suppression_rules",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("threat_class", sa.String(48), nullable=False),
        sa.Column("source", sa.String(64)),
        sa.Column("destination", sa.String(64)),
        sa.Column("detector_name", sa.String(64)),
        sa.Column("reason", sa.String(500), nullable=False),
        sa.Column("from_alert_id", sa.String(32)),
        sa.Column("created_by", sa.String(128), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("hits", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_hit_at", sa.DateTime()),
    )
    op.add_column("alerts", sa.Column("suppressed_by", sa.Integer()))
    op.create_index("ix_alerts_suppressed_by", "alerts", ["suppressed_by"])


def downgrade() -> None:
    op.drop_index("ix_alerts_suppressed_by", table_name="alerts")
    with op.batch_alter_table("alerts") as batch:
        batch.drop_column("suppressed_by")
    op.drop_table("suppression_rules")
    op.drop_index("ix_alert_feedback_verdict", table_name="alert_feedback")
    op.drop_table("alert_feedback")
