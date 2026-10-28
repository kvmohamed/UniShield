"""Alerts and analysis runs (the schema before migrations existed).

Revision ID: 0001_initial
Revises:
Create Date: 2026-10-22

Databases created by earlier versions with ``metadata.create_all`` have
exactly these tables; ``unishield.storage.migrate.upgrade`` stamps them at
this revision instead of running it.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "alerts",
        sa.Column("alert_id", sa.String(32), primary_key=True),
        sa.Column("timestamp", sa.DateTime(), nullable=False),
        sa.Column("window_start", sa.DateTime(), nullable=False),
        sa.Column("window_end", sa.DateTime(), nullable=False),
        sa.Column("source_ip", sa.String(64)),
        sa.Column("destination_ip", sa.String(64)),
        sa.Column("source_ip_hash", sa.String(128)),
        sa.Column("destination_ip_hash", sa.String(128)),
        sa.Column("flow_id", sa.String(128)),
        sa.Column("threat_class", sa.String(48), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("detector_name", sa.String(64), nullable=False),
        sa.Column("model_version", sa.String(64)),
        sa.Column("evidence", sa.JSON()),
        sa.Column("mitre_techniques", sa.JSON()),
        sa.Column("detection_latency_ms", sa.Float()),
        sa.Column("source_type", sa.String(32)),
        sa.Column("window_closed_at", sa.DateTime()),
        sa.Column("emitted_at", sa.DateTime()),
        sa.Column("stored_at", sa.DateTime()),
        sa.Column("run_id", sa.String(64)),
    )
    op.create_index("ix_alerts_window_end", "alerts", ["window_end"])
    op.create_index("ix_alerts_threat_class", "alerts", ["threat_class"])
    op.create_index("ix_alerts_severity", "alerts", ["severity"])
    op.create_index("ix_alerts_source_ip", "alerts", ["source_ip"])

    op.create_table(
        "runs",
        sa.Column("run_id", sa.String(64), primary_key=True),
        sa.Column("source", sa.String(512)),
        sa.Column("detection_mode", sa.String(16)),
        sa.Column("status", sa.String(32)),
        sa.Column("started_at", sa.DateTime()),
        sa.Column("finished_at", sa.DateTime()),
        sa.Column("records", sa.Integer()),
        sa.Column("windows", sa.Integer()),
        sa.Column("alerts", sa.Integer()),
        sa.Column("summary", sa.JSON()),
    )


def downgrade() -> None:
    op.drop_table("runs")
    op.drop_index("ix_alerts_source_ip", table_name="alerts")
    op.drop_index("ix_alerts_severity", table_name="alerts")
    op.drop_index("ix_alerts_threat_class", table_name="alerts")
    op.drop_index("ix_alerts_window_end", table_name="alerts")
    op.drop_table("alerts")
