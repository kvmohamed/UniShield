"""Index alerts by storage time for the retention job.

Revision ID: 0005_alert_retention_index
Revises: 0004_accounts
Create Date: 2026-10-22
"""

from __future__ import annotations

from alembic import op

revision = "0005_alert_retention_index"
down_revision = "0004_accounts"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_index("ix_alerts_stored_at", "alerts", ["stored_at"])


def downgrade() -> None:
    op.drop_index("ix_alerts_stored_at", table_name="alerts")
