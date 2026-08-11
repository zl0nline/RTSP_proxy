"""Bind management freshness to a database-observed timestamp.

Revision ID: 0004_management_freshness
Revises: 0003_audit_outbox_history
Create Date: 2026-08-12
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0004_management_freshness"
down_revision: str | None = "0003_audit_outbox_history"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "media_nodes",
        sa.Column("management_observed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.execute(
        "UPDATE media_nodes "
        "SET management_fresh = false, management_observed_at = NULL"
    )


def downgrade() -> None:
    op.drop_column("media_nodes", "management_observed_at")
