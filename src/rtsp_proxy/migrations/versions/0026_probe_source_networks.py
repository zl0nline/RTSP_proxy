"""Add audited operator-managed probe source networks.

Revision ID: 0026_probe_source_networks
Revises: 0025_permanent_service_grants
Create Date: 2026-09-16
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import CIDR

revision: str = "0026_probe_source_networks"
down_revision: str | None = "0025_permanent_service_grants"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("SET LOCAL lock_timeout = '1s'")
    op.execute("SET LOCAL statement_timeout = '30s'")
    op.create_table(
        "probe_source_networks",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("network", CIDR(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_by_account_id", sa.Uuid(), nullable=False),
        sa.Column("created_by_session_id", sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(
            ["created_by_account_id"], ["operator_accounts.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["created_by_session_id"], ["operator_sessions.id"], ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("id", name="probe_source_networks_pkey"),
        sa.UniqueConstraint("network", name="probe_source_networks_network_key"),
        sa.CheckConstraint(
            "family(network) = 4 AND masklen(network) IN (24, 32) OR "
            "family(network) = 6 AND masklen(network) = 128",
            name="probe_source_networks_prefix_valid",
        ),
    )


def downgrade() -> None:
    op.drop_table("probe_source_networks")
