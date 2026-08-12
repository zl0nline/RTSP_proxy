"""Persist camera desired lifecycle and permanently tombstone public IDs.

Revision ID: 0006_camera_reconcile
Revises: 0005_node_runtime
Create Date: 2026-08-12
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0006_camera_reconcile"
down_revision: str | None = "0005_node_runtime"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "cameras",
        sa.Column(
            "state",
            sa.String(length=16),
            nullable=False,
            server_default="enabled",
        ),
    )
    op.create_check_constraint(
        "ck_cameras_state",
        "cameras",
        "state IN ('enabled', 'disabled', 'deleting', 'deleted')",
    )
    op.create_table(
        "public_id_tombstones",
        sa.Column("public_id", sa.String(length=26), primary_key=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("clock_timestamp()"),
        ),
        sa.CheckConstraint(
            "public_id ~ '^[a-z2-7]{25}[aeimquy4]$'",
            name="ck_public_id_tombstones_public_id",
        ),
    )
    op.execute(
        "INSERT INTO public_id_tombstones (public_id) SELECT public_id FROM cameras"
    )


def downgrade() -> None:
    op.drop_table("public_id_tombstones")
    op.drop_constraint("ck_cameras_state", "cameras", type_="check")
    op.drop_column("cameras", "state")
