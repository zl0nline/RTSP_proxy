"""Persist revision-fenced camera move sagas.

Revision ID: 0007_camera_move_saga
Revises: 0006_camera_reconcile
Create Date: 2026-08-12
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0007_camera_move_saga"
down_revision: str | None = "0006_camera_reconcile"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "camera_move_sagas",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "camera_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("cameras.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "source_node_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("media_nodes.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "target_node_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("media_nodes.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("source_generation", sa.BigInteger(), nullable=False),
        sa.Column("target_generation", sa.BigInteger(), nullable=False),
        sa.Column("desired_revision", sa.BigInteger(), nullable=False),
        sa.Column("force", sa.Boolean(), nullable=False),
        sa.Column("state", sa.String(length=32), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("clock_timestamp()"),
        ),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "source_node_id <> target_node_id",
            name="ck_camera_move_distinct_nodes",
        ),
        sa.CheckConstraint(
            "source_generation >= 1",
            name="ck_camera_move_source_generation",
        ),
        sa.CheckConstraint(
            "target_generation = source_generation + 1",
            name="ck_camera_move_target_generation",
        ),
        sa.CheckConstraint(
            "desired_revision >= 2",
            name="ck_camera_move_desired_revision",
        ),
        sa.CheckConstraint(
            "state IN ('prepare_target', 'cleanup_source', 'complete')",
            name="ck_camera_move_state",
        ),
    )
    op.create_index(
        "uq_camera_move_active",
        "camera_move_sagas",
        ["camera_id"],
        unique=True,
        postgresql_where=sa.text("state <> 'complete'"),
    )
    op.create_index(
        "ix_camera_move_target_state",
        "camera_move_sagas",
        ["target_node_id", "state"],
    )


def downgrade() -> None:
    op.drop_table("camera_move_sagas")
