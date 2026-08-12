"""Persist crash-safe node port changes and deletable history references.

Revision ID: 0008_node_administration
Revises: 0007_camera_move_saga
Create Date: 2026-08-12
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0008_node_administration"
down_revision: str | None = "0007_camera_move_saga"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.drop_constraint(
        "camera_placement_history_node_id_fkey",
        "camera_placement_history",
        type_="foreignkey",
    )
    op.drop_constraint(
        "camera_move_sagas_source_node_id_fkey",
        "camera_move_sagas",
        type_="foreignkey",
    )
    op.drop_constraint(
        "camera_move_sagas_target_node_id_fkey",
        "camera_move_sagas",
        type_="foreignkey",
    )
    op.create_table(
        "node_port_change_sagas",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "node_id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
        ),
        sa.Column("old_port", sa.Integer(), nullable=False),
        sa.Column("new_port", sa.Integer(), nullable=False),
        sa.Column("source_revision", sa.BigInteger(), nullable=False),
        sa.Column("target_revision", sa.BigInteger(), nullable=False),
        sa.Column("registered_cameras", sa.Integer(), nullable=False),
        sa.Column("blast_radius_sha256", sa.String(length=64), nullable=False),
        sa.Column("state", sa.String(length=16), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("clock_timestamp()"),
        ),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "old_port BETWEEN 1 AND 65535",
            name="ck_node_port_change_old_port",
        ),
        sa.CheckConstraint(
            "new_port BETWEEN 1 AND 65535",
            name="ck_node_port_change_new_port",
        ),
        sa.CheckConstraint(
            "old_port <> new_port",
            name="ck_node_port_change_distinct_ports",
        ),
        sa.CheckConstraint(
            "source_revision >= 1",
            name="ck_node_port_change_source_revision",
        ),
        sa.CheckConstraint(
            "target_revision = source_revision + 1",
            name="ck_node_port_change_target_revision",
        ),
        sa.CheckConstraint(
            "registered_cameras BETWEEN 0 AND 100",
            name="ck_node_port_change_registered_cameras",
        ),
        sa.CheckConstraint(
            "blast_radius_sha256 ~ '^[0-9a-f]{64}$'",
            name="ck_node_port_change_blast_radius_sha256",
        ),
        sa.CheckConstraint(
            "state IN ('prepared', 'complete', 'aborted')",
            name="ck_node_port_change_state",
        ),
    )
    op.create_index(
        "uq_node_port_change_active_node",
        "node_port_change_sagas",
        ["node_id"],
        unique=True,
        postgresql_where=sa.text("state = 'prepared'"),
    )
    op.create_index(
        "uq_node_port_change_active_port",
        "node_port_change_sagas",
        ["new_port"],
        unique=True,
        postgresql_where=sa.text("state = 'prepared'"),
    )


def downgrade() -> None:
    op.drop_table("node_port_change_sagas")
    op.create_foreign_key(
        "camera_move_sagas_target_node_id_fkey",
        "camera_move_sagas",
        "media_nodes",
        ["target_node_id"],
        ["id"],
        ondelete="RESTRICT",
    )
    op.create_foreign_key(
        "camera_move_sagas_source_node_id_fkey",
        "camera_move_sagas",
        "media_nodes",
        ["source_node_id"],
        ["id"],
        ondelete="RESTRICT",
    )
    op.create_foreign_key(
        "camera_placement_history_node_id_fkey",
        "camera_placement_history",
        "media_nodes",
        ["node_id"],
        ["id"],
        ondelete="RESTRICT",
    )
