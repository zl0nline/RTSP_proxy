"""Create cameras and authoritative current placements.

Revision ID: 0002_cameras_and_placements
Revises: 0001_media_nodes
Create Date: 2026-08-12
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0002_cameras_and_placements"
down_revision: str | None = "0001_media_nodes"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "cameras",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("source_url", sa.Text(), nullable=False),
        sa.Column("public_id", sa.String(length=26), nullable=False, unique=True),
        sa.Column("desired_revision", sa.BigInteger(), nullable=False, server_default="1"),
        sa.Column("applied_revision", sa.BigInteger(), nullable=False, server_default="0"),
        sa.CheckConstraint(
            "public_id ~ '^[a-z2-7]{25}[aeimquy4]$'",
            name="ck_cameras_public_id",
        ),
        sa.CheckConstraint("desired_revision >= 1", name="ck_cameras_desired_revision"),
        sa.CheckConstraint(
            "applied_revision BETWEEN 0 AND desired_revision",
            name="ck_cameras_applied_revision",
        ),
    )
    op.create_table(
        "camera_placements",
        sa.Column(
            "camera_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("cameras.id", ondelete="RESTRICT"),
            primary_key=True,
        ),
        sa.Column(
            "node_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("media_nodes.id", ondelete="RESTRICT"),
            nullable=False,
            index=True,
        ),
        sa.Column("placement_mode", sa.String(length=16), nullable=False),
        sa.Column("generation", sa.BigInteger(), nullable=False, server_default="1"),
        sa.CheckConstraint("generation >= 1", name="ck_camera_placements_generation"),
        sa.CheckConstraint(
            "placement_mode IN ('automatic', 'manual')",
            name="ck_camera_placements_mode",
        ),
    )


def downgrade() -> None:
    op.drop_table("camera_placements")
    op.drop_table("cameras")
