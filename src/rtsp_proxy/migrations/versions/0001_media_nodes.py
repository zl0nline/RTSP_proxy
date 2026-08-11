"""Create the bounded media-node registry.

Revision ID: 0001_media_nodes
Revises:
Create Date: 2026-08-12
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001_media_nodes"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "media_nodes",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("external_port", sa.Integer(), nullable=False, unique=True),
        sa.Column("state", sa.String(length=32), nullable=False),
        sa.Column("runtime_state", sa.String(length=32), nullable=False),
        sa.Column("health", sa.String(length=32), nullable=False),
        sa.Column("registered_cameras", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("camera_capacity", sa.Integer(), nullable=False, server_default="100"),
        sa.Column("active_sources", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("maintenance", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column(
            "management_fresh",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
        sa.Column(
            "config_compatible",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
        sa.Column("desired_revision", sa.BigInteger(), nullable=False, server_default="1"),
        sa.Column("applied_revision", sa.BigInteger(), nullable=False, server_default="0"),
        sa.CheckConstraint(
            "external_port BETWEEN 1 AND 65535",
            name="ck_media_nodes_external_port",
        ),
        sa.CheckConstraint(
            "registered_cameras BETWEEN 0 AND 100",
            name="ck_media_nodes_registered_cameras",
        ),
        sa.CheckConstraint(
            "camera_capacity = 100",
            name="ck_media_nodes_camera_capacity",
        ),
        sa.CheckConstraint("active_sources >= 0", name="ck_media_nodes_active_sources"),
        sa.CheckConstraint(
            "state IN ('provisioning', 'stopped', 'stopping', 'starting', 'running', "
            "'draining', 'maintenance', 'failed', 'deleting')",
            name="ck_media_nodes_state",
        ),
        sa.CheckConstraint(
            "runtime_state IN ('provisioning', 'stopped', 'stopping', 'starting', 'running', "
            "'draining', 'maintenance', 'failed', 'deleting')",
            name="ck_media_nodes_runtime_state",
        ),
        sa.CheckConstraint(
            "health IN ('unknown', 'healthy', 'unhealthy')",
            name="ck_media_nodes_health",
        ),
        sa.CheckConstraint("desired_revision >= 1", name="ck_media_nodes_desired_revision"),
        sa.CheckConstraint(
            "applied_revision BETWEEN 0 AND desired_revision",
            name="ck_media_nodes_applied_revision",
        ),
    )


def downgrade() -> None:
    op.drop_table("media_nodes")
