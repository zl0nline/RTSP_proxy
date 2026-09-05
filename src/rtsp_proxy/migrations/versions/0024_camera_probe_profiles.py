"""Persist explicit camera monitoring profiles without enabling active probes.

Revision ID: 0024_camera_probe_profiles
Revises: 0023_probe_health_states
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0024_camera_probe_profiles"
down_revision: str | None = "0023_probe_health_states"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "camera_probe_profiles",
        sa.Column(
            "camera_id", postgresql.UUID(as_uuid=True),
            sa.ForeignKey("cameras.id", ondelete="CASCADE"), primary_key=True,
        ),
        sa.Column("revision", sa.BigInteger(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("max_source_sessions", sa.Integer(), nullable=False),
        sa.Column("require_video", sa.Boolean(), nullable=False),
        sa.Column("require_audio", sa.Boolean(), nullable=False),
        sa.Column("routine_seconds", sa.Integer(), nullable=False),
        sa.Column("confirmation_seconds", sa.Integer(), nullable=False),
        sa.Column("timeout_seconds", sa.Integer(), nullable=False),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False,
            server_default=sa.text("clock_timestamp()"),
        ),
        sa.Column("last_attempt_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint("revision >= 1", name="ck_camera_probe_profile_revision"),
        sa.CheckConstraint(
            "max_source_sessions BETWEEN 1 AND 16", name="ck_camera_probe_profile_capacity",
        ),
        sa.CheckConstraint("require_video OR require_audio", name="ck_camera_probe_profile_media"),
        sa.CheckConstraint(
            "routine_seconds BETWEEN 30 AND 86400 "
            "AND confirmation_seconds BETWEEN 1 AND 3600 "
            "AND confirmation_seconds <= routine_seconds "
            "AND timeout_seconds BETWEEN 1 AND 30",
            name="ck_camera_probe_profile_intervals",
        ),
        sa.CheckConstraint(
            "last_attempt_at IS NULL OR last_attempt_at >= updated_at",
            name="ck_camera_probe_profile_attempt_time",
        ),
    )


def downgrade() -> None:
    op.drop_table("camera_probe_profiles")
