"""Persist generation-bound source/path health transitions.

Revision ID: 0023_probe_health_states
Revises: 0022_camera_source_credentials
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0023_probe_health_states"
down_revision: str | None = "0022_camera_source_credentials"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "probe_health_states",
        sa.Column(
            "camera_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("cameras.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("method", sa.String(16), primary_key=True),
        sa.Column("generation_sha256", sa.String(64), nullable=False),
        sa.Column("health_state", sa.String(16), nullable=False),
        sa.Column("consecutive_failures", sa.Integer(), nullable=False),
        sa.Column("consecutive_successes", sa.Integer(), nullable=False),
        sa.Column("last_observation_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("last_deep_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_success_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint("method IN ('source','path')", name="ck_probe_health_method"),
        sa.CheckConstraint(
            "generation_sha256 ~ '^[0-9a-f]{64}$'", name="ck_probe_health_generation"
        ),
        sa.CheckConstraint(
            "health_state IN ('unknown','healthy','suspect','unhealthy','recovering')",
            name="ck_probe_health_state",
        ),
        sa.CheckConstraint(
            "consecutive_failures BETWEEN 0 AND 2 AND consecutive_successes BETWEEN 0 AND 2",
            name="ck_probe_health_counters",
        ),
        sa.CheckConstraint(
            "(last_observation_id IS NULL) = (last_deep_at IS NULL) "
            "AND (last_success_at IS NULL OR "
            "(last_deep_at IS NOT NULL AND last_success_at <= last_deep_at))",
            name="ck_probe_health_times",
        ),
    )


def downgrade() -> None:
    op.drop_table("probe_health_states")
