"""Add generation-fenced latest probe observations.

Revision ID: 0020_probe_observations
Revises: 0019_dashboard_rate_limits
Create Date: 2026-08-29
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0020_probe_observations"
down_revision: str | None = "0019_dashboard_rate_limits"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("SET LOCAL lock_timeout = '1s'")
    op.execute("SET LOCAL statement_timeout = '30s'")
    op.create_table(
        "camera_probe_endpoints",
        sa.Column(
            "camera_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("cameras.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("admitted_revision", sa.BigInteger(), nullable=False),
        sa.Column(
            "endpoint_generation",
            postgresql.UUID(as_uuid=True),
            nullable=False,
            unique=True,
        ),
        sa.Column("endpoint_address", postgresql.INET(), nullable=False),
        sa.Column("endpoint_port", sa.Integer(), nullable=False),
        sa.Column("site_key", sa.String(64), nullable=False),
        sa.Column("policy_sha256", sa.String(64), nullable=False),
        sa.Column("source_sha256", sa.String(64), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("clock_timestamp()"),
        ),
        sa.CheckConstraint(
            "admitted_revision >= 1",
            name="ck_camera_probe_endpoints_revision",
        ),
        sa.CheckConstraint(
            "endpoint_port BETWEEN 1 AND 65535",
            name="ck_camera_probe_endpoints_port",
        ),
        sa.CheckConstraint(
            "site_key ~ '^[a-z0-9][a-z0-9._-]{0,63}$'",
            name="ck_camera_probe_endpoints_site_key",
        ),
        sa.CheckConstraint(
            "policy_sha256 ~ '^[0-9a-f]{64}$'",
            name="ck_camera_probe_endpoints_policy_sha256",
        ),
        sa.CheckConstraint(
            "source_sha256 ~ '^[0-9a-f]{64}$'",
            name="ck_camera_probe_endpoints_sha256",
        ),
    )
    op.create_table(
        "probe_observations",
        sa.Column("observation_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("request_id", postgresql.UUID(as_uuid=True), nullable=False, unique=True),
        sa.Column(
            "camera_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("cameras.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("public_id", sa.String(length=26), nullable=False),
        sa.Column(
            "node_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("media_nodes.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("site_key", sa.String(length=64), nullable=False),
        sa.Column("desired_revision", sa.BigInteger(), nullable=False),
        sa.Column("placement_generation", sa.BigInteger(), nullable=False),
        sa.Column("target_node_state", sa.String(length=16), nullable=False),
        sa.Column("node_applied_revision", sa.BigInteger(), nullable=True),
        sa.Column("node_process_id", sa.Integer(), nullable=True),
        sa.Column("node_process_start_ticks", sa.BigInteger(), nullable=True),
        sa.Column("node_process_boot_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("node_release_id", sa.String(length=128), nullable=True),
        sa.Column(
            "source_endpoint_generation",
            postgresql.UUID(as_uuid=True),
            nullable=False,
        ),
        sa.Column("target_occupied", sa.Boolean(), nullable=False),
        sa.Column("target_source_pull_active", sa.Boolean(), nullable=False),
        sa.Column("target_max_source_sessions", sa.Integer(), nullable=False),
        sa.Column("method", sa.String(length=16), nullable=False),
        sa.Column("priority", sa.String(length=16), nullable=False),
        sa.Column("outcome", sa.String(length=16), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("attempt", sa.Integer(), nullable=False),
        sa.Column("failure_class", sa.String(length=32), nullable=True),
        sa.Column("video_codec", sa.String(length=32), nullable=True),
        sa.Column("audio_codec", sa.String(length=32), nullable=True),
        sa.CheckConstraint(
            "public_id ~ '^[a-z2-7]{25}[aeimquy4]$'",
            name="ck_probe_observations_public_id",
        ),
        sa.CheckConstraint(
            "site_key ~ '^[a-z0-9][a-z0-9._-]{0,63}$'",
            name="ck_probe_observations_site_key",
        ),
        sa.CheckConstraint(
            "desired_revision >= 1 AND placement_generation >= 1",
            name="ck_probe_observations_generation",
        ),
        sa.CheckConstraint(
            "target_max_source_sessions BETWEEN 1 AND 16",
            name="ck_probe_observations_source_sessions",
        ),
        sa.CheckConstraint(
            "target_node_state IN ('provisioning', 'stopped', 'stopping', 'starting', "
            "'running', 'draining', 'maintenance', 'failed', 'deleting')",
            name="ck_probe_observations_node_state",
        ),
        sa.CheckConstraint(
            "(node_applied_revision IS NULL AND node_process_id IS NULL "
            "AND node_process_start_ticks IS NULL AND node_process_boot_id IS NULL "
            "AND node_release_id IS NULL) OR "
            "(node_applied_revision >= 1 AND node_process_id >= 1 "
            "AND node_process_start_ticks >= 1 AND node_process_boot_id IS NOT NULL "
            "AND node_release_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$')",
            name="ck_probe_observations_node_generation",
        ),
        sa.CheckConstraint(
            "method IN ('source', 'path')",
            name="ck_probe_observations_method",
        ),
        sa.CheckConstraint(
            "(method <> 'path' OR "
            "(target_node_state = 'running' AND NOT target_occupied "
            "AND NOT target_source_pull_active "
            "AND node_applied_revision IS NOT NULL)) AND "
            "(method <> 'source' OR NOT target_source_pull_active "
            "OR target_max_source_sessions > 1)",
            name="ck_probe_observations_eligibility",
        ),
        sa.CheckConstraint(
            "priority IN ('manual', 'confirmation', 'routine')",
            name="ck_probe_observations_priority",
        ),
        sa.CheckConstraint(
            "outcome IN ('healthy', 'unhealthy', 'inconclusive')",
            name="ck_probe_observations_outcome",
        ),
        sa.CheckConstraint(
            "completed_at >= started_at "
            "AND completed_at <= started_at + INTERVAL '60 seconds'",
            name="ck_probe_observations_window",
        ),
        sa.CheckConstraint(
            "attempt BETWEEN 1 AND 10",
            name="ck_probe_observations_attempt",
        ),
        sa.CheckConstraint(
            "failure_class IS NULL OR failure_class IN "
            "('authentication', 'codec', 'connect_timeout', 'executor', 'output', "
            "'transport')",
            name="ck_probe_observations_failure_class",
        ),
        sa.CheckConstraint(
            "(outcome = 'healthy' AND failure_class IS NULL "
            "AND (video_codec IS NOT NULL OR audio_codec IS NOT NULL)) OR "
            "(outcome = 'unhealthy' AND failure_class IN "
            "('authentication', 'codec', 'connect_timeout', 'transport') "
            "AND video_codec IS NULL AND audio_codec IS NULL) OR "
            "(outcome = 'inconclusive' AND failure_class IN ('executor', 'output') "
            "AND video_codec IS NULL AND audio_codec IS NULL)",
            name="ck_probe_observations_result",
        ),
        sa.CheckConstraint(
            "video_codec IS NULL OR video_codec ~ '^[a-z0-9][a-z0-9._-]{0,31}$'",
            name="ck_probe_observations_video_codec",
        ),
        sa.CheckConstraint(
            "audio_codec IS NULL OR audio_codec ~ '^[a-z0-9][a-z0-9._-]{0,31}$'",
            name="ck_probe_observations_audio_codec",
        ),
        sa.UniqueConstraint(
            "camera_id",
            "method",
            name="uq_probe_observations_camera_method",
        ),
    )
    op.create_index(
        "ix_probe_observations_camera_completed",
        "probe_observations",
        ["camera_id", "completed_at"],
    )


def downgrade() -> None:
    op.drop_table("probe_observations")
    op.drop_table("camera_probe_endpoints")
