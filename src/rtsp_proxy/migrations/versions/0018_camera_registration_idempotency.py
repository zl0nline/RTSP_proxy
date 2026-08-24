"""Bind camera registration to an operator-session idempotency key.

Revision ID: 0018_camera_registration_keys
Revises: 0017_access_grant_keys
Create Date: 2026-08-24
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0018_camera_registration_keys"
down_revision: str | None = "0017_access_grant_keys"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("SET LOCAL lock_timeout = '1s'")
    op.execute("SET LOCAL statement_timeout = '30s'")
    op.drop_constraint(
        "operator_action_rate_limits_bucket_valid",
        "operator_action_rate_limits",
        type_="check",
    )
    op.create_check_constraint(
        "operator_action_rate_limits_bucket_valid",
        "operator_action_rate_limits",
        "bucket IN ('access_mutation', 'camera_mutation', 'secret_issue')",
    )
    op.create_table(
        "camera_registration_requests",
        sa.Column("actor_session_id", sa.Uuid(), nullable=False),
        sa.Column("idempotency_key", sa.Uuid(), nullable=False),
        sa.Column("actor_account_id", sa.Uuid(), nullable=False),
        sa.Column("request_sha256", sa.String(length=64), nullable=False),
        sa.Column("camera_id", sa.Uuid(), nullable=True),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("clock_timestamp()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["actor_account_id"],
            ["operator_accounts.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["camera_id"],
            ["cameras.id"],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint(
            "actor_session_id",
            "idempotency_key",
            name="camera_registration_requests_pkey",
        ),
        sa.UniqueConstraint(
            "camera_id",
            name="camera_registration_requests_camera_id_key",
        ),
        sa.CheckConstraint(
            "request_sha256 ~ '^[0-9a-f]{64}$'",
            name="camera_registration_requests_sha256_valid",
        ),
        sa.CheckConstraint(
            "(status = 'pending' AND camera_id IS NULL) OR "
            "(status = 'complete' AND camera_id IS NOT NULL)",
            name="camera_registration_requests_state_valid",
        ),
    )


def downgrade() -> None:
    op.drop_table("camera_registration_requests")
    op.drop_constraint(
        "operator_action_rate_limits_bucket_valid",
        "operator_action_rate_limits",
        type_="check",
    )
    op.create_check_constraint(
        "operator_action_rate_limits_bucket_valid",
        "operator_action_rate_limits",
        "bucket IN ('access_mutation', 'secret_issue')",
    )
