"""Bind secret-bearing access grant requests to operator idempotency keys.

Revision ID: 0017_access_grant_keys
Revises: 0016_node_registration_keys
Create Date: 2026-08-24
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0017_access_grant_keys"
down_revision: str | None = "0016_node_registration_keys"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("SET LOCAL lock_timeout = '1s'")
    op.execute("SET LOCAL statement_timeout = '30s'")
    op.create_table(
        "operator_action_rate_limits",
        sa.Column("account_id", sa.Uuid(), nullable=False),
        sa.Column("bucket", sa.String(length=32), nullable=False),
        sa.Column("window_started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(
            ["account_id"],
            ["operator_accounts.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint(
            "account_id",
            "bucket",
            name="operator_action_rate_limits_pkey",
        ),
        sa.CheckConstraint(
            "bucket IN ('access_mutation', 'secret_issue')",
            name="operator_action_rate_limits_bucket_valid",
        ),
        sa.CheckConstraint(
            "used BETWEEN 1 AND 3600",
            name="operator_action_rate_limits_used_valid",
        ),
    )
    op.create_table(
        "access_grant_issue_requests",
        sa.Column("actor_session_id", sa.Uuid(), nullable=False),
        sa.Column("idempotency_key", sa.Uuid(), nullable=False),
        sa.Column("actor_account_id", sa.Uuid(), nullable=False),
        sa.Column("operation", sa.String(length=16), nullable=False),
        sa.Column("camera_id", sa.Uuid(), nullable=False),
        sa.Column("source_grant_id", sa.Uuid(), nullable=True),
        sa.Column("request_sha256", sa.String(length=64), nullable=False),
        sa.Column("replacement_grant_id", sa.Uuid(), nullable=False),
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
        sa.ForeignKeyConstraint(
            ["source_grant_id"],
            ["camera_access_grants.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["replacement_grant_id"],
            ["camera_access_grants.id"],
            ondelete="RESTRICT",
            deferrable=True,
            initially="DEFERRED",
        ),
        sa.PrimaryKeyConstraint(
            "actor_session_id",
            "idempotency_key",
            name="access_grant_issue_requests_pkey",
        ),
    )
    op.create_check_constraint(
        "access_grant_issue_requests_operation_valid",
        "access_grant_issue_requests",
        "operation IN ('issue', 'rotate')",
    )
    op.create_check_constraint(
        "access_grant_issue_requests_source_valid",
        "access_grant_issue_requests",
        "(operation = 'issue' AND source_grant_id IS NULL) OR "
        "(operation = 'rotate' AND source_grant_id IS NOT NULL)",
    )
    op.create_check_constraint(
        "access_grant_issue_requests_sha256_valid",
        "access_grant_issue_requests",
        "request_sha256 ~ '^[0-9a-f]{64}$'",
    )


def downgrade() -> None:
    op.drop_table("access_grant_issue_requests")
    op.drop_table("operator_action_rate_limits")
