"""Add separate durable dashboard-read and live-reconnect buckets.

Revision ID: 0019_dashboard_rate_limits
Revises: 0018_camera_registration_keys
Create Date: 2026-08-29
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0019_dashboard_rate_limits"
down_revision: str | None = "0018_camera_registration_keys"
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
        "bucket IN ('access_mutation', 'camera_mutation', 'dashboard_read', "
        "'live_reconnect', 'secret_issue')",
    )


def downgrade() -> None:
    op.execute(
        "DELETE FROM operator_action_rate_limits "
        "WHERE bucket IN ('dashboard_read', 'live_reconnect')"
    )
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
