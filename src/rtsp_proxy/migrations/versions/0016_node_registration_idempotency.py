"""Bind operator node registration to a session-scoped idempotency key.

Revision ID: 0016_node_registration_keys
Revises: 0015_camera_name_contract
Create Date: 2026-08-24
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0016_node_registration_keys"
down_revision: str | None = "0015_camera_name_contract"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("SET LOCAL lock_timeout = '1s'")
    op.execute("SET LOCAL statement_timeout = '30s'")
    op.create_table(
        "node_registration_requests",
        sa.Column("actor_session_id", sa.Uuid(), nullable=False),
        sa.Column("idempotency_key", sa.Uuid(), nullable=False),
        sa.Column("actor_account_id", sa.Uuid(), nullable=False),
        sa.Column("request_sha256", sa.String(length=64), nullable=False),
        sa.Column("node_id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("clock_timestamp()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint(
            "actor_session_id",
            "idempotency_key",
            name="node_registration_requests_pkey",
        ),
    )
    op.create_check_constraint(
        "node_registration_requests_sha256_valid",
        "node_registration_requests",
        "request_sha256 ~ '^[0-9a-f]{64}$'",
    )


def downgrade() -> None:
    op.drop_table("node_registration_requests")
