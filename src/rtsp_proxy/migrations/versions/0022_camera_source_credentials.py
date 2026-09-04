"""Add encrypted camera source credentials.

Revision ID: 0022_camera_source_credentials
Revises: 0021_local_operator_login
Create Date: 2026-09-04
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0022_camera_source_credentials"
down_revision: str | None = "0021_local_operator_login"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "camera_source_credentials",
        sa.Column(
            "camera_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("cameras.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("key_id", sa.String(length=64), nullable=False),
        sa.Column("ciphertext", postgresql.BYTEA(), nullable=False),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("clock_timestamp()"),
        ),
        sa.CheckConstraint(
            "key_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'",
            name="ck_camera_source_credentials_key_id",
        ),
        sa.CheckConstraint(
            "octet_length(ciphertext) BETWEEN 29 AND 1024",
            name="ck_camera_source_credentials_ciphertext",
        ),
    )


def downgrade() -> None:
    op.drop_table("camera_source_credentials")
