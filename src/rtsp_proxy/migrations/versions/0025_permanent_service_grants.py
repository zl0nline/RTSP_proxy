"""Allow explicitly permanent service access grants.

Revision ID: 0025_permanent_service_grants
Revises: 0024_camera_probe_profiles
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0025_permanent_service_grants"
down_revision: str | None = "0024_camera_probe_profiles"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.drop_constraint(
        "ck_camera_access_grant_window",
        "camera_access_grants",
        type_="check",
    )
    op.alter_column("camera_access_grants", "expires_at", nullable=True)
    op.create_check_constraint(
        "ck_camera_access_grant_window",
        "camera_access_grants",
        "(expires_at IS NOT NULL AND not_before < expires_at) "
        "OR (expires_at IS NULL AND kind = 'service')",
    )


def downgrade() -> None:
    op.execute(
        sa.text(
            "UPDATE camera_access_grants SET expires_at = "
            "GREATEST(clock_timestamp(), not_before + interval '1 second') "
            "WHERE expires_at IS NULL"
        )
    )
    op.drop_constraint(
        "ck_camera_access_grant_window",
        "camera_access_grants",
        type_="check",
    )
    op.alter_column("camera_access_grants", "expires_at", nullable=False)
    op.create_check_constraint(
        "ck_camera_access_grant_window",
        "camera_access_grants",
        "not_before < expires_at",
    )
