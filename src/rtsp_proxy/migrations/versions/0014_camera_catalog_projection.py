"""Add the bounded, indexable camera catalog projection.

Revision ID: 0014_camera_catalog_projection
Revises: 0013_operator_login
Create Date: 2026-08-14
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0014_camera_catalog_projection"
down_revision: str | None = "0013_operator_login"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("SET LOCAL lock_timeout = '1s'")
    op.execute("SET LOCAL statement_timeout = '30s'")
    op.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm")
    op.execute(
        "CREATE INDEX ix_cameras_catalog_name_trgm "
        "ON cameras USING gin (name gin_trgm_ops)"
    )
    op.execute(
        "CREATE INDEX ix_cameras_catalog_public_id_trgm "
        "ON cameras USING gin (public_id gin_trgm_ops)"
    )
    op.execute(
        "CREATE INDEX ix_cameras_catalog_state_id "
        "ON cameras (state, id) WHERE state <> 'deleted'"
    )
    op.execute(
        "CREATE INDEX ix_camera_placements_catalog_node_camera "
        "ON camera_placements (node_id, camera_id)"
    )


def downgrade() -> None:
    op.drop_index(
        "ix_camera_placements_catalog_node_camera",
        table_name="camera_placements",
    )
    op.drop_index("ix_cameras_catalog_state_id", table_name="cameras")
    op.drop_index("ix_cameras_catalog_public_id_trgm", table_name="cameras")
    op.drop_index("ix_cameras_catalog_name_trgm", table_name="cameras")
