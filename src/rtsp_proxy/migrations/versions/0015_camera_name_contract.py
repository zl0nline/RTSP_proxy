"""Reject legacy camera names that violate the bounded UI contract.

Revision ID: 0015_camera_name_contract
Revises: 0014_camera_catalog_projection
Create Date: 2026-08-14
"""

import unicodedata
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0015_camera_name_contract"
down_revision: str | None = "0014_camera_catalog_projection"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("SET LOCAL lock_timeout = '1s'")
    op.execute("SET LOCAL statement_timeout = '30s'")
    connection = op.get_bind()
    invalid_ids = tuple(
        str(row.id)
        for row in connection.execute(
            sa.text(
                "SELECT id, name FROM cameras "
                "WHERE state <> 'deleted' ORDER BY id"
            )
        )
        if not _valid_name(str(row.name))
    )
    if invalid_ids:
        bounded_ids = ",".join(invalid_ids[:20])
        raise RuntimeError(
            "camera_name_contract_preflight_failed:"
            f"count={len(invalid_ids)}:camera_ids={bounded_ids}"
        )
    op.create_check_constraint(
        "ck_cameras_name",
        "cameras",
        "state = 'deleted' OR ("
        "length(name) BETWEEN 1 AND 128 "
        "AND btrim(name) <> '' "
        "AND name !~ '[[:cntrl:]]')",
    )


def downgrade() -> None:
    op.drop_constraint("ck_cameras_name", "cameras", type_="check")


def _valid_name(value: str) -> bool:
    return bool(
        value
        and len(value) <= 128
        and not value.isspace()
        and not any(
            unicodedata.category(character).startswith("C") for character in value
        )
    )
