"""Fence camera moves and bind their exact endpoints.

Revision ID: 0009_camera_move_safety
Revises: 0008_node_administration
Create Date: 2026-08-12
"""

from collections.abc import Sequence
from urllib.parse import urlsplit

import sqlalchemy as sa
from alembic import op

revision: str = "0009_camera_move_safety"
down_revision: str | None = "0008_node_administration"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    connection = op.get_bind()
    legacy_moves = connection.scalar(
        sa.text("SELECT count(*) FROM camera_move_sagas WHERE state <> 'complete'")
    )
    if legacy_moves:
        raise RuntimeError("legacy_nonterminal_camera_moves_require_manual_resolution")
    for source_url in connection.scalars(sa.text("SELECT source_url FROM cameras")):
        if not _valid_source_url(str(source_url)):
            raise RuntimeError("legacy_camera_source_url_invalid")
    legacy_nodes = connection.scalar(sa.text("SELECT count(*) FROM media_nodes"))
    if legacy_nodes:
        raise RuntimeError("phase_d_requires_empty_media_node_registry")

    op.alter_column("media_nodes", "release_id", server_default="0.1.0")
    op.create_check_constraint(
        "ck_cameras_source_url",
        "cameras",
        "octet_length(source_url) BETWEEN 1 AND 8192 "
        "AND lower(source_url) LIKE 'rtsp://%/%' "
        "AND length(split_part(source_url, '/', 3)) > 0 "
        "AND position('@' IN split_part(source_url, '/', 3)) = 0 "
        "AND position('?' IN source_url) = 0 "
        "AND position('#' IN source_url) = 0",
    )
    op.drop_index("uq_camera_move_active", table_name="camera_move_sagas")
    op.drop_constraint("ck_camera_move_state", "camera_move_sagas", type_="check")
    op.add_column(
        "camera_move_sagas",
        sa.Column(
            "confirmed_disconnect_readers",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
    )
    op.add_column("camera_move_sagas", sa.Column("source_port", sa.Integer(), nullable=True))
    op.add_column("camera_move_sagas", sa.Column("target_port", sa.Integer(), nullable=True))
    op.add_column(
        "camera_move_sagas",
        sa.Column("source_endpoint", sa.String(length=512), nullable=True),
    )
    op.add_column(
        "camera_move_sagas",
        sa.Column("target_endpoint", sa.String(length=512), nullable=True),
    )
    op.add_column(
        "camera_move_sagas",
        sa.Column("abort_reason", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "camera_move_sagas",
        sa.Column(
            "expires_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("clock_timestamp() + interval '5 minutes'"),
        ),
    )
    op.create_check_constraint(
        "ck_camera_move_confirmed_readers",
        "camera_move_sagas",
        "confirmed_disconnect_readers BETWEEN 0 AND 1",
    )
    op.create_check_constraint(
        "ck_camera_move_source_port",
        "camera_move_sagas",
        "source_port IS NULL OR source_port BETWEEN 1 AND 65535",
    )
    op.create_check_constraint(
        "ck_camera_move_target_port",
        "camera_move_sagas",
        "target_port IS NULL OR target_port BETWEEN 1 AND 65535",
    )
    op.create_check_constraint(
        "ck_camera_move_active_endpoint",
        "camera_move_sagas",
        "state IN ('complete', 'aborted') OR "
        "(source_port IS NOT NULL AND target_port IS NOT NULL "
        "AND source_endpoint IS NOT NULL AND target_endpoint IS NOT NULL)",
    )
    op.create_check_constraint(
        "ck_camera_move_state",
        "camera_move_sagas",
        "state IN ('prepare_target', 'activate_target', 'cleanup_source', "
        "'cleanup_target', 'complete', 'aborted')",
    )
    op.create_index(
        "uq_camera_move_active",
        "camera_move_sagas",
        ["camera_id"],
        unique=True,
        postgresql_where=sa.text("state NOT IN ('complete', 'aborted')"),
    )


def downgrade() -> None:
    op.drop_index("uq_camera_move_active", table_name="camera_move_sagas")
    op.drop_constraint("ck_camera_move_state", "camera_move_sagas", type_="check")
    op.drop_constraint("ck_camera_move_active_endpoint", "camera_move_sagas", type_="check")
    op.drop_constraint("ck_camera_move_target_port", "camera_move_sagas", type_="check")
    op.drop_constraint("ck_camera_move_source_port", "camera_move_sagas", type_="check")
    op.drop_constraint("ck_camera_move_confirmed_readers", "camera_move_sagas", type_="check")
    op.drop_constraint("ck_cameras_source_url", "cameras", type_="check")
    op.alter_column("media_nodes", "release_id", server_default="v1.20.0")
    op.execute(
        sa.text(
            "UPDATE camera_move_sagas SET state = CASE "
            "WHEN state = 'activate_target' THEN 'cleanup_source' "
            "WHEN state IN ('cleanup_target', 'aborted') THEN 'complete' "
            "ELSE state END"
        )
    )
    for column in (
        "expires_at",
        "abort_reason",
        "target_endpoint",
        "source_endpoint",
        "target_port",
        "source_port",
        "confirmed_disconnect_readers",
    ):
        op.drop_column("camera_move_sagas", column)
    op.create_check_constraint(
        "ck_camera_move_state",
        "camera_move_sagas",
        "state IN ('prepare_target', 'cleanup_source', 'complete')",
    )
    op.create_index(
        "uq_camera_move_active",
        "camera_move_sagas",
        ["camera_id"],
        unique=True,
        postgresql_where=sa.text("state <> 'complete'"),
    )


def _valid_source_url(value: str) -> bool:
    if len(value.encode("utf-8")) > 8192:
        return False
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        return False
    return bool(
        parsed.scheme.lower() == "rtsp"
        and parsed.hostname is not None
        and not parsed.fragment
        and parsed.path.startswith("/")
        and port != 0
        and parsed.username is None
        and parsed.password is None
        and not parsed.query
    )
