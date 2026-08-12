"""Persist per-node management endpoints and pinned media release identity.

Revision ID: 0005_node_runtime
Revises: 0004_management_freshness
Create Date: 2026-08-12
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0005_node_runtime"
down_revision: str | None = "0004_management_freshness"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("media_nodes", sa.Column("api_port", sa.Integer(), nullable=True))
    op.add_column("media_nodes", sa.Column("metrics_port", sa.Integer(), nullable=True))
    op.add_column(
        "media_nodes",
        sa.Column(
            "release_id",
            sa.String(length=128),
            nullable=False,
            server_default="v1.20.0",
        ),
    )
    op.add_column(
        "media_nodes",
        sa.Column(
            "creation_mode",
            sa.String(length=16),
            nullable=False,
            server_default="operator",
        ),
    )
    op.add_column(
        "media_nodes",
        sa.Column("runtime_observed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column("media_nodes", sa.Column("process_id", sa.Integer(), nullable=True))
    op.add_column(
        "media_nodes",
        sa.Column("process_start_ticks", sa.BigInteger(), nullable=True),
    )
    op.add_column(
        "media_nodes",
        sa.Column("process_boot_id", sa.Uuid(), nullable=True),
    )
    op.add_column(
        "media_nodes",
        sa.Column("observed_config_sha256", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "media_nodes",
        sa.Column("observed_release_id", sa.String(length=128), nullable=True),
    )
    op.add_column(
        "media_nodes",
        sa.Column(
            "mediamtx_binary_sha256",
            sa.String(length=64),
            nullable=False,
            server_default="0" * 64,
        ),
    )
    op.execute(
        """
        WITH ordered AS (
            SELECT id, row_number() OVER (ORDER BY id) AS position,
                   count(*) OVER () AS node_count
            FROM media_nodes
        ), candidates AS (
            SELECT port, row_number() OVER (ORDER BY priority, port) AS position
            FROM (
                SELECT port, 0 AS priority
                FROM generate_series(49152, 65535) AS port
                UNION ALL
                SELECT port, 1 AS priority
                FROM generate_series(1024, 49151) AS port
            ) AS candidate
            WHERE NOT EXISTS (
                SELECT 1 FROM media_nodes WHERE external_port = candidate.port
            )
        )
        UPDATE media_nodes AS node
        SET api_port = api.port,
            metrics_port = metrics.port
        FROM ordered
        JOIN candidates AS api ON api.position = ordered.position
        JOIN candidates AS metrics
          ON metrics.position = ordered.position + ordered.node_count
        WHERE node.id = ordered.id
        """
    )
    op.alter_column("media_nodes", "api_port", nullable=False)
    op.alter_column("media_nodes", "metrics_port", nullable=False)
    op.create_unique_constraint("uq_media_nodes_api_port", "media_nodes", ["api_port"])
    op.create_unique_constraint(
        "uq_media_nodes_metrics_port",
        "media_nodes",
        ["metrics_port"],
    )
    op.create_check_constraint(
        "ck_media_nodes_api_port",
        "media_nodes",
        "api_port BETWEEN 1 AND 65535",
    )
    op.create_check_constraint(
        "ck_media_nodes_metrics_port",
        "media_nodes",
        "metrics_port BETWEEN 1 AND 65535",
    )
    op.create_check_constraint(
        "ck_media_nodes_distinct_ports",
        "media_nodes",
        "external_port <> api_port AND external_port <> metrics_port "
        "AND api_port <> metrics_port",
    )
    op.create_check_constraint(
        "ck_media_nodes_binary_sha256",
        "media_nodes",
        "mediamtx_binary_sha256 ~ '^[0-9a-f]{64}$'",
    )
    op.create_check_constraint(
        "ck_media_nodes_creation_mode",
        "media_nodes",
        "creation_mode IN ('operator', 'automatic')",
    )
    op.create_check_constraint(
        "ck_media_nodes_process_id",
        "media_nodes",
        "process_id IS NULL OR process_id > 0",
    )
    op.create_check_constraint(
        "ck_media_nodes_process_start_ticks",
        "media_nodes",
        "process_start_ticks IS NULL OR process_start_ticks > 0",
    )
    op.create_check_constraint(
        "ck_media_nodes_observed_config_sha256",
        "media_nodes",
        "observed_config_sha256 IS NULL OR "
        "observed_config_sha256 ~ '^[0-9a-f]{64}$'",
    )


def downgrade() -> None:
    op.drop_constraint("ck_media_nodes_creation_mode", "media_nodes", type_="check")
    op.drop_constraint(
        "ck_media_nodes_observed_config_sha256",
        "media_nodes",
        type_="check",
    )
    op.drop_constraint(
        "ck_media_nodes_process_start_ticks",
        "media_nodes",
        type_="check",
    )
    op.drop_constraint("ck_media_nodes_process_id", "media_nodes", type_="check")
    op.drop_constraint("ck_media_nodes_binary_sha256", "media_nodes", type_="check")
    op.drop_constraint("ck_media_nodes_distinct_ports", "media_nodes", type_="check")
    op.drop_constraint("ck_media_nodes_metrics_port", "media_nodes", type_="check")
    op.drop_constraint("ck_media_nodes_api_port", "media_nodes", type_="check")
    op.drop_constraint("uq_media_nodes_metrics_port", "media_nodes", type_="unique")
    op.drop_constraint("uq_media_nodes_api_port", "media_nodes", type_="unique")
    op.drop_column("media_nodes", "mediamtx_binary_sha256")
    op.drop_column("media_nodes", "release_id")
    op.drop_column("media_nodes", "creation_mode")
    op.drop_column("media_nodes", "observed_release_id")
    op.drop_column("media_nodes", "observed_config_sha256")
    op.drop_column("media_nodes", "process_boot_id")
    op.drop_column("media_nodes", "process_start_ticks")
    op.drop_column("media_nodes", "process_id")
    op.drop_column("media_nodes", "runtime_observed_at")
    op.drop_column("media_nodes", "metrics_port")
    op.drop_column("media_nodes", "api_port")
