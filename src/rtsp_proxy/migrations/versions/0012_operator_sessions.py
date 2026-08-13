"""Add operator identities and revocable server-side sessions.

Revision ID: 0012_operator_sessions
Revises: 0011_observability
Create Date: 2026-08-13
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0012_operator_sessions"
down_revision: str | None = "0011_observability"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "operator_accounts",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("identity_source", sa.String(length=16), nullable=False),
        sa.Column("subject", sa.String(length=512), nullable=False),
        sa.Column("display_name", sa.String(length=256), nullable=False),
        sa.Column(
            "roles",
            postgresql.ARRAY(sa.String(length=32)),
            nullable=False,
        ),
        sa.Column(
            "scopes",
            postgresql.ARRAY(sa.String(length=256)),
            nullable=False,
        ),
        sa.Column("authz_version", sa.BigInteger(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("clock_timestamp()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("clock_timestamp()"),
        ),
        sa.UniqueConstraint(
            "identity_source",
            "subject",
            name="uq_operator_account_identity",
        ),
        sa.CheckConstraint(
            "identity_source IN ('oidc', 'break_glass')",
            name="ck_operator_account_identity_source",
        ),
        sa.CheckConstraint(
            "length(subject) BETWEEN 1 AND 512 AND "
            "length(display_name) BETWEEN 1 AND 256",
            name="ck_operator_account_names",
        ),
        sa.CheckConstraint(
            "cardinality(roles) BETWEEN 1 AND 5 AND "
            "roles <@ ARRAY['viewer','operator','admin','auditor','break_glass']::varchar[]",
            name="ck_operator_account_roles",
        ),
        sa.CheckConstraint(
            "(identity_source = 'break_glass' AND "
            "roles = ARRAY['break_glass']::varchar[]) OR "
            "(identity_source = 'oidc' AND "
            "NOT roles @> ARRAY['break_glass']::varchar[])",
            name="ck_operator_account_source_roles",
        ),
        sa.CheckConstraint(
            r"cardinality(scopes) BETWEEN 1 AND 128 AND "
            r"array_to_string(scopes, ',') ~ "
            r"'^(server:\*|(group|camera):[A-Za-z0-9][A-Za-z0-9._-]{0,127})"
            r"(,(server:\*|(group|camera):[A-Za-z0-9][A-Za-z0-9._-]{0,127}))*$'",
            name="ck_operator_account_scopes",
        ),
        sa.CheckConstraint(
            "authz_version >= 1",
            name="ck_operator_account_authz_version",
        ),
    )
    op.create_table(
        "operator_sessions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "account_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("operator_accounts.id", ondelete="RESTRICT"),
            nullable=False,
            index=True,
        ),
        sa.Column("token_sha256", sa.String(length=64), nullable=False, unique=True),
        sa.Column("csrf_sha256", sa.String(length=64), nullable=False),
        sa.Column("authz_version", sa.BigInteger(), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("idle_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("absolute_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("mfa_verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "token_sha256 ~ '^[0-9a-f]{64}$' AND csrf_sha256 ~ '^[0-9a-f]{64}$'",
            name="ck_operator_session_digests",
        ),
        sa.CheckConstraint(
            "authz_version >= 1",
            name="ck_operator_session_authz_version",
        ),
        sa.CheckConstraint(
            "last_seen_at >= issued_at AND idle_expires_at > issued_at "
            "AND absolute_expires_at > issued_at "
            "AND idle_expires_at <= absolute_expires_at",
            name="ck_operator_session_timing",
        ),
    )
    op.create_index(
        "ix_operator_sessions_active_account",
        "operator_sessions",
        ["account_id", "absolute_expires_at"],
        postgresql_where=sa.text("revoked_at IS NULL"),
    )


def downgrade() -> None:
    op.drop_index("ix_operator_sessions_active_account", table_name="operator_sessions")
    op.drop_table("operator_sessions")
    op.drop_table("operator_accounts")
