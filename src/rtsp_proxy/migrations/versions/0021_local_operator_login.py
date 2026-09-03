"""Add built-in local operator credentials alongside optional OIDC.

Revision ID: 0021_local_operator_login
Revises: 0020_probe_observations
Create Date: 2026-09-03
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0021_local_operator_login"
down_revision: str | None = "0020_probe_observations"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.drop_constraint("ck_operator_account_identity_source", "operator_accounts", type_="check")
    op.drop_constraint("ck_operator_account_source_roles", "operator_accounts", type_="check")
    op.drop_constraint(
        "ck_operator_account_break_glass_material",
        "operator_accounts",
        type_="check",
    )
    op.create_check_constraint(
        "ck_operator_account_identity_source",
        "operator_accounts",
        "identity_source IN ('oidc', 'local', 'break_glass')",
    )
    op.create_check_constraint(
        "ck_operator_account_source_roles",
        "operator_accounts",
        "(identity_source = 'break_glass' AND roles = ARRAY['break_glass']::varchar[]) OR "
        "(identity_source IN ('oidc', 'local') AND "
        "NOT roles @> ARRAY['break_glass']::varchar[])",
    )
    op.create_check_constraint(
        "ck_operator_account_break_glass_material",
        "operator_accounts",
        "(identity_source = 'break_glass' AND "
        "((enabled AND break_glass_password_scrypt IS NOT NULL "
        "AND break_glass_totp_secret IS NOT NULL) OR "
        "(NOT enabled AND break_glass_password_scrypt IS NULL "
        "AND break_glass_totp_secret IS NULL))) OR "
        "(identity_source IN ('oidc', 'local') AND "
        "break_glass_password_scrypt IS NULL AND break_glass_totp_secret IS NULL "
        "AND break_glass_last_totp_step IS NULL)",
    )
    op.create_table(
        "operator_local_credentials",
        sa.Column(
            "account_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("operator_accounts.id", ondelete="RESTRICT"),
            primary_key=True,
        ),
        sa.Column("username", sa.String(length=256), nullable=False, unique=True),
        sa.Column("password_scrypt", sa.LargeBinary(), nullable=False),
        sa.Column("totp_secret", postgresql.BYTEA(), nullable=True),
        sa.Column("last_totp_step", sa.BigInteger(), nullable=True),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("clock_timestamp()"),
        ),
        sa.CheckConstraint(
            "length(username) BETWEEN 1 AND 256 AND username !~ '[[:space:]]'",
            name="ck_operator_local_username",
        ),
        sa.CheckConstraint(
            "octet_length(password_scrypt) = 80",
            name="ck_operator_local_password",
        ),
        sa.CheckConstraint(
            "(totp_secret IS NOT NULL) OR (last_totp_step IS NULL)",
            name="ck_operator_local_totp",
        ),
        sa.CheckConstraint(
            "last_totp_step IS NULL OR last_totp_step >= 0",
            name="ck_operator_local_totp_step",
        ),
    )
    op.drop_constraint("ck_operator_login_audit_event", "operator_login_audit", type_="check")
    op.create_check_constraint(
        "ck_operator_login_audit_event",
        "operator_login_audit",
        "((auth_method = 'oidc_code_pkce' AND outcome = 'rejected') OR "
        "(auth_method = 'local_password' AND outcome IN ('accepted', 'rejected'))) AND "
        "reason_code IN ('operator_login_failed', 'authenticated', 'rate_limited') AND "
        "source_ip_sha256 ~ '^[0-9a-f]{64}$'",
    )


def downgrade() -> None:
    connection = op.get_bind()
    has_local_accounts = connection.scalar(
        sa.text("SELECT EXISTS (SELECT 1 FROM operator_accounts WHERE identity_source='local')")
    )
    if has_local_accounts:
        raise RuntimeError("local_operator_accounts_must_be_removed_before_downgrade")
    op.drop_constraint("ck_operator_login_audit_event", "operator_login_audit", type_="check")
    op.create_check_constraint(
        "ck_operator_login_audit_event",
        "operator_login_audit",
        "auth_method = 'oidc_code_pkce' AND outcome = 'rejected' AND "
        "reason_code = 'operator_login_failed' AND "
        "source_ip_sha256 ~ '^[0-9a-f]{64}$'",
    )
    op.drop_table("operator_local_credentials")
    op.drop_constraint(
        "ck_operator_account_break_glass_material",
        "operator_accounts",
        type_="check",
    )
    op.drop_constraint("ck_operator_account_source_roles", "operator_accounts", type_="check")
    op.drop_constraint("ck_operator_account_identity_source", "operator_accounts", type_="check")
    op.create_check_constraint(
        "ck_operator_account_identity_source",
        "operator_accounts",
        "identity_source IN ('oidc', 'break_glass')",
    )
    op.create_check_constraint(
        "ck_operator_account_source_roles",
        "operator_accounts",
        "(identity_source = 'break_glass' AND roles = ARRAY['break_glass']::varchar[]) OR "
        "(identity_source = 'oidc' AND NOT roles @> ARRAY['break_glass']::varchar[])",
    )
    op.create_check_constraint(
        "ck_operator_account_break_glass_material",
        "operator_accounts",
        "(identity_source = 'break_glass' AND "
        "((enabled AND break_glass_password_scrypt IS NOT NULL "
        "AND break_glass_totp_secret IS NOT NULL) OR "
        "(NOT enabled AND break_glass_password_scrypt IS NULL "
        "AND break_glass_totp_secret IS NULL))) OR "
        "(identity_source = 'oidc' AND break_glass_password_scrypt IS NULL "
        "AND break_glass_totp_secret IS NULL AND break_glass_last_totp_step IS NULL)",
    )
