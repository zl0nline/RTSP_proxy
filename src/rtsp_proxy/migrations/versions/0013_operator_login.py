"""Add durable one-time OIDC login flows and break-glass identity material.

Revision ID: 0013_operator_login
Revises: 0012_operator_sessions
Create Date: 2026-08-13
"""

import json
from collections.abc import Sequence
from uuid import uuid4

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0013_operator_login"
down_revision: str | None = "0012_operator_sessions"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    connection = op.get_bind()
    connection.execute(sa.text("SET LOCAL synchronous_commit = on"))
    disabled_break_glass = connection.execute(
        sa.text(
            "UPDATE operator_accounts SET enabled = false, "
            "authz_version = authz_version + 1, updated_at = clock_timestamp() "
            "WHERE identity_source = 'break_glass' AND enabled "
            "RETURNING id, authz_version"
        )
    ).mappings().all()
    for account in disabled_break_glass:
        event_id = uuid4()
        payload = json.dumps(
            {
                "account_id": str(account["id"]),
                "action": "operator.break_glass_disable",
                "actor": "system:migration:0013",
                "after": {
                    "authz_version": int(account["authz_version"]),
                    "enabled": False,
                },
                "auth_method": "system_migration",
                "before": {
                    "authz_version": int(account["authz_version"]) - 1,
                    "enabled": True,
                },
                "object_type": "operator_account",
                "outcome": "completed",
                "reason": "credential material absent from schema 0012",
            },
            separators=(",", ":"),
            sort_keys=True,
        )
        parameters = {
            "id": event_id,
            "aggregate_id": account["id"],
            "aggregate_revision": account["authz_version"],
            "payload": payload,
        }
        for table in ("audit_events", "outbox_messages"):
            connection.execute(
                sa.text(
                    f"INSERT INTO {table} "
                    "(id, aggregate_type, aggregate_id, event_type, "
                    "aggregate_revision, payload) VALUES "
                    "(:id, 'operator_account', :aggregate_id, "
                    "'operator.break_glass_disabled_for_migration', "
                    ":aggregate_revision, CAST(:payload AS jsonb))"
                ),
                parameters,
            )
    connection.execute(
        sa.text(
            "UPDATE operator_sessions SET revoked_at = clock_timestamp() "
            "WHERE revoked_at IS NULL AND account_id IN "
            "(SELECT id FROM operator_accounts WHERE identity_source = 'break_glass')"
        )
    )
    op.create_table(
        "oidc_login_flows",
        sa.Column("state_sha256", sa.String(length=64), primary_key=True),
        sa.Column("browser_sha256", sa.String(length=64), nullable=False),
        sa.Column("source_ip_sha256", sa.String(length=64), nullable=False),
        sa.Column("return_to", sa.String(length=2048), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "state_sha256 ~ '^[0-9a-f]{64}$' AND "
            "browser_sha256 ~ '^[0-9a-f]{64}$' AND "
            "source_ip_sha256 ~ '^[0-9a-f]{64}$'",
            name="ck_oidc_login_flow_digest",
        ),
        sa.CheckConstraint(
            "return_to ~ '^/[^/]' OR return_to = '/'",
            name="ck_oidc_login_flow_return_to",
        ),
        sa.CheckConstraint(
            "expires_at > created_at AND expires_at <= created_at + interval '10 minutes' "
            "AND (consumed_at IS NULL OR consumed_at >= created_at)",
            name="ck_oidc_login_flow_timing",
        ),
    )
    op.create_index(
        "ix_oidc_login_flows_expiry",
        "oidc_login_flows",
        ["expires_at"],
    )
    op.create_table(
        "oidc_claim_contract_state",
        sa.Column("singleton", sa.Boolean(), primary_key=True),
        sa.Column("healthy", sa.Boolean(), nullable=False),
        sa.Column(
            "last_checked_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("clock_timestamp()"),
        ),
        sa.Column(
            "last_changed_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("clock_timestamp()"),
        ),
        sa.CheckConstraint("singleton", name="ck_oidc_claim_contract_singleton"),
    )
    op.create_table(
        "operator_login_attempts",
        sa.Column("key_sha256", sa.String(length=64), primary_key=True),
        sa.Column("failure_count", sa.Integer(), nullable=False),
        sa.Column("first_attempt_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_attempt_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "key_sha256 ~ '^[0-9a-f]{64}$'",
            name="ck_operator_login_attempt_digest",
        ),
        sa.CheckConstraint(
            "failure_count BETWEEN 1 AND 1000000 AND "
            "last_attempt_at >= first_attempt_at AND "
            "(locked_until IS NULL OR locked_until > last_attempt_at)",
            name="ck_operator_login_attempt_state",
        ),
    )
    op.create_table(
        "operator_login_audit",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("auth_method", sa.String(length=32), nullable=False),
        sa.Column("outcome", sa.String(length=16), nullable=False),
        sa.Column("reason_code", sa.String(length=64), nullable=False),
        sa.Column("source_ip_sha256", sa.String(length=64), nullable=False),
        sa.Column(
            "occurred_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("clock_timestamp()"),
        ),
        sa.CheckConstraint(
            "auth_method = 'oidc_code_pkce' AND outcome = 'rejected' AND "
            "reason_code = 'operator_login_failed' AND "
            "source_ip_sha256 ~ '^[0-9a-f]{64}$'",
            name="ck_operator_login_audit_event",
        ),
    )
    op.execute(
        sa.text(
            "CREATE TRIGGER operator_login_audit_append_only "
            "BEFORE UPDATE OR DELETE ON operator_login_audit FOR EACH ROW "
            "EXECUTE FUNCTION rtsp_proxy_reject_append_only_mutation()"
        )
    )
    op.add_column(
        "operator_accounts",
        sa.Column("break_glass_password_scrypt", sa.LargeBinary(), nullable=True),
    )
    op.add_column(
        "operator_accounts",
        sa.Column("break_glass_totp_secret", postgresql.BYTEA(), nullable=True),
    )
    op.add_column(
        "operator_accounts",
        sa.Column("break_glass_last_totp_step", sa.BigInteger(), nullable=True),
    )
    op.create_check_constraint(
        "ck_operator_account_break_glass_material",
        "operator_accounts",
        "(identity_source = 'break_glass' AND "
        "((enabled AND break_glass_password_scrypt IS NOT NULL "
        "AND break_glass_totp_secret IS NOT NULL) OR "
        "(NOT enabled AND break_glass_password_scrypt IS NULL "
        "AND break_glass_totp_secret IS NULL))) "
        "OR (identity_source = 'oidc' AND break_glass_password_scrypt IS NULL "
        "AND break_glass_totp_secret IS NULL AND break_glass_last_totp_step IS NULL)",
    )
    op.create_check_constraint(
        "ck_operator_account_break_glass_totp_step",
        "operator_accounts",
        "break_glass_last_totp_step IS NULL OR break_glass_last_totp_step >= 0",
    )
    op.create_index(
        "uq_operator_account_single_break_glass",
        "operator_accounts",
        ["identity_source"],
        unique=True,
        postgresql_where=sa.text("identity_source = 'break_glass'"),
    )
    op.create_table(
        "operator_security_alerts",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "account_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("operator_accounts.id", ondelete="RESTRICT"),
            nullable=False,
            index=True,
        ),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("outcome", sa.String(length=16), nullable=False),
        sa.Column("reason_code", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("available_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("clock_timestamp()"),
        ),
        sa.Column("claimed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("claim_token", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("sent_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error_code", sa.String(length=64), nullable=True),
        sa.CheckConstraint(
            "(event_type = 'operator.break_glass_login' AND "
            "outcome IN ('accepted','rejected') AND "
            "reason_code IN ('authenticated','invalid_credentials','rate_limited')) OR "
            "(event_type = 'operator.oidc_claim_contract' AND "
            "outcome IN ('failed','recovered') AND "
            "reason_code IN ('claim_contract_changed','claim_contract_restored'))",
            name="ck_operator_security_alert_kind",
        ),
        sa.CheckConstraint(
            "status IN ('pending','processing','sent','failed_final') AND "
            "attempts BETWEEN 0 AND 10",
            name="ck_operator_security_alert_delivery",
        ),
        sa.CheckConstraint(
            "(status = 'processing' AND claimed_at IS NOT NULL AND "
            "claim_token IS NOT NULL) OR "
            "(status <> 'processing' AND claimed_at IS NULL AND claim_token IS NULL)",
            name="ck_operator_security_alert_claim",
        ),
        sa.CheckConstraint(
            "(status = 'sent' AND sent_at IS NOT NULL) OR (status <> 'sent' AND sent_at IS NULL)",
            name="ck_operator_security_alert_sent",
        ),
    )
    op.create_index(
        "ix_operator_security_alert_due",
        "operator_security_alerts",
        ["status", "available_at"],
    )
    op.execute(
        sa.text(
            r"""
            CREATE FUNCTION rtsp_proxy_security_alert_ready()
            RETURNS boolean
            LANGUAGE plpgsql
            SECURITY DEFINER
            SET search_path = pg_catalog, public
            AS $function$
            BEGIN
                UPDATE public.operator_security_alerts
                SET available_at = available_at WHERE false;
                RETURN true;
            END
            $function$;

            CREATE FUNCTION rtsp_proxy_security_alert_claim(
                p_now timestamptz, p_expired timestamptz, p_claim_token uuid
            )
            RETURNS SETOF public.operator_security_alerts
            LANGUAGE plpgsql
            SECURITY DEFINER
            SET search_path = pg_catalog, public
            AS $function$
            BEGIN
                PERFORM set_config('synchronous_commit', 'on', true);
                UPDATE public.operator_security_alerts
                SET status = 'failed_final', claimed_at = NULL, claim_token = NULL,
                    last_error_code = 'notification_delivery_ambiguous'
                WHERE status = 'processing' AND claimed_at <= p_expired;
                RETURN QUERY
                WITH candidate AS (
                    SELECT id FROM public.operator_security_alerts
                    WHERE status = 'pending' AND available_at <= p_now
                    ORDER BY available_at, id
                    FOR UPDATE SKIP LOCKED LIMIT 1
                )
                UPDATE public.operator_security_alerts AS alert
                SET status = 'processing', attempts = alert.attempts + 1,
                    claimed_at = p_now, claim_token = p_claim_token
                FROM candidate WHERE alert.id = candidate.id RETURNING alert.*;
            END
            $function$;

            CREATE FUNCTION rtsp_proxy_security_alert_complete(
                p_id uuid, p_claim_token uuid, p_succeeded boolean,
                p_completed_at timestamptz, p_max_attempts integer,
                p_retry_delay interval, p_delivery_ambiguous boolean
            )
            RETURNS SETOF public.operator_security_alerts
            LANGUAGE plpgsql
            SECURITY DEFINER
            SET search_path = pg_catalog, public
            AS $function$
            BEGIN
                IF p_max_attempts NOT BETWEEN 1 AND 10 OR p_retry_delay <= interval '0'
                THEN
                    RAISE EXCEPTION 'notification_completion_invalid'
                        USING ERRCODE = '22023';
                END IF;
                PERFORM set_config('synchronous_commit', 'on', true);
                RETURN QUERY
                UPDATE public.operator_security_alerts AS alert SET
                    status = CASE WHEN p_succeeded THEN 'sent'
                        WHEN p_delivery_ambiguous OR alert.attempts >= p_max_attempts
                        THEN 'failed_final' ELSE 'pending' END,
                    available_at = CASE WHEN p_succeeded OR p_delivery_ambiguous
                        OR alert.attempts >= p_max_attempts THEN p_completed_at
                        ELSE p_completed_at + p_retry_delay END,
                    claimed_at = NULL, claim_token = NULL,
                    sent_at = CASE WHEN p_succeeded THEN p_completed_at ELSE NULL END,
                    last_error_code = CASE WHEN p_succeeded THEN NULL
                        WHEN p_delivery_ambiguous
                        THEN 'notification_delivery_ambiguous'
                        ELSE 'notification_transport_failed' END
                WHERE alert.id = p_id AND alert.status = 'processing'
                    AND alert.claim_token = p_claim_token RETURNING alert.*;
            END
            $function$;

            REVOKE ALL ON FUNCTION rtsp_proxy_security_alert_ready() FROM PUBLIC;
            REVOKE ALL ON FUNCTION rtsp_proxy_security_alert_claim(
                timestamptz, timestamptz, uuid
            ) FROM PUBLIC;
            REVOKE ALL ON FUNCTION rtsp_proxy_security_alert_complete(
                uuid, uuid, boolean, timestamptz, integer, interval, boolean
            ) FROM PUBLIC;
            """
        )
    )


def downgrade() -> None:
    op.execute(
        sa.text(
            "DROP FUNCTION rtsp_proxy_security_alert_complete("
            "uuid,uuid,boolean,timestamptz,integer,interval,boolean); "
            "DROP FUNCTION rtsp_proxy_security_alert_claim(timestamptz,timestamptz,uuid); "
            "DROP FUNCTION rtsp_proxy_security_alert_ready();"
        )
    )
    op.drop_index(
        "ix_operator_security_alert_due",
        table_name="operator_security_alerts",
    )
    op.drop_table("operator_security_alerts")
    op.drop_table("oidc_claim_contract_state")
    op.drop_index(
        "uq_operator_account_single_break_glass",
        table_name="operator_accounts",
    )
    op.drop_constraint(
        "ck_operator_account_break_glass_totp_step",
        "operator_accounts",
        type_="check",
    )
    op.drop_constraint(
        "ck_operator_account_break_glass_material",
        "operator_accounts",
        type_="check",
    )
    op.drop_column("operator_accounts", "break_glass_last_totp_step")
    op.drop_column("operator_accounts", "break_glass_totp_secret")
    op.drop_column("operator_accounts", "break_glass_password_scrypt")
    op.drop_table("operator_login_audit")
    op.drop_table("operator_login_attempts")
    op.drop_index("ix_oidc_login_flows_expiry", table_name="oidc_login_flows")
    op.drop_table("oidc_login_flows")
