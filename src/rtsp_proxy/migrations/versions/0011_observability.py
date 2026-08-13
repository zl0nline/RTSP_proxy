"""Add durable fleet snapshots and node notification incidents.

Revision ID: 0011_observability
Revises: 0010_camera_access
Create Date: 2026-08-13
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0011_observability"
down_revision: str | None = "0010_camera_access"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "notification_incidents",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "node_id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
            index=True,
        ),
        sa.Column("state", sa.String(length=16), nullable=False),
        sa.Column("opened_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("recovered_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "state IN ('open', 'recovered', 'closed')",
            name="ck_notification_incident_state",
        ),
        sa.CheckConstraint(
            "(state = 'open' AND recovered_at IS NULL AND closed_at IS NULL) OR "
            "(state = 'recovered' AND recovered_at IS NOT NULL AND closed_at IS NULL) OR "
            "(state = 'closed' AND recovered_at IS NOT NULL AND closed_at IS NOT NULL)",
            name="ck_notification_incident_lifecycle",
        ),
    )
    op.create_index(
        "uq_notification_incident_open_node",
        "notification_incidents",
        ["node_id"],
        unique=True,
        postgresql_where=sa.text("state = 'open'"),
    )
    op.create_table(
        "notification_messages",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "incident_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("notification_incidents.id", ondelete="RESTRICT"),
            nullable=False,
            index=True,
        ),
        sa.Column(
            "node_id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
            index=True,
        ),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("dedupe_key", sa.String(length=128), nullable=False, unique=True),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column(
            "available_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
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
            "kind IN ('failure', 'recovery')",
            name="ck_notification_message_kind",
        ),
        sa.CheckConstraint(
            "status IN ('pending', 'processing', 'sent', 'failed_final')",
            name="ck_notification_message_status",
        ),
        sa.CheckConstraint(
            "attempts BETWEEN 0 AND 10",
            name="ck_notification_message_attempts",
        ),
        sa.CheckConstraint(
            "(status = 'processing' AND claimed_at IS NOT NULL AND claim_token IS NOT NULL) "
            "OR (status <> 'processing' AND claimed_at IS NULL AND claim_token IS NULL)",
            name="ck_notification_message_claim",
        ),
        sa.CheckConstraint(
            "(status = 'sent' AND sent_at IS NOT NULL) OR "
            "(status <> 'sent' AND sent_at IS NULL)",
            name="ck_notification_message_sent",
        ),
        sa.UniqueConstraint(
            "incident_id",
            "kind",
            name="uq_notification_message_incident_kind",
        ),
    )
    op.create_index(
        "ix_notification_message_due",
        "notification_messages",
        ["status", "available_at"],
    )
    op.create_table(
        "fleet_snapshots",
        sa.Column("singleton", sa.Boolean(), primary_key=True),
        sa.Column("generated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("payload", postgresql.JSONB(), nullable=False),
        sa.CheckConstraint("singleton", name="ck_fleet_snapshot_singleton"),
    )
    op.execute(
        sa.text(
            r"""
            CREATE FUNCTION rtsp_proxy_notifier_ready()
            RETURNS boolean
            LANGUAGE plpgsql
            SECURITY DEFINER
            SET search_path = pg_catalog, public
            AS $function$
            BEGIN
                UPDATE public.notification_messages
                SET available_at = available_at WHERE false;
                UPDATE public.notification_incidents SET state = state WHERE false;
                RETURN true;
            END
            $function$;

            CREATE FUNCTION rtsp_proxy_notifier_claim(
                p_now timestamptz,
                p_expired timestamptz,
                p_claim_token uuid
            )
            RETURNS TABLE (
                id uuid, incident_id uuid, node_id uuid, kind varchar,
                dedupe_key varchar, status varchar, attempts integer,
                available_at timestamptz, last_error_code varchar,
                claim_token uuid, claimed_at timestamptz,
                failure_delivery_outcome varchar
            )
            LANGUAGE plpgsql
            SECURITY DEFINER
            SET search_path = pg_catalog, public
            AS $function$
            BEGIN
                PERFORM set_config('synchronous_commit', 'on', true);
                UPDATE public.notification_messages AS expired
                SET status = 'failed_final', claimed_at = NULL, claim_token = NULL,
                    last_error_code = 'notification_delivery_ambiguous'
                WHERE expired.status = 'processing' AND expired.claimed_at <= p_expired;
                UPDATE public.notification_incidents AS incident
                SET state = 'closed', closed_at = p_now
                WHERE incident.state = 'recovered'
                  AND 2 = (SELECT count(*) FROM public.notification_messages AS message
                           WHERE message.incident_id = incident.id)
                  AND NOT EXISTS (
                      SELECT 1 FROM public.notification_messages AS message
                      WHERE message.incident_id = incident.id
                        AND message.status NOT IN ('sent', 'failed_final')
                  );
                RETURN QUERY
                WITH candidate AS (
                    SELECT message.id FROM public.notification_messages AS message
                    WHERE message.status = 'pending' AND message.available_at <= p_now
                      AND (message.kind = 'failure' OR EXISTS (
                          SELECT 1 FROM public.notification_messages AS failure
                          WHERE failure.incident_id = message.incident_id
                            AND failure.kind = 'failure'
                            AND failure.status IN ('sent', 'failed_final')
                      ))
                    ORDER BY message.available_at, message.id
                    FOR UPDATE SKIP LOCKED LIMIT 1
                ), claimed AS (
                    UPDATE public.notification_messages AS message
                    SET status = 'processing', claimed_at = p_now,
                        claim_token = p_claim_token, attempts = message.attempts + 1
                    FROM candidate WHERE message.id = candidate.id
                    RETURNING message.*
                )
                SELECT claimed.id, claimed.incident_id, claimed.node_id, claimed.kind,
                       claimed.dedupe_key, claimed.status, claimed.attempts,
                       claimed.available_at, claimed.last_error_code,
                       claimed.claim_token, claimed.claimed_at,
                       (SELECT failure.status
                        FROM public.notification_messages AS failure
                        WHERE failure.incident_id = claimed.incident_id
                          AND failure.kind = 'failure')
                FROM claimed;
            END
            $function$;

            CREATE FUNCTION rtsp_proxy_notifier_complete(
                p_id uuid, p_claim_token uuid, p_succeeded boolean,
                p_completed_at timestamptz, p_max_attempts integer,
                p_retry_delay interval, p_delivery_ambiguous boolean
            )
            RETURNS TABLE (
                id uuid, incident_id uuid, node_id uuid, kind varchar,
                dedupe_key varchar, status varchar, attempts integer,
                available_at timestamptz, last_error_code varchar,
                claim_token uuid, claimed_at timestamptz,
                failure_delivery_outcome varchar
            )
            LANGUAGE plpgsql
            SECURITY DEFINER
            SET search_path = pg_catalog, public
            AS $function$
            DECLARE
                current_message public.notification_messages%ROWTYPE;
                next_status varchar;
                next_available timestamptz;
                next_error varchar;
            BEGIN
                IF p_max_attempts NOT BETWEEN 1 AND 10 OR p_retry_delay <= interval '0' THEN
                    RAISE EXCEPTION 'notification_completion_invalid' USING ERRCODE = '22023';
                END IF;
                PERFORM set_config('synchronous_commit', 'on', true);
                SELECT * INTO current_message FROM public.notification_messages AS message
                WHERE message.id = p_id FOR UPDATE;
                IF NOT FOUND OR current_message.status <> 'processing'
                   OR current_message.claim_token <> p_claim_token THEN
                    RETURN;
                END IF;
                next_status := CASE
                    WHEN p_succeeded THEN 'sent'
                    WHEN p_delivery_ambiguous OR current_message.attempts >= p_max_attempts
                        THEN 'failed_final'
                    ELSE 'pending'
                END;
                next_available := CASE
                    WHEN next_status IN ('sent', 'failed_final') THEN p_completed_at
                    ELSE p_completed_at + p_retry_delay
                END;
                next_error := CASE
                    WHEN p_succeeded THEN NULL
                    WHEN p_delivery_ambiguous THEN 'notification_delivery_ambiguous'
                    ELSE 'notification_transport_failed'
                END;
                RETURN QUERY
                WITH updated AS (
                    UPDATE public.notification_messages AS message
                    SET status = next_status, available_at = next_available,
                        claimed_at = NULL, claim_token = NULL,
                        sent_at = CASE WHEN p_succeeded THEN p_completed_at ELSE NULL END,
                        last_error_code = next_error
                    WHERE message.id = p_id
                    RETURNING message.*
                ), closed AS (
                    UPDATE public.notification_incidents AS incident
                    SET state = 'closed', closed_at = p_completed_at
                    WHERE incident.id = current_message.incident_id
                      AND incident.state = 'recovered'
                      AND 2 = (SELECT count(*) FROM public.notification_messages AS message
                               WHERE message.incident_id = incident.id)
                      AND NOT EXISTS (
                          SELECT 1 FROM public.notification_messages AS message
                          WHERE message.incident_id = incident.id
                            AND message.status NOT IN ('sent', 'failed_final')
                      )
                    RETURNING incident.id
                )
                SELECT updated.id, updated.incident_id, updated.node_id, updated.kind,
                       updated.dedupe_key, updated.status, updated.attempts,
                       updated.available_at, updated.last_error_code,
                       updated.claim_token, updated.claimed_at, NULL::varchar
                FROM updated LEFT JOIN closed ON true;
            END
            $function$;

            REVOKE ALL ON FUNCTION rtsp_proxy_notifier_ready() FROM PUBLIC;
            REVOKE ALL ON FUNCTION rtsp_proxy_notifier_claim(timestamptz, timestamptz, uuid)
                FROM PUBLIC;
            REVOKE ALL ON FUNCTION rtsp_proxy_notifier_complete(
                uuid, uuid, boolean, timestamptz, integer, interval, boolean
            ) FROM PUBLIC;

            CREATE FUNCTION rtsp_proxy_collector_ready()
            RETURNS boolean
            LANGUAGE plpgsql
            SECURITY DEFINER
            SET search_path = pg_catalog, public
            AS $function$
            BEGIN
                UPDATE public.notification_incidents SET state = state WHERE false;
                UPDATE public.fleet_snapshots SET generated_at = generated_at WHERE false;
                RETURN true;
            END
            $function$;

            CREATE FUNCTION rtsp_proxy_collector_observe(
                p_node_id uuid, p_failed boolean, p_recovered boolean,
                p_observed_at timestamptz, p_incident_id uuid, p_message_id uuid
            )
            RETURNS TABLE (
                id uuid, node_id uuid, state varchar,
                opened_at timestamptz, recovered_at timestamptz, closed_at timestamptz
            )
            LANGUAGE plpgsql
            SECURITY DEFINER
            SET search_path = pg_catalog, public
            AS $function$
            DECLARE
                latest public.notification_incidents%ROWTYPE;
            BEGIN
                IF p_failed AND p_recovered THEN
                    RAISE EXCEPTION 'incident_observation_invalid' USING ERRCODE = '22023';
                END IF;
                PERFORM set_config('synchronous_commit', 'on', true);
                PERFORM pg_advisory_xact_lock(
                    hashtextextended(p_node_id::text, 711994)
                );
                IF NOT EXISTS (SELECT 1 FROM public.media_nodes WHERE media_nodes.id = p_node_id)
                THEN
                    RAISE EXCEPTION 'incident_node_missing' USING ERRCODE = '23503';
                END IF;
                SELECT * INTO latest
                FROM public.notification_incidents AS incident
                WHERE incident.node_id = p_node_id
                ORDER BY incident.opened_at DESC, incident.id DESC LIMIT 1;
                IF p_failed AND (NOT FOUND OR latest.state <> 'open') THEN
                    INSERT INTO public.notification_incidents (
                        id, node_id, state, opened_at
                    ) VALUES (p_incident_id, p_node_id, 'open', p_observed_at)
                    RETURNING * INTO latest;
                    INSERT INTO public.notification_messages (
                        id, incident_id, node_id, kind, dedupe_key,
                        status, attempts, available_at
                    ) VALUES (
                        p_message_id, latest.id, latest.node_id, 'failure',
                        'node-incident:' || latest.id::text || ':' || 'failure',
                        'pending', 0, p_observed_at
                    );
                ELSIF p_recovered AND FOUND AND latest.state = 'open' THEN
                    UPDATE public.notification_incidents AS incident
                    SET state = 'recovered', recovered_at = p_observed_at
                    WHERE incident.id = latest.id
                    RETURNING * INTO latest;
                    INSERT INTO public.notification_messages (
                        id, incident_id, node_id, kind, dedupe_key,
                        status, attempts, available_at
                    ) VALUES (
                        p_message_id, latest.id, latest.node_id, 'recovery',
                        'node-incident:' || latest.id::text || ':' || 'recovery',
                        'pending', 0, p_observed_at
                    );
                END IF;
                IF latest.id IS NOT NULL THEN
                    RETURN QUERY SELECT latest.id, latest.node_id, latest.state,
                        latest.opened_at, latest.recovered_at, latest.closed_at;
                END IF;
            END
            $function$;

            CREATE FUNCTION rtsp_proxy_collector_save_snapshot(
                p_generated_at timestamptz, p_payload jsonb
            )
            RETURNS boolean
            LANGUAGE plpgsql
            SECURITY DEFINER
            SET search_path = pg_catalog, public
            AS $function$
            BEGIN
                IF jsonb_typeof(p_payload) <> 'object' THEN
                    RAISE EXCEPTION 'fleet_snapshot_invalid' USING ERRCODE = '22023';
                END IF;
                INSERT INTO public.fleet_snapshots (singleton, generated_at, payload)
                VALUES (true, p_generated_at, p_payload)
                ON CONFLICT (singleton) DO UPDATE
                SET generated_at = EXCLUDED.generated_at, payload = EXCLUDED.payload;
                RETURN true;
            END
            $function$;

            REVOKE ALL ON FUNCTION rtsp_proxy_collector_ready() FROM PUBLIC;
            REVOKE ALL ON FUNCTION rtsp_proxy_collector_observe(
                uuid, boolean, boolean, timestamptz, uuid, uuid
            ) FROM PUBLIC;
            REVOKE ALL ON FUNCTION rtsp_proxy_collector_save_snapshot(timestamptz, jsonb)
                FROM PUBLIC;
            """
        )
    )


def downgrade() -> None:
    op.execute(
        "DROP FUNCTION IF EXISTS rtsp_proxy_collector_save_snapshot(timestamptz, jsonb)"
    )
    op.execute(
        "DROP FUNCTION IF EXISTS rtsp_proxy_collector_observe("
        "uuid, boolean, boolean, timestamptz, uuid, uuid)"
    )
    op.execute("DROP FUNCTION IF EXISTS rtsp_proxy_collector_ready()")
    op.execute(
        "DROP FUNCTION IF EXISTS rtsp_proxy_notifier_complete("
        "uuid, uuid, boolean, timestamptz, integer, interval, boolean)"
    )
    op.execute(
        "DROP FUNCTION IF EXISTS rtsp_proxy_notifier_claim(timestamptz, timestamptz, uuid)"
    )
    op.execute("DROP FUNCTION IF EXISTS rtsp_proxy_notifier_ready()")
    op.drop_table("fleet_snapshots")
    op.drop_index("ix_notification_message_due", table_name="notification_messages")
    op.drop_table("notification_messages")
    op.drop_index(
        "uq_notification_incident_open_node",
        table_name="notification_incidents",
    )
    op.drop_table("notification_incidents")
