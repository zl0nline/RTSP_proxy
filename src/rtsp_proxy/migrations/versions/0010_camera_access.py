"""Add per-camera ACL policy and revocable downstream access grants.

Revision ID: 0010_camera_access
Revises: 0009_camera_move_safety
Create Date: 2026-08-13
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0010_camera_access"
down_revision: str | None = "0009_camera_move_safety"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "camera_access_policies",
        sa.Column(
            "camera_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("cameras.id", ondelete="RESTRICT"),
            primary_key=True,
        ),
        sa.Column(
            "internet_cidrs",
            postgresql.ARRAY(postgresql.CIDR()),
            nullable=False,
            server_default="{}",
        ),
        sa.Column(
            "local_cidrs",
            postgresql.ARRAY(postgresql.CIDR()),
            nullable=False,
            server_default="{}",
        ),
        sa.Column("revision", sa.BigInteger(), nullable=False, server_default="1"),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("clock_timestamp()"),
        ),
        sa.CheckConstraint("revision >= 1", name="ck_camera_access_policy_revision"),
        sa.CheckConstraint(
            "cardinality(internet_cidrs) <= 128 AND cardinality(local_cidrs) <= 128",
            name="ck_camera_access_policy_cidr_limit",
        ),
    )
    op.execute(
        sa.text(
            "INSERT INTO camera_access_policies (camera_id) "
            "SELECT id FROM cameras WHERE state <> 'deleted'"
        )
    )
    op.create_table(
        "camera_access_grants",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "camera_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("cameras.id", ondelete="RESTRICT"),
            nullable=False,
            index=True,
        ),
        sa.Column("username", sa.String(length=64), nullable=False, unique=True),
        sa.Column("token_verifier", sa.String(length=64), nullable=False),
        sa.Column("pepper_key_id", sa.String(length=64), nullable=False),
        sa.Column("not_before", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("created_by", sa.String(length=128), nullable=False),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revision", sa.BigInteger(), nullable=False, server_default="1"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("clock_timestamp()"),
        ),
        sa.CheckConstraint(
            "username ~ '^grant-[0-9a-f]{32}$'",
            name="ck_camera_access_grant_username",
        ),
        sa.CheckConstraint(
            "token_verifier ~ '^[0-9a-f]{64}$'",
            name="ck_camera_access_grant_verifier",
        ),
        sa.CheckConstraint("length(pepper_key_id) > 0", name="ck_camera_access_grant_pepper"),
        sa.CheckConstraint("not_before < expires_at", name="ck_camera_access_grant_window"),
        sa.CheckConstraint("revision >= 1", name="ck_camera_access_grant_revision"),
        sa.CheckConstraint(
            "kind IN ('temporary', 'service')",
            name="ck_camera_access_grant_kind",
        ),
        sa.CheckConstraint(
            "length(created_by) BETWEEN 1 AND 128",
            name="ck_camera_access_grant_creator",
        ),
    )
    op.execute(
        sa.text(
            r"""
            CREATE FUNCTION rtsp_proxy_auth_mark_grant_used(p_grant_id uuid)
            RETURNS boolean
            LANGUAGE plpgsql
            SECURITY DEFINER
            SET search_path = pg_catalog, public
            AS $function$
            DECLARE
                changed boolean;
            BEGIN
                UPDATE public.camera_access_grants
                SET last_used_at = GREATEST(
                    COALESCE(last_used_at, '-infinity'::timestamptz),
                    clock_timestamp()
                )
                WHERE id = p_grant_id AND revoked_at IS NULL;
                changed := FOUND;
                RETURN changed;
            END
            $function$;

            CREATE FUNCTION rtsp_proxy_auth_rehash_grant(
                p_grant_id uuid,
                p_token_verifier text,
                p_pepper_key_id text,
                p_expected_revision bigint
            )
            RETURNS boolean
            LANGUAGE plpgsql
            SECURITY DEFINER
            SET search_path = pg_catalog, public
            AS $function$
            DECLARE
                changed public.camera_access_grants%ROWTYPE;
                event_id uuid;
                event_payload jsonb;
            BEGIN
                IF p_token_verifier !~ '^[0-9a-f]{64}$'
                   OR length(p_pepper_key_id) NOT BETWEEN 1 AND 64
                   OR p_expected_revision < 1 THEN
                    RAISE EXCEPTION 'access_grant_rehash_invalid'
                        USING ERRCODE = '22023';
                END IF;
                PERFORM set_config('synchronous_commit', 'on', true);
                UPDATE public.camera_access_grants
                SET token_verifier = p_token_verifier,
                    pepper_key_id = p_pepper_key_id,
                    revision = p_expected_revision + 1
                WHERE id = p_grant_id
                  AND revision = p_expected_revision
                  AND revoked_at IS NULL
                  AND pepper_key_id <> p_pepper_key_id
                RETURNING * INTO changed;
                IF NOT FOUND THEN
                    RETURN false;
                END IF;
                event_id := gen_random_uuid();
                event_payload := jsonb_build_object(
                    'camera_id', changed.camera_id::text,
                    'username', changed.username,
                    'pepper_key_id', changed.pepper_key_id,
                    'not_before', changed.not_before,
                    'expires_at', changed.expires_at,
                    'revoked_at', changed.revoked_at,
                    'revision', changed.revision,
                    'kind', changed.kind,
                    'created_by', changed.created_by,
                    'last_used_at', changed.last_used_at
                );
                INSERT INTO public.audit_events (
                    id, aggregate_type, aggregate_id, event_type,
                    aggregate_revision, payload
                ) VALUES (
                    event_id, 'camera_access_grant', changed.id,
                    'camera.access_grant_rehashed', changed.revision, event_payload
                );
                INSERT INTO public.outbox_messages (
                    id, aggregate_type, aggregate_id, event_type,
                    aggregate_revision, payload
                ) VALUES (
                    event_id, 'camera_access_grant', changed.id,
                    'camera.access_grant_rehashed', changed.revision, event_payload
                );
                RETURN true;
            END
            $function$;

            REVOKE ALL ON FUNCTION rtsp_proxy_auth_mark_grant_used(uuid) FROM PUBLIC;
            REVOKE ALL ON FUNCTION rtsp_proxy_auth_rehash_grant(uuid, text, text, bigint)
                FROM PUBLIC;
            """
        )
    )


def downgrade() -> None:
    op.execute(
        "DROP FUNCTION IF EXISTS rtsp_proxy_auth_rehash_grant(uuid, text, text, bigint)"
    )
    op.execute("DROP FUNCTION IF EXISTS rtsp_proxy_auth_mark_grant_used(uuid)")
    op.drop_table("camera_access_grants")
    op.drop_table("camera_access_policies")
