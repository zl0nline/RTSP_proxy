\set ON_ERROR_STOP on

DO $role$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'rtsp_proxy_notifier') THEN
        CREATE ROLE rtsp_proxy_notifier LOGIN
            NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION;
    END IF;
END
$role$;

ALTER ROLE rtsp_proxy_notifier
    NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
ALTER ROLE rtsp_proxy_notifier RESET ALL;

DO $memberships$
DECLARE
    granted_role record;
BEGIN
    FOR granted_role IN
        SELECT parent.rolname
        FROM pg_auth_members membership
        JOIN pg_roles parent ON parent.oid = membership.roleid
        JOIN pg_roles member ON member.oid = membership.member
        WHERE member.rolname = 'rtsp_proxy_notifier'
    LOOP
        EXECUTE format('REVOKE %I FROM rtsp_proxy_notifier', granted_role.rolname);
    END LOOP;
END
$memberships$;
REVOKE ALL ON DATABASE :"DBNAME" FROM rtsp_proxy_notifier;
GRANT CONNECT ON DATABASE :"DBNAME" TO rtsp_proxy_notifier;
REVOKE ALL ON SCHEMA public FROM rtsp_proxy_notifier;
GRANT USAGE ON SCHEMA public TO rtsp_proxy_notifier;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM rtsp_proxy_notifier;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM rtsp_proxy_notifier;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM rtsp_proxy_notifier;

GRANT SELECT (version_num) ON alembic_version TO rtsp_proxy_notifier;
GRANT EXECUTE ON FUNCTION rtsp_proxy_notifier_ready() TO rtsp_proxy_notifier;
GRANT EXECUTE ON FUNCTION rtsp_proxy_notifier_claim(timestamptz, timestamptz, uuid)
TO rtsp_proxy_notifier;
GRANT EXECUTE ON FUNCTION rtsp_proxy_notifier_complete(
    uuid, uuid, boolean, timestamptz, integer, interval, boolean
) TO rtsp_proxy_notifier;
GRANT EXECUTE ON FUNCTION rtsp_proxy_security_alert_ready()
TO rtsp_proxy_notifier;
GRANT EXECUTE ON FUNCTION rtsp_proxy_security_alert_claim(
    timestamptz, timestamptz, uuid
) TO rtsp_proxy_notifier;
GRANT EXECUTE ON FUNCTION rtsp_proxy_security_alert_complete(
    uuid, uuid, boolean, timestamptz, integer, interval, boolean
) TO rtsp_proxy_notifier;

ALTER DEFAULT PRIVILEGES IN SCHEMA public
    REVOKE ALL ON TABLES FROM rtsp_proxy_notifier;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    REVOKE ALL ON SEQUENCES FROM rtsp_proxy_notifier;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    REVOKE ALL ON FUNCTIONS FROM rtsp_proxy_notifier;
