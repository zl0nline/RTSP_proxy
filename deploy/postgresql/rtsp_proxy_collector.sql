\set ON_ERROR_STOP on

DO $role$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'rtsp_proxy_collector') THEN
        CREATE ROLE rtsp_proxy_collector LOGIN
            NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION;
    END IF;
END
$role$;

ALTER ROLE rtsp_proxy_collector
    NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
ALTER ROLE rtsp_proxy_collector RESET ALL;

DO $memberships$
DECLARE
    granted_role record;
BEGIN
    FOR granted_role IN
        SELECT parent.rolname
        FROM pg_auth_members membership
        JOIN pg_roles parent ON parent.oid = membership.roleid
        JOIN pg_roles member ON member.oid = membership.member
        WHERE member.rolname = 'rtsp_proxy_collector'
    LOOP
        EXECUTE format('REVOKE %I FROM rtsp_proxy_collector', granted_role.rolname);
    END LOOP;
END
$memberships$;
REVOKE ALL ON DATABASE :"DBNAME" FROM rtsp_proxy_collector;
GRANT CONNECT ON DATABASE :"DBNAME" TO rtsp_proxy_collector;
REVOKE ALL ON SCHEMA public FROM rtsp_proxy_collector;
GRANT USAGE ON SCHEMA public TO rtsp_proxy_collector;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM rtsp_proxy_collector;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM rtsp_proxy_collector;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM rtsp_proxy_collector;

GRANT SELECT (version_num) ON alembic_version TO rtsp_proxy_collector;
GRANT SELECT ON media_nodes TO rtsp_proxy_collector;
GRANT EXECUTE ON FUNCTION rtsp_proxy_collector_ready() TO rtsp_proxy_collector;
GRANT EXECUTE ON FUNCTION rtsp_proxy_collector_observe(
    uuid, boolean, boolean, timestamptz, uuid, uuid
) TO rtsp_proxy_collector;
GRANT EXECUTE ON FUNCTION rtsp_proxy_collector_save_snapshot(timestamptz, jsonb)
TO rtsp_proxy_collector;

ALTER DEFAULT PRIVILEGES IN SCHEMA public
    REVOKE ALL ON TABLES FROM rtsp_proxy_collector;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    REVOKE ALL ON SEQUENCES FROM rtsp_proxy_collector;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    REVOKE ALL ON FUNCTIONS FROM rtsp_proxy_collector;
