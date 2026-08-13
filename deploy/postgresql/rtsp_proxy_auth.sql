\set ON_ERROR_STOP on

DO $role$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'rtsp_proxy_auth') THEN
        CREATE ROLE rtsp_proxy_auth LOGIN
            NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION;
    END IF;
END
$role$;

ALTER ROLE rtsp_proxy_auth
    NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
ALTER ROLE rtsp_proxy_auth RESET ALL;

DO $memberships$
DECLARE
    granted_role record;
BEGIN
    FOR granted_role IN
        SELECT parent.rolname
        FROM pg_auth_members membership
        JOIN pg_roles parent ON parent.oid = membership.roleid
        JOIN pg_roles member ON member.oid = membership.member
        WHERE member.rolname = 'rtsp_proxy_auth'
    LOOP
        EXECUTE format('REVOKE %I FROM rtsp_proxy_auth', granted_role.rolname);
    END LOOP;
END
$memberships$;

REVOKE ALL ON DATABASE :"DBNAME" FROM rtsp_proxy_auth;
GRANT CONNECT ON DATABASE :"DBNAME" TO rtsp_proxy_auth;
REVOKE ALL ON SCHEMA public FROM rtsp_proxy_auth;
GRANT USAGE ON SCHEMA public TO rtsp_proxy_auth;

REVOKE ALL ON ALL TABLES IN SCHEMA public FROM rtsp_proxy_auth;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM rtsp_proxy_auth;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM rtsp_proxy_auth;
GRANT SELECT (version_num) ON alembic_version TO rtsp_proxy_auth;
GRANT SELECT (id, state, maintenance) ON media_nodes TO rtsp_proxy_auth;
GRANT SELECT (id, state, public_id) ON cameras TO rtsp_proxy_auth;
GRANT SELECT (camera_id, node_id) ON camera_placements TO rtsp_proxy_auth;
GRANT SELECT (camera_id, internet_cidrs, local_cidrs, revision)
ON camera_access_policies TO rtsp_proxy_auth;
GRANT SELECT ON camera_access_grants TO rtsp_proxy_auth;
REVOKE ALL ON FUNCTION rtsp_proxy_auth_mark_grant_used(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION rtsp_proxy_auth_rehash_grant(uuid, text, text, bigint)
FROM PUBLIC;
GRANT EXECUTE ON FUNCTION rtsp_proxy_auth_mark_grant_used(uuid) TO rtsp_proxy_auth;
GRANT EXECUTE ON FUNCTION rtsp_proxy_auth_rehash_grant(uuid, text, text, bigint)
TO rtsp_proxy_auth;

ALTER DEFAULT PRIVILEGES IN SCHEMA public
    REVOKE ALL ON TABLES FROM rtsp_proxy_auth;
