from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import stat
import subprocess
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import psycopg
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_REVISION = re.compile(r"^[0-9]{4}_[a-z0-9_]+$")
_RESTORE_DATABASE_PREFIX = "rtsp_proxy_restore_verify_"
_COMMAND_TIMEOUT_SECONDS = 3600


class OperationsError(RuntimeError):
    """A production operation failed closed with a non-secret reason code."""


@dataclass(frozen=True, slots=True)
class DatabaseSnapshot:
    revision: str
    server_version: str
    table_counts: Mapping[str, int]
    invariants: Mapping[str, bool]

    def __post_init__(self) -> None:
        if (
            _REVISION.fullmatch(self.revision) is None
            or not self.server_version
            or not self.table_counts
            or any(
                not table
                or count < 0
                or table != table.strip()
                or not table.replace("_", "a").isalnum()
                for table, count in self.table_counts.items()
            )
            or not self.invariants
            or any(not name or result is not True for name, result in self.invariants.items())
        ):
            raise OperationsError("database_snapshot_invalid")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="rtsp-proxy-operations")
    parser.add_argument(
        "--database-url-env",
        default="RTSP_PROXY_OPERATIONS_DATABASE_URL",
        help="name of the environment variable containing the PostgreSQL URL",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    backup = commands.add_parser("backup-database")
    backup.add_argument("--output", required=True, type=Path)
    backup.add_argument("--release-manifest", required=True, type=Path)

    restore = commands.add_parser("verify-database-restore")
    restore.add_argument("--archive", required=True, type=Path)
    restore.add_argument("--manifest", required=True, type=Path)
    restore.add_argument("--report", required=True, type=Path)
    restore.add_argument("--release-manifest", required=True, type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        database_url = _database_url(arguments.database_url_env)
        if arguments.command == "backup-database":
            manifest = backup_database(
                database_url=database_url,
                output=arguments.output,
                release_manifest=arguments.release_manifest,
            )
            print(
                "BACKUP_VERIFIED "
                f"archive={arguments.output} "
                f"sha256={manifest['archive']['sha256']} "
                f"schema={manifest['database']['revision']}"
            )
            return 0
        if arguments.command == "verify-database-restore":
            report = verify_database_restore(
                database_url=database_url,
                archive=arguments.archive,
                backup_manifest=arguments.manifest,
                report=arguments.report,
                release_manifest=arguments.release_manifest,
            )
            print(
                "RESTORE_VERIFIED "
                f"report={arguments.report} "
                f"sha256={report['archive_sha256']} "
                f"schema={report['database']['revision']}"
            )
            return 0
        raise OperationsError("operations_command_invalid")
    except OperationsError as error:
        print(f"operation failed: {error}", file=sys.stderr)
        return 1


def backup_database(
    *,
    database_url: str,
    output: Path,
    release_manifest: Path,
) -> dict[str, Any]:
    output = _new_private_output(output, suffix=".dump")
    manifest_path = Path(f"{output}.manifest.json")
    _new_private_output(manifest_path, suffix=".manifest.json")
    release = _load_release_manifest(release_manifest)
    connection_string = _psycopg_connection_string(database_url)
    temporary = output.parent / f".{output.name}.partial-{secrets.token_hex(8)}"
    started_at = _utc_now()
    archive_created = False
    manifest_created = False
    try:
        with psycopg.connect(connection_string) as connection:
            connection.execute(
                "BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY"
            )
            snapshot_id = connection.execute("SELECT pg_export_snapshot()").fetchone()
            if snapshot_id is None or not isinstance(snapshot_id[0], str):
                raise OperationsError("database_snapshot_export_failed")
            snapshot = _inspect_database(connection)
            _require_release_schema(release, snapshot.revision)
            _run_postgres_tool(
                "pg_dump",
                (
                    "--format=custom",
                    "--no-owner",
                    "--no-privileges",
                    f"--snapshot={snapshot_id[0]}",
                    f"--file={temporary}",
                ),
                database_url=database_url,
            )
            connection.commit()
        _require_regular_file(temporary)
        temporary.chmod(0o600)
        _fsync_file(temporary)
        _run_postgres_tool(
            "pg_restore",
            ("--list", str(temporary)),
            database_url=None,
        )
        digest, size = _hash_file(temporary)
        _link_exclusive(temporary, output)
        archive_created = True
        payload: dict[str, Any] = {
            "schema_version": 1,
            "status": "verified",
            "started_at": started_at,
            "completed_at": _utc_now(),
            "release": release,
            "archive": {
                "filename": output.name,
                "sha256": digest,
                "size_bytes": size,
                "format": "postgresql-custom",
            },
            "database": _snapshot_payload(snapshot),
        }
        _write_json_exclusive(manifest_path, payload)
        manifest_created = True
        return payload
    except OperationsError:
        _unlink_if_owned(temporary)
        if archive_created:
            _unlink_if_owned(output)
        if manifest_created:
            _unlink_if_owned(manifest_path)
        raise
    except (OSError, psycopg.Error, subprocess.SubprocessError, ValueError):
        _unlink_if_owned(temporary)
        if archive_created:
            _unlink_if_owned(output)
        if manifest_created:
            _unlink_if_owned(manifest_path)
        raise OperationsError("database_backup_failed") from None
    finally:
        _unlink_if_owned(temporary)


def verify_database_restore(
    *,
    database_url: str,
    archive: Path,
    backup_manifest: Path,
    report: Path,
    release_manifest: Path,
) -> dict[str, Any]:
    archive = _private_input(archive)
    backup_manifest = _private_input(backup_manifest)
    report = _new_private_output(report, suffix=".json")
    release = _load_release_manifest(release_manifest)
    backup = _load_json_object(backup_manifest, "backup_manifest_invalid")
    _validate_backup_manifest(backup, archive=archive, release=release)
    database_name = f"{_RESTORE_DATABASE_PREFIX}{secrets.token_hex(8)}"
    started_at = _utc_now()
    created = False
    report_created = False
    try:
        _create_database(database_url, database_name)
        created = True
        restore_url = _replace_database(database_url, database_name)
        _run_postgres_tool(
            "pg_restore",
            (
                "--exit-on-error",
                "--no-owner",
                "--no-privileges",
                f"--dbname={database_name}",
                str(archive),
            ),
            database_url=restore_url,
        )
        with psycopg.connect(_psycopg_connection_string(restore_url)) as connection:
            snapshot = _inspect_database(connection)
        expected_database = backup.get("database")
        if (
            not isinstance(expected_database, dict)
            or _snapshot_payload(snapshot) != expected_database
        ):
            raise OperationsError("restored_database_mismatch")
        _require_release_schema(release, snapshot.revision)
        archive_digest, _ = _hash_file(archive)
        payload: dict[str, Any] = {
            "schema_version": 1,
            "status": "pass",
            "started_at": started_at,
            "completed_at": _utc_now(),
            "archive_sha256": archive_digest,
            "release": release,
            "database": _snapshot_payload(snapshot),
            "temporary_database_removed": True,
        }
        _drop_database(database_url, database_name)
        created = False
        _write_json_exclusive(report, payload)
        report_created = True
        return payload
    except OperationsError:
        if report_created:
            _unlink_if_owned(report)
        raise
    except (OSError, psycopg.Error, subprocess.SubprocessError, ValueError):
        if report_created:
            _unlink_if_owned(report)
        raise OperationsError("database_restore_verification_failed") from None
    finally:
        if created:
            try:
                _drop_database(database_url, database_name)
            except (OperationsError, psycopg.Error):
                raise OperationsError("temporary_restore_database_cleanup_failed") from None


def _database_url(environment_name: str) -> str:
    if (
        not environment_name
        or environment_name != environment_name.strip()
        or not environment_name.replace("_", "a").isalnum()
    ):
        raise OperationsError("database_url_environment_name_invalid")
    value = os.environ.get(environment_name)
    if not value:
        raise OperationsError("database_url_required")
    return value


def _new_private_output(path: Path, *, suffix: str) -> Path:
    if not path.is_absolute() or not path.name.endswith(suffix):
        raise OperationsError("operations_output_path_invalid")
    try:
        parent = path.parent.resolve(strict=True)
        metadata = parent.stat()
    except OSError:
        raise OperationsError("operations_output_parent_invalid") from None
    if parent != path.parent or not stat.S_ISDIR(metadata.st_mode):
        raise OperationsError("operations_output_parent_invalid")
    if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) & 0o077:
        raise OperationsError("operations_output_parent_not_private")
    if path.exists() or path.is_symlink():
        raise OperationsError("operations_output_exists")
    return path


def _private_input(path: Path) -> Path:
    if not path.is_absolute():
        raise OperationsError("operations_input_path_invalid")
    try:
        metadata = path.lstat()
    except OSError:
        raise OperationsError("operations_input_missing") from None
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise OperationsError("operations_input_not_private")
    return path


def _load_release_manifest(path: Path) -> dict[str, Any]:
    payload = _load_json_object(path, "release_manifest_invalid")
    release_id = payload.get("release_id")
    git_commit = payload.get("git_commit")
    mediamtx = payload.get("mediamtx")
    architecture = mediamtx.get("linux_arch") if isinstance(mediamtx, dict) else None
    compatibility = payload.get("schema_compatibility")
    if (
        not isinstance(release_id, str)
        or not release_id
        or not isinstance(git_commit, str)
        or re.fullmatch(r"[0-9a-f]{40}", git_commit) is None
        or git_commit == "0" * 40
        or architecture not in {"amd64", "arm64"}
        or not isinstance(compatibility, dict)
        or _REVISION.fullmatch(str(compatibility.get("minimum", ""))) is None
        or _REVISION.fullmatch(str(compatibility.get("maximum", ""))) is None
    ):
        raise OperationsError("release_manifest_invalid")
    digest, _ = _hash_file(path)
    return {
        "release_id": release_id,
        "git_commit": git_commit,
        "architecture": architecture,
        "manifest_sha256": digest,
        "schema_minimum": compatibility["minimum"],
        "schema_maximum": compatibility["maximum"],
    }


def _require_release_schema(release: Mapping[str, Any], revision: str) -> None:
    if revision != release.get("schema_maximum"):
        raise OperationsError("database_schema_not_release_head")


def _inspect_database(connection: psycopg.Connection[Any]) -> DatabaseSnapshot:
    connection.execute("SET LOCAL statement_timeout = '30s'")
    revision_rows = connection.execute(
        "SELECT version_num FROM public.alembic_version"
    ).fetchall()
    if len(revision_rows) != 1 or not isinstance(revision_rows[0][0], str):
        raise OperationsError("database_revision_invalid")
    table_rows = connection.execute(
        "SELECT tablename FROM pg_catalog.pg_tables "
        "WHERE schemaname = 'public' ORDER BY tablename"
    ).fetchall()
    table_names = tuple(str(row[0]) for row in table_rows)
    if "alembic_version" not in table_names:
        raise OperationsError("database_table_inventory_invalid")
    counts: dict[str, int] = {}
    for table_name in table_names:
        count = connection.execute(
            sql.SQL("SELECT count(*) FROM public.{}").format(sql.Identifier(table_name))
        ).fetchone()
        if count is None or not isinstance(count[0], int):
            raise OperationsError("database_table_inventory_invalid")
        counts[table_name] = count[0]
    invariants = _database_invariants(connection, frozenset(table_names))
    server_version = connection.execute("SHOW server_version").fetchone()
    if server_version is None or not isinstance(server_version[0], str):
        raise OperationsError("database_server_version_invalid")
    return DatabaseSnapshot(
        revision=revision_rows[0][0],
        server_version=server_version[0],
        table_counts=counts,
        invariants=invariants,
    )


def _database_invariants(
    connection: psycopg.Connection[Any], tables: frozenset[str]
) -> dict[str, bool]:
    required = {
        "media_nodes",
        "cameras",
        "camera_placements",
        "camera_placement_history",
        "camera_access_policies",
        "audit_events",
        "outbox_messages",
    }
    if not required.issubset(tables):
        raise OperationsError("database_required_table_missing")
    checks = {
        "one_current_placement_per_live_camera": """
            SELECT NOT EXISTS (
              SELECT c.id FROM public.cameras c
              LEFT JOIN public.camera_placements p ON p.camera_id = c.id
              WHERE c.state <> 'deleted'
              GROUP BY c.id HAVING count(p.camera_id) <> 1
            )
        """,
        "node_registered_counts_match_placements": """
            SELECT NOT EXISTS (
              SELECT n.id FROM public.media_nodes n
              LEFT JOIN public.camera_placements p ON p.node_id = n.id
              LEFT JOIN public.cameras c ON c.id = p.camera_id AND c.state <> 'deleted'
              GROUP BY n.id, n.registered_cameras
              HAVING n.registered_cameras <> count(c.id)
            )
        """,
        "access_policy_per_live_camera": """
            SELECT NOT EXISTS (
              SELECT c.id FROM public.cameras c
              LEFT JOIN public.camera_access_policies p ON p.camera_id = c.id
              WHERE c.state <> 'deleted'
              GROUP BY c.id HAVING count(p.camera_id) <> 1
            )
        """,
        "current_placement_present_in_history": """
            SELECT NOT EXISTS (
              SELECT p.camera_id FROM public.camera_placements p
              LEFT JOIN public.camera_placement_history h
                ON h.camera_id = p.camera_id
               AND h.node_id = p.node_id
               AND h.generation = p.generation
              WHERE h.camera_id IS NULL
            )
        """,
        "normative_event_ids_do_not_conflict": """
            SELECT NOT EXISTS (
              SELECT a.id FROM public.audit_events a
              JOIN public.outbox_messages o ON o.id = a.id
              WHERE a.aggregate_type <> o.aggregate_type
                 OR a.aggregate_id <> o.aggregate_id
                 OR a.event_type <> o.event_type
                 OR a.aggregate_revision <> o.aggregate_revision
                 OR a.payload <> o.payload
            )
        """,
    }
    results: dict[str, bool] = {}
    for name, statement in checks.items():
        row = connection.execute(statement).fetchone()
        if row is None or row[0] is not True:
            raise OperationsError(f"database_invariant_failed:{name}")
        results[name] = True
    return results


def _snapshot_payload(snapshot: DatabaseSnapshot) -> dict[str, Any]:
    return {
        "revision": snapshot.revision,
        "server_version": snapshot.server_version,
        "table_counts": dict(sorted(snapshot.table_counts.items())),
        "invariants": dict(sorted(snapshot.invariants.items())),
    }


def _validate_backup_manifest(
    payload: Mapping[str, Any], *, archive: Path, release: Mapping[str, Any]
) -> None:
    archive_payload = payload.get("archive")
    if (
        payload.get("schema_version") != 1
        or payload.get("status") != "verified"
        or payload.get("release") != release
        or not isinstance(archive_payload, dict)
        or archive_payload.get("filename") != archive.name
        or archive_payload.get("format") != "postgresql-custom"
        or not isinstance(archive_payload.get("size_bytes"), int)
        or not isinstance(archive_payload.get("sha256"), str)
        or _SHA256.fullmatch(archive_payload["sha256"]) is None
    ):
        raise OperationsError("backup_manifest_invalid")
    digest, size = _hash_file(archive)
    if digest != archive_payload["sha256"] or size != archive_payload["size_bytes"]:
        raise OperationsError("backup_archive_digest_mismatch")


def _load_json_object(path: Path, error_code: str) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise OperationsError(error_code) from None
    if not isinstance(payload, dict):
        raise OperationsError(error_code)
    return payload


def _run_postgres_tool(
    tool: str,
    arguments: Sequence[str],
    *,
    database_url: str | None,
) -> None:
    executable = _trusted_tool(tool)
    environment = _postgres_environment(database_url) if database_url is not None else {}
    try:
        subprocess.run(
            (str(executable), *arguments),
            check=True,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            env=environment,
            timeout=_COMMAND_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError):
        raise OperationsError(f"{tool}_failed") from None


def _trusted_tool(name: str) -> Path:
    configured = os.environ.get(f"RTSP_PROXY_{name.upper()}_BINARY")
    candidate = Path(configured) if configured else _which(name)
    if candidate is None or not candidate.is_absolute():
        raise OperationsError(f"{name}_unavailable")
    try:
        resolved = candidate.resolve(strict=True)
        metadata = resolved.stat()
    except OSError:
        raise OperationsError(f"{name}_unavailable") from None
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o022:
        raise OperationsError(f"{name}_unsafe")
    # Invoke through the validated absolute candidate rather than its resolved
    # target. Debian/Ubuntu PostgreSQL tools are safe symlinks to pg_wrapper,
    # which selects pg_dump versus pg_restore from argv[0]. Resolving the link
    # for execution silently changes that contract to `pg_wrapper`.
    return candidate


def _which(name: str) -> Path | None:
    from shutil import which

    result = which(name)
    return None if result is None else Path(result)


def _postgres_environment(database_url: str) -> dict[str, str]:
    fields = conninfo_to_dict(_psycopg_connection_string(database_url))
    mapping = {
        "host": "PGHOST",
        "hostaddr": "PGHOSTADDR",
        "port": "PGPORT",
        "dbname": "PGDATABASE",
        "user": "PGUSER",
        "password": "PGPASSWORD",
        "sslmode": "PGSSLMODE",
        "sslrootcert": "PGSSLROOTCERT",
        "sslcert": "PGSSLCERT",
        "sslkey": "PGSSLKEY",
    }
    environment = {
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
    }
    for key, variable in mapping.items():
        value = fields.get(key)
        if value is not None:
            environment[variable] = str(value)
    if "PGDATABASE" not in environment:
        raise OperationsError("database_name_required")
    return environment


def _psycopg_connection_string(database_url: str) -> str:
    if database_url.startswith("postgresql+psycopg://"):
        return database_url.replace("postgresql+psycopg://", "postgresql://", 1)
    if database_url.startswith(("postgresql://", "postgres://")):
        return database_url
    try:
        fields = conninfo_to_dict(database_url)
    except psycopg.ProgrammingError:
        raise OperationsError("database_url_invalid") from None
    if not fields.get("dbname"):
        raise OperationsError("database_url_invalid")
    return database_url


def _replace_database(database_url: str, database_name: str) -> str:
    fields: dict[str, Any] = dict(
        conninfo_to_dict(_psycopg_connection_string(database_url))
    )
    fields["dbname"] = database_name
    return psycopg.conninfo.make_conninfo("", **fields)


def _admin_url(database_url: str) -> str:
    return _replace_database(database_url, "postgres")


def _create_database(database_url: str, database_name: str) -> None:
    try:
        with psycopg.connect(_admin_url(database_url), autocommit=True) as connection:
            connection.execute(
                sql.SQL("CREATE DATABASE {} TEMPLATE template0").format(
                    sql.Identifier(database_name)
                )
            )
    except psycopg.Error:
        raise OperationsError("temporary_restore_database_create_failed") from None


def _drop_database(database_url: str, database_name: str) -> None:
    if not database_name.startswith(_RESTORE_DATABASE_PREFIX):
        raise OperationsError("temporary_restore_database_name_invalid")
    try:
        with psycopg.connect(_admin_url(database_url), autocommit=True) as connection:
            connection.execute(
                sql.SQL("DROP DATABASE {} WITH (FORCE)").format(sql.Identifier(database_name))
            )
    except psycopg.Error:
        raise OperationsError("temporary_restore_database_drop_failed") from None


def _write_json_exclusive(path: Path, payload: Mapping[str, Any]) -> None:
    body = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        raise OperationsError("operations_output_exists") from None
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(body)
            output.flush()
            os.fsync(output.fileno())
    except BaseException:
        _unlink_if_owned(path)
        raise
    _fsync_directory(path.parent)


def _link_exclusive(source: Path, destination: Path) -> None:
    try:
        os.link(source, destination, follow_symlinks=False)
    except FileExistsError:
        raise OperationsError("operations_output_exists") from None
    _fsync_directory(destination.parent)


def _require_regular_file(path: Path) -> None:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise OperationsError("database_archive_invalid")


def _hash_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    try:
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
                size += len(chunk)
    except OSError:
        raise OperationsError("operations_input_unreadable") from None
    return digest.hexdigest(), size


def _fsync_file(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _unlink_if_owned(path: Path) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return
    if stat.S_ISREG(metadata.st_mode) and metadata.st_uid == os.geteuid():
        path.unlink(missing_ok=True)


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


if __name__ == "__main__":  # pragma: no cover - console entrypoint
    raise SystemExit(main())
