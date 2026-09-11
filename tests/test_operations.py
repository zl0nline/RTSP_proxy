from __future__ import annotations

import json
import os
from pathlib import Path
from uuid import uuid4

import psycopg
import pytest

from rtsp_proxy.migrate import upgrade_database
from rtsp_proxy.operations import (
    DatabaseSnapshot,
    OperationsError,
    _create_database,
    _database_invariants,
    _database_url,
    _drop_database,
    _hash_file,
    _link_exclusive,
    _load_json_object,
    _load_release_manifest,
    _new_private_output,
    _postgres_environment,
    _private_input,
    _psycopg_connection_string,
    _require_regular_file,
    _require_release_schema,
    _run_postgres_tool,
    _trusted_tool,
    _validate_backup_manifest,
    _write_json_exclusive,
    backup_database,
    main,
    verify_database_restore,
)


def _release_manifest(tmp_path: Path) -> Path:
    source = json.loads(
        Path("deploy/release-manifest.amd64.example.json").read_text(encoding="utf-8")
    )
    source["git_commit"] = "1" * 40
    destination = tmp_path / "release-manifest.json"
    destination.write_text(json.dumps(source), encoding="utf-8")
    destination.chmod(0o600)
    return destination


def _private_directory(tmp_path: Path) -> Path:
    destination = tmp_path / "backups"
    destination.mkdir(mode=0o700)
    destination.chmod(0o700)
    return destination


def _psycopg_url(database_url: str) -> str:
    return database_url.replace("postgresql+psycopg://", "postgresql://", 1)


def test_operations_output_requires_absolute_new_path_in_private_owned_directory(
    tmp_path: Path,
) -> None:
    private = _private_directory(tmp_path)
    output = private / "backup.dump"
    assert _new_private_output(output, suffix=".dump") == output

    output.touch()
    with pytest.raises(OperationsError, match="operations_output_exists"):
        _new_private_output(output, suffix=".dump")
    with pytest.raises(OperationsError, match="operations_output_path_invalid"):
        _new_private_output(Path("backup.dump"), suffix=".dump")

    public = tmp_path / "public"
    public.mkdir(mode=0o755)
    public.chmod(0o755)
    with pytest.raises(OperationsError, match="operations_output_parent_not_private"):
        _new_private_output(public / "backup.dump", suffix=".dump")


def test_postgres_environment_keeps_credentials_out_of_command_arguments() -> None:
    environment = _postgres_environment(
        "postgresql+psycopg://operator:sensitive@db.example:5433/rtsp_proxy?sslmode=require"
    )
    assert environment["PGHOST"] == "db.example"
    assert environment["PGPORT"] == "5433"
    assert environment["PGDATABASE"] == "rtsp_proxy"
    assert environment["PGUSER"] == "operator"
    assert environment["PGPASSWORD"] == "sensitive"
    assert environment["PGSSLMODE"] == "require"


def test_database_backup_and_isolated_restore_are_exact_and_remove_temporary_database(
    postgres_database_url: str,
    tmp_path: Path,
) -> None:
    upgrade_database(postgres_database_url)
    private = _private_directory(tmp_path)
    archive = private / "rtsp-proxy.dump"
    release = _release_manifest(private)

    backup = backup_database(
        database_url=postgres_database_url,
        output=archive,
        release_manifest=release,
    )
    manifest = Path(f"{archive}.manifest.json")
    assert backup["status"] == "verified"
    assert backup["database"]["revision"] == "0025_permanent_service_grants"
    assert backup["database"]["invariants"] == {
        "access_policy_per_live_camera": True,
        "current_placement_present_in_history": True,
        "node_registered_counts_match_placements": True,
        "normative_event_ids_do_not_conflict": True,
        "one_current_placement_per_live_camera": True,
    }
    assert archive.stat().st_mode & 0o777 == 0o600
    assert manifest.stat().st_mode & 0o777 == 0o600

    report = private / "restore-report.json"
    restored = verify_database_restore(
        database_url=postgres_database_url,
        archive=archive,
        backup_manifest=manifest,
        report=report,
        release_manifest=release,
    )
    assert restored["status"] == "pass"
    assert restored["temporary_database_removed"] is True
    assert restored["database"] == backup["database"]
    assert report.stat().st_mode & 0o777 == 0o600

    with psycopg.connect(_psycopg_url(postgres_database_url)) as connection:
        temporary = connection.execute(
            "SELECT datname FROM pg_database "
            "WHERE datname LIKE 'rtsp_proxy_restore_verify_%'"
        ).fetchall()
    assert temporary == []


def test_operations_cli_runs_verified_backup_and_restore_without_printing_dsn(
    postgres_database_url: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    upgrade_database(postgres_database_url)
    private = _private_directory(tmp_path)
    archive = private / "cli.dump"
    report = private / "cli-restore.json"
    release = _release_manifest(private)
    monkeypatch.setenv("SAFE_DATABASE_URL", postgres_database_url)

    assert (
        main(
            [
                "--database-url-env",
                "SAFE_DATABASE_URL",
                "backup-database",
                "--output",
                str(archive),
                "--release-manifest",
                str(release),
            ]
        )
        == 0
    )
    backup_output = capsys.readouterr()
    assert backup_output.err == ""
    assert backup_output.out.startswith(f"BACKUP_VERIFIED archive={archive} sha256=")
    assert postgres_database_url not in backup_output.out

    assert (
        main(
            [
                "--database-url-env",
                "SAFE_DATABASE_URL",
                "verify-database-restore",
                "--archive",
                str(archive),
                "--manifest",
                f"{archive}.manifest.json",
                "--report",
                str(report),
                "--release-manifest",
                str(release),
            ]
        )
        == 0
    )
    restore_output = capsys.readouterr()
    assert restore_output.err == ""
    assert restore_output.out.startswith(f"RESTORE_VERIFIED report={report} sha256=")
    assert postgres_database_url not in restore_output.out


def test_restore_rejects_archive_tampering_before_database_creation(
    postgres_database_url: str,
    tmp_path: Path,
) -> None:
    upgrade_database(postgres_database_url)
    private = _private_directory(tmp_path)
    archive = private / "rtsp-proxy.dump"
    release = _release_manifest(private)
    backup_database(
        database_url=postgres_database_url,
        output=archive,
        release_manifest=release,
    )
    archive.write_bytes(archive.read_bytes() + b"tamper")

    with pytest.raises(OperationsError, match="backup_archive_digest_mismatch"):
        verify_database_restore(
            database_url=postgres_database_url,
            archive=archive,
            backup_manifest=Path(f"{archive}.manifest.json"),
            report=private / "restore-report.json",
            release_manifest=release,
        )
    assert not (private / "restore-report.json").exists()


def test_operations_cli_reports_only_typed_failure_without_database_url(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    database_url = "postgresql://user:secret@example.invalid/rtsp_proxy"
    monkeypatch.setenv("RTSP_PROXY_OPERATIONS_DATABASE_URL", database_url)
    status = main(
        [
            "backup-database",
            "--output",
            str(tmp_path / "backup.dump"),
            "--release-manifest",
            str(tmp_path / "missing.json"),
        ]
    )
    output = capsys.readouterr()
    assert status == 1
    assert output.out == ""
    assert "secret" not in output.err
    assert "example.invalid" not in output.err


def test_backup_does_not_remove_a_racing_preexisting_output(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    private = _private_directory(tmp_path)
    archive = private / "backup.dump"
    release = _release_manifest(private)

    def race(*_args: object, **_kwargs: object) -> object:
        archive.write_text("owned-by-another-operation", encoding="utf-8")
        archive.chmod(0o600)
        raise OperationsError("operations_output_exists")

    monkeypatch.setattr("rtsp_proxy.operations.psycopg.connect", race)
    with pytest.raises(OperationsError, match="operations_output_exists"):
        backup_database(
            database_url="postgresql://postgres@localhost/rtsp_proxy",
            output=archive,
            release_manifest=release,
        )
    assert archive.read_text(encoding="utf-8") == "owned-by-another-operation"


def test_database_url_environment_name_is_not_shell_interpreted(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("SAFE", "postgresql://postgres@localhost/rtsp_proxy")
    status = main(
        [
            "--database-url-env",
            "SAFE;env",
            "backup-database",
            "--output",
            str(tmp_path / "backup.dump"),
            "--release-manifest",
            str(tmp_path / "release-manifest.json"),
        ]
    )
    assert status != 0
    assert "database_url_environment_name_invalid" in capsys.readouterr().err
    assert os.environ["SAFE"].endswith("/rtsp_proxy")


def test_operations_validation_rejects_unsafe_inputs_and_tooling(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    private = _private_directory(tmp_path)
    with pytest.raises(OperationsError, match="database_snapshot_invalid"):
        DatabaseSnapshot(
            revision="bad",
            server_version="16",
            table_counts={"table": 0},
            invariants={"ok": True},
        )
    with pytest.raises(OperationsError, match="operations_input_path_invalid"):
        _private_input(Path("relative.dump"))
    with pytest.raises(OperationsError, match="operations_input_missing"):
        _private_input(private / "missing.dump")

    public_input = private / "public.dump"
    public_input.write_bytes(b"archive")
    public_input.chmod(0o644)
    with pytest.raises(OperationsError, match="operations_input_not_private"):
        _private_input(public_input)

    invalid_release = private / "invalid-release.json"
    invalid_release.write_text(
        Path("deploy/release-manifest.amd64.example.json").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    invalid_release.chmod(0o600)
    with pytest.raises(OperationsError, match="release_manifest_invalid"):
        _load_release_manifest(invalid_release)

    with pytest.raises(OperationsError, match="database_url_invalid"):
        _psycopg_connection_string("not a postgres connection string")
    with pytest.raises(OperationsError, match="temporary_restore_database_name_invalid"):
        _drop_database("postgresql://postgres@localhost/postgres", "unexpected_name")

    unsafe_tool = private / "pg_dump"
    unsafe_tool.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    unsafe_tool.chmod(0o777)
    monkeypatch.setenv("RTSP_PROXY_PG_DUMP_BINARY", str(unsafe_tool))
    with pytest.raises(OperationsError, match="pg_dump_unsafe"):
        _trusted_tool("pg_dump")


def test_operations_filesystem_and_subprocess_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    private = _private_directory(tmp_path)
    existing = private / "existing.json"
    existing.write_text("owned", encoding="utf-8")
    existing.chmod(0o600)
    with pytest.raises(OperationsError, match="operations_output_exists"):
        _write_json_exclusive(existing, {"request_id": str(uuid4())})
    assert existing.read_text(encoding="utf-8") == "owned"

    archive = private / "archive.dump"
    archive.write_bytes(b"archive")
    archive.chmod(0o600)
    alias = private / "archive-alias.dump"
    os.link(archive, alias)
    with pytest.raises(OperationsError, match="database_archive_invalid"):
        _require_regular_file(archive)
    with pytest.raises(OperationsError, match="operations_input_unreadable"):
        _hash_file(private)

    monkeypatch.setattr("rtsp_proxy.operations._trusted_tool", lambda _name: Path("/usr/bin/false"))
    with pytest.raises(OperationsError, match="pg_restore_failed"):
        _run_postgres_tool("pg_restore", ("--version",), database_url=None)


def test_postgres_tool_preserves_safe_dispatch_symlink_name(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    dispatcher = tmp_path / "postgres-dispatcher"
    dispatcher.write_text(
        "#!/bin/sh\nprintf '%s' \"${0##*/}\" > \"$1\"\n",
        encoding="utf-8",
    )
    dispatcher.chmod(0o755)
    pg_dump = tmp_path / "pg_dump"
    pg_dump.symlink_to(dispatcher)
    observed = tmp_path / "invocation-name"
    monkeypatch.setenv("RTSP_PROXY_PG_DUMP_BINARY", str(pg_dump))

    _run_postgres_tool("pg_dump", (str(observed),), database_url=None)

    assert observed.read_text(encoding="utf-8") == "pg_dump"


def test_operations_rejects_missing_paths_database_and_manifest_metadata(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    private = _private_directory(tmp_path)
    monkeypatch.delenv("MISSING_DATABASE_URL", raising=False)
    with pytest.raises(OperationsError, match="database_url_required"):
        _database_url("MISSING_DATABASE_URL")
    with pytest.raises(OperationsError, match="operations_output_parent_invalid"):
        _new_private_output(tmp_path / "missing" / "backup.dump", suffix=".dump")

    alias = tmp_path / "backup-alias"
    alias.symlink_to(private, target_is_directory=True)
    with pytest.raises(OperationsError, match="operations_output_parent_invalid"):
        _new_private_output(alias / "backup.dump", suffix=".dump")

    json_list = private / "list.json"
    json_list.write_text("[]", encoding="utf-8")
    with pytest.raises(OperationsError, match="payload_invalid"):
        _load_json_object(json_list, "payload_invalid")
    with pytest.raises(OperationsError, match="database_schema_not_release_head"):
        _require_release_schema({"schema_maximum": "0024_camera_probe_profiles"}, "0023")
    with pytest.raises(OperationsError, match="database_required_table_missing"):
        _database_invariants(object(), frozenset())  # type: ignore[arg-type]

    archive = private / "archive.dump"
    archive.write_bytes(b"archive")
    archive.chmod(0o600)
    with pytest.raises(OperationsError, match="backup_manifest_invalid"):
        _validate_backup_manifest({}, archive=archive, release={})

    missing_tool = private / "missing-pg-dump"
    monkeypatch.setenv("RTSP_PROXY_PG_DUMP_BINARY", str(missing_tool))
    with pytest.raises(OperationsError, match="pg_dump_unavailable"):
        _trusted_tool("pg_dump")
    with pytest.raises(OperationsError, match="database_url_invalid"):
        _postgres_environment("host=localhost user=postgres")
    with pytest.raises(OperationsError, match="database_url_invalid"):
        _psycopg_connection_string("host=localhost user=postgres")

    destination = private / "destination.dump"
    destination.write_bytes(b"other")
    destination.chmod(0o600)
    with pytest.raises(OperationsError, match="operations_output_exists"):
        _link_exclusive(archive, destination)


def test_operations_normalizes_database_admin_and_snapshot_failures(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    private = _private_directory(tmp_path)
    release = _release_manifest(private)

    class MissingSnapshot:
        def __enter__(self) -> MissingSnapshot:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def execute(self, statement: str) -> MissingSnapshot:
            assert statement.startswith(("BEGIN TRANSACTION", "SELECT pg_export_snapshot"))
            return self

        def fetchone(self) -> None:
            return None

    monkeypatch.setattr("rtsp_proxy.operations.psycopg.connect", lambda *_args: MissingSnapshot())
    with pytest.raises(OperationsError, match="database_snapshot_export_failed"):
        backup_database(
            database_url="postgresql://postgres@localhost/rtsp_proxy",
            output=private / "snapshot-failed.dump",
            release_manifest=release,
        )
    assert not tuple(private.glob(".*.partial-*"))

    def unavailable(*_args: object, **_kwargs: object) -> None:
        raise psycopg.OperationalError("unavailable")

    monkeypatch.setattr("rtsp_proxy.operations.psycopg.connect", unavailable)
    with pytest.raises(OperationsError, match="temporary_restore_database_create_failed"):
        _create_database("postgresql://postgres@localhost/rtsp_proxy", "temporary")
    with pytest.raises(OperationsError, match="temporary_restore_database_drop_failed"):
        _drop_database(
            "postgresql://postgres@localhost/rtsp_proxy",
            "rtsp_proxy_restore_verify_deadbeef",
        )


def test_operations_rejects_missing_default_tool_and_failed_database_invariant(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("RTSP_PROXY_PG_DUMP_BINARY", raising=False)
    monkeypatch.setattr("rtsp_proxy.operations._which", lambda _name: None)
    with pytest.raises(OperationsError, match="pg_dump_unavailable"):
        _trusted_tool("pg_dump")

    class FailedInvariant:
        def execute(self, _statement: str) -> FailedInvariant:
            return self

        def fetchone(self) -> tuple[bool]:
            return (False,)

    required = frozenset(
        {
            "media_nodes",
            "cameras",
            "camera_placements",
            "camera_placement_history",
            "camera_access_policies",
            "audit_events",
            "outbox_messages",
        }
    )
    with pytest.raises(OperationsError, match="database_invariant_failed"):
        _database_invariants(FailedInvariant(), required)  # type: ignore[arg-type]


def test_operations_entrypoint_and_production_runbook_are_packaged_and_fail_closed() -> None:
    project = Path("pyproject.toml").read_text(encoding="utf-8")
    runbook = Path("deploy/PRODUCTION_RUNBOOK.md").read_text(encoding="utf-8")
    normalized_runbook = " ".join(runbook.split())
    readiness = Path("docs/PRODUCTION_READINESS.md").read_text(encoding="utf-8")

    assert 'rtsp-proxy-operations = "rtsp_proxy.operations:main"' in project
    assert "backup-database" in runbook
    assert "verify-database-restore" in runbook
    assert "RPO at most five minutes" in normalized_runbook
    assert "RTO at most 30 minutes" in normalized_runbook
    assert "A local fake SMTP server" in normalized_runbook
    assert "does not admit a production relay" in normalized_runbook
    assert "100 registered cameras on one node | **DEFERRED by owner**" in readiness
    assert "Production HOLD" in readiness
