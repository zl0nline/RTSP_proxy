from __future__ import annotations

import json
import os
from pathlib import Path

import psycopg
import pytest

from rtsp_proxy.migrate import upgrade_database
from rtsp_proxy.operations import (
    OperationsError,
    _new_private_output,
    _postgres_environment,
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
    assert backup["database"]["revision"] == "0024_camera_probe_profiles"
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
