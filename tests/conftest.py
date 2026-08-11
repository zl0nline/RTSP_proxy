from __future__ import annotations

import shutil
import socket
import subprocess
import time
from collections.abc import Iterator
from uuid import uuid4

import psycopg
import pytest
from psycopg import sql


@pytest.fixture(scope="session")
def _postgres_server_url(tmp_path_factory: pytest.TempPathFactory) -> Iterator[str]:
    initdb = shutil.which("initdb")
    postgres = shutil.which("postgres")
    if initdb is None or postgres is None:
        pytest.skip("native PostgreSQL binaries are required")

    root = tmp_path_factory.mktemp("postgres")
    data = root / "data"
    subprocess.run(
        [
            initdb,
            "--pgdata",
            str(data),
            "--username",
            "postgres",
            "--auth-local",
            "trust",
            "--auth-host",
            "trust",
            "--no-locale",
            "--encoding",
            "UTF8",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    port = _unused_tcp_port()
    server_log = root / "postgres.log"
    log_stream = server_log.open("w", encoding="utf-8")
    process = subprocess.Popen(
        [
            postgres,
            "-D",
            str(data),
            "-h",
            "127.0.0.1",
            "-p",
            str(port),
            "-k",
            "",
        ],
        stdout=subprocess.DEVNULL,
        stderr=log_stream,
        text=True,
    )
    database_url = f"postgresql+psycopg://postgres@127.0.0.1:{port}/postgres"
    try:
        try:
            _wait_for_postgres(database_url)
        except RuntimeError as error:
            log_stream.flush()
            diagnostic = server_log.read_text(encoding="utf-8", errors="replace")
            raise RuntimeError(
                f"postgres_test_server_start_timeout:\n{diagnostic[-4000:]}"
            ) from error
        yield database_url
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=10)
        log_stream.close()


@pytest.fixture
def postgres_database_url(_postgres_server_url: str) -> Iterator[str]:
    database_name = f"test_{uuid4().hex}"
    admin_url = _postgres_server_url.replace("postgresql+psycopg://", "postgresql://", 1)
    with psycopg.connect(admin_url, autocommit=True) as connection:
        connection.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(database_name)))
    database_url = _postgres_server_url.rsplit("/", 1)[0] + f"/{database_name}"
    try:
        yield database_url
    finally:
        with psycopg.connect(admin_url, autocommit=True) as connection:
            connection.execute(
                sql.SQL("DROP DATABASE {} WITH (FORCE)").format(sql.Identifier(database_name))
            )


def _unused_tcp_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _wait_for_postgres(database_url: str) -> None:
    psycopg_url = database_url.replace("postgresql+psycopg://", "postgresql://", 1)
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            with psycopg.connect(psycopg_url):
                return
        except psycopg.OperationalError:
            time.sleep(0.05)
    raise RuntimeError("postgres_test_server_start_timeout")
