from __future__ import annotations

import os
from importlib.resources import as_file, files

from alembic import command
from alembic.config import Config


class MigrationConfigurationError(ValueError):
    """The packaged schema migration cannot be configured safely."""


def upgrade_database(database_url: str, revision: str = "head") -> None:
    if not database_url:
        raise MigrationConfigurationError("database_url_required")
    migration_root = files("rtsp_proxy").joinpath("migrations")
    with as_file(migration_root) as migration_path:
        configuration = Config()
        configuration.set_main_option("script_location", str(migration_path))
        configuration.set_main_option("sqlalchemy.url", database_url.replace("%", "%%"))
        command.upgrade(configuration, revision)


def run_migrations() -> None:
    database_url = os.environ.get("RTSP_PROXY_DATABASE_URL")
    if database_url is None:
        raise MigrationConfigurationError("database_url_required")
    upgrade_database(database_url)
