from __future__ import annotations

import os
import sys

from sqlalchemy import create_engine, text
from sqlalchemy.exc import SQLAlchemyError


def main() -> None:
    database_url = os.environ.get("RTSP_PROXY_DATABASE_URL")
    if not database_url:
        print("database schema check failed: database_url_required", file=sys.stderr)
        raise SystemExit(1)
    engine = create_engine(
        database_url,
        hide_parameters=True,
        pool_size=1,
        max_overflow=0,
        pool_timeout=2,
        connect_args={"connect_timeout": 2},
    )
    try:
        with engine.connect() as connection:
            connection.execute(text("SET statement_timeout = '2s'"))
            revisions = tuple(connection.scalars(text("SELECT version_num FROM alembic_version")))
    except SQLAlchemyError:
        print("database schema check failed: database_unavailable", file=sys.stderr)
        raise SystemExit(1) from None
    finally:
        engine.dispose()
    if len(revisions) != 1:
        print("database schema check failed: database_revision_invalid", file=sys.stderr)
        raise SystemExit(1)
    print(revisions[0])


if __name__ == "__main__":  # pragma: no cover - console entrypoint
    main()
