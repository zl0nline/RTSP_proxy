from __future__ import annotations

import json
from collections.abc import Iterator
from time import monotonic
from uuid import UUID

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, insert, text
from sqlalchemy.exc import OperationalError

from rtsp_proxy.database import PostgresNodeStore, camera_placements, cameras
from rtsp_proxy.identifiers import generate_public_id
from rtsp_proxy.migrate import upgrade_database
from rtsp_proxy.nodes import (
    CameraCatalogQuery,
    CameraCatalogUnavailable,
    CameraControl,
    CameraState,
    InMemoryNodeStore,
    MediaNode,
    NodeControl,
    NodeHealth,
    NodeRuntimeAction,
    NodeRuntimeObservation,
    NodeState,
)

NODE_IDS = (
    UUID("00000000-0000-4000-8000-000000000001"),
    UUID("00000000-0000-4000-8000-000000000002"),
)
CAMERA_IDS = tuple(
    UUID(f"10000000-0000-4000-8000-{index:012d}")
    for index in (3, 1, 5, 2, 4, 6)
)
PUBLIC_IDS = tuple(f"{character * 25}a" for character in "abcdef")


class RunningNodeRuntime:
    def execute(
        self,
        _action: NodeRuntimeAction,
        node: MediaNode,
    ) -> NodeRuntimeObservation:
        return NodeRuntimeObservation(
            state=NodeState.RUNNING,
            health=NodeHealth.HEALTHY,
            management_fresh=True,
            config_compatible=True,
            applied_revision=node.desired_revision,
            process_id=node.external_port,
            process_start_ticks=1,
            process_boot_id=UUID("ffffffff-ffff-4fff-8fff-ffffffffffff"),
            config_sha256="a" * 64,
            release_id=node.release_id,
        )


def _catalog(
    *,
    persistent: bool,
    postgres_database_url: str,
) -> tuple[CameraControl, InMemoryNodeStore | PostgresNodeStore]:
    if persistent:
        upgrade_database(postgres_database_url)
        store: InMemoryNodeStore | PostgresNodeStore = PostgresNodeStore(
            postgres_database_url
        )
    else:
        store = InMemoryNodeStore()
    node_ids: Iterator[UUID] = iter(NODE_IDS)
    nodes = NodeControl(
        store=store,
        choose_port=lambda available: min(available),
        new_node_id=lambda: next(node_ids),
        node_runtime=RunningNodeRuntime(),
        provision_on_create=True,
        is_port_bindable=lambda _port: True,
    )
    first = nodes.register_node(
        name="node-a",
        port_range_start=12000,
        port_range_end=12001,
        max_nodes=2,
        external_port=12000,
    )
    second = nodes.register_node(
        name="node-b",
        port_range_start=12000,
        port_range_end=12001,
        max_nodes=2,
        external_port=12001,
    )
    camera_ids = iter(CAMERA_IDS)
    public_ids = iter(PUBLIC_IDS)
    cameras = CameraControl(
        store=store,
        new_camera_id=lambda: next(camera_ids),
        new_public_id=lambda: next(public_ids),
    )
    for name, node_id in (
        ("Warehouse", first.id),
        ("Front %_ Door", first.id),
        ("Lobby", second.id),
        ("Rear", first.id),
        ("Front Hall", second.id),
        ("Straße", first.id),
    ):
        cameras.create_camera(
            name=name,
            source_url=f"rtsp://camera.local/{name.replace(' ', '-').lower()}",
            node_id=node_id,
        )
    cameras.set_camera_enabled(CAMERA_IDS[3], enabled=False)
    return cameras, store


@pytest.mark.parametrize("persistent", [False, True])
def test_camera_catalog_keyset_is_bounded_stable_and_filterable(
    persistent: bool,
    postgres_database_url: str,
) -> None:
    cameras, store = _catalog(
        persistent=persistent,
        postgres_database_url=postgres_database_url,
    )
    try:
        first = cameras.catalog(CameraCatalogQuery(limit=2))
        second = cameras.catalog(CameraCatalogQuery(limit=2, after=first.next_after))
        last = cameras.catalog(CameraCatalogQuery(limit=2, after=second.next_after))

        assert [item.id for item in first.items] == sorted(CAMERA_IDS)[:2]
        assert first.next_after == sorted(CAMERA_IDS)[1]
        assert [item.id for item in second.items] == sorted(CAMERA_IDS)[2:4]
        assert second.next_after == sorted(CAMERA_IDS)[3]
        assert [item.id for item in last.items] == sorted(CAMERA_IDS)[4:]
        assert last.next_after is None

        search = cameras.catalog(CameraCatalogQuery(search="  Front  ", limit=10))
        literal_wildcards = cameras.catalog(CameraCatalogQuery(search="%_ D", limit=10))
        node_filter = cameras.catalog(CameraCatalogQuery(node_id=NODE_IDS[1], limit=10))
        state_filter = cameras.catalog(
            CameraCatalogQuery(state=CameraState.DISABLED, limit=10)
        )

        assert [item.name for item in search.items] == ["Front %_ Door", "Front Hall"]
        assert [item.name for item in literal_wildcards.items] == ["Front %_ Door"]
        assert [item.name for item in node_filter.items] == ["Front Hall", "Lobby"]
        assert [item.name for item in state_filter.items] == ["Rear"]
        assert [item.node_name for item in node_filter.items] == ["node-b", "node-b"]
        assert all(not hasattr(item, "source_url") for item in first.items)

        by_public_path = cameras.catalog(
            CameraCatalogQuery(search=str(PUBLIC_IDS[0]), limit=10)
        )

        assert [item.name for item in by_public_path.items] == ["Warehouse"]
        assert [
            item.name
            for item in cameras.catalog(
                CameraCatalogQuery(search="Straße", limit=10)
            ).items
        ] == ["Straße"]
        assert not cameras.catalog(
            CameraCatalogQuery(search="STRASSE", limit=10)
        ).items
    finally:
        close = getattr(store, "close", None)
        if close is not None:
            close()


def test_camera_catalog_query_rejects_unbounded_or_ambiguous_input(
) -> None:
    for kwargs in (
        {"limit": 0},
        {"limit": 101},
        {"search": "ab"},
        {"search": "x" * 129},
        {"search": "bad\nname"},
    ):
        reason = (
            "camera_catalog_limit_invalid"
            if "limit" in kwargs
            else "camera_catalog_search_invalid"
        )
        with pytest.raises(ValueError, match=reason):
            CameraCatalogQuery(**kwargs)


def test_postgres_camera_catalog_uses_indexed_projection_at_10k_rows(
    postgres_database_url: str,
) -> None:
    camera_control, store = _catalog(
        persistent=True,
        postgres_database_url=postgres_database_url,
    )
    assert isinstance(store, PostgresNodeStore)
    assert camera_control.catalog(CameraCatalogQuery(search="Front", limit=10)).items
    engine = create_engine(postgres_database_url)
    extra_count = 10_000 - len(CAMERA_IDS)
    extra_ids = tuple(
        UUID(int=0x20000000000040008000000000000000 + index)
        for index in range(extra_count)
    )
    try:
        with engine.begin() as connection:
            connection.execute(
                insert(cameras),
                [
                    {
                        "id": camera_id,
                        "name": f"Catalog camera {index:05d}",
                        "source_url": f"rtsp://camera.local/{index}",
                        "public_id": generate_public_id(),
                        "state": CameraState.ENABLED.value,
                        "desired_revision": 1,
                        "applied_revision": 0,
                    }
                    for index, camera_id in enumerate(extra_ids)
                ],
            )
            connection.execute(
                insert(camera_placements),
                [
                    {
                        "camera_id": camera_id,
                        "node_id": NODE_IDS[0],
                        "placement_mode": "automatic",
                        "generation": 1,
                    }
                    for camera_id in extra_ids
                ],
            )
            connection.execute(text("ANALYZE cameras"))
            connection.execute(text("SET LOCAL enable_seqscan = off"))
            plan = connection.scalar(
                text(
                    "EXPLAIN (FORMAT JSON) "
                    "SELECT cameras.id FROM cameras "
                    "WHERE cameras.name LIKE :pattern ESCAPE E'\\\\'"
                ),
                {"pattern": "%camera 09990%"},
            )
            index_definitions = tuple(
                connection.scalars(
                    text(
                        "SELECT indexdef FROM pg_indexes WHERE schemaname='public' "
                        "AND indexname LIKE 'ix_camera%catalog%' ORDER BY indexname"
                    )
                )
            )
        serialized_plan = json.dumps(plan, sort_keys=True)
        assert "ix_cameras_catalog_name_trgm" in serialized_plan, (
            serialized_plan,
            index_definitions,
        )
        assert len(index_definitions) == 4
        assert any("gin_trgm_ops" in definition for definition in index_definitions)
        assert any(
            "state, id" in definition and "deleted" in definition
            for definition in index_definitions
        )
    finally:
        engine.dispose()
        store.close()


def test_camera_catalog_requires_current_exact_projection(
    postgres_database_url: str,
) -> None:
    migration = Config("alembic.ini")
    migration.set_main_option("sqlalchemy.url", postgres_database_url)
    command.upgrade(migration, "0013_operator_login")
    store = PostgresNodeStore(postgres_database_url)
    control = CameraControl(
        store=store,
        new_camera_id=lambda: UUID(int=1),
        new_public_id=lambda: "a" * 26,
    )
    try:
        with pytest.raises(CameraCatalogUnavailable, match="camera_catalog_unavailable"):
            control.catalog(CameraCatalogQuery())

        command.upgrade(migration, "head")
        store.assert_camera_catalog_ready()
        engine = create_engine(postgres_database_url)
        try:
            with engine.begin() as connection:
                connection.execute(text("DROP INDEX ix_cameras_catalog_name_trgm"))
                connection.execute(
                    text(
                        "CREATE INDEX ix_cameras_catalog_name_trgm "
                        "ON cameras USING btree (name)"
                    )
                )
        finally:
            engine.dispose()

        with pytest.raises(CameraCatalogUnavailable, match="camera_catalog_unavailable"):
            control.catalog(CameraCatalogQuery())

        engine = create_engine(postgres_database_url)
        try:
            with engine.begin() as connection:
                connection.execute(text("DROP INDEX ix_cameras_catalog_name_trgm"))
                connection.execute(
                    text(
                        "CREATE INDEX ix_cameras_catalog_name_trgm "
                        "ON cameras USING gin (name gin_trgm_ops)"
                    )
                )
                connection.execute(
                    text(
                        "UPDATE pg_index SET indisvalid = false "
                        "WHERE indexrelid = "
                        "'ix_cameras_catalog_name_trgm'::regclass"
                    )
                )
        finally:
            engine.dispose()

        with pytest.raises(CameraCatalogUnavailable, match="camera_catalog_unavailable"):
            control.catalog(CameraCatalogQuery())
    finally:
        store.close()


def test_camera_catalog_migration_lock_wait_is_bounded_and_atomic(
    postgres_database_url: str,
) -> None:
    migration = Config("alembic.ini")
    migration.set_main_option("sqlalchemy.url", postgres_database_url)
    command.upgrade(migration, "0013_operator_login")
    engine = create_engine(postgres_database_url)
    try:
        with engine.begin() as blocker:
            blocker.execute(text("LOCK cameras IN ACCESS EXCLUSIVE MODE"))
            started = monotonic()
            with pytest.raises(OperationalError):
                command.upgrade(migration, "head")
            assert monotonic() - started < 3
        with engine.connect() as connection:
            assert connection.scalar(text("SELECT version_num FROM alembic_version")) == (
                "0013_operator_login"
            )
            assert connection.scalar(
                text(
                    "SELECT count(*) FROM pg_indexes WHERE schemaname='public' "
                    "AND indexname LIKE 'ix_camera%catalog%'"
                )
            ) == 0
    finally:
        engine.dispose()
