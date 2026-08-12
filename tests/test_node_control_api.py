import socket
import time
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from threading import Barrier, Event, Lock
from typing import cast
from uuid import UUID, uuid4

import pytest
from alembic import command
from alembic.config import Config
from fastapi import FastAPI
from fastapi.testclient import TestClient
from httpx2 import Response
from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError

from rtsp_proxy.app import create_app
from rtsp_proxy.config import RuntimeRole, Settings
from rtsp_proxy.database import DatabaseSchemaMismatch, PostgresNodeStore
from rtsp_proxy.identifiers import PublicId, generate_public_id
from rtsp_proxy.migrate import upgrade_database
from rtsp_proxy.nodes import (
    CameraControl,
    InMemoryNodeStore,
    InvalidCameraSource,
    MediaNode,
    NodeControl,
    NodeHealth,
    NodeLifecycleBusy,
    NodeLifecycleConflict,
    NodeNotEmpty,
    NodeProvisioningPolicy,
    NodeRuntime,
    NodeRuntimeAction,
    NodeRuntimeObservation,
    NodeState,
    tcp_port_is_bindable,
)
from rtsp_proxy.runtime import create_app_from_environment, create_background_app, run_web


def test_node_commands_fail_closed_when_the_control_store_is_not_configured() -> None:
    response = TestClient(create_app(Settings(role=RuntimeRole.WEB))).post(
        "/api/v1/nodes",
        json={"name": "unavailable"},
    )

    assert response.status_code == 503
    assert response.json() == {"detail": {"code": "node_control_unavailable"}}


def test_operator_can_register_a_node_with_an_automatically_allocated_port() -> None:
    control = NodeControl(
        store=InMemoryNodeStore(),
        choose_port=lambda available: 12001,
        new_node_id=lambda: UUID("00000000-0000-0000-0000-000000000001"),
    )
    app = create_app(
        Settings(
            role=RuntimeRole.WEB,
            node_port_range_start=12000,
            node_port_range_end=12002,
        ),
        node_control=control,
    )

    response = TestClient(app).post("/api/v1/nodes", json={"name": "media-a"})

    assert response.status_code == 201
    assert response.headers["location"] == (
        "/api/v1/nodes/00000000-0000-0000-0000-000000000001"
    )
    assert response.json() == {
        "id": "00000000-0000-0000-0000-000000000001",
        "name": "media-a",
        "external_port": 12001,
        "state": "provisioning",
        "runtime_state": "provisioning",
        "health": "unknown",
        "registered_cameras": 0,
        "camera_capacity": 100,
        "desired_revision": 1,
        "applied_revision": 0,
    }


def test_node_creation_lock_contention_returns_one_reservation_for_later_start() -> None:
    class BusyStore(InMemoryNodeStore):
        attempts = 0

        @contextmanager
        def lifecycle_guard(self, node_id: UUID) -> Iterator[None]:
            self.attempts += 1
            if self.attempts == 1:
                raise NodeLifecycleBusy("node_lifecycle_busy")
            yield

    store = BusyStore()
    client = TestClient(
        create_app(
            Settings(
                role=RuntimeRole.WEB,
                node_port_range_start=12000,
                node_port_range_end=12000,
            ),
            node_control=NodeControl(
                store=store,
                choose_port=lambda available: available[0],
                new_node_id=lambda: UUID("00000000-0000-0000-0000-000000000001"),
                node_runtime=RecordingLifecycleRuntime(),
                provision_on_create=True,
            ),
        ),
        raise_server_exceptions=False,
    )

    response = client.post("/api/v1/nodes", json={"name": "busy"})

    assert response.status_code == 201
    assert response.headers["location"] == (
        "/api/v1/nodes/00000000-0000-0000-0000-000000000001"
    )
    assert response.json()["state"] == "provisioning"
    assert len(store.list_nodes()) == 1

    start_response = client.post(f"{response.headers['location']}/start")

    assert start_response.status_code == 200
    assert start_response.json()["state"] == "running"
    assert len(store.list_nodes()) == 1


def test_each_registered_node_reserves_unique_loopback_management_ports() -> None:
    node_ids = iter(
        (
            UUID("00000000-0000-0000-0000-000000000001"),
            UUID("00000000-0000-0000-0000-000000000002"),
        )
    )
    control = NodeControl(
        store=InMemoryNodeStore(),
        choose_port=lambda available: available[0],
        new_node_id=lambda: next(node_ids),
    )
    client = TestClient(
        create_app(
            Settings(
                role=RuntimeRole.WEB,
                max_nodes=2,
                node_port_range_start=12000,
                node_port_range_end=12001,
                node_api_port_range_start=13000,
                node_api_port_range_end=13001,
                node_metrics_port_range_start=14000,
                node_metrics_port_range_end=14001,
            ),
            node_control=control,
        )
    )

    assert client.post("/api/v1/nodes", json={"name": "media-a"}).status_code == 201
    assert client.post("/api/v1/nodes", json={"name": "media-b"}).status_code == 201

    nodes = control.list_nodes()
    assert {(node.api_port, node.metrics_port) for node in nodes} == {
        (13000, 14000),
        (13001, 14001),
    }


def test_node_registration_reports_management_port_exhaustion_without_a_partial_node() -> None:
    node_ids = iter(
        (
            UUID("00000000-0000-0000-0000-000000000001"),
            UUID("00000000-0000-0000-0000-000000000002"),
        )
    )
    control = NodeControl(
        store=InMemoryNodeStore(),
        choose_port=lambda available: available[0],
        new_node_id=lambda: next(node_ids),
    )
    client = TestClient(
        create_app(
            Settings(
                role=RuntimeRole.WEB,
                max_nodes=2,
                node_port_range_start=12000,
                node_port_range_end=12001,
                node_api_port_range_start=13000,
                node_api_port_range_end=13000,
                node_metrics_port_range_start=14000,
                node_metrics_port_range_end=14000,
            ),
            node_control=control,
        ),
        raise_server_exceptions=False,
    )
    assert client.post("/api/v1/nodes", json={"name": "media-a"}).status_code == 201

    response = client.post("/api/v1/nodes", json={"name": "media-b"})

    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "node_management_ports_exhausted"
    assert client.get("/api/v1/nodes").json()["count"] == 1


def test_port_allocator_rechecks_bindability_and_retries_a_raced_candidate() -> None:
    observations: dict[int, int] = {}

    def changing_bindability(port: int) -> bool:
        observations[port] = observations.get(port, 0) + 1
        return port != 12000 or observations[port] == 1

    control = NodeControl(
        store=InMemoryNodeStore(),
        choose_port=lambda available: available[0],
        new_node_id=lambda: UUID("00000000-0000-0000-0000-000000000001"),
        is_port_bindable=changing_bindability,
    )
    client = TestClient(
        create_app(
            Settings(
                role=RuntimeRole.WEB,
                max_nodes=2,
                node_port_range_start=12000,
                node_port_range_end=12001,
            ),
            node_control=control,
        )
    )

    response = client.post("/api/v1/nodes", json={"name": "raced"})

    assert response.status_code == 201
    assert response.json()["external_port"] == 12001


def test_port_allocator_proves_every_candidate_before_reporting_exhaustion() -> None:
    observations: dict[int, int] = {}

    def changing_bindability(port: int) -> bool:
        observations[port] = observations.get(port, 0) + 1
        if observations[port] == 1:
            return True
        return port == 12008

    control = NodeControl(
        store=InMemoryNodeStore(),
        choose_port=lambda available: available[0],
        new_node_id=lambda: UUID("00000000-0000-0000-0000-000000000001"),
        is_port_bindable=changing_bindability,
    )
    client = TestClient(
        create_app(
            Settings(
                role=RuntimeRole.WEB,
                max_nodes=1,
                node_port_range_start=12000,
                node_port_range_end=12008,
            ),
            node_control=control,
        )
    )

    response = client.post("/api/v1/nodes", json={"name": "raced"})

    assert response.status_code == 201
    assert response.json()["external_port"] == 12008


def test_automatic_port_allocation_excludes_configured_reserved_ports() -> None:
    control = NodeControl(
        store=InMemoryNodeStore(),
        choose_port=lambda available: available[0],
        new_node_id=lambda: UUID("00000000-0000-0000-0000-000000000001"),
    )
    client = TestClient(
        create_app(
            Settings(
                role=RuntimeRole.WEB,
                max_nodes=1,
                node_port_range_start=12000,
                node_port_range_end=12001,
                node_port_reserved=(12000,),
            ),
            node_control=control,
        )
    )

    response = client.post("/api/v1/nodes", json={"name": "media-a"})

    assert response.status_code == 201
    assert response.json()["external_port"] == 12001


def test_registering_a_node_reports_the_required_error_when_ports_are_exhausted() -> None:
    node_ids = iter(
        (
            UUID("00000000-0000-0000-0000-000000000001"),
            UUID("00000000-0000-0000-0000-000000000002"),
        )
    )
    control = NodeControl(
        store=InMemoryNodeStore(),
        choose_port=lambda available: available[0],
        new_node_id=lambda: next(node_ids),
    )
    client = TestClient(
        create_app(
            Settings(
                role=RuntimeRole.WEB,
                max_nodes=2,
                node_port_range_start=12000,
                node_port_range_end=12000,
            ),
            node_control=control,
        ),
        raise_server_exceptions=False,
    )
    assert client.post("/api/v1/nodes", json={"name": "media-a"}).status_code == 201

    response = client.post("/api/v1/nodes", json={"name": "media-b"})

    assert response.status_code == 409
    assert response.json() == {
        "detail": {
            "code": "node_ports_exhausted",
            "message": "нет свободных портов для регистрации новой ноды",
        }
    }


def test_registering_a_node_cannot_exceed_the_configured_node_limit() -> None:
    node_ids = iter(
        (
            UUID("00000000-0000-0000-0000-000000000001"),
            UUID("00000000-0000-0000-0000-000000000002"),
        )
    )
    control = NodeControl(
        store=InMemoryNodeStore(),
        choose_port=lambda available: available[0],
        new_node_id=lambda: next(node_ids),
    )
    client = TestClient(
        create_app(
            Settings(
                role=RuntimeRole.WEB,
                max_nodes=1,
                node_port_range_start=12000,
                node_port_range_end=12001,
            ),
            node_control=control,
        ),
        raise_server_exceptions=False,
    )
    assert client.post("/api/v1/nodes", json={"name": "media-a"}).status_code == 201

    response = client.post("/api/v1/nodes", json={"name": "media-b"})

    assert response.status_code == 409
    assert response.json() == {
        "detail": {
            "code": "max_nodes_reached",
            "message": "достигнуто максимальное количество нод",
        }
    }


def test_operator_can_register_a_node_on_a_specific_free_port() -> None:
    control = NodeControl(
        store=InMemoryNodeStore(),
        choose_port=lambda available: available[0],
        new_node_id=lambda: UUID("00000000-0000-0000-0000-000000000001"),
    )
    client = TestClient(
        create_app(
            Settings(
                role=RuntimeRole.WEB,
                node_port_range_start=12000,
                node_port_range_end=12002,
            ),
            node_control=control,
        )
    )

    response = client.post(
        "/api/v1/nodes",
        json={"name": "media-a", "external_port": 12002},
    )

    assert response.status_code == 201
    assert response.json()["external_port"] == 12002


def test_manual_node_port_must_be_inside_the_configured_range() -> None:
    control = NodeControl(
        store=InMemoryNodeStore(),
        choose_port=lambda available: available[0],
        new_node_id=lambda: UUID("00000000-0000-0000-0000-000000000001"),
    )
    client = TestClient(
        create_app(
            Settings(
                role=RuntimeRole.WEB,
                node_port_range_start=12000,
                node_port_range_end=12002,
            ),
            node_control=control,
        ),
        raise_server_exceptions=False,
    )

    response = client.post(
        "/api/v1/nodes",
        json={"name": "media-a", "external_port": 11999},
    )

    assert response.status_code == 422
    assert response.json() == {
        "detail": {
            "code": "node_port_out_of_range",
            "message": "порт ноды находится вне разрешенного диапазона",
        }
    }


def test_manual_node_port_must_not_already_belong_to_another_node() -> None:
    node_ids = iter(
        (
            UUID("00000000-0000-0000-0000-000000000001"),
            UUID("00000000-0000-0000-0000-000000000002"),
        )
    )
    control = NodeControl(
        store=InMemoryNodeStore(),
        choose_port=lambda available: available[0],
        new_node_id=lambda: next(node_ids),
    )
    client = TestClient(
        create_app(
            Settings(
                role=RuntimeRole.WEB,
                node_port_range_start=12000,
                node_port_range_end=12002,
            ),
            node_control=control,
        ),
        raise_server_exceptions=False,
    )
    assert (
        client.post(
            "/api/v1/nodes",
            json={"name": "media-a", "external_port": 12001},
        ).status_code
        == 201
    )

    response = client.post(
        "/api/v1/nodes",
        json={"name": "media-b", "external_port": 12001},
    )

    assert response.status_code == 409
    assert response.json() == {
        "detail": {
            "code": "node_port_in_use",
            "message": "порт уже используется другой нодой",
        }
    }


def test_operator_can_list_registered_nodes_through_the_control_api() -> None:
    node_ids = iter(
        (
            UUID("00000000-0000-0000-0000-000000000001"),
            UUID("00000000-0000-0000-0000-000000000002"),
        )
    )
    control = NodeControl(
        store=InMemoryNodeStore(),
        choose_port=lambda available: available[0],
        new_node_id=lambda: next(node_ids),
    )
    client = TestClient(
        create_app(
            Settings(
                role=RuntimeRole.WEB,
                max_nodes=50,
                node_port_range_start=12000,
                node_port_range_end=12002,
            ),
            node_control=control,
        )
    )
    assert client.post("/api/v1/nodes", json={"name": "media-a"}).status_code == 201
    assert client.post("/api/v1/nodes", json={"name": "media-b"}).status_code == 201

    response = client.get("/api/v1/nodes")

    assert response.status_code == 200
    assert response.json() == {
        "items": [
            {
                "id": "00000000-0000-0000-0000-000000000001",
                "name": "media-a",
                "external_port": 12000,
                    "state": "provisioning",
                    "runtime_state": "provisioning",
                "health": "unknown",
                    "registered_cameras": 0,
                    "camera_capacity": 100,
                    "desired_revision": 1,
                    "applied_revision": 0,
            },
            {
                "id": "00000000-0000-0000-0000-000000000002",
                "name": "media-b",
                "external_port": 12001,
                    "state": "provisioning",
                    "runtime_state": "provisioning",
                "health": "unknown",
                    "registered_cameras": 0,
                    "camera_capacity": 100,
                    "desired_revision": 1,
                    "applied_revision": 0,
            },
        ],
        "count": 2,
        "max_nodes": 50,
    }


def test_automatic_camera_placement_uses_registered_then_active_load() -> None:
    observed_at = datetime.now(UTC)
    nodes = (
        MediaNode(
            id=UUID("00000000-0000-0000-0000-000000000001"),
            name="media-a",
            external_port=12000,
            state=NodeState.RUNNING,
            runtime_state=NodeState.RUNNING,
            health=NodeHealth.HEALTHY,
            management_fresh=True,
            management_observed_at=observed_at,
                config_compatible=True,
                applied_revision=1,
                registered_cameras=50,
            active_sources=2,
        ),
        MediaNode(
            id=UUID("00000000-0000-0000-0000-000000000002"),
            name="media-b",
            external_port=12001,
            state=NodeState.RUNNING,
            runtime_state=NodeState.RUNNING,
            health=NodeHealth.HEALTHY,
            management_fresh=True,
            management_observed_at=observed_at,
                config_compatible=True,
                applied_revision=1,
                registered_cameras=10,
            active_sources=5,
        ),
        MediaNode(
            id=UUID("00000000-0000-0000-0000-000000000003"),
            name="media-c",
            external_port=12002,
            state=NodeState.RUNNING,
            runtime_state=NodeState.RUNNING,
            health=NodeHealth.HEALTHY,
            management_fresh=True,
            management_observed_at=observed_at,
                config_compatible=True,
                applied_revision=1,
                registered_cameras=10,
            active_sources=1,
        ),
    )
    store = InMemoryNodeStore(nodes=nodes)
    camera_control = CameraControl(
        store=store,
        new_camera_id=lambda: UUID("10000000-0000-0000-0000-000000000001"),
        new_public_id=lambda: "a234567a234567a234567a2344",
    )
    client = TestClient(
        create_app(
            Settings(role=RuntimeRole.WEB),
            camera_control=camera_control,
        )
    )

    response = client.post(
        "/api/v1/cameras",
        json={"name": "entrance", "source_url": "rtsp://camera.local/main"},
    )

    assert response.status_code == 201
    assert response.json() == {
        "id": "10000000-0000-0000-0000-000000000001",
        "name": "entrance",
        "public_id": "a234567a234567a234567a2344",
        "node_id": "00000000-0000-0000-0000-000000000003",
        "node_port": 12002,
        "placement_mode": "automatic",
        "desired_revision": 1,
        "applied_revision": 0,
    }


def test_automatic_placement_skips_a_manually_created_provisioning_node() -> None:
    store = InMemoryNodeStore(
        nodes=(
            MediaNode(
                id=UUID("00000000-0000-0000-0000-000000000001"),
                name="manual-pending",
                external_port=12000,
            ),
        )
    )
    client = TestClient(
        create_app(
            Settings(role=RuntimeRole.WEB),
            camera_control=CameraControl(
                store=store,
                new_camera_id=lambda: UUID("10000000-0000-0000-0000-000000000001"),
                new_public_id=lambda: "a" * 26,
            ),
        )
    )

    response = client.post(
        "/api/v1/cameras",
        json={"name": "camera-a", "source_url": "rtsp://camera.local/main"},
    )

    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "eligible_node_missing"


def test_automatic_placement_does_not_reuse_a_maintenance_provisioning_node() -> None:
    store = InMemoryNodeStore(
        nodes=(
            MediaNode(
                id=UUID("00000000-0000-0000-0000-000000000001"),
                name="maintenance-pending",
                external_port=12000,
                maintenance=True,
            ),
        )
    )
    client = TestClient(
        create_app(
            Settings(role=RuntimeRole.WEB),
            camera_control=CameraControl(
                store=store,
                new_camera_id=lambda: UUID("10000000-0000-0000-0000-000000000001"),
                new_public_id=lambda: "a" * 26,
            ),
        )
    )

    response = client.post(
        "/api/v1/cameras",
        json={"name": "camera-a", "source_url": "rtsp://camera.local/main"},
    )

    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "eligible_node_missing"
    assert client.get("/api/v1/cameras").json()["count"] == 0


def test_automatic_placement_skips_maintenance_stale_or_incompatible_nodes() -> None:
    observed_at = datetime.now(UTC)
    blocked = (
        MediaNode(
            id=UUID("00000000-0000-0000-0000-000000000001"),
            name="maintenance",
            external_port=12000,
            state=NodeState.RUNNING,
            health=NodeHealth.HEALTHY,
            maintenance=True,
            management_fresh=True,
            management_observed_at=observed_at,
            config_compatible=True,
        ),
        MediaNode(
            id=UUID("00000000-0000-0000-0000-000000000002"),
            name="stale",
            external_port=12001,
            state=NodeState.RUNNING,
            health=NodeHealth.HEALTHY,
            management_fresh=True,
            management_observed_at=observed_at - timedelta(minutes=1),
            config_compatible=True,
        ),
        MediaNode(
            id=UUID("00000000-0000-0000-0000-000000000003"),
            name="incompatible",
            external_port=12002,
            state=NodeState.RUNNING,
            health=NodeHealth.HEALTHY,
            management_fresh=True,
            management_observed_at=observed_at,
            config_compatible=False,
        ),
    )
    target = MediaNode(
        id=UUID("00000000-0000-0000-0000-000000000004"),
        name="eligible",
        external_port=12003,
        state=NodeState.RUNNING,
        runtime_state=NodeState.RUNNING,
        health=NodeHealth.HEALTHY,
        management_fresh=True,
        management_observed_at=observed_at,
            config_compatible=True,
            applied_revision=1,
            registered_cameras=10,
    )
    store = InMemoryNodeStore(nodes=(*blocked, target))
    client = TestClient(
        create_app(
            Settings(role=RuntimeRole.WEB),
            camera_control=CameraControl(
                store=store,
                new_camera_id=lambda: UUID("10000000-0000-0000-0000-000000000001"),
                new_public_id=lambda: "a" * 26,
            ),
        )
    )

    response = client.post(
        "/api/v1/cameras",
        json={"name": "camera-a", "source_url": "rtsp://camera.local/main"},
    )

    assert response.status_code == 201
    assert response.json()["node_id"] == str(target.id)


def test_operator_can_place_a_camera_on_a_specific_eligible_node() -> None:
    observed_at = datetime.now(UTC)
    first_node_id = UUID("00000000-0000-0000-0000-000000000001")
    second_node_id = UUID("00000000-0000-0000-0000-000000000002")
    store = InMemoryNodeStore(
        nodes=(
            MediaNode(
                id=first_node_id,
                name="media-a",
                external_port=12000,
                state=NodeState.RUNNING,
                runtime_state=NodeState.RUNNING,
                health=NodeHealth.HEALTHY,
                management_fresh=True,
                management_observed_at=observed_at,
                    config_compatible=True,
                    applied_revision=1,
                    registered_cameras=40,
            ),
            MediaNode(
                id=second_node_id,
                name="media-b",
                external_port=12001,
                state=NodeState.RUNNING,
                runtime_state=NodeState.RUNNING,
                health=NodeHealth.HEALTHY,
                management_fresh=True,
                management_observed_at=observed_at,
                    config_compatible=True,
                    applied_revision=1,
                    registered_cameras=1,
            ),
        )
    )
    camera_control = CameraControl(
        store=store,
        new_camera_id=lambda: UUID("10000000-0000-0000-0000-000000000001"),
        new_public_id=lambda: "b234567b234567b234567b2344",
    )
    client = TestClient(
        create_app(
            Settings(role=RuntimeRole.WEB),
            camera_control=camera_control,
        )
    )

    response = client.post(
        "/api/v1/cameras",
        json={
            "name": "entrance",
            "source_url": "rtsp://camera.local/main",
            "node_id": str(first_node_id),
        },
    )

    assert response.status_code == 201
    assert response.json()["node_id"] == str(first_node_id)
    assert response.json()["node_port"] == 12000
    assert response.json()["placement_mode"] == "manual"


def test_camera_source_credentials_are_rejected_before_persistence() -> None:
    node = MediaNode(
        id=UUID("00000000-0000-0000-0000-000000000001"),
        name="media-a",
        external_port=12000,
        state=NodeState.RUNNING,
        health=NodeHealth.HEALTHY,
        management_fresh=True,
        config_compatible=True,
    )
    store = InMemoryNodeStore(nodes=(node,))
    client = TestClient(
        create_app(
            Settings(role=RuntimeRole.WEB),
            camera_control=CameraControl(
                store=store,
                new_camera_id=lambda: UUID("10000000-0000-0000-0000-000000000001"),
                new_public_id=lambda: "a234567a234567a234567a2344",
            ),
        )
    )

    response = client.post(
        "/api/v1/cameras",
        json={
            "name": "secret-camera",
            "source_url": "rtsp://operator:never-log-this@camera.local/main",
        },
    )

    assert response.status_code == 422
    assert "never-log-this" not in response.text
    assert client.get("/api/v1/cameras").json()["count"] == 0


def test_manual_camera_placement_reports_missing_node_consistently() -> None:
    client = TestClient(
        create_app(
            Settings(role=RuntimeRole.WEB),
            camera_control=CameraControl(
                store=InMemoryNodeStore(),
                new_camera_id=lambda: UUID("10000000-0000-0000-0000-000000000001"),
                new_public_id=lambda: "a" * 26,
            ),
        ),
        raise_server_exceptions=False,
    )

    response = client.post(
        "/api/v1/cameras",
        json={
            "name": "missing-target",
            "source_url": "rtsp://camera.local/main",
            "node_id": "00000000-0000-0000-0000-000000000099",
        },
    )

    assert response.status_code == 404
    assert response.json() == {"detail": {"code": "node_not_found"}}


def test_manual_camera_placement_cannot_create_a_101st_registered_camera() -> None:
    full_node_id = UUID("00000000-0000-0000-0000-000000000001")
    store = InMemoryNodeStore(
        nodes=(
            MediaNode(
                id=full_node_id,
                name="media-full",
                external_port=12000,
                state=NodeState.RUNNING,
                health=NodeHealth.HEALTHY,
                registered_cameras=100,
            ),
        )
    )
    camera_control = CameraControl(
        store=store,
        new_camera_id=lambda: UUID("10000000-0000-0000-0000-000000000001"),
        new_public_id=lambda: "c234567c234567c234567c2344",
    )
    client = TestClient(
        create_app(
            Settings(role=RuntimeRole.WEB),
            camera_control=camera_control,
        ),
        raise_server_exceptions=False,
    )

    response = client.post(
        "/api/v1/cameras",
        json={
            "name": "overflow",
            "source_url": "rtsp://camera.local/main",
            "node_id": str(full_node_id),
        },
    )

    assert response.status_code == 409
    assert response.json() == {
        "detail": {
            "code": "node_camera_capacity_reached",
            "message": "нода уже содержит 100 зарегистрированных камер",
        }
    }


def test_registered_node_survives_control_application_restart(
    postgres_database_url: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    migration = Config("alembic.ini")
    migration.set_main_option("sqlalchemy.url", postgres_database_url)
    command.upgrade(migration, "head")
    monkeypatch.setenv("RTSP_PROXY_ROLE", "web")
    monkeypatch.setenv("RTSP_PROXY_DATABASE_URL", postgres_database_url)
    monkeypatch.setenv("RTSP_PROXY_NODE_PORT_RANGE_START", "12000")
    monkeypatch.setenv("RTSP_PROXY_NODE_PORT_RANGE_END", "12002")

    create_response = TestClient(create_app_from_environment()).post(
        "/api/v1/nodes",
        json={"name": "persistent-node"},
    )
    assert create_response.status_code == 201

    list_response = TestClient(create_app_from_environment()).get("/api/v1/nodes")

    assert list_response.status_code == 200
    assert list_response.json()["count"] == 1
    assert list_response.json()["items"] == [create_response.json()]


def test_packaged_migration_runner_upgrades_an_empty_database(
    postgres_database_url: str,
) -> None:
    upgrade_database(postgres_database_url)

    engine = create_engine(postgres_database_url)
    with engine.connect() as connection:
        revision = connection.scalar(text("SELECT version_num FROM alembic_version"))
        table_count = connection.scalar(
            text(
                "SELECT count(*) FROM information_schema.tables "
                "WHERE table_schema = 'public' "
                "AND table_name IN ('media_nodes', 'cameras', 'audit_events', 'outbox_messages')"
            )
        )
    assert revision == "0005_node_runtime"
    assert table_count == 4


def test_management_freshness_migration_fails_closed_until_a_new_observation(
    postgres_database_url: str,
) -> None:
    migration = Config("alembic.ini")
    migration.set_main_option("sqlalchemy.url", postgres_database_url)
    command.upgrade(migration, "0003_audit_outbox_history")
    engine = create_engine(postgres_database_url)
    with engine.begin() as connection:
        connection.execute(
            text(
                """
                INSERT INTO media_nodes (
                    id, name, external_port, state, runtime_state, health,
                    registered_cameras, camera_capacity, active_sources,
                    maintenance, management_fresh, config_compatible,
                    desired_revision, applied_revision
                ) VALUES (
                    '00000000-0000-0000-0000-000000000001', 'stale', 12000,
                    'running', 'running', 'healthy', 0, 100, 0, false, true,
                    true, 1, 0
                )
                """
            )
        )

    command.upgrade(migration, "0004_management_freshness")

    with engine.connect() as connection:
        observation = connection.execute(
            text(
                "SELECT management_fresh, management_observed_at "
                "FROM media_nodes"
            )
        ).one()
    assert observation == (False, None)

    with pytest.raises(RuntimeError, match="requires an empty media_nodes registry"):
        command.upgrade(migration, "head")


def test_control_plane_refuses_to_start_on_an_older_database_revision(
    postgres_database_url: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    migration = Config("alembic.ini")
    migration.set_main_option("sqlalchemy.url", postgres_database_url)
    command.upgrade(migration, "0003_audit_outbox_history")
    monkeypatch.setenv("RTSP_PROXY_ROLE", "web")
    monkeypatch.setenv("RTSP_PROXY_DATABASE_URL", postgres_database_url)

    with pytest.raises(RuntimeError, match="database_schema_mismatch"):
        create_app_from_environment()


def test_schema_check_sanitizes_database_connection_failures() -> None:
    store = PostgresNodeStore(
        "postgresql+psycopg://postgres@127.0.0.1:1/unavailable",
        lifecycle_lock_timeout_seconds=0.1,
    )

    with pytest.raises(DatabaseSchemaMismatch, match="database_schema_mismatch"):
        store.assert_schema_compatible()


def test_control_plane_refuses_multiple_alembic_heads(
    postgres_database_url: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    upgrade_database(postgres_database_url)
    engine = create_engine(postgres_database_url)
    with engine.begin() as connection:
        connection.execute(
            text("INSERT INTO alembic_version (version_num) VALUES ('foreign_head')")
        )
    monkeypatch.setenv("RTSP_PROXY_ROLE", "web")
    monkeypatch.setenv("RTSP_PROXY_DATABASE_URL", postgres_database_url)

    with pytest.raises(RuntimeError, match="database_schema_mismatch"):
        create_app_from_environment()


def test_background_role_refuses_an_incompatible_database_revision(
    postgres_database_url: str,
) -> None:
    migration = Config("alembic.ini")
    migration.set_main_option("sqlalchemy.url", postgres_database_url)
    command.upgrade(migration, "0003_audit_outbox_history")

    with pytest.raises(RuntimeError, match="database_schema_mismatch"):
        create_background_app(
            Settings(
                role=RuntimeRole.RECONCILER,
                database_url=postgres_database_url,
            ),
            expected_role=RuntimeRole.RECONCILER,
        )


def test_node_creation_commits_desired_audit_and_outbox_in_one_transaction(
    postgres_database_url: str,
) -> None:
    migration = Config("alembic.ini")
    migration.set_main_option("sqlalchemy.url", postgres_database_url)
    command.upgrade(migration, "head")
    store = PostgresNodeStore(postgres_database_url)
    client = TestClient(
        create_app(
            Settings(
                role=RuntimeRole.WEB,
                node_port_range_start=12000,
                node_port_range_end=12000,
            ),
            node_control=NodeControl(
                store=store,
                choose_port=lambda available: available[0],
                new_node_id=lambda: UUID("00000000-0000-0000-0000-000000000001"),
            ),
        )
    )

    response = client.post("/api/v1/nodes", json={"name": "audited"})

    assert response.status_code == 201
    engine = create_engine(postgres_database_url)
    with engine.connect() as connection:
        audit = connection.execute(
            text(
                "SELECT aggregate_id, event_type, payload "
                "FROM audit_events ORDER BY occurred_at, id"
            )
        ).mappings().one()
        outbox = connection.execute(
            text(
                "SELECT aggregate_id, event_type, payload, status "
                "FROM outbox_messages ORDER BY occurred_at, id"
            )
        ).mappings().one()
        expected_payload = {
            "name": "audited",
            "external_port": 12000,
            "api_port": 20000,
            "metrics_port": 20100,
            "release_id": "v1.20.0",
            "creation_mode": "operator",
            "camera_capacity": 100,
            "desired_revision": 1,
        }
    assert audit == {
        "aggregate_id": UUID("00000000-0000-0000-0000-000000000001"),
        "event_type": "media_node.created",
        "payload": expected_payload,
    }
    assert outbox == {
        "aggregate_id": UUID("00000000-0000-0000-0000-000000000001"),
        "event_type": "media_node.created",
        "payload": expected_payload,
        "status": "pending",
    }


def test_node_start_commits_revisioned_desired_state_before_runtime_observation(
    postgres_database_url: str,
) -> None:
    upgrade_database(postgres_database_url)
    node_id = UUID("00000000-0000-0000-0000-000000000001")
    store = PostgresNodeStore(postgres_database_url)
    client = TestClient(
        create_app(
            Settings(
                role=RuntimeRole.WEB,
                node_port_range_start=12000,
                node_port_range_end=12000,
            ),
            node_control=NodeControl(
                store=store,
                choose_port=lambda available: available[0],
                new_node_id=lambda: node_id,
                node_runtime=StartingNodeRuntime(),
            ),
            shutdown=store.close,
        )
    )
    assert client.post("/api/v1/nodes", json={"name": "media-a"}).status_code == 201

    response = client.post(f"/api/v1/nodes/{node_id}/start")

    assert response.status_code == 200
    assert response.json()["state"] == "running"
    assert response.json()["runtime_state"] == "starting"
    assert response.json()["desired_revision"] == 2
    engine = create_engine(postgres_database_url)
    with engine.connect() as connection:
        events = connection.execute(
            text(
                "SELECT event_type, aggregate_revision FROM audit_events "
                "ORDER BY aggregate_revision"
            )
        ).tuples().all()
        outbox = connection.execute(
            text(
                "SELECT event_type, aggregate_revision FROM outbox_messages "
                "ORDER BY aggregate_revision"
            )
        ).tuples().all()
    assert events == [
        ("media_node.created", 1),
        ("media_node.desired_state_changed", 2),
    ]
    assert outbox == events


def test_node_registry_persists_the_canonical_stopping_state(
    postgres_database_url: str,
) -> None:
    upgrade_database(postgres_database_url)
    node_id = UUID("00000000-0000-0000-0000-000000000001")
    store = PostgresNodeStore(postgres_database_url)
    store.register_automatically(
        name="media-a",
        allowed_ports=(12000,),
        max_nodes=1,
        preferred_port=12000,
        choose_port=lambda available: available[0],
        new_node_id=lambda: node_id,
    )

    updated = store.request_desired_state(node_id, NodeState("stopping"))

    assert updated.state.value == "stopping"
    assert updated.desired_revision == 2
    assert store.get_node(node_id) == updated
    store.close()


def test_normative_mutation_forces_synchronous_durability(
    postgres_database_url: str,
) -> None:
    upgrade_database(postgres_database_url)
    engine = create_engine(postgres_database_url)
    with engine.begin() as connection:
        connection.execute(
            text(
                """
                CREATE FUNCTION reject_async_normative_write()
                RETURNS trigger AS $$
                BEGIN
                    IF current_setting('synchronous_commit') = 'off' THEN
                        RAISE EXCEPTION 'normative write is asynchronous';
                    END IF;
                    RETURN NEW;
                END;
                $$ LANGUAGE plpgsql
                """
            )
        )
        connection.execute(
            text(
                """
                CREATE TRIGGER audit_requires_sync
                BEFORE INSERT ON audit_events
                FOR EACH ROW EXECUTE FUNCTION reject_async_normative_write()
                """
            )
        )
    asynchronous_default_url = (
        postgres_database_url + "?options=-c%20synchronous_commit%3Doff"
    )
    store = PostgresNodeStore(asynchronous_default_url)
    client = TestClient(
        create_app(
            Settings(
                role=RuntimeRole.WEB,
                node_port_range_start=12000,
                node_port_range_end=12000,
            ),
            node_control=NodeControl(
                store=store,
                choose_port=lambda available: available[0],
                new_node_id=lambda: UUID("00000000-0000-0000-0000-000000000001"),
            ),
        ),
        raise_server_exceptions=False,
    )

    response = client.post("/api/v1/nodes", json={"name": "durable"})

    assert response.status_code == 201


def test_database_constraint_errors_never_render_camera_source_credentials(
    postgres_database_url: str,
) -> None:
    migration = Config("alembic.ini")
    migration.set_main_option("sqlalchemy.url", postgres_database_url)
    command.upgrade(migration, "head")
    store = PostgresNodeStore(postgres_database_url)
    node_id = UUID("00000000-0000-0000-0000-000000000001")
    store.register_automatically(
        name="media-a",
        allowed_ports=(12000,),
        max_nodes=1,
        preferred_port=12000,
        choose_port=lambda available: available[0],
        new_node_id=lambda: node_id,
    )
    store.request_desired_state(node_id, NodeState.RUNNING)
    store.apply_runtime_observation(
        node_id,
        NodeRuntimeObservation(
            state=NodeState.RUNNING,
            health=NodeHealth.HEALTHY,
            management_fresh=True,
            config_compatible=True,
            applied_revision=2,
            process_id=1001,
            process_start_ticks=2001,
            process_boot_id=UUID("20000000-0000-0000-0000-000000000001"),
            config_sha256="b" * 64,
            release_id="v1.20.0",
        ),
    )
    duplicate_public_id = "a" * 26
    store.place_camera_manually(
        camera_id=UUID("10000000-0000-0000-0000-000000000001"),
        name="first",
        source_url="rtsp://camera.local/main",
        public_id=PublicId.parse(duplicate_public_id),
        node_id=node_id,
    )

    with pytest.raises(IntegrityError) as captured:
        store.place_camera_manually(
            camera_id=UUID("10000000-0000-0000-0000-000000000002"),
            name="second",
            source_url="rtsp://camera.local/never-render-this",
            public_id=PublicId.parse(duplicate_public_id),
            node_id=node_id,
        )

    assert "never-render-this" not in str(captured.value)


def test_postgresql_adapter_rejects_credentialed_source_urls_if_called_directly(
    postgres_database_url: str,
) -> None:
    upgrade_database(postgres_database_url)
    store = PostgresNodeStore(postgres_database_url)
    node_id = UUID("00000000-0000-0000-0000-000000000001")
    store.register_automatically(
        name="media-a",
        allowed_ports=(12000,),
        max_nodes=1,
        preferred_port=12000,
        choose_port=lambda available: available[0],
        new_node_id=lambda: node_id,
    )
    store.apply_runtime_observation(
        node_id,
        NodeRuntimeObservation(
            state=NodeState.RUNNING,
            health=NodeHealth.HEALTHY,
            management_fresh=True,
            config_compatible=True,
            applied_revision=1,
            process_id=1001,
            process_start_ticks=2001,
            process_boot_id=UUID("20000000-0000-0000-0000-000000000001"),
            config_sha256="b" * 64,
            release_id="v1.20.0",
        ),
    )

    with pytest.raises(InvalidCameraSource):
        store.place_camera_manually(
            camera_id=UUID("10000000-0000-0000-0000-000000000001"),
            name="secret",
            source_url="rtsp://operator:never-store-this@camera.local/main",
            public_id=PublicId.parse("a" * 26),
            node_id=node_id,
        )

    assert store.list_cameras() == ()


def test_postgresql_release_transition_is_revisioned_and_audited(
    postgres_database_url: str,
) -> None:
    upgrade_database(postgres_database_url)
    store = PostgresNodeStore(postgres_database_url)
    node_id = UUID("00000000-0000-0000-0000-000000000001")
    store.register_automatically(
        name="media-a",
        allowed_ports=(12000,),
        max_nodes=1,
        preferred_port=12000,
        choose_port=lambda available: available[0],
        new_node_id=lambda: node_id,
    )
    running = store.request_desired_state(node_id, NodeState.RUNNING)
    store.apply_runtime_observation(
        node_id,
        NodeRuntimeObservation(
            state=NodeState.RUNNING,
            health=NodeHealth.HEALTHY,
            management_fresh=True,
            config_compatible=True,
            applied_revision=running.desired_revision,
            process_id=1001,
            process_start_ticks=2001,
            process_boot_id=UUID("20000000-0000-0000-0000-000000000001"),
            config_sha256="b" * 64,
            release_id=running.release_id,
        ),
    )
    stopping = store.request_desired_state(node_id, NodeState.STOPPED)
    store.apply_runtime_observation(
        node_id,
        NodeRuntimeObservation(
            state=NodeState.STOPPED,
            health=NodeHealth.UNKNOWN,
            config_compatible=True,
            applied_revision=stopping.desired_revision,
            config_sha256="b" * 64,
            release_id=stopping.release_id,
        ),
    )

    updated = store.request_release(
        node_id,
        release_id="release-2",
        mediamtx_binary_sha256="c" * 64,
    )

    assert updated.release_id == "release-2"
    assert updated.desired_revision == stopping.desired_revision + 1
    assert updated.applied_revision == 0
    assert updated.config_compatible is False
    engine = create_engine(postgres_database_url)
    with engine.connect() as connection:
        event = connection.execute(
            text(
                "SELECT event_type, payload FROM audit_events "
                "WHERE aggregate_id = :node_id AND event_type = :event_type"
            ),
            {"node_id": node_id, "event_type": "media_node.release_changed"},
        ).mappings().one()
    assert event["payload"]["release_id"] == "release-2"


def test_systemd_web_entrypoint_wires_the_persistent_node_control(
    postgres_database_url: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    migration = Config("alembic.ini")
    migration.set_main_option("sqlalchemy.url", postgres_database_url)
    command.upgrade(migration, "head")
    monkeypatch.setenv("RTSP_PROXY_ROLE", "web")
    monkeypatch.setenv("RTSP_PROXY_DATABASE_URL", postgres_database_url)
    monkeypatch.setenv("RTSP_PROXY_NODE_PORT_RANGE_START", "12000")
    monkeypatch.setenv("RTSP_PROXY_NODE_PORT_RANGE_END", "12002")
    launched: dict[str, object] = {}

    def capture_run(app: object, *, host: str, port: int) -> None:
        launched.update(app=app, host=host, port=port)

    monkeypatch.setattr("rtsp_proxy.runtime.uvicorn.run", capture_run)

    run_web()

    assert launched["host"] == "127.0.0.1"
    assert launched["port"] == 8000
    response = TestClient(cast(FastAPI, launched["app"])).post(
        "/api/v1/nodes",
        json={"name": "entrypoint-node"},
    )
    assert response.status_code == 201


def test_application_shutdown_closes_its_postgresql_pool(
    postgres_database_url: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    upgrade_database(postgres_database_url)
    monkeypatch.setenv("RTSP_PROXY_ROLE", "web")
    monkeypatch.setenv("RTSP_PROXY_DATABASE_URL", postgres_database_url)
    database_name = postgres_database_url.rsplit("/", 1)[1]
    admin_engine = create_engine(postgres_database_url.rsplit("/", 1)[0] + "/postgres")

    def application_connections() -> int:
        with admin_engine.connect() as connection:
            value = connection.scalar(
                text(
                    "SELECT count(*) FROM pg_stat_activity "
                    "WHERE datname = :database_name AND pid <> pg_backend_pid()"
                ),
                {"database_name": database_name},
            )
        assert value is not None
        return int(value)

    with TestClient(create_app_from_environment()) as client:
        assert client.get("/api/v1/nodes").status_code == 200
        assert application_connections() >= 1

    assert application_connections() == 0


def test_automatic_port_allocation_rejects_a_port_already_bound_on_the_server(
    postgres_database_url: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    migration = Config("alembic.ini")
    migration.set_main_option("sqlalchemy.url", postgres_database_url)
    command.upgrade(migration, "head")
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        occupied_port = int(listener.getsockname()[1])
        monkeypatch.setenv("RTSP_PROXY_ROLE", "web")
        monkeypatch.setenv("RTSP_PROXY_DATABASE_URL", postgres_database_url)
        monkeypatch.setenv("RTSP_PROXY_NODE_PORT_RANGE_START", str(occupied_port))
        monkeypatch.setenv("RTSP_PROXY_NODE_PORT_RANGE_END", str(occupied_port))

        response = TestClient(create_app_from_environment()).post(
            "/api/v1/nodes",
            json={"name": "cannot-bind"},
        )

    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "node_ports_exhausted"


def test_linux_port_probe_rejects_a_port_bound_only_on_ipv6() -> None:
    if not socket.has_ipv6:
        pytest.skip("IPv6 is not available")
    with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        try:
            listener.bind(("::", 0))
        except OSError:
            pytest.skip("IPv6 wildcard bind is not available")
        occupied_port = int(listener.getsockname()[1])

        assert tcp_port_is_bindable(occupied_port) is False


class SuccessfulNodeRuntime(NodeRuntime):
    def execute(
        self,
        action: NodeRuntimeAction,
        node: MediaNode,
    ) -> NodeRuntimeObservation:
        assert action in {
            NodeRuntimeAction.PROVISION_START,
            NodeRuntimeAction.START,
            NodeRuntimeAction.RESTART,
            NodeRuntimeAction.OBSERVE,
        }
        return NodeRuntimeObservation(
            state=NodeState.RUNNING,
            health=NodeHealth.HEALTHY,
            management_fresh=True,
            config_compatible=True,
            applied_revision=node.desired_revision,
            process_id=1001,
            process_start_ticks=2001,
            process_boot_id=UUID("20000000-0000-0000-0000-000000000001"),
            config_sha256="b" * 64,
            release_id=node.release_id,
        )


class StartingNodeRuntime(NodeRuntime):
    def execute(
        self,
        action: NodeRuntimeAction,
        node: MediaNode,
    ) -> NodeRuntimeObservation:
        assert action is NodeRuntimeAction.PROVISION_START
        assert node.state is NodeState.RUNNING
        assert node.desired_revision == 2
        return NodeRuntimeObservation(
            state=NodeState.STARTING,
            health=NodeHealth.UNKNOWN,
            management_fresh=False,
            config_compatible=False,
        )


def test_node_start_keeps_desired_and_observed_lifecycle_separate() -> None:
    control = NodeControl(
        store=InMemoryNodeStore(),
        choose_port=lambda available: available[0],
        new_node_id=lambda: UUID("00000000-0000-0000-0000-000000000001"),
        node_runtime=StartingNodeRuntime(),
    )
    client = TestClient(
        create_app(
            Settings(
                role=RuntimeRole.WEB,
                node_port_range_start=12000,
                node_port_range_end=12002,
            ),
            node_control=control,
        )
    )
    created = client.post("/api/v1/nodes", json={"name": "media-a"}).json()

    response = client.post(f"/api/v1/nodes/{created['id']}/start")

    assert response.status_code == 200
    assert response.json() == {
        **created,
        "state": "running",
        "runtime_state": "starting",
        "desired_revision": 2,
    }


def test_operator_can_start_a_registered_node_through_the_linux_runtime_boundary() -> None:
    control = NodeControl(
        store=InMemoryNodeStore(),
        choose_port=lambda available: available[0],
        new_node_id=lambda: UUID("00000000-0000-0000-0000-000000000001"),
        node_runtime=SuccessfulNodeRuntime(),
    )
    client = TestClient(
        create_app(
            Settings(
                role=RuntimeRole.WEB,
                node_port_range_start=12000,
                node_port_range_end=12002,
            ),
            node_control=control,
        )
    )
    created = client.post("/api/v1/nodes", json={"name": "media-a"}).json()

    response = client.post(f"/api/v1/nodes/{created['id']}/start")

    assert response.status_code == 200
    assert response.json() == {
        **created,
        "state": "running",
        "runtime_state": "running",
        "health": "healthy",
        "desired_revision": 2,
        "applied_revision": 2,
    }


class RecordingLifecycleRuntime(NodeRuntime):
    def __init__(self) -> None:
        self.calls: list[tuple[NodeRuntimeAction, UUID]] = []

    def execute(
        self,
        action: NodeRuntimeAction,
        node: MediaNode,
    ) -> NodeRuntimeObservation:
        self.calls.append((action, node.id))
        if action is NodeRuntimeAction.STOP:
            return NodeRuntimeObservation(
                state=NodeState.STOPPED,
                health=NodeHealth.UNKNOWN,
                config_compatible=True,
                applied_revision=node.desired_revision,
                config_sha256="c" * 64,
                release_id=node.release_id,
            )
        return NodeRuntimeObservation(
            state=NodeState.RUNNING,
            health=NodeHealth.HEALTHY,
            management_fresh=True,
            config_compatible=True,
            applied_revision=node.desired_revision,
            process_id=3000 + len(self.calls),
            process_start_ticks=4000 + len(self.calls),
            process_boot_id=UUID("30000000-0000-0000-0000-000000000001"),
            config_sha256="c" * 64,
            release_id=node.release_id,
        )


def test_node_create_can_complete_provision_start_and_persist_applied_revision() -> None:
    runtime = RecordingLifecycleRuntime()
    node_id = UUID("00000000-0000-0000-0000-000000000001")
    control = NodeControl(
        store=InMemoryNodeStore(),
        choose_port=lambda available: available[0],
        new_node_id=lambda: node_id,
        node_runtime=runtime,
        provision_on_create=True,
    )
    client = TestClient(
        create_app(
            Settings(
                role=RuntimeRole.WEB,
                node_port_range_start=12000,
                node_port_range_end=12000,
            ),
            node_control=control,
        )
    )

    response = client.post("/api/v1/nodes", json={"name": "media-a"})

    assert response.status_code == 201
    assert response.json()["state"] == "running"
    assert response.json()["runtime_state"] == "running"
    assert response.json()["desired_revision"] == 2
    assert response.json()["applied_revision"] == 2
    assert runtime.calls == [(NodeRuntimeAction.PROVISION_START, node_id)]
    persisted = control.list_nodes()[0]
    assert persisted.process_id == 3001
    assert persisted.observed_release_id == "v1.20.0"


def test_stop_and_restart_only_execute_the_selected_node_identity() -> None:
    node_ids = iter(
        (
            UUID("00000000-0000-0000-0000-000000000001"),
            UUID("00000000-0000-0000-0000-000000000002"),
        )
    )
    runtime = RecordingLifecycleRuntime()
    control = NodeControl(
        store=InMemoryNodeStore(),
        choose_port=lambda available: available[0],
        new_node_id=lambda: next(node_ids),
        node_runtime=runtime,
        provision_on_create=True,
    )
    client = TestClient(
        create_app(
            Settings(
                role=RuntimeRole.WEB,
                max_nodes=2,
                node_port_range_start=12000,
                node_port_range_end=12001,
            ),
            node_control=control,
        )
    )
    first = client.post("/api/v1/nodes", json={"name": "media-a"}).json()
    second = client.post("/api/v1/nodes", json={"name": "media-b"}).json()
    first_id = UUID(first["id"])
    second_id = UUID(second["id"])
    before_second = control.list_nodes()[1]

    restarted = client.post(f"/api/v1/nodes/{first_id}/restart")
    stopped = client.post(f"/api/v1/nodes/{first_id}/stop")

    assert restarted.status_code == 200
    assert restarted.json()["desired_revision"] == 3
    assert restarted.json()["applied_revision"] == 3
    assert stopped.status_code == 200
    assert stopped.json()["runtime_state"] == "stopped"
    assert runtime.calls == [
        (NodeRuntimeAction.PROVISION_START, first_id),
        (NodeRuntimeAction.PROVISION_START, second_id),
        (NodeRuntimeAction.RESTART, first_id),
        (NodeRuntimeAction.STOP, first_id),
    ]
    after_second = next(node for node in control.list_nodes() if node.id == second_id)
    assert after_second == before_second


def test_operator_updates_release_only_after_empty_stopped_convergence() -> None:
    node_id = UUID("00000000-0000-0000-0000-000000000001")
    runtime = RecordingLifecycleRuntime()
    control = NodeControl(
        store=InMemoryNodeStore(),
        choose_port=lambda available: available[0],
        new_node_id=lambda: node_id,
        node_runtime=runtime,
        provision_on_create=True,
    )
    client = TestClient(
        create_app(
            Settings(role=RuntimeRole.WEB),
            node_control=control,
        )
    )
    created = client.post("/api/v1/nodes", json={"name": "media-a"}).json()

    release_client = TestClient(
        create_app(
            Settings(
                role=RuntimeRole.WEB,
                node_release_id="release-2",
                node_mediamtx_binary_sha256="b" * 64,
            ),
            node_control=control,
        )
    )
    running = release_client.put(
        f"/api/v1/nodes/{node_id}/release",
        json={"release_id": "release-2", "mediamtx_binary_sha256": "b" * 64},
    )
    stopped = client.post(f"/api/v1/nodes/{node_id}/stop")
    updated = release_client.put(
        f"/api/v1/nodes/{node_id}/release",
        json={"release_id": "release-2", "mediamtx_binary_sha256": "b" * 64},
    )

    assert running.status_code == 409
    assert stopped.status_code == 200
    assert updated.status_code == 200
    assert updated.json()["desired_revision"] == created["desired_revision"] + 2
    assert updated.json()["applied_revision"] == 0
    persisted = control.list_nodes()[0]
    assert persisted.release_id == "release-2"
    assert persisted.mediamtx_binary_sha256 == "b" * 64
    assert persisted.config_compatible is False


class FailingNodeRuntime(NodeRuntime):
    def execute(
        self,
        action: NodeRuntimeAction,
        node: MediaNode,
    ) -> NodeRuntimeObservation:
        raise RuntimeError("must not escape")


def test_failed_provisioning_keeps_a_failed_node_and_returns_only_a_typed_error() -> None:
    node_id = UUID("00000000-0000-0000-0000-000000000001")
    control = NodeControl(
        store=InMemoryNodeStore(),
        choose_port=lambda available: available[0],
        new_node_id=lambda: node_id,
        node_runtime=FailingNodeRuntime(),
        provision_on_create=True,
    )
    client = TestClient(
        create_app(
            Settings(
                role=RuntimeRole.WEB,
                node_port_range_start=12000,
                node_port_range_end=12000,
            ),
            node_control=control,
        ),
        raise_server_exceptions=False,
    )

    response = client.post("/api/v1/nodes", json={"name": "broken"})

    assert response.status_code == 503
    assert response.json() == {
        "detail": {
            "code": "node_runtime_operation_failed",
            "node_id": str(node_id),
        }
    }
    persisted = control.list_nodes()
    assert len(persisted) == 1
    assert persisted[0].state is NodeState.RUNNING
    assert persisted[0].runtime_state is NodeState.FAILED
    assert persisted[0].health is NodeHealth.UNHEALTHY


def automatic_policy(*, max_nodes: int = 50) -> NodeProvisioningPolicy:
    return NodeProvisioningPolicy(
        port_range_start=12000,
        port_range_end=12009,
        max_nodes=max_nodes,
        reserved_ports=(),
        api_ports=tuple(range(13000, 13010)),
        metrics_ports=tuple(range(14000, 14010)),
        release_id="v1.20.0",
        mediamtx_binary_sha256="0" * 64,
    )


def test_automatic_camera_creation_provisions_before_committing_placement() -> None:
    runtime = RecordingLifecycleRuntime()
    node_id = UUID("00000000-0000-0000-0000-000000000001")
    store = InMemoryNodeStore()
    node_control = NodeControl(
        store=store,
        choose_port=lambda available: available[0],
        new_node_id=lambda: node_id,
        node_runtime=runtime,
    )
    camera_control = CameraControl(
        store=store,
        new_camera_id=lambda: UUID("10000000-0000-0000-0000-000000000001"),
        new_public_id=lambda: "a234567a234567a234567a2344",
        ensure_automatic_capacity=lambda: node_control.ensure_automatic_capacity(
            automatic_policy()
        ),
    )
    client = TestClient(
        create_app(
            Settings(role=RuntimeRole.WEB),
            node_control=node_control,
            camera_control=camera_control,
        )
    )

    response = client.post(
        "/api/v1/cameras",
        json={"name": "entrance", "source_url": "rtsp://camera.local/main"},
    )

    assert response.status_code == 201
    assert response.json()["node_id"] == str(node_id)
    assert runtime.calls == [(NodeRuntimeAction.PROVISION_START, node_id)]
    assert node_control.list_nodes()[0].runtime_state is NodeState.RUNNING
    assert node_control.list_nodes()[0].registered_cameras == 1


def test_failed_automatic_provisioning_commits_no_camera_or_placement() -> None:
    node_id = UUID("00000000-0000-0000-0000-000000000001")
    store = InMemoryNodeStore()
    node_control = NodeControl(
        store=store,
        choose_port=lambda available: available[0],
        new_node_id=lambda: node_id,
        node_runtime=FailingNodeRuntime(),
    )
    camera_control = CameraControl(
        store=store,
        new_camera_id=lambda: UUID("10000000-0000-0000-0000-000000000001"),
        new_public_id=lambda: "a234567a234567a234567a2344",
        ensure_automatic_capacity=lambda: node_control.ensure_automatic_capacity(
            automatic_policy()
        ),
    )
    client = TestClient(
        create_app(
            Settings(role=RuntimeRole.WEB),
            node_control=node_control,
            camera_control=camera_control,
        ),
        raise_server_exceptions=False,
    )

    response = client.post(
        "/api/v1/cameras",
        json={"name": "entrance", "source_url": "rtsp://camera.local/main"},
    )

    assert response.status_code == 503
    assert response.json()["detail"] == {
        "code": "node_runtime_operation_failed",
        "node_id": str(node_id),
    }
    assert camera_control.list_cameras() == ()
    assert len(node_control.list_nodes()) == 1
    assert node_control.list_nodes()[0].runtime_state is NodeState.FAILED


def test_concurrent_automatic_cameras_share_one_provisioned_node() -> None:
    runtime = RecordingLifecycleRuntime()
    node_ids = iter(
        (
            UUID("00000000-0000-0000-0000-000000000001"),
            UUID("00000000-0000-0000-0000-000000000002"),
        )
    )
    store = InMemoryNodeStore()
    node_control = NodeControl(
        store=store,
        choose_port=lambda available: available[0],
        new_node_id=lambda: next(node_ids),
        node_runtime=runtime,
    )
    camera_control = CameraControl(
        store=store,
        new_camera_id=uuid4,
        new_public_id=generate_public_id,
        ensure_automatic_capacity=lambda: node_control.ensure_automatic_capacity(
            automatic_policy()
        ),
    )
    client = TestClient(
        create_app(
            Settings(role=RuntimeRole.WEB),
            node_control=node_control,
            camera_control=camera_control,
        )
    )
    barrier = Barrier(2)

    def create_camera(index: int) -> Response:
        barrier.wait()
        return client.post(
            "/api/v1/cameras",
            json={
                "name": f"camera-{index}",
                "source_url": f"rtsp://camera-{index}.local/main",
            },
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        responses = tuple(executor.map(create_camera, range(2)))

    assert [response.status_code for response in responses] == [201, 201]
    assert len(node_control.list_nodes()) == 1
    assert node_control.list_nodes()[0].registered_cameras == 2
    assert camera_control.list_cameras()[0].node_id == camera_control.list_cameras()[1].node_id
    assert runtime.calls == [
        (
            NodeRuntimeAction.PROVISION_START,
            UUID("00000000-0000-0000-0000-000000000001"),
        )
    ]


def test_postgresql_serializes_cross_request_automatic_provisioning(
    postgres_database_url: str,
) -> None:
    upgrade_database(postgres_database_url)
    node_ids = iter(
        (
            UUID("00000000-0000-0000-0000-000000000001"),
            UUID("00000000-0000-0000-0000-000000000002"),
        )
    )
    runtime = RecordingLifecycleRuntime()
    store = PostgresNodeStore(postgres_database_url)
    node_control = NodeControl(
        store=store,
        choose_port=lambda available: available[0],
        new_node_id=lambda: next(node_ids),
        node_runtime=runtime,
        is_port_bindable=lambda port: True,
    )
    camera_control = CameraControl(
        store=store,
        new_camera_id=uuid4,
        new_public_id=generate_public_id,
        ensure_automatic_capacity=lambda: node_control.ensure_automatic_capacity(
            automatic_policy()
        ),
    )
    client = TestClient(
        create_app(
            Settings(role=RuntimeRole.WEB),
            node_control=node_control,
            camera_control=camera_control,
            shutdown=store.close,
        )
    )
    barrier = Barrier(2)

    def create_camera(index: int) -> Response:
        barrier.wait()
        return client.post(
            "/api/v1/cameras",
            json={
                "name": f"camera-{index}",
                "source_url": f"rtsp://camera-{index}.local/main",
            },
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        responses = tuple(executor.map(create_camera, range(2)))

    assert [response.status_code for response in responses] == [201, 201]
    assert len(store.list_nodes()) == 1
    assert store.list_nodes()[0].registered_cameras == 2
    assert len(store.list_cameras()) == 2
    assert runtime.calls == [
        (
            NodeRuntimeAction.PROVISION_START,
            UUID("00000000-0000-0000-0000-000000000001"),
        )
    ]


def test_application_startup_recovers_persisted_runtime_identity() -> None:
    node_id = UUID("00000000-0000-0000-0000-000000000001")
    store = InMemoryNodeStore(
        nodes=(
            MediaNode(
                id=node_id,
                name="recover-me",
                external_port=12000,
                state=NodeState.RUNNING,
                runtime_state=NodeState.FAILED,
                health=NodeHealth.UNHEALTHY,
                desired_revision=2,
            ),
        )
    )
    runtime = RecordingLifecycleRuntime()
    node_control = NodeControl(
        store=store,
        choose_port=lambda available: available[0],
        new_node_id=uuid4,
        node_runtime=runtime,
    )

    def recover() -> None:
        node_control.recover_runtime_state()

    app = create_app(
        Settings(role=RuntimeRole.WEB),
        node_control=node_control,
        startup=recover,
    )

    with TestClient(app) as client:
        response = client.get("/api/v1/nodes")

    assert response.status_code == 200
    assert response.json()["items"][0]["runtime_state"] == "running"
    assert response.json()["items"][0]["applied_revision"] == 2
    assert runtime.calls == [(NodeRuntimeAction.OBSERVE, node_id)]


def test_application_startup_starts_a_persisted_running_node_after_host_reboot() -> None:
    node_id = UUID("00000000-0000-0000-0000-000000000001")
    store = InMemoryNodeStore(
        nodes=(
            MediaNode(
                id=node_id,
                name="recover-me",
                external_port=12000,
                state=NodeState.RUNNING,
                runtime_state=NodeState.STOPPED,
                health=NodeHealth.UNKNOWN,
                config_compatible=True,
                desired_revision=2,
                applied_revision=2,
            ),
        )
    )

    class RebootRuntime(RecordingLifecycleRuntime):
        def execute(
            self,
            action: NodeRuntimeAction,
            node: MediaNode,
        ) -> NodeRuntimeObservation:
            if action is NodeRuntimeAction.OBSERVE:
                self.calls.append((action, node.id))
                return NodeRuntimeObservation(
                    state=NodeState.STOPPED,
                    health=NodeHealth.UNKNOWN,
                    config_compatible=True,
                    applied_revision=node.desired_revision,
                    config_sha256="c" * 64,
                    release_id=node.release_id,
                )
            return super().execute(action, node)

    runtime = RebootRuntime()
    control = NodeControl(
        store=store,
        choose_port=lambda available: available[0],
        new_node_id=uuid4,
        node_runtime=runtime,
    )

    recovered = control.recover_runtime_state()

    assert recovered[0].runtime_state is NodeState.RUNNING
    assert runtime.calls == [
        (NodeRuntimeAction.OBSERVE, node_id),
        (NodeRuntimeAction.START, node_id),
    ]


def test_startup_recovery_isolates_a_failed_node_and_continues_other_nodes() -> None:
    first = UUID("00000000-0000-0000-0000-000000000001")
    second = UUID("00000000-0000-0000-0000-000000000002")
    store = InMemoryNodeStore(
        nodes=(
            MediaNode(id=first, name="broken", external_port=12000),
            MediaNode(id=second, name="healthy", external_port=12001),
        )
    )

    class PartiallyFailingRuntime(NodeRuntime):
        def execute(
            self,
            action: NodeRuntimeAction,
            node: MediaNode,
        ) -> NodeRuntimeObservation:
            if node.id == first:
                raise RuntimeError("transient probe failure")
            return RecordingLifecycleRuntime().execute(action, node)

    control = NodeControl(
        store=store,
        choose_port=lambda available: available[0],
        new_node_id=uuid4,
        node_runtime=PartiallyFailingRuntime(),
    )

    recovered = control.recover_runtime_state()

    assert [node.id for node in recovered] == [first, second]
    assert recovered[0].runtime_state is NodeState.FAILED
    assert recovered[1].runtime_state is NodeState.RUNNING


def test_startup_recovery_converges_a_healthy_node_while_another_is_slow() -> None:
    slow = UUID("00000000-0000-0000-0000-000000000001")
    healthy = UUID("00000000-0000-0000-0000-000000000002")
    slow_entered = Event()
    release_slow = Event()
    healthy_observed = Event()
    store = InMemoryNodeStore(
        nodes=(
            MediaNode(id=slow, name="slow", external_port=12000),
            MediaNode(id=healthy, name="healthy", external_port=12001),
        )
    )

    class SlowAndHealthyRuntime(RecordingLifecycleRuntime):
        def execute(
            self,
            action: NodeRuntimeAction,
            node: MediaNode,
        ) -> NodeRuntimeObservation:
            if node.id == slow:
                slow_entered.set()
                assert release_slow.wait(timeout=5)
            else:
                healthy_observed.set()
            return super().execute(action, node)

    control = NodeControl(
        store=store,
        choose_port=lambda available: available[0],
        new_node_id=uuid4,
        node_runtime=SlowAndHealthyRuntime(),
        recovery_workers=2,
    )

    with ThreadPoolExecutor(max_workers=1) as executor:
        recovery = executor.submit(control.recover_runtime_state)
        assert slow_entered.wait(timeout=1)
        assert healthy_observed.wait(timeout=1)
        release_slow.set()
        recovered = recovery.result(timeout=2)

    assert [node.id for node in recovered] == [slow, healthy]


def test_startup_recovery_rechecks_operator_intent_after_its_initial_snapshot() -> None:
    node_id = UUID("00000000-0000-0000-0000-000000000001")
    snapshot_taken = Event()
    release_snapshot = Event()

    class PausingStore(InMemoryNodeStore):
        def list_nodes(self) -> tuple[MediaNode, ...]:
            nodes = super().list_nodes()
            if not snapshot_taken.is_set():
                snapshot_taken.set()
                assert release_snapshot.wait(timeout=5)
            return nodes

    class StatefulRuntime(NodeRuntime):
        def __init__(self) -> None:
            self.active = True
            self.calls: list[NodeRuntimeAction] = []

        def execute(
            self,
            action: NodeRuntimeAction,
            node: MediaNode,
        ) -> NodeRuntimeObservation:
            self.calls.append(action)
            if action is NodeRuntimeAction.STOP:
                self.active = False
            elif action in {
                NodeRuntimeAction.PROVISION_START,
                NodeRuntimeAction.START,
                NodeRuntimeAction.RESTART,
            }:
                self.active = True
            if not self.active:
                return NodeRuntimeObservation(
                    state=NodeState.STOPPED,
                    health=NodeHealth.UNKNOWN,
                    config_compatible=True,
                    applied_revision=node.desired_revision,
                    config_sha256="c" * 64,
                    release_id=node.release_id,
                )
            return SuccessfulNodeRuntime().execute(NodeRuntimeAction.OBSERVE, node)

    runtime = StatefulRuntime()
    store = PausingStore(
        nodes=(
            MediaNode(
                id=node_id,
                name="operator-wins",
                external_port=12000,
                state=NodeState.RUNNING,
                runtime_state=NodeState.RUNNING,
                health=NodeHealth.HEALTHY,
                desired_revision=2,
                applied_revision=2,
            ),
        )
    )
    control = NodeControl(
        store=store,
        choose_port=lambda available: available[0],
        new_node_id=uuid4,
        node_runtime=runtime,
    )

    with ThreadPoolExecutor(max_workers=1) as executor:
        recovery = executor.submit(control.recover_runtime_state)
        assert snapshot_taken.wait(timeout=1)
        stopped = control.stop_node(node_id)
        release_snapshot.set()
        recovered = recovery.result(timeout=2)

    assert stopped.state is NodeState.STOPPED
    assert recovered[0].state is NodeState.STOPPED
    assert recovered[0].runtime_state is NodeState.STOPPED
    assert runtime.calls == [NodeRuntimeAction.STOP, NodeRuntimeAction.OBSERVE]


@pytest.mark.parametrize("operation", ("start", "stop", "restart", "observe"))
def test_lifecycle_commands_fail_closed_without_the_privileged_runtime(
    operation: str,
) -> None:
    node_id = UUID("00000000-0000-0000-0000-000000000001")
    control = NodeControl(
        store=InMemoryNodeStore(),
        choose_port=lambda available: available[0],
        new_node_id=lambda: node_id,
    )
    client = TestClient(
        create_app(
            Settings(role=RuntimeRole.WEB),
            node_control=control,
        )
    )
    assert client.post("/api/v1/nodes", json={"name": "media-a"}).status_code == 201

    response = client.post(f"/api/v1/nodes/{node_id}/{operation}")

    assert response.status_code == 503
    assert response.json()["detail"]["code"] == "node_runtime_unavailable"


@pytest.mark.parametrize("operation", ("start", "stop", "restart", "observe"))
def test_lifecycle_commands_report_an_unknown_exact_node(operation: str) -> None:
    control = NodeControl(
        store=InMemoryNodeStore(),
        choose_port=lambda available: available[0],
        new_node_id=uuid4,
        node_runtime=RecordingLifecycleRuntime(),
    )
    client = TestClient(
        create_app(Settings(role=RuntimeRole.WEB), node_control=control)
    )

    response = client.post(
        f"/api/v1/nodes/00000000-0000-0000-0000-000000000099/{operation}"
    )

    assert response.status_code == 404
    assert response.json()["detail"]["code"] == "node_not_found"


def test_restart_requires_a_running_desired_node() -> None:
    node_id = UUID("00000000-0000-0000-0000-000000000001")
    control = NodeControl(
        store=InMemoryNodeStore(),
        choose_port=lambda available: available[0],
        new_node_id=lambda: node_id,
        node_runtime=RecordingLifecycleRuntime(),
    )
    client = TestClient(
        create_app(Settings(role=RuntimeRole.WEB), node_control=control)
    )
    assert client.post("/api/v1/nodes", json={"name": "media-a"}).status_code == 201

    response = client.post(f"/api/v1/nodes/{node_id}/restart")

    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "node_not_running"


@pytest.mark.parametrize("operation", ("start", "stop", "restart", "observe"))
def test_lifecycle_lock_contention_is_a_retryable_public_error(operation: str) -> None:
    node_id = UUID("00000000-0000-0000-0000-000000000001")

    class BusyStore(InMemoryNodeStore):
        @contextmanager
        def lifecycle_guard(self, node_id: UUID) -> Iterator[None]:
            raise NodeLifecycleBusy("node_lifecycle_busy")
            yield

    client = TestClient(
        create_app(
            Settings(role=RuntimeRole.WEB),
            node_control=NodeControl(
                store=BusyStore(
                    nodes=(MediaNode(id=node_id, name="busy", external_port=12000),)
                ),
                choose_port=lambda available: available[0],
                new_node_id=uuid4,
                node_runtime=RecordingLifecycleRuntime(),
            ),
        ),
        raise_server_exceptions=False,
    )

    response = client.post(f"/api/v1/nodes/{node_id}/{operation}")

    assert response.status_code == 503
    assert response.json()["detail"] == {"code": "node_lifecycle_busy"}


def test_release_lock_contention_is_a_retryable_public_error() -> None:
    node_id = UUID("00000000-0000-0000-0000-000000000001")

    class BusyStore(InMemoryNodeStore):
        @contextmanager
        def lifecycle_guard(self, node_id: UUID) -> Iterator[None]:
            raise NodeLifecycleBusy("node_lifecycle_busy")
            yield

    client = TestClient(
        create_app(
            Settings(
                role=RuntimeRole.WEB,
                node_release_id="release-2",
                node_mediamtx_binary_sha256="b" * 64,
            ),
            node_control=NodeControl(
                store=BusyStore(
                    nodes=(MediaNode(id=node_id, name="busy", external_port=12000),)
                ),
                choose_port=lambda available: available[0],
                new_node_id=uuid4,
                node_runtime=RecordingLifecycleRuntime(),
            ),
        ),
        raise_server_exceptions=False,
    )

    response = client.put(
        f"/api/v1/nodes/{node_id}/release",
        json={"release_id": "release-2", "mediamtx_binary_sha256": "b" * 64},
    )

    assert response.status_code == 503
    assert response.json()["detail"] == {"code": "node_lifecycle_busy"}


def test_automatic_capacity_lock_contention_is_a_retryable_public_error() -> None:
    def busy_capacity() -> MediaNode:
        raise NodeLifecycleBusy("node_lifecycle_busy")

    client = TestClient(
        create_app(
            Settings(role=RuntimeRole.WEB),
            camera_control=CameraControl(
                store=InMemoryNodeStore(),
                new_camera_id=uuid4,
                new_public_id=generate_public_id,
                ensure_automatic_capacity=busy_capacity,
            ),
        ),
        raise_server_exceptions=False,
    )

    response = client.post(
        "/api/v1/cameras",
        json={"name": "busy", "source_url": "rtsp://camera.local/main"},
    )

    assert response.status_code == 503
    assert response.json()["detail"] == {"code": "node_lifecycle_busy"}


def test_stop_requires_an_empty_node_until_the_drain_phase() -> None:
    node_id = UUID("00000000-0000-0000-0000-000000000001")
    control = NodeControl(
        store=InMemoryNodeStore(
            nodes=(
                MediaNode(
                    id=node_id,
                    name="occupied",
                    external_port=12000,
                    state=NodeState.RUNNING,
                    runtime_state=NodeState.RUNNING,
                    registered_cameras=1,
                ),
            )
        ),
        choose_port=lambda available: available[0],
        new_node_id=uuid4,
        node_runtime=RecordingLifecycleRuntime(),
    )
    client = TestClient(
        create_app(Settings(role=RuntimeRole.WEB), node_control=control)
    )

    response = client.post(f"/api/v1/nodes/{node_id}/stop")

    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "node_not_empty"


def test_restart_requires_an_empty_node_until_the_drain_phase() -> None:
    node_id = UUID("00000000-0000-0000-0000-000000000001")
    control = NodeControl(
        store=InMemoryNodeStore(
            nodes=(
                MediaNode(
                    id=node_id,
                    name="occupied",
                    external_port=12000,
                    state=NodeState.RUNNING,
                    runtime_state=NodeState.RUNNING,
                    registered_cameras=1,
                ),
            )
        ),
        choose_port=lambda available: available[0],
        new_node_id=uuid4,
        node_runtime=RecordingLifecycleRuntime(),
    )
    client = TestClient(
        create_app(Settings(role=RuntimeRole.WEB), node_control=control)
    )

    response = client.post(f"/api/v1/nodes/{node_id}/restart")

    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "node_not_empty"


def test_concurrent_lifecycle_commands_serialize_process_and_revision() -> None:
    node_id = UUID("00000000-0000-0000-0000-000000000001")
    store = InMemoryNodeStore(
        nodes=(
            MediaNode(
                id=node_id,
                name="media-a",
                external_port=12000,
                state=NodeState.STOPPED,
                runtime_state=NodeState.STOPPED,
            ),
        )
    )
    first_started = Event()
    release_first = Event()
    calls: list[NodeRuntimeAction] = []
    calls_lock = Lock()

    class BlockingRuntime(NodeRuntime):
        def execute(
            self,
            action: NodeRuntimeAction,
            node: MediaNode,
        ) -> NodeRuntimeObservation:
            with calls_lock:
                calls.append(action)
            if action is NodeRuntimeAction.PROVISION_START:
                first_started.set()
                assert release_first.wait(timeout=2)
                return RecordingLifecycleRuntime().execute(action, node)
            return RecordingLifecycleRuntime().execute(action, node)

    control = NodeControl(
        store=store,
        choose_port=lambda available: available[0],
        new_node_id=uuid4,
        node_runtime=BlockingRuntime(),
    )

    with ThreadPoolExecutor(max_workers=2) as executor:
        start_future = executor.submit(control.start_node, node_id)
        assert first_started.wait(timeout=1)
        stop_future = executor.submit(control.stop_node, node_id)
        time.sleep(0.05)
        assert calls == [NodeRuntimeAction.PROVISION_START]
        release_first.set()
        started = start_future.result(timeout=2)
        stopped = stop_future.result(timeout=2)

    assert started.desired_revision == 2
    assert stopped.desired_revision == 3
    assert stopped.runtime_state is NodeState.STOPPED
    assert calls == [NodeRuntimeAction.PROVISION_START, NodeRuntimeAction.STOP]


@pytest.mark.parametrize("operation", ("start", "stop", "restart", "observe"))
def test_lifecycle_runtime_failures_return_a_sanitized_node_scoped_error(
    operation: str,
) -> None:
    node_id = UUID("00000000-0000-0000-0000-000000000001")
    control = NodeControl(
        store=InMemoryNodeStore(
            nodes=(
                MediaNode(
                    id=node_id,
                    name="broken",
                    external_port=12000,
                    state=NodeState.RUNNING,
                    runtime_state=NodeState.FAILED,
                    desired_revision=2,
                    applied_revision=1,
                ),
            )
        ),
        choose_port=lambda available: available[0],
        new_node_id=uuid4,
        node_runtime=FailingNodeRuntime(),
    )
    client = TestClient(
        create_app(Settings(role=RuntimeRole.WEB), node_control=control),
        raise_server_exceptions=False,
    )

    response = client.post(f"/api/v1/nodes/{node_id}/{operation}")

    assert response.status_code == 503
    assert response.json()["detail"] == {
        "code": "node_runtime_operation_failed",
        "node_id": str(node_id),
    }


def test_camera_placement_survives_control_application_restart(
    postgres_database_url: str,
) -> None:
    migration = Config("alembic.ini")
    migration.set_main_option("sqlalchemy.url", postgres_database_url)
    command.upgrade(migration, "head")
    node_id = UUID("00000000-0000-0000-0000-000000000001")
    first_store = PostgresNodeStore(postgres_database_url)
    node_control = NodeControl(
        store=first_store,
        choose_port=lambda available: available[0],
        new_node_id=lambda: node_id,
        node_runtime=SuccessfulNodeRuntime(),
    )
    camera_control = CameraControl(
        store=first_store,
        new_camera_id=lambda: UUID("10000000-0000-0000-0000-000000000001"),
        new_public_id=lambda: "d234567d234567d234567d2344",
    )
    first_client = TestClient(
        create_app(
            Settings(
                role=RuntimeRole.WEB,
                node_port_range_start=12000,
                node_port_range_end=12002,
            ),
            node_control=node_control,
            camera_control=camera_control,
        )
    )
    assert first_client.post("/api/v1/nodes", json={"name": "media-a"}).status_code == 201
    assert first_client.post(f"/api/v1/nodes/{node_id}/start").status_code == 200
    created = first_client.post(
        "/api/v1/cameras",
        json={"name": "entrance", "source_url": "rtsp://camera.local/main"},
    )
    assert created.status_code == 201

    second_store = PostgresNodeStore(postgres_database_url)
    second_client = TestClient(
        create_app(
            Settings(role=RuntimeRole.WEB),
            camera_control=CameraControl(
                store=second_store,
                new_camera_id=lambda: UUID("10000000-0000-0000-0000-000000000002"),
                new_public_id=lambda: "e234567e234567e234567e2344",
            ),
        )
    )
    response = second_client.get("/api/v1/cameras")

    assert response.status_code == 200
    assert response.json() == {"items": [created.json()], "count": 1}


def test_postgresql_placement_expires_a_stale_management_observation(
    postgres_database_url: str,
) -> None:
    upgrade_database(postgres_database_url)
    store = PostgresNodeStore(postgres_database_url)
    node_id = UUID("00000000-0000-0000-0000-000000000001")
    with TestClient(
        create_app(
            Settings(role=RuntimeRole.WEB),
            node_control=NodeControl(
                store=store,
                choose_port=lambda available: available[0],
                new_node_id=lambda: node_id,
                node_runtime=SuccessfulNodeRuntime(),
            ),
            camera_control=CameraControl(
                store=store,
                new_camera_id=uuid4,
                new_public_id=generate_public_id,
                management_freshness_seconds=1,
            ),
            shutdown=store.close,
        )
    ) as client:
        assert client.post("/api/v1/nodes", json={"name": "media-a"}).status_code == 201
        assert client.post(f"/api/v1/nodes/{node_id}/start").status_code == 200
        time.sleep(1.1)

        response = client.post(
            "/api/v1/cameras",
            json={
                "name": "camera-a",
                "source_url": "rtsp://camera.local/main",
            },
        )

    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "eligible_node_missing"


def test_automatic_camera_placement_does_not_commit_before_node_provisioning() -> None:
    full_node = MediaNode(
        id=UUID("00000000-0000-0000-0000-000000000001"),
        name="media-full",
        external_port=12000,
        state=NodeState.RUNNING,
        health=NodeHealth.HEALTHY,
        registered_cameras=100,
    )
    store = InMemoryNodeStore(nodes=(full_node,))
    node_control = NodeControl(
        store=store,
        choose_port=lambda available: available[0],
        new_node_id=lambda: UUID("00000000-0000-0000-0000-000000000099"),
    )
    camera_control = CameraControl(
        store=store,
        new_camera_id=lambda: UUID("10000000-0000-0000-0000-000000000001"),
        new_public_id=lambda: "f234567f234567f234567f2344",
    )
    client = TestClient(
        create_app(
            Settings(role=RuntimeRole.WEB),
            node_control=node_control,
            camera_control=camera_control,
        )
    )

    response = client.post(
        "/api/v1/cameras",
        json={"name": "overflow", "source_url": "rtsp://camera.local/main"},
    )

    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "eligible_node_missing"
    listed = client.get("/api/v1/nodes").json()
    assert listed["count"] == 1
    assert client.get("/api/v1/cameras").json()["count"] == 0


def test_concurrent_automatic_placements_do_not_create_ghost_placements(
    postgres_database_url: str,
) -> None:
    migration = Config("alembic.ini")
    migration.set_main_option("sqlalchemy.url", postgres_database_url)
    command.upgrade(migration, "head")
    store = PostgresNodeStore(postgres_database_url)
    full_node_id = UUID("00000000-0000-0000-0000-000000000001")
    node_control = NodeControl(
        store=store,
        choose_port=lambda available: available[0],
        new_node_id=lambda: full_node_id,
        node_runtime=SuccessfulNodeRuntime(),
    )
    camera_control = CameraControl(
        store=store,
        new_camera_id=uuid4,
        new_public_id=generate_public_id,
    )
    client = TestClient(
        create_app(
            Settings(
                role=RuntimeRole.WEB,
                node_port_range_start=12000,
                node_port_range_end=12002,
            ),
            node_control=node_control,
            camera_control=camera_control,
        )
    )
    assert client.post("/api/v1/nodes", json={"name": "full"}).status_code == 201
    assert client.post(f"/api/v1/nodes/{full_node_id}/start").status_code == 200
    for index in range(100):
        response = client.post(
            "/api/v1/cameras",
            json={
                "name": f"seed-{index}",
                "source_url": f"rtsp://camera-{index}.local/main",
                "node_id": str(full_node_id),
            },
        )
        assert response.status_code == 201

    def place_overflow_camera(index: int) -> Response:
        return client.post(
            "/api/v1/cameras",
            json={
                "name": f"overflow-{index}",
                "source_url": f"rtsp://overflow-{index}.local/main",
            },
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        responses = tuple(executor.map(place_overflow_camera, range(2)))

    assert [response.status_code for response in responses] == [409, 409]
    assert all(
        response.json()["detail"]["code"] == "eligible_node_missing"
        for response in responses
    )
    listed = client.get("/api/v1/nodes").json()
    assert listed["count"] == 1
    assert listed["items"][0]["registered_cameras"] == 100
    assert client.get("/api/v1/cameras").json()["count"] == 100


def test_concurrent_manual_placements_cannot_cross_100_camera_limit(
    postgres_database_url: str,
) -> None:
    upgrade_database(postgres_database_url)
    store = PostgresNodeStore(postgres_database_url)
    node_id = UUID("00000000-0000-0000-0000-000000000001")
    client = TestClient(
        create_app(
            Settings(
                role=RuntimeRole.WEB,
                max_nodes=1,
                node_port_range_start=12000,
                node_port_range_end=12000,
            ),
            node_control=NodeControl(
                store=store,
                choose_port=lambda available: available[0],
                new_node_id=lambda: node_id,
                node_runtime=SuccessfulNodeRuntime(),
            ),
            camera_control=CameraControl(
                store=store,
                new_camera_id=uuid4,
                new_public_id=generate_public_id,
            ),
        )
    )
    assert client.post("/api/v1/nodes", json={"name": "media-a"}).status_code == 201
    assert client.post(f"/api/v1/nodes/{node_id}/start").status_code == 200
    for index in range(99):
        response = client.post(
            "/api/v1/cameras",
            json={
                "name": f"seed-{index}",
                "source_url": f"rtsp://camera-{index}.local/main",
                "node_id": str(node_id),
            },
        )
        assert response.status_code == 201
    barrier = Barrier(2)

    def place_last_camera(index: int) -> Response:
        barrier.wait()
        return client.post(
            "/api/v1/cameras",
            json={
                "name": f"racer-{index}",
                "source_url": f"rtsp://racer-{index}.local/main",
                "node_id": str(node_id),
            },
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        responses = tuple(executor.map(place_last_camera, range(2)))

    assert sorted(response.status_code for response in responses) == [201, 409]
    assert client.get("/api/v1/nodes").json()["items"][0]["registered_cameras"] == 100
    assert client.get("/api/v1/cameras").json()["count"] == 100


def test_postgresql_restart_and_camera_placement_are_one_atomic_choice(
    postgres_database_url: str,
) -> None:
    upgrade_database(postgres_database_url)
    store = PostgresNodeStore(postgres_database_url)
    node_id = UUID("00000000-0000-0000-0000-000000000001")
    runtime_entered = Event()
    release_runtime = Event()

    class BlockingRestartRuntime(SuccessfulNodeRuntime):
        def execute(
            self,
            action: NodeRuntimeAction,
            node: MediaNode,
        ) -> NodeRuntimeObservation:
            if action is NodeRuntimeAction.RESTART:
                runtime_entered.set()
                assert release_runtime.wait(timeout=5)
            return super().execute(action, node)

    client = TestClient(
        create_app(
            Settings(role=RuntimeRole.WEB),
            node_control=NodeControl(
                store=store,
                choose_port=lambda available: available[0],
                new_node_id=lambda: node_id,
                node_runtime=BlockingRestartRuntime(),
            ),
            camera_control=CameraControl(
                store=store,
                new_camera_id=uuid4,
                new_public_id=generate_public_id,
            ),
        )
    )
    assert client.post("/api/v1/nodes", json={"name": "media-a"}).status_code == 201
    assert client.post(f"/api/v1/nodes/{node_id}/start").status_code == 200

    with ThreadPoolExecutor(max_workers=2) as executor:
        restart = executor.submit(client.post, f"/api/v1/nodes/{node_id}/restart")
        assert runtime_entered.wait(timeout=5)
        placement = executor.submit(
            client.post,
            "/api/v1/cameras",
            json={
                "name": "must-wait",
                "source_url": "rtsp://camera.local/main",
                "node_id": str(node_id),
            },
        )
        placement_response = placement.result(timeout=5)
        release_runtime.set()
        restart_response = restart.result(timeout=5)

    assert restart_response.status_code == 200
    assert placement_response.status_code == 409
    assert placement_response.json()["detail"]["code"] == "eligible_node_missing"
    assert store.get_node(node_id).registered_cameras == 0  # type: ignore[union-attr]


def test_postgresql_stop_rechecks_empty_under_the_placement_lock(
    postgres_database_url: str,
) -> None:
    upgrade_database(postgres_database_url)
    store = PostgresNodeStore(postgres_database_url)
    node_id = UUID("00000000-0000-0000-0000-000000000001")
    node = store.register_automatically(
        name="media-a",
        allowed_ports=(12000,),
        max_nodes=1,
        preferred_port=12000,
        choose_port=lambda available: available[0],
        new_node_id=lambda: node_id,
        api_ports=(13000,),
        metrics_ports=(14000,),
    )
    running = store.request_desired_state(node.id, NodeState.RUNNING)
    store.apply_runtime_observation(
        node.id,
        SuccessfulNodeRuntime().execute(NodeRuntimeAction.START, running),
    )
    store.place_camera_manually(
        camera_id=UUID("10000000-0000-0000-0000-000000000001"),
        name="already-placed",
        source_url="rtsp://camera.local/main",
        public_id=PublicId.parse(generate_public_id()),
        node_id=node.id,
    )

    with pytest.raises(NodeNotEmpty, match="node_not_empty"):
        store.request_stop(node.id)

    unchanged = store.get_node(node.id)
    assert unchanged is not None
    assert unchanged.state is NodeState.RUNNING
    assert unchanged.registered_cameras == 1


def test_postgresql_stop_and_camera_placement_are_one_atomic_choice(
    postgres_database_url: str,
) -> None:
    upgrade_database(postgres_database_url)
    store = PostgresNodeStore(postgres_database_url)
    node_id = UUID("00000000-0000-0000-0000-000000000001")
    client = TestClient(
        create_app(
            Settings(role=RuntimeRole.WEB),
            node_control=NodeControl(
                store=store,
                choose_port=lambda available: available[0],
                new_node_id=lambda: node_id,
                node_runtime=RecordingLifecycleRuntime(),
            ),
            camera_control=CameraControl(
                store=store,
                new_camera_id=uuid4,
                new_public_id=generate_public_id,
            ),
        )
    )
    assert client.post("/api/v1/nodes", json={"name": "media-a"}).status_code == 201
    assert client.post(f"/api/v1/nodes/{node_id}/start").status_code == 200
    barrier = Barrier(2)

    def stop() -> Response:
        barrier.wait()
        return client.post(f"/api/v1/nodes/{node_id}/stop")

    def place() -> Response:
        barrier.wait()
        return client.post(
            "/api/v1/cameras",
            json={
                "name": "atomic-choice",
                "source_url": "rtsp://camera.local/main",
                "node_id": str(node_id),
            },
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        stop_future = executor.submit(stop)
        placement_future = executor.submit(place)
        stop_response = stop_future.result(timeout=5)
        placement_response = placement_future.result(timeout=5)

    assert (stop_response.status_code, placement_response.status_code) in {
        (200, 409),
        (409, 201),
    }
    final = store.get_node(node_id)
    assert final is not None
    if stop_response.status_code == 200:
        assert final.state is NodeState.STOPPED
        assert final.registered_cameras == 0
    else:
        assert stop_response.json()["detail"]["code"] == "node_not_empty"
        assert final.state is NodeState.RUNNING
        assert final.registered_cameras == 1


def test_postgresql_lifecycle_guard_has_a_bounded_dedicated_connection_pool(
    postgres_database_url: str,
) -> None:
    upgrade_database(postgres_database_url)
    store = PostgresNodeStore(
        postgres_database_url,
        lifecycle_lock_pool_size=2,
        lifecycle_lock_timeout_seconds=0.1,
    )
    node_ids = tuple(UUID(f"00000000-0000-0000-0000-{index:012d}") for index in range(1, 4))
    for index, node_id in enumerate(node_ids):
        def current_node_id(node_id: UUID = node_id) -> UUID:
            return node_id

        store.register_automatically(
            name=f"media-{index}",
            allowed_ports=tuple(range(12000, 12003)),
            max_nodes=3,
            preferred_port=12000 + index,
            choose_port=lambda available: available[0],
            new_node_id=current_node_id,
            api_ports=tuple(range(13000, 13003)),
            metrics_ports=tuple(range(14000, 14003)),
        )
    acquired = Barrier(3)
    release = Event()

    def hold_guard(node_id: UUID) -> UUID:
        with store.lifecycle_guard(node_id):
            acquired.wait(timeout=5)
            assert release.wait(timeout=5)
            return node_id

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = tuple(executor.submit(hold_guard, node_id) for node_id in node_ids[:2])
        acquired.wait(timeout=5)
        with (
            pytest.raises(NodeLifecycleConflict, match="node_lifecycle_busy"),
            store.lifecycle_guard(node_ids[2]),
        ):
            pytest.fail("unbounded lifecycle connection was acquired")
        release.set()
        observed = {future.result(timeout=5) for future in futures}

    assert observed == set(node_ids[:2])


def test_postgresql_lifecycle_guard_times_out_same_node_contention(
    postgres_database_url: str,
) -> None:
    upgrade_database(postgres_database_url)
    store = PostgresNodeStore(
        postgres_database_url,
        lifecycle_lock_pool_size=2,
        lifecycle_lock_timeout_seconds=0.1,
    )
    node = store.register_automatically(
        name="media-a",
        allowed_ports=(12000,),
        max_nodes=1,
        preferred_port=12000,
        choose_port=lambda available: available[0],
        new_node_id=lambda: UUID("00000000-0000-0000-0000-000000000001"),
        api_ports=(13000,),
        metrics_ports=(14000,),
    )

    def contend() -> str:
        with (
            pytest.raises(NodeLifecycleConflict, match="node_lifecycle_busy"),
            store.lifecycle_guard(node.id),
        ):
            pytest.fail("same-node advisory lock was not bounded")
        return "bounded"

    with store.lifecycle_guard(node.id), ThreadPoolExecutor(max_workers=1) as executor:
        assert executor.submit(contend).result(timeout=1) == "bounded"


@pytest.mark.parametrize(
    "changes",
    (
        {"lifecycle_lock_pool_size": 1},
        {"lifecycle_lock_pool_size": 17},
        {"lifecycle_lock_timeout_seconds": 0},
        {"lifecycle_lock_timeout_seconds": 31},
    ),
)
def test_postgresql_store_rejects_unbounded_lifecycle_lock_configuration(
    postgres_database_url: str,
    changes: dict[str, object],
) -> None:
    with pytest.raises(ValueError, match=r"node_lifecycle_lock_.+_invalid"):
        PostgresNodeStore(postgres_database_url, **changes)  # type: ignore[arg-type]


def test_postgresql_provisioning_guard_has_bounded_connection_acquisition(
    postgres_database_url: str,
) -> None:
    upgrade_database(postgres_database_url)
    store = PostgresNodeStore(
        postgres_database_url,
        lifecycle_lock_timeout_seconds=0.1,
    )

    def contend() -> str:
        with (
            pytest.raises(NodeLifecycleConflict, match="node_lifecycle_busy"),
            store.provisioning_guard(),
        ):
            pytest.fail("provisioning lock connection was not bounded")
        return "bounded"

    with store.provisioning_guard(), ThreadPoolExecutor(max_workers=1) as executor:
        assert executor.submit(contend).result(timeout=1) == "bounded"


def test_postgresql_lifecycle_guard_rejects_an_unknown_node(
    postgres_database_url: str,
) -> None:
    upgrade_database(postgres_database_url)
    store = PostgresNodeStore(postgres_database_url)

    with pytest.raises(LookupError, match="node_not_found"), store.lifecycle_guard(
        UUID("00000000-0000-0000-0000-000000000001")
    ):
        pytest.fail("unknown node entered lifecycle guard")


def test_concurrent_node_creation_serializes_the_last_available_port(
    postgres_database_url: str,
) -> None:
    upgrade_database(postgres_database_url)
    store = PostgresNodeStore(postgres_database_url)
    client = TestClient(
        create_app(
            Settings(
                role=RuntimeRole.WEB,
                max_nodes=2,
                node_port_range_start=12000,
                node_port_range_end=12000,
            ),
            node_control=NodeControl(
                store=store,
                choose_port=lambda available: available[0],
                new_node_id=uuid4,
                is_port_bindable=lambda port: True,
            ),
        )
    )
    barrier = Barrier(2)

    def create_node(index: int) -> Response:
        barrier.wait()
        return client.post("/api/v1/nodes", json={"name": f"racer-{index}"})

    with ThreadPoolExecutor(max_workers=2) as executor:
        responses = tuple(executor.map(create_node, range(2)))

    assert sorted(response.status_code for response in responses) == [201, 409]
    failed = next(response for response in responses if response.status_code == 409)
    assert failed.json()["detail"]["code"] == "node_ports_exhausted"
    assert client.get("/api/v1/nodes").json()["count"] == 1


def test_concurrent_manual_and_automatic_node_creation_cannot_exceed_max_nodes(
    postgres_database_url: str,
) -> None:
    upgrade_database(postgres_database_url)
    store = PostgresNodeStore(postgres_database_url)
    client = TestClient(
        create_app(
            Settings(
                role=RuntimeRole.WEB,
                max_nodes=1,
                node_port_range_start=12000,
                node_port_range_end=12001,
            ),
            node_control=NodeControl(
                store=store,
                choose_port=lambda available: available[0],
                new_node_id=uuid4,
                is_port_bindable=lambda port: True,
            ),
            shutdown=store.close,
        )
    )
    barrier = Barrier(2)

    def create_node(request: dict[str, object]) -> Response:
        barrier.wait()
        return client.post("/api/v1/nodes", json=request)

    requests = (
        {"name": "automatic"},
        {"name": "manual", "external_port": 12001},
    )
    with ThreadPoolExecutor(max_workers=2) as executor:
        responses = tuple(executor.map(create_node, requests))

    assert sorted(response.status_code for response in responses) == [201, 409]
    failed = next(response for response in responses if response.status_code == 409)
    assert failed.json()["detail"]["code"] == "max_nodes_reached"
    assert client.get("/api/v1/nodes").json()["count"] == 1
