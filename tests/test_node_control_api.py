import hashlib
import platform
import socket
import time
from collections.abc import Callable, Collection, Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import AbstractContextManager, contextmanager
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from ipaddress import ip_network
from pathlib import Path
from threading import Barrier, Event, Lock
from typing import Any, cast
from uuid import UUID, uuid4

import pytest
from alembic import command
from alembic.config import Config
from fastapi import FastAPI
from fastapi.testclient import TestClient
from httpx2 import Response
from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from rtsp_proxy.app import create_app
from rtsp_proxy.camera_secrets import (
    CameraSourceCredentialCipher,
    CameraSourceCredentials,
    CameraSourceKeyRing,
)
from rtsp_proxy.config import NodeRegistrationPolicy, RuntimeRole, Settings
from rtsp_proxy.database import DatabaseSchemaMismatch, PostgresNodeStore
from rtsp_proxy.identifiers import PublicId, generate_public_id
from rtsp_proxy.media import MediaNodeUnavailable, MediaPathConfig, MediaPathInventory
from rtsp_proxy.migrate import upgrade_database
from rtsp_proxy.nodes import (
    CameraControl,
    CameraLifecycleConflict,
    CameraMoveExpired,
    CameraNotFound,
    EligibleNodeMissing,
    InMemoryNodeStore,
    InvalidCameraName,
    InvalidCameraSource,
    MaximumNodesReached,
    MediaNode,
    NodeCameraCapacityReached,
    NodeCommandFence,
    NodeControl,
    NodeDisruptionConfirmationContext,
    NodeDisruptionConfirmationRequired,
    NodeDisruptionFenceLease,
    NodeDisruptionObservation,
    NodeHealth,
    NodeLifecycleBusy,
    NodeLifecycleConflict,
    NodeManagementPortRangeExhausted,
    NodeMutationContext,
    NodeNotEmpty,
    NodeNotFound,
    NodePortChange,
    NodePortInUse,
    NodePortOutOfRange,
    NodePortRangeExhausted,
    NodeProvisioningPolicy,
    NodeRuntime,
    NodeRuntimeAction,
    NodeRuntimeFailed,
    NodeRuntimeObservation,
    NodeRuntimeUnavailable,
    NodeState,
    ProbeEndpointSchemaUnavailable,
    camera_placement_fingerprint,
    tcp_port_is_bindable,
)
from rtsp_proxy.phase_d_transition import (
    PhaseDTransitionError,
    export_transition,
    restore_transition,
)
from rtsp_proxy.probe_security import ProbeEndpointAdmission
from rtsp_proxy.reconcile import (
    CameraMoveControl,
    CameraMutationControl,
    CameraOccupied,
    CameraReaderInvariantViolation,
    CameraRuntimeObserver,
    ConfirmationTokenService,
    MoveConfirmationRequired,
    ReconcileRetry,
)
from rtsp_proxy.release import trusted_mediamtx_identity
from rtsp_proxy.runtime import create_app_from_environment, create_background_app, run_web

TRUSTED_MEDIAMTX_SHA256 = trusted_mediamtx_identity(platform.machine())[1].root

NODE_MUTATION_CONTEXT = NodeMutationContext(
    actor_account_id=UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
    actor_session_id=UUID("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"),
    identity_source="oidc",
    actor_subject="oidc:operator@example.test",
    roles=("operator",),
    scopes=("server:*",),
    authz_version=3,
    request_id=UUID("cccccccc-cccc-4ccc-8ccc-cccccccccccc"),
    action="node.create",
    http_method="POST",
    resource_scope="server:*",
    resource_type="node",
    resource_id="collection",
    source_ip_sha256="1" * 64,
    user_agent_sha256="2" * 64,
)
NODE_CONFIRMATION_CONTEXT = NodeDisruptionConfirmationContext(
    account_id=NODE_MUTATION_CONTEXT.actor_account_id,
    session_id=NODE_MUTATION_CONTEXT.actor_session_id,
    authz_version=NODE_MUTATION_CONTEXT.authz_version,
    mfa_verified_at_unix_ms=1_788_091_200_000,
)


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
    assert response.headers["location"] == ("/api/v1/nodes/00000000-0000-0000-0000-000000000001")
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
    assert response.headers["location"] == ("/api/v1/nodes/00000000-0000-0000-0000-000000000001")
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
        "state": "enabled",
        "registered": True,
        "desired_revision": 1,
        "applied_revision": 0,
    }


def test_camera_create_fails_closed_when_bounded_endpoint_resolution_times_out() -> None:
    node = MediaNode(
        id=UUID("00000000-0000-0000-0000-000000000001"),
        name="media-a",
        external_port=12000,
        state=NodeState.RUNNING,
        runtime_state=NodeState.RUNNING,
        health=NodeHealth.HEALTHY,
        management_fresh=True,
        management_observed_at=datetime.now(UTC),
        config_compatible=True,
        applied_revision=1,
    )
    store = InMemoryNodeStore(nodes=(node,))

    def timed_out(_hostname: str) -> tuple[str, ...]:
        raise TimeoutError("resolver detail must not cross the API")

    control = CameraControl(
        store=store,
        new_camera_id=lambda: UUID("10000000-0000-0000-0000-000000000001"),
        new_public_id=lambda: "a234567a234567a234567a2344",
        probe_endpoint_admission=ProbeEndpointAdmission(
            site_key="site-a",
            allowed_networks=(ip_network("10.40.0.0/24"),),
            resolve=timed_out,
        ),
    )
    client = TestClient(
        create_app(
            Settings(role=RuntimeRole.WEB),
            camera_control=control,
        )
    )

    response = client.post(
        "/api/v1/cameras",
        json={"name": "entrance", "source_url": "rtsp://camera.example/main"},
    )

    assert response.status_code == 422
    assert response.json()["detail"] == {"code": "camera_source_endpoint_rejected"}
    assert store.list_cameras() == ()


def test_camera_create_reports_an_unconfigured_source_policy() -> None:
    node = MediaNode(
        id=UUID("00000000-0000-0000-0000-000000000001"),
        name="media-a",
        external_port=12000,
        state=NodeState.RUNNING,
        runtime_state=NodeState.RUNNING,
        health=NodeHealth.HEALTHY,
        management_fresh=True,
        management_observed_at=datetime.now(UTC),
        config_compatible=True,
        applied_revision=1,
    )
    store = InMemoryNodeStore(nodes=(node,))
    control = CameraControl(
        store=store,
        new_camera_id=lambda: UUID("10000000-0000-0000-0000-000000000001"),
        new_public_id=lambda: "a234567a234567a234567a2344",
        probe_endpoint_admission=ProbeEndpointAdmission(
            site_key="site-a",
            allowed_networks=(),
            resolve=lambda _hostname: ("10.40.0.11",),
        ),
    )

    response = TestClient(
        create_app(Settings(role=RuntimeRole.WEB), camera_control=control)
    ).post(
        "/api/v1/cameras",
        json={"name": "entrance", "source_url": "rtsp://camera.example/main"},
    )

    assert response.status_code == 422
    assert response.json() == {
        "detail": {"code": "probe_source_policy_not_configured"}
    }
    assert store.list_cameras() == ()


@pytest.mark.parametrize(
    ("error", "expected_status", "expected_code"),
    (
        (MaximumNodesReached("max_nodes_reached"), 409, "max_nodes_reached"),
        (NodePortRangeExhausted("node_ports_exhausted"), 409, "node_ports_exhausted"),
        (
            NodeManagementPortRangeExhausted("node_management_ports_exhausted"),
            409,
            "node_management_ports_exhausted",
        ),
        (NodeRuntimeUnavailable("node_runtime_unavailable"), 503, "node_runtime_unavailable"),
        (
            ProbeEndpointSchemaUnavailable("probe_endpoint_schema_unavailable"),
            503,
            "probe_endpoint_schema_unavailable",
        ),
    ),
)
def test_camera_create_maps_automatic_node_provisioning_failures(
    error: Exception,
    expected_status: int,
    expected_code: str,
) -> None:
    class FailingCameraControl:
        def create_camera(self, **_kwargs: object) -> None:
            raise error

    response = TestClient(
        create_app(
            Settings(role=RuntimeRole.WEB),
            camera_control=cast(CameraControl, FailingCameraControl()),
        )
    ).post(
        "/api/v1/cameras",
        json={"name": "entrance", "source_url": "rtsp://camera.example/main"},
    )

    assert response.status_code == expected_status
    assert response.json()["detail"]["code"] == expected_code


def test_camera_create_accepts_credentials_separately_without_returning_them() -> None:
    node = MediaNode(
        id=UUID("00000000-0000-0000-0000-000000000001"),
        name="media-a",
        external_port=12000,
        state=NodeState.RUNNING,
        runtime_state=NodeState.RUNNING,
        health=NodeHealth.HEALTHY,
        management_fresh=True,
        management_observed_at=datetime.now(UTC),
        config_compatible=True,
        applied_revision=1,
    )
    store = InMemoryNodeStore(nodes=(node,))
    control = CameraControl(
        store=store,
        new_camera_id=lambda: UUID("10000000-0000-4000-8000-000000000001"),
        new_public_id=lambda: "a234567a234567a234567a2344",
    )

    response = TestClient(
        create_app(Settings(role=RuntimeRole.WEB), camera_control=control)
    ).post(
        "/api/v1/cameras",
        json={
            "name": "entrance",
            "source_url": "rtsp://camera.example/main",
            "source_credentials": {
                "username": "operator",
                "password": "never-return-this-password",
            },
        },
    )

    assert response.status_code == 201
    assert store.list_cameras()[0].source_url == (
        "rtsp://operator:never-return-this-password@camera.example/main"
    )
    assert "operator" not in response.text
    assert "never-return-this-password" not in response.text


def test_postgres_camera_source_credentials_are_encrypted_and_restored(
    postgres_database_url: str,
) -> None:
    upgrade_database(postgres_database_url)
    cipher = CameraSourceCredentialCipher(
        CameraSourceKeyRing(primary_key_id="2026-09", keys={"2026-09": b"k" * 32})
    )
    store = PostgresNodeStore(postgres_database_url, camera_source_cipher=cipher)
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
    running = store.request_desired_state(node.id, NodeState.RUNNING)
    store.apply_runtime_observation(
        node.id,
        SuccessfulNodeRuntime().execute(NodeRuntimeAction.START, running),
    )
    password = "database-must-not-contain-this-password"

    control = CameraControl(
        store=store,
        new_camera_id=lambda: UUID("10000000-0000-4000-8000-000000000001"),
        new_public_id=lambda: "a234567a234567a234567a2344",
    )
    camera = control.create_camera(
        name="entrance",
        source_url="rtsp://camera.example/main",
        source_credentials=CameraSourceCredentials(
            username="operator",
            password=password,
        ),
        node_id=node.id,
    )

    engine = create_engine(postgres_database_url, hide_parameters=True)
    with engine.connect() as connection:
        stored = connection.execute(
            text(
                "SELECT c.source_url, s.key_id, s.ciphertext "
                "FROM cameras c JOIN camera_source_credentials s ON s.camera_id=c.id "
                "WHERE c.id=:camera_id"
            ),
            {"camera_id": camera.id},
        ).one()
    assert stored.source_url == "rtsp://camera.example/main"
    assert stored.key_id == "2026-09"
    assert password.encode() not in bytes(stored.ciphertext)
    assert store.get_camera(camera.id) == camera

    preserved = control.update_camera(
        camera.id,
        name="entrance renamed",
        source_url="rtsp://camera.example/sub",
        expected_revision=camera.desired_revision,
    )
    assert preserved.source_url == f"rtsp://operator:{password}@camera.example/sub"
    replacement_password = "replacement-database-secret"
    replaced = control.update_camera(
        camera.id,
        name="entrance renamed",
        source_url="rtsp://camera.example/sub",
        source_credentials=CameraSourceCredentials(
            username="replacement",
            password=replacement_password,
        ),
        expected_revision=preserved.desired_revision,
    )
    assert replaced.source_url == (
        f"rtsp://replacement:{replacement_password}@camera.example/sub"
    )
    with engine.connect() as connection:
        updated_row = connection.execute(
            text(
                "SELECT c.source_url, s.ciphertext FROM cameras c "
                "JOIN camera_source_credentials s ON s.camera_id=c.id WHERE c.id=:camera_id"
            ),
            {"camera_id": camera.id},
        ).one()
    assert updated_row.source_url == "rtsp://camera.example/sub"
    assert replacement_password.encode() not in bytes(updated_row.ciphertext)

    store.close()
    without_key = PostgresNodeStore(postgres_database_url)
    with pytest.raises(InvalidCameraSource, match="camera_source_credentials_unavailable"):
        without_key.get_camera(camera.id)
    without_key.close()
    engine.dispose()


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


@pytest.mark.parametrize("name", ("", "x" * 129, "bad\nname", "bad\u200bname"))
def test_camera_name_is_rejected_before_persistence(name: str) -> None:
    store = InMemoryNodeStore()
    control = CameraControl(
        store=store,
        new_camera_id=lambda: UUID("10000000-0000-0000-0000-000000000001"),
        new_public_id=lambda: "a234567a234567a234567a2344",
    )

    with pytest.raises(InvalidCameraName, match="camera_name_invalid"):
        control.create_camera(
            name=name,
            source_url="rtsp://camera.local/main",
        )

    assert store.list_cameras() == ()


def test_camera_update_and_disable_are_revisioned_desired_state() -> None:
    observed_at = datetime.now(UTC)
    camera_id = UUID("10000000-0000-0000-0000-000000000001")
    node_id = UUID("00000000-0000-0000-0000-000000000001")
    store = InMemoryNodeStore(
        nodes=(
            MediaNode(
                id=node_id,
                name="media-a",
                external_port=12000,
                state=NodeState.RUNNING,
                runtime_state=NodeState.RUNNING,
                health=NodeHealth.HEALTHY,
                management_fresh=True,
                management_observed_at=observed_at,
                config_compatible=True,
                desired_revision=1,
                applied_revision=1,
            ),
        )
    )
    cameras = CameraControl(
        store=store,
        new_camera_id=lambda: camera_id,
        new_public_id=lambda: "a" * 26,
    )
    media = ApiRecordingMediaFactory(node_id)
    mutations = CameraMutationControl(
        store=store,
        media_nodes=cast(Any, media),
        confirmations=node_confirmation_service(),
    )
    client = TestClient(
        create_app(
            Settings(role=RuntimeRole.WEB),
            camera_control=cameras,
            camera_mutation_control=mutations,
        )
    )
    assert (
        client.post(
            "/api/v1/cameras",
            json={"name": "entrance", "source_url": "rtsp://camera.local/main"},
        ).status_code
        == 201
    )

    updated = client.put(
        f"/api/v1/cameras/{camera_id}",
        json={"name": "entrance-new", "source_url": "rtsp://camera.local/new"},
    )
    disabled = client.post(f"/api/v1/cameras/{camera_id}/disable")

    assert updated.status_code == 200
    assert updated.json()["desired_revision"] == 2
    assert updated.json()["applied_revision"] == 0
    assert disabled.status_code == 200
    assert disabled.json()["state"] == "disabled"
    assert disabled.json()["desired_revision"] == 3
    assert disabled.json()["registered"] is True
    assert store.get_node(node_id).registered_cameras == 1  # type: ignore[union-attr]


def test_camera_move_preview_and_request_expose_desired_saga_state() -> None:
    observed_at = datetime.now(UTC)
    camera_id = UUID("10000000-0000-0000-0000-000000000001")
    source_id = UUID("00000000-0000-0000-0000-000000000001")
    target_id = UUID("00000000-0000-0000-0000-000000000002")
    store = InMemoryNodeStore(
        nodes=tuple(
            MediaNode(
                id=node_id,
                name=f"media-{node_id.int}",
                external_port=port,
                state=NodeState.RUNNING,
                runtime_state=NodeState.RUNNING,
                health=NodeHealth.HEALTHY,
                management_fresh=True,
                management_observed_at=observed_at,
                config_compatible=True,
                desired_revision=1,
                applied_revision=1,
            )
            for node_id, port in ((source_id, 12000), (target_id, 12001))
        )
    )
    camera_control = CameraControl(
        store=store,
        new_camera_id=lambda: camera_id,
        new_public_id=lambda: "a" * 26,
    )
    camera_control.create_camera(
        name="entrance",
        source_url="rtsp://camera.local/main",
        node_id=source_id,
    )

    class Runtime:
        def observe(self, selected_id: UUID) -> object:
            assert selected_id == camera_id
            from rtsp_proxy.reconcile import CameraRuntimeObservation

            return CameraRuntimeObservation(
                camera_id=camera_id,
                node_id=source_id,
                ready=True,
                reader_count=0,
                occupied=False,
                reader_limit_violated=False,
            )

    move_control = CameraMoveControl(
        store=store,
        runtime=cast(CameraRuntimeObserver, Runtime()),
        confirmations=ConfirmationTokenService(
            secret=b"test-confirmation-secret-that-is-at-least-32-bytes",
            lifetime_seconds=30,
        ),
        new_move_id=lambda: UUID("30000000-0000-0000-0000-000000000001"),
    )
    client = TestClient(
        create_app(
            Settings(role=RuntimeRole.WEB),
            camera_control=camera_control,
            camera_move_control=move_control,
        )
    )

    preview = client.post(
        f"/api/v1/cameras/{camera_id}/moves/preview",
        json={"target_node_id": str(target_id)},
    )
    requested = client.post(
        f"/api/v1/cameras/{camera_id}/moves",
        json={"target_node_id": str(target_id), "force": False},
    )
    status_response = client.get("/api/v1/camera-moves/30000000-0000-0000-0000-000000000001")

    assert preview.status_code == 200
    assert preview.json()["occupied"] is False
    assert preview.json()["confirmation_token"] is None
    assert requested.status_code == 202
    assert requested.json()["state"] == "prepare_target"
    assert requested.json()["source_node_id"] == str(source_id)
    assert requested.json()["target_node_id"] == str(target_id)
    assert status_response.json() == requested.json()


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
                "AND table_name IN "
                "('media_nodes', 'cameras', 'audit_events', 'outbox_messages', "
                "'camera_access_policies', 'camera_access_grants', "
                "'node_registration_requests', 'access_grant_issue_requests', "
                "'operator_action_rate_limits', 'camera_registration_requests', "
                "'probe_observations', 'camera_probe_endpoints', "
                "'camera_source_credentials')"
            )
        )
        assert revision == "0022_camera_source_credentials"
    assert table_count == 13


def test_postgresql_node_registration_idempotency_is_atomic_and_survives_deletion(
    postgres_database_url: str,
) -> None:
    upgrade_database(postgres_database_url)
    store = PostgresNodeStore(
        postgres_database_url,
        lifecycle_lock_timeout_seconds=2,
    )
    node_ids = iter(
        (
            UUID("00000000-0000-4000-8000-000000000101"),
            UUID("00000000-0000-4000-8000-000000000102"),
        )
    )
    context = replace(
        NODE_MUTATION_CONTEXT,
        idempotency_key=UUID("10000000-0000-4000-8000-000000000001"),
    )
    bindable = {12000: True}
    control = NodeControl(
        store=store,
        choose_port=lambda available: available[0],
        new_node_id=node_ids.__next__,
        is_port_bindable=lambda port: bindable.get(port, True),
    )

    def register() -> MediaNode:
        return control.register_node(
            name="idempotent-node",
            port_range_start=12000,
            port_range_end=12001,
            max_nodes=2,
            external_port=12000,
            api_ports=(13000, 13001),
            metrics_ports=(14000, 14001),
            mutation_context=context,
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        first_future = executor.submit(register)
        second_future = executor.submit(register)
        first = first_future.result(timeout=5)
        replay = second_future.result(timeout=5)

    assert replay.id == first.id
    engine = create_engine(postgres_database_url)
    with engine.connect() as connection:
        assert connection.scalar(text("SELECT count(*) FROM media_nodes")) == 1
        request = connection.execute(
            text(
                "SELECT actor_account_id, actor_session_id, idempotency_key, "
                "request_sha256, node_id FROM node_registration_requests"
            )
        ).one()
        events = connection.execute(
            text(
                "SELECT audit_events.payload, outbox_messages.payload "
                "FROM audit_events JOIN outbox_messages USING (id) "
                "WHERE audit_events.event_type='media_node.created'"
            )
        ).one()
    assert request.actor_account_id == context.actor_account_id
    assert request.actor_session_id == context.actor_session_id
    assert request.idempotency_key == context.idempotency_key
    assert request.node_id == first.id
    assert len(request.request_sha256) == 64
    assert events[0] == events[1]
    assert events[0]["operator"]["idempotency_key"] == str(context.idempotency_key)

    bindable[12000] = False
    replay_after_server_policy_change = control.register_node(
        name="idempotent-node",
        port_range_start=15000,
        port_range_end=15000,
        max_nodes=1,
        external_port=12000,
        reserved_ports=(15000,),
        api_ports=(16000,),
        metrics_ports=(17000,),
        release_id="0.9.0",
        mediamtx_binary_sha256="f" * 64,
        mutation_context=context,
    )
    assert replay_after_server_policy_change.id == first.id

    with pytest.raises(NodeLifecycleConflict, match="node_idempotency_conflict"):
        control.register_node(
            name="different-request",
            port_range_start=12000,
            port_range_end=12001,
            max_nodes=2,
            external_port=12000,
            api_ports=(13000, 13001),
            metrics_ports=(14000, 14001),
            mutation_context=context,
        )

    with engine.begin() as connection:
        connection.execute(text("DELETE FROM media_nodes WHERE id=:id"), {"id": first.id})
    with pytest.raises(NodeLifecycleConflict, match="node_idempotency_target_missing"):
        register()
    with engine.connect() as connection:
        assert connection.scalar(text("SELECT count(*) FROM node_registration_requests")) == 1
        assert connection.scalar(text("SELECT count(*) FROM media_nodes")) == 0
    engine.dispose()
    store.close()


def test_in_memory_node_registration_replays_stable_intent_after_policy_change() -> None:
    store = InMemoryNodeStore()
    bindable = {12000: True}
    context = replace(
        NODE_MUTATION_CONTEXT,
        idempotency_key=UUID("10000000-0000-4000-8000-000000000003"),
    )
    control = NodeControl(
        store=store,
        choose_port=lambda available: available[0],
        new_node_id=iter((UUID("00000000-0000-4000-8000-000000000104"),)).__next__,
        is_port_bindable=lambda port: bindable.get(port, True),
    )

    created = control.register_node(
        name="stable-intent-node",
        port_range_start=12000,
        port_range_end=12000,
        max_nodes=1,
        external_port=12000,
        api_ports=(13000,),
        metrics_ports=(14000,),
        mutation_context=context,
    )
    bindable[12000] = False
    replay = control.register_node(
        name="stable-intent-node",
        port_range_start=15000,
        port_range_end=15000,
        max_nodes=100,
        external_port=12000,
        reserved_ports=(15000,),
        api_ports=(16000,),
        metrics_ports=(17000,),
        release_id="0.9.0",
        mediamtx_binary_sha256="f" * 64,
        mutation_context=context,
    )

    assert replay == created
    assert store.list_nodes() == (created,)


def test_postgresql_authenticated_node_registration_waits_for_schema_0016(
    postgres_database_url: str,
) -> None:
    migration = Config("alembic.ini")
    migration.set_main_option("sqlalchemy.url", postgres_database_url)
    command.upgrade(migration, "0015_camera_name_contract")
    store = PostgresNodeStore(postgres_database_url)
    control = NodeControl(
        store=store,
        choose_port=lambda available: available[0],
        new_node_id=lambda: UUID("00000000-0000-4000-8000-000000000103"),
        is_port_bindable=lambda _port: True,
    )
    context = replace(
        NODE_MUTATION_CONTEXT,
        idempotency_key=UUID("10000000-0000-4000-8000-000000000002"),
    )

    with pytest.raises(
        NodeRuntimeUnavailable,
        match="node_registration_schema_unavailable",
    ):
        control.register_node(
            name="blocked-until-schema-current",
            port_range_start=12000,
            port_range_end=12000,
            max_nodes=1,
            api_ports=(13000,),
            metrics_ports=(14000,),
            mutation_context=context,
        )

    engine = create_engine(postgres_database_url)
    with engine.connect() as connection:
        assert connection.scalar(text("SELECT count(*) FROM media_nodes")) == 0
    engine.dispose()
    store.close()


def test_camera_name_migration_rejects_legacy_rows_before_strict_reads(
    postgres_database_url: str,
) -> None:
    migration = Config("alembic.ini")
    migration.set_main_option("sqlalchemy.url", postgres_database_url)
    command.upgrade(migration, "0014_camera_catalog_projection")
    engine = create_engine(postgres_database_url)
    invalid_names = ("", "   ", "bad\nname", "bad\u202ename", "bad\u200bname")
    camera_ids = tuple(
        UUID(f"10000000-0000-4000-8000-{index:012d}") for index in range(1, len(invalid_names) + 1)
    )
    with engine.begin() as connection:
        for index, (camera_id, name) in enumerate(zip(camera_ids, invalid_names, strict=True)):
            connection.execute(
                text(
                    "INSERT INTO cameras "
                    "(id, name, source_url, public_id, state, desired_revision, "
                    "applied_revision) VALUES "
                    "(:id, :name, :source_url, :public_id, 'enabled', 1, 0)"
                ),
                {
                    "id": camera_id,
                    "name": name,
                    "source_url": f"rtsp://camera-{index}.local/main",
                    "public_id": chr(ord("a") + index) * 25 + "a",
                },
            )

    with pytest.raises(RuntimeError, match="camera_name_contract_preflight_failed:count=5"):
        command.upgrade(migration, "head")

    with engine.connect() as connection:
        assert connection.scalar(text("SELECT version_num FROM alembic_version")) == (
            "0014_camera_catalog_projection"
        )
    with engine.begin() as connection:
        for index, camera_id in enumerate(camera_ids, start=1):
            connection.execute(
                text("UPDATE cameras SET name=:name WHERE id=:id"),
                {"id": camera_id, "name": f"Recovered camera {index}"},
            )
    command.upgrade(migration, "head")
    with engine.connect() as connection:
        assert connection.scalar(text("SELECT version_num FROM alembic_version")) == (
            "0022_camera_source_credentials"
        )


def test_camera_name_migration_preserves_an_invalid_deleted_legacy_tombstone(
    postgres_database_url: str,
) -> None:
    migration = Config("alembic.ini")
    migration.set_main_option("sqlalchemy.url", postgres_database_url)
    command.upgrade(migration, "0014_camera_catalog_projection")
    engine = create_engine(postgres_database_url)
    camera_id = UUID("10000000-0000-4000-8000-000000000099")
    public_id = "z" * 25 + "a"
    with engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO cameras "
                "(id, name, source_url, public_id, state, desired_revision, "
                "applied_revision) VALUES "
                "(:id, :name, 'rtsp://legacy-camera.local/main', :public_id, "
                "'deleted', 2, 2)"
            ),
            {"id": camera_id, "name": "legacy\nname", "public_id": public_id},
        )
        connection.execute(
            text("INSERT INTO public_id_tombstones (public_id) VALUES (:public_id)"),
            {"public_id": public_id},
        )

    command.upgrade(migration, "head")

    with engine.connect() as connection:
        assert connection.scalar(text("SELECT version_num FROM alembic_version")) == (
            "0022_camera_source_credentials"
        )
        assert (
            connection.scalar(text("SELECT name FROM cameras WHERE id=:id"), {"id": camera_id})
            == "legacy\nname"
        )
        assert (
            connection.scalar(
                text("SELECT count(*) FROM public_id_tombstones WHERE public_id=:public_id"),
                {"public_id": public_id},
            )
            == 1
        )


def test_camera_move_safety_migration_rejects_invalid_legacy_source_urls(
    postgres_database_url: str,
) -> None:
    migration = Config("alembic.ini")
    migration.set_main_option("sqlalchemy.url", postgres_database_url)
    command.upgrade(migration, "0008_node_administration")
    engine = create_engine(postgres_database_url)
    with engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO cameras "
                "(id, name, source_url, public_id, state, desired_revision, applied_revision) "
                "VALUES (:id, 'legacy', :source_url, :public_id, 'enabled', 1, 0)"
            ),
            {
                "id": UUID("10000000-0000-0000-0000-000000000001"),
                "source_url": "rtsp://camera.local/" + "x" * 8193,
                "public_id": "a" * 26,
            },
        )

    with pytest.raises(RuntimeError, match="legacy_camera_source_url_invalid"):
        command.upgrade(migration, "0009_camera_move_safety")


def test_camera_move_safety_migration_rejects_a_legacy_node_registry(
    postgres_database_url: str,
) -> None:
    migration = Config("alembic.ini")
    migration.set_main_option("sqlalchemy.url", postgres_database_url)
    command.upgrade(migration, "0008_node_administration")
    engine = create_engine(postgres_database_url)
    with engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO media_nodes "
                "(id, name, external_port, api_port, metrics_port, state, runtime_state, "
                "health, camera_capacity, registered_cameras, active_sources, maintenance, "
                "management_fresh, config_compatible, release_id, mediamtx_binary_sha256, "
                "desired_revision, applied_revision) "
                "VALUES (:id, 'legacy', 12000, 13000, 14000, 'stopped', 'stopped', "
                "'unknown', 100, 0, 0, false, false, false, 'v1.20.0', :digest, 1, 1)"
            ),
            {
                "id": UUID("00000000-0000-0000-0000-000000000001"),
                "digest": "a" * 64,
            },
        )

    with pytest.raises(RuntimeError, match="phase_d_requires_empty_media_node_registry"):
        command.upgrade(migration, "0009_camera_move_safety")


def test_camera_move_safety_migration_rejects_nonterminal_legacy_moves(
    postgres_database_url: str,
) -> None:
    migration = Config("alembic.ini")
    migration.set_main_option("sqlalchemy.url", postgres_database_url)
    command.upgrade(migration, "0008_node_administration")
    engine = create_engine(postgres_database_url)
    source_id = UUID("00000000-0000-0000-0000-000000000001")
    target_id = UUID("00000000-0000-0000-0000-000000000002")
    camera_id = UUID("10000000-0000-0000-0000-000000000001")
    with engine.begin() as connection:
        for node_id, name, port, api_port, metrics_port in (
            (source_id, "source", 12000, 13000, 14000),
            (target_id, "target", 12001, 13001, 14001),
        ):
            connection.execute(
                text(
                    "INSERT INTO media_nodes "
                    "(id, name, external_port, api_port, metrics_port, state, runtime_state, "
                    "health, camera_capacity, registered_cameras, active_sources, maintenance, "
                    "management_fresh, config_compatible, release_id, mediamtx_binary_sha256, "
                    "desired_revision, applied_revision) "
                    "VALUES (:id, :name, :port, :api_port, :metrics_port, 'running', 'running', "
                    "'healthy', 100, 0, 0, false, true, true, 'v1.20.0', :digest, 1, 1)"
                ),
                {
                    "id": node_id,
                    "name": name,
                    "port": port,
                    "api_port": api_port,
                    "metrics_port": metrics_port,
                    "digest": "a" * 64,
                },
            )
        connection.execute(
            text(
                "INSERT INTO cameras "
                "(id, name, source_url, public_id, state, desired_revision, applied_revision) "
                "VALUES (:id, 'legacy', 'rtsp://camera.local/main', :public_id, 'enabled', 2, 1)"
            ),
            {"id": camera_id, "public_id": "a" * 26},
        )
        connection.execute(
            text(
                "INSERT INTO camera_move_sagas "
                "(id, camera_id, source_node_id, target_node_id, source_generation, "
                "target_generation, desired_revision, force, state) "
                "VALUES (:id, :camera_id, :source, :target, 1, 2, 2, false, 'prepare_target')"
            ),
            {
                "id": UUID("30000000-0000-0000-0000-000000000001"),
                "camera_id": camera_id,
                "source": source_id,
                "target": target_id,
            },
        )

    with pytest.raises(
        RuntimeError,
        match="legacy_nonterminal_camera_moves_require_manual_resolution",
    ):
        command.upgrade(migration, "0009_camera_move_safety")


def test_camera_move_safety_migration_does_not_fabricate_terminal_endpoints(
    postgres_database_url: str,
) -> None:
    migration = Config("alembic.ini")
    migration.set_main_option("sqlalchemy.url", postgres_database_url)
    command.upgrade(migration, "0008_node_administration")
    engine = create_engine(postgres_database_url)
    source_id = UUID("00000000-0000-0000-0000-000000000001")
    target_id = UUID("00000000-0000-0000-0000-000000000002")
    camera_id = UUID("10000000-0000-0000-0000-000000000001")
    move_id = UUID("30000000-0000-0000-0000-000000000001")
    with engine.begin() as connection:
        for node_id, name, port, api_port, metrics_port in (
            (source_id, "source", 12000, 13000, 14000),
            (target_id, "target", 12001, 13001, 14001),
        ):
            connection.execute(
                text(
                    "INSERT INTO media_nodes "
                    "(id, name, external_port, api_port, metrics_port, state, runtime_state, "
                    "health, camera_capacity, registered_cameras, active_sources, maintenance, "
                    "management_fresh, config_compatible, release_id, mediamtx_binary_sha256, "
                    "desired_revision, applied_revision) "
                    "VALUES (:id, :name, :port, :api_port, :metrics_port, 'running', 'running', "
                    "'healthy', 100, 0, 0, false, true, true, 'legacy', :digest, 1, 1)"
                ),
                {
                    "id": node_id,
                    "name": name,
                    "port": port,
                    "api_port": api_port,
                    "metrics_port": metrics_port,
                    "digest": "a" * 64,
                },
            )
        connection.execute(
            text(
                "INSERT INTO cameras "
                "(id, name, source_url, public_id, state, desired_revision, applied_revision) "
                "VALUES (:id, 'legacy', 'rtsp://camera.local/main', :public_id, 'enabled', 2, 2)"
            ),
            {"id": camera_id, "public_id": "a" * 26},
        )
        connection.execute(
            text(
                "INSERT INTO camera_move_sagas "
                "(id, camera_id, source_node_id, target_node_id, source_generation, "
                "target_generation, desired_revision, force, state) "
                "VALUES (:id, :camera_id, :source, :target, 1, 2, 2, false, 'complete')"
            ),
            {
                "id": move_id,
                "camera_id": camera_id,
                "source": source_id,
                "target": target_id,
            },
        )
        connection.execute(text("DELETE FROM media_nodes"))

    command.upgrade(migration, "0009_camera_move_safety")

    with engine.connect() as connection:
        row = connection.execute(
            text(
                "SELECT source_port, target_port, source_endpoint, target_endpoint "
                "FROM camera_move_sagas WHERE id = :id"
            ),
            {"id": move_id},
        ).one()
    assert tuple(row) == (None, None, None, None)


@pytest.mark.parametrize(
    ("state", "maintenance", "reason"),
    (
        ("provisioning", False, "transition_node_state_invalid"),
        ("running", True, "transition_node_maintenance_invalid"),
    ),
)
def test_phase_d_transition_export_rejects_unsafe_node_intent_before_writing_manifest(
    postgres_database_url: str,
    tmp_path: Path,
    state: str,
    maintenance: bool,
    reason: str,
) -> None:
    migration = Config("alembic.ini")
    migration.set_main_option("sqlalchemy.url", postgres_database_url)
    command.upgrade(migration, "0008_node_administration")
    engine = create_engine(postgres_database_url)
    with engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO media_nodes "
                "(id, name, external_port, api_port, metrics_port, state, runtime_state, "
                "health, camera_capacity, registered_cameras, active_sources, maintenance, "
                "management_fresh, config_compatible, release_id, mediamtx_binary_sha256, "
                "creation_mode, desired_revision, applied_revision) "
                "VALUES (:id, 'unsafe', 12000, 13000, 14000, :state, 'stopped', "
                "'unknown', 100, 0, 0, :maintenance, false, false, 'phase-c', :digest, "
                "'operator', 1, 0)"
            ),
            {
                "id": UUID(int=1),
                "state": state,
                "maintenance": maintenance,
                "digest": "a" * 64,
            },
        )
    manifest = (tmp_path / "phase-d.json").resolve()

    with pytest.raises(PhaseDTransitionError, match=reason):
        export_transition(postgres_database_url, manifest)

    assert not manifest.exists()


def test_phase_d_transition_round_trip_preserves_camera_uuid_and_public_rtsp_path(
    postgres_database_url: str,
    tmp_path: Path,
) -> None:
    migration = Config("alembic.ini")
    migration.set_main_option("sqlalchemy.url", postgres_database_url)
    command.upgrade(migration, "0008_node_administration")
    engine = create_engine(postgres_database_url)
    node_id = UUID("00000000-0000-0000-0000-000000000001")
    camera_id = UUID("10000000-0000-0000-0000-000000000001")
    public_id = "a" * 26
    with engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO media_nodes "
                "(id, name, external_port, api_port, metrics_port, state, runtime_state, "
                "health, camera_capacity, registered_cameras, active_sources, maintenance, "
                "management_fresh, config_compatible, release_id, mediamtx_binary_sha256, "
                "creation_mode, desired_revision, applied_revision) "
                "VALUES (:id, 'media-a', 12000, 13000, 14000, 'maintenance', 'running', "
                "'healthy', 100, 1, 1, true, true, true, 'phase-c', :digest, "
                "'operator', 1, 1)"
            ),
            {"id": node_id, "digest": "a" * 64},
        )
        connection.execute(
            text(
                "INSERT INTO cameras "
                "(id, name, source_url, public_id, state, desired_revision, applied_revision) "
                "VALUES (:id, 'entrance', 'rtsp://camera.local/main', :public_id, "
                "'enabled', 1, 1)"
            ),
            {"id": camera_id, "public_id": public_id},
        )
        connection.execute(
            text("INSERT INTO public_id_tombstones (public_id) VALUES (:public_id)"),
            {"public_id": public_id},
        )
        connection.execute(
            text(
                "INSERT INTO camera_placements "
                "(camera_id, node_id, placement_mode, generation) "
                "VALUES (:camera_id, :node_id, 'manual', 1)"
            ),
            {"camera_id": camera_id, "node_id": node_id},
        )
        connection.execute(
            text(
                "INSERT INTO camera_placement_history "
                "(camera_id, node_id, placement_mode, generation) "
                "VALUES (:camera_id, :node_id, 'manual', 1)"
            ),
            {"camera_id": camera_id, "node_id": node_id},
        )
        connection.execute(
            text(
                "INSERT INTO audit_events "
                "(id, aggregate_type, aggregate_id, event_type, aggregate_revision, payload) "
                "VALUES (:id, 'media_node', :node_id, 'media_node.legacy', 7, '{}'::jsonb)"
            ),
            {"id": UUID(int=7), "node_id": node_id},
        )

    manifest = (tmp_path / "transition" / "phase-d.json").resolve()
    manifest_sha256 = export_transition(postgres_database_url, manifest)

    with engine.begin() as connection:
        connection.execute(text("DELETE FROM camera_placements"))
        connection.execute(
            text("UPDATE cameras SET state='deleted', desired_revision=2, applied_revision=2")
        )
        connection.execute(text("DELETE FROM media_nodes"))
    command.upgrade(migration, "head")
    with engine.begin() as connection:
        database_name = str(connection.scalar(text("SELECT current_database()")))
        quoted_database = connection.dialect.identifier_preparer.quote(database_name)
        connection.execute(text(f"ALTER DATABASE {quoted_database} SET synchronous_commit = off"))
        connection.execute(
            text(
                "CREATE FUNCTION require_sync_transition() RETURNS trigger AS $$ "
                "BEGIN IF current_setting('synchronous_commit') <> 'on' THEN "
                "RAISE EXCEPTION 'transition must be synchronous'; END IF; RETURN NEW; END; "
                "$$ LANGUAGE plpgsql"
            )
        )
        connection.execute(
            text(
                "CREATE TRIGGER require_sync_transition BEFORE INSERT ON audit_events "
                "FOR EACH ROW EXECUTE FUNCTION require_sync_transition()"
            )
        )
    _version, digest = trusted_mediamtx_identity(platform.machine(), "0.1.0")
    policy = NodeRegistrationPolicy(
        max_nodes=50,
        external_ports=range(12000, 12001),
        api_ports=range(13000, 13001),
        metrics_ports=range(14000, 14001),
        reserved_ports=frozenset(),
    )

    with pytest.raises(PhaseDTransitionError, match="transition_node_port_in_use"):
        restore_transition(
            postgres_database_url,
            manifest,
            manifest_sha256=manifest_sha256,
            release_id="0.1.0",
            mediamtx_binary_sha256=digest.root,
            node_policy=policy,
            port_is_bindable=lambda _port: False,
        )
    with engine.connect() as connection:
        assert connection.scalar(text("SELECT count(*) FROM media_nodes")) == 0

    restore_transition(
        postgres_database_url,
        manifest,
        manifest_sha256=manifest_sha256,
        release_id="0.1.0",
        mediamtx_binary_sha256=digest.root,
        node_policy=policy,
        port_is_bindable=lambda _port: True,
    )
    restore_transition(
        postgres_database_url,
        manifest,
        manifest_sha256=manifest_sha256,
        release_id="0.1.0",
        mediamtx_binary_sha256=digest.root,
        node_policy=policy,
        port_is_bindable=lambda _port: True,
    )

    with engine.connect() as connection:
        row = connection.execute(
            text(
                "SELECT cameras.id, cameras.public_id, cameras.state, "
                "camera_placements.node_id, camera_placements.generation, "
                "media_nodes.external_port, media_nodes.release_id, "
                "media_nodes.state, media_nodes.runtime_state, "
                "media_nodes.maintenance, media_nodes.desired_revision, "
                "media_nodes.applied_revision "
                "FROM cameras JOIN camera_placements ON camera_placements.camera_id=cameras.id "
                "JOIN media_nodes ON media_nodes.id=camera_placements.node_id"
            )
        ).one()
        tombstone_count = connection.scalar(
            text("SELECT count(*) FROM public_id_tombstones WHERE public_id=:public_id"),
            {"public_id": public_id},
        )
        access_policy = connection.execute(
            text(
                "SELECT internet_cidrs, local_cidrs, revision "
                "FROM camera_access_policies WHERE camera_id=:camera_id"
            ),
            {"camera_id": camera_id},
        ).one()
        access_policy_audit_count = connection.scalar(
            text(
                "SELECT count(*) FROM audit_events "
                "WHERE aggregate_type='camera_access_policy' "
                "AND aggregate_id=:camera_id "
                "AND event_type='camera.access_policy_created'"
            ),
            {"camera_id": camera_id},
        )
    assert row == (
        camera_id,
        public_id,
        "enabled",
        node_id,
        2,
        12000,
        "0.1.0",
        "maintenance",
        "provisioning",
        True,
        8,
        0,
    )
    assert tombstone_count == 1
    assert access_policy == ([], [], 1)
    assert access_policy_audit_count == 1
    assert f"rtsp://server:12000/{public_id}" == f"rtsp://server:12000/{row.public_id}"
    assert manifest.stat().st_mode & 0o777 == 0o600

    with engine.begin() as connection:
        connection.execute(
            text("DELETE FROM camera_access_policies WHERE camera_id=:camera_id"),
            {"camera_id": camera_id},
        )
    with pytest.raises(PhaseDTransitionError, match="transition_target_not_empty"):
        restore_transition(
            postgres_database_url,
            manifest,
            manifest_sha256=manifest_sha256,
            release_id="0.1.0",
            mediamtx_binary_sha256=digest.root,
            node_policy=policy,
            port_is_bindable=lambda _port: True,
        )

    with engine.begin() as connection:
        connection.execute(
            text("UPDATE cameras SET name='unexpected' WHERE id=:camera_id"),
            {"camera_id": camera_id},
        )
    with pytest.raises(PhaseDTransitionError, match="transition_target_not_empty"):
        restore_transition(
            postgres_database_url,
            manifest,
            manifest_sha256=manifest_sha256,
            release_id="0.1.0",
            mediamtx_binary_sha256=digest.root,
            node_policy=policy,
            port_is_bindable=lambda _port: True,
        )


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
            text("SELECT management_fresh, management_observed_at FROM media_nodes")
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


def test_new_control_plane_is_a_compatibility_bridge_for_previous_schema(
    postgres_database_url: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    migration = Config("alembic.ini")
    migration.set_main_option("sqlalchemy.url", postgres_database_url)
    command.upgrade(migration, "0012_operator_sessions")
    monkeypatch.setenv("RTSP_PROXY_ROLE", "web")
    monkeypatch.setenv("RTSP_PROXY_DATABASE_URL", postgres_database_url)

    app = create_app_from_environment()
    with TestClient(app) as client:
        assert client.get("/health/live").status_code == 200
        response = client.get("/api/v1/dashboard/snapshot")

    assert response.status_code == 503
    assert response.json()["detail"]["code"] == "fleet_snapshot_unavailable"


def test_schema_check_sanitizes_database_connection_failures() -> None:
    store = PostgresNodeStore(
        "postgresql+psycopg://postgres@127.0.0.1:1/unavailable",
        lifecycle_lock_timeout_seconds=0.1,
    )

    with pytest.raises(DatabaseSchemaMismatch, match="database_schema_mismatch"):
        store.assert_schema_compatible()

    with pytest.raises(DatabaseSchemaMismatch, match="database_schema_mismatch"):
        store.schema_is_current()


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
                node_runtime_socket=Path("/run/missing.sock"),
                node_mediamtx_binary_sha256=TRUSTED_MEDIAMTX_SHA256,
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
        audit = (
            connection.execute(
                text(
                    "SELECT aggregate_id, event_type, payload "
                    "FROM audit_events ORDER BY occurred_at, id"
                )
            )
            .mappings()
            .one()
        )
        outbox = (
            connection.execute(
                text(
                    "SELECT aggregate_id, event_type, payload, status "
                    "FROM outbox_messages ORDER BY occurred_at, id"
                )
            )
            .mappings()
            .one()
        )
        expected_payload = {
            "name": "audited",
            "external_port": 12000,
            "api_port": 20000,
            "metrics_port": 20100,
            "release_id": "0.2.1",
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


def test_postgres_node_command_persists_redacted_operator_attribution(
    postgres_database_url: str,
) -> None:
    upgrade_database(postgres_database_url)
    store = PostgresNodeStore(postgres_database_url)
    node_id = UUID("00000000-0000-0000-0000-000000000001")

    node = store.register_automatically(
        name="audited-dashboard-node",
        allowed_ports=(12000,),
        max_nodes=1,
        preferred_port=12000,
        choose_port=lambda available: available[0],
        new_node_id=lambda: node_id,
        mutation_context=NODE_MUTATION_CONTEXT,
    )

    engine = create_engine(postgres_database_url, hide_parameters=True)
    with engine.connect() as connection:
        audit = (
            connection.execute(
                text("SELECT id, payload FROM audit_events WHERE aggregate_type = 'media_node'")
            )
            .mappings()
            .one()
        )
        outbox = (
            connection.execute(
                text("SELECT id, payload FROM outbox_messages WHERE aggregate_type = 'media_node'")
            )
            .mappings()
            .one()
        )
    assert audit == outbox
    assert node.desired_revision == 1
    assert audit["payload"]["operator"] == NODE_MUTATION_CONTEXT.event_payload()
    assert "password" not in str(audit["payload"]).lower()
    engine.dispose()
    store.close()


def test_postgres_node_command_fence_is_checked_before_normative_mutation(
    postgres_database_url: str,
) -> None:
    upgrade_database(postgres_database_url)
    store = PostgresNodeStore(postgres_database_url)
    node_id = UUID("00000000-0000-0000-0000-000000000001")
    node = store.register_automatically(
        name="fenced-dashboard-node",
        allowed_ports=(12000,),
        max_nodes=1,
        preferred_port=12000,
        choose_port=lambda available: available[0],
        new_node_id=lambda: node_id,
    )

    with pytest.raises(NodeLifecycleConflict, match="node_command_fence_conflict"):
        store.request_desired_state(
            node.id,
            NodeState.RUNNING,
            fence=NodeCommandFence(
                expected_revision=node.desired_revision + 1,
                expected_state=NodeState.PROVISIONING,
            ),
            mutation_context=NODE_MUTATION_CONTEXT,
        )

    persisted = store.get_node(node.id)
    assert persisted == node
    engine = create_engine(postgres_database_url, hide_parameters=True)
    with engine.connect() as connection:
        assert (
            connection.scalar(
                text("SELECT count(*) FROM audit_events WHERE aggregate_id = :node_id"),
                {"node_id": node.id},
            )
            == 1
        )
        assert (
            connection.scalar(
                text("SELECT count(*) FROM outbox_messages WHERE aggregate_id = :node_id"),
                {"node_id": node.id},
            )
            == 1
        )
    engine.dispose()
    store.close()


@pytest.mark.parametrize("rejected_table", ["audit_events", "outbox_messages"])
def test_postgres_node_registration_rolls_back_when_normative_append_fails(
    postgres_database_url: str,
    rejected_table: str,
) -> None:
    upgrade_database(postgres_database_url)
    engine = create_engine(postgres_database_url, hide_parameters=True)
    trigger_name = f"reject_node_{rejected_table}"
    with engine.begin() as connection:
        connection.execute(
            text(
                f"CREATE FUNCTION {trigger_name}() RETURNS trigger AS $$ "
                "BEGIN RAISE EXCEPTION 'reject node event'; END; $$ LANGUAGE plpgsql"
            )
        )
        connection.execute(
            text(
                f"CREATE TRIGGER {trigger_name} BEFORE INSERT ON {rejected_table} "
                "FOR EACH ROW WHEN (NEW.aggregate_type = 'media_node') "
                f"EXECUTE FUNCTION {trigger_name}()"
            )
        )
    store = PostgresNodeStore(postgres_database_url)

    with pytest.raises(SQLAlchemyError):
        store.register_automatically(
            name="rolled-back-dashboard-node",
            allowed_ports=(12000,),
            max_nodes=1,
            preferred_port=12000,
            choose_port=lambda available: available[0],
            new_node_id=lambda: UUID("00000000-0000-0000-0000-000000000001"),
            mutation_context=NODE_MUTATION_CONTEXT,
        )

    assert store.list_nodes() == ()
    with engine.connect() as connection:
        assert (
            connection.scalar(
                text("SELECT count(*) FROM audit_events WHERE aggregate_type = 'media_node'")
            )
            == 0
        )
        assert (
            connection.scalar(
                text("SELECT count(*) FROM outbox_messages WHERE aggregate_type = 'media_node'")
            )
            == 0
        )
    store.close()
    engine.dispose()


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
        events = (
            connection.execute(
                text(
                    "SELECT event_type, aggregate_revision FROM audit_events "
                    "ORDER BY aggregate_revision"
                )
            )
            .tuples()
            .all()
        )
        outbox = (
            connection.execute(
                text(
                    "SELECT event_type, aggregate_revision FROM outbox_messages "
                    "ORDER BY aggregate_revision"
                )
            )
            .tuples()
            .all()
        )
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
    asynchronous_default_url = postgres_database_url + "?options=-c%20synchronous_commit%3Doff"
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
            release_id="0.1.0",
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
            release_id="0.1.0",
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

    with pytest.raises(InvalidCameraName, match="camera_name_invalid"):
        store.place_camera_manually(
            camera_id=UUID("10000000-0000-0000-0000-000000000002"),
            name="x" * 129,
            source_url="rtsp://camera.local/main",
            public_id=PublicId.parse("b" * 25 + "a"),
            node_id=node_id,
        )

    assert store.list_cameras() == ()


@pytest.mark.parametrize(
    ("source_url", "reason"),
    (
        ("rtsp://camera.local/" + ("é" * 4090), "camera_source_url_too_long"),
        ("rtsp://camera.local:bad/main", "camera_source_url_invalid"),
        ("http://camera.local/main", "camera_source_url_invalid"),
        ("rtsp://camera.local/main?token=secret", "camera_source_secret_reference_required"),
    ),
)
def test_camera_source_validation_fails_before_persistence(
    source_url: str,
    reason: str,
) -> None:
    node_id = UUID("00000000-0000-0000-0000-000000000001")
    now = datetime.now(UTC)
    store = InMemoryNodeStore(
        nodes=(
            MediaNode(
                id=node_id,
                name="media-a",
                external_port=12000,
                state=NodeState.RUNNING,
                runtime_state=NodeState.RUNNING,
                health=NodeHealth.HEALTHY,
                management_fresh=True,
                management_observed_at=now,
                runtime_observed_at=now,
                config_compatible=True,
                desired_revision=1,
                applied_revision=1,
            ),
        )
    )

    with pytest.raises(InvalidCameraSource, match=reason):
        store.place_camera_manually(
            camera_id=UUID("10000000-0000-0000-0000-000000000001"),
            name="invalid",
            source_url=source_url,
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
        event = (
            connection.execute(
                text(
                    "SELECT event_type, payload FROM audit_events "
                    "WHERE aggregate_id = :node_id AND event_type = :event_type"
                ),
                {"node_id": node_id, "event_type": "media_node.release_changed"},
            )
            .mappings()
            .one()
        )
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

    def capture_run(
        app: object,
        *,
        host: str,
        port: int,
        access_log: bool,
        ssl_certfile: str | None,
        ssl_keyfile: str | None,
    ) -> None:
        launched.update(
            app=app,
            host=host,
            port=port,
            access_log=access_log,
            ssl_certfile=ssl_certfile,
            ssl_keyfile=ssl_keyfile,
        )

    monkeypatch.setattr("rtsp_proxy.runtime.uvicorn.run", capture_run)

    run_web()

    assert launched["host"] == "127.0.0.1"
    assert launched["port"] == 8000
    assert launched["access_log"] is False
    assert launched["ssl_certfile"] is None
    assert launched["ssl_keyfile"] is None
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
        if action in {NodeRuntimeAction.STOP, NodeRuntimeAction.DELETE} or (
            action is NodeRuntimeAction.OBSERVE
            and node.state is NodeState.DRAINING
            and node.runtime_state is not NodeState.RUNNING
        ):
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

    def observe_disruption(self, node: MediaNode) -> NodeDisruptionObservation:
        return RecordingDisruptionObserver().observe(node)

    def fence_disruption(
        self,
        node: MediaNode,
        affected_public_ids: tuple[PublicId, ...],
    ) -> AbstractContextManager[NodeDisruptionFenceLease]:
        return RecordingDisruptionObserver().fence(node, affected_public_ids)


class RecordingDisruptionObserver:
    def __init__(
        self,
        active_reader_public_ids: tuple[PublicId, ...] = (),
        *,
        on_fenced: Callable[[], None] | None = None,
    ) -> None:
        self.active_reader_public_ids = active_reader_public_ids
        self.on_fenced = on_fenced
        self.fence_active = False
        self.process_id_override: int | None = None

    def observe(self, node: MediaNode) -> NodeDisruptionObservation:
        if (
            node.process_id is None
            or node.process_start_ticks is None
            or node.process_boot_id is None
        ):
            raise AssertionError("ready node fixture lacks process identity")
        return NodeDisruptionObservation(
            active_reader_public_ids=self.active_reader_public_ids,
            observed_at=datetime.now(UTC),
            process_id=self.process_id_override or node.process_id,
            process_start_ticks=node.process_start_ticks,
            process_boot_id=node.process_boot_id,
            release_id=node.release_id,
        )

    @contextmanager
    def fence(
        self,
        node: MediaNode,
        affected_public_ids: tuple[PublicId, ...],
    ) -> Iterator[NodeDisruptionFenceLease]:
        if not set(self.active_reader_public_ids).issubset(affected_public_ids):
            raise AssertionError("reader fixture outside affected camera inventory")
        self.fence_active = True
        try:
            if self.on_fenced is not None:
                self.on_fenced()
            yield NodeDisruptionFenceLease(observation=self.observe(node))
        finally:
            self.fence_active = False


def test_node_disruption_proof_rejects_duplicate_readers_and_invalid_deadline() -> None:
    public_id = PublicId.parse("a" * 26)
    observed_at = datetime.now(UTC)
    boot_id = UUID("30000000-0000-0000-0000-000000000001")

    with pytest.raises(ValueError, match="node_disruption_observation_invalid"):
        NodeDisruptionObservation(
            active_reader_public_ids=(public_id, public_id),
            observed_at=observed_at,
            process_id=3001,
            process_start_ticks=4001,
            process_boot_id=boot_id,
            release_id="0.2.1",
        )

    observation = NodeDisruptionObservation(
        active_reader_public_ids=(public_id,),
        observed_at=observed_at,
        process_id=3001,
        process_start_ticks=4001,
        process_boot_id=boot_id,
        release_id="0.2.1",
    )
    with pytest.raises(ValueError, match="node_disruption_deadline_invalid"):
        NodeDisruptionFenceLease(
            observation=observation,
            work_deadline_unix_ms=0,
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
    assert persisted.observed_release_id == "0.2.1"


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


@pytest.mark.parametrize("operation", ("stop", "restart", "release"))
def test_node_operations_expose_an_active_camera_move_conflict(operation: str) -> None:
    class ActiveMoveStore(InMemoryNodeStore):
        def request_stop(
            self,
            node_id: UUID,
            *,
            fence: NodeCommandFence | None = None,
            mutation_context: NodeMutationContext | None = None,
        ) -> MediaNode:
            del fence, mutation_context
            raise NodeLifecycleConflict("node_operation_in_progress")

        def request_restart(
            self,
            node_id: UUID,
            *,
            fence: NodeCommandFence | None = None,
            mutation_context: NodeMutationContext | None = None,
        ) -> MediaNode:
            del fence, mutation_context
            raise NodeLifecycleConflict("node_operation_in_progress")

        def request_release(
            self,
            node_id: UUID,
            *,
            release_id: str,
            mediamtx_binary_sha256: str,
            fence: NodeCommandFence | None = None,
            mutation_context: NodeMutationContext | None = None,
        ) -> MediaNode:
            del fence, mutation_context
            raise NodeLifecycleConflict("node_operation_in_progress")

    node_id = UUID("00000000-0000-0000-0000-000000000001")
    control = NodeControl(
        store=ActiveMoveStore(nodes=(MediaNode(id=node_id, name="media-a", external_port=12000),)),
        choose_port=lambda available: available[0],
        new_node_id=uuid4,
        node_runtime=RecordingLifecycleRuntime(),
    )
    settings = Settings(
        role=RuntimeRole.WEB,
        node_release_id="release-2",
        node_mediamtx_binary_sha256="b" * 64,
    )
    client = TestClient(create_app(settings, node_control=control))

    if operation == "release":
        response = client.put(
            f"/api/v1/nodes/{node_id}/release",
            json={"release_id": "release-2", "mediamtx_binary_sha256": "b" * 64},
        )
    else:
        response = client.post(f"/api/v1/nodes/{node_id}/{operation}")

    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "node_operation_in_progress"


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
        release_id="0.1.0",
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
        ensure_automatic_capacity=lambda _context: node_control.ensure_automatic_capacity(
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
        ensure_automatic_capacity=lambda _context: node_control.ensure_automatic_capacity(
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
        ensure_automatic_capacity=lambda _context: node_control.ensure_automatic_capacity(
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
        ensure_automatic_capacity=lambda _context: node_control.ensure_automatic_capacity(
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
    client = TestClient(create_app(Settings(role=RuntimeRole.WEB), node_control=control))

    response = client.post(f"/api/v1/nodes/00000000-0000-0000-0000-000000000099/{operation}")

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
    client = TestClient(create_app(Settings(role=RuntimeRole.WEB), node_control=control))
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
                store=BusyStore(nodes=(MediaNode(id=node_id, name="busy", external_port=12000),)),
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
                store=BusyStore(nodes=(MediaNode(id=node_id, name="busy", external_port=12000),)),
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
    def busy_capacity(_context: NodeMutationContext | None) -> MediaNode:
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
    client = TestClient(create_app(Settings(role=RuntimeRole.WEB), node_control=control))

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
    client = TestClient(create_app(Settings(role=RuntimeRole.WEB), node_control=control))

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
        response.json()["detail"]["code"] == "eligible_node_missing" for response in responses
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


def test_postgresql_reconcile_guard_honors_shutdown_cancellation(
    postgres_database_url: str,
) -> None:
    upgrade_database(postgres_database_url)
    store = PostgresNodeStore(
        postgres_database_url,
        lifecycle_lock_pool_size=2,
        lifecycle_lock_timeout_seconds=30,
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
    cancelled = Event()

    def contend() -> str:
        with store.reconcile_guard(node.id, cancelled=cancelled.is_set):
            pytest.fail("cancelled reconcile guard was acquired")
        return "unreachable"

    with store.lifecycle_guard(node.id), ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(contend)
        time.sleep(0.1)
        cancelled.set()
        with pytest.raises(NodeLifecycleBusy, match="node_lifecycle_busy"):
            future.result(timeout=1)


def test_in_memory_move_deadline_is_rechecked_at_the_atomic_switch() -> None:
    source_id = UUID("00000000-0000-0000-0000-000000000001")
    target_id = UUID("00000000-0000-0000-0000-000000000002")
    camera_id = UUID("10000000-0000-0000-0000-000000000001")
    now = datetime.now(UTC)
    current_time = [now]
    store = InMemoryNodeStore(
        nodes=tuple(
            MediaNode(
                id=node_id,
                name=name,
                external_port=port,
                state=NodeState.RUNNING,
                runtime_state=NodeState.RUNNING,
                health=NodeHealth.HEALTHY,
                management_fresh=True,
                management_observed_at=now,
                config_compatible=True,
                desired_revision=1,
                applied_revision=1,
            )
            for node_id, name, port in (
                (source_id, "source", 12000),
                (target_id, "target", 12001),
            )
        ),
        clock=lambda: current_time[0],
    )
    store.place_camera_manually(
        camera_id=camera_id,
        name="entrance",
        source_url="rtsp://camera.local/main",
        public_id=PublicId.parse("a" * 26),
        node_id=source_id,
    )
    move = store.create_camera_move(
        move_id=UUID("30000000-0000-0000-0000-000000000001"),
        camera_id=camera_id,
        target_node_id=target_id,
        expected_revision=1,
        force=False,
        timeout_seconds=1,
    )
    current_time[0] += timedelta(seconds=2)

    with pytest.raises(CameraMoveExpired, match="camera_move_expired"):
        store.switch_camera_move(move.id)

    camera = store.get_camera(camera_id)
    assert camera is not None
    assert camera.node_id == source_id
    assert store.get_node(source_id).registered_cameras == 1  # type: ignore[union-attr]
    assert store.get_node(target_id).registered_cameras == 0  # type: ignore[union-attr]


def test_postgresql_move_deadline_is_rechecked_in_the_switch_transaction(
    postgres_database_url: str,
) -> None:
    upgrade_database(postgres_database_url)
    store = PostgresNodeStore(postgres_database_url)
    source_id = UUID("00000000-0000-0000-0000-000000000001")
    target_id = UUID("00000000-0000-0000-0000-000000000002")
    camera_id = UUID("10000000-0000-0000-0000-000000000001")
    for node_id, name, port in (
        (source_id, "source", 12000),
        (target_id, "target", 12001),
    ):

        def allocate_node_id(selected: UUID = node_id) -> UUID:
            return selected

        node = store.register_automatically(
            name=name,
            allowed_ports=(12000, 12001),
            max_nodes=2,
            preferred_port=port,
            choose_port=lambda available: available[0],
            new_node_id=allocate_node_id,
            api_ports=(13000, 13001),
            metrics_ports=(14000, 14001),
        )
        node = store.request_desired_state(node.id, NodeState.RUNNING)
        store.apply_runtime_observation(
            node.id,
            runtime_observation_for(node.id, revision=node.desired_revision),
        )
    camera = store.place_camera_manually(
        camera_id=camera_id,
        name="entrance",
        source_url="rtsp://camera.local/main",
        public_id=PublicId.parse("a" * 26),
        node_id=source_id,
    )
    move = store.create_camera_move(
        move_id=UUID("30000000-0000-0000-0000-000000000001"),
        camera_id=camera.id,
        target_node_id=target_id,
        expected_revision=camera.desired_revision,
        force=False,
        timeout_seconds=300,
    )

    engine = create_engine(postgres_database_url)
    with engine.begin() as connection:
        connection.execute(
            text(
                "UPDATE camera_move_sagas "
                "SET expires_at = clock_timestamp() - interval '1 second' "
                "WHERE id = :move_id"
            ),
            {"move_id": move.id},
        )

    with pytest.raises(CameraMoveExpired, match="camera_move_expired"):
        store.switch_camera_move(move.id)

    unchanged = store.get_camera(camera.id)
    assert unchanged is not None
    assert unchanged.node_id == source_id
    assert store.get_node(source_id).registered_cameras == 1  # type: ignore[union-attr]
    assert store.get_node(target_id).registered_cameras == 0  # type: ignore[union-attr]
    store.close()


def test_postgresql_move_switch_honors_shutdown_while_placement_lock_is_held(
    postgres_database_url: str,
) -> None:
    upgrade_database(postgres_database_url)
    store = PostgresNodeStore(postgres_database_url, lifecycle_lock_timeout_seconds=30)
    source_id = UUID("00000000-0000-0000-0000-000000000001")
    target_id = UUID("00000000-0000-0000-0000-000000000002")
    camera_id = UUID("10000000-0000-0000-0000-000000000001")
    for node_id, name, port in (
        (source_id, "source", 12000),
        (target_id, "target", 12001),
    ):

        def allocate_node_id(selected: UUID = node_id) -> UUID:
            return selected

        node = store.register_automatically(
            name=name,
            allowed_ports=(12000, 12001),
            max_nodes=2,
            preferred_port=port,
            choose_port=lambda available: available[0],
            new_node_id=allocate_node_id,
            api_ports=(13000, 13001),
            metrics_ports=(14000, 14001),
        )
        node = store.request_desired_state(node.id, NodeState.RUNNING)
        store.apply_runtime_observation(
            node.id,
            runtime_observation_for(node.id, revision=node.desired_revision),
        )
    camera = store.place_camera_manually(
        camera_id=camera_id,
        name="entrance",
        source_url="rtsp://camera.local/main",
        public_id=PublicId.parse("a" * 26),
        node_id=source_id,
    )
    move = store.create_camera_move(
        move_id=UUID("30000000-0000-0000-0000-000000000001"),
        camera_id=camera.id,
        target_node_id=target_id,
        expected_revision=camera.desired_revision,
        force=False,
    )
    cancelled = Event()
    engine = create_engine(postgres_database_url)
    with engine.connect() as blocker, ThreadPoolExecutor(max_workers=1) as executor:
        blocker.execute(
            text("SELECT pg_advisory_lock(:key)"),
            {"key": 0x43414D504C414345},
        )
        try:
            future = executor.submit(
                lambda: store.switch_camera_move(move.id, cancelled=cancelled.is_set)
            )
            time.sleep(0.1)
            cancelled.set()
            with pytest.raises(NodeLifecycleBusy, match="node_lifecycle_busy"):
                future.result(timeout=1)
        finally:
            blocker.execute(
                text("SELECT pg_advisory_unlock(:key)"),
                {"key": 0x43414D504C414345},
            )
    engine.dispose()
    store.close()


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

    with (
        pytest.raises(LookupError, match="node_not_found"),
        store.lifecycle_guard(UUID("00000000-0000-0000-0000-000000000001")),
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


def node_confirmation_service() -> ConfirmationTokenService:
    return ConfirmationTokenService(
        secret=b"test-confirmation-secret-that-is-at-least-32-bytes",
        lifetime_seconds=30,
        wall_time=lambda: 1_700_000_000.0,
    )


def test_drain_and_maintenance_exclude_placement_without_stopping_the_node() -> None:
    node_id = UUID("00000000-0000-0000-0000-000000000001")
    now = datetime.now(UTC)
    store = InMemoryNodeStore(
        nodes=(
            MediaNode(
                id=node_id,
                name="media-a",
                external_port=12000,
                state=NodeState.RUNNING,
                runtime_state=NodeState.RUNNING,
                health=NodeHealth.HEALTHY,
                management_fresh=True,
                management_observed_at=now,
                config_compatible=True,
                desired_revision=1,
                applied_revision=1,
            ),
        )
    )
    control = NodeControl(
        store=store,
        choose_port=lambda available: available[0],
        new_node_id=uuid4,
    )
    client = TestClient(create_app(Settings(role=RuntimeRole.WEB), node_control=control))

    drained = client.post(f"/api/v1/nodes/{node_id}/drain")
    maintained = client.post(f"/api/v1/nodes/{node_id}/maintenance")

    assert drained.status_code == 200
    assert drained.json()["state"] == "draining"
    assert drained.json()["runtime_state"] == "running"
    assert maintained.status_code == 200
    assert maintained.json()["state"] == "maintenance"
    with pytest.raises(EligibleNodeMissing, match="manual_node_ineligible"):
        store.place_camera_manually(
            camera_id=UUID("10000000-0000-0000-0000-000000000001"),
            name="blocked",
            source_url="rtsp://camera.local/main",
            public_id=PublicId.parse("a" * 26),
            node_id=node_id,
        )


def test_reconfigure_requires_drain_and_exact_confirmation_then_preserves_endpoint() -> None:
    runtime = RecordingLifecycleRuntime()
    node_id = UUID("00000000-0000-0000-0000-000000000001")
    camera_id = UUID("10000000-0000-0000-0000-000000000001")
    store = InMemoryNodeStore()
    control = NodeControl(
        store=store,
        choose_port=lambda available: available[0],
        new_node_id=lambda: node_id,
        node_runtime=runtime,
        provision_on_create=True,
        confirmations=node_confirmation_service(),
    )
    cameras = CameraControl(
        store=store,
        new_camera_id=lambda: camera_id,
        new_public_id=lambda: "a" * 26,
    )
    client = TestClient(
        create_app(
            Settings(
                role=RuntimeRole.WEB,
                node_port_range_start=12000,
                node_port_range_end=12000,
            ),
            node_control=control,
            camera_control=cameras,
        )
    )
    created = client.post(
        "/api/v1/nodes",
        json={"name": "media-a", "external_port": 12000},
    )
    camera = cameras.create_camera(
        name="entrance",
        source_url="rtsp://camera.local/main",
        node_id=node_id,
    )

    not_drained = client.post(f"/api/v1/nodes/{node_id}/reconfigure/preview")
    assert not_drained.status_code == 409
    assert not_drained.json()["detail"]["code"] == "node_not_draining"
    assert client.post(f"/api/v1/nodes/{node_id}/drain").status_code == 200

    missing_confirmation = client.post(
        f"/api/v1/nodes/{node_id}/reconfigure",
        json={},
    )
    preview = client.post(f"/api/v1/nodes/{node_id}/reconfigure/preview")
    reconfigured = client.post(
        f"/api/v1/nodes/{node_id}/reconfigure",
        json={"confirmation_token": preview.json()["confirmation_token"]},
    )
    replay = client.post(
        f"/api/v1/nodes/{node_id}/reconfigure",
        json={"confirmation_token": preview.json()["confirmation_token"]},
    )

    assert created.status_code == 201
    assert missing_confirmation.status_code == 409
    assert missing_confirmation.json()["detail"]["code"] == (
        "node_disruption_confirmation_required"
    )
    assert preview.status_code == 200
    assert preview.json()["external_port"] == 12000
    assert preview.json()["registered_cameras"] == 1
    assert preview.json()["target_release_id"] == "0.2.1"
    assert preview.json()["target_mediamtx_binary_sha256"] == "0" * 64
    assert reconfigured.status_code == 200
    assert reconfigured.json()["state"] == "draining"
    assert reconfigured.json()["runtime_state"] == "running"
    assert reconfigured.json()["external_port"] == 12000
    assert reconfigured.json()["applied_revision"] == reconfigured.json()["desired_revision"]
    assert cameras.list_cameras()[0] == camera
    assert runtime.calls[-1] == (NodeRuntimeAction.RECONFIGURE_RESTART, node_id)
    assert replay.status_code == 409
    assert replay.json()["detail"]["code"] == "node_disruption_confirmation_required"
    resumed = client.post(f"/api/v1/nodes/{node_id}/resume")
    assert resumed.status_code == 200
    assert resumed.json()["state"] == "running"


def test_confirmed_reconfigure_upgrades_nonempty_node_release_atomically() -> None:
    runtime = RecordingLifecycleRuntime()
    node_id = UUID("00000000-0000-0000-0000-000000000001")
    camera_id = UUID("10000000-0000-0000-0000-000000000001")
    store = InMemoryNodeStore()
    control = NodeControl(
        store=store,
        choose_port=lambda available: available[0],
        new_node_id=lambda: node_id,
        node_runtime=runtime,
        provision_on_create=True,
        confirmations=node_confirmation_service(),
        reconfigure_release_id="0.2.0",
        reconfigure_mediamtx_binary_sha256="b" * 64,
    )
    cameras = CameraControl(
        store=store,
        new_camera_id=lambda: camera_id,
        new_public_id=lambda: "a" * 26,
    )
    created = control.register_node(
        name="legacy-node",
        port_range_start=12000,
        port_range_end=12000,
        max_nodes=1,
        release_id="0.1.0",
        mediamtx_binary_sha256="a" * 64,
    )
    camera = cameras.create_camera(
        name="entrance",
        source_url="rtsp://camera.local/main",
        node_id=node_id,
    )
    control.set_administrative_state(node_id, NodeState.DRAINING)
    preview = control.preview_reconfigure(node_id)

    assert preview.target_release_id == "0.2.0"
    assert preview.target_mediamtx_binary_sha256 == "b" * 64

    upgraded = control.reconfigure_node(
        node_id,
        confirmation_token=preview.confirmation_token,
    )

    assert created.release_id == "0.1.0"
    assert upgraded.release_id == "0.2.0"
    assert upgraded.mediamtx_binary_sha256 == "b" * 64
    assert upgraded.applied_revision == upgraded.desired_revision
    assert cameras.list_cameras() == (camera,)
    assert runtime.calls[-1] == (NodeRuntimeAction.RECONFIGURE_RESTART, node_id)


def test_postgresql_confirmed_reconfigure_upgrades_nonempty_node_release(
    postgres_database_url: str,
) -> None:
    upgrade_database(postgres_database_url)
    store = PostgresNodeStore(postgres_database_url)
    runtime = RecordingLifecycleRuntime()
    node_id = UUID("00000000-0000-0000-0000-000000000001")
    camera_id = UUID("10000000-0000-0000-0000-000000000001")
    control = NodeControl(
        store=store,
        choose_port=lambda available: available[0],
        new_node_id=lambda: node_id,
        node_runtime=runtime,
        provision_on_create=True,
        confirmations=node_confirmation_service(),
        reconfigure_release_id="0.2.0",
        reconfigure_mediamtx_binary_sha256="b" * 64,
    )
    control.register_node(
        name="legacy-postgres-node",
        port_range_start=12000,
        port_range_end=12000,
        max_nodes=1,
        release_id="0.1.0",
        mediamtx_binary_sha256="a" * 64,
    )
    CameraControl(
        store=store,
        new_camera_id=lambda: camera_id,
        new_public_id=lambda: "a" * 26,
    ).create_camera(
        name="entrance",
        source_url="rtsp://camera.local/main",
        node_id=node_id,
    )
    control.set_administrative_state(node_id, NodeState.DRAINING)
    preview = control.preview_reconfigure(node_id)

    upgraded = control.reconfigure_node(
        node_id,
        confirmation_token=preview.confirmation_token,
    )

    engine = create_engine(postgres_database_url)
    with engine.connect() as connection:
        event = connection.execute(
            text(
                "SELECT payload->>'previous_release_id', payload->>'release_id', "
                "payload->>'release_changed' FROM audit_events "
                "WHERE aggregate_id=:node_id "
                "AND event_type='media_node.reconfigure_requested'"
            ),
            {"node_id": node_id},
        ).one()
    engine.dispose()
    store.close()

    assert upgraded.release_id == "0.2.0"
    assert upgraded.mediamtx_binary_sha256 == "b" * 64
    assert upgraded.registered_cameras == 1
    assert event == ("0.1.0", "0.2.0", "true")


def test_failed_reconfigure_can_be_retried_only_while_node_remains_draining() -> None:
    node_id = UUID("00000000-0000-0000-0000-000000000001")
    store = InMemoryNodeStore(
        nodes=(
            MediaNode(
                id=node_id,
                name="media-a",
                external_port=12000,
                state=NodeState.DRAINING,
                runtime_state=NodeState.FAILED,
                desired_revision=2,
                applied_revision=1,
            ),
        )
    )
    runtime = RecordingLifecycleRuntime()
    control = NodeControl(
        store=store,
        choose_port=lambda available: available[0],
        new_node_id=uuid4,
        node_runtime=runtime,
        confirmations=node_confirmation_service(),
    )

    preview = control.preview_reconfigure(node_id)
    recovered = control.reconfigure_node(
        node_id,
        confirmation_token=preview.confirmation_token,
    )

    assert recovered.state is NodeState.DRAINING
    assert recovered.runtime_state is NodeState.RUNNING
    assert recovered.applied_revision == recovered.desired_revision == 3
    assert runtime.calls == [
        (NodeRuntimeAction.OBSERVE, node_id),
        (NodeRuntimeAction.OBSERVE, node_id),
        (NodeRuntimeAction.RECONFIGURE_RESTART, node_id),
    ]


def test_node_administration_public_errors_are_typed() -> None:
    unknown_id = UUID("00000000-0000-0000-0000-000000000099")
    without_control = TestClient(create_app(Settings(role=RuntimeRole.WEB)))

    assert without_control.post(f"/api/v1/nodes/{unknown_id}/drain").status_code == 503
    assert (
        without_control.post(
            f"/api/v1/nodes/{unknown_id}/port-change/preview",
            json={"new_port": 12000},
        ).status_code
        == 503
    )
    assert (
        without_control.post(
            f"/api/v1/nodes/{unknown_id}/reconfigure/preview",
        ).status_code
        == 503
    )
    assert (
        without_control.post(
            f"/api/v1/nodes/{unknown_id}/reconfigure",
            json={"confirmation_token": "invalid"},
        ).status_code
        == 503
    )
    assert (
        without_control.post(
            f"/api/v1/nodes/{unknown_id}/port-change",
            json={"new_port": 12000},
        ).status_code
        == 503
    )
    assert without_control.delete(f"/api/v1/nodes/{unknown_id}").status_code == 503

    node_id = UUID("00000000-0000-0000-0000-000000000001")
    store = InMemoryNodeStore(
        nodes=(
            MediaNode(
                id=node_id,
                name="media-a",
                external_port=12000,
                state=NodeState.RUNNING,
                runtime_state=NodeState.RUNNING,
                process_id=3001,
                process_start_ticks=4001,
                process_boot_id=UUID("30000000-0000-0000-0000-000000000001"),
            ),
        )
    )
    control = NodeControl(
        store=store,
        choose_port=lambda available: available[0],
        new_node_id=uuid4,
        node_runtime=RecordingLifecycleRuntime(),
        confirmations=node_confirmation_service(),
    )
    client = TestClient(
        create_app(
            Settings(
                role=RuntimeRole.WEB,
                node_port_range_start=12000,
                node_port_range_end=12001,
            ),
            node_control=control,
        )
    )

    missing = client.post(f"/api/v1/nodes/{unknown_id}/drain")
    missing_resume = client.post(f"/api/v1/nodes/{unknown_id}/resume")
    missing_preview = client.post(
        f"/api/v1/nodes/{unknown_id}/port-change/preview",
        json={"new_port": 12001},
    )
    missing_change = client.post(
        f"/api/v1/nodes/{unknown_id}/port-change",
        json={"new_port": 12001, "confirmation_token": "invalid"},
    )
    missing_reconfigure_preview = client.post(f"/api/v1/nodes/{unknown_id}/reconfigure/preview")
    missing_reconfigure = client.post(
        f"/api/v1/nodes/{unknown_id}/reconfigure",
        json={"confirmation_token": "invalid"},
    )
    missing_delete = client.delete(f"/api/v1/nodes/{unknown_id}")
    invalid_transition = client.post(f"/api/v1/nodes/{node_id}/maintenance")
    out_of_range = client.post(
        f"/api/v1/nodes/{node_id}/port-change/preview",
        json={"new_port": 13000},
    )
    unchanged = client.post(
        f"/api/v1/nodes/{node_id}/port-change/preview",
        json={"new_port": 12000},
    )
    delete_running = client.delete(f"/api/v1/nodes/{node_id}")

    assert missing.status_code == 404
    assert missing_resume.status_code == 404
    assert missing_preview.status_code == 404
    assert missing_change.status_code == 404
    assert missing_reconfigure_preview.status_code == 404
    assert missing_reconfigure.status_code == 404
    assert missing_delete.status_code == 404
    assert invalid_transition.status_code == 409
    assert invalid_transition.json()["detail"]["code"] == ("node_administrative_transition_invalid")
    assert out_of_range.status_code == 422
    assert unchanged.status_code == 409
    assert unchanged.json()["detail"]["code"] == "node_port_unchanged"
    assert delete_running.status_code == 409


def test_node_administration_maps_busy_runtime_and_store_errors() -> None:
    node_id = UUID("00000000-0000-0000-0000-000000000001")

    class AdministrationErrorStore(InMemoryNodeStore):
        administrative_error: Exception | None = None
        preview_error: Exception | None = None
        port_error: Exception | None = None
        delete_error: Exception | None = None

        def request_administrative_state(
            self,
            requested_node_id: UUID,
            state: NodeState,
            *,
            fence: NodeCommandFence | None = None,
            mutation_context: NodeMutationContext | None = None,
        ) -> MediaNode:
            if self.administrative_error is not None:
                raise self.administrative_error
            return super().request_administrative_state(
                requested_node_id,
                state,
                fence=fence,
                mutation_context=mutation_context,
            )

        def get_node(self, requested_node_id: UUID) -> MediaNode | None:
            if self.preview_error is not None:
                raise self.preview_error
            return super().get_node(requested_node_id)

        def begin_port_change(
            self,
            *,
            change_id: UUID,
            node_id: UUID,
            new_port: int,
            allowed_ports: Collection[int],
            expected_revision: int,
            expected_registered_cameras: int,
            expected_blast_radius_sha256: str,
            mutation_context: NodeMutationContext | None = None,
        ) -> NodePortChange:
            if self.port_error is not None:
                raise self.port_error
            return super().begin_port_change(
                change_id=change_id,
                node_id=node_id,
                new_port=new_port,
                allowed_ports=allowed_ports,
                expected_revision=expected_revision,
                expected_registered_cameras=expected_registered_cameras,
                expected_blast_radius_sha256=expected_blast_radius_sha256,
                mutation_context=mutation_context,
            )

        def request_node_delete(
            self,
            requested_node_id: UUID,
            *,
            fence: NodeCommandFence | None = None,
            mutation_context: NodeMutationContext | None = None,
        ) -> MediaNode:
            if self.delete_error is not None:
                raise self.delete_error
            return super().request_node_delete(
                requested_node_id,
                fence=fence,
                mutation_context=mutation_context,
            )

    store = AdministrationErrorStore(
        nodes=(
            MediaNode(
                id=node_id,
                name="media-a",
                external_port=12000,
                state=NodeState.RUNNING,
                runtime_state=NodeState.RUNNING,
                process_id=3001,
                process_start_ticks=4001,
                process_boot_id=UUID("30000000-0000-0000-0000-000000000001"),
            ),
        )
    )
    control = NodeControl(
        store=store,
        choose_port=lambda available: available[0],
        new_node_id=uuid4,
        node_runtime=RecordingLifecycleRuntime(),
        confirmations=node_confirmation_service(),
        is_port_bindable=lambda _port: True,
    )
    client = TestClient(
        create_app(
            Settings(
                role=RuntimeRole.WEB,
                node_port_range_start=12000,
                node_port_range_end=12001,
            ),
            node_control=control,
        )
    )

    store.administrative_error = NodeLifecycleBusy("node_lifecycle_busy")
    assert client.post(f"/api/v1/nodes/{node_id}/drain").status_code == 503
    store.administrative_error = None
    store.preview_error = NodeRuntimeUnavailable("node_confirmation_unavailable")
    assert (
        client.post(
            f"/api/v1/nodes/{node_id}/port-change/preview",
            json={"new_port": 12001},
        ).status_code
        == 503
    )
    store.preview_error = None
    preview = client.post(
        f"/api/v1/nodes/{node_id}/port-change/preview",
        json={"new_port": 12001},
    ).json()
    store.port_error = NodePortOutOfRange("node_port_out_of_range")
    assert (
        client.post(
            f"/api/v1/nodes/{node_id}/port-change",
            json={"new_port": 12001, "confirmation_token": preview["confirmation_token"]},
        ).status_code
        == 422
    )
    store.port_error = None
    store.delete_error = NodeRuntimeUnavailable("node_runtime_unavailable")
    assert client.delete(f"/api/v1/nodes/{node_id}").status_code == 503
    store.delete_error = NodeLifecycleBusy("node_lifecycle_busy")
    assert client.delete(f"/api/v1/nodes/{node_id}").status_code == 503
    store.delete_error = NodeNotEmpty("node_not_empty")
    assert client.delete(f"/api/v1/nodes/{node_id}").status_code == 409
    store.delete_error = NodeRuntimeFailed("node_delete_failed", node_id=node_id)
    response = client.delete(f"/api/v1/nodes/{node_id}")
    assert response.status_code == 503
    assert response.json()["detail"]["code"] == "node_delete_failed"


def test_reconfigure_public_endpoint_maps_busy_confirmation_and_runtime_failures() -> None:
    node_id = UUID("00000000-0000-0000-0000-000000000001")
    store = InMemoryNodeStore(
        nodes=(
            MediaNode(
                id=node_id,
                name="media-a",
                external_port=12000,
                state=NodeState.DRAINING,
                runtime_state=NodeState.RUNNING,
                process_id=3001,
                process_start_ticks=4001,
                process_boot_id=UUID("30000000-0000-0000-0000-000000000001"),
            ),
        )
    )

    class ReconfigureControl(NodeControl):
        preview_error: Exception | None = None
        reconfigure_error: Exception | None = None

        def preview_reconfigure(
            self,
            node_id: UUID,
            *,
            confirmation_context: NodeDisruptionConfirmationContext | None = None,
        ) -> Any:
            if self.preview_error is not None:
                raise self.preview_error
            return super().preview_reconfigure(
                node_id,
                confirmation_context=confirmation_context,
            )

        def reconfigure_node(
            self,
            node_id: UUID,
            *,
            confirmation_token: str | None,
            confirmation_context: NodeDisruptionConfirmationContext | None = None,
            fence: NodeCommandFence | None = None,
            mutation_context: NodeMutationContext | None = None,
        ) -> MediaNode:
            if self.reconfigure_error is not None:
                raise self.reconfigure_error
            return super().reconfigure_node(
                node_id,
                confirmation_token=confirmation_token,
                confirmation_context=confirmation_context,
                fence=fence,
                mutation_context=mutation_context,
            )

    control = ReconfigureControl(
        store=store,
        choose_port=lambda available: available[0],
        new_node_id=uuid4,
        node_runtime=RecordingLifecycleRuntime(),
        confirmations=node_confirmation_service(),
    )
    client = TestClient(create_app(Settings(role=RuntimeRole.WEB), node_control=control))

    preview_cases: tuple[tuple[Exception, int], ...] = (
        (NodeLifecycleBusy("node_lifecycle_busy"), 503),
        (NodeRuntimeUnavailable("node_confirmation_unavailable"), 503),
        (NodeLifecycleConflict("node_not_draining"), 409),
    )
    for error, expected_status in preview_cases:
        control.preview_error = error
        assert (
            client.post(f"/api/v1/nodes/{node_id}/reconfigure/preview").status_code
            == expected_status
        )
    control.preview_error = None
    token = client.post(f"/api/v1/nodes/{node_id}/reconfigure/preview").json()["confirmation_token"]
    reconfigure_cases: tuple[tuple[Exception, int], ...] = (
        (NodeLifecycleBusy("node_lifecycle_busy"), 503),
        (NodeRuntimeUnavailable("node_runtime_unavailable"), 503),
        (NodeLifecycleConflict("node_operation_in_progress"), 409),
        (NodeRuntimeFailed("node_runtime_operation_failed", node_id=node_id), 503),
    )
    for error, expected_status in reconfigure_cases:
        control.reconfigure_error = error
        response = client.post(
            f"/api/v1/nodes/{node_id}/reconfigure",
            json={"confirmation_token": token},
        )
        assert response.status_code == expected_status


def test_port_change_public_endpoint_maps_busy_port_and_runtime_failures() -> None:
    node_id = UUID("00000000-0000-0000-0000-000000000001")
    store = InMemoryNodeStore(
        nodes=(
            MediaNode(
                id=node_id,
                name="media-a",
                external_port=12000,
                state=NodeState.RUNNING,
                runtime_state=NodeState.RUNNING,
                process_id=3001,
                process_start_ticks=4001,
                process_boot_id=UUID("30000000-0000-0000-0000-000000000001"),
            ),
        )
    )
    confirmations = node_confirmation_service()

    class PortChangeControl(NodeControl):
        error: Exception | None = None

        def change_port(
            self,
            node_id: UUID,
            *,
            new_port: int,
            allowed_ports: Collection[int],
            confirmation_token: str | None,
            confirmation_context: NodeDisruptionConfirmationContext | None = None,
            fence: NodeCommandFence | None = None,
            mutation_context: NodeMutationContext | None = None,
        ) -> MediaNode:
            if self.error is not None:
                raise self.error
            return super().change_port(
                node_id,
                new_port=new_port,
                allowed_ports=allowed_ports,
                confirmation_token=confirmation_token,
                confirmation_context=confirmation_context,
                fence=fence,
                mutation_context=mutation_context,
            )

    control = PortChangeControl(
        store=store,
        choose_port=lambda available: available[0],
        new_node_id=uuid4,
        node_runtime=RecordingLifecycleRuntime(),
        confirmations=confirmations,
        is_port_bindable=lambda _port: True,
    )
    client = TestClient(
        create_app(
            Settings(
                role=RuntimeRole.WEB,
                node_port_range_start=12000,
                node_port_range_end=12001,
            ),
            node_control=control,
        )
    )
    token = control.preview_port_change(
        node_id,
        new_port=12001,
        allowed_ports=(12000, 12001),
    ).confirmation_token

    expected = (
        (NodeLifecycleBusy("node_lifecycle_busy"), 503),
        (NodePortInUse("node_port_in_use"), 409),
        (NodeLifecycleConflict("node_not_running"), 409),
        (NodeRuntimeUnavailable("node_runtime_unavailable"), 503),
        (NodeRuntimeFailed("node_runtime_operation_failed", node_id=node_id), 503),
    )
    for error, status_code in expected:
        control.error = error
        response = client.post(
            f"/api/v1/nodes/{node_id}/port-change",
            json={"new_port": 12001, "confirmation_token": token},
        )
        assert response.status_code == status_code


def test_port_change_requires_exact_confirmation_and_updates_camera_endpoint() -> None:
    runtime = RecordingLifecycleRuntime()
    node_id = UUID("00000000-0000-0000-0000-000000000001")
    camera_id = UUID("10000000-0000-0000-0000-000000000001")
    store = InMemoryNodeStore()
    control = NodeControl(
        store=store,
        choose_port=lambda available: available[0],
        new_node_id=lambda: node_id,
        new_operation_id=lambda: UUID("40000000-0000-0000-0000-000000000001"),
        node_runtime=runtime,
        provision_on_create=True,
        confirmations=node_confirmation_service(),
    )
    camera_control = CameraControl(
        store=store,
        new_camera_id=lambda: camera_id,
        new_public_id=lambda: "a" * 26,
    )
    client = TestClient(
        create_app(
            Settings(
                role=RuntimeRole.WEB,
                node_port_range_start=12000,
                node_port_range_end=12002,
            ),
            node_control=control,
            camera_control=camera_control,
        )
    )
    client.post("/api/v1/nodes", json={"name": "media-a", "external_port": 12000})
    camera_control.create_camera(
        name="entrance",
        source_url="rtsp://camera.local/main",
        node_id=node_id,
    )

    rejected = client.post(
        f"/api/v1/nodes/{node_id}/port-change",
        json={"new_port": 12001},
    )
    preview = client.post(
        f"/api/v1/nodes/{node_id}/port-change/preview",
        json={"new_port": 12001},
    )
    changed = client.post(
        f"/api/v1/nodes/{node_id}/port-change",
        json={
            "new_port": 12001,
            "confirmation_token": preview.json()["confirmation_token"],
        },
    )

    assert rejected.status_code == 409
    assert rejected.json()["detail"]["code"] == "node_disruption_confirmation_required"
    assert preview.json()["registered_cameras"] == 1
    assert changed.status_code == 200
    assert changed.json()["external_port"] == 12001
    assert camera_control.list_cameras()[0].node_port == 12001
    assert runtime.calls[-1] == (NodeRuntimeAction.RECONFIGURE_RESTART, node_id)


def test_port_change_confirmation_binds_exact_camera_placements_not_only_count() -> None:
    source_id = UUID("00000000-0000-0000-0000-000000000001")
    target_id = UUID("00000000-0000-0000-0000-000000000002")
    first_camera_id = UUID("10000000-0000-0000-0000-000000000001")
    second_camera_id = UUID("10000000-0000-0000-0000-000000000002")
    now = datetime.now(UTC)
    store = InMemoryNodeStore(
        nodes=tuple(
            MediaNode(
                id=node_id,
                name=name,
                external_port=port,
                state=NodeState.RUNNING,
                runtime_state=NodeState.RUNNING,
                health=NodeHealth.HEALTHY,
                management_fresh=True,
                management_observed_at=now,
                config_compatible=True,
                desired_revision=1,
                applied_revision=1,
                process_id=3001,
                process_start_ticks=4001,
                process_boot_id=UUID("30000000-0000-0000-0000-000000000001"),
            )
            for node_id, name, port in (
                (source_id, "media-a", 12000),
                (target_id, "media-b", 12001),
            )
        )
    )
    store.place_camera_manually(
        camera_id=first_camera_id,
        name="first",
        source_url="rtsp://first.local/main",
        public_id=PublicId.parse("a" * 26),
        node_id=source_id,
    )
    store.place_camera_manually(
        camera_id=second_camera_id,
        name="second",
        source_url="rtsp://second.local/main",
        public_id=PublicId.parse("b" * 25 + "e"),
        node_id=target_id,
    )
    control = NodeControl(
        store=store,
        choose_port=lambda available: available[0],
        new_node_id=uuid4,
        node_runtime=RecordingLifecycleRuntime(),
        confirmations=node_confirmation_service(),
        is_port_bindable=lambda _port: True,
    )
    preview = control.preview_port_change(
        source_id,
        new_port=12002,
        allowed_ports=(12000, 12001, 12002),
    )

    first_move = store.create_camera_move(
        move_id=UUID("30000000-0000-0000-0000-000000000001"),
        camera_id=first_camera_id,
        target_node_id=target_id,
        expected_revision=1,
        force=False,
    )
    store.switch_camera_move(first_move.id)
    store.mark_camera_move_source_cleaned(first_move.id)
    store.complete_camera_move(first_move.id)
    second_move = store.create_camera_move(
        move_id=UUID("30000000-0000-0000-0000-000000000002"),
        camera_id=second_camera_id,
        target_node_id=source_id,
        expected_revision=1,
        force=False,
    )
    store.switch_camera_move(second_move.id)
    store.mark_camera_move_source_cleaned(second_move.id)
    store.complete_camera_move(second_move.id)

    with pytest.raises(NodeDisruptionConfirmationRequired):
        control.change_port(
            source_id,
            new_port=12002,
            allowed_ports=(12000, 12001, 12002),
            confirmation_token=preview.confirmation_token,
        )


def test_port_change_confirmation_expires_when_exact_reader_set_changes() -> None:
    node_id = UUID("00000000-0000-0000-0000-000000000001")
    camera_id = UUID("10000000-0000-0000-0000-000000000001")
    public_id = PublicId.parse("a" * 26)
    store = InMemoryNodeStore(
        nodes=(
            MediaNode(
                id=node_id,
                name="media-a",
                external_port=12000,
                state=NodeState.RUNNING,
                runtime_state=NodeState.RUNNING,
                health=NodeHealth.HEALTHY,
                management_fresh=True,
                management_observed_at=datetime.now(UTC),
                config_compatible=True,
                desired_revision=1,
                applied_revision=1,
                process_id=3001,
                process_start_ticks=4001,
                process_boot_id=UUID("30000000-0000-0000-0000-000000000001"),
            ),
        )
    )
    store.place_camera_manually(
        camera_id=camera_id,
        name="entrance",
        source_url="rtsp://camera.local/main",
        public_id=public_id,
        node_id=node_id,
    )
    observer = RecordingDisruptionObserver((public_id,))
    control = NodeControl(
        store=store,
        choose_port=lambda available: available[0],
        new_node_id=uuid4,
        node_runtime=RecordingLifecycleRuntime(),
        disruption_observer=observer,
        confirmations=node_confirmation_service(),
        is_port_bindable=lambda _port: True,
    )
    preview = control.preview_port_change(
        node_id,
        new_port=12001,
        allowed_ports=(12000, 12001),
    )

    assert preview.active_reader_public_ids == (public_id,)
    observer.active_reader_public_ids = ()

    with pytest.raises(NodeDisruptionConfirmationRequired):
        control.change_port(
            node_id,
            new_port=12001,
            allowed_ports=(12000, 12001),
            confirmation_token=preview.confirmation_token,
        )


def test_port_change_keeps_reader_admission_fenced_through_disruptive_action() -> None:
    node_id = UUID("00000000-0000-0000-0000-000000000001")
    public_id = PublicId.parse("a" * 26)
    store = InMemoryNodeStore(
        nodes=(
            MediaNode(
                id=node_id,
                name="media-a",
                external_port=12000,
                state=NodeState.RUNNING,
                runtime_state=NodeState.RUNNING,
                health=NodeHealth.HEALTHY,
                management_fresh=True,
                management_observed_at=datetime.now(UTC),
                config_compatible=True,
                desired_revision=1,
                applied_revision=1,
                process_id=3001,
                process_start_ticks=4001,
                process_boot_id=UUID("30000000-0000-0000-0000-000000000001"),
            ),
        )
    )
    store.place_camera_manually(
        camera_id=UUID("10000000-0000-0000-0000-000000000001"),
        name="entrance",
        source_url="rtsp://camera.local/main",
        public_id=public_id,
        node_id=node_id,
    )
    late_attempts: list[str] = []
    observer = RecordingDisruptionObserver()

    def attempt_late_reader() -> None:
        late_attempts.append("denied" if observer.fence_active else "admitted")

    observer.on_fenced = attempt_late_reader

    class FenceAwareRuntime(RecordingLifecycleRuntime):
        def execute(
            self,
            action: NodeRuntimeAction,
            node: MediaNode,
        ) -> NodeRuntimeObservation:
            if action is NodeRuntimeAction.RECONFIGURE_RESTART:
                assert observer.fence_active
            return super().execute(action, node)

    control = NodeControl(
        store=store,
        choose_port=lambda available: available[0],
        new_node_id=uuid4,
        node_runtime=FenceAwareRuntime(),
        disruption_observer=observer,
        confirmations=node_confirmation_service(),
        is_port_bindable=lambda _port: True,
    )
    preview = control.preview_port_change(
        node_id,
        new_port=12001,
        allowed_ports=(12000, 12001),
    )

    changed = control.change_port(
        node_id,
        new_port=12001,
        allowed_ports=(12000, 12001),
        confirmation_token=preview.confirmation_token,
    )

    assert changed.external_port == 12001
    assert late_attempts == ["denied"]
    assert not observer.fence_active


def test_port_change_bounds_runtime_action_before_admission_fence_cleanup() -> None:
    node_id = UUID("00000000-0000-0000-0000-000000000001")
    public_id = PublicId.parse("a" * 26)
    work_deadline_unix_ms = int(time.time() * 1000) + 250
    store = InMemoryNodeStore(
        nodes=(
            MediaNode(
                id=node_id,
                name="media-a",
                external_port=12000,
                state=NodeState.RUNNING,
                runtime_state=NodeState.RUNNING,
                health=NodeHealth.HEALTHY,
                management_fresh=True,
                management_observed_at=datetime.now(UTC),
                config_compatible=True,
                desired_revision=1,
                applied_revision=1,
                process_id=3001,
                process_start_ticks=4001,
                process_boot_id=UUID("30000000-0000-0000-0000-000000000001"),
            ),
        )
    )
    store.place_camera_manually(
        camera_id=UUID("10000000-0000-0000-0000-000000000001"),
        name="entrance",
        source_url="rtsp://camera.local/main",
        public_id=public_id,
        node_id=node_id,
    )

    class DeadlineFence(RecordingDisruptionObserver):
        @contextmanager
        def fence(
            self,
            node: MediaNode,
            affected_public_ids: tuple[PublicId, ...],
        ) -> Iterator[NodeDisruptionFenceLease]:
            self.fence_active = True
            try:
                yield NodeDisruptionFenceLease(
                    observation=self.observe(node),
                    work_deadline_unix_ms=work_deadline_unix_ms,
                )
            finally:
                self.fence_active = False

    class DeadlineRuntime(RecordingLifecycleRuntime):
        def __init__(self) -> None:
            super().__init__()
            self.deadlines: list[int] = []

        def execute_until(
            self,
            action: NodeRuntimeAction,
            node: MediaNode,
            *,
            deadline_unix_ms: int,
        ) -> NodeRuntimeObservation:
            assert action is NodeRuntimeAction.RECONFIGURE_RESTART
            self.deadlines.append(deadline_unix_ms)
            if node.external_port == 12001:
                time.sleep(0.3)
                raise RuntimeError("runtime stalled until bounded deadline")
            assert deadline_unix_ms <= int(time.time() * 1000)
            raise RuntimeError("rollback rejected after bounded deadline")

    observer = DeadlineFence()
    runtime = DeadlineRuntime()
    control = NodeControl(
        store=store,
        choose_port=lambda available: available[0],
        new_node_id=uuid4,
        node_runtime=runtime,
        disruption_observer=observer,
        confirmations=node_confirmation_service(),
        is_port_bindable=lambda _port: True,
    )
    preview = control.preview_port_change(
        node_id,
        new_port=12001,
        allowed_ports=(12000, 12001),
    )

    started_at = time.monotonic()
    with pytest.raises(NodeRuntimeFailed, match="node_port_change_rollback_failed"):
        control.change_port(
            node_id,
            new_port=12001,
            allowed_ports=(12000, 12001),
            confirmation_token=preview.confirmation_token,
        )

    assert runtime.deadlines == [work_deadline_unix_ms, work_deadline_unix_ms]
    assert not observer.fence_active
    assert time.monotonic() - started_at < 1


def test_port_change_rejects_process_swap_after_admission_fence() -> None:
    node_id = UUID("00000000-0000-0000-0000-000000000001")
    node = MediaNode(
        id=node_id,
        name="media-a",
        external_port=12000,
        state=NodeState.RUNNING,
        runtime_state=NodeState.RUNNING,
        health=NodeHealth.HEALTHY,
        management_fresh=True,
        config_compatible=True,
        desired_revision=1,
        applied_revision=1,
        process_id=3001,
        process_start_ticks=4001,
        process_boot_id=UUID("30000000-0000-0000-0000-000000000001"),
    )
    store = InMemoryNodeStore(nodes=(node,))
    observer = RecordingDisruptionObserver()
    runtime = RecordingLifecycleRuntime()
    control = NodeControl(
        store=store,
        choose_port=lambda available: available[0],
        new_node_id=uuid4,
        node_runtime=runtime,
        disruption_observer=observer,
        confirmations=node_confirmation_service(),
        is_port_bindable=lambda _port: True,
    )
    preview = control.preview_port_change(
        node_id,
        new_port=12001,
        allowed_ports=(12000, 12001),
    )
    observer.on_fenced = lambda: setattr(observer, "process_id_override", 9999)

    with pytest.raises(NodeRuntimeUnavailable, match="node_disruption_observation_invalid"):
        control.change_port(
            node_id,
            new_port=12001,
            allowed_ports=(12000, 12001),
            confirmation_token=preview.confirmation_token,
        )

    assert runtime.calls == []
    assert store.get_node(node_id) == node


def test_disruptive_node_workflows_have_a_global_nonblocking_admission_budget() -> None:
    first_id = UUID("00000000-0000-0000-0000-000000000001")
    second_id = UUID("00000000-0000-0000-0000-000000000002")
    entered = Event()
    release = Event()

    def block_first_fence() -> None:
        entered.set()
        assert release.wait(timeout=2)

    observer = RecordingDisruptionObserver(on_fenced=block_first_fence)
    store = InMemoryNodeStore(
        nodes=tuple(
            MediaNode(
                id=node_id,
                name=name,
                external_port=port,
                state=NodeState.RUNNING,
                runtime_state=NodeState.RUNNING,
                health=NodeHealth.HEALTHY,
                management_fresh=True,
                config_compatible=True,
                desired_revision=1,
                applied_revision=1,
                process_id=process_id,
                process_start_ticks=process_id + 1000,
                process_boot_id=UUID("30000000-0000-0000-0000-000000000001"),
            )
            for node_id, name, port, process_id in (
                (first_id, "media-a", 12000, 3001),
                (second_id, "media-b", 12001, 3002),
            )
        )
    )
    control = NodeControl(
        store=store,
        choose_port=lambda available: available[0],
        new_node_id=uuid4,
        node_runtime=RecordingLifecycleRuntime(),
        disruption_observer=observer,
        confirmations=node_confirmation_service(),
        is_port_bindable=lambda _port: True,
        disruption_workers=1,
    )
    first_preview = control.preview_port_change(
        first_id,
        new_port=12002,
        allowed_ports=(12000, 12001, 12002, 12003),
    )
    second_preview = control.preview_port_change(
        second_id,
        new_port=12003,
        allowed_ports=(12000, 12001, 12002, 12003),
    )

    with ThreadPoolExecutor(max_workers=1) as executor:
        first = executor.submit(
            control.change_port,
            first_id,
            new_port=12002,
            allowed_ports=(12000, 12001, 12002, 12003),
            confirmation_token=first_preview.confirmation_token,
        )
        assert entered.wait(timeout=2)
        with pytest.raises(NodeLifecycleBusy, match="node_disruption_busy"):
            control.change_port(
                second_id,
                new_port=12003,
                allowed_ports=(12000, 12001, 12002, 12003),
                confirmation_token=second_preview.confirmation_token,
            )
        release.set()
        assert first.result(timeout=2).external_port == 12002


def test_prepared_port_change_fences_new_camera_placement() -> None:
    node_id = UUID("00000000-0000-0000-0000-000000000001")
    now = datetime.now(UTC)
    store = InMemoryNodeStore(
        nodes=(
            MediaNode(
                id=node_id,
                name="media-a",
                external_port=12000,
                state=NodeState.RUNNING,
                runtime_state=NodeState.RUNNING,
                health=NodeHealth.HEALTHY,
                management_fresh=True,
                management_observed_at=now,
                config_compatible=True,
                desired_revision=1,
                applied_revision=1,
            ),
        )
    )
    store.begin_port_change(
        change_id=UUID("40000000-0000-0000-0000-000000000001"),
        node_id=node_id,
        new_port=12001,
        allowed_ports=(12000, 12001),
        expected_revision=1,
        expected_registered_cameras=0,
        expected_blast_radius_sha256=hashlib.sha256(b"").hexdigest(),
    )

    with pytest.raises(EligibleNodeMissing, match="manual_node_ineligible"):
        store.place_camera_manually(
            camera_id=UUID("10000000-0000-0000-0000-000000000001"),
            name="blocked",
            source_url="rtsp://camera.local/main",
            public_id=PublicId.parse("a" * 26),
            node_id=node_id,
        )
    with pytest.raises(EligibleNodeMissing, match="eligible_node_missing"):
        store.place_camera_automatically(
            camera_id=UUID("10000000-0000-0000-0000-000000000002"),
            name="blocked-auto",
            source_url="rtsp://camera.local/main",
            public_id=PublicId.parse("b" * 25 + "e"),
        )


def test_failed_port_change_rolls_runtime_and_database_back_to_old_port() -> None:
    node_id = UUID("00000000-0000-0000-0000-000000000001")

    class FailNewPortOnce(RecordingLifecycleRuntime):
        def execute(
            self,
            action: NodeRuntimeAction,
            node: MediaNode,
        ) -> NodeRuntimeObservation:
            if action is NodeRuntimeAction.RECONFIGURE_RESTART and node.external_port == 12001:
                self.calls.append((action, node.id))
                raise RuntimeError("new listener failed")
            return super().execute(action, node)

    runtime = FailNewPortOnce()
    store = InMemoryNodeStore()
    control = NodeControl(
        store=store,
        choose_port=lambda available: available[0],
        new_node_id=lambda: node_id,
        new_operation_id=lambda: UUID("40000000-0000-0000-0000-000000000001"),
        node_runtime=runtime,
        provision_on_create=True,
        confirmations=node_confirmation_service(),
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
    client.post("/api/v1/nodes", json={"name": "media-a", "external_port": 12000})
    preview = client.post(
        f"/api/v1/nodes/{node_id}/port-change/preview",
        json={"new_port": 12001},
    ).json()

    response = client.post(
        f"/api/v1/nodes/{node_id}/port-change",
        json={"new_port": 12001, "confirmation_token": preview["confirmation_token"]},
    )

    assert response.status_code == 503
    assert response.json()["detail"]["code"] == "node_port_change_rolled_back"
    persisted = store.get_node(node_id)
    assert persisted is not None and persisted.external_port == 12000
    assert persisted.runtime_state is NodeState.RUNNING
    assert store.list_incomplete_port_changes() == ()


def test_port_change_commit_response_loss_returns_the_committed_node() -> None:
    node_id = UUID("00000000-0000-0000-0000-000000000001")

    class ResponseLostAfterCommit(InMemoryNodeStore):
        def complete_port_change(
            self,
            change_id: UUID,
            observation: NodeRuntimeObservation,
        ) -> MediaNode:
            super().complete_port_change(change_id, observation)
            raise RuntimeError("database response lost")

    store = ResponseLostAfterCommit()
    control = NodeControl(
        store=store,
        choose_port=lambda available: available[0],
        new_node_id=lambda: node_id,
        node_runtime=RecordingLifecycleRuntime(),
        provision_on_create=True,
        confirmations=node_confirmation_service(),
        is_port_bindable=lambda _port: True,
    )
    control.register_node(
        name="media-a",
        port_range_start=12000,
        port_range_end=12001,
        max_nodes=1,
        external_port=12000,
    )
    preview = control.preview_port_change(
        node_id,
        new_port=12001,
        allowed_ports=(12000, 12001),
    )

    committed = control.change_port(
        node_id,
        new_port=12001,
        allowed_ports=(12000, 12001),
        confirmation_token=preview.confirmation_token,
    )

    assert committed.external_port == 12001
    assert store.list_incomplete_port_changes() == ()


def test_port_change_fails_closed_when_commit_state_cannot_be_read() -> None:
    node_id = UUID("00000000-0000-0000-0000-000000000001")

    class CommitAndReadUnavailable(InMemoryNodeStore):
        fail_reads = False

        def complete_port_change(
            self,
            change_id: UUID,
            observation: NodeRuntimeObservation,
        ) -> MediaNode:
            self.fail_reads = True
            raise RuntimeError("commit unavailable")

        def get_node(self, requested_node_id: UUID) -> MediaNode | None:
            if self.fail_reads:
                raise RuntimeError("read unavailable")
            return super().get_node(requested_node_id)

    store = CommitAndReadUnavailable()
    control = NodeControl(
        store=store,
        choose_port=lambda available: available[0],
        new_node_id=lambda: node_id,
        node_runtime=RecordingLifecycleRuntime(),
        provision_on_create=True,
        confirmations=node_confirmation_service(),
        is_port_bindable=lambda _port: True,
    )
    control.register_node(
        name="media-a",
        port_range_start=12000,
        port_range_end=12001,
        max_nodes=1,
        external_port=12000,
    )
    preview = control.preview_port_change(
        node_id,
        new_port=12001,
        allowed_ports=(12000, 12001),
    )

    with pytest.raises(NodeRuntimeFailed, match="node_port_change_commit_unknown"):
        control.change_port(
            node_id,
            new_port=12001,
            allowed_ports=(12000, 12001),
            confirmation_token=preview.confirmation_token,
        )


def test_port_change_rollback_failure_marks_only_the_node_failed() -> None:
    node_id = UUID("00000000-0000-0000-0000-000000000001")

    class FailEveryReconfigure(RecordingLifecycleRuntime):
        def execute(
            self,
            action: NodeRuntimeAction,
            node: MediaNode,
        ) -> NodeRuntimeObservation:
            if action is NodeRuntimeAction.RECONFIGURE_RESTART:
                raise RuntimeError("restart failed")
            return super().execute(action, node)

    store = InMemoryNodeStore()
    control = NodeControl(
        store=store,
        choose_port=lambda available: available[0],
        new_node_id=lambda: node_id,
        node_runtime=FailEveryReconfigure(),
        provision_on_create=True,
        confirmations=node_confirmation_service(),
        is_port_bindable=lambda _port: True,
    )
    control.register_node(
        name="media-a",
        port_range_start=12000,
        port_range_end=12001,
        max_nodes=1,
        external_port=12000,
    )
    preview = control.preview_port_change(
        node_id,
        new_port=12001,
        allowed_ports=(12000, 12001),
    )

    with pytest.raises(NodeRuntimeFailed, match="node_port_change_rollback_failed"):
        control.change_port(
            node_id,
            new_port=12001,
            allowed_ports=(12000, 12001),
            confirmation_token=preview.confirmation_token,
        )

    failed = store.get_node(node_id)
    assert failed is not None and failed.runtime_state is NodeState.FAILED


def test_startup_recovery_rolls_back_a_prepared_port_change_before_observation() -> None:
    node_id = UUID("00000000-0000-0000-0000-000000000001")
    runtime = RecordingLifecycleRuntime()
    store = InMemoryNodeStore()
    control = NodeControl(
        store=store,
        choose_port=lambda available: available[0],
        new_node_id=lambda: node_id,
        new_operation_id=lambda: UUID("40000000-0000-0000-0000-000000000001"),
        node_runtime=runtime,
        provision_on_create=True,
    )
    node = control.register_node(
        name="media-a",
        port_range_start=12000,
        port_range_end=12002,
        max_nodes=1,
        external_port=12000,
    )
    store.begin_port_change(
        change_id=UUID("40000000-0000-0000-0000-000000000001"),
        node_id=node_id,
        new_port=12001,
        allowed_ports=(12000, 12001, 12002),
        expected_revision=node.desired_revision,
        expected_registered_cameras=0,
        expected_blast_radius_sha256=hashlib.sha256(b"").hexdigest(),
    )

    recovered = control.recover_runtime_state()

    persisted = store.get_node(node_id)
    assert persisted is not None and persisted.external_port == 12000
    assert store.list_incomplete_port_changes() == ()
    assert recovered[0].runtime_state is NodeState.RUNNING
    assert runtime.calls[1] == (NodeRuntimeAction.RECONFIGURE_RESTART, node_id)


def test_prepared_port_change_reserves_target_for_new_node_registration() -> None:
    node_id = UUID("00000000-0000-0000-0000-000000000001")
    store = InMemoryNodeStore(
        nodes=(
            MediaNode(
                id=node_id,
                name="media-a",
                external_port=12000,
                state=NodeState.RUNNING,
                runtime_state=NodeState.RUNNING,
                desired_revision=1,
                applied_revision=1,
            ),
        )
    )
    store.begin_port_change(
        change_id=UUID("40000000-0000-0000-0000-000000000001"),
        node_id=node_id,
        new_port=12001,
        allowed_ports=(12000, 12001),
        expected_revision=1,
        expected_registered_cameras=0,
        expected_blast_radius_sha256=hashlib.sha256(b"").hexdigest(),
    )

    with pytest.raises(NodePortInUse, match="node_port_in_use"):
        store.register_automatically(
            name="media-b",
            allowed_ports=(12000, 12001),
            max_nodes=2,
            preferred_port=12001,
            choose_port=lambda available: available[0],
            new_node_id=lambda: UUID("00000000-0000-0000-0000-000000000002"),
        )


def test_in_memory_port_change_and_delete_guards_are_fail_closed() -> None:
    node_id = UUID("00000000-0000-0000-0000-000000000001")
    camera_id = UUID("10000000-0000-0000-0000-000000000001")
    now = datetime.now(UTC)

    def store_with_camera() -> InMemoryNodeStore:
        store = InMemoryNodeStore(
            nodes=(
                MediaNode(
                    id=node_id,
                    name="media-a",
                    external_port=12000,
                    state=NodeState.RUNNING,
                    runtime_state=NodeState.RUNNING,
                    health=NodeHealth.HEALTHY,
                    management_fresh=True,
                    management_observed_at=now,
                    config_compatible=True,
                    desired_revision=1,
                    applied_revision=1,
                ),
            )
        )
        store.place_camera_manually(
            camera_id=camera_id,
            name="entrance",
            source_url="rtsp://camera.local/main",
            public_id=PublicId.parse("a" * 26),
            node_id=node_id,
        )
        return store

    cases = (
        (UUID(int=99), 12001, (12000, 12001), 1, 1, "a" * 64, NodeNotFound),
        (node_id, 13000, (12000, 12001), 1, 1, "a" * 64, NodePortOutOfRange),
        (node_id, 12001, (12000, 12001), 2, 1, "a" * 64, NodeLifecycleConflict),
        (node_id, 12001, (12000, 12001), 1, 0, "a" * 64, NodeLifecycleConflict),
        (node_id, 12000, (12000, 12001), 1, 1, "a" * 64, NodeLifecycleConflict),
    )
    for requested, port, allowed, revision, count, fingerprint, error in cases:
        with pytest.raises(error):
            store_with_camera().begin_port_change(
                change_id=UUID(int=4),
                node_id=requested,
                new_port=port,
                allowed_ports=allowed,
                expected_revision=revision,
                expected_registered_cameras=count,
                expected_blast_radius_sha256=fingerprint,
            )

    store = store_with_camera()
    fingerprint = camera_placement_fingerprint(((camera_id, 1),))
    change = store.begin_port_change(
        change_id=UUID(int=4),
        node_id=node_id,
        new_port=12001,
        allowed_ports=(12000, 12001),
        expected_revision=1,
        expected_registered_cameras=1,
        expected_blast_radius_sha256=fingerprint,
    )
    with pytest.raises(NodePortInUse):
        store.register_automatically(
            name="media-b",
            allowed_ports=(12001,),
            max_nodes=2,
            preferred_port=12001,
            choose_port=lambda ports: ports[0],
            new_node_id=lambda: UUID(int=2),
        )
    with pytest.raises(NodeLifecycleConflict, match="node_port_change_in_progress"):
        store.begin_port_change(
            change_id=UUID(int=5),
            node_id=node_id,
            new_port=12002,
            allowed_ports=(12000, 12001, 12002),
            expected_revision=1,
            expected_registered_cameras=1,
            expected_blast_radius_sha256=fingerprint,
        )
    with pytest.raises(NodeNotFound):
        store.complete_port_change(
            UUID(int=99),
            NodeRuntimeObservation(state=NodeState.FAILED, health=NodeHealth.UNHEALTHY),
        )
    store.abort_port_change(change.id, runtime_observation_for(node_id, revision=1))
    assert store.abort_port_change(change.id, runtime_observation_for(node_id, revision=1))
    with pytest.raises(NodeLifecycleConflict, match="node_port_change_not_prepared"):
        store.complete_port_change(change.id, runtime_observation_for(node_id, revision=2))
    with pytest.raises(NodeNotEmpty):
        store.request_node_delete(node_id)
    with pytest.raises(NodeNotFound):
        store.request_node_delete(UUID(int=99))

    empty = InMemoryNodeStore(
        nodes=(MediaNode(id=node_id, name="empty", external_port=12000, state=NodeState.STOPPED),)
    )
    with pytest.raises(NodeLifecycleConflict):
        empty.finalize_node_delete(node_id)
    deleting = empty.request_node_delete(node_id)
    assert empty.request_node_delete(node_id) == deleting
    empty.finalize_node_delete(UUID("00000000-0000-0000-0000-000000000002"))
    empty.finalize_node_delete(node_id)
    empty.finalize_node_delete(node_id)


def test_prepared_port_change_fences_camera_mutations_and_moves() -> None:
    source_id = UUID("00000000-0000-0000-0000-000000000001")
    target_id = UUID("00000000-0000-0000-0000-000000000002")
    camera_id = UUID("10000000-0000-0000-0000-000000000001")
    now = datetime.now(UTC)
    store = InMemoryNodeStore(
        nodes=tuple(
            MediaNode(
                id=node_id,
                name=name,
                external_port=port,
                state=NodeState.RUNNING,
                runtime_state=NodeState.RUNNING,
                health=NodeHealth.HEALTHY,
                management_fresh=True,
                management_observed_at=now,
                config_compatible=True,
                desired_revision=1,
                applied_revision=1,
            )
            for node_id, name, port in (
                (source_id, "source", 12000),
                (target_id, "target", 12001),
            )
        )
    )
    camera = store.place_camera_manually(
        camera_id=camera_id,
        name="entrance",
        source_url="rtsp://camera.local/main",
        public_id=PublicId.parse("a" * 26),
        node_id=source_id,
    )
    store.begin_port_change(
        change_id=UUID(int=4),
        node_id=source_id,
        new_port=12002,
        allowed_ports=(12000, 12001, 12002),
        expected_revision=1,
        expected_registered_cameras=1,
        expected_blast_radius_sha256=camera_placement_fingerprint(((camera_id, 1),)),
    )

    operations: tuple[Callable[[], object], ...] = (
        lambda: store.update_camera(
            camera.id,
            name="changed",
            source_url="rtsp://camera.local/main",
        ),
        lambda: store.set_camera_enabled(camera.id, enabled=False),
        lambda: store.request_camera_delete(camera.id),
        lambda: store.create_camera_move(
            move_id=UUID(int=3),
            camera_id=camera.id,
            target_node_id=target_id,
            expected_revision=1,
            force=False,
        ),
    )
    for operation in operations:
        with pytest.raises(CameraLifecycleConflict, match="node_port_change_in_progress"):
            operation()


def test_in_memory_store_rejects_invalid_camera_and_move_transitions() -> None:
    source_id = UUID("00000000-0000-0000-0000-000000000001")
    target_id = UUID("00000000-0000-0000-0000-000000000002")
    camera_id = UUID("10000000-0000-0000-0000-000000000001")
    now = datetime.now(UTC)

    def store_with_camera() -> InMemoryNodeStore:
        store = InMemoryNodeStore(
            nodes=tuple(
                MediaNode(
                    id=node_id,
                    name=name,
                    external_port=port,
                    state=NodeState.RUNNING,
                    runtime_state=NodeState.RUNNING,
                    health=NodeHealth.HEALTHY,
                    management_fresh=True,
                    management_observed_at=now,
                    config_compatible=True,
                    desired_revision=1,
                    applied_revision=1,
                    process_id=3001,
                    process_start_ticks=4001,
                    process_boot_id=UUID("30000000-0000-0000-0000-000000000001"),
                )
                for node_id, name, port in (
                    (source_id, "source", 12000),
                    (target_id, "target", 12001),
                )
            )
        )
        store.place_camera_manually(
            camera_id=camera_id,
            name="entrance",
            source_url="rtsp://camera.local/main",
            public_id=PublicId.parse("a" * 26),
            node_id=source_id,
        )
        return store

    missing = UUID(int=99)
    store = store_with_camera()
    assert store.list_node_cameras(source_id)[0].id == camera_id
    with pytest.raises(NodeNotFound):
        store.list_node_cameras(missing)
    operations: tuple[Callable[[], object], ...] = (
        lambda: store.update_camera(
            missing,
            name="x",
            source_url="rtsp://camera.local/main",
        ),
        lambda: store.set_camera_enabled(missing, enabled=False),
        lambda: store.request_camera_delete(missing),
    )
    for operation in operations:
        with pytest.raises(CameraNotFound):
            operation()
    assert (
        store.update_camera(
            camera_id,
            name="entrance",
            source_url="rtsp://camera.local/main",
        ).desired_revision
        == 1
    )
    store.set_camera_enabled(camera_id, enabled=False)
    assert store.set_camera_enabled(camera_id, enabled=False).state.value == "disabled"
    with pytest.raises(CameraLifecycleConflict, match="camera_not_enabled"):
        store.create_camera_move(
            move_id=UUID(int=3),
            camera_id=camera_id,
            target_node_id=target_id,
            expected_revision=2,
            force=False,
        )

    store = store_with_camera()
    invalid_moves = (
        (missing, target_id, 1, CameraNotFound),
        (camera_id, target_id, 2, CameraLifecycleConflict),
        (camera_id, source_id, 1, CameraLifecycleConflict),
        (camera_id, missing, 1, NodeNotFound),
    )
    for requested_camera, requested_target, revision, error in invalid_moves:
        with pytest.raises(error):
            store.create_camera_move(
                move_id=uuid4(),
                camera_id=requested_camera,
                target_node_id=requested_target,
                expected_revision=revision,
                force=False,
            )
    move = store.create_camera_move(
        move_id=UUID(int=3),
        camera_id=camera_id,
        target_node_id=target_id,
        expected_revision=1,
        force=False,
    )
    with pytest.raises(CameraLifecycleConflict, match="camera_move_in_progress"):
        store.create_camera_move(
            move_id=UUID(int=4),
            camera_id=camera_id,
            target_node_id=target_id,
            expected_revision=2,
            force=False,
        )
    with pytest.raises(CameraNotFound):
        store.switch_camera_move(missing)
    with pytest.raises(CameraNotFound):
        store.complete_camera_move(missing)
    with pytest.raises(CameraLifecycleConflict, match="camera_move_not_switched"):
        store.complete_camera_move(move.id)
    assert not store.mark_camera_applied(
        camera_id=camera_id,
        node_id=source_id,
        placement_generation=1,
        desired_revision=2,
    )


def test_node_control_fails_closed_on_old_listener_and_delete_runtime_mismatch() -> None:
    node_id = UUID("00000000-0000-0000-0000-000000000001")
    runtime = RecordingLifecycleRuntime()
    store = InMemoryNodeStore()
    port_checks: dict[int, int] = {}

    def bindable(port: int) -> bool:
        port_checks[port] = port_checks.get(port, 0) + 1
        if port == 12000:
            return port_checks[port] <= 2
        return port != 12000

    control = NodeControl(
        store=store,
        choose_port=lambda ports: ports[0],
        new_node_id=lambda: node_id,
        node_runtime=runtime,
        provision_on_create=True,
        confirmations=node_confirmation_service(),
        is_port_bindable=bindable,
        sleep=lambda _seconds: None,
    )
    control.register_node(
        name="media-a",
        port_range_start=12000,
        port_range_end=12001,
        max_nodes=1,
        external_port=12000,
    )
    preview = control.preview_port_change(
        node_id,
        new_port=12001,
        allowed_ports=(12000, 12001),
    )
    with pytest.raises(NodeRuntimeFailed, match="node_port_change_rolled_back"):
        control.change_port(
            node_id,
            new_port=12001,
            allowed_ports=(12000, 12001),
            confirmation_token=preview.confirmation_token,
        )

    class BadDeleteRuntime(RecordingLifecycleRuntime):
        def execute(
            self,
            action: NodeRuntimeAction,
            node: MediaNode,
        ) -> NodeRuntimeObservation:
            if action is NodeRuntimeAction.DELETE:
                return runtime_observation_for(node.id, revision=node.desired_revision)
            return super().execute(action, node)

    delete_store = InMemoryNodeStore(
        nodes=(MediaNode(id=node_id, name="stopped", external_port=12000, state=NodeState.STOPPED),)
    )
    delete_control = NodeControl(
        store=delete_store,
        choose_port=lambda ports: ports[0],
        new_node_id=uuid4,
        node_runtime=BadDeleteRuntime(),
    )
    with pytest.raises(NodeRuntimeFailed, match="node_delete_failed"):
        delete_control.delete_node(node_id)
    assert delete_store.get_node(node_id).runtime_state is NodeState.FAILED  # type: ignore[union-attr]


def runtime_observation_for(node_id: UUID, *, revision: int) -> NodeRuntimeObservation:
    return NodeRuntimeObservation(
        state=NodeState.RUNNING,
        health=NodeHealth.HEALTHY,
        management_fresh=True,
        config_compatible=True,
        applied_revision=revision,
        process_id=100 + node_id.int,
        process_start_ticks=1000,
        process_boot_id=UUID("20000000-0000-0000-0000-000000000001"),
        config_sha256="b" * 64,
        release_id="0.1.0",
    )


def test_delete_node_requires_empty_stopped_and_releases_its_port() -> None:
    runtime = RecordingLifecycleRuntime()
    node_id = UUID("00000000-0000-0000-0000-000000000001")
    store = InMemoryNodeStore()
    control = NodeControl(
        store=store,
        choose_port=lambda available: available[0],
        new_node_id=lambda: node_id,
        node_runtime=runtime,
        provision_on_create=True,
    )
    client = TestClient(create_app(Settings(role=RuntimeRole.WEB), node_control=control))
    client.post("/api/v1/nodes", json={"name": "media-a"})

    running = client.delete(f"/api/v1/nodes/{node_id}")
    client.post(f"/api/v1/nodes/{node_id}/stop")
    deleted = client.delete(f"/api/v1/nodes/{node_id}")

    assert running.status_code == 409
    assert running.json()["detail"]["code"] == "node_delete_requires_stopped_or_failed"
    assert deleted.status_code == 204
    assert store.get_node(node_id) is None
    assert runtime.calls[-1] == (NodeRuntimeAction.DELETE, node_id)


def test_postgresql_deleted_node_keeps_append_only_placement_history(
    postgres_database_url: str,
) -> None:
    upgrade_database(postgres_database_url)
    store = PostgresNodeStore(postgres_database_url)
    node_id = UUID("00000000-0000-0000-0000-000000000001")
    camera_id = UUID("10000000-0000-0000-0000-000000000001")
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
    node = store.request_desired_state(node.id, NodeState.RUNNING)
    store.apply_runtime_observation(
        node.id,
        SuccessfulNodeRuntime().execute(NodeRuntimeAction.START, node),
    )
    camera = store.place_camera_manually(
        camera_id=camera_id,
        name="entrance",
        source_url="rtsp://camera.local/main",
        public_id=PublicId.parse("a" * 26),
        node_id=node_id,
    )
    store.request_camera_delete(camera.id)
    assert store.mark_camera_applied(
        camera_id=camera.id,
        node_id=node_id,
        placement_generation=1,
        desired_revision=2,
    )
    stopped = store.request_stop(node_id)
    store.apply_runtime_observation(
        node_id,
        NodeRuntimeObservation(
            state=NodeState.STOPPED,
            health=NodeHealth.UNKNOWN,
            config_compatible=True,
            applied_revision=stopped.desired_revision,
            config_sha256="b" * 64,
            release_id=stopped.release_id,
        ),
    )
    store.request_node_delete(node_id)
    store.finalize_node_delete(node_id)

    engine = create_engine(postgres_database_url)
    with engine.connect() as connection:
        historical_node = connection.scalar(
            text(
                "SELECT node_id FROM camera_placement_history "
                "WHERE camera_id = :camera_id AND generation = 1"
            ),
            {"camera_id": camera_id},
        )
    assert historical_node == node_id
    assert store.get_node(node_id) is None
    store.close()


def test_postgresql_node_administration_happy_path_is_crash_durable(
    postgres_database_url: str,
) -> None:
    upgrade_database(postgres_database_url)
    store = PostgresNodeStore(postgres_database_url)
    node_id = UUID("00000000-0000-0000-0000-000000000001")
    camera_id = UUID("10000000-0000-0000-0000-000000000001")
    control = NodeControl(
        store=store,
        choose_port=lambda available: available[0],
        new_node_id=lambda: node_id,
        new_operation_id=lambda: UUID("40000000-0000-0000-0000-000000000001"),
        node_runtime=RecordingLifecycleRuntime(),
        provision_on_create=True,
        confirmations=node_confirmation_service(),
        is_port_bindable=lambda _port: True,
    )
    cameras_control = CameraControl(
        store=store,
        new_camera_id=lambda: camera_id,
        new_public_id=lambda: "a" * 26,
    )
    control.register_node(
        name="media-a",
        port_range_start=12000,
        port_range_end=12002,
        max_nodes=1,
        external_port=12000,
    )
    camera = cameras_control.create_camera(
        name="entrance",
        source_url="rtsp://camera.local/main",
        node_id=node_id,
    )

    control.set_administrative_state(node_id, NodeState.DRAINING)
    reconfigure_preview = control.preview_reconfigure(
        node_id,
        confirmation_context=NODE_CONFIRMATION_CONTEXT,
    )
    reconfigured = control.reconfigure_node(
        node_id,
        confirmation_token=reconfigure_preview.confirmation_token,
        confirmation_context=NODE_CONFIRMATION_CONTEXT,
        mutation_context=replace(
            NODE_MUTATION_CONTEXT,
            action="node.reconfigure",
            resource_id=str(node_id),
        ),
    )
    control.set_administrative_state(node_id, NodeState.RUNNING)

    preview = control.preview_port_change(
        node_id,
        new_port=12001,
        allowed_ports=(12000, 12001, 12002),
        confirmation_context=NODE_CONFIRMATION_CONTEXT,
    )
    changed = control.change_port(
        node_id,
        new_port=12001,
        allowed_ports=(12000, 12001, 12002),
        confirmation_token=preview.confirmation_token,
        confirmation_context=NODE_CONFIRMATION_CONTEXT,
        mutation_context=replace(
            NODE_MUTATION_CONTEXT,
            action="node.port_change",
            resource_id=str(node_id),
        ),
    )
    drained = control.set_administrative_state(node_id, NodeState.DRAINING)
    maintained = control.set_administrative_state(node_id, NodeState.MAINTENANCE)
    resumed = control.set_administrative_state(node_id, NodeState.RUNNING)
    deleting_camera = cameras_control.delete_camera(camera.id)
    assert store.mark_camera_applied(
        camera_id=camera.id,
        node_id=node_id,
        placement_generation=camera.placement_generation,
        desired_revision=deleting_camera.desired_revision,
    )
    stopped = control.stop_node(node_id)
    control.delete_node(node_id)

    expected_blast_radius = hashlib.sha256(
        f"{camera.id}:{camera.placement_generation}".encode("ascii")
    ).hexdigest()
    assert changed.external_port == 12001
    assert reconfigured.external_port == 12000
    assert reconfigured.state is NodeState.DRAINING
    assert reconfigured.applied_revision == reconfigured.desired_revision
    assert reconfigure_preview.registered_cameras == 1
    assert reconfigure_preview.blast_radius_sha256 == expected_blast_radius
    assert preview.registered_cameras == 1
    assert preview.blast_radius_sha256 == expected_blast_radius
    assert drained.state is NodeState.DRAINING
    assert maintained.state is NodeState.MAINTENANCE
    assert resumed.state is NodeState.RUNNING
    assert stopped.runtime_state is NodeState.STOPPED
    assert store.get_node(node_id) is None
    assert store.list_incomplete_port_changes() == ()

    engine = create_engine(postgres_database_url)
    with engine.connect() as connection:
        saga = connection.execute(
            text(
                "SELECT state, registered_cameras, blast_radius_sha256 FROM node_port_change_sagas"
            )
        ).one()
        historical_node = connection.scalar(
            text("SELECT node_id FROM camera_placement_history WHERE camera_id = :camera_id"),
            {"camera_id": camera_id},
        )
        disruptive_payloads = tuple(
            connection.scalars(
                text(
                    "SELECT payload FROM audit_events "
                    "WHERE aggregate_id = :node_id "
                    "AND event_type IN "
                    "('media_node.reconfigure_requested', 'media_node.port_change_prepared') "
                    "ORDER BY event_type"
                ),
                {"node_id": node_id},
            )
        )
    assert saga == ("complete", 1, expected_blast_radius)
    assert historical_node == node_id
    assert len(disruptive_payloads) == 2
    for payload in disruptive_payloads:
        proof = payload["operator"]["disruption_confirmation"]
        assert proof["mfa_verified_at_unix_ms"] == 1_788_091_200_000
        assert proof["active_readers"] == 0
        assert proof["reader_blast_radius_sha256"]
        assert proof["reader_observed_at_unix_ms"] > 0
        assert proof["runtime_state"] == "running"
        assert proof["process_id"] > 0
        assert proof["process_start_ticks"] > 0
        assert proof["process_boot_id"] == "30000000-0000-0000-0000-000000000001"
    store.close()


def test_postgresql_disruption_audit_preserves_failed_runtime_state_proof(
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
    desired = store.request_desired_state(node.id, NodeState.RUNNING)
    store.apply_runtime_observation(
        node.id,
        NodeRuntimeObservation(
            state=NodeState.FAILED,
            health=NodeHealth.UNHEALTHY,
            applied_revision=desired.applied_revision,
        ),
    )
    store.request_administrative_state(node.id, NodeState.DRAINING)
    control = NodeControl(
        store=store,
        choose_port=lambda available: available[0],
        new_node_id=uuid4,
        node_runtime=RecordingLifecycleRuntime(),
        confirmations=node_confirmation_service(),
    )
    preview = control.preview_reconfigure(
        node_id,
        confirmation_context=NODE_CONFIRMATION_CONTEXT,
    )

    control.reconfigure_node(
        node_id,
        confirmation_token=preview.confirmation_token,
        confirmation_context=NODE_CONFIRMATION_CONTEXT,
        mutation_context=replace(
            NODE_MUTATION_CONTEXT,
            action="node.reconfigure",
            resource_id=str(node_id),
        ),
    )

    engine = create_engine(postgres_database_url, hide_parameters=True)
    with engine.connect() as connection:
        payload = connection.scalar(
            text(
                "SELECT payload FROM audit_events "
                "WHERE aggregate_id=:node_id "
                "AND event_type='media_node.reconfigure_requested'"
            ),
            {"node_id": node_id},
        )
    engine.dispose()
    store.close()
    assert payload["operator"]["disruption_confirmation"]["runtime_state"] == "failed"


def test_postgresql_node_administration_rejects_stale_or_conflicting_operations(
    postgres_database_url: str,
) -> None:
    upgrade_database(postgres_database_url)
    store = PostgresNodeStore(postgres_database_url)
    node_id = UUID("00000000-0000-0000-0000-000000000001")
    node = store.register_automatically(
        name="media-a",
        allowed_ports=(12000, 12001),
        max_nodes=1,
        preferred_port=12000,
        choose_port=lambda ports: ports[0],
        new_node_id=lambda: node_id,
        api_ports=(13000,),
        metrics_ports=(14000,),
    )
    node = store.request_desired_state(node.id, NodeState.RUNNING)
    store.apply_runtime_observation(node.id, runtime_observation_for(node.id, revision=2))

    with pytest.raises(NodeNotFound):
        store.request_administrative_state(UUID(int=99), NodeState.DRAINING)
    drained = store.request_administrative_state(node.id, NodeState.DRAINING)
    assert store.request_administrative_state(node.id, NodeState.DRAINING) == drained
    store.request_administrative_state(node.id, NodeState.RUNNING)
    with pytest.raises(NodeLifecycleConflict):
        store.request_administrative_state(node.id, NodeState.MAINTENANCE)

    fingerprint = camera_placement_fingerprint(())
    cases = (
        (UUID(int=99), 12001, (12000, 12001), 4, NodeNotFound),
        (node_id, 13000, (12000, 12001), 4, NodePortOutOfRange),
        (node_id, 12001, (12000, 12001), 99, NodeLifecycleConflict),
        (node_id, 12000, (12000, 12001), 4, NodeLifecycleConflict),
    )
    for requested, port, allowed, revision, error in cases:
        with pytest.raises(error):
            store.begin_port_change(
                change_id=uuid4(),
                node_id=requested,
                new_port=port,
                allowed_ports=allowed,
                expected_revision=revision,
                expected_registered_cameras=0,
                expected_blast_radius_sha256=fingerprint,
            )
    with pytest.raises(NodeLifecycleConflict, match="node_blast_radius_changed"):
        store.begin_port_change(
            change_id=uuid4(),
            node_id=node_id,
            new_port=12001,
            allowed_ports=(12000, 12001),
            expected_revision=4,
            expected_registered_cameras=1,
            expected_blast_radius_sha256="a" * 64,
        )

    change = store.begin_port_change(
        change_id=UUID(int=4),
        node_id=node_id,
        new_port=12001,
        allowed_ports=(12000, 12001),
        expected_revision=4,
        expected_registered_cameras=0,
        expected_blast_radius_sha256=fingerprint,
    )
    with pytest.raises(NodePortInUse):
        store.begin_port_change(
            change_id=UUID(int=5),
            node_id=node_id,
            new_port=12001,
            allowed_ports=(12000, 12001),
            expected_revision=4,
            expected_registered_cameras=0,
            expected_blast_radius_sha256=fingerprint,
        )
    with pytest.raises(NodeNotFound):
        store.abort_port_change(UUID(int=99), runtime_observation_for(node_id, revision=4))
    restored = store.abort_port_change(change.id, runtime_observation_for(node_id, revision=4))
    repeated = store.abort_port_change(
        change.id,
        runtime_observation_for(node_id, revision=4),
    )
    assert repeated == restored
    with pytest.raises(NodeLifecycleConflict, match="node_port_change_not_prepared"):
        store.complete_port_change(change.id, runtime_observation_for(node_id, revision=5))

    with pytest.raises(NodeLifecycleConflict):
        store.request_node_delete(node_id)
    stopped = store.request_stop(node_id)
    store.apply_runtime_observation(
        node_id,
        NodeRuntimeObservation(
            state=NodeState.STOPPED,
            health=NodeHealth.UNKNOWN,
            config_compatible=True,
            applied_revision=stopped.desired_revision,
            config_sha256="b" * 64,
            release_id="0.1.0",
        ),
    )
    deleting = store.request_node_delete(node_id)
    assert store.request_node_delete(node_id) == deleting
    store.finalize_node_delete(UUID(int=99))
    store.finalize_node_delete(node_id)
    store.finalize_node_delete(node_id)
    store.close()


def test_postgresql_port_change_fences_camera_updates_and_moves(
    postgres_database_url: str,
) -> None:
    upgrade_database(postgres_database_url)
    store = PostgresNodeStore(postgres_database_url)
    now = datetime.now(UTC)
    source_id = UUID("00000000-0000-0000-0000-000000000001")
    target_id = UUID("00000000-0000-0000-0000-000000000002")
    camera_id = UUID("10000000-0000-0000-0000-000000000001")
    for node_id, name, port, api_port, metrics_port in (
        (source_id, "source", 12000, 13000, 14000),
        (target_id, "target", 12001, 13001, 14001),
    ):

        def allocate_node_id(selected: UUID = node_id) -> UUID:
            return selected

        node = store.register_automatically(
            name=name,
            allowed_ports=(port,),
            max_nodes=2,
            preferred_port=port,
            choose_port=lambda ports: ports[0],
            new_node_id=allocate_node_id,
            api_ports=(api_port,),
            metrics_ports=(metrics_port,),
        )
        node = store.request_desired_state(node.id, NodeState.RUNNING)
        observation = runtime_observation_for(node.id, revision=2)
        store.apply_runtime_observation(node.id, observation)
    camera = store.place_camera_manually(
        camera_id=camera_id,
        name="entrance",
        source_url="rtsp://camera.local/main",
        public_id=PublicId.parse("a" * 26),
        node_id=source_id,
        management_freshness_seconds=int((datetime.now(UTC) - now).total_seconds()) + 30,
    )
    store.begin_port_change(
        change_id=UUID(int=4),
        node_id=source_id,
        new_port=12002,
        allowed_ports=(12000, 12001, 12002),
        expected_revision=2,
        expected_registered_cameras=1,
        expected_blast_radius_sha256=camera_placement_fingerprint(((camera_id, 1),)),
    )
    assert store.list_camera_move_targets(camera.id) == ()

    for operation in (
        lambda: store.update_camera(
            camera.id,
            name="changed",
            source_url="rtsp://camera.local/main",
        ),
        lambda: store.set_camera_enabled(camera.id, enabled=False),
        lambda: store.request_camera_delete(camera.id),
        lambda: store.create_camera_move(
            move_id=UUID(int=3),
            camera_id=camera.id,
            target_node_id=target_id,
            expected_revision=1,
            force=False,
        ),
    ):
        with pytest.raises(CameraLifecycleConflict, match="node_port_change_in_progress"):
            operation()
    assert store.list_node_active_moves(source_id) == ()
    with pytest.raises(NodeNotFound):
        store.list_node_cameras(UUID(int=99))
    store.close()


def test_postgresql_camera_move_uses_the_configured_freshness_at_commit(
    postgres_database_url: str,
) -> None:
    upgrade_database(postgres_database_url)
    store = PostgresNodeStore(postgres_database_url)
    source_id = UUID("00000000-0000-0000-0000-000000000011")
    target_id = UUID("00000000-0000-0000-0000-000000000012")
    camera_id = UUID("10000000-0000-0000-0000-000000000011")
    for node_id, name, port, api_port, metrics_port in (
        (source_id, "source", 12100, 13100, 14100),
        (target_id, "target", 12101, 13101, 14101),
    ):

        def allocate_node_id(selected: UUID = node_id) -> UUID:
            return selected

        node = store.register_automatically(
            name=name,
            allowed_ports=(port,),
            max_nodes=2,
            preferred_port=port,
            choose_port=lambda ports: ports[0],
            new_node_id=allocate_node_id,
            api_ports=(api_port,),
            metrics_ports=(metrics_port,),
        )
        node = store.request_desired_state(node.id, NodeState.RUNNING)
        store.apply_runtime_observation(
            node.id,
            runtime_observation_for(node.id, revision=node.desired_revision),
        )
    camera = store.place_camera_manually(
        camera_id=camera_id,
        name="entrance",
        source_url="rtsp://camera.local/main",
        public_id=PublicId.parse("e" * 25 + "a"),
        node_id=source_id,
    )
    engine = create_engine(postgres_database_url)
    with engine.begin() as connection:
        connection.execute(
            text(
                "UPDATE media_nodes "
                "SET management_observed_at = clock_timestamp() - interval '45 seconds' "
                "WHERE id = :node_id"
            ),
            {"node_id": target_id},
        )

    assert (
        store.list_camera_move_targets(
            camera.id,
            management_freshness_seconds=30,
        )
        == ()
    )
    assert [
        node.id
        for node in store.list_camera_move_targets(
            camera.id,
            management_freshness_seconds=60,
        )
    ] == [target_id]
    move = store.create_camera_move(
        move_id=UUID("30000000-0000-0000-0000-000000000011"),
        camera_id=camera.id,
        target_node_id=target_id,
        expected_revision=camera.desired_revision,
        force=False,
        management_freshness_seconds=60,
    )
    assert move.target_node_id == target_id
    engine.dispose()
    store.close()


def test_camera_and_move_routes_cover_success_and_typed_failures() -> None:
    node_a = UUID("00000000-0000-0000-0000-000000000001")
    node_b = UUID("00000000-0000-0000-0000-000000000002")
    camera_id = UUID("10000000-0000-0000-0000-000000000001")
    store = InMemoryNodeStore(
        nodes=tuple(
            MediaNode(
                id=node_id,
                name=name,
                external_port=port,
                state=NodeState.RUNNING,
                runtime_state=NodeState.RUNNING,
                health=NodeHealth.HEALTHY,
                management_fresh=True,
                management_observed_at=datetime.now(UTC),
                config_compatible=True,
                desired_revision=1,
                applied_revision=1,
            )
            for node_id, name, port in (
                (node_a, "media-a", 12000),
                (node_b, "media-b", 12001),
            )
        )
    )
    cameras = CameraControl(
        store=store,
        new_camera_id=lambda: camera_id,
        new_public_id=lambda: "a" * 26,
    )
    camera = cameras.create_camera(
        name="entrance",
        source_url="rtsp://camera.local/main",
        node_id=node_a,
    )
    media = ApiRecordingMediaFactory(node_a, node_b)
    observer = CameraRuntimeObserver(
        store=store,
        media_nodes=cast(Any, media),
    )
    moves = CameraMoveControl(
        store=store,
        runtime=observer,
        confirmations=node_confirmation_service(),
        new_move_id=lambda: UUID("30000000-0000-0000-0000-000000000001"),
    )
    client = TestClient(
        create_app(
            Settings(role=RuntimeRole.WEB),
            camera_control=cameras,
            camera_mutation_control=CameraMutationControl(
                store=store,
                media_nodes=cast(Any, media),
                confirmations=node_confirmation_service(),
            ),
            camera_runtime_observer=observer,
            camera_move_control=moves,
        )
    )

    updated = client.put(
        f"/api/v1/cameras/{camera.id}",
        json={"name": "front", "source_url": "rtsp://camera.local/sub"},
    )
    disabled = client.post(f"/api/v1/cameras/{camera.id}/disable")
    enabled = client.post(f"/api/v1/cameras/{camera.id}/enable")
    runtime = client.get(f"/api/v1/cameras/{camera.id}/runtime")
    preview = client.post(
        f"/api/v1/cameras/{camera.id}/moves/preview",
        json={"target_node_id": str(node_b)},
    )
    requested = client.post(
        f"/api/v1/cameras/{camera.id}/moves",
        json={"target_node_id": str(node_b)},
    )
    move_id = requested.json()["id"]

    assert updated.status_code == disabled.status_code == enabled.status_code == 200
    assert runtime.json()["reader_count"] == 0
    assert preview.status_code == 200
    assert requested.status_code == 202
    assert client.get(f"/api/v1/camera-moves/{move_id}").status_code == 200
    missing_move = client.get("/api/v1/camera-moves/40000000-0000-0000-0000-000000000001")
    assert missing_move.status_code == 404
    assert client.delete(f"/api/v1/cameras/{camera.id}").status_code == 409
    assert client.get("/api/v1/cameras").json()["count"] == 1


class ApiRecordingMediaNode:
    def __init__(self) -> None:
        self.runtime: dict[PublicId, tuple[bool, int] | None] = {}
        self.paths: dict[PublicId, MediaPathConfig] = {}

    def path_runtime_status(self, name: PublicId) -> tuple[bool, int] | None:
        return self.runtime.get(name, (False, 0))

    def put_path(self, path: MediaPathConfig) -> None:
        self.paths[path.name] = path

    def get_path(self, name: PublicId) -> MediaPathConfig | None:
        return self.paths.get(name)

    def inventory_paths(self) -> MediaPathInventory:
        return MediaPathInventory(
            camera_ids=tuple(sorted(self.paths, key=str)),
            no_oracle_matcher_present=False,
        )

    def delete_path(self, name: PublicId) -> None:
        self.paths.pop(name, None)


class ApiRecordingMediaFactory:
    def __init__(self, *node_ids: UUID) -> None:
        self.clients = {node_id: ApiRecordingMediaNode() for node_id in node_ids}

    def for_node(self, node: MediaNode) -> ApiRecordingMediaNode:
        return self.clients[node.id]


def test_disruptive_camera_routes_preview_and_confirm_exact_current_reader() -> None:
    node_id = UUID("00000000-0000-0000-0000-000000000001")
    camera_id = UUID("10000000-0000-0000-0000-000000000001")
    node = MediaNode(
        id=node_id,
        name="media-a",
        external_port=12000,
        state=NodeState.RUNNING,
        runtime_state=NodeState.RUNNING,
        health=NodeHealth.HEALTHY,
        management_fresh=True,
        management_observed_at=datetime.now(UTC),
        config_compatible=True,
        desired_revision=1,
        applied_revision=1,
    )
    store = InMemoryNodeStore(nodes=(node,))
    cameras = CameraControl(
        store=store,
        new_camera_id=lambda: camera_id,
        new_public_id=lambda: "a" * 26,
    )
    camera = cameras.create_camera(
        name="entrance",
        source_url="rtsp://camera.local/main",
        node_id=node_id,
    )
    media = ApiRecordingMediaFactory(node_id)
    media.clients[node_id].paths[camera.public_id] = MediaPathConfig(
        name=camera.public_id,
        source_url=camera.source_url,
    )
    media.clients[node_id].runtime[camera.public_id] = (True, 1)
    mutations = CameraMutationControl(
        store=store,
        media_nodes=cast(Any, media),
        confirmations=node_confirmation_service(),
    )
    client = TestClient(
        create_app(
            Settings(role=RuntimeRole.WEB),
            camera_control=cameras,
            camera_mutation_control=mutations,
        )
    )

    media.clients[node_id].runtime[camera.public_id] = (True, 2)
    assert (
        client.post(
            f"/api/v1/cameras/{camera_id}/mutations/preview",
            json={"operation": "disable"},
        ).status_code
        == 409
    )
    media.clients[node_id].runtime[camera.public_id] = (True, 1)
    assert (
        client.post(
            f"/api/v1/cameras/{camera_id}/mutations/preview",
            json={"operation": "update_source"},
        ).status_code
        == 422
    )
    invalid_source_preview = client.post(
        f"/api/v1/cameras/{camera_id}/mutations/preview",
        json={
            "operation": "update_source",
            "name": "entrance-new",
            "source_url": "rtsp://user:secret@camera.local/sub",
        },
    )
    assert invalid_source_preview.status_code == 422
    assert invalid_source_preview.json() == {
        "detail": {"code": "camera_source_secret_reference_required"}
    }
    preview = client.post(
        f"/api/v1/cameras/{camera_id}/mutations/preview",
        json={"operation": "disable"},
    )
    assert preview.status_code == 200
    assert preview.json()["disconnect_readers"] == 1
    assert client.post(f"/api/v1/cameras/{camera_id}/disable").status_code == 409
    disabled = client.post(
        f"/api/v1/cameras/{camera_id}/disable",
        json={"confirmation_token": preview.json()["confirmation_token"]},
    )
    assert disabled.status_code == 200
    assert disabled.json()["state"] == "disabled"

    assert client.post(f"/api/v1/cameras/{camera_id}/enable").status_code == 200
    update_preview = client.post(
        f"/api/v1/cameras/{camera_id}/mutations/preview",
        json={
            "operation": "update_source",
            "name": "entrance-new",
            "source_url": "rtsp://camera.local/sub",
        },
    ).json()
    assert (
        client.put(
            f"/api/v1/cameras/{camera_id}",
            json={"name": "entrance-new", "source_url": "rtsp://camera.local/sub"},
        ).status_code
        == 409
    )
    updated = client.put(
        f"/api/v1/cameras/{camera_id}",
        json={
            "name": "entrance-new",
            "source_url": "rtsp://camera.local/sub",
            "confirmation_token": update_preview["confirmation_token"],
        },
    )
    assert updated.status_code == 200
    assert updated.json()["name"] == "entrance-new"

    delete_preview = client.post(
        f"/api/v1/cameras/{camera_id}/mutations/preview",
        json={"operation": "delete"},
    ).json()
    assert client.delete(f"/api/v1/cameras/{camera_id}").status_code == 409
    deleting = client.request(
        "DELETE",
        f"/api/v1/cameras/{camera_id}",
        json={"confirmation_token": delete_preview["confirmation_token"]},
    )
    assert deleting.status_code == 202
    assert deleting.json()["state"] == "deleting"


def test_camera_mutation_preview_maps_missing_camera_and_reader_violation() -> None:
    class ErrorMutations:
        error: Exception = CameraNotFound("camera_not_found")

        def preview(self, *args: object, **kwargs: object) -> object:
            raise self.error

    mutations = ErrorMutations()
    client = TestClient(
        create_app(
            Settings(role=RuntimeRole.WEB),
            camera_mutation_control=cast(CameraMutationControl, mutations),
        )
    )
    camera_id = UUID("10000000-0000-0000-0000-000000000001")
    endpoint = f"/api/v1/cameras/{camera_id}/mutations/preview"
    assert client.post(endpoint, json={"operation": "disable"}).status_code == 404
    mutations.error = CameraReaderInvariantViolation("camera_reader_limit_violated")
    assert client.post(endpoint, json={"operation": "disable"}).status_code == 409


def test_camera_routes_fail_closed_for_missing_controls_and_domain_errors() -> None:
    missing = TestClient(create_app(Settings(role=RuntimeRole.WEB)))
    camera_id = UUID("10000000-0000-0000-0000-000000000001")
    node_id = UUID("00000000-0000-0000-0000-000000000002")
    move_id = UUID("30000000-0000-0000-0000-000000000001")

    assert missing.get("/api/v1/cameras").status_code == 503
    assert (
        missing.put(
            f"/api/v1/cameras/{camera_id}",
            json={"name": "x", "source_url": "rtsp://camera.local/main"},
        ).status_code
        == 503
    )
    assert missing.get(f"/api/v1/cameras/{camera_id}/runtime").status_code == 503
    assert (
        missing.post(
            f"/api/v1/cameras/{camera_id}/moves/preview",
            json={"target_node_id": str(node_id)},
        ).status_code
        == 503
    )
    assert (
        missing.post(
            f"/api/v1/cameras/{camera_id}/moves",
            json={"target_node_id": str(node_id)},
        ).status_code
        == 503
    )
    assert missing.get(f"/api/v1/camera-moves/{move_id}").status_code == 503

    store_without_runtime = InMemoryNodeStore()
    camera_control_without_runtime = CameraControl(
        store=store_without_runtime,
        new_camera_id=uuid4,
        new_public_id=lambda: "a" * 26,
    )
    without_runtime = TestClient(
        create_app(
            Settings(role=RuntimeRole.WEB),
            camera_control=camera_control_without_runtime,
        )
    )
    update_without_runtime = without_runtime.put(
        f"/api/v1/cameras/{camera_id}",
        json={"name": "x", "source_url": "rtsp://camera.local/main"},
    )
    assert update_without_runtime.status_code == 503
    assert update_without_runtime.json()["detail"]["code"] == (
        "camera_mutation_confirmation_unavailable"
    )
    assert without_runtime.post(f"/api/v1/cameras/{camera_id}/disable").status_code == 503
    assert without_runtime.delete(f"/api/v1/cameras/{camera_id}").status_code == 503
    assert (
        without_runtime.post(
            f"/api/v1/cameras/{camera_id}/mutations/preview",
            json={"operation": "disable"},
        ).status_code
        == 503
    )

    class ErrorCameraControl(CameraControl):
        error: Exception = CameraNotFound("camera_not_found")

        def update_camera(self, *args: object, **kwargs: object) -> Any:
            raise self.error

        def set_camera_enabled(self, *args: object, **kwargs: object) -> Any:
            raise self.error

        def delete_camera(self, *args: object, **kwargs: object) -> Any:
            raise self.error

    class ErrorMoveControl:
        error: Exception = CameraNotFound("camera_not_found")

        def preview(self, *args: object, **kwargs: object) -> Any:
            raise self.error

        def request_move(self, *args: object, **kwargs: object) -> Any:
            raise self.error

        def get_move(self, requested_move_id: UUID) -> None:
            return None

    class ErrorRuntimeObserver:
        def observe(self, requested_camera_id: UUID) -> Any:
            raise CameraNotFound("camera_not_found")

    class ErrorMutations:
        def update(
            self,
            camera_id: UUID,
            *,
            name: str,
            source_url: str,
            expected_revision: int | None = None,
            confirmation_token: str | None,
        ) -> Any:
            return cameras.update_camera(
                camera_id,
                name=name,
                source_url=source_url,
                expected_revision=expected_revision,
            )

        def disable(
            self,
            camera_id: UUID,
            *,
            expected_revision: int | None = None,
            confirmation_token: str | None,
        ) -> Any:
            return cameras.set_camera_enabled(
                camera_id,
                enabled=False,
                expected_revision=expected_revision,
            )

        def delete(
            self,
            camera_id: UUID,
            *,
            expected_revision: int | None = None,
            confirmation_token: str | None,
        ) -> Any:
            return cameras.delete_camera(camera_id)

    cameras = ErrorCameraControl(
        store=InMemoryNodeStore(),
        new_camera_id=uuid4,
        new_public_id=lambda: "a" * 26,
    )
    moves = ErrorMoveControl()
    client = TestClient(
        create_app(
            Settings(role=RuntimeRole.WEB),
            camera_control=cameras,
            camera_mutation_control=cast(CameraMutationControl, ErrorMutations()),
            camera_runtime_observer=cast(CameraRuntimeObserver, ErrorRuntimeObserver()),
            camera_move_control=cast(CameraMoveControl, moves),
        )
    )

    def update() -> Response:
        return client.put(
            f"/api/v1/cameras/{camera_id}",
            json={"name": "x", "source_url": "rtsp://camera.local/main"},
        )

    assert update().status_code == 404
    cameras.error = CameraLifecycleConflict("camera_deleting")
    assert update().status_code == 409
    cameras.error = InvalidCameraSource("camera_source_secret_reference_required")
    assert update().status_code == 422
    cameras.error = CameraNotFound("camera_not_found")
    assert client.post(f"/api/v1/cameras/{camera_id}/enable").status_code == 404
    cameras.error = CameraLifecycleConflict("camera_deleting")
    assert client.post(f"/api/v1/cameras/{camera_id}/disable").status_code == 409
    assert client.delete(f"/api/v1/cameras/{camera_id}").status_code == 409
    assert client.get(f"/api/v1/cameras/{camera_id}/runtime").status_code == 404

    preview_request = {"target_node_id": str(node_id)}
    for error, expected in (
        (CameraNotFound("camera_not_found"), 404),
        (NodeNotFound("node_not_found"), 404),
        (CameraLifecycleConflict("camera_move_in_progress"), 409),
        (CameraReaderInvariantViolation("camera_reader_limit_violated"), 409),
    ):
        moves.error = error
        assert (
            client.post(
                f"/api/v1/cameras/{camera_id}/moves/preview", json=preview_request
            ).status_code
            == expected
        )
    for request_error, expected in (
        (CameraNotFound("camera_not_found"), 404),
        (NodeNotFound("node_not_found"), 404),
        (CameraOccupied("camera_occupied"), 409),
        (CameraReaderInvariantViolation("camera_reader_limit_violated"), 409),
        (MoveConfirmationRequired("move_confirmation_required"), 409),
        (NodeCameraCapacityReached("node_camera_capacity_reached"), 409),
    ):
        moves.error = request_error
        assert (
            client.post(f"/api/v1/cameras/{camera_id}/moves", json=preview_request).status_code
            == expected
        )


@pytest.mark.parametrize(
    "error",
    (
        NodeLifecycleBusy("node_lifecycle_busy"),
        ReconcileRetry("camera_runtime_node_missing"),
        MediaNodeUnavailable("mediamtx_unavailable"),
    ),
)
def test_camera_routes_sanitize_retryable_runtime_failures(error: Exception) -> None:
    camera_id = UUID("10000000-0000-0000-0000-000000000001")

    class FailingMutations:
        def update(self, *args: object, **kwargs: object) -> Any:
            raise error

    client = TestClient(
        create_app(
            Settings(role=RuntimeRole.WEB),
            camera_control=cast(CameraControl, object()),
            camera_mutation_control=cast(CameraMutationControl, FailingMutations()),
        )
    )

    response = client.put(
        f"/api/v1/cameras/{camera_id}",
        json={"name": "x", "source_url": "rtsp://camera.local/main"},
    )

    assert response.status_code == 503
    assert response.headers["Retry-After"] == "1"
    assert response.json()["detail"]["code"] in {
        "node_lifecycle_busy",
        "camera_runtime_retry",
    }
    assert "mediamtx" not in response.text
