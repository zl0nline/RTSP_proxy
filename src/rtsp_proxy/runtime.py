import argparse
import json
import logging
import os
import secrets
import threading
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any
from uuid import uuid4

import uvicorn
from fastapi import FastAPI

from rtsp_proxy.app import create_app
from rtsp_proxy.config import RuntimeRole, Settings
from rtsp_proxy.database import PostgresNodeStore
from rtsp_proxy.identifiers import generate_public_id
from rtsp_proxy.node_runtime import UnixMediaNodeClientFactory, UnixNodeRuntimeClient
from rtsp_proxy.nodes import (
    CameraControl,
    NodeControl,
    NodeProvisioningPolicy,
    tcp_port_is_bindable,
)
from rtsp_proxy.reconcile import (
    CameraMoveControl,
    CameraMoveReconciler,
    CameraMutationControl,
    CameraReconciler,
    CameraRuntimeObserver,
    ConfirmationTokenService,
    ReconcileCancelled,
    ReconcileCoordinator,
)

ENV_TO_FIELD = {
    "RTSP_PROXY_ROLE": "role",
    "RTSP_PROXY_HTTP_HOST": "http_host",
    "RTSP_PROXY_HTTP_PORT": "http_port",
    "RTSP_PROXY_MAX_NODES": "max_nodes",
    "RTSP_PROXY_NODE_PORT_RANGE_START": "node_port_range_start",
    "RTSP_PROXY_NODE_PORT_RANGE_END": "node_port_range_end",
    "RTSP_PROXY_NODE_API_PORT_RANGE_START": "node_api_port_range_start",
    "RTSP_PROXY_NODE_API_PORT_RANGE_END": "node_api_port_range_end",
    "RTSP_PROXY_NODE_METRICS_PORT_RANGE_START": "node_metrics_port_range_start",
    "RTSP_PROXY_NODE_METRICS_PORT_RANGE_END": "node_metrics_port_range_end",
    "RTSP_PROXY_NODE_PORT_RESERVED": "node_port_reserved",
    "RTSP_PROXY_NODE_MANAGEMENT_FRESHNESS_SECONDS": ("node_management_freshness_seconds"),
    "RTSP_PROXY_NODE_LIFECYCLE_LOCK_POOL_SIZE": "node_lifecycle_lock_pool_size",
    "RTSP_PROXY_NODE_LIFECYCLE_LOCK_TIMEOUT_SECONDS": ("node_lifecycle_lock_timeout_seconds"),
    "RTSP_PROXY_NODE_RUNTIME_SOCKET": "node_runtime_socket",
    "RTSP_PROXY_NODE_RUNTIME_TIMEOUT_SECONDS": "node_runtime_timeout_seconds",
    "RTSP_PROXY_RECONCILE_INTERVAL_SECONDS": "reconcile_interval_seconds",
    "RTSP_PROXY_CONFIRMATION_SECRET": "confirmation_secret",
    "RTSP_PROXY_NODE_RELEASE_ID": "node_release_id",
    "RTSP_PROXY_NODE_MEDIAMTX_BINARY_SHA256": "node_mediamtx_binary_sha256",
    "RTSP_PROXY_DATABASE_URL": "database_url",
}

LOGGER = logging.getLogger(__name__)


class ConfigurationError(ValueError):
    """Runtime configuration cannot be loaded safely."""


def load_settings(environ: Mapping[str, str] | None = None) -> Settings:
    values = os.environ if environ is None else environ
    config: dict[str, Any] = {}

    config_file = values.get("RTSP_PROXY_CONFIG_FILE")
    if config_file:
        config.update(_read_config_file(Path(config_file)))

    for environment_name, field_name in ENV_TO_FIELD.items():
        if environment_name in values:
            config[field_name] = values[environment_name]

    return Settings.model_validate(config)


def create_app_from_environment() -> FastAPI:
    return _create_runtime_app(load_settings())


def _create_runtime_app(settings: Settings) -> FastAPI:
    store = _open_verified_store(settings)
    if store is None:
        return create_app(settings)
    node_runtime = (
        None
        if settings.node_runtime_socket is None
        else UnixNodeRuntimeClient(
            socket_path=settings.node_runtime_socket,
            timeout_seconds=settings.node_runtime_timeout_seconds,
        )
    )
    node_control = NodeControl(
        store=store,
        choose_port=secrets.choice,
        new_node_id=uuid4,
        is_port_bindable=tcp_port_is_bindable,
        node_runtime=node_runtime,
        provision_on_create=node_runtime is not None,
        recovery_workers=settings.node_lifecycle_lock_pool_size,
        confirmations=(
            None
            if settings.confirmation_secret is None
            else ConfirmationTokenService(
                secret=settings.confirmation_secret.encode("utf-8"),
                lifetime_seconds=30,
            )
        ),
    )
    provisioning_policy = NodeProvisioningPolicy(
        port_range_start=settings.node_port_range_start,
        port_range_end=settings.node_port_range_end,
        max_nodes=settings.max_nodes,
        reserved_ports=settings.node_port_reserved,
        api_ports=tuple(
            range(
                settings.node_api_port_range_start,
                settings.node_api_port_range_end + 1,
            )
        ),
        metrics_ports=tuple(
            range(
                settings.node_metrics_port_range_start,
                settings.node_metrics_port_range_end + 1,
            )
        ),
        release_id=settings.node_release_id,
        mediamtx_binary_sha256=settings.node_mediamtx_binary_sha256,
        management_freshness_seconds=settings.node_management_freshness_seconds,
    )

    def recover_runtime_state() -> None:
        node_control.recover_runtime_state()

    media_factory = (
        None
        if settings.node_runtime_socket is None
        else UnixMediaNodeClientFactory(
            socket_path=settings.node_runtime_socket,
            timeout_seconds=min(10, settings.node_runtime_timeout_seconds),
        )
    )
    camera_runtime = (
        None
        if media_factory is None
        else CameraRuntimeObserver(store=store, media_nodes=media_factory)
    )
    move_control = (
        None
        if camera_runtime is None or settings.confirmation_secret is None
        else CameraMoveControl(
            store=store,
            runtime=camera_runtime,
            confirmations=ConfirmationTokenService(
                secret=settings.confirmation_secret.encode("utf-8"),
                lifetime_seconds=30,
            ),
            new_move_id=uuid4,
        )
    )
    mutation_control = (
        None
        if media_factory is None or settings.confirmation_secret is None
        else CameraMutationControl(
            store=store,
            media_nodes=media_factory,
            confirmations=ConfirmationTokenService(
                secret=settings.confirmation_secret.encode("utf-8"),
                lifetime_seconds=30,
            ),
        )
    )

    return create_app(
        settings,
        node_control=node_control,
        camera_control=CameraControl(
            store=store,
            new_camera_id=uuid4,
            new_public_id=generate_public_id,
            management_freshness_seconds=settings.node_management_freshness_seconds,
            ensure_automatic_capacity=(
                None
                if node_runtime is None
                else lambda: node_control.ensure_automatic_capacity(provisioning_policy)
            ),
        ),
        camera_move_control=move_control,
        camera_mutation_control=mutation_control,
        camera_runtime_observer=camera_runtime,
        startup=(None if node_runtime is None else recover_runtime_state),
        shutdown=store.close,
    )


def create_background_app(
    settings: Settings,
    *,
    expected_role: RuntimeRole,
) -> FastAPI:
    if expected_role is RuntimeRole.WEB or settings.role is RuntimeRole.WEB:
        raise ConfigurationError("background_role_required")
    if settings.role is not expected_role:
        raise ConfigurationError("background_role_mismatch")
    store = _open_verified_store(settings)
    startup: Callable[[], None] | None = None
    shutdown: Callable[[], None] | None = None if store is None else store.close
    if (
        store is not None
        and expected_role is RuntimeRole.RECONCILER
        and settings.node_runtime_socket is not None
    ):
        media = UnixMediaNodeClientFactory(
            socket_path=settings.node_runtime_socket,
            timeout_seconds=min(10, settings.node_runtime_timeout_seconds),
        )
        coordinator = ReconcileCoordinator(
            store=store,
            cameras=CameraReconciler(store=store, media_nodes=media),
            moves=CameraMoveReconciler(store=store, media_nodes=media),
        )
        stop = threading.Event()
        thread: threading.Thread | None = None

        def reconcile_loop() -> None:
            while not stop.is_set():
                try:
                    coordinator.run_once(cancelled=stop.is_set)
                except ReconcileCancelled:
                    break
                except Exception:
                    LOGGER.exception("camera reconcile cycle failed")
                stop.wait(settings.reconcile_interval_seconds)

        def start_reconciler() -> None:
            nonlocal thread
            thread = threading.Thread(
                target=reconcile_loop,
                name="rtsp-proxy-reconciler",
                daemon=False,
            )
            thread.start()

        def stop_reconciler() -> None:
            stop.set()
            try:
                if thread is not None:
                    thread.join(
                        timeout=max(
                            settings.reconcile_interval_seconds,
                            min(10, settings.node_runtime_timeout_seconds),
                        )
                        + 2
                    )
                    if thread.is_alive():
                        raise RuntimeError("reconciler_shutdown_timeout")
            finally:
                if thread is None or not thread.is_alive():
                    store.close()

        startup = start_reconciler
        shutdown = stop_reconciler
    return create_app(
        settings,
        startup=startup,
        shutdown=shutdown,
    )


def _open_verified_store(settings: Settings) -> PostgresNodeStore | None:
    if settings.database_url is None:
        return None
    store = PostgresNodeStore(
        settings.database_url,
        lifecycle_lock_pool_size=settings.node_lifecycle_lock_pool_size,
        lifecycle_lock_timeout_seconds=settings.node_lifecycle_lock_timeout_seconds,
    )
    try:
        store.assert_schema_compatible()
    except Exception:
        store.close()
        raise
    return store


def run_web() -> None:
    settings = load_settings()
    if settings.role is not RuntimeRole.WEB:
        raise ConfigurationError("web_role_required")
    uvicorn.run(
        _create_runtime_app(settings),
        host=str(settings.http_host),
        port=settings.http_port,
    )


def run_background(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="rtsp-proxy-role",
        description="Run one validated RTSP Proxy background role.",
    )
    parser.add_argument(
        "--expected-role",
        choices=[role.value for role in RuntimeRole if role is not RuntimeRole.WEB],
        required=True,
    )
    arguments = parser.parse_args(argv)
    settings = load_settings()
    uvicorn.run(
        create_background_app(
            settings,
            expected_role=RuntimeRole(arguments.expected_role),
        ),
        host=str(settings.http_host),
        port=settings.http_port,
    )


def _read_config_file(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ConfigurationError("invalid_config_file") from error
    if not isinstance(value, dict):
        raise ConfigurationError("invalid_config_file")
    return value
