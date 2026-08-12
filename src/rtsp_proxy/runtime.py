import argparse
import json
import os
import secrets
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any
from uuid import uuid4

import uvicorn
from fastapi import FastAPI

from rtsp_proxy.app import create_app
from rtsp_proxy.config import RuntimeRole, Settings
from rtsp_proxy.database import PostgresNodeStore
from rtsp_proxy.identifiers import generate_public_id
from rtsp_proxy.node_runtime import UnixNodeRuntimeClient
from rtsp_proxy.nodes import (
    CameraControl,
    NodeControl,
    NodeProvisioningPolicy,
    tcp_port_is_bindable,
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
    "RTSP_PROXY_NODE_MANAGEMENT_FRESHNESS_SECONDS": (
        "node_management_freshness_seconds"
    ),
    "RTSP_PROXY_NODE_LIFECYCLE_LOCK_POOL_SIZE": "node_lifecycle_lock_pool_size",
    "RTSP_PROXY_NODE_LIFECYCLE_LOCK_TIMEOUT_SECONDS": (
        "node_lifecycle_lock_timeout_seconds"
    ),
    "RTSP_PROXY_NODE_RUNTIME_SOCKET": "node_runtime_socket",
    "RTSP_PROXY_NODE_RUNTIME_TIMEOUT_SECONDS": "node_runtime_timeout_seconds",
    "RTSP_PROXY_NODE_RELEASE_ID": "node_release_id",
    "RTSP_PROXY_NODE_MEDIAMTX_BINARY_SHA256": "node_mediamtx_binary_sha256",
    "RTSP_PROXY_DATABASE_URL": "database_url",
}


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
                else lambda: node_control.ensure_automatic_capacity(
                    provisioning_policy
                )
            ),
        ),
        startup=(
            None if node_runtime is None else recover_runtime_state
        ),
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
    return create_app(
        settings,
        shutdown=None if store is None else store.close,
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
