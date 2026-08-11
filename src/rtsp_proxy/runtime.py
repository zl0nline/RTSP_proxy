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
from rtsp_proxy.nodes import (
    CameraControl,
    NodeControl,
    tcp_port_is_bindable,
)

ENV_TO_FIELD = {
    "RTSP_PROXY_ROLE": "role",
    "RTSP_PROXY_HTTP_HOST": "http_host",
    "RTSP_PROXY_HTTP_PORT": "http_port",
    "RTSP_PROXY_MAX_NODES": "max_nodes",
    "RTSP_PROXY_NODE_PORT_RANGE_START": "node_port_range_start",
    "RTSP_PROXY_NODE_PORT_RANGE_END": "node_port_range_end",
    "RTSP_PROXY_NODE_PORT_RESERVED": "node_port_reserved",
    "RTSP_PROXY_NODE_MANAGEMENT_FRESHNESS_SECONDS": (
        "node_management_freshness_seconds"
    ),
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
    return create_app(
        settings,
        node_control=NodeControl(
            store=store,
            choose_port=secrets.choice,
            new_node_id=uuid4,
            is_port_bindable=tcp_port_is_bindable,
        ),
        camera_control=CameraControl(
            store=store,
            new_camera_id=uuid4,
            new_public_id=generate_public_id,
            management_freshness_seconds=settings.node_management_freshness_seconds,
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
    store = PostgresNodeStore(settings.database_url)
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
