import json
import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import uvicorn
from fastapi import FastAPI

from rtsp_proxy.app import create_app
from rtsp_proxy.config import RuntimeRole, Settings

ENV_TO_FIELD = {
    "RTSP_PROXY_ROLE": "role",
    "RTSP_PROXY_HTTP_HOST": "http_host",
    "RTSP_PROXY_HTTP_PORT": "http_port",
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
    return create_app(load_settings())


def create_background_app(settings: Settings) -> FastAPI:
    if settings.role is RuntimeRole.WEB:
        raise ConfigurationError("background_role_required")
    return create_app(settings)


def run_web() -> None:
    settings = load_settings()
    if settings.role is not RuntimeRole.WEB:
        raise ConfigurationError("web_role_required")
    uvicorn.run(
        create_app(settings),
        host=str(settings.http_host),
        port=settings.http_port,
    )


def run_background() -> None:
    settings = load_settings()
    uvicorn.run(
        create_background_app(settings),
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
