import os
from collections.abc import Mapping

from fastapi import FastAPI

from rtsp_proxy.app import create_app
from rtsp_proxy.config import RuntimeRole, Settings


def load_settings(environ: Mapping[str, str] | None = None) -> Settings:
    values = os.environ if environ is None else environ
    return Settings(role=RuntimeRole(values["RTSP_PROXY_ROLE"]))


def create_app_from_environment() -> FastAPI:
    return create_app(load_settings())
