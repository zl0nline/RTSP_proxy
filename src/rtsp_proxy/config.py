from enum import StrEnum
from ipaddress import IPv4Address

from pydantic import Field, IPvAnyAddress
from pydantic_settings import BaseSettings, SettingsConfigDict


class RuntimeRole(StrEnum):
    WEB = "web"
    WORKER = "worker"
    RECONCILER = "reconciler"
    PROBE = "probe"
    COLLECTOR = "collector"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="RTSP_PROXY_",
        extra="forbid",
        frozen=True,
    )

    role: RuntimeRole
    http_host: IPvAnyAddress = IPv4Address("127.0.0.1")
    http_port: int = Field(default=8000, ge=1, le=65535)
