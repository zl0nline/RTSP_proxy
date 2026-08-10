from enum import StrEnum

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
