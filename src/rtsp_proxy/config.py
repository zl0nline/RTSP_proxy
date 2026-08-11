from __future__ import annotations

from enum import StrEnum
from ipaddress import IPv4Address
from typing import Annotated, Any

from pydantic import Field, IPvAnyAddress, field_validator, model_validator
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
    max_nodes: int = Field(default=50, ge=1, le=100)
    node_port_range_start: int = Field(default=10000, ge=1, le=65535)
    node_port_range_end: int = Field(default=10999, ge=1, le=65535)
    node_port_reserved: tuple[Annotated[int, Field(ge=1, le=65535)], ...] = ()
    node_management_freshness_seconds: int = Field(default=30, ge=1, le=300)
    database_url: str | None = None

    @field_validator("node_port_reserved", mode="before")
    @classmethod
    def parse_reserved_ports(cls, value: Any) -> Any:
        if isinstance(value, str):
            if not value.strip():
                return ()
            try:
                return tuple(int(part.strip()) for part in value.split(","))
            except ValueError as error:
                raise ValueError("node_port_reserved_invalid") from error
        return value

    @field_validator("node_port_reserved")
    @classmethod
    def canonicalize_reserved_ports(cls, value: tuple[int, ...]) -> tuple[int, ...]:
        if len(value) != len(set(value)):
            raise ValueError("node_port_reserved_duplicate")
        return tuple(sorted(value))

    @model_validator(mode="after")
    def validate_node_port_range(self) -> Settings:
        if self.node_port_range_start > self.node_port_range_end:
            raise ValueError("node_port_range_invalid")
        configured = set(range(self.node_port_range_start, self.node_port_range_end + 1))
        if self.http_port in configured:
            raise ValueError("node_port_range_overlaps_control_port")
        available = configured.difference(self.node_port_reserved)
        if not available:
            raise ValueError("node_port_range_too_small")
        return self
