from __future__ import annotations

from enum import StrEnum
from ipaddress import IPv4Address
from pathlib import Path
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
    node_api_port_range_start: int = Field(default=20000, ge=1, le=65535)
    node_api_port_range_end: int = Field(default=20099, ge=1, le=65535)
    node_metrics_port_range_start: int = Field(default=20100, ge=1, le=65535)
    node_metrics_port_range_end: int = Field(default=20199, ge=1, le=65535)
    node_port_reserved: tuple[Annotated[int, Field(ge=1, le=65535)], ...] = ()
    node_management_freshness_seconds: int = Field(default=30, ge=1, le=300)
    node_lifecycle_lock_pool_size: int = Field(default=4, ge=2, le=16)
    node_lifecycle_lock_timeout_seconds: float = Field(default=5, gt=0, le=30)
    node_runtime_socket: Path | None = None
    node_runtime_timeout_seconds: float = Field(default=60, gt=1, le=60)
    reconcile_interval_seconds: float = Field(default=1, ge=0.1, le=60)
    confirmation_secret: str | None = Field(default=None, min_length=43, max_length=256)
    node_release_id: str = Field(
        default="v1.20.0",
        pattern=r"^[0-9A-Za-z][0-9A-Za-z._-]{0,127}$",
    )
    node_mediamtx_binary_sha256: str = Field(
        default="0" * 64,
        pattern=r"^[0-9a-f]{64}$",
    )
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
        ranges = (
            (self.node_port_range_start, self.node_port_range_end),
            (self.node_api_port_range_start, self.node_api_port_range_end),
            (self.node_metrics_port_range_start, self.node_metrics_port_range_end),
        )
        if any(start > end for start, end in ranges):
            raise ValueError("node_port_range_invalid")
        external, api, metrics = (
            set(range(start, end + 1)) for start, end in ranges
        )
        if external & api or external & metrics or api & metrics:
            raise ValueError("node_port_ranges_overlap")
        if any(self.http_port in configured for configured in (external, api, metrics)):
            raise ValueError("node_port_range_overlaps_control_port")
        if set(self.node_port_reserved) & (api | metrics):
            raise ValueError("node_management_port_reserved")
        available = external.difference(self.node_port_reserved)
        if not available:
            raise ValueError("node_port_range_too_small")
        if self.node_runtime_socket is not None:
            if not self.node_runtime_socket.is_absolute():
                raise ValueError("node_runtime_socket_must_be_absolute")
            if self.node_mediamtx_binary_sha256 == "0" * 64:
                raise ValueError("node_release_identity_required")
            if self.role is RuntimeRole.WEB and self.confirmation_secret is None:
                raise ValueError("confirmation_secret_required")
        return self
