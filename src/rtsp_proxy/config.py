from __future__ import annotations

import platform
from dataclasses import dataclass
from enum import StrEnum
from ipaddress import IPv4Address
from pathlib import Path
from typing import Annotated, Any

from pydantic import Field, IPvAnyAddress, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from rtsp_proxy.release import (
    ReleaseVerificationError,
    trusted_mediamtx_activation_identity,
)


class RuntimeRole(StrEnum):
    WEB = "web"
    AUTH = "auth"
    WORKER = "worker"
    RECONCILER = "reconciler"
    PROBE = "probe"
    COLLECTOR = "collector"


@dataclass(frozen=True, slots=True)
class NodeRegistrationPolicy:
    """Current host admission policy used by registration and offline restore."""

    max_nodes: int
    external_ports: range
    api_ports: range
    metrics_ports: range
    reserved_ports: frozenset[int]

    def __post_init__(self) -> None:
        if self.max_nodes < 1 or self.max_nodes > 100:
            raise ValueError("max_nodes_invalid")
        if not self.external_ports or not self.api_ports or not self.metrics_ports:
            raise ValueError("node_port_range_invalid")

    def permits(self, *, external_port: int, api_port: int, metrics_port: int) -> bool:
        return bool(
            external_port in self.external_ports
            and external_port not in self.reserved_ports
            and api_port in self.api_ports
            and metrics_port in self.metrics_ports
        )


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
    collector_interval_seconds: float = Field(default=5, ge=1, le=60)
    confirmation_secret: str | None = Field(default=None, min_length=43, max_length=256)
    node_release_id: str = Field(
        default="0.2.1",
        pattern=r"^[0-9A-Za-z][0-9A-Za-z._-]{0,127}$",
    )
    node_mediamtx_binary_sha256: str = Field(
        default="0" * 64,
        pattern=r"^[0-9a-f]{64}$",
    )
    database_url: str | None = None
    auth_host: IPvAnyAddress = IPv4Address("127.0.0.1")
    auth_port: int = Field(default=8010, ge=1, le=65535)
    auth_database_timeout_seconds: float = Field(default=1, ge=0.1, le=5)
    access_pepper_file: Path | None = None
    smtp_host: str | None = Field(default=None, min_length=1, max_length=253)
    smtp_port: int = Field(default=587, ge=1, le=65535)
    smtp_username: str | None = Field(default=None, min_length=1, max_length=253)
    smtp_password_file: Path | None = None
    smtp_ca_file: Path | None = None
    smtp_from_address: str | None = Field(default=None, min_length=3, max_length=320)
    smtp_to_address: str | None = Field(default=None, min_length=3, max_length=320)
    smtp_starttls: bool = True
    smtp_timeout_seconds: float = Field(default=10, gt=0, le=30)
    notification_max_attempts: int = Field(default=3, ge=1, le=10)
    notification_retry_seconds: int = Field(default=60, ge=1, le=3600)

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
        if not self.auth_host.is_loopback:
            raise ValueError("auth_host_must_be_loopback")
        if self.auth_port == self.http_port or any(
            self.auth_port in configured for configured in (external, api, metrics)
        ):
            raise ValueError("auth_port_overlap")
        if self.role is RuntimeRole.AUTH:
            if self.access_pepper_file is None or not self.access_pepper_file.is_absolute():
                raise ValueError("access_pepper_file_required")
            if self.database_url is None:
                raise ValueError("database_url_required")
        if self.role in {
            RuntimeRole.WORKER,
            RuntimeRole.RECONCILER,
            RuntimeRole.PROBE,
            RuntimeRole.COLLECTOR,
        } and self.database_url is None:
            raise ValueError("database_url_required")
        if self.role in {
            RuntimeRole.RECONCILER,
            RuntimeRole.PROBE,
            RuntimeRole.COLLECTOR,
        } and self.node_runtime_socket is None:
            raise ValueError("node_runtime_socket_required")
        smtp_values = (
            self.smtp_host,
            self.smtp_username,
            self.smtp_password_file,
            self.smtp_from_address,
            self.smtp_to_address,
        )
        if self.smtp_ca_file is not None and self.smtp_host is None:
            raise ValueError("smtp_configuration_incomplete")
        if any(value is not None for value in smtp_values):
            if any(value is None for value in smtp_values):
                raise ValueError("smtp_configuration_incomplete")
            assert self.smtp_password_file is not None
            if not self.smtp_password_file.is_absolute():
                raise ValueError("smtp_password_file_must_be_absolute")
            if not self.smtp_starttls:
                raise ValueError("smtp_starttls_required")
            if self.smtp_ca_file is not None and not self.smtp_ca_file.is_absolute():
                raise ValueError("smtp_ca_file_must_be_absolute")
        elif self.role is RuntimeRole.WORKER:
            raise ValueError("smtp_configuration_required")
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
            try:
                _version, trusted_digest = trusted_mediamtx_activation_identity(
                    platform.machine(),
                    self.node_release_id,
                )
            except ReleaseVerificationError:
                raise ValueError("node_release_identity_untrusted") from None
            if self.node_mediamtx_binary_sha256 != trusted_digest.root:
                raise ValueError("node_release_identity_untrusted")
            if self.role is RuntimeRole.WEB and self.confirmation_secret is None:
                raise ValueError("confirmation_secret_required")
        return self

    def node_registration_policy(self) -> NodeRegistrationPolicy:
        return NodeRegistrationPolicy(
            max_nodes=self.max_nodes,
            external_ports=range(self.node_port_range_start, self.node_port_range_end + 1),
            api_ports=range(
                self.node_api_port_range_start,
                self.node_api_port_range_end + 1,
            ),
            metrics_ports=range(
                self.node_metrics_port_range_start,
                self.node_metrics_port_range_end + 1,
            ),
            reserved_ports=frozenset(self.node_port_reserved),
        )
