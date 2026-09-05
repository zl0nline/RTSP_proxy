from __future__ import annotations

import hashlib
import re
import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field
from ipaddress import (
    IPv4Address,
    IPv4Network,
    IPv6Address,
    IPv6Network,
    ip_address,
)
from threading import BoundedSemaphore
from urllib.parse import unquote, urlsplit
from uuid import UUID, uuid4

from rtsp_proxy.probe_executor import (
    probe_credential_component_valid,
    serialize_probe_input,
)

_IpAddress = IPv4Address | IPv6Address
_IpNetwork = IPv4Network | IPv6Network
_SITE_KEY = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
# Non-link-local metadata/credential endpoints. Primary-source references and
# scope are recorded in docs/evidence/phase-g-probe-network-policy.md.
_PLATFORM_METADATA_ENDPOINTS = frozenset(
    (IPv6Address("fd00:ec2::254"), IPv6Address("fd00:ec2::23"), IPv4Address("100.100.100.200"))
)


class ProbeEndpointRejected(ValueError):
    """A camera endpoint cannot cross the isolated probe boundary."""


@dataclass(frozen=True, slots=True)
class _ProbeCredential:
    username: str = field(repr=False)
    password: str = field(repr=False)

    def __post_init__(self) -> None:
        if not probe_credential_component_valid(self.username, maximum_bytes=64) or not (
            probe_credential_component_valid(self.password, maximum_bytes=256)
        ):
            raise ProbeEndpointRejected("probe_credential_invalid")


@dataclass(frozen=True, slots=True)
class ProbeEndpointIdentity:
    generation: UUID
    address: _IpAddress
    port: int
    site_key: str
    policy_sha256: str
    source_url_sha256: str = field(repr=False)

    def __post_init__(self) -> None:
        if (
            self.generation.version != 4
            or not 1 <= self.port <= 65_535
            or _SITE_KEY.fullmatch(self.site_key) is None
            or not _sha256_valid(self.policy_sha256)
            or not _sha256_valid(self.source_url_sha256)
        ):
            raise ProbeEndpointRejected("probe_endpoint_identity_invalid")


class BoundedGetentResolver:
    """Bound Linux NSS resolution by concurrency, wall time and output size."""

    def __init__(
        self,
        *,
        executable: str = "/usr/bin/getent",
        timeout_seconds: float = 2.0,
        max_concurrency: int = 4,
        run: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    ) -> None:
        if (
            not executable.startswith("/")
            or not 0.1 <= timeout_seconds <= 5
            or not 1 <= max_concurrency <= 16
        ):
            raise ValueError("probe_resolver_policy_invalid")
        self._executable = executable
        self._timeout_seconds = timeout_seconds
        self._slots = BoundedSemaphore(max_concurrency)
        self._run = run

    def __call__(self, hostname: str) -> tuple[str, ...]:
        if not self._slots.acquire(blocking=False):
            raise ProbeEndpointRejected("probe_resolver_capacity_exhausted")
        try:
            try:
                result = self._run(
                    [self._executable, "ahosts", hostname],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=self._timeout_seconds,
                )
            except (OSError, subprocess.SubprocessError):
                raise ProbeEndpointRejected("probe_destination_unavailable") from None
            if result.returncode != 0 or len(result.stdout.encode("utf-8")) > 65_536:
                raise ProbeEndpointRejected("probe_destination_unavailable")
            addresses = tuple(
                sorted(
                    {
                        line.split(maxsplit=1)[0]
                        for line in result.stdout.splitlines()
                        if line.strip()
                    }
                )
            )
            if not 1 <= len(addresses) <= 16:
                raise ProbeEndpointRejected("probe_destination_unavailable")
            return addresses
        finally:
            self._slots.release()


@dataclass(frozen=True, slots=True)
class AdmittedProbeEndpoint:
    identity: ProbeEndpointIdentity
    _path_and_query: str = field(repr=False)
    _credential: _ProbeCredential | None = field(repr=False)

    def __post_init__(self) -> None:
        if (
            not self._path_and_query.startswith("/")
            or len(self._path_and_query.encode("utf-8")) > 8_192
            or any(character in self._path_and_query for character in "'\\\r\n\x00")
        ):
            raise ProbeEndpointRejected("probe_endpoint_invalid")

    @property
    def literal_host(self) -> str:
        return str(self.identity.address)

    @property
    def port(self) -> int:
        return self.identity.port

    def ffconcat_payload(self, *, io_timeout_microseconds: int = 5_000_000) -> bytes:
        if not 100_000 <= io_timeout_microseconds <= 30_000_000:
            raise ValueError("probe_io_timeout_invalid")
        credential = self._credential
        return serialize_probe_input(
            address=self.identity.address,
            port=self.port,
            path_and_query=self._path_and_query,
            username=None if credential is None else credential.username,
            password=None if credential is None else credential.password,
            io_timeout_microseconds=io_timeout_microseconds,
        )


class ProbeEndpointAdmission:
    """Resolve once and bind an RTSP source to one allowed literal destination."""

    def __init__(
        self,
        *,
        site_key: str,
        allowed_networks: tuple[_IpNetwork, ...],
        resolve: Callable[[str], tuple[str, ...]],
        new_generation: Callable[[], UUID] = uuid4,
    ) -> None:
        if (
            _SITE_KEY.fullmatch(site_key) is None
            or len(allowed_networks) > 128
            or len(allowed_networks) != len(set(allowed_networks))
        ):
            raise ValueError("probe_network_policy_invalid")
        self._site_key = site_key
        self._allowed_networks = allowed_networks
        self._policy_sha256 = hashlib.sha256(
            (
                f"site:{site_key}\n"
                + "\n".join(
                    f"{network.version}:{network.with_prefixlen}"
                    for network in sorted(
                        allowed_networks,
                        key=lambda network: (
                            network.version,
                            network.network_address.packed,
                            network.prefixlen,
                        ),
                    )
                )
            ).encode()
        ).hexdigest()
        self._resolve = resolve
        self._new_generation = new_generation

    @property
    def policy_sha256(self) -> str:
        return self._policy_sha256

    def admit(self, source_url: str) -> AdmittedProbeEndpoint:
        hostname, port, path_and_query, credential, source_sha256 = _parse_source_url(
            source_url
        )
        if not self._allowed_networks:
            raise ProbeEndpointRejected("probe_source_policy_not_configured")
        literal = _literal_address(hostname)
        if literal is None:
            canonical_hostname = _canonical_hostname(hostname)
            try:
                raw_addresses = self._resolve(canonical_hostname)
            except Exception:
                raise ProbeEndpointRejected("probe_destination_unavailable") from None
            if not 1 <= len(raw_addresses) <= 16:
                raise ProbeEndpointRejected("probe_destination_unavailable")
            try:
                addresses = tuple(
                    sorted(
                        {_normalize_address(ip_address(value)) for value in raw_addresses},
                        key=_address_sort_key,
                    )
                )
            except ValueError:
                raise ProbeEndpointRejected("probe_destination_unavailable") from None
        else:
            addresses = (_normalize_address(literal),)
        if any(probe_destination_is_forbidden(address) for address in addresses):
            raise ProbeEndpointRejected("probe_destination_forbidden")
        if any(not self._allowed(address) for address in addresses):
            raise ProbeEndpointRejected("probe_destination_not_allowed")
        generation = self._new_generation()
        if generation.version != 4:
            raise ProbeEndpointRejected("probe_endpoint_identity_invalid")
        return AdmittedProbeEndpoint(
            identity=ProbeEndpointIdentity(
                generation=generation,
                address=addresses[0],
                port=port,
                site_key=self._site_key,
                policy_sha256=self._policy_sha256,
                source_url_sha256=source_sha256,
            ),
            _path_and_query=path_and_query,
            _credential=credential,
        )

    def restore(
        self,
        source_url: str,
        identity: ProbeEndpointIdentity,
    ) -> AdmittedProbeEndpoint:
        """Rehydrate one persisted admission without DNS or a new generation."""

        if not isinstance(identity, ProbeEndpointIdentity):
            raise ProbeEndpointRejected("probe_endpoint_identity_invalid")
        hostname, port, path_and_query, credential, source_sha256 = _parse_source_url(
            source_url
        )
        literal = _literal_address(hostname)
        if (
            identity.site_key != self._site_key
            or identity.policy_sha256 != self._policy_sha256
            or identity.source_url_sha256 != source_sha256
            or identity.port != port
            or probe_destination_is_forbidden(identity.address)
            or not self._allowed(identity.address)
            or (
                literal is not None
                and _normalize_address(literal) != identity.address
            )
        ):
            raise ProbeEndpointRejected("probe_endpoint_identity_invalid")
        return AdmittedProbeEndpoint(
            identity=identity,
            _path_and_query=path_and_query,
            _credential=credential,
        )

    def _allowed(self, address: _IpAddress) -> bool:
        return any(
            address.version == network.version and address in network
            for network in self._allowed_networks
        )


def _sha256_valid(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value)


def _parse_source_url(
    source_url: str,
) -> tuple[str, int, str, _ProbeCredential | None, str]:
    if not isinstance(source_url, str) or any(
        character in source_url for character in "\r\n\x00"
    ):
        raise ProbeEndpointRejected("probe_endpoint_invalid")
    try:
        encoded = source_url.encode("utf-8")
        parsed = urlsplit(source_url)
        hostname = parsed.hostname
        port = 554 if parsed.port is None else parsed.port
    except (UnicodeError, ValueError):
        raise ProbeEndpointRejected("probe_endpoint_invalid") from None
    if (
        not 1 <= len(encoded) <= 8_192
        or parsed.scheme.lower() != "rtsp"
        or hostname is None
        or parsed.fragment
        or not 1 <= port <= 65_535
    ):
        raise ProbeEndpointRejected("probe_endpoint_invalid")
    credential = _parse_credential(parsed.username, parsed.password)
    path_and_query = parsed.path or "/"
    if parsed.query:
        path_and_query += f"?{parsed.query}"
    if any(character in path_and_query for character in "'\\\r\n\x00"):
        raise ProbeEndpointRejected("probe_endpoint_invalid")
    return (
        hostname,
        port,
        path_and_query,
        credential,
        hashlib.sha256(encoded).hexdigest(),
    )


def _parse_credential(username: str | None, password: str | None) -> _ProbeCredential | None:
    if username is None and password is None:
        return None
    if username is None or password is None:
        raise ProbeEndpointRejected("probe_credential_invalid")
    return _ProbeCredential(username=unquote(username), password=unquote(password))


def _literal_address(hostname: str) -> _IpAddress | None:
    if "%" in hostname:
        raise ProbeEndpointRejected("probe_endpoint_invalid")
    try:
        return ip_address(hostname)
    except ValueError:
        return None


def _canonical_hostname(hostname: str) -> str:
    canonical = hostname.rstrip(".")
    try:
        canonical = canonical.encode("idna").decode("ascii").lower()
    except UnicodeError:
        raise ProbeEndpointRejected("probe_endpoint_invalid") from None
    if not 1 <= len(canonical) <= 253 or any(
        not label or len(label) > 63 for label in canonical.split(".")
    ):
        raise ProbeEndpointRejected("probe_endpoint_invalid")
    return canonical


def _normalize_address(address: _IpAddress) -> _IpAddress:
    if isinstance(address, IPv6Address) and address.ipv4_mapped is not None:
        return address.ipv4_mapped
    return address


def probe_destination_is_forbidden(address: _IpAddress) -> bool:
    """Reject special-use targets independently of the configured camera CIDRs."""

    return bool(
        address.is_unspecified
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address in _PLATFORM_METADATA_ENDPOINTS
    )


def _address_sort_key(address: _IpAddress) -> tuple[int, bytes]:
    return address.version, address.packed
