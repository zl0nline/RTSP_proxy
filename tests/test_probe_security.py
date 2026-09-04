from __future__ import annotations

import hashlib
import subprocess
from dataclasses import replace
from ipaddress import ip_address, ip_network
from threading import Event, Thread
from uuid import UUID

import pytest

from rtsp_proxy.probe_security import (
    BoundedGetentResolver,
    ProbeEndpointAdmission,
    ProbeEndpointRejected,
)


def test_empty_source_policy_reports_not_configured_instead_of_generic_denial() -> None:
    admission = ProbeEndpointAdmission(
        site_key="site-a",
        allowed_networks=(),
        resolve=lambda _hostname: ("10.40.0.11",),
    )

    with pytest.raises(ProbeEndpointRejected, match=r"^probe_source_policy_not_configured$"):
        admission.admit("rtsp://camera.example/live")


def test_endpoint_admission_resolves_once_and_emits_only_a_literal_target() -> None:
    resolved: list[str] = []

    def resolve(hostname: str) -> tuple[str, ...]:
        resolved.append(hostname)
        return ("10.40.0.11", "10.40.0.12")

    admission = ProbeEndpointAdmission(
        site_key="site-a",
        allowed_networks=(ip_network("10.40.0.0/24"),),
        resolve=resolve,
    )
    endpoint = admission.admit("rtsp://camera:secret@CÄMERA.example/live/main")

    assert resolved == ["xn--cmera-gra.example"]
    assert endpoint.literal_host == "10.40.0.11"
    assert endpoint.port == 554
    assert endpoint.identity.generation.version == 4
    assert endpoint.identity.site_key == "site-a"
    assert len(endpoint.identity.policy_sha256) == 64
    assert endpoint.identity.source_url_sha256 == hashlib.sha256(
        "rtsp://camera:secret@CÄMERA.example/live/main".encode()
    ).hexdigest()
    assert "camera" not in repr(endpoint)
    assert "secret" not in repr(endpoint)
    payload = endpoint.ffconcat_payload()
    assert payload.startswith(b"ffconcat version 1.0\nfile '")
    assert b"camera:secret@10.40.0.11:554/live/main" in payload
    assert b"example" not in payload
    assert payload.endswith(
        b"option rtsp_transport tcp\n"
        b"option rtsp_flags no_redirect\n"
        b"option rw_timeout 5000000\n"
    )


@pytest.mark.parametrize(
    "addresses",
    [
        ("10.40.0.11", "169.254.169.254"),
        ("::ffff:169.254.169.254",),
        ("127.0.0.1",),
        ("::1",),
        ("224.0.0.1",),
    ],
)
def test_endpoint_admission_rejects_every_special_or_mixed_dns_answer(
    addresses: tuple[str, ...],
) -> None:
    admission = ProbeEndpointAdmission(
        site_key="site-a",
        allowed_networks=(
            ip_network("0.0.0.0/0"),
            ip_network("::/0"),
        ),
        resolve=lambda _hostname: addresses,
    )
    with pytest.raises(ProbeEndpointRejected, match="probe_destination_forbidden"):
        admission.admit("rtsp://camera.example/live")


@pytest.mark.parametrize(
    "source_url",
    [
        "http://10.40.0.11/live",
        "rtsp://user-only@10.40.0.11/live",
        "rtsp://user:pass@10.40.0.11/live#fragment",
        "rtsp://user:pa%0Ass@10.40.0.11/live",
        "rtsp://10.40.0.11/live'escape",
        "rtsp://[fe80::1%25eth0]/live",
    ],
)
def test_endpoint_admission_rejects_protocol_and_credential_ambiguity(
    source_url: str,
) -> None:
    admission = ProbeEndpointAdmission(
        site_key="site-a",
        allowed_networks=(ip_network("10.40.0.0/24"),),
        resolve=lambda _hostname: (),
    )
    with pytest.raises(ProbeEndpointRejected):
        admission.admit(source_url)


def test_literal_endpoint_never_uses_dns_and_must_be_in_the_site_policy() -> None:
    def unexpected_dns(_hostname: str) -> tuple[str, ...]:
        raise AssertionError("literal target must not resolve again")

    admission = ProbeEndpointAdmission(
        site_key="site-a",
        allowed_networks=(ip_network("10.40.0.0/24"),),
        resolve=unexpected_dns,
    )
    endpoint = admission.admit("rtsp://10.40.0.99:8554/live")
    assert endpoint.literal_host == "10.40.0.99"
    assert endpoint.port == 8554

    with pytest.raises(ProbeEndpointRejected, match="probe_destination_not_allowed"):
        admission.admit("rtsp://10.41.0.1/live")


def test_each_readmission_creates_a_new_immutable_endpoint_generation() -> None:
    generations = iter(
        (
            UUID("70000000-0000-4000-8000-000000000001"),
            UUID("70000000-0000-4000-8000-000000000002"),
        )
    )
    admission = ProbeEndpointAdmission(
        site_key="site-a",
        allowed_networks=(ip_network("10.40.0.0/24"),),
        resolve=lambda _hostname: ("10.40.0.11",),
        new_generation=generations.__next__,
    )

    first = admission.admit("rtsp://camera.example/live")
    second = admission.admit("rtsp://camera.example/live")

    assert first.identity.address == second.identity.address
    assert first.identity.generation != second.identity.generation


def test_persisted_endpoint_is_restored_without_dns_or_a_new_generation() -> None:
    resolved: list[str] = []

    def resolve(hostname: str) -> tuple[str, ...]:
        resolved.append(hostname)
        return ("10.40.0.11",)

    admission = ProbeEndpointAdmission(
        site_key="site-a",
        allowed_networks=(ip_network("10.40.0.0/24"),),
        resolve=resolve,
    )
    source_url = "rtsp://camera:secret@camera.example/live"
    admitted = admission.admit(source_url)
    restored = admission.restore(source_url, admitted.identity)

    assert resolved == ["camera.example"]
    assert restored.identity is admitted.identity
    assert restored.ffconcat_payload() == admitted.ffconcat_payload()


@pytest.mark.parametrize(
    "source_url,identity_port",
    (
        ("rtsp://camera.example/other", 554),
        ("rtsp://camera.example/live", 8554),
    ),
)
def test_restore_rejects_source_port_and_literal_identity_mismatch(
    source_url: str,
    identity_port: int,
) -> None:
    admission = ProbeEndpointAdmission(
        site_key="site-a",
        allowed_networks=(ip_network("10.40.0.0/24"),),
        resolve=lambda _hostname: ("10.40.0.11",),
    )
    admitted = admission.admit("rtsp://camera.example/live")
    identity = replace(admitted.identity, port=identity_port)

    with pytest.raises(ProbeEndpointRejected, match="probe_endpoint_identity_invalid"):
        admission.restore(source_url, identity)


def test_restore_rejects_literal_address_mismatch() -> None:
    admission = ProbeEndpointAdmission(
        site_key="site-a",
        allowed_networks=(ip_network("10.40.0.0/24"),),
        resolve=lambda _hostname: (),
    )
    source_url = "rtsp://10.40.0.12/live"
    admitted = admission.admit(source_url)
    changed_address = replace(admitted.identity, address=ip_address("10.40.0.11"))

    with pytest.raises(ProbeEndpointRejected, match="probe_endpoint_identity_invalid"):
        admission.restore(source_url, changed_address)


def test_restore_rejects_stale_site_policy_without_resolving_again() -> None:
    admission = ProbeEndpointAdmission(
        site_key="site-a",
        allowed_networks=(ip_network("10.40.0.0/24"),),
        resolve=lambda _hostname: ("10.40.0.11",),
    )
    admitted = admission.admit("rtsp://camera.example/live")
    changed_policy = ProbeEndpointAdmission(
        site_key="site-a",
        allowed_networks=(ip_network("10.40.0.0/25"),),
        resolve=lambda _hostname: (_ for _ in ()).throw(
            AssertionError("restore must not resolve")
        ),
    )

    with pytest.raises(ProbeEndpointRejected, match="probe_endpoint_identity_invalid"):
        changed_policy.restore("rtsp://camera.example/live", admitted.identity)


def test_endpoint_diagnostics_never_expose_path_or_query_credentials() -> None:
    admission = ProbeEndpointAdmission(
        site_key="site-a",
        allowed_networks=(ip_network("10.40.0.0/24"),),
        resolve=lambda _hostname: (),
    )
    endpoint = admission.admit(
        "rtsp://camera:password@10.40.0.99/live/token-secret"
        "?access_token=query-secret"
    )

    diagnostic = repr(endpoint)
    assert "camera" not in diagnostic
    assert "password" not in diagnostic
    assert "token-secret" not in diagnostic
    assert "query-secret" not in diagnostic


def test_empty_site_policy_is_an_explicit_deny_all() -> None:
    admission = ProbeEndpointAdmission(
        site_key="site-a",
        allowed_networks=(),
        resolve=lambda _hostname: ("10.40.0.11",),
    )

    with pytest.raises(ProbeEndpointRejected, match="probe_source_policy_not_configured"):
        admission.admit("rtsp://camera.example/live")


def test_site_identity_is_part_of_the_immutable_policy_digest() -> None:
    networks = (ip_network("10.40.0.0/24"),)
    first = ProbeEndpointAdmission(
        site_key="site-a",
        allowed_networks=networks,
        resolve=lambda _hostname: ("10.40.0.11",),
    )
    second = ProbeEndpointAdmission(
        site_key="site-b",
        allowed_networks=networks,
        resolve=lambda _hostname: ("10.40.0.11",),
    )

    assert first.policy_sha256 != second.policy_sha256


def test_nested_cidr_permutation_has_one_canonical_policy_digest() -> None:
    first = ProbeEndpointAdmission(
        site_key="site-a",
        allowed_networks=(
            ip_network("10.0.0.0/8"),
            ip_network("10.0.0.0/16"),
        ),
        resolve=lambda _hostname: ("10.0.0.11",),
    )
    second = ProbeEndpointAdmission(
        site_key="site-a",
        allowed_networks=(
            ip_network("10.0.0.0/16"),
            ip_network("10.0.0.0/8"),
        ),
        resolve=lambda _hostname: ("10.0.0.11",),
    )

    assert first.policy_sha256 == second.policy_sha256


def test_bounded_getent_resolver_passes_a_hard_timeout_and_parses_addresses() -> None:
    calls: list[tuple[object, ...]] = []

    def run(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append((*args, kwargs))
        return subprocess.CompletedProcess(
            args=["/usr/bin/getent"],
            returncode=0,
            stdout="10.40.0.12 STREAM camera.example\n10.40.0.11 STREAM camera.example\n",
            stderr="",
        )

    resolver = BoundedGetentResolver(timeout_seconds=1.25, run=run)

    assert resolver("camera.example") == ("10.40.0.11", "10.40.0.12")
    assert calls[0][0] == ["/usr/bin/getent", "ahosts", "camera.example"]
    call_options = calls[0][-1]
    assert isinstance(call_options, dict)
    assert call_options["timeout"] == 1.25


def test_bounded_getent_resolver_normalizes_timeout_without_leaking_hostname() -> None:
    def timeout(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired("getent", 1)

    resolver = BoundedGetentResolver(run=timeout)
    with pytest.raises(ProbeEndpointRejected) as error:
        resolver("secret-camera-name.example")

    assert str(error.value) == "probe_destination_unavailable"
    assert "secret-camera-name" not in str(error.value)


def test_bounded_getent_resolver_rejects_work_beyond_its_fixed_slots() -> None:
    started = Event()
    release = Event()
    first_result: list[tuple[str, ...]] = []

    def blocking_run(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        started.set()
        assert release.wait(timeout=2)
        return subprocess.CompletedProcess(
            args=["/usr/bin/getent"],
            returncode=0,
            stdout="10.40.0.11 STREAM camera.example\n",
            stderr="",
        )

    resolver = BoundedGetentResolver(max_concurrency=1, run=blocking_run)
    worker = Thread(target=lambda: first_result.append(resolver("camera-a.example")))
    worker.start()
    assert started.wait(timeout=1)
    try:
        with pytest.raises(
            ProbeEndpointRejected,
            match="probe_resolver_capacity_exhausted",
        ):
            resolver("camera-b.example")
    finally:
        release.set()
        worker.join(timeout=2)

    assert not worker.is_alive()
    assert first_result == [("10.40.0.11",)]
