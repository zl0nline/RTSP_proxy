from __future__ import annotations

import runpy
from ipaddress import ip_address
from pathlib import Path
from uuid import uuid4

import pytest

from rtsp_proxy.probe_executor import parse_probe_input_payload

_FIXTURE = runpy.run_path(str(Path("tests/fixtures/probe_broker_client.py")))


@pytest.mark.parametrize("input_case", _FIXTURE["HOSTILE_INPUT_CASES"])
def test_installed_contract_payloads_really_violate_the_production_input_contract(
    input_case: str,
) -> None:
    endpoint = _FIXTURE["_contract_endpoint"](
        endpoint_generation=uuid4(), address=ip_address("127.0.0.1"), port=8554,
    )
    canonical = parse_probe_input_payload(endpoint.ffconcat_payload())
    payload = _FIXTURE["_hostile_payload"](endpoint, input_case)
    assert b"probe-broker-secret-canary" in payload
    if input_case in {"tuple_address", "tuple_port"}:
        forged = parse_probe_input_payload(payload)
        assert forged.target != canonical.target
    else:
        with pytest.raises(ValueError, match="probe_input_payload_invalid"):
            parse_probe_input_payload(payload)


def test_hostile_contract_fixture_refuses_unknown_case_or_wrong_target() -> None:
    endpoint = _FIXTURE["_contract_endpoint"](
        endpoint_generation=uuid4(), address=ip_address("127.0.0.1"), port=8554,
    )
    with pytest.raises(KeyError):
        _FIXTURE["_hostile_payload"](endpoint, "not-a-contract-case")
    wrong_target = _FIXTURE["_contract_endpoint"](
        endpoint_generation=uuid4(), address=ip_address("127.0.0.2"), port=8554,
    )
    with pytest.raises(ValueError, match="hostile_fixture_target_invalid"):
        _FIXTURE["_hostile_payload"](wrong_target, "http")
