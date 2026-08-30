from __future__ import annotations

import os
import select
import subprocess
import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from ipaddress import ip_address
from uuid import uuid4

import pytest

from rtsp_proxy.probe_broker import ProbeBrokerRequest
from rtsp_proxy.probe_executor import (
    ProbeConnectGuardTarget,
    create_sealed_probe_input,
    serialize_probe_input,
)
from rtsp_proxy.probe_systemd import (
    ProbeSystemdError,
    ProbeTransientDescriptors,
    ProbeTransientLease,
    SystemdProbeManager,
)
from rtsp_proxy.probe_systemd_dbus import DbusNextSystemdTransport

pytestmark = [
    pytest.mark.contract,
    pytest.mark.skipif(
        os.environ.get("RTSP_PROXY_RUN_PROBE_SYSTEMD_CONTRACT") != "1",
        reason="privileged system-manager contract is opt-in",
    ),
    pytest.mark.skipif(sys.platform != "linux", reason="Linux systemd contract"),
]


@dataclass(slots=True)
class _RunningFixture:
    manager: SystemdProbeManager
    request: ProbeBrokerRequest
    lease: ProbeTransientLease
    unit_name: str
    gate_write_fd: int
    output_read_fd: int


def _unit_properties(unit_name: str) -> dict[str, str]:
    observed = subprocess.run(
        [
            "systemctl",
            "show",
            unit_name,
            "--property=ActiveState",
            "--property=Type",
            "--property=CollectMode",
            "--property=DynamicUser",
            "--property=LimitCORE",
            "--property=NoNewPrivileges",
            "--property=ProtectSystem",
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=2,
    )
    if observed.returncode != 0:
        return {}
    return {
        key: value
        for line in observed.stdout.splitlines()
        if "=" in line
        for key, value in [line.split("=", 1)]
    }


def _wait_for_properties(unit_name: str) -> dict[str, str]:
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        properties = _unit_properties(unit_name)
        if properties.get("ActiveState") == "active":
            return properties
        time.sleep(0.02)
    pytest.fail("transient probe fixture did not become active behind its gate")


def _wait_until_collected(unit_name: str) -> None:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        observed = subprocess.run(
            ["systemctl", "show", unit_name, "--property=LoadState", "--value"],
            check=False,
            capture_output=True,
            text=True,
            timeout=2,
        )
        if observed.returncode != 0 or observed.stdout.strip() == "not-found":
            return
        time.sleep(0.05)
    pytest.fail("transient probe fixture was not garbage-collected")


@contextmanager
def _running_fixture(
    path: str,
    *,
    password: str = "not-logged",
) -> Iterator[_RunningFixture]:
    if os.geteuid() != 0:
        pytest.fail("probe systemd contract requires a root test process")
    request_id = uuid4()
    target = ProbeConnectGuardTarget(address=ip_address("192.0.2.10"), port=8554)
    payload = serialize_probe_input(
        address=target.address,
        port=target.port,
        path_and_query=path,
        username="contract",
        password=password,
        io_timeout_microseconds=1_000_000,
    )
    sealed_input_fd = create_sealed_probe_input(payload)
    run_gate_read_fd, run_gate_write_fd = os.pipe()
    output_read_fd, output_write_fd = os.pipe()
    request = ProbeBrokerRequest(
        request_id=request_id,
        endpoint_generation=uuid4(),
        target=target,
        deadline_unix_ms=int(time.time() * 1000) + 10_000,
    )
    manager = SystemdProbeManager(transport=DbusNextSystemdTransport())
    unit_name = f"rtsp-probe-{request_id.hex}.service"
    started = False
    start_error: BaseException | None = None
    try:
        lease = manager.start(
            request,
            descriptors=ProbeTransientDescriptors(
                run_gate_fd=run_gate_read_fd,
                sealed_input_fd=sealed_input_fd,
                output_read_fd=output_read_fd,
                output_write_fd=output_write_fd,
            ),
            timeout_seconds=5.0,
        )
        started = True
    except BaseException as error:
        start_error = error
    finally:
        os.close(run_gate_read_fd)
        os.close(sealed_input_fd)
        os.close(output_write_fd)
    if start_error is not None:
        cleanup_errors: list[BaseException] = []
        for descriptor in (run_gate_write_fd, output_read_fd):
            try:
                os.close(descriptor)
            except BaseException as error:
                cleanup_errors.append(error)
        try:
            _wait_until_collected(unit_name)
        except BaseException as error:
            cleanup_errors.append(error)
        if cleanup_errors:
            raise BaseExceptionGroup(
                "transient fixture start and cleanup failed",
                [start_error, *cleanup_errors],
            ) from None
        raise start_error from None
    fixture = _RunningFixture(
        manager=manager,
        request=request,
        lease=lease,
        unit_name=unit_name,
        gate_write_fd=run_gate_write_fd,
        output_read_fd=output_read_fd,
    )
    body_error: BaseException | None = None
    try:
        yield fixture
    except BaseException as error:
        body_error = error
    finally:
        final_cleanup_errors: list[BaseException] = []
        if started:
            try:
                manager.cancel(lease)
            except ProbeSystemdError as error:
                if str(error) == "probe_transient_cleanup_in_progress":
                    try:
                        if manager.retry_pending_cleanup() != 0:
                            raise ProbeSystemdError("probe_transient_cleanup_pending")
                    except BaseException as cleanup_error:
                        final_cleanup_errors.append(cleanup_error)
                elif str(error) != "probe_transient_lease_invalid":
                    final_cleanup_errors.append(error)
            except BaseException as error:
                final_cleanup_errors.append(error)
        if fixture.gate_write_fd >= 0:
            try:
                os.close(fixture.gate_write_fd)
            except BaseException as error:
                final_cleanup_errors.append(error)
        try:
            os.close(output_read_fd)
        except BaseException as error:
            final_cleanup_errors.append(error)
        try:
            _wait_until_collected(unit_name)
        except BaseException as error:
            final_cleanup_errors.append(error)
        if body_error is not None and final_cleanup_errors:
            raise BaseExceptionGroup(
                "transient fixture body and cleanup failed",
                [body_error, *final_cleanup_errors],
            ) from None
        if body_error is not None:
            raise body_error from None
        if final_cleanup_errors:
            raise BaseExceptionGroup(
                "transient fixture cleanup failed",
                final_cleanup_errors,
            ) from None


def _release(fixture: _RunningFixture) -> None:
    os.write(fixture.gate_write_fd, b"R")
    os.close(fixture.gate_write_fd)
    fixture.gate_write_fd = -1


def test_system_manager_enforces_policy_gate_and_sealed_input_flow() -> None:
    with _running_fixture("/probe-systemd-contract") as fixture:
        properties = _wait_for_properties(fixture.unit_name)
        assert properties == {
            "ActiveState": "active",
            "Type": "exec",
            "CollectMode": "inactive-or-failed",
            "DynamicUser": "yes",
            "LimitCORE": "0",
            "NoNewPrivileges": "yes",
            "ProtectSystem": "strict",
        }
        assert select.select([fixture.output_read_fd], [], [], 0)[0] == []

        _release(fixture)

        assert fixture.manager.read_output(
            fixture.lease,
            output_fd=fixture.output_read_fd,
            timeout_seconds=5.0,
        ) == b'{"status":"fixture-ok"}\n'


def test_system_manager_stops_output_overflow_and_collects_the_unit() -> None:
    with _running_fixture("/probe-systemd-overflow") as fixture:
        _wait_for_properties(fixture.unit_name)
        _release(fixture)

        with pytest.raises(ProbeSystemdError, match="probe_transient_output_overflow"):
            fixture.manager.read_output(
                fixture.lease,
                output_fd=fixture.output_read_fd,
                timeout_seconds=5.0,
            )


def test_system_manager_disables_core_dump_before_reading_the_secret() -> None:
    secret = "probe-core-secret-canary"
    with _running_fixture(
        "/probe-systemd-core-limit",
        password=secret,
    ) as fixture:
        properties = _wait_for_properties(fixture.unit_name)
        assert properties["LimitCORE"] == "0"
        _release(fixture)

        assert fixture.manager.read_output(
            fixture.lease,
            output_fd=fixture.output_read_fd,
            timeout_seconds=5.0,
        ) == b'{"core_limit":[0,0]}\n'
        journal = subprocess.run(
            [
                "journalctl",
                "--unit",
                fixture.unit_name,
                "--no-pager",
                "--output=cat",
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=2,
        )

        assert secret not in journal.stdout + journal.stderr


def test_system_manager_cancels_and_collects_a_running_unit() -> None:
    with _running_fixture("/probe-systemd-cancel") as fixture:
        _wait_for_properties(fixture.unit_name)
        _release(fixture)
        started_at = time.monotonic()

        fixture.manager.cancel(fixture.lease)

        assert time.monotonic() - started_at < 6


def test_system_manager_reconciles_a_unit_left_by_a_previous_manager() -> None:
    with _running_fixture("/probe-systemd-reconcile") as fixture:
        _wait_for_properties(fixture.unit_name)
        restarted = DbusNextSystemdTransport()

        assert restarted.reconcile_owned(timeout_seconds=5.0) == 0
        _wait_until_collected(fixture.unit_name)
