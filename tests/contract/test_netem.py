from __future__ import annotations

import os
import shutil
import subprocess
import sys
import uuid
from pathlib import Path

import pytest

from rtsp_proxy.load_netem import (
    NetemFlow,
    NetemSitePlan,
    SubprocessNetemKernel,
    capture_netem_observation,
    install_netem,
    remove_netem,
)

pytestmark = pytest.mark.contract


def run(*arguments: str) -> None:
    subprocess.run(arguments, check=True, capture_output=True, text=True, timeout=15)


def send_tcp_flows(ip_binary: Path, namespace: str, source_port: int) -> None:
    script = (
        "import socket\n"
        "for _ in range(4):\n"
        " s=socket.socket()\n"
        " s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)\n"
        f" s.bind(('192.0.2.10',{source_port}))\n"
        " s.settimeout(1)\n"
        " s.connect_ex(('192.0.2.20',9999))\n"
        " s.close()\n"
    )
    run(
        str(ip_binary),
        "netns",
        "exec",
        namespace,
        sys.executable,
        "-c",
        script,
    )


@pytest.mark.skipif(
    os.environ.get("RTSP_NETEM_NATIVE") != "1",
    reason="native privileged Linux netem contract is opt-in",
)
def test_linux_netem_installs_exact_scoped_ifb_and_detects_drift() -> None:
    if os.geteuid() != 0:
        pytest.fail("RTSP_NETEM_NATIVE requires a root test process")
    ip_binary = Path(shutil.which("ip") or "")
    tc_binary = Path(shutil.which("tc") or "")
    if not ip_binary.is_absolute() or not tc_binary.is_absolute():
        pytest.fail("iproute2 ip/tc binaries are required")
    suffix = uuid.uuid4().hex[:10]
    namespace = f"rtspnetem-{suffix}"
    source_namespace = f"rtspsource-{suffix}"
    created_namespaces: list[str] = []
    try:
        run(str(ip_binary), "netns", "add", namespace)
        created_namespaces.append(namespace)
        run(str(ip_binary), "netns", "add", source_namespace)
        created_namespaces.append(source_namespace)
        run(
            str(ip_binary),
            "link",
            "add",
            "camera0",
            "type",
            "veth",
            "peer",
            "name",
            "source0",
        )
        run(str(ip_binary), "link", "set", "camera0", "netns", namespace)
        run(str(ip_binary), "link", "set", "source0", "netns", source_namespace)
        run(
            str(ip_binary),
            "netns",
            "exec",
            namespace,
            str(ip_binary),
            "link",
            "add",
            "rtspifb0",
            "type",
            "ifb",
        )
        for interface in ("camera0", "rtspifb0"):
            run(
                str(ip_binary),
                "netns",
                "exec",
                namespace,
                str(ip_binary),
                "link",
                "set",
                "dev",
                interface,
                "mtu",
                "1500",
                "up",
            )
        run(
            str(ip_binary),
            "netns",
            "exec",
            namespace,
            str(ip_binary),
            "address",
            "add",
            "192.0.2.20/24",
            "dev",
            "camera0",
        )
        run(
            str(ip_binary),
            "netns",
            "exec",
            source_namespace,
            str(ip_binary),
            "address",
            "add",
            "192.0.2.10/24",
            "dev",
            "source0",
        )
        run(
            str(ip_binary),
            "netns",
            "exec",
            source_namespace,
            str(ip_binary),
            "link",
            "set",
            "dev",
            "source0",
            "mtu",
            "1500",
            "up",
        )
        plan = NetemSitePlan(
            schema_version=1,
            profile_sha256="a" * 64,
            site="sut",
            role="sut",
            receiver_host="proxy.load.internal",
            ingress_interface="camera0",
            ifb_interface="rtspifb0",
            ingress_mtu_bytes=1500,
            delay_ms=50,
            jitter_ms=10,
            loss_percent=0.5,
            queue_limit_packets=1000,
            flows=(
                NetemFlow(
                    source_ipv4="192.0.2.10",
                    source_port=8554,
                    preference=49000,
                ),
            ),
        )
        kernel = SubprocessNetemKernel(
            tc_binary=tc_binary,
            ip_binary=ip_binary,
            network_namespace=namespace,
        )

        install_netem(kernel, plan)
        before = capture_netem_observation(kernel, plan)
        send_tcp_flows(ip_binary, source_namespace, 8554)
        matching = capture_netem_observation(kernel, plan)
        assert matching.configuration.flows == plan.flows
        assert matching.configuration.delay_ms == 50
        assert matching.configuration.loss_percent == 0.5
        assert matching.configuration.delay_qdisc_handle == "7a10:"
        assert matching.configuration.loss_qdisc_handle == "7a20:"
        assert matching.packets > before.packets
        assert matching.flow_counters[0].packets > before.flow_counters[0].packets
        scoped_packets = matching.flow_counters[0].packets - before.flow_counters[0].packets
        assert scoped_packets == (matching.packets - before.packets) + (
            matching.drops - before.drops
        )

        send_tcp_flows(ip_binary, source_namespace, 8555)
        control = capture_netem_observation(kernel, plan)
        assert control.packets == matching.packets
        assert control.flow_counters == matching.flow_counters

        kernel.mutate_tc(
            (
                "qdisc",
                "change",
                "dev",
                "rtspifb0",
                "root",
                "handle",
                "7a10:",
                "netem",
                "limit",
                "1000",
                "delay",
                "51ms",
                "10ms",
            )
        )
        with pytest.raises(ValueError, match="netem_qdisc_options_invalid"):
            capture_netem_observation(kernel, plan)
        kernel.mutate_tc(
            (
                "qdisc",
                "change",
                "dev",
                "rtspifb0",
                "root",
                "handle",
                "7a10:",
                "netem",
                "limit",
                "1000",
                "delay",
                "50ms",
                "10ms",
            )
        )
        remove_netem(kernel, plan)
    finally:
        for created_namespace in reversed(created_namespaces):
            subprocess.run(
                [str(ip_binary), "netns", "del", created_namespace],
                check=False,
                capture_output=True,
                text=True,
                timeout=15,
            )
