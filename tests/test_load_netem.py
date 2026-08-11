from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

import pytest

from rtsp_proxy.load_catalog import build_direct_reader_plan, build_proxy_reader_plan
from rtsp_proxy.load_cli import main as load_cli_main
from rtsp_proxy.load_evidence import (
    REQUIRED_SUT_METRIC_FAMILIES,
    KernelClockProof,
    ResourceObservation,
    RuntimeProcessBinding,
    RuntimeProcessLimit,
    SutObservation,
    summarize_generator_headroom,
    summarize_sut_capacity,
)
from rtsp_proxy.load_netem import (
    NETEM_FILTER_PREF_START,
    NetemFlowCounters,
    NetemKernel,
    NetemObservation,
    NetemSitePlan,
    NetemSummary,
    NetemToolIdentity,
    SubprocessNetemKernel,
    capture_netem_observation,
    install_netem,
    load_netem_observations,
    remove_netem,
    required_netem_site_plans,
    sample_linux_netem,
    summarize_netem,
    validate_netem_comparison_tool_versions,
)
from rtsp_proxy.load_profile import (
    LoadProfile,
    canonical_profile_bytes,
    finalize_run_directory,
    generator_sampling_end_unix_ms,
    initialize_run_directory,
    lifecycle_start_unix_ms,
    measurement_end_unix_ms,
    measurement_start_unix_ms,
    ramp_end_unix_ms,
    sut_sampling_end_unix_ms,
    verify_run_directory,
    warm_anchor_start_unix_ms,
    workload_end_unix_ms,
)
from rtsp_proxy.load_results import summarize_reader_events
from rtsp_proxy.load_run import prepare_run_directory, sha256_file, write_summary
from tests.test_load_profile import (
    runtime_manifest,
    runtime_process_bindings_sha256,
    valid_profile,
    write_fixture_manifest,
)


class FakeNetemKernel(NetemKernel):
    def __init__(self) -> None:
        identity = NetemToolIdentity(
            path="/usr/sbin/tc",
            sha256="a" * 64,
            version="tc utility, iproute2-6.11.0",
        )
        self._tc_identity = identity
        self._ip_identity = identity.model_copy(update={"path": "/usr/sbin/ip", "sha256": "b" * 64})
        self.ingress_qdiscs: list[dict[str, object]] = [
            {"kind": "fq_codel", "handle": "0:", "root": True}
        ]
        self.ifb_qdiscs: list[dict[str, object]] = [
            {"kind": "noqueue", "handle": "0:", "root": True}
        ]
        self.filters: list[dict[str, object]] = []
        self.egress: list[dict[str, object]] = []
        self.commands: list[tuple[str, ...]] = []
        self.ifb_addr_info: list[dict[str, object]] = []

    @property
    def tc_identity(self) -> NetemToolIdentity:
        return self._tc_identity

    @property
    def ip_identity(self) -> NetemToolIdentity:
        return self._ip_identity

    def link(self, interface: str) -> dict[str, object]:
        if interface == "camera0":
            return {
                "ifindex": 2,
                "ifname": "camera0",
                "flags": ["BROADCAST", "UP"],
                "mtu": 1500,
                "addr_info": [{"family": "inet", "local": "198.51.100.10"}],
            }
        if interface == "rtspifb0":
            return {
                "ifindex": 3,
                "ifname": "rtspifb0",
                "flags": ["BROADCAST", "UP"],
                "mtu": 1500,
                "addr_info": self.ifb_addr_info,
                "linkinfo": {"info_kind": "ifb"},
            }
        raise ValueError("unknown fake interface")

    def qdiscs(self, interface: str) -> list[dict[str, object]]:
        return self.ingress_qdiscs if interface == "camera0" else self.ifb_qdiscs

    def ingress_filters(self, interface: str) -> list[dict[str, object]]:
        assert interface == "camera0"
        return self.filters

    def egress_filters(self, interface: str) -> list[dict[str, object]]:
        assert interface == "camera0"
        return self.egress

    def mutate_tc(self, arguments: tuple[str, ...]) -> None:
        self.commands.append(arguments)
        if arguments[:6] == ("qdisc", "add", "dev", "rtspifb0", "root", "handle"):
            delay_index = arguments.index("delay")
            limit_index = arguments.index("limit")
            self.ifb_qdiscs = [
                {
                    "kind": "netem",
                    "handle": "7a10:",
                    "root": True,
                    "options": {
                        "limit": int(arguments[limit_index + 1]),
                        "delay": {
                            "delay": float(arguments[delay_index + 1].removesuffix("ms")) / 1000,
                            "jitter": float(arguments[delay_index + 2].removesuffix("ms")) / 1000,
                            "correlation": 0.0,
                        },
                        "ecn": False,
                        "gap": 0,
                    },
                    "bytes": 0,
                    "packets": 0,
                    "drops": 0,
                    "overlimits": 0,
                    "backlog": 0,
                    "qlen": 0,
                }
            ]
            return
        if arguments[:6] == ("qdisc", "add", "dev", "rtspifb0", "parent", "7a10:1"):
            loss_index = arguments.index("loss")
            limit_index = arguments.index("limit")
            self.ifb_qdiscs.append(
                {
                    "kind": "netem",
                    "handle": "7a20:",
                    "parent": "7a10:1",
                    "options": {
                        "limit": int(arguments[limit_index + 1]),
                        "loss-random": {
                            "loss": float(arguments[loss_index + 2].removesuffix("%")) / 100,
                            "correlation": 0.0,
                        },
                        "ecn": False,
                        "gap": 0,
                    },
                    "bytes": 0,
                    "packets": 0,
                    "drops": 0,
                    "overlimits": 0,
                    "backlog": 0,
                    "qlen": 0,
                }
            )
            return
        if arguments == ("qdisc", "add", "dev", "camera0", "clsact"):
            self.ingress_qdiscs.append({"kind": "clsact", "handle": "ffff:"})
            return
        if arguments[:4] == ("filter", "add", "dev", "camera0"):
            pref_index = arguments.index("pref")
            source_ip_index = arguments.index("src_ip")
            source_port_index = arguments.index("src_port")
            self.filters.append(
                {
                    "protocol": "ip",
                    "pref": int(arguments[pref_index + 1]),
                    "chain": int(arguments[arguments.index("chain") + 1]),
                    "kind": "flower",
                    "options": {
                        "keys": {
                            "eth_type": "ipv4",
                            "ip_proto": "tcp",
                            "src_ip": arguments[source_ip_index + 1].removesuffix("/32"),
                            "src_port": int(arguments[source_port_index + 1]),
                        },
                        "skip_hw": True,
                        "not_in_hw": True,
                        "actions": [
                            {
                                "kind": "mirred",
                                "mirred_action": "redirect",
                                "direction": "egress",
                                "to_dev": "rtspifb0",
                                "stats": {
                                    "packets": 0,
                                    "bytes": 0,
                                    "drops": 0,
                                    "overlimits": 0,
                                },
                            }
                        ],
                    },
                }
            )
            return
        if arguments == ("qdisc", "del", "dev", "camera0", "clsact"):
            self.ingress_qdiscs = [
                item for item in self.ingress_qdiscs if item.get("kind") != "clsact"
            ]
            self.filters = []
            return
        if arguments == ("qdisc", "del", "dev", "rtspifb0", "root"):
            self.ifb_qdiscs = [{"kind": "noqueue", "handle": "0:", "root": True}]
            return
        raise AssertionError(arguments)


def wan_profile(*, endpoint_mode: str = "proxy", measurement_seconds: int = 2) -> LoadProfile:
    raw = valid_profile(tier="capacity")
    raw["tier"] = "smoke"
    workload = raw["workload"]
    network = raw["network"]
    duration = raw["duration"]
    hosts = raw["generator_hosts"]
    assert (
        isinstance(workload, dict)
        and isinstance(network, dict)
        and isinstance(duration, dict)
        and isinstance(hosts, list)
    )
    workload["endpoint_mode"] = endpoint_mode
    duration.update(
        warmup_seconds=0,
        measurement_seconds=measurement_seconds,
        soak_seconds=0,
    )
    network.update(
        profile="wan",
        rtt_ms=50,
        jitter_ms=10,
        loss_percent=0.5,
        ifb_interface="rtspifb0",
        netem_queue_limit_packets=1000,
    )
    for index, host in enumerate(hosts):
        assert isinstance(host, dict)
        host["rtsp_host"] = f"192.0.2.{10 + index}"
    return LoadProfile.model_validate(raw)


def write_host_identity(
    root: Path,
    *,
    machine_id: str = "test-machine",
    boot_id: str = "11111111-1111-1111-1111-111111111111",
) -> None:
    (root / "etc").mkdir(parents=True)
    (root / "proc/sys/kernel/random").mkdir(parents=True)
    (root / "etc/machine-id").write_text(f"{machine_id}\n", encoding="ascii")
    (root / "proc/sys/kernel/random/boot_id").write_text(
        f"{boot_id}\n",
        encoding="ascii",
    )


def clock(at_unix_ms: int) -> KernelClockProof:
    return KernelClockProof(
        observed_at_unix_ms=at_unix_ms,
        synchronized=True,
        state=0,
        status=0,
        max_error_ms=1,
    )


def fixed_clock(at_unix_ms: int) -> Callable[[float], KernelClockProof]:
    def proof(_maximum: float) -> KernelClockProof:
        return clock(at_unix_ms)

    return proof


def flow_counters_at(plan: NetemSitePlan, value: int) -> tuple[NetemFlowCounters, ...]:
    packets_per_flow, remainder = divmod(value, len(plan.flows))
    return tuple(
        NetemFlowCounters(
            preference=flow.preference,
            source_ipv4=flow.source_ipv4,
            source_port=flow.source_port,
            packets=packets_per_flow + (1 if index < remainder else 0),
            bytes=(packets_per_flow + (1 if index < remainder else 0)) * 100,
            drops=0,
            overlimits=0,
        )
        for index, flow in enumerate(plan.flows)
    )


def sample_times(start_ms: int, end_ms: int) -> tuple[int, ...]:
    values = list(range(start_ms, end_ms + 1, 1000))
    if values[-1] != end_ms:
        values.append(end_ms)
    return tuple(values)


def traffic_observation(
    base: NetemObservation,
    plan: NetemSitePlan,
    *,
    observed_at_ms: int,
    attempted_packets: int,
) -> NetemObservation:
    random_drops = (
        max(1, round(attempted_packets * plan.loss_percent / 100))
        if attempted_packets
        else 0
    )
    delivered = attempted_packets - random_drops
    return base.model_copy(
        update={
            "timestamp": datetime.fromtimestamp(observed_at_ms / 1000, UTC),
            "clock_proof": clock(observed_at_ms),
            "packets": delivered,
            "bytes": delivered * 100,
            "drops": random_drops,
            "random_loss_packets": delivered,
            "random_loss_bytes": delivered * 100,
            "random_loss_drops": random_drops,
            "flow_counters": flow_counters_at(plan, attempted_packets),
        }
    )


def resource_observation(
    *,
    host: str,
    machine_id_sha256: str,
    boot_id: str,
    observed_at_ms: int,
    processes: tuple[RuntimeProcessBinding, ...],
) -> ResourceObservation:
    return ResourceObservation(
        generator_host=host,
        machine_id_sha256=machine_id_sha256,
        boot_id=boot_id,
        timestamp=datetime.fromtimestamp(observed_at_ms / 1000, UTC)
        .isoformat()
        .replace("+00:00", "Z"),
        interval_seconds=1,
        host_cpu_percent=10,
        host_ram_percent=10,
        max_process_cpu_percent=10,
        cgroup_cpu_percent=10,
        cgroup_ram_percent=10,
        max_process_fd_percent=10,
        socket_percent=10,
        ephemeral_port_start=32768,
        ephemeral_port_end=60999,
        ephemeral_port_capacity=28232,
        reserved_ports_sha256=hashlib.sha256(b"").hexdigest(),
        cgroup_pids_percent=10,
        network_percent=10,
        network_packets_per_second=1000,
        packet_rate_percent=10,
        interface_mtu_bytes=1500,
        memory_total_bytes=16 * 1024**3,
        nic_link_speed_bits_per_second=10_000_000_000,
        cgroup_cpu_capacity_cores=4,
        cgroup_memory_limit_bytes=8 * 1024**3,
        cgroup_pids_limit=100000,
        process_count=len(processes),
        workload_processes=processes,
        workload_processes_sha256=runtime_process_bindings_sha256(processes),
        workload_process_limits=tuple(
            RuntimeProcessLimit(pid=item.pid, max_open_files=65536) for item in processes
        ),
        cgroup_path_sha256="c" * 64,
        cgroup_constraint_chain_sha256="5" * 64,
    )


def cold_reader_events(
    profile: LoadProfile, run_directory: Path, scheduled_start_ms: int
) -> list[dict[str, object]]:
    events: list[dict[str, object]] = []
    reader_plan_builder = (
        build_proxy_reader_plan
        if profile.workload.endpoint_mode == "proxy"
        else build_direct_reader_plan
    )
    for shard_index, host in enumerate(profile.generator_hosts):
        plan = reader_plan_builder(profile, host.name)
        shard_readers = 0
        shard_packets = 0
        for target in plan.targets:
            for offset in range(target.reader_count):
                reader_id = target.reader_id_start + offset
                schedule_position = target.measured_schedule_start + offset
                started_ms = scheduled_start_ms + schedule_position * 100
                started_relative = started_ms - scheduled_start_ms
                play_relative = started_relative + 10
                decodable_relative = play_relative + 100
                events.extend(
                    (
                        {
                            "event": "reader_started",
                            "reader_id": reader_id,
                            "cycle": 0,
                            "path": target.path,
                            "at_monotonic_ms": started_relative,
                            "at_unix_ms": started_ms,
                        },
                        {
                            "event": "play_sent",
                            "reader_id": reader_id,
                            "cycle": 0,
                            "path": target.path,
                            "at_monotonic_ms": play_relative,
                            "describe_to_play_ms": 10,
                        },
                        {
                            "event": "first_decodable_frame",
                            "reader_id": reader_id,
                            "cycle": 0,
                            "path": target.path,
                            "at_monotonic_ms": decodable_relative,
                            "describe_to_first_decodable_ms": 110,
                            "play_to_first_decodable_ms": 100,
                            "access_unit": True,
                        },
                        {
                            "event": "reader_rtp_segment",
                            "reader_id": reader_id,
                            "cycle": 0,
                            "path": target.path,
                            "track": "video",
                            "phase": "measurement",
                            "first_at_monotonic_ms": max(
                                measurement_start_unix_ms(profile, scheduled_start_ms)
                                - scheduled_start_ms,
                                decodable_relative,
                            ),
                            "last_at_monotonic_ms": measurement_end_unix_ms(
                                profile, scheduled_start_ms
                            )
                            - scheduled_start_ms
                            - 1,
                            "received_packets": 250,
                            "sequence_expected_packets": 250,
                            "sequence_gaps": 0,
                        },
                        {
                            "event": "reader_rtp_phase",
                            "reader_id": reader_id,
                            "path": target.path,
                            "at_monotonic_ms": workload_end_unix_ms(profile, scheduled_start_ms)
                            - scheduled_start_ms,
                            "audio_expected": False,
                            "quiesced": True,
                            "video_parse_failures": 0,
                            "audio_parse_failures": 0,
                            "measurement_video_rtp_packets": 250,
                            "measurement_video_rtp_sequence_gaps": 0,
                            "soak_video_rtp_packets": 0,
                            "soak_video_rtp_sequence_gaps": 0,
                            "measurement_audio_rtp_packets": 0,
                            "measurement_audio_rtp_sequence_gaps": 0,
                            "soak_audio_rtp_packets": 0,
                            "soak_audio_rtp_sequence_gaps": 0,
                        },
                    )
                )
                shard_readers += 1
                shard_packets += 250
        events.append(
            {
                "event": "run_completed",
                "at_monotonic_ms": workload_end_unix_ms(profile, scheduled_start_ms)
                - scheduled_start_ms,
                "started_readers": shard_readers,
                "ready_readers": shard_readers,
                "failed_attempts": 0,
                "normal_completion": True,
                "interrupted": False,
                "lifecycle_complete": True,
                "exit_code": 0,
                "schedule_shard_index": shard_index,
                "schedule_shards": len(profile.generator_hosts),
                "generator_host": host.name,
                "profile_sha256": canonical_profile_bytes(profile)[1],
                "reader_plan_sha256": sha256_file(run_directory / f"reader-plan-{host.name}.tsv"),
                "anchor_start_unix_ms": warm_anchor_start_unix_ms(profile, scheduled_start_ms),
                "scheduled_start_unix_ms": scheduled_start_ms,
                "ramp_end_unix_ms": ramp_end_unix_ms(profile, scheduled_start_ms),
                "lifecycle_start_unix_ms": lifecycle_start_unix_ms(profile, scheduled_start_ms),
                "measurement_start_unix_ms": measurement_start_unix_ms(profile, scheduled_start_ms),
                "measurement_end_unix_ms": measurement_end_unix_ms(profile, scheduled_start_ms),
                "scheduled_workload_end_unix_ms": workload_end_unix_ms(profile, scheduled_start_ms),
                "process_start_unix_ms": scheduled_start_ms - 100,
                "workload_end_unix_ms": workload_end_unix_ms(profile, scheduled_start_ms),
                "process_end_unix_ms": workload_end_unix_ms(profile, scheduled_start_ms) + 100,
                "clock_synchronized": True,
                "clock_max_error_ms": 1,
                "lifecycle_scheduled_slots": 0,
                "injected_disconnects": 0,
                "rtp_packets": shard_packets,
                "measurement_rtp_packets": shard_packets,
                "soak_rtp_packets": 0,
                "measurement_rtp_sequence_gaps": 0,
                "soak_rtp_sequence_gaps": 0,
            }
        )
    return events


def write_reader_evidence(
    profile: LoadProfile, run_directory: Path, scheduled_start_ms: int
) -> None:
    events_path = run_directory / "raw/readers.jsonl"
    events_path.write_text(
        "".join(
            json.dumps(event) + "\n"
            for event in cold_reader_events(profile, run_directory, scheduled_start_ms)
        ),
        encoding="utf-8",
    )
    write_summary(
        run_directory / "summary/readers.json",
        summarize_reader_events(profile, events_path),
    )


def write_generator_evidence(
    profile: LoadProfile,
    run_directory: Path,
    scheduled_start_ms: int,
    machine_ids: dict[str, str],
    boot_id: str,
) -> None:
    launch = json.loads((run_directory / "launch-plan.json").read_text(encoding="utf-8"))
    for host_index, host in enumerate(profile.generator_hosts):
        process_digests = [
            profile.artifacts.pull_server_sha256
            for item in launch["source_servers"]
            if item["generator_host"] == host.name
        ] + [
            profile.artifacts.load_reader_sha256
            for item in launch["readers"]
            if item["generator_host"] == host.name
        ]
        processes = tuple(
            RuntimeProcessBinding(
                pid=1000 + host_index * 10 + index,
                executable_sha256=digest,
                start_time_ticks=10000 + host_index * 10 + index,
            )
            for index, digest in enumerate(process_digests)
        )
        observations = tuple(
            resource_observation(
                host=host.name,
                machine_id_sha256=machine_ids[host.name],
                boot_id=boot_id,
                observed_at_ms=observed_at_ms,
                processes=processes,
            )
            for observed_at_ms in sample_times(
                warm_anchor_start_unix_ms(profile, scheduled_start_ms),
                workload_end_unix_ms(profile, scheduled_start_ms),
            )
        )
        raw_path = run_directory / f"raw/generator-{host.name}.jsonl"
        raw_path.write_text(
            "".join(item.model_dump_json() + "\n" for item in observations),
            encoding="utf-8",
        )
        write_summary(
            run_directory / f"summary/generator-{host.name}.json",
            summarize_generator_headroom(
                observations,
                expected_generator_host=host.name,
                minimum_duration_seconds=profile.duration.measurement_seconds,
                expected_interval_seconds=profile.evidence_sampling.interval_seconds,
                maximum_gap_factor=profile.evidence_sampling.maximum_gap_factor,
                observations_sha256=sha256_file(raw_path),
                measurement_start_unix_ms=measurement_start_unix_ms(profile, scheduled_start_ms),
                measurement_end_unix_ms=measurement_end_unix_ms(profile, scheduled_start_ms),
                soak_end_unix_ms=workload_end_unix_ms(profile, scheduled_start_ms),
            ),
        )
        write_summary(
            run_directory / f"raw/runtime-generator-{host.name}.json",
            runtime_manifest(
                profile,
                role="generator",
                host=host.name,
                architecture=host.architecture,
                processes=processes,
                machine_id_sha256=machine_ids[host.name],
                boot_id=boot_id,
                observed_at_unix_ms=scheduled_start_ms,
            ),
        )


def write_sut_evidence(
    profile: LoadProfile,
    run_directory: Path,
    scheduled_start_ms: int,
    machine_id_sha256: str,
    boot_id: str,
) -> None:
    processes = (
        RuntimeProcessBinding(
            pid=2000,
            executable_sha256=profile.artifacts.mediamtx_sha256,
            start_time_ticks=20000,
        ),
    )
    observations = tuple(
        SutObservation(
            sut_host=profile.sut_rtsp_host,
            timestamp=datetime.fromtimestamp(observed_at_ms / 1000, UTC)
            .isoformat()
            .replace("+00:00", "Z"),
            clock_proof=clock(observed_at_ms),
            resource=resource_observation(
                host=profile.sut_rtsp_host,
                machine_id_sha256=machine_id_sha256,
                boot_id=boot_id,
                observed_at_ms=observed_at_ms,
                processes=processes,
            ),
            mediamtx_rss_bytes=1024,
            mediamtx_open_file_descriptors=10,
            metrics_families=REQUIRED_SUT_METRIC_FAMILIES,
            total_rtsp_sessions=0,
            ready_runtime_paths=0,
            active_session_counters=(),
            active_path_counters=(),
            cumulative_inbound_rtp_packets=0,
            cumulative_outbound_rtp_packets=0,
            inbound_rtp_packets_lost=0,
            inbound_rtp_packets_in_error=0,
            inbound_rtcp_packets_in_error=0,
            outbound_rtp_packets_discarded=0,
            outbound_rtp_packets_reported_lost=0,
            rtcp_packets_in_error=0,
            rtp_packets_in_error=0,
            rtp_packets_lost=0,
            path_inbound_frames_in_error=0,
        )
        for observed_at_ms in sample_times(
            scheduled_start_ms, sut_sampling_end_unix_ms(profile, scheduled_start_ms)
        )
    )
    raw_path = run_directory / "raw/sut.jsonl"
    raw_path.write_text(
        "".join(item.model_dump_json() + "\n" for item in observations), encoding="utf-8"
    )
    write_summary(
        run_directory / "summary/sut.json",
        summarize_sut_capacity(
            observations,
            expected_sut_host=profile.sut_rtsp_host,
            expected_interval_seconds=profile.evidence_sampling.interval_seconds,
            maximum_gap_factor=profile.evidence_sampling.maximum_gap_factor,
            observations_sha256=sha256_file(raw_path),
            measurement_start_unix_ms=measurement_start_unix_ms(profile, scheduled_start_ms),
            measurement_end_unix_ms=measurement_end_unix_ms(profile, scheduled_start_ms),
            soak_end_unix_ms=workload_end_unix_ms(profile, scheduled_start_ms),
            maximum_clock_error_ms=profile.evidence_sampling.maximum_clock_error_ms,
            capacity_gate=False,
        ),
    )
    write_summary(
        run_directory / "raw/runtime-sut.json",
        runtime_manifest(
            profile,
            role="sut",
            host=profile.sut_rtsp_host,
            architecture=profile.sut_architecture,
            processes=processes,
            machine_id_sha256=machine_id_sha256,
            boot_id=boot_id,
            observed_at_unix_ms=scheduled_start_ms,
        ),
    )


def write_netem_evidence(
    profile: LoadProfile,
    run_directory: Path,
    scheduled_start_ms: int,
    identity_roots: dict[str, Path],
) -> None:
    for plan in required_netem_site_plans(profile):
        kernel = FakeNetemKernel()
        install_netem(kernel, plan)
        anchor_ms = warm_anchor_start_unix_ms(profile, scheduled_start_ms)
        sampling_end_ms = (
            sut_sampling_end_unix_ms(profile, scheduled_start_ms)
            if plan.role == "sut"
            else generator_sampling_end_unix_ms(profile, scheduled_start_ms)
        )
        workload_end_ms = workload_end_unix_ms(profile, scheduled_start_ms)

        base = capture_netem_observation(
            kernel,
            plan,
            root=identity_roots[plan.receiver_host],
            clock_proof=fixed_clock(anchor_ms),
        )
        observations_list: list[NetemObservation] = []
        for observed_at_ms in sample_times(anchor_ms, sampling_end_ms):
            attempted = max(0, min(observed_at_ms, workload_end_ms) - anchor_ms)
            observations_list.append(
                traffic_observation(
                    base,
                    plan,
                    observed_at_ms=observed_at_ms,
                    attempted_packets=attempted,
                )
            )
        observations = tuple(observations_list)
        raw_path = run_directory / f"raw/netem-{plan.site}.jsonl"
        raw_path.write_text(
            "".join(item.model_dump_json() + "\n" for item in observations),
            encoding="utf-8",
        )
        write_summary(
            run_directory / f"summary/netem-{plan.site}.json",
            summarize_netem(
                profile,
                plan,
                observations,
                observations_sha256=sha256_file(raw_path),
                coordinated_start_unix_ms=scheduled_start_ms,
            ),
        )


def cold_wan_profile_pair(
    tmp_path: Path,
) -> tuple[LoadProfile, LoadProfile, Path, Path, Path]:
    pull_server = tmp_path / "rtsp-pull-server"
    load_reader = tmp_path / "rtsp-load-reader"
    fixture = tmp_path / "fixture.h264"
    pull_server.write_bytes(b"pull-server")
    load_reader.write_bytes(b"load-reader")
    fixture.write_bytes(b"fixture")
    pull_server.chmod(0o750)
    load_reader.chmod(0o750)
    raw = valid_profile(tier="capacity")
    raw["tier"] = "smoke"
    artifacts = raw["artifacts"]
    fixture_profile = raw["fixture"]
    workload = raw["workload"]
    network = raw["network"]
    duration = raw["duration"]
    hosts = raw["generator_hosts"]
    assert isinstance(artifacts, dict)
    assert isinstance(fixture_profile, dict)
    assert isinstance(workload, dict)
    assert isinstance(network, dict)
    assert isinstance(duration, dict)
    assert isinstance(hosts, list)
    artifacts["pull_server_sha256"] = hashlib.sha256(b"pull-server").hexdigest()
    artifacts["load_reader_sha256"] = hashlib.sha256(b"load-reader").hexdigest()
    fixture_profile.update(path=str(fixture), sha256=hashlib.sha256(b"fixture").hexdigest())
    workload.update(session_temperature="cold", total_readers=4)
    duration.update(warmup_seconds=0, measurement_seconds=2, soak_seconds=0)
    network.update(
        profile="wan",
        rtt_ms=50,
        jitter_ms=10,
        loss_percent=0.5,
        ifb_interface="rtspifb0",
        netem_queue_limit_packets=1000,
    )
    for index, host in enumerate(hosts):
        assert isinstance(host, dict)
        host["rtsp_host"] = f"192.0.2.{10 + index}"
    proxy = LoadProfile.model_validate(raw)
    direct_payload = proxy.model_dump(mode="json")
    direct_workload = direct_payload["workload"]
    assert isinstance(direct_workload, dict)
    direct_workload["endpoint_mode"] = "direct-control"
    direct = LoadProfile.model_validate(direct_payload)
    write_fixture_manifest(proxy)
    return proxy, direct, pull_server, load_reader, fixture


def write_finalizable_wan_evidence(
    profile: LoadProfile,
    run_directory: Path,
    *,
    scheduled_start_ms: int,
    machine_ids: dict[str, str],
    identity_roots: dict[str, Path],
    boot_id: str,
) -> None:
    write_reader_evidence(profile, run_directory, scheduled_start_ms)
    write_generator_evidence(profile, run_directory, scheduled_start_ms, machine_ids, boot_id)
    if profile.workload.endpoint_mode == "proxy":
        write_sut_evidence(
            profile,
            run_directory,
            scheduled_start_ms,
            machine_ids[profile.sut_rtsp_host],
            boot_id,
        )
        observed_start = scheduled_start_ms - 1000
        observed_end = scheduled_start_ms - 500
        paths = [target.path for target in build_proxy_reader_plan(profile).targets]
        (run_directory / "raw/cold-preflight.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "profile_sha256": canonical_profile_bytes(profile)[1],
                    "scheduled_start_unix_ms": scheduled_start_ms,
                    "observed_start_unix_ms": observed_start,
                    "observed_end_unix_ms": observed_end,
                    "clock_proof_start": clock(observed_start).model_dump(mode="json"),
                    "clock_proof_end": clock(observed_end).model_dump(mode="json"),
                    "reset_paths": paths,
                    "unavailable_paths": paths,
                }
            )
            + "\n",
            encoding="utf-8",
        )
    write_netem_evidence(profile, run_directory, scheduled_start_ms, identity_roots)


def test_site_plans_scope_proxy_and_remote_direct_ingress() -> None:
    proxy = wan_profile()
    direct = wan_profile(endpoint_mode="direct-control")

    proxy_plans = required_netem_site_plans(proxy)
    direct_plans = required_netem_site_plans(direct)

    assert len(proxy_plans) == 1
    assert proxy_plans[0].site == "sut"
    assert [(item.source_ipv4, item.source_port) for item in proxy_plans[0].flows] == [
        ("192.0.2.10", 8554),
        ("192.0.2.11", 8554),
    ]
    assert [item.site for item in direct_plans] == ["generator-a", "generator-b"]
    assert [item.flows[0].source_ipv4 for item in direct_plans] == [
        "192.0.2.11",
        "192.0.2.10",
    ]
    assert all(item.flows[0].preference == NETEM_FILTER_PREF_START for item in direct_plans)


def test_public_wan_cold_pair_copies_recomputes_finalizes_and_verifies(
    tmp_path: Path,
) -> None:
    proxy, direct, pull_server, load_reader, _fixture = cold_wan_profile_pair(tmp_path)
    scheduled_start_ms = 4_102_444_800_000
    proxy_run = tmp_path / "proxy-run"
    direct_run = tmp_path / "direct-run"
    for profile, run_directory in ((direct, direct_run), (proxy, proxy_run)):
        prepare_run_directory(
            profile,
            run_directory,
            pull_server_binary=pull_server,
            load_reader_binary=load_reader,
            coordinated_start_unix_ms=scheduled_start_ms,
        )

    boot_id = "11111111-1111-1111-1111-111111111111"
    receiver_hosts = {
        *(host.name for host in proxy.generator_hosts),
        proxy.sut_rtsp_host,
    }
    machine_ids: dict[str, str] = {}
    identity_roots: dict[str, Path] = {}
    for receiver_host in receiver_hosts:
        machine_text = f"machine-{receiver_host}"
        machine_ids[receiver_host] = hashlib.sha256(machine_text.encode()).hexdigest()
        identity_root = tmp_path / f"identity-{receiver_host}"
        write_host_identity(identity_root, machine_id=machine_text, boot_id=boot_id)
        identity_roots[receiver_host] = identity_root

    write_finalizable_wan_evidence(
        direct,
        direct_run,
        scheduled_start_ms=scheduled_start_ms,
        machine_ids=machine_ids,
        identity_roots=identity_roots,
        boot_id=boot_id,
    )
    assert load_cli_main(["finalize", str(direct_run)]) == 0
    assert load_cli_main(["verify", str(direct_run)]) == 0

    write_finalizable_wan_evidence(
        proxy,
        proxy_run,
        scheduled_start_ms=scheduled_start_ms,
        machine_ids=machine_ids,
        identity_roots=identity_roots,
        boot_id=boot_id,
    )
    assert (
        load_cli_main(
            [
                "compare-cold",
                str(proxy_run),
                str(proxy_run / "raw/readers.jsonl"),
                str(direct_run),
                str(direct_run / "raw/readers.jsonl"),
                str(proxy_run / "summary/cold-comparison.json"),
            ]
        )
        == 0
    )
    comparison_payload = json.loads(
        (proxy_run / "summary/cold-comparison.json").read_text(encoding="utf-8")
    )
    assert comparison_payload["wan_loss"]["proxy_attempted_packets"] > 0
    assert comparison_payload["wan_loss"]["direct_attempted_packets"] > 0
    assert comparison_payload["wan_loss"]["proxy_random_loss_drops"] > 0
    assert comparison_payload["wan_loss"]["direct_random_loss_drops"] > 0
    assert isinstance(
        comparison_payload["wan_loss"]["proxy_minus_direct_loss_percentage_points"],
        float,
    )
    assert {
        "direct-netem-generator-a.jsonl",
        "direct-netem-generator-b.jsonl",
        "direct-netem-summary-generator-a.json",
        "direct-netem-summary-generator-b.json",
        "direct-launch-plan.json",
    }.issubset({item.name for item in (proxy_run / "reference").iterdir()})

    copied_summary = proxy_run / "reference/direct-netem-summary-generator-a.json"
    original_summary = copied_summary.read_bytes()
    copied_summary.write_text('{"valid":false}\n', encoding="utf-8")
    with pytest.raises(ValueError, match="direct_netem_reference_manifest_binding_invalid"):
        finalize_run_directory(proxy_run)
    copied_summary.write_bytes(original_summary)

    comparison_path = proxy_run / "summary/cold-comparison.json"
    original_comparison = comparison_path.read_bytes()
    tampered_comparison = json.loads(original_comparison)
    tampered_comparison["wan_loss"]["proxy_minus_direct_loss_percentage_points"] += 1
    comparison_path.write_text(json.dumps(tampered_comparison) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="cold_comparison_not_reproducible_or_invalid"):
        finalize_run_directory(proxy_run)
    comparison_path.write_bytes(original_comparison)

    assert load_cli_main(["finalize", str(proxy_run)]) == 0
    assert load_cli_main(["verify", str(proxy_run)]) == 0
    verify_run_directory(proxy_run)


def test_install_and_remove_own_only_clean_scoped_netem_state(tmp_path: Path) -> None:
    plan = required_netem_site_plans(wan_profile())[0]
    kernel = FakeNetemKernel()

    install_netem(kernel, plan)

    assert kernel.ifb_qdiscs[0]["kind"] == "netem"
    assert len(kernel.filters) == 2
    assert all(
        item["options"]["keys"]["src_port"] == 8554  # type: ignore[index]
        for item in kernel.filters
    )
    with pytest.raises(ValueError, match="netem_ingress_filter_not_clean"):
        install_netem(kernel, plan)

    remove_netem(kernel, plan)
    assert kernel.filters == []
    assert str(kernel.ifb_qdiscs[0]["kind"]) == "noqueue"

    kernel.ifb_qdiscs = [{"kind": "fq_codel", "handle": "0:", "root": True}]
    install_netem(kernel, plan)
    remove_netem(kernel, plan)

    install_netem(kernel, plan)
    details = tuple(kernel.filters)
    kernel.filters = [
        item
        for detail in details
        for item in (
            {
                "protocol": detail["protocol"],
                "pref": detail["pref"],
                "kind": detail["kind"],
                "chain": detail["chain"],
            },
            detail,
        )
    ]
    write_host_identity(tmp_path)
    capture_netem_observation(kernel, plan, root=tmp_path, clock_proof=lambda _: clock(1))
    remove_netem(kernel, plan)


def test_ifb_accepts_only_automatic_ipv6_link_local_address() -> None:
    plan = required_netem_site_plans(wan_profile())[0]
    kernel = FakeNetemKernel()
    kernel.ifb_addr_info = [
        {
            "family": "inet6",
            "local": "fe80::5054:ff:fe12:3456",
            "prefixlen": 64,
            "scope": "link",
        }
    ]

    install_netem(kernel, plan)
    remove_netem(kernel, plan)

    kernel.ifb_addr_info = [
        {
            "family": "inet",
            "local": "198.51.100.10",
            "prefixlen": 24,
            "scope": "global",
        }
    ]
    with pytest.raises(ValueError, match="netem_ifb_not_dedicated"):
        install_netem(kernel, plan)

    class IncompleteIfbKernel(FakeNetemKernel):
        def __init__(self, *, master: bool) -> None:
            super().__init__()
            self.master = master

        def link(self, interface: str) -> dict[str, object]:
            result = super().link(interface)
            if interface == "rtspifb0":
                if self.master:
                    result["master"] = "bond0"
                else:
                    result.pop("addr_info")
            return result

    with pytest.raises(ValueError, match="netem_ifb_not_dedicated"):
        install_netem(IncompleteIfbKernel(master=False), plan)
    with pytest.raises(ValueError, match="netem_ifb_not_dedicated"):
        install_netem(IncompleteIfbKernel(master=True), plan)


def test_observation_and_summary_reject_state_drift_and_queue_overlimit(tmp_path: Path) -> None:
    profile = wan_profile(measurement_seconds=20)
    plan = required_netem_site_plans(profile)[0]
    kernel = FakeNetemKernel()
    install_netem(kernel, plan)
    write_host_identity(tmp_path)
    start_ms = 4_102_444_800_000
    anchor_ms = warm_anchor_start_unix_ms(profile, start_ms)
    base = capture_netem_observation(
        kernel,
        plan,
        root=tmp_path,
        clock_proof=lambda _maximum: clock(anchor_ms),
    )
    workload_end_ms = workload_end_unix_ms(profile, start_ms)
    end_ms = sut_sampling_end_unix_ms(profile, start_ms)
    observations: list[NetemObservation] = []
    current_ms = anchor_ms
    while current_ms <= end_ms:
        offset = min(current_ms, workload_end_ms) - anchor_ms
        observations.append(
            traffic_observation(
                base,
                plan,
                observed_at_ms=current_ms,
                attempted_packets=offset * 10 + 1,
            )
        )
        current_ms += 1000
    if round(observations[-1].timestamp.timestamp() * 1000) < end_ms:
        observations.append(
            traffic_observation(
                base,
                plan,
                observed_at_ms=end_ms,
                attempted_packets=(workload_end_ms - anchor_ms) * 10 + 1,
            )
        )
    if round(observations[-1].timestamp.timestamp() * 1000) < end_ms:
        observations.append(
            observations[-1].model_copy(
                update={
                    "timestamp": datetime.fromtimestamp(end_ms / 1000, tz=UTC),
                    "clock_proof": clock(end_ms),
                    "packets": (workload_end_ms - anchor_ms) * 10,
                    "bytes": (workload_end_ms - anchor_ms) * 1000,
                }
            )
        )
    summary = summarize_netem(
        profile,
        plan,
        tuple(observations),
        observations_sha256=hashlib.sha256(b"observations").hexdigest(),
        coordinated_start_unix_ms=start_ms,
    )
    assert summary.valid
    assert summary.packets_delta > 0
    assert len(summary.flow_deltas) == len(plan.flows)
    assert all(item.packets_delta > 0 for item in summary.flow_deltas)

    missing_flow = list(observations)
    final_flows = list(missing_flow[-1].flow_counters)
    final_flows[-1] = missing_flow[0].flow_counters[-1]
    missing_flow[-1] = missing_flow[-1].model_copy(update={"flow_counters": tuple(final_flows)})
    missing_flow_summary = summarize_netem(
        profile,
        plan,
        tuple(missing_flow),
        observations_sha256="b" * 64,
        coordinated_start_unix_ms=start_ms,
    )
    assert not missing_flow_summary.valid
    assert "netem_flow_traffic_missing" in missing_flow_summary.invalid_reasons

    dropped_flow = list(observations)
    dropped_counters = list(dropped_flow[-1].flow_counters)
    dropped_counters[0] = dropped_counters[0].model_copy(update={"drops": 1})
    dropped_flow[-1] = dropped_flow[-1].model_copy(
        update={"flow_counters": tuple(dropped_counters)}
    )
    dropped_flow_summary = summarize_netem(
        profile,
        plan,
        tuple(dropped_flow),
        observations_sha256="e" * 64,
        coordinated_start_unix_ms=start_ms,
    )
    assert not dropped_flow_summary.valid
    assert "netem_flow_action_drop" in dropped_flow_summary.invalid_reasons

    tampered = list(observations)
    tampered[-1] = tampered[-1].model_copy(update={"overlimits": 1})
    invalid = summarize_netem(
        profile,
        plan,
        tuple(tampered),
        observations_sha256="c" * 64,
        coordinated_start_unix_ms=start_ms,
    )
    assert not invalid.valid
    assert "netem_queue_overlimit" in invalid.invalid_reasons

    excessive_drops = list(observations)
    excessive_drops[-1] = excessive_drops[-1].model_copy(
        update={"drops": excessive_drops[-1].packets}
    )
    saturated = summarize_netem(
        profile,
        plan,
        tuple(excessive_drops),
        observations_sha256="9" * 64,
        coordinated_start_unix_ms=start_ms,
    )
    assert not saturated.valid
    assert "netem_queue_overflow_drop" in saturated.invalid_reasons

    excessive_random_loss = list(observations)
    excessive_random_loss[-1] = excessive_random_loss[-1].model_copy(
        update={
            "drops": excessive_random_loss[-1].packets,
            "random_loss_drops": excessive_random_loss[-1].packets,
        }
    )
    excessive_random = summarize_netem(
        profile,
        plan,
        tuple(excessive_random_loss),
        observations_sha256="8" * 64,
        coordinated_start_unix_ms=start_ms,
    )
    assert not excessive_random.valid
    assert "netem_drop_rate_above_random_loss_envelope" in excessive_random.invalid_reasons

    missing_random_loss = [
        item.model_copy(update={"drops": 0, "random_loss_drops": 0})
        for item in observations
    ]
    missing_random = summarize_netem(
        profile,
        plan,
        tuple(missing_random_loss),
        observations_sha256="7" * 64,
        coordinated_start_unix_ms=start_ms,
    )
    assert not missing_random.valid
    assert "netem_drop_rate_below_random_loss_envelope" in missing_random.invalid_reasons

    kernel.ifb_qdiscs[0]["options"]["delay"]["delay"] = 0.15  # type: ignore[index]
    with pytest.raises(ValueError, match="netem_qdisc_options_invalid"):
        capture_netem_observation(
            kernel,
            plan,
            root=tmp_path,
            clock_proof=lambda _maximum: clock(anchor_ms),
        )

    wrong_ifb_mtu = observations[-1].model_copy(
        update={
            "configuration": observations[-1].configuration.model_copy(
                update={"ifb_mtu_bytes": 1499}
            )
        }
    )
    wrong_mtu_summary = summarize_netem(
        profile,
        plan,
        (*observations[:-1], wrong_ifb_mtu),
        observations_sha256="d" * 64,
        coordinated_start_unix_ms=start_ms,
    )
    assert not wrong_mtu_summary.valid
    assert "netem_observation_binding_invalid" in wrong_mtu_summary.invalid_reasons


def test_sampler_publishes_exclusive_typed_jsonl(tmp_path: Path) -> None:
    profile = wan_profile()
    plan = required_netem_site_plans(profile)[0]
    kernel = FakeNetemKernel()
    install_netem(kernel, plan)
    write_host_identity(tmp_path)
    start_ms = 4_102_444_800_000
    output = tmp_path / "netem.jsonl"
    sampling_end_ms = sut_sampling_end_unix_ms(profile, start_ms)

    sampled = sample_linux_netem(
        profile,
        plan,
        output,
        kernel=kernel,
        coordinated_start_unix_ms=start_ms,
        root=tmp_path,
        sleep=lambda _seconds: None,
        monotonic=lambda: 10.0,
        unix_time=lambda: 9_000_000_000.0,
        clock_proof=lambda _maximum: clock(sampling_end_ms),
    )

    assert load_netem_observations(output) == sampled
    assert output.stat().st_mode & 0o777 == 0o640
    clock_values = iter(
        (
            clock(warm_anchor_start_unix_ms(profile, start_ms)),
            clock(sampling_end_ms),
        )
    )
    sleep_calls: list[float] = []
    two_sample_output = tmp_path / "netem-two-samples.jsonl"
    assert (
        len(
            sample_linux_netem(
                profile,
                plan,
                two_sample_output,
                kernel=kernel,
                coordinated_start_unix_ms=start_ms,
                root=tmp_path,
                sleep=sleep_calls.append,
                monotonic=lambda: 10.0,
                unix_time=lambda: 9_000_000_000.0,
                clock_proof=lambda _maximum: next(clock_values),
            )
        )
        == 2
    )
    assert sleep_calls == [profile.evidence_sampling.interval_seconds]
    with pytest.raises(FileExistsError):
        sample_linux_netem(
            profile,
            plan,
            output,
            kernel=kernel,
            coordinated_start_unix_ms=start_ms,
            root=tmp_path,
        )

    empty = tmp_path / "empty.jsonl"
    empty.write_text("", encoding="utf-8")
    with pytest.raises(ValueError, match="netem_observations_empty"):
        load_netem_observations(empty)
    blank = tmp_path / "blank.jsonl"
    blank.write_text("\n", encoding="utf-8")
    with pytest.raises(ValueError, match="netem_observation_blank_line"):
        load_netem_observations(blank)
    with pytest.raises(ValueError, match="netem_observations_must_be_regular_file"):
        load_netem_observations(tmp_path / "missing.jsonl")


def test_summary_fails_closed_for_identity_clock_gap_counter_and_window_drift(
    tmp_path: Path,
) -> None:
    profile = wan_profile(measurement_seconds=20)
    plan = required_netem_site_plans(profile)[0]
    kernel = FakeNetemKernel()
    install_netem(kernel, plan)
    write_host_identity(tmp_path)
    start_ms = 4_102_444_800_000
    first_ms = start_ms + 1000
    first = capture_netem_observation(
        kernel,
        plan,
        root=tmp_path,
        clock_proof=lambda _maximum: clock(first_ms),
    ).model_copy(update={"packets": 10, "bytes": 1000})
    changed_configuration = first.configuration.model_copy(update={"delay_ms": 51})
    second_ms = first_ms + 5000
    second = first.model_copy(
        update={
            "profile_sha256": "d" * 64,
            "timestamp": datetime.fromtimestamp(second_ms / 1000, tz=UTC),
            "clock_proof": clock(second_ms).model_copy(
                update={"synchronized": False, "max_error_ms": 100}
            ),
            "machine_id_sha256": "e" * 64,
            "configuration": changed_configuration,
            "packets": 1,
            "bytes": 1,
            "drops": 0,
            "overlimits": 1,
            "queued_packets": plan.queue_limit_packets,
            "flow_counters": flow_counters_at(plan, 0),
        }
    )

    summary = summarize_netem(
        profile,
        plan,
        (first, second),
        observations_sha256="f" * 64,
        coordinated_start_unix_ms=start_ms,
    )

    assert not summary.valid
    assert {
        "netem_observation_binding_invalid",
        "netem_clock_unsynchronized",
        "netem_runtime_identity_changed",
        "netem_observation_gap_invalid",
        "netem_counter_reset",
        "netem_queue_limit_reached",
        "netem_observation_started_after_load",
        "netem_observation_ended_before_drain",
        "netem_no_scoped_traffic_observed",
        "netem_queue_overlimit",
    }.issubset(summary.invalid_reasons)
    with pytest.raises(ValueError, match="netem_observations_empty"):
        summarize_netem(
            profile,
            plan,
            (),
            observations_sha256="f" * 64,
            coordinated_start_unix_ms=start_ms,
        )


def test_models_and_clean_install_guards_reject_ambiguous_ownership() -> None:
    plan = required_netem_site_plans(wan_profile())[0]
    with pytest.raises(ValueError, match="netem_site_plan_not_canonical"):
        NetemSitePlan.model_validate({**plan.model_dump(mode="json"), "flows": []})
    with pytest.raises(ValueError, match="netem_site_plan_not_canonical"):
        NetemSitePlan.model_validate({**plan.model_dump(mode="json"), "ifb_interface": "camera0"})
    valid_summary = NetemSummary(
        schema_version=1,
        valid=True,
        invalid_reasons=(),
        profile_sha256="a" * 64,
        plan_sha256="b" * 64,
        observations_sha256="c" * 64,
        site="sut",
        receiver_host="proxy.load.internal",
        machine_id_sha256="d" * 64,
        boot_id="11111111-1111-1111-1111-111111111111",
        first_observation_unix_ms=1,
        last_observation_unix_ms=2,
        sample_count=1,
        maximum_gap_seconds=0,
        packets_delta=1,
        bytes_delta=1,
        drops_delta=1,
        random_loss_drops_delta=1,
        queue_overflow_drops_delta=0,
        drop_envelope_minimum=1,
        drop_envelope_maximum=3,
        observed_drop_percent=50,
        overlimits_delta=0,
        random_loss_overlimits_delta=0,
        maximum_queued_packets=0,
        maximum_random_loss_queued_packets=0,
        scoped_input_packets_delta=2,
        scoped_input_bytes_delta=1,
        flow_deltas=(),
    )
    with pytest.raises(ValueError, match="netem_summary_validity_mismatch"):
        valid_summary.model_copy(update={"invalid_reasons": ("drift",)}).model_validate(
            {**valid_summary.model_dump(mode="json"), "invalid_reasons": ["drift"]}
        )
    dirty_filter = FakeNetemKernel()
    dirty_filter.filters.append({"kind": "foreign"})
    with pytest.raises(ValueError, match="netem_ingress_filter_not_clean"):
        install_netem(dirty_filter, plan)
    dirty_ingress = FakeNetemKernel()
    dirty_ingress.ingress_qdiscs.append({"kind": "clsact"})
    with pytest.raises(ValueError, match="netem_ingress_qdisc_not_clean"):
        install_netem(dirty_ingress, plan)
    dirty_ifb = FakeNetemKernel()
    dirty_ifb.ifb_qdiscs = [{"kind": "fq_codel"}]
    with pytest.raises(ValueError, match="netem_ifb_qdisc_not_clean"):
        install_netem(dirty_ifb, plan)

    foreign_empty_clsact = FakeNetemKernel()
    foreign_empty_clsact.ingress_qdiscs.append({"kind": "clsact", "handle": "ffff:"})
    with pytest.raises(ValueError, match="netem_cleanup_foreign_ingress_state"):
        remove_netem(foreign_empty_clsact, plan)

    duplicate_filter = FakeNetemKernel()
    install_netem(duplicate_filter, plan)
    duplicate_filter.filters.append(duplicate_filter.filters[0].copy())
    with pytest.raises(ValueError, match="netem_cleanup_foreign_ingress_state"):
        remove_netem(duplicate_filter, plan)
    assert len(duplicate_filter.filters) == len(plan.flows) + 1

    foreign_egress = FakeNetemKernel()
    install_netem(foreign_egress, plan)
    foreign_egress.egress.append({"kind": "foreign"})
    with pytest.raises(ValueError, match="netem_cleanup_foreign_egress_state"):
        remove_netem(foreign_egress, plan)
    assert foreign_egress.egress == [{"kind": "foreign"}]

    foreign_chain = FakeNetemKernel()
    install_netem(foreign_chain, plan)
    foreign_chain.filters.append(
        {
            **foreign_chain.filters[0],
            "chain": 1,
        }
    )
    with pytest.raises(ValueError, match="netem_cleanup_foreign_ingress_state"):
        remove_netem(foreign_chain, plan)
    assert any(item.get("chain") == 1 for item in foreign_chain.filters)


def test_comparison_allows_per_architecture_tool_digests_but_pins_versions(
    tmp_path: Path,
) -> None:
    profile = wan_profile()
    plan = required_netem_site_plans(profile)[0]
    kernel = FakeNetemKernel()
    install_netem(kernel, plan)
    write_host_identity(tmp_path)
    observed_ms = 4_102_444_800_000
    first = capture_netem_observation(
        kernel,
        plan,
        root=tmp_path,
        clock_proof=lambda _maximum: clock(observed_ms),
    )
    cross_architecture = first.model_copy(
        update={
            "tc": first.tc.model_copy(update={"path": "/usr/bin/tc", "sha256": "c" * 64}),
            "ip": first.ip.model_copy(update={"path": "/usr/bin/ip", "sha256": "d" * 64}),
        }
    )

    validate_netem_comparison_tool_versions(((first,), (cross_architecture,)))
    incompatible = cross_architecture.model_copy(
        update={"tc": cross_architecture.tc.model_copy(update={"version": "iproute2-6.2.0"})}
    )
    with pytest.raises(ValueError, match="netem_comparison_tool_version_mismatch"):
        validate_netem_comparison_tool_versions(((first,), (incompatible,)))


def test_subprocess_adapter_validates_tools_json_and_namespace(tmp_path: Path) -> None:
    tool_body = """#!/usr/bin/env python3
import json
import sys
args = sys.argv[1:]
if args == ['-Version']:
    print('tc utility, iproute2-6.11.0')
elif 'address' in args:
    print(json.dumps([{'ifindex': 2, 'ifname': args[-1], 'mtu': 1500, 'flags': ['UP']}]))
elif 'qdisc' in args:
    print(json.dumps([{'kind': 'noqueue', 'root': True}]))
elif 'filter' in args:
    print('[]')
"""
    tc_binary = tmp_path / "tc"
    ip_binary = tmp_path / "ip"
    for binary in (tc_binary, ip_binary):
        binary.write_text(tool_body, encoding="utf-8")
        binary.chmod(0o750)
    kernel = SubprocessNetemKernel(tc_binary=tc_binary, ip_binary=ip_binary)

    assert kernel.tc_identity.version.endswith("6.11.0")
    assert kernel.ip_identity.sha256 == hashlib.sha256(tool_body.encode()).hexdigest()
    assert kernel.link("camera0")["ifname"] == "camera0"
    assert kernel.qdiscs("camera0")[0]["kind"] == "noqueue"
    assert kernel.ingress_filters("camera0") == []
    kernel.mutate_tc(("qdisc", "show"))
    namespaced = SubprocessNetemKernel(
        tc_binary=tc_binary,
        ip_binary=ip_binary,
        network_namespace="lab-1",
    )
    assert namespaced.qdiscs("camera0")[0]["kind"] == "noqueue"
    with pytest.raises(ValueError, match="netem_network_namespace_invalid"):
        SubprocessNetemKernel(
            tc_binary=tc_binary,
            ip_binary=ip_binary,
            network_namespace="INVALID!",
        )

    bad_binary = tmp_path / "bad-tc"
    bad_binary.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "print('tc utility, iproute2-6.11.0' "
        "if sys.argv[1:] == ['-Version'] else 'bad')\n",
        encoding="utf-8",
    )
    bad_binary.chmod(0o750)
    bad_kernel = SubprocessNetemKernel(tc_binary=bad_binary, ip_binary=ip_binary)
    with pytest.raises(ValueError, match="netem_kernel_json_invalid"):
        bad_kernel.qdiscs("camera0")

    non_executable = tmp_path / "not-executable"
    non_executable.write_text("tool", encoding="utf-8")
    with pytest.raises(ValueError, match="netem_tool_must_be_absolute_regular_file"):
        SubprocessNetemKernel(tc_binary=non_executable, ip_binary=ip_binary)

    tc_symlink = tmp_path / "tc-symlink"
    tc_symlink.symlink_to(tc_binary)
    symlinked_kernel = SubprocessNetemKernel(tc_binary=tc_symlink, ip_binary=ip_binary)
    assert symlinked_kernel.tc_identity.path == str(tc_binary.resolve())
    assert symlinked_kernel.tc_identity.sha256 == hashlib.sha256(tool_body.encode()).hexdigest()

    broken_symlink = tmp_path / "broken-tc"
    broken_symlink.symlink_to(tmp_path / "missing-tc")
    with pytest.raises(ValueError, match="netem_tool_must_be_absolute_regular_file"):
        SubprocessNetemKernel(tc_binary=broken_symlink, ip_binary=ip_binary)


def test_lan_has_no_netem_sites() -> None:
    lan = LoadProfile.model_validate(valid_profile())
    assert required_netem_site_plans(lan) == ()
    wan = wan_profile()
    incomplete = wan.model_copy(
        update={"network": wan.network.model_copy(update={"ifb_interface": None})}
    )
    with pytest.raises(ValueError, match="network_impairment_profile_incomplete"):
        required_netem_site_plans(incomplete)


def test_public_cli_summarizes_typed_netem_evidence(tmp_path: Path) -> None:
    profile = wan_profile()
    plan = required_netem_site_plans(profile)[0]
    run_directory = tmp_path / "run"
    initialize_run_directory(profile, run_directory)
    raw_directory = run_directory / "raw"
    summary_directory = run_directory / "summary"
    raw_directory.mkdir()
    summary_directory.mkdir()
    start_ms = 4_102_444_800_000
    (run_directory / "launch-plan.json").write_text(
        json.dumps({"coordinated_start_unix_ms": start_ms}),
        encoding="utf-8",
    )
    kernel = FakeNetemKernel()
    install_netem(kernel, plan)
    identity_root = tmp_path / "identity"
    write_host_identity(identity_root)
    anchor_ms = warm_anchor_start_unix_ms(profile, start_ms)
    base = capture_netem_observation(
        kernel,
        plan,
        root=identity_root,
        clock_proof=lambda _maximum: clock(anchor_ms),
    )
    workload_end_ms = workload_end_unix_ms(profile, start_ms)
    end_ms = sut_sampling_end_unix_ms(profile, start_ms)
    observations: list[NetemObservation] = []
    current_ms = anchor_ms
    while current_ms <= end_ms:
        offset = min(current_ms, workload_end_ms) - anchor_ms
        observations.append(
            traffic_observation(
                base,
                plan,
                observed_at_ms=current_ms,
                attempted_packets=offset + 1,
            )
        )
        current_ms += 1000
    if round(observations[-1].timestamp.timestamp() * 1000) < end_ms:
        observations.append(
            traffic_observation(
                base,
                plan,
                observed_at_ms=end_ms,
                attempted_packets=workload_end_ms - anchor_ms + 1,
            )
        )
    observations_path = raw_directory / "netem-sut.jsonl"
    observations_path.write_text(
        "".join(item.model_dump_json() + "\n" for item in observations),
        encoding="utf-8",
    )
    output = summary_directory / "netem-sut.json"

    assert (
        load_cli_main(
            [
                "summarize-netem",
                str(run_directory),
                str(observations_path),
                str(output),
                "--site",
                "sut",
            ]
        )
        == 0
    )
    assert NetemSummary.model_validate_json(output.read_text(encoding="utf-8")).valid
    assert (
        load_cli_main(
            [
                "summarize-netem",
                str(run_directory),
                str(observations_path),
                str(summary_directory / "wrong.json"),
                "--site",
                "missing",
            ]
        )
        == 2
    )


def test_public_cli_installs_and_removes_through_external_iproute2_adapter(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile = wan_profile()
    run_directory = tmp_path / "run"
    initialize_run_directory(profile, run_directory)
    state_path = tmp_path / "tc-state.json"
    state_path.write_text(
        json.dumps({"ifb": False, "loss": False, "clsact": False, "filters": []}),
        encoding="utf-8",
    )
    monkeypatch.setenv("FAKE_TC_STATE", str(state_path))
    tool_body = """#!/usr/bin/env python3
import json
import os
import sys
from pathlib import Path
args = sys.argv[1:]
state_path = Path(os.environ['FAKE_TC_STATE'])
state = json.loads(state_path.read_text())
if args == ['-Version']:
    print('tc utility, iproute2-6.11.0')
elif 'address' in args:
    name = args[-1]
    link = {'ifindex': 3 if name == 'rtspifb0' else 2, 'ifname': name,
            'mtu': 1500, 'flags': ['UP'], 'addr_info': []}
    if name == 'rtspifb0':
        link['linkinfo'] = {'info_kind': 'ifb'}
    print(json.dumps([link]))
elif '-j' in args and 'qdisc' in args:
    name = args[-1]
    if name == 'rtspifb0':
        result = (([{'kind': 'netem', 'handle': '7a10:', 'root': True,
                        'options': {'limit': 1000,
                                    'delay': {'delay': 0.05, 'jitter': 0.01,
                                              'correlation': 0.0},
                                    'ecn': False, 'gap': 0}}] +
                       ([{'kind': 'netem', 'handle': '7a20:', 'parent': '7a10:1',
                        'options': {'limit': 4294967295,
                                    'loss-random': {'loss': 0.005, 'correlation': 0.0},
                                    'ecn': False, 'gap': 0}}] if state['loss'] else []))
                      if state['ifb'] else [{'kind': 'noqueue', 'handle': '0:', 'root': True}])
    else:
        result = [{'kind': 'fq_codel', 'root': True}]
        if state['clsact']:
            result.append({'kind': 'clsact', 'handle': 'ffff:'})
    print(json.dumps(result))
elif '-j' in args and 'filter' in args:
    print(json.dumps(state['filters'] if args[-1] == 'ingress' else []))
elif args[:5] == ['qdisc', 'add', 'dev', 'rtspifb0', 'root']:
    state['ifb'] = True
elif args[:6] == ['qdisc', 'add', 'dev', 'rtspifb0', 'parent', '7a10:1']:
    state['loss'] = True
elif args == ['qdisc', 'add', 'dev', 'camera0', 'clsact']:
    state['clsact'] = True
elif args[:4] == ['filter', 'add', 'dev', 'camera0']:
    pref = int(args[args.index('pref') + 1])
    chain = int(args[args.index('chain') + 1])
    source_ip = args[args.index('src_ip') + 1].removesuffix('/32')
    source_port = int(args[args.index('src_port') + 1])
    state['filters'].append({'protocol': 'ip', 'pref': pref, 'chain': chain,
      'kind': 'flower',
      'options': {'keys': {'eth_type': 'ipv4', 'ip_proto': 'tcp',
                           'src_ip': source_ip, 'src_port': source_port},
                  'skip_hw': True,
                  'actions': [{'kind': 'mirred', 'mirred_action': 'redirect',
                               'direction': 'egress', 'to_dev': 'rtspifb0',
                               'stats': {'packets': 0, 'bytes': 0,
                                         'drops': 0, 'overlimits': 0}}]}})
elif args == ['qdisc', 'del', 'dev', 'camera0', 'clsact']:
    state['clsact'] = False
    state['filters'] = []
elif args == ['qdisc', 'del', 'dev', 'rtspifb0', 'root']:
    state['ifb'] = False
    state['loss'] = False
else:
    print('unsupported', args, file=sys.stderr)
    raise SystemExit(2)
state_path.write_text(json.dumps(state))
"""
    tc_binary = tmp_path / "tc"
    ip_binary = tmp_path / "ip"
    for binary in (tc_binary, ip_binary):
        binary.write_text(tool_body, encoding="utf-8")
        binary.chmod(0o750)

    common = [
        str(run_directory),
        "--site",
        "sut",
        "--tc-binary",
        str(tc_binary),
        "--ip-binary",
        str(ip_binary),
    ]
    assert load_cli_main(["install-netem", *common]) == 0
    installed = json.loads(state_path.read_text(encoding="utf-8"))
    assert installed["ifb"] and installed["clsact"] and len(installed["filters"]) == 2
    assert load_cli_main(["remove-netem", *common]) == 0
    removed = json.loads(state_path.read_text(encoding="utf-8"))
    assert not removed["ifb"] and not removed["clsact"] and removed["filters"] == []


def test_install_rollback_and_cleanup_verification_fail_closed(tmp_path: Path) -> None:
    plan = required_netem_site_plans(wan_profile())[0]

    class FailingFilterKernel(FakeNetemKernel):
        def mutate_tc(self, arguments: tuple[str, ...]) -> None:
            if arguments[:2] == ("filter", "add"):
                raise ValueError("injected filter failure")
            super().mutate_tc(arguments)

    failed = FailingFilterKernel()
    with pytest.raises(ValueError, match="injected filter failure"):
        install_netem(failed, plan)
    assert failed.filters == []
    assert failed.ifb_qdiscs[0]["kind"] == "noqueue"
    assert all(item.get("kind") != "clsact" for item in failed.ingress_qdiscs)

    class TimeoutAfterApplyKernel(FakeNetemKernel):
        def __init__(self) -> None:
            super().__init__()
            self.inject_timeout = True

        def mutate_tc(self, arguments: tuple[str, ...]) -> None:
            super().mutate_tc(arguments)
            if self.inject_timeout and arguments[:5] == (
                "qdisc",
                "add",
                "dev",
                "rtspifb0",
                "root",
            ):
                self.inject_timeout = False
                raise TimeoutError("command applied before timeout")

    timed_out = TimeoutAfterApplyKernel()
    with pytest.raises(TimeoutError, match="applied before timeout"):
        install_netem(timed_out, plan)
    assert timed_out.filters == []
    assert str(timed_out.ifb_qdiscs[0]["kind"]) == "noqueue"
    assert all(item.get("kind") != "clsact" for item in timed_out.ingress_qdiscs)

    class ConcurrentWinnerKernel(FakeNetemKernel):
        def mutate_tc(self, arguments: tuple[str, ...]) -> None:
            if arguments[:5] == (
                "qdisc",
                "add",
                "dev",
                "rtspifb0",
                "root",
            ):
                winner = FakeNetemKernel()
                install_netem(winner, plan)
                self.ingress_qdiscs = winner.ingress_qdiscs
                self.ifb_qdiscs = winner.ifb_qdiscs
                self.filters = winner.filters
                raise ValueError("netem_command_failed:EEXIST")
            super().mutate_tc(arguments)

    lost_race = ConcurrentWinnerKernel()
    with pytest.raises(ValueError, match="EEXIST"):
        install_netem(lost_race, plan)
    assert len(lost_race.filters) == len(plan.flows)
    assert str(lost_race.ifb_qdiscs[0]["kind"]) == "netem"

    partially_removed = FakeNetemKernel()
    install_netem(partially_removed, plan)
    partially_removed.mutate_tc(("qdisc", "del", "dev", "camera0", "clsact"))
    remove_netem(partially_removed, plan)
    remove_netem(partially_removed, plan)
    assert str(partially_removed.ifb_qdiscs[0]["kind"]) == "noqueue"

    class LeavesFilterKernel(FakeNetemKernel):
        def mutate_tc(self, arguments: tuple[str, ...]) -> None:
            if arguments == ("qdisc", "del", "dev", "camera0", "clsact"):
                return
            super().mutate_tc(arguments)

    leaves_filter = LeavesFilterKernel()
    install_netem(leaves_filter, plan)
    with pytest.raises(ValueError, match="netem_cleanup_ingress_filter_remains"):
        remove_netem(leaves_filter, plan)

    class LeavesClsactKernel(FakeNetemKernel):
        def mutate_tc(self, arguments: tuple[str, ...]) -> None:
            if arguments == ("qdisc", "del", "dev", "camera0", "clsact"):
                self.filters = []
                return
            super().mutate_tc(arguments)

    leaves_clsact = LeavesClsactKernel()
    install_netem(leaves_clsact, plan)
    with pytest.raises(ValueError, match="netem_cleanup_ingress_qdisc_remains"):
        remove_netem(leaves_clsact, plan)

    class TimeoutWithoutCleanupKernel(FakeNetemKernel):
        def mutate_tc(self, arguments: tuple[str, ...]) -> None:
            if arguments == ("qdisc", "del", "dev", "rtspifb0", "root"):
                raise TimeoutError("cleanup timeout")
            super().mutate_tc(arguments)

    cleanup_timeout = TimeoutWithoutCleanupKernel()
    install_netem(cleanup_timeout, plan)
    with pytest.raises(ValueError, match="netem_cleanup_ifb_qdisc_remains"):
        remove_netem(cleanup_timeout, plan)

    drifted = FakeNetemKernel()
    install_netem(drifted, plan)
    drifted.ifb_qdiscs[0]["options"]["limit"] = 2000  # type: ignore[index]
    with pytest.raises(ValueError, match="netem_cleanup_foreign_ifb_state"):
        remove_netem(drifted, plan)

    write_host_identity(tmp_path)
    valid = FakeNetemKernel()
    install_netem(valid, plan)
    observed_ms = 4_102_444_800_000
    observation = capture_netem_observation(
        valid,
        plan,
        root=tmp_path,
        clock_proof=lambda _maximum: clock(observed_ms),
    )
    payload = observation.model_dump(mode="json")
    proof_payload = payload["clock_proof"]
    assert isinstance(proof_payload, dict)
    proof_payload["observed_at_unix_ms"] = observed_ms + 100
    with pytest.raises(ValueError, match="netem_observation_timestamp_clock_mismatch"):
        NetemObservation.model_validate(payload)


def test_subprocess_adapter_rejects_wrong_json_shapes(tmp_path: Path) -> None:
    script = tmp_path / "shape-tool"
    script.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "if sys.argv[1:] == ['-Version']:\n"
        "    print('tc utility, iproute2-6.11.0')\n"
        "elif 'address' in sys.argv:\n"
        "    print('[]')\n"
        "else:\n"
        "    print('{}')\n",
        encoding="utf-8",
    )
    script.chmod(0o750)
    kernel = SubprocessNetemKernel(tc_binary=script, ip_binary=script)
    with pytest.raises(ValueError, match="netem_link_inventory_invalid"):
        kernel.link("camera0")
    with pytest.raises(ValueError, match="netem_kernel_json_invalid"):
        kernel.qdiscs("camera0")
