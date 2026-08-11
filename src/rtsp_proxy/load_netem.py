from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import os
import stat
import subprocess
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Literal, Protocol, Self, cast

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

from rtsp_proxy.load_catalog import (
    build_direct_reader_plan,
    build_proxy_reader_plan,
    direct_source_host,
)
from rtsp_proxy.load_evidence import KernelClockProof, prove_linux_clock
from rtsp_proxy.load_profile import (
    LoadProfile,
    canonical_profile_bytes,
    generator_sampling_end_unix_ms,
    sut_sampling_end_unix_ms,
    warm_anchor_start_unix_ms,
)

Sha256 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
SafeName = Annotated[str, StringConstraints(pattern=r"^[a-zA-Z0-9._-]{1,128}$")]
SafeHost = Annotated[str, StringConstraints(pattern=r"^[a-zA-Z0-9._-]{1,253}$")]
InterfaceName = Annotated[str, StringConstraints(pattern=r"^[a-zA-Z0-9_.:-]{1,15}$")]
NETEM_QDISC_HANDLE = "7a10:"
NETEM_FILTER_PREF_START = 49000


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)


class NetemFlow(StrictModel):
    source_ipv4: Annotated[str, StringConstraints(pattern=r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")]
    source_port: Annotated[int, Field(ge=1, le=65535)]
    preference: Annotated[int, Field(ge=1, le=65535)]

    @model_validator(mode="after")
    def require_canonical_ipv4(self) -> Self:
        try:
            canonical = str(ipaddress.IPv4Address(self.source_ipv4))
        except ipaddress.AddressValueError as error:
            raise ValueError("netem_flow_source_ipv4_invalid") from error
        if canonical != self.source_ipv4:
            raise ValueError("netem_flow_source_ipv4_not_canonical")
        return self


class NetemSitePlan(StrictModel):
    schema_version: Literal[1]
    profile_sha256: Sha256
    site: SafeName
    role: Literal["sut", "generator"]
    receiver_host: SafeHost
    ingress_interface: InterfaceName
    ifb_interface: InterfaceName
    ingress_mtu_bytes: Annotated[int, Field(ge=576, le=9216)]
    delay_ms: Annotated[float, Field(gt=0)]
    jitter_ms: Annotated[float, Field(ge=0)]
    loss_percent: Annotated[float, Field(gt=0, lt=100)]
    queue_limit_packets: Annotated[int, Field(ge=1000, le=4294967295)]
    flows: tuple[NetemFlow, ...]

    @model_validator(mode="after")
    def require_canonical_scoped_plan(self) -> Self:
        flow_keys = tuple(
            (item.preference, item.source_ipv4, item.source_port) for item in self.flows
        )
        if (
            not self.flows
            or flow_keys != tuple(sorted(set(flow_keys)))
            or len({item.preference for item in self.flows}) != len(self.flows)
            or self.ingress_interface == self.ifb_interface
        ):
            raise ValueError("netem_site_plan_not_canonical")
        return self

    @property
    def sha256(self) -> str:
        return _canonical_sha256(self.model_dump(mode="json"))


class NetemToolIdentity(StrictModel):
    path: Annotated[str, StringConstraints(pattern=r"^/[^\x00\r\n]{1,1023}$")]
    sha256: Sha256
    version: Annotated[str, StringConstraints(min_length=1, max_length=512)]


class NetemKernelConfiguration(StrictModel):
    ingress_interface: InterfaceName
    ifb_interface: InterfaceName
    ingress_ifindex: Annotated[int, Field(gt=0)]
    ifb_ifindex: Annotated[int, Field(gt=0)]
    ingress_mtu_bytes: Annotated[int, Field(ge=576, le=9216)]
    ifb_mtu_bytes: Annotated[int, Field(ge=576, le=9216)]
    qdisc_handle: Literal["7a10:"]
    delay_ms: Annotated[float, Field(gt=0)]
    jitter_ms: Annotated[float, Field(ge=0)]
    loss_percent: Annotated[float, Field(gt=0, lt=100)]
    queue_limit_packets: Annotated[int, Field(ge=1000, le=4294967295)]
    flows: tuple[NetemFlow, ...]


class NetemFlowCounters(StrictModel):
    preference: Annotated[int, Field(ge=1, le=65535)]
    source_ipv4: Annotated[str, StringConstraints(pattern=r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")]
    source_port: Annotated[int, Field(ge=1, le=65535)]
    packets: Annotated[int, Field(ge=0)]
    bytes: Annotated[int, Field(ge=0)]
    drops: Annotated[int, Field(ge=0)]
    overlimits: Annotated[int, Field(ge=0)]

    @property
    def key(self) -> tuple[int, str, int]:
        return self.preference, self.source_ipv4, self.source_port


class NetemFlowDelta(StrictModel):
    preference: Annotated[int, Field(ge=1, le=65535)]
    source_ipv4: Annotated[str, StringConstraints(pattern=r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")]
    source_port: Annotated[int, Field(ge=1, le=65535)]
    packets_delta: Annotated[int, Field(ge=0)]
    bytes_delta: Annotated[int, Field(ge=0)]
    drops_delta: Annotated[int, Field(ge=0)]
    overlimits_delta: Annotated[int, Field(ge=0)]


class NetemObservation(StrictModel):
    schema_version: Literal[1]
    profile_sha256: Sha256
    plan_sha256: Sha256
    site: SafeName
    receiver_host: SafeHost
    timestamp: datetime
    clock_proof: KernelClockProof
    machine_id_sha256: Sha256
    boot_id: Annotated[
        str,
        StringConstraints(
            pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
        ),
    ]
    tc: NetemToolIdentity
    ip: NetemToolIdentity
    configuration: NetemKernelConfiguration
    packets: Annotated[int, Field(ge=0)]
    bytes: Annotated[int, Field(ge=0)]
    drops: Annotated[int, Field(ge=0)]
    overlimits: Annotated[int, Field(ge=0)]
    backlog_bytes: Annotated[int, Field(ge=0)]
    queued_packets: Annotated[int, Field(ge=0)]
    flow_counters: tuple[NetemFlowCounters, ...]

    @model_validator(mode="after")
    def bind_timestamp_to_clock(self) -> Self:
        observed_ms = round(self.timestamp.timestamp() * 1000)
        if abs(observed_ms - self.clock_proof.observed_at_unix_ms) > 1:
            raise ValueError("netem_observation_timestamp_clock_mismatch")
        return self


class NetemSummary(StrictModel):
    schema_version: Literal[1]
    valid: bool
    invalid_reasons: tuple[str, ...]
    profile_sha256: Sha256
    plan_sha256: Sha256
    observations_sha256: Sha256
    site: SafeName
    receiver_host: SafeHost
    machine_id_sha256: Sha256
    boot_id: str
    first_observation_unix_ms: Annotated[int, Field(gt=0)]
    last_observation_unix_ms: Annotated[int, Field(gt=0)]
    sample_count: Annotated[int, Field(gt=0)]
    maximum_gap_seconds: Annotated[float, Field(ge=0)]
    packets_delta: Annotated[int, Field(ge=0)]
    bytes_delta: Annotated[int, Field(ge=0)]
    drops_delta: Annotated[int, Field(ge=0)]
    drop_envelope_maximum: Annotated[int, Field(ge=0)]
    observed_drop_percent: Annotated[float, Field(ge=0, le=100)]
    overlimits_delta: Annotated[int, Field(ge=0)]
    maximum_queued_packets: Annotated[int, Field(ge=0)]
    scoped_input_packets_delta: Annotated[int, Field(ge=0)]
    scoped_input_bytes_delta: Annotated[int, Field(ge=0)]
    flow_deltas: tuple[NetemFlowDelta, ...]

    @model_validator(mode="after")
    def bind_validity_to_reasons(self) -> Self:
        if self.valid != (not self.invalid_reasons):
            raise ValueError("netem_summary_validity_mismatch")
        return self


class NetemKernel(Protocol):
    @property
    def tc_identity(self) -> NetemToolIdentity: ...

    @property
    def ip_identity(self) -> NetemToolIdentity: ...

    def link(self, interface: str) -> dict[str, object]: ...

    def qdiscs(self, interface: str) -> list[dict[str, object]]: ...

    def ingress_filters(self, interface: str) -> list[dict[str, object]]: ...

    def egress_filters(self, interface: str) -> list[dict[str, object]]: ...

    def mutate_tc(self, arguments: tuple[str, ...]) -> None: ...


class SubprocessNetemKernel:
    def __init__(
        self,
        *,
        tc_binary: Path,
        ip_binary: Path,
        network_namespace: str | None = None,
    ) -> None:
        self._tc_binary = _require_executable(tc_binary)
        self._ip_binary = _require_executable(ip_binary)
        if network_namespace is not None and (
            not network_namespace
            or len(network_namespace) > 63
            or any(
                character not in "abcdefghijklmnopqrstuvwxyz0123456789-_"
                for character in network_namespace
            )
        ):
            raise ValueError("netem_network_namespace_invalid")
        self._network_namespace = network_namespace
        _tool_identity(self._tc_binary, ("-Version",))
        _tool_identity(self._ip_binary, ("-Version",))

    @property
    def tc_identity(self) -> NetemToolIdentity:
        return _tool_identity(self._tc_binary, ("-Version",))

    @property
    def ip_identity(self) -> NetemToolIdentity:
        return _tool_identity(self._ip_binary, ("-Version",))

    def link(self, interface: str) -> dict[str, object]:
        payload = self._run_json(
            self._ip_binary,
            ("-j", "-d", "address", "show", "dev", interface),
        )
        if not isinstance(payload, list) or len(payload) != 1 or not isinstance(payload[0], dict):
            raise ValueError("netem_link_inventory_invalid")
        return cast(dict[str, object], payload[0])

    def qdiscs(self, interface: str) -> list[dict[str, object]]:
        return self._run_object_list(
            self._tc_binary,
            ("-s", "-j", "qdisc", "show", "dev", interface),
        )

    def ingress_filters(self, interface: str) -> list[dict[str, object]]:
        return self._run_object_list(
            self._tc_binary,
            ("-s", "-j", "filter", "show", "dev", interface, "ingress"),
        )

    def egress_filters(self, interface: str) -> list[dict[str, object]]:
        return self._run_object_list(
            self._tc_binary,
            ("-s", "-j", "filter", "show", "dev", interface, "egress"),
        )

    def mutate_tc(self, arguments: tuple[str, ...]) -> None:
        self._run_tool(self._tc_binary, arguments)

    def _run_object_list(self, binary: Path, arguments: tuple[str, ...]) -> list[dict[str, object]]:
        payload = self._run_json(binary, arguments)
        if not isinstance(payload, list) or any(not isinstance(item, dict) for item in payload):
            raise ValueError("netem_kernel_json_invalid")
        return cast(list[dict[str, object]], payload)

    def _run_json(self, binary: Path, arguments: tuple[str, ...]) -> object:
        output = self._run_tool(binary, arguments)
        try:
            return json.loads(output)
        except json.JSONDecodeError as error:
            raise ValueError("netem_kernel_json_invalid") from error

    def _run_tool(self, binary: Path, arguments: tuple[str, ...]) -> str:
        if self._network_namespace is None:
            return _run(binary, arguments)
        return _run(
            self._ip_binary,
            (
                "netns",
                "exec",
                self._network_namespace,
                str(binary),
                *arguments,
            ),
        )


def required_netem_site_plans(profile: LoadProfile) -> tuple[NetemSitePlan, ...]:
    if profile.network.profile == "lan":
        return ()
    if profile.network.ifb_interface is None or profile.network.netem_queue_limit_packets is None:
        raise ValueError("network_impairment_profile_incomplete")
    _, profile_sha256 = canonical_profile_bytes(profile)
    if profile.workload.endpoint_mode == "proxy":
        endpoints = tuple(
            (host.rtsp_host, host.rtsp_port)
            for host in profile.generator_hosts
            if build_proxy_reader_plan(profile, host.name).targets
        )
        return (
            _site_plan(
                profile,
                profile_sha256=profile_sha256,
                site="sut",
                role="sut",
                receiver_host=profile.sut_rtsp_host,
                endpoints=endpoints,
            ),
        )
    plans: list[NetemSitePlan] = []
    for reader_host in profile.generator_hosts:
        if not build_direct_reader_plan(profile, reader_host.name).targets:
            continue
        source_host = direct_source_host(profile, reader_host.name)
        plans.append(
            _site_plan(
                profile,
                profile_sha256=profile_sha256,
                site=reader_host.name,
                role="generator",
                receiver_host=reader_host.name,
                endpoints=((source_host.rtsp_host, source_host.rtsp_port),),
            )
        )
    return tuple(plans)


def install_netem(kernel: NetemKernel, plan: NetemSitePlan) -> None:
    _validate_links(kernel, plan)
    if kernel.ingress_filters(plan.ingress_interface):
        raise ValueError("netem_ingress_filter_not_clean")
    ingress_special = [
        item
        for item in kernel.qdiscs(plan.ingress_interface)
        if item.get("kind") in {"clsact", "ingress"}
    ]
    if ingress_special:
        raise ValueError("netem_ingress_qdisc_not_clean")
    if not _is_kernel_default_qdisc_inventory(kernel.qdiscs(plan.ifb_interface)):
        raise ValueError("netem_ifb_qdisc_not_clean")

    ifb_add_arguments = (
        "qdisc",
        "add",
        "dev",
        plan.ifb_interface,
        "root",
        "handle",
        NETEM_QDISC_HANDLE,
        "netem",
        "limit",
        str(plan.queue_limit_packets),
        "delay",
        f"{_decimal(plan.delay_ms)}ms",
        f"{_decimal(plan.jitter_ms)}ms",
        "loss",
        "random",
        f"{_decimal(plan.loss_percent)}%",
    )
    mutation_may_have_applied = False
    try:
        try:
            kernel.mutate_tc(ifb_add_arguments)
        except ValueError:
            # A completed tc/netlink rejection is atomic and proves that this
            # invocation did not create the first owned object. In particular,
            # do not tear down an exact state won by a concurrent installer.
            raise
        except BaseException:
            # Timeout/interruption can happen after the kernel committed the
            # request, so read-back cleanup is mandatory.
            mutation_may_have_applied = True
            raise
        mutation_may_have_applied = True
        kernel.mutate_tc(("qdisc", "add", "dev", plan.ingress_interface, "clsact"))
        for flow in plan.flows:
            kernel.mutate_tc(_filter_add_arguments(plan, flow))
        _validate_links(kernel, plan)
        _validate_kernel_state(kernel, plan)
    except BaseException:
        if mutation_may_have_applied:
            try:
                _cleanup_owned_netem(kernel, plan)
            except BaseException as cleanup_error:
                raise ValueError("netem_install_failed_cleanup_incomplete") from cleanup_error
        raise


def remove_netem(kernel: NetemKernel, plan: NetemSitePlan) -> None:
    _validate_links(kernel, plan)
    _cleanup_owned_netem(kernel, plan)


def capture_netem_observation(
    kernel: NetemKernel,
    plan: NetemSitePlan,
    *,
    root: Path = Path("/"),
    clock_proof: Callable[[float], KernelClockProof] = prove_linux_clock,
) -> NetemObservation:
    ingress, ifb = _validate_links(kernel, plan)
    qdisc, flow_counters = _validate_kernel_state(kernel, plan)
    proof = clock_proof(1000)
    timestamp = datetime.fromtimestamp(proof.observed_at_unix_ms / 1000, tz=UTC)
    machine_id = _bounded_text(root / "etc/machine-id", 128)
    boot_id = _bounded_text(root / "proc/sys/kernel/random/boot_id", 128)
    return NetemObservation(
        schema_version=1,
        profile_sha256=plan.profile_sha256,
        plan_sha256=plan.sha256,
        site=plan.site,
        receiver_host=plan.receiver_host,
        timestamp=timestamp,
        clock_proof=proof,
        machine_id_sha256=hashlib.sha256(machine_id.encode()).hexdigest(),
        boot_id=boot_id,
        tc=kernel.tc_identity,
        ip=kernel.ip_identity,
        configuration=NetemKernelConfiguration(
            ingress_interface=plan.ingress_interface,
            ifb_interface=plan.ifb_interface,
            ingress_ifindex=_positive_int(ingress.get("ifindex"), "netem_ingress_ifindex_invalid"),
            ifb_ifindex=_positive_int(ifb.get("ifindex"), "netem_ifb_ifindex_invalid"),
            ingress_mtu_bytes=_positive_int(ingress.get("mtu"), "netem_ingress_mtu_invalid"),
            ifb_mtu_bytes=_positive_int(ifb.get("mtu"), "netem_ifb_mtu_invalid"),
            qdisc_handle="7a10:",
            delay_ms=plan.delay_ms,
            jitter_ms=plan.jitter_ms,
            loss_percent=plan.loss_percent,
            queue_limit_packets=plan.queue_limit_packets,
            flows=plan.flows,
        ),
        packets=_nonnegative_int(qdisc.get("packets"), "netem_qdisc_stats_invalid"),
        bytes=_nonnegative_int(qdisc.get("bytes"), "netem_qdisc_stats_invalid"),
        drops=_nonnegative_int(qdisc.get("drops"), "netem_qdisc_stats_invalid"),
        overlimits=_nonnegative_int(qdisc.get("overlimits"), "netem_qdisc_stats_invalid"),
        backlog_bytes=_nonnegative_int(qdisc.get("backlog"), "netem_qdisc_stats_invalid"),
        queued_packets=_nonnegative_int(qdisc.get("qlen"), "netem_qdisc_stats_invalid"),
        flow_counters=flow_counters,
    )


def sample_linux_netem(
    profile: LoadProfile,
    plan: NetemSitePlan,
    output: Path,
    *,
    kernel: NetemKernel,
    coordinated_start_unix_ms: int,
    root: Path = Path("/"),
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
    unix_time: Callable[[], float] = time.time,
    clock_proof: Callable[[float], KernelClockProof] = prove_linux_clock,
) -> tuple[NetemObservation, ...]:
    if output.exists():
        raise FileExistsError(output)
    interval = profile.evidence_sampling.interval_seconds
    sampling_end = (
        sut_sampling_end_unix_ms if plan.role == "sut" else generator_sampling_end_unix_ms
    )
    end_unix_ms = sampling_end(profile, coordinated_start_unix_ms)
    observations: list[NetemObservation] = []
    next_sample = monotonic()
    with output.open("x", encoding="utf-8") as destination:
        os.fchmod(destination.fileno(), 0o640)
        while True:
            observation = capture_netem_observation(
                kernel,
                plan,
                root=root,
                clock_proof=clock_proof,
            )
            destination.write(observation.model_dump_json() + "\n")
            destination.flush()
            os.fsync(destination.fileno())
            observations.append(observation)
            if observation.clock_proof.observed_at_unix_ms >= end_unix_ms:
                break
            next_sample += interval
            sleep(max(0, next_sample - monotonic()))
    return tuple(observations)


def load_netem_observations(path: Path) -> tuple[NetemObservation, ...]:
    if path.is_symlink() or not path.is_file() or not stat.S_ISREG(path.stat().st_mode):
        raise ValueError("netem_observations_must_be_regular_file")
    observations: list[NetemObservation] = []
    with path.open(encoding="utf-8") as source:
        for line in source:
            if not line.strip():
                raise ValueError("netem_observation_blank_line")
            observations.append(NetemObservation.model_validate_json(line))
    if not observations:
        raise ValueError("netem_observations_empty")
    return tuple(observations)


def summarize_netem(
    profile: LoadProfile,
    plan: NetemSitePlan,
    observations: tuple[NetemObservation, ...],
    *,
    observations_sha256: str,
    coordinated_start_unix_ms: int,
) -> NetemSummary:
    if not observations:
        raise ValueError("netem_observations_empty")
    reasons: set[str] = set()
    expected_configuration = _configuration_without_ifindices(plan)
    first = observations[0]
    previous = first
    maximum_gap = 0.0
    expected_flow_keys = tuple(
        (flow.preference, flow.source_ipv4, flow.source_port) for flow in plan.flows
    )
    for observation in observations:
        if (
            observation.profile_sha256 != plan.profile_sha256
            or observation.plan_sha256 != plan.sha256
            or observation.site != plan.site
            or observation.receiver_host != plan.receiver_host
            or _configuration_without_ifindices_from_observation(observation)
            != expected_configuration
        ):
            reasons.add("netem_observation_binding_invalid")
        if (
            not observation.clock_proof.synchronized
            or observation.clock_proof.max_error_ms
            > profile.evidence_sampling.maximum_clock_error_ms
        ):
            reasons.add("netem_clock_unsynchronized")
        if (
            observation.machine_id_sha256 != first.machine_id_sha256
            or observation.boot_id != first.boot_id
            or observation.tc != first.tc
            or observation.ip != first.ip
            or observation.configuration.ingress_ifindex != first.configuration.ingress_ifindex
            or observation.configuration.ifb_ifindex != first.configuration.ifb_ifindex
        ):
            reasons.add("netem_runtime_identity_changed")
        observed_flow_keys = tuple(item.key for item in observation.flow_counters)
        if observed_flow_keys != expected_flow_keys:
            reasons.add("netem_flow_counter_set_invalid")
        if observation is not first:
            gap = (observation.timestamp - previous.timestamp).total_seconds()
            maximum_gap = max(maximum_gap, gap)
            if gap <= 0 or gap > (
                profile.evidence_sampling.interval_seconds
                * profile.evidence_sampling.maximum_gap_factor
            ):
                reasons.add("netem_observation_gap_invalid")
            if any(
                current < prior
                for current, prior in (
                    (observation.packets, previous.packets),
                    (observation.bytes, previous.bytes),
                    (observation.drops, previous.drops),
                    (observation.overlimits, previous.overlimits),
                )
            ):
                reasons.add("netem_counter_reset")
            previous_flows = {item.key: item for item in previous.flow_counters}
            for current in observation.flow_counters:
                prior = previous_flows.get(current.key)
                if prior is None or any(
                    current_value < prior_value
                    for current_value, prior_value in (
                        (current.packets, prior.packets),
                        (current.bytes, prior.bytes),
                        (current.drops, prior.drops),
                        (current.overlimits, prior.overlimits),
                    )
                ):
                    reasons.add("netem_flow_counter_reset")
        if observation.queued_packets >= plan.queue_limit_packets:
            reasons.add("netem_queue_limit_reached")
        previous = observation
    first_ms = round(first.timestamp.timestamp() * 1000)
    last_ms = round(observations[-1].timestamp.timestamp() * 1000)
    if first_ms > warm_anchor_start_unix_ms(profile, coordinated_start_unix_ms):
        reasons.add("netem_observation_started_after_load")
    required_sampling_end = (
        sut_sampling_end_unix_ms if plan.role == "sut" else generator_sampling_end_unix_ms
    )(profile, coordinated_start_unix_ms)
    if last_ms < required_sampling_end:
        reasons.add("netem_observation_ended_before_drain")
    packets_delta = observations[-1].packets - first.packets
    bytes_delta = observations[-1].bytes - first.bytes
    drops_delta = observations[-1].drops - first.drops
    overlimits_delta = observations[-1].overlimits - first.overlimits
    if packets_delta <= 0 or bytes_delta <= 0:
        reasons.add("netem_no_scoped_traffic_observed")
    attempted_packets = max(0, packets_delta) + max(0, drops_delta)
    drop_envelope_maximum = _random_loss_drop_upper_bound(attempted_packets, plan.loss_percent)
    if drops_delta > drop_envelope_maximum:
        reasons.add("netem_drop_rate_above_random_loss_envelope")
    first_flows = {item.key: item for item in first.flow_counters}
    last_flows = {item.key: item for item in observations[-1].flow_counters}
    flow_deltas: list[NetemFlowDelta] = []
    for flow_key in expected_flow_keys:
        initial = first_flows.get(flow_key)
        final = last_flows.get(flow_key)
        if initial is None or final is None:
            reasons.add("netem_flow_counter_set_invalid")
            continue
        packet_delta = final.packets - initial.packets
        byte_delta = final.bytes - initial.bytes
        drop_delta = final.drops - initial.drops
        overlimit_delta = final.overlimits - initial.overlimits
        if packet_delta <= 0 or byte_delta <= 0:
            reasons.add("netem_flow_traffic_missing")
        if drop_delta < 0 or overlimit_delta < 0:
            reasons.add("netem_flow_counter_reset")
        if drop_delta != 0:
            reasons.add("netem_flow_action_drop")
        if overlimit_delta != 0:
            reasons.add("netem_flow_action_overlimit")
        flow_deltas.append(
            NetemFlowDelta(
                preference=flow_key[0],
                source_ipv4=flow_key[1],
                source_port=flow_key[2],
                packets_delta=max(0, packet_delta),
                bytes_delta=max(0, byte_delta),
                drops_delta=max(0, drop_delta),
                overlimits_delta=max(0, overlimit_delta),
            )
        )
    scoped_input_packets_delta = sum(item.packets_delta for item in flow_deltas)
    scoped_input_bytes_delta = sum(item.bytes_delta for item in flow_deltas)
    if any(
        (
            first.queued_packets,
            observations[-1].queued_packets,
            first.backlog_bytes,
            observations[-1].backlog_bytes,
        )
    ):
        reasons.add("netem_queue_not_drained_at_boundary")
    if scoped_input_packets_delta != max(0, packets_delta) + max(0, drops_delta):
        reasons.add("netem_scoped_packet_accounting_mismatch")
    if (
        len(observations) < 2
        or any(
            getattr(observations[-1], field) != getattr(observations[-2], field)
            for field in ("packets", "bytes", "drops", "overlimits")
        )
        or observations[-1].flow_counters != observations[-2].flow_counters
    ):
        reasons.add("netem_traffic_not_quiescent_at_end")
    if overlimits_delta != 0:
        reasons.add("netem_queue_overlimit")
    ordered_reasons = tuple(sorted(reasons))
    return NetemSummary(
        schema_version=1,
        valid=not ordered_reasons,
        invalid_reasons=ordered_reasons,
        profile_sha256=plan.profile_sha256,
        plan_sha256=plan.sha256,
        observations_sha256=observations_sha256,
        site=plan.site,
        receiver_host=plan.receiver_host,
        machine_id_sha256=first.machine_id_sha256,
        boot_id=first.boot_id,
        first_observation_unix_ms=first_ms,
        last_observation_unix_ms=last_ms,
        sample_count=len(observations),
        maximum_gap_seconds=maximum_gap,
        packets_delta=max(0, packets_delta),
        bytes_delta=max(0, bytes_delta),
        drops_delta=max(0, drops_delta),
        drop_envelope_maximum=drop_envelope_maximum,
        observed_drop_percent=(
            max(0, drops_delta) / attempted_packets * 100 if attempted_packets else 0
        ),
        overlimits_delta=max(0, overlimits_delta),
        maximum_queued_packets=max(item.queued_packets for item in observations),
        scoped_input_packets_delta=scoped_input_packets_delta,
        scoped_input_bytes_delta=scoped_input_bytes_delta,
        flow_deltas=tuple(flow_deltas),
    )


def validate_netem_comparison_tool_versions(
    observation_sets: tuple[tuple[NetemObservation, ...], ...],
) -> None:
    if any(not observations for observations in observation_sets):
        raise ValueError("netem_comparison_observations_empty")
    versions = {
        (observations[0].tc.version, observations[0].ip.version)
        for observations in observation_sets
    }
    if len(versions) > 1:
        raise ValueError("netem_comparison_tool_version_mismatch")


def _site_plan(
    profile: LoadProfile,
    *,
    profile_sha256: str,
    site: str,
    role: Literal["sut", "generator"],
    receiver_host: str,
    endpoints: tuple[tuple[str, int], ...],
) -> NetemSitePlan:
    if profile.network.ifb_interface is None or profile.network.netem_queue_limit_packets is None:
        raise ValueError("network_impairment_profile_incomplete")
    unique_endpoints = tuple(sorted(set(endpoints)))
    flows = tuple(
        NetemFlow(
            source_ipv4=address,
            source_port=port,
            preference=NETEM_FILTER_PREF_START + index,
        )
        for index, (address, port) in enumerate(unique_endpoints)
    )
    return NetemSitePlan(
        schema_version=1,
        profile_sha256=profile_sha256,
        site=site,
        role=role,
        receiver_host=receiver_host,
        ingress_interface=profile.network.interface,
        ifb_interface=profile.network.ifb_interface,
        ingress_mtu_bytes=profile.network.mtu_bytes,
        delay_ms=profile.network.rtt_ms,
        jitter_ms=profile.network.jitter_ms,
        loss_percent=profile.network.loss_percent,
        queue_limit_packets=profile.network.netem_queue_limit_packets,
        flows=flows,
    )


def _validate_links(
    kernel: NetemKernel, plan: NetemSitePlan
) -> tuple[dict[str, object], dict[str, object]]:
    ingress = kernel.link(plan.ingress_interface)
    ifb = kernel.link(plan.ifb_interface)
    if (
        ingress.get("ifname") != plan.ingress_interface
        or ingress.get("mtu") != plan.ingress_mtu_bytes
        or not isinstance(ingress.get("flags"), list)
        or "UP" not in cast(list[object], ingress["flags"])
        or ifb.get("ifname") != plan.ifb_interface
        or ifb.get("mtu") != plan.ingress_mtu_bytes
        or not isinstance(ifb.get("flags"), list)
        or "UP" not in cast(list[object], ifb["flags"])
    ):
        raise ValueError("netem_link_contract_invalid")
    linkinfo = ifb.get("linkinfo")
    if (
        not isinstance(linkinfo, dict)
        or linkinfo.get("info_kind") != "ifb"
        or not _ifb_address_inventory_is_dedicated(ifb.get("addr_info"))
    ):
        raise ValueError("netem_ifb_not_dedicated")
    _positive_int(ingress.get("ifindex"), "netem_ingress_ifindex_invalid")
    _positive_int(ifb.get("ifindex"), "netem_ifb_ifindex_invalid")
    return ingress, ifb


def _ifb_address_inventory_is_dedicated(value: object) -> bool:
    if value is None:
        return True
    if not isinstance(value, list):
        return False
    for entry in value:
        if not isinstance(entry, dict):
            return False
        local = entry.get("local")
        if entry.get("family") != "inet6" or entry.get("scope") != "link":
            return False
        if not isinstance(local, str):
            return False
        try:
            address = ipaddress.IPv6Address(local)
        except ipaddress.AddressValueError:
            return False
        if not address.is_link_local:
            return False
    return True


def _validate_kernel_state(
    kernel: NetemKernel, plan: NetemSitePlan
) -> tuple[dict[str, object], tuple[NetemFlowCounters, ...]]:
    ifb_qdiscs = kernel.qdiscs(plan.ifb_interface)
    netem = [
        item
        for item in ifb_qdiscs
        if item.get("kind") == "netem"
        and item.get("handle") == NETEM_QDISC_HANDLE
        and item.get("root") is True
    ]
    if len(netem) != 1 or len(ifb_qdiscs) != 1:
        raise ValueError("netem_qdisc_set_invalid")
    _validate_netem_options(netem[0].get("options"), plan)
    ingress_special = [
        item
        for item in kernel.qdiscs(plan.ingress_interface)
        if item.get("kind") in {"clsact", "ingress"}
    ]
    if len(ingress_special) != 1 or ingress_special[0].get("kind") != "clsact":
        raise ValueError("netem_clsact_invalid")
    filters = kernel.ingress_filters(plan.ingress_interface)
    if kernel.egress_filters(plan.ingress_interface):
        raise ValueError("netem_egress_filter_set_invalid")
    if len(filters) != len(plan.flows):
        inventory = json.dumps(filters, sort_keys=True, separators=(",", ":"))[:4096]
        raise ValueError(f"netem_filter_set_invalid:{inventory}")
    observed_counters = tuple(
        sorted(
            (_parse_filter(item, plan.ifb_interface) for item in filters),
            key=lambda item: item.key,
        )
    )
    observed = tuple(item.key for item in observed_counters)
    expected = tuple(
        sorted((item.preference, item.source_ipv4, item.source_port) for item in plan.flows)
    )
    if observed != expected:
        raise ValueError("netem_filter_set_invalid")
    return netem[0], observed_counters


def _validate_netem_options(options: object, plan: NetemSitePlan) -> None:
    if not isinstance(options, dict):
        raise ValueError("netem_qdisc_options_invalid")
    allowed = {"limit", "delay", "loss-random", "ecn", "gap"}
    if set(options) - allowed:
        raise ValueError("netem_qdisc_options_invalid")
    delay = options.get("delay")
    loss = options.get("loss-random")
    if not isinstance(delay, dict) or not isinstance(loss, dict):
        raise ValueError("netem_qdisc_options_invalid")
    if (
        options.get("limit") != plan.queue_limit_packets
        or not _near(delay.get("delay"), plan.delay_ms / 1000)
        or not _near(delay.get("jitter"), plan.jitter_ms / 1000)
        or not _near(delay.get("correlation", 0), 0)
        or not _near(loss.get("loss"), plan.loss_percent / 100)
        or not _near(loss.get("correlation", 0), 0)
        or options.get("ecn") not in (None, False)
        or options.get("gap") not in (None, 0)
    ):
        raise ValueError("netem_qdisc_options_invalid")


def _parse_filter(item: dict[str, object], ifb_interface: str) -> NetemFlowCounters:
    options = item.get("options")
    if (
        item.get("protocol") != "ip"
        or item.get("kind") != "flower"
        or item.get("chain") != 0
        or not isinstance(item.get("pref"), int)
        or not isinstance(options, dict)
        or options.get("skip_hw") is not True
    ):
        raise ValueError("netem_filter_set_invalid")
    keys = options.get("keys")
    actions = options.get("actions")
    if not isinstance(keys, dict) or not isinstance(actions, list) or len(actions) != 1:
        raise ValueError("netem_filter_set_invalid")
    allowed_keys = {"eth_type", "ip_proto", "src_ip", "src_port"}
    source_ip = keys.get("src_ip")
    source_port = keys.get("src_port")
    if (
        set(keys) != allowed_keys
        or keys.get("eth_type") != "ipv4"
        or keys.get("ip_proto") != "tcp"
        or not isinstance(source_ip, str)
        or not isinstance(source_port, int)
    ):
        raise ValueError("netem_filter_set_invalid")
    try:
        source_network = ipaddress.IPv4Network(source_ip, strict=True)
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError) as error:
        raise ValueError("netem_filter_set_invalid") from error
    if source_network.prefixlen != 32:
        raise ValueError("netem_filter_set_invalid")
    action = actions[0]
    if (
        not isinstance(action, dict)
        or action.get("kind") != "mirred"
        or action.get("mirred_action") != "redirect"
        or action.get("direction") != "egress"
        or action.get("to_dev") != ifb_interface
    ):
        raise ValueError("netem_filter_set_invalid")
    stats = action.get("stats")
    if not isinstance(stats, dict):
        raise ValueError("netem_filter_action_stats_invalid")
    return NetemFlowCounters(
        preference=cast(int, item["pref"]),
        source_ipv4=str(source_network.network_address),
        source_port=source_port,
        packets=_nonnegative_int(stats.get("packets"), "netem_filter_action_stats_invalid"),
        bytes=_nonnegative_int(stats.get("bytes"), "netem_filter_action_stats_invalid"),
        drops=_nonnegative_int(stats.get("drops"), "netem_filter_action_stats_invalid"),
        overlimits=_nonnegative_int(stats.get("overlimits"), "netem_filter_action_stats_invalid"),
    )


def _filter_add_arguments(plan: NetemSitePlan, flow: NetemFlow) -> tuple[str, ...]:
    return (
        "filter",
        "add",
        "dev",
        plan.ingress_interface,
        "ingress",
        "chain",
        "0",
        "protocol",
        "ip",
        "pref",
        str(flow.preference),
        "flower",
        "skip_hw",
        "ip_proto",
        "tcp",
        "src_ip",
        f"{flow.source_ipv4}/32",
        "src_port",
        str(flow.source_port),
        "action",
        "mirred",
        "egress",
        "redirect",
        "dev",
        plan.ifb_interface,
    )


def _cleanup_owned_netem(kernel: NetemKernel, plan: NetemSitePlan) -> None:
    """Remove this plan's complete or partial state and prove that it is gone."""

    filters = kernel.ingress_filters(plan.ingress_interface)
    if kernel.egress_filters(plan.ingress_interface):
        raise ValueError("netem_cleanup_foreign_egress_state")
    ingress_special = [
        item
        for item in kernel.qdiscs(plan.ingress_interface)
        if item.get("kind") in {"clsact", "ingress"}
    ]
    if len(ingress_special) > 1 or any(item.get("kind") != "clsact" for item in ingress_special):
        raise ValueError("netem_cleanup_foreign_ingress_state")
    expected_flow_keys = {
        (item.preference, item.source_ipv4, item.source_port) for item in plan.flows
    }
    observed_flow_keys: set[tuple[int, str, int]] = set()
    for item in filters:
        try:
            observed_flow_keys.add(_parse_filter(item, plan.ifb_interface).key)
        except ValueError as error:
            raise ValueError("netem_cleanup_foreign_ingress_state") from error
    if len(observed_flow_keys) != len(filters) or not observed_flow_keys.issubset(
        expected_flow_keys
    ):
        raise ValueError("netem_cleanup_foreign_ingress_state")
    if filters and not ingress_special:
        raise ValueError("netem_cleanup_foreign_ingress_state")

    ifb_qdiscs = kernel.qdiscs(plan.ifb_interface)
    owned_ifb_qdiscs = [
        item
        for item in ifb_qdiscs
        if item.get("kind") == "netem"
        and item.get("handle") == NETEM_QDISC_HANDLE
        and item.get("root") is True
    ]
    if len(owned_ifb_qdiscs) > 1:
        raise ValueError("netem_cleanup_foreign_ifb_state")
    if owned_ifb_qdiscs:
        if len(ifb_qdiscs) != 1:
            raise ValueError("netem_cleanup_foreign_ifb_state")
        try:
            _validate_netem_options(owned_ifb_qdiscs[0].get("options"), plan)
        except ValueError as error:
            raise ValueError("netem_cleanup_foreign_ifb_state") from error
    elif not _is_kernel_default_qdisc_inventory(ifb_qdiscs):
        raise ValueError("netem_cleanup_foreign_ifb_state")
    if ingress_special and not observed_flow_keys and not owned_ifb_qdiscs:
        raise ValueError("netem_cleanup_foreign_ingress_state")

    ingress_error: BaseException | None = None
    if ingress_special:
        try:
            kernel.mutate_tc(("qdisc", "del", "dev", plan.ingress_interface, "clsact"))
        except BaseException as error:
            ingress_error = error
        remaining_filters = kernel.ingress_filters(plan.ingress_interface)
        remaining_ingress = [
            item
            for item in kernel.qdiscs(plan.ingress_interface)
            if item.get("kind") in {"clsact", "ingress"}
        ]
        if remaining_filters:
            raise ValueError("netem_cleanup_ingress_filter_remains") from ingress_error
        if remaining_ingress:
            raise ValueError("netem_cleanup_ingress_qdisc_remains") from ingress_error

    ifb_error: BaseException | None = None
    if owned_ifb_qdiscs:
        try:
            kernel.mutate_tc(("qdisc", "del", "dev", plan.ifb_interface, "root"))
        except BaseException as error:
            ifb_error = error
    if not _is_kernel_default_qdisc_inventory(kernel.qdiscs(plan.ifb_interface)):
        raise ValueError("netem_cleanup_ifb_qdisc_remains") from ifb_error


def _is_kernel_default_qdisc_inventory(items: list[dict[str, object]]) -> bool:
    if len(items) != 1:
        return False
    item = items[0]
    kind = item.get("kind")
    return (
        isinstance(kind, str)
        and bool(kind)
        and kind not in {"netem", "clsact", "ingress"}
        and item.get("handle") == "0:"
        and item.get("root") is True
    )


def _configuration_without_ifindices(plan: NetemSitePlan) -> tuple[object, ...]:
    return (
        plan.ingress_interface,
        plan.ifb_interface,
        plan.ingress_mtu_bytes,
        plan.ingress_mtu_bytes,
        plan.delay_ms,
        plan.jitter_ms,
        plan.loss_percent,
        plan.queue_limit_packets,
        plan.flows,
    )


def _configuration_without_ifindices_from_observation(
    observation: NetemObservation,
) -> tuple[object, ...]:
    config = observation.configuration
    return (
        config.ingress_interface,
        config.ifb_interface,
        config.ingress_mtu_bytes,
        config.ifb_mtu_bytes,
        config.delay_ms,
        config.jitter_ms,
        config.loss_percent,
        config.queue_limit_packets,
        config.flows,
    )


def _require_executable(path: Path) -> Path:
    if not path.is_absolute():
        raise ValueError("netem_tool_must_be_absolute_regular_file")
    try:
        resolved = path.resolve(strict=True)
        mode = resolved.stat().st_mode
    except (OSError, RuntimeError):
        raise ValueError("netem_tool_must_be_absolute_regular_file") from None
    if not stat.S_ISREG(mode) or mode & 0o111 == 0:
        raise ValueError("netem_tool_must_be_absolute_regular_file")
    return resolved


def _tool_identity(path: Path, version_arguments: tuple[str, ...]) -> NetemToolIdentity:
    version = _run(path, version_arguments).strip()
    if not version or "iproute2" not in version:
        raise ValueError("netem_tool_version_invalid")
    return NetemToolIdentity(path=str(path), sha256=_sha256_file(path), version=version)


def _run(binary: Path, arguments: tuple[str, ...]) -> str:
    result = subprocess.run(
        [str(binary), *arguments],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    if result.returncode != 0:
        raise ValueError(f"netem_command_failed:{result.stderr.strip()[:512]}")
    return result.stdout


def _bounded_text(path: Path, maximum_bytes: int) -> str:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > maximum_bytes:
        raise ValueError("netem_host_identity_invalid")
    value = path.read_text(encoding="ascii").strip().lower()
    if not value:
        raise ValueError("netem_host_identity_invalid")
    return value


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_sha256(payload: object) -> str:
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _decimal(value: float) -> str:
    return format(value, ".9f").rstrip("0").rstrip(".") or "0"


def _near(value: object, expected: float) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and abs(value - expected) <= 1e-9
    )


def _random_loss_drop_upper_bound(attempted_packets: int, loss_percent: float) -> int:
    if attempted_packets <= 0:
        return 0
    probability = loss_percent / 100
    expected = attempted_packets * probability
    standard_deviation = math.sqrt(attempted_packets * probability * (1 - probability))
    measurement_tolerance = max(3, math.ceil(attempted_packets * 0.001))
    return min(
        attempted_packets,
        math.ceil(expected + 6 * standard_deviation) + measurement_tolerance,
    )


def _positive_int(value: object, reason: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ValueError(reason)
    return value


def _nonnegative_int(value: object, reason: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(reason)
    return value
