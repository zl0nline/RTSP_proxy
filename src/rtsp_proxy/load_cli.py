from __future__ import annotations

import argparse
import json
import math
import os
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

from rtsp_proxy.load_catalog import (
    apply_load_catalog,
    build_load_catalog,
    capture_cold_preflight,
    capture_warm_preflight,
)
from rtsp_proxy.load_evidence import (
    load_observations,
    load_sut_observations,
    sample_linux_generator_resources,
    sample_linux_sut_resources,
    summarize_generator_headroom,
    summarize_sut_capacity,
)
from rtsp_proxy.load_netem import (
    NetemSitePlan,
    NetemSummary,
    SubprocessNetemKernel,
    install_netem,
    load_netem_observations,
    recompute_stored_netem_summary,
    remove_netem,
    required_netem_site_plans,
    sample_linux_netem,
    summarize_netem,
)
from rtsp_proxy.load_profile import (
    LoadProfile,
    canonical_profile_bytes,
    finalize_run_directory,
    generator_sampling_end_unix_ms,
    measurement_end_unix_ms,
    measurement_start_unix_ms,
    sut_sampling_end_unix_ms,
    verify_run_directory,
    workload_end_unix_ms,
)
from rtsp_proxy.load_results import (
    merge_reader_event_files,
    summarize_cold_comparison,
    summarize_reader_events,
    summarize_wan_loss_comparison,
)
from rtsp_proxy.load_run import (
    inspect_fixture,
    load_stored_profile,
    prepare_run_directory,
    sha256_file,
    write_summary,
)
from rtsp_proxy.load_runtime import capture_generator_runtime, capture_sut_runtime
from rtsp_proxy.media import MediaMtxClient


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="rtsp-proxy-load")
    commands = parser.add_subparsers(dest="command", required=True)
    validate = commands.add_parser("validate")
    validate.add_argument("profile", type=Path)

    inspect = commands.add_parser("inspect-fixture")
    inspect.add_argument("profile", type=Path)
    inspect.add_argument("--ffmpeg-binary", required=True, type=Path)
    inspect.add_argument("--ffprobe-binary", required=True, type=Path)
    inspect.add_argument("--output", type=Path)

    prepare = commands.add_parser("prepare")
    prepare.add_argument("profile", type=Path)
    prepare.add_argument("destination", type=Path)
    prepare.add_argument("--pull-server-binary", required=True, type=Path)
    prepare.add_argument("--load-reader-binary", required=True, type=Path)
    prepare.add_argument("--start-unix-ms", required=True, type=int)

    apply_paths = commands.add_parser("apply-paths")
    apply_paths.add_argument("run_directory", type=Path)
    apply_paths.add_argument("--api-url", required=True)
    apply_paths.add_argument("--timeout", type=float, default=2)

    cold_preflight = commands.add_parser("preflight-cold")
    cold_preflight.add_argument("run_directory", type=Path)
    cold_preflight.add_argument("--api-url", required=True)
    cold_preflight.add_argument("--timeout", type=float, default=2)

    warm_preflight = commands.add_parser("preflight-warm")
    warm_preflight.add_argument("run_directory", type=Path)
    warm_preflight.add_argument("--api-url", required=True)
    warm_preflight.add_argument("--timeout", type=float, default=2)

    runtime_generator = commands.add_parser("capture-generator-runtime")
    runtime_generator.add_argument("run_directory", type=Path)
    runtime_generator.add_argument("--generator-host", required=True)
    runtime_generator.add_argument("--source-pid", required=True, action="append", type=int)
    runtime_generator.add_argument("--reader-pid", action="append", type=int, default=[])
    runtime_generator.add_argument("--cgroup", required=True)
    runtime_generator.add_argument("--gst-launch-binary", required=True, type=Path)

    runtime_sut = commands.add_parser("capture-sut-runtime")
    runtime_sut.add_argument("run_directory", type=Path)
    runtime_sut.add_argument("--mediamtx-pid", required=True, type=int)
    runtime_sut.add_argument("--cgroup", required=True)

    sample = commands.add_parser("sample-generator")
    sample.add_argument("run_directory", type=Path)
    sample.add_argument("output", type=Path)
    sample.add_argument("--generator-host", required=True)
    sample.add_argument("--source-pid", required=True, action="append", type=int)
    sample.add_argument("--reader-pid", action="append", type=int, default=[])
    sample.add_argument("--cgroup", required=True)

    summarize = commands.add_parser("summarize-generator")
    summarize.add_argument("run_directory", type=Path)
    summarize.add_argument("observations", type=Path)
    summarize.add_argument("output", type=Path)
    summarize.add_argument("--generator-host", required=True)

    sample_sut = commands.add_parser("sample-sut")
    sample_sut.add_argument("run_directory", type=Path)
    sample_sut.add_argument("output", type=Path)
    sample_sut.add_argument("--mediamtx-pid", required=True, type=int)
    sample_sut.add_argument("--cgroup", required=True)
    sample_sut.add_argument("--metrics-url", required=True)

    summarize_sut = commands.add_parser("summarize-sut")
    summarize_sut.add_argument("run_directory", type=Path)
    summarize_sut.add_argument("observations", type=Path)
    summarize_sut.add_argument("output", type=Path)

    for command_name in ("install-netem", "remove-netem"):
        netem_command = commands.add_parser(command_name)
        netem_command.add_argument("run_directory", type=Path)
        netem_command.add_argument("--site", required=True)
        netem_command.add_argument("--tc-binary", required=True, type=Path)
        netem_command.add_argument("--ip-binary", required=True, type=Path)

    sample_netem = commands.add_parser("sample-netem")
    sample_netem.add_argument("run_directory", type=Path)
    sample_netem.add_argument("output", type=Path)
    sample_netem.add_argument("--site", required=True)
    sample_netem.add_argument("--tc-binary", required=True, type=Path)
    sample_netem.add_argument("--ip-binary", required=True, type=Path)

    summarize_netem_command = commands.add_parser("summarize-netem")
    summarize_netem_command.add_argument("run_directory", type=Path)
    summarize_netem_command.add_argument("observations", type=Path)
    summarize_netem_command.add_argument("output", type=Path)
    summarize_netem_command.add_argument("--site", required=True)

    summarize_readers = commands.add_parser("summarize-readers")
    summarize_readers.add_argument("run_directory", type=Path)
    summarize_readers.add_argument("events", type=Path)
    summarize_readers.add_argument("output", type=Path)

    merge_readers = commands.add_parser("merge-readers")
    merge_readers.add_argument("run_directory", type=Path)
    merge_readers.add_argument("output", type=Path)
    merge_readers.add_argument("inputs", nargs="+", type=Path)

    compare_cold = commands.add_parser("compare-cold")
    compare_cold.add_argument("proxy_run_directory", type=Path)
    compare_cold.add_argument("proxy_events", type=Path)
    compare_cold.add_argument("direct_run_directory", type=Path)
    compare_cold.add_argument("direct_events", type=Path)
    compare_cold.add_argument("output", type=Path)

    finalize = commands.add_parser("finalize")
    finalize.add_argument("run_directory", type=Path)
    verify = commands.add_parser("verify")
    verify.add_argument("run_directory", type=Path)
    return parser


def _load_profile(path: Path) -> LoadProfile:
    payload = json.loads(path.read_text(encoding="utf-8"))
    return LoadProfile.model_validate(payload)


def _require_run_path(run_directory: Path, path: Path) -> None:
    run_root = run_directory.resolve(strict=True)
    parent = path.parent.resolve(strict=True)
    if parent != run_root and run_root not in parent.parents:
        raise ValueError("evidence_path_outside_run_directory")


def _recompute_run_netem_summaries(
    run_directory: Path, profile: LoadProfile
) -> tuple[NetemSummary, ...]:
    launch = json.loads((run_directory / "launch-plan.json").read_text(encoding="utf-8"))
    coordinated_start = launch.get("coordinated_start_unix_ms")
    if not isinstance(coordinated_start, int) or isinstance(coordinated_start, bool):
        raise ValueError("launch_plan_start_invalid")
    summaries: list[NetemSummary] = []
    for plan in required_netem_site_plans(profile):
        _, summary = recompute_stored_netem_summary(
            profile,
            plan,
            run_directory / "raw" / f"netem-{plan.site}.jsonl",
            run_directory / "summary" / f"netem-{plan.site}.json",
            coordinated_start_unix_ms=coordinated_start,
        )
        summaries.append(summary)
    return tuple(summaries)


def _loopback_api_url(value: str) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme != "http"
        or parsed.hostname not in {"127.0.0.1", "::1"}
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
        or parsed.port is None
    ):
        raise ValueError("management_api_must_be_literal_loopback_http")
    return value.rstrip("/")


def _loopback_metrics_url(value: str) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme != "http"
        or parsed.hostname not in {"127.0.0.1", "::1"}
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path != "/metrics"
        or parsed.port is None
    ):
        raise ValueError("metrics_must_be_literal_loopback_http")
    return value


def _copy_reference_exclusive(source: Path, destination: Path) -> None:
    if source.is_symlink() or not source.is_file():
        raise ValueError("reference_source_must_be_regular_file")
    with source.open("rb") as input_file, destination.open("xb") as output_file:
        for chunk in iter(lambda: input_file.read(1024 * 1024), b""):
            output_file.write(chunk)
        output_file.flush()
        os.fsync(output_file.fileno())
    destination.chmod(0o640)


def _netem_plan(profile: LoadProfile, site: str) -> NetemSitePlan:
    matches = tuple(plan for plan in required_netem_site_plans(profile) if plan.site == site)
    if len(matches) != 1:
        raise ValueError("netem_site_not_required_by_profile")
    return matches[0]


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "validate":
            profile = _load_profile(arguments.profile)
            _, profile_sha256 = canonical_profile_bytes(profile)
            print(f"VALID profile_sha256={profile_sha256} tier={profile.tier}")
            return 0
        if arguments.command == "inspect-fixture":
            profile = _load_profile(arguments.profile)
            manifest = inspect_fixture(
                profile,
                ffmpeg_binary=arguments.ffmpeg_binary,
                ffprobe_binary=arguments.ffprobe_binary,
                destination=arguments.output,
            )
            output = arguments.output or Path(f"{profile.fixture.path}.manifest.json")
            print(
                f"INSPECTED_FIXTURE frames={manifest.frame_count} "
                f"keyframes={len(manifest.keyframe_indices)} output={output}"
            )
            return 0
        if arguments.command == "prepare":
            profile = _load_profile(arguments.profile)
            launch_plan = prepare_run_directory(
                profile,
                arguments.destination,
                pull_server_binary=arguments.pull_server_binary,
                load_reader_binary=arguments.load_reader_binary,
                coordinated_start_unix_ms=arguments.start_unix_ms,
            )
            print(
                f"PREPARED directory={arguments.destination} "
                f"sources={len(launch_plan['source_servers'])} "
                f"readers={len(launch_plan['readers'])}"
            )
            return 0
        if arguments.command == "verify":
            verify_run_directory(arguments.run_directory)
            print(f"VERIFIED directory={arguments.run_directory}")
            return 0
        if arguments.command == "finalize":
            finalize_run_directory(arguments.run_directory)
            print(f"FINALIZED directory={arguments.run_directory}")
            return 0

        run_directory: Path = (
            arguments.proxy_run_directory
            if arguments.command == "compare-cold"
            else arguments.run_directory
        )
        profile = load_stored_profile(run_directory)
        if arguments.command in {"install-netem", "remove-netem", "sample-netem"}:
            plan = _netem_plan(profile, arguments.site)
            kernel = SubprocessNetemKernel(
                tc_binary=arguments.tc_binary,
                ip_binary=arguments.ip_binary,
            )
            if arguments.command == "install-netem":
                install_netem(kernel, plan)
                print(f"INSTALLED_NETEM site={plan.site} plan_sha256={plan.sha256}")
                return 0
            if arguments.command == "remove-netem":
                remove_netem(kernel, plan)
                print(f"REMOVED_NETEM site={plan.site}")
                return 0
            _require_run_path(run_directory, arguments.output)
            launch_plan = json.loads(
                (run_directory / "launch-plan.json").read_text(encoding="utf-8")
            )
            coordinated_start = launch_plan.get("coordinated_start_unix_ms")
            if not isinstance(coordinated_start, int) or isinstance(coordinated_start, bool):
                raise ValueError("launch_plan_start_invalid")
            sampled_netem_observations = sample_linux_netem(
                profile,
                plan,
                arguments.output,
                kernel=kernel,
                coordinated_start_unix_ms=coordinated_start,
            )
            print(
                f"SAMPLED_NETEM site={plan.site} samples={len(sampled_netem_observations)} "
                f"output={arguments.output}"
            )
            return 0
        if arguments.command == "summarize-netem":
            _require_run_path(run_directory, arguments.observations)
            _require_run_path(run_directory, arguments.output)
            plan = _netem_plan(profile, arguments.site)
            launch_plan = json.loads(
                (run_directory / "launch-plan.json").read_text(encoding="utf-8")
            )
            coordinated_start = launch_plan.get("coordinated_start_unix_ms")
            if not isinstance(coordinated_start, int) or isinstance(coordinated_start, bool):
                raise ValueError("launch_plan_start_invalid")
            netem_observations = load_netem_observations(arguments.observations)
            summary = summarize_netem(
                profile,
                plan,
                netem_observations,
                observations_sha256=sha256_file(arguments.observations),
                coordinated_start_unix_ms=coordinated_start,
            )
            write_summary(arguments.output, summary)
            print(
                f"SUMMARIZED_NETEM site={plan.site} valid={str(summary.valid).lower()} "
                f"output={arguments.output}"
            )
            return 0 if summary.valid else 3
        if arguments.command == "apply-paths":
            result = apply_load_catalog(
                build_load_catalog(profile),
                MediaMtxClient(
                    api_url=_loopback_api_url(arguments.api_url),
                    timeout_seconds=arguments.timeout,
                ),
            )
            print(f"APPLIED paths={result.applied_paths} verified={result.verified_paths}")
            return 0
        if arguments.command in {"preflight-cold", "preflight-warm"}:
            launch_plan = json.loads(
                (run_directory / "launch-plan.json").read_text(encoding="utf-8")
            )
            scheduled_start = launch_plan.get("coordinated_start_unix_ms")
            if not isinstance(scheduled_start, int) or isinstance(scheduled_start, bool):
                raise ValueError("launch_plan_start_invalid")
            client = MediaMtxClient(
                api_url=_loopback_api_url(arguments.api_url),
                timeout_seconds=arguments.timeout,
            )
            payload = (
                capture_cold_preflight(
                    profile,
                    client,
                    scheduled_start_unix_ms=scheduled_start,
                )
                if arguments.command == "preflight-cold"
                else capture_warm_preflight(
                    profile,
                    client,
                    scheduled_start_unix_ms=scheduled_start,
                )
            )
            output = (
                run_directory
                / "raw"
                / (
                    "cold-preflight.json"
                    if arguments.command == "preflight-cold"
                    else "warm-preflight.json"
                )
            )
            write_summary(output, payload)
            paths = payload[
                "unavailable_paths" if arguments.command == "preflight-cold" else "ready_paths"
            ]
            if not isinstance(paths, list):
                raise ValueError("preflight_evidence_invalid")
            label = (
                "COLD_PREFLIGHT inactive"
                if arguments.command == "preflight-cold"
                else "WARM_PREFLIGHT ready"
            )
            print(f"{label}={len(paths)} output={output}")
            return 0
        if arguments.command == "capture-generator-runtime":
            source_pids = tuple(arguments.source_pid)
            reader_pids = tuple(arguments.reader_pid)
            launch_plan = json.loads(
                (run_directory / "launch-plan.json").read_text(encoding="utf-8")
            )
            expected_source_count = sum(
                launch.get("generator_host") == arguments.generator_host
                for launch in launch_plan.get("source_servers", [])
            )
            expected_reader_count = sum(
                launch.get("generator_host") == arguments.generator_host
                for launch in launch_plan.get("readers", [])
            )
            if (
                len(source_pids) != expected_source_count
                or len(reader_pids) != expected_reader_count
            ):
                raise ValueError("generator_workload_pid_set_incomplete")
            expected_executables = {
                **{pid: profile.artifacts.pull_server_sha256 for pid in source_pids},
                **{pid: profile.artifacts.load_reader_sha256 for pid in reader_pids},
            }
            runtime_manifest = capture_generator_runtime(
                profile,
                host=arguments.generator_host,
                pids=source_pids + reader_pids,
                cgroup=arguments.cgroup,
                expected_executables=expected_executables,
                gst_launch_binary=arguments.gst_launch_binary,
            )
            output = run_directory / "raw" / f"runtime-generator-{arguments.generator_host}.json"
            write_summary(output, runtime_manifest)
            print(f"CAPTURED_GENERATOR_RUNTIME host={arguments.generator_host} output={output}")
            return 0
        if arguments.command == "capture-sut-runtime":
            if profile.workload.endpoint_mode != "proxy" and profile.tier != "capacity":
                raise ValueError("sut_runtime_not_required_for_direct_functional_profile")
            runtime_manifest = capture_sut_runtime(
                profile,
                pid=arguments.mediamtx_pid,
                cgroup=arguments.cgroup,
            )
            output = run_directory / "raw" / "runtime-sut.json"
            write_summary(output, runtime_manifest)
            print(f"CAPTURED_SUT_RUNTIME output={output}")
            return 0
        if arguments.command == "sample-generator":
            if arguments.generator_host not in {host.name for host in profile.generator_hosts}:
                raise ValueError("unknown_generator_host")
            _require_run_path(run_directory, arguments.output)
            source_pids = tuple(arguments.source_pid)
            reader_pids = tuple(arguments.reader_pid)
            launch_plan = json.loads(
                (run_directory / "launch-plan.json").read_text(encoding="utf-8")
            )
            expected_source_count = sum(
                launch.get("generator_host") == arguments.generator_host
                for launch in launch_plan.get("source_servers", [])
            )
            expected_reader_count = sum(
                launch.get("generator_host") == arguments.generator_host
                for launch in launch_plan.get("readers", [])
            )
            if (
                len(source_pids) != expected_source_count
                or len(reader_pids) != expected_reader_count
            ):
                raise ValueError("generator_workload_pid_set_incomplete")
            expected_executables = {
                **{pid: profile.artifacts.pull_server_sha256 for pid in source_pids},
                **{pid: profile.artifacts.load_reader_sha256 for pid in reader_pids},
            }
            coordinated_start_ms = launch_plan.get("coordinated_start_unix_ms")
            if not isinstance(coordinated_start_ms, int) or isinstance(coordinated_start_ms, bool):
                raise ValueError("launch_plan_start_invalid")
            sample_until_ms = generator_sampling_end_unix_ms(profile, coordinated_start_ms)
            duration_seconds = math.ceil((sample_until_ms - time.time_ns() // 1_000_000) / 1000)
            if duration_seconds < 1:
                raise ValueError("generator_sampling_window_already_expired")
            count = sample_linux_generator_resources(
                root=Path("/"),
                generator_host=arguments.generator_host,
                interface=profile.network.interface,
                pids=source_pids + reader_pids,
                cgroup=arguments.cgroup,
                expected_executables=expected_executables,
                expected_mtu_bytes=profile.network.mtu_bytes,
                output=arguments.output,
                duration_seconds=duration_seconds,
                interval_seconds=profile.evidence_sampling.interval_seconds,
            )
            print(f"SAMPLED observations={count} output={arguments.output}")
            return 0
        if arguments.command == "sample-sut":
            if profile.workload.endpoint_mode != "proxy" and profile.tier != "capacity":
                raise ValueError("sut_sampler_not_required_for_direct_functional_profile")
            _require_run_path(run_directory, arguments.output)
            launch_plan = json.loads(
                (run_directory / "launch-plan.json").read_text(encoding="utf-8")
            )
            coordinated_start_ms = launch_plan.get("coordinated_start_unix_ms")
            if not isinstance(coordinated_start_ms, int) or isinstance(coordinated_start_ms, bool):
                raise ValueError("launch_plan_start_invalid")
            sample_until_ms = sut_sampling_end_unix_ms(profile, coordinated_start_ms)
            duration_seconds = math.ceil((sample_until_ms - time.time_ns() // 1_000_000) / 1000)
            if duration_seconds < 1:
                raise ValueError("sut_sampling_window_already_expired")
            count = sample_linux_sut_resources(
                root=Path("/"),
                sut_host=profile.sut_rtsp_host,
                interface=profile.network.interface,
                mediamtx_pid=arguments.mediamtx_pid,
                cgroup=arguments.cgroup,
                expected_mediamtx_sha256=profile.artifacts.mediamtx_sha256,
                expected_mtu_bytes=profile.network.mtu_bytes,
                metrics_url=_loopback_metrics_url(arguments.metrics_url),
                output=arguments.output,
                duration_seconds=duration_seconds,
                interval_seconds=profile.evidence_sampling.interval_seconds,
                maximum_clock_error_ms=profile.evidence_sampling.maximum_clock_error_ms,
            )
            print(f"SAMPLED_SUT observations={count} output={arguments.output}")
            return 0
        if arguments.command == "summarize-generator":
            _require_run_path(run_directory, arguments.observations)
            _require_run_path(run_directory, arguments.output)
            observations = load_observations(arguments.observations)
            launch_plan = json.loads(
                (run_directory / "launch-plan.json").read_text(encoding="utf-8")
            )
            coordinated_start_ms = launch_plan.get("coordinated_start_unix_ms")
            if not isinstance(coordinated_start_ms, int) or isinstance(coordinated_start_ms, bool):
                raise ValueError("launch_plan_start_invalid")
            generator_summary = summarize_generator_headroom(
                observations,
                expected_generator_host=arguments.generator_host,
                minimum_duration_seconds=profile.duration.measurement_seconds,
                expected_interval_seconds=profile.evidence_sampling.interval_seconds,
                maximum_gap_factor=profile.evidence_sampling.maximum_gap_factor,
                observations_sha256=sha256_file(arguments.observations),
                capacity_gate=profile.tier == "capacity",
                measurement_start_unix_ms=measurement_start_unix_ms(profile, coordinated_start_ms),
                measurement_end_unix_ms=measurement_end_unix_ms(profile, coordinated_start_ms),
                soak_end_unix_ms=workload_end_unix_ms(profile, coordinated_start_ms),
            )
            write_summary(arguments.output, generator_summary)
            print(f"SUMMARIZED_GENERATOR output={arguments.output}")
            return 0 if generator_summary.valid else 3
        if arguments.command == "summarize-sut":
            if profile.workload.endpoint_mode != "proxy" and profile.tier != "capacity":
                raise ValueError("sut_summary_not_required_for_direct_functional_profile")
            _require_run_path(run_directory, arguments.observations)
            _require_run_path(run_directory, arguments.output)
            sut_observations = load_sut_observations(arguments.observations)
            launch_plan = json.loads(
                (run_directory / "launch-plan.json").read_text(encoding="utf-8")
            )
            coordinated_start_ms = launch_plan.get("coordinated_start_unix_ms")
            if not isinstance(coordinated_start_ms, int) or isinstance(coordinated_start_ms, bool):
                raise ValueError("launch_plan_start_invalid")
            sut_summary = summarize_sut_capacity(
                sut_observations,
                expected_sut_host=profile.sut_rtsp_host,
                expected_interval_seconds=profile.evidence_sampling.interval_seconds,
                maximum_gap_factor=profile.evidence_sampling.maximum_gap_factor,
                observations_sha256=sha256_file(arguments.observations),
                measurement_start_unix_ms=measurement_start_unix_ms(profile, coordinated_start_ms),
                measurement_end_unix_ms=measurement_end_unix_ms(profile, coordinated_start_ms),
                soak_end_unix_ms=workload_end_unix_ms(profile, coordinated_start_ms),
                maximum_clock_error_ms=profile.evidence_sampling.maximum_clock_error_ms,
                capacity_gate=profile.tier == "capacity",
            )
            write_summary(arguments.output, sut_summary)
            print(f"SUMMARIZED_SUT output={arguments.output}")
            return 0 if sut_summary.valid else 3
        if arguments.command == "summarize-readers":
            _require_run_path(run_directory, arguments.events)
            _require_run_path(run_directory, arguments.output)
            reader_summary = summarize_reader_events(profile, arguments.events)
            write_summary(arguments.output, reader_summary)
            print(f"SUMMARIZED_READERS output={arguments.output}")
            return 0 if reader_summary.valid else 3
        if arguments.command == "merge-readers":
            _require_run_path(run_directory, arguments.output)
            for input_path in arguments.inputs:
                _require_run_path(run_directory, input_path)
            count = merge_reader_event_files(tuple(arguments.inputs), arguments.output)
            print(f"MERGED_READERS events={count} output={arguments.output}")
            return 0
        if arguments.command == "compare-cold":
            direct_profile = load_stored_profile(arguments.direct_run_directory)
            verify_run_directory(arguments.direct_run_directory)
            proxy_netem_summaries = _recompute_run_netem_summaries(run_directory, profile)
            direct_netem_summaries = _recompute_run_netem_summaries(
                arguments.direct_run_directory, direct_profile
            )
            _require_run_path(run_directory, arguments.proxy_events)
            _require_run_path(arguments.direct_run_directory, arguments.direct_events)
            _require_run_path(run_directory, arguments.output)
            reference_directory = run_directory / "reference"
            reference_directory.mkdir(mode=0o750, exist_ok=False)
            reference_profile = reference_directory / "direct-profile.json"
            reference_events = reference_directory / "direct-readers.jsonl"
            reference_manifest = reference_directory / "direct-final-manifest.json"
            reference_launch = reference_directory / "direct-launch-plan.json"
            _copy_reference_exclusive(
                arguments.direct_run_directory / "profile.json", reference_profile
            )
            _copy_reference_exclusive(arguments.direct_events, reference_events)
            _copy_reference_exclusive(
                arguments.direct_run_directory / "final-manifest.json",
                reference_manifest,
            )
            _copy_reference_exclusive(
                arguments.direct_run_directory / "launch-plan.json",
                reference_launch,
            )
            for host in direct_profile.generator_hosts:
                _copy_reference_exclusive(
                    arguments.direct_run_directory / "raw" / f"runtime-generator-{host.name}.json",
                    reference_directory / f"direct-runtime-generator-{host.name}.json",
                )
            for plan in required_netem_site_plans(direct_profile):
                _copy_reference_exclusive(
                    arguments.direct_run_directory / "raw" / f"netem-{plan.site}.jsonl",
                    reference_directory / f"direct-netem-{plan.site}.jsonl",
                )
                _copy_reference_exclusive(
                    arguments.direct_run_directory / "summary" / f"netem-{plan.site}.json",
                    reference_directory / f"direct-netem-summary-{plan.site}.json",
                )
            comparison = summarize_cold_comparison(
                profile,
                arguments.proxy_events,
                direct_profile,
                reference_events,
                direct_final_manifest_sha256=sha256_file(reference_manifest),
                wan_loss=(
                    summarize_wan_loss_comparison(
                        proxy_netem_summaries,
                        direct_netem_summaries,
                    )
                    if proxy_netem_summaries
                    else None
                ),
            )
            write_summary(arguments.output, comparison)
            print(f"SUMMARIZED_COLD_COMPARISON output={arguments.output}")
            return 0 if comparison.valid else 3
    except FileExistsError:
        print("load_profile_error: destination_exists", file=sys.stderr)
    except (OSError, ValueError):
        print("load_profile_error: invalid_or_unreadable_profile", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
