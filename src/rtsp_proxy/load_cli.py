from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from urllib.parse import urlsplit

from rtsp_proxy.load_catalog import apply_load_catalog, build_load_catalog
from rtsp_proxy.load_evidence import (
    load_observations,
    sample_linux_generator_resources,
    summarize_generator_headroom,
)
from rtsp_proxy.load_profile import (
    LoadProfile,
    canonical_profile_bytes,
    finalize_run_directory,
    verify_run_directory,
)
from rtsp_proxy.load_results import (
    merge_reader_event_files,
    summarize_cold_comparison,
    summarize_reader_events,
)
from rtsp_proxy.load_run import (
    load_stored_profile,
    prepare_run_directory,
    sha256_file,
    write_summary,
)
from rtsp_proxy.media import MediaMtxClient


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="rtsp-proxy-load")
    commands = parser.add_subparsers(dest="command", required=True)
    validate = commands.add_parser("validate")
    validate.add_argument("profile", type=Path)

    prepare = commands.add_parser("prepare")
    prepare.add_argument("profile", type=Path)
    prepare.add_argument("destination", type=Path)
    prepare.add_argument("--pull-server-binary", required=True, type=Path)
    prepare.add_argument("--load-reader-binary", required=True, type=Path)

    apply_paths = commands.add_parser("apply-paths")
    apply_paths.add_argument("run_directory", type=Path)
    apply_paths.add_argument("--api-url", required=True)
    apply_paths.add_argument("--timeout", type=float, default=2)

    sample = commands.add_parser("sample-generator")
    sample.add_argument("run_directory", type=Path)
    sample.add_argument("output", type=Path)
    sample.add_argument("--generator-host", required=True)
    sample.add_argument("--pid", required=True, action="append", type=int)
    sample.add_argument("--cgroup", required=True)

    summarize = commands.add_parser("summarize-generator")
    summarize.add_argument("run_directory", type=Path)
    summarize.add_argument("observations", type=Path)
    summarize.add_argument("output", type=Path)
    summarize.add_argument("--generator-host", required=True)

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


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "validate":
            profile = _load_profile(arguments.profile)
            _, profile_sha256 = canonical_profile_bytes(profile)
            print(f"VALID profile_sha256={profile_sha256} tier={profile.tier}")
            return 0
        if arguments.command == "prepare":
            profile = _load_profile(arguments.profile)
            launch_plan = prepare_run_directory(
                profile,
                arguments.destination,
                pull_server_binary=arguments.pull_server_binary,
                load_reader_binary=arguments.load_reader_binary,
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
        if arguments.command == "sample-generator":
            if arguments.generator_host not in {
                host.name for host in profile.generator_hosts
            }:
                raise ValueError("unknown_generator_host")
            _require_run_path(run_directory, arguments.output)
            count = sample_linux_generator_resources(
                root=Path("/"),
                generator_host=arguments.generator_host,
                interface=profile.network.interface,
                pids=tuple(arguments.pid),
                cgroup=arguments.cgroup,
                output=arguments.output,
                duration_seconds=profile.duration.total_seconds,
                interval_seconds=profile.evidence_sampling.interval_seconds,
            )
            print(f"SAMPLED observations={count} output={arguments.output}")
            return 0
        if arguments.command == "summarize-generator":
            _require_run_path(run_directory, arguments.observations)
            _require_run_path(run_directory, arguments.output)
            observations = load_observations(arguments.observations)
            generator_summary = summarize_generator_headroom(
                observations,
                expected_generator_host=arguments.generator_host,
                minimum_duration_seconds=profile.duration.total_seconds,
                expected_interval_seconds=profile.evidence_sampling.interval_seconds,
                maximum_gap_factor=profile.evidence_sampling.maximum_gap_factor,
                observations_sha256=sha256_file(arguments.observations),
            )
            write_summary(arguments.output, generator_summary)
            print(f"SUMMARIZED_GENERATOR output={arguments.output}")
            return 0 if generator_summary.valid else 3
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
            _require_run_path(run_directory, arguments.proxy_events)
            _require_run_path(arguments.direct_run_directory, arguments.direct_events)
            _require_run_path(run_directory, arguments.output)
            comparison = summarize_cold_comparison(
                profile,
                arguments.proxy_events,
                direct_profile,
                arguments.direct_events,
                direct_final_manifest_sha256=sha256_file(
                    arguments.direct_run_directory / "final-manifest.json"
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
