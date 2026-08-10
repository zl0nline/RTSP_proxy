from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from rtsp_proxy.load_catalog import apply_load_catalog, build_load_catalog, write_load_catalog
from rtsp_proxy.load_evidence import (
    load_observations,
    sample_linux_host_resources,
    summarize_generator_headroom,
)
from rtsp_proxy.load_profile import (
    LoadProfile,
    canonical_profile_bytes,
    initialize_run_directory,
)
from rtsp_proxy.media import MediaMtxClient


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="rtsp-proxy-load")
    commands = parser.add_subparsers(dest="command", required=True)
    validate = commands.add_parser("validate")
    validate.add_argument("profile", type=Path)
    initialize = commands.add_parser("init")
    initialize.add_argument("profile", type=Path)
    initialize.add_argument("destination", type=Path)
    catalog = commands.add_parser("render-catalog")
    catalog.add_argument("profile", type=Path)
    catalog.add_argument("destination", type=Path)
    apply_paths = commands.add_parser("apply-paths")
    apply_paths.add_argument("profile", type=Path)
    apply_paths.add_argument("--api-url", required=True)
    apply_paths.add_argument("--timeout", type=float, default=2)
    sample = commands.add_parser("sample-host")
    sample.add_argument("profile", type=Path)
    sample.add_argument("output", type=Path)
    sample.add_argument("--root", type=Path, default=Path("/"))
    sample.add_argument("--interval", type=float, default=1)
    summarize = commands.add_parser("summarize-generator")
    summarize.add_argument("profile", type=Path)
    summarize.add_argument("observations", type=Path)
    return parser


def _load_profile(path: Path) -> LoadProfile:
    payload = json.loads(path.read_text(encoding="utf-8"))
    return LoadProfile.model_validate(payload)


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        profile = _load_profile(arguments.profile)
        if arguments.command == "validate":
            _, profile_sha256 = canonical_profile_bytes(profile)
            print(f"VALID profile_sha256={profile_sha256} tier={profile.tier}")
            return 0
        if arguments.command == "init":
            initialize_run_directory(profile, arguments.destination)
            print(f"INITIALIZED directory={arguments.destination}")
            return 0
        if arguments.command == "render-catalog":
            catalog_sha256 = write_load_catalog(profile, arguments.destination)
            print(
                f"CATALOG path={arguments.destination} sha256={catalog_sha256}"
            )
            return 0
        if arguments.command == "apply-paths":
            result = apply_load_catalog(
                build_load_catalog(profile),
                MediaMtxClient(
                    api_url=arguments.api_url,
                    timeout_seconds=arguments.timeout,
                ),
            )
            print(
                f"APPLIED paths={result.applied_paths} "
                f"verified={result.verified_paths}"
            )
            return 0
        expected_duration = (
            profile.duration.warmup_seconds
            + profile.duration.measurement_seconds
            + profile.duration.soak_seconds
        )
        if arguments.command == "sample-host":
            count = sample_linux_host_resources(
                root=arguments.root,
                interface=profile.network.interface,
                output=arguments.output,
                duration_seconds=expected_duration,
                interval_seconds=arguments.interval,
            )
            print(f"SAMPLED observations={count} output={arguments.output}")
            return 0
        observations = load_observations(arguments.observations)
        summary = summarize_generator_headroom(
            observations,
            minimum_duration_seconds=expected_duration,
        )
        print(json.dumps(summary.model_dump(mode="json"), sort_keys=True))
        return 0 if summary.valid else 3
    except FileExistsError:
        print("load_profile_error: destination_exists", file=sys.stderr)
    except (OSError, ValueError):
        print("load_profile_error: invalid_or_unreadable_profile", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
