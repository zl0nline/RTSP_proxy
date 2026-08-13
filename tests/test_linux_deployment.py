import hashlib
import json
import subprocess
from configparser import ConfigParser
from pathlib import Path

import pytest

from rtsp_proxy.release import ReleaseVerificationError, trusted_mediamtx_identity


class CaseSensitiveConfigParser(ConfigParser):
    def optionxform(self, optionstr: str) -> str:
        return optionstr


def read_unit(name: str) -> ConfigParser:
    parser = CaseSensitiveConfigParser(interpolation=None, strict=True)
    parser.read(Path("deploy/systemd") / name)
    return parser


def test_service_users_can_traverse_only_their_own_config_directory() -> None:
    entries = Path("deploy/tmpfiles.d/rtsp-proxy.conf").read_text(encoding="utf-8").splitlines()

    assert "d /etc/rtsp-proxy 0755 root root -" in entries
    assert "d /etc/rtsp-proxy/control-plane 0750 root rtsp-proxy -" in entries
    assert "d /etc/rtsp-proxy/mediamtx 0750 root mediamtx -" in entries
    assert "d /etc/rtsp-proxy/nodes 0700 root root -" in entries

    web = read_unit("rtsp-proxy-web.service")
    media = read_unit("mediamtx.service")
    assert web["Service"]["EnvironmentFile"] == ("/etc/rtsp-proxy/control-plane/rtsp-proxy.env")
    assert media["Service"]["ExecStart"].endswith(" /etc/rtsp-proxy/mediamtx/mediamtx.yml")


def test_units_keep_release_tree_read_only_and_drop_privileges() -> None:
    for name in ("rtsp-proxy-web.service", "rtsp-proxy@.service", "mediamtx.service"):
        service = read_unit(name)["Service"]
        assert service["NoNewPrivileges"] == "yes"
        assert service["ProtectSystem"] == "strict"
        assert service["ProtectHome"] == "yes"
        assert service["CapabilityBoundingSet"] == ""
        assert "/opt/rtsp-proxy" not in service["ReadWritePaths"]
        assert service["RuntimeDirectoryMode"] == "0750"
        assert service["StateDirectoryMode"] == "0750"
        assert service["LogsDirectoryMode"] == "0750"


def test_background_roles_use_a_separate_systemd_template() -> None:
    service = read_unit("rtsp-proxy@.service")["Service"]

    assert service["Environment"] == "RTSP_PROXY_ROLE=%i"
    assert service["ExecStart"] == (
        "/opt/rtsp-proxy/current/.venv/bin/rtsp-proxy-role --expected-role=%i"
    )
    assert service["EnvironmentFile"] == ("/etc/rtsp-proxy/control-plane/rtsp-proxy-%i.env")


def test_media_nodes_use_an_exact_isolated_systemd_instance() -> None:
    service = read_unit("rtsp-proxy-media@.service")["Service"]

    assert service["DynamicUser"] == "yes"
    assert service["EnvironmentFile"] == "/etc/rtsp-proxy/nodes/%i/runtime.env"
    assert service["LoadCredential"] == ("mediamtx.yml:/etc/rtsp-proxy/nodes/%i/mediamtx.yml")
    assert service["ExecStart"] == (
        "/usr/bin/env ${RTSP_PROXY_MEDIAMTX_BINARY} "
        "/run/credentials/rtsp-proxy-media@%i.service/mediamtx.yml"
    )
    assert service["RuntimeDirectory"] == "rtsp-proxy/nodes/%i"
    assert service["StateDirectory"] == "rtsp-proxy/nodes/%i"
    assert service["LogsDirectory"] == "rtsp-proxy/nodes/%i"
    assert service["ReadWritePaths"] == (
        "/run/rtsp-proxy/nodes/%i /var/lib/rtsp-proxy/nodes/%i /var/log/rtsp-proxy/nodes/%i"
    )
    assert service["NoNewPrivileges"] == "yes"
    assert service["ProtectSystem"] == "strict"
    assert service["CapabilityBoundingSet"] == ""
    assert service["InaccessiblePaths"] == (
        "/etc/rtsp-proxy/nodes/%i/management.json "
        "/etc/rtsp-proxy/nodes/%i/reader.json"
    )
    assert service["TimeoutStopSec"] == "15s"


def test_control_plane_reaches_systemd_only_through_the_scoped_unix_helper() -> None:
    helper = read_unit("rtsp-proxy-node-runtime.service")["Service"]
    runtime_socket = read_unit("rtsp-proxy-node-runtime.socket")["Socket"]

    assert helper["User"] == "root"
    assert helper["ExecStart"] == ("/opt/rtsp-proxy/current/.venv/bin/rtsp-proxy-node-helper")
    assert helper["EnvironmentFile"] == "/etc/rtsp-proxy/node-runtime.env"
    assert helper["ReadWritePaths"] == "/etc/rtsp-proxy/nodes"
    assert helper["NoNewPrivileges"] == "yes"
    assert helper["ProtectSystem"] == "strict"
    assert helper["CapabilityBoundingSet"] == ""
    assert runtime_socket["ListenStream"] == ("/run/rtsp-proxy-node-runtime/control.sock")
    assert runtime_socket["SocketUser"] == "root"
    assert runtime_socket["SocketGroup"] == "rtsp-proxy"
    assert runtime_socket["SocketMode"] == "0660"


def test_control_and_helper_examples_define_one_identical_runtime_policy() -> None:
    control = dict(
        line.split("=", 1)
        for line in Path("deploy/rtsp-proxy.env.example").read_text().splitlines()
        if line and not line.startswith("#")
    )
    helper = dict(
        line.split("=", 1)
        for line in Path("deploy/node-runtime.env.example").read_text().splitlines()
        if line and not line.startswith("#")
    )
    pairs = (
        ("NODE_PORT_RANGE_START", "EXTERNAL_PORT_START"),
        ("NODE_PORT_RANGE_END", "EXTERNAL_PORT_END"),
        ("NODE_API_PORT_RANGE_START", "API_PORT_START"),
        ("NODE_API_PORT_RANGE_END", "API_PORT_END"),
        ("NODE_METRICS_PORT_RANGE_START", "METRICS_PORT_START"),
        ("NODE_METRICS_PORT_RANGE_END", "METRICS_PORT_END"),
        ("NODE_RELEASE_ID", "RELEASE_ID"),
        ("NODE_MEDIAMTX_BINARY_SHA256", "MEDIAMTX_BINARY_SHA256"),
    )
    for control_name, helper_name in pairs:
        assert (
            control[f"RTSP_PROXY_{control_name}"]
            == (helper[f"RTSP_PROXY_NODE_HELPER_{helper_name}"])
        )


def test_native_ci_runs_the_release_verifier_against_staged_real_binaries() -> None:
    workflow = Path(".github/workflows/ci.yml").read_text(encoding="utf-8")

    assert "Verify native release manifest end to end" in workflow
    assert "uv run rtsp-proxy-verify-release --manifest" in workflow


def test_mediamtx_patch_build_has_immutable_source_and_patch_provenance() -> None:
    catalog = json.loads(Path("deploy/artifact-catalog.json").read_text(encoding="utf-8"))
    media = catalog["mediamtx"]
    trusted = json.loads(
        Path("src/rtsp_proxy/artifacts/mediamtx.json").read_text(encoding="utf-8")
    )
    patch_path = Path(media["patch"])

    assert media["source_commit"] == "1b943637a4b5778bb929a7af7687b048fecaa03f"
    assert media["go_version"] == "go1.26.5"
    assert media["version"] == "v1.20.0-rtsp-proxy.1"
    assert hashlib.sha256(patch_path.read_bytes()).hexdigest() == media["patch_sha256"]
    assert trusted == {
        "schema_version": 2,
        "releases": {
            "0.1.0": {
                "version": media["version"],
                "architectures": media["architectures"],
            }
        },
    }

    workflow = Path(".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert workflow.count("tools/build_mediamtx.sh") == 2
    assert "Download and verify MediaMTX v1.20.0" not in workflow
    assert "Download, verify and stage MediaMTX" not in workflow


def test_initial_patched_release_has_no_fabricated_previous_trust_entry() -> None:
    _version, current = trusted_mediamtx_identity("amd64", "0.1.0")

    assert current.root == (
        "29694cbfed07896d6d47ac19a1cb450e627569b9052ad0909c1b1c0594898cc6"
    )
    with pytest.raises(ReleaseVerificationError, match="trusted_artifact_catalog_invalid"):
        trusted_mediamtx_identity("amd64", "0.0.9")


def test_mediamtx_source_builder_has_valid_shell_syntax() -> None:
    result = subprocess.run(
        ["sh", "-n", "tools/build_mediamtx.sh"],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr


def test_load_fixture_builder_has_valid_bash_syntax() -> None:
    result = subprocess.run(
        ["bash", "-n", "tools/load/prepare_fixture.sh"],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
