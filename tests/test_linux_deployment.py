import hashlib
import json
import subprocess
import sys
from configparser import ConfigParser
from pathlib import Path

import pytest

from rtsp_proxy.nft_reconcile import NftReconcileError, validate_owned_table
from rtsp_proxy.release import APPLICATION_SCHEMA, trusted_mediamtx_identity


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
    assert "d /etc/rtsp-proxy/control-plane 0750 root rtsp-proxy-access -" in entries
    assert "d /etc/rtsp-proxy/mediamtx 0750 root mediamtx -" in entries
    assert "d /etc/rtsp-proxy/nodes 0700 root root -" in entries

    web = read_unit("rtsp-proxy-web.service")
    media = read_unit("mediamtx.service")
    assert web["Service"]["EnvironmentFile"] == ("/etc/rtsp-proxy/control-plane/rtsp-proxy.env")
    assert web["Service"]["Environment"] == "RTSP_PROXY_ROLE=web"
    assert web["Service"]["ExecStart"] == (
        "/opt/rtsp-proxy/current/.venv/bin/rtsp-proxy-web "
        "--management-tls-certificate-file=%d/management-tls.pem "
        "--management-tls-private-key-file=%d/management-tls.pem"
    )
    assert web["Service"]["LoadCredential"] == (
        "management-tls.pem:/etc/rtsp-proxy/control-plane/management-tls-current/"
        "management-tls.pem"
    )
    auth_drop_in = read_unit("rtsp-proxy-web-auth.conf.example")["Service"]
    assert "%d/oidc-client-secret" in auth_drop_in["Environment"]
    assert "oidc-client-secret:" in auth_drop_in["LoadCredential"]
    assert "break-glass-key:" in auth_drop_in["LoadCredential"]
    assert media["Service"]["ExecStart"].endswith(" /etc/rtsp-proxy/mediamtx/mediamtx.yml")

    users = Path("deploy/sysusers.d/rtsp-proxy.conf").read_text(encoding="utf-8")
    assert "g rtsp-proxy-access - -" in users
    assert "m rtsp-proxy rtsp-proxy-access" in users
    assert "m rtsp-proxy-auth rtsp-proxy-access" in users


def test_units_keep_release_tree_read_only_and_drop_privileges() -> None:
    for name in (
        "rtsp-proxy-web.service",
        "rtsp-proxy@.service",
        "mediamtx.service",
    ):
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


def test_collector_has_a_dedicated_read_only_helper_boundary() -> None:
    collector = read_unit("rtsp-proxy-collector.service")
    metrics_helper = read_unit("rtsp-proxy-node-metrics.service")
    metrics_socket = read_unit("rtsp-proxy-node-metrics.socket")["Socket"]
    users = Path("deploy/sysusers.d/rtsp-proxy.conf").read_text(encoding="utf-8")

    assert collector["Service"]["User"] == "rtsp-proxy-collector"
    assert collector["Service"]["TimeoutStopSec"] == "30s"
    assert collector["Service"]["Environment"] == "RTSP_PROXY_ROLE=collector"
    assert metrics_socket["ListenStream"] == "/run/rtsp-proxy-node-metrics/metrics.sock"
    assert metrics_socket["SocketGroup"] == "rtsp-proxy-collector"
    assert metrics_socket["SocketMode"] == "0660"
    assert metrics_helper["Service"]["Environment"] == ("RTSP_PROXY_NODE_HELPER_READ_ONLY=true")
    assert metrics_helper["Service"]["ReadOnlyPaths"] == (
        "/etc/rtsp-proxy/nodes /etc/rtsp-proxy/control-plane/access-peppers.json"
    )
    assert "u rtsp-proxy-collector " in users


def test_notifier_uses_a_dedicated_identity_and_systemd_credential() -> None:
    notifier = read_unit("rtsp-proxy-notifier.service")["Service"]
    users = Path("deploy/sysusers.d/rtsp-proxy.conf").read_text(encoding="utf-8")

    assert notifier["User"] == "rtsp-proxy-notifier"
    assert notifier["Environment"] == (
        '"RTSP_PROXY_ROLE=worker" "RTSP_PROXY_SMTP_PASSWORD_FILE=%d/smtp-password"'
    )
    assert notifier["LoadCredential"] == (
        "smtp-password:/etc/rtsp-proxy/control-plane/smtp-password"
    )
    assert notifier["EnvironmentFile"] == "/etc/rtsp-proxy/notifier.env"
    assert notifier["TimeoutStopSec"] == "45s"
    assert notifier["CapabilityBoundingSet"] == ""
    assert "u rtsp-proxy-notifier " in users
    notifier_environment = Path("deploy/notifier.env.example").read_text(encoding="utf-8")
    assert "SMTP_PASSWORD" not in notifier_environment
    collector_environment = Path("deploy/collector.env.example").read_text(encoding="utf-8")
    assert "postgresql+psycopg://rtsp_proxy_collector@" in collector_environment
    assert "postgresql+psycopg://rtsp_proxy_notifier@" in notifier_environment
    assert "NODE_RUNTIME_SOCKET=/run/rtsp-proxy-node-metrics/metrics.sock" in (
        collector_environment
    )


def test_management_tls_rotation_runbook_switches_one_validated_pair_atomically() -> None:
    runbook = Path("deploy/README.md").read_text(encoding="utf-8")

    assert "ipaddress.ip_address(sys.argv[1])" in runbook
    assert "-checkip \"$tls_management_name\"" in runbook
    assert "-checkhost \"$tls_management_name\"" in runbook
    assert "For an IPv6" in runbook
    assert "literal, keep the SAN value unbracketed" in runbook
    assert "tls_management_url=https://management.example.net:8000/health/ready" in runbook
    assert "ln -s \"$tls_candidate_target\" \"$tls_next_link\"" in runbook
    atomic_switch = 'mv -Tf "$tls_next_link" "$tls_current_link"'
    assert atomic_switch in runbook
    assert runbook.index("trap tls_restore EXIT HUP INT TERM") < runbook.rindex(atomic_switch)
    assert "readlink \"$tls_current_link\"" in runbook
    assert "flock -n 9" in runbook
    assert "/run/lock/rtsp-proxy-management-tls.lock" not in runbook
    assert "tls_lock=$tls_control_root/.management-tls-rotation.lock" in runbook
    assert "set -o noclobber" in runbook
    assert "regular file:0:0:600:1" in runbook
    assert "os.fsync" in runbook
    assert '"$tls_previous_dir/management-tls.pem" -pubkey -noout' in runbook
    assert '"$tls_previous_dir/management-tls.pem" -pubout -outform DER' in runbook
    candidate_link = 'ln -s "$tls_candidate_target" "$tls_next_link"'
    assert runbook.rfind('tls_fsync "$tls_control_root"', 0, runbook.index(candidate_link)) > 0
    assert "tls_restart_and_wait" in runbook
    assert "InvocationID" in runbook
    assert 'if ! tls_previous_invocation=$(timeout --signal=KILL 2s systemctl show' in runbook
    assert '[ -z "$tls_previous_invocation" ]; then' in runbook
    assert '"$tls_observed_invocation" != "$tls_previous_invocation"' in runbook
    assert "tls_served_fingerprint" in runbook
    assert 'test "$tls_served" = "$tls_candidate_fingerprint"' in runbook
    assert 'test "$tls_served" = "$tls_previous_fingerprint"' in runbook
    assert "--connect-timeout 2 --max-time 5" in runbook


def test_media_auth_callback_is_a_dedicated_unprivileged_loopback_service() -> None:
    service = read_unit("rtsp-proxy-auth.service")["Service"]
    environment = Path("deploy/rtsp-proxy-auth.env.example").read_text(encoding="utf-8")

    assert service["User"] == "rtsp-proxy-auth"
    assert service["Group"] == "rtsp-proxy-auth"
    assert service["Environment"] == "RTSP_PROXY_ROLE=auth"
    assert service["EnvironmentFile"] == ("/etc/rtsp-proxy/control-plane/rtsp-proxy-auth.env")
    assert service["ExecStart"] == "/opt/rtsp-proxy/current/.venv/bin/rtsp-proxy-auth"
    assert service["NoNewPrivileges"] == "yes"
    assert service["CapabilityBoundingSet"] == ""
    assert service["ReadOnlyPaths"] == ("/etc/rtsp-proxy/control-plane/access-peppers.json")
    assert service["ReadWritePaths"] == "/run/rtsp-proxy-auth"
    assert "StateDirectory" not in service
    assert "LogsDirectory" not in service
    assert "RTSP_PROXY_AUTH_HOST=127.0.0.1" in environment
    assert "RTSP_PROXY_AUTH_PORT=8010" in environment
    assert "RTSP_PROXY_ACCESS_PEPPER_FILE=/etc/rtsp-proxy/control-plane/" in environment


def test_media_nodes_use_an_exact_isolated_systemd_instance() -> None:
    unit = read_unit("rtsp-proxy-media@.service")
    service = unit["Service"]

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
        "/etc/rtsp-proxy/nodes/%i/management.json /etc/rtsp-proxy/nodes/%i/reader.json"
    )
    assert service["TimeoutStopSec"] == "15s"
    assert service["LimitNOFILE"] == "131072"
    assert service["TasksMax"] == "256"
    assert "rtsp-proxy-auth.service" in unit["Unit"]["Wants"]
    assert "rtsp-proxy-auth.service" in unit["Unit"]["After"]


def test_nftables_policy_is_additive_bounded_and_scoped_to_node_ports() -> None:
    policy = Path("deploy/nftables/rtsp-proxy.nft").read_text(encoding="utf-8")

    assert 'comment "rtsp-proxy-owned:v1"' in policy
    assert "destroy table inet rtsp_proxy" not in policy
    assert "type filter hook input priority -5; policy accept;" in policy
    assert "elements = { 10000-10999 }" in policy
    assert policy.count("size 65536") == 4
    assert "size 256" in policy
    assert policy.count("ct count over 128") == 3
    assert 'comment "rtsp-proxy per-node connection cap"' in policy
    assert policy.count("limit rate over 100/second burst 200 packets") == 2
    assert "flush ruleset" not in policy
    assert "policy drop" not in policy

    unit = read_unit("rtsp-proxy-nftables.service")
    assert unit["Unit"]["Before"] == (
        "network.target rtsp-proxy-node-runtime.service rtsp-proxy-media@.service"
    )
    assert unit["Service"]["ExecStart"] == (
        "/opt/rtsp-proxy/current/.venv/bin/rtsp-proxy-nft-reconcile"
    )
    assert unit["Service"]["CapabilityBoundingSet"] == "CAP_NET_ADMIN"


def test_nftables_inventory_requires_exact_owned_schema() -> None:
    entries: list[dict[str, object]] = [
        {
            "table": {
                "family": "inet",
                "name": "rtsp_proxy",
                "comment": "rtsp-proxy-owned:v1",
            }
        }
    ]
    entries.extend(
        {"set": {"family": "inet", "table": "rtsp_proxy", **contract}}
        for contract in (
            {"name": "node_ports", "type": "inet_service", "flags": ["interval"]},
            {
                "name": "syn_rate_v4",
                "type": ["ipv4_addr", "inet_service"],
                "flags": ["dynamic", "timeout"],
            },
            {
                "name": "syn_rate_v6",
                "type": ["ipv6_addr", "inet_service"],
                "flags": ["dynamic", "timeout"],
            },
            {
                "name": "connections_v4",
                "type": ["ipv4_addr", "inet_service"],
                "flags": ["dynamic"],
            },
            {
                "name": "connections_v6",
                "type": ["ipv6_addr", "inet_service"],
                "flags": ["dynamic"],
            },
            {
                "name": "node_connections",
                "type": "inet_service",
                "flags": ["dynamic"],
            },
        )
    )
    entries.append(
        {
            "chain": {
                "family": "inet",
                "table": "rtsp_proxy",
                "name": "input",
                "type": "filter",
                "hook": "input",
                "prio": -5,
                "policy": "accept",
            }
        }
    )
    for comment in (
        "rtsp-proxy per-node connection cap",
        "rtsp-proxy per-ip-port connection cap",
        "rtsp-proxy per-ip-port connection cap",
        "rtsp-proxy per-ip-port SYN rate",
        "rtsp-proxy per-ip-port SYN rate",
    ):
        entries.append(
            {
                "rule": {
                    "family": "inet",
                    "table": "rtsp_proxy",
                    "comment": comment,
                }
            }
        )
    inventory: dict[str, object] = {"nftables": entries}

    validate_owned_table(inventory)
    table = entries[0]["table"]
    assert isinstance(table, dict)
    table["comment"] = "foreign"
    with pytest.raises(NftReconcileError, match="nft_table_ownership_unproven"):
        validate_owned_table(inventory)


def test_control_plane_reaches_systemd_only_through_the_scoped_unix_helper() -> None:
    helper_unit = read_unit("rtsp-proxy-node-runtime.service")
    helper = helper_unit["Service"]
    runtime_socket = read_unit("rtsp-proxy-node-runtime.socket")["Socket"]

    assert helper["User"] == "root"
    assert helper["ExecStart"] == ("/opt/rtsp-proxy/current/.venv/bin/rtsp-proxy-node-helper")
    assert helper["EnvironmentFile"] == "/etc/rtsp-proxy/node-runtime.env"
    assert helper["ReadWritePaths"] == "/etc/rtsp-proxy/nodes"
    assert helper["NoNewPrivileges"] == "yes"
    assert helper["ProtectSystem"] == "strict"
    assert helper["CapabilityBoundingSet"] == ""
    assert helper_unit["Unit"]["Requires"] == (
        "rtsp-proxy-node-runtime.socket rtsp-proxy-nftables.service"
    )
    assert helper_unit["Unit"]["Wants"] == "rtsp-proxy-auth.service"
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
    assert ".artifacts/release-venv/bin/rtsp-proxy-verify-release" in workflow
    assert "trusted_probe_ffprobe_identity" in workflow
    assert "trusted_probe_connect_guard_identity" in workflow
    assert "Download controlled probe ffprobe" in workflow
    assert "Download verified probe connect guard" in workflow
    assert ".artifacts/release/libexec/rtsp-proxy-probe/ffprobe" in workflow
    assert (
        ".artifacts/release/libexec/rtsp-proxy-probe/"
        "rtsp_probe_connect_guard.bpf.o"
    ) in workflow
    assert "Verify installed root broker transaction" in workflow
    assert "tests/contract/test_probe_broker_service.py" in workflow


def test_release_and_runtime_connect_guard_catalogs_are_exactly_aligned() -> None:
    deployment = json.loads(
        Path("deploy/artifact-catalog.json").read_text(encoding="utf-8")
    )["probe_connect_guard"]
    runtime = json.loads(
        Path("src/rtsp_proxy/artifacts/probe_connect_guard.json").read_text(
            encoding="utf-8"
        )
    )
    release = runtime["releases"][runtime["current_release_id"]]

    assert deployment["release_id"] == runtime["current_release_id"]
    assert deployment["architectures"] == release["architectures"]


def test_native_ci_enforces_coverage_with_an_independent_exit_gate() -> None:
    workflow = Path(".github/workflows/ci.yml").read_text(encoding="utf-8")
    coverage_step = workflow.split("- name: Test with coverage", 1)[1].split(
        "- name: Lint",
        1,
    )[0]

    assert "uv run pytest --cov=rtsp_proxy --cov-report=term-missing" in coverage_step
    assert "uv run coverage report --precision=2 --fail-under=90" in coverage_step


def test_packaged_migration_ci_asserts_the_current_application_schema() -> None:
    workflow = Path(".github/workflows/ci.yml").read_text(encoding="utf-8")
    migration_step = workflow.split(
        "- name: Verify packaged migrations against native PostgreSQL",
        1,
    )[1].split("- name: Validate systemd units", 1)[0]

    assert f'= "{APPLICATION_SCHEMA}"' in migration_step


def test_systemd_validation_stages_probe_broker_entrypoint() -> None:
    workflow = Path(".github/workflows/ci.yml").read_text(encoding="utf-8")
    validation_step = workflow.split("- name: Validate systemd units", 1)[1].split(
        "- name: Validate owned nftables policy",
        1,
    )[0]

    assert (
        "/opt/rtsp-proxy/releases/ci/.venv/bin/rtsp-proxy-probe-broker"
        in validation_step
    )
    assert validation_step.index("rtsp-proxy-probe-broker") < validation_step.index(
        "systemd-analyze verify"
    )


def test_native_broker_ci_stages_client_outside_the_release() -> None:
    workflow = Path(".github/workflows/ci.yml").read_text(encoding="utf-8")
    transaction_step = workflow.split(
        "- name: Verify installed root broker transaction",
        1,
    )[1].split("- name: Verify effective listener contract", 1)[0]

    client_path = "/run/rtsp-proxy-probe-contract/client.py"
    assert client_path in transaction_step
    assert "tests/fixtures/probe_broker_client.py" in transaction_step
    assert f"RTSP_PROXY_PROBE_BROKER_CLIENT={client_path}" in transaction_step
    assert "/opt/rtsp-proxy/releases/probe-contract/client.py" not in transaction_step


def test_mediamtx_patch_build_has_immutable_source_and_patch_provenance() -> None:
    catalog = json.loads(Path("deploy/artifact-catalog.json").read_text(encoding="utf-8"))
    media = catalog["mediamtx"]
    trusted = json.loads(Path("src/rtsp_proxy/artifacts/mediamtx.json").read_text(encoding="utf-8"))
    patch_path = Path(media["patch"])

    assert media["source_commit"] == "1b943637a4b5778bb929a7af7687b048fecaa03f"
    assert media["go_version"] == "go1.26.5"
    assert media["version"] == "v1.20.0-rtsp-proxy.3"
    assert hashlib.sha256(patch_path.read_bytes()).hexdigest() == media["patch_sha256"]
    gortsplib = media["gortsplib"]
    assert gortsplib["version"] == "v5.6.3"
    race_test_patch = Path(gortsplib["race_test_patch"])
    assert race_test_patch.is_file()
    assert (
        hashlib.sha256(race_test_patch.read_bytes()).hexdigest()
        == gortsplib["race_test_patch_sha256"]
    )
    gortsplib_patch = Path(gortsplib["patch"])
    assert gortsplib_patch.is_file()
    assert hashlib.sha256(gortsplib_patch.read_bytes()).hexdigest() == gortsplib["patch_sha256"]
    build_script = Path("tools/build_mediamtx.sh").read_text(encoding="utf-8")
    assert 'go mod edit -replace "github.com/bluenviron/gortsplib/v5=' in build_script
    assert build_script.count("TestServerSessionRecordStateMetricsRace") == 2
    assert "unpatched gortsplib unexpectedly passed" in build_script
    assert trusted["schema_version"] == 2
    assert trusted["releases"]["0.2.1"] == {
        "version": media["version"],
        "activation_compatible": True,
        "architectures": media["architectures"],
    }
    assert trusted["releases"]["0.2.0"]["version"] == "v1.20.0-rtsp-proxy.2"
    assert trusted["releases"]["0.2.0"]["activation_compatible"] is True
    assert trusted["releases"]["0.1.0"]["version"] == "v1.20.0-rtsp-proxy.1"
    assert trusted["releases"]["0.1.0"]["activation_compatible"] is False

    workflow = Path(".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert workflow.count("tools/build_mediamtx.sh") == 2
    assert "Download and verify MediaMTX v1.20.0" not in workflow
    assert "Download, verify and stage MediaMTX" not in workflow


def test_current_and_previous_patched_releases_have_distinct_trust_entries() -> None:
    previous_version, previous = trusted_mediamtx_identity("amd64", "0.1.0")
    previous_callback_version, previous_callback = trusted_mediamtx_identity("amd64", "0.2.0")
    current_version, current = trusted_mediamtx_identity("amd64", "0.2.1")

    assert previous_version == "v1.20.0-rtsp-proxy.1"
    assert previous.root == ("29694cbfed07896d6d47ac19a1cb450e627569b9052ad0909c1b1c0594898cc6")
    assert previous_callback_version == "v1.20.0-rtsp-proxy.2"
    assert previous_callback.root == (
        "3ca0e018599b2768a1965144aa56d55fedcc71ba1c8d4cfa279635e9e99b9198"
    )
    assert current_version == "v1.20.0-rtsp-proxy.3"
    assert current.root == ("e9cd3733549c378af566802d82980e161b957c658c27d87d5e21ddf3e4ede27f")
    assert current != previous


def test_mediamtx_source_builder_has_valid_shell_syntax() -> None:
    result = subprocess.run(
        ["sh", "-n", "tools/build_mediamtx.sh"],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr

    builder = Path("tools/build_mediamtx.sh").read_text(encoding="utf-8")
    assert "go test -race ./internal/auth ./internal/core ./internal/servers/rtsp" in builder


def test_probe_ffprobe_native_candidate_has_immutable_build_provenance() -> None:
    catalog = json.loads(Path("deploy/artifact-catalog.json").read_text(encoding="utf-8"))
    probe = catalog["probe_ffprobe"]
    trusted_probe = json.loads(
        Path("src/rtsp_proxy/artifacts/probe_ffprobe.json").read_text(encoding="utf-8")
    )
    patch = Path(probe["patch"])

    assert probe["status"] == "digest-pinned-native-candidate"
    assert probe["source_repository"] == "https://github.com/FFmpeg/FFmpeg"
    assert probe["source_commit"] == "9b6c8969e05b4f0b29f0f85cd501be6b3e582e6b"
    assert probe["source_date_epoch"] == 1_785_458_830
    assert probe["version"] == "9b6c896-rtsp-proxy.1"
    assert hashlib.sha256(patch.read_bytes()).hexdigest() == probe["patch_sha256"]
    assert probe["build_environment"] == {
        "ubuntu_snapshot": "https://snapshot.ubuntu.com/ubuntu/20260829T120000Z/",
        "packages": {
            "binutils": "2.42-4ubuntu2.10",
            "gcc": "4:13.2.0-7ubuntu1",
            "gcc-13": "13.3.0-6ubuntu2~24.04.1",
            "libc6-dev": "2.39-0ubuntu8.8",
            "make": "4.3-4.1build2",
        },
    }
    assert probe["cflags"] == ["-O2", "-fno-ident"]
    assert probe["source_prefix_map"] == "/usr/src/ffmpeg"
    assert probe["architectures"] == {
        "amd64": {
            "binary_sha256": (
                "f4daff8216f93062965b4947982cafe50cf97363c4e7b01c66f455e7a37463f3"
            )
        },
        "arm64": {
            "binary_sha256": (
                "cfebf1bf05e18d6d5dd680d890ec8bd0a6ae1e7db303bdc1ca131f51ae7ce557"
            )
        },
    }
    assert trusted_probe == {
        "schema_version": 1,
        "version": probe["version"],
        "architectures": probe["architectures"],
    }

    result = subprocess.run(
        ["sh", "-n", "tools/build_probe_ffprobe.sh"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr

    builder = Path("tools/build_probe_ffprobe.sh").read_text(encoding="utf-8")
    assert "git -C \"$source_root\" apply --check" in builder
    assert "dpkg-query" in builder
    assert (
        'export CFLAGS="$cflags -ffile-prefix-map=$source_root=$source_prefix_map"'
        in builder
    )
    flags = probe["configure_flags"]
    assert "--disable-autodetect" in flags
    assert "--disable-ffmpeg" in flags
    assert "--disable-x86asm" in flags
    assert "--enable-protocol=file,pipe,tcp" in flags
    assert "--enable-demuxer=concat,rtsp,sdp,rtp" in flags
    assert "--extra-version=rtsp-proxy.1" in flags


def test_load_fixture_builder_has_valid_bash_syntax() -> None:
    result = subprocess.run(
        ["bash", "-n", "tools/load/prepare_fixture.sh"],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr


def test_browser_e2e_cleanup_preserves_an_early_failure(tmp_path: Path) -> None:
    environment = {
        "PATH": "/usr/bin:/bin",
        "TMPDIR": str(tmp_path),
    }
    result = subprocess.run(
        ["bash", "tools/e2e/dashboard_browser.sh"],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )

    assert result.returncode != 0
    assert "agent-browser" in result.stderr
    assert list(tmp_path.iterdir()) == []


def test_browser_e2e_evidence_verifier_requires_exact_nonempty_artifacts(
    tmp_path: Path,
) -> None:
    expected_text = (
        "01-anonymous.snapshot.txt",
        "02-dashboard.snapshot.txt",
        "03-confirmation.snapshot.txt",
        "04-logged-out.snapshot.txt",
    )
    expected_png = (
        "02-dashboard.png",
        "03-confirmation.png",
        "04-logged-out.png",
    )
    for name in expected_text:
        (tmp_path / name).write_text("semantic snapshot\n", encoding="utf-8")
    for name in expected_png:
        (tmp_path / name).write_bytes(b"\x89PNG\r\n\x1a\nimage")

    verifier = Path("tools/e2e/verify_dashboard_browser_artifacts.py")
    valid = subprocess.run(
        [sys.executable, str(verifier), str(tmp_path)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert valid.returncode == 0, valid.stderr

    (tmp_path / "03-confirmation.png").write_bytes(b"not-a-png")
    invalid_png = subprocess.run(
        [sys.executable, str(verifier), str(tmp_path)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert invalid_png.returncode != 0
    assert "browser_evidence_png_invalid" in invalid_png.stderr

    (tmp_path / "03-confirmation.png").write_bytes(b"\x89PNG\r\n\x1a\nimage")
    (tmp_path / "unexpected.txt").write_text("unexpected\n", encoding="utf-8")
    unexpected = subprocess.run(
        [sys.executable, str(verifier), str(tmp_path)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert unexpected.returncode != 0
    assert "browser_evidence_file_set_invalid" in unexpected.stderr
