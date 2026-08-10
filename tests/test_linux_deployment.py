from configparser import ConfigParser
from pathlib import Path


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

    web = read_unit("rtsp-proxy-web.service")
    media = read_unit("mediamtx.service")
    assert web["Service"]["EnvironmentFile"] == (
        "/etc/rtsp-proxy/control-plane/rtsp-proxy.env"
    )
    assert media["Service"]["ExecStart"].endswith(
        " /etc/rtsp-proxy/mediamtx/mediamtx.yml"
    )


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
    assert service["EnvironmentFile"] == (
        "/etc/rtsp-proxy/control-plane/rtsp-proxy-%i.env"
    )


def test_native_ci_runs_the_release_verifier_against_staged_real_binaries() -> None:
    workflow = Path(".github/workflows/ci.yml").read_text(encoding="utf-8")

    assert "Verify native release manifest end to end" in workflow
    assert "uv run rtsp-proxy-verify-release --manifest" in workflow
