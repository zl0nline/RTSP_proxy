#!/usr/bin/env bash
set -euo pipefail

test "$(id -u)" -eq 0 || {
  printf 'bootstrap requires root\n' >&2
  exit 1
}
test -r /etc/os-release || {
  printf 'os-release unavailable\n' >&2
  exit 1
}
. /etc/os-release
test "${ID:-}" = ubuntu || {
  printf 'unsupported distribution: %s\n' "${ID:-unknown}" >&2
  exit 1
}
case "${VERSION_ID:-}" in
  24.04|26.04) ;;
  *)
    printf 'unsupported Ubuntu release: %s\n' "${VERSION_ID:-unknown}" >&2
    exit 1
    ;;
esac
case "$(uname -m)" in
  x86_64|aarch64) ;;
  *)
    printf 'unsupported architecture: %s\n' "$(uname -m)" >&2
    exit 1
    ;;
esac

bootstrap_mode=${1:---check}
case "$bootstrap_mode" in
  --check|--install) ;;
  *)
    printf 'usage: %s [--check|--install]\n' "$0" >&2
    exit 2
    ;;
esac

deploy_uv=${RTSP_PROXY_DEPLOY_UV:-/usr/local/bin/uv}
if [ "$bootstrap_mode" = --install ]; then
  apt-get -o Acquire::Retries=10 -o Acquire::https::Timeout=30 update
  DEBIAN_FRONTEND=noninteractive apt-get \
    -o Acquire::Retries=10 -o Acquire::https::Timeout=30 install --yes \
    bpftool ca-certificates curl git jq nftables openssl postgresql-client \
    systemd systemd-container
fi

test -x "$deploy_uv" || {
  printf 'trusted uv executable missing at %s\n' "$deploy_uv" >&2
  printf 'install a reviewed uv release there or set RTSP_PROXY_DEPLOY_UV\n' >&2
  exit 1
}
test "$(stat -c '%F:%u:%a' "$deploy_uv")" = 'regular file:0:755' || {
  printf 'uv must be a root-owned regular executable with mode 0755\n' >&2
  exit 1
}

python_root=/opt/rtsp-proxy/python
install -d -o root -g root -m 0755 /opt/rtsp-proxy "$python_root"
if [ "$bootstrap_mode" = --install ]; then
  UV_PYTHON_INSTALL_DIR="$python_root" "$deploy_uv" python install 3.12
fi
UV_PYTHON_INSTALL_DIR="$python_root" "$deploy_uv" python find 3.12 >/dev/null

for command in bpftool curl git jq nft openssl psql systemctl systemd-run; do
  command -v "$command" >/dev/null || {
    printf 'required command missing: %s\n' "$command" >&2
    exit 1
  }
done
test -d /sys/fs/bpf || {
  printf 'bpffs mountpoint missing: /sys/fs/bpf\n' >&2
  exit 1
}
printf 'host prerequisite check passed for Ubuntu %s %s\n' "$VERSION_ID" "$(uname -m)"
