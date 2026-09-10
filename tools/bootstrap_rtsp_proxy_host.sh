#!/usr/bin/env bash
set -euo pipefail

umask 022
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
bootstrap_python=${RTSP_PROXY_BOOTSTRAP_PYTHON:-python3}

bootstrap_mode=${1:---check}
case "$bootstrap_mode" in
  --check|--install) ;;
  *)
    printf 'usage: %s [--check|--install]\n' "$0" >&2
    exit 2
    ;;
esac

deploy_uv=${RTSP_PROXY_DEPLOY_UV:-/usr/local/bin/uv}
test "$bootstrap_mode" != --install || test "$(id -u)" -eq 0 || {
  printf 'bootstrap install requires root\n' >&2
  exit 1
}
host_doctor_arguments=(
  --verify-uv
  --uv "$deploy_uv"
  --bootstrap-catalog "$repo_root/deploy/bootstrap-artifacts.json"
)
test "$bootstrap_mode" != --install || host_doctor_arguments+=(
  --install
)
"$bootstrap_python" "$repo_root/src/rtsp_proxy/host_platform.py" \
  "${host_doctor_arguments[@]}"

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
if [ "$bootstrap_mode" = --install ]; then
  install -d -o root -g root -m 0755 /opt/rtsp-proxy "$python_root"
  UV_PYTHON_INSTALL_DIR="$python_root" "$deploy_uv" python install 3.12
  find "$python_root" -type d -exec chmod a+rx,go-w {} +
  find "$python_root" -type f -exec chmod a+r,go-w {} +
  find "$python_root" -type f -perm /111 -exec chmod a+x {} +
fi
[ -d "$python_root" ] || {
  printf 'isolated Python runtime missing: %s\n' "$python_root" >&2
  exit 1
}
python_executable=$(UV_PYTHON_INSTALL_DIR="$python_root" "$deploy_uv" python find 3.12)
if find "$python_root" -type d ! -perm -0005 -print -quit | grep -q . \
  || find "$python_root" -type f ! -perm -0004 -print -quit | grep -q . \
  || find "$python_root" -type f -perm -0100 ! -perm -0001 -print -quit | grep -q .
then
  printf 'python runtime is not traversable/readable by service users: %s\n' \
    "$python_root" >&2
  exit 1
fi
test -x "$python_executable" || {
  printf 'python runtime executable unavailable: %s\n' "$python_executable" >&2
  exit 1
}

for command in curl git jq nft openssl psql systemctl systemd-run; do
  command -v "$command" >/dev/null || {
    printf 'required command missing: %s\n' "$command" >&2
    exit 1
  }
done
test -d /sys/fs/bpf || {
  printf 'bpffs mountpoint missing: /sys/fs/bpf\n' >&2
  exit 1
}
printf 'isolated Python 3.12 runtime check passed\n'
