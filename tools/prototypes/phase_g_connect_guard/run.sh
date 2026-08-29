#!/usr/bin/env bash
# PROTOTYPE ONLY: prove systemd address-only filtering and exact cgroup IP:port filtering.
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  echo "run as root: sudo tools/prototypes/phase_g_connect_guard/run.sh" >&2
  exit 2
fi

prototype_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
work_dir="$(mktemp -d /run/rtsp-probe-connect-guard.XXXXXX)"
work_name="$(basename -- "$work_dir")"
unit_prefix="rtsp-probe-prototype-${work_name##*.}"
baseline_unit="${unit_prefix}-baseline.service"
guarded_unit="${unit_prefix}-guarded.service"
baseline_runtime="${unit_prefix}-baseline"
guarded_runtime="${unit_prefix}-guarded"
pin_dir="/sys/fs/bpf/${unit_prefix}"
allowed_port=39001
denied_port=39002
server_pid=""
guarded_cgroup=""
ipv4_attached=0
ipv6_attached=0

cleanup() {
  set +e
  if [[ "$ipv4_attached" -eq 1 && -n "$guarded_cgroup" ]]; then
    bpftool cgroup detach "/sys/fs/cgroup${guarded_cgroup}" \
      cgroup_inet4_connect pinned "$pin_dir/guard_ipv4"
  fi
  if [[ "$ipv6_attached" -eq 1 && -n "$guarded_cgroup" ]]; then
    bpftool cgroup detach "/sys/fs/cgroup${guarded_cgroup}" \
      cgroup_inet6_connect pinned "$pin_dir/guard_ipv6"
  fi
  touch "$work_dir/baseline.exit" "$work_dir/guarded.exit"
  systemctl stop "$baseline_unit" "$guarded_unit" >/dev/null 2>&1
  if [[ -n "$server_pid" ]]; then
    kill "$server_pid" >/dev/null 2>&1
    wait "$server_pid" >/dev/null 2>&1
  fi
  rm -f "$pin_dir/guard_ipv4" "$pin_dir/guard_ipv6"
  rmdir "$pin_dir" >/dev/null 2>&1
  rm -f "/run/$baseline_runtime/result.json" "/run/$guarded_runtime/result.json"
  rmdir "/run/$baseline_runtime" "/run/$guarded_runtime" >/dev/null 2>&1
  rm -f "$work_dir/guard.bpf.o" "$work_dir/probe_net.py" \
    "$work_dir/fixture.ready" "$work_dir/baseline.gate" \
    "$work_dir/baseline.exit" "$work_dir/guarded.gate" "$work_dir/guarded.exit"
  rmdir "$work_dir" >/dev/null 2>&1
}
trap cleanup EXIT INT TERM

case "$(uname -m)" in
  x86_64)
    target_arch=x86
    multiarch=x86_64-linux-gnu
    ;;
  aarch64)
    target_arch=arm64
    multiarch=aarch64-linux-gnu
    ;;
  *)
    echo "unsupported prototype architecture" >&2
    exit 2
    ;;
esac

install -m 0555 "$prototype_dir/probe_net.py" "$work_dir/probe_net.py"
chmod 0755 "$work_dir"
clang -O2 -g -target bpf -D"__TARGET_ARCH_${target_arch}" \
  -D"ALLOWED_PORT=${allowed_port}" -I"/usr/include/${multiarch}" \
  -c "$prototype_dir/guard.bpf.c" -o "$work_dir/guard.bpf.o"

"$work_dir/probe_net.py" serve \
  --allowed-port "$allowed_port" --denied-port "$denied_port" \
  --ready "$work_dir/fixture.ready" &
server_pid=$!
for _attempt in {1..100}; do
  [[ -e "$work_dir/fixture.ready" ]] && break
  sleep 0.02
done
[[ -e "$work_dir/fixture.ready" ]]

start_canary() {
  local unit="$1"
  local runtime="$2"
  local gate="$3"
  local exit_gate="$4"
  systemd-run --quiet --no-block --unit "$unit" --service-type=exec \
    --property=DynamicUser=yes \
    --property=NoNewPrivileges=yes \
    --property=CapabilityBoundingSet= \
    --property=AmbientCapabilities= \
    --property=ProtectSystem=strict \
    --property=ProtectHome=yes \
    --property=PrivateDevices=yes \
    --property=ProtectKernelTunables=yes \
    --property=ProtectKernelModules=yes \
    --property=ProtectControlGroups=yes \
    --property=RestrictSUIDSGID=yes \
    --property=LockPersonality=yes \
    --property=RestrictRealtime=yes \
    --property="RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6" \
    --property=SocketBindDeny=any \
    --property=IPAddressDeny=any \
    --property=IPAddressAllow=127.0.0.1/32 \
    --property=IPAddressAllow=::1/128 \
    --property=MemoryMax=64M \
    --property=MemorySwapMax=0 \
    --property=TasksMax=8 \
    --property=LimitNOFILE=64 \
    --property=RuntimeMaxSec=20 \
    --property=TimeoutStopSec=2 \
    --property=KillMode=control-group \
    --property="RuntimeDirectory=$runtime" \
    --property=RuntimeDirectoryMode=0700 \
    --property=RuntimeDirectoryPreserve=yes \
    /usr/bin/python3 "$work_dir/probe_net.py" check \
      --allowed-port "$allowed_port" --denied-port "$denied_port" \
      --gate "$gate" --exit-gate "$exit_gate" \
      --output "/run/$runtime/result.json"
}

wait_for_unit_cgroup() {
  local unit="$1"
  local cgroup=""
  for _attempt in {1..100}; do
    cgroup="$(systemctl show --property=ControlGroup --value "$unit")"
    [[ -n "$cgroup" ]] && break
    sleep 0.02
  done
  [[ -n "$cgroup" ]]
  printf '%s\n' "$cgroup"
}

wait_for_result() {
  local output="$1"
  for _attempt in {1..200}; do
    [[ -s "$output" ]] && return 0
    sleep 0.02
  done
  return 1
}

start_canary "$baseline_unit" "$baseline_runtime" \
  "$work_dir/baseline.gate" "$work_dir/baseline.exit"
wait_for_unit_cgroup "$baseline_unit" >/dev/null
touch "$work_dir/baseline.gate"
wait_for_result "/run/$baseline_runtime/result.json"
"$work_dir/probe_net.py" validate --output "/run/$baseline_runtime/result.json"
touch "$work_dir/baseline.exit"

start_canary "$guarded_unit" "$guarded_runtime" \
  "$work_dir/guarded.gate" "$work_dir/guarded.exit"
guarded_cgroup="$(wait_for_unit_cgroup "$guarded_unit")"
mkdir "$pin_dir"
bpftool prog loadall "$work_dir/guard.bpf.o" "$pin_dir"
bpftool cgroup attach "/sys/fs/cgroup${guarded_cgroup}" \
  cgroup_inet4_connect pinned "$pin_dir/guard_ipv4"
ipv4_attached=1
bpftool cgroup attach "/sys/fs/cgroup${guarded_cgroup}" \
  cgroup_inet6_connect pinned "$pin_dir/guard_ipv6"
ipv6_attached=1
bpftool cgroup show "/sys/fs/cgroup${guarded_cgroup}"

touch "$work_dir/guarded.gate"
wait_for_result "/run/$guarded_runtime/result.json"
"$work_dir/probe_net.py" validate \
  --output "/run/$guarded_runtime/result.json" --guarded

bpftool cgroup detach "/sys/fs/cgroup${guarded_cgroup}" \
  cgroup_inet4_connect pinned "$pin_dir/guard_ipv4"
ipv4_attached=0
bpftool cgroup detach "/sys/fs/cgroup${guarded_cgroup}" \
  cgroup_inet6_connect pinned "$pin_dir/guard_ipv6"
ipv6_attached=0
if bpftool cgroup show "/sys/fs/cgroup${guarded_cgroup}" | \
  grep -Eq 'guard_ipv4|guard_ipv6'; then
  echo "prototype guard remained attached after detach" >&2
  exit 1
fi
touch "$work_dir/guarded.exit"

echo "PASS: systemd address policy admitted both ports; cgroup connect4/connect6 guard admitted only ${allowed_port}."
