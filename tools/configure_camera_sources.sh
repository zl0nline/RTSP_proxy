#!/bin/sh
set -eu

release_id=""
source_cidrs=""
web_environment=/etc/rtsp-proxy/control-plane/rtsp-proxy.env
reconciler_environment=/etc/rtsp-proxy/control-plane/rtsp-proxy-reconciler.env
key_file=/etc/rtsp-proxy/control-plane/camera-source-keys.json

usage() {
  printf '%s\n' \
    'Usage: configure_camera_sources.sh --release-id ID --source-cidrs CIDR[,CIDR...]' \
    '' \
    'Configures the camera network allowlist and the local encryption keyring.' \
    'Run through sudo after installing the release and before adding cameras.'
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --release-id) [ "$#" -ge 2 ] || { usage >&2; exit 2; }; release_id=$2; shift 2 ;;
    --source-cidrs) [ "$#" -ge 2 ] || { usage >&2; exit 2; }; source_cidrs=$2; shift 2 ;;
    --web-environment) [ "$#" -ge 2 ] || { usage >&2; exit 2; }; web_environment=$2; shift 2 ;;
    --reconciler-environment) [ "$#" -ge 2 ] || { usage >&2; exit 2; }; reconciler_environment=$2; shift 2 ;;
    --key-file) [ "$#" -ge 2 ] || { usage >&2; exit 2; }; key_file=$2; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) printf 'unknown argument: %s\n' "$1" >&2; usage >&2; exit 2 ;;
  esac
done

[ "$(uname -s)" = Linux ] || { printf '%s\n' 'Linux host required' >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || { printf '%s\n' 'run this command through sudo' >&2; exit 1; }
case "$release_id" in
  ''|.|..|*[!0-9A-Za-z._-]*) printf '%s\n' 'invalid release id' >&2; exit 2 ;;
esac
[ -n "$source_cidrs" ] || {
  printf '%s\n' 'source CIDRs must not be empty (empty policy intentionally denies every camera)' >&2
  exit 2
}
case "$source_cidrs" in
  *[!0-9A-Fa-f:.,/[:space:]]*) printf '%s\n' 'source CIDRs contain invalid characters' >&2; exit 2 ;;
esac
for path in "$web_environment" "$reconciler_environment" "$key_file"; do
  case "$path" in /*) ;; *) printf '%s\n' 'all paths must be absolute' >&2; exit 2 ;; esac
done

release_python=/opt/rtsp-proxy/releases/$release_id/.venv/bin/python
[ -x "$release_python" ] || { printf '%s\n' "release Python missing: $release_python" >&2; exit 1; }
"$release_python" -c \
  'import ipaddress,sys; values=[v.strip() for v in sys.argv[1].split(",")]; assert values and all(values); [ipaddress.ip_network(v, strict=True) for v in values]' \
  "$source_cidrs" >/dev/null 2>&1 || {
  printf '%s\n' 'source CIDRs must be canonical comma-separated IPv4/IPv6 networks' >&2
  exit 2
}
[ -f "$web_environment" ] || { printf '%s\n' "environment file missing: $web_environment" >&2; exit 1; }
[ -f "$reconciler_environment" ] || { printf '%s\n' "environment file missing: $reconciler_environment" >&2; exit 1; }

install -d -m 0750 -o root -g rtsp-proxy-access "$(dirname "$key_file")"
if [ ! -e "$key_file" ]; then
  key_temp=$(mktemp "$(dirname "$key_file")/.camera-source-keys.XXXXXX")
  cleanup_key() { rm -f "$key_temp"; }
  trap cleanup_key EXIT HUP INT TERM
  "$release_python" -c \
    'import base64,json,secrets; print(json.dumps({"primary_key_id":"initial","keys":{"initial":base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()}},separators=(",",":")))' \
    >"$key_temp"
  chmod 0640 "$key_temp"
  chown root:rtsp-proxy-access "$key_temp"
  mv -T "$key_temp" "$key_file"
  trap - EXIT HUP INT TERM
fi

key_mode=$(stat -c '%a:%U:%G:%F:%h' "$key_file")
[ "$key_mode" = '640:root:rtsp-proxy-access:regular file:1' ] || {
  printf '%s\n' "unsafe camera keyring: expected 640:root:rtsp-proxy-access:regular file:1, got $key_mode" >&2
  exit 1
}

update_environment() {
  target_file=$1
  target_temp=$(mktemp "$(dirname "$target_file")/.camera-source-env.XXXXXX")
  awk '
    index($0, "RTSP_PROXY_PROBE_SOURCE_CIDRS=") == 1 { next }
    index($0, "RTSP_PROXY_CAMERA_SOURCE_KEYS_FILE=") == 1 { next }
    { print }
  ' "$target_file" >"$target_temp"
  printf 'RTSP_PROXY_PROBE_SOURCE_CIDRS=%s\n' "$source_cidrs" >>"$target_temp"
  printf 'RTSP_PROXY_CAMERA_SOURCE_KEYS_FILE=%s\n' "$key_file" >>"$target_temp"
  chmod "$(stat -c '%a' "$target_file")" "$target_temp"
  chown --reference="$target_file" "$target_temp"
  mv -T "$target_temp" "$target_file"
}

update_environment "$web_environment"
update_environment "$reconciler_environment"

printf '%s\n' \
  'Camera source policy and encrypted credential storage configured.' \
  'Restart rtsp-proxy-web.service and rtsp-proxy@reconciler.service.'
