#!/bin/sh
set -eu

release_id=""
environment_file=/etc/rtsp-proxy/control-plane/rtsp-proxy.env
username=admin
display_name="Local administrator"
with_totp=0

usage() {
  printf '%s\n' \
    'Usage: configure_local_auth.sh --release-id ID [options]' \
    '' \
    'Options:' \
    '  --environment-file PATH  active WEB environment file' \
    '  --username NAME          first local username (default: admin)' \
    '  --display-name NAME      dashboard display name' \
    '  --with-totp              show a one-time TOTP enrollment URI'
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --release-id) [ "$#" -ge 2 ] || { usage >&2; exit 2; }; release_id=$2; shift 2 ;;
    --environment-file) [ "$#" -ge 2 ] || { usage >&2; exit 2; }; environment_file=$2; shift 2 ;;
    --username) [ "$#" -ge 2 ] || { usage >&2; exit 2; }; username=$2; shift 2 ;;
    --display-name) [ "$#" -ge 2 ] || { usage >&2; exit 2; }; display_name=$2; shift 2 ;;
    --with-totp) with_totp=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) printf 'unknown argument: %s\n' "$1" >&2; usage >&2; exit 2 ;;
  esac
done

[ "$(uname -s)" = Linux ] || { printf '%s\n' 'Linux host required' >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || { printf '%s\n' 'run this command through sudo' >&2; exit 1; }
case "$release_id" in
  ''|*[!0-9A-Za-z._-]*) printf '%s\n' 'invalid release id' >&2; exit 2 ;;
esac
case "$username" in
  ''|*:*|*[!0-9A-Za-z._-]*) printf '%s\n' 'invalid local username' >&2; exit 2 ;;
esac
case "$environment_file" in
  /*) ;;
  *) printf '%s\n' 'environment file must be absolute' >&2; exit 2 ;;
esac

release_root=/opt/rtsp-proxy/releases/$release_id
operator_cli=$release_root/.venv/bin/rtsp-proxy-local-operator
example=/etc/rtsp-proxy/examples/rtsp-proxy-web-local-auth.conf.example
dropin_directory=/etc/systemd/system/rtsp-proxy-web.service.d
dropin_file=$dropin_directory/local-auth.conf
key_file=/etc/rtsp-proxy/control-plane/local-auth-key

[ -x "$operator_cli" ] || { printf '%s\n' "local operator CLI missing in $release_root" >&2; exit 1; }
[ -f "$environment_file" ] || { printf '%s\n' "environment file not found: $environment_file" >&2; exit 1; }
[ -f "$example" ] || { printf '%s\n' "local auth systemd example not found: $example" >&2; exit 1; }

database_url=$(awk '
  index($0, "RTSP_PROXY_DATABASE_URL=") == 1 {
    sub(/^RTSP_PROXY_DATABASE_URL=/, "")
    print
    found=1
    exit
  }
  END { if (!found) exit 1 }
' "$environment_file") || {
  printf '%s\n' 'RTSP_PROXY_DATABASE_URL is missing from the WEB environment file' >&2
  exit 1
}
[ -n "$database_url" ] || { printf '%s\n' 'RTSP_PROXY_DATABASE_URL is empty' >&2; exit 1; }

install -d -m 0750 -o root -g rtsp-proxy-access /etc/rtsp-proxy/control-plane
if [ ! -e "$key_file" ]; then
  key_temp=$(mktemp /etc/rtsp-proxy/control-plane/.local-auth-key.XXXXXX)
  cleanup_key() { rm -f "$key_temp"; }
  trap cleanup_key EXIT HUP INT TERM
  "$release_root/.venv/bin/python" -c \
    'import base64, secrets; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode())' \
    >"$key_temp"
  chmod 0600 "$key_temp"
  chown root:root "$key_temp"
  mv -T "$key_temp" "$key_file"
  trap - EXIT HUP INT TERM
fi

key_mode=$(stat -c '%a:%u:%g:%F' "$key_file")
[ "$key_mode" = '600:0:0:regular file' ] || {
  printf '%s\n' "unsafe local auth key: expected 600:0:0:regular file, got $key_mode" >&2
  exit 1
}

set -- --username "$username" --display-name "$display_name"
if [ "$with_totp" -eq 1 ]; then
  set -- "$@" --with-totp
fi
RTSP_PROXY_DATABASE_URL=$database_url \
RTSP_PROXY_LOCAL_AUTH_ENCRYPTION_KEY_FILE=$key_file \
  "$operator_cli" "$@"

config_temp=$(mktemp "$(dirname "$environment_file")/.rtsp-proxy.env.XXXXXX")
cleanup_config() { rm -f "$config_temp"; }
trap cleanup_config EXIT HUP INT TERM
awk '
  index($0, "RTSP_PROXY_LOCAL_AUTH_ENABLED=") == 1 { next }
  { print }
  END { print "RTSP_PROXY_LOCAL_AUTH_ENABLED=true" }
' "$environment_file" >"$config_temp"
config_mode=$(stat -c '%a' "$environment_file")
chmod "$config_mode" "$config_temp"
chown --reference="$environment_file" "$config_temp"
mv -T "$config_temp" "$environment_file"
trap - EXIT HUP INT TERM

install -d -m 0755 -o root -g root "$dropin_directory"
install -m 0644 -o root -g root "$example" "$dropin_file"
systemctl daemon-reload

printf '%s\n' \
  'Local login configured.' \
  'Start or restart rtsp-proxy-web.service, then open /auth/local/login.'
