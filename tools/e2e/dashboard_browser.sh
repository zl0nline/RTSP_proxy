#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
work_dir=$(mktemp -d "${TMPDIR:-/tmp}/rtsp-proxy-browser-e2e.XXXXXX")
session="rtsp-proxy-e2e-$$"
server_pid=""
artifact_dir=${RTSP_PROXY_BROWSER_ARTIFACT_DIR:-"$work_dir/artifacts"}
browser_no_sandbox=${RTSP_PROXY_BROWSER_NO_SANDBOX:-0}

cleanup() {
  local status=$?
  trap - EXIT
  agent-browser --session "$session" close >/dev/null 2>&1 || true
  if [[ -n "$server_pid" ]]; then
    kill "$server_pid" >/dev/null 2>&1 || true
    wait "$server_pid" >/dev/null 2>&1 || true
  fi
  case "$work_dir" in
    "${TMPDIR:-/tmp}/rtsp-proxy-browser-e2e."*) rm -rf -- "$work_dir" ;;
  esac
  exit "$status"
}
trap cleanup EXIT

if ! command -v agent-browser >/dev/null; then
  printf 'agent-browser is required for dashboard browser E2E\n' >&2
  exit 127
fi
if ! command -v openssl >/dev/null; then
  printf 'openssl is required for dashboard browser E2E\n' >&2
  exit 127
fi
mkdir -p "$artifact_dir"

openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -keyout "$work_dir/tls.key" \
  -out "$work_dir/tls.crt" \
  -subj "/CN=127.0.0.1" \
  -addext "subjectAltName=IP:127.0.0.1" \
  >/dev/null 2>&1

port=$(uv run python -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')
origin="https://127.0.0.1:$port"
uv run python tests/browser/dashboard_lab.py \
  --host 127.0.0.1 \
  --port "$port" \
  --certificate "$work_dir/tls.crt" \
  --key "$work_dir/tls.key" \
  >"$work_dir/server.log" 2>&1 &
server_pid=$!

for _attempt in $(seq 1 100); do
  if curl --silent --show-error --fail --insecure "$origin/health/live" >/dev/null 2>&1; then
    break
  fi
  if ! kill -0 "$server_pid" >/dev/null 2>&1; then
    sed -n '1,240p' "$work_dir/server.log" >&2
    exit 1
  fi
  sleep 0.1
done
curl --silent --show-error --fail --insecure "$origin/health/live" >/dev/null

browser() {
  agent-browser --session "$session" "$@"
}

require_body_text() {
  local expected=$1
  local body
  body=$(browser get text body)
  if [[ "$body" != *"$expected"* ]]; then
    printf 'expected browser body text not found: %s\n%s\n' "$expected" "$body" >&2
    return 1
  fi
}

require_url_contains() {
  local expected=$1
  local current
  current=$(browser get url)
  if [[ "$current" != *"$expected"* ]]; then
    printf 'expected browser URL fragment not found: %s\n%s\n' "$expected" "$current" >&2
    return 1
  fi
}

activate() {
  browser focus "$1" >/dev/null
  browser press Enter >/dev/null
}

if [[ "$browser_no_sandbox" == "1" ]]; then
  # Only for an isolated disposable CI/lab host whose AppArmor policy disables
  # Chromium user namespaces. The production dashboard never launches a browser.
  agent-browser --session "$session" --args "--no-sandbox" \
    --ignore-https-errors open "$origin/dashboard" >/dev/null
else
  agent-browser --session "$session" \
    --ignore-https-errors open "$origin/dashboard" >/dev/null
fi
require_body_text "Требуется вход оператора"
browser snapshot -i -c >"$artifact_dir/01-anonymous.snapshot.txt"
activate 'a[href="/auth/oidc/login"]'
require_url_contains "/lab/idp/authorize"
require_body_text "Тестовый IdP"
activate 'main a'
require_url_contains "/dashboard"
require_body_text "edge-browser-lab"
require_body_text "1 / 50"

browser press Tab >/dev/null
focused_class=$(browser eval "document.activeElement.className")
if [[ "$focused_class" != *"skip-link"* ]]; then
  printf 'skip link is not the first keyboard focus target: %s\n' "$focused_class" >&2
  exit 1
fi
browser snapshot -i -c >"$artifact_dir/02-dashboard.snapshot.txt"
browser screenshot --full "$artifact_dir/02-dashboard.png" >/dev/null

activate 'a[href="/dashboard/cameras"]'
require_url_contains "/dashboard/cameras"
activate 'a[href="/dashboard/cameras/cccccccc-cccc-4ccc-8ccc-cccccccccccc"]'
require_url_contains "/dashboard/cameras/cccccccc-cccc-4ccc-8ccc-cccccccccccc"
require_body_text "rtsp://<server-address>:10543/aaaaaaaaaaaaaaaaaaaaaaaaaa"
activate 'form[action$="/mutations/preview"] button'
require_body_text "Будет отключён 1 downstream-клиент"
browser snapshot -i -c >"$artifact_dir/03-confirmation.snapshot.txt"
browser screenshot --full "$artifact_dir/03-confirmation.png" >/dev/null

activate 'a[href="/dashboard/cameras/cccccccc-cccc-4ccc-8ccc-cccccccccccc"]'
activate 'form[action$="/mutations/preview"] button'
activate 'form[action$="/mutations/apply"] button'
require_url_contains "/dashboard/cameras/cccccccc-cccc-4ccc-8ccc-cccccccccccc"
require_body_text "DISABLED"

activate 'a[href="/dashboard/logout"]'
require_url_contains "/dashboard/logout"
require_body_text "Завершить сеанс?"
activate 'form[action="/dashboard/logout"] button'
require_url_contains "/dashboard"
require_body_text "Требуется вход оператора"
browser snapshot -i -c >"$artifact_dir/04-logged-out.snapshot.txt"
browser screenshot --full "$artifact_dir/04-logged-out.png" >/dev/null

page_errors=$(browser errors)
if [[ -n "$page_errors" && "$page_errors" != *"No page errors"* ]]; then
  printf 'browser page errors:\n%s\n' "$page_errors" >&2
  exit 1
fi

printf 'browser E2E passed: OIDC, keyboard focus, occupied confirmation, logout\n'
