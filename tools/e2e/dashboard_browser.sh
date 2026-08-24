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
artifact_dir=$(cd "$artifact_dir" && pwd -P)

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

javascript_string() {
  uv run python -c 'import json, sys; print(json.dumps(sys.stdin.read()))'
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

active_matches() {
  local selector_json
  selector_json=$(printf '%s' "$1" | javascript_string)
  browser eval "document.activeElement instanceof Element && document.activeElement.matches($selector_json)"
}

require_active() {
  local selector=$1
  local actual
  actual=$(active_matches "$selector")
  if [[ "$actual" != "true" ]]; then
    printf 'expected active element to match %s, got %s\n' "$selector" "$actual" >&2
    return 1
  fi
}

keyboard_activate() {
  local selector=$1
  local actual
  for _attempt in $(seq 1 40); do
    actual=$(active_matches "$selector")
    if [[ "$actual" == "true" ]]; then
      browser press Enter >/dev/null
      return
    fi
    browser press Tab >/dev/null
  done
  printf 'keyboard traversal did not reach selector: %s\n' "$selector" >&2
  return 1
}

require_contrast() {
  local selector_json minimum ratio
  selector_json=$(printf '%s' "$1" | javascript_string)
  minimum=$2
  ratio=$(browser eval "(() => {
    const element = document.querySelector($selector_json);
    if (!element) return 0;
    const parse = (value) => {
      const parts = value.match(/[0-9.]+/g).map(Number);
      return [parts[0], parts[1], parts[2], parts.length > 3 ? parts[3] : 1];
    };
    const background = (start) => {
      for (let node = start; node; node = node.parentElement) {
        const candidate = parse(getComputedStyle(node).backgroundColor);
        if (candidate[3] > 0) return candidate;
      }
      return [255, 255, 255, 1];
    };
    const luminance = (rgb) => {
      const linear = rgb.slice(0, 3).map((channel) => {
        const value = channel / 255;
        return value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4;
      });
      return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2];
    };
    const foreground = luminance(parse(getComputedStyle(element).color));
    const backdrop = luminance(background(element));
    return (Math.max(foreground, backdrop) + 0.05) / (Math.min(foreground, backdrop) + 0.05);
  })()")
  uv run python -c \
    'import sys; raise SystemExit(0 if float(sys.argv[1]) >= float(sys.argv[2]) else 1)' \
    "$ratio" "$minimum" || {
      printf 'contrast ratio %s for %s is below %s\n' "$ratio" "$1" "$minimum" >&2
      return 1
    }
}

require_secret_absent() {
  local canary=$1
  local surfaces page_errors
  surfaces=$(browser eval "(async () => {
    const cacheEntries = [];
    if ('caches' in window) {
      for (const cacheName of await caches.keys()) {
        const cache = await caches.open(cacheName);
        for (const request of await cache.keys()) {
          cacheEntries.push(request.url);
          const response = await cache.match(request);
          if (response) cacheEntries.push(await response.clone().text());
        }
      }
    }
    return JSON.stringify({
      dom: document.documentElement.outerHTML,
      cookies: document.cookie,
      localStorage: {...localStorage},
      sessionStorage: {...sessionStorage},
      cacheEntries,
      resources: performance.getEntriesByType('resource').map((entry) => entry.name),
    });
  })()")
  page_errors=$(browser errors)
  if [[ "$surfaces" == *"$canary"* || "$page_errors" == *"$canary"* ]]; then
    printf 'source secret canary leaked into a browser-visible surface\n' >&2
    return 1
  fi
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
require_contrast "body" 4.5
browser snapshot -i -c >"$artifact_dir/01-anonymous.snapshot.txt"
keyboard_activate 'a[href="/auth/oidc/login"]'
require_url_contains "/lab/idp/authorize"
require_body_text "Тестовый IdP"
keyboard_activate 'main a'
require_url_contains "/dashboard"
require_body_text "edge-browser-lab"
require_body_text "1 / 50"

browser press Tab >/dev/null
require_active ".skip-link"
require_contrast "body" 4.5
require_contrast 'a[href="/dashboard/cameras"]' 4.5
browser snapshot -i -c >"$artifact_dir/02-dashboard.snapshot.txt"
browser screenshot --full "$artifact_dir/02-dashboard.png" >/dev/null

keyboard_activate 'a[href="/dashboard/nodes/new"]'
require_url_contains "/dashboard/nodes/new"
require_body_text "Регистрация и порт"
browser find label "Имя ноды" fill "browser-created-node" >/dev/null
keyboard_activate 'form[action="/dashboard/nodes"] button'
require_url_contains "/dashboard/nodes/dddddddd-dddd-4ddd-8ddd-dddddddddddd/registered"
require_body_text "Нода зарегистрирована"
require_body_text "browser-created-node"
keyboard_activate 'a[href="/dashboard"]'
require_url_contains "/dashboard"

keyboard_activate 'a[href="/dashboard/cameras"]'
require_url_contains "/dashboard/cameras"
keyboard_activate 'a[href="/dashboard/cameras/cccccccc-cccc-4ccc-8ccc-cccccccccccc"]'
require_url_contains "/dashboard/cameras/cccccccc-cccc-4ccc-8ccc-cccccccccccc"
require_body_text "rtsp://<server-address>:10543/aaaaaaaaaaaaaaaaaaaaaaaaaa"
require_secret_absent "rtsp://source-secret-canary.invalid/private"
keyboard_activate 'a[href$="/access"]'
require_url_contains "/dashboard/cameras/cccccccc-cccc-4ccc-8ccc-cccccccccccc/access"
require_body_text "Два независимых уровня"
require_body_text "Если оба списка пусты"
browser find label "Срок, секунд" fill "3600" >/dev/null
keyboard_activate 'form[action$="/access-grants"] button'
require_body_text "Показывается только один раз"
require_body_text "browser-downstream-secret-canary-0123456789abcdef"
require_secret_absent "rtsp://source-secret-canary.invalid/private"
browser wait 3000 >/dev/null
require_url_contains "/dashboard/cameras/cccccccc-cccc-4ccc-8ccc-cccccccccccc/access"
require_body_text "Зарегистрированные grant’ы"
require_secret_absent "browser-downstream-secret-canary-0123456789abcdef"
keyboard_activate 'a[href="/dashboard/cameras/cccccccc-cccc-4ccc-8ccc-cccccccccccc"]'
require_url_contains "/dashboard/cameras/cccccccc-cccc-4ccc-8ccc-cccccccccccc"
keyboard_activate 'form[action$="/mutations/preview"] button'
require_body_text "Будет отключён 1 downstream-клиент"
require_active "h1[autofocus]"
confirmation_semantics=$(browser eval "(() => {
  const alert = document.querySelector('section[role=alert][aria-live=assertive]');
  if (!alert) return false;
  const labelledBy = alert.getAttribute('aria-labelledby');
  return Boolean(labelledBy && document.getElementById(labelledBy)?.textContent.includes('1 downstream-клиент'));
})()")
if [[ "$confirmation_semantics" != "true" ]]; then
  printf 'confirmation is missing its assertive labelled alert semantics\n' >&2
  exit 1
fi
require_contrast ".danger-button" 4.5
require_secret_absent "rtsp://source-secret-canary.invalid/private"
browser snapshot -i -c >"$artifact_dir/03-confirmation.snapshot.txt"
browser screenshot --full "$artifact_dir/03-confirmation.png" >/dev/null

keyboard_activate 'a[href="/dashboard/cameras/cccccccc-cccc-4ccc-8ccc-cccccccccccc"]'
keyboard_activate 'form[action$="/mutations/preview"] button'
require_active "h1[autofocus]"
keyboard_activate 'form[action$="/mutations/apply"] button'
require_url_contains "/dashboard/cameras/cccccccc-cccc-4ccc-8ccc-cccccccccccc"
require_body_text "DISABLED"
require_secret_absent "rtsp://source-secret-canary.invalid/private"

keyboard_activate 'a[href="/dashboard/logout"]'
require_url_contains "/dashboard/logout"
require_body_text "Завершить сеанс?"
keyboard_activate 'form[action="/dashboard/logout"] button'
require_url_contains "/dashboard"
require_body_text "Требуется вход оператора"
require_secret_absent "rtsp://source-secret-canary.invalid/private"
browser snapshot -i -c >"$artifact_dir/04-logged-out.snapshot.txt"
browser screenshot --full "$artifact_dir/04-logged-out.png" >/dev/null

page_errors=$(browser errors)
if [[ -n "$page_errors" && "$page_errors" != *"No page errors"* ]]; then
  printf 'browser page errors:\n%s\n' "$page_errors" >&2
  exit 1
fi
if grep -R -F --binary-files=text \
  "rtsp://source-secret-canary.invalid/private" "$artifact_dir" >/dev/null; then
  printf 'source secret canary leaked into browser evidence artifacts\n' >&2
  exit 1
fi
uv run python "$repo_root/tools/e2e/verify_dashboard_browser_artifacts.py" \
  "$artifact_dir"

printf 'browser E2E passed: OIDC, node registration, access grant, keyboard focus, occupied confirmation, logout\n'
