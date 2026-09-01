#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
deploy_uv=${RTSP_PROXY_DEPLOY_UV:-/usr/local/bin/uv}
exec "$repo_root/.venv/bin/python" -m rtsp_proxy.deploy \
  --uv "$deploy_uv" --source-root "$repo_root" update "$@"
