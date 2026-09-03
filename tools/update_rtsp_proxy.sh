#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
deploy_uv=${RTSP_PROXY_DEPLOY_UV:-/usr/local/bin/uv}
deploy_python=$(UV_PYTHON_INSTALL_DIR=/opt/rtsp-proxy/python \
  "$deploy_uv" python find 3.12)
exec "$deploy_python" -I "$repo_root/src/rtsp_proxy/deploy.py" \
  --uv "$deploy_uv" --source-root "$repo_root" update "$@"
