#!/usr/bin/env bash
set -euo pipefail

profile=${1:-}
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)

case "$profile" in
  debian-13)
    image=debian:13-slim
    manager=apt-get
    prepare='apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install --yes python3'
    ;;
  fedora-42)
    image=fedora:42
    manager=dnf
    prepare='dnf install --assumeyes python3'
    ;;
  rocky-10)
    image=rockylinux/rockylinux:10
    manager=dnf
    prepare='dnf install --assumeyes python3'
    ;;
  opensuse-tumbleweed)
    image=opensuse/tumbleweed:latest
    manager=zypper
    prepare='sed -i "s|http://|https://|g" /etc/zypp/repos.d/*.repo && zypper --non-interactive install --no-recommends python3'
    ;;
  arch)
    image=archlinux:base
    manager=pacman
    prepare='pacman --sync --refresh --sysupgrade --needed --noconfirm python'
    ;;
  *)
    printf 'unknown host adapter profile: %s\n' "$profile" >&2
    exit 2
    ;;
esac

docker run --rm \
  --volume "$repo_root:/work:ro" \
  --workdir /work \
  "$image" \
  /bin/sh -ec "$prepare
PYTHONPATH=/work/src python3 /work/tools/ci/validate_host_package_adapter.py '$manager'"
