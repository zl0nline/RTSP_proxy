#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 1 || -z "$1" ]]; then
  echo "usage: tools/probe/build_connect_guard.sh OUTPUT" >&2
  exit 2
fi

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
output="$1"
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
    echo "unsupported probe guard architecture" >&2
    exit 2
    ;;
esac

mkdir -p "$(dirname -- "$output")"
clang -O2 -g -Wall -Werror -target bpf -D"__TARGET_ARCH_${target_arch}" \
  -I"/usr/include/${multiarch}" -I"$script_dir" \
  -c "$script_dir/rtsp_probe_connect_guard.bpf.c" -o "$output"
test -s "$output"
