#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 1 || -z "$1" ]]; then
  echo "usage: tools/probe/build_connect_guard.sh OUTPUT" >&2
  exit 2
fi

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
output="$1"
compiler="${RTSP_PROXY_PROBE_CLANG:-clang}"
if [[ "$compiler" == */* ]]; then
  [[ "$compiler" == /* && -x "$compiler" ]]
else
  command -v "$compiler" >/dev/null
fi
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
"$compiler" -O2 -g -Wall -Werror -target bpf -D"__TARGET_ARCH_${target_arch}" \
  -ffile-prefix-map="$script_dir=/usr/src/rtsp-proxy/probe" \
  -fdebug-prefix-map="$script_dir=/usr/src/rtsp-proxy/probe" \
  -I"/usr/include/${multiarch}" -I"$script_dir" \
  -c "$script_dir/rtsp_probe_connect_guard.bpf.c" -o "$output"
test -s "$output"
