#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
    echo "usage: $0 <amd64|arm64> <output>" >&2
    exit 64
fi

architecture=$1
output=$2
case "$architecture" in
    amd64|arm64) ;;
    *)
        echo "unsupported MediaMTX architecture: $architecture" >&2
        exit 64
        ;;
esac

mkdir -p "$(dirname -- "$output")"
output_directory=$(CDPATH= cd -- "$(dirname -- "$output")" && pwd)
output="$output_directory/$(basename -- "$output")"

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
catalog="$repo_root/deploy/artifact-catalog.json"
source_repository=$(jq --raw-output '.mediamtx.source_repository' "$catalog")
source_commit=$(jq --raw-output '.mediamtx.source_commit' "$catalog")
patch_path=$(jq --raw-output '.mediamtx.patch' "$catalog")
patch_sha256=$(jq --raw-output '.mediamtx.patch_sha256' "$catalog")
expected_go_version=$(jq --raw-output '.mediamtx.go_version' "$catalog")
version=$(jq --raw-output '.mediamtx.version' "$catalog")
expected_binary_sha256=$(
    jq --raw-output --arg arch "$architecture" \
        '.mediamtx.architectures[$arch].binary_sha256' "$catalog"
)

sha256_check() {
    expected=$1
    path=$2
    if command -v sha256sum >/dev/null 2>&1; then
        actual=$(sha256sum "$path" | awk '{print $1}')
    else
        actual=$(shasum -a 256 "$path" | awk '{print $1}')
    fi
    if [ "$actual" != "$expected" ]; then
        echo "SHA-256 mismatch for $path: expected $expected, got $actual" >&2
        exit 1
    fi
}

if [ "$(go version | awk '{print $3}')" != "$expected_go_version" ]; then
    echo "MediaMTX requires $expected_go_version" >&2
    exit 1
fi
sha256_check "$patch_sha256" "$repo_root/$patch_path"

build_root=$(mktemp -d)
trap 'rm -rf -- "$build_root"' EXIT HUP INT TERM
source_root="$build_root/mediamtx"

git init --quiet "$source_root"
git -C "$source_root" remote add origin "$source_repository"
git -C "$source_root" fetch --quiet --depth 1 origin "$source_commit"
git -C "$source_root" checkout --quiet --detach FETCH_HEAD
test "$(git -C "$source_root" rev-parse HEAD)" = "$source_commit"
git -C "$source_root" apply --check "$repo_root/$patch_path"
git -C "$source_root" apply "$repo_root/$patch_path"

(
    cd "$source_root"
    go generate ./...
    go test -race ./internal/auth ./internal/core ./internal/servers/rtsp
)
printf '%s\n' "$version" > "$source_root/internal/core/VERSION"

CGO_ENABLED=0 GOOS=linux GOARCH="$architecture" \
    go build -C "$source_root" -trimpath -buildvcs=false -o "$output" .
chmod 0755 "$output"
sha256_check "$expected_binary_sha256" "$output"
