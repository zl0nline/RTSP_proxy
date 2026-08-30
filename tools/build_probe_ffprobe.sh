#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
    echo "usage: $0 <amd64|arm64> <output>" >&2
    exit 64
fi

architecture=$1
output=$2
case "$architecture" in
    amd64) expected_machine=x86_64 ;;
    arm64) expected_machine=aarch64 ;;
    *)
        echo "unsupported probe ffprobe architecture: $architecture" >&2
        exit 64
        ;;
esac
if [ "$(uname -m)" != "$expected_machine" ]; then
    echo "probe ffprobe requires native $expected_machine execution" >&2
    exit 1
fi

umask 022
mkdir -p "$(dirname -- "$output")"
output_directory=$(CDPATH= cd -- "$(dirname -- "$output")" && pwd)
output="$output_directory/$(basename -- "$output")"

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
catalog="$repo_root/deploy/artifact-catalog.json"
source_repository=$(jq --raw-output '.probe_ffprobe.source_repository' "$catalog")
source_commit=$(jq --raw-output '.probe_ffprobe.source_commit' "$catalog")
source_date_epoch=$(jq --raw-output '.probe_ffprobe.source_date_epoch' "$catalog")
patch_path=$(jq --raw-output '.probe_ffprobe.patch' "$catalog")
patch_sha256=$(jq --raw-output '.probe_ffprobe.patch_sha256' "$catalog")
compiler=$(jq --raw-output '.probe_ffprobe.compiler' "$catalog")
compiler_major=$(jq --raw-output '.probe_ffprobe.compiler_major' "$catalog")
expected_version=$(jq --raw-output '.probe_ffprobe.version' "$catalog")
candidate_status=$(jq --exit-status --raw-output '.probe_ffprobe.status' "$catalog")
source_prefix_map=$(
    jq --exit-status --raw-output '.probe_ffprobe.source_prefix_map' "$catalog"
)
case "$candidate_status" in
    source-only) expected_binary_sha256= ;;
    digest-pinned-native-candidate)
        expected_binary_sha256=$(
            jq --exit-status --raw-output --arg arch "$architecture" \
                '.probe_ffprobe.architectures[$arch].binary_sha256' "$catalog"
        )
        ;;
    *)
        echo "unsupported probe ffprobe candidate status: $candidate_status" >&2
        exit 1
        ;;
esac

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

actual_patch_sha256=$(sha256_of "$repo_root/$patch_path")
if [ "$actual_patch_sha256" != "$patch_sha256" ]; then
    echo "probe ffprobe patch SHA-256 mismatch" >&2
    exit 1
fi
if [ "$compiler" != "gcc" ]; then
    echo "unsupported probe ffprobe compiler: $compiler" >&2
    exit 1
fi
if ! command -v dpkg-query >/dev/null 2>&1; then
    echo "probe ffprobe requires the catalog-pinned Ubuntu build environment" >&2
    exit 1
fi
packages_file=$(mktemp)
trap 'rm -f -- "$packages_file"' EXIT HUP INT TERM
jq --raw-output \
    '.probe_ffprobe.build_environment.packages | to_entries[] | [.key, .value] | @tsv' \
    "$catalog" > "$packages_file"
tab=$(printf '\t')
while IFS="$tab" read -r package expected_package_version; do
    actual_package_version=$(
        dpkg-query --show --showformat='${Version}' "$package" 2>/dev/null
    ) || {
        echo "probe ffprobe build package is missing: $package" >&2
        exit 1
    }
    if [ "$actual_package_version" != "$expected_package_version" ]; then
        echo "probe ffprobe requires $package=$expected_package_version" >&2
        exit 1
    fi
done < "$packages_file"
actual_compiler_major=$(gcc -dumpfullversion | awk -F. '{print $1}')
if [ "$actual_compiler_major" != "$compiler_major" ]; then
    echo "probe ffprobe requires gcc major $compiler_major" >&2
    exit 1
fi

build_root=$(mktemp -d)
trap 'rm -rf -- "$build_root"; rm -f -- "$packages_file"' EXIT HUP INT TERM
source_root="$build_root/ffmpeg"
object_root="$build_root/build"
flags_file="$build_root/configure-flags"

git init --quiet "$source_root"
git -C "$source_root" remote add origin "$source_repository"
git -C "$source_root" fetch --quiet --depth 1 origin "$source_commit"
git -C "$source_root" checkout --quiet --detach FETCH_HEAD
test "$(git -C "$source_root" rev-parse HEAD)" = "$source_commit"
git -C "$source_root" apply --check "$repo_root/$patch_path"
git -C "$source_root" apply "$repo_root/$patch_path"

jq --raw-output '.probe_ffprobe.configure_flags[]' "$catalog" > "$flags_file"
set --
while IFS= read -r flag; do
    set -- "$@" "$flag"
done < "$flags_file"
cflags=$(jq --exit-status --raw-output '.probe_ffprobe.cflags | join(" ")' "$catalog")

mkdir "$object_root"
(
    cd "$object_root"
    export LC_ALL=C
    export TZ=UTC
    export SOURCE_DATE_EPOCH="$source_date_epoch"
    export ZERO_AR_DATE=1
    export CFLAGS="$cflags -ffile-prefix-map=$source_root=$source_prefix_map"
    "$source_root/configure" "$@"
    make -j2 ffprobe
)

actual_version=$(
    "$object_root/ffprobe" -version | awk 'NR == 1 {print $3}'
)
if [ "$actual_version" != "$expected_version" ]; then
    echo "probe ffprobe version mismatch: expected $expected_version, got $actual_version" >&2
    exit 1
fi
install -m 0755 "$object_root/ffprobe" "$output"
actual_binary_sha256=$(sha256_of "$output")
if [ -n "$expected_binary_sha256" ] && \
    [ "$actual_binary_sha256" != "$expected_binary_sha256" ]; then
    echo "probe ffprobe binary SHA-256 mismatch: expected $expected_binary_sha256, got $actual_binary_sha256" >&2
    exit 1
fi
printf '%s  %s\n' "$actual_binary_sha256" "$output"
