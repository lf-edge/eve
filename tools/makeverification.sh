#!/bin/sh
# Usage:
#
#      ./makeflash.sh [-C size] <input dir> <output.img> [partitions]
#
EVE="$(cd "$(dirname "$0")" && pwd)/../"
PATH="$EVE/build-tools/bin:$PATH"
MKFLASH_TAG="$(linuxkit pkg show-tag "$EVE/pkg/mkverification-raw-efi")"

if [ "$1" = "-C" ]; then
    SIZE="$2"
    dd if=/dev/zero of="$4" seek=$(( SIZE * 1024 * 1024 - 1)) bs=1 count=1
    # If we're a non-root user, the bind mount gets permissions sensitive.
    # So we go docker^Wcowboy style
    chmod ugo+w "$4"
    shift 2
fi

SOURCE="$(cd "$1" && pwd)"
IMAGE="$(cd "$(dirname "$2")" && pwd)/$(basename "$2")"
shift 2
docker run --rm -v "$SOURCE:/parts" -v "$IMAGE:/output.img" "$MKFLASH_TAG" /output.img "$@"
