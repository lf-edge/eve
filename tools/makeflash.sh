#!/bin/sh
# Usage:
#
#      ./makeflash.sh <raw.img> [-C] <input dir> <output.img> [partitions]
#
EVE="$(cd "$(dirname "$0")" && pwd)/../"
PATH="$EVE/build-tools/bin:$PATH"
# shellcheck disable=SC2086
MKFLASH_TAG="$(linuxkit pkg ${LINUXKIT_ORG_TARGET} show-tag "$EVE/pkg/$1")"
shift 1

# Recreate image file
CREATE_IMG_ARG=""
if [ "$1" = "-C" ]; then
    rm -f "$3"
    touch "$3"
    chmod ugo+w "$3"
    # Pass '-C' further
    CREATE_IMG_ARG="-C"
    shift
fi

SOURCE="$(cd "$1" && pwd)"
IMAGE="$(cd "$(dirname "$2")" && pwd)/$(basename "$2")"
shift 2

docker run --rm -e DEBUG="$DEBUG" -e PLATFORM="$PLATFORM" -v "$SOURCE:/parts" -v "$IMAGE:/output.img" "$MKFLASH_TAG" "$CREATE_IMG_ARG" /output.img "$@"
