#!/bin/sh
# Usage:
#
#      ./makeflash.sh <raw.img> [-C] <input dir> <output.img> [partitions]
#
EVE="$(cd "$(dirname "$0")" && pwd)/../"
PATH="$EVE/build-tools/bin:$PATH"
MKFLASH_TAG="$(linuxkit pkg show-tag "$EVE/pkg/$1")"
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

docker run --rm -v "$SOURCE:/parts" -v "$IMAGE:/output.img" "$MKFLASH_TAG" "$CREATE_IMG_ARG" /output.img "$@"
