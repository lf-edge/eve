#!/bin/sh
# Usage:
#
#      ./makeconfig.sh <conf dir> <output.img>
#
EVE="$(cd "$(dirname "$0")" && pwd)/../"
PATH="$EVE/build-tools/bin:$PATH"
MKCONFIG_TAG="$(linuxkit pkg show-tag "$EVE/pkg/mkconf")"
SOURCE="$(cd "$1" && pwd)"
IMAGE="$(cd "$(dirname "$2")" && pwd)/$(basename "$2")"

if [ ! -d "$SOURCE" ] || [ $# -ne 2 ]; then
   echo "Usage: $0 <input dir> <output config image file>"
   exit 1
fi

: > "$IMAGE"
(cd "$SOURCE" ; tar chf - ./*) | docker run -i -e ZARCH -v "$IMAGE:/config.img" "${MKCONFIG_TAG}" /config.img
