#!/bin/sh
# Usage:
#
#      ./makeconfig.sh <conf dir> <output.img>
#
MKCONFIG_TAG="$(linuxkit pkg show-tag pkg/mkconf)"
SOURCE="$(cd "$1" && pwd)"
IMAGE="$(cd "$(dirname "$2")" && pwd)/$(basename "$2")"

if [ ! -d "$SOURCE" ] || [ $# -ne 2 ]; then
   echo "Usage: $0 <input dir> <output config image file>"
   exit 1
fi

touch "$IMAGE"
(cd "$SOURCE" ; tar chf - ./*) | docker run -e ZARCH -i -v "$IMAGE:/config.img" "${MKCONFIG_TAG}" /config.img
