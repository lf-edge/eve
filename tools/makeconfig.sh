#!/bin/sh
# Usage:
#
#      ./makeconfig.sh <output.img> [list of config files]
#
EVE="$(cd "$(dirname "$0")" && pwd)/../"
PATH="$EVE/build-tools/bin:$PATH"
MKCONFIG_TAG="$(linuxkit pkg show-tag "$EVE/pkg/mkconf")"
IMAGE="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"

if [ $# -lt 2 ]; then
   echo "Usage: $0 <output.img> [list of config files]"
   exit 1
fi

shift

: > "$IMAGE"
(tar -chf - "$@") | docker run -i -e ZARCH -v "$IMAGE:/config.img" "${MKCONFIG_TAG}" /config.img

if [ ! -s "$IMAGE" ]; then
   echo "$IMAGE was not written."
   rm "$IMAGE"
   exit 1
fi
