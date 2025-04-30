#!/bin/sh
# Usage:
#
#      ./makeconfig.sh <output.img> <version> [list of config files]
#
EVE="$(cd "$(dirname "$0")" && pwd)/../"
PATH="$EVE/build-tools/bin:$PATH"
# shellcheck disable=SC2086
MKCONFIG_TAG="$(linuxkit pkg ${LINUXKIT_ORG_TARGET} show-tag "$EVE/pkg/mkconf")"
IMAGE="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
ROOTFS_VERSION="$2"

if [ $# -lt 3 ]; then
   echo "Usage: $0 <output.img> <version> [list of config files]"
   exit 1
fi

shift 2

: > "$IMAGE"
(tar -chf - "$@") | docker run -i --rm -e ROOTFS_VERSION="$ROOTFS_VERSION" -e ZARCH="$ZARCH" -v "$IMAGE:/config.img" "${MKCONFIG_TAG}" /config.img

if [ ! -s "$IMAGE" ]; then
   echo "$IMAGE was not written."
   rm "$IMAGE"
   exit 1
fi
