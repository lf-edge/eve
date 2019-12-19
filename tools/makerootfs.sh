#!/bin/sh
# Usage:
#
#     ./makerootfs.sh <image.yml> <output rootfs image>  [<fs>]

set -e

EVE="$(cd "$(dirname "$0")" && pwd)/../"
PATH="$EVE/build-tools/bin:$PATH"
MKROOTFS_TAG="$(linuxkit pkg show-tag "$EVE/pkg/mkrootfs-${3:-squash}")"
YMLFILE="$1"
IMAGE="$(cd "$(dirname "$2")" && pwd)/$(basename "$2")"

if [ ! -f "$YMLFILE" ] || [ $# -lt 2 ]; then
    echo "Usage: $0 <image.yml> <output rootfs image> [{ext4|squash}]"
    exit 1
fi

linuxkit build -o - "$YMLFILE" | docker run -v /dev:/dev --privileged -i ${MKROOTFS_TAG} > "$IMAGE"
