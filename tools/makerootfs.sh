#!/bin/bash
# Usage:
#
#     ./makerootfs.sh <image.yml> <output rootfs image> <fs> <arch>
# <fs> defaults to squash
# <arch> defaults to the current machine architecture

set -e
set -o pipefail

EVE="$(cd "$(dirname "$0")" && pwd)/../"
PATH="$EVE/build-tools/bin:$PATH"
MKROOTFS_TAG="$(linuxkit pkg show-tag "$EVE/pkg/mkrootfs-${3:-squash}")"
YMLFILE="$1"
IMAGE="$(cd "$(dirname "$2")" && pwd)/$(basename "$2")"

if [ ! -f "$YMLFILE" ] || [ $# -lt 2 ]; then
    echo "Usage: $0 <image.yml> <output rootfs image> [{ext4|squash}]"
    exit 1
fi

# did we specify an architecture?
ARCH="$4"
ARCHARG=""
if [ -n "$ARCH" ]; then
  ARCHARG="-arch ${ARCH}"
fi

: > "$IMAGE"
linuxkit build -docker ${ARCHARG} -o - "$YMLFILE" | docker run -i --rm -v /dev:/dev --privileged -v "$IMAGE:/rootfs.img" "${MKROOTFS_TAG}"
