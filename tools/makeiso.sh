#!/bin/sh

[ -n "$DEBUG" ] && set -x

EVE="$(cd "$(dirname "$0")" && pwd)/../"
PATH="$EVE/build-tools/bin:$PATH"
INSTALLER_TAR="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
# shellcheck disable=SC2086
MKIMAGE_TAG="$(linuxkit pkg ${LINUXKIT_ORG_TARGET} show-tag "$EVE/pkg/mkimage-iso-efi")"
ISO="$(cd "$(dirname "$2")" && pwd)/$(basename "$2")"

if [ ! -f "$INSTALLER_TAR" ] || [ $# -lt 2 ]; then
   echo "Usage: $0 <input tar> <output iso image file> [installer]"
   exit 1
fi

: > "$ISO"
# shellcheck disable=SC2086
cat $INSTALLER_TAR | docker run -i --rm -e DEBUG="$DEBUG" -e VOLUME_LABEL=EVEISO -v "$ISO:/output.iso" "$MKIMAGE_TAG" $3
