#!/bin/sh

[ -n "$DEBUG" ] && set -x

if [ -z "$DOCKER_ARCH_TAG" ] ; then
  case $(uname -m) in
    x86_64) ARCH=amd64
      ;;
    aarch64) ARCH=arm64
      ;;
    *) echo "Unsupported architecture $(uname -m). Exiting" && exit 1
      ;;
  esac
else
  ARCH="${DOCKER_ARCH_TAG}"
fi

EVE="$(cd "$(dirname "$0")" && pwd)/../"
PATH="$EVE/build-tools/bin:$PATH"
INSTALLER_TAR="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
MKIMAGE_TAG="$(linuxkit pkg show-tag "$EVE/pkg/mkimage-iso-efi")"
ISO="$(cd "$(dirname "$2")" && pwd)/$(basename "$2")"

if [ ! -f "$INSTALLER_TAR" ] || [ $# -lt 2 ]; then
   echo "Usage: $0 <input tar> <output iso image file> [installer]"
   exit 1
fi

: > "$ISO"
# shellcheck disable=SC2086
cat $INSTALLER_TAR | docker run -i --platform "linux/${ARCH}" --rm -e DEBUG="$DEBUG" -e VOLUME_LABEL=EVEISO -v "$ISO:/output.iso" "$MKIMAGE_TAG" $3
