#!/bin/sh
EVE="$(cd "$(dirname "$0")" && pwd)/../"
PATH="$EVE/build-tools/bin:$PATH"
MKIMAGE_TAG="$(linuxkit pkg show-tag "$EVE/pkg/mkimage-iso-efi")"
SOURCE="$(cd "$1" && pwd)"
ISO="$(cd "$(dirname "$2")" && pwd)/$(basename "$2")"

if [ ! -d "$SOURCE" ] || [ $# -ne 2 ]; then
   echo "Usage: $0 <input dir> <output iso image file>"
   exit 1
fi

touch "$ISO"
docker run -t -v "$SOURCE:/bits" -v "$ISO:/output.iso" "$MKIMAGE_TAG"
