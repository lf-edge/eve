#!/bin/sh
# Usage:
#
#     ./makeimg.sh <image.yml> <output.img>
#
MKIMAGE_TAG="$(linuxkit pkg show-tag pkg/mkimage-raw-efi)-amd64"

linuxkit build -o - $1 | docker run -v /dev:/dev --privileged -i ${MKIMAGE_TAG} > $2
