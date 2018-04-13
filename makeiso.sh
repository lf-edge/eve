#!/bin/sh
# Usage:
#
#     ./makeiso.sh <image.yml> <output.iso>
#
MKIMAGE_TAG="$(linuxkit pkg show-tag pkg/mkimage-iso-efi)"

linuxkit build -o - $1 | docker run -e ZEN_DEFAULT_BOOT -i ${MKIMAGE_TAG} > $2
