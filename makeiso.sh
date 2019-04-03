#!/bin/sh
# Usage:
#
#     ./makeiso.sh <image.yml> <build-dir> <output.iso>
#
MKIMAGE_TAG="$(linuxkit pkg show-tag pkg/mkimage-iso-efi)"
YMLFILE=
case $1 in
    /*) YMLFILE=$1 ;;
    *) YMLFILE=$PWD/$1 ;;
esac

(cd $2 && linuxkit build -o - $YMLFILE) | docker run -i ${MKIMAGE_TAG} > $3
