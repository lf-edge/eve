#!/bin/sh
# Usage:
#
#     ./makerootfs.sh <image.yml> <output.img>
#
MKROOTFS_TAG="$(linuxkit pkg show-tag pkg/mkrootfs-ext4)-amd64"

linuxkit build -o - $1 | docker run -v /dev:/dev --privileged -i ${MKROOTFS_TAG} > $2
