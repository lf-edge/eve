#!/bin/sh
# Usage:
#
#      ./makeflash.sh [-C size] <output.img> [num of partitions]
#
MKFLASH_TAG="$(linuxkit pkg show-tag pkg/mkimage-raw-efi)"

if [ "$1" = "-C" ]; then
    SIZE=$2
    IMAGE=$3
    dd if=/dev/zero of=$IMAGE seek=$(( $SIZE * 1024 * 1024 - 1)) bs=1 count=1
    # If we're a non-root user, the bind mount gets permissions sensitive.
    # So we go docker^Wcowboy style
    chmod ugo+w $IMAGE
    NUMPARTS="$4"
else
    IMAGE=$1
    NUMPARTS="$2"
fi

# Docker, for unknown reasons, decides whether a passed bind mount is
# a file or a directory based on whether is a absolute pathname or a
# relative one (!).
#
# Of course, BSDs do not have the GNU specific realpath, so substitute
# it with a shell script.

case $IMAGE in
    /*) ;;
    *) IMAGE=$PWD/$IMAGE;;
esac

docker run --privileged -v $IMAGE:/output.img -i ${MKFLASH_TAG} /output.img "$NUMPARTS"
