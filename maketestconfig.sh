#!/bin/sh
# Usage:
#
#      ./makeflash.sh <output.img>
#
MKCONFIG_TAG="$(linuxkit pkg show-tag pkg/test-conf)-amd64"

IMAGE=$1

# Ensure existence of image file
touch $IMAGE

# Docker, for unknown reasons, decides whether a passed bind mount is
# a file or a directory based on whether is a absolute pathname or a
# relative one (!).
#
# Of course, BSDs do not have the GNU specific realpath, so substitute
# it with a shell script.

case $1 in
    /*) ;;
    *) IMAGE=$PWD/$IMAGE;;
esac

docker run --privileged -v $IMAGE:/config.img -i ${MKCONFIG_TAG} /config.img
