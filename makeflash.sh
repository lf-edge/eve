#!/bin/sh
# Usage:
#
#      ./makeflash.sh <output.img>
#
MKFLASH_TAG="$(linuxkit pkg show-tag pkg/mkflash)-amd64"

docker run --privileged -v $1:/output.img -i ${MKFLASH_TAG} /output.img
