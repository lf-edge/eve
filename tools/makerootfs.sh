#!/bin/sh
# Usage:
#
#     ./makerootfs.sh <image.yml> <build-dir> <fs> <output.img>
#
#     will cd to <build-dir> before running `linuxkit build`

set -e

usage() {
    echo "Usage:"
    echo
    echo "$0 <image.yml> {ext4|squash} <output.img>"
    echo "	will cd to <build-dir> before running linuxkit build"
    echo
    exit 1
}

if [ $# -ne 3 ]; then
    usage
fi

case $2 in
    ext4) MKROOTFS_PKG=mkrootfs-ext4 ;;
    squash) MKROOTFS_PKG=mkrootfs-squash ;;
    *) usage
esac
MKROOTFS_TAG="$(linuxkit pkg show-tag pkg/${MKROOTFS_PKG})"
YMLFILE=
case $1 in
    /*) YMLFILE=$1 ;;
    *) YMLFILE=$PWD/$1 ;;
esac

(cd $(dirname $3) && linuxkit build -o - $YMLFILE) | docker run -v /dev:/dev --privileged -i ${MKROOTFS_TAG} > $3
