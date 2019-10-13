#!/bin/sh
# Usage:
#
#      ./makeusbconf.sh [-d] [-i] [-s <size in Kb>] [-f <file> ] <output.img>
#
MKFLASH_TAG="$(linuxkit pkg show-tag pkg/mkimage-raw-efi)"

usage() {
    echo "Usage: $0 [-d] [-i] [-s <size in Kb>] [-f <file> ] <output.img>"
}

cleanup() {
    rm $TMPDIR/* 2>/dev/null
    rmdir $TMPDIR
}

SIZE=204800
TMPDIR=$(mktemp -d)

while getopts dif:s: o
do      case "$o" in
        d)      mkdir $TMPDIR/dump;;
        i)      mkdir $TMPDIR/identity;;
        f)      cp $OPTARG $TMPDIR/usb.json;;
        s)      SIZE=$OPTARG;;
        [?])    usage
                exit 1;;
        esac
done

shift $((OPTIND-1))

[ $# != 1 ] && cleanup && usage && exit 1

IMAGE=$1
[ -f $IMAGE ] || dd if=/dev/zero of=$IMAGE seek=$SIZE bs=1024 count=0

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

(cd $TMPDIR ; tar cvf - *) | docker run -v $IMAGE:/output.img -i ${MKFLASH_TAG} /output.img usb_conf 2>/dev/null >&2
