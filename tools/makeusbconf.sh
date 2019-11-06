#!/bin/sh
# Usage:
#
#      ./makeusbconf.sh [-d] [-i] [-s <size in Kb>] [-f <file> ] <output.img>
#
USAGE="Usage: $0 [-d] [-i] [-s <size in Kb>] [-f <file> ] <output.img>"

MKFLASH_TAG="$(linuxkit pkg show-tag pkg/mkimage-raw-efi)"

cleanup() {
    rm "$TMPDIR"/* 2>/dev/null
    rmdir "$TMPDIR"/* 2>/dev/null
    rmdir "$TMPDIR"
}

bail() {
    echo "$*"
    cleanup
    exit 1
}

silent() {
    if ! OUT=$("$@" 2>&1) ; then
       bail "ERROR: $* $OUT"
    fi
}

SIZE=204800
TMPDIR=$(mktemp -d)

while getopts dif:s: o
do      case "$o" in
        d)      mkdir "$TMPDIR/dump" || bail "can't create $TMPDIR/dump";;
        i)      mkdir "$TMPDIR/identity" || bail "can't create $TMPDIR/identity";;
        f)      cp "$OPTARG" "$TMPDIR/usb.json" || bail "can't access $OPTARG" ;;
        s)      SIZE="$OPTARG";;
        [?])    bail "$USAGE";;
        esac
done

shift $((OPTIND-1))
[ $# != 1 ] && bail "$USAGE"
[ -z "$(ls -A "$TMPDIR")" ] && bail "ERROR: one of the -d -i or -f has to be given"


IMAGE="$1"
if [ -b "$IMAGE" ] ; then
   [ "$(uname -s)" = Linux ] || bail "ERROR: writing directly to the device is only supported on Linux"
   IMAGE_BIND_OPT="--device"
else
   [ -e "$IMAGE" ] || silent dd if=/dev/zero of="$IMAGE" seek="$SIZE" bs=1024 count=0
   IMAGE_BIND_OPT="-v"
fi

# Docker, for unknown reasons, decides whether a passed bind mount is
# a file or a directory based on whether is a absolute pathname or a
# relative one (!).
#
# Of course, BSDs do not have the GNU specific realpath, so substitute
# it with a shell script.

case "$IMAGE" in
    /*) ;;
    *) IMAGE="$PWD/$IMAGE";;
esac

(cd "$TMPDIR" || exit 1; tar cf - ./*) | docker run "$IMAGE_BIND_OPT" "$IMAGE:/output.img" -i "${MKFLASH_TAG}" /output.img usb_conf
