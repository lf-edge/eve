#!/bin/sh
# Usage:
#
#      ./makeusbconf.sh [-d] [-i] [-s <size in Kb>] [-f <file> ] <output.img>
#
USAGE="Usage: $0 [-d] [-i] [-s <size in Kb>] [-f <file> ] <output.img>"

EVE="$(cd "$(dirname "$0")" && pwd)/../"
PATH="$EVE/build-tools/bin:$PATH"
MKFLASH_TAG="$(linuxkit pkg show-tag "$EVE/pkg/mkimage-raw-efi")"

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

confirm_erase() {
    echo ""
    echo "This will erase $1 which contains:"
    lsblk "$1"
    echo ""
    while /bin/true; do
        printf 'Are you sure(Yes/No)? '
        read -r resp
        if [ "$resp" = "Yes" ]; then
            break
        elif [ "$resp" = "No" ]; then
            exit 0
        fi
    done
    echo "Proceeding to clear $1"
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

IMAGE="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
if [ -b "$IMAGE" ] ; then
   [ "$(uname -s)" = Linux ] || bail "ERROR: writing directly to the device is only supported on Linux"
   IMAGE_BIND_OPT="--device"
   confirm_erase "$IMAGE"
else
   [ -e "$IMAGE" ] || silent dd if=/dev/zero of="$IMAGE" seek="$SIZE" bs=1024 count=0
   IMAGE_BIND_OPT="-v"
fi

(cd "$TMPDIR" || exit 1; tar cf - ./*) | docker run -i --rm "$IMAGE_BIND_OPT" "$IMAGE:/output.img" "${MKFLASH_TAG}" /output.img usb_conf
cleanup
