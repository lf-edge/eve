#!/bin/sh
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# eve-mkinitramfs.sh - build a busybox based initramfs out of a rootfs.
#
# Usage:
#   eve-mkinitramfs.sh [-r <rootfs>] -i <init> -o <outfile> [<path> ...]
#
# <init> becomes /init. busybox (the static one, package busybox-static) is
# taken from the rootfs (default /) and installed as /bin/busybox with /bin/sh
# pointing to it, so init scripts written for Alpine's busybox ash, like
# mkinitfs' initramfs-init, run unchanged; they install the other applets
# themselves with busybox --install. Every <path> is copied along with the
# shared libraries it needs, see copy-with-libs.sh.
set -e

usage() {
    echo "Usage: $0 [-r <rootfs>] -i <init> -o <outfile> [<path> ...]" >&2
    exit 1
}

ROOT=/
INIT=""
OUTFILE=""
while getopts "r:i:o:" opt; do
    case "$opt" in
        r) ROOT="$OPTARG" ;;
        i) INIT="$OPTARG" ;;
        o) OUTFILE="$OPTARG" ;;
        *) usage ;;
    esac
done
shift $((OPTIND - 1))
{ [ -n "$INIT" ] && [ -n "$OUTFILE" ]; } || usage

for tool in cpio gzip lddtree; do
    command -v "$tool" >/dev/null 2>&1 || { echo "$0: $tool not found (cpio, gzip, pax-utils)" >&2; exit 1; }
done
[ -x "$ROOT/bin/busybox" ] || { echo "$0: $ROOT/bin/busybox not found (busybox-static)" >&2; exit 1; }

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# the same merged-/usr layout as the rootfs the files come from, so that the
# scripts' absolute paths (/sbin/poweroff, /bin/busybox, ...) keep working
for d in usr/bin usr/sbin usr/lib usr/lib64 dev proc sys run etc tmp mnt newroot media/boot; do
    mkdir -p "$tmp/$d"
done
for d in bin sbin lib lib64; do
    ln -s "usr/$d" "$tmp/$d"
done

copy-with-libs.sh -r "$ROOT" -o "$tmp" /bin/busybox "$@"
ln -sf busybox "$tmp/bin/sh"
# the applet links are made from inside, so that they point to /bin/busybox,
# and go to the directories busybox has for them, like Alpine's init expects
# (nlplug-findfs is told to run /sbin/mdev)
chroot "$tmp" /bin/busybox --install -s
install -m 755 "$INIT" "$tmp/init"
printf 'root:x:0:0:root:/root:/bin/sh\n' > "$tmp/etc/passwd"
printf 'root:x:0:\n' > "$tmp/etc/group"
: > "$tmp/etc/fstab"

(cd "$tmp" && find . | sort | cpio --quiet --renumber-inodes -o -H newc | gzip -9n) > "$OUTFILE"
echo "$OUTFILE: $(du -h "$OUTFILE" | cut -f1)"
