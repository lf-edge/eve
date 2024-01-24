#!/bin/sh
EVE="$(cd "$(dirname "$0")" && pwd)/../"
PATH="$EVE/build-tools/bin:$PATH"
SOURCE="$(cd "$1" && pwd)"
ROOTFSTAR="$2"
IMG="$3"
NET="$(cd "$(dirname "$4")" && pwd)/$(basename "$4")"

if [ ! -d "$SOURCE" ] || [ $# -lt 4 ]; then
   echo "Usage: $0 <input dir> <rootfs tarball> <image file name> <output tar image file>"
   exit 1
fi

: > "$NET"

#  # FIXME: this will also go away once we rationalize
#  # how we're managing config for things like netboot
cat <<__EOT__ | docker run --rm -v "$SOURCE:/bits" -v "$ROOTFSTAR:/rootfs.tar" -v "$NET:/output.tar" -i alpine:3.13 sh
   cd "\$(mktemp -d)"
   mkdir -p media/root-rw/boot /rootfs
   tar -xf /rootfs.tar boot/kernel -C /rootfs/
   cp /rootfs/boot/kernel /bits/
   cp /bits/config.img /bits/persist.img media/root-rw
   echo netboot > media/root-rw/boot/.uuid
   find . | sort | cpio --quiet -o -H newc | gzip > /initrd.bits
   ln -s /bits/* /
   tar -C / -chvf /output.tar ipxe.efi.cfg kernel initrd.img "$IMG" initrd.bits rootfs.img
__EOT__
