#!/bin/sh
EVE="$(cd "$(dirname "$0")" && pwd)/../"
PATH="$EVE/build-tools/bin:$PATH"
SOURCE="$(cd "$1" && pwd)"
IMG="$2"
NET="$(cd "$(dirname "$3")" && pwd)/$(basename "$3")"

if [ ! -d "$SOURCE" ] || [ $# -lt 3 ]; then
   echo "Usage: $0 <input dir> <image file name> <output tar image file>"
   exit 1
fi

: > "$NET"

#  # FIXME: this will also go away once we rationalize
#  # how we're managing config for things like netboot
cat <<__EOT__ | docker run --rm -v "$SOURCE:/bits" -v "$NET:/output.tar" -i alpine:3.13 sh
   cd "\$(mktemp -d)"
   mkdir -p media/root-rw/boot
   cp /bits/config.img /bits/persist.img media/root-rw
   echo netboot > media/root-rw/boot/.uuid
   find . | sort | cpio --quiet -o -H newc | gzip > /initrd.bits
   ln -s /bits/* /
   tar -C / -chvf /output.tar ipxe.efi.cfg kernel initrd.img "$IMG" initrd.bits rootfs.img
__EOT__
