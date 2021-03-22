#!/bin/sh
EVE="$(cd "$(dirname "$0")" && pwd)/../"
PATH="$EVE/build-tools/bin:$PATH"
MKIMAGE_TAG="$(linuxkit pkg show-tag "$EVE/pkg/mkimage-iso-efi")"
SOURCE="$(cd "$1" && pwd)"
NET="$(cd "$(dirname "$2")" && pwd)/$(basename "$2")"

if [ ! -d "$SOURCE" ] || [ $# -lt 2 ]; then
   echo "Usage: $0 <input dir> <output tar image file>"
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
   tar -C / -chvf /output.tar ipxe.efi.cfg kernel initrd.img installer.img initrd.bits rootfs.img
__EOT__
