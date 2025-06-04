#!/bin/sh

# makenet.sh builds a tar file with everything you need to boot EVE installer over iPXE.
# The expected process is to untar the resulting file in the serving directory of a TFTP server and
# then boot the target machine using iPXE pointing at the serving directory.

# the boot is controlled by the contents of ipxe.efi.cfg.

set -e
[ -n "$DEBUG" ] && set -x

EVE="$(cd "$(dirname "$0")" && pwd)/../"
PATH="$EVE/build-tools/bin:$PATH"
SOURCE="$(cd "$1" && pwd)"
IMG="$2"
IMGNAME=$(basename "${IMG}")
OUTPUT="$(cd "$(dirname "$3")" && pwd)/$(basename "$3")"

if [ ! -d "$SOURCE" ] || [ $# -lt 3 ]; then
   echo "Usage: $0 <input dir> <installer image> <output tar image file>"
   exit 1
fi

: > "$OUTPUT"

# using simple Alpine, we build a directory with everything we need,
# and then tar it up.
# - ipxe.efi
# - ipxe.efi.cfg
# - installer image (whatever it is called), normally installer.iso)
# - grub EFI boot file, arch-specific e.g. BOOTX64.EFI or BOOTAA64.EFI, into EFI/BOOT
# - special-purpose grub config file constructed inside this container, into EFI/BOOT
cat <<'EOT' | docker run --rm -e DEBUG="$DEBUG" -v "$SOURCE:/bits" -v "$IMG:/installer/${IMGNAME}" -v "$OUTPUT:/output.tar" -i alpine:3.20 sh
   set -e
   [ -n "$DEBUG" ] && set -x
   cp /bits/ipxe.efi /installer
   cp /bits/ipxe.efi.cfg /installer
   mkdir -p /installer/EFI/BOOT
   cp /bits/EFI/BOOT/BOOT*EFI /installer/EFI/BOOT/
   # by default, BOOT*.EFI looks for grub.cfg in its source location at EFI/BOOT/grub.cfg, so put it there
   cat <<'EOF' > /installer/EFI/BOOT/grub.cfg
echo "Downloading installer. This may take some time. Please wait patiently."
loopback loop0 ($cmddevice)/installer.iso
set root=loop0
set isnetboot=true
export isnetboot
configfile ($root)/EFI/BOOT/grub.cfg
EOF
   tar -C /installer -chvf /output.tar .
EOT
