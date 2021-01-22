#!/bin/sh
set -e

exec 3>&1
exec 1>&2

OUTPUT_IMG=/tmp/output.img

bail() {
  echo "$@"
  exit 1
}

dump() {
  INAME="$1"
  ONAME="$2"

  # First let's see if postprocesing of a raw diks was requested
  case "$FMT" in
     qcow2) qemu-img convert -c -f raw -O qcow2 "$INAME" "$INAME.qcow2"
            INAME="$INAME.qcow2"
            ONAME="$ONAME.qcow2"
            ;;
     vdi) qemu-img convert -f raw -O vdi "$INAME" "$INAME.vdi"
            INAME="$INAME.vdi"
            ONAME="$ONAME.vdi"
            ;;
     parallels) qemu-img convert -f raw -O parallels "$INAME" "$INAME.parallels"
            INAME="$INAME.parallels"
            ONAME="$ONAME.parallels"
            ;;
     gcp) mv "$INAME" disk.raw
            tar --mode=644 --owner=root --group=root -S -h -czvf "$INAME.img.tar.gz" "disk.raw"
            INAME="$INAME.img.tar.gz"
            ONAME="$ONAME.img.tar.gz"
            ;;
  esac

  # If /out or /out/f were provided it means we need to deposit output there instead of stdout
  if mountpoint -q /out ; then
     dd if="$INAME" bs=1M of=/out/"$ONAME"
  elif mountpoint -q /out/f; then
     dd if="$INAME" bs=1M of=/out/f
  else
     dd if="$INAME" bs=1M >&3
  fi
}

do_help() {
cat <<__EOT__
Usage: docker run lfedge/eve [-f fmt] version|rootfs|live|installer_raw|installer_iso|installer_net

The artifact will be produced on stdout, so don't forget to redirect it to a file.

Optionally you can pass the following right before run in docker run:
 -v <local folder>:/in to overwrite the files in config partition with the files from /in
 -v <local folder>:/out or -v <local empty file>:/out/f to redirect output from stdout
Passing -v <local folder>:/out makes sure the file created is given most appropriate name.

-f fmt selects a packaging format: raw (default), qcow2, parallels, vdi and gcp are all valid options.

live and installer_raw support an optional last argument specifying the size of the image in Mb.
__EOT__
  exit 0
}

create_efi_raw() {
  rm -rf /parts
  ln -s /bits /parts
  dd if=/dev/zero of="$OUTPUT_IMG" seek=$(( $1 * 1024 * 1024 - 1)) bs=1 count=1
  /make-raw "$OUTPUT_IMG" "$2"
}

do_rootfs() {
  dump /bits/rootfs.img rootfs.img
}

do_version() {
  echo /bits/*.squash | sed -e 's#/bits/rootfs-##' -e 's#.squash##' >&3
}

do_live() {
  PART_SPEC="efi conf imga"
  # each live image is expected to have a soft serial number that
  # typically gets provisioned by an installer -- since we're
  # shortcutting the installer step here we need to generate it
  # if it is missing in CONFIG partition
  if mcopy -o -i /bits/config.img ::/soft_serial /tmp; then
     IMAGE_UUID=$(cat /tmp/soft_serial)
  else
     IMAGE_UUID=$(uuidgen | tee /tmp/soft_serial)
     mcopy -o -i /bits/config.img /tmp/soft_serial ::/soft_serial
  fi
  create_efi_raw "${1:-350}" "$PART_SPEC"
  dump "$OUTPUT_IMG" live.raw
  echo "$IMAGE_UUID" >&2
}

do_installer_raw() {
  create_efi_raw "${1:-350}" "conf_win installer inventory_win"
  dump "$OUTPUT_IMG" installer.raw
}

do_installer_iso() {
  rm -rf /parts
  /make-efi
  dump /output.iso installer.iso
}

do_installer_net() {
  ln -s /sys/class/mem/null /media/boot
  find /bits /media/boot -xdev | grep -v initrd.img | sort | cpio --quiet -o -H newc | gzip > /initrd.bits
  ln -s /bits/initrd.img /initrd.img
  unsquashfs -d /tmp/kernel rootfs.img boot/kernel
  mv /tmp/kernel/boot/kernel /
  cat > /ipxe.efi.cfg <<__EOT__
#!ipxe
# dhcp
# chain --autofree https://github.com/lf-edge/eve/releases/download/1.2.3/ipxe.efi.cfg
kernel kernel eve_installer=\${mac:hexhyp} fastboot console=ttyS0 console=ttyS1 console=ttyS2 console=ttyAMA0 console=ttyAMA1 console=tty0 initrd=initrd.img initrd=initrd.bits
initrd initrd.img
initrd initrd.bits
boot
__EOT__
  tar -C / -chvf /output.net ipxe.efi.cfg kernel initrd.img initrd.bits
  dump /output.net installer.net
}

# Lets' parse global options first
while true; do
   case "$1" in
     -f*) #shellcheck disable=SC2039
          FMT="${1/-f/}"
          if [ -z "$FMT" ]; then
             FMT="$2"
             shift
          fi
          shift
          [ "$FMT" != "raw" ] && [ "$FMT" != "gcp" ] && [ "$FMT" != "qcow2" ] && [ "$FMT" != "parallels" ] && [ "$FMT" != "vdi" ] && bail "Unknown format: $FMT"
          ;;
       *) break
          ;;
   esac
done

# If we were not told to do anything, print help and exit with success
[ $# -eq 0 ] && do_help

# Let's see what was it that we were asked to do
ACTION="do_$1"
#shellcheck disable=SC2039
[ "$(type -t "$ACTION")" = "$ACTION" ] || bail "Error: unsupported command '$1' - use 'help' command for more information."
shift

# If /in was provided, for now we assume it was to override configs
if mountpoint -q /in; then
   mcopy -o -i /bits/config.img -s /in/* ::/
fi

# Do. Or do not. There is no try.
"$ACTION" "$@"
