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

  # First let's see if postprocessing of a raw disk was requested
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
Usage: docker run [-v <option>] lfedge/eve [-f <fmt>] version|rootfs|live|installer_raw|installer_iso|installer_net

The artifact will be produced on stdout, so don't forget to redirect
it to a file or use the /out option below.

Example:
docker run --rm lfedge/eve installer_raw > installer.raw

Where "--rm" is a generic optional Docker argument that simply means
to remove the locally pulled container after the command completes.

Optionally you can pass arguments right after docker run:

 -v <full path to local folder>:/in

This allows you to overwrite files in the EVE-OS config partition with
your own local modifications of those files (must have the same name).

Example:
docker run -v $HOME/eve-overrides:/in --rm lfedge/eve:latest installer_raw > installer.raw

Where your local "eve-overrides" directory contains one file "server"
with one text string "some.eve-controller-url.com"

 -v <full path to new local folder>:/out

This allows you to redirect output from stdout to a file, with your
choice of path.

Example:
docker run -v $HOME/eve-images:/out --rm lfedge/eve:latest installer_raw

Optionally you can specify an alternate image format:

 -f <fmt>

This specifies a packaging format: raw (default), qcow2, parallels,
vdi, and gcp are all valid options.

Example:
docker run --rm lfedge/eve -f qcow2 installer_iso > eve-iso.img

The two raw formats "live" and "installer_raw" support an optional
last argument specifying the size of the image in Mb.
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

do_build_config() {
  unsquashfs -cat /bits/rootfs.img /etc/linuxkit-eve-config.yml >&3
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
  /make-efi installer
  dump /output.iso installer.iso
}

do_installer_net() {
  # FIXME: this will also go away once we rationalize
  # how we're managing config for things like netboot
  (cd "$(mktemp -d)" && mkdir -p media/root-rw/boot
   cp /bits/config.img /bits/persist.img media/root-rw
   echo netboot > media/root-rw/boot/.uuid
   find . | sort | cpio --quiet -o -H newc) | gzip > /initrd.bits
  ln -s /bits/* /
  unsquashfs -d /tmp/kernel rootfs.img boot/kernel
  mv /tmp/kernel/boot/kernel /
  tar --mode=644 -C / -chvf /output.net ipxe.efi.cfg ipxe.efi kernel initrd.img installer.img initrd.bits rootfs.img
  if [ "$(uname -m)" = aarch64 ]
  then
  cat > /tmp/boot.scr <<__EOT__
dhcp
tftpboot \${kernel_addr_r} ipxe.efi
bootefi \${kernel_addr_r}
__EOT__
    mkimage -A arm64 -O linux -T script -C none -a 0 -e 0 -n "U-Boot Script" -d /tmp/boot.scr /boot.scr.uimg
    ln -fs /bits/boot/* /
    tar -C / -rhvf /output.net boot.scr.uimg overlays u-boot.bin bcm2711-rpi-4-b.dtb config.txt fixup4.dat start4.elf
  fi
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
