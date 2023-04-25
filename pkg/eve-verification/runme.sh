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
Usage: docker run [-v <option>] lfedge/verification [-f <fmt>] [-p <platform>] [--accept-license] version|verification_rootfs|verification_live|verification_raw|verification_iso|verification_net

The artifact will be produced on stdout, so don't forget to redirect
it to a file or use the /out option below.

Example:
docker run --rm lfedge/verification verification_raw > verification.raw

Where "--rm" is a generic optional Docker argument that simply means
to remove the locally pulled container after the command completes.

Optionally you can pass arguments right after docker run:

 -v <full path to local folder>:/in

This allows you to overwrite files in the EVE-OS config partition with
your own local modifications of those files (must have the same name).

Example:
docker run -v $HOME/verification-overrides:/in --rm lfedge/verification:latest verification_raw > verification.raw

Where your local "verification-overrides" directory contains one file "server"
with one text string "some.verification-controller-url.com"

 -v <full path to new local folder>:/out

This allows you to redirect output from stdout to a file, with your
choice of path.

Example:
docker run -v $HOME/eve-images:/out --rm lfedge/verification:latest verification_raw

Optionally you can specify an alternate image format:

 -f <fmt>

This specifies a packaging format: raw (default), qcow2, parallels,
vdi, and gcp are all valid options.

Example:
docker run --rm lfedge/verification -f qcow2 verification_iso > verification-iso.img

The two raw formats "verification_live" and "verification_raw" support an optional
last argument specifying the size of the image in Mb.

Optionally you can specify platform:

 -p <platform>

This specifies a platform for this image: none (default),
imx8mq_evk are all valid options.

Example:
docker run --rm lfedge/verification -f verification_raw -p imx8mq_evk verification_live > verification.raw

In some cases, you will have to agree to a license when creating
EVE-OS images. To do this, use the --accept-license option.

Example:
docker run --rm lfedge/verification -f verification_raw -p imx8mq_evk --accept-license verification_live > verification.raw
__EOT__
  exit 0
}

create_efi_raw() {
  rm -rf /parts
  ln -s /bits /parts
  dd if=/dev/zero of="$OUTPUT_IMG" seek=$(( $1 * 1024 * 1024 - 1)) bs=1 count=1
  /make-raw "$OUTPUT_IMG" "$2"
}

do_verification_rootfs() {
  dump /bits/rootfs.img rootfs.img
}

do_version() {
  echo /bits/*.squash | sed -e 's#/bits/rootfs-##' -e 's#.squash##' >&3
}

do_build_config() {
  unsquashfs -cat /bits/rootfs.img /etc/linuxkit-eve-config.yml >&3
}

do_verification_live() {
  PART_SPEC="efi conf imga"
  # each verification_live image is expected to have a soft serial number that
  # typically gets provisioned by an verification -- since we're
  # shortcutting the verification step here we need to generate it
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

do_verification_raw() {
  create_efi_raw "${1:-350}" "conf_win verification inventory_win"
  dump "$OUTPUT_IMG" verification.raw
}

do_verification_iso() {
  rm -rf /parts
  /make-efi verification
  dump /output.iso verification.iso
}

do_verification_net() {
  # FIXME: this will also go away once we rationalize
  # how we're managing config for things like netboot
  (cd "$(mktemp -d)" && mkdir -p media/root-rw/boot
   cp /bits/config.img /bits/persist.img media/root-rw
   echo netboot > media/root-rw/boot/.uuid
   find . | sort | cpio --quiet -o -H newc) | gzip > /initrd.bits
  ln -s /bits/* /
  unsquashfs -d /tmp/kernel rootfs.img boot/kernel
  mv /tmp/kernel/boot/kernel /
  tar --mode=644 -C / -chvf /output.net ipxe.efi.cfg ipxe.efi kernel initrd.img verification.img initrd.bits rootfs.img
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
  dump /output.net verification.net
}

do_sbom() {
  cat /bits/*.spdx.json >&3
}

prepare_for_platform() {
    case "$PLATFORM" in
    imx8m*) #shellcheck disable=SC2039
        cat /bits/bsp-imx/NXP-EULA-LICENSE.txt
        [ -n "$ACCEPT" ] || bail "You need to read and accept the EULA before you can continue. Use the --accept-license argument."
        cp /bits/bsp-imx/"$PLATFORM"-flash.bin /bits/imx8-flash.bin
        [ -n "$(ls /bits/bsp-imx/*.dtb 2> /dev/null)" ] && cp /bits/bsp-imx/*.dtb /bits/boot
        ;;
    *) #shellcheck disable=SC2039,SC2104
        break
        ;;
    esac
}

# Lets' parse global options first
while true; do
   case "$1" in
     -f*) #shellcheck disable=SC2039
          #shellcheck disable=SC3060
          FMT="${1/-f/}"
          if [ -z "$FMT" ]; then
             FMT="$2"
             shift
          fi
          shift
          [ "$FMT" != "raw" ] && [ "$FMT" != "gcp" ] && [ "$FMT" != "qcow2" ] && [ "$FMT" != "parallels" ] && [ "$FMT" != "vdi" ] && bail "Unknown format: $FMT"
          ;;
     -p*) #shellcheck disable=SC2039,SC3060
          PLATFORM="${1/-p/}"
          if [ -z "$PLATFORM" ]; then
             PLATFORM="$2"
             shift
          fi
          shift
          #shellcheck disable=SC3057
          BASEPLATFORM="${PLATFORM:0:5}"
          [ "$PLATFORM" != "none" ] && [ "$BASEPLATFORM" != "imx8m" ] && bail "Unknown platform: $PLATFORM"
          ;;
     --accept-license*) #shellcheck disable=SC2039,SC3060
          ACCEPT=1
          shift
          ;;
       *) break
          ;;
   esac
done

# If we were not told to do anything, print help and exit with success
[ $# -eq 0 ] && do_help

# Prepare some files for selected platform
prepare_for_platform

# Let's see what was it that we were asked to do
ACTION="do_$1"
#shellcheck disable=SC2039
#shellcheck disable=SC3045
[ "$(type -t "$ACTION")" = "$ACTION" ] || bail "Error: unsupported command '$1' - use 'help' command for more information."
shift

# If /in was provided, for now we assume it was to override configs
if mountpoint -q /in; then
   mcopy -o -i /bits/config.img -s /in/* ::/
fi

# Do. Or do not. There is no try.
"$ACTION" "$@"
