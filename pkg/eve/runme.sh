#!/bin/sh
set -e
[ -n "$DEBUG" ] && set -x

exec 3>&1
exec 1>&2

OUTPUT_IMG=/tmp/output.img
DEFAULT_LIVE_IMG_SIZE=592
DEFAULT_INSTALLER_IMG_SIZE=592
DEFAULT_NVIDIA_IMG_SIZE=900

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
Usage: docker run [-v <option>] lfedge/eve [-f <fmt>] [-p <platform>] [--accept-license] version|rootfs|live|installer_raw|installer_iso|installer_net

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
docker run -v /path/to/eve/conf:/in --rm lfedge/eve:latest installer_raw > installer.raw
or
docker run -v /path/to/eve/conf/server:/in/server -v /path/to/eve/pkg/pillar/conf/root-certificate.pem:/in/root-certificate.pem --rm lfedge/eve:latest installer_raw > installer.raw

Where your local "conf" directory contains files like server or root-certificate.pem that
you want to use instead of the default ones in the image.
You can also mount (multiple) single files.

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

Optionally you can specify platform:

 -p <platform>

This specifies a platform for this image, e.g.:

default (no platform provided), imx8mq_evk, imx8mp_pollux are all valid
options.

Note that NVIDIA images are only valid for a specific plataform. For
instance: nvidia-jp6 images cannot be used with any other platform other
than nvidia-jp6. The same applies for nvidia-jp5.

Example:
docker run --rm lfedge/eve -f raw -p imx8mq_evk live > live.raw

In some cases, you will have to agree to a license when creating
EVE-OS images. To do this, use the --accept-license option.

Example:
docker run --rm lfedge/eve -f raw -p imx8mq_evk --accept-license live > live.raw
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
  cat /bits/eve_version >&3
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
  create_efi_raw "${1:-${DEFAULT_LIVE_IMG_SIZE}}" "$PART_SPEC"
  dump "$OUTPUT_IMG" live.raw
  echo "$IMAGE_UUID" >&2
}

do_installer_raw() {
  create_efi_raw "${1:-${DEFAULT_INSTALLER_IMG_SIZE}}" "efi conf_win installer inventory_win"
  dump "$OUTPUT_IMG" installer.raw
}

# create_installer_iso creates the installer iso and leaves it as /output.iso
# common base for other usages like do_installer_iso and do_installer_net
create_installer_iso() {
  mkdir -p /installer_root
  cp /bits/installer.img /installer_root/
  if [ -e /bits/config.img ]; then
      cp /bits/config.img /installer_root/
  fi
  tar -C /installer_root -cf - . | VOLUME_LABEL=EVEISO IN_IMAGE=installer.img IN_FORMAT=squashfs /make-efi installer
  rm -rf /installer_root
}

do_installer_iso() {
  create_installer_iso
  dump /output.iso installer.iso
}

do_installer_net() {
  # net installer depends on installer.iso
  rm -rf /installer /parts
  mkdir -p /installer
  cp /bits/ipxe.efi.cfg /installer
  mkdir -p /installer/EFI/BOOT
  cp /bits/EFI/BOOT/BOOT*EFI /installer/EFI/BOOT/
  create_installer_iso
  mv /output.iso /installer/installer.iso

  # all of this is taken straight from ../../tools/makenet.sh
  # it should be unified somehow
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
  dump /output.tar installer.net
}

do_sbom() {
  cat /bits/*.spdx.json >&3
}

prepare_for_platform() {
    # First we need to check if we are an image for NVIDIA platform
    if grep -q "\(.*\)-nvidia-\(.*\)" /bits/eve_version; then
        # It's a NVIDIA image, increase the default size for installer
        NVIDIA_PLAT=$(sed "s/.*-\(nvidia-jp.\)-.*/\1/" < /bits/eve_version)
        DEFAULT_INSTALLER_IMG_SIZE=$DEFAULT_NVIDIA_IMG_SIZE
        NVIDIA=true
    else
        NVIDIA_PLAT=""
        NVIDIA=false
    fi

    # Parse platform argument
    case "$PLATFORM" in
    imx8m*) #shellcheck disable=SC2039
        if [ "$NVIDIA" = "true" ]; then
            bail "This image is only valid for NVIDIA platform."
        fi
        cat /bits/bsp-imx/NXP-EULA-LICENSE.txt
        [ -n "$ACCEPT" ] || bail "You need to read and accept the EULA before you can continue. Use the --accept-license argument."
        cp /bits/bsp-imx/"$PLATFORM"-flash.bin /bits/imx8-flash.bin
        [ -n "$(ls /bits/bsp-imx/*.dtb 2> /dev/null)" ] && cp /bits/bsp-imx/*.dtb /bits/boot
        ;;
    nvidia*)
        if [ "$NVIDIA" = "false" ]; then
            bail "This image is not for NVIDIA platform."
        else
            if [ "$PLATFORM" != "$NVIDIA_PLAT" ]; then
                bail "This image is not for $PLATFORM but for $NVIDIA_PLAT instead."
            fi
        fi
        ;;
    *) #shellcheck disable=SC2039,SC2104
        break
        ;;
    esac
}

# Lets' parse global options first
while true; do
   case "$1" in
     -f*) #shellcheck disable=SC2039,SC3060
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
          [ "$PLATFORM" != "none" ] && \
              [ "${PLATFORM:0:5}" != "imx8m" ] && \
              [ "${PLATFORM:0:6}" != "nvidia" ] &&  bail "Unknown platform: $PLATFORM"
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
#shellcheck disable=SC2039,SC3045
[ "$(type -t "$ACTION")" = "$ACTION" ] || bail "Error: unsupported command '$1' - use 'help' command for more information."
shift

# If /in has content, we assume it was put there to override configs
if [ "$(ls -A /in)" ]; then
   mcopy -o -i /bits/config.img -s /in/* ::/
fi

# Do. Or do not. There is no try.
"$ACTION" "$@"
