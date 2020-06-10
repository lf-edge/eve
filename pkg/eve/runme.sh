#!/bin/sh

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
       gcp) tar --mode=644 --owner=root --group=root -S -h -czvf "$INAME.img.tar.gz" "$INAME"
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
     dd if="$INAME" bs=1M
  fi
}

do_help() {
cat <<__EOT__
Usage: docker run lfedge/eve [-f fmt] version|rootfs|live|installer_raw|installer_iso

The artifact will be produced on stdout, so don't forget to redirect it to a file.

Optionally you can pass the following right before run in docker run:
 -v <local folder>:/in to overwrite the files in config partition with the files from /in
 -v <local folder>:/out or -v <local empty file>:/out/f to redirect output from stdout
Passing -v <local folder>:/out makes sure the file created is given most appropriate name.

-f fmt selects a packaging format: raw (default), qcow2 and gcp are all valid options.
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
  echo /bits/*.squash | sed -e 's#/bits/rootfs-##' -e 's#.squash##'
}

do_live() {
  PART_SPEC="efi conf imga"
  [ -d /bits/boot ] && PART_SPEC="boot conf imga"
  create_efi_raw "${1:-350}" "$PART_SPEC"
  dump "$OUTPUT_IMG" live.raw
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

# Lets' parse global options first
while true; do
   case "$1" in
     -f*) FMT="${1/-f/}"
	  if [ -z "$FMT" ]; then
	     FMT="$2"
	     shift
          fi
	  shift
	  [ "$FMT" != "raw" ] && [ "$FMT" != "gcp" ] && [ "$FMT" != "qcow2" ] && bail "Unknown format: $FMT"
	  ;;
       *) break
	  ;;
   esac
done

# Let's see what was it that we were asked to do
ACTION="do_$1"
#shellcheck disable=SC2039
[ "$(type -t "$ACTION")" = "$ACTION" ] || ACTION=do_help
shift

# If /in was provided, for now we assume it was to override configs
if mountpoint -q /in; then
   mcopy -o -i /bits/config.img -s /in/* ::/
fi

# Do. Or do not. There is no try.
"$ACTION" "$@"
