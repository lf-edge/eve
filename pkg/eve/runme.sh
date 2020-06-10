#!/bin/sh

OUTPUT_IMG=/tmp/output.img

bail() {
  echo "$@"
  exit 1
}

dump() {
  # If /out or /out/f were provided it means we need to deposit output there instead of stdout
  if mountpoint -q /out && [ -n "$2" ]; then
     dd if="$1" bs=1M of=/out/"$2"
  elif mountpoint -q /out/f; then
     dd if="$1" bs=1M of=/out/f
  else
     dd if="$1" bs=1M
  fi
}

do_help() {
  echo "Usage: docker run lfedge/eve [version|rootfs|live|installer_raw|installer_iso]"
  echo "       optionally you can pass -v <local folder>:/in to overwrite files in config partition"
  echo "                           and -v <local folder>:/out to redirect output into a folder"
  echo "                            or -v <local empty file>:/out/f to redirect out into a particular local file"
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
