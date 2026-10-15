#!/bin/sh

# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
set -e
[ -n "$DEBUG" ] && set -x

exec 3>&1
exec 1>&2

bail() {
  echo "$@"
  exit 1
}

do_help() {
cat <<__EOT__
Usage: docker run [-v <option>] lfedge/evetest-sdn:<tag> [-f <fmt>] help|version|image

The artifact will be produced on stdout, so don't forget to redirect
it to a file or use the /out option below.

Example:
docker run --rm lfedge/evetest-sdn:<tag> image > evetest-sdn.raw

Where "--rm" is a generic optional Docker argument that simply means
to remove the locally pulled container after the command completes.

Optionally you can mount a directory for the output.

 -v <full path to new local folder>:/out

This allows you to redirect output from stdout to a file, with your
choice of path.

Example:
docker run -v $HOME/evetest-images:/out --rm lfedge/evetest-sdn:<tag> image

Optionally you can specify an alternative image format:

 -f <fmt>

This specifies a packaging format: raw (default), qcow2, parallels,
vdi, and gcp are all valid options.

Example:
docker run --rm lfedge/evetest-sdn:<tag> -f qcow2 image > evetest-sdn.img
__EOT__
  exit 0
}

do_version() {
  cat /bits/sdn-version >&3
}

do_image() {
  dump /bits/sdn-bios.img evetest-sdn.img
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

  # If /out is provided it means we need to deposit output there instead of stdout
  if mountpoint -q /out ; then
     dd if="$INAME" bs=1M of=/out/"$ONAME"
  else
     dd if="$INAME" bs=1M >&3
  fi
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
          [ "$FMT" != "raw" ] && [ "$FMT" != "gcp" ] && [ "$FMT" != "qcow2" ] &&\
            [ "$FMT" != "parallels" ] && [ "$FMT" != "vdi" ] && bail "Unknown format: $FMT"
          ;;
     *) break
          ;;
   esac
done

# If we were not told to do anything, print help and exit with success
[ $# -eq 0 ] && do_help

# Let's see what was it that we were asked to do
ACTION="do_$1"
#shellcheck disable=SC2039,SC3045
type "$ACTION" >/dev/null 2>&1 || \
  bail "Error: unsupported command '$1' - use 'help' command for more information."
shift

# Perform the selected action.
"$ACTION" "$@"
