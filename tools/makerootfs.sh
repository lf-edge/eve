#!/bin/bash
# Usage:
#
#     ./makerootfs.sh mode [-y <image.yml>] [-i <output rootfs image>] [-t <tar file>] [-f <filesystem format>] [-a <arch>] [-d <directory where to execute>]
# <fs> defaults to squash
# <arch> defaults to the current machine architecture

# NOTE: this will get executed from the provided -d <dir>, or else the current directory
# make NO assumptions about where this runs; if you can, use absolute paths

set -e
set -o pipefail

# mode 3 - generate image from yml
do_image() {
  # shellcheck disable=SC2166
  if [ -z "$ymlfile" -o -z "$imgfile" -o -n "$tarfile" ]; then
    echo "must supply ymlfile and imgfile and not tarfile" >&2
    help
  fi
  # did we specify an architecture?
  ARCHARG=""
  if [ -n "$arch" ]; then
    ARCHARG="--arch ${arch}"
  fi
  : > "$IMAGE"
  # shellcheck disable=SC2086
  linuxkit build --docker ${ARCHARG} -o - "$ymlfile" | docker run -i --rm -v /dev:/dev --privileged -v "$IMAGE:/rootfs.img" "${MKROOTFS_TAG}"
}

# mode 1 - generate tarfile from yml and save
do_tar() {
  # shellcheck disable=SC2166
  if [ -z "$ymlfile" -o -z "$tarfile" -o -n "$imgfile" ]; then
    echo "must supply ymlfile and tarfile and not imgfile" >&2
    help
  fi
  # did we specify an architecture?
  ARCHARG=""
  if [ -n "$arch" ]; then
    ARCHARG="--arch ${arch}"
  fi
  if [ -z "$updatetar" ] || [ ! -e "${tarfile}" ]; then
    # shellcheck disable=SC2086
    linuxkit build --docker ${ARCHARG} --o "${tarfile}" "$ymlfile"
  else
    # shellcheck disable=SC2086
    linuxkit build --docker ${ARCHARG} --o "${tarfile}.new" --input-tar "${tarfile}"  "$ymlfile"
    newmd5=$(md5sum "${tarfile}.new" | awk '{print $1}')
    oldmd5=$(md5sum "${tarfile}" | awk '{print $1}')
    # Don't touch the modification time if files are equal. Crucial for Makefile.
    if [ "$newmd5" != "$oldmd5" ]; then
      mv "${tarfile}.new" "${tarfile}"
    else
      rm "${tarfile}.new"
    fi
  fi
}

# mode 2 - generate image from tarfile
do_imagefromtar() {
  # shellcheck disable=SC2166
  if [ -z "$tarfile" -o -z "$imgfile" -o -n "$ymlfile" ]; then
    echo "must supply tarfile and imgfile and not ymlfile" >&2
    help
  fi
  : > "$IMAGE"
  # shellcheck disable=SC2002
  cat "${tarfile}" | docker run -i --rm -v /dev:/dev --privileged -v "$IMAGE:/rootfs.img" "${MKROOTFS_TAG}"
}

abspath() {
  local target
  local dir
  local filename
  local absolute_dir

  target="$1"
  if [ -z "$target" ]; then
    echo "Error: Unable to find file '$target'" >&2
    return 1
  fi
  # we have two problems here:
  # First, we want to realpath a file that may not exist yet.
  # on some OSes, it is fine; on others, it returns an error.
  # a prerequisite is that the directory exists, so we can realpath that,
  # and just append the filename after.
  # Second, we want to use realpath, but it is not available on all OSes.
  dir=$(dirname "$target")
  filename=$(basename "$target")
  if [ ! -d "$dir" ]; then
    echo "Error: Unable to find directory '$dir'" >&2
    return 1
  fi
  absolute_dir=$(cd "$dir"; pwd -P)
  echo "${absolute_dir}/${filename}"
}

bail() {
  echo "$@" >&2
  help
}


# no mode we recognize
help() {
  echo "Usage: $0 <mode> [-y <image.yml>] [-i <output rootfs image>] [-t <tarfile>] [-f {ext4|squash}] [-a <arch>] [-d <directory>]" >&2
  echo "must be one of the following modes:" >&2
  echo "  generate final image from yml:" >&2
  echo "    $0 image [-y <image.yml>] [-i <output rootfs image>] [-f {ext4|squash}] [-a <arch>]" >&2
  echo "  generate tar from yml:" >&2
  echo "    $0 tar [-y <image.yml>] [-t <output tarfile>] [-a <arch>]" >&2
  echo "  generate final image from tar:" >&2
  echo "    $0 imagefromtar [-i <output rootfs image>] [-f {ext4|squash}] [-t <input tarfile>]" >&2
  echo
  echo "setting the directory via -d will change to execute in the given directory" >&2
  exit 1
}

# there are 3 modes we can run in:
# 1. generate tarfile from yml and save
# 2. generate image from tarfile
# 3. generate image from yml
mode="$1"
shift

unset tarfile imgfile arch format ymlfile execidr updatetar
while getopts "t:i:a:f:y:d:uh" o
do
  case $o in
    t)
      tarfile=$(abspath "$OPTARG")
      ;;
    i)
      imgfile=$(abspath "$OPTARG")
      ;;
    a)
      arch="$OPTARG"
      ;;
    f)
      format="$OPTARG"
      ;;
    y)
      ymlfile=$(abspath "$OPTARG")
      ;;
    d)
      execdir=$(abspath "$OPTARG")
      ;;
    u)
      updatetar=1
      ;;
    h)
      help
      ;;
    *)
      ;;
  esac
done

[ -z "$format" ] && format="squash"

EVE="$(cd "$(dirname "$0")" && pwd)/../"
PATH="$EVE/build-tools/bin:$PATH"
# shellcheck disable=SC2086
MKROOTFS_TAG="$(linuxkit pkg ${LINUXKIT_ORG_TARGET} show-tag "$EVE/pkg/mkrootfs-${format}")"
IMAGE="$(cd "$(dirname "$imgfile")" && pwd)/$(basename "$imgfile")"

[ -n "$execdir" ] && cd "$execdir"

action="do_${mode}"
#shellcheck disable=SC2039
command -V "$action" > /dev/null 2>&1 || bail "Error: unsupported command '$mode'."

# Do. Or do not. There is no try.
"$action" "$@"

