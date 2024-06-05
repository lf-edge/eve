#!/bin/sh

# Copyright (c) 2024 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

# This script extracts all .deb packages from a Jetson Linux archive and
# process a CDI yaml file in order to copy all files pointed by the CDI to
# the destination location.

extract_debs() {
    DEBS=$(ls Linux_for_Tegra/nv_tegra/l4t_deb_packages/*.deb)
    for x in $DEBS; do
        dpkg -x "$x" "$1"
    done
}

copy_rootfs_files() {
    FILES=$(cat "$1")
    for x in $FILES; do
        DESTDIR=$(dirname "$x")
        mkdir -p "$3"/"$DESTDIR"
        cp -rP "$2"/"$x" "$3"/"$x"
    done
}

process_cdi() {
    grep hostPath < "$1" | awk '{print $2}' > "$2"
}

# Check arguments
if [ $# != 3 ]; then
    echo "Use: $0 <cdi-file> <rootfs-extracted> <destination-folder>"
    echo
    exit 1
fi

CDIFILE=$1
ROOTFSA=$2
ROOTFSB=$3

# Extract debian packages
mkdir -p "$ROOTFSA"
extract_debs "$ROOTFSA"

# Process the CDI file
FLIST=$(mktemp)
process_cdi "$CDIFILE" "$FLIST"

# Copy requested files to the new rootfs folder
mkdir -p "$ROOTFSB"
copy_rootfs_files "$FLIST" "$ROOTFSA" "$ROOTFSB"

# Remove temporary file
rm "$FLIST"

echo "Done."
