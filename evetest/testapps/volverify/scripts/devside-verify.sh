#!/bin/sh
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Judge one carried-over app volume image, without the app running.
#
# Usage: devside-verify.sh <volume-image> <seed> <ops> <max-blocks> <expect-committed>
#
# Runs from EVE's dom0 against a volume image that upgradeconverter left behind
# (/persist/vault/volumes-kvm or /persist/clear/volumes), and also by hand inside
# the volverify app itself against any ext4 image volverify wrote. Both call sites
# need the same verdict, so it lives with the app rather than with the assertions.
#
# Prints DEVSIDE-FSCK-RC and DEVSIDE-VERIFY-RC on success, or a single
# DEVSIDE=<reason> line when it could not reach a verdict.
set -u

if [ "$#" -ne 5 ]; then
    echo "usage: $0 <volume-image> <seed> <ops> <max-blocks> <expect-committed>" >&2
    exit 2
fi

F="$1"
SEED="$2"
OPS="$3"
MAX_BLOCKS="$4"
EXPECT_COMMITTED="$5"

# volverify ships next to this script, so the copy that wrote the volume is the
# copy that reads it back. On a device the pair comes from the unpacked app image;
# inside the app both are on $PATH.
VV="$(dirname "$0")/volverify"
if [ ! -x "$VV" ]; then
    VV=$(command -v volverify 2>/dev/null)
fi
if [ -z "$VV" ] || [ ! -x "$VV" ]; then
    echo "DEVSIDE=no-volverify"
    exit 0
fi
[ -f "$F" ] || { echo "DEVSIDE=no-relocated-volume"; exit 0; }

# Read the filesystem before anything mounts it: a mount replays the journal and can
# repair the very damage being measured.
e2fsck -fn "$F" > /tmp/dsfsck.out 2>&1
echo "DEVSIDE-FSCK-RC=$?"
sed -n '1,40p' /tmp/dsfsck.out

mkdir -p /tmp/dsmnt
L=$(losetup -r -f --show "$F" 2>&1) || { echo "DEVSIDE=losetup-failed:$L"; exit 0; }
if mount -o ro,noload "$L" /tmp/dsmnt 2>&1; then
    # Redirect rather than pipe, so the status is volverify's and not the pager's.
    "$VV" verify --dir /tmp/dsmnt --seed "$SEED" --ops "$OPS" \
        --block-size 4096 --max-blocks "$MAX_BLOCKS" \
        --expect-committed "$EXPECT_COMMITTED" > /tmp/dsvv.out 2>&1
    echo "DEVSIDE-VERIFY-RC=$?"
    grep -aE 'committed=|verify:' /tmp/dsvv.out | tail -4
    umount /tmp/dsmnt || true
else
    echo "DEVSIDE=mount-failed"
fi
losetup -d "$L" || true
rm -rf /tmp/dsmnt /tmp/dsvv.out /tmp/dsfsck.out
