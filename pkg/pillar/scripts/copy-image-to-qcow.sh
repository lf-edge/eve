#!/bin/bash
#
# Copyright (c) 2024 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

#SRCDIR is the container rootfs directory of the image
# ie /persist/vault/volumes/*container directory
#DESTFILE is the qcow2 file
# 1) Create an empty qcow2 file
# 2) mkfs ext4 and mount it as nbd device
# 3) rsync the SRCDIR to mounted qcow2

echo "$(date -Ins -u) Starting copy-image-to-qcow.sh"

SRCDIR=$1
DESTFILE=$2
MOUNTDIR=/tmp/dest.$$

if [ ! -d "$SRCDIR" ]; then
   echo "$SRCDIR does not exist"
   exit 1
fi

if [ -f "$DESTFILE" ]; then
   echo "$DESTFILE already exists"
   exit 1
fi

SIZEMB=$(du -sm "$SRCDIR"/ | awk '{print $1}')
#This is a workaround for now we allocate twice the size of SRCDIR, somehow rsync at the end of script does not like the
#exact size allocated for qcow2, it expects little bit more, may be for some metadata.
#It does not cost us anything allocating more space here since its thin allocated.
SIZEMB=$((SIZEMB * 2))
/usr/bin/qemu-img create -o preallocation=off -f qcow2 "$DESTFILE" "$SIZEMB""M"
qemu-img info -U --output=json "$DESTFILE"
#Get an exclusive lock so that no one else mounts the /dev/nbd10
LOCK_FILE="/run/create-image.lock"
WAIT_INTERVAL=5
# Loop until an exclusive lock is acquired
while true; do
    exec 200>"$LOCK_FILE"
    if flock -x 200; then
        break  # Exit the loop if the lock is acquired
    else
        echo "Waiting for exclusive lock..."
        sleep "$WAIT_INTERVAL"
    fi
done

# Set up ndb to mount qcow file.
modprobe nbd max_part=8
/usr/bin/qemu-nbd --connect=/dev/nbd10 "$DESTFILE"
sleep 10
mke2fs -t ext4 /dev/nbd10
qemu-img info -U --output=json "$DESTFILE"
mkdir -p "$MOUNTDIR"
mount -t ext4 /dev/nbd10 "$MOUNTDIR"
failed=0

echo "Starting rsync"
#Use rsync to keep source permissions and ownership
if ! rsync -arl  "$SRCDIR"/* "$MOUNTDIR"; then
failed=1
fi
umount "$MOUNTDIR"
qemu-nbd --disconnect /dev/nbd10
rm -rf "$MOUNTDIR"
flock -u 200
if [ "$failed" = "1" ]; then
echo "Failed to copy to qcow2 file $DESTFILE, deleting it"
exit 1
fi
echo "rsync succeeded"
qemu-img info -U --output=json "$DESTFILE"
echo "$(date -Ins -u) Converted $SRCDIR to $DESTFILE"
exit 0
