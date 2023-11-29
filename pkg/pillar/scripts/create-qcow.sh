#!/bin/bash
#
# Copyright (c) 2023 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

echo "$(date -Ins -u) Starting create-qcow.sh"

SRCDIR=$1
DESTFILE=$2
#SIZE=$3

if [ ! -d $SRCDIR ]; then
   echo "$SRCDIR does not exist"
   exit 1
fi

if [ -f $DESTFILE ]; then
   echo "$DESTFILE already exists"
   exit 1
fi

SIZE=`du -s --bytes $SRCDIR/ | awk '{print $1}'`
## Add 10% or 10MB for ext4 metadata
#((OVERHEAD = SIZE/10))
#if [ $OVERHEAD -lt 10485760 ]; then
#    OVERHEAD=10485760
#fi

((SIZE = SIZE * 2))
echo $SIZE
/usr/bin/qemu-img create -o preallocation=off -f qcow2 $DESTFILE $SIZE
#/usr/bin/qemu-img create -f qcow2 $DESTFILE $SIZE

#Get an exclusive lock so that no one else mounts the /dev/nbd10
LOCK_FILE="/run/create-qcow.lock"

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
/usr/bin/qemu-nbd --connect=/dev/nbd10 $DESTFILE 
mke2fs -t ext4 /dev/nbd10
mkdir -p /run/dest
mount /dev/nbd10 /run/dest
failed=0

echo "Starting rsync"
#Use rsync to keep source permissions and ownership
rsync -ar  $SRCDIR/* /run/dest
if [ $? -ne 0 ]; then
echo "Failed to copy to qcow2 file $DESTFILE"
failed=1
fi
umount /run/dest
qemu-nbd --disconnect /dev/nbd10
flock -u 200 
if [ "$failed" = "1" ]; then
exit 1
fi
echo "rsync succeeded"
echo "$(date -Ins -u) Converted $SRCDIR to $DESTFILE"
exit 0
