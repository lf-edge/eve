#!/bin/sh
#
# Copyright (c) 2018 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

# Create a USB stick with the DevicePortConfig usb.json file as input
# Usage: mkusb.sh [-t] <file> <dev>

TEST=0

while [ $# -gt 0 ]; do
    if [ "$1" = "-t" ]; then
        TEST=1
        shift
    else
        break
    fi
done

if [ $# != 2 ]; then
    echo "Usage: mkusb.sh [-t] <file> <dev>"
    exit 1
fi
FILE=$1
DEV=$2

if [ ! -f "$FILE" ]; then
    echo "File $FILE does not exist"
    echo "Usage: mkusb.sh [-t] <file> <dev>"
    exit 1
fi

if ! python -m json.tool "$FILE" >/dev/null; then
    echo "Invalid json in $FILE"
    python -m json.tool "$FILE"
    exit 1
fi
    
if [ ! -b "$DEV" ]; then
    echo "Not a special device: $DEV"
    exit 1
fi

echo ""
echo "THIS WILL ERASE $DEV"
lsblk "$DEV"
echo ""
while /bin/true; do
    echo -n 'Are you sure(Yes/No)? '
    read -r resp
    if [ "$resp" = "Yes" ]; then
        break
    elif [ "$resp" = "No" ]; then
        exit 0
    fi
done

echo "Proceeding to clear $DEV"

PARTS=$(lsblk -o NAME -r -n "$DEV")
for p in $PARTS; do
    umount -f /dev/"$p"
done

sgdisk --zap "$DEV"
sgdisk --mbrtogpt "$DEV"
NUM_PART=1
SEC_START=2048
SEC_END=4096
PART_TYPE=EBD0A0A2-B9E5-4433-87C0-68B6B72699C7

sgdisk --new $NUM_PART:$SEC_START:$SEC_END \
       --typecode=$NUM_PART:$PART_TYPE \
       --change-name=$NUM_PART:'DevicePortConfig' "$DEV"

SPECIAL=$(cgpt find -l DevicePortConfig)
# XXX or cgpt find -t $PART_TYPE
if [ -z "$SPECIAL" ]; then
    echo "Failed to create and label DevicePortConfig"
    exit 1
fi
mkdosfs -I "$SPECIAL"
TMPDIR=/mnt/$$
mkdir $TMPDIR
mount "$SPECIAL" $TMPDIR
cp -p "$FILE" $TMPDIR
umount -f "$SPECIAL"
rmdir $TMPDIR

# XXX test using
if [ $TEST = 1 ]; then
    SPECIAL=$(cgpt find -l DevicePortConfig)
    mount -t vfat "$SPECIAL" /mnt
    ls /mnt
    df -k /mnt
    ls -l /mnt
    umount "$SPECIAL"
fi
