#!/bin/sh
#
# Copyright (c) 2018 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

PERSISTDIR=/var/persist
CONFIGDIR=/var/config
mkdir -p $PERSISTDIR
chmod 700 $PERSISTDIR
mkdir -p $CONFIGDIR
chmod 700 $CONFIGDIR
if CONFIG=$(/hostfs/sbin/findfs PARTLABEL=CONFIG) && [ -n "$CONFIG" ]; then
    if ! fsck.vfat -y "$CONFIG"; then
        echo "$(date -Ins -u) fsck.vfat $CONFIG failed"
    fi
    if ! mount -t vfat -o dirsync,noatime "$CONFIG" $CONFIGDIR; then
        echo "$(date -Ins -u) mount $CONFIG failed"
    fi
else
    echo "$(date -Ins -u) No separate $CONFIGDIR partition"
fi

P3_FS_TYPE="ext3"
FSCK_FAILED=0
#For systems with ext3 filesystem, try not to change to ext4, since it will brick
#the device when falling back to old images expecting P3 to be ext3. Migrate to ext4
#when we do usb install, this way the transition is more controlled.
if P3=$(/hostfs/sbin/findfs PARTLABEL=P3) && [ -n "$P3" ]; then
    P3_FS_TYPE=$(blkid "$P3"| awk '{print $3}' | sed 's/TYPE=//' | sed 's/"//g')
    echo "$(date -Ins -u) Using $P3 (formatted with $P3_FS_TYPE), for $PERSISTDIR"

    if [ "$P3_FS_TYPE" = "ext3" ]; then
        if ! fsck.ext3 -y "$P3"; then
            FSCK_FAILED=1
        fi
    else
        P3_FS_TYPE="ext4"
        if ! fsck.ext4 -y "$P3"; then
            FSCK_FAILED=1
        fi
    fi

    #Any fsck error (ext3 or ext4), will lead to formatting P3 with ext4
    if [ $FSCK_FAILED = 1 ]; then
        echo "$(date -Ins -u) mkfs.ext4 on $P3 for $PERSISTDIR"
        #Use -F option twice, to avoid any user confirmation in mkfs
        if ! mkfs -t ext4 -v -F -F -O encrypt "$P3"; then
            echo "$(date -Ins -u) mkfs.ext4 $P3 failed"
        else
            echo "$(date -Ins -u) mkfs.ext4 $P3 successful"
            P3_FS_TYPE="ext4"
        fi
    fi

    if [ "$P3_FS_TYPE" = "ext3" ]; then
        if ! mount -t ext3 -o dirsync,noatime "$P3" $PERSISTDIR; then
            echo "$(date -Ins -u) mount $P3 failed"
        fi
    fi
    #On ext4, enable encryption support before mounting.
    if [ "$P3_FS_TYPE" = "ext4" ]; then
        tune2fs -O encrypt "$P3"
        if ! mount -t ext4 -o dirsync,noatime "$P3" $PERSISTDIR; then
            echo "$(date -Ins -u) mount $P3 failed"
        fi
    fi
else
    echo "$(date -Ins -u) No separate $PERSISTDIR partition"
fi

UUID_SYMLINK_PATH="/dev/disk/by-uuid"
mkdir -p $UUID_SYMLINK_PATH
chmod 700 $UUID_SYMLINK_PATH
BLK_DEVICES=$(ls /sys/class/block/)
for BLK_DEVICE in $BLK_DEVICES; do
    BLK_UUID=$(blkid "/dev/$BLK_DEVICE" | sed -n 's/.*UUID=//p' | sed 's/"//g' | awk '{print $1}')
    if [ -n "${BLK_UUID}" ]; then
        ln -s "/dev/$BLK_DEVICE" "$UUID_SYMLINK_PATH/$BLK_UUID"
    fi
done
