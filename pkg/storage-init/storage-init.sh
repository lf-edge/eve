#!/bin/sh
#
# Copyright (c) 2018 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

PERSISTDIR=/var/persist
CONFIGDIR=/var/config

# The only bit of initialization we do is to point containerd to /persist
# The trick here is to only do it if /persist is available and otherwise
# allow containerd to run with /var/lib/containerd on tmpfs (to make sure
# that the system comes up somehow)
init_containerd() {
    mkdir -p "$PERSISTDIR/containerd"
    mkdir -p /hostfs/var/lib
    ln -s "$PERSISTDIR/containerd" /hostfs/var/lib/containerd
}

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

# First lets see if we're missing P3 (/persist) altogether and try to create it.
# This is safe, since the worst case scenario we may hose the system, but the
# system without P3 (/persist) is almost a warm brick anyways. The reason we are
# not refusing to proceed though, is that we still hope that if everything else
# fails useful feedback will be reported to the controller about the "warm brick"
# state.
P3=$(/hostfs/sbin/findfs PARTLABEL=P3)
IMGA=$(/hostfs/sbin/findfs PARTLABEL=IMGA)
IMGB=$(/hostfs/sbin/findfs PARTLABEL=IMGB)
# if we don't have a P3 (/persist) partition, but we do have at least IMGA, then
# we can calculate where the P3 (/persist) should exist on disk and make it.
# Optionally same applies to IMGB partition (if it is missing in the GPT).
if [ -z "$P3" ] && [ -n "$IMGA" ]; then
   DEV=$(echo /sys/block/*/"${IMGA#/dev/}")
   DEV="/dev/$(echo "$DEV" | cut -f4 -d/)"

   # if sgdisk complains we need to repair the GPT
   if sgdisk -v "$DEV" | grep -q 'Identified.*problems'; then
       # save a copy of the MBR + first partition entry
       # the logic here is that whatever booted us was good
       # enough to get us here, so we'd rather sgdisk disn't
       # mess up a good thing for us
       dd if="$DEV" of=/tmp/mbr.bin bs=1 count=$((446 + 16)) conv=noerror,sync,notrunc

       sgdisk -h1 -e "$DEV"

       # move 1st MBR entry to 2nd place
       dd if="$DEV" of="$DEV" bs=1 skip=446 seek=$(( 446 + 16)) count=16 conv=noerror,sync,notrunc
       # restore 1st MBR entry + first partition entry
       dd if=/tmp/mbr.bin of="$DEV" bs=1 conv=noerror,sync,notrunc

       # focrce kernel to re-scan partition table
       partprobe "$DEV"
   fi

   # lets see if IMGB partition is around, if not - create it
   if [ -z "$IMGB" ]; then
      IMGA_ID=$(sgdisk -p "$DEV" | grep "IMGA$" | awk '{print $1;}')

      IMGA_SIZE=$(sgdisk -i "$IMGA_ID" "$DEV" | awk '/^Partition size:/ { print $3; }')
      IMGA_GUID=$(sgdisk -i "$IMGA_ID" "$DEV" | awk '/^Partition unique GUID:/ { print $4; }')

      SEC_START=$(sgdisk -f "$DEV")
      SEC_END=$((SEC_START + IMGA_SIZE))
      IMGB_ID=$((IMGA_ID + 1))

      sgdisk --new "$IMGB_ID:$SEC_START:$SEC_END" \
             --typecode="$IMGB_ID:$IMGA_GUID" --change-name="$IMGB_ID:IMGB" "$DEV"
   fi

   LAST_PART_ID=$(sgdisk -p "$DEV" | awk '{a=$1;} END { print a;}')
   P3_ID=$((LAST_PART_ID + 1))
   sgdisk --largest-new="$P3_ID" \
          --typecode="$P3_ID:5f24425a-2dfa-11e8-a270-7b663faccc2c" --change-name="$P3_ID:P3" "$DEV"
fi

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
        else
            init_containerd
        fi
    fi
    #On ext4, enable encryption support before mounting.
    if [ "$P3_FS_TYPE" = "ext4" ]; then
        tune2fs -O encrypt "$P3"
        if ! mount -t ext4 -o dirsync,noatime "$P3" $PERSISTDIR; then
            echo "$(date -Ins -u) mount $P3 failed"
        else
            init_containerd
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
