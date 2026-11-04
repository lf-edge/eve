#!/bin/sh
# Copyright (c) 2024 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
# XXX only for demo
# Remove the files created by fdo client and the device.*.pem from onboarding
# then reboot

mount_partlabel() {
  PARTLABEL="$1"
  if [ -z "$2" ]; then
    echo "ERROR: no mountpoint provided" && exit 3
  fi
  MOUNTPOINT="$2"
  if ! mkdir -p "$MOUNTPOINT"; then
     echo "ERROR: failed to ensure $MOUNTPOINT" && exit 1
  fi
  MOUNT_DEV=$(/sbin/findfs PARTLABEL="$PARTLABEL")
  if [ -z "$MOUNT_DEV" ]; then
    echo "ERROR: no device with PARTLABEL=$PARTLABEL found" && exit 1
  fi
  if ! mount -t vfat -o rw,iocharset=iso8859-1 "$MOUNT_DEV" "$MOUNTPOINT"; then
     echo "ERROR: mount $MOUNT_DEV on $MOUNTPOINT failed" && exit 1
  fi
}

unmount_partlabel() {
  PARTLABEL="$1"
  MOUNT_DEV=$(/sbin/findfs PARTLABEL="$PARTLABEL")
  if [ -z "$MOUNT_DEV" ]; then
    echo "ERROR: no device with PARTLABEL=$PARTLABEL found" && exit 1
  fi
  if ! umount "$MOUNT_DEV"; then
     echo "ERROR: umount $MOUNT_DEV failed" && exit 1
  fi
}


# Remove for subsequent boots
MNTPOINT=/tmp/mnt
mkdir $MNTPOINT
mount_partlabel "CONFIG" $MNTPOINT
rm -f $MNTPOINT/server
rm -f $MNTPOINT/root-certificate.pem
rm -f $MNTPOINT/device.*.pem
unmount_partlabel "CONFIG" $MNTPOINT

# Remove from running system
mount -o remount,rw /config
rm -f /config/server
rm -f /config/root-certificate.pem
rm -f /config/device.*.pem
mount -o remount,ro /config

sync
echo "$(date -Ins -u) rebooting in 5 seconds"
sleep 5
sync
reboot

