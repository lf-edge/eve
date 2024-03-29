#!/bin/sh
# Copyright (c) 2024 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
# Invoke the fdo client binary and copy files in place

FDO_CLIENT=/opt/zededa/bin/fdo-alpine-3.16/linux-client
FDO_DIR=/tmp/fdo-files
# Files are deposited in CWD. Really painful to not be able to specify an outdir
rm -rf $FDO_DIR
mkdir $FDO_DIR

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


echo "$(date -Ins -u) Starting FDO client"
# Painful
cp -rp /opt/zededa/bin/fdo-alpine-3.16/data $FDO_DIR
(cd $FDO_DIR || exit 2; $FDO_CLIENT)
echo "$(date -Ins -u) FDO client got files:" $FDO_DIR/*

# In case there are .txt extensions
if [ -f $FDO_DIR/server.txt ]; then
    mv $FDO_DIR/server.txt $FDO_DIR/server
fi
if [ -f $FDO_DIR/root-certificate.pem.txt ]; then
    mv $FDO_DIR/root-certificate.pem.txt $FDO_DIR/root-certificate.pem
fi
if ! [ -f $FDO_DIR/server ] && ! [ -f $FDO_DIR/root-certificate.pem ]; then
    echo "$(date -Ins -u) FDO client - no files. Wait a bit"
    sleep 10
    exit 1
fi
# Make available for subsequent boots
MNTPOINT=/tmp/mnt
mkdir $MNTPOINT
mount_partlabel "CONFIG" $MNTPOINT
cp -p $FDO_DIR/server $MNTPOINT/server
cp -p $FDO_DIR/root-certificate.pem $MNTPOINT/root-certificate.pem
unmount_partlabel "CONFIG" $MNTPOINT

# Make available to running system
mount -o remount,rw /config
cp -p $FDO_DIR/server /config/server
cp -p $FDO_DIR/root-certificate.pem /config/root-certificate.pem
mount -o remount,ro /config

echo "$(date -Ins -u) FDO client saved files:" /config/*
if [ -f /config/server ] && [ -f /config/root-certificate.pem ]; then
    exit 0
else
    sleep 60
    exit 0
fi
