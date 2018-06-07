#!/bin/sh
# Run against a rootfs.img

ROOTFS=rootfs.img

if [ $# = 1 ]; then
    ROOTFS=$1
fi

sudo mount -o loop ${ROOTFS} /mnt
VERS=`sudo cat /mnt/containers/services/zededa-tools/lower/opt/zededa/bin/versioninfo`
sudo umount /mnt
echo $VERS
