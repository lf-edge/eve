#!/bin/sh
# Run against a rootfs.img

ROOTFS=rootfs.img
PRINTALL=0

while [ $# != 0 ]; do
    if [ $1 = "-a" ]; then
	PRINTALL=1
    else
	ROOTFS=$1
    fi
    shift
done

sudo mount -o loop ${ROOTFS} /mnt
VERS=`sudo cat /mnt/containers/services/zededa-tools/lower/opt/zededa/bin/versioninfo`
VERS1=`sudo cat /mnt/containers/services/zededa-tools/lower/opt/zededa/bin/versioninfo.1`
ZA=`sudo file -L /mnt/containers/services/zededa-tools/lower/opt/zededa/bin/zedagent`
LZ=`sudo file /mnt/containers/services/zededa-tools/lower/opt/zededa/bin/lisp-ztr`
sudo umount /mnt
echo $VERS
if [ $PRINTALL = 1 ]; then
    echo "version.1: $VERS1"
    echo "file zedagent: $ZA"
    echo "file lisp-ztr: $LZ"
fi
