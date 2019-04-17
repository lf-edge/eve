#!/bin/sh

bail() {
  echo "$@"
  exit 0
}

if [ $# -eq 0 ] ; then
   echo "Usage: $0 [-|shell_script]"
   echo "       specifying - instead of a shell script will generate tarball.gz on stdout"
elif [ "$1" = "-" ] ; then
   tar -C /bits -czf - .
elif [ "$1" = "version" ] ; then
   mount -o loop /bits/rootfs.img /mnt >/dev/null 2>&1 || bail "FAIL: make sure to add --privileged to you docker run"
   cat /mnt/containers/services/pillar/lower/opt/zededa/bin/versioninfo
   umount /mnt
else
   bash -c "$*"
fi
