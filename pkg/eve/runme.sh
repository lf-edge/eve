#!/bin/sh

bail() {
  echo "$@"
  exit 1
}

if [ $# -eq 0 ] ; then
   echo "Usage: $0 [-|shell_script]"
   echo "       specifying - instead of a shell script will generate tarball.gz on stdout"
elif [ "$1" = "-" ] ; then
   tar -C /bits -czf - .
elif [ "$1" = "version" ] ; then
   unsquashfs -d /tmp/v /bits/rootfs.img /etc/eve-release > /dev/null 2>&1 || bail "can't unpack rootfs"
   VERSION=$(cat /tmp/v/etc/eve-release)
   echo "$VERSION"
else
   bash -c "$*"
fi
