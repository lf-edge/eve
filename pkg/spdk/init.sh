#!/bin/sh

mkdir -p /dev/shm
mount -t tmpfs tmpfs /dev/shm

mkdir -p /var/tmp/

#Launch the SPDK target
HUGEMEM=256 /usr/share/spdk/scripts/setup.sh

mkdir -p /var/run/spdk/vhost-user/
mkdir -p /var/run/spdk/vhost-user/block/
mkdir -p /var/run/spdk/vhost-user/block/sockets/
mkdir -p /var/run/spdk/vhost-user/block/devices/

#/usr/bin/spdk_tgt -S /var/run/spdk/vhost-user/block/sockets/
/usr/bin/vhost -S /var/run/spdk/vhost-user/block/sockets/

while true; do sleep 60; done
