#!/bin/sh

ZFS_BRANCH=zfs-2.2.2

# Build and install libzfs
libzfs() {
    [ -d /zfs ] && return
    apt -y install uuid-dev libblkid-dev libssl-dev
    git clone https://github.com/openzfs/zfs.git -b ${ZFS_BRANCH} /zfs
    cd /zfs || return
    ./autogen.sh && \
    ./configure \
        --prefix=/usr \
        --with-tirpc \
        --sysconfdir=/etc \
        --mandir=/usr/share/man \
        --infodir=/usr/share/info \
        --localstatedir=/var \
        --with-config=user \
        --with-udevdir=/lib/udev \
        --disable-systemd \
        --disable-static && \
    ./scripts/make_gitrev.sh && \
    make -j "$(getconf _NPROCESSORS_ONLN)" && \
    make -j "$(getconf _NPROCESSORS_ONLN)" install
}

# Install dependencies
apt -y update
libzfs

# Run test-patch
test-patch \
    --basedir=/src \
    --test-parallel=true \
    --dirty-workspace \
    --empty-patch \
    --plugins=all \
    --patch-dir=/src/yetus-output
