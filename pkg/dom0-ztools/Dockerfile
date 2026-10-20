# syntax=docker/dockerfile-upstream:1.5.0-rc2-labs

# Copyright (c) 2025 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

FROM lfedge/eve-ubuntu:17fea35e37517165b27e0e3f142d38750eb0a544 AS zfs
ENV BUILD_PKGS="git patch ca-certificates util-linux build-essential gettext libtirpc-dev automake autoconf \
    libtool linux-libc-dev libattr1-dev libssl-dev uuid-dev libblkid-dev zlib1g-dev libaio-dev pkg-config coreutils"
ENV PKGS="ca-certificates util-linux libuuid1 libtirpc3t64 libblkid1 libssl3t64 zlib1g libaio1t64"
RUN eve-ubuntu-deploy.sh

# should be aligned with kernel
#  * ZFS on Linux
ENV ZFS_VERSION=2.3.6
ENV ZFS_COMMIT=zfs-${ZFS_VERSION}
ENV ZFS_REPO=https://github.com/openzfs/zfs.git

WORKDIR /tmp/zfs
ADD ${ZFS_REPO}#${ZFS_COMMIT} /tmp/zfs

RUN ./autogen.sh && \
    ./configure \
    --prefix=/usr \
    --with-tirpc \
    --sysconfdir=/etc \
    --mandir=/usr/share/man \
    --infodir=/usr/share/info \
    --localstatedir=/var \
    --with-config=user \
    --with-udevdir=/usr/lib/udev \
    --disable-systemd \
    --disable-pyzfs \
    --disable-static && \
    ./scripts/make_gitrev.sh && \
    make -j "$(getconf _NPROCESSORS_ONLN)" && \
    make DESTDIR=/tmp/zfs-out install-strip

# cleanup
RUN rm -rf /tmp/zfs-out/usr/share && rm -rf /tmp/zfs-out/usr/src && \
    rm -rf /tmp/zfs-out/etc/init.d && rm -rf /tmp/zfs-out/etc/conf.d

# make the list of files built from zfs to reuse later (pillar copies them),
# with the paths they have in a merged-/usr rootfs like /out
# hadolint ignore=DL4006
RUN find /tmp/zfs-out \( -type f -o -type l \) | sed -e 's@/tmp/zfs-out@@' -e 's@^/\(bin\|sbin\|lib\|lib64\)/@/usr/\1/@' > /tmp/zfs-files
# hadolint ignore=DL4006
RUN tar -C /tmp/zfs-out -cf - . | tar -C /out --keep-directory-symlink -xf -

# Register zfs in the dpkg status area, mandatory for it to be included in the SBOM.
RUN register-sbom-pkg.sh -n zfs -v "${ZFS_VERSION}" -l CDDL-1.0 -u https://github.com/openzfs/zfs

# The image is an init overlay of the EVE host rootfs (pkg/init, the same
# Ubuntu base): stage the zfs userland with the libraries it needs as plain
# directories (no merged-/usr symlinks), the way the host rootfs is laid out.
# hadolint ignore=SC2046
RUN copy-with-libs.sh -o /stage $(cat /tmp/zfs-files) && \
    cp /tmp/zfs-files /stage/etc/zfs-files && \
    cp -a /out/var/lib/dpkg/status.d /stage/var/lib/dpkg/ && \
    mkdir -p /stage/etc/cdi

### Create system-wide groups and users ###
# root, nobody, the tpms group that owns /dev/tpm* (see mdev.conf) and the
# vtpm user of the vtpm container, which is a member of tpms
RUN printf 'root:x:0:0:root:/root:/bin/sh\nnobody:x:65534:65534:nobody:/nonexistent:/bin/false\nvtpm:x:101:101:vtpm:/nonexistent:/bin/false\n' > /stage/etc/passwd && \
    printf 'root:x:0:\ndisk:x:6:\ntpms:x:100:vtpm\nvtpm:x:101:\nnogroup:x:65534:\n' > /stage/etc/group

FROM scratch
COPY --from=zfs /stage/ /
# hadolint ignore=DL3020
ADD rootfs/ /
