# syntax=docker/dockerfile-upstream:1.5.0-rc2-labs

# Copyright (c) 2024 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

FROM lfedge/eve-ubuntu:17fea35e37517165b27e0e3f142d38750eb0a544 AS build
ENV BUILD_PKGS="gcc make libc6-dev linux-libc-dev pkg-config gperf gettext libkmod-dev libblkid-dev"
ENV PKGS="kmod libkmod2 libblkid1"
RUN eve-ubuntu-deploy.sh

# eudev, the udev of the former Alpine based image: udevadm copies in other
# packages (wwan) talk to this udevd, so they all come from the same source
# the release tarball ships the configure script and the generated man pages,
# the git tree would need autotools and xsltproc to produce them
ENV EUDEV_VERSION=3.2.14
ADD https://github.com/eudev-project/eudev/releases/download/v${EUDEV_VERSION}/eudev-${EUDEV_VERSION}.tar.gz /eudev.tar.gz
RUN mkdir /eudev && tar -xzf /eudev.tar.gz --strip-components=1 -C /eudev && rm -f /eudev.tar.gz
WORKDIR /eudev
RUN ./configure --prefix=/usr --sysconfdir=/etc --with-rootprefix=/usr --with-rootlibdir=/usr/lib \
                --with-rootlibexecdir=/usr/lib/udev --disable-manpages --disable-static && \
    make -j "$(getconf _NPROCESSORS_ONLN)" && \
    make DESTDIR=/out install
WORKDIR /

# Register eudev in the dpkg status area, mandatory for it to be included in the SBOM.
RUN register-sbom-pkg.sh -n eudev -v "${EUDEV_VERSION}" -l GPL-2.0-only -u https://github.com/eudev-project/eudev

COPY etc/init.d/008-udevd /out/etc/init.d/
COPY etc/udev/rules.d/* /out/etc/udev/rules.d/

# Remove default rules from udev (we don't support many groups from these rules)
# and the hardware database sources, which nothing compiles into a hwdb.bin.
# The block device rules stay: they import the blkid properties (PARTUUID,
# PARTLABEL, ...) into the udev database, which is where Ubuntu's lsblk, used
# by zboot and pillar, takes them from (Alpine's lsblk probed the devices itself).
RUN find /out/usr/lib/udev/rules.d -type f ! -name 60-block.rules ! -name 60-persistent-storage.rules -delete && \
    rm -rf /out/usr/lib/udev/hwdb.d /out/etc/udev/hwdb.d

# The image is an init overlay of the EVE host rootfs: the daemon, the tools
# and the libraries they need, no package manager, no merged-/usr symlinks.
RUN copy-with-libs.sh -o /stage /usr/sbin/udevd /usr/bin/udevadm /usr/bin/kmod /usr/sbin/depmod /usr/sbin/insmod \
        /usr/sbin/lsmod /usr/sbin/modinfo /usr/sbin/modprobe /usr/sbin/rmmod /usr/lib/udev /etc/udev /etc/init.d/008-udevd && \
    cp -a /out/var/lib/dpkg/status.d /stage/var/lib/dpkg/

FROM scratch

COPY --from=build /stage/ /

ENTRYPOINT []
CMD []
