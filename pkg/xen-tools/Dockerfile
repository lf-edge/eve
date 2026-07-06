# syntax=docker/dockerfile-upstream:1.5.0-rc2-labs

# Copyright (c) 2023-2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

FROM lfedge/eve-uefi:849c3926f4680b9012cadb9c8116dae86cbbad23 AS uefi-build
FROM lfedge/eve-alpine:f9b45a5a3b3a18a8503cbe6d1258a1025450fe0e AS runx-build
ENV BUILD_PKGS="mkinitfs gcc musl-dev e2fsprogs chrony agetty"
RUN eve-alpine-deploy.sh

RUN rm -f /sbin/poweroff /etc/mkinitfs/features.d/base.files
COPY initrd/base.files /etc/mkinitfs/features.d/base.files
COPY initrd/init-initrd initrd/mount_disk.sh initrd/udhcpc_script.sh /
COPY initrd/poweroff /sbin/poweroff
COPY initrd/chroot2.c initrd/hacf.c /tmp/
COPY initrd/00000080 /etc/acpi/PWRF/
COPY initrd/eve-enter-container /bin/
COPY initrd/dotprofile /root/.profile
RUN gcc -s -o /chroot2 /tmp/chroot2.c -Wall -Werror
RUN gcc -s -o /hacf /tmp/hacf.c -Wall -Werror
RUN mkinitfs -n -F base -i /init-initrd -o /runx-initrd

FROM lfedge/eve-alpine:f9b45a5a3b3a18a8503cbe6d1258a1025450fe0e AS build
ENV BUILD_PKGS="\
    gcc make libc-dev dev86 xz-dev perl bash python3-dev \
    gettext iasl util-linux-dev ncurses-dev glib-dev \
    pixman-dev libaio-dev yajl-dev argp-standalone \
    linux-headers git patch texinfo tar libcap-ng-dev \
    attr-dev flex bison cmake libusb-dev zstd-dev \
    python3 build-base ninja gnutls-dev agetty py3-setuptools"

ENV BUILD_PKGS_arm64=dtc-dev

ENV PKGS="alpine-baselayout libgcc bash musl-utils libaio libbz2 glib pixman yajl keyutils libusb xz-libs libuuid zstd-libs util-linux-misc gnutls"
ENV PKGS_arm64=libfdt

RUN eve-alpine-deploy.sh

# Alpine linux defines all 64bit integer types as long. Patch
# /usr/include/bits/alltypes.h to fix compilation with -m32
WORKDIR /
COPY alpine.patch /
RUN patch -p1 < alpine.patch

ENV LIBURING_VERSION=0.7
ENV LIBURING_SOURCE=https://git.kernel.org/pub/scm/linux/kernel/git/axboe/liburing.git/snapshot/liburing-${LIBURING_VERSION}.tar.gz

# Download and verify liburing
# hadolint ignore=DL3020
ADD ${LIBURING_SOURCE} /liburing.tar.gz
RUN tar --absolute-names -xz < /liburing.tar.gz && mv "/liburing-${LIBURING_VERSION}" /liburing

WORKDIR /liburing
RUN ./configure --prefix=/usr
RUN make src && make install DESTDIR=/out && make install

# Filter out unneeded stuff
RUN rm -rf /out/usr/man
RUN strip /out/usr/lib/* || :

# Register liburing in the APK DB, mandatory for it to be included in the SBOM.
RUN register-sbom-pkg.sh -n liburing -v "${LIBURING_VERSION}" -l LGPL-2.1-only -u https://github.com/axboe/liburing

# When changing this version, also update SEABIOS_UPSTREAM_REVISION to whatever is in `Config.mk` in the xen source
ENV XEN_VERSION=4.21.1
ENV XEN_SOURCE=https://downloads.xenproject.org/release/xen/${XEN_VERSION}/xen-${XEN_VERSION}.tar.gz
ENV EXTRA_QEMUU_CONFIGURE_ARGS="--enable-libusb --enable-linux-aio \
    --enable-vhost-net --enable-vhost-kernel \
    --enable-vhost-user --enable-linux-io-uring --enable-zstd"

WORKDIR /

# Download and verify xen
#TODO: verify Xen
# hadolint ignore=DL3020
ADD ${XEN_SOURCE} /xen.tar.gz
RUN [ -f "$(basename ${XEN_SOURCE})" ] || tar --absolute-names -xz < /xen.tar.gz && mv "/xen-${XEN_VERSION}" /xen

# Starting with xen 4.21, the release tarball no longer bundles tools/qemu-xen/
# in-tree (4.19 did).  Fetch the qemu source separately so our local patches in
# patches-${XEN_VERSION} that touch tools/qemu-xen/ have something to apply
# against, and so the xen build uses our patched tree instead of cloning a
# fresh one.
#
# We pull the official upstream qemu release tarball rather than cloning
# xenbits.xen.org/qemu-xen.git so that every source line in the resulting
# image can be attributed to a discrete URL + sha256 by the buildkit SBOM
# scanner.  A `RUN git clone` would be opaque to that tooling.
#
# qemu-xen-4.21.0 ≡ upstream qemu v9.1.0 plus two small Xen-bus patches
# (xs_node_read helper, %ms scanf fix); we carry those as 02-/03- patches in
# patches-${XEN_VERSION}/ so the resulting tree is functionally identical to
# qemu-xen-4.21.0.
ENV QEMU_VERSION=9.1.0
ENV QEMU_SOURCE=https://download.qemu.org/qemu-${QEMU_VERSION}.tar.xz
# hadolint ignore=DL3020
ADD ${QEMU_SOURCE} /qemu.tar.xz
RUN mkdir -p /xen/tools/qemu-xen && \
    tar --absolute-names -xJf /qemu.tar.xz --strip-components=1 -C /xen/tools/qemu-xen && \
    rm -f /qemu.tar.xz && \
    rm -rf /xen/tools/qemu-xen/roms

# Meson subprojects.  qemu's release tarball ships .wrap files (not the
# subproject source itself); without these, the meson build step in the
# qemu configure phase would try to `git clone` each from gitlab.com at
# build time, which (a) leaks the source URL out of the SBOM, and (b)
# requires `network: yes` in build.yml.
#
# Instead, ADD each subproject's tarball at the exact SHA the wrap pins
# (one ADD per source = one SBOM record per source) and stage them under
# subprojects/<name>/ where meson expects them.  Meson short-circuits the
# wrap fetch when the target directory already exists.
# hadolint ignore=DL3020
ADD https://gitlab.com/qemu-project/berkeley-softfloat-3/-/archive/b64af41c3276f97f0e181920400ee056b9c88037/berkeley-softfloat-3-b64af41c3276f97f0e181920400ee056b9c88037.tar.gz /subprojects/berkeley-softfloat-3.tar.gz
# hadolint ignore=DL3020
ADD https://gitlab.com/qemu-project/berkeley-testfloat-3/-/archive/e7af9751d9f9fd3b47911f51a5cfd08af256a9ab/berkeley-testfloat-3-e7af9751d9f9fd3b47911f51a5cfd08af256a9ab.tar.gz /subprojects/berkeley-testfloat-3.tar.gz
# hadolint ignore=DL3020
ADD https://gitlab.com/qemu-project/dtc/-/archive/b6910bec11614980a21e46fbccc35934b671bd81/dtc-b6910bec11614980a21e46fbccc35934b671bd81.tar.gz /subprojects/dtc.tar.gz
# hadolint ignore=DL3020
ADD https://gitlab.com/qemu-project/keycodemapdb/-/archive/f5772a62ec52591ff6870b7e8ef32482371f22c6/keycodemapdb-f5772a62ec52591ff6870b7e8ef32482371f22c6.tar.gz /subprojects/keycodemapdb.tar.gz
# hadolint ignore=DL3020
ADD https://gitlab.com/libblkio/libblkio/-/archive/f84cc963a444e4cb34813b2dcfc5bf8526947dc0/libblkio-f84cc963a444e4cb34813b2dcfc5bf8526947dc0.tar.gz /subprojects/libblkio.tar.gz
# hadolint ignore=DL3020
ADD https://gitlab.com/qemu-project/libvfio-user/-/archive/0b28d205572c80b568a1003db2c8f37ca333e4d7/libvfio-user-0b28d205572c80b568a1003db2c8f37ca333e4d7.tar.gz /subprojects/libvfio-user.tar.gz
# hadolint ignore=DL3020
ADD https://gitlab.freedesktop.org/slirp/libslirp/-/archive/26be815b86e8d49add8c9a8b320239b9594ff03d/libslirp-26be815b86e8d49add8c9a8b320239b9594ff03d.tar.gz /subprojects/slirp.tar.gz
RUN cd /xen/tools/qemu-xen/subprojects && \
    for name in berkeley-softfloat-3 berkeley-testfloat-3 dtc keycodemapdb libblkio libvfio-user slirp; do \
        rm -rf "$name" && mkdir "$name" && \
        tar --absolute-names -xzf "/subprojects/$name.tar.gz" -C "$name" --strip-components=1; \
    done && \
    # berkeley-softfloat-3 / berkeley-testfloat-3 .wrap files declare
    # `patch_directory = <name>`, telling meson to overlay
    # subprojects/packagefiles/<name>/ (a meson.build that qemu provides for
    # this otherwise-build-system-less upstream) onto the extracted source.
    # When meson skips the wrap fetch (because we pre-extracted), it also
    # skips the overlay — apply it manually here.
    for name in berkeley-softfloat-3 berkeley-testfloat-3; do \
        cp -r packagefiles/"$name"/. "$name"/; \
    done && \
    rm -rf /subprojects

# Apply local patches
COPY patches-${XEN_VERSION} /patches
WORKDIR /xen
RUN cat /patches/*.patch /patches/"$(uname -m)"/*.patch | patch -p1

# we will need this to build xen; without it, it will try and download directly
# Note that Xen's `configure` command uses this env variable SEABIOS_UPSTREAM_URL to find the seabios source.
ENV SEABIOS_UPSTREAM_URL /seabios.git
# this revision should be kept in sync with the XEN_VERSION by reading `Config.mk` in the xen source
ENV SEABIOS_UPSTREAM_REVISION rel-1.16.3
ADD --keep-git-dir git://xenbits.xen.org/seabios.git#${SEABIOS_UPSTREAM_REVISION} ${SEABIOS_UPSTREAM_URL}
# we need this because it will complain about ambiguous refs
RUN git config --global core.warnambiguousrefs false

RUN mkdir -p /out

# FEATURES="--enable-stubdom --enable-vtpm-stubdom --enable-vtpmmgr-stubdom"
COPY gmp.patch /xen/stubdom

WORKDIR /xen

# disable golang as it does not play well together with musl (stderr is defined as FILE* const and fails to compile)
RUN ./configure --prefix=/usr --disable-xen --disable-golang --disable-qemu-traditional --disable-docs --enable-9pfs \
    --with-system-ovmf=/usr/lib/xen/boot/ovmf.bin --disable-stubdom --disable-openbios \
    --enable-vhost-vsock --enable-vhost-scsi \
    --disable-microblaze --disable-mips --disable-ppc \
    --disable-sparc --disable-tricore --disable-alpha --disable-hppa \
    --disable-storage-daemon
RUN make -j "$(getconf _NPROCESSORS_ONLN)" && make dist
RUN dist/install.sh /out

# Register xen in the APK DB, mandatory for it to be included in the SBOM.
RUN register-sbom-pkg.sh -n xen -v "${XEN_VERSION}" -l GPL-2.0-only -u https://xenproject.org

# Register seabios in the APK DB, mandatory for it to be included in the SBOM.
RUN register-sbom-pkg.sh -n seabios -v "${SEABIOS_UPSTREAM_REVISION}" -l LGPL-2.1-only -u https://www.seabios.org

# Filter out a few things that we don't currently need
RUN rm -rf /out/usr/share/qemu-xen/qemu/edk2-* /out/var/run /usr/include /usr/lib/*.a
# FIXME: this is a workaround for Xen on ARM still requiring qemu-system-i386
#   https://wiki.xenproject.org/wiki/Xen_ARM_with_Virtualization_Extensions#Use_of_qemu-system-i386_on_ARM
WORKDIR /out/usr/lib/xen/bin/
RUN strip * || :
RUN if [ "$(uname -m)" = "x86_64" ]; then rm -f qemu-system-i386 && ln -s "qemu-system-$(uname -m)" qemu-system-i386 ;fi

COPY --from=uefi-build / /uefi/
RUN mkdir -p /out/usr/lib/xen/boot && cp /uefi/OVMF.fd /out/usr/lib/xen/boot/ovmf.bin && \
    cp /uefi/OVMF_PVH.fd /out/usr/lib/xen/boot/ovmf-pvh.bin && \
    { [ -f /uefi/OVMF_CODE.fd ] && cp /uefi/OVMF_CODE.fd /out/usr/lib/xen/boot/OVMF_CODE.fd || :; } && \
    { [ -f /uefi/igd.rom ] && cp /uefi/igd.rom /out/usr/lib/xen/boot/igd.rom || :; }

# We need to keep a slim profile, which means removing things we don't need
RUN rm -rf /out/usr/lib/libxen*.a /out/usr/lib/libxl*.a /out/usr/lib/debug /out/usr/lib/python*
RUN rm -rf /out/usr/share/man
RUN rm -rf /out/usr/share/qemu-xen/qemu/openbios-*
RUN rm -rf /out/usr/lib/xen/bin/qemu-storage-daemon
RUN rm /out/usr/share/qemu-xen/qemu/skiboot.lid
RUN rm /out/usr/share/qemu-xen/qemu/hppa-firmware.img
RUN rm /out/usr/share/qemu-xen/qemu/s390-netboot.img
RUN rm /out/usr/share/qemu-xen/qemu/opensbi-riscv32-generic-fw_dynamic.bin
RUN rm /out/usr/share/qemu-xen/qemu/opensbi-riscv64-generic-fw_dynamic.bin
RUN rm /out/usr/share/qemu-xen/qemu/slof.bin

FROM scratch
COPY --from=build /out/ /
COPY --from=runx-build /runx-initrd /usr/lib/xen/boot/runx-initrd
COPY init.sh /
COPY qemu-ifup xen-start /etc/xen/scripts/

# Adjust /var/run, /var/lib and /var/lock to be shared
RUN mv /var /var.template && ln -s /run /var && ln -s /run /var.template/run

# Add a few mountpoints so we can use lowerfs in R/O mode
RUN mkdir /persist /hostfs

ENTRYPOINT []
CMD ["/init.sh"]
