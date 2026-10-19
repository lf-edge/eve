# syntax=docker/dockerfile-upstream:1.5.0-rc2-labs

# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

# The service every domain's QEMU runs in. pillar starts each domain as a
# containerd task whose root is this service's rootfs, so the image carries
# QEMU, the libraries it links, the firmware it loads (OVMF and igd.rom, from
# pkg/uefi) and the tap setup script, /etc/qemu-ifup. The service process
# itself (init.sh) only prepares the rootfs and stays up.
#
# QEMU is built for KVM from the upstream release, with EVE's patches in
# patches/ (see patches/README.md). The release tarball carries the meson
# subprojects the build uses, so it needs no network. liburing is built from
# source: the eve-alpine mirror has its runtime library but not liburing-dev.
#
# QEMU and liburing are compiled on the build platform, with EVE's cross
# compilers when it differs from the target, never under emulation: only the
# package installs and the final library check run as the target.

# Tools that run on the build platform.
ARG BUILD_PKGS_BASE="build-base meson samurai pkgconf python3 py3-setuptools py3-pip py3-wheel \
    perl bash coreutils patch flex bison"
# Headers and libraries of the target that QEMU and liburing build against.
ARG TARGET_DEV_PKGS="musl-dev libgcc linux-headers glib-dev pixman-dev zlib-dev gnutls-dev \
    libusb-dev zstd-dev libaio-dev bzip2-dev libcap-ng-dev attr-dev util-linux-dev dtc-dev"
ARG EVE_ALPINE_IMAGE=lfedge/eve-alpine:1fdf3241f1aef1dd3e8ad7433c85474bc522f3f5

FROM lfedge/eve-uefi:3f3413e719c910ad307ff5f3efe2c77eb5db11e9 AS uefi-build

# The base the scripts run on, and the Alpine libraries QEMU links.
# hadolint ignore=DL3006
FROM ${EVE_ALPINE_IMAGE} AS runtime
ENV PKGS="alpine-baselayout libgcc bash musl-utils keyutils util-linux-misc \
    glib pixman gnutls libusb libaio libbz2 xz-libs zstd-libs zlib libuuid libfdt"
RUN eve-alpine-deploy.sh

# hadolint ignore=DL3006
FROM ${EVE_ALPINE_IMAGE} AS build-native
ARG BUILD_PKGS_BASE
ARG TARGET_DEV_PKGS
RUN BUILD_PKGS="${BUILD_PKGS_BASE} ${TARGET_DEV_PKGS}" eve-alpine-deploy.sh

# hadolint ignore=DL3006,DL3029
FROM --platform=${BUILDPLATFORM} ${EVE_ALPINE_IMAGE} AS build-cross
ARG BUILD_PKGS_BASE
RUN BUILD_PKGS="${BUILD_PKGS_BASE}" eve-alpine-deploy.sh

# hadolint ignore=DL3029
FROM --platform=${BUILDPLATFORM} lfedge/eve-cross-compilers:c86cb13f88256ac3ca3ec1f8d746dc3ed74b1ed2 AS cross-compilers

# The target's headers and libraries, for the cross compiler's sysroot.
# hadolint ignore=DL3006
FROM ${EVE_ALPINE_IMAGE} AS cross-compile-libs
ARG TARGET_DEV_PKGS
ENV PKGS=${TARGET_DEV_PKGS}
RUN eve-alpine-deploy.sh

FROM build-cross AS build-cross-target-arm64
ENV EVE_TARGET_ARCH=aarch64
FROM build-cross AS build-cross-target-amd64
ENV EVE_TARGET_ARCH=x86_64

# hadolint ignore=DL3006
FROM build-cross-target-${TARGETARCH} AS build-cross-target
ENV CROSS_COMPILE_ENV="${EVE_TARGET_ARCH}"-alpine-linux-musl-
ENV SYSROOT=/usr/"${EVE_TARGET_ARCH}"-alpine-linux-musl
COPY --from=cross-compilers /packages /packages
# hadolint ignore=DL3018
RUN apk add --no-cache --allow-untrusted -X /packages build-base-"${EVE_TARGET_ARCH}"
COPY --from=cross-compile-libs /out/ ${SYSROOT}/
# GCC 14 no longer passes its configured sysroot to the linker, so name it
# for both, and point pkg-config at the target's .pc files.
ENV SYSROOT_FLAGS="--sysroot=${SYSROOT}"
ENV PKG_CONFIG_SYSROOT_DIR=${SYSROOT}
ENV PKG_CONFIG_LIBDIR=${SYSROOT}/usr/lib/pkgconfig:${SYSROOT}/usr/share/pkgconfig

FROM build-cross-target AS target-arm64-build-amd64
FROM build-cross-target AS target-amd64-build-arm64
FROM build-native AS target-amd64-build-amd64
FROM build-native AS target-arm64-build-arm64

# hadolint ignore=DL3006
FROM target-${TARGETARCH}-build-${BUILDARCH} AS build
ARG TARGETARCH

# QEMU_RELEASE, not QEMU_VERSION: qemu-user reads QEMU_* variables as its own
# options, and QEMU_VERSION would turn every emulated step into `-version`.
ENV LIBURING_VERSION=2.15
ENV LIBURING_SHA256=28661631f95fce6b3a0f77e40442a937cf4c62cac76a2671ad68378cafb5c21e
ENV QEMU_RELEASE=11.1.2
ENV QEMU_SHA256=731b5681e4bb18be313231579b8efd0296c5b015fa36dc533874b639ba838016
# hadolint ignore=DL3020
ADD https://git.kernel.org/pub/scm/linux/kernel/git/axboe/liburing.git/snapshot/liburing-${LIBURING_VERSION}.tar.gz /liburing.tar.gz
# hadolint ignore=DL3020
ADD https://download.qemu.org/qemu-${QEMU_RELEASE}.tar.xz /qemu.tar.xz
RUN printf '%s  %s\n' "$LIBURING_SHA256" /liburing.tar.gz "$QEMU_SHA256" /qemu.tar.xz > /sources.sha256 && \
    sha256sum -c /sources.sha256 && \
    mkdir -p /src && \
    tar -C /src -xzf /liburing.tar.gz && \
    tar -C /src -xJf /qemu.tar.xz

# liburing is installed twice: into the image, and into the build root (the
# sysroot, when cross compiling) for QEMU to build against.
WORKDIR /src/liburing-${LIBURING_VERSION}
RUN CFLAGS="-O2 ${SYSROOT_FLAGS:-}" LDFLAGS="${SYSROOT_FLAGS:-}" \
        ./configure --prefix=/usr --cc="${CROSS_COMPILE_ENV:-}gcc" && \
    make -C src -j "$(getconf _NPROCESSORS_ONLN)" && \
    make install DESTDIR=/dist && \
    make install DESTDIR="${SYSROOT:-/}" && \
    "${CROSS_COMPILE_ENV:-}"strip /dist/usr/lib/liburing*.so.*

# A patch that no longer applies exactly fails the build: no fuzz, no
# reversed or already-applied hunks.
WORKDIR /src/qemu-${QEMU_RELEASE}
COPY patches /patches
RUN for p in /patches/*.patch; do \
        patch -p1 --fuzz=0 --forward --batch < "$p" || exit 1; \
    done

# DEBUG ONLY: to build the x-inject-internal-error QMP command (patch 9006),
# uncomment this line. linuxkit cannot pass build arguments, so the edit is
# the toggle. Production builds have neither the code nor the command.
# ENV QEMU_DEBUG_CFLAGS="-DCONFIG_EVE_CRASH_INJECTOR"

# Nothing on the device uses QEMU's tools (pillar ships its own qemu-img),
# TCG plugins or slirp user networking, so none is built. Frame pointers stay,
# so that a core dump gives a usable stack: unwinding a musl-linked QEMU
# without them yields a few frames at best.
RUN case "${TARGETARCH}" in \
        amd64) TARGETS=x86_64-softmmu ;; \
        arm64) TARGETS=aarch64-softmmu ;; \
        *)     echo "unsupported architecture ${TARGETARCH}"; exit 1 ;; \
    esac && \
    PKG_CONFIG=pkg-config ./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var \
        --cross-prefix="${CROSS_COMPILE_ENV:-}" \
        --target-list="$TARGETS" --disable-download \
        --enable-kvm --disable-xen --disable-tools --disable-plugins \
        --disable-werror --disable-docs --disable-guest-agent \
        --disable-slirp --disable-sdl --disable-gtk --disable-curses \
        --disable-opengl --disable-dbus-display \
        --enable-trace-backends=log,simple \
        --enable-libusb --enable-linux-aio --enable-linux-io-uring --enable-zstd \
        --enable-vhost-net --enable-vhost-kernel --enable-vhost-user \
        --enable-virtfs --enable-tpm --enable-vnc --enable-gnutls --enable-fdt=system \
        --extra-cflags="${SYSROOT_FLAGS:-} -DXATTR_SIZE_MAX=65536 -fno-omit-frame-pointer ${QEMU_DEBUG_CFLAGS:-}" \
        --extra-ldflags="${SYSROOT_FLAGS:-}" && \
    make -j "$(getconf _NPROCESSORS_ONLN)" && \
    make install DESTDIR=/dist

# QEMU ships stripped. To ship its debug info - so that a core from a device
# opens against the rootfs in gdb with no further setup - replace the plain
# strip below with the commented split, which keeps the symbols under
# /usr/lib/debug, where gdb finds them through .gnu_debuglink.
RUN "${CROSS_COMPILE_ENV:-}"strip /dist/usr/bin/qemu-system-*
# RUN mkdir -p /dist/usr/lib/debug/usr/bin && \
#     for f in /dist/usr/bin/qemu-system-*; do \
#         b=$(basename "$f"); \
#         "${CROSS_COMPILE_ENV:-}"objcopy --only-keep-debug "$f" "/dist/usr/lib/debug/usr/bin/$b.debug" && \
#         "${CROSS_COMPILE_ENV:-}"strip --strip-debug --strip-unneeded "$f" && \
#         "${CROSS_COMPILE_ENV:-}"objcopy --add-gnu-debuglink="/dist/usr/lib/debug/usr/bin/$b.debug" "$f"; \
#     done

COPY --from=uefi-build / /uefi/
RUN mkdir -p /dist/usr/share/ovmf && \
    cp /uefi/OVMF.fd /dist/usr/share/ovmf/OVMF.fd && \
    if [ "${TARGETARCH}" = amd64 ]; then \
        cp /uefi/OVMF_CODE.fd /dist/usr/share/ovmf/OVMF_CODE.fd && \
        cp /uefi/igd.rom /dist/usr/share/qemu/igd.rom; \
    fi

# Build-time files, and QEMU firmware for machines EVE never runs. The edk2
# images go too: EVE's OVMF comes from pkg/uefi.
RUN rm -rf /dist/var /dist/usr/include /dist/usr/lib/pkgconfig /dist/usr/man /dist/usr/share/man \
           /dist/usr/share/doc /dist/usr/share/qemu/edk2-* /dist/usr/share/qemu/openbios-* && \
    find /dist -type f -name '*.a' -delete && \
    rm -f /dist/usr/share/qemu/skiboot.lid /dist/usr/share/qemu/hppa-firmware.img \
          /dist/usr/share/qemu/hppa-firmware64.img /dist/usr/share/qemu/s390-ccw.img \
          /dist/usr/share/qemu/s390-netboot.img /dist/usr/share/qemu/slof.bin \
          /dist/usr/share/qemu/opensbi-riscv32-generic-fw_dynamic.bin \
          /dist/usr/share/qemu/opensbi-riscv64-generic-fw_dynamic.bin

RUN register-sbom-pkg.sh -o /sbom -n liburing -v "${LIBURING_VERSION}" \
        -l "LGPL-2.1-only OR MIT" -u https://github.com/axboe/liburing && \
    register-sbom-pkg.sh -o /sbom -n qemu -v "${QEMU_RELEASE}" -l GPL-2.0-only \
        -u https://www.qemu.org

# QEMU joins its runtime libraries, as the target.
FROM runtime AS image
COPY --from=build /dist/ /out/
COPY --from=build /sbom/lib/apk/db/installed /qemu-sbom
RUN merge-sbom-db.sh -o /out/lib/apk/db/installed /out/lib/apk/db/installed /qemu-sbom && \
    rm -rf /out/var/run
# Fail here, not at the first VM start, if a library QEMU needs is missing:
# resolve it inside the image with the image's own loader, which exits
# non-zero when anything is unresolved.
RUN for f in /out/usr/bin/qemu-system-*; do \
        chroot /out "/lib/ld-musl-$(uname -m).so.1" --list "${f#/out}" >/dev/null || \
            { echo "ERROR: $f does not resolve in the image"; exit 1; }; \
    done

FROM scratch
COPY --from=image /out/ /
COPY init.sh /
COPY qemu-ifup /etc/

# Adjust /var/run, /var/lib and /var/lock to be shared
RUN mv /var /var.template && ln -s /run /var && ln -s /run /var.template/run

# Add a few mountpoints so we can use lowerfs in R/O mode
RUN mkdir /persist /hostfs

ENTRYPOINT []
CMD ["/init.sh"]
