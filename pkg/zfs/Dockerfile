# syntax=docker/dockerfile-upstream:1.5.0-rc2-labs

# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

# This package builds OpenZFS userspace libraries and tools from source.
# It is intended to be consumed by other packages (dom0-ztools, build-tools,
# pillar, etc.) so that ZFS is built only once.

ARG EVE_ALPINE_IMAGE=lfedge/eve-alpine:745ae9066273c73b0fd879c4ba4ff626a8392d04

# Native build environment (runs under emulation when cross-building)
# hadolint ignore=DL3006
FROM ${EVE_ALPINE_IMAGE} AS build-native
ENV BUILD_PKGS="git patch ca-certificates util-linux build-base gettext-dev libtirpc-dev automake autoconf \
    libtool linux-headers attr-dev e2fsprogs-dev glib-dev openssl-dev util-linux-dev coreutils"
ENV PKGS="ca-certificates util-linux libintl libuuid libtirpc libblkid libcrypto1.1 zlib"
RUN eve-alpine-deploy.sh

# Cross build environment (runs natively on host)
# hadolint ignore=DL3006,DL3029
FROM --platform=${BUILDPLATFORM} ${EVE_ALPINE_IMAGE} AS build-cross
ENV BUILD_PKGS="git patch ca-certificates util-linux build-base gettext-dev libtirpc-dev automake autoconf \
    libtool linux-headers attr-dev e2fsprogs-dev glib-dev openssl-dev util-linux-dev coreutils"
ENV PKGS="ca-certificates util-linux libintl libuuid libtirpc libblkid libcrypto1.1 zlib"
RUN eve-alpine-deploy.sh

# Cross-compilers (host arch)
# hadolint ignore=DL3029
FROM --platform=${BUILDPLATFORM} lfedge/eve-cross-compilers:f476a79bcd086759592a105a49f9ed5bfa2c4ffa AS cross-compilers

# Target-arch libraries needed for cross-compile sysroot
# hadolint ignore=DL3006
FROM ${EVE_ALPINE_IMAGE} AS cross-compile-libs
ENV PKGS="musl-dev libgcc libintl libuuid libtirpc libtirpc-dev libblkid linux-headers \
    util-linux-dev openssl-dev attr-dev e2fsprogs-dev zlib-dev gettext-dev"
RUN eve-alpine-deploy.sh

# Map TARGETARCH to cross-compiler triple
FROM build-cross AS build-cross-target-arm64
ENV EVE_TARGET_ARCH=aarch64
FROM build-cross AS build-cross-target-amd64
ENV EVE_TARGET_ARCH=x86_64

# hadolint ignore=DL3006
FROM build-cross-target-${TARGETARCH} AS build-cross-target
ENV CROSS_COMPILE_ENV="${EVE_TARGET_ARCH}"-alpine-linux-musl-
COPY --from=cross-compilers /packages /packages
# hadolint ignore=DL3018
RUN apk add --no-cache --allow-untrusted -X /packages build-base-"${EVE_TARGET_ARCH}"
COPY --from=cross-compile-libs /out/ /usr/"${EVE_TARGET_ARCH}"-alpine-linux-musl/

# Select: cross when TARGETARCH != BUILDARCH, native when they match
FROM build-cross-target AS target-arm64-build-amd64
FROM build-cross-target AS target-amd64-build-arm64
FROM build-native AS target-amd64-build-amd64
FROM build-native AS target-arm64-build-arm64
# riscv64: no cross-compiler available, always use native (qemu emulation)
FROM build-native AS target-riscv64-build-amd64
FROM build-native AS target-riscv64-build-arm64
FROM build-native AS target-riscv64-build-riscv64

# hadolint ignore=DL3006
FROM target-${TARGETARCH}-build-${BUILDARCH} AS build

# ZFS_VERSION is passed via buildArgs in build-*.yml variants
ARG ZFS_VERSION=2.3.3
ENV ZFS_COMMIT=zfs-${ZFS_VERSION}
ENV ZFS_REPO=https://github.com/openzfs/zfs.git

# CC and LDFLAGS are set by cross-compile stages; empty for native builds
ENV CC=${CROSS_COMPILE_ENV}gcc
ENV LDFLAGS=${CROSS_COMPILE_ENV:+"-lintl"}

WORKDIR /tmp/zfs
# hadolint ignore=DL3020
ADD ${ZFS_REPO}#${ZFS_COMMIT} /tmp/zfs

# For cross-compilation we need --host=<triple> so autoconf picks the
# cross-compiler and builds for the target architecture.
# For native builds CROSS_COMPILE_ENV is empty, so --host is omitted.
RUN ./autogen.sh && \
    ./configure \
    ${CROSS_COMPILE_ENV:+--host="${EVE_TARGET_ARCH}-alpine-linux-musl"} \
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
    make DESTDIR=/tmp/zfs-out install-strip

# cleanup unnecessary files
RUN rm -rf /tmp/zfs-out/usr/share && rm -rf /tmp/zfs-out/usr/src && \
    rm -rf /tmp/zfs-out/etc/init.d && rm -rf /tmp/zfs-out/etc/conf.d

# generate a list of all files produced by the ZFS build so that
# downstream consumers can selectively copy them
# hadolint ignore=DL4006
RUN find /tmp/zfs-out -mindepth 1 | sed 's@/tmp/zfs-out@@' > /tmp/zfs-files

FROM scratch
COPY --from=build /tmp/zfs-out/ /
COPY --from=build /tmp/zfs-files /etc/zfs-files
