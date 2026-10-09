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

FROM lfedge/eve-uefi:69dbd346e47296abc02b605cc54b3f6e4fba4e98 AS uefi-build

FROM lfedge/eve-alpine:080e2b4c683508649d72d2ae9b166153d819ca5d AS build
# py3-setuptools, py3-pip and py3-wheel: configure builds QEMU's Python
# tooling venv from the system site packages.
ENV BUILD_PKGS="build-base meson samurai pkgconf python3 py3-setuptools py3-pip py3-wheel \
    perl bash coreutils patch linux-headers flex bison glib-dev pixman-dev zlib-dev gnutls-dev \
    libusb-dev zstd-dev libaio-dev bzip2-dev libcap-ng-dev attr-dev util-linux-dev dtc-dev"
# The base the scripts run on, and the Alpine libraries QEMU links.
ENV PKGS="alpine-baselayout libgcc bash musl-utils keyutils util-linux-misc \
    glib pixman gnutls libusb libaio libbz2 xz-libs zstd-libs zlib libuuid libfdt"
RUN eve-alpine-deploy.sh

ENV LIBURING_VERSION=2.15
ENV LIBURING_SHA256=28661631f95fce6b3a0f77e40442a937cf4c62cac76a2671ad68378cafb5c21e
ENV QEMU_VERSION=11.1.2
ENV QEMU_SHA256=731b5681e4bb18be313231579b8efd0296c5b015fa36dc533874b639ba838016
# hadolint ignore=DL3020
ADD https://git.kernel.org/pub/scm/linux/kernel/git/axboe/liburing.git/snapshot/liburing-${LIBURING_VERSION}.tar.gz /liburing.tar.gz
# hadolint ignore=DL3020
ADD https://download.qemu.org/qemu-${QEMU_VERSION}.tar.xz /qemu.tar.xz
RUN printf '%s  %s\n' "$LIBURING_SHA256" /liburing.tar.gz "$QEMU_SHA256" /qemu.tar.xz > /sources.sha256 && \
    sha256sum -c /sources.sha256 && \
    mkdir -p /src && \
    tar -C /src -xzf /liburing.tar.gz && \
    tar -C /src -xJf /qemu.tar.xz

# liburing is installed twice: into the image, and into the build root for
# QEMU to build against.
WORKDIR /src/liburing-${LIBURING_VERSION}
RUN ./configure --prefix=/usr && \
    make -C src -j "$(getconf _NPROCESSORS_ONLN)" && \
    make install DESTDIR=/out && \
    make install && \
    strip /out/usr/lib/liburing*.so.*

# A patch that no longer applies exactly fails the build: no fuzz, no
# reversed or already-applied hunks.
WORKDIR /src/qemu-${QEMU_VERSION}
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
RUN case "$(uname -m)" in \
        x86_64)  TARGETS=x86_64-softmmu ;; \
        aarch64) TARGETS=aarch64-softmmu ;; \
        *)       echo "unsupported architecture $(uname -m)"; exit 1 ;; \
    esac && \
    ./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var \
        --target-list="$TARGETS" --disable-download \
        --enable-kvm --disable-xen --disable-tools --disable-plugins \
        --disable-werror --disable-docs --disable-guest-agent \
        --disable-slirp --disable-sdl --disable-gtk --disable-curses \
        --disable-opengl --disable-dbus-display \
        --enable-trace-backends=log,simple \
        --enable-libusb --enable-linux-aio --enable-linux-io-uring --enable-zstd \
        --enable-vhost-net --enable-vhost-kernel --enable-vhost-user \
        --enable-virtfs --enable-tpm --enable-vnc --enable-gnutls --enable-fdt=system \
        --extra-cflags="-DXATTR_SIZE_MAX=65536 -fno-omit-frame-pointer ${QEMU_DEBUG_CFLAGS:-}" && \
    make -j "$(getconf _NPROCESSORS_ONLN)" && \
    make install DESTDIR=/out

# QEMU ships stripped. To ship its debug info - so that a core from a device
# opens against the rootfs in gdb with no further setup - replace the plain
# strip below with the commented split, which keeps the symbols under
# /usr/lib/debug, where gdb finds them through .gnu_debuglink.
RUN strip /out/usr/bin/qemu-system-*
# RUN mkdir -p /out/usr/lib/debug/usr/bin && \
#     for f in /out/usr/bin/qemu-system-*; do \
#         b=$(basename "$f"); \
#         objcopy --only-keep-debug "$f" "/out/usr/lib/debug/usr/bin/$b.debug" && \
#         strip --strip-debug --strip-unneeded "$f" && \
#         objcopy --add-gnu-debuglink="/out/usr/lib/debug/usr/bin/$b.debug" "$f"; \
#     done

# Fail here, not at the first VM start, if a library QEMU needs is missing:
# resolve it inside the image with the image's own loader, which exits
# non-zero when anything is unresolved.
RUN for f in /out/usr/bin/qemu-system-*; do \
        chroot /out "/lib/ld-musl-$(uname -m).so.1" --list "${f#/out}" >/dev/null || \
            { echo "ERROR: $f does not resolve in the image"; exit 1; }; \
    done

COPY --from=uefi-build / /uefi/
RUN mkdir -p /out/usr/share/ovmf && \
    cp /uefi/OVMF.fd /out/usr/share/ovmf/OVMF.fd && \
    if [ "$(uname -m)" = x86_64 ]; then \
        cp /uefi/OVMF_CODE.fd /out/usr/share/ovmf/OVMF_CODE.fd && \
        cp /uefi/igd.rom /out/usr/share/qemu/igd.rom; \
    fi

# Build-time files, and QEMU firmware for machines EVE never runs. The edk2
# images go too: EVE's OVMF comes from pkg/uefi.
RUN rm -rf /out/var/run /out/usr/include /out/usr/lib/pkgconfig /out/usr/man /out/usr/share/man \
           /out/usr/share/doc /out/usr/share/qemu/edk2-* /out/usr/share/qemu/openbios-* && \
    find /out -type f -name '*.a' -delete && \
    rm -f /out/usr/share/qemu/skiboot.lid /out/usr/share/qemu/hppa-firmware.img \
          /out/usr/share/qemu/hppa-firmware64.img /out/usr/share/qemu/s390-ccw.img \
          /out/usr/share/qemu/s390-netboot.img /out/usr/share/qemu/slof.bin \
          /out/usr/share/qemu/opensbi-riscv32-generic-fw_dynamic.bin \
          /out/usr/share/qemu/opensbi-riscv64-generic-fw_dynamic.bin

RUN register-sbom-pkg.sh -n liburing -v "${LIBURING_VERSION}" \
        -l "LGPL-2.1-only OR MIT" -u https://github.com/axboe/liburing && \
    register-sbom-pkg.sh -n qemu -v "${QEMU_VERSION}" -l GPL-2.0-only \
        -u https://www.qemu.org

FROM scratch
COPY --from=build /out/ /
COPY init.sh /
COPY qemu-ifup /etc/

# Adjust /var/run, /var/lib and /var/lock to be shared
RUN mv /var /var.template && ln -s /run /var && ln -s /run /var.template/run

# Add a few mountpoints so we can use lowerfs in R/O mode
RUN mkdir /persist /hostfs

ENTRYPOINT []
CMD ["/init.sh"]
