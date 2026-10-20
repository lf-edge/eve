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
# subprojects the build uses, so it needs no network. The libraries QEMU
# links, liburing included, are Ubuntu's.
#
# QEMU is compiled as the target, under emulation when the build platform
# differs: eve-ubuntu has the cross compilers, but not the target's
# development libraries a sysroot for QEMU would need.
#
# qemu-img and qemu-nbd are built as well: pillar copies them from this
# image, and the squashfs stores the files the two images share once.

FROM lfedge/eve-uefi:cbe04da0bf4436fdffbebed11a6a436d31519189 AS uefi-build

FROM lfedge/eve-ubuntu:17fea35e37517165b27e0e3f142d38750eb0a544 AS build
# The build tools, and the headers of the libraries QEMU links.
ENV BUILD_PKGS="gcc make libc6-dev linux-libc-dev ninja-build pkg-config perl bash patch flex bison \
    python3 python3-venv python3-setuptools python3-pip python3-wheel \
    libglib2.0-dev libpixman-1-dev zlib1g-dev libgnutls28-dev libusb-1.0-0-dev libzstd-dev liblzma-dev \
    libaio-dev libbz2-dev libcap-ng-dev libattr1-dev uuid-dev libfdt-dev liburing-dev"
# The libraries QEMU links, as the image, keyutils for init.sh and busybox for
# qemu-ifup (the host rootfs ships the same binary: stored once).
ENV PKGS="libgcc-s1 bash keyutils busybox-static libglib2.0-0t64 libpixman-1-0 libgnutls30t64 libusb-1.0-0 \
    libzstd1 liblzma5 libaio1t64 libbz2-1.0 libcap-ng0 libattr1 libuuid1 libfdt1 liburing2 util-linux mount"
RUN eve-ubuntu-deploy.sh

# QEMU_RELEASE, not QEMU_VERSION: qemu-user reads QEMU_* variables as its own
# options, and QEMU_VERSION would turn every emulated step into `-version`.
ENV QEMU_RELEASE=11.1.2
ENV QEMU_SHA256=731b5681e4bb18be313231579b8efd0296c5b015fa36dc533874b639ba838016
# hadolint ignore=DL3020
ADD https://download.qemu.org/qemu-${QEMU_RELEASE}.tar.xz /qemu.tar.xz
RUN echo "${QEMU_SHA256}  /qemu.tar.xz" > /sources.sha256 && \
    sha256sum -c /sources.sha256 && \
    mkdir -p /src && \
    tar -C /src -xJf /qemu.tar.xz

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

# Nothing on the device uses QEMU's TCG plugins or slirp user networking, so
# neither is built; of the tools, only qemu-img and qemu-nbd are kept below.
# Frame pointers stay, so that a core dump gives a usable stack.
ARG TARGETARCH
RUN case "${TARGETARCH}" in \
        amd64) TARGETS=x86_64-softmmu ;; \
        arm64) TARGETS=aarch64-softmmu ;; \
        *)     echo "unsupported architecture ${TARGETARCH}"; exit 1 ;; \
    esac && \
    ./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var \
        --target-list="$TARGETS" --disable-download \
        --enable-kvm --disable-xen --enable-tools --disable-plugins \
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
RUN find /out/usr/bin -type f -name 'qemu-*' ! -name 'qemu-system-*' ! -name qemu-img ! -name qemu-nbd -delete && \
    rm -f /out/usr/bin/elf2dmp && \
    strip /out/usr/bin/qemu-*
# RUN mkdir -p /out/usr/lib/debug/usr/bin && \
#     for f in /out/usr/bin/qemu-*; do \
#         b=$(basename "$f"); \
#         objcopy --only-keep-debug "$f" "/out/usr/lib/debug/usr/bin/$b.debug" && \
#         strip --strip-debug --strip-unneeded "$f" && \
#         objcopy --add-gnu-debuglink="/out/usr/lib/debug/usr/bin/$b.debug" "$f"; \
#     done

COPY --from=uefi-build / /uefi/
RUN mkdir -p /out/usr/share/ovmf && \
    cp /uefi/OVMF.fd /out/usr/share/ovmf/OVMF.fd && \
    if [ "${TARGETARCH}" = amd64 ]; then \
        cp /uefi/OVMF_CODE.fd /out/usr/share/ovmf/OVMF_CODE.fd && \
        cp /uefi/igd.rom /out/usr/share/qemu/igd.rom; \
    fi

# Build-time files, the desktop entry and icons, the helpers, and QEMU
# firmware for machines EVE never runs. The edk2 images go too: EVE's OVMF
# comes from pkg/uefi.
RUN rm -rf /out/var/run /out/usr/include /out/usr/share/man /out/usr/share/applications \
           /out/usr/share/icons /out/usr/libexec/qemu-* \
           /out/usr/share/qemu/edk2-* /out/usr/share/qemu/openbios-* && \
    find /out -type f -name '*.a' -delete && \
    rm -f /out/usr/share/qemu/skiboot.lid /out/usr/share/qemu/hppa-firmware.img \
          /out/usr/share/qemu/hppa-firmware64.img /out/usr/share/qemu/s390-ccw.img \
          /out/usr/share/qemu/s390-netboot.img /out/usr/share/qemu/slof.bin \
          /out/usr/share/qemu/opensbi-riscv32-generic-fw_dynamic.bin \
          /out/usr/share/qemu/opensbi-riscv64-generic-fw_dynamic.bin

# Register qemu in the dpkg status area, mandatory for it to be included in the SBOM.
RUN register-sbom-pkg.sh -n qemu -v "${QEMU_RELEASE}" -l GPL-2.0-only -u https://www.qemu.org

# Fail here, not at the first VM start, if a library QEMU needs is missing:
# resolve each binary inside the image, with the image's own loader.
RUN for f in /out/usr/bin/qemu-*; do \
        chroot /out ldd "${f#/out}" > /tmp/ldd.out 2>&1 || true; \
        if grep -q 'not found' /tmp/ldd.out; then \
            echo "ERROR: $f does not resolve in the image"; cat /tmp/ldd.out; exit 1; \
        fi; \
    done

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
