FROM lfedge/eve-alpine:3e3111a703366e9ac607d9c33d5fded006fa1df3 as initrd-build
RUN apk add --no-cache mkinitfs=3.4.1-r1 gcc=8.3.0-r0 musl-dev=1.1.20-r5 e2fsprogs=1.44.5-r1

RUN rm -f /sbin/poweroff /etc/mkinitfs/features.d/base.files
COPY initrd/base.files /etc/mkinitfs/features.d/base.files
COPY initrd/init-initrd initrd/mount_disk.sh initrd/udhcpc_script.sh /
COPY initrd/poweroff /sbin/poweroff
COPY initrd/chroot2.c /tmp/
COPY initrd/micro-init.c /tmp/
COPY initrd/00000080 /etc/acpi/PWRF/
RUN gcc -s -o /chroot2 /tmp/chroot2.c
RUN gcc -s -o /micro-init /tmp/micro-init.c
RUN mkinitfs -n -F base -i /micro-init -o /runx-initrd

FROM alpine:3.12 as build

ENV KVMTOOL_VERSION=90b2d3adadf218dfc6bdfdfcefe269843360223c

ADD  https://git.kernel.org/pub/scm/linux/kernel/git/will/kvmtool.git/snapshot/kvmtool-${KVMTOOL_VERSION}.tar.gz /kvmtool.tar.gz
COPY *.patch /

RUN apk add --no-cache       \
      gcc=9.3.0-r2           \
      make=4.3-r0            \
      libc-dev=0.7.2-r3      \
      binutils-dev=2.34-r1   \
      patch=2.7.6-r6         \
      libaio-dev=0.3.112-r1  \
      zlib-dev=1.2.11-r3     \
      zlib-static=1.2.11-r3  \
      linux-headers=5.4.5-r1 \
      libvncserver-dev=0.9.13-r1

RUN if [ $(uname -m) == aarch64 ]; then apk add --no-cache dtc=1.6.0-r0 dtc-dev=1.6.0-r0 ;fi

RUN tar xzvf kvmtool.tar.gz > /dev/null 2>&1 ;\
    mv kvmtool-${KVMTOOL_VERSION} kvmtool

WORKDIR /kvmtool

RUN patch -p1 < /0001-Makefile-Update-bfd-detection.patch          ; \
    patch -p1 < /0002-alpine-define-workaround.patch               ; \
    patch -p1 < /0003-kvm.h-Change-the-control-socket-path.patch   ; \
    patch -p1 < /0004-pci-Deactivate-BARs-before-reactivating.patch ; \
    patch -p1 < /0005-script-option.patch ;\
    make -j "$(getconf _NPROCESSORS_ONLN)" && make install DESTDIR=/usr HOME=

# Building qemu in strip-down mirovm only mode
RUN apk add --no-cache curl=7.69.1-r3
# qemu 5.1 dependencies
RUN apk add --no-cache python3=3.8.5-r0 glib-dev=2.64.6-r0 pixman-dev=0.40.0-r2
# qemu 5.2+ dependencies
RUN apk add --no-cache py3-setuptools=47.0.0-r0 bash=5.0.17-r0 perl=5.30.3-r0
# ninja dependencies
RUN apk add --no-cache cmake=3.17.2-r0 g++=9.3.0-r2

# building ninja
WORKDIR /ninja-1.10.1
# hadolint ignore=DL4006
RUN curl -L https://github.com/ninja-build/ninja/archive/v1.10.1.tar.gz | tar -C / -xzf -
RUN cmake -Bbuild-cmake -H.
RUN cmake --build build-cmake
RUN cmake --install build-cmake --prefix /usr

# building qemu
WORKDIR /qemu-5.2.0-rc1
# hadolint ignore=DL4006
RUN curl https://download.qemu.org/qemu-5.2.0-rc1.tar.xz | tar -C / -xJf -

COPY i386-softmmu.mak default-configs/devices/i386-softmmu.mak
COPY meson.build hw/acpi/meson.build

# systemtap is not available on Alpine, so we're putting together dtrace tooling
# by hand. More instruction on qemu systemtap probes here:
#    https://www.berrange.com/posts/2019/02/18/easier-qemu-live-tracing-using-systemtap/
COPY dtrace /usr/bin/dtrace
COPY include /usr/include

# --block-drv-whitelist=L --block-drv-rw-whitelist=L --block-drv-ro-whitelist=L
# --with-coroutine
# --disable-system
# --audio-drv-list=none
# ? --disable-vxhs
# T --disable-slirp
ENV CONF_aarch64 --enable-fdt=git
ENV CONF_x86_64 --disable-tcg --disable-fdt --without-default-devices --enable-trace-backends=dtrace

RUN eval ./configure '$CONF_'$(uname -m) --target-list=$(uname -m)-softmmu --enable-kvm --disable-user --disable-linux-user --disable-bsd-user --disable-docs --disable-guest-agent --disable-guest-agent-msi --disable-pie --disable-modules --disable-module-upgrades --disable-debug-tcg --disable-debug-info --disable-sparse --disable-gnutls --disable-nettle --disable-gcrypt --disable-auth-pam --disable-sdl --disable-sdl-image --disable-gtk --disable-vte --disable-curses --disable-iconv --disable-vnc --disable-vnc-sasl --disable-vnc-jpeg --disable-vnc-png --disable-cocoa --disable-virtfs --disable-mpath --disable-xen --disable-xen-pci-passthrough --disable-brlapi --disable-curl --disable-membarrier --disable-hax --disable-hvf --disable-whpx --disable-rdma --disable-pvrdma --disable-vde --disable-netmap --disable-linux-aio --disable-linux-io-uring --disable-cap-ng --disable-attr --disable-vhost-net --disable-vhost-vsock --disable-vhost-scsi --disable-vhost-crypto --disable-vhost-kernel --disable-vhost-user --disable-spice --disable-rbd --disable-libiscsi --disable-libnfs --disable-smartcard --disable-libusb --disable-live-block-migration --disable-usb-redir --disable-lzo --disable-snappy --disable-bzip2 --disable-lzfse --disable-zstd --disable-seccomp --disable-coroutine-pool --disable-glusterfs --disable-tpm --disable-libssh --disable-numa --disable-libxml2 --disable-tcmalloc --disable-jemalloc --disable-avx2 --disable-avx512f --disable-replication --disable-opengl --disable-virglrenderer --disable-xfsctl --disable-qom-cast-debug --disable-tools --disable-bochs --disable-cloop --disable-dmg --disable-qcow1 --disable-vdi --disable-vvfat --disable-qed --disable-parallels --disable-sheepdog --disable-crypto-afalg --disable-capstone --disable-debug-mutex --disable-libpmem --disable-xkbcommon

# qemu's configure script takes presence of as sys/signal.h as
# a hint to set HAVE_SYS_SIGNAL_H=y, meanwhile the only reason
# musl has sys/signal.h to begin with is to warn not to use it
RUN sed -ie '/^HAVE_SYS_SIGNAL_H=y/d' build/config-host.mak

RUN make -j "$(getconf _NPROCESSORS_ONLN)" V=1
RUN strip build/qemu-system-$(uname -m)

RUN mkdir /bios ; if [ $(uname -m) = x86_64 ]; then                                      \
      cp build/pc-bios/optionrom/linuxboot_dma.bin build/pc-bios/bios-microvm.bin /bios ;\
    fi

FROM alpine:3.12

# libgcc, pixman and glib are required for qemu
# it maybe possible to get rid of libgcc & pixman
RUN apk add --no-cache \
            libgcc=9.3.0-r2 \
            pixman=0.40.0-r2 \
            glib=2.64.6-r0 \
            libvncserver=0.9.13-r1 \
            libaio=0.3.112-r1

RUN if [ $(uname -m) == aarch64 ]; then apk add --no-cache libfdt=1.6.0-r0 libstdc++=9.3.0-r2 ;fi

COPY --from=build /usr/bin/lkvm /usr/bin/lkvm
COPY --from=build /qemu-5.2.0-rc1/build/qemu-system-* /usr/bin/
COPY --from=build /bios /usr/share/qemu
COPY --from=initrd-build /runx-initrd /boot/runx-initrd
COPY init.sh /
COPY kvmtool-ifup /etc/kvmtool/scripts/
RUN ln -sf lkvm /usr/bin/vm
RUN ldd /usr/bin/lkvm
RUN ldd /usr/bin/qemu-system-$(uname -m)

ENTRYPOINT ["/init.sh"]
