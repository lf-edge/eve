FROM lfedge/eve-alpine:9fb9b9cbf7d90066a70e4704d04a6fe248ff52bb as build
# Building qemu in strip-down mirovm only mode:
# qemu 5.1 dependencies: python3 glib-dev pixman-dev
# qemu 5.2+ dependencies: py3-setuptools bash perl
# ninja dependencies: cmake g++
ENV BUILD_PKGS gcc make libc-dev binutils-dev patch libaio-dev zlib-dev zlib-static linux-headers libvncserver-dev python3 glib-dev pixman-dev py3-setuptools bash perl cmake g++
ENV BUILD_PKGS_arm64 dtc dtc-dev
# libgcc, pixman and glib are required for qemu
# it maybe possible to get rid of libgcc & pixman
ENV PKGS libgcc pixman glib libvncserver libaio musl-utils
ENV PKGS_arm64 libfdt libstdc++
RUN eve-alpine-deploy.sh

ENV KVMTOOL_VERSION=90b2d3adadf218dfc6bdfdfcefe269843360223c

ADD  https://git.kernel.org/pub/scm/linux/kernel/git/will/kvmtool.git/snapshot/kvmtool-${KVMTOOL_VERSION}.tar.gz /kvmtool.tar.gz
COPY *.patch /

RUN tar xzvf kvmtool.tar.gz > /dev/null 2>&1 ;\
    mv kvmtool-${KVMTOOL_VERSION} kvmtool

WORKDIR /kvmtool

RUN patch -p1 < /0001-Makefile-Update-bfd-detection.patch ;\
    patch -p1 < /0002-alpine-define-workaround.patch      ;\
    make -j "$(getconf _NPROCESSORS_ONLN)" && make install DESTDIR=/usr HOME=

# building ninja
WORKDIR /ninja-1.10.1
ADD https://github.com/ninja-build/ninja/archive/v1.10.1.tar.gz /ninja.tar.gz
RUN tar -C / -xzf /ninja.tar.gz
RUN cmake -Bbuild-cmake -H.
RUN cmake --build build-cmake
RUN cmake --install build-cmake --prefix /usr

# building qemu
WORKDIR /qemu-5.2.0
ADD https://download.qemu.org/qemu-5.2.0.tar.xz /qemu-5.2.0.tar.xz
RUN tar -C / -xJf /qemu-5.2.0.tar.xz

COPY i386-softmmu.mak default-configs/devices/i386-softmmu.mak
COPY meson.build hw/acpi/meson.build

RUN patch -p1 < /0003-vhost-nvme.patch

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

RUN eval ./configure '$CONF_'$(uname -m) --target-list=$(uname -m)-softmmu --enable-kvm --disable-user --disable-linux-user --disable-bsd-user --disable-docs --disable-guest-agent --disable-guest-agent-msi --disable-pie --disable-modules --disable-module-upgrades --disable-debug-tcg --disable-debug-info --disable-sparse --disable-gnutls --disable-nettle --disable-gcrypt --disable-auth-pam --disable-sdl --disable-sdl-image --disable-gtk --disable-vte --disable-curses --disable-iconv --disable-vnc --disable-vnc-sasl --disable-vnc-jpeg --disable-vnc-png --disable-cocoa --disable-virtfs --disable-mpath --disable-xen --disable-xen-pci-passthrough --disable-brlapi --disable-curl --disable-membarrier --disable-hax --disable-hvf --disable-whpx --disable-rdma --disable-pvrdma --disable-vde --disable-netmap --disable-linux-aio --disable-linux-io-uring --disable-cap-ng --disable-attr --disable-vhost-net --disable-vhost-vsock --disable-vhost-scsi --disable-vhost-crypto --disable-spice --disable-rbd --disable-libiscsi --disable-libnfs --disable-smartcard --disable-libusb --disable-live-block-migration --disable-usb-redir --disable-lzo --disable-snappy --disable-bzip2 --disable-lzfse --disable-zstd --disable-seccomp --disable-coroutine-pool --disable-glusterfs --disable-tpm --disable-libssh --disable-numa --disable-libxml2 --disable-tcmalloc --disable-jemalloc --disable-avx2 --disable-avx512f --disable-replication --disable-opengl --disable-virglrenderer --disable-xfsctl --disable-qom-cast-debug --disable-tools --disable-bochs --disable-cloop --disable-dmg --disable-qcow1 --disable-vdi --disable-vvfat --disable-qed --disable-parallels --disable-sheepdog --disable-crypto-afalg --disable-capstone --disable-debug-mutex --disable-libpmem --disable-xkbcommon

# qemu's configure script takes presence of as sys/signal.h as
# a hint to set HAVE_SYS_SIGNAL_H=y, meanwhile the only reason
# musl has sys/signal.h to begin with is to warn not to use it
RUN sed -ie '/^HAVE_SYS_SIGNAL_H=y/d' build/config-host.mak

RUN make -j "$(getconf _NPROCESSORS_ONLN)" V=1
RUN strip build/qemu-system-$(uname -m)

RUN mkdir /bios ; if [ $(uname -m) = x86_64 ]; then                                      \
      cp build/pc-bios/optionrom/linuxboot_dma.bin build/pc-bios/bios-microvm.bin /bios ;\
    fi

FROM scratch

COPY --from=build /out/ /
COPY --from=build /usr/bin/lkvm /usr/bin/lkvm
COPY --from=build /qemu-5.2.0/build/qemu-system-* /usr/bin/
COPY --from=build /bios /usr/share/qemu
RUN ln -sf lkvm /usr/bin/vm
RUN ldd /usr/bin/lkvm
RUN ldd /usr/bin/qemu-system-$(uname -m)

ENTRYPOINT ["/bin/sh", "-c", "while true; do sleep 100000; done"]
#CMD ["/usr/sbin/vm",]
