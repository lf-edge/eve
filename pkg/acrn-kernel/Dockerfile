FROM alpine:3.10 as kernel-build
#linuxkit/alpine:f2f4db272c910d136380781a97e475013fabda8b AS kernel-build

RUN apk --no-cache add \
    argp-standalone=1.3-r3 \
    automake=1.16.1-r0 \
    bash=5.0.0-r0 \
    bc=1.07.1-r1 \
    binutils-dev=2.32-r0 \
    bison=3.3.2-r0 \
    build-base=0.5-r1 \
    curl=7.66.0-r0 \
    diffutils=3.7-r0 \
    flex=2.6.4-r2 \
    git=2.22.0-r0 \
    gmp-dev=6.1.2-r1 \
    gnupg=2.2.16-r0 \
    installkernel=3.5-r0 \
    kmod=24-r1 \
    libressl-dev=2.7.5-r0 \
    linux-headers=4.19.36-r0 \
    ncurses-dev=6.1_p20190518-r0 \
    python2=2.7.16-r1 \
    findutils=4.6.0-r1 \
    sed=4.7-r0 \
    squashfs-tools=4.3-r5 \
    tar=1.32-r0 \
    xz=5.2.4-r0 \
    xz-dev=5.2.4-r0 \
    zlib-dev=1.2.11-r1 \
    openssl=1.1.1d-r0 \
    lz4=1.9.1-r0 \
    elfutils-libelf=0.168-r2 \
    elfutils=0.168-r2 \
    elfutils-dev=0.168-r2


# Download acrn-kernel
ENV KERNEL_VERSION acrn-2019w39.3-150000p
ENV KERNEL_SOURCE=https://github.com/projectacrn/acrn-kernel/archive/${KERNEL_VERSION}.tar.gz
RUN \
    [ -f "$(basename ${KERNEL_SOURCE})" ] || curl -fsSLO "${KERNEL_SOURCE}" && \
    tar --absolute-names -xz < "$(basename ${KERNEL_SOURCE})" && mv "/acrn-kernel-${KERNEL_VERSION}" /acrn-kernel
RUN ls -l /acrn-kernel

# Apply local patches
COPY patches-${KERNEL_VERSION} /patches
WORKDIR /acrn-kernel
RUN set -e && for patch in /patches/*.patch; do \
        echo "Applying $patch"; \
        patch -p1 < "$patch"; \
    done

# build acrn-kernel
RUN mkdir /out
RUN cp kernel_config_uefi_sos .config && \
    make olddefconfig && \
    make -j4 && \
    cp arch/x86_64/boot/bzImage /out/kernel; \
    cp System.map /out

RUN echo "KERNEL_SOURCE=${KERNEL_SOURCE}" > /out/kernel-source-info

# Don't install modules for now. We should trim the config.
RUN touch /out/kernel.tar
RUN touch /out/kernel-dev.tar

# Headers (userspace API)
RUN mkdir -p /tmp/kernel-headers/usr && \
    make INSTALL_HDR_PATH=/tmp/kernel-headers/usr headers_install && \
    ( cd /tmp/kernel-headers && tar cf /out/kernel-headers.tar usr )

FROM scratch
ENTRYPOINT []
CMD []
WORKDIR /
COPY --from=kernel-build /out/* /
