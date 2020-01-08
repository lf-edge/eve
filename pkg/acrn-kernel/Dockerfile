FROM lfedge/eve-alpine:8727b17d0d3c6d85ed6634637e76e6fbab83b726 as kernel-build

RUN apk --no-cache add \
    argp-standalone=1.3-r3 \
    automake=1.16.1-r0 \
    bash=4.4.19-r1 \
    bc=1.07.1-r0 \
    binutils-dev=2.31.1-r2 \
    bison=3.0.5-r0 \
    build-base=0.5-r1 \
    curl=7.64.0-r3 \
    diffutils=3.7-r0 \
    flex=2.6.4-r1 \
    git=2.20.2-r0 \
    gmp-dev=6.1.2-r1 \
    gnupg=2.2.19-r0 \
    installkernel=3.5-r0 \
    kmod=24-r1 \
    libressl-dev=2.7.5-r0 \
    linux-headers=4.18.13-r1 \
    ncurses-dev=6.1_p20190105-r0 \
    python2=2.7.16-r2 \
    findutils=4.6.0-r1 \
    sed=4.5-r0 \
    squashfs-tools=4.3-r5 \
    tar=1.32-r0 \
    xz=5.2.4-r0 \
    xz-dev=5.2.4-r0 \
    zlib-dev=1.2.11-r1 \
    openssl=1.1.1d-r2 \
    lz4-libs=1.8.3-r2 \
    elfutils-libelf=0.168-r2 \
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
RUN if [ "$(uname -m)" = "x86_64" ] ; then \
    cp kernel_config_uefi_sos .config && \
    make olddefconfig && \
    make -j4 && \
    cp arch/x86_64/boot/bzImage /out/kernel && \
    cp System.map /out ;\
fi

RUN echo "KERNEL_SOURCE=${KERNEL_SOURCE}" > /out/kernel-source-info

# Don't install modules for now. We should trim the config.
RUN touch /out/kernel.tar
RUN touch /out/kernel-dev.tar
# Don't install the headers for now.
RUN touch /out/kernel-headers.tar

FROM scratch
ENTRYPOINT []
CMD []
WORKDIR /
COPY --from=kernel-build /out/* /
