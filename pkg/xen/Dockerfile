FROM alpine:3.6 as kernel-build
#linuxkit/alpine:f2f4db272c910d136380781a97e475013fabda8b AS kernel-build
RUN apk update

RUN apk add \
    argp-standalone \
    automake \
    bash \
    bc \
    binutils-dev \
    bison \
    build-base \
    curl \
    diffutils \
    flex \
    git \
    gmp-dev \
    gnupg \
    installkernel \
    kmod \
    libelf-dev \
    libressl-dev \
    linux-headers \
    ncurses-dev \
    python2 \
    sed \
    squashfs-tools \
    tar \
    xz \
    xz-dev \
    zlib-dev

# libunwind-dev pkg is missed from arm64 now, below statement will be removed if the pkg is available.
RUN [ $(uname -m) == x86_64 ] && apk add libunwind-dev || true

ENV XEN_VERSION 4.9.0
ENV XEN_SOURCE=https://downloads.xenproject.org/release/xen/${XEN_VERSION}/xen-${XEN_VERSION}.tar.gz

# Download and verify xen
#TODO: verify Xen
RUN \
    [ -f xen-${XEN_VERSION}.tar.gz ] || curl -fsSLO ${XEN_SOURCE} && \
    gzip -d xen-${XEN_VERSION}.tar.gz && \
    cat xen-${XEN_VERSION}.tar | tar --absolute-names -x && mv /xen-${XEN_VERSION} /xen

# Xen config
COPY xen_config* /xen/
WORKDIR /xen/xen

RUN case $(uname -m) in \
    x86_64) \
        XEN_DEF_CONF=/xen/xen/arch/x86/configs/x86_64_defconfig; \
	;; \
    esac && \
    cp /xen/xen_config-${XEN_VERSION}-$(uname -m) ${XEN_DEF_CONF}; \
    rm /xen/xen_config* && \
    make defconfig && \
    make oldconfig

RUN mkdir -p /out/boot

RUN make && cp xen.gz /out/boot/xen.gz

FROM scratch
ENTRYPOINT []
CMD []
WORKDIR /boot
COPY --from=kernel-build /out/* .
