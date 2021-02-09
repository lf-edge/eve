FROM alpine:3.13.1 as kernel-build
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
    zlib-dev \
    libunwind-dev

ENV XEN_UBOOT_ADDR 0x81000000
ENV XEN_VERSION 4.14.0
ENV XEN_SOURCE=https://downloads.xenproject.org/release/xen/${XEN_VERSION}/xen-${XEN_VERSION}.tar.gz

# Download and verify xen
#TODO: verify Xen
RUN \
    [ -f "$(basename ${XEN_SOURCE})" ] || curl -fsSLO "${XEN_SOURCE}" && \
    tar --absolute-names -xz < "$(basename ${XEN_SOURCE})" && mv "/xen-${XEN_VERSION}" /xen

WORKDIR /xen/xen
COPY *.patch arch /tmp/
RUN cp /tmp/"$(uname -m)"/*.patch /tmp/
RUN for p in /tmp/*.patch ; do patch -p1 < "$p" || exit 1 ; done
RUN chmod +x scripts/* || :

RUN make defconfig && \
    make oldconfig && \
    mkdir -p /out/boot

RUN make && \
    case $(uname -m) in \
    x86_64) \
        cp xen.gz /out/boot/xen.gz \
	;; \
    aarch64) \
        (cd /tmp ; wget -O - ftp://ftp.denx.de/pub/u-boot/u-boot-2018.09.tar.bz2 | tar xjf - ; cd u-boot-* ; make defconfig ; make tools-all) ;\
        /tmp/u-boot-*/tools/mkimage -A arm64 -T kernel -a $XEN_UBOOT_ADDR -e $XEN_UBOOT_ADDR -C none -d xen /out/boot/xen.uboot ;\
        cp xen.efi /out/boot/ \
        ;; \
    esac

FROM scratch
ENTRYPOINT []
CMD []
WORKDIR /boot
COPY --from=kernel-build /out/* .
