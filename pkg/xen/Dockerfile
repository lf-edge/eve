FROM lfedge/eve-alpine:145f062a40639b6c65efa36bed1c5614b873be52 as kernel-build

ENV BUILD_PKGS argp-standalone automake bash bc binutils-dev bison build-base \
               curl diffutils flex git gmp-dev gnupg installkernel kmod \
               elfutils-dev openssl-dev linux-headers ncurses-dev python3 \
               sed squashfs-tools tar xz xz-dev zlib-dev libunwind-dev
ENV BUILD_PKGS_arm64 uboot-tools
RUN eve-alpine-deploy.sh

ENV XEN_UBOOT_ADDR 0x81000000
ENV XEN_VERSION 4.15.0
ENV XEN_SOURCE=https://downloads.xenproject.org/release/xen/${XEN_VERSION}/xen-${XEN_VERSION}.tar.gz

# Download and verify xen
#TODO: verify Xen
RUN \
    [ -f "$(basename ${XEN_SOURCE})" ] || curl -fsSLO "${XEN_SOURCE}" && \
    tar --absolute-names -xz < "$(basename ${XEN_SOURCE})" && mv "/xen-${XEN_VERSION}" /xen && \
    echo ${XEN_SOURCE} >>/source-info

WORKDIR /xen/xen
COPY *.patch arch /tmp/
RUN cp /tmp/"$(uname -m)"/*.patch /tmp/
RUN for p in /tmp/*.patch ; do patch -p1 < "$p" || exit 1 ; done
RUN chmod +x scripts/* || :

RUN make defconfig && \
    make oldconfig && \
    rm -rf /out && mkdir -p /out/boot

RUN make -j "$(getconf _NPROCESSORS_ONLN)" && \
    case $(uname -m) in \
    x86_64) \
        cp xen.gz /out/boot/xen.gz \
	;; \
    aarch64) \
        mkimage -A arm64 -T kernel -a $XEN_UBOOT_ADDR -e $XEN_UBOOT_ADDR -C none -d xen /out/boot/xen.uboot ;\
        cp xen.efi /out/boot/ \
        ;; \
    esac

FROM scratch
ENTRYPOINT []
CMD []
WORKDIR /boot
COPY --from=kernel-build /out/* .
COPY --from=kernel-build /source-info /
