FROM lfedge/eve-alpine:145f062a40639b6c65efa36bed1c5614b873be52 AS build

ENV BUILD_PKGS patch curl make gcc perl util-linux-dev git mtools linux-headers musl-dev xz-dev
# bash xorriso coreutils syslinux
RUN eve-alpine-deploy.sh

WORKDIR /ws
RUN git clone --depth 1 -b v1.21.1 https://github.com/ipxe/ipxe.git . &&\
    echo "git https://github.com/ipxe/ipxe.git v1.21.1" >>/source-info

COPY embedded.cfg src/embedded.cfg
COPY *patch /tmp/

# hadolint ignore=DL4006
RUN cat /tmp/*patch | patch -p1

# bin/ipxe.iso
ENV TARGET_x86_64  bin-x86_64-efi/ipxe.efi bin/ipxe.dsk bin/ipxe.lkrn bin/undionly.kpxe
ENV TARGET_aarch64 bin-arm64-efi/ipxe.efi
ENV TARGET_riscv64 clean

RUN eval make -j "$(getconf _NPROCESSORS_ONLN)" -C src DOWNLOAD_PROTO_HTTPS=1 NO_WERROR=1 EMBED=embedded.cfg \$TARGET_`uname -m`
RUN mkdir -p /ws/src/bin-riscv64 && touch /ws/src/bin-riscv64/ipxe.riscv64 && touch /ws/src/bin-riscv64/ipxe.riscv64.debug
RUN mv /ws/src/bin/undionly.kpxe /ws/src/bin/ipxe.undionly 2>/dev/null || :
RUN rm /ws/src/bin*/*.*.*

FROM scratch
COPY --from=build /ws/src/bin*/ipxe.* /
COPY --from=build /source-info /
