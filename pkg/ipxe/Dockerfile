FROM lfedge/eve-alpine:6.2.0 as build

ENV BUILD_PKGS patch curl make gcc perl util-linux-dev git mtools linux-headers musl-dev xz-dev
# bash xorriso coreutils syslinux
RUN eve-alpine-deploy.sh

WORKDIR /ws
RUN git clone --depth 1 -b v1.21.1 https://github.com/ipxe/ipxe.git .

COPY embedded.cfg src/embedded.cfg
COPY *patch /tmp/

# hadolint ignore=DL4006
RUN cat /tmp/*patch | patch -p1

# bin/ipxe.iso
ENV TARGET_x86_64  bin-x86_64-efi/ipxe.efi bin/ipxe.dsk bin/ipxe.lkrn bin/undionly.kpxe
ENV TARGET_aarch64 bin-arm64-efi/ipxe.efi

RUN eval make -j "$(getconf _NPROCESSORS_ONLN)" -C src DOWNLOAD_PROTO_HTTPS=1 EMBED=embedded.cfg \$TARGET_`uname -m`
RUN mv /ws/src/bin/undionly.kpxe /ws/src/bin/ipxe.undionly 2>/dev/null || :
RUN rm /ws/src/bin*/*.*.*

FROM scratch
COPY --from=build /ws/src/bin*/ipxe.* /
