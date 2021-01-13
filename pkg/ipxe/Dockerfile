FROM lfedge/eve-alpine:5.16.0 as build

RUN apk add --no-cache       \
    patch=2.7.6-r6           \
    curl=7.64.0-r3           \
    make=4.2.1-r2            \
    gcc=8.3.0-r0             \
    perl=5.26.3-r0           \
    util-linux-dev=2.33-r0   \
    git=2.20.2-r0            \
    mtools=4.0.23-r0         \
    linux-headers=4.18.13-r1 \
    musl-dev=1.1.20-r5       \
    xz-dev=5.2.4-r0
# bash xorriso coreutils syslinux

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
