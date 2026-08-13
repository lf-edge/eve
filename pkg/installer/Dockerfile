# syntax=docker/dockerfile:1.10.0
# Copyright (c) 2024 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

# Interactive mode for the installer
FROM --platform=$BUILDPLATFORM lfedge/eve-rust:1.93.1-1 AS rust-host
ARG TARGETARCH

# map Docker's $TARGETARCH to Rust target
FROM rust-host AS target-amd64
ENV CARGO_BUILD_TARGET="x86_64-unknown-linux-musl"

FROM rust-host AS target-arm64
ENV CARGO_BUILD_TARGET="aarch64-unknown-linux-musl"

FROM rust-host AS target-riscv64
ENV CARGO_BUILD_TARGET="riscv64gc-unknown-linux-musl"

# hadolint ignore=DL3006
FROM target-$TARGETARCH AS rust

WORKDIR /usr/local/my-installer
COPY . .

# tools already in place
RUN cargo build --release --verbose
RUN cargo sbom > sbom.spdx.json

RUN cp "/usr/local/my-installer/target/$CARGO_BUILD_TARGET/release/installer" /usr/local/my-installer/target/installer

FROM lfedge/eve-debug:d1461b73753e42bf288cc3e35514fa0a9d1061a2 AS debug

# Dockerfile to build installer img initrd
FROM lfedge/eve-alpine:d075dd224fa7a7540817d224cc28d3cd998ad04c AS build
SHELL ["/bin/ash", "-eo", "pipefail", "-c"]
ENV BUILD_PKGS="mkinitfs grep patch make coreutils musl-dev gcc g++ perl \
    autoconf automake libtool file bsd-compat-headers libc-dev \
    util-linux-dev flex linux-headers glib-dev libxrandr-dev zlib-dev \
    libusb-dev kmod-dev curl curl-dev eudev-dev libdrm-dev i2c-tools-dev hwinfo \
    binutils-dev libaio-dev zlib-static libvncserver-dev python3 pixman-dev \
    py3-setuptools bash cmake m4 pkgconf pkgconfig autoconf-archive \
    cryptsetup-dev lddtree git"
ENV PKGS="mtools dosfstools libarchive-tools sgdisk e2fsprogs util-linux \
    squashfs-tools coreutils tar dmidecode smartmontools libaio libaio-dev \
    glib zlib libusb curl libcurl xz pciutils usbutils hdparm ncurses-dev jq \
    wireless-tools libxrandr eudev-libs sudo fio iperf3 sysstat \
    lm-sensors acpi iw libdrm hwinfo dhcpcd e2fsprogs-extra \
    libgcc pixman libvncserver musl-utils \
    tpm2-tss-esys tpm2-tss-fapi tpm2-tss-rc \
    kmod-libs tpm2-tss-sys tpm2-tss-tctildr tpm2-abrmd libblkid cryptsetup-libs efibootmgr"
RUN eve-alpine-deploy.sh

COPY src/ /src/
WORKDIR /src
RUN go build -o /out/tpmmgr ./tpmmgr
RUN go build -o /out/vmcap ./vmcap

WORKDIR /out

ADD --keep-git-dir=true https://github.com/tpm2-software/tpm2-tools.git#5.5 /out/tpm2-tools-5.5

# build tpm2-tss, it is needed by tpm2-tools
WORKDIR /tpm2-tss
ADD --keep-git-dir=true https://github.com/tpm2-software/tpm2-tss.git#4.0.1 /tpm2-tss
RUN ./bootstrap && \
    ./configure --disable-dependency-tracking && \
    make -j$(nproc) && \
    make install
RUN cp /usr/local/lib/libtss2* /out/usr/lib/
RUN strip --strip-unneeded /out/usr/lib/libtss2*.so*

# Register tpm2-tss in the APK DB, mandatory for it to be included in the SBOM.
RUN register-sbom-pkg.sh -n tpm2-tss -v 4.0.1 -l BSD-2-Clause -u https://github.com/tpm2-software/tpm2-tss

WORKDIR /out/tpm2-tools-5.5
RUN ./bootstrap
RUN ./configure --prefix=/out/usr CFLAGS="-Wno-error"
RUN make -j"$(nproc)" CFLAGS="-Wno-error"
RUN make install

# Register tpm2-tools in the APK DB, mandatory for it to be included in the SBOM.
RUN register-sbom-pkg.sh -n tpm2-tools -v 5.5 -l BSD-3-Clause -u https://github.com/tpm2-software/tpm2-tools

RUN rm -rf /out/tpm2-tools-5.5

COPY --from=rust /usr/local/my-installer/target/installer /out/sbin/installer
COPY --from=rust /usr/local/my-installer/sbom.spdx.json /out/sbin/sbom.spdx.json

FROM scratch
COPY --from=build /out/ /
COPY --from=debug /usr/bin/spec.sh /
COPY install parse-installer-conf.sh verify /
ENV RUST_BACKTRACE full

WORKDIR /
RUN echo "mtools_skip_check=1" >> etc/mtools.conf
RUN mkdir -p parts bits config persist opt/pillar opt/debug lib/modules run sys opt/vtpm root efifs

ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# hadolint ignore=DL3002
USER 0:0

ENTRYPOINT [ "/bin/sh", "-c", "/install </dev/console >/dev/console 2>&1" ]
