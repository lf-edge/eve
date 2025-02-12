# syntax=docker/dockerfile:1.10.0
# Copyright (c) 2024 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

# Interactive mode for the installer
FROM --platform=$BUILDPLATFORM lfedge/eve-rust:1.80.1 AS rust-host
ARG TARGETARCH

# map Docker's $TARGETARCH to Rust target
FROM rust-host AS target-amd64
ENV CARGO_BUILD_TARGET="x86_64-unknown-linux-musl"

FROM rust-host AS target-arm64
ENV CARGO_BUILD_TARGET="aarch64-unknown-linux-musl"

FROM rust-host AS target-riscv64
ENV CARGO_BUILD_TARGET="riscv64gc-unknown-linux-gnu"

# hadolint ignore=DL3006
FROM target-$TARGETARCH AS rust

WORKDIR /usr/local/my-installer
COPY . .

# tools already in place
RUN cargo build --release --verbose
RUN cargo sbom > sbom.spdx.json

RUN cp "/usr/local/my-installer/target/$CARGO_BUILD_TARGET/release/installer" /usr/local/my-installer/target/installer

# Dockerfile to build installer img initrd
FROM lfedge/eve-alpine:591df01e581889c3027514c8a91feaca1c8ad49f AS build
SHELL ["/bin/ash", "-eo", "pipefail", "-c"]
ENV BUILD_PKGS mkinitfs grep patch make coreutils musl-dev gcc g++ perl \
    autoconf automake libtool file bsd-compat-headers libc-dev \
    util-linux-dev flex linux-headers glib-dev libxrandr-dev zlib-dev \
    libusb-dev kmod-dev curl eudev-dev libdrm-dev i2c-tools-dev hwinfo \
    binutils-dev libaio-dev zlib-static libvncserver-dev python3 pixman-dev \
    py3-setuptools bash cmake m4 pkgconf pkgconfig autoconf-archive tpm2-tss-dev \
    cryptsetup-dev go lddtree git
ENV PKGS mtools dosfstools libarchive-tools sgdisk e2fsprogs util-linux \
    squashfs-tools coreutils tar dmidecode smartmontools libaio libaio-dev \
    glib zlib libusb curl xz pciutils usbutils hdparm ncurses-dev jq \
    wireless-tools libxrandr eudev-libs sudo fio iperf3 sysstat \
    lm-sensors acpi iw libdrm hwinfo dhclient e2fsprogs-extra \
    libgcc pixman libvncserver musl-utils \
    tpm2-tss-dev tpm2-tss-esys tpm2-tss-fapi tpm2-tss-rc \
    kmod-libs tpm2-tss-sys tpm2-tss-tctildr tpm2-abrmd libblkid cryptsetup-libs
RUN eve-alpine-deploy.sh

COPY src/ /src/
WORKDIR /src
RUN go build -o /out/tpmmgr ./tpmmgr
RUN go build -o /out/vmcap ./vmcap

WORKDIR /out

ADD https://www.ddcutil.com/tarballs/ddcutil-1.2.2.tar.gz /out/ddcutil-1.2.2.tar.gz
ADD http://sources.buildroot.net/edid-decode/edid-decode-188950472c19492547e298b27f9da0d72cf826df.tar.gz /out/edid-decode-188950472c19492547e298b27f9da0d72cf826df.tar.gz
ADD https://github.com/linuxhw/build-stuff/releases/download/1.6/hw-probe-1.6-AI.tar.gz /out/hw-probe-1.6-AI.tar.gz
# Temporarily removed ubuntu VM image to make the verification image smaller.
#ADD https://cloud-images.ubuntu.com/minimal/releases/jammy/release/ubuntu-22.04-minimal-cloudimg-amd64.img /out/ubuntu-22.04-minimal-cloudimg-amd64.img
ADD https://github.com/tpm2-software/tpm2-tools/archive/5.2.tar.gz /out/5.2.tar.gz

RUN tar -xf hw-probe-1.6-AI.tar.gz \
    && tar -xf ddcutil-1.2.2.tar.gz \
    && tar -xf edid-decode-188950472c19492547e298b27f9da0d72cf826df.tar.gz \
    && tar -xf 5.2.tar.gz \
    && rm -rf hw-probe-1.6-AI.tar.gz ddcutil-1.2.2.tar.gz 5.2.tar.gz \
    edid-decode-188950472c19492547e298b27f9da0d72cf826df.tar.gz
WORKDIR /out/edid-decode-188950472c19492547e298b27f9da0d72cf826df
RUN make \
    && find . -type f | perl -lne "print if -B and -x" | xargs strip \
    && install -m 0755 edid-decode /out/usr/bin
WORKDIR /out/ddcutil-1.2.2
RUN ./configure --prefix=/out/usr \
    && make \
    && find . -type f | perl -lne "print if -B and -x" | xargs strip \
    && make install
WORKDIR /out/hw-probe-1.6-AI
RUN install -m 755 hw-probe.pl /out/usr/bin/hw-probe  \
    && sed -i "s/root\/HW_PROBE/tmp\/HW_PROBE/" /out/usr/bin/hw-probe
WORKDIR /out/tpm2-tools-5.2
RUN ./bootstrap \
    && ./configure --prefix=/out/usr \
    && make -j"$(nproc)" \
    && make install \
    && rm -rf /out/edid-decode-188950472c19492547e298b27f9da0d72cf826df \
    /out/ddcutil-1.2.2 /out/hw-probe-1.6-AI /out/tpm2-tools-5.2

COPY --from=rust /usr/local/my-installer/target/installer /out/sbin/installer
COPY --from=rust /usr/local/my-installer/sbom.spdx.json /out/sbin/sbom.spdx.json

FROM scratch
COPY --from=build /out/ /
COPY install parse-installer-conf.sh spec.sh verify verifytpm.sh /
ENV RUST_BACKTRACE full

WORKDIR /
RUN echo "mtools_skip_check=1" >> etc/mtools.conf
RUN mkdir -p parts bits config persist opt/pillar opt/debug lib/modules run sys opt/vtpm root efifs

ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# hadolint ignore=DL3002
USER 0:0

ENTRYPOINT [ "/bin/sh", "-c", "/install </dev/console >/dev/console 2>&1" ]
