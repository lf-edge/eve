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

FROM lfedge/eve-debug:bf4555da8b11ed2a82501a32735041d3d32e7cf5 AS debug

# Dockerfile to build installer img initrd
FROM lfedge/eve-ubuntu:17fea35e37517165b27e0e3f142d38750eb0a544 AS build
SHELL ["/bin/bash", "-eo", "pipefail", "-c"]
ENV PKGS="mtools dosfstools libarchive-tools gdisk e2fsprogs util-linux mount \
    squashfs-tools coreutils tar gzip dmidecode smartmontools libaio1t64 \
    libglib2.0-0t64 zlib1g libusb-1.0-0 curl xz-utils pciutils usbutils hdparm jq \
    libxrandr2 libudev1 sudo fio iperf3 sysstat \
    lm-sensors acpi iw libdrm2 hwinfo dhcpcd-base \
    libgcc-s1 libpixman-1-0 libvncserver1 bash procps psmisc iproute2 kmod uuid-runtime nvme-cli login \
    tpm2-tools tpm2-abrmd libkmod2 libblkid1 libcryptsetup12 efibootmgr busybox-static"
RUN eve-ubuntu-deploy.sh

# the installer reboots or powers off the device when it is done; those are
# busybox applets here
RUN ln -s /usr/bin/busybox /out/usr/sbin/reboot && ln -s /usr/bin/busybox /out/usr/sbin/poweroff

COPY src/ /src/
WORKDIR /src
RUN go build -o /out/tpmmgr ./tpmmgr
RUN go build -o /out/vmcap ./vmcap

WORKDIR /out

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
