# syntax=docker/dockerfile-upstream:1.5.0-rc2-labs
# Copyright (c) 2025-2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

FROM lfedge/eve-alpine:39f46094f640424c345164420ed789afd8a4088b AS build-base
ENV BUILD_PKGS bash binutils-dev build-base bc bison flex gnutls gnutls-dev openssl-dev python3 swig dtc git
ENV BUILD_PKGS_amd64 linux-headers python3-dev py-pip
RUN eve-alpine-deploy.sh

SHELL ["/bin/bash", "-eo", "pipefail", "-c"]

ENV UBOOT_VERSION=v2026.04
ENV UBOOT_REPO=https://github.com/u-boot/u-boot.git
ADD --keep-git-dir ${UBOOT_REPO}#${UBOOT_VERSION} /u-boot

WORKDIR /u-boot
COPY patches /tmp/patches

RUN mkdir -p /boot
RUN git config --global user.name 'Project EVE'
RUN git config --global user.email 'builder@projecteve.dev'
# hadolint ignore=SC2046
RUN git am /tmp/patches/patches-${UBOOT_VERSION}/*

FROM build-base AS build-amd64
ENV TARGET qemu-x86_64_defconfig
FROM build-base AS build-arm64
ENV TARGET rpi_arm64_defconfig

ENV RASPBERRY_FIRMWARE_BLOBS_VERSION=1.20260521
ENV RASPBERRY_FIRMWARE_BLOBS=https://github.com/raspberrypi/firmware/raw/${RASPBERRY_FIRMWARE_BLOBS_VERSION}

# download blobs for raspberry
# hadolint ignore=DL3020
ADD ${RASPBERRY_FIRMWARE_BLOBS}/boot/fixup4.dat /tmp/rpi/fixup4.dat
# hadolint ignore=DL3020
ADD ${RASPBERRY_FIRMWARE_BLOBS}/boot/fixup4cd.dat /tmp/rpi/fixup4cd.dat
# hadolint ignore=DL3020
ADD ${RASPBERRY_FIRMWARE_BLOBS}/boot/fixup4db.dat /tmp/rpi/fixup4db.dat
# hadolint ignore=DL3020
ADD ${RASPBERRY_FIRMWARE_BLOBS}/boot/fixup4x.dat /tmp/rpi/fixup4x.dat
# hadolint ignore=DL3020
ADD ${RASPBERRY_FIRMWARE_BLOBS}/boot/start4.elf /tmp/rpi/start4.elf
# hadolint ignore=DL3020
ADD ${RASPBERRY_FIRMWARE_BLOBS}/boot/start4cd.elf /tmp/rpi/start4cd.elf
# hadolint ignore=DL3020
ADD ${RASPBERRY_FIRMWARE_BLOBS}/boot/start4db.elf /tmp/rpi/start4db.elf
# hadolint ignore=DL3020
ADD ${RASPBERRY_FIRMWARE_BLOBS}/boot/start4x.elf /tmp/rpi/start4x.elf
# hadolint ignore=DL3020
ADD ${RASPBERRY_FIRMWARE_BLOBS}/boot/bcm2711-rpi-4-b.dtb /tmp/rpi/bcm2711-rpi-4-b.dtb
# hadolint ignore=DL3020
ADD ${RASPBERRY_FIRMWARE_BLOBS}/boot/bcm2711-rpi-cm4.dtb /tmp/rpi/bcm2711-rpi-cm4.dtb
# hadolint ignore=DL3020
ADD ${RASPBERRY_FIRMWARE_BLOBS}/boot/bcm2712-rpi-5-b.dtb /tmp/rpi/bcm2712-rpi-5-b.dtb
# hadolint ignore=DL3020
ADD ${RASPBERRY_FIRMWARE_BLOBS}/boot/bcm2712d0-rpi-5-b.dtb /tmp/rpi/bcm2712d0-rpi-5-b.dtb
# hadolint ignore=DL3020
ADD ${RASPBERRY_FIRMWARE_BLOBS}/boot/bcm2712-d-rpi-5-b.dtb /tmp/rpi/bcm2712-d-rpi-5-b.dtb
# hadolint ignore=DL3020
ADD ${RASPBERRY_FIRMWARE_BLOBS}/boot/overlays/overlay_map.dtb /tmp/rpi/overlays/overlay_map.dtb
# hadolint ignore=DL3020
ADD ${RASPBERRY_FIRMWARE_BLOBS}/boot/overlays/vc4-kms-v3d.dtbo /tmp/rpi/overlays/vc4-kms-v3d.dtbo
# hadolint ignore=DL3020
ADD ${RASPBERRY_FIRMWARE_BLOBS}/boot/overlays/vc4-kms-v3d-pi4.dtbo /tmp/rpi/overlays/vc4-kms-v3d-pi4.dtbo
# hadolint ignore=DL3020
ADD ${RASPBERRY_FIRMWARE_BLOBS}/boot/overlays/vc4-kms-v3d-pi5.dtbo /tmp/rpi/overlays/vc4-kms-v3d-pi5.dtbo
# hadolint ignore=DL3020
ADD ${RASPBERRY_FIRMWARE_BLOBS}/boot/overlays/disable-bt.dtbo /tmp/rpi/overlays/disable-bt.dtbo
# hadolint ignore=DL3020
ADD ${RASPBERRY_FIRMWARE_BLOBS}/boot/overlays/disable-bt-pi5.dtbo /tmp/rpi/overlays/disable-bt-pi5.dtbo
# hadolint ignore=DL3020
ADD ${RASPBERRY_FIRMWARE_BLOBS}/boot/overlays/miniuart-bt.dtbo /tmp/rpi/overlays/miniuart-bt.dtbo
# hadolint ignore=DL3020
ADD ${RASPBERRY_FIRMWARE_BLOBS}/boot/overlays/tpm-slb9670.dtbo /tmp/rpi/overlays/tpm-slb9670.dtbo

COPY rpi /tmp/rpi

# hadolint ignore=DL3020,SC3060
RUN  for i in /tmp/rpi/overlays/*.dts ; do \
         dtc -@ -I dts -O dtb -o "${i/.dts/.dtbo}" "$i" && rm "$i"; \
     done; \
     cp -r /tmp/rpi/* /boot

FROM build-base AS build-riscv64
ENV TARGET qemu-riscv64_smode_defconfig

# hadolint ignore=DL3006
FROM build-${TARGETARCH} AS build

# generate default config for the target
RUN make "$TARGET"
RUN make -j "$(getconf _NPROCESSORS_ONLN)"

# export a final set of u-boot artifacts into /boot
RUN cp /u-boot/u-boot.bin /boot

# Register u-boot in the APK DB, mandatory for it to be included in the SBOM.
RUN register-sbom-pkg.sh -n u-boot -v "${VERSION}" -l GPL-2.0-only -u https://www.denx.de/wiki/U-Boot

# Register raspberrypi-firmware in the APK DB, mandatory for it to be included in the SBOM.
RUN if [ "$(uname -m)" = aarch64 ]; then \
        register-sbom-pkg.sh -n raspberrypi-firmware -v "${RASPBERRY_FIRMWARE_BLOBS_VERSION}" -l proprietary -u https://github.com/raspberrypi/firmware; \
    fi

FROM scratch
ENTRYPOINT []
CMD []
COPY --from=build /u-boot/u-boot* /u-boot/
COPY --from=build /boot /boot
COPY --from=build /out/lib/apk/db/installed /lib/apk/db/installed
