# syntax=docker/dockerfile-upstream:1.5.0-rc2-labs
# Copyright (c) 2025-2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

# The image ships only /boot, whose contents go onto the ESP, plus the apk db
# for the SBOM. On arm64 /boot holds u-boot.bin and the Raspberry Pi firmware,
# DTBs and overlays; on riscv64 it holds u-boot.bin, which QEMU loads.
# amd64 boots through UEFI and uses no u-boot, so its /boot is empty.

FROM lfedge/eve-alpine:080e2b4c683508649d72d2ae9b166153d819ca5d AS build-amd64
RUN eve-alpine-deploy.sh && mkdir -p /boot

FROM lfedge/eve-alpine:080e2b4c683508649d72d2ae9b166153d819ca5d AS uboot
ENV BUILD_PKGS bash binutils-dev build-base bc bison flex gnutls gnutls-dev openssl-dev python3 swig dtc git
RUN eve-alpine-deploy.sh

SHELL ["/bin/bash", "-eo", "pipefail", "-c"]

ENV UBOOT_VERSION=v2026.04
ENV UBOOT_REPO=https://github.com/u-boot/u-boot.git
# hadolint ignore=DL3020
ADD --keep-git-dir ${UBOOT_REPO}#${UBOOT_VERSION} /u-boot

WORKDIR /u-boot
COPY patches /tmp/patches

RUN mkdir -p /boot
RUN git config --global user.name 'Project EVE'
RUN git config --global user.email 'builder@projecteve.dev'
# hadolint ignore=SC2046
RUN git am /tmp/patches/patches-${UBOOT_VERSION}/*

# generate default config for the target
ARG TARGETARCH
RUN case "${TARGETARCH}" in \
        arm64) make rpi_arm64_defconfig ;; \
        riscv64) make qemu-riscv64_smode_defconfig ;; \
        *) echo "no u-boot target for ${TARGETARCH}"; exit 1 ;; \
    esac
RUN make -j "$(getconf _NPROCESSORS_ONLN)"

# export a final set of u-boot artifacts into /boot
RUN cp /u-boot/u-boot.bin /boot

# Register u-boot in the APK DB, mandatory for it to be included in the SBOM.
RUN register-sbom-pkg.sh -n u-boot -v "${UBOOT_VERSION}" -l GPL-2.0-only -u https://www.denx.de/wiki/U-Boot

FROM uboot AS build-arm64
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

# Register raspberrypi-firmware in the APK DB, mandatory for it to be included in the SBOM.
RUN register-sbom-pkg.sh -n raspberrypi-firmware -v "${RASPBERRY_FIRMWARE_BLOBS_VERSION}" -l proprietary -u https://github.com/raspberrypi/firmware

FROM uboot AS build-riscv64

# hadolint ignore=DL3006
FROM build-${TARGETARCH} AS build

FROM scratch
ENTRYPOINT []
CMD []
COPY --from=build /boot /boot
COPY --from=build /out/lib/apk/db/installed /lib/apk/db/installed
