FROM lfedge/eve-alpine:0f2e0da38e30753c68410727a6cc269e57ff74f2 AS build-base
ENV BUILD_PKGS bash binutils-dev build-base bc bison flex openssl-dev python3 swig dtc
ENV BUILD_PKGS_amd64 python3-dev py-pip
RUN eve-alpine-deploy.sh

SHELL ["/bin/bash", "-eo", "pipefail", "-c"]

ENV VERSION v2024.10-rc2
ENV SOURCE_URL https://github.com/u-boot/u-boot/archive/${VERSION}.tar.gz
ENV RASPBERRY_FIRMWARE_BLOBS_VERSION 1.20211007
ENV RASPBERRY_FIRMWARE_BLOBS_VERSION_RPI5 1.20240306
ENV RASPBERRY_FIRMWARE_BLOBS https://github.com/raspberrypi/firmware/raw/${RASPBERRY_FIRMWARE_BLOBS_VERSION}
ENV RASPBERRY_FIRMWARE_BLOBS_RPI5 https://github.com/raspberrypi/firmware/raw/${RASPBERRY_FIRMWARE_BLOBS_VERSION_RPI5}

# hadolint ignore=DL3020
ADD ${SOURCE_URL} /uboot.tar.gz
RUN tar -C / -xzf /uboot.tar.gz && rm -f /uboot.tar.gz && mv /u-boot* /u-boot

WORKDIR /u-boot
COPY patches /tmp/patches

RUN mkdir /boot


FROM build-base AS build-amd64
ENV TARGET qemu-x86_64_defconfig
RUN for p in /tmp/patches/patches-"${VERSION}"/*.patch ; do patch -p1 < "$p" || exit 1 ; done
# FIXME: we need to get to the bottom of this weird workaround on x86/Alpine
RUN sed -ie 's#CONFIG_IS_ENABLED(X86_64)#1#' ./arch/x86/include/asm/byteorder.h

FROM build-base AS build-arm64
ENV TARGET rpi_4_defconfig
RUN for p in /tmp/patches/patches-"${VERSION}"/*.patch ; do patch -p1 < "$p" || exit 1 ; done

# FIXME: copy RPi4 dtb
COPY rpi /tmp/rpi
# download blobs for raspberry -d YYY
# hadolint ignore=DL3020
ADD ${RASPBERRY_FIRMWARE_BLOBS}/boot/fixup4.dat /tmp/rpi/fixup4.dat
# hadolint ignore=DL3020
ADD ${RASPBERRY_FIRMWARE_BLOBS}/boot/start4.elf /tmp/rpi/start4.elf
# hadolint ignore=DL3020
ADD ${RASPBERRY_FIRMWARE_BLOBS}/boot/bcm2711-rpi-cm4.dtb /tmp/rpi/bcm2711-rpi-cm4.dtb
# hadolint ignore=DL3020
ADD ${RASPBERRY_FIRMWARE_BLOBS_RPI5}/boot/bcm2712-rpi-5-b.dtb /tmp/rpi/bcm2712-rpi-5-b.dtb
# hadolint ignore=DL3020,SC3060
RUN  for i in /tmp/rpi/overlays/*.dts ; do                                         \
          dtc -@ -I dts -O dtb -o "${i/.dts/.dtbo}" "$i" && rm "$i"     ;\
       done                                                                         ;\
       cp -r /tmp/rpi/* /boot

FROM build-base AS build-riscv64
ENV TARGET qemu-riscv64_smode_defconfig
RUN for p in /tmp/patches/patches-"${VERSION}"/*.patch ; do patch -p1 < "$p" || exit 1 ; done

# hadolint ignore=DL3006
FROM build-${TARGETARCH} AS build

# need to tweak u-boot config with our local settings
COPY config /tmp/
RUN cat /tmp/config >> "configs/${TARGET}"
# generate default config for the target
RUN make "$TARGET"
RUN make -j "$(getconf _NPROCESSORS_ONLN)"

# export a final set of u-boot artifacts into /boot
RUN cp /u-boot/u-boot.bin /boot
RUN if [ "$(uname -m)" = aarch64 ]; then \
          cp /u-boot/arch/arm/dts/bcm2711-rpi-4-b.dtb /boot          ;\
       fi

FROM scratch
ENTRYPOINT []
CMD []
COPY --from=build /u-boot/u-boot* /u-boot/
COPY --from=build /boot /boot
