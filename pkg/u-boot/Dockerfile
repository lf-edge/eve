FROM lfedge/eve-alpine:9fb9b9cbf7d90066a70e4704d04a6fe248ff52bb as build-base
ENV BUILD_PKGS bash binutils-dev build-base bc bison flex openssl-dev python3 swig dtc
ENV BUILD_PKGS_amd64 python3-dev py-pip
RUN eve-alpine-deploy.sh

SHELL ["/bin/bash", "-eo", "pipefail", "-c"]

ENV VERSION v2022.10
ENV SOURCE_URL https://github.com/u-boot/u-boot/archive/${VERSION}.tar.gz
ENV RASPBERRY_FIRMWARE_BLOBS_VERSION 1.20211007
ENV RASPBERRY_FIRMWARE_BLOBS https://github.com/raspberrypi/firmware/raw/${RASPBERRY_FIRMWARE_BLOBS_VERSION}

# hadolint ignore=DL3020
ADD ${SOURCE_URL} /uboot.tar.gz
RUN tar -C / -xzf /uboot.tar.gz && rm -f /uboot.tar.gz && mv /u-boot* /u-boot

WORKDIR /u-boot
COPY patches /tmp/patches

RUN mkdir /boot


FROM build-base AS build-amd64
ENV TARGET qemu-x86_64_defconfig
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
# hadolint ignore=SC3060
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
