ARG EVE_BUILDER_IMAGE=lfedge/eve-alpine:6.7.0
# hadolint ignore=DL3006
FROM ${EVE_BUILDER_IMAGE} as build
ENV BUILD_PKGS bash binutils-dev build-base bc curl bison flex openssl-dev python3 swig
ENV BUILD_PKGS_amd64 python3-dev py-pip
RUN eve-alpine-deploy.sh

SHELL ["/bin/bash", "-eo", "pipefail", "-c"]

ENV VERSION v2021.10
ENV SOURCE_URL https://github.com/u-boot/u-boot/archive/${VERSION}.tar.gz
ENV RAPBERRY_FIRMWARE_BLOBS_VERSION 1.20200601
ENV RAPBERRY_FIRMWARE_BLOBS https://github.com/raspberrypi/firmware/raw/${RAPBERRY_FIRMWARE_BLOBS_VERSION}
ENV TARGET_x86_64 qemu-x86_64_defconfig
ENV TARGET_aarch64 rpi_4_defconfig
ENV TARGET_riscv64 qemu-riscv64_smode_defconfig

RUN curl -fsSL ${SOURCE_URL} | tar -C / -xzf - && mv /u-boot* /u-boot

WORKDIR /u-boot
# FIXME: we need to get to the bottom of this weird workaround on x86/Alpine
RUN [ "$(uname -m)" != x86_64 ] || sed -ie 's#CONFIG_IS_ENABLED(X86_64)#1#' ./arch/x86/include/asm/byteorder.h
COPY patches /tmp/patches
RUN if [ "$(uname -m)" = aarch64 ]; then\
       for p in /tmp/patches/patches-"${VERSION}"/*.patch ; do patch -p1 < "$p" || exit 1 ; done;\
    fi
# need to tweak u-boot config with our local settings
COPY config /tmp/
RUN cat /tmp/config >> "configs/$(eval echo \$TARGET_"$(uname -m)")"
# generate default config for the target
RUN eval make \$TARGET_"$(uname -m)"
RUN make -j "$(getconf _NPROCESSORS_ONLN)"

# export a final set of u-boot artifacts into /boot
RUN mkdir /boot && cp /u-boot/u-boot.bin /boot
# FIXME: copy RPi4 dtb
COPY rpi /tmp/rpi
# download blobs for raspberry -d YYY
RUN if [ "$(uname -m)" = aarch64 ]; then \
       curl -fsSLo /tmp/rpi/fixup4.dat "${RAPBERRY_FIRMWARE_BLOBS}/boot/fixup4.dat" ;\
       curl -fsSLo /tmp/rpi/start4.elf "${RAPBERRY_FIRMWARE_BLOBS}/boot/start4.elf" ;\
       for i in /tmp/rpi/overlays/*.dts ; do                                         \
          scripts/dtc/dtc -@ -I dts -O dtb -o "${i/.dts/.dtbo}" "$i" && rm "$i"     ;\
       done                                                                         ;\
       cp -r /tmp/rpi/* /boot                                                       ;\
    fi

FROM scratch
ENTRYPOINT []
CMD []
COPY --from=build /u-boot/u-boot* /u-boot/
COPY --from=build /boot /boot
