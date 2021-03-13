FROM lfedge/eve-alpine:99db0c3af59a9656315c9d7a0ad8a24f631134b0 as build
ENV BUILD_PKGS binutils-dev build-base bc curl bison flex openssl-dev python3 swig
ENV BUILD_PKGS_amd64 python3-dev
RUN eve-alpine-deploy.sh

ENV VERSION v2020.07
ENV SOURCE_URL https://github.com/u-boot/u-boot/archive/${VERSION}.tar.gz
ENV RAPBERRY_FIRMWARE_BLOBS_VERSION 1.20200601
ENV RAPBERRY_FIRMWARE_BLOBS https://github.com/raspberrypi/firmware/raw/${RAPBERRY_FIRMWARE_BLOBS_VERSION}
ENV TARGET_x86_64 qemu-x86_defconfig
ENV TARGET_aarch64 rpi_4_defconfig

RUN curl -fsSL ${SOURCE_URL} | tar -C / -xzf - && mv /u-boot* /u-boot

WORKDIR /u-boot
# FIXME: we need to get to the bottom of this weird workaround on x86/Alpine
RUN [ "$(uname -m)" != x86_64 ] || sed -ie 's#CONFIG_IS_ENABLED(X86_64)#1#' ./arch/x86/include/asm/byteorder.h
COPY patches /tmp/patches
RUN if [ "$(uname -m)" = aarch64 ]; then\
       for p in /tmp/patches/patches-"${VERSION}"/*.patch ; do patch -p1 < "$p" || exit 1 ; done;\
    fi
RUN eval make \$TARGET_"$(uname -m)"
RUN make -j "$(getconf _NPROCESSORS_ONLN)"

# export a final set of u-boot artifacts into /boot
RUN mkdir /boot && cp /u-boot/u-boot.bin /boot
# FIXME: copy RPi4 dtb
COPY rpi /tmp/rpi
# download blobs for raspberry
RUN if [ "$(uname -m)" = aarch64 ]; then curl -fsSLo /tmp/rpi/fixup4.dat ${RAPBERRY_FIRMWARE_BLOBS}/boot/fixup4.dat ; fi
RUN if [ "$(uname -m)" = aarch64 ]; then curl -fsSLo /tmp/rpi/start4.elf ${RAPBERRY_FIRMWARE_BLOBS}/boot/start4.elf ; fi
RUN if [ "$(uname -m)" = aarch64 ]; then cp -r /tmp/rpi/* /boot ; fi


FROM scratch
ENTRYPOINT []
CMD []
COPY --from=build /u-boot/u-boot* /u-boot/
COPY --from=build /boot /boot
