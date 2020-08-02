FROM linuxkit/alpine:3fdc49366257e53276c6f363956a4353f95d9a81 as build

ENV VERSION v2020.07
ENV SOURCE_URL https://github.com/u-boot/u-boot/archive/${VERSION}.tar.gz
ENV TARGET_x86_64 qemu-x86_defconfig
ENV TARGET_aarch64 rpi_4_defconfig

RUN apk add --no-cache     \
    binutils-dev=2.31.1-r2 \
    build-base=0.5-r1      \
    bc=1.07.1-r0           \
    curl=7.64.0-r2         \
    bison=3.0.5-r0         \
    flex=2.6.4-r1          \
    openssl-dev=1.1.1b-r1  \
    python3                \
    swig

RUN curl -fsSL ${SOURCE_URL} | tar -C / -xzf - && mv /u-boot* /u-boot

WORKDIR /u-boot
# FIXME: we need to get to the bottom of this weird workaround on x86/Alpine
RUN if [ "$(uname -m)" = x86_64 ]; then                                              \
       cp /etc/apk/repositories.upstream /etc/apk/repositories                     &&\
       apk add --no-cache python3-dev=3.6.9-r3                                     &&\
       sed -ie 's#CONFIG_IS_ENABLED(X86_64)#1#' ./arch/x86/include/asm/byteorder.h  ;\
    fi
COPY patches /tmp/patches
RUN if [ "$(uname -m)" = aarch64 ]; then\
       for p in /tmp/patches/patches-"${VERSION}"/*.patch ; do patch -p1 < "$p" || exit 1 ; done;\
    fi
RUN eval make \$TARGET_"$(uname -m)"
RUN make -j "$(getconf _NPROCESSORS_ONLN)"

# export a final set of u-boot artifacts into /boot
RUN mkdir /boot && cp /u-boot/u-boot.bin /boot
# FIXME: copy RPi4 binary blobs for now
COPY rpi /tmp/rpi
RUN if [ "$(uname -m)" = aarch64 ]; then cp -r /tmp/rpi/* /boot ; fi


FROM scratch
ENTRYPOINT []
CMD []
COPY --from=build /u-boot/u-boot* /u-boot/
COPY --from=build /boot /boot
