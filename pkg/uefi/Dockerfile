# Instructions for this package are taken from:
#   https://wiki.ubuntu.com/UEFI/EDK2
#   https://wiki.linaro.org/LEG/UEFIforQEMU
#
# On ARM here's what works for other boars:
#   git clone https://github.com/tianocore/edk2
#   git clone https://github.com/tianocore/edk2-platforms
#   git clone https://github.com/tianocore/edk2-non-osi
#   git clone https://git.linaro.org/uefi/uefi-tools.git
#   ./uefi-tools/edk2-build.sh -b DEBUG -b RELEASE all
#
ARG EVE_BUILDER_IMAGE=lfedge/eve-alpine:6.7.0
# hadolint ignore=DL3006
FROM ${EVE_BUILDER_IMAGE} as build
ENV BUILD_PKGS curl make gcc g++ python3 libuuid nasm util-linux-dev bash git util-linux patch
ENV BUILD_PKGS_amd64 iasl
ENV BUILD_PKGS_arm64 iasl
RUN eve-alpine-deploy.sh

ENV EDK_COMMIT ca407c7246bf405da6d9b1b9d93e5e7f17b4b1f9
ENV SBI_COMMIT cbaa9b0333517b3c25bea8d1c71ac8005ff1f727

RUN git clone -b edk2-stable202005 https://github.com/tianocore/edk2.git /ws && git -C /ws checkout ${EDK_COMMIT}
RUN git clone https://github.com/riscv/opensbi.git /opensbi && git -C /opensbi checkout ${SBI_COMMIT}
WORKDIR /ws
RUN git submodule update --init
COPY build.sh /ws/
COPY patch /ws/patch
RUN for p in /ws/patch/*.patch ; do patch -p1 < "$p"; echo "$p"; done
RUN sed -i 's/DEFINE DEBUG_PRINT_ERROR_LEVEL = 0x8000004F/DEFINE DEBUG_PRINT_ERROR_LEVEL = 0x00000001/g' ArmVirtPkg/ArmVirt.dsc.inc
RUN ln -s python3 /usr/bin/python
RUN ./build.sh

# now create an out dir for all the artifacts
RUN rm -rf /out && mkdir /out && cp /ws/OVMF*.fd /out && if [ "$(uname -m)" = x86_64 ]; then cp /ws/*.rom /out/ ;fi

# FIXME: we should be building Raspbery Pi 4 UEFI implementations
COPY rpi /tmp/rpi
RUN if [ "$(uname -m)" = aarch64 ]; then cp -r /tmp/rpi /out/ ;fi

FROM scratch
COPY --from=build /out/* /
