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
FROM lfedge/eve-alpine:145f062a40639b6c65efa36bed1c5614b873be52 as build
ENV BUILD_PKGS curl make gcc g++ python3 libuuid nasm util-linux-dev bash git util-linux patch
ENV BUILD_PKGS_amd64 iasl
ENV BUILD_PKGS_arm64 iasl
RUN eve-alpine-deploy.sh
RUN ln -s python3 /usr/bin/python

ENV EDK_VERSION_aarch64 edk2-stable202208
ENV EDK_COMMIT_aarch64 edk2-stable202208

ENV EDK_VERSION_x86_64 edk2-stable202005
ENV EDK_COMMIT_x86_64 ca407c7246bf405da6d9b1b9d93e5e7f17b4b1f9

ENV SBI_COMMIT cbaa9b0333517b3c25bea8d1c71ac8005ff1f727

COPY edk2-patches /edk2-patches
RUN if [ "$(uname -m)" != riscv64 ]; then \
        git clone -b "$(eval echo \$EDK_VERSION_"$(uname -m)")" https://github.com/tianocore/edk2.git /edk2 && \
        git -C /edk2 checkout "$(eval echo \$EDK_COMMIT_"$(uname -m)")" && \
        git -C /edk2 submodule update --init; \
    fi
RUN set -e ; [ ! -d /edk2 ] ||  [ ! -d /edk2-patches/"$(eval echo \$EDK_VERSION_"$(uname -m)")" ] || \
        for patch in /edk2-patches/"$(eval echo \$EDK_VERSION_"$(uname -m)")"/*.patch; do \
            echo "Applying $patch"; \
            patch -d /edk2 -p1 < "$patch" || exit 1 ; \
        done

RUN if [ "$(uname -m)" = riscv64 ]; then \
        git clone https://github.com/riscv/opensbi.git /opensbi && \
        git -C /opensbi checkout ${SBI_COMMIT}; \
    fi

WORKDIR /edk2
COPY build.sh /edk2/
RUN ./build.sh

# now create an out dir for all the artifacts
RUN rm -rf /out && mkdir /out && cp /edk2/OVMF*.fd /out && if [ "$(uname -m)" = x86_64 ]; then cp /edk2/*.rom /out/ ;fi

# FIXME: we should be building Raspbery Pi 4 UEFI implementations
COPY rpi /tmp/rpi
RUN if [ "$(uname -m)" = aarch64 ]; then cp -r /tmp/rpi /out/ ;fi

FROM scratch
COPY --from=build /out/* /
