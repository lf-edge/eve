# syntax=docker/dockerfile-upstream:1.5.0-rc2-labs
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
FROM lfedge/eve-alpine:0f2e0da38e30753c68410727a6cc269e57ff74f2 AS build
ENV BUILD_PKGS make gcc g++ python3 libuuid nasm util-linux-dev bash git util-linux patch
ENV BUILD_PKGS_amd64 iasl
ENV BUILD_PKGS_arm64 iasl
RUN eve-alpine-deploy.sh
RUN ln -s python3 /usr/bin/python

COPY edk2-patches /edk2-patches

FROM build AS build-arm64-versions

ENV EDK_VERSION edk2-stable202208
ENV EDK_COMMIT ba0e0e4c6a174b71b18ccd6e47319cc45878893c

# FIXME: we should be building Raspberry Pi 4 UEFI implementations
COPY rpi /rpi

FROM build AS build-amd64-versions

ENV EDK_VERSION edk2-stable202408.01
ENV EDK_COMMIT 4dfdca63a93497203f197ec98ba20e2327e4afe4

FROM build-${TARGETARCH}-versions AS build-edk2

WORKDIR /edk2
ADD --keep-git-dir=true https://github.com/tianocore/edk2.git#${EDK_COMMIT} /edk2

RUN set -e ; [ ! -d /edk2 ] ||  [ ! -d /edk2-patches/${EDK_VERSION} ] || \
        for patch in /edk2-patches/${EDK_VERSION}/*.patch; do \
            echo "Applying $patch"; \
            git apply -p1 < "$patch" || exit 1 ; \
        done

FROM build-edk2 AS build-amd64

FROM build-edk2 AS build-arm64

FROM build AS build-riscv64

ENV SBI_COMMIT cbaa9b0333517b3c25bea8d1c71ac8005ff1f727
ADD https://github.com/riscv/opensbi/tarball/${SBI_COMMIT} /opensbi.tgz

WORKDIR /opensbi
RUN tar -zxvf /opensbi.tgz  --strip-components=1 && \
    rm /opensbi.tgz

FROM build-${TARGETARCH} AS build-interim

WORKDIR /edk2
COPY build.sh /edk2/
RUN ./build.sh

# create an out dir for all the artifacts
RUN rm -rf /out && mkdir /out && cp /edk2/OVMF*.fd /out

# some architecture specific cases. There probably is a cleaner dockerfile-native way to do this.
RUN case $(uname -m) in \
    aarch64) \
        cp -r /rpi /out/ \
        ;; \
    esac


FROM scratch
COPY --from=build-interim /out/* /
