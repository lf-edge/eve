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
# It is possible to do a docker-based aarch64 build on x86.
# If you want to do that -- make sure to pass the following
# argument to the docker build:
#   --build-arg BUILD_CONTAINER=alpine@sha256:286be1c7f84de7cbae6cf8aa4e13b3ce2f2512353b3e734336e47e92de4a881e
ARG BUILD_CONTAINER=alpine:3.7
FROM ${BUILD_CONTAINER} as build

# hadolint ignore=DL3018
RUN apk add --no-cache curl make gcc g++ python libuuid iasl nasm util-linux-dev bash git util-linux

RUN git clone --depth 1 -b edk2-stable201908 https://github.com/tianocore/edk2.git /ws
WORKDIR /ws
RUN git submodule update --init --depth 1
COPY build.sh /ws/
COPY patch /ws/patch
RUN bash -c 'patch -p0 < patch/*'
RUN make -C BaseTools
RUN ./build.sh

# now create an out dir for all the artifacts
RUN mkdir /out && cp /ws/OVMF*.fd /out

# FIXME: we should be building Raspbery Pi 4 UEFI implementations
COPY rpi /tmp/rpi
RUN if [ "$(uname -m)" = aarch64 ]; then cp -r /tmp/rpi /out/ ;fi

FROM scratch
COPY --from=build /out/* /
