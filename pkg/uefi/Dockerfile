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
FROM lfedge/eve-alpine:6.2.0 as build
ENV BUILD_PKGS curl make gcc g++ python3 libuuid iasl nasm util-linux-dev bash git util-linux patch
RUN eve-alpine-deploy.sh

RUN git clone --depth 1 -b edk2-stable202005 https://github.com/tianocore/edk2.git /ws
WORKDIR /ws
RUN git submodule update --init
COPY build.sh /ws/
COPY patch /ws/patch
RUN bash -c 'patch -p0 < patch/*'
RUN ln -s python3 /usr/bin/python
RUN make -C BaseTools
RUN ./build.sh

# now create an out dir for all the artifacts
RUN rm -rf /out && mkdir /out && cp /ws/OVMF*.fd /out

# FIXME: we should be building Raspbery Pi 4 UEFI implementations
COPY rpi /tmp/rpi
RUN if [ "$(uname -m)" = aarch64 ]; then cp -r /tmp/rpi /out/ ;fi

FROM scratch
COPY --from=build /out/* /
