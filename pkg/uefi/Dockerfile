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

RUN apk add --no-cache curl make gcc g++ python libuuid iasl nasm util-linux-dev bash
RUN mkdir /ws ; curl -L https://github.com/tianocore/edk2/archive/vUDK2018.tar.gz | tar --strip-components 1 -C /ws -xzf -

WORKDIR /ws
ENV BUILD_ARGS_aarch64 -b RELEASE -t GCC5 -a AARCH64 -p ArmVirtPkg/ArmVirtQemu.dsc
ENV BUILD_ARGS_x86_64  -b RELEASE -t GCC5 -a X64 -p OvmfPkg/OvmfPkgX64.dsc
COPY patch /ws/patch
RUN bash -c 'patch -p0 < patch/*'
RUN make -C BaseTools
RUN bash -c ". edksetup.sh ; build \$BUILD_ARGS_"`uname -m`
RUN cp Build/OvmfX64/RELEASE_*/FV/OVMF*.fd . 2>/dev/null || \
    (cp Build/ArmVirtQemu-AARCH64/RELEASE_GCC5/FV/QEMU_EFI.fd OVMF.fd ;\
     cp Build/ArmVirtQemu-AARCH64/RELEASE_GCC5/FV/QEMU_VARS.fd OVMF_VARS.fd)

FROM scratch
COPY --from=build /ws/OVMF*.fd /
