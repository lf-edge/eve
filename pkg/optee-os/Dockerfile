# syntax=docker/dockerfile-upstream:1.5.0-rc2-labs

# use the same set of packages for simplicity
ARG BUILD_PKGS_BASE="autoconf automake bash binutils binutils-dev build-essential bc bison curl device-tree-compiler libexpat1-dev flex libssl-dev uuid-dev swig libgnutls28-dev perl python3 python3-dev python3-setuptools python3-pycryptodome python3-pyelftools python3-cryptography"

# we use the same image in several places
ARG EVE_UBUNTU_IMAGE=lfedge/eve-ubuntu:17fea35e37517165b27e0e3f142d38750eb0a544

# native build: the compiler of the build host targets the firmware's
# architecture already. The 32-bit ARM compiler is needed by every build for
# the arm32 TAs and does not exist on riscv64, where nothing is built anyway.
# hadolint ignore=DL3006
FROM ${EVE_UBUNTU_IMAGE} AS build-native
ARG BUILD_PKGS_BASE
RUN BUILD_PKGS="${BUILD_PKGS_BASE}" BUILD_PKGS_amd64=gcc-arm-linux-gnueabihf BUILD_PKGS_arm64=gcc-arm-linux-gnueabihf eve-ubuntu-deploy.sh
ENV CROSS_COMPILE_ENV=""

# cross build: Ubuntu's cross compiler for the target on the build host
# hadolint ignore=DL3006,DL3029
FROM --platform=${BUILDPLATFORM} ${EVE_UBUNTU_IMAGE} AS build-cross
ARG BUILD_PKGS_BASE
RUN BUILD_PKGS="${BUILD_PKGS_BASE}" BUILD_PKGS_amd64=gcc-arm-linux-gnueabihf BUILD_PKGS_arm64=gcc-arm-linux-gnueabihf eve-ubuntu-deploy.sh

FROM build-cross AS build-cross-target-amd64
RUN BUILD_PKGS=gcc-x86-64-linux-gnu eve-ubuntu-deploy.sh
ENV CROSS_COMPILE_ENV=x86_64-linux-gnu-
FROM build-cross AS build-cross-target-arm64
RUN BUILD_PKGS=gcc-aarch64-linux-gnu eve-ubuntu-deploy.sh
ENV CROSS_COMPILE_ENV=aarch64-linux-gnu-
FROM build-cross AS build-cross-target-riscv64
RUN BUILD_PKGS=gcc-riscv64-linux-gnu eve-ubuntu-deploy.sh
ENV CROSS_COMPILE_ENV=riscv64-linux-gnu-

# cross-compilers
FROM build-cross-target-arm64 AS target-arm64-build-amd64
FROM build-cross-target-amd64 AS target-amd64-build-arm64
FROM build-cross-target-riscv64 AS target-riscv64-build-amd64
FROM build-cross-target-riscv64 AS target-riscv64-build-arm64
# native
FROM build-native AS target-amd64-build-amd64
FROM build-native AS target-arm64-build-arm64
FROM build-native AS target-riscv64-build-riscv64

# hadolint ignore=DL3006
FROM target-${TARGETARCH}-build-${BUILDARCH} AS build
ARG TARGETARCH

# ARM32 compiler is needed on all platforms
ENV CROSS_COMPILE_ARM32_ENV="arm-linux-gnueabihf-"

SHELL ["/bin/bash", "-eo", "pipefail", "-c"]

RUN mkdir /optee_os /opteeos_bins

# Patches
COPY patches /tmp/patches

# RSA keys to sign TAs
COPY eve-optee.pem.gz  /optee_os
COPY eve-optee-pub.pem.gz /optee_os

WORKDIR /optee_os

RUN gunzip eve-optee.pem.gz && gunzip eve-optee-pub.pem.gz
ENV EVE_TA_SIGN_KEY="/optee_os/eve-optee.pem"

# Target platforms to build OPTEE-OS
ENV OPTEEOS_TARGETS="qemu imx8mp_pollux imx8mp_epc_r3720"

# QEMU
ENV OPTEEOS_REV_qemu=2be3770e85826ae69748fc3e68920d7293a98c5d
ENV OPTEEOS_qemu="vexpress-qemu_armv8a"
ENV OPTEEOS_FLAVOR_qemu=""
ENV OPTEEOS_UART_qemu="0x7ff70000"
ENV OPTEEOS_SRC_qemu="qemu"
ENV OPTEEOS_CUSTOM_qemu=""

# i.MX8MP
ENV OPTEEOS_REV_imx8mp_pollux=c939619d64dea014ad1b8382356eee4d1cbfbb22
ENV OPTEEOS_imx8mp_pollux="imx"
ENV OPTEEOS_FLAVOR_imx8mp_pollux="mx8mpevk"
ENV OPTEEOS_UART_imx8mp_pollux="0x30860000"
ENV OPTEEOS_SRC_imx8mp_pollux="pollux"
ENV OPTEEOS_CUSTOM_imx8mp_pollux=""

ENV OPTEEOS_REV_imx8mp_epc_r3720=c939619d64dea014ad1b8382356eee4d1cbfbb22
ENV OPTEEOS_imx8mp_epc_r3720="imx"
ENV OPTEEOS_FLAVOR_imx8mp_epc_r3720="mx8mpevk"
ENV OPTEEOS_UART_imx8mp_epc_r3720="0x30880000"
ENV OPTEEOS_SRC_imx8mp_epc_r3720="epc_r3720"
ENV OPTEEOS_CUSTOM_imx8mp_epc_r3720="CFG_DDR_SIZE=0x180000000ULL"

# Repositories
ADD https://github.com/OP-TEE/optee_os.git#${OPTEEOS_REV_qemu} ${OPTEEOS_SRC_qemu}
ADD https://github.com/nxp-imx/imx-optee-os.git#${OPTEEOS_REV_imx8mp_epc_r3720} ${OPTEEOS_SRC_imx8mp_epc_r3720}
ADD https://github.com/nxp-imx/imx-optee-os.git#${OPTEEOS_REV_imx8mp_pollux} ${OPTEEOS_SRC_imx8mp_pollux}

# hadolint ignore=DL3003,SC2086
RUN for t in ${OPTEEOS_TARGETS}; do \
        [ "$TARGETARCH" != "arm64" ] && break ;\
        target=$(eval echo \$OPTEEOS_${t}) ;\
        repo=$(eval echo \$OPTEEOS_SRC_${t}) ;\
        uartbase=$(eval echo \$OPTEEOS_UART_${t}) ;\
        flavor=$(eval echo \$OPTEEOS_FLAVOR_${t}) ;\
        customdef=$(eval echo \$OPTEEOS_CUSTOM_${t}) ;\
        patchfile=$(eval echo /tmp/patches/series-${t}) ;\
        (cd ${repo} ;\
         cp ${EVE_TA_SIGN_KEY} keys/default_ta.pem && \
         [ -f "$patchfile" ] && for p in `cat $patchfile`; \
             do patch -p1 < "/tmp/patches/${p}"; done ;\
         make clean && \
         make -j "$(getconf _NPROCESSORS_ONLN)" \
            CROSS_COMPILE="${CROSS_COMPILE_ENV}" \
            CROSS_COMPILE_core="${CROSS_COMPILE_ENV}" \
            CROSS_COMPILE_ta_arm32="${CROSS_COMPILE_ARM32_ENV}" \
            CROSS_COMPILE_ta_arm64="${CROSS_COMPILE_ENV}" \
            CFG_TEE_BENCHMARK=n \
            CFG_TEE_CORE_LOG_LEVEL=1 \
            PLATFORM="${target}" \
            PLATFORM_FLAVOR="${flavor}" \
            CFG_UART_BASE="${uartbase}" \
            O=out/arm \
            LDFLAGS="--no-warn-rwx-segments" \
            ${customdef} ;\
         mkdir -p "/opteeos_bins/${t}" ;\
         cp out/arm/core/tee-raw.bin "/opteeos_bins/${t}/optee.bin" ;\
         cp -r out/arm/export-ta_arm64 "/opteeos_bins/${t}/export-ta_arm64") ;\
    done

# Register optee_os in the dpkg status area, mandatory for it to be included in the SBOM.
RUN register-sbom-pkg.sh && if [ "$TARGETARCH" = "arm64" ]; then \
        register-sbom-pkg.sh -n optee_os -v "$(printf '%.8s' "${OPTEEOS_REV_qemu}")" -l BSD-2-Clause -u https://github.com/OP-TEE/optee_os && \
        register-sbom-pkg.sh -n imx-optee-os -v "$(printf '%.8s' "${OPTEEOS_REV_imx8mp_pollux}")" -l BSD-2-Clause -u https://github.com/nxp-imx/imx-optee-os; \
    fi

FROM scratch
COPY --from=build /opteeos_bins/ /opteeos_images
COPY --from=build /optee_os/*.pem /opteeos_images
COPY --from=build /out/var/lib/dpkg/status.d /var/lib/dpkg/status.d
