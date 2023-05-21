# syntax=docker/dockerfile-upstream:1.5.0-rc2-labs

# use the same set of packages for simplicity
ARG BUILD_PKGS_BASE="autoconf automake bash binutils binutils-dev build-base bc bison curl dtc expat flex openssl-dev util-linux-dev swig gnutls-dev perl python3 python3-dev py3-setuptools py3-pycryptodome py3-elftools py3-cryptography"

# we use the same image in several places
ARG EVE_ALPINE_IMAGE=lfedge/eve-alpine:269db59bde11b9acd9a5485c98a7c1383a159613

# hadolint ignore=DL3006
FROM ${EVE_ALPINE_IMAGE} as build-native
ARG BUILD_PKGS_BASE
RUN BUILD_PKGS="${BUILD_PKGS_BASE}" eve-alpine-deploy.sh

# hadolint ignore=DL3006,DL3029
FROM --platform=${BUILDPLATFORM} ${EVE_ALPINE_IMAGE} as build-cross
ARG BUILD_PKGS_BASE
RUN BUILD_PKGS="${BUILD_PKGS_BASE}" eve-alpine-deploy.sh

# hadolint ignore=DL3029
FROM --platform=${BUILDPLATFORM} lfedge/eve-cross-compilers:250abc77c8c39664905b66a2673102ec5cd3b056 AS cross-compilers

# will use several packages from target arch and copy them to sysroot
# hadolint ignore=DL3006
FROM ${EVE_ALPINE_IMAGE} AS cross-compile-libs
ENV PKGS musl-dev libgcc libintl libuuid libtirpc libblkid libattr
RUN eve-alpine-deploy.sh

# adjust EVE_TARGET_ARCH for cross-compiler
FROM build-cross AS build-cross-target-amd64
ENV EVE_TARGET_ARCH=x86_64
FROM build-cross AS build-cross-target-arm64
ENV EVE_TARGET_ARCH=aarch64
FROM build-cross AS build-cross-target-riscv64
ENV EVE_TARGET_ARCH=riscv64

# hadolint ignore=DL3006
FROM build-cross-target-${TARGETARCH} AS build-cross-target
ENV CROSS_COMPILE_ENV="${EVE_TARGET_ARCH}"-alpine-linux-musl-
ENV CROSS_COMPILE_ARM32_ENV="armv6-alpine-linux-musleabihf-"
COPY --from=cross-compilers /packages /packages
# hadolint ignore=DL3018
RUN apk add --no-cache --allow-untrusted -X /packages build-base-"${EVE_TARGET_ARCH}" build-base-armhf
COPY --from=cross-compile-libs /out/ /usr/"${EVE_TARGET_ARCH}"-alpine-linux-musl/

# cross-compilers
FROM build-cross-target AS target-arm64-build-amd64
FROM build-cross-target AS target-amd64-build-arm64
FROM build-cross-target AS target-riscv64-build-amd64
FROM build-cross-target AS target-riscv64-build-arm64
# native
FROM build-native AS target-amd64-build-amd64
FROM build-native AS target-arm64-build-arm64
FROM build-native AS target-riscv64-build-riscv64

# hadolint ignore=DL3006
FROM target-${TARGETARCH}-build-${BUILDARCH} AS build

# ARM32 compiler is needed on all platforms
ENV CROSS_COMPILE_ARM32_ENV="armv6-alpine-linux-musleabihf-"
COPY --from=cross-compilers /packages /packages
# hadolint ignore=DL3018
RUN apk add --no-cache --allow-untrusted -X /packages build-base-armhf

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
        [ "$EVE_TARGET_ARCH" != "aarch64" ] && break ;\
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
            ${customdef} ;\
         mkdir -p "/opteeos_bins/${t}" ;\
         cp out/arm/core/tee-raw.bin "/opteeos_bins/${t}/optee.bin" ;\
         cp -r out/arm/export-ta_arm64 "/opteeos_bins/${t}/export-ta_arm64") ;\
    done

FROM scratch
COPY --from=build /opteeos_bins/ /opteeos_images
COPY --from=build /optee_os/*.pem /opteeos_images

