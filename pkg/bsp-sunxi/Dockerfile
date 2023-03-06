# syntax=docker/dockerfile-upstream:1.5.0-rc2-labs
FROM lfedge/eve-alpine:b678c1428a2c2c3f9121c1351eec3a8922ba53b9 as build-base
RUN mkdir /bsp

FROM build-base AS build-amd64
FROM build-base AS build-riscv64
FROM build-base AS build-arm64
ENV BUILD_PKGS bash binutils-dev build-base bc bison gcc-or1k-elf flex openssl-dev util-linux-dev swig gnutls-dev perl python3 python3-dev py3-setuptools py3-pycryptodome py3-elftools
RUN eve-alpine-deploy.sh

SHELL ["/bin/bash", "-eo", "pipefail", "-c"]

ENV BSP_TARGETS "opi3_lts"

# Orange Pi3 LTS ENV
ENV ATF_PLAT_opi3_lts sun50i_h6
ENV ATF_COMMIT_opi3_lts v2.2
ENV CRUST_DEFCONF_opi3_lts orangepi_3_defconfig
ENV CRUST_COMMIT_opi3_lts c308a504853e7fdb47169796c9a832796410ece8
ENV UBOOT_DEFCONF_opi3_lts orangepi_3_lts_defconfig
ENV UBOOT_COMMIT_opi3_lts v2023.01
ENV UBOOT_BLOB_opi3_lts u-boot-sunxi-with-spl.bin
ENV BOOT_OFFSET_opi3_lts 128

# Orange Pi3 LTS sources
ADD https://github.com/ARM-software/arm-trusted-firmware.git#${ATF_COMMIT_opi3_lts} atf-opi3_lts/
ADD https://github.com/crust-firmware/crust.git#${CRUST_COMMIT_opi3_lts} crust-opi3_lts/
ADD https://github.com/u-boot/u-boot.git#${UBOOT_COMMIT_opi3_lts} u-boot-opi3_lts/

COPY patches /tmp/patches

# Build ATF
RUN mkdir /atf-blobs
# hadolint ignore=DL3003,SC2086
RUN for t in ${BSP_TARGETS}; do \
        target=$(eval echo \$ATF_PLAT_${t}) ;\
        (cd "atf-${t}" ;\
         make clean && \
         make -j "$(getconf _NPROCESSORS_ONLN)" \
            PLAT=${target} \
            bl31 ;\
         mv build/${target}/release/bl31.bin /atf-blobs/${t}-bl31.bin) ;\
    done

# Build crust
RUN mkdir /crust-blobs
# hadolint ignore=DL3003,SC2086
RUN for t in ${BSP_TARGETS}; do \
        defconf=$(eval echo \$CRUST_DEFCONF_${t}) ;\
        (cd "crust-${t}" ;\
         make clean && \
         make CROSS_COMPILE=or1k-elf- ${defconf} && \
         make CROSS_COMPILE=or1k-elf- -j "$(getconf _NPROCESSORS_ONLN)" ;\
         mv build/scp/scp.bin /crust-blobs/${t}-scp.bin) ;\
    done

# Build u-boot
# hadolint ignore=DL3003,SC2086
RUN for t in ${BSP_TARGETS}; do \
        defconf=$(eval echo \$UBOOT_DEFCONF_${t}) ;\
        (cd "u-boot-${t}" ;\
         for p in /tmp/patches/"${t}"/u-boot-"$(eval echo \$UBOOT_COMMIT_${t})"/*.patch ; do patch -p1 < "$p" || exit 1 ; done ;\
         make clean && \
         make ${defconf} && \
         make BL31=/atf-blobs/${t}-bl31.bin SCP=/crust-blobs/${t}-scp.bin -j "$(getconf _NPROCESSORS_ONLN)" ;\
         mv $(eval echo \$UBOOT_BLOB_${t}) /bsp/${t}-flash.bin) ;\
    done

# Generate configs
RUN for t in ${BSP_TARGETS}; do \
        echo "# Bootloader offset" > /bsp/${t}-flash.conf ;\
        echo "offset=$(eval echo \$BOOT_OFFSET_${t})" >> /bsp/${t}-flash.conf ;\
    done

# hadolint ignore=DL3006
FROM build-${TARGETARCH} AS bsp-sunxi-build

FROM scratch
ENTRYPOINT []
CMD []
COPY --from=bsp-sunxi-build /bsp /bsp-sunxi
