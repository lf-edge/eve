# syntax=docker/dockerfile-upstream:1.5.0-rc2-labs
FROM lfedge/eve-alpine:8e3ddd8016f778932e9c204a3ec195ed74d1600a as build-base
RUN mkdir /bsp

FROM build-base AS build-amd64
FROM build-base AS build-riscv64
FROM build-base AS build-arm64
ENV BUILD_PKGS bash binutils-dev build-base bc bison flex openssl-dev util-linux-dev swig gnutls-dev perl python3 python3-dev py3-setuptools py3-pycryptodome py3-elftools
RUN eve-alpine-deploy.sh

SHELL ["/bin/bash", "-eo", "pipefail", "-c"]

ENV UBOOT_TARGETS "imx8mq_evk imx8mp_pollux"
ENV ATF_TARGETS "imx8mq_evk imx8mp_pollux"

RUN mkdir /uboot-firmwares

# ATF
WORKDIR /imx-atf
# last commit from imx_5.4.70_2.3.0 branch
ENV ATF_COMMIT_imx8mq_evk 15e8ff164a8becfddb76cba2c68eeeae684cb398
ENV ATF_imx8mq_evk "imx8mq"
# revision used by phytec's yocto bsp: lf-5.10.72-2.2.0
ENV ATF_COMMIT_imx8mp_pollux 5782363f92a2fdf926784449270433cf3ddf44bd
ENV ATF_imx8mp_pollux "imx8mp"
ADD https://github.com/nxp-imx/imx-atf.git#${ATF_COMMIT_imx8mq_evk} ${ATF_imx8mq_evk}/
ADD https://github.com/nxp-imx/imx-atf.git#${ATF_COMMIT_imx8mp_pollux} ${ATF_imx8mp_pollux}/
# hadolint ignore=DL3003,SC2086
RUN for t in ${ATF_TARGETS}; do \
        target=$(eval echo \$ATF_${t}) ;\
        (cd ${target} ;\
         make clean && \
         make -j "$(getconf _NPROCESSORS_ONLN)" \
            IMX_BOOT_UART_BASE="0x30860000" \
            PLAT=${target} \
            bl31 ;\
         mv build/${target}/release/bl31.bin /uboot-firmwares/${target}-bl31.bin) ;\
    done

# IMX firmware
WORKDIR /tmp
ENV FIRMWARE_VER=8.18
ADD https://www.nxp.com/lgfiles/NMG/MAD/YOCTO/firmware-imx-${FIRMWARE_VER}.bin firmware-imx-${FIRMWARE_VER}.bin
RUN chmod 777 firmware-imx-${FIRMWARE_VER}.bin && \
        echo "n" | ./firmware-imx-8.18.bin | head -n -1 > /bsp/NXP-EULA-LICENSE.txt || true && \
        ./firmware-imx-${FIRMWARE_VER}.bin --auto-accept && \
        rm firmware-imx-${FIRMWARE_VER}.bin && \
        mv firmware-imx-${FIRMWARE_VER}/firmware /firmware

# Copy all the necessary firmware for u-boot
ENV DDR_FIRMWARE "ddr/synopsys/lpddr4_pmu_train_1d_imem.bin \
 ddr/synopsys/lpddr4_pmu_train_1d_dmem.bin \
 ddr/synopsys/lpddr4_pmu_train_2d_imem.bin \
 ddr/synopsys/lpddr4_pmu_train_2d_dmem.bin \
 ddr/synopsys/lpddr4_pmu_train_1d_imem_202006.bin \
 ddr/synopsys/lpddr4_pmu_train_1d_dmem_202006.bin \
 ddr/synopsys/lpddr4_pmu_train_2d_imem_202006.bin \
 ddr/synopsys/lpddr4_pmu_train_2d_dmem_202006.bin \
"
ENV VIDEO_FIRMWARE "hdmi/cadence/signed_hdmi_imx8m.bin"
RUN for firmware_file in ${DDR_FIRMWARE} ${VIDEO_FIRMWARE}; do \
        cp /firmware/${firmware_file} /uboot-firmwares ;\
    done


ENV UBOOT_VERSION lf_v2022.04
ENV UBOOT_COMMIT 181859317bfafef1da79c59a4498650168ad9df6
WORKDIR /u-boot-imx
ADD https://github.com/nxp-imx/uboot-imx.git#${UBOOT_COMMIT} .
RUN mv /uboot-firmwares/* .

COPY patches /tmp/patches
RUN for p in /tmp/patches/uboot-patches-"${UBOOT_VERSION}"/*.patch ; do patch -p1 < "$p" || exit 1 ; done

# Define atf target and files for imx8mq_evk board
ENV UBOOT_FILES_imx8mq_evk "flash.bin"
ENV UBOOT_CONFIG_imx8mq_evk "imx8mq_evk"
ENV FLASH_OFFSET_imx8mq_evk "33"
ENV UBOOT_FILES_imx8mp_pollux "flash.bin"
ENV UBOOT_CONFIG_imx8mp_pollux "phycore-imx8mp"
ENV UBOOT_DTB_imx8mp_pollux "arch/arm/dts/imx8mp-phyboard-pollux-rdk.dtb"
ENV FLASH_OFFSET_imx8mp_pollux "32"
# hadolint ignore=DL3059,SC2086
RUN for target in ${UBOOT_TARGETS}; do \
        make clean && rm -rf bl31.bin && \
        cp "$(eval echo \$ATF_"${target}")"-bl31.bin bl31.bin && \
        make "$(eval echo \$UBOOT_CONFIG_${target})"_defconfig && \
        make -j "$(getconf _NPROCESSORS_ONLN)" ;\
        for file in "$(eval echo \$UBOOT_FILES_"${target}")"; do \
            cp $file /bsp/${target}-${file} ;\
        done;\
        offset=$(eval echo \$FLASH_OFFSET_${target}) ;\
        echo "# Bootloader offset" > /bsp/${target}-flash.conf ;\
        echo "offset=${offset}" >> /bsp/${target}-flash.conf ;\
        udtb=$(eval echo \$UBOOT_DTB_"${target}") ;\
        [ -f "$udtb" ] && cp $udtb /bsp/ ;\
    done

# hadolint ignore=DL3006
FROM build-${TARGETARCH} AS bsp-imx-build

FROM scratch
ENTRYPOINT []
CMD []
COPY --from=bsp-imx-build /bsp /bsp-imx
