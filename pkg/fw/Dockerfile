FROM lfedge/eve-alpine:9fb9b9cbf7d90066a70e4704d04a6fe248ff52bb as build

ENV BUILD_PKGS tar make
RUN eve-alpine-deploy.sh

ENV WIRELESS_REGDB_VERSION 2022.06.06
ENV WIRELESS_REGDB_REPO https://mirrors.edge.kernel.org/pub/software/network/wireless-regdb/wireless-regdb
ADD ${WIRELESS_REGDB_REPO}-${WIRELESS_REGDB_VERSION}.tar.gz /wireless-regdb.tar.gz
RUN mkdir /wireless-regdb &&\
    tar -xz --strip-components=1 -C /wireless-regdb -f /wireless-regdb.tar.gz &&\
    cp /wireless-regdb/regulatory.db /wireless-regdb/regulatory.db.p7s /lib/firmware

ENV LINUX_FIRMWARE_VERSION 20220708
ENV LINUX_FIRMWARE_URL https://git.kernel.org/pub/scm/linux/kernel/git/firmware/linux-firmware.git/snapshot/linux-firmware
ADD ${LINUX_FIRMWARE_URL}-${LINUX_FIRMWARE_VERSION}.tar.gz /linux-firmware.tar.gz
RUN mkdir /linux-firmware &&\
    tar -xz --strip-components=1 -C /linux-firmware -f /linux-firmware.tar.gz &&\
    make -C /linux-firmware FIRMWAREDIR="/lib/firmware" install

# patch merged, but not released, remove this when update LINUX_FIRMWARE_VERSION
RUN rm /lib/firmware/brcm/brcmfmac43455-sdio.AW-CM256SM.txt &&\
    cp /linux-firmware/brcm/brcmfmac43455-sdio.AW-CM256SM.txt /lib/firmware/brcm &&\
    ln -s brcmfmac43455-sdio.AW-CM256SM.txt /lib/firmware/brcm/brcmfmac43455-sdio.beagle,am5729-beagleboneai.txt &&\
    ln -s brcmfmac43455-sdio.AW-CM256SM.txt /lib/firmware/brcm/brcmfmac43455-sdio.pine64,pinebook-pro.txt &&\
    ln -s brcmfmac43455-sdio.AW-CM256SM.txt /lib/firmware/brcm/brcmfmac43455-sdio.pine64,pinephone-pro.txt &&\
    ln -s brcmfmac43455-sdio.AW-CM256SM.txt /lib/firmware/brcm/brcmfmac43455-sdio.pine64,quartz64-b.txt
# add compat links for pre-5.0 kernel
RUN ln -s brcmfmac43455-sdio.raspberrypi,3-model-b-plus.txt /lib/firmware/brcm/brcmfmac43455-sdio.txt &&\
    ln -s brcmfmac43430-sdio.raspberrypi,3-model-b.txt /lib/firmware/brcm/brcmfmac43430-sdio.txt
# symlinks for Visionfive1 riscv64 boards
RUN ln -s ../cypress/cyfmac43430-sdio.bin /lib/firmware/brcm/brcmfmac43430-sdio.starfive,visionfive-v1.bin

ENV RPI_FIRMWARE_VERSION 2c8f665254899a52260788dd902083bb57a99738
ENV RPI_FIRMWARE_URL https://github.com/RPi-Distro/firmware-nonfree/archive
ADD ${RPI_FIRMWARE_URL}/${RPI_FIRMWARE_VERSION}.tar.gz /rpifirmware.tar.gz
RUN mkdir /rpi-firmware &&\
    tar -xz --strip-components=1 -C /rpi-firmware -f /rpifirmware.tar.gz &&\
    cp -a /rpi-firmware/debian/config/brcm80211/brcm/brcmfmac43436* /lib/firmware/brcm

ENV RPI_BT_FIRMWARE_VERSION e7fd166981ab4bb9a36c2d1500205a078a35714d
ENV RPI_BT_FIRMWARE_URL https://github.com/RPi-Distro/bluez-firmware/raw

WORKDIR /lib/firmware/brcm
ADD ${RPI_BT_FIRMWARE_URL}/${RPI_BT_FIRMWARE_VERSION}/broadcom/BCM43430A1.hcd .
ADD ${RPI_BT_FIRMWARE_URL}/${RPI_BT_FIRMWARE_VERSION}/broadcom/BCM4345C0.hcd .
ADD ${RPI_BT_FIRMWARE_URL}/${RPI_BT_FIRMWARE_VERSION}/broadcom/BCM43430B0.hcd .
ADD ${RPI_BT_FIRMWARE_URL}/${RPI_BT_FIRMWARE_VERSION}/broadcom/BCM4345C5.hcd .

FROM lfedge/eve-alpine:9fb9b9cbf7d90066a70e4704d04a6fe248ff52bb as compactor
ENTRYPOINT []
WORKDIR /
COPY --from=build /lib/firmware/regulatory* /lib/firmware/
COPY --from=build /lib/firmware/bnx2x/* /lib/firmware/bnx2x/
COPY --from=build /lib/firmware/mrvl/*.bin /lib/firmware/mrvl/
COPY --from=build /lib/firmware/rt2870.bin /lib/firmware/rt2870.bin
COPY --from=build /lib/firmware/rtlwifi/*.bin /lib/firmware/rtlwifi/
COPY --from=build /lib/firmware/iwlwifi-3168* /lib/firmware/
COPY --from=build /lib/firmware/iwlwifi-8265* /lib/firmware/
COPY --from=build /lib/firmware/iwlwifi-7260* /lib/firmware/
COPY --from=build /lib/firmware/iwlwifi-9260* /lib/firmware/
# AX210 160MHZ
COPY --from=build /lib/firmware/iwlwifi-ty-a0-gf-a0-59.ucode /lib/firmware/
COPY --from=build /lib/firmware/intel/ibt-0041-0041* /lib/firmware/intel/
# NVidia Jetson
COPY --from=build /lib/firmware/nvidia/tegra210 /lib/firmware/nvidia/tegra210
# Dell Edge Gateway 300x firmware
COPY --from=build /lib/firmware/rsi* /lib/firmware/rsi/
# Intel Corporation Cannon Point-LP CNVi [Wireless-AC] (rev 30)
COPY --from=build /lib/firmware/iwlwifi-9000-* /lib/firmware/
# Intel Wireless 22000 series (AX200 on NUC9VXQNX)
COPY --from=build /lib/firmware/iwlwifi-cc-a0* /lib/firmware/
# Intel Wireless 22000 series (AX201 on NUC10i7FNH)
COPY --from=build /lib/firmware/iwlwifi-QuZ-a0-hr-b0* /lib/firmware/
# RTL8111/8168/8411 PCI Express Gigabit Ethernet Controller
COPY --from=build /lib/firmware/rtl_nic/* /lib/firmware/rtl_nic/
# Firmware for Raspberry Pi4 and Broadcom wifi
COPY --from=build /lib/firmware/brcm /lib/firmware/brcm
COPY --from=build /lib/firmware/cypress /lib/firmware/cypress
# ath10k firmware
COPY --from=build /lib/firmware/ath10k /lib/firmware/ath10k
# firmware for HiKey
COPY --from=build /lib/firmware/ti-connectivity /lib/firmware/ti-connectivity
# to keep compatibility with the current layout
RUN cp --symbolic-link /lib/firmware/brcm/* /lib/firmware

FROM scratch
ENTRYPOINT []
WORKDIR /

COPY --from=compactor /lib/firmware /lib/firmware
