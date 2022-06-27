FROM alpine:edge as build

# hadolint ignore=DL3018
RUN apk add --no-cache \
    wireless-regdb \
    linux-firmware-bnx2x \
    linux-firmware-other \
    linux-firmware-ath10k \
    linux-firmware-mrvl \
    linux-firmware-rtlwifi \
    linux-firmware-rsi \
    linux-firmware-nvidia \
    linux-firmware-rtl_nic \
    linux-firmware-brcm \
    linux-firmware-ti-connectivity

FROM busybox as compactor
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
COPY --from=build /lib/firmware/iwlwifi-ty-a0-gf-a0-62.ucode /lib/firmware/
COPY --from=build /lib/firmware/iwlwifi-ty-a0-gf-a0.pnvm /lib/firmware/
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
