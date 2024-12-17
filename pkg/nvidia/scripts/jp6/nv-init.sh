#!/bin/sh

# Copyright (c) 2025 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

VENDOR="/opt/vendor/nvidia"
FANCTRL="${VENDOR}/bin/nvfanctrl"

# This script is executed from pillar, so we need to export the variables
# below to execute udevadm from hostfs
export PATH="$PATH:/hostfs/bin"
export LD_LIBRARY_PATH="/hostfs/lib"

# Setup modules and devices
modprobe nvidia
modprobe nvidia_modeset
modprobe nvhost_capture
modprobe nvhost_isp5
modprobe nvhost_nvcsi_t194
modprobe nvhost_nvdla
modprobe nvhost_pva
modprobe nvhost_vi5
modprobe nvethernet
modprobe nvpps
modprobe nvvrs_pseq_rtc
modprobe nvidia_p2p
modprobe nv_imx219
modprobe tegra_drm
modprobe tegra_wmark
modprobe tegra210_adma
modprobe tegra_se
modprobe ina3221
modprobe r8168
modprobe governor_pod_scaling

mkdir -p /dev/dri/by-path

# Setup udev rules
mkdir -p /run/udev/rules.d/
cp "${VENDOR}"/etc/udev/rules.d/* /run/udev/rules.d/
# Reload rules and trigger udev events
udevadm control --reload
udevadm info -a -p /devices/platform/gpu.0

# Enforces add for framebuffer and nvidia modules, so we have /dev/fb0 and
# /dev/nvidiactrl even when there is no monitor connected to the display
# port. These devices must be present because they are on the CDI spec.
echo "add" > /sys/module/fb/uevent 2> /dev/null
echo "add" > /sys/module/nvidia/uevent 2> /dev/null
echo "add" > /sys/module/nvidia_modeset/uevent 2> /dev/null
echo "add" > /sys/class/rtc/rtc1/uevent
echo "bind" > /sys/bus/platform/devices/15480000.nvdec/uevent 2> /dev/null

# Start FAN controller detached from terminal
if [ -f "$FANCTRL" ]; then
    "$FANCTRL" -m quiet > /dev/kmsg 2>&1 &
fi
