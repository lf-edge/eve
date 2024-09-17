#!/bin/sh

# Copyright (c) 2024 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

VENDOR="/opt/vendor/nvidia"
FANCTRL="${VENDOR}/bin/nvfanctrl"

# This script is executed from pillar, so we need to export the variables
# below to execute udevadm from hostfs
export PATH="$PATH:/hostfs/bin"
export LD_LIBRARY_PATH="/hostfs/lib"

# Setup udev rules
mkdir -p /run/udev/rules.d/
cp "${VENDOR}"/etc/udev/rules.d/* /run/udev/rules.d/
# Reload rules and trigger udev events
udevadm control --reload
udevadm info -a -p /devices/gpu.0

# Load modules
modprobe nvidia
modprobe nvidia_modeset

# Enforces add for framebuffer and nvidia modules, so we have /dev/fb0 and
# /dev/nvidiactrl even when there is no monitor connected to the display
# port. These devices must be present because they are on the CDI spec.
echo "add" > /sys/module/fb/uevent 2> /dev/null
echo "add" > /sys/module/nvidia/uevent 2> /dev/null

# Start FAN controller detached from terminal
if [ -f "$FANCTRL" ]; then
    "$FANCTRL" -m quiet > /dev/kmsg 2>&1 &
fi
