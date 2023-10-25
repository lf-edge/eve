#!/bin/sh
# Copyright (c) 2023 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

set -e

echo "Loading kernel modules used by ModemManager"
modprobe -a qcserial usb_wwan qmi_wwan cdc_wdm cdc_mbim cdc_acm
echo "Kernel modules are loaded"

echo "Starting D-Bus daemon"
mkdir -p /var/run/dbus
dbus-daemon --system
echo "D-Bus daemon started"

echo "Starting Udev daemon"
udevd --debug --daemon 2>/dev/null
# Apply installed ModemManager udev rules.
udevadm control --reload
udevadm trigger
echo "Udev daemon started"

echo "Starting Modem Manager"
ModemManager --debug &

echo "Starting Modem Manager Agent"
# Monitor liveness of the agent (and Modem Manager) with watchdog.
mkdir -p /run/watchdog/file
touch /run/watchdog/file/wwan.touch
mmagent
