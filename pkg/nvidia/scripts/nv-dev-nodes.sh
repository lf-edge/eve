#!/bin/sh

# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

# Create NVIDIA device nodes
case "$1" in
nvidia_uvm)
    major=$(awk '$2 == "nvidia-uvm" {print $1}' /proc/devices)
    [ -n "$major" ] || exit 1
    rm -f /dev/nvidia-uvm /dev/nvidia-uvm-tools
    mknod -m 660 /dev/nvidia-uvm c "$major" 0
    mknod -m 660 /dev/nvidia-uvm-tools c "$major" 1
    ;;
esac

