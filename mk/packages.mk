# Copyright (c) 2025 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Package list definitions for EVE build system.
# This file is included by the main Makefile and defines which packages
# are built for each combination of architecture, hypervisor, and platform.
#
# Input variables (must be set before including this file):
#   ZARCH    - target architecture (amd64, arm64, riscv64)
#   PLATFORM - target platform (generic, nvidia-jp5, rt, imx8mp_pollux, ...)
#   HV       - hypervisor (kvm, xen, k, mini)

# Packages common to all builds.
# NOTE: pkg/alpine is prepended separately in the Makefile as it must be first.
# NOTE: pkg/alpine-base, pkg/eve, and pkg/sources are never part of PKGS.
COMMON_PKGS = \
    pkg/apparmor \
    pkg/bpftrace \
    pkg/cross-compilers \
    pkg/debug \
    pkg/dnsmasq \
    pkg/dom0-ztools \
    pkg/edgeview \
    pkg/fscrypt \
    pkg/fw \
    pkg/gpt-tools \
    pkg/grub \
    pkg/guacd \
    pkg/installer \
    pkg/ipxe \
    pkg/kdump \
    pkg/kexec \
    pkg/measure-config \
    pkg/memory-monitor \
    pkg/mkconf \
    pkg/mkimage-iso-efi \
    pkg/mkimage-raw-efi \
    pkg/mkrootfs-ext4 \
    pkg/mkrootfs-squash \
    pkg/monitor \
    pkg/newlog \
    pkg/node-exporter \
    pkg/pillar \
    pkg/recovertpm \
    pkg/rngd \
    pkg/storage-init \
    pkg/udev \
    pkg/uefi \
    pkg/vector \
    pkg/vtpm \
    pkg/watchdog \
    pkg/wwan \
    pkg/xen \
    pkg/xen-tools

# Architecture-specific packages
ARCH_PKGS_amd64 =
ARCH_PKGS_arm64 = pkg/u-boot
ARCH_PKGS_riscv64 = pkg/u-boot

# Hypervisor-specific packages
HV_PKGS_kvm =
HV_PKGS_xen =
HV_PKGS_mini =
HV_PKGS_k = pkg/kube pkg/external-boot-image

# Platform-specific packages
PLATFORM_PKGS_generic =
PLATFORM_PKGS_rt =
PLATFORM_PKGS_evaluation =
PLATFORM_PKGS_nvidia-jp5 = pkg/nvidia
PLATFORM_PKGS_nvidia-jp6 = pkg/nvidia
PLATFORM_PKGS_imx8mp_pollux = pkg/bsp-imx pkg/optee-os
PLATFORM_PKGS_imx8mp_epc_r3720 = pkg/bsp-imx pkg/optee-os
PLATFORM_PKGS_imx8mq_evk = pkg/bsp-imx pkg/optee-os
