#!/bin/bash

# shellcheck disable=SC1091
. edksetup.sh

set -e

case $(uname -m) in
    aarch64) build -b RELEASE -t GCC5 -a AARCH64 -p ArmVirtPkg/ArmVirtQemu.dsc
             cp Build/ArmVirtQemu-AARCH64/RELEASE_GCC5/FV/QEMU_EFI.fd OVMF.fd
             cp Build/ArmVirtQemu-AARCH64/RELEASE_GCC5/FV/QEMU_VARS.fd OVMF_VARS.fd
             # now let's build PVH UEFI kernel
             make -C BaseTools/Source/C
             build -b RELEASE -t GCC5 -a AARCH64  -p ArmVirtPkg/ArmVirtXen.dsc
             cp Build/ArmVirtXen-AARCH64/RELEASE_*/FV/XEN_EFI.fd OVMF_PVH.fd
             ;;
     x86_64) build -b RELEASE -t GCC5 -a X64 -p OvmfPkg/OvmfPkgX64.dsc
             cp Build/OvmfX64/RELEASE_*/FV/OVMF*.fd .
             build -b RELEASE -t GCC5 -a X64 -p OvmfPkg/OvmfXen.dsc
             cp Build/OvmfXen/RELEASE_*/FV/OVMF.fd OVMF_PVH.fd
             ;;
          *) echo "Unsupported architecture $(uname). Bailing."
             exit 1
             ;;
esac
