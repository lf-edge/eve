#!/bin/bash

make -C BaseTools

# shellcheck disable=SC1091
. edksetup.sh

set -e

case $(uname -m) in
    riscv64) make -C /opensbi -j "$(nproc)" PLATFORM=generic
             cp /opensbi/build/platform/generic/firmware/fw_payload.elf OVMF_CODE.fd
             cp /opensbi/build/platform/generic/firmware/fw_payload.bin OVMF_VARS.fd
             cp /opensbi/build/platform/generic/firmware/fw_jump.bin OVMF.fd
             ;;
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
             BaseTools/Source/C/bin/EfiRom -f 0x1F96 -i 0x0778 -e Build/OvmfX64/RELEASE_*/X64/IgdAssignmentDxe.efi
             cp Build/OvmfX64/RELEASE_*/X64/IgdAssignmentDxe.rom IgdAssignmentDxe.rom
             cp Build/OvmfXen/RELEASE_*/FV/OVMF.fd OVMF_PVH.fd
             ;;
          *) echo "Unsupported architecture $(uname). Bailing."
             exit 1
             ;;
esac
