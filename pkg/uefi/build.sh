#!/bin/bash

TARGET=RELEASE

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
    aarch64) build -b ${TARGET} -t GCC5 -a AARCH64 -p ArmVirtPkg/ArmVirtQemu.dsc -D TPM2_ENABLE=TRUE -D TPM2_CONFIG_ENABLE=TRUE
             cp Build/ArmVirtQemu-AARCH64/${TARGET}_GCC5/FV/QEMU_EFI.fd OVMF.fd
             cp Build/ArmVirtQemu-AARCH64/${TARGET}_GCC5/FV/QEMU_VARS.fd OVMF_VARS.fd
             # now let's build PVH UEFI kernel
             make -C BaseTools/Source/C
             build -b ${TARGET} -t GCC5 -a AARCH64  -p ArmVirtPkg/ArmVirtXen.dsc
             cp Build/ArmVirtXen-AARCH64/${TARGET}_*/FV/XEN_EFI.fd OVMF_PVH.fd
             ;;
     x86_64) build -b ${TARGET} -t GCC5 -a X64 -p OvmfPkg/OvmfPkgX64.dsc -D TPM_ENABLE=TRUE -D TPM_CONFIG_ENABLE=TRUE
             cp Build/OvmfX64/${TARGET}_*/FV/OVMF*.fd .
             build -b ${TARGET} -t GCC5 -a X64 -p OvmfPkg/OvmfXen.dsc
             BaseTools/Source/C/bin/EfiRom -f 0x1F96 -i 0x0778 -e Build/OvmfX64/${TARGET}_*/X64/IgdAssignmentDxe.efi
             cp Build/OvmfX64/${TARGET}_*/X64/IgdAssignmentDxe.rom IgdAssignmentDxe.rom
             cp Build/OvmfXen/${TARGET}_*/FV/OVMF.fd OVMF_PVH.fd
             ;;
          *) echo "Unsupported architecture $(uname). Bailing."
             exit 1
             ;;
esac
