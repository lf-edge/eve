#!/bin/bash

TARGET=RELEASE

make -C BaseTools -j "$(nproc)"
OVMF_COMMON_FLAGS="-DNETWORK_TLS_ENABLE"
OVMF_COMMON_FLAGS+=" -DSECURE_BOOT_ENABLE=TRUE"
OVMF_COMMON_FLAGS+=" -DTPM2_CONFIG_ENABLE=TRUE"
OVMF_COMMON_FLAGS+=" -DTPM2_ENABLE=TRUE"
OVMF_COMMON_FLAGS+=" -DFD_SIZE_4MB"

# shellcheck disable=SC1091
. edksetup.sh

set -e

# shellcheck disable=SC2086
case $(uname -m) in
    riscv64) make -C /opensbi -j "$(nproc)" PLATFORM=generic
             cp /opensbi/build/platform/generic/firmware/fw_payload.elf OVMF_CODE.fd
             cp /opensbi/build/platform/generic/firmware/fw_payload.bin OVMF_VARS.fd
             cp /opensbi/build/platform/generic/firmware/fw_jump.bin OVMF.fd
             ;;
    aarch64) build -b ${TARGET} -t GCC5 -a AARCH64 -n "$(nproc)" -p ArmVirtPkg/ArmVirtQemu.dsc -D TPM2_ENABLE=TRUE -D TPM2_CONFIG_ENABLE=TRUE
             cp Build/ArmVirtQemu-AARCH64/${TARGET}_GCC5/FV/QEMU_EFI.fd OVMF.fd
             cp Build/ArmVirtQemu-AARCH64/${TARGET}_GCC5/FV/QEMU_VARS.fd OVMF_VARS.fd
             # now let's build PVH UEFI kernel
             make -C BaseTools/Source/C -j "$(nproc)"
             build -b ${TARGET} -t GCC5 -a AARCH64 -n "$(nproc)" -p ArmVirtPkg/ArmVirtXen.dsc
             cp Build/ArmVirtXen-AARCH64/${TARGET}_*/FV/XEN_EFI.fd OVMF_PVH.fd
             ;;
     x86_64) build -b ${TARGET} -t GCC5 -a X64 -n "$(nproc)" -p OvmfPkg/OvmfPkgX64.dsc ${OVMF_COMMON_FLAGS}
             cp Build/OvmfX64/${TARGET}_*/FV/OVMF*.fd .
             build -b ${TARGET} -t GCC5 -a X64 -n "$(nproc)" -p OvmfPkg/OvmfXen.dsc
             cp Build/OvmfXen/${TARGET}_*/FV/OVMF.fd OVMF_PVH.fd
             # Build VfioIgdPkg open-source IGD Option ROM (IgdAssignmentDxe only).
             # Handles Gen11+ 64-bit BDSM at PCI config 0xC0, unlike classic IgdAssignmentDxe.
             build -b ${TARGET} -t GCC5 -a X64 -n "$(nproc)" -p VfioIgdPkg/VfioIgdPkg.dsc
             EfiRom -f 0x8086 -i 0xffff \
                 -e Build/VfioIgdPkg/${TARGET}_GCC5/X64/IgdAssignmentDxe.efi \
                 -o igd.rom
             ;;
          *) echo "Unsupported architecture $(uname). Bailing."
             exit 1
             ;;
esac
