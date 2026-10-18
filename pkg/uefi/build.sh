#!/bin/bash

# Flip to DEBUG to layer the VfioIgdPkg diagnostic patches under
# /vfioigd-debug-patches/ + the matching DSC PCD/HobLib mods below.
# RELEASE skips both.
TARGET=RELEASE

# Debug knob: override OVMF's PcdPlatformBootTimeOut (in seconds).
# Stock value is 0, which makes the UEFI splash / boot-menu phase
# flash by in well under 100 ms — imperceptible on monitors that take
# a moment to wake after the first EDID handshake.  Bump to e.g. 5
# when diagnosing GOP / display paths so the boot menu stays visible
# long enough to confirm which physical output is receiving UEFI
# console frames.  Revert to 0 before shipping — a non-zero value
# delays every boot by that many seconds and exposes a boot menu to
# anyone with a keyboard attached.
UEFI_BOOT_TIMEOUT=${UEFI_BOOT_TIMEOUT:-0}

# EXTRA_OPTFLAGS is appended last to the BaseTools CFLAGS: the host tools
# are built with -Werror, which newer gcc releases keep tripping over.
# Fail here rather than later with "BaseTools C Tool binary was not found".
make -C BaseTools -j "$(nproc)" EXTRA_OPTFLAGS=-Wno-error || exit 1
OVMF_COMMON_FLAGS="-DNETWORK_TLS_ENABLE"
OVMF_COMMON_FLAGS+=" -DSECURE_BOOT_ENABLE=TRUE"
OVMF_COMMON_FLAGS+=" -DTPM2_CONFIG_ENABLE=TRUE"
OVMF_COMMON_FLAGS+=" -DTPM2_ENABLE=TRUE"
OVMF_COMMON_FLAGS+=" -DFD_SIZE_4MB"

if [ "${UEFI_BOOT_TIMEOUT}" != "0" ]; then
    # Patch the DSC directly.  `build --pcd` is unreliable for
    # DynamicDefault PCDs across EDK2 versions and silently no-ops
    # when the type / syntax does not match exactly; sed-in-place is
    # crude but guaranteed.  Anchored to the exact stock-value line so
    # we no-op if someone has already changed PcdPlatformBootTimeOut
    # away from the default.
    sed -i -E "s@^([[:space:]]*gEfiMdePkgTokenSpaceGuid\.PcdPlatformBootTimeOut)\|0[[:space:]]*\$@\1|${UEFI_BOOT_TIMEOUT}@" \
        OvmfPkg/OvmfPkgX64.dsc
    echo "UEFI_BOOT_TIMEOUT=${UEFI_BOOT_TIMEOUT} applied; DSC now reads:"
    grep "PcdPlatformBootTimeOut" OvmfPkg/OvmfPkgX64.dsc
fi

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
             make -C BaseTools/Source/C -j "$(nproc)" EXTRA_OPTFLAGS=-Wno-error
             build -b ${TARGET} -t GCC5 -a AARCH64 -n "$(nproc)" -p ArmVirtPkg/ArmVirtXen.dsc
             cp Build/ArmVirtXen-AARCH64/${TARGET}_*/FV/XEN_EFI.fd OVMF_PVH.fd
             ;;
     x86_64) build -b ${TARGET} -t GCC5 -a X64 -n "$(nproc)" -p OvmfPkg/OvmfPkgX64.dsc ${OVMF_COMMON_FLAGS}
             cp Build/OvmfX64/${TARGET}_*/FV/OVMF*.fd .
             build -b ${TARGET} -t GCC5 -a X64 -n "$(nproc)" -p OvmfPkg/OvmfXen.dsc
             cp Build/OvmfXen/${TARGET}_*/FV/OVMF.fd OVMF_PVH.fd
             # When UEFI_TARGET=DEBUG: layer the diagnostic patches and
             # adjust the VfioIgdPkg DSC.  RELEASE builds skip this
             # entire block so production images carry no trace code.
             #
             # The DSC mods are:
             #   - PcdDebugPropertyMask=0x0F   PRINT + ASSERT + CODE +
             #                                  CLEAR_MEMORY enabled, but
             #                                  NOT ASSERT_DEADLOOP — so
             #                                  asserts print and continue
             #                                  rather than halting the
             #                                  DXE phase (BaseHobLibNull
             #                                  asserts on every call;
             #                                  HobLib swap below makes
             #                                  most of those go away,
             #                                  but anything else that
             #                                  asserts shouldn't brick
             #                                  the boot).
             #   - PcdFixedDebugPrintErrorLevel=0x804F004F   matches what
             #                                  OvmfPkg uses for its own
             #                                  DEBUG builds.
             #   - HobLib swap: replace BaseHobLibNull (a stub where every
             #                  call ASSERTs) with the real DxeHobLib so
             #                  QemuFwCfgDxeLib's HOB lookups work.
             #                  Pulls in UefiLib + DevicePathLib.
             #
             # All sed mods are guarded by grep so reruns are idempotent.
             if [ "${TARGET}" = "DEBUG" ] && [ -d /vfioigd-debug-patches ] ; then
                 for patch in /vfioigd-debug-patches/*.patch ; do
                     echo "Applying $patch (DEBUG-only)"
                     git -C /edk2/VfioIgdPkg apply -p1 < "$patch" || exit 1
                 done
                 if ! grep -q PcdFixedDebugPrintErrorLevel VfioIgdPkg/VfioIgdPkg.dsc ; then
                     sed -i 's#^\[Components\]#[PcdsFixedAtBuild]\n  gEfiMdePkgTokenSpaceGuid.PcdDebugPropertyMask|0x0F\n  gEfiMdePkgTokenSpaceGuid.PcdFixedDebugPrintErrorLevel|0x804F004F\n\n[Components]#' VfioIgdPkg/VfioIgdPkg.dsc
                 fi
                 if grep -q 'HobLib|MdeModulePkg/Library/BaseHobLibNull/BaseHobLibNull.inf' VfioIgdPkg/VfioIgdPkg.dsc ; then
                     sed -i 's#^\(\s*HobLib\)|MdeModulePkg/Library/BaseHobLibNull/BaseHobLibNull.inf#\1|MdePkg/Library/DxeHobLib/DxeHobLib.inf\n  UefiLib|MdePkg/Library/UefiLib/UefiLib.inf\n  DevicePathLib|MdePkg/Library/UefiDevicePathLib/UefiDevicePathLib.inf#' VfioIgdPkg/VfioIgdPkg.dsc
                 fi
                 echo "VfioIgdPkg DEBUG mods applied:"
                 grep -E 'HobLib|UefiLib|DevicePathLib|PcdsFixedAtBuild|PcdDebugPropertyMask' VfioIgdPkg/VfioIgdPkg.dsc | head
             fi

             # Build VfioIgdPkg open-source IGD option-ROM (IgdAssignmentDxe).
             # Wrap as a multi-image PCI option-ROM with EfiRom.  PCIR
             # vendor 0x8086, device 0xffff (wildcard — applies to any
             # Intel iGPU; the per-device match is done by IgdAssignmentDxe
             # itself based on PCI class + vendor).
             build -b ${TARGET} -t GCC5 -a X64 -n "$(nproc)" -p VfioIgdPkg/VfioIgdPkg.dsc
             EfiRom -f 0x8086 -i 0xffff \
                 -e Build/VfioIgdPkg/${TARGET}_GCC5/X64/IgdAssignmentDxe.efi \
                 -o igd.rom
             ;;
          *) echo "Unsupported architecture $(uname). Bailing."
             exit 1
             ;;
esac
