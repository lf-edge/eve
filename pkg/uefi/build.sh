#!/bin/bash

# shellcheck disable=SC1091
. edksetup.sh

set -e
NCPUS=$(getconf _NPROCESSORS_ONLN)

make -j ${NCPUS} -C BaseTools/Source/C

BUILD_TYPE=DEBUG
DEFINES=-DDEBUG_ON_SERIAL_PORT
NCPUS=$(getconf _NPROCESSORS_ONLN)

make -j ${NCPUS} -C BaseTools/Source/C

case $(uname -m) in
    aarch64) build -b ${BUILD_TYPE} -t GCC5 -a AARCH64 -p ArmVirtPkg/ArmVirtQemu.dsc -n ${NCPUS} ${DEFINES}
             cp Build/ArmVirtQemu-AARCH64/${BUILD_TYPE}_GCC5/FV/QEMU_EFI.fd OVMF.fd
             cp Build/ArmVirtQemu-AARCH64/${BUILD_TYPE}_GCC5/FV/QEMU_VARS.fd OVMF_VARS.fd
             # now let's build PVH UEFI kernel
             build -b ${BUILD_TYPE} -t GCC5 -a AARCH64  -p ArmVirtPkg/ArmVirtXen.dsc -n ${NCPUS} ${DEFINES}
             cp Build/ArmVirtXen-AARCH64/${BUILD_TYPE}_*/FV/XEN_EFI.fd OVMF_PVH.fd
             ;;
     x86_64) build -b ${BUILD_TYPE} -t GCC5 -a X64 -p OvmfPkg/OvmfPkgX64.dsc -n ${NCPUS} ${DEFINES}
             cp Build/OvmfX64/${BUILD_TYPE}_*/FV/OVMF*.fd .
             build -b ${BUILD_TYPE} -t GCC5 -a X64 -p OvmfPkg/OvmfXen.dsc -n ${NCPUS} ${DEFINES}
             cp Build/OvmfXen/${BUILD_TYPE}_*/FV/OVMF.fd OVMF_PVH.fd
             ;;
          *) echo "Unsupported architecture $(uname). Bailing."
             exit 1
             ;;
esac
