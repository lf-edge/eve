#!/bin/sh
mkdir -p /run/kvm
cp /hostfs/etc/ovmf/eve_efi.img /run/kvm/eve_efi.img
/usr/lib/xen/bin/qemu-system-x86_64 \
    -machine "type=pc-q35-3.1" \
    -drive "if=pflash,unit=0,format=raw,readonly=on,file=/usr/lib/xen/boot/OVMF_CODE.fd" \
    -drive "if=pflash,unit=1,format=raw,readonly=off,file=${1}" \
    -drive "file=/run/kvm/eve_efi.img,format=raw" \
    -smbios "type=11,value=${2}" \
    -net none \
    -nographic