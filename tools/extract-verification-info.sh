#!/bin/bash

img=$1

if [ "$img" == "" ] || [ "$EUID" -ne 0 ]; then
  echo "Usage sudo ./extract-verification-info.sh <USB_device_name|verification_img>"
  echo "E.g., sudo ./extract-verification-info.sh /dev/disk4"
  echo "Or, sudo ./extract-verification-info.sh dist/amd64/current/verification.raw"
  exit
fi

checkOScmd=$(echo "${OSTYPE}" | grep darwin) # Running on MacOS
mountDir="/tmp/verification_mnt"
if [ -n "${checkOScmd}" ]; then # MacOS
  devicename="${img}"
  if [ -f "${img}" ]; then # file
    tmp=$(/usr/bin/hdiutil attach -imagekey diskimage-class=CRawDiskImage -nomount "${img}")
    devicename=$(echo "${tmp}" | grep "GUID_partition_scheme" | awk '{print $1}')
  fi
  /usr/sbin/diskutil mount "${devicename}"s5
  mountDir="/Volumes/INVENTORY"
else # Linux
  mkdir "${mountDir}"
  if [ -f "${img}" ]; then # file
    size=$(fdisk -l "$img" | grep raw5 | awk '{print $2}')
    mount -o offset=$((size*512)) "$img" "${mountDir}"
  else # block device
    mount "${img}"5 "${mountDir}"
  fi
fi

cp -r ${mountDir}/* ./
cat ${mountDir}/*/summary.log

if [ -n "${checkOScmd}" ]; then # MacOS
  /usr/sbin/diskutil umount "${devicename}"s5
  if [ -f "${img}" ]; then # file
    /usr/bin/hdiutil detach "${devicename}"
  fi
else # Linux
  umount "${mountDir}"
  rmdir "${mountDir}"
fi
