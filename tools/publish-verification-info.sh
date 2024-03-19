#!/bin/bash

img="$1"
url="$2"

if [ "$img" == "" ] || [ "$url" == "" ] || [ "$EUID" -ne 0 ]; then
  echo "Usage sudo ./publish-verification-info.sh <USB_device_name|verification_img> <server_url>"
  echo "E.g., sudo ./publish-verification-info.sh /dev/disk4 https://somewhere.example.com:8999"
  echo "Or, sudo ./publish-verification-info.sh dist/amd64/current/verification.raw https://somewhere.example.com:8999"
  exit
fi

checkOScmd=$(echo "${OSTYPE}" | grep darwin) # Running on MacOS
mountDir="/tmp/verification_mnt"
if [ -n "${checkOScmd}" ];  then # MacOS
  devicename="${img}"
  if [ -f "${img}" ]; then # file
    tmp=$(/usr/bin/hdiutil attach -imagekey diskimage-class=CRawDiskImage -nomount "${img}")
    devicename=$(echo "${tmp}" | grep "GUID_partition_scheme" | awk '{print $1}')
  fi
  /usr/sbin/diskutil mount "${devicename}"s5
  mountDir="/Volumes/INVENTORY/"
else # Linux
  mkdir "${mountDir}"
  if [ -f "${img}" ]; then # file
    size=$(fdisk -l "$img" | grep raw5 | awk '{print $2}')
    mount -o offset=$((size*512)) "$img" "${mountDir}"
  else # block device
    mount "${img}"5 "${mountDir}"
  fi
fi

dirname=$(cat "${mountDir}/"*/summary.log | grep "Model:" | awk '{ for (i = 2; i < NF; i++) printf "%s-", $i; printf "%s", $i }' | tr -d ',()+\n\r')
eve_version=$(cat "${mountDir}"/*"/eve-release")
dirname="${dirname}###${eve_version}"

echo "${dirname}"

mkdir "${dirname}"
cp -r "${mountDir}"/*/* "${dirname}/"
tar xvf "${dirname}/hw.info.txz" -C "${dirname}"
rm "${dirname}/hw.info.txz"

fname="${dirname}.tar.gz"
tar zcvf "${fname}" "${dirname}"
rm -rf "${dirname}"

CSRF_TOKEN=$(curl -s -c cookies.txt "$url/upload" | xmllint --html --xpath 'string(//input[@name="csrfmiddlewaretoken"]/@value)' - 2>/dev/null)
curl -e "$url" -X POST -b cookies.txt -F "csrfmiddlewaretoken=$CSRF_TOKEN" -F  "file=@${fname}" "$url/upload"

rm cookies.txt "${fname}"
if [ -n "${checkOScmd}" ]; then # MacOS
  /usr/sbin/diskutil umount "${devicename}"s5
  if [ -f "${img}" ]; then # file
    /usr/bin/hdiutil detach "${devicename}"
  fi
else # Linux
  umount "${mountDir}"
  rmdir "${mountDir}"
fi
