#!/bin/bash

img="$1"
url="$2"

if [ "$img" == "" ] || [ "$url" == "" ]; then
  echo "Usage ./publish_verification_info.sh <USB_device_name|verification_img> <server_url>"
  echo "E.g., ./publish_verification_info.sh /dev/disk4 https://somewhere.example.com:8999"
  echo "Or, ./publish_verification_info.sh dist/amd64/current/verification.img https://somewhere.example.com:8999"
  exit
fi

checkOScmd="echo ${OSTYPE} | grep -q darwin" # Running on MacOS
checkVerificationImg="eval file ${img} | grep -q DOS/MBR" # this is a file not a block device
mountDir="/tmp/verification_mnt"
if eval "${checkOScmd}"; then # MacOS
  devicename="${img}"
  if eval "${checkVerificationImg}"; then # file
    tmp=$(/usr/bin/hdiutil attach -imagekey diskimage-class=CRawDiskImage -nomount "${img}")
    devicename=$(echo "${tmp}" | grep "GUID_partition_scheme" | awk '{print $1}')
  fi
  /usr/sbin/diskutil mount "${devicename}"s5
  mountDir="/Volumes/INVENTORY/"
else # Linux
  mkdir "${mountDir}"
  if eval "${checkVerificationImg}"; then # file
    size=$(fdisk -l "$img" | grep raw5 | awk '{print $2}')
    sudo mount -o offset=$((size*512)) "$img" "${mountDir}"
  else # block device
    sudo mount "${img}"5 "${mountDir}"
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
curl -X POST -b cookies.txt -F "csrfmiddlewaretoken=$CSRF_TOKEN" -F  "file=@${fname}" "$url/upload"

rm cookies.txt "${fname}"
if eval "${checkOScmd}"; then # MacOS
  /usr/sbin/diskutil umount "${devicename}"s5
  if eval "${checkVerificationImg}"; then # file
    /usr/bin/hdiutil detach "${devicename}"
  fi
else # Linux
  sudo umount "${mountDir}"
  rmdir "${mountDir}"
fi
