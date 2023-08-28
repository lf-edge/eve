#!/bin/bash

verification_dir="$1"
img="$1/verification.raw"
ip="$2"

if [ "$verification_dir" == "" ] || [ "$ip" == "" ]; then
  echo "Usage ./publish_verification_info.sh <verification_dir> <server_ip>"
  exit
fi

size=$(fdisk -l "$img" | grep raw5 | awk '{print $2}')
mkdir /tmp/verification_mnt
sudo mount -o offset=$((size*512)) "$img" /tmp/verification_mnt

dirname=$(cat /tmp/verification_mnt/*/hardwaremodel.txt | grep "Product Name:" | awk '{ for (i = 3; i <= NF; i++) printf "%s", $i; printf "\n" }' | tr ',' '-' | tr '(' '-' | tr ')' '-' | tr '+' '-')
eve_version=$(cat "${verification_dir}/verification/eve_version")
dirname="${dirname}###${eve_version}"

mkdir "$dirname"
cp -r /tmp/verification_mnt/*/* "$dirname/"
tar xvf "${dirname}/hw.info.txz" -C "$dirname"
rm "$dirname/hw.info.txz"

fname="${dirname}.tar.gz"
tar zcvf "${fname}" "$dirname"
rm -rf "$dirname"

CSRF_TOKEN=$(curl -s -c cookies.txt "http://$ip:8999/upload" | xmllint --html --xpath 'string(//input[@name="csrfmiddlewaretoken"]/@value)' - 2>/dev/null)
curl -X POST -b cookies.txt -F "csrfmiddlewaretoken=$CSRF_TOKEN" -F  "file=@${fname}" "http://$ip:8999/upload"

rm cookies.txt "${fname}"
sudo umount /tmp/verification_mnt
rmdir /tmp/verification_mnt
