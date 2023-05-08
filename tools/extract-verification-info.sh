#!/bin/bash

img=$1

if [ "$img" == "" ]; then
  echo "Usage ./extract_verification_info.sh <verification.img>"
  exit
fi

size=$(fdisk -l "$img" | grep raw5 | awk '{print $2}')
mkdir /tmp/verification_mnt
sudo mount -o offset=$((size*512)) "$img" /tmp/verification_mnt
cp /tmp/verification_mnt/*/summary.log ./
cat /tmp/verification_mnt/*/summary.log
sudo umount /tmp/verification_mnt
rmdir /tmp/verification_mnt
