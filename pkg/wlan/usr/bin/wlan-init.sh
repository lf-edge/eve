#!/bin/sh
ip link set wlan0 up
while true ; do
  wpa_supplicant -Dwext -iwlan0 -c /etc/wpa_supplicant/wpa_supplicant.conf
  sleep 10
done
