#!/bin/sh
# Note: Can't use wpa_supplicant without WPA; have to disable it then e.g.,
# iwconfig wlan0 essid "ietf-hotel"
ip link set wlan0 up
while true ; do
  wpa_supplicant -Dwext -iwlan0 -c /etc/wpa_supplicant/wpa_supplicant.conf -d
  sleep 10
done
