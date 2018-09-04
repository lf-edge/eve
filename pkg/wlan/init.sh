#!/bin/sh
# Note: Can't use wpa_supplicant without WPA; have to disable it then e.g.,
# iwconfig wlan0 essid "ietf-hotel"

# FIXME: workaround for mlan0 driver of Advantech
(ip link set mlan0 down ; ip link set mlan0 name wlan0) || /bin/true

ip link set wlan0 up
while true ; do
  [ -f /config/wpa_supplicant.conf ] && wpa_supplicant -Dwext -iwlan0 -c /config/wpa_supplicant.conf -d
  sleep 10
done
