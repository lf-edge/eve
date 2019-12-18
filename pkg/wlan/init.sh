#!/bin/sh
# Note: Can't use wpa_supplicant without WPA; have to disable it then e.g.,
# iwconfig wlan0 essid "ietf-hotel"

# FIXME: workaround for mlan0 driver of Advantech
(ip link set mlan0 down ; ip link set mlan0 name wlan0) || /bin/true

ip link set wlan0 up
filetime=0
wpaproc="wpa_supplicant"
if [ -f /config/wpa_supplicant.conf ]; then
  filetime=$(stat -c %Y /config/wpa_supplicant.conf)
  wpa_supplicant -Dwext -iwlan0 -c /config/wpa_supplicant.conf -d -B
fi
while true ; do
  sleep 10
  if [ -f /config/wpa_supplicant.conf ]; then
    newfiletime=$(stat -c %Y /config/wpa_supplicant.conf)
    if [ "${newfiletime}" -ne "${filetime}" ]; then
      filetime=$newfiletime
      if [ -z "$(pgrep -x "wpa_supplicant")" ]; then
        wpa_supplicant -Dwext -iwlan0 -c /config/wpa_supplicant.conf -d -B
      else
        killall -s HUP $wpaproc
      fi
    fi
  fi
done
