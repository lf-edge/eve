#!/bin/sh
# Note: Can't use wpa_supplicant without WPA; have to disable it then e.g.,
# iwconfig wlan0 essid "ietf-hotel"

# FIXME: workaround for mlan0 driver of Advantech
(ip link set mlan0 down ; ip link set mlan0 name wlan0) || /bin/true

ip link set wlan0 up
filetime=0
wpaproc="wpa_supplicant"
configdir=/run/wlan
configfile=/run/wlan/wpa_supplicant.conf
if [ -d "$configdir" ] && [ -f "$configfile" ]; then
  filetime=$(stat -c %Y "$configfile")
  wpa_supplicant -Dwext -iwlan0 -c "$configfile" -d -B
fi
while true ; do
  sleep 10
  if [ -d "$configdir" ] && [ -f /run/wlan/wpa_supplicant.conf ]; then
    newfiletime=$(stat -c %Y "$configfile")
    if [ "${newfiletime}" -ne "${filetime}" ]; then
      filetime=$newfiletime
      if [ -z "$(pgrep -x "wpa_supplicant")" ]; then
        wpa_supplicant -Dwext -iwlan0 -c "$configfile" -d -B
      else
        killall -s HUP $wpaproc
      fi
    fi
  fi
done
