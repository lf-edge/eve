#!/bin/sh
set -x

BBS=/run/wwan
# FIXME: we really need to pick the following from some config
WATCHDOG_TIMEOUT=300
LTESTAT_TIMEOUT=60

mkdir $BBS

# uqmi -d /dev/cdc-wdm0 --start-network vzwinternet --autoconnect
# uqmi -d /dev/cdc-wdm0 --get-data-status
# udhcpc -i wwan0
modprobe ppp_async

# poor man's watchdog
while true ; do
  # it would be really usefull to replace the following by a value we pick up from the $BBS
  sleep $WATCHDOG_TIMEOUT
  # it is ok for this file not to be there -- eventually it'll appear and we'll pick it up
  cp -f /var/run/ppp/resolv.conf $BBS/resolv.conf || :
  if ! ping -W 20 -w 20 -c 1 -I ppp0 8.8.8.8 > /dev/null 2>&1 ; then
    # theoretically we could've used SIGHUP here and NOT restart ppp
    kill -9 `cat /var/run/ppp0.pid`
    rm -f /var/lock/LCK..tty*

    rmmod -f qcserial
    rmmod -f qmi_wwan
    modprobe qcserial
    modprobe qmi_wwan

    timeout -t $LTESTAT_TIMEOUT -s KILL uqmi -d /dev/cdc-wdm0 --get-serving-system > $BBS/serving-system.json 2>&1
    timeout -t $LTESTAT_TIMEOUT -s KILL uqmi -d /dev/cdc-wdm0 --get-signal-info > $BBS/signal-info.json 2>&1

    pppd call vzwinternet &
  fi
done
