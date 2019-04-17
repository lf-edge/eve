#!/bin/sh
set -x

# Currently our message bus is files in /run
# When we replace it, we should pay attention
# to the notion of the current context which
# is currently expressed as an FS path rooted
# under /run. This makes all rendezvous points 
# be relative path names (either ./ for the ones
# that are local to this service or ../ for the
# global context).
#
# Some inspiration (but not the code!) taken from:
#    https://github.com/openwrt-mirror/openwrt/blob/master/package/network/utils/uqmi/files/lib/netifd/proto/qmi.sh
BBS=/run/wwan

# FIXME: we really need to pick the following from some config
APN=internetd.gdsp
IFACE=wwan0
QMI_DEV=/dev/cdc-wdm0

WATCHDOG_TIMEOUT=300
LTESTAT_TIMEOUT=120

function mbus_publish() {
  [ -d "$BBS" ] || mkdir -p $BBS || exit 1
  cat > "$BBS/${1}.json"
}

function qmi() {
  JSON=`timeout -t $LTESTAT_TIMEOUT -s KILL uqmi -d $QMI_DEV "$@" 2>&1`
  if [ $? -eq 0 ] && (echo "$JSON" | jq -ea . > /dev/null 2>&1) ; then
    echo "$JSON"
    return 0
  fi
  return 1
}

function mod_reload() {
  local RLIST
  for mod in $* ; do
    RLIST="$mod $RLIST"
    rmmod -f $mod
  done
  for mod in $RLIST ; do
    RLIST="$mod $RLIST"
    modprobe $mod
  done
}

function start_network() {
  ip link set $IFACE down
  echo Y > /sys/class/net/$IFACE/qmi/raw_ip
  ip link set $IFACE up
  qmi --device $QMI_DEV --start-network --apn $APN --keep-client-id wds |\
    mbus_publish pdh_$IFACE
}

function wait_for_wds() {
  local STATUS="null"
  while [ "$STATUS" != "connected" ] ; do
    STATUS=`qmi --get-data-status | jq -r .`
    sleep 5
  done
}

function wait_for_register() {
  local STATUS="null"
  while [ "$STATUS" != "registered" ] ; do
    STATUS=`qmi --get-serving-system | jq -r .registration`
    sleep 5
  done
}

function wait_for_settings() {
  local MTU="null"
  while [ "$MTU" == "null" -o "$MTU" == ""  ] ; do
    MTU=`qmi --get-current-settings | jq -r .mtu`
    sleep 5
  done
}

function bringup_iface() {
  JSON=`qmi --get-current-settings`
  ifconfig $IFACE `echo "$JSON" | jq -r .ipv4.ip` \
                   netmask `echo "$JSON" | jq -r .ipv4.subnet` \
                   pointopoint `echo "$JSON" | jq -r .ipv4.gateway`
  # NOTE we may want to disable /proc/sys/net/ipv4/conf/default/rp_filter instead
  #      Verify it by cat /proc/net/netstat | awk '{print $80}'
  ip route add default via `echo "$JSON" | jq -r .ipv4.gateway` dev $IFACE metric 65000
  mkdir $BBS/resolv.conf || :
  cat > $BBS/resolv.conf/${IFACE}.dhcp <<__EOT__
nameserver `echo "$JSON" | jq -r .ipv4.dns1`
nameserver `echo "$JSON" | jq -r .ipv4.dns2`
__EOT__
}

function reset_modem() {
  # last ditch attempt to reset our modem -- not sure how effective :-(
  # mod_reload qcserial usb_wwan qmi_wwan cdc_wdm
  local PDH=`cat $BBS/pdh_$IFACE.json 2>/dev/null`

  for i in $PDH 0xFFFFFFFF ; do
    qmi --stop-network $i --autoconnect
  done

  qmi --reset-dms

  for i in $PDH 0xFFFFFFFF ; do
    qmi --stop-network $i --autoconnect
  done
}

# FIXME: if we decide to no longer play with rmmod/modprobe we should
#        move this to the wwan's build.yml
modprobe -a qcserial usb_wwan qmi_wwan cdc_wdm

# poor man's watchdog
while true ; do
  # ping is supposed to return 0 even if just a single packet out of 3 gets through
  if ! ping -W 20 -w 20 -c 3 -I $IFACE 8.8.8.8 > /dev/null 2>&1 ; then
    reset_modem 
 
    # lets see what networks are available still
    qmi --network-scan |\
      mbus_publish networks-info

    # hopefully we can recover now
    wait_for_register
    start_network
    wait_for_wds
    wait_for_settings
    bringup_iface
  fi

  # collect current stats
  for i in serving-system signal-info current-settings ; do
    qmi --get-$i | mbus_publish $i
  done

  sleep $WATCHDOG_TIMEOUT
done
