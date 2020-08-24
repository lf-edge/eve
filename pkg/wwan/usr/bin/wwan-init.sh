#!/bin/sh
# set -x

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
IFACE=wwan0
CDC_DEV=cdc-wdm0
MODE=qmi

WATCHDOG_TIMEOUT=300
LTESTAT_TIMEOUT=120

get_apn() {
  APN="$(cat /run/accesspoint/"$IFACE" 2>/dev/null)"
  echo "${APN:-internetd.gdsp}"
}

mbus_publish() {
  [ -d "$BBS" ] || mkdir -p $BBS || exit 1
  cat > "$BBS/${1}.json"
}

mbim() {
  timeout -s KILL "$LTESTAT_TIMEOUT" mbimcli -p -d "/dev/$CDC_DEV" "$@"
}

qmi() {
  JSON=`timeout -s KILL "$LTESTAT_TIMEOUT" uqmi -d "/dev/$CDC_DEV" "$@" 2>&1`
  if [ $? -eq 0 ] && (echo "$JSON" | jq -ea . > /dev/null 2>&1) ; then
    echo "$JSON"
    return 0
  fi
  return 1
}

mod_reload() {
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

start_network() {
  echo "Starting network for APN $(get_apn)"
  if [ "$MODE" = mbim ]; then
     # NOTE that after --attach-packet-service we may end in a state
     # where packet service is attached but WDS hasn't come up online
     # just yet. We're blocking on WDS in wait_for_wds(). However, it
     # may be useful to check --query-packet-service-state just in case.
     mbim --attach-packet-service
     sleep 10
     mbim --connect="apn='$(get_apn)'"
  else
     ip link set $IFACE down
     echo Y > /sys/class/net/$IFACE/qmi/raw_ip
     ip link set $IFACE up

     qmi --start-network --apn "$(get_apn)" --keep-client-id wds |\
         mbus_publish pdh_$IFACE
  fi
}

wait_for() {
  EXPECT="$1"
  shift
  for i in `seq 1 10`; do
     eval RES='"$('"$*"')"'
     [ "$RES" = "$EXPECT" ] && return 0
     sleep 6
  done
  return 1
}

wait_for_sim() {
  # FIXME XXX this is only for MBIM for now
  if [ "$MODE" = mbim ]; then
     CMD="mbim --query-subscriber-ready-status | grep -q 'Ready state: .initialized.' && echo initialized"
  else
     CMD="echo initialized"
  fi

  wait_for initialized "$CMD"
}

wait_for_wds() {
  echo "Waiting for DATA services to connect"
  if [ "$MODE" = mbim ]; then
     # FIXME XXX there seems to be cases where this looks like connected
     CMD="mbim --query-connection-state | grep -q 'Activation state: .activated.' && echo connected"
  else
     CMD="qmi --get-data-status | jq -r ."
  fi

  wait_for connected "$CMD"
}

wait_for_register() {
  echo "Waiting for the device to register on the network"
  if [ "$MODE" = mbim ]; then
     CMD="mbim --query-registration-state | grep -qE 'Register state:.*(home|roaming|partner)' && echo registered"
  else
     CMD="qmi --get-serving-system | jq -r .registration"
  fi

  wait_for registered "$CMD"
}

wait_for_settings() {
  echo "Waiting for IP configuration for the $IFACE interface"
  if [ "$MODE" = mbim ]; then
     CMD="mbim --query-ip-configuration"
  else
     CMD="qmi --get-current-settings"
  fi

  wait_for connected "$CMD | jq -r .ipv4.ip | grep -q '[0-9]*\.[0-9]*\.[0-9]*\.[0-9]*' && echo connected"
}

bringup_iface() {
  if [ "$MODE" = mbim ]; then
     JSON=$(mbim --query-ip-configuration)
  else
     JSON=$(qmi --get-current-settings)
  fi
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

scan_providers() {
  if [ "$MODE" = mbim ]; then
     # FIXME XXX this seems to return Busy more often than not
     # detach-packet-service may be required
     mbim --query-visible-providers |\
          mbus_publish networks-info
     return $?
  fi

  qmi --network-scan |\
      mbus_publish networks-info
}

reset_modem() {
  if [ "$MODE" = mbim ]; then
     mbim --disconnect
     mbim --detach-packet-service
     return $?
  fi

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

detect_mode() {
  modprobe -a qcserial usb_wwan qmi_wwan cdc_wdm cdc_mbim cdc_acm
  if [ "$(basename "$(readlink "/sys/class/usbmisc/$CDC_DEV/device/driver/module")")" = cdc_mbim ]; then
     MODE=mbim
  fi
}

# lets start with detecting what we're dealing with
detect_mode
echo "Starting wwan manager in $MODE mode"

# poor man's watchdog
while true ; do
  # ping is supposed to return 0 even if just a single packet out of 3 gets through
  if ! ping -W 20 -w 20 -c 3 -I $IFACE 8.8.8.8 > /dev/null 2>&1 ; then
    reset_modem

    # lets see what networks are available still
    scan_providers

    # hopefully we can recover now
    wait_for_sim || continue
    wait_for_register || continue
    start_network
    wait_for_wds || continue
    wait_for_settings || continue
    bringup_iface
  fi

  # collect current stats
  if [ "$MODE" = mbim ]; then
     for i in home-provider signal-state ip-configuration ; do
         mbim --query-$i | mbus_publish $i
     done
  else
     for i in serving-system signal-info current-settings ; do
         qmi --get-$i | mbus_publish $i
     done
  fi

  sleep $WATCHDOG_TIMEOUT
done
