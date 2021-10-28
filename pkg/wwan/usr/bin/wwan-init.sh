#!/bin/sh
# shellcheck disable=SC2039
# shellcheck disable=SC2155
# shellcheck disable=SC2034 # Constants defined here are used by sourced wwan-mbim.sh and wwan-mbim.sh
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
CONFIG_PATH="${BBS}/config.json"
STATUS_PATH="${BBS}/status.json"
METRICS_PATH="${BBS}/metrics.json"

LTESTAT_TIMEOUT=120
PROBE_INTERVAL=300  # how often to probe the connectivity status (in seconds)
METRICS_INTERVAL=60 # how often to obtain and publish metrics (in seconds)
UNAVAIL_SIGNAL_METRIC=$(printf "%d" 0x7FFFFFFF) # max int32

DEFAULT_APN="internet"
DEFAULT_PROBE_ADDR="8.8.8.8"

IPV4_REGEXP='[0-9]\+\.[0-9]\+\.[0-9]\+\.[0-9]\+'

SRC="$(cd "$(dirname "$0")" || exit 1; pwd)"
# shellcheck source=./pkg/wwan/usr/bin/wwan-qmi.sh
. "${SRC}/wwan-qmi.sh"
# shellcheck source=./pkg/wwan/usr/bin/wwan-mbim.sh
. "${SRC}/wwan-mbim.sh"

json_attr() {
  printf '"%s":%s' "$1" "$2"
}

json_str_attr() {
  printf '"%s":"%s"' "$1" "$2"
}

json_struct() {
  local ITEMS="$(for ARG in "${@}"; do printf ",%s" "$ARG"; done | cut -c2-)"
  printf "{%s}" "$ITEMS"
}

json_array() {
  local ITEMS="$(while read -r LINE; do [ -n "${LINE}" ] && printf ",%s" "${LINE}"; done | cut -c2-)"
  printf "[%s]" "$ITEMS"
}

parse_json_attr() {
  local JSON="$1"
  local JSON_PATH="$2"
  echo "$JSON" | jq -rc ".$JSON_PATH | select (.!=null)"
}

mod_reload() {
  local RLIST
  for mod in "$@" ; do
    RLIST="$mod $RLIST"
    rmmod -f "$mod"
  done
  for mod in $RLIST ; do
    RLIST="$mod $RLIST"
    modprobe "$mod"
  done
}

wait_for() {
  local EXPECT="$1"
  shift
  for i in $(seq 1 10); do
     eval RES='"$('"$*"')"'
     [ "$RES" = "$EXPECT" ] && return 0
     sleep 6
  done
  return 1
}

mbus_publish() {
  [ -d "$BBS" ] || mkdir -p $BBS || exit 1
  cat > "$BBS/${1}.json"
}

# parse value of an attribute returned by mbimcli or qmicli
parse_modem_attr() {
  local STDOUT="$1"
  local ATTR="$2"
  local VAL="$(echo "$STDOUT" | sed -n "s/\s*$ATTR: \(.*\)/\1/p" | tr -d "'")"
  if [ "$VAL" = "unknown" ]; then
    # "unknown" is used by VALIDATE_UNKNOWN macro in libqmi and libmbim
    VAL=""
  fi
  printf "%s" "$VAL"
}

config_checksum() {
  local CONFIG="$1"
  printf "%s" "$CONFIG" | sha256sum | cut -d " " -f1
}

sys_get_modem_protocol() {
  local SYS_DEV="$1"
  local MODULE="$(basename "$(readlink "${SYS_DEV}/device/driver/module")")"
  case "$MODULE" in
    "cdc_mbim") echo "mbim"
    ;;
    "qmi_wwan") echo "qmi"
    ;;
    *) return 1
    ;;
  esac
}

sys_get_modem_interface() {
  local SYS_DEV="$1"
  ls "${SYS_DEV}/device/net"
}

sys_get_modem_usbaddr() {
  local SYS_DEV="$1"
  local DEV_PATH="$(readlink -f "${SYS_DEV}/device")"
  while [ -e "$DEV_PATH/subsystem" ]; do
    if [ "$(basename "$(readlink "$DEV_PATH/subsystem")")" != "usb" ]; then
      DEV_PATH="$(dirname "$DEV_PATH")"
      continue
    fi
    basename "$DEV_PATH" | cut -d ":" -f 1 | tr '-' ':'
    return
  done
}

sys_get_modem_pciaddr() {
  local SYS_DEV="$1"
  local DEV_PATH="$(readlink -f "${DEV}/device")"
  while [ -e "$DEV_PATH/subsystem" ]; do
    if [ "$(basename "$(readlink "$DEV_PATH/subsystem")")" != "pci" ]; then
      DEV_PATH="$(dirname "$DEV_PATH")"
    continue
    fi
    basename "$DEV_PATH"
    return
  done
}

# If successful, sets CDC_DEV, PROTOCOL, IFACE, USB_ADDR and PCI_ADDR variables.
lookup_modem() {
  local ARG_IF="$1"
  local ARG_USB="$2"
  local ARG_PCI="$3"

  for DEV in /sys/class/usbmisc/*; do
    DEV_PROT=$(sys_get_modem_protocol "$DEV") || continue

    # check interface name
    DEV_IF="$(sys_get_modem_interface "$DEV")"
    [ -n "$ARG_IF" ] && [ "$ARG_IF" != "$DEV_IF" ] && continue

    # check USB address
    DEV_USB="$(sys_get_modem_usbaddr "$DEV")"
    [ -n "$ARG_USB" ] && [ "$ARG_USB" != "$DEV_USB" ] && continue

    # check PCI address
    DEV_PCI="$(sys_get_modem_pciaddr "$DEV")"
    [ -n "$ARG_PCI" ] && [ "$ARG_PCI" != "$DEV_PCI" ] && continue

    PROTOCOL="$DEV_PROT"
    IFACE="$DEV_IF"
    USB_ADDR="$DEV_USB"
    PCI_ADDR="$DEV_PCI"
    CDC_DEV="$(basename "${DEV}")"
    return 0
  done

  echo "Failed to find modem for "\
    "interface=${ARG_IF:-<ANY>}, USB=${ARG_USB:-<ANY>}, PCI=${ARG_PCI:-<ANY>}" >&2
  return 1
}

bringup_iface() {
  if [ "$PROTOCOL" = mbim ]; then
     local JSON=$(mbim --query-ip-configuration)
     local DNS0="dns0"
     local DNS1="dns1"
  else
     local JSON=$(uqmi --get-current-settings)
     local DNS0="dns1"
     local DNS1="dns2"
  fi
  ifconfig "$IFACE" "$(echo "$JSON" | jq -r .ipv4.ip)" \
                   netmask "$(echo "$JSON" | jq -r .ipv4.subnet)" \
                   pointopoint "$(echo "$JSON" | jq -r .ipv4.gateway)"
  # NOTE we may want to disable /proc/sys/net/ipv4/conf/default/rp_filter instead
  #      Verify it by cat /proc/net/netstat | awk '{print $80}'
  ip route add default via "$(echo "$JSON" | jq -r .ipv4.gateway)" dev "$IFACE" metric 65000
  mkdir "$BBS/resolv.conf" || :
  cat > "$BBS/resolv.conf/${IFACE}.dhcp" <<__EOT__
nameserver $(echo "$JSON" | jq -r .ipv4.$DNS0)
nameserver $(echo "$JSON" | jq -r .ipv4.$DNS1)
__EOT__
}

probe() {
  if [ "$PROBE_DISABLED" = "true" ]; then
    # probing disabled, skip it
    unset PROBE_ERROR
    return 0
  fi
  # ping is supposed to return 0 even if just a single packet out of 3 gets through
  local PROBE_OUTPUT
  if PROBE_OUTPUT="$(ping -W 20 -w 20 -c 3 -I "$IFACE" "$PROBE_ADDR" 2>&1)"; then
    unset PROBE_ERROR
    return 0
  else
    PROBE_ERROR="$(printf "%s" "$PROBE_OUTPUT" | grep "packet loss")"
    if [ -z "$PROBE_ERROR" ]; then
      PROBE_ERROR="$PROBE_OUTPUT"
    fi
    PROBE_ERROR="Failed to ping $PROBE_ADDR via $IFACE: $PROBE_ERROR"
    return 1
  fi
}

collect_network_status() {
  local QUICK="$1"
  local PROVIDERS="[]"
  if [ "$QUICK" != "y" ]; then
    # The process of scanning for available providers takes up to 1 minute.
    # It is done only during PROBING events and skipped when config is changed
    # (e.g. radio-silence mode is switched ON/OFF) so that the updated status is promptly
    # published for better user experience.
    PROVIDERS="$("${PROTOCOL}_get_providers")"
  fi
  local MODULE="$(json_struct \
    "$(json_str_attr imei     "$("${PROTOCOL}_get_imei")")" \
    "$(json_str_attr model    "$("${PROTOCOL}_get_modem_model")")" \
    "$(json_str_attr revision "$("${PROTOCOL}_get_modem_revision")")" \
    "$(json_str_attr control-protocol "$PROTOCOL")" \
    "$(json_str_attr operating-mode   "$("${PROTOCOL}_get_op_mode")")")"
  local NETWORK_STATUS="$(json_struct \
    "$(json_str_attr logical-label    "$LOGICAL_LABEL")" \
    "$(json_attr     physical-addrs   "$ADDRS")" \
    "$(json_attr     cellular-module  "$MODULE")" \
    "$(json_attr     sim-cards        "$("${PROTOCOL}_get_sim_cards")")" \
    "$(json_str_attr config-error     "$CONFIG_ERROR")" \
    "$(json_str_attr probe-error      "$PROBE_ERROR")" \
    "$(json_attr     providers        "$PROVIDERS")")"
  STATUS="${STATUS}${NETWORK_STATUS}\n"
}

collect_network_metrics() {
  local NETWORK_METRICS="$(json_struct \
    "$(json_str_attr logical-label  "$LOGICAL_LABEL")" \
    "$(json_attr     physical-addrs "$ADDRS")" \
    "$(json_attr     packet-stats   "$("${PROTOCOL}_get_packet_stats")")" \
    "$(json_attr     signal-info    "$("${PROTOCOL}_get_signal_info")")")"
  METRICS="${METRICS}${NETWORK_METRICS}\n"
}

event_stream() {
  inotifywait -qm "${BBS}" -e create -e modify -e delete &
  while true; do
    echo "PROBE"
    sleep "$PROBE_INTERVAL"
  done &
  while true; do
    echo "METRICS"
    sleep "$METRICS_INTERVAL"
  done
}

echo "Starting wwan manager"
mkdir -p "${BBS}"
modprobe -a qcserial usb_wwan qmi_wwan cdc_wdm cdc_mbim cdc_acm

# For cellular modems we do not rely on rfkill to enable/disable radio transmission.
# This is because rfkill driver for wwan is often not available.
# Instead, the operational state and RF of cellular modems is managed via QMI or MBIM.
# But should rfkill driver for wwan be provided and because by default RF is blocked
# for all wireless devices (rfkill.default_state=0; used for WiFi), we need to preventively
# unblock rfkill for wwan to ensure that it doesn't override wwan RF state as configured from here.
rfkill unblock wwan

# Main event loop
event_stream | while read -r EVENT; do
  if ! echo "$EVENT" | grep -q "PROBE\|METRICS\|config.json"; then
    continue
  fi

  CONFIG_CHANGE=n
  if [ "$EVENT" != "PROBE" ] && [ "$EVENT" != "METRICS" ]; then
    CONFIG_CHANGE=y
  fi

  CONFIG="$(cat "${CONFIG_PATH}" 2>/dev/null)"
  if [ "$CONFIG_CHANGE" = "y" ]; then
    if [ "$LAST_CONFIG" = "$CONFIG" ]; then
      # spurious notification, ignore
      continue
    else
      LAST_CONFIG="$CONFIG"
    fi
  fi
  CHECKSUM="$(config_checksum "$CONFIG")"

  unset MODEMS
  unset STATUS
  unset METRICS
  RADIO_SILENCE="$(parse_json_attr "$CONFIG" "\"radio-silence\"")"

  # iterate over each configured cellular network
  while read -r NETWORK; do
    [ -z "$NETWORK" ] && continue
    unset CONFIG_ERROR
    unset PROBE_ERROR

    # parse network configuration
    LOGICAL_LABEL="$(parse_json_attr "$NETWORK" "\"logical-label\"")"
    ADDRS="$(parse_json_attr "$NETWORK" "\"physical-addrs\"")"
    IFACE="$(parse_json_attr "$ADDRS" "interface")"
    USB_ADDR="$(parse_json_attr "$ADDRS" "usb")"
    PCI_ADDR="$(parse_json_attr "$ADDRS" "pci")"
    PROBE="$(parse_json_attr "$NETWORK" "probe")"
    PROBE_DISABLED="$(parse_json_attr "$PROBE" "disable")"
    PROBE_ADDR="$(parse_json_attr "$PROBE" "address")"
    PROBE_ADDR="${PROBE_ADDR:-$DEFAULT_PROBE_ADDR}"
    APN="$(parse_json_attr "$NETWORK" "apns[0]")" # FIXME XXX limited to a single APN for now
    APN="${APN:-$DEFAULT_APN}"

    if ! lookup_modem "${IFACE}" "${USB_ADDR}" "${PCI_ADDR}" 2>/tmp/wwan.stderr; then
      CONFIG_ERROR="$(cat /tmp/wwan.stderr)"
      NETWORK_STATUS="$(json_struct \
        "$(json_str_attr logical-label  "$LOGICAL_LABEL")" \
        "$(json_attr     physical-addrs "$ADDRS")" \
        "$(json_str_attr config-error   "$CONFIG_ERROR")")"
      STATUS="${STATUS}${NETWORK_STATUS}\n"
      continue
    fi
    MODEMS="${MODEMS}${CDC_DEV}\n"
    echo "Processing managed modem (event: $EVENT): $CDC_DEV"

    # in status.json and metrics.json print all modem addresses (as found by lookup_modem),
    # not just the ones used in config.json
    ADDRS="$(json_struct \
      "$(json_str_attr interface "$IFACE")" \
      "$(json_str_attr usb       "$USB_ADDR")" \
      "$(json_str_attr pci       "$PCI_ADDR")")"

    if [ "$EVENT" = "METRICS" ]; then
      collect_network_metrics 2>/dev/null
      continue
    fi

    # reflect updated config or just probe the current status
    if [ "$RADIO_SILENCE" != "true" ]; then
      if [ "$CONFIG_CHANGE" = "y" ] || ! probe; then
        echo "[$CDC_DEV] Restarting connection (APN=${APN}, interface=${IFACE})"
        {
          "${PROTOCOL}_reset_modem"       &&\
          "${PROTOCOL}_toggle_rf" on      &&\
          "${PROTOCOL}_wait_for_sim"      &&\
          "${PROTOCOL}_wait_for_register" &&\
          "${PROTOCOL}_start_network"     &&\
          "${PROTOCOL}_wait_for_wds"      &&\
          "${PROTOCOL}_wait_for_settings" &&\
          bringup_iface                   &&\
          echo "[$CDC_DEV] Connection successfully restarted"
        } 2>/tmp/wwan.stderr
        RV=$?
        if [ $RV -ne 0 ]; then
          CONFIG_ERROR="$(sort -u < /tmp/wwan.stderr)"
          CONFIG_ERROR="${CONFIG_ERROR:-(Re)Connection attempt failed with rv=$RV}"
        fi
        # retry probe to update PROBE_ERROR
        sleep 3
        probe
      fi
    else # Radio-silence is ON
      if [ "$("${PROTOCOL}_get_op_mode")" != "radio-off" ]; then
        echo "[$CDC_DEV] Trying to disable radio (APN=${APN}, interface=${IFACE})"
        if ! "${PROTOCOL}_toggle_rf" off 2>/tmp/wwan.stderr; then
          CONFIG_ERROR="$(cat /tmp/wwan.stderr)"
        else
          if ! wait_for radio-off "${PROTOCOL}_get_op_mode"; then
            CONFIG_ERROR="Timeout waiting for radio to turn off"
          fi
        fi
      fi
    fi

    collect_network_status "$CONFIG_CHANGE"
  done <<__EOT__
  $(echo "$CONFIG" | jq -c '.networks[]' 2>/dev/null)
__EOT__

  # manage RF state also for modems not configured by the controller
  for DEV in /sys/class/usbmisc/*; do
    unset CONFIG_ERROR
    unset PROBE_ERROR
    unset LOGICAL_LABEL # unmanaged modems do not have logical name

    PROTOCOL="$(sys_get_modem_protocol "$DEV")" || continue
    CDC_DEV="$(basename "${DEV}")"
    if printf "%b" "$MODEMS" | grep -q "^$CDC_DEV$"; then
      # this modem has configuration and was already processed
      continue
    fi
    echo "Processing unmanaged modem (event: $EVENT): $CDC_DEV"
    IFACE=$(sys_get_modem_interface "$DEV")
    USB_ADDR=$(sys_get_modem_usbaddr "$DEV")
    PCI_ADDR=$(sys_get_modem_pciaddr "$DEV")
    ADDRS="$(json_struct \
        "$(json_str_attr interface "$IFACE")" \
        "$(json_str_attr usb       "$USB_ADDR")" \
        "$(json_str_attr pci       "$PCI_ADDR")")"

    if [ "$EVENT" = "METRICS" ]; then
      collect_network_metrics 2>/dev/null
      continue
    fi

    if [ "$("${PROTOCOL}_get_op_mode")" != "radio-off" ]; then
      echo "[$CDC_DEV] Trying to disable radio (interface=${IFACE})"
      if ! "${PROTOCOL}_toggle_rf" off 2>/tmp/wwan.stderr; then
        CONFIG_ERROR="$(cat /tmp/wwan.stderr)"
      else
        if ! wait_for radio-off "${PROTOCOL}_get_op_mode"; then
          CONFIG_ERROR="Timeout waiting for radio to turn off"
        fi
      fi
    fi

    collect_network_status "$CONFIG_CHANGE"
  done

  if [ "$EVENT" = "METRICS" ]; then
    json_struct \
      "$(json_attr networks "$(printf "%b" "$METRICS" | json_array)")" \
        | jq > "${METRICS_PATH}.tmp"
    # update metrics atomically
    mv "${METRICS_PATH}.tmp" "${METRICS_PATH}"
  else
    json_struct \
      "$(json_attr     networks        "$(printf "%b" "$STATUS" | json_array)")" \
      "$(json_str_attr config-checksum "$CHECKSUM")" \
        | jq > "${STATUS_PATH}.tmp"
    # update metrics atomically
    mv "${STATUS_PATH}.tmp" "${STATUS_PATH}"
  fi
done
