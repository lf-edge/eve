#!/bin/sh
# shellcheck disable=SC2039
# shellcheck disable=SC2155
# shellcheck disable=SC2034 # Constants defined here are used by sourced wwan-qmi.sh and wwan-mbim.sh
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
LOCINFO_PATH="${BBS}/location.json"

LTESTAT_TIMEOUT=120
PROBE_INTERVAL=300  # how often to probe the connectivity status (in seconds)
METRICS_INTERVAL=60 # how often to obtain and publish metrics (in seconds)
UNAVAIL_SIGNAL_METRIC=$(printf "%d" 0x7FFFFFFF) # max int32

DEFAULT_APN="internet"
DEFAULT_PROBE_ADDR="8.8.8.8"

IPV4_REGEXP='^[0-9]\+\.[0-9]\+\.[0-9]\+\.[0-9]\+$'

SRC="$(cd "$(dirname "$0")" || exit 1; pwd)"
# shellcheck source=./pkg/wwan/usr/bin/wwan-qmi.sh
. "${SRC}/wwan-qmi.sh"
# shellcheck source=./pkg/wwan/usr/bin/wwan-mbim.sh
. "${SRC}/wwan-mbim.sh"
# shellcheck source=./pkg/wwan/usr/bin/wwan-loc.sh
. "${SRC}/wwan-loc.sh"

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
  local UNIT="$3"
  local VAL="$(echo "$STDOUT" | sed -n "s/\s*$ATTR: \(.*\)$UNIT/\1/p" | head -n 1 | tr -d "'")"
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
  local DEV_PATH="$(readlink -f "${SYS_DEV}/device")"
  while [ -e "$DEV_PATH/subsystem" ]; do
    if [ "$(basename "$(readlink "$DEV_PATH/subsystem")")" != "pci" ]; then
      DEV_PATH="$(dirname "$DEV_PATH")"
    continue
    fi
    basename "$DEV_PATH"
    return
  done
}

# https://en.wikipedia.org/wiki/Hayes_command_set
# Args: <command> <tty device>
send_hayes_command() {
  printf "%s\r\n" "$1" | picocom -qrx 2000 -b 9600 "$2"
}

sys_get_modem_ttys() {
  # Convert USB address to <bus>-<port> as used in the /sys filesystem.
  local USB_ADDR="$(echo "$1" | tr ':' '-')"
  find /sys/bus/usb/devices -maxdepth 1 -name "${USB_ADDR}*" |\
    while read -r USB_INTF; do
      find "$(realpath "$USB_INTF")" -maxdepth 1 -name "tty*" -exec basename {} \;
    done
}

sys_get_modem_atport() {
  for TTY in $(sys_get_modem_ttys "$1"); do
    if send_hayes_command "AT" "/dev/$TTY" 2>/dev/null | grep -q "OK"; then
      echo "/dev/$TTY"
      return
    fi
  done
  return 1
}

# If successful, sets CDC_DEV, PROTOCOL, IFACE, USB_ADDR, PCI_ADDR and AT_PORT variables.
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

    AT_PORT="$(sys_get_modem_atport "$DEV_USB")"

    PROTOCOL="$DEV_PROT"
    IFACE="$DEV_IF"
    USB_ADDR="$DEV_USB"
    PCI_ADDR="$DEV_PCI"
    CDC_DEV="$(basename "${DEV}")"
    return 0
  done

  echo "Failed to find modem for"\
    "interface=${ARG_IF:-<ANY>}, USB=${ARG_USB:-<ANY>}, PCI=${ARG_PCI:-<ANY>}" >&2
  return 1
}

bringup_iface() {
  if ! "${PROTOCOL}_get_ip_settings"; then
    echo "Failed to get IP config for interface $IFACE"
    return 1
  fi
  ifconfig "$IFACE" "$IP" netmask "$SUBNET" pointopoint "$GW"
  if [ -n "$MTU" ]; then
    ip link set mtu "$MTU" dev "$IFACE"
  fi
  # NOTE we may want to disable /proc/sys/net/ipv4/conf/default/rp_filter instead
  #      Verify it by cat /proc/net/netstat | awk '{print $80}'
  ip route add default via "$GW" dev "$IFACE" metric 65000
  mkdir -p "$BBS/resolv.conf"
  local RESOLV_CONF="$BBS/resolv.conf/${IFACE}.dhcp"
  : > "$RESOLV_CONF"
  for DNS in "$DNS1" "$DNS2"; do
    if [ -n "$DNS" ]; then
      # The sole purpose of this route is to make sure that DNS probing,
      # done by probe_connectivity() using nslookup, uses interface wwan0
      # and not some other interface with a default route.
      # nslookup does not allow to specify source IP address. We could use dig
      # instead (with `-b <IP>` arg), but that requires to bring bind-tools
      # into eve-alpine with all its dependencies.
      # The route should not cause any harm since EVE uses separate per-interface
      # routing tables instead of the main table.
      ip route add "$DNS" via "$GW" dev "$IFACE"
      echo "nameserver $DNS" >> "$RESOLV_CONF"
    fi
  done
}

bringdown_iface() {
  # Truncate resolv.conf if it exists.
  local RESOLV_CONF="$BBS/resolv.conf/${IFACE}.dhcp"
  if [ -f "$RESOLV_CONF" ]; then
    : > "$RESOLV_CONF"
  fi
  # Remove IP address and routes from the interface.
  ip addr flush dev "$IFACE"
}

check_connectivity() {
  # First check the connectivity status as reported by the modem.
  if [ "$("${PROTOCOL}_get_op_mode")" != "online-and-connected" ]; then
    return 1
  fi
  # (optionally) Check connectivity by communicating with a remote endpoint.
  probe_connectivity
}

probe_connectivity() {
  unset PROBE_ERROR
  if [ "$PROBE_DISABLED" = "true" ]; then
    # probing disabled, skip it
    return 0
  fi
  if [ -n "$PROBE_ADDR" ]; then
    # User-configured ICMP probe address.
    add_probe_error "$(icmp_probe "$PROBE_ADDR")"
    return
  fi
  # Default probing behaviour (not configured by user).
  # First try endpoints from inside the LTE network:
  #  - TCP handshake with an IP-addressed proxy
  #  - DNS request to a DNS server provided by the LTE network
  # As a last resort, try ping to Google DNS (can be blocked by firewall).
  if "${PROTOCOL}_get_ip_settings"; then
    # Try TCP handshake with an IP-addressed proxy.
    while read -r PROXY; do
      [ -z "$PROXY" ] && continue
      local SERVER="$(parse_json_attr "$PROXY" "server")"
      local PORT="$(parse_json_attr "$PROXY" "port")"
      if echo "$SERVER" | grep -q "$IPV4_REGEXP"; then
        if nc -w 5 -s "$IP" -z -n "$SERVER" "$PORT" >/dev/null 2>&1; then
          return 0
        fi
        add_probe_error "TCP handshake with proxy $SERVER:$PORT failed"
      fi
    done <<__EOT__
$(echo "$PROXIES" | jq -c '.[]' 2>/dev/null)
__EOT__
    # Try DNS query (for the root domain to get only small-sized response).
    for DNS in "$DNS1" "$DNS2"; do
      if [ -n "$DNS" ]; then
        if nslookup -retry=1 -timeout=5 -type=a . "$DNS" >/dev/null 2>&1; then
          return 0
        fi
        add_probe_error "DNS query sent to $DNS failed"
      fi
    done
  fi
  # Try to ping Google DNS.
  # This is a last-resort probing option.
  # In a private LTE network ICMP requests headed towards public DNS servers
  # may be blocked by the firewall and thus produce probing false negatives.
  add_probe_error "$(icmp_probe "$DEFAULT_PROBE_ADDR")"
}

add_probe_error() {
  if [ -z "$1" ]; then
    return
  fi
  if [ -n "$PROBE_ERROR" ]; then
    PROBE_ERROR="$PROBE_ERROR; $1"
  else
    PROBE_ERROR="$1"
  fi
}

icmp_probe() {
  local PROBE_ADDR="$1"
  # ping is supposed to return 0 even if just a single packet out of 3 gets through
  local PROBE_OUTPUT
  if PROBE_OUTPUT="$(ping -W 20 -w 20 -c 3 -I "$IFACE" "$PROBE_ADDR" 2>&1)"; then
    return 0
  else
    local PROBE_ERROR="$(printf "%s" "$PROBE_OUTPUT" | grep "packet loss")"
    if [ -z "$PROBE_ERROR" ]; then
      PROBE_ERROR="$PROBE_OUTPUT"
    fi
    echo "Failed to ping $PROBE_ADDR via $IFACE: $PROBE_ERROR"
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

switch_to_preferred_proto() {
  local MODEL="$("${PROTOCOL}_get_modem_model")"
  case "$MODEL" in
   "EM7565")
     # With Sierra Wireless EM7565 we are experiencing quite often a firmware
     # bug causing the transmit queue to get stuck. In dmesg we see:
     #   NETDEV WATCHDOG: wwan0 (qmi_wwan): transmit queue 0 timed out
     # Followed by a stacktrace which shows that netif_tx_lock hangs.
     # This can be only fixed by restarting the modem, but it does not guarantee
     # that it will not happen again and so we may end up restarting the modem
     # quite frequently, disrupting the ongoing traffic.
     # This bug is easily reproducible with the QMI control protocol.
     # With MBIM, we have not been able to reproduce this issue even after many
     # attempts. Therefore we prefer to use MBIM with this modem until we find
     # a better solution.
     if [ "$PROTOCOL" != "mbim" ]; then
       if [ -z "$AT_PORT" ]; then
         echo "Cannot switch modem $LOGICAL_LABEL to MBIM: AT port is not available"
         return 1
       fi
       echo "Switching modem $LOGICAL_LABEL to MBIM (using AT port: ${AT_PORT})..."
       for CMD in '+++' 'AT!ENTERCND="A710"' 'AT!USBCOMP=1,1,100D' 'AT!RESET'; do
         local OUT="$(send_hayes_command "$CMD" "${AT_PORT}")"
         if echo "$OUT" | grep -q "ERROR"; then
           echo "Failed to switch modem $LOGICAL_LABEL to MBIM: $OUT"
           return 1
         fi
       done
       return 0
     fi
   ;;
  esac
  return 1 # No switch executed.
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
  unset LOC_TRACKING_DEV
  unset LOC_TRACKING_PROTO
  unset LOC_TRACKING_LL
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
    PROXIES="$(parse_json_attr "$NETWORK" "proxies")"
    APN="$(parse_json_attr "$NETWORK" "apns[0]")" # FIXME XXX limited to a single APN for now
    APN="${APN:-$DEFAULT_APN}"
    LOC_TRACKING="$(parse_json_attr "$NETWORK" "\"location-tracking\"")"

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

    if switch_to_preferred_proto; then
      # Modem is being restarted, return back to it later.
      continue
    fi

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

    if [ "$LOC_TRACKING" = "true" ]; then
      LOC_TRACKING_DEV="$CDC_DEV"
      LOC_TRACKING_PROTO="$PROTOCOL"
      LOC_TRACKING_LL="$LOGICAL_LABEL"
    fi

    # reflect updated config or just probe the current status
    if [ "$RADIO_SILENCE" != "true" ]; then
      if [ "$CONFIG_CHANGE" = "y" ] || ! check_connectivity; then
        echo "[$CDC_DEV] Restarting connection (APN=${APN}, interface=${IFACE})"
        {
          bringdown_iface                 &&\
          "${PROTOCOL}_stop_network"      &&\
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
        probe_connectivity
      fi
    else # Radio-silence is ON
      if [ "$("${PROTOCOL}_get_op_mode")" != "radio-off" ]; then
        echo "[$CDC_DEV] Trying to disable radio (APN=${APN}, interface=${IFACE})"
        if ! "${PROTOCOL}_toggle_rf" off 2>/tmp/wwan.stderr; then
          CONFIG_ERROR="$(cat /tmp/wwan.stderr)"
        else
          if ! wait_for radio-off "${PROTOCOL}_get_op_mode"; then
            CONFIG_ERROR="Timeout waiting for radio to turn off"
          else
            bringdown_iface
          fi
        fi
      fi
    fi

    collect_network_status "$CONFIG_CHANGE"
  done <<__EOT__
  $(echo "$CONFIG" | jq -c '.networks[]' 2>/dev/null)
__EOT__

  # Start/stop location tracking.
  if [ "$CONFIG_CHANGE" = "y" ]; then
    if [ -n "$LOC_TRACKING_DEV" ]; then
      if [ -z "$LOC_TRACKER" ]; then
        location_tracking "${LOC_TRACKING_LL}" "${LOC_TRACKING_DEV}"\
                          "${LOC_TRACKING_PROTO}" "${LOCINFO_PATH}" &
        LOC_TRACKER=$!
      fi
    else
      if [ -n "$LOC_TRACKER" ]; then
        kill_process_tree $LOC_TRACKER >/dev/null 2>&1
        echo "Location tracking was stopped (parent process: $LOC_TRACKER)"
        unset LOC_TRACKER
      fi
    fi
  fi

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
        else
          bringdown_iface
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
    # update status atomically
    mv "${STATUS_PATH}.tmp" "${STATUS_PATH}"
  fi
done
