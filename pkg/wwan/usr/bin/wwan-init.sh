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

CMD_TIMEOUT=5 # timeout applied for MBIM and QMI commands
# How often to probe the connectivity status (in seconds).
# Note that on most iterations we only run "Quick" probe, checking the status of connectivity
# without generating any traffic and triggering re-connect if a modem is found to be offline.
# Every 5 minutes the probe is elevated to "Standard" probe and we also collect and publish
# state data to /run/wwan/status.json.
# And every 1 hour we additionally query the set of visible providers from "Long" probe
# (also published in status.json).
PROBE_INTERVAL=20
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

join_lines_with_semicolon() {
  cat - | sed ':a;N;$!ba;s/\n/; /g'
}

escape_apostrophe() {
  cat - | sed 's/\"/\\\"/g'
}

join_lines_with_escaped_newline() {
  cat - | sed ':a;N;$!ba;s/\n/\\n/g'
}

bool_to_yesno() {
  local INPUT
  read -r INPUT
  [ "$INPUT" = "true" ] && echo "yes" || echo "no"
}

yesno_to_bool() {
  local INPUT
  read -r INPUT
  [ "$INPUT" = "yes" ] && echo "true" || echo "false"
}

bool_to_onoff() {
  local INPUT
  read -r INPUT
  [ "$INPUT" = "true" ] && echo "on" || echo "off"
}

onoff_to_bool() {
  local INPUT
  read -r INPUT
  [ "$INPUT" = "on" ] && echo "true" || echo "false"
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
  local ATTEMPTS="$1"
  local EXPECT="$2"
  shift 2
  for i in $(seq 1 "$ATTEMPTS"); do
     eval RES='"$('"$*"')"'
     [ "$RES" = "$EXPECT" ] && return 0
     sleep 3
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
  if [ "$VERBOSE" = "true" ]; then
    log_debug Running AT command: "$1"
  fi
  local OUTPUT
  local RV
  OUTPUT="$(printf "%s\r\n" "$1" | picocom -qrx 2000 -b 9600 "$2")"
  RV=$?
  if [ "$VERBOSE" = "true" ]; then
    log_debug AT output: "$OUTPUT"
  fi
  echo "$OUTPUT"
  return $RV
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

# If successful, sets CDC_DEV, PROTOCOL, IFACE, USB_ADDR and PCI_ADDR variables.
lookup_modem() {
  local ARG_IF="$1"
  local ARG_USB="$2"
  local ARG_PCI="$3"

  for DEV in /sys/class/usbmisc/*; do
    if [ "$VERBOSE" = "true" ]; then
      log_debug "lookup_modem: $DEV"
    fi
    local DEV_PROT="$(sys_get_modem_protocol "$DEV")" || continue

    # check interface name
    local DEV_IF="$(sys_get_modem_interface "$DEV")"
    [ -n "$ARG_IF" ] && [ "$ARG_IF" != "$DEV_IF" ] && continue

    # check USB address
    local DEV_USB="$(sys_get_modem_usbaddr "$DEV")"
    [ -n "$ARG_USB" ] && [ "$ARG_USB" != "$DEV_USB" ] && continue

    # check PCI address
    local DEV_PCI="$(sys_get_modem_pciaddr "$DEV")"
    [ -n "$ARG_PCI" ] && [ "$ARG_PCI" != "$DEV_PCI" ] && continue

    PROTOCOL="$DEV_PROT"
    IFACE="$DEV_IF"
    USB_ADDR="$DEV_USB"
    PCI_ADDR="$DEV_PCI"
    CDC_DEV="$(basename "${DEV}")"
    return 0
  done

  log_error "Failed to find modem for"\
    "interface=${ARG_IF:-<ANY>}, USB=${ARG_USB:-<ANY>}, PCI=${ARG_PCI:-<ANY>}"
  return 1
}

bringup_iface() {
  if ! "${PROTOCOL}_get_ip_settings"; then
    log_error "Failed to get IP config for interface $IFACE"
    return 1
  fi
  ifconfig "$IFACE" "$IP" netmask "$SUBNET" pointopoint "$GW"
  if [ -n "$MTU" ]; then
    ip link set mtu "$MTU" dev "$IFACE"
  fi
  local METRIC=65000
  # If interface name is something unexpected, metric will stay as 65000.
  local IDX="${IFACE#"wwan"}"
  # With multiple modems there will be multiple default routes and each should
  # have different metric otherwise there is a conflict.
  # Note that the actual metric value does not matter all that much. EVE does not use
  # the main routing table, instead it chooses uplink interface for a particular mgmt
  # request or network instance and routes the traffic using the interface-specific
  # table.
  METRIC="$((METRIC+IDX))"
  # NOTE we may want to disable /proc/sys/net/ipv4/conf/default/rp_filter instead
  #      Verify it by cat /proc/net/netstat | awk '{print $80}'
  ip route add default via "$GW" dev "$IFACE" metric "${METRIC}"
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
  # Remove resolv.conf if it exists.
  local RESOLV_CONF="$BBS/resolv.conf/${IFACE}.dhcp"
  rm -f "$RESOLV_CONF"
  # Remove IP address and routes from the interface.
  ip addr flush dev "$IFACE"
}

# Sets global variable DP_STUCK to "y" if data-plane is found to be stuck.
check_connectivity() {
  local EVENT="$1"
  unset PROBE_ERROR
  # First check the connectivity status as reported by the modem.
  local OP_STATUS="$("${PROTOCOL}_get_op_mode")"
  if [ "$OP_STATUS" != "online-and-connected" ]; then
    add_probe_error "modem is not connected (operational mode: ${OP_STATUS})"
    return 1
  fi
  if "${PROTOCOL}_get_ip_address" | grep -vq "$IPV4_REGEXP"; then
    add_probe_error "no IP address assigned"
    return 1
  fi
  if [ "$EVENT" = "QUICK-PROBE" ]; then
    # Do not generate any traffic during a quick probe.
    # Assume that the connectivity is OK if modem says so.
    return 0
  fi
  # (optionally) Check connectivity by communicating with a remote endpoint.
  PS_BEFORE="$("${PROTOCOL}_get_packet_stats")"
  if ! probe_connectivity; then
    PS_AFTER="$("${PROTOCOL}_get_packet_stats")"
    # If packet counters as reported by the modem has not changed,
    # then data-plane is very likely stuck.
    if [ "$PS_BEFORE" != "$PS_AFTER" ]; then
      DP_STUCK=y
      add_probe_error "data-plane of the modem is stuck"
    fi
    return 1
  fi
}

probe_connectivity() {
  if [ "$PROBE_DISABLED" = "true" ]; then
    # probing disabled, skip it
    return 0
  fi
  if [ -n "$PROBE_ADDR" ]; then
    # User-configured ICMP probe address.
    icmp_probe "$PROBE_ADDR"
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
  icmp_probe "$DEFAULT_PROBE_ADDR"
}

add_probe_error() {
  if [ -z "$1" ]; then
    return
  fi
  local ERR_MSG="$(echo "$1" | join_lines_with_semicolon | escape_apostrophe)"
  if [ -n "$PROBE_ERROR" ]; then
    PROBE_ERROR="$PROBE_ERROR; $ERR_MSG"
  else
    PROBE_ERROR="$ERR_MSG"
  fi
  if [ "$VERBOSE" = "true" ]; then
    log_debug "[$CDC_DEV] Check connectivity: $1"
  fi
}

icmp_probe() {
  local PING_ADDR="$1"
  # ping is supposed to return 0 even if just a single packet out of 3 gets through
  local PING_OUTPUT
  if PING_OUTPUT="$(ping -W 20 -w 20 -c 3 -I "$IFACE" "$PING_ADDR" 2>&1)"; then
    return 0
  else
    local PING_ERROR="$(printf "%s" "$PING_OUTPUT" | grep "packet loss")"
    if [ -z "$PING_ERROR" ]; then
      PING_ERROR="$PING_OUTPUT"
    fi
    add_probe_error "Failed to ping $PING_ADDR via $IFACE: $PING_ERROR"
    return 1
  fi
}

collect_network_status() {
  local EVENT="$1"
  local PROVIDERS="[]"
  if [ "$EVENT" = "LONG-PROBE" ]; then
    # The process of scanning for available providers takes up to 1 minute.
    # It is done only during LONG-PROBE events and skipped when config is changed
    # (e.g. radio-silence mode is switched ON/OFF) so that the updated status is promptly
    # published for better user experience.
    PROVIDERS="$("${PROTOCOL}_get_providers")"
  elif [ "$QUERY_VISIBLE_PROVIDERS" = "true" ]; then
    # Just preserve the list of providers previously obtained for this modem.
    # If scanning of visible providers is disabled, we do not preserve previously
    # obtained data. Over time, this data becomes increasingly obsolete and could confuse
    # users.
    PROVIDERS="$(jq -rc --arg CDC_DEV "$CDC_DEV" \
      '.networks[] | select(."physical-addrs".dev==$CDC_DEV) | ."visible-providers"' \
      "${STATUS_PATH}" 2>/dev/null)"
    PROVIDERS="${PROVIDERS:-"[]"}"
  fi
  local OP_MODE="$("${PROTOCOL}_get_op_mode")"
  local MODULE="$(json_struct \
    "$(json_str_attr imei     "$("${PROTOCOL}_get_imei")")" \
    "$(json_str_attr model    "$("${PROTOCOL}_get_modem_model")")" \
    "$(json_str_attr revision "$("${PROTOCOL}_get_modem_revision")")" \
    "$(json_str_attr manufacturer "$("${PROTOCOL}_get_modem_manufacturer")")" \
    "$(json_str_attr control-protocol "$PROTOCOL")" \
    "$(json_str_attr operating-mode   "$OP_MODE")")"
  local NETWORK_STATUS="$(json_struct \
    "$(json_str_attr logical-label        "$LOGICAL_LABEL")" \
    "$(json_attr     physical-addrs       "$ADDRS")" \
    "$(json_attr     cellular-module      "$MODULE")" \
    "$(json_attr     sim-cards            "$("${PROTOCOL}_get_sim_cards")")" \
    "$(json_str_attr config-error         "$CONFIG_ERROR")" \
    "$(json_str_attr probe-error          "$PROBE_ERROR")" \
    "$(json_attr     visible-providers    "$PROVIDERS")" \
    "$(json_attr     current-provider     "$("${PROTOCOL}_get_current_provider")")" \
    "$(json_attr     current-rats         "$("${PROTOCOL}_get_currently_used_rats")")" \
    "$(json_attr     connected-at         "$(get_connection_time)")" \
    "$(json_attr     suspended-quickprobe "${SUSPEND_QUICKPROBE:-false}")")"
  STATUS="${STATUS}${NETWORK_STATUS}\n"
}

# When modem is connected, the corresponding resolv.conf file is created and/or updated
# (at least emptied).
# Disconnected modem does not have resolv.conf.
get_connection_time() {
  local TIMESTAMP="$(stat -c "%Y" "$BBS/resolv.conf/${IFACE}.dhcp" 2>/dev/null)"
  TIMESTAMP="${TIMESTAMP:-0}"
  echo "$TIMESTAMP"
}

is_quickprobe_suspended() {
  local SUSPENDED="$(jq -rc --arg CDC_DEV "$CDC_DEV" \
    '.networks[] | select(."physical-addrs".dev==$CDC_DEV) | ."suspended-quickprobe"' \
    "${STATUS_PATH}" 2>/dev/null)"
  [ "$SUSPENDED" = "true" ] && return 0 || return 1
}

sim_card_status_changed() {
  local PREV_STATUS="$(jq -rc --arg CDC_DEV "$CDC_DEV" \
    '.networks[] | select(."physical-addrs".dev==$CDC_DEV) | ."sim-cards"' \
    "${STATUS_PATH}" 2>/dev/null)"
  [ "$PREV_STATUS" != "$("${PROTOCOL}_get_sim_cards")" ] && return 0 || return 1
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
       local AT_PORT="$(sys_get_modem_atport "$USB_ADDR")"
       if [ -z "$AT_PORT" ]; then
         log_error "Cannot switch modem $LOGICAL_LABEL to MBIM: AT port is not available"
         return 1
       fi
       log_debug "Switching modem $LOGICAL_LABEL to MBIM (using AT port: ${AT_PORT})..."
       for CMD in '+++' 'AT!ENTERCND="A710"' 'AT!USBCOMP=1,1,100D' 'AT!RESET'; do
         local OUT="$(send_hayes_command "$CMD" "${AT_PORT}")"
         if echo "$OUT" | grep -q "ERROR"; then
           log_error "Failed to switch modem $LOGICAL_LABEL to MBIM: $OUT"
           return 1
         fi
       done
       return 0
     fi
   ;;
  esac
  return 1 # No switch executed.
}

# According to ETSI TS 100 916 V7.4.0 (1999-11), Section 8.2,
# "AT+CFUN=1,1" is one of the commands a modem should implement.
reset_modem_method1() {
  local AT_PORT="$1"
  for CMD in '+++' 'AT+CFUN=1,1'; do
    local OUT="$(send_hayes_command "$CMD" "${AT_PORT}")"
    if echo "$OUT" | grep -q "ERROR"; then
      log_error "Failed to reset modem $LOGICAL_LABEL using AT+CFUN=1,1: $OUT"
      return 1
    fi
  done
}

# Just for a rare case that "AT+CFUN=1,1" is not available, we try also AT!RESET,
# which, however, is Sierra Wireless specific.
reset_modem_method2() {
  local AT_PORT="$1"
  for CMD in '+++' 'AT!RESET'; do
    local OUT="$(send_hayes_command "$CMD" "${AT_PORT}")"
    if echo "$OUT" | grep -q "ERROR"; then
      log_error "Failed to reset modem $LOGICAL_LABEL using" 'AT!RESET' ": $OUT"
      return 1
    fi
  done
}

reset_modem() {
  local AT_PORT="$(sys_get_modem_atport "$USB_ADDR")"
  if [ -z "$AT_PORT" ]; then
    log_error "Cannot reset modem $LOGICAL_LABEL: AT port is not available"
    return 1
  fi
  log_debug "Resetting modem $LOGICAL_LABEL (using AT port: ${AT_PORT})..."
  reset_modem_method1 "$AT_PORT" || reset_modem_method2 "$AT_PORT" || return 1
}

LOG_PIPE="/tmp/wwan-log.pipe"
if [ ! -p "$LOG_PIPE" ]; then
  rm -f "$LOG_PIPE"
  mkfifo "$LOG_PIPE"
fi

log_debug() {
  local MSG="$*"
  echo "$MSG" | join_lines_with_escaped_newline > "$LOG_PIPE"
}

log_error() {
  local MSG="$*"
  echo "Error: $MSG" | join_lines_with_escaped_newline > "$LOG_PIPE"
  # Additionally to logging, print the error message to stderr.
  # This is then typically redirected to /tmp/wwan.stderr and loaded into CONFIG_ERROR
  # variable.
  echo "$MSG" >&2
}

logger() {
  # EVE collects logs from the stdout of this script.
  while [ -p "$LOG_PIPE" ]; do cat "$LOG_PIPE"; done
}

logger &

# Suspend periodic events, i.e. probes and metrics (not config change notifications).
# This is used to avoid long backlog of pending periodic events.
suspend_periodic_events() {
  touch "${BBS}/${1}.suspend"
}

release_periodic_events() {
  rm -f "${BBS}/${1}.suspend"
}

wait_if_suspended() {
  local WAS_SUSPENDED
  while [ -f "${BBS}/${1}.suspend" ]; do
    WAS_SUSPENDED="y"
    sleep 1
  done
  if [ "$WAS_SUSPENDED" = "y" ]; then
    # Processing of an event just completed - do not immediately trigger another one.
    sleep 5
  fi
}

event_stream() {
  inotifywait -qm "${BBS}" --include config.json -e create -e modify -e delete -e moved_to &
  while true; do
    wait_if_suspended "probe"
    echo "PROBE"
    sleep "$PROBE_INTERVAL"
  done &
  # Do not ask for metrics immediately after boot (may delay applying initial config),
  # instead wait 2 minutes.
  sleep 120
  while true; do
    wait_if_suspended "metrics"
    echo "METRICS"
    sleep "$METRICS_INTERVAL"
  done
}

log_debug "Starting wwan manager"
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
PROBE_ITER=0
ENFORCE_LONG_PROBE=n
STATUS_OUTDATED=n
event_stream | while read -r EVENT; do
  if ! echo "$EVENT" | grep -q "PROBE\|METRICS\|config.json"; then
    continue
  fi

  if [ "$EVENT" != "PROBE" ] && [ "$EVENT" != "METRICS" ]; then
    EVENT="CONFIG-CHANGE"
    # Next probe will update the set of visible/used providers
    # (unless QUERY_VISIBLE_PROVIDERS is disabled).
    ENFORCE_LONG_PROBE="y"
  fi

  CONFIG="$(cat "${CONFIG_PATH}" 2>/dev/null)"
  if [ "$EVENT" = "CONFIG-CHANGE" ]; then
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
  VERBOSE="$(parse_json_attr "$CONFIG" "\"verbose\"")"
  QUERY_VISIBLE_PROVIDERS="$(parse_json_attr "$CONFIG" "\"query-visible-providers\"")"

  if [ "$EVENT" = "PROBE" ]; then
    PROBE_ITER="$((PROBE_ITER+1))"
    # Every 20 seconds check the modem connectivity status.
    # Quick probe only checks the status as reported by the modem,
    # without generating any traffic.
    EVENT="QUICK-PROBE"
    if [ "$((PROBE_ITER % 15))" = "0" ] || [ "$STATUS_OUTDATED" = "y" ]; then
      # Every 5 minutes update status.json.
      # Also when QUICK-PROBE changes modem status (e.g. reconnects), next PROBE
      # will be elevated to at least STANDARD-PROBE level.
      # First update is not done immediately but after 5 minutes (PROBE_ITER starts with 1).
      EVENT="STANDARD-PROBE"
    fi
    if [ "$QUERY_VISIBLE_PROVIDERS" = "true" ]; then
      if [ "$((PROBE_ITER % 180))" = "31" ] || [ "$ENFORCE_LONG_PROBE" = "y" ]; then
        # Every 1 hour additionally query the set of visible providers.
        # Also after processing config change, next PROBE will be elevated to LONG-PROBE level.
        # First LONG-PROBE is done after 10 minutes (modulo equals 31; PROBE_ITER starts with 1).
        EVENT="LONG-PROBE"
      fi
    fi
    ENFORCE_LONG_PROBE=n
  fi

  if [ "$VERBOSE" = "true" ]; then
    log_debug Event: "$EVENT"
  fi

  # Avoid periodic events getting backlogged while this one completes.
  suspend_periodic_events "probe"
  suspend_periodic_events "metrics"

  # iterate over each configured cellular network
  while read -r NETWORK; do
    [ -z "$NETWORK" ] && continue
    unset CONFIG_ERROR
    unset PROBE_ERROR
    # Quick probe can be suspended (until Standard probe is reached) when reconnection
    # attempts are not helping to bring the connectivity back. We do not want to trigger
    # modem reconnection so often if it is getting us nowhere.
    unset SUSPEND_QUICKPROBE

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
    SIM_SLOT="$(parse_json_attr "$NETWORK" "\"sim-slot\"")"
    APN="$(parse_json_attr "$NETWORK" "apn")"
    APN="${APN:-$DEFAULT_APN}"
    AUTH_PROTO="$(parse_json_attr "$NETWORK" "\"auth-protocol\"")"
    USERNAME="$(parse_json_attr "$NETWORK" "username")"
    ENC_PASSWORD="$(parse_json_attr "$NETWORK" "\"encrypted-password\"")"
    PREFERRED_PLMNS="$(parse_json_attr "$NETWORK" "\"preferred-plmns\"")"
    PREFERRED_RATS="$(parse_json_attr "$NETWORK" "\"preferred-rats\"")"
    FORBID_ROAMING="$(parse_json_attr "$NETWORK" "\"forbid-roaming\"")"
    LOC_TRACKING="$(parse_json_attr "$NETWORK" "\"location-tracking\"")"

    if ! lookup_modem "${IFACE}" "${USB_ADDR}" "${PCI_ADDR}" 2>/tmp/wwan.stderr; then
      CONFIG_ERROR="$(join_lines_with_semicolon </tmp/wwan.stderr | escape_apostrophe)"
      NETWORK_STATUS="$(json_struct \
        "$(json_str_attr logical-label  "$LOGICAL_LABEL")" \
        "$(json_attr     physical-addrs "$ADDRS")" \
        "$(json_str_attr config-error   "$CONFIG_ERROR")")"
      STATUS="${STATUS}${NETWORK_STATUS}\n"
      if ! grep -q "$CONFIG_ERROR" <"${STATUS_PATH}"; then
        STATUS_OUTDATED=y
      fi
      continue
    fi

    MODEMS="${MODEMS}${CDC_DEV}\n"
    if [ "$VERBOSE" = "true" ]; then
      log_debug "Processing managed modem (event: $EVENT): $CDC_DEV"
    fi

    # Check responsiveness of the control-plane.
    if ! "${PROTOCOL}_is_modem_responsive" 2>/dev/null; then
      CONFIG_ERROR="Modem $LOGICAL_LABEL is not responsive"
      log_debug "$CONFIG_ERROR"
      NETWORK_STATUS="$(json_struct \
        "$(json_str_attr logical-label  "$LOGICAL_LABEL")" \
        "$(json_attr     physical-addrs "$ADDRS")" \
        "$(json_str_attr config-error   "$CONFIG_ERROR")")"
      STATUS="${STATUS}${NETWORK_STATUS}\n"
      if [ "$(get_connection_time)" != "0" ]; then
        bringdown_iface
        STATUS_OUTDATED=y
      fi
      if [ "$EVENT" != "QUICK-PROBE" ] && [ "$EVENT" != "METRICS" ]; then
        reset_modem
        # Do not wait for reset to complete, return back to this modem later
        # (e.g. in the next probing event).
      fi
      continue
    fi

    if switch_to_preferred_proto 2>/dev/null; then
      # Modem is being restarted, return back to it later.
      continue
    fi

    # in status.json and metrics.json print all modem addresses (as found by lookup_modem),
    # not just the ones used in config.json
    ADDRS="$(json_struct \
      "$(json_str_attr interface "$IFACE")" \
      "$(json_str_attr usb       "$USB_ADDR")" \
      "$(json_str_attr pci       "$PCI_ADDR")" \
      "$(json_str_attr dev       "$CDC_DEV")")"

    if [ "$EVENT" = "METRICS" ]; then
      collect_network_metrics 2>/dev/null
      continue
    fi

    if [ "$LOC_TRACKING" = "true" ]; then
      LOC_TRACKING_DEV="$CDC_DEV"
      LOC_TRACKING_PROTO="$PROTOCOL"
      LOC_TRACKING_LL="$LOGICAL_LABEL"
    fi

    if [ "$EVENT" = "QUICK-PROBE" ] && is_quickprobe_suspended; then
      if sim_card_status_changed; then
        log_debug "[$CDC_DEV] Quick-probe is suspended but SIM card status changed"
      else
        [ "$VERBOSE" = "true" ] && log_debug "[$CDC_DEV] Quick-probe is suspended"
        continue
      fi
    fi

    # reflect updated config or just probe the current status
    if [ "$RADIO_SILENCE" != "true" ]; then
      DP_STUCK="n"
      if [ "$EVENT" = "CONFIG-CHANGE" ] || ! check_connectivity "$EVENT"; then
        if [ "$(get_connection_time)" != "0" ]; then
          bringdown_iface
          # Connectivity just stopped working or config changed.
          # Ensure that status.json is updated during this event or by the next probe.
          STATUS_OUTDATED=y
        fi
        if [ "$DP_STUCK" = "y" ]; then
            if [ "$EVENT" != "QUICK-PROBE" ]; then
              # Reset modem to recover
              bringdown_iface
              reset_modem
            fi
            NETWORK_STATUS="$(json_struct \
                    "$(json_str_attr logical-label  "$LOGICAL_LABEL")" \
                    "$(json_attr     physical-addrs "$ADDRS")" \
                    "$(json_str_attr probe-error    "$PROBE_ERROR")")"
            STATUS="${STATUS}${NETWORK_STATUS}\n"
            continue
        fi
        if [ -n "$USERNAME" ]; then
          log_debug "[$CDC_DEV] Restarting connection (NETWORK=${LOGICAL_LABEL}, APN=${APN}, " \
               "username=${USERNAME}, auth-proto=${AUTH_PROTO})"
          # Try to decrypt user password.
          if ! PASSWORD="$(decryptpasswd "$ENC_PASSWORD" 2>/tmp/wwan.stderr)"; then
            CONFIG_ERROR="$(join_lines_with_semicolon </tmp/wwan.stderr | escape_apostrophe)"
            NETWORK_STATUS="$(json_struct \
                    "$(json_str_attr logical-label  "$LOGICAL_LABEL")" \
                    "$(json_attr     physical-addrs "$ADDRS")" \
                    "$(json_str_attr config-error   "$CONFIG_ERROR")")"
            STATUS="${STATUS}${NETWORK_STATUS}\n"
            continue
          fi
        else
          log_debug "[$CDC_DEV] Restarting connection (NETWORK=${LOGICAL_LABEL}, APN=${APN})"
        fi
        {
          bringdown_iface                  &&\
          "${PROTOCOL}_stop_network"       &&\
          "${PROTOCOL}_toggle_rf" on       &&\
          "${PROTOCOL}_wait_for_sim"       &&\
          "${PROTOCOL}_wait_for_register"  &&\
          "${PROTOCOL}_start_network"      &&\
          "${PROTOCOL}_wait_for_wds"       &&\
          "${PROTOCOL}_wait_for_ip_config" &&\
          bringup_iface                    &&\
          STATUS_OUTDATED=y                &&\
          log_debug "[$CDC_DEV] Connection successfully restarted (NETWORK=${LOGICAL_LABEL})"
        } 2>/tmp/wwan.stderr
        RV=$?
        if [ $RV -ne 0 ]; then
          CONFIG_ERROR="$(sort -u < /tmp/wwan.stderr | join_lines_with_semicolon | escape_apostrophe)"
          CONFIG_ERROR="${CONFIG_ERROR:-(Re)Connection attempt failed with rv=$RV}"
          # Avoid frequent reconnection attempts by disabling quick probe until Standard
          # or Long probe fixes the current connection problem.
          # Suspend is bypassed only if we detect change in the SIM card status
          # (e.g. SIM card was inserted, replaced, etc.).
          SUSPEND_QUICKPROBE="true"
        fi
        # retry probe to update PROBE_ERROR
        if [ "$EVENT" != "QUICK-PROBE" ]; then
          sleep 3
          if ! check_connectivity "$EVENT"; then
            SUSPEND_QUICKPROBE="true"
          fi
        fi
      fi
    else # Radio-silence is ON
      if [ "$("${PROTOCOL}_get_op_mode")" != "radio-off" ]; then
        log_debug "[$CDC_DEV] Trying to disable radio (network=${LOGICAL_LABEL})"
        STATUS_OUTDATED=y
        if ! "${PROTOCOL}_toggle_rf" off 2>/tmp/wwan.stderr; then
          CONFIG_ERROR="$(join_lines_with_semicolon </tmp/wwan.stderr | escape_apostrophe)"
        else
          if ! wait_for 3 radio-off "${PROTOCOL}_get_op_mode"; then
            CONFIG_ERROR="Timeout waiting for radio to turn off"
          else
            bringdown_iface
          fi
        fi
      fi
    fi

    if [ "$EVENT" != "QUICK-PROBE" ]; then
      collect_network_status "$EVENT"
    fi
  done <<__EOT__
  $(echo "$CONFIG" | jq -c '.networks[]' 2>/dev/null)
__EOT__

  # Start/stop location tracking.
  if [ "$EVENT" = "CONFIG-CHANGE" ]; then
    if [ -n "$LOC_TRACKING_DEV" ]; then
      if [ -z "$LOC_TRACKER" ]; then
        location_tracking "${LOC_TRACKING_LL}" "${LOC_TRACKING_DEV}"\
                          "${LOC_TRACKING_PROTO}" "${LOCINFO_PATH}" &
        LOC_TRACKER=$!
      fi
    else
      if [ -n "$LOC_TRACKER" ]; then
        kill_process_tree $LOC_TRACKER >/dev/null 2>&1
        log_debug "Location tracking was stopped (parent process: $LOC_TRACKER)"
        unset LOC_TRACKER
      fi
    fi
  fi

  # manage RF state also for modems not configured by the controller
  for DEV in /sys/class/usbmisc/*; do
    unset CONFIG_ERROR
    unset PROBE_ERROR
    unset LOGICAL_LABEL # unmanaged modems do not have logical name
    unset SUSPEND_QUICKPROBE

    PROTOCOL="$(sys_get_modem_protocol "$DEV")" || continue
    CDC_DEV="$(basename "${DEV}")"
    if printf "%b" "$MODEMS" | grep -q "^$CDC_DEV$"; then
      # this modem has configuration and was already processed
      continue
    fi
    if [ "$VERBOSE" = "true" ]; then
      log_debug "Processing unmanaged modem (event: $EVENT): $CDC_DEV"
    fi
    IFACE=$(sys_get_modem_interface "$DEV")
    USB_ADDR=$(sys_get_modem_usbaddr "$DEV")
    PCI_ADDR=$(sys_get_modem_pciaddr "$DEV")
    ADDRS="$(json_struct \
        "$(json_str_attr interface "$IFACE")" \
        "$(json_str_attr usb       "$USB_ADDR")" \
        "$(json_str_attr pci       "$PCI_ADDR")" \
        "$(json_str_attr dev       "$CDC_DEV")")"

    if [ "$EVENT" = "METRICS" ]; then
      collect_network_metrics 2>/dev/null
      continue
    fi

    if [ "$(get_connection_time)" != "0" ]; then
      bringdown_iface
      STATUS_OUTDATED=y
    fi

    if [ "$("${PROTOCOL}_get_op_mode")" != "radio-off" ]; then
      log_debug "[$CDC_DEV] Trying to disable radio"
      STATUS_OUTDATED=y
      if ! "${PROTOCOL}_toggle_rf" off 2>/tmp/wwan.stderr; then
        CONFIG_ERROR="$(join_lines_with_semicolon </tmp/wwan.stderr | escape_apostrophe)"
      else
        if ! wait_for 3 radio-off "${PROTOCOL}_get_op_mode"; then
          CONFIG_ERROR="Timeout waiting for radio to turn off"
        fi
      fi
    fi

    if [ "$EVENT" != "QUICK-PROBE" ]; then
      collect_network_status "$EVENT"
    fi
  done

  # No blocking operations below this point.
  release_periodic_events "probe"
  release_periodic_events "metrics"

  # Do not update status.json during a quick probe, continue with the next event..
  if [ "$EVENT" = "QUICK-PROBE" ]; then
    continue
  fi

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
    STATUS_OUTDATED=n
  fi
done
