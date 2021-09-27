#!/bin/sh
# shellcheck disable=SC2039
# shellcheck disable=SC2155

uqmi() {
  local JSON
  if JSON="$(timeout -s KILL "$LTESTAT_TIMEOUT" uqmi -d "/dev/$CDC_DEV" "$@")"; then
    if echo "$JSON" | jq -ea . > /dev/null 2>&1; then
      echo "$JSON"
      return 0
    fi
  fi
  return 1
}

# We prefer to use uqmi over qmicli as a CLI agent for QMI devices.
# However, some fields are available for retrieval only with qmicli.
qmicli() {
  timeout -s KILL "$LTESTAT_TIMEOUT" qmicli -d "/dev/$CDC_DEV" "$@"
}

qmi_get_packet_stats() {
  local STATS="$(qmicli --wds-get-packet-statistics)"
  local TXP=$(parse_modem_attr "$STATS" "TX packets OK")
  local TXB=$(parse_modem_attr "$STATS" "TX bytes OK")
  local TXD=$(parse_modem_attr "$STATS" "TX packets dropped")
  local RXP=$(parse_modem_attr "$STATS" "RX packets OK")
  local RXB=$(parse_modem_attr "$STATS" "RX bytes OK")
  local RXD=$(parse_modem_attr "$STATS" "RX packets dropped")
  json_struct \
    "$(json_attr tx-bytes "${TXB:-0}")" "$(json_attr tx-packets "${TXP:-0}")" "$(json_attr tx-drops "${TXD:-0}")" \
    "$(json_attr rx-bytes "${RXB:-0}")" "$(json_attr rx-packets "${RXP:-0}")" "$(json_attr rx-drops "${RXD:-0}")"
}

qmi_get_signal_info() {
  local INFO
  INFO="$(uqmi --get-signal-info)" || INFO="{}"
  FILTER="{rssi: (if .rssi == null then $UNAVAIL_SIGNAL_METRIC else .rssi end),
           rsrq: (if .rsrq == null then $UNAVAIL_SIGNAL_METRIC else .rsrq end),
           rsrp: (if .rsrp == null then $UNAVAIL_SIGNAL_METRIC else .rsrp end),
           snr:  (if .snr  == null then $UNAVAIL_SIGNAL_METRIC else .snr end)}"
  echo "$INFO" | jq -c "$FILTER"
}

# qmi_get_op_mode returns one of: "" (aka unspecified), "online", "online-and-connected", "radio-off", "offline", "unrecognized"
qmi_get_op_mode() {
  local OP_MODE="$(qmicli --dms-get-operating-mode | sed -n "s/\s*Mode: '\(.*\)'/\1/p")"
  case "$OP_MODE" in
    "online")
      if [ "$(uqmi --get-data-status)" = '"connected"' ]; then
        echo "online-and-connected"
      else
        echo "online"
      fi
    ;;
    "offline") echo "$OP_MODE"
    ;;
    "low-power" | "persistent-low-power" | "mode-only-low-power") echo "radio-off"
    ;;
    *) echo "unrecognized"
    ;;
  esac
}

qmi_get_imei() {
  uqmi --get-imei | tr -d '"'
}

qmi_get_modem_model() {
  qmicli --dms-get-model | sed -n "s/\s*Model: '\(.*\)'/\1/p"
}

qmi_get_modem_revision() {
  qmicli --dms-get-revision | sed -n "s/\s*Revision: '\(.*\)'/\1/p"
}

qmi_get_providers() {
  local PROVIDERS
  if ! PROVIDERS="$(uqmi --network-scan)"; then
    echo "[]"
    return 1
  fi
  FILTER='[.network_info[] | { "plmn": [if .mcc == null then "000" else .mcc end, if .mnc == null then "000" else .mnc end] | join("-"),
                               "description": .description,
                               "current-serving": .status | contains(["current_serving"]),
                               "roaming":  .status | contains(["roaming"])}
          ] | unique'
  echo "$PROVIDERS" | jq -c "$FILTER"
}

get_get_sim_iccid() {
  local OUTPUT
  # Get ICCID from User Identity Module (UIM).
  # Please refer to ETSI/3GPP "TS 102 221" section 13.2 for the coding of this EF.
  if ! OUTPUT="$(qmicli --uim-read-transparent=0x3F00,0x2FE2)"; then
    return 1
  fi
  printf "%s" "$OUTPUT" | awk '
    BEGIN{FS=":"; ORS=""}
    /Read result:/ {target=NR+1}
    (NR==target) {
      for(i=1; i<=NF; i++) {
        gsub(/[ \tF]*/,"",$i);
        # Each byte contains 2 digits.
        # First digit of each pair is encoded by the less significant half of the byte.
        # For digits to be read from left to right, they need to be swapped.
        print substr($i, 2, 1);
        print substr($i, 1, 1);
      }
    }'
}

get_get_sim_imsi() {
  local OUTPUT
  # Get IMSI from User Identity Module (UIM).
  # Please refer to ETSI/3GPP "TS 31.102" section 4.2.2 for the coding of this EF.
  if ! OUTPUT="$(qmicli --uim-read-transparent=0x3F00,0x7FFF,0x6F07)"; then
    return 1
  fi
  printf "%s" "$OUTPUT" | awk '
    BEGIN{FS=":"; ORS=""}
    /Read result:/ {target=NR+1}
    (NR==target) {
      # We skip the first byte (starting with i=2) containing the IMSI length.
      for(i=2; i<=NF; i++) {
        gsub(/[ \tF]*/,"",$i);
        # Each byte contains 2 digits.
        # First digit of each pair is encoded by the less significant half of the byte.
        # For digits to be read from left to right, they need to be swapped.
        # Also, we skip the third digit (first substr for i=2) with parity check.
        if (i>2) print substr($i, 2, 1);
        print substr($i, 1, 1);
      }
    }'
}

qmi_get_sim_cards() {
  # FIXME XXX Limited to a single SIM card
  if ! ICCID="$(get_get_sim_iccid)"; then
    echo "[]"
    return 1
  fi
  if ! IMSI="$(get_get_sim_imsi)"; then
    echo "[]"
    return 1
  fi
  SIM="$(json_struct "$(json_str_attr "iccid" "$ICCID")" "$(json_str_attr "imsi" "$IMSI")")\n"
  printf "%b" "$SIM" | json_array
}

qmi_start_network() {
  echo "[$CDC_DEV] Starting network for APN ${APN}"
  ip link set "$IFACE" down
  echo Y > "/sys/class/net/$IFACE/qmi/raw_ip"
  ip link set "$IFACE" up

  uqmi --sync
  uqmi --start-network --apn "${APN}" --keep-client-id wds |\
      mbus_publish "pdh_$IFACE"
}

qmi_wait_for_sim() {
  # FIXME XXX this is only for MBIM for now
  :
}

qmi_wait_for_wds() {
  echo "[$CDC_DEV] Waiting for DATA services to connect"
  local CMD="uqmi --get-data-status | jq -r ."

  if ! wait_for connected "$CMD"; then
    echo "Timeout waiting for DATA services to connect" >&2
    return 1
  fi
}

qmi_wait_for_register() {
  echo "[$CDC_DEV] Waiting for the device to register on the network"
  local CMD="uqmi --get-serving-system | jq -r .registration"

  if ! wait_for registered "$CMD"; then
    echo "Timeout waiting for the device to register on the network" >&2
    return 1
  fi
}

qmi_wait_for_settings() {
  echo "[$CDC_DEV] Waiting for IP configuration for the $IFACE interface"
  local CMD="uqmi --get-current-settings"

  if ! wait_for connected "$CMD | jq -r .ipv4.ip | grep -q \"$IPV4_REGEXP\" && echo connected"; then
    echo "Timeout waiting for IP configuration for the $IFACE interface" >&2
    return 1
  fi
}

qmi_reset_modem() {
  # last ditch attempt to reset our modem -- not sure how effective :-(
  local PDH="$(cat "${BBS}/pdh_${IFACE}.json" 2>/dev/null)"

  for i in "$PDH" 0xFFFFFFFF ; do
    uqmi --stop-network "$i" --autoconnect || continue
  done

  qmicli --dms-reset

  for i in "$PDH" 0xFFFFFFFF ; do
    uqmi --stop-network "$i" --autoconnect || continue
  done
}

qmi_toggle_rf() {
  if [ "$1" = "off" ]; then
    echo "[$CDC_DEV] Disabling RF"
    uqmi --set-device-operating-mode "persistent_low_power"
  else
    echo "[$CDC_DEV] Enabling RF"
    uqmi --set-device-operating-mode "online"
  fi
}
