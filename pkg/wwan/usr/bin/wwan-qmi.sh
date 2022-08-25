#!/bin/sh
# shellcheck disable=SC2039
# shellcheck disable=SC2155
# shellcheck disable=SC2034

qmi() {
  timeout -s KILL "$LTESTAT_TIMEOUT" qmicli -p -d "/dev/$CDC_DEV" "$@"
}

qmi_get_packet_stats() {
  local STATS="$(qmi --wds-get-packet-statistics)"
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
  local INFO="$(qmi --nas-get-signal-info)"
  local RSSI="$(parse_modem_attr "$INFO" "RSSI" " dBm")"
  local RSRQ="$(parse_modem_attr "$INFO" "RSRQ" " dB")"
  local RSRP="$(parse_modem_attr "$INFO" "RSRP" " dBm")"
  local SNR="$(parse_modem_attr "$INFO"  "SNR"  " dB")"
  # SNR is published with one decimal place.
  # Round it to the nearest integer.
  if [ -n "$SNR" ]; then
    SNR="$(printf "%.0f" "$SNR")"
  fi
  json_struct \
    "$(json_attr rssi "${RSSI:-$UNAVAIL_SIGNAL_METRIC}")" \
    "$(json_attr rsrq "${RSRQ:-$UNAVAIL_SIGNAL_METRIC}")" \
    "$(json_attr rsrp "${RSRP:-$UNAVAIL_SIGNAL_METRIC}")" \
    "$(json_attr snr  "${SNR:-$UNAVAIL_SIGNAL_METRIC}")"
}

qmi_get_packet_state() {
  qmi --wds-get-packet-service-status | sed -n "s/.*Connection status: '\(.*\)'/\1/p"
}

# qmi_get_op_mode returns one of: "" (aka unspecified), "online", "online-and-connected", "radio-off", "offline", "unrecognized"
qmi_get_op_mode() {
  local OP_MODE="$(parse_modem_attr "$(qmi --dms-get-operating-mode)" "Mode")"
  case "$OP_MODE" in
    "online")
      if [ "$(qmi_get_packet_state)" = "connected" ]; then
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
  parse_modem_attr "$(qmi --dms-get-ids)" "IMEI"
}

qmi_get_modem_model() {
  parse_modem_attr "$(qmi --dms-get-model)" "Model"
}

qmi_get_modem_revision() {
  parse_modem_attr "$(qmi --dms-get-revision)" "Revision"
}

qmi_get_serving_system() {
  local INFO="$(qmi --nas-get-serving-system)"
  local REGSTATE="$(parse_modem_attr "$INFO" "Registration state")"
  if [ "$REGSTATE" != "registered" ]; then
    return 1
  fi
  local MCC="$(parse_modem_attr "$INFO" "MCC")"
  local MNC="$(parse_modem_attr "$INFO" "MNC")"
  local DESCRIPTION="$(parse_modem_attr "$INFO" "Description")"
  local ROAMING="$(parse_modem_attr "$INFO"  "Roaming status")"
  local PLMN="$(printf "%03d-%02d" "$MCC" "$MNC" 2>/dev/null)"
  if [ "$ROAMING" = "on" ]; then
    ROAMING="true"
  else
    ROAMING="false"
  fi
  json_struct \
    "$(json_str_attr plmn "${PLMN}")" \
    "$(json_str_attr description "${DESCRIPTION}")" \
    "$(json_attr current-serving "true")" \
    "$(json_attr roaming "${ROAMING}")"
}

qmi_get_providers() {
  local PROVIDERS
  if ! PROVIDERS="$(qmi --nas-network-scan)"; then
    # Alternative to listing all providers is to return info at least
    # for the current provider.
    SERVING="$(qmi_get_serving_system)"
    printf "[%b]" "$SERVING"
    return
  fi
  if ! echo "$PROVIDERS"  | grep -q "Network \[[0-9]\+\]"; then
    # Network scan was most likely aborted with output:
    #  Network scan result: abort
    SERVING="$(qmi_get_serving_system)"
    printf "[%b]" "$SERVING"
    return
  fi
  echo "$PROVIDERS" | awk '
    BEGIN{RS="Network [[0-9]+]:"; FS="\n"; print "["}
    $0 ~ /Status: / {
      print sep_outer "{"
      sep_inner=""
      mcc=""
      mnc=""
      for(i=1; i<=NF; i++) {
        kv=""
        if ($i~/MCC:/) {
          mcc = gensub(/.*: \x27(.*)\x27/, "\\1", 1, $i)
        }
        if ($i~/MNC:/) {
          mnc = gensub(/.*: \x27(.*)\x27/, "\\1", 1, $i)
        }
        if ($i~/Description:/) {
          kv = gensub(/.*: \x27(.*)\x27/, "\"description\": \"\\1\"", 1, $i)
        }
        if ($i~/Status:/) {
          current="false"
          roaming="false"
          if ($i~/current-serving/) current="true"
          if ($i~/roaming/) roaming="true"
          kv="\"current-serving\":" current ",\"roaming\":" roaming
        }
        if (kv) {
          print sep_inner kv
          sep_inner=","
        }
      }
      if (mcc && mnc) {
        printf "%s \"plmn\": \"%03d-%02d\"", sep_inner, mcc, mnc
      }
      print "}"
      sep_outer=","
    }
    END{print "]"}' | jq -c "unique"
}

qmi_get_sim_iccid() {
  local OUTPUT
  # Get ICCID from User Identity Module (UIM).
  # Please refer to ETSI/3GPP "TS 102 221" section 13.2 for the coding of this EF.
  if ! OUTPUT="$(qmi --uim-read-transparent=0x3F00,0x2FE2)"; then
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

qmi_get_sim_imsi() {
  local OUTPUT
  # Get IMSI from User Identity Module (UIM).
  # Please refer to ETSI/3GPP "TS 31.102" section 4.2.2 for the coding of this EF.
  if ! OUTPUT="$(qmi --uim-read-transparent=0x3F00,0x7FFF,0x6F07)"; then
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
  if ! ICCID="$(qmi_get_sim_iccid)"; then
    echo "[]"
    return 1
  fi
  if ! IMSI="$(qmi_get_sim_imsi)"; then
    echo "[]"
    return 1
  fi
  SIM="$(json_struct "$(json_str_attr "iccid" "$ICCID")" "$(json_str_attr "imsi" "$IMSI")")\n"
  printf "%b" "$SIM" | json_array
}

qmi_get_ip_settings() {
  if ! SETTINGS="$(qmi --wds-get-current-settings)"; then
    return 1
  fi
  IP=$(parse_modem_attr "$SETTINGS" "IPv4 address")
  SUBNET=$(parse_modem_attr "$SETTINGS" "IPv4 subnet mask")
  GW=$(parse_modem_attr "$SETTINGS" "IPv4 gateway address")
  DNS1=$(parse_modem_attr "$SETTINGS" "IPv4 primary DNS")
  DNS2=$(parse_modem_attr "$SETTINGS" "IPv4 secondary DNS")
  MTU=$(parse_modem_attr "$SETTINGS" "MTU")
}

qmi_start_network() {
  echo "[$CDC_DEV] Starting network for APN ${APN}"
  ip link set "$IFACE" down
  echo Y > "/sys/class/net/$IFACE/qmi/raw_ip"
  ip link set "$IFACE" up

  qmi --wds-reset
  if ! OUTPUT="$(qmi --wds-start-network="ip-type=4,apn=${APN}" --client-no-release-cid)"; then
    return 1
  fi

  parse_modem_attr "$OUTPUT" "Packet data handle" | mbus_publish "pdh_$IFACE"
  parse_modem_attr "$OUTPUT" "CID" | mbus_publish "cid_$IFACE"
}

qmi_get_sim_status() {
  # FIXME: limited to a single SIM card
  parse_modem_attr "$(qmi --uim-get-card-status)" "Application state" | head -n 1
}

qmi_wait_for_sim() {
  echo "[$CDC_DEV] Waiting for SIM card to initialize"
  local CMD="qmi_get_sim_status"

  if ! wait_for ready "$CMD"; then
    echo "Timeout waiting for SIM initialization" >&2
    return 1
  fi
}

qmi_wait_for_wds() {
  echo "[$CDC_DEV] Waiting for DATA services to connect"
  local CMD="qmi_get_packet_state"

  if ! wait_for connected "$CMD"; then
    echo "Timeout waiting for DATA services to connect" >&2
    return 1
  fi
}

qmi_get_registration_status() {
  parse_modem_attr "$(qmi --nas-get-serving-system)" "Registration state"
}

qmi_wait_for_register() {
  # Make sure we are registering with the right APN.
  # Some LTE networks require explicit (and correct) APN for the registration/attach
  # procedure (for the initial EPS bearer activation).
  local PROFILE="$(qmi --wds-get-default-profile-num=3gpp)"
  local PROFILE_NUM="$(parse_modem_attr "$PROFILE" "Default profile number")"
  qmi --wds-modify-profile="3gpp,${PROFILE_NUM},apn=${APN}"

  echo "[$CDC_DEV] Waiting for the device to register on the network"
  local CMD="qmi_get_registration_status"

  if ! wait_for registered "$CMD"; then
    echo "Timeout waiting for the device to register on the network" >&2
    return 1
  fi
}

qmi_get_ip_address() {
  parse_modem_attr "$(qmi --wds-get-current-settings)" "IPv4 address"
}

qmi_wait_for_settings() {
  echo "[$CDC_DEV] Waiting for IP configuration for the $IFACE interface"
  local CMD="qmi_get_ip_address | grep -q \"$IPV4_REGEXP\" && echo connected"

  if ! wait_for connected "$CMD"; then
    echo "Timeout waiting for IP configuration for the $IFACE interface" >&2
    return 1
  fi
}

qmi_stop_network() {
  local PDH="$(cat "${BBS}/pdh_${IFACE}.json" 2>/dev/null)"
  local CID="$(cat "${BBS}/cid_${IFACE}.json" 2>/dev/null)"

  if ! qmi --wds-stop-network="$PDH" --client-cid="$CID"; then
    # If qmicli failed to stop the network, reset operating mode of the modem.
    qmi --dms-set-operating-mode=low-power
    sleep 1
    qmi --dms-set-operating-mode=online
  fi
}

qmi_toggle_rf() {
  if [ "$1" = "off" ]; then
    echo "[$CDC_DEV] Disabling RF"
    qmi --dms-set-operating-mode=persistent-low-power
  else
    echo "[$CDC_DEV] Enabling RF"
    qmi --dms-set-operating-mode=online
  fi
}
