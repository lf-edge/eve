#!/bin/sh
# shellcheck disable=SC2039
# shellcheck disable=SC2155
# shellcheck disable=SC2034

qmi() {
  if [ "$VERBOSE" = "true" ]; then
    # Do not log user password.
    local FILTERED_ARGS
    FILTERED_ARGS="$(echo "$@" | sed "s/password='\([^']*\)'/password='***'/g")"
    log_debug Running: qmicli -p -d "/dev/$CDC_DEV" "$FILTERED_ARGS"
  fi
  local OUTPUT
  local RV
  OUTPUT="$(timeout -s INT -k 5 "$CMD_TIMEOUT" \
    qmicli -p -d "/dev/$CDC_DEV" "$@" 2>/tmp/qmicli.stderr)"
  RV=$?
  if [ "$VERBOSE" = "true" ]; then
    log_debug qmicli output: "$OUTPUT"
    [ -s /tmp/qmicli.stderr ] && log_debug qmicli error: "$(cat /tmp/qmicli.stderr)"
    log_debug qmicli RV: "$RV"
  fi
  echo "$OUTPUT"
  cat /tmp/qmicli.stderr 1>&2
  return $RV
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
  local RV=$?
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
  return $RV
}

# Possible states are: unknown, disconnected, connected, suspended, authenticating
qmi_get_connection_state() {
  qmi --wds-get-packet-service-status | sed -n "s/.*Connection status: '\(.*\)'/\1/p"
}

# qmi_get_op_mode returns one of: "" (aka unspecified), "online", "online-and-connected",
# "radio-off", "offline", "unrecognized"
qmi_get_op_mode() {
  local OP_MODE="$(parse_modem_attr "$(qmi --dms-get-operating-mode)" "Mode")"
  case "$OP_MODE" in
    "online")
      if [ "$(qmi_get_connection_state)" = "connected" ]; then
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

qmi_get_modem_manufacturer() {
  parse_modem_attr "$(qmi --dms-get-manufacturer)" "Manufacturer"
}

qmi_get_current_provider() {
  local INFO="$(qmi --nas-get-serving-system)"
  local REGSTATE="$(parse_modem_attr "$INFO" "Registration state")"
  if [ "$REGSTATE" != "registered" ] && [ "$REGSTATE" != "registration-denied" ]; then
    echo "{}"
    return 1
  fi
  local MCC="$(parse_modem_attr "$INFO" "MCC")"
  local MNC="$(parse_modem_attr "$INFO" "MNC")"
  local PLMN="$(printf "%03d-%02d" "$MCC" "$MNC" 2>/dev/null)"
  local DESCRIPTION="$(parse_modem_attr "$INFO" "Description")"
  local ROAMING="$(parse_modem_attr "$INFO" "Roaming status" | onoff_to_bool)"
  local FORBIDDEN="$(parse_modem_attr "$INFO" "Forbidden" | yesno_to_bool)"
  json_struct \
    "$(json_str_attr plmn "${PLMN}")" \
    "$(json_str_attr description "${DESCRIPTION}")" \
    "$(json_attr current-serving "true")" \
    "$(json_attr roaming "${ROAMING}")" \
    "$(json_attr forbidden "${FORBIDDEN}")"
}

qmi_get_providers() {
  local PROVIDERS
  if [ "$(qmi_get_op_mode)" = "radio-off" ]; then
    # With radio off, an attempt to list visible providers would fail and log error.
    echo "[]"
    return
  fi
  if ! PROVIDERS="$(CMD_TIMEOUT=120 qmi --nas-network-scan)"; then
    # Alternative to listing all providers is to return info at least
    # for the current provider.
    if SERVING="$(qmi_get_current_provider)"; then
      printf "[%b]" "$SERVING"
    else
      echo "[]"
    fi
    return
  fi
  if ! echo "$PROVIDERS"  | grep -q "Network \[[0-9]\+\]"; then
    # Network scan was most likely aborted with output:
    #  Network scan result: abort
    if SERVING="$(qmi_get_current_provider)"; then
      printf "[%b]" "$SERVING"
    else
      echo "[]"
    fi
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
          forbidden="true"
          if ($i~/current-serving/) current="true"
          if ($i~/roaming/) roaming="true"
          if ($i~/not-forbidden/) forbidden="false"
          kv="\"current-serving\":" current ",\"roaming\":" roaming ",\"forbidden\":" forbidden
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

qmi_get_currently_used_rats() {
  local INFO
  if ! INFO="$(qmi --nas-get-serving-system)"; then
    echo "[]"
    return
  fi
  echo "$INFO" | awk '
    /Radio interfaces:/ {
      getline
      while ($1 ~ /\[[0-9]+\]:/) {
        gsub(/'\''/, "", $2)
        if ($2 != "none") {
          rats = rats "\"" $2 "\","
        }
        getline
      }
    }
    END {
      sub(/,$/, "", rats)
      printf "[%s]", rats
    }'
}

qmi_get_all_sim_slots() {
  local STATUS
  if ! STATUS="$(qmi --uim-get-slot-status)"; then
    # if uim-get-slot-status fails, then the modem has most likely only one slot.
    echo "1"
    return 0
  fi
  echo "$STATUS" | awk '
    /Physical slot/ { slot_index = gensub(/([0-9]+).*/, "\\1", 1, $3); print slot_index }'
}

qmi_get_active_sim_slot() {
  local STATUS
  if ! STATUS="$(qmi --uim-get-slot-status)"; then
    # if uim-get-slot-status fails, then the modem has most likely only one slot
    # (and it cannot be deactivated).
    echo "1"
    return 0
  fi
  local SLOT="$(echo "$STATUS" | awk '
    /Physical slot/ { slot_index = gensub(/([0-9]+).*/, "\\1", 1, $3) }
    /Slot status: active/ { print slot_index }')"
  local SLOT="${SLOT:-1}"
  echo "$SLOT"
}

qmi_check_sim_card_presence() {
  local SLOT="$1"
  local STATUS
  local STATE
  if STATUS="$(qmi --uim-get-card-status)"; then
    STATE="$(echo "$STATUS" | awk '
      /^Slot \[[0-9]+\]:/ {
        slot_index = substr($2, 2, length($2) - 3)
      }
      /Card state:/ && slot_index == "'"$SLOT"'" {
        gsub(/'\''/, "", $3)
        print $3
      }')"
  else
    # Card status not available, try to get slot status.
    STATUS="$(qmi --uim-get-slot-status)"
    STATE="$(echo "$STATUS" | awk '
      /Physical slot/ { slot_index = $3 }
      /Card status:/ && slot_index == "'"$SLOT"':" { print $3 }')"
  fi
  [ "$STATE" = "present" ] && return 0 || return 1
}

qmi_get_sim_state() {
  local SLOT="$1"
  local ACTIVE_SLOT="$(qmi_get_active_sim_slot)"
  if [ -z "$SLOT" ]; then
    SLOT="$ACTIVE_SLOT"
  fi
  if ! qmi_check_sim_card_presence "$SLOT"; then
    echo "absent"
    return
  fi
  if [ "$SLOT" != "$ACTIVE_SLOT" ]; then
    echo "inactive"
    return
  fi
  local STATUS="$(qmi --uim-get-card-status)"
  # Possible values obtained below: unknown, detected, pin1-or-upin-pin-required,
  # puk1-or-upin-puk-required, check-personalization-state, pin1-blocked, illegal, ready
  local STATE="$(echo "$STATUS" | awk '
    /\s*Primary GW/ {
      slot = gensub(/.*slot \x27([0-9]+)\x27.*/, "\\1", 1)
      app = gensub(/.*application \x27([0-9]+)\x27.*/, "\\1", 1)
    }
    /^Slot/ {
      current_slot = gensub(/^Slot \[([0-9]+)\].*/, "\\1", 1)
    }
    /\s*Application \[[0-9]+\]:/ {
      current_app = gensub(/\s*Application \[([0-9]+)\].*/, "\\1", 1)
    }
    /\s*Application state:/ && slot == current_slot && app == current_app {
      gsub(/\x27/, "", $3); print $3
    }')"
  STATE="${STATE:-"unknown"}"
  echo "$STATE"
}

# Get ICCID of the currently active SIM card.
# It is not supported (and likely not even possible) to obtain ICCIDs of SIM
# cards inside inactive slots.
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
  local SIMS
  local ACTIVE_SLOT="$(qmi_get_active_sim_slot)"
  for SLOT in $(qmi_get_all_sim_slots); do
    local ICCID=""
    local IMSI=""
    local STATE="$(qmi_get_sim_state "$SLOT")"
    local ACTIVATED="false"
    if [ "$SLOT" = "$ACTIVE_SLOT" ]; then
      ACTIVATED="true"
      ICCID="$(qmi_get_sim_iccid)"
      IMSI="$(qmi_get_sim_imsi)"
    fi
    local SIM_STATUS="$(json_struct \
      "$(json_attr     slot-number    "$SLOT")" \
      "$(json_attr     slot-activated "$ACTIVATED")" \
      "$(json_str_attr iccid          "$ICCID")" \
      "$(json_str_attr imsi           "$IMSI")" \
      "$(json_str_attr state          "$STATE")")"
    SIMS="${SIMS}${SIM_STATUS}\n"
  done
  printf "%b" "$SIMS" | json_array
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
  log_debug "[$CDC_DEV] Starting network for APN ${APN}"
  ip link set "$IFACE" down
  echo Y > "/sys/class/net/$IFACE/qmi/raw_ip"
  ip link set "$IFACE" up
  qmi --wds-reset
  local ARGS="ip-type=4,apn='${APN}'"
  if [ -n "$USERNAME" ]; then
    local PROTO
    case "$AUTH_PROTO" in
      "") PROTO="none"
      ;;
      "pap-and-chap") PROTO="both"
      ;;
      *) PROTO="$AUTH_PROTO"
      ;;
    esac
    ARGS="$ARGS,username='${USERNAME}',password='${PASSWORD}',auth='${PROTO}'"
  fi
  if ! OUTPUT="$(qmi --wds-start-network="$ARGS" --client-no-release-cid)"; then
    return 1
  fi
  parse_modem_attr "$OUTPUT" "Packet data handle" | mbus_publish "pdh_$IFACE"
  parse_modem_attr "$OUTPUT" "CID" | mbus_publish "cid_$IFACE"
}

qmi_switch_to_selected_slot() {
  if [ -n "$SIM_SLOT" ] && [ "$SIM_SLOT" != "0" ]; then
    if [ "$(qmi_get_active_sim_slot)" != "$SIM_SLOT" ]; then
      if ! qmi --uim-switch-slot="$SIM_SLOT"; then
        log_error "Failed to switch to SIM slot $SIM_SLOT"
        return 1
      fi
      if ! wait_for 3 "$SIM_SLOT" qmi_get_active_sim_slot; then
        log_error "Timeout waiting for modem to switch to SIM slot $SIM_SLOT"
        return 1
      fi
      # Give modem some time to update the SIM state.
      sleep 3
    fi
  fi
}

qmi_wait_for_sim() {
  # Switch to the correct SIM slot first.
  if ! qmi_switch_to_selected_slot; then
    return 1
  fi
  log_debug "[$CDC_DEV] Waiting for SIM card to initialize"
  # Do not wait if SIM is blocked or absent.
  local CMD="qmi_get_sim_state | grep -qE '(ready|absent|required|blocked|illegal)' && echo 'done'"
  if ! wait_for 3 "done" "$CMD"; then
    log_error "Timeout waiting for SIM initialization"
    return 1
  fi
  local STATE="$(qmi_get_sim_state)"
  if [ "$STATE" = ready ]; then
    return 0
  fi
  log_error "SIM card is not ready (state: $STATE)"
  return 1
}

qmi_wait_for_wds() {
  log_debug "[$CDC_DEV] Waiting for DATA services to connect"
  if ! wait_for 5 connected qmi_get_connection_state; then
    log_error "Timeout waiting for DATA services to connect"
    return 1
  fi
}

# Possible states: not-registered, registered, not-registered-searching, registration-denied
qmi_get_registration_state() {
  parse_modem_attr "$(qmi --nas-get-serving-system)" "Registration state"
}

qmi_get_registered_plmn() {
  local INFO="$(qmi --nas-get-serving-system)"
  local MCC="$(parse_modem_attr "$INFO" "MCC")"
  local MNC="$(parse_modem_attr "$INFO" "MNC")"
  printf "%03d-%02d" "$MCC" "$MNC" 2>/dev/null
}

# Configure profile for the initial/default EPS bearer activation.
qmi_set_registration_profile() {
  local PROFILE="$(qmi --wds-get-default-profile-num=3gpp)"
  local PROFILE_NUM="$(parse_modem_attr "$PROFILE" "Default profile number")"
  local NO_ROAMING="$(echo "$FORBID_ROAMING" | bool_to_yesno)"
  local ARGS="3gpp,${PROFILE_NUM},apn=${APN},pdp-type=ipv4,no-roaming=${NO_ROAMING}"
  qmi --wds-modify-profile="$ARGS"
}

# TODO: preferred PLMNs do not work
#  - nas-set-preferred-networks returns UimUninitialized
qmi_set_preferred_plmns_and_rats() {
  if [ -n "$PREFERRED_RATS" ] || [ -n "$PREFERRED_PLMNS" ]; then
    local RESET_MODEM=n
    if [ -n "$PREFERRED_RATS" ]; then
      local PREV_PREF="$(qmi --nas-get-system-selection-preference)"
      local PREF_RATS="$(echo "$PREFERRED_RATS" | tr -d "[]\"" | tr "," "|")"
      if qmi --nas-set-system-selection-preference="$PREF_RATS"; then
        local NEW_PREF="$(qmi --nas-get-system-selection-preference)"
        if [ "$PREV_PREF" != "$NEW_PREF" ]; then
          RESET_MODEM=y
        fi
      fi
    fi
    if [ -n "$PREFERRED_PLMNS" ]; then
      local PREV_PREF="$(qmi --nas-get-preferred-networks)"
      # Add "all" after each PLMN - it means we accept any access technology.
      local PREF_NETS="$(echo "$PREFERRED_PLMNS" | tr -d "[]\"-" | awk -F"," '
         {
           for (i=1; i<=NF; i++) {
             printf "%s,all", $i
             if (i < NF) printf ","
           }
         }')"
      if qmi --nas-set-preferred-networks="$PREF_NETS"; then
        local NEW_PREF="$(qmi --nas-get-preferred-networks)"
        if [ "$PREV_PREF" != "$NEW_PREF" ]; then
          RESET_MODEM=y
        fi
      fi
    fi
    # Reset modem to trigger re-registration.
    if [ "$RESET_MODEM" = y ]; then
      qmi --dms-set-operating-mode=offline
      qmi --dms-set-operating-mode=reset
      CMD="qmi --dms-get-operating-mode | grep -q Mode && echo running"
      if ! wait_for 10 running "$CMD" 2>/dev/null; then
        log_error "Timeout waiting for modem to reset"
        return 1
      fi
    fi
  fi
}

qmi_log_registration_debug_info() {
  if [ "$VERBOSE" = "true" ]; then
    # Output of these commands will be logged and can be used for debugging.
    qmi --nas-get-system-selection-preference >/dev/null 2>&1
    qmi --nas-get-preferred-networks >/dev/null 2>&1
    qmi --nas-get-cell-location-info >/dev/null 2>&1
    qmi --nas-get-signal-strength >/dev/null 2>&1
    qmi --nas-get-rf-band-info >/dev/null 2>&1
  fi
}

qmi_wait_for_register() {
  # Apply config for the initial EPS Bearer activation.
  qmi_set_registration_profile
  qmi_set_preferred_plmns_and_rats
  # Wait for the initial EPS Bearer activation.
  log_debug "[$CDC_DEV] Waiting for the device to register on the network"
  qmi_log_registration_debug_info
  # Wait until registered or getting denied.
  local CMD="qmi_get_registration_state | grep -Eq '(^registered|denied)' && echo 'done'"
  if ! wait_for 10 "done" "$CMD"; then
    log_error "Timeout waiting for the device to register on the network"
    return 1
  fi
  STATE="$(qmi_get_registration_state)"
  if [ "$STATE" = registered ]; then
    log_debug "[$CDC_DEV] Registered on network $(qmi_get_registered_plmn)"
    return 0
  fi
  log_error "Network registration failed (state: $STATE)"
  return 1
}

qmi_get_ip_address() {
  parse_modem_attr "$(qmi --wds-get-current-settings)" "IPv4 address"
}

qmi_wait_for_ip_config() {
  log_debug "[$CDC_DEV] Waiting for IP configuration for the $IFACE interface"
  local CMD="qmi_get_ip_address | grep -q \"$IPV4_REGEXP\" && echo connected"
  if ! wait_for 5 connected "$CMD"; then
    log_error "Timeout waiting for IP configuration for the $IFACE interface"
    return 1
  fi
}

qmi_stop_network() {
  local PDH="$(cat "${BBS}/pdh_${IFACE}.json" 2>/dev/null)"
  local CID="$(cat "${BBS}/cid_${IFACE}.json" 2>/dev/null)"
  if ! qmi --wds-stop-network="$PDH" --client-cid="$CID"; then
    # If qmicli failed to stop the network, reset operating mode of the modem.
    if [ "$(qmi_get_op_mode)" = "online-and-connected" ]; then
      qmi --dms-set-operating-mode=low-power
      sleep 1
      qmi --dms-set-operating-mode=online
    fi
  fi
  # Never return error from here, let reconnection attempt to continue.
  return 0
}

qmi_toggle_rf() {
  if [ "$1" = "off" ]; then
    log_debug "[$CDC_DEV] Disabling RF"
    qmi --dms-set-operating-mode=persistent-low-power
  else
    log_debug "[$CDC_DEV] Enabling RF"
    qmi --dms-set-operating-mode=online
  fi
}

qmi_is_modem_responsive() {
  # Try NOOP methods from DMS and NAS services.
  # If both are failing to return within 3secs, consider device as unresponsive.
  ! CMD_TIMEOUT=3 qmi --dms-noop && ! CMD_TIMEOUT=3 qmi --nas-noop && return 1
  return 0
}
