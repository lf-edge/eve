#!/bin/sh
# shellcheck disable=SC2039
# shellcheck disable=SC2155
# shellcheck disable=SC2034

mbim() {
  if [ "$VERBOSE" = "true" ]; then
    # Do not log user password.
    local FILTERED_ARGS
    FILTERED_ARGS=$(echo "$@" | sed "s/password='\([^']*\)'/password='***'/g")
    log_debug Running: mbimcli -p -d "/dev/$CDC_DEV" "$FILTERED_ARGS"
  fi
  local OUTPUT
  local RV
  OUTPUT="$(timeout -s INT -k 5 "$CMD_TIMEOUT" \
    mbimcli -p -d "/dev/$CDC_DEV" "$@" 2>/tmp/mbimcli.stderr)"
  RV=$?
  if [ "$VERBOSE" = "true" ]; then
    log_debug mbimcli output: "$OUTPUT"
    [ -s /tmp/mbimcli.stderr ] && log_debug mbimcli error: "$(cat /tmp/mbimcli.stderr)"
    log_debug mbimcli RV: "$RV"
  fi
  echo "$OUTPUT"
  cat /tmp/mbimcli.stderr 1>&2
  return $RV
}

mbim_get_packet_stats() {
  local STATS="$(mbim --query-packet-statistics)"
  local TXP=$(parse_modem_attr "$STATS" "Packets (out)")
  local TXB=$(parse_modem_attr "$STATS" "Octets (out)")
  local TXD=$(parse_modem_attr "$STATS" "Discards (out)")
  local TXE=$(parse_modem_attr "$STATS" "Errors (out)")
  local RXP=$(parse_modem_attr "$STATS" "Packets (in)")
  local RXB=$(parse_modem_attr "$STATS" "Octets (in)")
  local RXD=$(parse_modem_attr "$STATS" "Discards (in)")
  local RXE=$(parse_modem_attr "$STATS" "Errors (in)")
  json_struct \
    "$(json_attr tx-bytes "${TXB:-0}")" "$(json_attr tx-packets "${TXP:-0}")" "$(json_attr tx-drops "$(( TXD + TXE ))")" \
    "$(json_attr rx-bytes "${RXB:-0}")" "$(json_attr rx-packets "${RXP:-0}")" "$(json_attr rx-drops "$(( RXD + RXE ))")"
}

mbim_get_signal_info() {
  local INFO
  # Prefer signal info obtained using QMI-over-MBIM - it provides all metrics,
  # not just RSSI.
  if INFO="$(qmi_get_signal_info)"; then
    echo "$INFO"
    return 0
  fi
  INFO="$(mbim --query-signal-state)"
  local RV=$?
  local RSSI=$(parse_modem_attr "$INFO" "RSSI \[0-31,99\]")
  if [ "${RSSI:-99}" -eq 99 ]; then
    RSSI="$UNAVAIL_SIGNAL_METRIC"
  else
    # See table 10-58 (MBIM_SIGNAL_STATE_INFO) in MBIM_v1_0_USBIF_FINAL.pdf
    RSSI="$(( -113 + (2 * RSSI) ))"
  fi
  json_struct \
    "$(json_attr rssi "$RSSI")" \
    "$(json_attr rsrq "$UNAVAIL_SIGNAL_METRIC")" \
    "$(json_attr rsrp "$UNAVAIL_SIGNAL_METRIC")" \
    "$(json_attr snr  "$UNAVAIL_SIGNAL_METRIC")"
  return $RV
}

mbim_is_radio_off() {
  local RF_STATE="$(mbim --query-radio-state)"
  local HW_RF_STATE="$(parse_modem_attr "$RF_STATE" "Hardware radio state")"
  local SW_RF_STATE="$(parse_modem_attr "$RF_STATE" "Software radio state")"
  if [ "$HW_RF_STATE" = "off" ] || [ "$SW_RF_STATE" = "off" ]; then
    return 0
  fi
  return 1
}

# mbim_get_op_mode returns one of: "" (aka unspecified), "online", "online-and-connected", "radio-off", "offline", "unrecognized"
mbim_get_op_mode() {
  if mbim_is_radio_off; then
    echo "radio-off"
    return
  fi
  if mbim_get_registration_state | grep -qvE '(home|roaming|partner)'; then
    echo "offline"
    return
  fi
  if [ "$(mbim_get_packet_service_state)" = "attached" ] && \
     [ "$(mbim_get_connection_state)" = "activated" ]; then
     echo "online-and-connected"
     return
  fi
  echo "online"
}

mbim_get_imei() {
  parse_modem_attr "$(mbim --query-device-caps)" "Device ID"
}

mbim_get_modem_model() {
  parse_modem_attr "$(mbim --query-device-caps)" "Hardware info"
}

mbim_get_modem_revision() {
  parse_modem_attr "$(mbim --query-device-caps)" "Firmware info"
}

mbim_get_modem_manufacturer() {
  # Not available with pure MBIM, try QMI-over-MBIM.
  qmi_get_modem_manufacturer
}

mbim_get_current_provider() {
  local INFO="$(mbim --query-registration-state)"
  local REGSTATE="$(parse_modem_attr "$INFO" "Register state")"
  if echo "$REGSTATE" | grep -qvE '(home|roaming|partner|denied)'; then
    echo "{}"
    return 1
  fi
  local PLMN="$(parse_modem_attr "$INFO" "Provider ID")"
  local DESCRIPTION="$(parse_modem_attr "$INFO" "Provider name")"
  local ROAMING="false"
  # Convert PLMN to dash-separated format (xxx-yy).
  PLMN="$(echo "$PLMN" | cut -c1-3)-$(echo "$PLMN" | cut -c4-)"
  if [ "$REGSTATE" = "roaming" ]; then
    ROAMING="true"
  fi
  local FORBIDDEN="false"
  if [ "$REGSTATE" = "denied" ]; then
    FORBIDDEN="true"
  fi
  json_struct \
    "$(json_str_attr plmn "${PLMN}")" \
    "$(json_str_attr description "${DESCRIPTION}")" \
    "$(json_attr current-serving "true")" \
    "$(json_attr roaming "${ROAMING}")" \
    "$(json_attr forbidden "${FORBIDDEN}")"
}

mbim_get_providers() {
  local PROVIDERS
  if mbim_is_radio_off; then
    # With radio off, an attempt to list visible providers would fail and log error.
    echo "[]"
    return
  fi
  if ! PROVIDERS="$(CMD_TIMEOUT=120 mbim --query-visible-providers)"; then
    # Alternative to listing all providers is to return info at least
    # for the current provider.
    if SERVING="$(mbim_get_current_provider)"; then
      printf "[%b]" "$SERVING"
    else
      echo "[]"
    fi
    return
  fi
  echo "$PROVIDERS" | awk '
    BEGIN{RS="Provider [[0-9]+]:"; FS="\n"; print "["}
    $0 ~ /Provider ID: / {
      print sep_outer "{"
      sep_inner=""
      for(i=1; i<=NF; i++) {
        kv=""
        if ($i~/Provider ID:/) {
          # Put dash between MCC and MNC.
          # Note: \x27 is a single apostrophe
          kv = gensub(/.*: \x27([0-9]{3})([0-9]{2,3})\x27/, "\"plmn\": \"\\1-\\2\"", 1, $i)
        }
        if ($i~/Provider name:/) {
          kv = gensub(/.*: \x27(.*)\x27/, "\"description\": \"\\1\"", 1, $i)
        }
        if ($i~/State:/) {
          current="false"
          roaming="false"
          forbidden="false"
          if ($i~/registered/) current="true"
          if ($i~/roaming/) roaming="true"
          if ($i~/forbidden/) forbidden="true"
          kv="\"current-serving\":" current ",\"roaming\":" roaming ",\"forbidden\":" forbidden
        }
        if (kv) {
          print sep_inner kv
          sep_inner=","
        }
      }
      print "}"
      sep_outer=","
    }
    END{print "]"}' | jq -c "unique"
}

mbim_get_currently_used_rats() {
  # Only available with QMI or QMI-over-MBIM.
  qmi_get_currently_used_rats
}

mbim_get_all_sim_slots() {
  local CAPS="$(mbim --ms-query-sys-caps)"
  local COUNT="$(parse_modem_attr "$CAPS" "Number of slots")"
  COUNT="${COUNT:-1}" # Assume there is only one slot.
  local IDX=1
  while [ "$IDX" -le "$COUNT" ]; do
    echo "$IDX"
    IDX="$((IDX + 1))"
  done
}

mbim_get_active_sim_slot() {
  # XXX "state-empty" seems to be reported for absent SIM card even when slot
  # is inactive (instead of "state-off-empty" which would be correct).
  local EMPTY_SLOT=""
  local SLOT=""
  for SLOT in $(mbim_get_all_sim_slots); do
    local STATUS="$(mbim --ms-query-slot-info-status "$((SLOT-1))")"
    local STATE="$(parse_modem_attr "$STATUS" "Slot '$((SLOT-1))'")"
    case "$STATE" in
      ""|"state-unknown"|"state-off-empty"|"state-off")
        continue
      ;;
      "state-empty")
        # Can't tell if the slot is activated.
        EMPTY_SLOT="$SLOT"
        continue
      ;;
      *) echo "$SLOT" && return
      ;;
    esac
  done
  # Try QMI-over-MBIM if supported and we failed to find activated slot with MBIM.
  SLOT="$(qmi_get_active_sim_slot)"
  [ -n "$SLOT" ] && echo "$SLOT" && return
  # Assume that the SIM slot without card inserted is the activated one.
  # With multiple empty SIM slots present this is not going to always give
  # the correct answer.
  [ -n "$EMPTY_SLOT" ] && echo "$EMPTY_SLOT"
}

mbim_get_sim_cards() {
  local SIMS
  local SUBSCRIBER="$(mbim --query-subscriber-ready-status)"
  local ACTIVE_SLOT="$(mbim_get_active_sim_slot)"
  for SLOT in $(mbim_get_all_sim_slots); do
    local ICCID=""
    local IMSI=""
    local ACTIVATED="false"
    if [ "$SLOT" = "$ACTIVE_SLOT" ]; then
      ACTIVATED="true"
      # Get ICCID of the currently active SIM card.
      # It is not supported (and likely not even possible) to obtain ICCIDs of SIM
      # cards inside inactive slots.
      ICCID=$(parse_modem_attr "$SUBSCRIBER" "SIM ICCID")
      # Remove trailing Fs that modem may add as a padding.
      ICCID="$(echo "$ICCID" | tr -d "F")"
      IMSI="$(parse_modem_attr "$SUBSCRIBER" "Subscriber ID")"
    fi
    local SIM_STATE="unknown"
    local STATUS="$(mbim --ms-query-slot-info-status "$((SLOT-1))")"
    local SLOT_STATE="$(parse_modem_attr "$STATUS" "Slot '$((SLOT-1))'")"
    case "$SLOT_STATE" in
      "state-off-empty"|"state-empty")
        # Takes precedence over "inactive".
        SIM_STATE="absent"
      ;;
      "state-off")
        SIM_STATE="inactive"
      ;;
      "state-active"|"state-active-esim")
        # See mbim_get_subscriber_state for possible values.
        SIM_STATE="$(parse_modem_attr "$SUBSCRIBER" "Ready state")"
      ;;
      *) # one of: state-error, state-not-ready, state-active-esim-no-profiles
        SIM_STATE="${SLOT_STATE#state-}"
      ;;
    esac
    local SIM_STATUS="$(json_struct \
      "$(json_attr     slot-number    "$SLOT")" \
      "$(json_attr     slot-activated "$ACTIVATED")" \
      "$(json_str_attr iccid          "$ICCID")" \
      "$(json_str_attr imsi           "$IMSI")" \
      "$(json_str_attr state          "$SIM_STATE")")"
    SIMS="${SIMS}${SIM_STATUS}\n"
  done
  printf "%b" "$SIMS" | json_array
}

mbim_get_ip_settings() {
  if ! SETTINGS="$(mbim --query-ip-configuration)"; then
    return 1
  fi
  IP="$(echo "$SETTINGS" | jq -r .ipv4.ip)"
  SUBNET="$(echo "$SETTINGS" | jq -r .ipv4.subnet)"
  GW="$(echo "$SETTINGS" | jq -r .ipv4.gateway)"
  DNS1="$(echo "$SETTINGS" | jq -r .ipv4.dns0)"
  DNS2="$(echo "$SETTINGS" | jq -r .ipv4.dns1)"
  MTU="$(echo "$SETTINGS" | jq -r .mtu)"
}

mbim_start_network() {
  log_debug "[$CDC_DEV] Starting network for APN ${APN}"
  if ! mbim --attach-packet-service; then
    # Maybe the modem was restarted to apply changed preferred PLMNs/RATs.
    # Wait for subscriber initialization (again), then retry (but only once).
    if ! mbim_wait_for_subscriber_init || ! mbim --attach-packet-service; then
      log_error "Failed to attach to packet service"
      return 1
    fi
  fi
  local ARGS="apn='${APN}'"
  if [ -n "$USERNAME" ]; then
    local PROTO
    case "$AUTH_PROTO" in
      "") PROTO="none"
      ;;
      "pap-and-chap")
        # This option does not seem to be supported with mbimcli
        log_error "unsupported authentication protocol: $AUTH_PROTO"
        return 1
      ;;
      *) PROTO="$AUTH_PROTO"
      ;;
    esac
    ARGS="$ARGS,username='${USERNAME}',password='${PASSWORD}',auth='${PROTO}'"
  fi
  mbim --connect="$ARGS"
}

mbim_switch_to_selected_slot() {
  if [ -n "$SIM_SLOT" ] && [ "$SIM_SLOT" != "0" ]; then
    if [ "$(mbim_get_active_sim_slot)" != "$SIM_SLOT" ]; then
      if ! mbim --ms-set-device-slot-mappings="$((SIM_SLOT-1))"; then
        log_error "Failed to switch to SIM slot $SIM_SLOT"
        return 1
      fi
      if ! wait_for 3 "$SIM_SLOT" mbim_get_active_sim_slot; then
        log_error "Timeout waiting for modem to switch to SIM slot $SIM_SLOT"
        return 1
      fi
      # Give modem some time to update the SIM & Subscriber state.
      sleep 3
    fi
  fi
}

# Possible values: not-initialized, initialized, sim-not-inserted, bad-sim, failure,
# not-activated, device-locked
mbim_get_subscriber_state() {
  parse_modem_attr "$(mbim --query-subscriber-ready-status)" "Ready state"
}

mbim_wait_for_subscriber_init() {
  # Wait as long as the state is not-activated or not-initialized.
  local CMD="mbim_get_subscriber_state | grep -q '^not-' || echo 'done'"
  if ! wait_for 3 "done" "$CMD"; then
    log_error "Timeout waiting for SIM initialization"
    return 1
  fi
  local STATE="$(mbim_get_subscriber_state)"
  if [ "$STATE" = initialized ]; then
    return 0
  fi
  log_error "Subscriber is not initialized (state: $STATE)"
  return 1
}

mbim_wait_for_sim() {
  # Switch to the correct SIM slot first.
  if ! mbim_switch_to_selected_slot; then
    return 1
  fi
  log_debug "[$CDC_DEV] Waiting for SIM card to initialize"
  mbim_wait_for_subscriber_init
}

# Returns one of: "unknown", "activated", "activating", "deactivated", "deactivating".
mbim_get_connection_state() {
  parse_modem_attr "$(mbim --query-connection-state)" "Activation state"
}

# Returns one of: "unknown", "attaching", "attached", "detaching", "detached".
mbim_get_packet_service_state() {
  parse_modem_attr "$(mbim --query-packet-service-state)" "Packet service state"
}

mbim_wait_for_wds() {
  log_debug "[$CDC_DEV] Waiting for DATA services to connect"
  if ! wait_for 5 attached mbim_get_packet_service_state; then
    log_error "Timeout waiting for Packet service to attach"
    return 1
  fi
  if ! wait_for 5 activated mbim_get_connection_state; then
    log_error "Timeout waiting for connection to activate"
    return 1
  fi
}

# Returns one of: "unknown", "deregistered", "searching", "home", "roaming",
# "partner" (registered in a preferred roaming network), "denied".
mbim_get_registration_state() {
  parse_modem_attr "$(mbim --query-registration-state)" "Register state"
}

mbim_get_registered_plmn() {
  parse_modem_attr "$(mbim --query-registration-state)" "Provider ID"
}

mbim_log_registration_debug_info() {
  if [ "$VERBOSE" = "true" ]; then
    # Output of these commands will be logged and can be used for debugging.
    mbim --query-preferred-providers >/dev/null 2>&1
    mbim --query-signal-state >/dev/null 2>&1
    # If QMI-over-MBIM is available...
    qmi_log_registration_debug_info
  fi
}

mbim_wait_for_register() {
  # Configuring profile for the initial EPS bearer activation as well as selecting
  # preferred RATs and providers is apparently only possible with QMI or QMI-over-MBIM.
  qmi_set_registration_profile
  qmi_set_preferred_plmns_and_rats
  # Wait for the initial EPS Bearer activation.
  log_debug "[$CDC_DEV] Waiting for the device to register on the network"
  mbim_log_registration_debug_info
  local CMD="mbim_get_registration_state | grep -qE '(home|roaming|partner|denied)' && echo 'done'"
  if ! wait_for 10 "done" "$CMD"; then
    log_error "Timeout waiting for the device to register on the network"
    return 1
  fi
  if [ "$(mbim_get_registration_state)" != denied ]; then
    log_debug "[$CDC_DEV] Registered on network $(mbim_get_registered_plmn)"
    return 0
  fi
  log_error "Network registration was denied"
  return 1
}

mbim_get_ip_address() {
  mbim --query-ip-configuration | jq -r .ipv4.ip
}

mbim_wait_for_ip_config() {
  log_debug "[$CDC_DEV] Waiting for IP configuration for the $IFACE interface"
  local CMD="mbim_get_ip_address | grep -q \"$IPV4_REGEXP\" && echo connected"
  if ! wait_for 5 connected "$CMD"; then
    log_error "Timeout waiting for IP configuration for the $IFACE interface"
    return 1
  fi
}

mbim_stop_network() {
  mbim --disconnect || true
  mbim --detach-packet-service || true
}

mbim_toggle_rf() {
  if [ "$1" = "off" ]; then
    log_debug "[$CDC_DEV] Disabling RF"
    mbim --set-radio-state "off"
  else
    log_debug "[$CDC_DEV] Enabling RF"
    mbim --set-radio-state "on"
  fi
}

mbim_is_modem_responsive() {
  # Try the NOOP method and to get device capabilities.
  # If both calls are failing to return in 3 seconds, consider device as unresponsive.
  ! CMD_TIMEOUT=3 mbim --noop && ! CMD_TIMEOUT=3 mbim --query-device-caps && return 1
  return 0
}
