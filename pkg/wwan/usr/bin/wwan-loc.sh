#!/bin/sh
# shellcheck disable=SC2039
# shellcheck disable=SC2155

kill_process_tree() {
  local parent="$1" child
  for child in $(ps -o ppid= -o pid= | awk "\$1==$parent {print \$2}"); do
    kill_process_tree "$child"
  done
  kill "$parent"
  for _ in $(seq 3); do
    kill -0 "$parent" 2>/dev/null || return 0
    sleep 1
  done
  kill -9 "$parent"
}

publish_location() {
  local LOGICAL_LABEL="$1"
  local INPUT="$2"
  local OUTPUT="$3"
  # Value not valid for any of the numerical attributes.
  # Note that for (unsigned) UTC timestamp we use 0 to represent unavailable value.
  local UNAVAIL_LOC_PARAM="-32768"
  awk -v unavail="$UNAVAIL_LOC_PARAM" -v logicallabel="$LOGICAL_LABEL" \
  'BEGIN { RS="\\[position report\\]"; FS="\n"; ORS="" }
  $0 ~ /status:/ {
     printf "{\"logical-label\": \"%s\"", logicallabel
     for(i=1; i<=NF; i++) {
       kv=""
       if ($i~/latitude:/) {
         if ($i~/n\/a/) {
           kv = "\"latitude\": " unavail
         } else {
           kv = gensub(/.*: *(.*) +degrees/, "\"latitude\": \\1", 1, $i)
         }
       }
       if ($i~/longitude:/) {
         if ($i~/n\/a/) {
           kv = "\"longitude\": " unavail
         } else {
           kv = gensub(/.*: *(.*) +degrees/, "\"longitude\": \\1", 1, $i)
         }
       }
       if ($i~/altitude w.r.t. mean sea level:/) {
         if ($i~/n\/a/) {
           kv = "\"altitude\": " unavail
         } else {
           kv = gensub(/.*: *(.*) +meters/, "\"altitude\": \\1", 1, $i)
         }
       }
       if ($i~/circular horizontal position uncertainty:/) {
         if ($i~/n\/a/) {
           kv = "\"horizontal-uncertainty\": " unavail
         } else {
           kv = gensub(/.*: *(.*) +meters/, "\"horizontal-uncertainty\": \\1", 1, $i)
         }
       }
       if ($i~/vertical uncertainty:/) {
         if ($i~/n\/a/) {
           kv = "\"vertical-uncertainty\": " unavail
         } else {
           kv = gensub(/.*: *(.*) +meters/, "\"vertical-uncertainty\": \\1", 1, $i)
         }
       }
       if ($i~/horizontal reliability:/) {
         kv = gensub(/.*: *(.*)/, "\"horizontal-reliability\": \"\\1\"", 1, $i)
       }
       if ($i~/vertical reliability:/) {
         kv = gensub(/.*: *(.*)/, "\"vertical-reliability\": \"\\1\"", 1, $i)
       }
       if ($i~/UTC timestamp:/) {
         if ($i~/n\/a/) {
           kv = "\"utc-timestamp\": 0"
         } else {
           kv = gensub(/.*: *(.*) +ms/, "\"utc-timestamp\": \\1", 1, $i)
         }
       }
       if (kv) {
         print ", " kv
       }
     }
     print "}\n"
     fflush()
  }' < "$INPUT" | while read -r GNSS_INFO; do
                    echo "$GNSS_INFO" | jq > "${OUTPUT}.tmp";
                    # Update location atomically.
                    mv "${OUTPUT}.tmp" "${OUTPUT}"
                  done
  log_debug "Location publisher stopped"
}

# Function keeps publishing location updates to /run/wwan/location.json
# FIXME XXX Limited to a single cellular modem
location_tracking() {
  local LOGICAL_LABEL="$1"
  local CDC_DEV="$2"
  local PROTOCOL="$3"
  local OUTPUT_FILE="$4"
  local RETRY_AFTER=15
  local FIRST_ATTEMPT=y
  local STDERR="/tmp/wwan-loc.stderr"
  local PIPE="/tmp/wwan-loc.pipe"
  if [[ ! -p "$PIPE" ]]; then
    rm -f "$PIPE"
    mkfifo "$PIPE"
  fi

  while true; do
    if [ "$FIRST_ATTEMPT" = "n" ]; then
      sleep 1 # Maybe intentionally killed, wait before claiming that we will retry.
      log_debug "Retrying location tracking after $RETRY_AFTER seconds..."
      sleep $RETRY_AFTER
    fi
    FIRST_ATTEMPT=n

    # Start location tracking session.
    # For commands from location service qmicli supports both QMI and MBIM protocols.
    if ! LOC_START="$(timeout -s KILL 60 qmicli -p "--device-open-$PROTOCOL" \
                                                -d "/dev/$CDC_DEV" --loc-start \
                                                --client-no-release-cid)"; then
      log_error "Failed to start location service"
      continue
    fi
    CID=$(echo "$LOC_START" | sed -n "s/\s*CID: '\(.*\)'/\1/p")
    log_debug "Location tracking CID is $CID"

    publish_location "$LOGICAL_LABEL" "$PIPE" "$OUTPUT_FILE" &
    PUBLISHER_PID=$!
    log_debug "PID of the location publisher is $PUBLISHER_PID"

    qmicli -p "--device-open-$PROTOCOL" -d "/dev/$CDC_DEV" \
           --loc-follow-position-report "--client-cid=$CID" >"$PIPE" 2>"$STDERR" &
    TRACKER_PID=$!
    log_debug "PID of the location tracker is $TRACKER_PID"

    # Watchdog - we expect at least one location update every minute,
    # otherwise we consider the location tracking to be stuck.
    MODTIME="$(date "+%s" -r "$OUTPUT_FILE" 2>/dev/null)"
    while true; do
      sleep 60
      if [ ! -f "$OUTPUT_FILE" ]; then
        log_debug "Location info is not available, restarting tracker"
        break
      fi
      NEW_MODTIME="$(date "+%s" -r "$OUTPUT_FILE" 2>/dev/null)"
      if [ "$MODTIME" = "$NEW_MODTIME" ]; then
        log_debug "Location info has not been updated in the last minute, restarting tracker"
        break
      fi
      MODTIME="$NEW_MODTIME"
    done

    # Stop location tracking - it is likely stuck.
    kill_process_tree $PUBLISHER_PID >/dev/null 2>&1
    kill_process_tree $TRACKER_PID >/dev/null 2>&1
    log_debug "Location tracking was killed"
    cat "$STDERR"

    # Release client CID
    timeout -s KILL 60 qmicli -p "--device-open-$PROTOCOL" -d "/dev/$CDC_DEV" \
                              --loc-noop "--client-cid=$CID" 2>/dev/null
  done
}
