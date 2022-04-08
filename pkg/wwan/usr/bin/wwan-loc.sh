#!/bin/sh
# shellcheck disable=SC2039
# shellcheck disable=SC2155

kill_process_tree() {
  local parent="$1" child
  for child in $(ps -o ppid= -o pid= | awk "\$1==$parent {print \$2}"); do
    kill_process_tree "$child"
  done
  kill "$parent"
}

# Function keeps publishing location updates to /run/wwan/location.json
location_tracking() {
  local CDC_DEV="$1"
  local PROTOCOL="$2"
  local OUTPUT_FILE="$3"
  local RETRY_AFTER=60
  local FIRST_ATTEMPT=y

  # Make sure we use the qmicli binary directly here and not through the wrapper
  # function defined in wwan-qmi.sh
  QMICLI="$(which qmicli)"

  while true; do
    if [ "$FIRST_ATTEMPT" = "n" ]; then
      sleep 1 # Maybe intentionally killed, wait before claiming that we will retry.
      echo "Retrying location tracking after $RETRY_AFTER seconds..."
      sleep $RETRY_AFTER
    fi
    FIRST_ATTEMPT=n
    # For commands from location service qmicli supports both QMI and MBIM protocols.
    if ! LOC_START="$(timeout -s KILL 60 "$QMICLI" -p "--device-open-$PROTOCOL" \
                                                   -d "/dev/$CDC_DEV" --loc-start \
                                                   --client-no-release-cid)"; then
      echo "Failed to start location service"
      continue
    fi
    CID=$(echo "$LOC_START" | sed -n "s/\s*CID: '\(.*\)'/\1/p")
    echo "Location tracking CID is $CID"
    "$QMICLI" -p "--device-open-$PROTOCOL" -d "/dev/$CDC_DEV" \
              --loc-follow-position-report "--client-cid=$CID" 2>/tmp/wwan-loc.stderr |\
      awk 'BEGIN { RS="\\[position report\\]"; FS="\n"; ORS="" }
           $0 ~ /status: +success/ {
              sep_inner=""
              print "{"
              for(i=1; i<=NF; i++) {
                kv=""
                if ($i~/latitude:/) {
                  kv = gensub(/.*: *(.*) +degrees/, "\"latitude\": \\1", 1, $i)
                }
                if ($i~/longitude:/) {
                  kv = gensub(/.*: *(.*) +degrees/, "\"longitude\": \\1", 1, $i)
                }
                if ($i~/altitude w.r.t. mean sea level:/) {
                  kv = gensub(/.*: *(.*) +meters/, "\"altitude\": \\1", 1, $i)
                }
                if ($i~/circular horizontal position uncertainty:/) {
                  kv = gensub(/.*: *(.*) +meters/, "\"horizontal-uncertainty\": \\1", 1, $i)
                }
                if ($i~/vertical uncertainty:/) {
                  kv = gensub(/.*: *(.*) +meters/, "\"vertical-uncertainty\": \\1", 1, $i)
                }
                if ($i~/horizontal reliability:/) {
                  kv = gensub(/.*: *(.*)/, "\"horizontal-reliability\": \"\\1\"", 1, $i)
                }
                if ($i~/vertical reliability:/) {
                  kv = gensub(/.*: *(.*)/, "\"vertical-reliability\": \"\\1\"", 1, $i)
                }
                if ($i~/UTC timestamp:/) {
                  kv = gensub(/.*: *(.*) +ms/, "\"utc-timestamp\": \\1", 1, $i)
                }
                if (kv) {
                  print sep_inner kv
                  sep_inner=", "
                }
              }
              print "}\n"
              fflush()
           }' | while read -r LOCINFO; do
                  echo "$LOCINFO" | jq > "$OUTPUT_FILE";
                done
    echo "Location tracking exited"
    cat /tmp/wwan-loc.stderr
    # Release client CID
    timeout -s KILL 60 "$QMICLI" -p "--device-open-$PROTOCOL" -d "/dev/$CDC_DEV" \
                                 --loc-noop "--client-cid=$CID" 2>/dev/null
  done
}
