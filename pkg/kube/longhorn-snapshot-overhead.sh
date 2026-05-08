#!/bin/sh
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Reports per-volume snapshot filesystem overhead for Longhorn volumes.
#
# Each Longhorn snapshot is copy-on-write: status.size is the number of bytes
# exclusively owned by that snapshot (written since the previous snapshot).
# Summing these across a volume gives the total space the snapshot chain
# consumes beyond the live data (status.actualSize).
#
# The "volume-head" pseudo-snapshot (named <vol>-volume-head) represents the
# live data pointer and is excluded from overhead calculations.
#
# Usage: longhorn-snapshot-overhead.sh [-v] [-n namespace]
#   -v              show individual snapshot details per volume
#   -n namespace    Longhorn namespace (default: longhorn-system)

NAMESPACE=longhorn-system
VERBOSE=0

while getopts "vn:" opt; do
    case $opt in
        v) VERBOSE=1 ;;
        n) NAMESPACE="$OPTARG" ;;
        *) printf "Usage: %s [-v] [-n namespace]\n" "$0" >&2; exit 1 ;;
    esac
done

for cmd in kubectl jq awk; do
    if ! command -v "$cmd" > /dev/null 2>&1; then
        printf "ERROR: %s is required but not found\n" "$cmd" >&2
        exit 1
    fi
done

human_bytes() {
    b=$1
    awk -v b="$b" 'BEGIN {
        if      (b <= 0)           printf "0B"
        else if (b >= 1073741824)  printf "%.1fGi", b/1073741824
        else if (b >= 1048576)     printf "%.1fMi", b/1048576
        else if (b >= 1024)        printf "%.1fKi", b/1024
        else                       printf "%dB", b
    }'
}

vol_json=$(kubectl -n "$NAMESPACE" get volumes.longhorn.io -o json 2>/dev/null)
if [ -z "$vol_json" ]; then
    printf "ERROR: could not query Longhorn volumes in namespace %s\n" "$NAMESPACE" >&2
    exit 1
fi

vol_count=$(printf '%s' "$vol_json" | jq '.items | length')
if [ "$vol_count" = "0" ]; then
    printf "No Longhorn volumes found in namespace %s\n" "$NAMESPACE"
    exit 0
fi

snap_tmp=$(mktemp)
snap_json=$(kubectl -n "$NAMESPACE" get snapshots.longhorn.io -o json 2>"$snap_tmp")
snap_rc=$?
if [ "$snap_rc" -ne 0 ]; then
    printf "warn: kubectl get snapshots.longhorn.io failed: %s\n" "$(cat "$snap_tmp")" >&2
    snap_json='{"items":[]}'
elif [ -z "$snap_json" ]; then
    snap_json='{"items":[]}'
fi
rm -f "$snap_tmp"

printf "%-44s %11s %11s %6s %11s %9s  STATE\n" \
    "VOLUME" "PROVISIONED" "ACTUAL" "SNAPS" "SNAP-USED" "OVERHEAD"
printf "%-44s %11s %11s %6s %11s %9s  -----\n" \
    "--------------------------------------------" "-----------" "-----------" "------" "-----------" "---------"

printf '%s' "$vol_json" | jq -r '.items[] | [
    .metadata.name,
    ((.spec.size // "0") | tostring),
    (.status.actualSize // 0 | tostring),
    (.status.state // "unknown")
] | @tsv' | while IFS="$(printf '\t')" read -r vol_name spec_size actual_size vol_state; do

    snap_agg=$(printf '%s' "$snap_json" | jq --arg vol "$vol_name" '
        [ .items[] |
          select(
            .spec.volume == $vol and
            (.metadata.name | endswith("-volume-head") | not)
          )
        ] | {
            count: length,
            bytes: ([ .[].status.size ] | map(if type == "number" then . else (. // 0 | tonumber) end) | add // 0),
            list:  [ .[] | {
                n: .metadata.name,
                b: .status.size,
                t: (.status.creationTime // ""),
                u: .status.userCreated
            }]
        }
    ')

    snap_count=$(printf '%s' "$snap_agg" | jq -r '.count')
    snap_bytes=$(printf '%s' "$snap_agg" | jq -r '.bytes')

    overhead="0%"
    if [ "$actual_size" -gt 0 ] 2>/dev/null && [ "$snap_bytes" -gt 0 ] 2>/dev/null; then
        overhead=$(awk -v s="$snap_bytes" -v a="$actual_size" 'BEGIN { printf "%.1f%%", (s/a)*100 }')
    elif [ "$snap_bytes" -gt 0 ] 2>/dev/null; then
        overhead="n/a"
    fi

    printf "%-44s %11s %11s %6s %11s %9s  %s\n" \
        "$vol_name" \
        "$(human_bytes "$spec_size")" \
        "$(human_bytes "$actual_size")" \
        "$snap_count" \
        "$(human_bytes "$snap_bytes")" \
        "$overhead" \
        "$vol_state"

    if [ "$VERBOSE" = "1" ] && [ "$snap_count" -gt 0 ]; then
        printf '%s' "$snap_agg" | jq -r '
            .list | sort_by(.t) | .[] |
            [.n, (.b | tostring), (.t // "unknown"), (if .u then "user" else "system" end)] | @tsv
        ' | while IFS="$(printf '\t')" read -r sname sbytes screated stype; do
            printf "  %-42s %11s  %-30s [%s]\n" \
                "$sname" "$(human_bytes "$sbytes")" "$screated" "$stype"
        done
        printf "\n"
    fi
done

# Totals calculated independently from jq (avoids subshell accumulation issues)
tot_snap=$(printf '%s' "$snap_json" | jq '
    [ .items[] |
      select(.metadata.name | endswith("-volume-head") | not) |
      .status.size | if type == "number" then . else (. // 0 | tonumber) end
    ] | add // 0
')
tot_actual=$(printf '%s' "$vol_json" | jq '[.items[].status.actualSize // 0] | add // 0')

printf "\n"
printf "Volumes: %d\n" "$vol_count"
printf "Total snapshot space:  %s\n" "$(human_bytes "$tot_snap")"
printf "Total volume actual:   %s\n" "$(human_bytes "$tot_actual")"
if [ "$tot_actual" -gt 0 ] 2>/dev/null && [ "$tot_snap" -gt 0 ] 2>/dev/null; then
    awk -v s="$tot_snap" -v a="$tot_actual" 'BEGIN { printf "Overall overhead:      %.1f%%\n", (s/a)*100 }'
fi
