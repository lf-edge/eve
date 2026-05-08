#!/bin/sh
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Verifies that EVE's pubsub-reported PVC sizes agree with Longhorn ground truth.
#
# Ground truth (LH-TOTAL) = status.actualSize (live data) + snapshot chain bytes.
# Snapshot bytes are the CoW deltas exclusively owned by each snapshot; the
# volume-head pseudo-snapshot is excluded.
#
# EVE reports this in two pubsub paths, both checked here:
#   VolumeStatus.CurrentSize     /run/volumemgr/VolumeStatus/<key>.json
#   KubeClusterInfo.AllocatedBytes  /run/zedkube/KubeClusterInfo/global.json
#
# Run on a cluster node:
#   eve exec kube /usr/bin/kube-test-longhorn-pvc-size.sh [-t pct] [-n ns] [-v]
#
# Exit: 0 if all volumes within tolerance, 1 if any DRIFT or missing entry.
#
# Usage: kube-test-longhorn-pvc-size.sh [-t pct] [-n namespace] [-v]
#   -t pct        acceptable drift percentage (default: 10)
#   -n namespace  Longhorn namespace (default: longhorn-system)
#   -v            verbose: show per-snapshot breakdown per volume

NAMESPACE=longhorn-system
TOLERANCE_PCT=10
VERBOSE=0
VS_DIR=/run/volumemgr/VolumeStatus
KCI_FILE=/run/zedkube/KubeClusterInfo/global.json

while getopts "t:vn:" opt; do
    case $opt in
        t) TOLERANCE_PCT="$OPTARG" ;;
        v) VERBOSE=1 ;;
        n) NAMESPACE="$OPTARG" ;;
        *) printf "Usage: %s [-t pct] [-n namespace] [-v]\n" "$0" >&2; exit 1 ;;
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

# delta_pct actual reported → "X.X%" absolute percentage difference
delta_pct() {
    awk -v a="$1" -v r="$2" 'BEGIN {
        if (a <= 0) { printf "n/a"; exit }
        d = a - r; if (d < 0) d = -d
        printf "%.1f%%", (d / a) * 100
    }'
}

# within_tol actual reported tol → exits 0 (in tolerance) or 1 (out of tolerance)
within_tol() {
    awk -v a="$1" -v r="$2" -v t="$3" 'BEGIN {
        if (a <= 0) { exit 0 }
        d = a - r; if (d < 0) d = -d
        exit ((d / a) * 100 > t) ? 1 : 0
    }'
}

# --- collect Longhorn volumes ---
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

# --- collect Longhorn snapshots ---
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

# --- pre-fetch K8s PVCs once ---
# VolumeStatus.FileLocation and KubeClusterInfo.Volumes[].Name both hold the K8s PVC
# name (<EVE-VolumeID>-pvc-<gen>), NOT the Longhorn volume name (pvc-<k8s-uid>).
# The K8s PVC object is the bridge: its spec.volumeName equals the Longhorn volume name.
pvc_list=$(kubectl get pvc -A -o json 2>/dev/null || echo '{"items":[]}')

# --- check pubsub paths ---
kci_available=0
[ -f "$KCI_FILE" ] && kci_available=1

vs_available=0
for _f in "$VS_DIR"/*.json; do
    [ -f "$_f" ] && vs_available=1 && break
done

if [ "$kci_available" = "0" ]; then
    printf "warn: %s not found — KCI columns will show NO-KCI\n" "$KCI_FILE" >&2
fi
if [ "$vs_available" = "0" ]; then
    printf "warn: no VolumeStatus files in %s — VS columns will show NO-VS\n" "$VS_DIR" >&2
fi

# --- print header ---
printf "%-44s %10s %10s %10s  %-10s %-8s %-6s  %-10s %-8s %-6s\n" \
    "VOLUME" "LH-LIVE" "LH-SNAP" "LH-TOTAL" "VS-CURR" "VS-DELTA" "VS-ST" "KCI-ALLOC" "KCI-DELTA" "KCI-ST"
printf "%-44s %10s %10s %10s  %-10s %-8s %-6s  %-10s %-8s %-6s\n" \
    "--------------------------------------------" "----------" "----------" "----------" \
    "----------" "--------" "------" "----------" "--------" "------"

# --- per-volume comparison ---
fail_tmp=$(mktemp)

printf '%s' "$vol_json" | jq -r '.items[] | [
    .metadata.name,
    (.status.actualSize // 0 | tostring)
] | @tsv' | while IFS="$(printf '\t')" read -r vol_name actual_size; do

    # sum snapshot bytes for this volume, excluding the volume-head pseudo-snapshot
    snap_agg=$(printf '%s' "$snap_json" | jq --arg vol "$vol_name" '
        [ .items[] |
          select(
            .spec.volume == $vol and
            (.metadata.name | endswith("-volume-head") | not)
          )
        ] | {
            count: length,
            bytes: ([ .[].status.size ] | map(if type == "number" then . else (. // 0 | tonumber) end) | add // 0),
            list:  [ .[] | { n: .metadata.name, b: .status.size, t: (.status.creationTime // ""), u: .status.userCreated } ]
        }
    ')
    snap_bytes=$(printf '%s' "$snap_agg" | jq -r '.bytes')
    snap_count=$(printf '%s' "$snap_agg" | jq -r '.count')
    # Use jq for addition — busybox awk printf "%d" truncates to 32-bit on large values.
    lh_total=$(jq -n --argjson a "$actual_size" --argjson s "$snap_bytes" '$a + $s')

    # --- resolve K8s PVC name from Longhorn volume name ---
    # FileLocation and KubeVolumeInfo.Name hold the K8s PVC name, not the LH volume name.
    k8s_pvc=$(printf '%s' "$pvc_list" | jq -r --arg lh "$vol_name" \
        '.items[] | select(.spec.volumeName == $lh) | .metadata.name')

    # --- VolumeStatus lookup: match FileLocation == K8s PVC name ---
    vs_current="NO-VS"
    if [ -n "$k8s_pvc" ]; then
        for vs_file in "$VS_DIR"/*.json; do
            [ -f "$vs_file" ] || continue
            fl=$(jq -r '.FileLocation // ""' "$vs_file" 2>/dev/null)
            if [ "$fl" = "$k8s_pvc" ]; then
                vs_current=$(jq -r '.CurrentSize // 0' "$vs_file" 2>/dev/null)
                break
            fi
        done
    fi

    # --- KubeClusterInfo lookup ---
    # Storage field is serialised as "pubsub-large-Storage" in the on-disk JSON.
    kci_alloc="NO-KCI"
    if [ "$kci_available" = "1" ] && [ -n "$k8s_pvc" ]; then
        val=$(jq -r --arg pvc "$k8s_pvc" \
            '.["pubsub-large-Storage"].Volumes[] | select(.Name == $pvc) | .AllocatedBytes' \
            "$KCI_FILE" 2>/dev/null)
        if [ -n "$val" ] && [ "$val" != "null" ]; then
            kci_alloc="$val"
        fi
    fi

    # --- compute VS status ---
    if [ "$vs_current" = "NO-VS" ]; then
        vs_delta="n/a"
        vs_st="NO-VS"
    else
        vs_delta=$(delta_pct "$lh_total" "$vs_current")
        if within_tol "$lh_total" "$vs_current" "$TOLERANCE_PCT"; then
            vs_st="MATCH"
        else
            vs_st="DRIFT"
        fi
    fi

    # --- compute KCI status ---
    if [ "$kci_alloc" = "NO-KCI" ]; then
        kci_delta="n/a"
        kci_st="NO-KCI"
    else
        kci_delta=$(delta_pct "$lh_total" "$kci_alloc")
        if within_tol "$lh_total" "$kci_alloc" "$TOLERANCE_PCT"; then
            kci_st="MATCH"
        else
            kci_st="DRIFT"
        fi
    fi

    # record failure if either column is non-MATCH
    if [ "$vs_st" != "MATCH" ] || [ "$kci_st" != "MATCH" ]; then
        printf "%s\n" "$vol_name" >> "$fail_tmp"
    fi

    # --- print row ---
    if [ "$vs_current" = "NO-VS" ]; then
        vs_human="NO-VS"
    else
        vs_human=$(human_bytes "$vs_current")
    fi
    if [ "$kci_alloc" = "NO-KCI" ]; then
        kci_human="NO-KCI"
    else
        kci_human=$(human_bytes "$kci_alloc")
    fi

    printf "%-44s %10s %10s %10s  %-10s %-8s %-6s  %-10s %-8s %-6s\n" \
        "$vol_name" \
        "$(human_bytes "$actual_size")" \
        "$(human_bytes "$snap_bytes")" \
        "$(human_bytes "$lh_total")" \
        "$vs_human" "$vs_delta" "$vs_st" \
        "$kci_human" "$kci_delta" "$kci_st"

    if [ "$VERBOSE" = "1" ]; then
        printf "  k8s-pvc: %s\n" "${k8s_pvc:-<not found>}"
    fi
    if [ "$VERBOSE" = "1" ] && [ "$snap_count" -gt 0 ]; then
        printf '%s' "$snap_agg" | jq -r '
            .list | sort_by(.t) | .[] |
            [.n, (.b | tostring), (.t // "unknown"), (if .u then "user" else "system" end)] | @tsv
        ' | while IFS="$(printf '\t')" read -r sname sbytes screated stype; do
            printf "  snap %-40s %10s  %-30s [%s]\n" \
                "$sname" "$(human_bytes "$sbytes")" "$screated" "$stype"
        done
    fi
done

printf "\n"

# --- summary ---
if [ -s "$fail_tmp" ]; then
    fail_count=$(wc -l < "$fail_tmp" | tr -d ' ')
    printf "FAIL: %d/%d volume(s) outside %d%% tolerance or missing pubsub entry\n" \
        "$fail_count" "$vol_count" "$TOLERANCE_PCT"
    rm -f "$fail_tmp"
    exit 1
fi
rm -f "$fail_tmp"
printf "PASS: all %d volume(s) within %d%% tolerance\n" "$vol_count" "$TOLERANCE_PCT"
exit 0
