#!/bin/sh
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

# hold-vmi-init.sh <app-prefix> [hold-seconds]
#
# Continually freezes virt-launcher pods for an app until the hold timer
# expires. Kubernetes creates a replacement pod every 1-3 minutes when it
# detects the launcher is stuck; this script freezes each replacement as it
# appears, maintaining the stuck-in-Init state for the full hold duration.
#
# Detection: kubectl get pods -w streams new pods from the API server the
# moment the VMI controller creates them — before kubelet, before containerd.
# Freeze: pod-level cgroup freezer is atomically written (FROZEN/THAWED).
#
# Usage:
#   ./hold-vmi-init.sh enc-pin-cherry1-390a4
#   ./hold-vmi-init.sh enc-pin-cherry1-390a4 120
#
# Override namespace: NS=other-namespace ./hold-vmi-init.sh <prefix>

APP_PREFIX="${1:?Usage: $0 <app-prefix> [hold-seconds]}"
HOLD_SECS="${2:-600}"
NS="${NS:-eve-kube-app}"
LAUNCHER_PREFIX="virt-launcher-${APP_PREFIX}"

# ---------------------------------------------------------------------------
# Temp files and cleanup
# ---------------------------------------------------------------------------

SEEN_PODS=$(mktemp)      # pod names already dispatched (dedup across iterations)
FROZEN_CGROUPS=$(mktemp) # cgroup freezer.state paths to thaw on exit
WATCH_PIPE=$(mktemp -u)  # FIFO for kubectl watch output

cleanup() {
    thaw_all
    kill "$WATCH_PID" 2>/dev/null
    rm -f "$SEEN_PODS" "$FROZEN_CGROUPS" "$WATCH_PIPE"
}
trap cleanup EXIT INT TERM

# ---------------------------------------------------------------------------
# Functions
# ---------------------------------------------------------------------------

find_vmi() {
    kubectl -n "$NS" get vmi --no-headers 2>/dev/null \
        | awk -v p="$APP_PREFIX" '$1 ~ "^"p {print $1}' | head -1
}

delete_vmi_async() {
    kubectl -n "$NS" delete vmi "$1" &
    echo "Deleting $1 (async)..."
}

# Pre-populate SEEN_PODS with pods already on the node so the watch stream's
# initial state dump does not cause us to freeze already-running pods.
seed_seen_pods() {
    kubectl -n "$NS" get pods --no-headers 2>/dev/null \
        | awk -v p="$LAUNCHER_PREFIX" '$1 ~ "^"p {print $1}' \
        >> "$SEEN_PODS"
}

# Returns 0 (true) if this pod should be frozen: matches our prefix, is in an
# early phase (Pending/Init/ContainerCreating), and has not been seen before.
pod_is_new() {
    local name="$1" status="$2"
    case "$name" in
        ${LAUNCHER_PREFIX}*) ;;
        *) return 1 ;;
    esac
    case "$status" in
        Running|Terminating|Succeeded|Failed|Completed|Error) return 1 ;;
    esac
    grep -qxF "$name" "$SEEN_PODS" 2>/dev/null && return 1
    return 0
}

mark_seen() {
    echo "$1" >> "$SEEN_PODS"
}

get_pod_uid() {
    kubectl -n "$NS" get pod "$1" \
        -o jsonpath='{.metadata.uid}' 2>/dev/null
}

# Polls for the pod-level freezer.state path up to 2 seconds.
find_cgroup() {
    local uid="$1" i=0 cgroup
    while [ "$i" -lt 20 ]; do
        cgroup=$(find /sys/fs/cgroup/freezer/kubepods -name "freezer.state" \
                 -path "*pod${uid}*" 2>/dev/null | sort | head -1)
        [ -n "$cgroup" ] && echo "$cgroup" && return 0
        sleep 0.1
        i=$((i + 1))
    done
    return 1
}

freeze_pod() {
    local pod="$1" uid="$2" cgroup="$3"
    echo FROZEN > "$cgroup"
    echo "$cgroup" >> "$FROZEN_CGROUPS"
    echo "$(date '+%H:%M:%S') Frozen:  $pod"
    echo "          UID:     $uid"
    echo "          Cgroup:  $cgroup"
}

thaw_all() {
    [ ! -s "$FROZEN_CGROUPS" ] && return
    echo "Thawing all frozen pods..."
    while IFS= read -r cgroup; do
        [ -f "$cgroup" ] && echo THAWED > "$cgroup" \
            && echo "  Thawed: $cgroup"
    done < "$FROZEN_CGROUPS"
}

# Called for each new pod event. Marks it seen immediately to prevent
# duplicate processing if the watch stream emits multiple events for it.
handle_pod() {
    local pod="$1"
    mark_seen "$pod"

    local uid
    uid=$(get_pod_uid "$pod")
    if [ -z "$uid" ]; then
        echo "$(date '+%H:%M:%S') Skip: could not get UID for $pod"
        return
    fi

    local cgroup
    cgroup=$(find_cgroup "$uid")
    if [ -z "$cgroup" ]; then
        echo "$(date '+%H:%M:%S') Skip: cgroup not found for $pod (UID $uid)"
        return
    fi

    freeze_pod "$pod" "$uid" "$cgroup"
}

# Streams pod watch events from the API server via a FIFO (avoiding a
# subshell so SEEN_PODS and FROZEN_CGROUPS remain writable). Exits when
# HOLD_SECS have elapsed or the watch stream closes.
watch_and_freeze() {
    local deadline=$(($(date +%s) + HOLD_SECS))

    mkfifo "$WATCH_PIPE"
    timeout "$HOLD_SECS" \
        kubectl -n "$NS" get pods -w --no-headers 2>/dev/null \
        > "$WATCH_PIPE" &
    WATCH_PID=$!

    local name status
    while IFS= read -r line; do
        [ "$(date +%s)" -ge "$deadline" ] && break

        name=$(echo "$line" | awk '{print $1}')
        status=$(echo "$line" | awk '{print $3}')

        pod_is_new "$name" "$status" || continue
        handle_pod "$name"
    done < "$WATCH_PIPE"

    kill "$WATCH_PID" 2>/dev/null
    rm -f "$WATCH_PIPE"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

VMI=$(find_vmi)
[ -z "$VMI" ] && { echo "error: no VMI for '${APP_PREFIX}' in ${NS}" >&2; exit 1; }

OLD_POD=$(kubectl -n "$NS" get pods --no-headers 2>/dev/null \
          | awk -v p="$LAUNCHER_PREFIX" '$1 ~ "^"p {print $1}' | head -1)

echo "VMI:     $VMI"
echo "Old pod: ${OLD_POD:-<none>}"
echo "Hold:    ${HOLD_SECS}s"
echo ""

seed_seen_pods
delete_vmi_async "$VMI"
echo "Watching for replacement pods to freeze..."
echo ""

watch_and_freeze

echo ""
echo "Hold period expired — thawing and exiting."
