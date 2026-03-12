#!/bin/sh
#
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Script to manually stop/start k3s for debugging purposes
#

K3S_LOG_DIR="/persist/kubelog"
INSTALL_LOG="${K3S_LOG_DIR}/k3s-install.log"

# shellcheck source=pkg/kube/cluster-utils.sh
. /usr/bin/cluster-utils.sh

# Wait for /var/lib to be ready (it might be a mount point)
# But don't wait forever
MAX_WAIT=30
WAITED=0
while [ ! -d /var/lib ] && [ $WAITED -lt $MAX_WAIT ]; do
    sleep 1
    WAITED=$((WAITED + 1))
done

ACTION="$1"
if [ -z "$ACTION" ]; then
    # Detect action from filename (e.g., k3s-stop -> stop)
    ACTION=$(basename "$0" | sed 's/k3s-//')
fi

case "$ACTION" in
    stop)
        logmsg "Manual k3s stop requested"
        mkdir -p "$(dirname "$K3S_STOP_FLAG")"
        touch "$K3S_STOP_FLAG"
        if terminate_k3s; then
            logmsg "Manual k3s stop completed"
            echo "k3s stopped"
        else
            logmsg "Manual k3s stop failed"
            echo "Failed to stop k3s"
            exit 1
        fi
        ;;
    start)
        logmsg "Manual k3s start requested"
        rm -f "$K3S_STOP_FLAG"
        touch "$K3S_MANUAL_START_FLAG"
        logmsg "Removed stop flag, k3s should restart shortly"
        echo "k3s start requested (monitor status with k3s-status)"
        ;;
    status)
        pids=$(pgrep -f "$K3S_SERVER_CMD")
        if [ -n "$pids" ]; then
            echo "Status: Running (PIDs: $pids)"
        else
            echo "Status: Stopped"
        fi

        if [ -f "$K3S_STOP_FLAG" ]; then
            echo "Stop Flag: Present ($K3S_STOP_FLAG)"
        else
            echo "Stop Flag: Absent"
        fi
        ;;
    *)
        echo "Usage: $(basename "$0") {stop|start|status}"
        exit 1
        ;;
esac
