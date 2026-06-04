#!/bin/sh
#
# Copyright (c) 2024-2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

LOG_DIR=/persist/kubelog
BUNDLE_NAME=support-bundle-collect-info
BUNDLE_TIMEOUT_SECONDS=${TIMEOUT_SECONDS:-300}

# This script is called from collect-info, help it avoid a timeout
# by checking for longhorn installed state and return before applying
# the support bundle manifest.
if ! kubectl get namespace/longhorn-system; then
    echo "Longhorn not installed, skipping SupportBundle"
    exit 1
fi

echo "============"
echo "kubectl -n longhorn-system get replicaset,deployment,daemonset,service,pod,volume,replica,engine,engineimage,nodes.longhorn.io,volumeattachments.longhorn.io -o wide"
echo "============"
kubectl -n longhorn-system get replicaset,deployment,daemonset,service,pod,volume,replica,engine,engineimage,nodes.longhorn.io,volumeattachments.longhorn.io -o wide
echo "============"
echo "kubectl -n longhorn-system get volume fields:  .metadata.name spec.nodeID status.currentNodeID status.ownerID status.pendingNodeId"
echo "============"
kubectl -n longhorn-system get volume -o json | jq '.items[] | "name:\(.metadata.name) spec.nodeID:\(.spec.nodeID) status.currentNodeID:\(.status.currentNodeID) status.ownerID:\(.status.ownerID) status.pendingNodeId:\(.status.pendingNodeID)"'
echo "============"

# Check whether an existing bundle can be reused, needs cleanup, or is stale.
# Returns: "ready", "wait", "delete", or "none"
check_existing_bundle() {
    existing=$(kubectl -n longhorn-system get supportbundle.longhorn.io/"${BUNDLE_NAME}" -o json 2>/dev/null) || { echo "none"; return; }

    state=$(echo "$existing" | jq -r '.status.state // "Unknown"')
    creation_ts=$(echo "$existing" | jq -r '.metadata.creationTimestamp // ""')

    age=0
    if [ -n "$creation_ts" ]; then
        created_epoch=$(date -d "$creation_ts" +%s 2>/dev/null || date -j -f "%Y-%m-%dT%H:%M:%SZ" "$creation_ts" +%s 2>/dev/null || echo 0)
        now_epoch=$(date +%s)
        age=$((now_epoch - created_epoch))
    fi

    case "$state" in
        ReadyForDownload)
            # A previously downloaded bundle that has aged out is safe to delete
            # on the next run; this avoids a multi-node race where all nodes
            # simultaneously download and delete the same bundle.
            if [ "$age" -gt "$BUNDLE_TIMEOUT_SECONDS" ]; then
                echo "Existing bundle is $age seconds old and ReadyForDownload — treating as stale" >&2
                echo "delete"
                return
            fi
            echo "ready"
            return
            ;;
        Error)
            echo "delete"
            return
            ;;
    esac

    # For in-progress states, check how old the bundle is. If it exceeds
    # BUNDLE_TIMEOUT_SECONDS the node that created it likely died mid-generation.
    if [ "$age" -gt "$BUNDLE_TIMEOUT_SECONDS" ]; then
        echo "Existing bundle is $age seconds old and in state '$state' — treating as stale" >&2
        echo "delete"
        return
    fi

    echo "wait"
}

echo "Checking for existing support bundle at $(date)"
action=$(check_existing_bundle)

if [ "$action" = "delete" ]; then
    echo "Deleting existing bundle in error/stale state"
    kubectl -n longhorn-system delete supportbundle.longhorn.io/"${BUNDLE_NAME}" --ignore-not-found
    # Wait for the deletion to complete before recreating
    kubectl -n longhorn-system wait --for=delete supportbundle.longhorn.io/"${BUNDLE_NAME}" --timeout=60s 2>/dev/null || true
    action="none"
fi

if [ "$action" = "none" ]; then
    echo "Applying longhorn support bundle yaml at $(date)"
    cat <<EOF | kubectl apply -f -
---
apiVersion: longhorn.io/v1beta2
kind: SupportBundle
metadata:
  name: ${BUNDLE_NAME}
  namespace: longhorn-system
spec:
  description: collect-info
  issueURL: ""
  nodeID: ""
EOF
elif [ "$action" = "ready" ]; then
    echo "Existing support bundle is already ReadyForDownload, skipping generation"
elif [ "$action" = "wait" ]; then
    echo "Another node is already generating the support bundle, waiting for it to complete"
fi

# Wait for bundle to reach ReadyForDownload, with a hard timeout.
deadline=$(($(date +%s) + BUNDLE_TIMEOUT_SECONDS))
while true; do
    state=$(kubectl -n longhorn-system get supportbundle.longhorn.io/"${BUNDLE_NAME}" -o json 2>/dev/null | jq -r '.status.state // "Unknown"')
    if [ "$state" = "ReadyForDownload" ]; then
        break
    fi
    if [ "$state" = "Error" ]; then
        echo "Support bundle entered Error state, aborting"
        kubectl -n longhorn-system delete supportbundle.longhorn.io/"${BUNDLE_NAME}" --ignore-not-found
        exit 1
    fi
    if [ "$(date +%s)" -ge "$deadline" ]; then
        echo "Timed out waiting for support bundle after ${BUNDLE_TIMEOUT_SECONDS}s (state: $state)"
        kubectl -n longhorn-system delete supportbundle.longhorn.io/"${BUNDLE_NAME}" --ignore-not-found
        exit 1
    fi
    sleep 10
    progress=$(kubectl -n longhorn-system get supportbundle.longhorn.io/"${BUNDLE_NAME}" -o json 2>/dev/null | jq -r '.status.progress // 0')
    echo "support bundle progress percentage: $progress"
done

ip=$(kubectl -n longhorn-system get supportbundle.longhorn.io/"${BUNDLE_NAME}" -o json | jq -r .status.managerIP)
filename=$(kubectl -n longhorn-system get supportbundle.longhorn.io/"${BUNDLE_NAME}" -o json | jq -r .status.filename)

# Sort creation time, keep 4 latest support bundles
find "${LOG_DIR}" -name "longhornsupportbundle_*" | sort -n | head -n -4 | xargs rm -f

curl "http://${ip}:8080/bundle" > "${LOG_DIR}/longhorn${filename}"
echo "longhorn support bundle downloaded to ${LOG_DIR}/longhorn${filename}"

# Bundle is intentionally left in ReadyForDownload state so that other nodes
# can download it. check_existing_bundle will delete it on the next run once
# it has aged past BUNDLE_TIMEOUT_SECONDS.
