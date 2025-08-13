#!/bin/sh
#
# Copyright (c) 2024 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

LOG_DIR=/persist/kubelog

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

echo "Apply longhorn support bundle yaml at $(date)"

cat <<EOF | kubectl apply -f -
---
apiVersion: longhorn.io/v1beta2
kind: SupportBundle
metadata:
  name: support-bundle-collect-info
  namespace: longhorn-system
spec:
  description: collect-info
  issueURL: ""
  nodeID: ""
EOF

while true; do
    state=$(kubectl -n longhorn-system get supportbundle.longhorn.io/support-bundle-collect-info -o json | jq -r .status.state)
    if [ "$state" = "ReadyForDownload" ]; then
        break
    fi
    sleep 10
    progress=$(kubectl -n longhorn-system get supportbundle.longhorn.io/support-bundle-collect-info -o json | jq -r .status.progress)
    echo "support bundle progress percentage: $progress"
done

ip=$(kubectl -n longhorn-system get supportbundle.longhorn.io/support-bundle-collect-info -o json | jq -r .status.managerIP)
filename=$(kubectl -n longhorn-system get supportbundle.longhorn.io/support-bundle-collect-info -o json | jq -r .status.filename)

# Sort creation time, keep 4 latest support bundles
find "${LOG_DIR}" -name "longhornsupportbundle_*" | sort -n | head -n -4 | xargs rm -f

curl "http://${ip}:8080/bundle" > "${LOG_DIR}/longhorn${filename}"
echo "longhorn support bundle downloaded to ${LOG_DIR}/longhorn${filename}"

kubectl -n longhorn-system delete supportbundle.longhorn.io/support-bundle-collect-info