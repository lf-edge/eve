#!/bin/sh
#
# Copyright (c) 2024 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

LOG_DIR=/persist/newlog/kube

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