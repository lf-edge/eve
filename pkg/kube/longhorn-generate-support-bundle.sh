#!/bin/sh

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

ready=0
while [ $ready -ne 1 ]; do
    state=$(kubectl -n longhorn-system get supportbundle.longhorn.io/support-bundle-collect-info -o json | jq -r .status.state)
    if [ "$state" = "ReadyForDownload" ]; then
        ready=1
        break
    fi
    sleep 10
    progress=$(kubectl -n longhorn-system get supportbundle.longhorn.io/support-bundle-collect-info -o json | jq -r .status.progress)
    echo "support bundle progress percentage: $progress"
done

ip=$(kubectl -n longhorn-system get supportbundle.longhorn.io/support-bundle-collect-info -o json | jq -r .status.managerIP)
filename=$(kubectl -n longhorn-system get supportbundle.longhorn.io/support-bundle-collect-info -o json | jq -r .status.filename)

old_log_count=$(find "$LOG_DIR" -type f -name "longhornsupportbundle_*" | wc -l)
if [ "$old_log_count" -gt 4 ]; then
    # shellcheck disable=SC2046
    rm $(find "$LOG_DIR" -type f -name "longhornsupportbundle_*" | sort -n | head -n -4)
fi

curl "http://${ip}:8080/bundle" > "${LOG_DIR}/longhorn${filename}"
echo "longhorn support bundle downloaded to ${LOG_DIR}/longhorn${filename}"

kubectl -n longhorn-system delete supportbundle.longhorn.io/support-bundle-collect-info
