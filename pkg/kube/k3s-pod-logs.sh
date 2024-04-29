#!/bin/sh
rm -f /persist/newlog/kube/k3s-pod-logs-*.tar.gz
OUT_FILE=/persist/newlog/kube/k3s-pod-logs-$(date +'%Y%m%d-%H%M%S' -u).tar.gz
tar cfz "$OUT_FILE" -C /var/log/pods/ .
echo "Created: $OUT_FILE"