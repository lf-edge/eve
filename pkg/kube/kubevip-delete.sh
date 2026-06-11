#!/bin/sh
#
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# kubevip-delete.sh
# Removes Kube-VIP resources from the cluster. The ConfigMap is
# generated at apply-time by kubevip-apply.sh and may not exist on
# nodes that never applied (e.g. non-bootstrap nodes); we delete by
# name so the operation is idempotent across both shapes.

INSTALL_LOG="/persist/kubelog/k3s-install.log"

logmsg() {
    ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    printf '%s kubevip-delete: %s\n' "$ts" "$*" | tee -a "$INSTALL_LOG"
}

failed=0
kubectl delete --ignore-not-found -f /etc/kubevip-ds.yaml || failed=1
kubectl delete --ignore-not-found configmap kubevip -n kube-system || failed=1
kubectl delete --ignore-not-found -f /etc/kubevip-sa.yaml || failed=1
if [ "$failed" -eq 0 ]; then
    logmsg "Kube-VIP resources successfully removed"
else
    logmsg "Error deleting one or more Kube-VIP resources"
    exit 1
fi
