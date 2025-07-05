#!/bin/sh
#
# Copyright (c) 2025 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# kubevip-delete.sh
# This script deletes the Kube-VIP ConfigMap and associated resources.
# This script is for testing only, not for production use.

if kubectl delete -f /etc/kubevip-ds.yaml && \
   kubectl delete -f /etc/kubevip-cm.yaml && \
   kubectl delete -f /etc/kubevip-sa.yaml; then
    echo "Kube-VIP resources successfully removed"
else
    echo "Error deleting Kube-VIP resources"
    exit 1
fi
