#!/bin/sh
#
# Copyright (c) 2025 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

LOG_DIR=/persist/kubelog

kubectl get events --all-namespaces -o custom-columns="TIME:.metadata.creationTimestamp,NAMESPACE:.metadata.namespace,TYPE:.type,REASON:.reason,OBJECT:.involvedObject.name,MESSAGE:.message" --sort-by='.metadata.creationTimestamp' > ${LOG_DIR}/all-kube-events-sorted.log