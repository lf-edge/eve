#!/bin/sh
#
# Copyright (c) 2024 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

# shellcheck source=pkg/kube/descheduler-utils.sh
. /usr/bin/descheduler-utils.sh

EdgeNodeInfoPath="/persist/status/zedagent/EdgeNodeInfo/global.json"
COMP_UPDATE_PATH="/usr/bin/update-component"

link_multus_into_k3s() {
    ln -s /var/lib/cni/bin/multus /var/lib/rancher/k3s/data/current/bin/multus
}

# Update_RunDeschedulerOnBoot will run the descheduler to evict pods from the edge node
# on boot. This is to allow rebalancing apps via re-scheduling them with an aim to meet
# affinity as specified in the pod config.
Update_RunDeschedulerOnBoot() {
    # Currently only run once per boot
    if [ -f /tmp/descheduler-ran-onboot ]; then
        return
    fi

    if [ ! -f $EdgeNodeInfoPath ]; then
        return
    fi
    # is api ready
    if ! update_isClusterReady; then
        return
    fi
    # Don't run unless it has been installed
    if ! descheduler_install; then
        return
    fi
    # node ready and allowing scheduling
    node=$(jq -r '.DeviceName' < $EdgeNodeInfoPath | tr -d '\n' | tr '[:upper:]' '[:lower:]')
    node_count_ready=$(kubectl get "node/${node}" | grep -v SchedulingDisabled | grep -cw Ready )
    if [ "$node_count_ready" -ne 1 ]; then
        return
    fi
    # Ensure all infrastructure pods are online on node
    lhStatus=$(kubectl -n longhorn-system get daemonsets -o json | jq '.items[].status | .numberReady==.desiredNumberScheduled' | tr -d '\n')
    if [ "$lhStatus" != "truetruetrue" ]; then
        return
    fi
    kvStatus=$(kubectl -n kubevirt get daemonsets -o json | jq '.items[].status | .numberReady==.desiredNumberScheduled' | tr -d '\n')
    if [ "$kvStatus" != "true" ]; then
        return
    fi
    # Job lives persistently in cluster, cleanup after old runs
    if kubectl -n kube-system get job/descheduler-job; then
        kubectl -n kube-system delete job/descheduler-job
    fi
    kubectl apply -f /etc/descheduler-job.yaml
    touch /tmp/descheduler-ran-onboot
}

update_isClusterReady() {
    if ! kubectl cluster-info; then
        return 1
    fi

    if ! update_Helper_APIResponding; then
        return 1
    fi
    return 0
}

update_Helper_APIResponding() {
    if $COMP_UPDATE_PATH --check-api-ready; then
        return 0
    fi
    return 1
}