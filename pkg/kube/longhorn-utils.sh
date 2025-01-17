#!/bin/sh
#
# Copyright (c) 2024 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

LONGHORN_VERSION=v1.6.3

longhorn_install() {
    node_name=$1
    logmsg "Installing longhorn version ${LONGHORN_VERSION}"
    apply_longhorn_disk_config "$node_name"
    lhCfgPath=/etc/lh-cfg-${LONGHORN_VERSION}.yaml
    if ! grep -q 'create-default-disk-labeled-nodes: true' "$lhCfgPath"; then
            sed -i '/  default-setting.yaml: |-/a\    create-default-disk-labeled-nodes: true' "$lhCfgPath"
    fi
    if ! kubectl apply -f "$lhCfgPath"; then
            return 1
    fi
    return 0
}

longhorn_is_ready() {
    lhStatus=$(kubectl -n longhorn-system get daemonsets -o json | jq '.items[].status | .numberReady==.desiredNumberScheduled' | tr -d '\n')
    if [ "$lhStatus" != "truetruetrue" ]; then
            return 1
    fi
    return 0
}

apply_longhorn_disk_config() {
        node=$1
        kubectl label node "$node" node.longhorn.io/create-default-disk='config'
        kubectl annotate node "$node" node.longhorn.io/default-disks-config='[ { "path":"/persist/vault/volumes", "allowScheduling":true }]'
}

check_overwrite_nsmounter() {
        ### REMOVE ME+
        # When https://github.com/longhorn/longhorn/issues/6857 is resolved, remove this 'REMOVE ME' section
        # In addition to pkg/kube/nsmounter and the copy of it in pkg/kube/Dockerfile
        longhornCsiPluginPods=$(kubectl -n longhorn-system get pod -o json | jq -r '.items[] | select(.metadata.labels.app=="longhorn-csi-plugin" and .status.phase=="Running") | .metadata.name')
        for csiPod in $longhornCsiPluginPods; do
                if ! kubectl -n longhorn-system exec "pod/${csiPod}" --container=longhorn-csi-plugin -- ls /usr/local/sbin/nsmounter.updated > /dev/null 2>@1; then
                        if kubectl -n longhorn-system exec -i "pod/${csiPod}" --container=longhorn-csi-plugin -- tee /usr/local/sbin/nsmounter < /usr/bin/nsmounter; then
                                logmsg "Updated nsmounter in longhorn pod ${csiPod}"
                                kubectl -n longhorn-system exec "pod/${csiPod}" --container=longhorn-csi-plugin -- touch /usr/local/sbin/nsmounter.updated
                        fi
                fi
        done
        ### REMOVE ME-
}

# A spot to do persistent configuration of longhorn
# These are applied once per cluster
longhorn_post_install_config() {
        # Wait for longhorn objects to be available before patching them
        lhSettingsAvailable=$(kubectl -n longhorn-system get settings -o json | jq '.items | length>0')
        if [ "$lhSettingsAvailable" != "true" ]; then
                return
        fi
        kubectl  -n longhorn-system patch settings.longhorn.io/upgrade-checker -p '[{"op":"replace","path":"/value","value":"false"}]' --type json
}