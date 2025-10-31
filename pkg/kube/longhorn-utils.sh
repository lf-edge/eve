#!/bin/sh
#
# Copyright (c) 2024 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

# shellcheck source=/dev/null
. /usr/bin/cluster-utils.sh

LONGHORN_VERSION=v1.9.1

# Used to gate logging only once in Longhorn_is_ready
bootLhRdyComplete=""

longhorn_rdy_complete_file() {
    if [ "$bootLhRdyComplete" = "" ]; then
        bootLhRdyComplete=$(mktemp /tmp/lhreadyXXXXXX)
    fi
}

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

Longhorn_uninstall() {
    logmsg "longhorn_uninstall ${LONGHORN_VERSION} beginning"
    while ! kubectl apply -f /etc/longhorn_uninstall_settings.yaml; do
        sleep 5
    done
    logmsg "longhorn_uninstall: set uninstall setting"

    while ! kubectl create -f https://raw.githubusercontent.com/longhorn/longhorn/${LONGHORN_VERSION}/uninstall/uninstall.yaml; do
        sleep 5
    done
    logmsg "longhorn_uninstall job wait begun"

    # A clean idle system can take ~1 min, allow for some delay
    i=1
    while [ $i -lt 1000 ]; do
        success=$(kubectl get job/longhorn-uninstall -n longhorn-system -o jsonpath='{.status.succeeded}')
        if [ "$success" = "1" ]; then
                logmsg "longhorn_uninstall job success"
                break
        fi
        sleep 5
        i=$((i+1))
    done
    logmsg "longhorn_uninstall job wait stopped"

    # Can return failure for non-fatal conditions
    kubectl delete -f https://raw.githubusercontent.com/longhorn/longhorn/${LONGHORN_VERSION}/deploy/longhorn.yaml
    logmsg "longhorn_uninstall deploy deleted"

    kubectl delete -f https://raw.githubusercontent.com/longhorn/longhorn/${LONGHORN_VERSION}/uninstall/uninstall.yaml
    logmsg "longhorn_uninstall job deletion"

    lhScs=$(kubectl get sc -o jsonpath='{range .items[?(@.provisioner=="driver.longhorn.io")]}{.metadata.name}{" "}{end}')
    for sc in $lhScs; do
        kubectl delete sc "$sc" >> "$INSTALL_LOG" 2>&1
    done

    rm /var/lib/longhorn_initialized
    return 0
}

cleanup_storageclasses() {
        if [ -e "${KUBE_MANIFESTS_DIR}/storage-classes.yaml" ]; then
                rm "${KUBE_MANIFESTS_DIR}/storage-classes.yaml"
        fi
        if kubectl -n kube-system get AddOn/storage-classes; then
                kubectl -n kube-system delete AddOn/storage-classes >> "$INSTALL_LOG" 2>&1
        fi
        if kubectl get sc lh-sc-rep1; then
                logmsg "Removing storage-classes"
                kubectl delete -f /etc/k3s-manifests/storage-classes.yaml
        fi
}

longhorn_node_create() {
    node="$1"
    kubectl apply -f - <<EOF
---
apiVersion: longhorn.io/v1beta2
kind: Node
metadata:
  name: ${node}
  namespace: longhorn-system
spec:
  allowScheduling: true
  evictionRequested: false
  tags: []
EOF
}

# Longhorn_is_ready is expected to be called periodically during runtime
# It attempts to detect and recover from various installation issues
# which block unattended install/config experience.
Longhorn_is_ready() {
    longhorn_rdy_complete_file

    # Namespace will exist while longhorn uninstall job completes.
    # Don't get in its way, submitting node creations.
    if [ -f /tmp/replicated-storage-uninstall-inprogress ]; then
        return 1
    fi
    if [ -f /var/lib/base-k3s-mode ]; then
        return 0
    fi

    if ! kubectl get namespace/longhorn-system; then
        return 0
    fi

    # All ds ready
    lhStatus=$(kubectl -n longhorn-system get daemonsets -o json | jq '.items[].status | .numberReady==.desiredNumberScheduled' | tr -d '\n')
    if [ "$lhStatus" != "truetruetrue" ]; then
        if [ -e "${bootLhRdyComplete}" ]; then
                # Allow the final ready log message when its reached.
                rm "$bootLhRdyComplete"
        fi
        return 1
    fi

    if [ ! -e /persist/status/zedagent/EdgeNodeInfo/global.json ]; then
        return 1
    fi

    node=$(jq -r '.DeviceName' < /persist/status/zedagent/EdgeNodeInfo/global.json | tr -d '\n')
    node=$(convert_to_k8s_compatible "$node")

    # longhorn node exists
    if ! kubectl -n longhorn-system get nodes.longhorn.io "$node"; then
        if [ -e "${bootLhRdyComplete}" ]; then
                # Allow the final ready log message when its reached.
                rm "$bootLhRdyComplete"
        fi

        logmsg "lh nodes.longhorn.io $node missing, creating"

        # Recovery attempt
        longhorn_node_create "$node"
        return 1
    fi

    # ndm has all nodes
    ndm=$(kubectl -n longhorn-system get engineimage -o json | jq .items[].status.nodeDeploymentMap)
    dep=$(echo "$ndm" | jq --arg n "$node" '.[$n]')
    if [ "$dep" != "true" ]; then
        logmsg "lh node:$node engine not deployed"
        # find engine pod name
        pod=$(kubectl -n longhorn-system get pod -l longhorn.io/component=engine-image -o json | jq -r --arg n "$node" '.items[] | select(.spec.nodeName==$n) | .metadata.name')
        if [ "$pod" = "" ]; then
                # maybe restarting or not yet created (new install)
                return 1
        fi
        phase=$(kubectl -n longhorn-system get "pod/${pod}" -o json | jq -r .status.phase)
        if [ "$phase" != "Running" ]; then
                # maybe restarting
                return 1
        fi
        # delete it
        kubectl -n longhorn-system delete "pod/${pod}"
        logmsg "lh node:$node engine:$pod deleted for re-init due to ndm inconsistency"

        # Find the owner of the node deployment map and cycle that pod so it regenerates.
        ndmOwnerID=$(kubectl -n longhorn-system get engineimage -o json | jq -r .items[].status.ownerID)
        if [ "$ndmOwnerID" != "" ]; then
            ndmMgrPod=$(kubectl -n longhorn-system get pod -l app=longhorn-manager  -o json | jq -r --arg n "$ndmOwnerID" '.items[] | select(.spec.nodeName==$n) | .metadata.name')
            if [ "$ndmMgrPod" != "" ]; then
                logmsg "lh ownerID node:$ndmOwnerID manager:$ndmMgrPod deleted for re-init due to ndm inconsistency"
                kubectl -n longhorn-system delete "pod/${ndmMgrPod}"
            fi
        fi

        return 1
    fi
    if [ ! -e "${bootLhRdyComplete}" ]; then
        logmsg "longhorn ds ready, node:$node nodedeploymentmap:$(echo "$ndm" | tr -d '\n')"
        touch "${bootLhRdyComplete}"
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

longhorn_node_set_sched() {
        node_name=$1
        # string "true" or "false"
        enabled=$2
        if [ "$enabled" != "true" ] && [ "$enabled" != "false" ]; then
                logmsg "invalid request for node config: $enabled"
        fi
        sched=$enabled
        evict="false"
        if [ "$enabled" = "false" ]; then
                evict="true"
        fi
        default_disk_name=$(kubectl -n longhorn-system get nodes.longhorn.io "${node_name}" -o json | jq -r '.spec.disks | keys[]')
        {
                kubectl -n longhorn-system patch nodes.longhorn.io "${node_name}" -p "[{'op':'replace','path':'/spec/allowScheduling','value':$sched}]" --type json
                kubectl -n longhorn-system patch nodes.longhorn.io "${node_name}" -p "[{'op':'replace','path':'/spec/evictionRequested','value':$evict}]" --type json
                kubectl -n longhorn-system patch nodes.longhorn.io "${node_name}" -p "[{'op':'replace','path':\"/spec/disks/${default_disk_name}/allowScheduling\",'value':$sched}]" --type json
                kubectl -n longhorn-system patch nodes.longhorn.io "${node_name}" -p "[{'op':'replace','path':\"/spec/disks/${default_disk_name}/evictionRequested\",'value':$evict}]" --type json
        } >> "$INSTALL_LOG" 2>&1
}


longhorn_rescale() {
        req_replica_count=$1

        # Scale all deployments
        depList="csi-attacher csi-provisioner csi-resizer csi-snapshotter"
        for dep in $depList; do
                replica_count=$(kubectl -n longhorn-system get deployment "$dep" -o json | jq -r .spec.replicas)
                if [ "$replica_count" != "$req_replica_count" ]; then
                        logmsg "scaling:$dep"
                        # shellcheck disable=SC2086
                        kubectl -n longhorn-system scale --replicas=${req_replica_count} deployment "$dep" >> "$INSTALL_LOG" 2>&1
                fi
        done

        dsList=$(kubectl -n longhorn-system get daemonset -o json | jq -r .items[].metadata.name)
        for ds in $dsList; do
                for i in $(seq 1 5); do
                        logmsg "setting node selector for ds:$ds"
                        if kubectl patch daemonset "$ds" -n longhorn-system -p '{"spec":{"template":{"spec":{"nodeSelector":{"tie-breaker-node":"false"}}}}}' >> "$INSTALL_LOG" 2>&1; then
                                break
                        fi
                done
        done
}