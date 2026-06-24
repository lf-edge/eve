#!/bin/sh
#
# Copyright (c) 2024 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

# shellcheck source=/dev/null
. /usr/bin/cluster-utils.sh
# shellcheck source=/dev/null
. /usr/bin/registration-utils.sh

LONGHORN_VERSION=v1.9.1

# Filesystem path Longhorn is told to use as its default disk (on /persist).
LONGHORN_DISK_PATH="/persist/vault/volumes"

# Resource floors below which Longhorn is unlikely to come up / schedule
# replicas reliably. These drive the pre-flight warnings in
# longhorn_preflight_check(); they are advisory (logged, not fatal).
#   - Memory: Longhorn documents a 4 GiB per-node minimum, and that is for
#     Longhorn alone - it runs alongside k3s and kubevirt here, so a node at
#     the floor is already tight (https://longhorn.io/docs/1.9.1/best-practices/).
#   - Storage: Longhorn refuses to schedule replicas once a disk drops below
#     storageMinimalAvailablePercentage (default 25%) of its capacity. On a
#     small /persist (e.g. a 32 GiB boot disk) EVE's own usage pushes available
#     under that floor and no replica can be placed; a 64 GiB boot disk leaves
#     enough headroom. We warn when the schedulable slice is below
#     LONGHORN_MIN_SCHEDULABLE_GIB.
LONGHORN_MIN_MEM_GIB=4
LONGHORN_MIN_STORAGE_PCT=25
LONGHORN_MIN_SCHEDULABLE_GIB=16

# Used to gate logging only once in Longhorn_is_ready
bootLhRdyComplete=""

# longhorn_preflight_check warns (to the k3s install log) when node memory or the
# schedulable space on the Longhorn default-disk path is below what Longhorn needs
# to start and place replicas. Advisory only: it never fails the install (returns 0).
longhorn_preflight_check() {
    mem_kib=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo 2>/dev/null)
    if [ -n "$mem_kib" ]; then
        mem_gib=$((mem_kib / 1024 / 1024))
        if [ "$mem_gib" -lt "$LONGHORN_MIN_MEM_GIB" ]; then
            logmsg "WARNING: node has ${mem_gib} GiB RAM; Longhorn needs at least ${LONGHORN_MIN_MEM_GIB} GiB per node (and more running alongside k3s/kubevirt). Longhorn may fail to start reliably; provision more memory."
        fi
    else
        logmsg "WARNING: could not read MemTotal from /proc/meminfo; skipping Longhorn memory pre-flight check"
    fi

    disk_path="$LONGHORN_DISK_PATH"
    [ -d "$disk_path" ] || disk_path="/persist"
    # -P guarantees single-line POSIX output, so columns are fixed: 2=total, 4=available.
    # shellcheck disable=SC2046 # intentional split of df's two-number output
    set -- $(df -kP "$disk_path" 2>/dev/null | awk 'NR==2 {print $2, $4}')
    if [ "$#" -eq 2 ]; then
        total_kib=$1
        avail_kib=$2
        total_gib=$((total_kib / 1024 / 1024))
        avail_gib=$((avail_kib / 1024 / 1024))
        reserve_kib=$((total_kib * LONGHORN_MIN_STORAGE_PCT / 100))
        sched_kib=$((avail_kib - reserve_kib))
        [ "$sched_kib" -lt 0 ] && sched_kib=0
        sched_gib=$((sched_kib / 1024 / 1024))
        if [ "$sched_gib" -lt "$LONGHORN_MIN_SCHEDULABLE_GIB" ]; then
            logmsg "WARNING: Longhorn default disk ${disk_path} has ${avail_gib} GiB free of ${total_gib} GiB; after the ${LONGHORN_MIN_STORAGE_PCT}% Longhorn reserve only ~${sched_gib} GiB is schedulable (< ${LONGHORN_MIN_SCHEDULABLE_GIB} GiB). Replicas may fail to schedule; a 64 GiB boot disk is recommended for EVE-k."
        fi
    else
        logmsg "WARNING: could not read df output for ${disk_path}; skipping Longhorn storage pre-flight check"
    fi
    return 0
}

longhorn_install() {
    node_name=$1
    logmsg "Installing longhorn version ${LONGHORN_VERSION}"
    longhorn_preflight_check
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
    longhorn_post_install_config_clean
    while ! kubectl apply -f /etc/longhorn_uninstall_settings.yaml; do
        sleep 5
    done
    logmsg "longhorn_uninstall: set uninstall setting"

    while ! mgmtproxy_run kubectl create -f https://raw.githubusercontent.com/longhorn/longhorn/${LONGHORN_VERSION}/uninstall/uninstall.yaml; do
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
    mgmtproxy_run kubectl delete -f https://raw.githubusercontent.com/longhorn/longhorn/${LONGHORN_VERSION}/deploy/longhorn.yaml
    logmsg "longhorn_uninstall deploy deleted"

    mgmtproxy_run kubectl delete -f https://raw.githubusercontent.com/longhorn/longhorn/${LONGHORN_VERSION}/uninstall/uninstall.yaml
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
# We assume that when this is called zedagent has initialized and
# published EdgeNodeInfo (from a checkpoint if disconnected),
Longhorn_is_ready() {
    # Namespace will exist while longhorn uninstall job completes.
    # Don't get in its way, submitting node creations.
    if [ -f /tmp/replicated-storage-uninstall-inprogress ]; then
        return 1
    fi
    if [ -f /var/lib/native-kubernetes-mode ]; then
        return 0
    fi

    if ! kubectl get namespace/longhorn-system; then
        return 0
    fi

    # All ds ready
    lhStatus=$(kubectl -n longhorn-system get daemonsets -o json | jq '.items[].status | .numberReady==.desiredNumberScheduled' | tr -d '\n')
    if [ "$lhStatus" != "truetruetrue" ]; then
        if [ -n "${bootLhRdyComplete}" ]; then
                # Allow the final ready log message when its reached.
                bootLhRdyComplete=""
        fi
        return 1
    fi

    if [ ! -e /run/zedagent/EdgeNodeInfo/global.json ]; then
        return 1
    fi

    node=$(jq -r '.DeviceName' < /run/zedagent/EdgeNodeInfo/global.json | tr -d '\n')
    node=$(convert_to_k8s_compatible "$node")

    # longhorn node exists
    if ! kubectl -n longhorn-system get nodes.longhorn.io "$node"; then
        if [ -n "${bootLhRdyComplete}" ]; then
                # Allow the final ready log message when its reached.
                bootLhRdyComplete=""
        fi

        logmsg "lh nodes.longhorn.io $node missing, creating"

        # Recovery attempt
        longhorn_node_create "$node"
        return 1
    fi

    # Tie breaker nodes disable scheduling for a node, use the longhorn api to avoid an unnecessary dependency here.
    # This avoids a regular "not deployed" print.
    ndm=""
    schedulable=$(kubectl -n longhorn-system get nodes.longhorn.io "$node" -o json | jq -r '.status.conditions[] | select(.type=="Schedulable") | .status')
    if [ "$schedulable" = "True" ]; then
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
    elif [ "$schedulable" != "False" ]; then
        logmsg "Unable to determine lh node $node Schedulable status, Condition missing or unexpected value, not ready yet"
        return 1
    fi

    if [ -z "${bootLhRdyComplete}" ]; then
        logmsg "longhorn ds ready, node:$node nodedeploymentmap:$(echo "$ndm" | tr -d '\n')"
        bootLhRdyComplete="1"
    fi
    return 0
}

apply_longhorn_disk_config() {
        node=$1
        kubectl label node "$node" node.longhorn.io/create-default-disk='config'
        kubectl annotate node "$node" node.longhorn.io/default-disks-config="[ { \"path\":\"${LONGHORN_DISK_PATH}\", \"allowScheduling\":true }]"
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
        lhCfgFilename=longhorn-cfg.yaml
        lhCfgYamlSrcPath=/etc/${lhCfgFilename}
        lhCfgYamlDstPath=${KUBE_MANIFESTS_DIR}/${lhCfgFilename}

        if [ ! -f "$lhCfgYamlDstPath" ]; then
                cp "$lhCfgYamlSrcPath" "$lhCfgYamlDstPath"
        fi
}

longhorn_post_install_config_clean() {
        if [ -f "$lhCfgYamlDstPath" ]; then
                rm "$lhCfgYamlDstPath"
        fi
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
