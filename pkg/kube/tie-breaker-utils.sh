#!/bin/sh
#
# Copyright (c) 2025 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

# shellcheck source=pkg/kube/pubsub.sh
. /usr/bin/pubsub.sh
# shellcheck source=pkg/kube/longhorn-utils.sh
. /usr/bin/longhorn-utils.sh
# shellcheck source=/dev/null
. /usr/bin/cluster-utils.sh
# shellcheck source=pkg/kube/cluster-update.sh
. /usr/bin/cluster-update.sh
# shellcheck source=pkg/kube/kubevirt-utils.sh
. /usr/bin/kubevirt-utils.sh

tie_breaker_config_isSet() {
    # Read the JSON data from the file, return 0 if successful, 1 if not
    if [ ! -f "$ENCC_FILE_PATH" ]; then
      return 1
    fi
    encc_data=$(cat "$ENCC_FILE_PATH")
    tie_breaker_node_id=$(echo "$encc_data" | jq -r '.TieBreakerNodeID')
    if [ "$tie_breaker_node_id" != "" ]; then
        return 0
    fi
    return 1
}
tie_breaker_config_getNodeUuid() {
    # Read the JSON data from the file, return 0 if successful, 1 if not
    if [ ! -f "$ENCC_FILE_PATH" ]; then
      echo ""
      return 1
    fi
    encc_data=$(cat "$ENCC_FILE_PATH")
    tie_breaker_node_id=$(echo "$encc_data" | jq -r '.TieBreakerNodeID.UUID')
    if [ "$tie_breaker_node_id" != "" ]; then
        echo "$tie_breaker_node_id"
        return 0
    fi
    echo ""
    return 1
}

tie_breaker_status_isSelf() {
        tie_breaker_node_uuid=$1
        if [ "$DEVUUID" = "$tie_breaker_node_uuid" ]; then
                return 0
        else
                return 1
        fi
}
TIE_BREAKER_STATUSLABEL="tie-breaker-config-applied=1"
tie_breaker_status_set() {
        allnodes=$(kubectl get nodes -o jsonpath='{.items[*].metadata.name}')
        for node in $allnodes; do
                kubectl label node "${node}" "${TIE_BREAKER_STATUSLABEL}"
        done
}
tie_breaker_status_get() {
        nodeCount=$(kubectl get node -l "${TIE_BREAKER_STATUSLABEL}" -o go-template='{{len .items}}')
        if [ "$nodeCount" = "3" ]; then
                return 0
        fi
        # New cluster or node replacement
        return 1
}
node_count_is_cluster() {
        nodeCount=$(kubectl get node -o go-template='{{len .items}}')
        if [ "$nodeCount" = "3" ]; then
                return 0
        fi
        return 1
}

# Intended to only be run at cluster creation time by all nodes
Tie_breaker_configApply() {
        if ! tie_breaker_config_isSet; then
                return
        fi

        if [ ! -f /var/lib/node-labels-initialized ]; then
                return
        fi

        if ! node_count_is_cluster; then
                return
        fi

        tie_breaker_node_uuid=$(tie_breaker_config_getNodeUuid)

        if ! tie_breaker_status_isSelf "$tie_breaker_node_uuid"; then
                return
        fi

        # If you're the tie-breaker node: config components then start the drain...
        if tie_breaker_status_get; then
                return
        fi

        tie_breaker_k8s_node_name=$(node_name_from_uuid "$tie_breaker_node_uuid")
        if [ "$tie_breaker_k8s_node_name" = "" ]; then
                return
        fi

        logmsg "tie-breaker config-apply for nodeId:${tie_breaker_node_uuid} node:${tie_breaker_k8s_node_name}"
        Nodes_tie_breaker_config_apply "$tie_breaker_node_uuid"

        logmsg "tie-breaker config-apply:kubevirt"
        Kubevirt_config 2
        Kubevirt_tie_breaker_config_apply

        logmsg "tie-breaker config-apply:cdi"
        Cdi_config

        logmsg "tie-breaker config-apply:longhorn"
        longhorn_node_set_sched "${node}" "false"
        longhorn_rescale 2

        logmsg "evicting tie-breaker nodeId:${tie_breaker_node_uuid} node:${tie_breaker_k8s_node_name}"
        kubectl drain "${tie_breaker_k8s_node_name}" --delete-emptydir-data=true --ignore-daemonsets >> "$INSTALL_LOG" 2>&1
        logmsg "evicted tie-breaker nodeId:${tie_breaker_node_uuid} node:${tie_breaker_k8s_node_name}"

        tie_breaker_status_set
}
