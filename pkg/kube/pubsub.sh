#!/bin/sh
#
# Copyright (c) 2025 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

# shellcheck disable=SC2034
ENCC_FILE_PATH="/run/zedagent/EdgeNodeClusterConfig/global.json"

# XXX also need to make this !persist
# shellcheck disable=SC2034
KUBECFG_FILE_PATH="/persist/status/zedkube/KubeConfig/global.json"

# XXX need to unpersist this too
# shellcheck disable=SC2034
KCUS_FILE_PATH="/persist/status/zedagent/KubeClusterUpdateStatus/global.json"

# XXX will callers wait for initial?
ZedKube_KubeConfig_exists() {
    if [ -f "$KUBECFG_FILE_PATH" ]; then
        return 0
    fi
    return 1
}

ZedKube_KubeConfig_k3sVersion() {
    if ! ZedKube_KubeConfig_exists; then
        echo ""
        return
    fi
    jq -r .K3sVersion < "$KUBECFG_FILE_PATH"
}
