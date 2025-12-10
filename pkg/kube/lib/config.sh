#!/bin/sh
#
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

# Base Static k3s Config is in /etc/rancher/k3s/config.yaml, following config in each file
K3S_CONFIG_DIR="/etc/rancher/k3s/config.yaml.d"
# shellcheck disable=SC2034
K3S_NODENAME_CONFIG_FILE="${K3S_CONFIG_DIR}/00-nodename.yaml"
# shellcheck disable=SC2034
K3S_CLUSTER_CONFIG_FILE="${K3S_CONFIG_DIR}/01-clusterconfig.yaml"
# shellcheck disable=SC2034
K3S_USER_OVERRIDE_CONFIG_SRC="/persist/vault/k3s-user-override.yaml"
# shellcheck disable=SC2034
K3S_USER_OVERRIDE_CONFIG_DST="${K3S_CONFIG_DIR}/99-k3s-config-user-overrides.yaml"

# Config_k3s_override_apply - sync config if changed
# return 0 - for no change, 1 - config added, 2 - config changed, 3 - config removed
Config_k3s_override_apply() {
    # Config not defined from controller
    if [ ! -f "$K3S_USER_OVERRIDE_CONFIG_SRC" ]; then
            if [ ! -f "$K3S_USER_OVERRIDE_CONFIG_DST" ]; then
                    # No current config exists, no change, exit
                    return 0
            fi
            rm "$K3S_USER_OVERRIDE_CONFIG_DST"
            return 3
    fi

    # Config set from controller
    if [ ! -f "$K3S_USER_OVERRIDE_CONFIG_DST" ]; then
            cp "$K3S_USER_OVERRIDE_CONFIG_SRC" "$K3S_USER_OVERRIDE_CONFIG_DST"
            return 1
    fi

    # Config may be updated from controller
    if ! cmp -s "$K3S_USER_OVERRIDE_CONFIG_SRC" "$K3S_USER_OVERRIDE_CONFIG_DST"; then
            cp -f "$K3S_USER_OVERRIDE_CONFIG_SRC" "$K3S_USER_OVERRIDE_CONFIG_DST"
            return 2
    fi
    # Config exists, unchanged
    return 0
}