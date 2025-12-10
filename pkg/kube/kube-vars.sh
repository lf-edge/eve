#!/bin/sh
#
# Copyright (c) 2025 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

# Base Static k3s Config is in /etc/rancher/k3s/config.yaml, following config in each file
K3S_CONFIG_DIR="/etc/rancher/k3s/config.yaml.d"
# shellcheck disable=SC2034
k3s_nodename_config_file="${K3S_CONFIG_DIR}/00-nodename.yaml"
# shellcheck disable=SC2034
k3s_cluster_config_file="${K3S_CONFIG_DIR}/01-clusterconfig.yaml"
# shellcheck disable=SC2034
K3S_USER_OVERRIDE_CONFIG_SRC="/persist/vault/k3s-user-override.yaml"
# shellcheck disable=SC2034
K3S_USER_OVERRIDE_CONFIG_DST="${K3S_CONFIG_DIR}/99-k3s-config-user-overrides.yaml"