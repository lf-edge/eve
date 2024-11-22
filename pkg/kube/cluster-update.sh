#!/bin/sh
#
# Copyright (c) 2024 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

link_multus_into_k3s() {
    ln -s /var/lib/cni/bin/multus /var/lib/rancher/k3s/data/current/bin/multus
}
