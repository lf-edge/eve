#!/bin/sh
#
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Sourced by cluster-init.sh, and by test/cni-state-utils-test.sh on a build
# host, so it must not source anything or have side effects.

# Where flannel publishes the pod subnet assigned to this node. The flannel CNI
# plugin reads it on every ADD to build the host-local delegate's range, so its
# contents decide which addresses pods on this node are given.
FLANNEL_SUBNET_ENV="/run/flannel/subnet.env"

# host-local's reservation directory for the k3s "cbr0" network: one file per
# address in use, plus last_reserved_ip.
CNI_IPAM_STATE_DIR="/var/lib/cni/networks/cbr0"

# remove_stale_cni_state [subnet_env] [ipam_dir]
#
# Drops the pod-subnet state this node built up while it ran its own
# single-node cluster, so that nothing can hand out an address from the retired
# subnet once the node has joined. The arguments default to the real paths.
#
# A node running standalone owns 10.42.0.0/24; joining assigns it a different
# podCIDR, and flannel rewrites subnet.env to match. Between the join and that
# rewrite the flannel CNI plugin still reads the old subnet, so a pod networked
# in that window is given an address the cluster routes to a different node.
# It never recovers: the address is fixed for the pod's lifetime, and a
# daemonset pod that crash-loops on it restarts in place and keeps it.
#
# Removing subnet.env makes that window fail closed instead. A CNI ADD with no
# subnet to read fails, kubelet retries, and the pod is networked correctly
# once flannel has published the new subnet.
#
# The host-local reservations go too. They are keyed by network name rather
# than by subnet, so the retired subnet's entries would otherwise sit in the
# directory indefinitely; flannel and host-local rebuild both paths on the
# next start.
#
# Absent paths are not an error. Returns non-zero if either removal failed.
remove_stale_cni_state() {
    _rscs_subnet_env="${1:-$FLANNEL_SUBNET_ENV}"
    _rscs_ipam_dir="${2:-$CNI_IPAM_STATE_DIR}"
    _rscs_rc=0
    rm -f "$_rscs_subnet_env" || _rscs_rc=1
    rm -rf "$_rscs_ipam_dir" || _rscs_rc=1
    return $_rscs_rc
}
