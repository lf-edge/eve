#!/bin/sh
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Unit test for remove_stale_cni_state, run on a build host by
# `make -C pkg/kube test`. Exits non-zero if any case fails.

# shellcheck source=pkg/kube/cni-state-utils.sh
. "$(dirname "$0")/../cni-state-utils.sh"

failures=0
fail() {
    echo "FAIL: $*"
    failures=$((failures + 1))
}

root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT

# The join path depends on nothing surviving that could hand a pod an address
# from the subnet this node owned while it ran standalone.
test_clears_subnet_and_reservations() {
    dir="$root/clears"
    subnet_env="$dir/run/flannel/subnet.env"
    ipam_dir="$dir/var/lib/cni/networks/cbr0"
    mkdir -p "$(dirname "$subnet_env")" "$ipam_dir"
    printf 'FLANNEL_NETWORK=10.42.0.0/16\nFLANNEL_SUBNET=10.42.0.1/24\n' > "$subnet_env"
    for name in 10.42.0.2 10.42.0.3 last_reserved_ip.0; do
        echo x > "$ipam_dir/$name"
    done

    if ! remove_stale_cni_state "$subnet_env" "$ipam_dir"; then
        fail "clears: remove_stale_cni_state returned non-zero"
    fi
    if [ -e "$subnet_env" ]; then
        fail "clears: subnet.env survived; a CNI ADD could still read the retired subnet"
    fi
    if [ -e "$ipam_dir" ]; then
        fail "clears: IPAM reservations survived"
    fi
}

# A node whose CNI never ran: absent paths are not an error.
test_missing_paths() {
    dir="$root/missing"
    if ! remove_stale_cni_state "$dir/run/flannel/subnet.env" \
            "$dir/var/lib/cni/networks/cbr0"; then
        fail "missing: absent paths must be a no-op"
    fi
}

test_clears_subnet_and_reservations
test_missing_paths

if [ "$failures" -ne 0 ]; then
    echo "$failures failure(s)"
    exit 1
fi
echo "PASS: remove_stale_cni_state"
