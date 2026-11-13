#!/bin/bash
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

kernel_source=$1
kernel_repository=$2
kernel_branch=$3
kernel_commit=$4
kernel_config_flavor=$5
config_hash=$6
compiler=$7
kernel_tag=$8
linuxkit=$9
kernel_patch="$(cd "$(dirname "$0")" && pwd)/ima-measurement-only-kernel.patch"

# The tag includes the pinned commit, config flavor, compiler, and patch hash.
if "$linuxkit" cache ls 2>&1 | awk -v tag="$kernel_tag" '$1 == tag { found=1 } END { exit !found }'; then
    echo "Using cached IMA kernel: $kernel_tag"
    exit 0
fi

if [ ! -e "$kernel_source" ]; then
    mkdir -p "$(dirname "$kernel_source")"
    git clone --no-checkout --depth=1 --branch "$kernel_branch" \
        "$kernel_repository" "$kernel_source"
    # If the branch has advanced, fetch its history to reach EVE's pinned commit.
    if ! git -C "$kernel_source" cat-file -e "$kernel_commit^{commit}"; then
        git -C "$kernel_source" fetch --unshallow origin "$kernel_branch"
    fi
    git -C "$kernel_source" checkout --detach "$kernel_commit"
fi

actual_commit=$(git -C "$kernel_source" rev-parse HEAD)
case "$actual_commit" in
    "$kernel_commit"*) ;;
    *) echo "Kernel source must be at $kernel_commit (found $actual_commit)" >&2; exit 1 ;;
esac

# Accept a previously applied patch without duplicating its configuration entries.
if git -C "$kernel_source" apply --check "$kernel_patch" 2>/dev/null; then
    git -C "$kernel_source" apply "$kernel_patch"
elif ! git -C "$kernel_source" apply --reverse --check "$kernel_patch" 2>/dev/null; then
    echo "IMA configuration patch does not apply to $kernel_source" >&2
    exit 1
fi

make -C "$kernel_source" -f Makefile.eve \
    LK="$linuxkit" BRANCH="$kernel_branch" VERSION="$kernel_commit" \
    DIRTY="-ima-$config_hash" KERNEL_CONFIG_FLAVOR="$kernel_config_flavor" \
    "kernel-$compiler"
