#!/bin/bash
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# sweep-floor.sh — characterize the ext4 shrink floor across the matrix in the
# storage-resizer README TODO, to derive a shrink safety margin (fixed MB + %).
#
# The floor (smallest size resize2fs -M accepts) is a property of the filesystem
# geometry + contents, NOT the storage medium, so unlike the timing benchmark
# this can run fast on any box. It DOES need root: a realistic floor requires the
# in-place mount fill (mkfs.ext4 -d scatters data and overestimates the floor),
# and the --age fragmentation profile churns files on the mounted fs.
#
#   sudo ./sweep-floor.sh <workdir-on-a-real-ext4>
#
# Writes one JSON report per cell to ./floor-results/, then run analyze-floor.py.
set -eu

WORKDIR=${1:?usage: sudo ./sweep-floor.sh <workdir-on-a-real-ext4>}
BENCH=${BENCH:-./resize-bench}
OUT=${OUT:-floor-results}
mkdir -p "$OUT"

if [ "$(id -u)" -ne 0 ]; then
    echo "sweep-floor.sh: run as root (sudo) — the floor needs an in-place mount fill" >&2
    exit 1
fi

# Axes from the TODO matrix. Sizes span the size-proportional vs fixed split;
# fills find where shrink starts failing; frag/feature profiles bound the parts
# the online check cannot observe (so the margin must assume their worst case).
#SIZES=(8G 32G 64G 100G 256G)
SIZES=(8G 16G 32G 64G)
FILLS=(30 50 70 85 95)

# Fragmentation profiles: name -> extra flags.
declare -A FRAG=(
    [mix]="--small-files 2000"          # the default two-tier mix
    [small]="--small-files 200000"      # inode-heavy: many small files
    [aged]="--small-files 2000 --age 3" # fragmented: delete-then-refill churn
)
# Feature profiles: name -> mkfs.ext4 opts. "eve" mirrors storage-init.sh's
# `mkfs -t ext4 -F -F -O encrypt`.
declare -A FEAT=(
    [default]=""
    [eve]="-O encrypt"
    [nojournal]="-O ^has_journal"
)

for size in "${SIZES[@]}"; do
    for fill in "${FILLS[@]}"; do
        for frag in "${!FRAG[@]}"; do
            for feat in "${!FEAT[@]}"; do
                name="$OUT/s${size}-f${fill}-${frag}-${feat}.json"
                echo "== ${size} fill=${fill}% frag=${frag} feat=${feat} =="
                # Build the arg list; arrays keep the spaces in the opt values intact.
                args=(--workdir "$WORKDIR" --phase floor --fill-method mount
                      --persist-size "$size" --fill "$fill" --json)
                # shellcheck disable=SC2206
                args+=(${FRAG[$frag]})
                if [ -n "${FEAT[$feat]}" ]; then
                    args+=(--mkfs-opts "${FEAT[$feat]}")
                fi
                if "$BENCH" "${args[@]}" > "$name" 2>"$name.log"; then
                    :
                else
                    echo "  FAILED (too full/fragmented to minimize) — see $name.log" >&2
                    # Keep an empty marker; analyze-floor.py skips unparseable files.
                fi
            done
        done
    done
done

echo
echo "done -> $OUT/    next: ./analyze-floor.py $OUT"
