#!/bin/bash
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Makes a VM look like vm-build.sh finished, from a real build already in it,
# so that "release-rebuild.sh finish" (wait + compare) can be exercised on a
# real rebuild without spending the build's hours:
#
#   make-test-env.sh <vm> <tag> <arch.hv.platform> [<eve checkout in the VM>]
#
# The checkout (default /home/ubuntu/eve) must hold
# dist/<arch>/<tag>/installer/rootfs.img from a SIGNING.md step 3 build. An
# existing ~/rebuild is moved aside. The status says TEST ENV, which
# release-rebuild.sh compare repeats in its RESULT line.
set -euo pipefail
[ $# -ge 3 ] || { sed -n '2,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//' >&2; exit 2; }
VM=$1 TAG=$2 T=$3 SRC=${4:-/home/ubuntu/eve}
multipass exec "$VM" -- bash -s "$TAG" "$T" "$SRC" <<'IN_VM'
set -euo pipefail
TAG=$1 T=$2 SRC=$3
arch=${T%%.*}
img=$SRC/dist/$arch/$TAG/installer/rootfs.img
[ -f "$img" ] || { echo "no $img in $(hostname)" >&2; exit 1; }
W=$HOME/rebuild
if [ -e "$W" ]; then
  mv "$W" "$W.before-test-env.$(date +%s)"
fi
mkdir -p "$W/out" "$W/logs"
cp "$img" "$W/out/$T.rootfs.img"
for f in "$HOME"/*.log; do cp "$f" "$W/logs/"; done
sha=$(sha256sum < "$W/out/$T.rootfs.img" | cut -d' ' -f1)
now=$(date -u +%FT%TZ)
{
  echo "$now begin TEST ENV from $img ($(git -C "$SRC" rev-parse HEAD), owner $(stat -c %u:%g "$img"))"
  echo "$now $T rootfs $sha"
  echo "$now done"
} > "$W/status"
cat "$W/status"
IN_VM
