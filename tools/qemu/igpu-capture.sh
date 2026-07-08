#!/usr/bin/env bash
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
# Capture two MMIO snapshots of the current iGPU state from an EVE node and pull
# them to the workstation for local decode/diff with igpu-regdiff.py.
#
# Runs on the WORKSTATION. The reproducer state transition (corrupted screen ->
# recover on sleep/wake) is driven manually; this just snapshots "right now".
#
#   tools/qemu/igpu-capture.sh A            # capture state A (e.g. corrupted)
#   ... trigger sleep/wake so the screen recovers ...
#   tools/qemu/igpu-capture.sh B            # capture state B (e.g. recovered)
#   tools/qemu/igpu-regdiff.py --a igpu-dumps/A1*.bin igpu-dumps/A2*.bin \
#                              --b igpu-dumps/B1*.bin igpu-dumps/B2*.bin
#
# Two samples per state let igpu-regdiff.py filter volatile registers.
set -euo pipefail

NODE=${NODE:?set NODE=root@<edge-node-ip>}
KEY=${KEY:-$HOME/.ssh/id_rsa}
LOCALDIR=${LOCALDIR:-igpu-dumps}
DELAY=${DELAY:-0.5}
LABEL=${1:?usage: igpu-capture.sh <label> (e.g. A or B)}

HERE="$(cd "$(dirname "$0")" && pwd)"
# Ignore known_hosts: the node regenerates its host key on reboot, which the
# reproducer does every cycle.
SSHOPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -i "$KEY")
SSH=(ssh "${SSHOPTS[@]}" "$NODE")
SCP=(scp "${SSHOPTS[@]}")
DUMP='python3 /persist/qemu-tools/igpu-dump.py'
filt() { grep -viE 'deprecat|cgroup'; }
run_dump() {  # $1=exec-id-suffix $2=label -> runs igpu-dump.py in debug ctr
  "${SSH[@]}" "ctr -n services.linuxkit t exec --exec-id dbg-$1 debug $DUMP $2"
}

mkdir -p "$LOCALDIR"

# Deploy/refresh on-node tools (idempotent; /persist survives reboots).
"${SSH[@]}" 'mkdir -p /persist/qemu-tools/dumps'
"${SCP[@]}" "$HERE/igpu-dump.py" "$NODE:/persist/qemu-tools/igpu-dump.py" >/dev/null

for s in 1 2; do
  out=$(run_dump "$LABEL$s-$$" "${LABEL}${s}" 2>&1 | filt)
  echo "$out"
  path=$(echo "$out" | awk '/^wrote /{print $2}')
  [ -n "$path" ] || { echo "ERROR: no blob produced (iGPU asleep?)"; exit 1; }
  "${SCP[@]}" "$NODE:$path" "$NODE:$path.json" "$LOCALDIR/" >/dev/null
  echo "  -> $LOCALDIR/$(basename "$path")"
  [ "$s" = 1 ] && sleep "$DELAY"
done
echo "captured state '$LABEL' into $LOCALDIR/"
