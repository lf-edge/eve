#!/bin/bash
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# On-filesystem fidelity check for volverify: round-trips the write/verify pattern
# on a real loopback ext4 (not tmpfs), then injects truncation and block-zeroing
# and confirms the verifier detects them. A final stage corrupts filesystem data
# and runs e2fsck so the lost+found / orphaned-vs-present-corrupt path exercises
# the real fsck behavior the soak depends on.
#
# Requires root (losetup/mkfs/mount). Run: sudo ./scripts/loopback-ext4-test.sh

set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
	echo "must run as root (losetup/mount); re-run with sudo" >&2
	exit 1
fi

HERE="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
IMG="$WORK/vol.img"
MNT="$WORK/mnt"
BIN="$WORK/volverify"
LOOP=""

cleanup() {
	mountpoint -q "$MNT" && umount "$MNT" || true
	[ -n "$LOOP" ] && losetup -d "$LOOP" 2>/dev/null || true
	rm -rf "$WORK"
}
trap cleanup EXIT

# Deterministic op stream small enough to run quickly but large enough to spill
# files across many block groups.
SEED=20260723
OPS=4000
COMMON="--seed $SEED --ops $OPS --block-size 4096 --small-blocks 8 --med-blocks 512 --max-blocks 4096"

echo "== build volverify =="
( cd "$HERE" && GOWORK=off go build -o "$BIN" ./cmd/volverify )

echo "== create + mount loopback ext4 (1 GiB) =="
mkdir -p "$MNT"
truncate -s 1G "$IMG"
mkfs.ext4 -q -F "$IMG"
LOOP="$(losetup --find --show "$IMG")"
mount "$LOOP" "$MNT"

echo "== write pattern =="
# shellcheck disable=SC2086
"$BIN" write --dir "$MNT" $COMMON

echo "== verify (expect clean on a real ext4) =="
# shellcheck disable=SC2086
"$BIN" verify --dir "$MNT" $COMMON
echo "PASS: clean round-trip on ext4"

echo "== inject truncation + block-zeroing on two files =="
# Collect matches with mapfile rather than `find | head` — under pipefail the
# early pipe close makes find exit 141 (SIGPIPE) and set -e then aborts.
mapfile -t FILES < <(find "$MNT" -name 'f*.blk')
if [ "${#FILES[@]}" -lt 2 ]; then
	echo "FAIL: need >=2 data files to corrupt, found ${#FILES[@]}" >&2
	exit 1
fi
VICTIM="${FILES[0]}"
VICTIM2="${FILES[1]}"
truncate -s 0 "$VICTIM"
dd if=/dev/zero of="$VICTIM2" bs=4096 count=1 conv=notrunc status=none

echo "== verify (expect anomalies) =="
# shellcheck disable=SC2086
if "$BIN" verify --dir "$MNT" $COMMON; then
	echo "FAIL: verifier reported clean after injected corruption" >&2
	exit 1
fi
echo "PASS: verifier detected injected truncation/zeroing"

echo "== fsck path: corrupt fs data then e2fsck, re-verify (informational) =="
umount "$MNT"
# Zero a 4 MiB span in the data area to force e2fsck into real repairs.
dd if=/dev/zero of="$IMG" bs=1M count=4 seek=200 conv=notrunc status=none
e2fsck -fy "$IMG" || true
mount "$LOOP" "$MNT"
echo "-- lost+found after e2fsck:"; ls -1 "$MNT/lost+found" 2>/dev/null || true
echo "-- verifier report after e2fsck:"
# shellcheck disable=SC2086
"$BIN" verify --dir "$MNT" $COMMON || true

echo "ALL DONE"
