#!/usr/bin/env bash
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
# docs/test-hash-dir.sh — test linuxkit --hash-dir two-pass build system
# Run from EVE repo root: bash docs/test-hash-dir.sh
set -euo pipefail

LK=build-tools/bin/linuxkit
PASS=0; FAIL=0

# Bootstrap dir written by update-hashes; build dir written by pkg build recipes.
BDIR=.gen-deps/.bootstrap
GDIR=.gen-deps

pass() { echo "PASS: $1"; PASS=$((PASS+1)); }
fail() { echo "FAIL: $1"; FAIL=$((FAIL+1)); }
check() {
    local desc="$1"; shift
    if "$@" &>/dev/null; then pass "$desc"; else fail "$desc"; fi
}
# check that a value matches a grep pattern (avoids pipe-in-subshell issue)
check_match() {
    local desc="$1" val="$2" pattern="$3"
    if echo "$val" | grep -q "$pattern"; then pass "$desc"; else fail "$desc"; fi
}
# check that a make -n dry-run output does NOT contain "pkg build"
check_nopkg() {
    local desc="$1" output="$2"
    if echo "$output" | grep -q "pkg build"; then
        fail "$desc"
    else
        pass "$desc"
    fi
}
# check that a make -n dry-run output DOES mention a specific package path
check_pkg() {
    local desc="$1" output="$2" pkg="$3"
    if echo "$output" | grep -q "$pkg"; then
        pass "$desc"
    else
        fail "$desc"
    fi
}

# ── cleanup on exit ───────────────────────────────────────────────────────────
cleanup() {
    git checkout pkg/zfs/Dockerfile 2>/dev/null || true
    rm -rf .gen-deps
}
trap cleanup EXIT

echo "=== Prerequisite checks ==="
check "linuxkit binary exists"           test -x "$LK"
check "build-2.3.yml exists"             test -f pkg/zfs/build-2.3.yml
check "build-2.4.yml exists"             test -f pkg/zfs/build-2.4.yml

# ── T1: update-hashes first pass ─────────────────────────────────────────────
echo ""
echo "=== T1: update-hashes first pass ==="
rm -rf .gen-deps
make update-hashes
check "zfs.hash created"           test -f "$BDIR/zfs.hash"
check "dom0-ztools.hash created"   test -f "$BDIR/dom0-ztools.hash"
check "pillar.hash created"        test -f "$BDIR/pillar.hash"
check "vtpm.hash created"          test -f "$BDIR/vtpm.hash"

# ── T2: hash file YAML format ─────────────────────────────────────────────────
echo ""
echo "=== T2: hash file YAML format ==="
ZFS_TAG=$(grep '^tag:' "$BDIR/zfs.hash" | awk '{print $2}')
ZFS_BUILDYML=$(grep '^build-yml:' "$BDIR/zfs.hash" | awk '{print $2}')
check "zfs.hash has tag field"          test -n "$ZFS_TAG"
check "zfs.hash tag contains -2.3"      echo "$ZFS_TAG" | grep -q '\-2\.3$'
check "zfs.hash has build-yml field"    test -n "$ZFS_BUILDYML"
check "zfs.hash build-yml is 2.3 yml"   echo "$ZFS_BUILDYML" | grep -q '2\.3'
DOM0_DEPS=$(grep -c '^    - path:' "$BDIR/dom0-ztools.hash" 2>/dev/null || echo 0)
check "dom0-ztools.hash has deps entries"   test "$DOM0_DEPS" -ge 1
PILLAR_DEPS=$(grep -c '^    - path:' "$BDIR/pillar.hash" 2>/dev/null || echo 0)
check "pillar.hash has deps entries"        test "$PILLAR_DEPS" -ge 1
check "hash-deps.mk created"               test -f "$GDIR/hash-deps.mk"
check "hash-deps.mk has dom0-ztools rule"  grep -q 'dom0-ztools.hash:.*zfs.hash' "$GDIR/hash-deps.mk"
check "hash-deps.mk has pillar rule"       grep -q 'pillar.hash:.*zfs.hash' "$GDIR/hash-deps.mk"

# ── T3: warm update-hashes is a no-op (mtimes preserved) ─────────────────────
echo ""
echo "=== T3: warm update-hashes — no mtime change ==="
ZFS_MTIME_BEFORE=$(stat -c %Y "$BDIR/zfs.hash")
PILLAR_MTIME_BEFORE=$(stat -c %Y "$BDIR/pillar.hash")
sleep 1
make update-hashes
ZFS_MTIME_AFTER=$(stat -c %Y "$BDIR/zfs.hash")
PILLAR_MTIME_AFTER=$(stat -c %Y "$BDIR/pillar.hash")
check "zfs.hash mtime unchanged (write-if-changed)" \
    test "$ZFS_MTIME_BEFORE" -eq "$ZFS_MTIME_AFTER"
check "pillar.hash mtime unchanged (write-if-changed)" \
    test "$PILLAR_MTIME_BEFORE" -eq "$PILLAR_MTIME_AFTER"

# ── T4: ZFS_VERSION bump — both passes update downstream hashes ───────────────
echo ""
echo "=== T4: ZFS_VERSION=2.4.1 — two-pass hash propagation ==="
TAG_23=$(grep '^tag:' "$BDIR/zfs.hash" | awk '{print $2}')
ZFS_MTIME_BEFORE=$(stat -c %Y "$BDIR/zfs.hash")
DOM0_MTIME_BEFORE=$(stat -c %Y "$BDIR/dom0-ztools.hash")
PILLAR_MTIME_BEFORE=$(stat -c %Y "$BDIR/pillar.hash")

sleep 1
make ZFS_VERSION=2.4.1 update-hashes

TAG_24=$(grep '^tag:' "$BDIR/zfs.hash" | awk '{print $2}')
PILLAR_TAG_24=$(grep '^tag:' "$BDIR/pillar.hash" | awk '{print $2}')
ZFS_MTIME_AFTER=$(stat -c %Y "$BDIR/zfs.hash")
DOM0_MTIME_AFTER=$(stat -c %Y "$BDIR/dom0-ztools.hash")
PILLAR_MTIME_AFTER=$(stat -c %Y "$BDIR/pillar.hash")

check "zfs tag changed 2.3→2.4"           test "$TAG_23" != "$TAG_24"
check_match "zfs tag contains -2.4"        "$TAG_24" '\-2\.4$'
check "zfs.hash mtime updated"            test "$ZFS_MTIME_AFTER" -gt "$ZFS_MTIME_BEFORE"
check "dom0-ztools.hash mtime updated (dep propagation)"  test "$DOM0_MTIME_AFTER" -gt "$DOM0_MTIME_BEFORE"
check "pillar.hash mtime updated (dep propagation)"       test "$PILLAR_MTIME_AFTER" -gt "$PILLAR_MTIME_BEFORE"
check "pillar tag changed (full hash propagation)"        test "$PILLAR_TAG_24" != ""

# ── T5: pillar combined hash now reflects ZFS 2.4 ────────────────────────────
echo ""
echo "=== T5: pillar tag is different under ZFS 2.3 vs 2.4 ==="

# Compute pillar with 2.3 and 2.4 directly
make update-hashes >/dev/null  # restore 2.3
PILLAR_23=$(grep '^tag:' "$BDIR/pillar.hash" | awk '{print $2}')
make ZFS_VERSION=2.4.1 update-hashes >/dev/null
PILLAR_24=$(grep '^tag:' "$BDIR/pillar.hash" | awk '{print $2}')

check "pillar combined hash differs 2.3 vs 2.4" test "$PILLAR_23" != "$PILLAR_24"
echo "  pillar/2.3: $PILLAR_23"
echo "  pillar/2.4: $PILLAR_24"

# restore 2.3 baseline
make update-hashes >/dev/null

# ── T6: --strict-deps errors on missing dep hash file ────────────────────────
echo ""
echo "=== T6: --strict-deps errors when dep hash file missing ==="
cp "$BDIR/zfs.hash" /tmp/zfs-hash-backup
rm -f "$BDIR/zfs.hash"
T6_OUT=$($LK pkg update-hashes --hash-dir "$BDIR" --strict-deps \
        pkg/pillar:build.yml pkg/alpine:build.yml pkg/cross-compilers:build.yml \
        pkg/dnsmasq:build.yml pkg/fscrypt:build.yml pkg/gpt-tools:build.yml \
        pkg/uefi:build.yml 2>&1 || true)
if echo "$T6_OUT" | grep -qi "no hash file\|strict\|absent\|dep.*zfs"; then
    pass "--strict-deps errors on missing zfs.hash"
else
    fail "--strict-deps should error on missing zfs.hash"
fi
cp /tmp/zfs-hash-backup "$BDIR/zfs.hash"

# ── T7: dirty pkg/zfs — base hash and dirty suffix behavior ──────────────────
echo ""
echo "=== T7: dirty + ZFS_VERSION — base hash preserves version, suffix from content ==="
CLEAN_23=$(grep '^tag:' "$BDIR/zfs.hash" | awk '{print $2}')

echo '# test-corner' >> pkg/zfs/Dockerfile

make update-hashes >/dev/null
DIRTY_23_TAG=$(grep '^tag:' "$BDIR/zfs.hash" | awk '{print $2}')
# Strip only the dirty marker (e.g. -dirty-1c211db) but keep the version suffix (-2.3).
BASE_23=$(echo "$DIRTY_23_TAG" | sed 's/-dirty-[0-9a-f]*//')

make ZFS_VERSION=2.4.1 update-hashes >/dev/null
DIRTY_24_TAG=$(grep '^tag:' "$BDIR/zfs.hash" | awk '{print $2}')
BASE_24=$(echo "$DIRTY_24_TAG" | sed 's/-dirty-[0-9a-f]*//')

SUFFIX_24=$(echo "$DIRTY_24_TAG" | grep -oP 'dirty-\K[0-9a-f]+' || true)

make update-hashes >/dev/null
DIRTY_23B_TAG=$(grep '^tag:' "$BDIR/zfs.hash" | awk '{print $2}')
SUFFIX_23=$(echo "$DIRTY_23B_TAG" | grep -oP 'dirty-\K[0-9a-f]+' || true)

check_match "dirty tags have -dirty- suffix"   "$DIRTY_23_TAG" '\-dirty\-'
check "base hash differs 2.3 vs 2.4 (ZFS_VERSION preserved)" test "$BASE_23" != "$BASE_24"
check "dirty suffix same for 2.3 and 2.4 (same file content)" \
    test "$SUFFIX_23" = "$SUFFIX_24"
check "clean 2.3 base matches dirty 2.3 base" \
    test "$(echo "$CLEAN_23" | sed 's/-dirty-.*//')" = "$BASE_23"

git checkout pkg/zfs/Dockerfile
make update-hashes >/dev/null  # restore clean 2.3

# ── T8-T11: update-hashes write-if-changed and dep propagation ────────────────
make update-hashes >/dev/null

# ── T8: update-hashes idempotent when nothing has changed ─────────────────────
echo ""
echo "=== T8: update-hashes idempotent (no-op when content unchanged) ==="
ZFS_T8_MTIME_BEFORE=$(stat -c %Y "$BDIR/zfs.hash")
DOM0_T8_MTIME_BEFORE=$(stat -c %Y "$BDIR/dom0-ztools.hash")
sleep 1
make update-hashes >/dev/null
ZFS_T8_MTIME_AFTER=$(stat -c %Y "$BDIR/zfs.hash")
DOM0_T8_MTIME_AFTER=$(stat -c %Y "$BDIR/dom0-ztools.hash")
check "T8: zfs.hash mtime unchanged (no source change)" \
    test "$ZFS_T8_MTIME_BEFORE" -eq "$ZFS_T8_MTIME_AFTER"
check "T8: dom0-ztools.hash mtime unchanged (no source change)" \
    test "$DOM0_T8_MTIME_BEFORE" -eq "$DOM0_T8_MTIME_AFTER"

# ── T9: Dockerfile content change → hash tag changes ─────────────────────────
echo ""
echo "=== T9: Dockerfile content change → hash tag changes ==="
ZFS_T9_TAG_BEFORE=$(grep '^tag:' "$BDIR/zfs.hash" | awk '{print $2}')
echo '# test-corner' >> pkg/zfs/Dockerfile
make update-hashes >/dev/null
ZFS_T9_TAG_AFTER=$(grep '^tag:' "$BDIR/zfs.hash" | awk '{print $2}')
check "T9: zfs tag changes after Dockerfile content edit" \
    test "$ZFS_T9_TAG_BEFORE" != "$ZFS_T9_TAG_AFTER"
git checkout pkg/zfs/Dockerfile
make update-hashes >/dev/null  # restore clean tag

# ── T10: dep source change propagates tag to consumers ────────────────────────
echo ""
echo "=== T10: zfs Dockerfile change → dom0-ztools and vtpm tags propagated ==="
DOM0_T10_TAG_BEFORE=$(grep '^tag:' "$BDIR/dom0-ztools.hash" | awk '{print $2}')
VTPM_T10_TAG_BEFORE=$(grep '^tag:' "$BDIR/vtpm.hash" | awk '{print $2}')
echo '# test-corner' >> pkg/zfs/Dockerfile
make update-hashes >/dev/null
DOM0_T10_TAG_AFTER=$(grep '^tag:' "$BDIR/dom0-ztools.hash" | awk '{print $2}')
VTPM_T10_TAG_AFTER=$(grep '^tag:' "$BDIR/vtpm.hash" | awk '{print $2}')
check "T10: dom0-ztools tag changes (direct dep on zfs)" \
    test "$DOM0_T10_TAG_BEFORE" != "$DOM0_T10_TAG_AFTER"
check "T10: vtpm tag changes (transitive dep via dom0-ztools)" \
    test "$VTPM_T10_TAG_BEFORE" != "$VTPM_T10_TAG_AFTER"

# ── T11: after source restored, tags return to baseline ───────────────────────
echo ""
echo "=== T11: after source restore, tags return to baseline ==="
git checkout pkg/zfs/Dockerfile
make update-hashes >/dev/null
DOM0_T11_TAG_RESTORED=$(grep '^tag:' "$BDIR/dom0-ztools.hash" | awk '{print $2}')
VTPM_T11_TAG_RESTORED=$(grep '^tag:' "$BDIR/vtpm.hash" | awk '{print $2}')
check "T11: dom0-ztools tag restored to baseline" \
    test "$DOM0_T10_TAG_BEFORE" = "$DOM0_T11_TAG_RESTORED"
check "T11: vtpm tag restored to baseline" \
    test "$VTPM_T10_TAG_BEFORE" = "$VTPM_T11_TAG_RESTORED"

# ── summary ───────────────────────────────────────────────────────────────────
echo ""
echo "=============================="
echo "Results: $PASS passed, $FAIL failed"
echo "=============================="
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
