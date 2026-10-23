#!/bin/bash
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Rebuilds a draft EVE release from its tag in a fresh Multipass VM and compares
# the rebuild with the release images using eve-build-diff: docs/SIGNING.md
# "Approving a release", steps 1-4.
#
#   release-rebuild.sh [run|resolve|start|wait|compare|finish|status] <tag> <release-id> <release-url>
#
# The three arguments are the line the draft listing in SIGNING.md prints, e.g.
#   17.6.0 123456789 https://github.com/lf-edge/eve/releases/tag/untagged-<hex>
#
#   run      resolve + start + wait + compare (default; about 8 hours)
#   resolve  check the draft, fetch its images.txt, pick targets and digests
#   start    launch and provision the VM, check its build user, start the build
#   wait     poll the build until it ends
#   compare  copy each rebuilt rootfs out and run eve-build-diff against the
#            release's eve digest; exit 0 only if every target compares clean
#   finish   wait + compare, to resume a run or to exercise a test VM made by
#            make-test-env.sh
#   status   show the state, the VM and the build's progress
#
# Environment:
#   EVE_BUILD_DIFF  eve-build-diff.py to use (default: the one in the parent
#                   directory; run both from a reviewed master checkout)
#   TARGETS         arch.hv.platform list (default: amd64.kvm.generic if the
#                   draft has it, else every target of the host's arch)
#   REBUILD         compare this rootfs.img instead of the VM's (tests only;
#                   one target)
#   FAKE_BUILD=1    plumbing test: the VM copies the release's own rootfs out of
#                   its eve image instead of running make (minutes, not hours;
#                   compare must then exit 0)
#   VM              the build VM (default eve-rebuild-<tag>)
#   STATE_ROOT      default ./eve-release-rebuild; must be readable by the
#                   multipass snap (not hidden, not /tmp)
#   VM_CPUS VM_MEM VM_DISK GO_VERSION   default 6, 12G, 100G, 1.25.11
set -euo pipefail

SCRIPTS=$(dirname "$(readlink -f "$0")")
STATE_ROOT=${STATE_ROOT:-$PWD/eve-release-rebuild}
EVE_BUILD_DIFF=${EVE_BUILD_DIFF:-$(dirname "$SCRIPTS")/eve-build-diff.py}
VM_CPUS=${VM_CPUS:-6} VM_MEM=${VM_MEM:-12G} VM_DISK=${VM_DISK:-100G} GO_VERSION=${GO_VERSION:-1.25.11}
POLL=${POLL:-300}

die() { echo "release-rebuild: $*" >&2; exit 1; }
log() { echo "$(date -u +%FT%TZ) $*" | tee -a "$S/log"; }

cmd=run
case "${1:-}" in run|resolve|start|wait|compare|finish|status) cmd=$1; shift ;; esac
[ $# = 3 ] || { sed -n '2,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//' >&2; exit 2; }
TAG=$1 ID=$2 URL=$3

[[ "$URL" =~ ^https://github\.com/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)/releases/tag/[^/]+$ ]] ||
  die "not a GitHub release URL: $URL"
REPO=${BASH_REMATCH[1]}
[[ "$ID" =~ ^[0-9]+$ ]] || die "release id is not a number: $ID"
[[ "$TAG" =~ ^[0-9A-Za-z._-]+$ ]] || die "bad tag: $TAG"
S=$STATE_ROOT/${REPO//\//-}-$TAG
VM=${VM:-eve-rebuild-$(tr -c 'a-z0-9\n' - <<< "${TAG,,}")}
mkdir -p "$S"

host_arch() { case $(uname -m) in x86_64) echo amd64 ;; aarch64) echo arm64 ;; *) uname -m ;; esac; }

# Checks the draft against the arguments and fetches what it will sign. Run by
# every command, so a draft that changed since the build started is caught.
resolve() {
  local rel tag draft url commit n d
  rel=$(gh api "repos/$REPO/releases/$ID") || die "no release $ID in $REPO"
  tag=$(jq -r .tag_name <<< "$rel") draft=$(jq -r .draft <<< "$rel") url=$(jq -r .html_url <<< "$rel")
  [ "$tag" = "$TAG" ] || die "release $ID is $tag, not $TAG"
  [ "$url" = "$URL" ] || die "release $ID is at $url, not $URL"
  [ "$draft" = true ] || die "release $ID is not a draft"
  commit=$(gh api "repos/$REPO/commits/$TAG" --jq .sha) || die "no tag $TAG in $REPO"
  if [ -f "$S/commit" ]; then
    [ "$(cat "$S/commit")" = "$commit" ] || die "$TAG moved: $(cat "$S/commit") at start, $commit now"
  fi
  echo "$commit" > "$S/commit"

  mkdir -p "$S/release.new"
  gh api --paginate "repos/$REPO/releases/$ID/assets" --jq '.[] | "\(.id) \(.name)"' > "$S/assets"
  while read -r aid name; do
    gh api -H 'Accept: application/octet-stream' "repos/$REPO/releases/assets/$aid" > "$S/release.new/$name" ||
      die "cannot download $name"
  done < <(grep -E ' [^ ]+\.images\.txt$' "$S/assets" || true)
  n=$(find "$S/release.new" -name '*.images.txt' | wc -l)
  [ "$n" -gt 0 ] || die "release $ID has no *.images.txt assets"
  if [ -d "$S/release" ]; then
    diff -r "$S/release" "$S/release.new" > /dev/null || die "the draft's images.txt changed since the start; see $S/release{,.new}"
    rm -r "$S/release.new"
  else
    mv "$S/release.new" "$S/release"
  fi

  if [ -z "${TARGETS:-}" ]; then
    if [ -f "$S/release/amd64.kvm.generic.images.txt" ] && [ "$(host_arch)" = amd64 ]; then
      TARGETS=amd64.kvm.generic
    else
      TARGETS=$(find "$S/release" -maxdepth 1 -name "$(host_arch).*.*.images.txt" -printf '%f\n' |
        sed 's/\.images\.txt$//' | sort | xargs)
    fi
  fi
  [ -n "$TARGETS" ] || die "no $(host_arch) target in the draft"
  for t in $TARGETS; do
    [[ "$t" == "$(host_arch)".* ]] || die "$t cannot be built on this $(host_arch) host"
    [ -f "$S/release/$t.images.txt" ] || die "the draft has no $t.images.txt"
    d=$(grep -E '^([a-z0-9._-]+/)+eve@sha256:[0-9a-f]{64}$' "$S/release/$t.images.txt") ||
      die "$t.images.txt has no eve digest"
    [ "$(wc -l <<< "$d")" = 1 ] || die "$t.images.txt has several eve digests"
    echo "$d" > "$S/$t.eve"
  done
  echo "$TARGETS" > "$S/targets"
  echo "release $REPO $ID draft, tag $TAG at $commit"
  for t in $TARGETS; do echo "  $t: $(cat "$S/$t.eve")"; done
}

vm_ssh() { multipass exec "$VM" -- "$@"; }

start() {
  multipass info "$VM" > /dev/null 2>&1 && die "VM $VM exists; delete it (multipass delete --purge $VM) for a clean rebuild"
  log "launch $VM ($VM_CPUS CPUs, $VM_MEM, $VM_DISK)"
  multipass launch -n "$VM" -c "$VM_CPUS" -m "$VM_MEM" -d "$VM_DISK" noble >> "$S/log" 2>&1 || die "launch failed; see $S/log"
  # Over stdin: the multipass snap cannot read hidden directories.
  local f
  for f in vm-provision.sh vm-build.sh; do
    vm_ssh tee "/home/ubuntu/$f" < "$SCRIPTS/$f" > /dev/null || die "cannot copy $f into $VM"
  done
  log "provision"
  vm_ssh bash /home/ubuntu/vm-provision.sh "$GO_VERSION" >> "$S/log" 2>&1 || die "provisioning failed; see $S/log"
  # The docker group applies from the next login; restart rather than sg or
  # newgrp, which would change the build's primary group.
  multipass restart "$VM" || die "restart failed"
  # restart returns before sshd accepts connections.
  local idout=
  for _ in $(seq 30); do
    # multipass prints its "Starting" spinner to stdout while the VM boots.
    idout=$(vm_ssh id 2> /dev/null | grep -ao 'uid=[^[:cntrl:]]*') && break
    sleep 5
  done
  [ -n "$idout" ] || die "cannot reach $VM after the restart"
  log "build user: $idout"
  [[ "$idout" == *"gid=1000(ubuntu)"* && "$idout" == *"(docker)"* ]] || die "unexpected build user: $idout"
  vm_ssh docker info > /dev/null 2>&1 || die "docker is not usable without sudo in $VM"
  local fake=
  [ -z "${FAKE_BUILD:-}" ] || fake="FAKE_BUILD=$(cat "$S/$(cat "$S/targets").eve")"
  # A multipass exec has returned without the backgrounded build ever running,
  # so the session waits for the build's first status line, and the launch is
  # retried while no build has started.
  for _ in 1 2 3; do
    vm_ssh bash -c "$fake setsid -f bash /home/ubuntu/vm-build.sh $REPO $TAG $(cat "$S/commit") $(cat "$S/targets") \
        > /home/ubuntu/vm-build.log 2>&1 < /dev/null
      for _ in \$(seq 60); do [ -s /home/ubuntu/rebuild/status ] && exit 0; sleep 1; done; exit 1" && break
    vm_ssh test -e /home/ubuntu/rebuild && break
    log "the build did not start: $(vm_ssh cat /home/ubuntu/vm-build.log 2>&1 | tail -1); retrying"
  done
  vm_ssh cat /home/ubuntu/rebuild/status 2> /dev/null | tee -a "$S/log" ||
    die "the build did not start: $(vm_ssh cat /home/ubuntu/vm-build.log 2>&1)"
  vm_ssh grep -q FAILED /home/ubuntu/rebuild/status && die "the build failed at once"
  log "started; progress in $VM:/home/ubuntu/rebuild/status"
}

status() {
  echo "state $S"
  [ -f "$S/targets" ] && echo "targets $(cat "$S/targets")"
  multipass info "$VM" 2> /dev/null | grep -E '^(Name|State)' || echo "no VM $VM"
  vm_ssh tail -5 /home/ubuntu/rebuild/status 2> /dev/null || true
  vm_ssh pgrep -f '[v]m-build.sh' > /dev/null 2>&1 && echo "build running" || echo "build not running"
}

# Exits 0 when the build finished with "done". A failed multipass exec is
# taken as transient; pgrep's exit 1 with no final status line means the build
# died.
wait_build() {
  local last rc
  while :; do
    last=$(vm_ssh tail -1 /home/ubuntu/rebuild/status 2> /dev/null || true)
    echo "$(date -u +%FT%TZ) $last" >> "$S/wait.log"
    [[ "$last" == *" done" || "$last" == *" FAILED: "* ]] && break
    rc=0
    vm_ssh pgrep -f '[v]m-build.sh' > /dev/null 2>&1 || rc=$?
    [ "$rc" != 1 ] || { last="build process gone without a final status"; break; }
    sleep "$POLL"
  done
  vm_ssh cat /home/ubuntu/rebuild/status > "$S/vm-status" || die "cannot read the build status"
  [[ "$last" == "build process gone"* ]] || last=$(tail -1 "$S/vm-status")
  log "build ended: $last"
  [[ "$last" == *" done" ]]
}

compare() {
  local t img want got rc ref overall=0 tooldir toolrev targets
  [ -f "$EVE_BUILD_DIFF" ] || die "no eve-build-diff at $EVE_BUILD_DIFF; set EVE_BUILD_DIFF"
  tooldir=$(dirname "$EVE_BUILD_DIFF")
  toolrev=$(git -C "$tooldir" log -1 --format='%h %s' 2> /dev/null || echo "not in git")
  log "eve-build-diff: $EVE_BUILD_DIFF ($toolrev)"
  read -ra targets < "$S/targets"
  for t in "${targets[@]}"; do
    if [ -n "${REBUILD:-}" ]; then
      img=$REBUILD
      log "$t: comparing $img (REBUILD override, not the VM's build)"
    else
      want=$(sed -n "s/.* $t rootfs \([0-9a-f]\{64\}\)$/\1/p" "$S/vm-status" 2> /dev/null || true)
      [ -n "$want" ] || die "$t: no finished rootfs in the build status; run wait first"
      img=$S/$t.rootfs.img
      multipass transfer "$VM:/home/ubuntu/rebuild/out/$t.rootfs.img" "$img" ||
        die "$t: cannot copy the rootfs out of $VM"
      got=$(sha256sum < "$img" | cut -d' ' -f1)
      [ "$got" = "$want" ] || die "$t: copied rootfs is $got, the VM built $want"
      log "$t: rebuild $img sha256 $got"
    fi
    ref=docker:$(cat "$S/$t.eve")
    rc=0
    python3 "$EVE_BUILD_DIFF" --json "$S/$t.report.json" "$ref" "$img" > "$S/$t.diff.txt" 2>&1 || rc=$?
    log "$t: eve-build-diff exit $rc: $(grep -E '^[0-9]+ entries' "$S/$t.diff.txt" || tail -1 "$S/$t.diff.txt")"
    [ "$rc" = 0 ] || overall=1
  done
  local test=
  if grep -qE 'TEST ENV| FAKE_BUILD ' "$S/vm-status" 2> /dev/null || [ -n "${REBUILD:-}" ]; then
    test="TEST ENV, NOT APPROVABLE: "
  fi
  if [ "$overall" = 0 ]; then
    log "${test}RESULT: every target matches its release image up to known differences; reports in $S"
  else
    log "${test}RESULT: DO NOT APPROVE: unexplained differences or a failed comparison; see $S/*.diff.txt"
  fi
  return "$overall"
}

case $cmd in
  resolve) resolve ;;
  start) resolve; start ;;
  wait) resolve > /dev/null; wait_build ;;
  compare) resolve > /dev/null; compare ;;
  status) status ;;
  finish) resolve > /dev/null; wait_build || die "build failed; see $S/vm-status"; compare ;;
  run) resolve; start; wait_build || die "build failed; see $S/vm-status"; compare ;;
esac
