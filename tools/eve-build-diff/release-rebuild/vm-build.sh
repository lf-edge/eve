#!/bin/bash
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Runs inside the rebuild VM: docs/SIGNING.md "Approving a release" step 3 for
# each target, with checks that the build environment matches the release
# runners where it shows in the image (eve-build-diff's checkout-umask rule).
#
#   vm-build.sh <owner/repo> <tag> <commit> <arch.hv.platform>...
#   vm-build.sh --check-tree <dir>     # the ownership/mode check alone
#
# Progress goes to ~/rebuild/status, one timestamped line per stage; the last
# line is "done" or "FAILED: <reason>". Rebuilt images are copied to
# ~/rebuild/out/<arch.hv.platform>.rootfs.img.
set -uo pipefail
umask 022

# Gids the checkout-umask rule in known-diffs.toml accepts.
ALLOWED_GIDS="0 1000 1001"

W=$HOME/rebuild
STATUS=$W/status
stage() { echo "$(date -u +%FT%TZ) $*" | tee -a "$STATUS"; }
die() { stage "FAILED: $*"; exit 1; }

# Every file COPY'd into a package keeps its checkout gid and mode, so check
# the checkout before spending hours on it.
check_tree() {
  local dir=$1 bad n
  local gidexpr=()
  for g in $ALLOWED_GIDS; do gidexpr+=(-not -gid "$g"); done
  bad=$(find "$dir" "${gidexpr[@]}" -print | head -5)
  [ -z "$bad" ] || { echo "files with a gid outside {$ALLOWED_GIDS}:"; echo "$bad"; return 1; }
  bad=$(find "$dir" -not -type l -perm /022 -print | head -5)
  [ -z "$bad" ] || { echo "group- or other-writable files (umask not 022):"; echo "$bad"; return 1; }
  n=$(find "$dir" | wc -l)
  echo "$n entries, gids within {$ALLOWED_GIDS}, no group/other write"
}

if [ "${1:-}" = --check-tree ]; then
  check_tree "$2"
  exit
fi

[ $# -ge 4 ] || { echo "usage: $0 <owner/repo> <tag> <commit> <arch.hv.platform>..." >&2; exit 2; }
REPO=$1 TAG=$2 COMMIT=$3
shift 3
[ ! -e "$W" ] || { echo "$W exists; a rebuild must start from a fresh VM" >&2; exit 1; }
mkdir -p "$W/out" "$W/logs"

stage "begin $REPO $TAG $COMMIT targets: $*"
gid=$(id -g)
case " $ALLOWED_GIDS " in *" $gid "*) ;; *) die "primary gid $gid is not one of {$ALLOWED_GIDS}" ;; esac
[ "$(umask)" = 0022 ] || die "umask $(umask)"
id -nG | grep -qw docker || die "$(id -un) is not in the docker group"
docker info > /dev/null 2>&1 || die "docker is not usable as $(id -un)"
docker buildx version > /dev/null 2>&1 || die "docker buildx missing"
go version > /dev/null 2>&1 || die "go missing (make builds linuxkit from source)"
stage "env: $(id) umask $(umask) $(go version | cut -d' ' -f3) $(docker --version)"

git clone --branch "$TAG" "https://github.com/$REPO" "$W/eve" > "$W/logs/clone.log" 2>&1 || die "clone failed"
head=$(git -C "$W/eve" rev-parse HEAD)
[ "$head" = "$COMMIT" ] || die "tag $TAG is $head here, $COMMIT on GitHub"
out=$(check_tree "$W/eve") || die "checkout: $out"
stage "clone $head: $out"

cd "$W/eve" || die "cd"
# The Makefile takes the version from git describe, which picks the newest of
# several tags on one commit; the release was built before any later tag.
described=$(git describe --always --tags)
[ "$described" = "$TAG" ] || stage "git describe says $described; building as $TAG (REPO_TAG)"
for t in "$@"; do
  IFS=. read -r arch hv platform <<< "$t"
  img=dist/$arch/$TAG/installer/rootfs.img
  if [ -n "${FAKE_BUILD:-}" ]; then
    # Plumbing test only: the release's own rootfs stands in for the build.
    stage "$t FAKE_BUILD from $FAKE_BUILD"
    mkdir -p "$(dirname "$img")"
    cid=$(docker create "$FAKE_BUILD" /none) || die "docker create $FAKE_BUILD"
    docker cp "$cid:/bits/rootfs.img" "$img" > /dev/null || die "docker cp"
    docker rm "$cid" > /dev/null
    cp "$img" "$W/out/$t.rootfs.img" || die "copy $img"
    stage "$t rootfs $(sha256sum < "$W/out/$t.rootfs.img" | cut -d' ' -f1)"
    continue
  fi
  stage "$t pkgs start"
  plog=$W/logs/$t.pkgs.log
  make HV="$hv" ZARCH="$arch" PLATFORM="$platform" REPO_TAG="$TAG" FORCE_BUILD=--force \
    -o eve-alpine -o eve-alpine-base -o pkg/alpine -o pkg/alpine-base pkgs > "$plog" 2>&1 &
  pid=$! seen=0
  while kill -0 "$pid" 2> /dev/null; do
    sleep 60
    n=$(grep -c '^Building "lfedge/' "$plog" || true)
    [ "$n" = "$seen" ] && continue
    seen=$n
    stage "$t pkgs: $n started, now $(grep -o '^Building "lfedge/[^:]*' "$plog" | tail -1 | sed 's|.*lfedge/||')"
  done
  wait "$pid" || die "$t pkgs failed, see $plog"
  stage "$t rootfs start"
  make HV="$hv" ZARCH="$arch" PLATFORM="$platform" REPO_TAG="$TAG" rootfs > "$W/logs/$t.rootfs.log" 2>&1 ||
    die "$t rootfs failed, see $W/logs/$t.rootfs.log"
  [ -f "$img" ] || die "$t: no $img"
  cp "$img" "$W/out/$t.rootfs.img" || die "copy $img"
  stage "$t rootfs $(sha256sum < "$W/out/$t.rootfs.img" | cut -d' ' -f1)"
done
stage "done"
