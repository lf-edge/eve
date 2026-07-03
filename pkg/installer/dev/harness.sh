#!/usr/bin/env bash
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# QEMU VM dev harness for the EVE installer (see docs SP-2h spec).
set -euo pipefail

DEV_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$DEV_DIR/../../.." && pwd)"
WORK_DIR="$DEV_DIR/work"
CI_DIR="$DEV_DIR/cloud-init"

SSH_PORT=2223
SSH_USER=ubuntu
CLOUD_IMG_URL="https://cloud-images.ubuntu.com/releases/24.04/release/ubuntu-24.04-server-cloudimg-amd64.img"

log() { printf '[harness] %s\n' "$*" >&2; }
die() { printf '[harness] ERROR: %s\n' "$*" >&2; exit 1; }

# Echo "CODE_PATH VARS_TEMPLATE_PATH" for the first OVMF pair found.
_find_ovmf() {
  local codes=(/usr/share/OVMF/OVMF_CODE_4M.fd /usr/share/OVMF/OVMF_CODE.fd \
               /usr/share/edk2/x64/OVMF_CODE.4m.fd /usr/share/ovmf/OVMF.fd)
  local vars=(/usr/share/OVMF/OVMF_VARS_4M.fd /usr/share/OVMF/OVMF_VARS.fd \
              /usr/share/edk2/x64/OVMF_VARS.4m.fd /usr/share/OVMF/OVMF_VARS.fd)
  local i
  for i in "${!codes[@]}"; do
    if [ -f "${codes[$i]}" ] && [ -f "${vars[$i]}" ]; then
      echo "${codes[$i]} ${vars[$i]}"; return 0
    fi
  done
  return 1
}

cmd_build() {
  local missing=""
  for t in qemu-system-x86_64 qemu-img swtpm genisoimage ssh ssh-keygen curl; do
    command -v "$t" >/dev/null 2>&1 || missing="$missing $t"
  done
  [ -z "$missing" ] || die "missing host tools:$missing"
  _find_ovmf >/dev/null || die "OVMF firmware not found (install ovmf)"

  mkdir -p "$WORK_DIR"
  if [ ! -f "$WORK_DIR/base.img" ]; then
    log "downloading Ubuntu cloud image"
    curl -fL "$CLOUD_IMG_URL" -o "$WORK_DIR/base.img"
  fi
  if [ ! -f "$WORK_DIR/id_ed25519" ]; then
    ssh-keygen -t ed25519 -N "" -f "$WORK_DIR/id_ed25519" -q
  fi
  sed "s#__SSH_PUBKEY__#$(cat "$WORK_DIR/id_ed25519.pub")#" \
    "$CI_DIR/user-data.tmpl" > "$WORK_DIR/user-data"
  genisoimage -output "$WORK_DIR/seed.iso" -volid cidata -joliet -rock \
    "$WORK_DIR/user-data" "$CI_DIR/meta-data" >/dev/null 2>&1
  log "build complete (base image, ssh key, seed ready)"
}

usage() {
  cat >&2 <<EOF
usage: harness.sh <command>
  build     check prereqs, fetch base image, make ssh key + cloud-init seed
  up        boot the VM (test disks, swtpm, OVMF, 9p repo, ssh)
  run ...   run a command inside the VM over ssh
  inspect   show test-disk partition tables / filesystems
  down      shut the VM down (keep OS overlay); --purge removes everything
  selftest  L1 self-check (exits non-zero on failure)
  ssh       interactive shell in the VM
EOF
  exit 2
}

case "${1:-}" in
  build) shift; cmd_build "$@";;
  *)     usage;;
esac
