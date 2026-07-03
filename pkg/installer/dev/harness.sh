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

hssh() {
  ssh -i "$WORK_DIR/id_ed25519" -p "$SSH_PORT" \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o LogLevel=ERROR "$SSH_USER@127.0.0.1" "$@"
}

cmd_up() {
  local disks=2 size=8G
  while [ $# -gt 0 ]; do
    case "$1" in
      --disks) disks="$2"; shift 2;;
      --size)  size="$2"; shift 2;;
      *) die "up: unknown arg $1";;
    esac
  done
  [ -f "$WORK_DIR/base.img" ] || die "run 'harness.sh build' first"
  [ -f "$WORK_DIR/qemu.pid" ] && kill -0 "$(cat "$WORK_DIR/qemu.pid")" 2>/dev/null \
    && die "already up (run: harness.sh down)"

  read -r OVMF_CODE OVMF_VARS_TMPL < <(_find_ovmf)
  cp -f "$OVMF_VARS_TMPL" "$WORK_DIR/OVMF_VARS.fd"

  # OS overlay: provisioned once, reused for fast subsequent boots
  if [ ! -f "$WORK_DIR/os.qcow2" ]; then
    log "creating OS overlay (first boot will run cloud-init)"
    qemu-img create -f qcow2 -b "$WORK_DIR/base.img" -F qcow2 "$WORK_DIR/os.qcow2" 20G >/dev/null
  fi

  # fresh test disks each session
  local drives=() n dev test_devs=""
  for n in $(seq 1 "$disks"); do
    truncate -s "$size" "$WORK_DIR/disk$n.img"
    drives+=(-drive "file=$WORK_DIR/disk$n.img,if=virtio,format=raw,cache=unsafe")
    dev="/dev/vd$(printf "\\$(printf '%03o' $((98 + n - 1)))")"  # vdb, vdc, ...
    test_devs="$test_devs $dev"
  done
  test_devs="${test_devs# }"

  # swtpm
  mkdir -p "$WORK_DIR/swtpm"
  swtpm socket --tpmstate "dir=$WORK_DIR/swtpm" \
    --ctrl "type=unixio,path=$WORK_DIR/swtpm/sock" --tpm2 \
    --daemon --pid "file=$WORK_DIR/swtpm/pid"

  log "booting VM"
  qemu-system-x86_64 -enable-kvm -m 2048 -smp 2 \
    -drive "if=pflash,format=raw,readonly=on,file=$OVMF_CODE" \
    -drive "if=pflash,format=raw,file=$WORK_DIR/OVMF_VARS.fd" \
    -drive "file=$WORK_DIR/os.qcow2,if=virtio,format=qcow2" \
    "${drives[@]}" \
    -drive "file=$WORK_DIR/seed.iso,if=none,id=seed,format=raw,readonly=on" \
    -device ide-cd,drive=seed \
    -chardev "socket,id=chrtpm,path=$WORK_DIR/swtpm/sock" \
    -tpmdev emulator,id=tpm0,chardev=chrtpm -device tpm-crb,tpmdev=tpm0 \
    -virtfs "local,path=$REPO_ROOT,mount_tag=repo,security_model=none,readonly=on" \
    -netdev "user,id=n0,hostfwd=tcp:127.0.0.1:$SSH_PORT-:22" \
    -device virtio-net-pci,netdev=n0 \
    -display none -serial "file:$WORK_DIR/serial.log" \
    -daemonize -pidfile "$WORK_DIR/qemu.pid"

  log "waiting for ssh (first boot provisions via cloud-init; can take ~1-2 min)"
  local i
  for i in $(seq 1 180); do
    if hssh true 2>/dev/null; then break; fi
    sleep 2
    [ "$i" = 180 ] && { cmd_down; die "VM did not come up (see $WORK_DIR/serial.log)"; }
  done

  cat > "$WORK_DIR/harness-env" <<EOF
TEST_DISKS="$test_devs"
BOOT_DISK="/dev/vda"
SSH_PORT="$SSH_PORT"
EOF
  log "up: test disks =$test_devs (boot disk /dev/vda)"
}

cmd_down() {
  local purge=0; [ "${1:-}" = "--purge" ] && purge=1
  if [ -f "$WORK_DIR/qemu.pid" ]; then
    hssh sudo poweroff 2>/dev/null || true
    sleep 3
    kill "$(cat "$WORK_DIR/qemu.pid")" 2>/dev/null || true
    rm -f "$WORK_DIR/qemu.pid"
  fi
  [ -f "$WORK_DIR/swtpm/pid" ] && { kill "$(cat "$WORK_DIR/swtpm/pid")" 2>/dev/null || true; }
  rm -f "$WORK_DIR"/disk*.img "$WORK_DIR/harness-env" "$WORK_DIR/serial.log"
  if [ "$purge" = 1 ]; then
    rm -rf "$WORK_DIR/os.qcow2" "$WORK_DIR/swtpm" "$WORK_DIR/OVMF_VARS.fd"
    log "purged (OS overlay + swtpm state removed)"
  fi
  log "down"
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
  up)    shift; cmd_up "$@";;
  down)  shift; cmd_down "$@";;
  ssh)   shift; hssh "$@";;
  *)     usage;;
esac
