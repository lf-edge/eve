#!/bin/sh
#
# Copyright (c) 2025 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# cgv2-audit.sh — inspect cgroup v2 on EVE (run from debug container)
# - Prefers host view at /hostfs; falls back to container /sys if missing
# - Dumps controllers, subtree_control, cpuset init, common limits, and PIDs
# - Optionally installs bpftool via apk when run with: CGV2_INSTALL_BPFTOOL=1 ./cgv2-audit.sh
#
# Env knobs:
#   CGV2_ROOT=/hostfs           # host root prefix (default)
#   CGV2_INSTALL_BPFTOOL=1      # try to apk add bpftool if missing
#   CGV2_ALPINE_VER=3.17        # repo version used for bpftool install

set -eu

CGV2_INSTALL_BPFTOOL=1
CGV2_ALPINE_VER=3.17

ROOT="${CGV2_ROOT:-/hostfs}"
ALT="/sys"  # container fallback
CGROOT="${ROOT}/sys/fs/cgroup"
HPROC="${ROOT}/proc"

hr() { printf '%s\n' "------------------------------------------------------------"; }
kv() { printf '  %-22s : %s\n' "$1" "$2"; }
readf() { [ -f "$1" ] && cat "$1" || echo "-"; }

have() { command -v "$1" >/dev/null 2>&1; }

mountline() {
  # Try host mountinfo first, then container
  if [ -r "${HPROC}/self/mountinfo" ]; then
    grep -E " /sys/fs/cgroup " "${HPROC}/self/mountinfo" || true
  else
    mount | grep -E " on /sys/fs/cgroup type cgroup2" || true
  fi
}

# Convert absolute cgroup path to host path if needed
H() {
  case "$1" in
    "${ROOT}"/*)  printf '%s' "$1" ;;
    /*)           printf '%s%s' "$ROOT" "$1" ;;
    *)            printf '%s/%s' "$CGROOT" "$1" ;;
  esac
}

# Print a node’s info (expects an absolute cgroup path like /sys/fs/cgroup/…)
show_node() {
  node="$1"
  hnode="$(H "$node")"
  [ -d "$hnode" ] || return 0
  printf "%s\n" "$node"
  kv "controllers avail"  "$(readf "$hnode/cgroup.controllers")"
  kv "subtree_control"    "$(readf "$hnode/cgroup.subtree_control")"
  kv "procs (count)"      "$( [ -f "$hnode/cgroup.procs" ] && wc -l < "$hnode/cgroup.procs" || echo "-" )"

  # cpuset status
  kv "cpuset.cpus"        "$(readf "$hnode/cpuset.cpus")"
  kv "cpuset.cpus.eff"    "$(readf "$hnode/cpuset.cpus.effective")"
  kv "cpuset.mems"        "$(readf "$hnode/cpuset.mems")"
  kv "cpuset.mems.eff"    "$(readf "$hnode/cpuset.mems.effective")"

  # common limits
  kv "cpu.max"            "$(readf "$hnode/cpu.max")"
  kv "cpu.weight"         "$(readf "$hnode/cpu.weight")"
  kv "memory.max"         "$(readf "$hnode/memory.max")"
  kv "memory.high"        "$(readf "$hnode/memory.high")"
  kv "memory.swap.max"    "$(readf "$hnode/memory.swap.max")"
  kv "pids.max"           "$(readf "$hnode/pids.max")"
  kv "io.weight"          "$(readf "$hnode/io.weight")"

  # Warn if +cpuset without init
  sc="$(readf "$hnode/cgroup.subtree_control")"
  ccpu="$(readf "$hnode/cpuset.cpus" | tr -d '\n')"
  cmem="$(readf "$hnode/cpuset.mems" | tr -d '\n')"
  if echo "$sc" | grep -q "+cpuset"; then
    [ -n "$ccpu" ] && [ "$ccpu" != "-" ] || printf "  [WARN] %s: +cpuset enabled but cpuset.cpus empty\n" "$node"
    [ -n "$cmem" ] && [ "$cmem" != "-" ] || printf "  [WARN] %s: +cpuset enabled but cpuset.mems empty\n" "$node"
  fi

  # Show up to 5 PIDs with names (from host /proc)
  if [ -f "$hnode/cgroup.procs" ] && [ -d "$HPROC" ]; then
    n=0
    while read -r pid; do
      [ -n "$pid" ] || continue
      name="-"
      [ -f "$HPROC/$pid/comm" ] && name="$(tr -d '\n' < "$HPROC/$pid/comm")"
      if [ "$name" = "-" ] && [ -r "$HPROC/$pid/cmdline" ]; then
        name="$(tr '\0' ' ' < "$HPROC/$pid/cmdline" | sed 's/ *$//')"
      fi
      printf "    pid=%s  cmd=%s\n" "$pid" "${name:-?}"
      n=$((n+1)); [ "$n" -ge 25 ] && break
    done < "$hnode/cgroup.procs"
  fi
  hr
}

bpftool_try() {
  node="$1"
  hnode="$(H "$node")"
  if have bpftool; then
    echo "Attached BPF programs (if any) at $node:"
    # Prefer cgroup-aware listing; fallback to generic
    if bpftool cgroup show "$hnode" 2>/dev/null; then :; else
      bpftool prog show 2>/dev/null | grep -i cgroup || true
    fi
    hr
  else
    echo "bpftool not present — skipping BPF inspection"
    hr
  fi
}

maybe_install_bpftool() {
  [ "${CGV2_INSTALL_BPFTOOL:-0}" = "1" ] || return 0
  have bpftool && return 0
  if have apk; then
    ver="${CGV2_ALPINE_VER:-3.17}"
    echo "Installing bpftool via apk (Alpine ${ver})…"
    set +e
    apk add --no-cache \
      -X "https://dl-cdn.alpinelinux.org/alpine/v${ver}/main" \
      -X "https://dl-cdn.alpinelinux.org/alpine/v${ver}/community" \
      bpftool
    rc=$?
    set -e
    [ $rc -eq 0 ] || echo "apk install failed (exit $rc)"
  fi
}

config_try() {
  echo "Kernel config (host):"
  if [ -r "${HPROC}/config.gz" ]; then
    zcat "${HPROC}/config.gz" | grep -E '^(CONFIG_(CGROUPS|CGROUP_BPF|BPF|BPF_SYSCALL|BPF_JIT|CGROUP_PIDS|CGROUP_SCHED|BLK_CGROUP))=' || true
  else
    echo "  ${HPROC}/config.gz not available"
  fi
  hr
}

main() {
  echo "cgroup v2 audit — $(date)"
  hr

  # Pick host view if available; else fall back
  if [ -f "${CGROOT}/cgroup.controllers" ]; then
    echo "[ using HOST cgroup view at ${CGROOT} ]"
  elif [ -f "${ALT}/fs/cgroup/cgroup.controllers" ]; then
    ROOT=""; CGROOT="${ALT}/fs/cgroup"; HPROC="/proc"
    echo "[ host view missing; using CONTAINER view at ${CGROOT} ]"
  else
    echo "ERROR: no cgroup v2 mount found under ${ROOT}/sys/fs/cgroup or ${ALT}/fs/cgroup"
    exit 1
  fi
  hr

  echo "[ mount (host perspective) ]"
  mountline || true
  [ -f "${CGROOT}/cgroup.controllers" ] || { echo "ERROR: cgroup.controllers missing"; exit 1; }
  hr

  echo "[ root ]"
  show_node "/sys/fs/cgroup"

  if [ -d "$(H /sys/fs/cgroup/eve)" ]; then
    echo "[ /sys/fs/cgroup/eve ]"
    show_node "/sys/fs/cgroup/eve"

    if [ -d "$(H /sys/fs/cgroup/eve/containerd)" ]; then
      echo "[ /sys/fs/cgroup/eve/containerd ]"
      show_node "/sys/fs/cgroup/eve/containerd"
    fi

    if [ -d "$(H /sys/fs/cgroup/eve/services)" ]; then
      echo "[ /sys/fs/cgroup/eve/services ]"
      show_node "/sys/fs/cgroup/eve/services"
      for d in "$(H /sys/fs/cgroup/eve/services)"/*; do
        [ -d "$d" ] || continue
        # strip ROOT prefix for pretty printing
        rel="${d#"${ROOT}"}"
        echo "[ $rel ]"
        show_node "$rel"
      done
    fi
  fi

  echo "[ cgroup-bpf ]"
  maybe_install_bpftool
  bpftool_try "/sys/fs/cgroup"

  config_try

  echo "Hints:"
  echo "  • If +cpuset is enabled anywhere, ensure cpuset.cpus and cpuset.mems are set at that level."
  echo "  • runc on v2 uses BPF_CGROUP_DEVICE for device filtering; CONFIG_CGROUP_BPF must be enabled."
  echo "  • Per-service tuning lives in leaves: memory.max/high, cpu.max/weight, pids.max, io.weight."
}

main "$@"
