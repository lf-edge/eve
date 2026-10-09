#!/bin/sh
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# inject-crash.sh — DEBUG-ONLY on-device fault injector for validating the
# qemu/guest crash-dump capture path on real hardware. Run it on an EVE node.
#
#   inject-crash.sh qemu  <domain-name> [SIG]
#       Send a fatal signal (default ABRT) to the domain's qemu process. The
#       kernel writes a process core via core_pattern -> pillar picks it up and
#       compresses it into the vault. Tests "mode B". Works with
#       a stock qemu — no debug build needed.
#
#   inject-crash.sh guest <domain-name>
#       Send the x-inject-internal-error QMP command, which stops the VM in
#       RUN_STATE_INTERNAL_ERROR as a KVM_RUN failure would. Tests "mode A".
#       REQUIRES a debug QEMU: uncomment the CONFIG_EVE_CRASH_INJECTOR line in
#       pkg/qemu/Dockerfile.
#
# The domain name is the qemu -name, i.e. the DomainStatus.DomainName
# (<uuid>.<version>.<appnum>); `ls /run/hypervisor/kvm/` lists live ones.

set -eu

KVMDIR=/run/hypervisor/kvm

usage() { sed -n '2,21p' "$0"; exit 2; }

qmp() {
    # qmp <socket> <command-json...> : run the QMP handshake then the commands.
    sock=$1; shift
    {
        printf '%s\n' '{"execute":"qmp_capabilities"}'
        for c in "$@"; do printf '%s\n' "$c"; done
        sleep 1   # give qemu time to reply before socat closes the connection
    } | socat - "UNIX-CONNECT:$sock"
}

[ $# -ge 2 ] || usage
mode=$1; dom=$2
dir=$KVMDIR/$dom
[ -d "$dir" ] || { echo "no such domain dir: $dir (live: $(ls $KVMDIR 2>/dev/null))" >&2; exit 1; }
sock=$dir/qmp

case "$mode" in
qemu)
    sig=${3:-ABRT}
    pid=$(cat "$dir/pid" 2>/dev/null || true)
    [ -n "$pid" ] || { echo "no pid file at $dir/pid" >&2; exit 1; }
    echo "injecting SIG$sig into qemu pid $pid (domain $dom)"
    kill -"$sig" "$pid"
    ;;
guest)
    command -v socat >/dev/null || { echo "socat not found" >&2; exit 1; }
    echo "stopping domain $dom in internal-error"
    out=$(qmp "$sock" '{"execute":"x-inject-internal-error"}')
    echo "$out"
    case "$out" in
    *CommandNotFound*)
        echo "this QEMU has no injector; build pkg/qemu with CONFIG_EVE_CRASH_INJECTOR" >&2
        exit 1 ;;
    esac
    ;;
*)
    usage
    ;;
esac
