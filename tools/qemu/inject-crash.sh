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
#   inject-crash.sh guest <domain-name> [qom-path] [window-us] [count]
#       Send the vfio-force-mem-toggle QMP command, forcing the memslot
#       teardown race -> KVM_RUN -EFAULT -> RUN_STATE_INTERNAL_ERROR. Tests
#       "mode A". REQUIRES a qemu-xen built with CONFIG_EVE_CRASH_INJECTOR
#       (xen-tools CRASH_INJECTOR=y). Discover the qom-path with:
#           inject-crash.sh qom <domain-name>
#
#   inject-crash.sh qom   <domain-name>
#       List candidate vfio-pci QOM paths for the 'guest' command.
#
# The domain name is the qemu -name, i.e. the DomainStatus.DomainName
# (<uuid>.<version>.<appnum>); `ls /run/hypervisor/kvm/` lists live ones.

set -eu

KVMDIR=/run/hypervisor/kvm

usage() { sed -n '2,30p' "$0"; exit 2; }

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
qom)
    command -v socat >/dev/null || { echo "socat not found" >&2; exit 1; }
    echo "vfio-pci devices under this domain (use the returned qom-path with 'guest'):"
    qmp "$sock" '{"execute":"qom-list","arguments":{"path":"/machine/peripheral-anon"}}' \
                '{"execute":"query-pci"}'
    ;;
guest)
    command -v socat >/dev/null || { echo "socat not found" >&2; exit 1; }
    qom=${3:-/machine/peripheral-anon/device[0]}
    win=${4:-5000}
    cnt=${5:-50}
    echo "forcing vfio MEM toggle on $qom (window=${win}us count=$cnt) for domain $dom"
    qmp "$sock" "{\"execute\":\"vfio-force-mem-toggle\",\"arguments\":{\"path\":\"$qom\",\"window-us\":$win,\"count\":$cnt}}"
    ;;
*)
    usage
    ;;
esac
