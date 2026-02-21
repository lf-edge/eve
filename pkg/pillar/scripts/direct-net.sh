#!/bin/sh
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# direct-net.sh — move a physical network interface into (or out of)
# a container's network namespace for NOHYPE direct-attach.
#
# Called as an OCI prestart / poststop hook.
# stdin receives the container state JSON from runc (contains "pid").
#
# Usage:
#   direct-net.sh up   <host-ifname> <guest-ifname>
#   direct-net.sh down <host-ifname> <guest-ifname>

set -e

PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH

log() {
    echo "direct-net.sh: $*" >&2
}

try() {
    RETRIES=3
    while [ "$RETRIES" -gt 0 ]; do
        if "$@"; then
            return 0
        fi
        RETRIES="$(( RETRIES - 1 ))"
        sleep 1
    done
    return 1
}

# Given a host interface name, try to find the PCI address by checking
# /sys/class/net/<ifname>/device.  Returns empty string if not found.
ifname_to_pci() {
    local _link
    _link=$(readlink "/sys/class/net/$1/device" 2>/dev/null) || true
    if [ -n "$_link" ]; then
        basename "$_link"
    fi
}

# Given a PCI address, find the current kernel interface name by
# looking at /sys/bus/pci/devices/<addr>/net/.
pci_to_ifname() {
    local _dir="/sys/bus/pci/devices/$1/net"
    if [ -d "$_dir" ]; then
        find "$_dir" -maxdepth 1 -mindepth 1 -printf '%f\n' 2>/dev/null | head -1
    fi
}

# runc feeds us a JSON blob on stdin with the container PID.
CTR_PID=$(jq -r '.pid')

case "$1" in
    up)
        HOST_IF="$2"
        GUEST_IF="$3"

        if [ -z "$HOST_IF" ] || [ -z "$CTR_PID" ]; then
            echo "ERROR: usage: $0 up <host-ifname> <guest-ifname>" >&2
            exit 1
        fi

        log "up: host_if=$HOST_IF guest_if=$GUEST_IF ctr_pid=$CTR_PID"

        # Check if the expected interface exists.  If not, the kernel may
        # have assigned a different name after vfio-pci unbind + driver
        # rebind (the ethN counter only goes up).  domainmgr should have
        # renamed it, but as a safety net we also try PCI-based discovery.
        if ! ip link show "$HOST_IF" >/dev/null 2>&1; then
            log "WARNING: interface $HOST_IF not found in host namespace"
            log "  host interfaces: $(ip -o link show | awk -F': ' '{print $2}' | tr '\n' ' ')"
            # Dump PCI net sysfs for debugging
            for d in /sys/bus/pci/devices/*/net; do
                [ -d "$d" ] || continue
                _pci=$(echo "$d" | sed 's|/sys/bus/pci/devices/||;s|/net||')
                _ifs=$(find "$d" -maxdepth 1 -mindepth 1 -printf '%f ' 2>/dev/null)
                log "  pci=$_pci interfaces=$_ifs"
            done
        fi

        # Move the physical interface into the container's network namespace.
        try ip link set "$HOST_IF" netns "$CTR_PID"

        # Rename inside the container if a guest name was provided and differs.
        if [ -n "$GUEST_IF" ] && [ "$GUEST_IF" != "$HOST_IF" ]; then
            try nsenter -t "$CTR_PID" -n ip link set "$HOST_IF" name "$GUEST_IF"
            try nsenter -t "$CTR_PID" -n ip link set "$GUEST_IF" up
        else
            try nsenter -t "$CTR_PID" -n ip link set "$HOST_IF" up
        fi

        log "up: successfully moved $HOST_IF into container pid=$CTR_PID as ${GUEST_IF:-$HOST_IF}"
        ;;

    down)
        HOST_IF="$2"
        GUEST_IF="$3"

        if [ -z "$HOST_IF" ]; then
            echo "ERROR: usage: $0 down <host-ifname> <guest-ifname>" >&2
            exit 1
        fi

        log "down: host_if=$HOST_IF guest_if=$GUEST_IF ctr_pid=$CTR_PID"

        # The interface normally returns to the root namespace automatically
        # when the container's network namespace is destroyed.  However if
        # the namespace is still alive (e.g. graceful stop) we move it back
        # explicitly.
        IF_IN_CTR="${GUEST_IF:-$HOST_IF}"
        if [ -n "$CTR_PID" ] && [ "$CTR_PID" != "0" ] && \
           [ -d "/proc/$CTR_PID/ns" ] 2>/dev/null; then
            # Move back into the root (PID 1) network namespace.
            log "down: moving $IF_IN_CTR back from container pid=$CTR_PID"
            nsenter -t "$CTR_PID" -n ip link set "$IF_IN_CTR" netns 1 2>/dev/null || true
        fi

        # If the interface came back with the guest name, rename it back to
        # the host name so the system is in a clean state.
        if [ -n "$GUEST_IF" ] && [ "$GUEST_IF" != "$HOST_IF" ]; then
            if ip link show "$GUEST_IF" >/dev/null 2>&1; then
                log "down: renaming $GUEST_IF back to $HOST_IF"
                ip link set "$GUEST_IF" name "$HOST_IF" 2>/dev/null || true
            fi
        fi

        # Ensure the interface is up in the host namespace so the system
        # can reuse it.
        ip link set "$HOST_IF" up 2>/dev/null || true
        log "down: done for $HOST_IF"
        ;;

    *)
        echo "ERROR: usage: $0 up|down <host-ifname> <guest-ifname>" >&2
        exit 2
        ;;
esac
