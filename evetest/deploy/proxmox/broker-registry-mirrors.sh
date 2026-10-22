#!/bin/sh
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# OCI registry pull-through cache mirrors setup script, run on the broker VM by
# evetest-registry-mirrors.service (see broker-cloudinit.yaml). Embedded into
# the assembled Proxmox broker installer by `make proxmox-broker-installer`
# (see evetest/deploy/proxmox/installer.sh.tmpl), which substitutes:
#   __WITH_MIRRORS__ - "true" if --with-oci-registry-mirrors was passed, else "false"
#   __UPLINK_IP__    - broker VM's IPv4 uplink address
#   __BASE_PORT__    - first of six consecutive ports used by the mirrors
set -eu

WITH_MIRRORS="__WITH_MIRRORS__"
UPLINK_IP="__UPLINK_IP__"
BASE_PORT=__BASE_PORT__

[ "$WITH_MIRRORS" = "true" ] || exit 0

# Resolve the uplink interface name dynamically from the already-known IPv4
# address, rather than hardcoding a device name (network interface naming
# isn't guaranteed across cloud images).
UPLINK_IF=$(ip -4 -o addr show | awk -v ip="$UPLINK_IP" '$4 ~ "^"ip"/" {print $2; exit}')

# Wait (bounded) for the uplink interface to get a global IPv6 address via
# SLAAC/DHCPv6, so mirror containers (and the env vars advertising them) can
# also be reached over IPv6 -- needed by devices whose network model is
# IPv6-only. If none appears in time, mirrors are published IPv4-only, same
# as before this address was ever attempted.
UPLINK_IPV6=""
i=0
while [ "$i" -lt 30 ]; do
    UPLINK_IPV6=$(ip -6 -o addr show dev "$UPLINK_IF" scope global 2>/dev/null \
        | awk '{print $4}' | cut -d/ -f1 | head -1)
    [ -n "$UPLINK_IPV6" ] && break
    i=$((i+1))
    sleep 1
done
if [ -z "$UPLINK_IPV6" ]; then
    echo "evetest-setup-registry-mirrors: no global IPv6 on $UPLINK_IF after 30s, mirrors will be IPv4-only" >&2
fi

start_mirror() {   # $1=name  $2=port  $3=upstream-url
    docker rm -f "evetest-mirror-$1" >/dev/null 2>&1 || true
    v6_publish=""
    [ -n "$UPLINK_IPV6" ] && v6_publish="-p [${UPLINK_IPV6}]:$2:5000"
    # shellcheck disable=SC2086  # $v6_publish is intentionally word-split (0 or 2 args)
    docker run -d --name "evetest-mirror-$1" --restart always \
        -e REGISTRY_PROXY_REMOTEURL="$3" \
        -p "${UPLINK_IP}:$2:5000" \
        $v6_publish \
        registry:2
}

start_mirror docker $((BASE_PORT+0)) https://registry-1.docker.io
start_mirror ghcr   $((BASE_PORT+1)) https://ghcr.io
start_mirror quay   $((BASE_PORT+2)) https://quay.io
start_mirror k8s    $((BASE_PORT+3)) https://registry.k8s.io
start_mirror gcr    $((BASE_PORT+4)) https://gcr.io
start_mirror mcr    $((BASE_PORT+5)) https://mcr.microsoft.com

# Env vars advertised to the broker (and, from there, to evetest clients) for
# each mirror -- comma-separated IPv4[,IPv6] addresses. Written here (rather
# than by the installer at install time, host-side) because the IPv6 address
# is only known once discovered above; evetest-broker.service is ordered to
# start only after this script (and this file) is ready.
mirror_urls() {   # $1=port
    v4="http://${UPLINK_IP}:$1"
    if [ -n "$UPLINK_IPV6" ]; then
        echo "${v4},http://[${UPLINK_IPV6}]:$1"
    else
        echo "$v4"
    fi
}

install -d -m 0755 /etc/evetest
cat > /etc/evetest/broker-mirrors.env <<EOF
EVETEST_REGISTRY_MIRROR_DOCKER=$(mirror_urls $((BASE_PORT+0)))
EVETEST_REGISTRY_MIRROR_GHCR=$(mirror_urls $((BASE_PORT+1)))
EVETEST_REGISTRY_MIRROR_QUAY=$(mirror_urls $((BASE_PORT+2)))
EVETEST_REGISTRY_MIRROR_K8S=$(mirror_urls $((BASE_PORT+3)))
EVETEST_REGISTRY_MIRROR_GCR=$(mirror_urls $((BASE_PORT+4)))
EVETEST_REGISTRY_MIRROR_MCR=$(mirror_urls $((BASE_PORT+5)))
EOF
chmod 0600 /etc/evetest/broker-mirrors.env
