#!/bin/sh

# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
# shellcheck disable=SC3043

MAC="$(echo "$1" | tr '[:upper:]' '[:lower:]')"
FOUND=0

emit_ipv4() {
  local NETNS="$1"
  local PREFIX=""
  if [ -n "$NETNS" ]; then
    PREFIX="ip netns exec $NETNS"
  fi

  while read -r ARP_ENTRY; do
    local ENTRY_IP
    ENTRY_IP="$(echo "$ARP_ENTRY" | awk '{print $2}' | tr -d '()')"
    local ENTRY_MAC
    ENTRY_MAC="$(echo "$ARP_ENTRY" | awk '{print $4}')"
    if [ "$MAC" = "$ENTRY_MAC" ]; then
      echo "$ENTRY_IP"
      FOUND=1
    fi
  done <<EOF
$($PREFIX arp -an 2>/dev/null)
EOF
}

emit_ipv6() {
  local NETNS="$1"
  local PREFIX=""
  if [ -n "$NETNS" ]; then
    PREFIX="ip netns exec $NETNS"
  fi

  while read -r ND_ENTRY; do
    local ENTRY_IP
    ENTRY_IP="$(echo "$ND_ENTRY" | awk '{print $1}')"
    if [ "${ENTRY_IP#fe80:}" != "$ENTRY_IP" ]; then
      # Skip link-local address.
      continue
    fi
    local ENTRY_MAC
    ENTRY_MAC="$(echo "$ND_ENTRY" | awk '{for(i=1;i<=NF;i++) if($i=="lladdr") print $(i+1)}')"
    if [ "$MAC" = "$ENTRY_MAC" ]; then
      echo "$ENTRY_IP"
      FOUND=1
    fi
  done <<EOF
$($PREFIX ip -6 neigh show 2>/dev/null)
EOF
}

# --- main namespace ---
emit_ipv4
emit_ipv6

# --- all named namespaces ---
for NETNS in $(ip netns list | awk '{print $1}'); do
  emit_ipv4 "$NETNS"
  emit_ipv6 "$NETNS"
done

if [ "$FOUND" -eq 0 ]; then
  echo "Failed to get IP address for MAC=$MAC" >&2
  exit 1
fi

exit 0
