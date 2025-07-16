#!/usr/bin/env bash
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# vm-destroy.sh — Destroy a VM created by vm-create.sh.
#
# Optionally unregisters the GitHub Actions runner before destroying the VM.
# Requires --user and --pat to unregister (PAT needs Read & Write Administration
# permission).
#
# Usage: ./vm-destroy.sh [--user <username>] [--pat <pat>] [--name <vm-name>]

set -euo pipefail

VM_NAME="evetest-runner"
GH_USER=""
GH_PAT=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --name) VM_NAME="$2"; shift 2 ;;
        --user) GH_USER="$2"; shift 2 ;;
        --pat)  GH_PAT="$2";  shift 2 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

if ! virsh domstate "$VM_NAME" &>/dev/null; then
    echo "VM '$VM_NAME' does not exist, nothing to do."
    exit 0
fi

# ── Unregister GitHub runner (optional) ─────────────────────────────────────
if [[ -n "$GH_USER" && -n "$GH_PAT" ]]; then
    RUNNER_ID=$(curl -s -H "Authorization: Bearer ${GH_PAT}" \
        "https://api.github.com/repos/${GH_USER}/eve/actions/runners" \
        | jq -r --arg name "$VM_NAME" '.runners[] | select(.name==$name) | .id')
    if [[ -n "$RUNNER_ID" ]]; then
        echo "Unregistering GitHub runner '$VM_NAME' (id: $RUNNER_ID)..."
        RESPONSE=$(curl -s -w "\n%{http_code}" -X DELETE \
            -H "Authorization: Bearer ${GH_PAT}" \
            "https://api.github.com/repos/${GH_USER}/eve/actions/runners/${RUNNER_ID}")
        HTTP_STATUS=$(echo "$RESPONSE" | tail -1)
        BODY=$(echo "$RESPONSE" | head -n -1)
        if [[ "$HTTP_STATUS" != "204" ]]; then
            echo "Failed to unregister runner (HTTP $HTTP_STATUS): $BODY"
            echo "Aborting VM destruction."
            exit 1
        fi
        echo "Runner unregistered."
    else
        echo "Runner '$VM_NAME' not found in GitHub (already gone or never registered)."
    fi
fi

# ── Destroy VM ───────────────────────────────────────────────────────────────
echo "Destroying VM '$VM_NAME'..."
virsh destroy  "$VM_NAME" 2>/dev/null || true
virsh undefine "$VM_NAME" --remove-all-storage
rm -f "/var/lib/libvirt/images/${VM_NAME}-seed.iso"
rm -f "$(dirname "$0")/evetest-runner.env"
echo "Done."
