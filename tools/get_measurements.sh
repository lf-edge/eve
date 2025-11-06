#!/bin/bash
#
# Copyright (c) 2025 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# This script automates the collection of TPM binary BIOS measurements across different
# partition states (active/updating) for both IMGA and IMGB partitions. It builds EVE,
# boots it in QEMU with TPM enabled, and captures TPM measurements by:
# 1. Recording measurements for the current partition in both active and updating states
# 2. Copying the rootfs to the other partition
# 3. Switching to the other partition and recording its measurements in both states
# The resulting binary_bios_measurements_* files can be used for TPM PCR validation testing.
set -e

wait_for_ssh() {
    local max_attempts=60
    local attempt=1
    echo "Waiting for SSH connection..."
    while [ $attempt -le $max_attempts ]; do
        if ssh -i /tmp/eve_key -p 2222 -o StrictHostKeyChecking=no -o ConnectTimeout=5 root@localhost "echo 'SSH ready'" &>/dev/null; then
            return 0
        fi
        echo -n "."
        sleep 5
        attempt=$((attempt + 1))
    done
    echo "Failed to establish SSH connection after $max_attempts attempts"
    exit 1
}

# Generate random SSH key
ssh-keygen -t ed25519 -f /tmp/eve_key -N "" -q

# Add public key to authorized_keys
mkdir -p conf
cp /tmp/eve_key.pub conf/authorized_keys

# Build system for amd64 architecture
make clean pkgs live ZARCH=amd64

# Boot system with TPM
make run TPM=y &

# Wait for system to boot
wait_for_ssh && sleep 5

SSH_CMD="ssh -i /tmp/eve_key -p 2222 -o StrictHostKeyChecking=no root@localhost"

# get the current and other partition
CURPART=$($SSH_CMD "eve exec pillar zboot curpart")
OTHERPART=$([ "$CURPART" = "IMGA" ] && echo "IMGB" || echo "IMGA")

# get the current active part tpm logs
$SSH_CMD "cat /sys/kernel/security/tpm0/binary_bios_measurements" > "binary_bios_measurements_${CURPART}_active"

# set the current partition to updating
$SSH_CMD "eve exec pillar zboot set_partstate ${CURPART} updating && reboot"

# Wait for system to boot
wait_for_ssh && sleep 5

# get the current partition updating tpm logs
$SSH_CMD "cat /sys/kernel/security/tpm0/binary_bios_measurements" > "binary_bios_measurements_${CURPART}_updating"

# copy rootfs to other partition
$SSH_CMD << 'EOF'
PARTITIONS=$(lsblk -rno NAME,SIZE | awk '$2 ~ /512M/ {print $1}')
ROOTFS_PART=""
OTHER_PART=""
for part in $PARTITIONS; do
    if findmnt /dev/$part | grep -q "/"; then
        ROOTFS_PART=$part
    else
        OTHER_PART=$part
    fi
done

if [ -n "$ROOTFS_PART" ] && [ -n "$OTHER_PART" ]; then
    echo "Copying /dev/$ROOTFS_PART to /dev/$OTHER_PART"
    dd if=/dev/$ROOTFS_PART of=/dev/$OTHER_PART bs=4M
    sync
fi
EOF

# set the other partition to active
$SSH_CMD "eve exec pillar zboot set_partstate ${OTHERPART} active && reboot"

# Wait for system to boot
wait_for_ssh && sleep 5

# get the other part active tpm logs
$SSH_CMD  "cat /sys/kernel/security/tpm0/binary_bios_measurements" > "binary_bios_measurements_${OTHERPART}_active"

# set the other partition to updating
$SSH_CMD "eve exec pillar zboot set_partstate ${OTHERPART} updating && reboot"

# Wait for system to boot
wait_for_ssh && sleep 5


# get the other part updating tpm logs
$SSH_CMD "cat /sys/kernel/security/tpm0/binary_bios_measurements" > "binary_bios_measurements_${OTHERPART}_updating"


pkill -f qemu-system-x86_64
echo "done"
