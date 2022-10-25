#!/bin/sh
#
# Copyright (c) 2022 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

WATCHDOG_PID=/run/watchdog/pid
WATCHDOG_FILE=/run/watchdog/file
CONFIGDIR=/config
PERSISTDIR=/persist
PERSIST_CERTS="$PERSISTDIR/certs"
DEVICE_KEY_NAME="$CONFIGDIR/device.key.pem"
PERSIST_AGENT_DEBUG=$PERSISTDIR/agentdebug
BINDIR=/opt/zededa/bin
TMPDIR="${PERSISTDIR}/tmp"
ZTMPDIR=/run/global
DPCDIR="$ZTMPDIR/DevicePortConfig"
FIRSTBOOTFILE="$ZTMPDIR/first-boot"
FIRSTBOOT=
TPM_DEVICE_PATH="/dev/tpmrm0"
SECURITYFSPATH=/sys/kernel/security
PATH=$BINDIR:$PATH
DISKSPACE_RECOVERY_LIMIT=70

# shellcheck source=pkg/pillar/scripts/common.sh
. /opt/zededa/bin/common.sh

echo "$(date -Ins -u) Starting onboot.sh"

# Copy pre-defined fscrypt.conf
cp fscrypt.conf /etc/fscrypt.conf

mkdir -p $ZTMPDIR
if [ -d $TMPDIR ]; then
    echo "$(date -Ins -u) Old TMPDIR files:"
    ls -lt $TMPDIR
    rm -rf $TMPDIR
fi
mkdir -p $TMPDIR
export TMPDIR

if ! mount -t securityfs securityfs "$SECURITYFSPATH"; then
    echo "$(date -Ins -u) mounting securityfs failed"
fi

DIRS="$PERSIST_CERTS $PERSIST_AGENT_DEBUG /persist/status/zedclient/OnboardingStatus"

# If /persist/installer/first-boot exists treat this as a first boot
# we rename file to not assume that it is the first boot if we reboot occasionally
if [ -f "$PERSISTDIR/installer/first-boot" ]; then
    mv "$PERSISTDIR/installer/first-boot" "$PERSISTDIR/installer/send-require"
    touch $FIRSTBOOTFILE # For nodeagent
    FIRSTBOOT=1
fi

# If /persist didn't exist or was removed treat this as a first boot
if [ ! -d $PERSIST_CERTS ]; then
    touch $FIRSTBOOTFILE # For nodeagent
    FIRSTBOOT=1
fi

for d in $DIRS; do
    d1=$(dirname "$d")
    if [ ! -d "$d1" ]; then
        echo "$(date -Ins -u) Create $d1"
        mkdir -p "$d1"
        chmod 700 "$d1"
    fi
    if [ ! -d "$d" ]; then
        echo "$(date -Ins -u) Create $d"
        mkdir -p "$d"
        chmod 700 "$d"
    fi
done

# Save any existing checkpoint directory for debugging
rm -rf $PERSIST_AGENT_DEBUG/checkpoint
if [ -d /persist/checkpoint ]; then
    echo "$(date -Ins -u) Saving copy of /persist/checkpoint in /persist/agentdebug"
    cp -rp /persist/checkpoint $PERSIST_AGENT_DEBUG/
fi

# Save any existing /persist/status directory for debugging
rm -rf $PERSIST_AGENT_DEBUG/status
if [ -d /persist/status ]; then
    echo "$(date -Ins -u) Saving copy of /persist/status in /persist/agentdebug"
    cp -rp /persist/status $PERSIST_AGENT_DEBUG/
fi

echo "$(date -Ins -u) Configuration from factory/install:"
(cd $CONFIGDIR || return; ls -l)
echo

# If zedbox is already running we don't have to start it.
if ! pgrep zedbox >/dev/null; then
    echo "$(date -Ins -u) Starting zedbox"
    $BINDIR/zedbox &
    wait_for_touch zedbox
fi

mkdir -p "$WATCHDOG_PID" "$WATCHDOG_FILE"
touch "$WATCHDOG_PID/zedbox.pid" "$WATCHDOG_FILE/zedbox.touch"

if [ -c $TPM_DEVICE_PATH ] && ! [ -f $DEVICE_KEY_NAME ]; then
    # It is a device with TPM, enable disk encryption
    if ! $BINDIR/vaultmgr setupDeprecatedVaults; then
        echo "$(date -Ins -u) device-steps: vaultmgr setupDeprecatedVaults failed"
    fi
fi

if [ -f $PERSISTDIR/reboot-reason ]; then
    echo "Reboot reason: $(cat $PERSISTDIR/reboot-reason)" > /dev/console
elif [ -n "$FIRSTBOOT" ]; then
    echo "Reboot reason: NORMAL: First boot of device - at $(date -Ins -u)" > /dev/console
else
    echo "Reboot reason: UNKNOWN: reboot reason - power failure or crash - at $(date -Ins -u)" > /dev/console
fi

if [ ! -d $PERSISTDIR/log ]; then
    echo "$(date -Ins -u) Creating $PERSISTDIR/log"
    mkdir $PERSISTDIR/log
fi

if [ ! -d $PERSISTDIR/status ]; then
    echo "$(date -Ins -u) Creating $PERSISTDIR/status"
    mkdir $PERSISTDIR/status
fi

if [ -f $CONFIGDIR/restartcounter ]; then
    echo "$(date -Ins -u) move $CONFIGDIR/restartcounter $PERSISTDIR/status"
    mv $CONFIGDIR/restartcounter $PERSISTDIR/status
fi
if [ -f $CONFIGDIR/rebootConfig ]; then
    echo "$(date -Ins -u) move $CONFIGDIR/rebootConfig $PERSISTDIR/status"
    mv $CONFIGDIR/rebootConfig $PERSISTDIR/status
fi
if [ -f $CONFIGDIR/hardwaremodel ]; then
    echo "$(date -Ins -u) move $CONFIGDIR/hardwaremodel $PERSISTDIR/status"
    mv $CONFIGDIR/hardwaremodel $PERSISTDIR/status
fi

# Checking for low diskspace at bootup. If used percentage of
# /persist directory is more than 70% then we will remove the
# following sub directories:
# /persist/log/*
# /persist/newlog/appUpload/*
# /persist/newlog/devUpload/*
# /persist/newlog/keepSentQueue/*
# /persist/newlog/failedUpload/*
diskspace_used=$(df /persist |awk '/\/dev\//{printf("%d",$5);}')
echo "Used percentage of /persist: $diskspace_used"
if [ "$diskspace_used" -ge "$DISKSPACE_RECOVERY_LIMIT" ]
then
    echo "Used percentage of /persist is $diskspace_used more than the limit $DISKSPACE_RECOVERY_LIMIT"
    for DIR in log newlog/keepSentQueue newlog/failedUpload newlog/appUpload newlog/devUpload
    do
        dir_del=$PERSISTDIR/$DIR
        rm -rf "${dir_del:?}/"*
        diskspace_used=$(df /persist |awk '/\/dev\//{printf("%d",$5);}')
        echo "Used percentage of /persist is $diskspace_used after clearing $dir_del"
        if [ "$diskspace_used" -le "$DISKSPACE_RECOVERY_LIMIT" ]
        then
            break
        fi
    done
    diskspace_used=$(df /persist |awk '/\/dev\//{printf("%d",$5);}')
    echo "Used percentage of /persist after recovery: $diskspace_used"
fi

# Run upgradeconverter
mkdir -p /persist/ingested/
echo "$(date -Ins -u) device-steps: Starting upgradeconverter (pre-vault)"
$BINDIR/upgradeconverter pre-vault
echo "$(date -Ins -u) device-steps: upgradeconverter (pre-vault) Completed"

# BlinkCounter 1 means we have started; might not yet have IP addresses
# client/selfRegister and zedagent update this when the found at least
# one free uplink with IP address(s)
mkdir -p "$ZTMPDIR/LedBlinkCounter"
echo '{"BlinkCounter": 1}' > "$ZTMPDIR/LedBlinkCounter/ledconfig.json"

mkdir -p $DPCDIR

# Read any usb.json with DevicePortConfig, and deposit our identity
access_usb

# Update our local /etc/hosts with entries coming from /config
# We append on every boot since /etc/hosts starts from read-only rootfs
[ -f /config/hosts ] && cat /config/hosts >> /etc/hosts

echo "$(date -Ins -u) onboot.sh done"
