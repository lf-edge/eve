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
SWTPM_RUN_PATH=/run/swtpm
SWTPM_PERSIST_PATH=/persist/swtpm
PATH=$BINDIR:$PATH
MIN_DISKSPACE=4096 # MBytes

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

mkdir -p "$WATCHDOG_PID" "$WATCHDOG_FILE"
touch "$WATCHDOG_PID/zedbox.pid" "$WATCHDOG_FILE/zedbox.touch"

if [ -c $TPM_DEVICE_PATH ] && ! [ -f $DEVICE_KEY_NAME ]; then
    # It is a device with TPM, enable disk encryption
    if ! $BINDIR/vaultmgr setupDeprecatedVaults; then
        echo "$(date -Ins -u) onboot.sh: vaultmgr setupDeprecatedVaults failed"
    fi
fi

if [ -f $PERSISTDIR/reboot-reason ]; then
    echo "Reboot reason: $(cat $PERSISTDIR/reboot-reason)" | tee /dev/console
elif [ -n "$FIRSTBOOT" ]; then
    echo "Reboot reason: NORMAL: First boot of device - at $(date -Ins -u)" | tee /dev/console
else
    echo "Reboot reason: UNKNOWN: reboot reason - power failure or crash - at $(date -Ins -u)" | tee /dev/console
fi

if [ ! -d $PERSISTDIR/log ]; then
    echo "$(date -Ins -u) Creating $PERSISTDIR/log"
    mkdir $PERSISTDIR/log
fi

if [ ! -d $PERSISTDIR/status ]; then
    echo "$(date -Ins -u) Creating $PERSISTDIR/status"
    mkdir $PERSISTDIR/status
fi

# percent_used <dataset name> (without leading '/')
percent_used() {
    res=$(zfs list -pH -o available,used "$1")
    # shellcheck disable=SC2181
    if [ $? = 0 ]; then
        # shellcheck disable=SC2086
        avail=$(echo $res | cut -d\  -f1)
        # shellcheck disable=SC2086
        used=$(echo $res | cut -d\  -f2)
        echo $((100*used/(avail+used)))
    else
        df --sync /"$1" |awk '{printf("%d",$5);}'
    fi
}

# /persist/pubsub-large does not need to be persisted across reboots, but
# is in /persist to avoid using overlayfs aka memory for content which might
# be Megabytes in size
rm -rf /persist/pubsub-large

# free_space <dataset name> (without leading '/')
# return value is truncated to MBytes
# Note that we use df even for zfs since the "available" property in zfs
# includes unused space in child datasets
free_space() {
    ds="$1"
    res=$(df --sync -k --output=avail "/$ds" | tail -1)
    echo $((res/1024))
}

# Checking for low diskspace at bootup.
# If there is less than 4Mbytes (MIN_DISKSPACE) then remove the content of the
# following directories in order until we have that amount of available space
# following sub directories:
PERSIST_CLEANUPS='log netdump kcrashes memory-monitor/output eve-info patchEnvelopesCache patchEnvelopesUsageCache newlog/keepSentQueue newlog/failedUpload newlog/appUpload newlog/devUpload containerd-system-root vault/downloader vault/verifier agentdebug'
# NOTE that we can not cleanup /persist/containerd and /persist/{vault,clear}/volumes since those are used by applications.
#
# Note that we need to free up some space before Linuxkit starts containerd,
# we need to wait a bit for ZFS deletes to take place, but we are not yet
# running watchdogd to we need to hurry to not have the watchdog fire.
# So we sleep a minimal of 2 seconds per directory.
diskspace_free=$(free_space persist)
echo "Free space in /persist: $diskspace_free MBytes" | tee /dev/console
if [ "$diskspace_free" -lt "$MIN_DISKSPACE" ]
then
    echo "Free space in /persist is only $diskspace_free hence below the limit $MIN_DISKSPACE MBytes" | tee /dev/console
    for DIR in $PERSIST_CLEANUPS
    do
        dir_del=$PERSISTDIR/$DIR
        rm -rf "${dir_del:?}/"*
        diskspace_free=$(free_space persist)
        echo "Free space in /persist after clearing $dir_del: $diskspace_free MBytes" | tee /dev/console
        # Need to wait for ZFS to free space
        sleep 2
        diskspace_free=$(free_space persist)
        echo "Free space in /persist after clearing $dir_del and 2s sleep: $diskspace_free MBytes" | tee /dev/console
        if [ "$diskspace_free" -ge "$MIN_DISKSPACE" ]
        then
            break
        fi
    done
    diskspace_free=$(free_space persist)
    echo "Free space in /persist after recovery: $diskspace_free MBytes" | tee /dev/console
fi

# Run upgradeconverter
mkdir -p /persist/ingested/
echo "$(date -Ins -u) onboot.sh: Starting upgradeconverter (pre-vault)"
$BINDIR/upgradeconverter pre-vault
echo "$(date -Ins -u) onboot.sh: upgradeconverter (pre-vault) Completed"

# BlinkCounter 1 means we have started; might not yet have IP addresses
# client/selfRegister and zedagent update this when the found at least
# one free uplink with IP address(s)
mkdir -p "$ZTMPDIR/LedBlinkCounter"
echo '{"BlinkCounter": 1}' > "$ZTMPDIR/LedBlinkCounter/ledconfig.json"

mkdir -p $DPCDIR

# This directories is used by swtpm to create its communication socket and save
# its tpm states. 101:101 is actually vtpm:vtpm.
# XXX : use names instead of numeric uid/gid
mkdir -p $SWTPM_RUN_PATH
mkdir -p $SWTPM_PERSIST_PATH
chown 101:101 $SWTPM_RUN_PATH
chown 101:101 $SWTPM_PERSIST_PATH
chmod 740 $SWTPM_RUN_PATH
chmod 740 $SWTPM_PERSIST_PATH

echo "$(date -Ins -u) onboot.sh done"
