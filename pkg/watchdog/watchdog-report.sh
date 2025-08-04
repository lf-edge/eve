#!/bin/sh
#
# Copyright (c) 2018 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

# Plugged in as a watchdog repair script just so that we can record the
# watchdog reason
# Does NOT attempt any repair

# First log to /persist in case zboot/kernel is hung on disk

log() {
    printf '%s %s\n' "$(date -Is)" "$*" >> /persist/log/watchdog.log
}

DATE=$(date -Is)
CURPART=$(cat /run/eve.id)
EVE_VERSION=$(cat /run/eve-release)
bootReason=""
echo "Watchdog report for $CURPART EVE version $EVE_VERSION at $DATE: $*" >>/persist/reboot-reason
echo "$CURPART" > /persist/reboot-image
sync

# If a /run/<agent.touch> then try sending a SIGUSR1 to get a stack trace
if [ $# -ge 2 ]; then
    agent=$(echo "$2" | grep '/run/.*\.touch' | sed 's,/run/\(.*\)\.touch,\1,')
    if [ -n "$agent" ]; then
        bootReason="BootReasonWatchdogHung" # Must match string in types package
        log "Watchdog report for $agent"
        echo "pkill -USR1 /opt/zededa/bin/zedbox"
        pkill -USR1 /opt/zededa/bin/zedbox
    fi
fi

log "Watchdog report for $CURPART EVE version $EVE_VERSION at $DATE: $*"
ps >>/persist/log/watchdog.log
log "Watchdog report done"

# If a /run/<agent.pid> then look for an oom message in dmesg for that agent
# and always record <agent> in reboot-reason
oom=""
agent=""
if [ $# -ge 2 ]; then
    agent=$(echo "$2" | grep '/run/.*\.pid' | sed 's,/run/\(.*\)\.pid,\1,')
    if [ -n "$agent" ]; then
        bootReason="BootReasonWatchdogPid" # Must match string in types package
        oom=$(dmesg | grep oom_reaper | grep "$agent")
    fi
fi
if [ -z "$oom" ]; then
    # Any other oom message?
    oom=$(dmesg | grep oom_reaper)
fi
if [ -z "$oom" ]; then
    # Any other oom message?
    oom=$(dmesg | grep "Out of memory")
fi
if [ -n "$oom" ]; then
    echo "$oom" >>/persist/reboot-reason
    bootReason="BootReasonOOM" # Must match string in types package
fi

# printing reboot-reason to the console
echo "Rebooting EVE. Reason: $(cat /persist/reboot-reason)" > /dev/console

if [ -n "$bootReason" ]; then
    # Do not overwrite an existing file since it is likely to be more
    # specific like Fatal
    if [ -f /persist/boot-reason ]; then
        log "Watchdog report not replacing $(cat /persist/boot-reason) with $bootReason"
    else
        echo $bootReason > /persist/boot-reason
        log "Watchdog report saved $bootReason"
    fi
fi

log "Run collect-info.sh now to capture the state before reboot"
## ─────── First check if we need to mute ──────────────────────────────────────────
MUTE_DAYS=7
MIN_DISKSPACE=100000000 # 100MB
TAR_DIR="/persist/eve-info"
SKIP_COLLECT=0

# glob for prior tarballs
pattern="$TAR_DIR/wd-eve-info-*.tar.gz"

# pick newest by name (we don't expect any non-alphanumeric characters in the name)
# shellcheck disable=SC2012
latest=$(ls -1 "$pattern" 2>/dev/null | sort | tail -n 1)

if [ -n "$latest" ]; then
    # Get the file's modification time as epoch seconds
    last_epoch=$(stat -c %Y "$latest" 2>/dev/null)
    [ -z "$last_epoch" ] && last_epoch=0

    now=$(date +%s)

    # compute cutoff and diff
    cutoff=$(( MUTE_DAYS * 24 * 3600 ))
    diff=$(( now - last_epoch ))

    # if within the mute window, bail out
    if [ "$diff" -lt "$cutoff" ]; then
        SKIP_COLLECT=1
        log "Skipping collect-info: last report at $(date -d @"$last_epoch") is within ${MUTE_DAYS}d."
    fi

    # check if we have enough space for a new tarball
    diskspace_free=$(df "$TAR_DIR" | tail -n 1 | awk '{print $4 * 1024}')
    # check if we have at least 100MB available
    if [ "$diskspace_free" -lt "$MIN_DISKSPACE" ]; then
        SKIP_COLLECT=1
        log "Skipping collect-info: not enough space in $TAR_DIR (available: ${diskspace_free} bytes)."
    fi
fi
## ─────────────────────────────────────────────────────────────────────

if [ $SKIP_COLLECT -eq 0 ]; then
    exec_id="$(basename "$(mktemp)")"
    if output=$(
        ctr --namespace services.linuxkit t exec --exec-id "$exec_id" debug \
            /containers/services/debug/rootfs/usr/bin/collect-info.sh -w -t 0 2>&1
    ); then
        log "collect-info.sh succeeded (exec-id=$exec_id). Output:"
    else
        rc=$?
        log "collect-info.sh FAILED with exit code $rc (exec-id=$exec_id). Output:"
    fi
    log "$output"
fi

sync
sleep 30
sync
exit 254
