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
exec_id="$(basename "$(mktemp)")"
if output=$(
    ctr --namespace services.linuxkit t exec --exec-id "$exec_id" debug \
        /containers/services/debug/rootfs/usr/bin/collect-info.sh -t 0 2>&1
); then
    log "collect-info.sh succeeded (exec-id=$exec_id). Output:"
    log "$output"
else
    rc=$?
    log "collect-info.sh FAILED with exit code $rc (exec-id=$exec_id). Output:"
    log "$output"
fi

sync
sleep 30
sync
exit 254
