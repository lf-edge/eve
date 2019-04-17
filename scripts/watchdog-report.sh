#!/bin/sh
#
# Copyright (c) 2018 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

# Plugged in as a watchdog repair script just so that we can record the
# watchdog reason
# Does NOT attempt any repair

# First log to /persist in case zboot/kernel is hung on disk

DATE=$(date -Ins)
echo "Watchdog report at $DATE: $*" >>/persist/reboot-reason
sync

# If a /var/run/<agent.touch> then try sending a SIGUSR1 to get a stack trace
if [ $# -ge 2 ]; then
    agent=$(echo "$2" | grep '/var/run/.*\.touch' | sed 's,/var/run/\(.*\)\.touch,\1,')
    if [ -n "$agent" ]; then
        echo "pkill -USR1 /opt/zededa/bin/$agent"
        pkill -USR1 /opt/zededa/bin/"$agent"
    fi
fi

CURPART=$(zboot curpart)
echo "Watchdog report at $DATE: $*" >>/persist/"$CURPART"/reboot-reason
sync
sleep 30
sync
exit 254
