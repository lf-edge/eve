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

CURPART=$(zboot curpart)
# If a /var/run/<agent.touch> then try sending a SIGUSR1 to get a stack trace
# and extract that stack trace.
stack=""
if [ $# -ge 2 ]; then
    agent=$(echo "$2" | grep '/var/run/.*\.touch' | sed 's,/var/run/\(.*\)\.touch,\1,')
    if [ -n "$agent" ]; then
        echo "pkill -USR1 /opt/zededa/bin/$agent"
        pkill -USR1 /opt/zededa/bin/"$agent"
        sleep 5
        # Note that logmanager.log is not json format
        if [ "$agent" = "logmanager" ]; then
            stack=$(grep level=warning /persist/log/logmanager.log | grep "stack trace")
        else
            stack=$(grep level...warning "/persist/$CURPART/log/$agent.log" | grep "stack trace")
        fi
    fi
fi

echo "Watchdog report at $DATE: $*" >>/persist/log/watchdog.log
ps >>/persist/log/watchdog.log
echo "Watchdog report done" >>/persist/log/watchdog.log

echo "Watchdog report at $DATE: $*" >>/persist/"$CURPART"/reboot-reason
# If a /var/run/<agent.pid> then look for a level fatal" message in its log
fatal=""
if [ $# -ge 2 ]; then
    agent=$(echo "$2" | grep '/var/run/.*\.pid' | sed 's,/var/run/\(.*\)\.pid,\1,')
    # Note that logmanager.log is not json format
    if [ "$agent" = "logmanager" ]; then
        fatal=$(grep level=fatal /persist/log/logmanager.log)
        stack=$(grep level=error /persist/log/logmanager.log | grep "stack trace")
    elif [ -n "$agent" ]; then
        fatal=$(grep level...fatal "/persist/$CURPART/log/$agent.log")
        stack=$(grep level...error "/persist/$CURPART/log/$agent.log" | grep "stack trace")
    fi
fi
if [ -n "$fatal" ]; then
   echo "$fatal" >>/persist/"$CURPART"/reboot-reason
fi
if [ -n "$stack" ]; then
   echo "$stack" >>/persist/"$CURPART"/reboot-stack
fi

sync
sleep 30
sync
exit 254
