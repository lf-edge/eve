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
        # Map the various zedagent* to zedagent
        if [ "$agent" = "zedagentmetrics" ] -o [ "$agent" = "zedagentconfig" ] -o [ "$agent" = "zedagentdevinfo" ]; then
            agent="zedagent"
        fi
        echo "pkill -USR1 /opt/zededa/bin/$agent"
        pkill -USR1 /opt/zededa/bin/"$agent"
    fi
fi

echo "Watchdog report at $DATE: $*" >>/persist/log/watchdog.log
ps >>/persist/log/watchdog.log
echo "Watchdog report done" >>/persist/log/watchdog.log

CURPART=$(zboot curpart)
echo "Watchdog report at $DATE: $*" >>/persist/"$CURPART"/reboot-reason

# If a /var/run/<agent.pid> then look for an oom message in dmesg for that agent
oom=""
if [ $# -ge 2 ]; then
    agent=$(echo "$2" | grep '/var/run/.*\.pid' | sed 's,/var/run/\(.*\)\.pid,\1,')
    if [ -n "$agent" ]; then
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
   echo "$oom" >>/persist/"$CURPART"/reboot-reason
fi

sync
sleep 30
sync
exit 254
