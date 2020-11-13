#!/bin/sh

ForceOldlog=/config/Force-Use-Oldlog
if [ -f "$ForceOldlog" ]; then
    mkdir -p /run/watchdog/pid
    ./monitor-rsyslog.sh
else
    echo "Default to use Newlog, rsyslog exit..."
fi