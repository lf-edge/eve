#!/bin/sh

if [ "$1" = logmanager ]; then
    /bin/mv -f /persist/rsyslog/logmanager.log /persist/rsyslog/logmanager-prev.log
elif [ "$1" = syslog ]; then
    /bin/mv -f /persist/rsyslog/syslog.txt /persist/rsyslog/syslog.prev.txt
else
    echo "rsyslogd: un-recognized logfile $1"
    exit
fi
