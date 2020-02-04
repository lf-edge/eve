#!/bin/sh

mkdir -p /run/watchdog/pid 2>/dev/null || :
(cd /run/watchdog/pid && touch logread.pid rsyslogd.pid monitor-rsyslogd.pid)

./monitor-rsyslog.sh &

LOGREAD_PID_WAIT=3600
while true;
do
    if [ -n "$(pgrep logread)" ]; then
        sleep 10
        continue
    fi
    (/usr/bin/logread -F -socket /run/memlogdq.sock | logger) &
    echo $! > /run/logread.pid

    LOOP_COUNT=0
    while [ -z "$(pgrep logread)" ];
    do
        sleep 1
        LOOP_COUNT=$((LOOP_COUNT + 1))
        if [ "$LOOP_COUNT" -ge "$LOGREAD_PID_WAIT" ]; then
            echo "$(date -Ins -u) Error: Could not find logread process"
            break
        fi
    done

    LOGREAD_PID=$(pgrep logread)
    if [ -n "$LOGREAD_PID" ]; then
        echo "$LOGREAD_PID" > /run/logread.pid
    else
        echo "$(date -Ins -u) Error: logread has not started"
    fi
done
