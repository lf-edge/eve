#!/bin/sh

/usr/bin/newlogd &
mkdir -p /run/watchdog/pid
touch /run/watchdog/pid/newlogd.pid

NEWLOGD_PID=$(cat /run/newlogd.pid)
LOOP_COUNT=0
while [ -z "$NEWLOGD_PID" ] && [ "$LOOP_COUNT" -le 30 ];
do
    sleep 1
    LOOP_COUNT=$((LOOP_COUNT + 1))
    NEWLOGD_PID=$(cat /run/newlogd.pid)
done

NEWLOGD_RESTART_COUNT=0

echo "newlogd init.sh starting..., newlogd pid $NEWLOGD_PID"
while true;
do
    sleep 10
    PID=$(pgrep /usr/bin/newlogd)
    if [ "$NEWLOGD_RESTART_COUNT" -eq "0" ] && { [ "$PID" != "$NEWLOGD_PID" ] || [ -z "$NEWLOGD_PID" ]; }; then
        ## restart it once to pickup the stack trace of newlogd
        /usr/bin/newlogd -r &
        NEWLOGD_RESTART_COUNT=$((NEWLOGD_RESTART_COUNT + 1))
        echo "newlogd init.sh restarted"
    fi
done