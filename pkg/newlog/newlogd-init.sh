#!/bin/sh

echo "$(date --iso-8601=ns --utc) starting newlogd"
/usr/bin/newlogd &
NEWLOGD_PID=$!
echo "$(date --iso-8601=ns --utc) newlogd is starting..., pid $NEWLOGD_PID"

NEWLOGD_TOUCH_FILE="/run/newlogd.touch"
SECONDS_PASSED=0
while [ ! -f "$NEWLOGD_TOUCH_FILE" ] && [ "$SECONDS_PASSED" -le 60 ];
do
    echo "$(date --iso-8601=ns --utc) waiting for $NEWLOGD_TOUCH_FILE"
    sleep 3
    SECONDS_PASSED=$((SECONDS_PASSED + 3))
done

if [ ! -f "$NEWLOGD_TOUCH_FILE" ]; then
    echo "$(date --iso-8601=ns --utc) gave up waiting for $NEWLOGD_TOUCH_FILE"
else
    echo "$(date --iso-8601=ns --utc) waited $SECONDS_PASSED seconds for $NEWLOGD_TOUCH_FILE"
fi

# subject for watchdog
mkdir -p /run/watchdog/pid /run/watchdog/file
touch /run/watchdog/pid/newlogd.pid /run/watchdog/file/newlogd.touch

NEWLOGD_RESTART_COUNT=0

while true;
do
    sleep 10
    PID=$(pgrep /usr/bin/newlogd)
    if [ "$NEWLOGD_RESTART_COUNT" -eq "0" ] && [ "$PID" != "$NEWLOGD_PID" ]; then
        if [ -n "$PID" ]; then
          # kill old process
          echo "$(date --iso-8601=ns --utc) kill old newlogd with pid $PID"
          kill -9 "$PID"
        fi
        ## restart it once to pickup the stack trace of newlogd
        /usr/bin/newlogd -r &
        NEWLOGD_RESTART_COUNT=$((NEWLOGD_RESTART_COUNT + 1))
        echo "$(date --iso-8601=ns --utc) newlogd restarted"
    fi
done