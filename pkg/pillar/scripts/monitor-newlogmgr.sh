#!/bin/sh

BINDIR=/opt/zededa/bin

wait_for_newlogmgr()
{
    # limit the wait to 30 seconds
    LOOP_COUNT=0
    while [ -z "$(pgrep newlogmgr)" ];
    do
        echo "Waiting for newlogmgr to start"
        LOOP_COUNT=$((LOOP_COUNT + 1))
        if [ "$LOOP_COUNT" -ge 30 ]; then
            break
        fi
        sleep 1
    done
}

# write our own /run/monitor-newlogmgr.pid
echo $$ > /run/monitor-newlogmgr.pid
touch /run/watchdog/pid/monitor-newlogmgr.pid

NEWLOGMGR_PID=$(cat /run/newlogmgr.pid)

echo "$(date -Ins -u) monitor-newlogmgr: started, newlogmgr PID $NEWLOGMGR_PID"

while true;
do
    sleep 10
    PID=$(pgrep newlogmgr)
    if [ "$PID" != "$NEWLOGMGR_PID" ] || [ -z "$NEWLOGMGR_PID" ]; then
        echo "Error: newlogmgr died, trying to restart newlogmgr"

        # restart and wait for newlogmgr with -r option
        echo "$(date -Ins -u) Starting newlogmgr"
        $BINDIR/newlogmgr -r &
        wait_for_newlogmgr

        PID=$(pgrep newlogmgr)
        echo "monitor-newlogmgr: Restarted newlogmgr with pid $PID"

        # done, only restart once
        exit
    fi
done
