#!/bin/sh

start_rsyslogd()
{
    RSYSLOG_WORK_DIR=/persist/rsyslog
    OLD_DIR=/persist/syslog
    # We need to clean up old state it seems. Use $OLD_DIR as the hint
    if [ -d "$OLD_DIR" ]; then
        echo "Moving old $OLD_DIR and $RSYSLOG_WORK_DIR out of the way"
        mv "$OLD_DIR" "$OLD_DIR".old
        mv "$RSYSLOG_WORK_DIR" "$RSYSLOG_WORK_DIR".old
    fi
    if [ ! -d "$RSYSLOG_WORK_DIR" ]; then
        mkdir -p $RSYSLOG_WORK_DIR
        chmod 644 $RSYSLOG_WORK_DIR
    fi

    IMGP=$(cat /run/eve.id 2>/dev/null)
    IMGP=${IMGP:-IMGX} /usr/sbin/rsyslogd -n &
    touch /run/watchdog/pid/rsyslogd.pid
}

wait_for_rsyslogd()
{
    # limit the wait to 30 seconds
    LOOP_COUNT=0
    while [ -z "$(pgrep rsyslogd)" ];
    do
        echo "Waiting for rsyslogd to start"
        LOOP_COUNT=$((LOOP_COUNT + 1))
        if [ "$LOOP_COUNT" -ge 30 ]; then
            break
        fi
        sleep 1
    done
}

# write our own PID to /run/monitor-rsyslogd.pid
echo $$ > /run/monitor-rsyslogd.pid
touch /run/watchdog/pid/monitor-rsyslogd.pid

# start rsyslogd for the fist time after device boot
start_rsyslogd

# wait for rsyslogd to start
wait_for_rsyslogd

RSYSLOG_PID=$(cat /run/rsyslogd.pid)

# wait for /run/rsyslogd.pid to appear
# Do not wait for more than 30 seconds
LOOP_COUNT=0
while [ -z "$RSYSLOG_PID" ] && [ "$LOOP_COUNT" -le 30 ];
do
    sleep 1
    LOOP_COUNT=$((LOOP_COUNT + 1))
    RSYSLOG_PID=$(cat /run/rsyslogd.pid)
done

RSYSLOGD_RESTART_COUNT=0
RSYSLOGD_MAX_RESTART_COUNT=30
while true;
do
    sleep 10
    PID=$(pgrep rsyslogd)
    if [ "$PID" != "$RSYSLOG_PID" ] || [ -z "$RSYSLOG_PID" ]; then
        echo "Error: rsyslogd died, trying to restart rsyslogd"
        # tar the current contents of /persist/rsyslog and clear them
        NAME="rsyslogd-$(date '+%Y-%m-%d-%H-%M-%S').tar.gz"
        tar -cvzf "/persist/rsyslog-backup/$NAME" /persist/rsyslog/*
        rm -rf /persist/rsyslog

        # restart and wait for rsyslogd
        if [ "$RSYSLOGD_RESTART_COUNT" -ge "$RSYSLOGD_MAX_RESTART_COUNT" ]; then
            exit
        fi
        start_rsyslogd
        RSYSLOGD_RESTART_COUNT=$((RSYSLOGD_RESTART_COUNT + 1))
        wait_for_rsyslogd

        # It can take some time for /run/rsyslogd.pid to get
        # updated with new pid. Wait till that happens.
        PID=$(pgrep rsyslogd)
        while [ -n "$PID" ] && [ "$RSYSLOG_PID" != "$PID" ];
        do
            echo "Error: rsyslogd PID: $PID is not in sync with /run/rsyslogd.pid: $RSYSLOG_PID"
            sleep 1
            PID=$(pgrep rsyslogd)
            RSYSLOG_PID=$(cat /run/rsyslogd.pid)
        done
        if [ -n "$PID" ]; then
            RSYSLOGD_RESTART_COUNT=0
            echo "Started rsyslogd again with pid $RSYSLOG_PID"
        fi
    fi
    if [ -z "$PID" ]; then
        echo "rsyslogd NOT running"
    fi
done
