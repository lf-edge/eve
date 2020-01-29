#!/bin/sh

wait_for_rsyslogd()
{
    while [ -z "$(pgrep rsyslogd)" ];
    do
        echo "Waiting for rsyslogd to start"
        sleep 1
    done
}

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

        # restart rsyslogd
        ./start-rsyslogd.sh
        wait_for_rsyslogd

        # It can take some time for /run/rsyslogd.pid to get
        # updated with new pid. Wait till that happens.
        PID=$(pgrep rsyslogd)
        while [ "$RSYSLOG_PID" != "$PID" ];
        do
            echo "Error: rsyslogd PID: $PID is not in sync with /run/rsyslogd.pid: $(RSYSLOG_PID)"
            sleep 1
            PID=$(pgrep rsyslogd)
            RSYSLOG_PID=$(cat /run/rsyslogd.pid)
        done
        echo "Started rsyslogd again with pid $RSYSLOG_PID"
    fi
    echo "rsyslogd running with pid $RSYSLOG_PID"
done
