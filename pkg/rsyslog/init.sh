#!/bin/sh

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
# XXX IMGB?
IMGP=IMGA /usr/sbin/rsyslogd
