#!/bin/sh

RSYSLOG_WORK_DIR=/persist/rsyslog
if [ ! -d "$RSYSLOG_WORK_DIR" ]; then
  mkdir -p $RSYSLOG_WORK_DIR
  chmod 644 $RSYSLOG_WORK_DIR
fi
IMGP=IMGA /usr/sbin/rsyslogd
