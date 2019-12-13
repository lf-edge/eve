#!/bin/sh

RSYSLOG_LOG_DIR=/persist/syslog/
RSYSLOG_WORK_DIR=/persist/rsyslog
if [ ! -d "$RSYSLOG_WORK_DIR" ]; then
  mkdir -p $RSYSLOG_WORK_DIR
  chmod 644 $RSYSLOG_WORK_DIR
fi
if [ ! -d "$RSYSLOG_LOG_DIR" ]; then
  mkdir -p $RSYSLOG_LOG_DIR
  chmod 644 $RSYSLOG_LOG_DIR
fi
IMGP=IMGA /usr/sbin/rsyslogd
