# EVE LOGGING PIPELINE

This document describes the different stages logs on a EVE edge node go through before being delivered to cloud. It also describes the various congestion points in the current log pipeline along with the places where logs could leak (dropped on the floor) with the current state of EVE code.

## Log Pipeline

The current log pipeline can be vertically split into the following three stages.

1. Log generation
2. Log aggregation and persistence
3. Log export to cloud

![EVE Logging Pipeline](pics/eve_logging_pipeline.png)

## Log Generation

All containers will now log directly to stdout, which are then picked up by containerd. Containerd then forwards the logs received to memlogd service that maintains a circular buffer of fixed size for storing log messages. Memlogd provides a way (via unix domain sockets) to read the logs present in it’s buffer and also stream the incoming logs. EVE currently uses imemlogd plugin for rsyslogd (developed internally) to stream logs from memlogd service.

If there are too many logs coming from various containers and the log reader is not able to keep up, oldest logs from the current circular buffer will be overwritten. All logs read by memlgod by rsyslogd will be written to disk queues. When there is heavy disk usage and rsyslogd does not get sufficient time to write incoming logs to disk, it can result in log loss from memlogd.

The following diagram shows the flow of logs from containers to rsyslog and to cloud.

![EVE Log Flow](pics/eve_log_flow.png)

## Log Aggregation

All logs collected from various containers/service in the system will reach rsyslogd demon. Rsyslogd queues the incoming logs on disk. Rsyslogd is configured to use disk queues in order to minimize log loss during power/network failures.

Useful information about the current state of logs/queues can be seen in the following directories:
1. /persist/rsyslog/ - This directory has the current log queue files. It also has syslog.txt to which rsyslog writes the last 10MB worth of logs forwarded to logmanager.
2. /persist/rsyslog-backup - In the event of rsyslogd crash, monitor-rsyslog.sh script moves the current queue files into this directory and re-starts rsyslogd with clean state.

When a direct ssh connection to a device is possible, /persist/rsyslog/syslog.txt file can be looked into for recent logs. Rsyslogd is configured to queue upto 1 million logs or 2GB worth of logs (which ever condition hits first). Beyond this any incoming logs will be tail dropped.

## Log export to cloud

Rsyslogd is configured to send logs via TCP socket to logmanager. Logmanager bundles the logs into protobuf messages and exports them to cloud using API. Today when a device loses network connectivity to cloud, there is a back-off mechanism built into the logmanager that prompts rsyslogd to stop sending logs. When there is network drop, logmanager stops reading log messages from rsyslogd (TCP socket). Rsyslogd stops sending logs when it's output socket buffer is full. As a result following logs will be queued on disk. After the device's network connectivity is restored, rsyslogd starts sending logs from it's disk queues.
