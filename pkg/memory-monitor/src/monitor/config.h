// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

#ifndef MM_CONFIG_H
#define MM_CONFIG_H

#define APP_DIR "/persist/memory-monitor"

#define CONFIG_RW_DIR      APP_DIR
#define CONFIG_DEFAULT_DIR "/etc"
#define CONFIG_FILE        "memory-monitor.conf"

#define HANDLER_SCRIPT      "handler.sh"

#define LOG_DIR             "output"
#define EVENT_LOG_FILE      "events.log"
#define HANDLER_LOG_FILE    "handler.log"
#define EVENT_METADATA_FILE "event_info.txt"

#define ZEDBOX_PID_FILE_PATH "/run/zedbox.pid"

typedef struct {
    // Threshold for the cgroup memory/eve/services/pillar, in bytes
    unsigned long cgroup_pillar_threshold_bytes;
    // Threshold for the cgroups eve, in percent from the memory limit of the cgroup
    // The limit itself is read from memory.limit_in_bytes in runtime
    unsigned int cgroup_eve_threshold_percent;
    // Threshold for the proc zedbox, in bytes
    unsigned long proc_zedbox_threshold_bytes;
} config_t;

// About the difference between pillar and zedbox
// 1. The pillar is a cgroup that contains zedbox AND some other services, like ntpd, sshd, etc.
//    We monitor the memory usage of the pillar cgroup by the cgroups events.
// 2. The zedbox is a process that runs in the pillar cgroup.
//    We monitor the memory usage of the zedbox process by reading the current RSS from /proc/<pid>/status.

void config_read(config_t *config);
void config_validate(config_t *config);

#endif //MM_CONFIG_H
