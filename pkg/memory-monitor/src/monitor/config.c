// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <stdlib.h>

#include "util.h"

#include "config.h"

#define MAX_LINE_LENGTH 100
#define MAX_VALUE_LENGTH 50


#define DEFAULT_CGROUP_EVE_THRESHOLD_PERCENT 98
// The memory limit for the cgroup pillar is usually 650MB, so let's try to detect when the memory usage is ~2/3 of the limit
#define DEFAULT_CGROUP_PILLAR_THRESHOLD_MB 400
// Usually the zedbox process uses around 100-120MB of memory, so we set the threshold to 130MB
#define DEFAULT_PROC_ZEDBOX_THRESHOLD_MB 130

void config_read(config_t *config) {

    // Try to open the config file in a RW partition, that can be updated by the user
    FILE *config_file = fopen(CONFIG_RW_DIR "/" CONFIG_FILE, "r");
    if (config_file == NULL) {
        // If the file is not found, try to open the default config file
        config_file = fopen(CONFIG_DEFAULT_DIR "/" CONFIG_FILE, "r");
        if (config_file == NULL) {
            syslog(LOG_ERR, "Failed to open config file: %s", strerror(errno));
            return;
        }
    }

    char line[MAX_LINE_LENGTH];
    unsigned long threshold;
    while (fgets(line, sizeof(line), config_file)) {
        char key[MAX_VALUE_LENGTH];
        char value[MAX_VALUE_LENGTH];

        if (sscanf(line, "%[^=]=%s", key, value) != 2) {
            syslog(LOG_WARNING, "Invalid config line: %s", line);
            continue;
        }

        bool error;
        if (strcmp(key, "CGROUP_PILLAR_THRESHOLD_MB") == 0) {
            threshold = strtoudec(value, &error);
            if (error) {
                syslog(LOG_WARNING, "Invalid value for CGROUP_PILLAR_THRESHOLD_MB: %s, using default value", value);
                config->cgroup_pillar_threshold_bytes = DEFAULT_CGROUP_PILLAR_THRESHOLD_MB << 20;
            } else {
                config->cgroup_pillar_threshold_bytes = threshold << 20;
            }
            if (convert_mb_to_bytes(threshold, &config->cgroup_pillar_threshold_bytes) != 0) {
                syslog(LOG_WARNING, "Invalid value for CGROUP_PILLAR_THRESHOLD_MB: %s, using default value", value);
                config->cgroup_pillar_threshold_bytes = DEFAULT_CGROUP_PILLAR_THRESHOLD_MB << 20;
            }
        } else if (strcmp(key, "PROC_ZEDBOX_THRESHOLD_MB") == 0) {
            threshold = strtoul(value, NULL, 10);
            if (convert_mb_to_bytes(threshold, &config->proc_zedbox_threshold_bytes) != 0) {
                syslog(LOG_WARNING, "Invalid value for PROC_ZEDBOX_THRESHOLD_MB: %s, using default value", value);
                config->proc_zedbox_threshold_bytes = DEFAULT_PROC_ZEDBOX_THRESHOLD_MB << 20;
            }
        } else if (strcmp(key, "CGROUP_EVE_THRESHOLD_PERCENT") == 0) {
            threshold = strtoudec(value, &error);
            if (error) {
                syslog(LOG_WARNING, "Invalid value for CGROUP_EVE_THRESHOLD_PERCENT: %s, using default value", value);
                config->cgroup_eve_threshold_percent = DEFAULT_CGROUP_EVE_THRESHOLD_PERCENT;
            } else {
                config->cgroup_eve_threshold_percent = threshold;
            }
        } else {
            syslog(LOG_WARNING, "Unknown config key: %s", key);
        }
    }

    fclose(config_file);
}

void config_validate(config_t *config) {
    // Let the pillar and zedbox thresholds be between 10MB and 8GB
    if (config->cgroup_pillar_threshold_bytes <(10 << 20) || config->cgroup_pillar_threshold_bytes > (8UL << 30)) {
        syslog(LOG_WARNING, "CGROUP_PILLAR_THRESHOLD_MB is out of range (should be between 10MB and 8GB), using default value");
        config->cgroup_pillar_threshold_bytes = DEFAULT_CGROUP_PILLAR_THRESHOLD_MB << 20;
    }

    if (config->proc_zedbox_threshold_bytes <(10 << 20) || config->proc_zedbox_threshold_bytes > (8UL << 30)) {
        syslog(LOG_WARNING, "PROC_ZEDBOX_THRESHOLD_MB is out of range (should be between 10MB and 8GB), using default value");
        config->proc_zedbox_threshold_bytes = DEFAULT_PROC_ZEDBOX_THRESHOLD_MB << 20;
    }

    // The percentage should be between 1 and 100
    if (config->cgroup_eve_threshold_percent < 1 || config->cgroup_eve_threshold_percent > 100) {
        syslog(LOG_WARNING, "CGROUP_EVE_THRESHOLD_PERCENT is out of range, using default value");
        config->cgroup_eve_threshold_percent = DEFAULT_CGROUP_EVE_THRESHOLD_PERCENT;
    }
}
