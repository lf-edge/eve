// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "monitor.h"
#include "util.h"

#include "psi.h"

// Maximum line in /proc/pressure/memory: "some avg10=100.00 avg60=100.00 avg300=100.00 total=<maxint>"
// it's around 120 characters, so 256 should be enough
#define MAX_PSI_LINE_LENGTH 256

typedef struct {
    float some10_value;
    float some60_value;
    float some300_value;
    unsigned long some_total;
    float full10_value;
    float full60_value;
    float full300_value;
    unsigned long full_total;
} current_psi_values_t;


// Check if the PSI is enabled by attempting to access the required files and checking their format
bool psi_is_enabled() {
    // Check if the PSI is enabled by attempting to open the /proc/pressure directory
    if (access("/proc/pressure", F_OK) != 0) {
        syslog(LOG_ERR, "/proc/pressure does not exist\n");
        return false;
    }
    // Check if the memory pressure file exists
    FILE *fp = fopen("/proc/pressure/memory", "r");
    if (fp == NULL) {
        syslog(LOG_ERR, "/proc/pressure/memory does not exist\n");
        return false;
    }

    // Check if the memory pressure file contains the data of expected format:
    // some avg10=0.00 avg60=0.00 avg300=0.00 total=0
    // full avg10=0.00 avg60=0.00 avg300=0.00 total=0
    char line[MAX_PSI_LINE_LENGTH];
    if (fgets(line, sizeof(line), fp) == NULL) {
        syslog(LOG_ERR, "Failed to read the first line from /proc/pressure/memory\n");
        fclose(fp);
        return false;
    }
    // Check if the line contains the expected values
    float value10, value60, value300;
    unsigned long total;
    if (sscanf(line, "some avg10=%f avg60=%f avg300=%f total=%lu", &value10, &value60, &value300, &total) != 4) {
        syslog(LOG_ERR, "Invalid format of the first line in /proc/pressure/memory\n");
        fclose(fp);
        return false;
    }

    // Read the next line
    if (fgets(line, sizeof(line), fp) == NULL) {
        syslog(LOG_ERR, "Failed to read the second line from /proc/pressure/memory\n");
        fclose(fp);
        return false;
    }
    // Check if the line contains the expected values
    if (sscanf(line, "full avg10=%f avg60=%f avg300=%f total=%lu", &value10, &value60, &value300, &total) != 4) {
        syslog(LOG_ERR, "Invalid format of the second line in /proc/pressure/memory\n");
        fclose(fp);
        return false;
    }

    fclose(fp);
    return true;
}

static void read_psi_values(current_psi_values_t *psi_values) {
    // Read the PSI metrics for memory pressure
    // The values are read from /proc/pressure/memory
    // The format is:
    // some avg10=0.00 avg60=0.00 avg300=0.00 total=0
    // full avg10=0.00 avg60=0.00 avg300=0.00 total=0
    FILE *fp = fopen("/proc/pressure/memory", "r");
    if (fp == NULL) {
        return;
    }

    char line[MAX_PSI_LINE_LENGTH];
    while (fgets(line, sizeof(line), fp) != NULL) {
        if (strncmp(line, "some", strlen("some")) == 0) {
            // It's ok to use sscanf here, as we know the format of the line, and we are not parsing user input
            sscanf(line, "some avg10=%f avg60=%f avg300=%f total=%lu",
                   &psi_values->some10_value, &psi_values->some60_value, &psi_values->some300_value, &psi_values->some_total);
        } else if (strncmp(line, "full", strlen("full")) == 0) {
            sscanf(line, "full avg10=%f avg60=%f avg300=%f total=%lu",
                   &psi_values->full10_value, &psi_values->full60_value, &psi_values->full300_value, &psi_values->full_total);
        }
    }
    fclose(fp);
}

static int psi_check_threshold(float threshold) {
    static atomic_bool handler_executed = ATOMIC_VAR_INIT(false);
    current_psi_values_t psi_values;
    read_psi_values(&psi_values);
    // Check if full_avg10 exceeds the threshold to detect potential upcoming OOM.
    // We're focusing on full_avg10 because it indicates severe memory pressure where all processes are stalled.
    // This makes it a strong predictor of system-wide OOM events, especially in "fast" OOM situations.
    // Although som_avg10 is more sensitive and can spike without leading to an inevitable OOM,
    // it's still useful for predicting fast OOMs and detecting memory pressure before the system fully stalls.
    // We avoid relying too much on avg60 and avg300 because they can be too slow to react to rapid changes.
    if (psi_values.full10_value > threshold) {
        atomic_bool expected = ATOMIC_VAR_INIT(false);
        if (!atomic_compare_exchange_strong(&handler_executed, &expected, true)) {
            return 0;
        }
        syslog(LOG_INFO, "------ Memory Pressure Event ------\n");
        char event_msg[MAX_EVENT_MSG_LENGTH];
        snprintf(event_msg, sizeof(event_msg), "Memory pressure is high: all avg10=%.2f\n", psi_values.full10_value);
        int status = run_handler(HANDLER_SCRIPT, event_msg);
        if (status != 0) {
            syslog(LOG_WARNING, "Failed to run the handler script\n");
        }
        return 1;
    } else {
        atomic_store(&handler_executed, false);
    }
    return 0;
}

// Monitor the PSI and trigger the handler if the threshold is reached
void* psi_monitor_thread(void *args) {
    if (args == NULL) {
        syslog(LOG_ERR, "Invalid arguments for the PSI monitor thread\n");
        return NULL;
    }
    monitor_psi_args_t *psi_args = (monitor_psi_args_t *)args;
    float threshold = (float)psi_args->threshold;
    free(psi_args);
    while (!psi_check_threshold(threshold)) {
        sleep(CHECK_INTERVAL_SEC);
    }
    syslog(LOG_ERR, "Exiting the PSI monitor thread\n");
    return NULL;
}
