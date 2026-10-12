// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

#ifndef MM_EVENT_H
#define MM_EVENT_H

#include <stdbool.h>

typedef enum {
    PRESSURE_EVENT,   // a PSI trigger on the cgroup's memory.pressure fired
    THRESHOLD_EVENT,  // the cgroup's memory without page cache reached a threshold (polled)
} trigger_type_t;

typedef struct event_desc {
    char *cgroup_name;
    trigger_type_t type;
    int fd;                  // PRESSURE_EVENT: the armed trigger, -1 when unavailable
    const char *psi_trigger; // PRESSURE_EVENT: "some|full <stall us> <window us>"
    unsigned long threshold; // THRESHOLD_EVENT: bytes
    bool above;              // THRESHOLD_EVENT: the last poll was at or above the threshold
} event_desc_t;

/**
 * Arm the PSI trigger of a PRESSURE_EVENT and set desc->fd.
 * @return 0, or -1 when the kernel or the cgroup has no PSI.
 */
int event_register(event_desc_t *desc);

#endif //MM_EVENT_H
