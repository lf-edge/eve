// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

#ifndef MM_EVENT_H
#define MM_EVENT_H

typedef enum {
    PRESSURE_EVENT,
    THRESHOLD_EVENT,
} trigger_type_t;

typedef enum {
    // Make the enum unsigned long to align with the threshold value size, as they are used in the same union
    PRESSURE_LEVEL_LOW = 0UL,
    PRESSURE_LEVEL_MEDIUM,
    PRESSURE_LEVEL_CRITICAL,
} pressure_level_t;

typedef struct event_desc {
    char *cgroup_name;
    int event_fd;
    int trigger_fd;
    int control_fd;
    trigger_type_t type;
    union {
        pressure_level_t pressure_level;
        unsigned long threshold;
    };
} event_desc_t;

/**
 * Register an event descriptor.
 * @param desc
 * @return
 */
int event_register(event_desc_t *desc);

/**
 * Open the control file for a given cgroup.
 *
 * This function opens the control file for the cgroup specified by `cgroup_name`.
 * The control file is used to control the behavior of the cgroup.
 *
 * @param cgroup_name The name of the cgroup for which to open the control file.
 *
 * @return A file descriptor for the cgroup's control file on success, or a
 * negative error code on failure.
 */
int event_open_control(const char *cgroup_name);

#endif //MM_EVENT_H
