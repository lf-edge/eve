// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

#ifndef MM_MONITOR_H
#define MM_MONITOR_H

#include <stddef.h>
#include <pthread.h>

#include "event.h"
#include "config.h"

typedef struct {
    int pid;
    unsigned long threshold;
} monitor_procfs_args_t;

typedef struct {
    // A pointer to the array of event descriptors
    event_desc_t *events;
    // The number of event descriptors in the array
    size_t events_count;
} monitor_cgroups_events_args_t;

typedef struct threads_to_finish {
    pthread_t *threads;
    size_t count;
} threads_to_finish_t;

typedef struct fds_to_close {
    int *fds;
    size_t count;
} fds_to_close_t;

typedef struct resources_to_cleanup {
    threads_to_finish_t threads_to_finish;
    fds_to_close_t fds_to_close;
} resources_to_cleanup_t;

// Monitor the memory usage of the zedbox process and trigger the handler if the limit is reached
int monitor_start(config_t *config, resources_to_cleanup_t *resources_to_cleanup);
int run_handler(const char *script_name, const char* event_msg);

#endif //MM_MONITOR_H
