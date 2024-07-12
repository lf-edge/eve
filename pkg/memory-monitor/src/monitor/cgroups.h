// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

#ifndef MM_CGROUPS_H
#define MM_CGROUPS_H

#define CGROUP_PATH_PREFIX "/sys/fs/cgroup/memory"
#define EVE_CGROUP         "eve"
#define PILLAR_CGROUP      "eve/services/pillar"

#include <stdbool.h>

int cgroup_validate(const char *cgroup_name);
int cgroup_get_memory_limit(const char *cgroup_name, unsigned long *limit);
void cgroup_move_process_to_root_memory(int pid);
void* cgroups_events_monitor_thread(void *args);
bool cgroup_adjust_memory_limit(const char *cgroup_name, int adjust_by_mb);

#endif //MM_CGROUPS_H
