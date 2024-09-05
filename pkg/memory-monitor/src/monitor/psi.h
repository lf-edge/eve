// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

#ifndef MEMORY_MONITOR_PSI_H
#define MEMORY_MONITOR_PSI_H

#include <stdbool.h>

// psi_is_enabled checks if the PSI is enabled
bool psi_is_enabled();
// psi_monitor_thread is a thread that monitors the PSI values and triggers the handler if the threshold is reached
void* psi_monitor_thread(void *args);

#endif //MEMORY_MONITOR_PSI_H
