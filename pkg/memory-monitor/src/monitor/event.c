// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

#include <errno.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "cgroups.h"

#include "event.h"

int event_register(event_desc_t *desc) {
    char path_str[PATH_MAX + 1];
    int printed;

    desc->fd = -1;
    if (desc->type != PRESSURE_EVENT)
        return 0;
    if (cgroup_validate(desc->cgroup_name) != 0) {
        syslog(LOG_WARNING, "Cannot register event for cgroup: %s", desc->cgroup_name);
        return -1;
    }
    printed = snprintf(path_str, sizeof(path_str), "%s/%s/memory.pressure", CGROUP_PATH_PREFIX, desc->cgroup_name);
    if (printed < 0 || printed >= sizeof(path_str)) {
        syslog(LOG_ERR, "Path to the memory.pressure file is too long\n");
        return -1;
    }
    int fd = open(path_str, O_RDWR | O_NONBLOCK);
    if (fd == -1) {
        syslog(LOG_WARNING, "opening %s: %s (kernel without PSI?)", path_str, strerror(errno));
        return -1;
    }
    // The kernel's PSI documentation writes the trigger with its NUL.
    if (write(fd, desc->psi_trigger, strlen(desc->psi_trigger) + 1) < 0) {
        syslog(LOG_WARNING, "arming \"%s\" on %s: %s", desc->psi_trigger, path_str, strerror(errno));
        close(fd);
        return -1;
    }
    desc->fd = fd;
    return 0;
}
