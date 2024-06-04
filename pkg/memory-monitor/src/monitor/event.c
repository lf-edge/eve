// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

#include <errno.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/eventfd.h>
#include <syslog.h>
#include <unistd.h>

#include "cgroups.h"

#include "event.h"

// String values for the pressure levels
static const char *pressure_levels[] = {
        [PRESSURE_LEVEL_LOW] = "low",
        [PRESSURE_LEVEL_MEDIUM] = "medium",
        [PRESSURE_LEVEL_CRITICAL] = "critical",
};

// File location of the trigger file
static const char *trigger_files[] = {
        [PRESSURE_EVENT] = "memory.pressure_level",
        [THRESHOLD_EVENT] = "memory.usage_in_bytes",
};

int event_register(event_desc_t *desc) {
    char buf[PATH_MAX + 1];
    int event_fd, trigger_fd;

    // Validate cgroup_name
    if (cgroup_validate(desc->cgroup_name) != 0) {
        syslog(LOG_WARNING, "Cannot register event for cgroup: %s", desc->cgroup_name);
        return -1;
    }

    if (desc->control_fd == -1) {
        syslog(LOG_WARNING, "Control file descriptor is not open for cgroup: %s", desc->cgroup_name);
        return -1;
    }

    // Create an event_fd for receiving notifications
    event_fd = eventfd(0, 0);
    if (event_fd == -1) {
        syslog(LOG_ERR, "creating event_fd: %s", strerror(errno));
        return -1;
    }
    desc->event_fd = event_fd;

    // Open the trigger file
    snprintf(buf, sizeof(buf), "%s/%s/%s", CGROUP_PATH_PREFIX, desc->cgroup_name, trigger_files[desc->type]);
    trigger_fd = open(buf, O_WRONLY);
    if (trigger_fd == -1) {
        syslog(LOG_ERR, "opening trigger file: %s", strerror(errno));
        close(event_fd);
        return -1;
    }
    desc->trigger_fd = trigger_fd;

    char prop_string[256];
    switch (desc->type) {
        case PRESSURE_EVENT:
            snprintf(prop_string, sizeof(prop_string), "%s", pressure_levels[desc->pressure_level]);
            break;
        case THRESHOLD_EVENT:
            snprintf(prop_string, sizeof(prop_string), "%lu", desc->threshold);
            break;
        default:
            syslog(LOG_INFO, "Invalid event type\n");
            close(event_fd);
            close(trigger_fd);
            return -1;
    }

    // Write to cgroup.event_control to register the event
    snprintf(buf, sizeof(buf), "%d %d %s", event_fd, trigger_fd, prop_string);
    if (write(desc->control_fd, buf, strlen(buf)) == -1) {
        syslog(LOG_ERR, "writing event_control: %s", strerror(errno));
        close(event_fd);
        close(trigger_fd);
        return -1;
    }

    return 0;
}

int event_open_control(const char *cgroup_name) {
    char buf[256];
    int control_fd;

    // Open event_control file
    snprintf(buf, sizeof(buf), "%s/%s/cgroup.event_control", CGROUP_PATH_PREFIX, cgroup_name);
    control_fd = open(buf, O_WRONLY);
    if (control_fd == -1) {
        syslog(LOG_ERR, "opening event_control: %s", strerror(errno));
        return -1;
    }

    return control_fd;
}
