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

// Maximum length of the property string. It's either the length of the pressure level string or the length of the
// threshold value. For the pressure level, the maximum length is length of "critical" (8), and for the threshold value,
// the maximum length is the length of an unsigned long (20). So, the maximum length is 20.
// Let's use 256 to be on the safe side.
#define MAX_PROP_STRING_LENGTH 256

// Maximum length of the control line. It's the maximum length of the property string plus the length of the event_fd,
// trigger_fd, and the spaces between them. So, the maximum length is 256 + 20 + 20 + 2 = 298.
// Let's use 512 to be on the safe side.
#define MAX_CONTROL_LINE_LENGTH 512

// File location of the trigger file
static const char *trigger_files[] = {
        [PRESSURE_EVENT] = "memory.pressure_level",
        [THRESHOLD_EVENT] = "memory.usage_in_bytes",
};

int event_register(event_desc_t *desc) {
    char path_str[PATH_MAX + 1];
    char control_line_str[MAX_CONTROL_LINE_LENGTH];
    int event_fd, trigger_fd;
    int printed;

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
    printed = snprintf(path_str, sizeof(path_str), "%s/%s/%s", CGROUP_PATH_PREFIX, desc->cgroup_name, trigger_files[desc->type]);
    if (printed < 0 || printed >= sizeof(path_str)) {
        syslog(LOG_ERR, "Failed to construct the path to the trigger file\n");
        close(event_fd);
        return -1;
    }
    trigger_fd = open(path_str, O_WRONLY);
    if (trigger_fd == -1) {
        syslog(LOG_ERR, "opening trigger file: %s", strerror(errno));
        close(event_fd);
        return -1;
    }
    desc->trigger_fd = trigger_fd;

    char prop_string[MAX_PROP_STRING_LENGTH];
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
    printed = snprintf(control_line_str, sizeof(control_line_str), "%d %d %s", event_fd, trigger_fd, prop_string);
    if (printed < 0 || printed >= sizeof(control_line_str)) {
        syslog(LOG_ERR, "Failed to construct the control line\n");
        close(event_fd);
        close(trigger_fd);
        return -1;
    }
    if (write(desc->control_fd, control_line_str, strlen(control_line_str)) == -1) {
        syslog(LOG_ERR, "writing event_control: %s", strerror(errno));
        close(event_fd);
        close(trigger_fd);
        return -1;
    }

    return 0;
}

int event_open_control(const char *cgroup_name) {
    char path_str[PATH_MAX + 1];
    int control_fd;
    int printed;

    // Open event_control file
    printed = snprintf(path_str, sizeof(path_str), "%s/%s/cgroup.event_control", CGROUP_PATH_PREFIX, cgroup_name);
    if (printed < 0 || printed >= sizeof(path_str)) {
        syslog(LOG_ERR, "Failed to construct the path to the event_control file\n");
        return -1;
    }
    control_fd = open(path_str, O_WRONLY);
    if (control_fd == -1) {
        syslog(LOG_ERR, "opening event_control: %s", strerror(errno));
        return -1;
    }

    return control_fd;
}
