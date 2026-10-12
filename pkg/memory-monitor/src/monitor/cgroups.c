// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "config.h"
#include "event.h"
#include "monitor.h"
#include "util.h"

#include "cgroups.h"

// The longest line in the memory.stat file is the line with a key like "hierarchical_workingset_activate_anon" (37 bytes)
// and the longest value is the dec representation of a 64-bit integer "18446744073709551615" (20 bytes), so the longest
// line is 37 + 1 (for space) + 20 + 1 (for the newline character) = 58 bytes.
// So, 256 is more than a safe value for the line length.
// That's true for Linux kernel 6.1, and will be true for the future versions, as the kernel developers are unlikely to
// change the format of the memory.stat file.
#define MAX_MEMORY_STAT_LINE_LENGTH 256

// The maximum length of the memory.current / memory.max file is the length of a 65-bit integer,
// which is 20 bytes, plus the newline character, so 21 bytes is a safe value for the string length.
// To be extra safe, we set the value to 256.
#define MAX_MEMORY_STRING_LENGTH 256

// Reads a cgroup file holding one number, such as memory.current or
// memory.max; "max" reads as ULONG_MAX. Returns 0 on success, -1 on error.
int cgroup_read_value(const char *cgroup_name, const char *file, unsigned long *value) {
    char path[PATH_MAX + 1];
    char str[MAX_MEMORY_STRING_LENGTH];
    int printed;

    printed = snprintf(path, sizeof(path), "%s/%s/%s", CGROUP_PATH_PREFIX, cgroup_name, file);
    if (printed < 0 || printed >= sizeof(path)) {
        syslog(LOG_ERR, "Path to %s of %s is too long\n", file, cgroup_name);
        return -1;
    }
    int fd = open(path, O_RDONLY);
    if (fd == -1) {
        syslog(LOG_ERR, "opening %s: %s", path, strerror(errno));
        return -1;
    }
    ssize_t nread = read(fd, str, sizeof(str) - 1);
    if (nread <= 0) {
        syslog(LOG_ERR, "reading %s: %s", path, nread == 0 ? "no data" : strerror(errno));
        close(fd);
        return -1;
    }
    close(fd);

    str[nread] = '\0';
    if (strncmp(str, "max", 3) == 0) {
        *value = ULONG_MAX;
        return 0;
    }
    bool error;
    *value = strtoudec(str, &error);
    return error ? -1 : 0;
}

// Returns the value of key in the cgroup's memory.stat, 0 when absent.
unsigned long cgroup_get_memory_stat(const char *cgroup_name, const char *key) {
    char path_str[PATH_MAX + 1];
    char line[MAX_MEMORY_STAT_LINE_LENGTH];
    unsigned long value = 0;
    size_t key_len = strlen(key);
    int printed;

    printed = snprintf(path_str, sizeof(path_str), "%s/%s/memory.stat", CGROUP_PATH_PREFIX, cgroup_name);
    if (printed < 0 || printed >= sizeof(path_str)) {
        syslog(LOG_ERR, "Path to the memory.stat file is too long\n");
        return 0;
    }
    FILE *file = fopen(path_str, "r");
    if (file == NULL) {
        syslog(LOG_ERR, "opening memory.stat: %s", strerror(errno));
        return 0;
    }
    while (fgets(line, sizeof(line), file) != NULL) {
        // Match the whole key: "file" must not match "file_mapped".
        if (strncmp(line, key, key_len) == 0 && line[key_len] == ' ') {
            bool error;
            value = strtoudec(line + key_len + 1, &error);
            if (error) {
                syslog(LOG_ERR, "strtoudec: %s", strerror(errno));
                value = 0;
            }
            break;
        }
    }
    fclose(file);
    return value;
}

int cgroup_validate(const char *cgroup_name) {
    char path_str[PATH_MAX + 1];
    int fd;
    int printed;

    // Check if the cgroup exists
    printed = snprintf(path_str, sizeof(path_str), "%s/%s", CGROUP_PATH_PREFIX, cgroup_name);
    if (printed < 0 || printed >= sizeof(path_str)) {
        syslog(LOG_ERR, "Path to the cgroup is too long\n");
        return 1;
    }
    fd = open(path_str, O_RDONLY);
    if (fd == -1) {
        syslog(LOG_ERR, "open cgroup: %s", strerror(errno));
        return 1;
    }
    close(fd);

    return 0;
}

void cgroup_move_process_to_root(int pid) {
    FILE* procs_file = fopen("/sys/fs/cgroup/cgroup.procs", "w");
    if (procs_file == NULL) {
        syslog(LOG_ERR, "Failed to open cgroup.procs file: %s", strerror(errno));
        return;
    }

    if (fprintf(procs_file, "%d\n", pid) < 0) {
        syslog(LOG_ERR, "Failed to write PID to cgroup.procs file: %s", strerror(errno));
    }

    fclose(procs_file);
}

void* cgroups_events_monitor_thread(void *args) {
    event_desc_t *events = ((monitor_cgroups_events_args_t *) args)->events;
    size_t events_count = ((monitor_cgroups_events_args_t *) args)->events_count;

    // We got all the necessary data from the args, so we can free it
    free(args);

    // PSI triggers wake poll(); threshold events are checked on every wake and
    // at least every CHECK_INTERVAL_SEC. poll() ignores negative fds.
    struct pollfd fds[events_count];
    for (size_t i = 0; i < events_count; i++) {
        fds[i].fd = events[i].type == PRESSURE_EVENT ? events[i].fd : -1;
        fds[i].events = POLLPRI;
    }

    while (true) {
        if (poll(fds, events_count, CHECK_INTERVAL_SEC * 1000) < 0) {
            if (errno == EINTR)
                continue;
            syslog(LOG_ERR, "poll: %s", strerror(errno));
            break;
        }
        bool handling_necessary = false;
        char event_msg[MAX_EVENT_MSG_LENGTH];

        for (size_t i = 0; i < events_count; i++) {
            event_desc_t *event = &events[i];
            if (event->type == PRESSURE_EVENT) {
                if (fds[i].revents & POLLERR) {
                    syslog(LOG_ERR, "%s: PSI trigger gone, no more pressure events\n", event->cgroup_name);
                    fds[i].fd = -1;
                } else if (fds[i].revents & POLLPRI) {
                    syslog(LOG_INFO, "----- %s pressure event -----\n", event->cgroup_name);
                    snprintf(event_msg, sizeof(event_msg), "Pressure event for cgroup %s (%s)\n",
                             event->cgroup_name, event->psi_trigger);
                    handling_necessary = true;
                }
                continue;
            }
            // The page cache counts in memory.current but is easily reclaimed,
            // so it does not count towards the threshold.
            unsigned long usage;
            if (cgroup_read_value(event->cgroup_name, "memory.current", &usage) != 0)
                continue;
            unsigned long cache = cgroup_get_memory_stat(event->cgroup_name, "file");
            unsigned long used = usage > cache ? usage - cache : 0;
            if (threshold_crossed(&event->above, used, event->threshold)) {
                syslog(LOG_INFO, "----- %s threshold is reached -----\n", event->cgroup_name);
                snprintf(event_msg, sizeof(event_msg), "Threshold is reached for cgroup %s: %lu bytes (threshold: %lu bytes)\n",
                         event->cgroup_name, used, event->threshold);
                handling_necessary = true;
            }
        }

        if (handling_necessary && run_handler(HANDLER_SCRIPT, event_msg) != 0) {
            syslog(LOG_WARNING, "Failed to run the handler script\n");
        }
    }

    // We should never reach this point
    syslog(LOG_ERR, "Exiting the cgroups events monitor thread\n");
    return NULL;
}

bool cgroup_adjust_memory_limit(const char *cgroup_name, int adjust_by_mb)
{
    int printed;
    // Convert the limit in MB to bytes
    long adjust_by_bytes;
    if (convert_mb_to_bytes_signed(adjust_by_mb, &adjust_by_bytes) != 0) {
        syslog(LOG_WARNING, "Invalid memory limit value: %d MB\n", adjust_by_mb);
        return false;
    }

    // Read the current memory limit
    unsigned long current_limit;
    if (cgroup_read_value(cgroup_name, "memory.max", &current_limit) != 0) {
        syslog(LOG_WARNING, "Failed to read the current memory limit\n");
        return false;
    }

    // Check that the current limit is fit into the signed long, so we can use it in the arithmetic operations
    if (current_limit > LONG_MAX) {
        syslog(LOG_WARNING, "Invalid memory limit value: %lu\n", current_limit);
        return false;
    }

    // Adjust the memory limit by the value of the adjust_by_mb
    // Check if the new limit is within the range of the unsigned long and not less than 0
    long new_limit;
    if (__builtin_saddl_overflow((long)current_limit, adjust_by_bytes, &new_limit)) {
        syslog(LOG_WARNING, "Invalid memory limit value: %lu\n", current_limit);
        return false;
    }

    // cgroup v2 takes a memory.max below the usage, then reclaims and OOM-kills
    // inside the cgroup until the usage fits; v1 refused such a write (EBUSY).
    if (adjust_by_bytes < 0) {
        unsigned long usage;
        if (cgroup_read_value(cgroup_name, "memory.current", &usage) != 0) {
            syslog(LOG_WARNING, "Failed to read the memory usage of %s, keeping its memory limit\n", cgroup_name);
            return false;
        }
        if (!memory_limit_can_lower(usage, new_limit)) {
            syslog(LOG_WARNING, "%s uses %lu bytes, above its original limit of %ld bytes, keeping the raised limit\n",
                   cgroup_name, usage, new_limit);
            return false;
        }
    }

    // Write the new memory limit
    char limit_file[PATH_MAX + 1];
    int fd;
    ssize_t nwritten;

    // Open memory.max file
    printed = snprintf(limit_file, sizeof(limit_file), "%s/%s/memory.max", CGROUP_PATH_PREFIX, cgroup_name);
    if (printed < 0 || printed >= sizeof(limit_file)) {
        syslog(LOG_ERR, "Path to the memory.max file is too long\n");
        return false;
    }
    fd = open(limit_file, O_WRONLY);
    if (fd == -1) {
        syslog(LOG_ERR, "opening memory.max: %s", strerror(errno));
        return false;
    }

    char str_limit[MAX_MEMORY_STRING_LENGTH];
    snprintf(str_limit, sizeof(str_limit), "%lu", current_limit + adjust_by_bytes);

    // Write the new limit
    nwritten = write(fd, str_limit, strlen(str_limit));
    if (nwritten == -1) {
        syslog(LOG_ERR, "writing memory.max: %s", strerror(errno));
        close(fd);
        return false;
    }

    close(fd);
    return true;
}
