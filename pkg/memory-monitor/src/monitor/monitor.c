// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

#include <errno.h>
#include <linux/limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/stat.h>
#include <unistd.h>

#include "cgroups.h"
#include "config.h"
#include "event.h"
#include "procfs.h"
#include "psi.h"
#include "util.h"

#include "monitor.h"

#define ADJUST_MEMORY_LIMIT 50


// Usually, the maximum length of a PID is 32768 characters, but even if it's a 64-bit value, it's unlikely to be more
// than 20 characters. So, let's use 32 characters as the maximum length.
#define MAX_PID_LENGTH 32

// There are extra 3 threads that are used to monitor the system:
// * procfs monitor thread: to check stats of the zedbox process
// * cgroups eventfd polling thread: to check the memory usage of the eve and pillar cgroups
// * PSI (Pressure Stall Information) monitoring thread: to check the memory pressure of the entire system
#define MONITORING_THREADS_COUNT 3


extern int handler_log_fd_g;
extern char binary_location_g[PATH_MAX + 1];

// The mutex is used to prevent the handler script from being executed multiple times
// There are two ways to trigger the handler script: with the regular cgroup event and with the memory usage check
// The memory usage check is done every 5 seconds in a separate thread, so the handler script can be executed 2 times:
// from the main thread and from the memory usage check thread.
pthread_mutex_t handler_mutex = PTHREAD_MUTEX_INITIALIZER;

int run_handler(const char *script_name, const char *event_msg) {
    pthread_mutex_lock(&handler_mutex);
    char script_path[PATH_MAX +1];
    int printed;

    // Get the timestamp, so it's the same for the event log and the output directory name
    time_t t = time(NULL);

    // Log the event
    log_event(&t, event_msg);

    // Execute the script
    syslog(LOG_INFO, "Running handler script\n");

    // Create a name of the new output directory output/YYYY-MM-DD-HH-mm-SS
    char output_dir[PATH_MAX + 1];
    struct tm tm = *localtime(&t);
    printed = snprintf(output_dir, sizeof(output_dir), "%s/%04d-%02d-%02d-%02d-%02d-%02d",
             LOG_DIR,
             tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
             tm.tm_hour, tm.tm_min, tm.tm_sec);
    if (printed < 0 || printed >= sizeof(output_dir)) {
        syslog(LOG_ERR, "Failed to create the output directory name\n");
        pthread_mutex_unlock(&handler_mutex);
        return 1;
    }

    // Create the output directory
    if (mkdir(output_dir, 0755) == -1) {
        syslog(LOG_ERR, "mkdir: %s", strerror(errno));
        pthread_mutex_unlock(&handler_mutex);
        return 1;
    }

    // Put a metadata file with the event message to the output directory
    char metadata_file[PATH_MAX + 1];

    printed = snprintf(metadata_file, sizeof(metadata_file), "%s/%s", output_dir, EVENT_METADATA_FILE);
    if (printed < 0 || printed >= sizeof(metadata_file)) {
        syslog(LOG_ERR, "Failed to create the metadata file path\n");
        pthread_mutex_unlock(&handler_mutex);
        return 1;
    }
    FILE *metadata_fp = fopen(metadata_file, "w");
    if (metadata_fp == NULL) {
        syslog(LOG_ERR, "fopen: %s", strerror(errno));
        pthread_mutex_unlock(&handler_mutex);
        return 1;
    }
    char eve_version[MAX_EVE_VERSION_LENGTH];
    if (get_eve_release(eve_version) == 0) {
        fprintf(metadata_fp, "EVE version: %s\n", eve_version);
    }
    fprintf(metadata_fp, "%s", event_msg);
    fclose(metadata_fp);

    // Construct the path to the script
    printed = snprintf(script_path, sizeof(script_path), "%s/%s", binary_location_g, script_name);
    if (printed < 0 || printed >= sizeof(script_path)) {
        syslog(LOG_ERR, "Failed to create the script path\n");
        pthread_mutex_unlock(&handler_mutex);
        return 1;
    }

    // Create the cmd to run the script: script_path output_dir
    char cmd[PATH_MAX + 1];
    printed = snprintf(cmd, sizeof(cmd), "%s %s", script_path, output_dir);
    if (printed < 0 || printed >= sizeof(cmd)) {
        syslog(LOG_ERR, "Failed to create the command\n");
        pthread_mutex_unlock(&handler_mutex);
        return 1;
    }

    // Check the handler log fd
    if (handler_log_fd_g == -1) {
        syslog(LOG_ERR, "Invalid handler log fd\n");
        pthread_mutex_unlock(&handler_mutex);
        return 1;
    }

    // Clean the handler log file before running the script, so we can see only the last event
    if (ftruncate(handler_log_fd_g, 0) == -1) {
        syslog(LOG_ERR, "ftruncate: %s", strerror(errno));
        pthread_mutex_unlock(&handler_mutex);
        return 1;
    }

    // Increase the mem limit of the Pillar cgroup, as the handler will call golang heap dump that requires more memory
    bool mem_limit_adjusted = cgroup_adjust_memory_limit(PILLAR_CGROUP, ADJUST_MEMORY_LIMIT);
    if (!mem_limit_adjusted) {
        syslog(LOG_WARNING, "Failed to temporarily adjust the memory limit of the Pillar cgroup\n");
    }

    // Execute the script
    int status = system(cmd);

    // If the memory limit was adjusted, decrease it back
    if (mem_limit_adjusted) {
        if (!cgroup_adjust_memory_limit(PILLAR_CGROUP, -ADJUST_MEMORY_LIMIT)) {
            syslog(LOG_WARNING, "Failed to restore the memory limit of the Pillar cgroup\n");
        }
    }

    // Check the exit conditions of the script
    if (status == -1) {
        syslog(LOG_ERR, "system: %s", strerror(errno));
        pthread_mutex_unlock(&handler_mutex);
        return 1;
    }
    if (WIFEXITED(status)) {
        syslog(LOG_INFO, "Handler script exited with status %d\n", WEXITSTATUS(status));
        // If the status is 0, clean the handler log file, as we don't need to debug the script
        if (WEXITSTATUS(status) == 0) {
            if (ftruncate(handler_log_fd_g, 0) == -1) {
                syslog(LOG_ERR, "ftruncate: %s", strerror(errno));
                pthread_mutex_unlock(&handler_mutex);
                return 1;
            }
        } else {
            // If the status is not 0, print several lines from the end of the log file
            char *tail = get_tail(LOG_DIR "/" HANDLER_LOG_FILE, 10);
            if (tail != NULL) {
                syslog(LOG_ERR, "Handler script output (last 10 lines):\n%s\n", tail);
                free(tail);
            } else {
                syslog(LOG_ERR, "Failed to read the handler log file\n");
            }
        }
    } else {
        syslog(LOG_INFO, "Handler script exited abnormally by signal %d\n", WTERMSIG(status));
    }
    pthread_mutex_unlock(&handler_mutex);
    return 0;
}

static pthread_t run_procfs_monitor(config_t *config) {
    unsigned long threshold = config->proc_zedbox_threshold_bytes;
    // Create a thread to watch the memory limit of the zedbox process every 10 seconds
    // and trigger the handler if the limit is reached

    // Wait for the zedbox process to start and write its PID to /run/zedbox.pid
    while (access(ZEDBOX_PID_FILE_PATH, F_OK) == -1) {
        sleep(1);
    }

    // Get the PID of the zedbox process, read it from /run/zedbox.pid
    FILE *pid_file;
    int pid;
    pid_file = fopen(ZEDBOX_PID_FILE_PATH, "r");
    if (pid_file == NULL) {
        syslog(LOG_ERR, "opening zedbox.pid: %s", strerror(errno));
        // Let's consider 0 as an invalid thread id
        return 0;
    }
    char pid_str[MAX_PID_LENGTH];
    if (fgets(pid_str, sizeof(pid_str), pid_file) == NULL) {
        syslog(LOG_ERR, "reading zedbox.pid: %s", strerror(errno));
        fclose(pid_file);
        return 0;
    }
    fclose(pid_file);

    bool error;
    pid = (int) strtodec(pid_str, &error);
    if (error) {
        syslog(LOG_ERR, "Invalid PID in zedbox.pid: %s", pid_str);
        return 0;
    }

    // Create a thread to watch the memory limit of the zedbox process every 10 seconds
    // and trigger the handler if the limit is reached
    pthread_t thread;
    monitor_procfs_args_t *args = malloc(sizeof(monitor_procfs_args_t));
    args->pid = pid;
    args->threshold = threshold;
    int result = pthread_create(&thread, NULL, (void *(*)(void *)) procfs_monitor_thread, args);
    if (result != 0) {
        free(args);
        syslog(LOG_WARNING, "pthread_create: %s", strerror(result));
        return 0;
    }

    return thread;
}

static pthread_t run_cgroups_events_monitor(config_t *config, fds_to_close_t *fds_to_close) {
    // Read the eve cgroup limit and set the threshold to 95% of it
    unsigned long eve_limit_bytes, eve_threshold_bytes;

    int result = cgroup_get_memory_limit(EVE_CGROUP, &eve_limit_bytes);
    if (result == -1) {
        syslog(LOG_INFO, "Failed to read the eve cgroup limit\n");
        // Let's consider 0 as an invalid thread id
        return 0;
    }
    // Set the threshold to 95% of the limit
    eve_threshold_bytes = eve_limit_bytes / 100 * config->cgroup_eve_threshold_percent;

    // Open the event control file for the eve cgroup
    int eve_control_fd = event_open_control(EVE_CGROUP);
    if (eve_control_fd == -1) {
        syslog(LOG_WARNING, "Failed to open the event control file for the eve cgroup\n");
    }

    event_desc_t eve_threshold_desc = {
            .cgroup_name = EVE_CGROUP,
            .control_fd = eve_control_fd,
            .type = THRESHOLD_EVENT,
            .threshold = eve_threshold_bytes,
            .event_fd = -1, // will be set by the event_register function
            .trigger_fd = -1, // will be set by the event_register function
    };
    result = event_register(&eve_threshold_desc);
    if (result == -1) {
        syslog(LOG_WARNING, "Failed to register event for the eve cgroup\n");
    }

    event_desc_t eve_pressure_desc = {
            .cgroup_name = EVE_CGROUP,
            .control_fd = eve_control_fd,
            .type = PRESSURE_EVENT,
            // Use "critical" pressure level for the eve cgroup, as "low" and "medium" are triggered too often,
            // for example, when the system reclaim the memory used by the cache
            .pressure_level = PRESSURE_LEVEL_CRITICAL,
            .event_fd = -1, // will be set by the event_register function
            .trigger_fd = -1, // will be set by the event_register function
    };
    result = event_register(&eve_pressure_desc);
    if (result == -1) {
        syslog(LOG_WARNING, "Failed to register pressure event for the eve cgroup\n");
    }

    // Open the event control file for the Pillar cgroup
    int pillar_control_fd = event_open_control(PILLAR_CGROUP);
    if (pillar_control_fd == -1) {
        syslog(LOG_WARNING, "Failed to open the event control file for the pillar cgroup\n");
    }
    event_desc_t pillar_threshold_desc = {
            .cgroup_name = PILLAR_CGROUP,
            .control_fd = pillar_control_fd,
            .type = THRESHOLD_EVENT,
            .threshold = config->cgroup_pillar_threshold_bytes,
            .event_fd = -1, // will be set by the event_register function
            .trigger_fd = -1, // will be set by the event_register function
    };
    result = event_register(&pillar_threshold_desc);
    if (result == -1) {
        syslog(LOG_WARNING, "Failed to register event for the pillar cgroup\n");
    }

    event_desc_t pillar_pressure_desc = (event_desc_t) {
            .cgroup_name = PILLAR_CGROUP,
            .control_fd = pillar_control_fd,
            .type = PRESSURE_EVENT,
            .pressure_level = PRESSURE_LEVEL_LOW,
            .event_fd = -1, // will be set by the event_register function
            .trigger_fd = -1, // will be set by the event_register function
    };
    result = event_register(&pillar_pressure_desc);
    if (result == -1) {
        syslog(LOG_WARNING, "Failed to register pressure event for the pillar cgroup\n");
    }

    syslog(LOG_INFO, "Waiting for cgroups events\n");

    #define EVENTS_COUNT 4

    event_desc_t *events_descs = malloc(sizeof(event_desc_t) * EVENTS_COUNT);
    events_descs[0] = eve_threshold_desc;
    events_descs[1] = eve_pressure_desc;
    events_descs[2] = pillar_threshold_desc;
    events_descs[3] = pillar_pressure_desc;

    pthread_t thread;
    monitor_cgroups_events_args_t *args = malloc(sizeof(monitor_cgroups_events_args_t));
    args->events = (event_desc_t*)events_descs;
    args->events_count = EVENTS_COUNT;
    if (pthread_create(&thread, NULL, cgroups_events_monitor_thread, args) != 0) {
        free(args);
        syslog(LOG_WARNING, "Failed to create a thread for the cgroups events monitor\n");
        return 0;
    }

    // Add the fds to the list to return them to the caller, so they can be closed later
    // For each event, we have 3 fds: event_fd, trigger_fd, and control_fd
    fds_to_close->count = EVENTS_COUNT * 3;
    fds_to_close->fds = malloc(sizeof(int) * fds_to_close->count);
    for (int i = 0; i < EVENTS_COUNT; i++) {
        event_desc_t *event_p = &events_descs[i];
        fds_to_close->fds[i * 3] = event_p->event_fd;
        fds_to_close->fds[i * 3 + 1] = event_p->trigger_fd;
        fds_to_close->fds[i * 3 + 2] = event_p->control_fd;
    }

    return thread;
}

static pthread_t run_psi_monitor(config_t *config) {
    // Check that PSI is enabled
    if (!psi_is_enabled()) {
        syslog(LOG_WARNING, "PSI is not enabled in the kernel config\n");
        return 0;
    }

    // Create a thread to monitor the PSI events
    monitor_psi_args_t *args = malloc(sizeof(monitor_psi_args_t));
    if (args == NULL) {
        syslog(LOG_ERR, "Failed to allocate memory for the PSI monitor args\n");
        return 0;
    }
    args->threshold = config->psi_threshold_percent;

    pthread_t thread;
    if (pthread_create(&thread, NULL, psi_monitor_thread, args) != 0) {
        syslog(LOG_WARNING, "Failed to create a thread for the PSI monitor\n");
        free(args);
        return 0;
    }

    return thread;
}


int monitor_start(config_t *config, resources_to_cleanup_t *resources_to_cleanup)
{
    bool monitor_runs = false;

    if (validate_script(HANDLER_SCRIPT) != 0) {
        syslog(LOG_ERR, "Invalid handler script\n");
        return 1;
    }

    resources_to_cleanup->threads_to_finish.threads = malloc(sizeof(pthread_t) * MONITORING_THREADS_COUNT);
    if (resources_to_cleanup->threads_to_finish.threads == NULL) {
        syslog(LOG_ERR, "Failed to allocate memory for the threads to finish\n");
        return 1;
    }
    for (size_t i = 0; i < MONITORING_THREADS_COUNT; i++) {
        resources_to_cleanup->threads_to_finish.threads[i] = 0;
    }

    // Run a thread to watch memory limit of the zedbox process every 10 seconds and trigger the handler if the limit is reached
    pthread_t procfs_monitor_thread = run_procfs_monitor(config);
    if (procfs_monitor_thread == 0) {
        syslog(LOG_WARNING, "Failed to run the procfs monitor\n");
    } else {
        resources_to_cleanup->threads_to_finish.threads[0] = procfs_monitor_thread;
        resources_to_cleanup->threads_to_finish.count++;
        monitor_runs = true;
    }

    // Run a monitor for the cgroups events
    pthread_t cgroups_monitor_thread = run_cgroups_events_monitor(config, &resources_to_cleanup->fds_to_close);
    if (cgroups_monitor_thread == 0) {
        syslog(LOG_WARNING, "Failed to run the cgroups events monitor\n");
    } else {
        size_t i = resources_to_cleanup->threads_to_finish.count;
        resources_to_cleanup->threads_to_finish.threads[i] = cgroups_monitor_thread;
        resources_to_cleanup->threads_to_finish.count++;
        monitor_runs = true;
    }

    // Run a monitor for the PSI events
    pthread_t psi_monitor_thread = run_psi_monitor(config);
    if (psi_monitor_thread == 0) {
        syslog(LOG_WARNING, "Failed to run the PSI monitor\n");
    } else {
        size_t i = resources_to_cleanup->threads_to_finish.count;
        resources_to_cleanup->threads_to_finish.threads[i] = psi_monitor_thread;
        resources_to_cleanup->threads_to_finish.count++;
        monitor_runs = true;
    }

    if (!monitor_runs) {
        syslog(LOG_ERR, "Failed to run any monitor\n");
        return 1;
    }

    return 0;
}
