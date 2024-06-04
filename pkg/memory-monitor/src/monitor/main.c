// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <syslog.h>
#include <unistd.h>

#include "cgroups.h"
#include "config.h"

#include "monitor.h"

bool syslog_opened = false;
fds_to_close_t fds_to_close = {NULL, 0};

void cleanup() {
    // Close the system log
    if (syslog_opened) {
        syslog(LOG_INFO, "Stopping\n");
        closelog();
    }
    if (fds_to_close.fds == NULL) {
        return;
    }
    for (size_t i = 0; i < fds_to_close.count; i++) {
        if (fds_to_close.fds[i] != -1) {
            close(fds_to_close.fds[i]);
        }
    }
    free(fds_to_close.fds);
}

void sig_handler(int signo) {
    exit(signo);
}

int main() {
    pid_t pid, sid;

    // Fork off the parent process
    pid = fork();
    if (pid < 0) {
        exit(EXIT_FAILURE);
    }
    // If we got a good PID, then we can exit the parent process
    if (pid > 0) {
        exit(EXIT_SUCCESS);
    }

    // Move the process to the root cgroup
    cgroup_move_process_to_root_memory(getpid());

    // Change the file mode mask
    umask(0);

    // Create a new SID for the child process
    sid = setsid();
    if (sid < 0) {
        exit(EXIT_FAILURE);
    }

    // Change the current working directory
    if ((chdir(APP_DIR)) < 0) {
        exit(EXIT_FAILURE);
    }

    // Close the standard file descriptors
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    // Create the log directory if it doesn't exist
    if (access(LOG_DIR, F_OK) == -1) {
        if (mkdir(LOG_DIR, 0755) == -1) {
            syslog(LOG_ERR, "Failed to create log directory: %s", strerror(errno));
            exit(EXIT_FAILURE);
        }
    }

    // Redirect the standard file descriptors to a dedicated file
    int handler_log_fd = open(LOG_DIR "/" HANDLER_LOG_FILE, O_WRONLY | O_CREAT | O_APPEND, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (handler_log_fd == -1) {
        exit(EXIT_FAILURE);
    }
    dup2(handler_log_fd, STDOUT_FILENO);
    dup2(handler_log_fd, STDERR_FILENO);
    if (handler_log_fd > STDERR_FILENO) {
        close(handler_log_fd);
    }

    // Set the signal handler for signals sent to kill the process
    // We need to call exit() in the handler to close the system log and clean up the resources
    if (signal(SIGTERM, sig_handler) == SIG_ERR) {
        exit(EXIT_FAILURE);
    }
    atexit(cleanup);

    // Open the system log
    openlog("memory-monitor", LOG_PID | LOG_NDELAY, LOG_DAEMON);
    syslog_opened = true;

    syslog(LOG_INFO, "Starting\n");

    config_t config;
    config_read(&config);
    config_validate(&config);

    // Run the monitor
    monitor(&config, handler_log_fd, &fds_to_close);

    // We should never reach this point, if we do, something went wrong
    return 1;
}
