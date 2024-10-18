// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "config.h"

extern char binary_location_g[PATH_MAX + 1];

int validate_script(const char *script_name) {
    char script_path[PATH_MAX + 1];
    int printed;
    // Check the length of the path to the script to ignore warning in the next sprintf
    if (strlen(binary_location_g) + strlen(script_name) + 1 > sizeof(script_path)) {
        syslog(LOG_ERR, "Path to the script is too long\n");
        return 1;
    }

    // Construct the path to the script
    printed = snprintf(script_path, sizeof(script_path) - 1, "%s/%s", binary_location_g, script_name);
    if (printed < 0 || printed >= sizeof(script_path)) {
        syslog(LOG_ERR, "Failed to construct the path to the script\n");
        return 1;
    }

    // Check if the script exists
    if (access(script_path, X_OK) == -1) {
        syslog(LOG_ERR, "access script: %s", strerror(errno));
        return 1;
    }
    return 0;
}

// Run the eve version from /run/eve-release
int get_eve_release(char *eve_release) {
    FILE *fp = fopen("/run/eve-release", "r");
    if (fp == NULL) {
        syslog(LOG_ERR, "Failed to open /run/eve-release: %s", strerror(errno));
        return 1;
    }
    if (fgets(eve_release, 256, fp) == NULL) {
        syslog(LOG_ERR, "Failed to read /run/eve-release: %s", strerror(errno));
        fclose(fp);
        return 1;
    }
    // Remove the newline character
    eve_release[strcspn(eve_release, "\n")] = 0;
    fclose(fp);
    return 0;
}

void log_event(const time_t *t, const char *format, ...) {

    // Get the path to the event log file
    const char *log_file = LOG_DIR "/" EVENT_LOG_FILE;

    FILE *event_log = fopen(log_file, "a");
    if (event_log == NULL) {
        syslog(LOG_ERR, "Failed to open event log: %s", strerror(errno));
        return;
    }

    // Add a timestamp to the log entry
    time_t time_to_use;
    if (t == NULL) {
        time_to_use = time(NULL);
    } else {
        time_to_use = *t;
    }

    struct tm tm = *localtime(&time_to_use);
    fprintf(event_log, "[ %04d-%02d-%02d / %02d:%02d:%02d ] ",
            tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
            tm.tm_hour, tm.tm_min, tm.tm_sec);

    // Write the eve version to the log file
    char eve_release[256];
    if (get_eve_release(eve_release) == 0) {
        fprintf(event_log, "<EVE: %s> ", eve_release);
    }

    // Write the formatted string to the log file
    va_list args;
    va_start(args, format);
    vfprintf(event_log, format, args);
    va_end(args);

    fclose(event_log);
}

long strtodec(const char *str, bool *error) {
    char *endptr;
    errno = 0;
    long val = strtol(str, &endptr, 10);
    if ( (errno == ERANGE && (val == LONG_MAX || val == LONG_MIN  )) || // overflow or underflow
         (errno != 0 && val == 0) || // conversion error
         (*endptr != '\0' && *endptr != '\n') || // trailing characters
         (endptr == str) ) { // no digits were found
        syslog(LOG_ERR, "Invalid value: %s", str);
        *error = true;
        return LONG_MAX;
    }
    *error = false;
    return val;
}

unsigned long strtoudec(const char *str, bool *error) {
    char *endptr;
    errno = 0;
    unsigned long val = strtoul(str, &endptr, 10);
    if ( (errno == ERANGE && val == ULONG_MAX) || // overflow
         (errno != 0 && val == 0) || // conversion error
         (*endptr != '\0' && *endptr != '\n') || // trailing characters
         (endptr == str) ) { // no digits were found
        syslog(LOG_ERR, "Invalid value: %s", str);
        *error = true;
        return ULONG_MAX;
    }
    *error = false;
    return val;
}
int convert_mb_to_bytes(unsigned long mb, unsigned long *bytes_out) {
    if (__builtin_umull_overflow(mb, 1024 * 1024, bytes_out)) {
        syslog(LOG_ERR, "Invalid value: %lu MB", mb);
        return 1;
    }
    return 0;
}

int convert_mb_to_bytes_signed(long mb, long *bytes_out) {
    if (__builtin_smull_overflow(mb, 1024 * 1024, bytes_out)) {
        syslog(LOG_ERR, "Invalid value: %ld MB", mb);
        return 1;
    }
    return 0;
}

char *get_tail(const char *file_path, size_t num_lines) {
    // Open the file
    FILE *file = fopen(file_path, "r");
    if (file == NULL) {
        syslog(LOG_ERR, "Failed to open file: %s", strerror(errno));
        return NULL;
    }

    // Seek to the end of the file
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    if (file_size == -1) {
        syslog(LOG_ERR, "Failed to get file size: %s", strerror(errno));
        fclose(file);
        return NULL;
    }

    // Start reading the file backwards to find the last `num_lines` lines
    int lines_read = 0;
    long i;
    char c;
    for (i = file_size - 1; i >= 0; i--) {
        fseek(file, i, SEEK_SET);
        c = fgetc(file);
        if (c == '\n') {
            lines_read++;
            if (lines_read == num_lines + 1) { // +1 to include the current line
                break;
            }
        }
    }

    // If we didn't find enough lines, reset i to start of file
    if (i < 0) {
        i = 0;
    } else {
        i += 2; // Move past the '\n' we stopped at
    }

    // Allocate memory for the buffer to hold the result
    size_t buffer_size = file_size - i + 1; // Include space for null terminator
    char *buffer = (char *) malloc(buffer_size);
    if (buffer == NULL) {
        syslog(LOG_ERR, "Failed to allocate memory: %s", strerror(errno));
        fclose(file);
        return NULL;
    }

    // Read from the file from the correct position
    fseek(file, i, SEEK_SET);
    size_t bytes_read = fread(buffer, 1, buffer_size - 1, file);
    if (bytes_read != buffer_size - 1) {
        syslog(LOG_ERR, "Failed to read file: %s", strerror(errno));
        free(buffer);
        fclose(file);
        return NULL;
    }
    buffer[buffer_size - 1] = '\0'; // Null-terminate the buffer

    fclose(file);
    return buffer;
}
