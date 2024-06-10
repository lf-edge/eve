// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

#ifndef MM_UTILS_H
#define MM_UTILS_H

#include <stdbool.h>
#include <time.h>

int validate_script(const char *script_name);
int convert_mb_to_bytes(unsigned long mb, unsigned long *bytes_out);
int convert_mb_to_bytes_signed(long mb, long *bytes_out);
int get_eve_release(char *eve_release);
void log_event(const time_t *t, const char *format, ...);
long strtodec(const char *str, bool *error);
unsigned long strtoudec(const char *str, bool *error);

#endif //MM_UTILS_H
