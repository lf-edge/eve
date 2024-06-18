// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

#ifndef MM_UTILS_H
#define MM_UTILS_H

#include <stdbool.h>
#include <time.h>

// The maximum possible length of the EVE_VERSION variable depends on the lengths of the variables it is composed of.
// Let's break it down:
//  EVE_SNAPSHOT_VERSION: This is set to "0.0.0" by default. So, it contributes 5 characters.
//  REPO_BRANCH: This is the name of the current Git branch. The Git documentation suggests that branch names should be
//               no more than 50 characters for compatibility reasons.
//  REPO_SHA: This is the SHA of the current Git commit. Git SHAs are 40 characters long.
//  REPO_DIRTY_TAG: This is a timestamp that is added if the repository is dirty (has uncommitted changes).
//                  It is in the format "-YYYY-MM-DD.HH.MM", which is 17 characters long.
//  DEV_TAG: This is set to "-dev" if the DEV variable is set to "y". So, it can contribute up to 4 characters.
//  REPO_TAG: This is the current Git tag. Git doesn't impose a hard limit on tag lengths, but a common practice is to
//            keep them under 100 characters.
// So, the maximum length of ROOTFS_VERSION can be calculated as follows:
//  5 (EVE_SNAPSHOT_VERSION) + 1 (dash) + 50 (REPO_BRANCH) + 1 (dash) + 40 (REPO_SHA) + 17 (REPO_DIRTY_TAG) +
//  4 (DEV_TAG) = 118 characters
// Or, if REPO_TAG is used instead of the snapshot version and other variables, it can be up to 100 characters.
// Therefore, the maximum possible length of ROOTFS_VERSION is 118 characters when using the snapshot version, branch,
// SHA, and other variables, or 100 characters when using a Git tag.
// Let's use 256 characters as the maximum length to be on the safe side.
#define MAX_EVE_VERSION_LENGTH 256

#define MAX_EVENT_MSG_LENGTH 256

int validate_script(const char *script_name);
int convert_mb_to_bytes(unsigned long mb, unsigned long *bytes_out);
int convert_mb_to_bytes_signed(long mb, long *bytes_out);
int get_eve_release(char *eve_release);
void log_event(const time_t *t, const char *format, ...);
long strtodec(const char *str, bool *error);
unsigned long strtoudec(const char *str, bool *error);

#endif //MM_UTILS_H
