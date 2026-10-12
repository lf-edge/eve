// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

#include <assert.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>

#include "util.h"

// util.c references it; main.c defines it in the real binary.
char binary_location_g[PATH_MAX + 1];

// Threshold events are polled every CHECK_INTERVAL_SEC; the handler must run
// once per upward crossing, not on every poll while above.
static void test_threshold_crossed(void) {
    bool above = false;
    assert(!threshold_crossed(&above, 10, 100));
    assert(threshold_crossed(&above, 100, 100));  // reaching the threshold fires
    assert(!threshold_crossed(&above, 150, 100)); // staying above does not
    assert(!threshold_crossed(&above, 50, 100));  // falling below re-arms
    assert(threshold_crossed(&above, 120, 100));  // the next crossing fires again
    puts("threshold_crossed: ok");
}

// Restoring pillar's limit after the handler must not go below its usage:
// cgroup v2 would OOM-kill inside pillar's cgroup to fit.
static void test_memory_limit_can_lower(void) {
    assert(memory_limit_can_lower(100, 200));
    assert(memory_limit_can_lower(200, 200));   // usage at the limit fits
    assert(!memory_limit_can_lower(201, 200));  // usage above the limit keeps the raised one
    assert(!memory_limit_can_lower(0, -1));     // a negative limit is never written
    assert(!memory_limit_can_lower(ULONG_MAX, LONG_MAX));
    puts("memory_limit_can_lower: ok");
}

int main(void) {
    test_threshold_crossed();
    test_memory_limit_can_lower();
    return 0;
}
