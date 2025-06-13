#!/bin/sh
#
# Copyright (c) 2025 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

is_amd64() {
    mach_type=$(uname -m)
    if [ "$mach_type" = "x86_64" ]; then
        return 0
    fi
    if [ "$mach_type" = "amd64" ]; then
        return 0
    fi
    return 1
}