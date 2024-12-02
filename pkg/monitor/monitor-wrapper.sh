#!/bin/sh

# Copyright (c) 2024 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

/sbin/monitor
# wait for key press so user can see the panic info
# shellcheck disable=SC3045,SC2162
read -r -p "Press any key to continue... " -n1 -s
