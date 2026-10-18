#!/bin/sh

# Copyright (c) 2024-2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

/sbin/monitor
# wait for key press so user can see the panic info
printf "Press any key to continue... "
stty -icanon -echo 2>/dev/null
dd bs=1 count=1 2>/dev/null >/dev/null
stty sane 2>/dev/null
