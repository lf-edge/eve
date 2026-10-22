#!/bin/bash

# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

/usr/sbin/sshd
/usr/local/bin/lps &
exec /bin/bash
