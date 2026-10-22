#!/bin/bash

# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

# The volverify binary is not a daemon: the test drives it on demand over SSH
# (RunShellScriptInsideApp). Start sshd and keep the container alive.

/usr/sbin/sshd
exec sleep infinity
