#!/bin/sh
#
# Copyright (c) 2024 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#

# Start the monitoring task in the background
/usr/bin/edgeview-collectinfo.sh &

# Start the sshd service
/usr/bin/ssh-service.sh
