#!/bin/sh

# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

# Emits a startup banner followed by a numbered heartbeat every few seconds.
# Tests match on these two message kinds to verify that EVE collects
# application stdout from container creation onwards and keeps streaming it
# to the controller. The heartbeat counter restarts from 1 on every container
# (re)creation, so counting banner occurrences tells restarts apart.

echo "evetest-logger-ctr: started"

i=0
while true; do
    i=$((i + 1))
    echo "evetest-logger-ctr: heartbeat $i"
    sleep 5
done
