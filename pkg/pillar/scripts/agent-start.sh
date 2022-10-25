#!/bin/sh
#
# Copyright (c) 2022 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

WATCHDOG_FILE=/run/watchdog/file
BINDIR=/opt/zededa/bin
PATH=$BINDIR:$PATH

# shellcheck source=pkg/pillar/scripts/common.sh
. "$BINDIR/common.sh"

agent=$1
shift

echo "$(date -Ins -u) starting service: $agent"

# notify zedbox to start agent
"$BINDIR/$agent" "$@" &

if [ "$agent" != "diag" ]; then
  wait_for_touch "$agent"
  touch "$WATCHDOG_FILE/$agent.touch"
fi

echo "$(date -Ins -u) starting service done: $agent"

# endless loop as agent is running as goroutine inside zedbox
while true; do
  sleep 10
done
