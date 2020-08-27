#!/bin/sh
if ! [ -d /persist/debug ]; then
  mkdir -p /persist/debug
else
  cp -rf /persist/debug /persist/debug.old
  cp -rf /persist/agentdebug/zedbox/* /persist/debug.old
fi
while true; do
  echo "$(date -Ins -u) Taking stack traces" > /persist/debug/periodic_sigusr1.out
  # shellcheck disable=SC2069
  pkill -USR1 /opt/zededa/bin/zedbox 2>&1 > /persist/debug/periodic_sigusr1_pkill.out
  sleep 15
done
