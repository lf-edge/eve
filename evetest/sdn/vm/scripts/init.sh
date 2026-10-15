#!/bin/sh

# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

{
  echo "Starting SSH daemon..."
  /usr/sbin/sshd -E /run/sshd.log -h /root/.ssh/sdn_rsa

  echo "Starting Evetest SDN mgmt agent..."
  while true; do
    sdnagent -debug
    echo "Restarting Evetest SDN mgmt Agent!!!"
  done

} > /run/sdn.log 2>&1
