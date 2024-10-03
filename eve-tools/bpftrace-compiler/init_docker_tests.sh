#!/bin/sh

# Copyright (c) 2024 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

mkdir -p /sys/fs/cgroup/init
echo 1 > /sys/fs/cgroup/init/cgroup.procs
echo +cpu > /sys/fs/cgroup/cgroup.subtree_control

/usr/bin/dockerd -l fatal &
exec "$@"
