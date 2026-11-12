#!/bin/bash

# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

/usr/sbin/sshd
mkdir -p /run/avahi-daemon
avahi-daemon --daemonize --no-drop-root --no-chroot --no-rlimits
python3 -m http.server 80 --directory /srv/www >/var/log/http-server.log 2>&1 &

# See ubuntu-ctr/init.sh for why the console shell is followed by a sleep.
bash
exec sleep infinity
