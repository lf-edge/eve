#!/bin/sh
#
# Copyright (c) 2018 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

TMPDIR=/var/tmp/zededa

echo "Retrieved overlay /etc/hosts with:"
cat $TMPDIR/zedserverconfig
# edit zedserverconfig into /etc/hosts
match=`awk '{print $2}' $TMPDIR/zedserverconfig| sort -u | awk 'BEGIN {m=""} { m = sprintf("%s|%s", m, $1) } END { m = substr(m, 2, length(m)); printf ".*:.*(%s)\n", m}'`
egrep -v $match /etc/hosts >/tmp/hosts.$$
cat $TMPDIR/zedserverconfig >>/tmp/hosts.$$
echo "New /etc/hosts:"
cat /tmp/hosts.$$
cp /tmp/hosts.$$ /etc/hosts
rm -f /tmp/hosts.$$
