#!/bin/sh

# setting things up for being able to access linux kernel symbols
echo 0 >  /proc/sys/kernel/kptr_restrict
echo -1 > /proc/sys/kernel/perf_event_paranoid

KEYS=$(find /etc/ssh -name 'ssh_host_*_key')
[ -z "$KEYS" ] && ssh-keygen -A >/dev/null 2>/dev/null

exec /usr/sbin/sshd -D -e
