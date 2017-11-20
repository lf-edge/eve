#!/bin/sh
#
# This *really* needs to be replaced with tini+monit ASAP.

# Need to disable H/W TCP offload since it seems to mess us up
ethtool -K eth0 gro off
ethtool -K eth1 gro off

# For convenice's sake we're putting SSH inisde of a root container 
/usr/sbin/sshd

# Finally, we need to start Xen
XENCONSOLED_ARGS='--log=all --log-dir=/var/log/xen' /etc/init.d/xencommons start

# This is an optional component - only run it if it is there
/opt/zededa/bin/device-steps.sh -w < /opt/zededa/etc/cert-input.txt || :

tail -f /var/log/*
