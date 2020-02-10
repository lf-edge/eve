#!/bin/sh
#
# This *really* needs to be replaced with tini+monit ASAP.

# Start with a default content for resolv.conf
echo 'nameserver 8.8.8.8' > /etc/resolv.conf

# Need to disable H/W TCP offload since it seems to mess us up
for i in $(cd /sys/class/net || return ; echo eth*) ; do
  ethtool -K "$i" gro off
  ethtool -K "$i" sg off
done

echo 'Starting device-steps'
/opt/zededa/bin/device-steps.sh
