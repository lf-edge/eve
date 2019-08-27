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

# Need this for logrotate
/usr/sbin/crond -d 8

# Finally, we need to start Xen
# In case it hangs and we have no hardware watchdog we run it in the background
XENCONSOLED_ARGS='--log=all --log-dir=/var/log/xen' /etc/init.d/xencommons start &
sleep 5 # Let it come up

echo 'Starting device-steps'
/opt/zededa/bin/device-steps.sh >/var/log/device-steps.log 2>&1

