#!/bin/sh
#

# Finally, we need to start Xen
# In case it hangs and we have no hardware watchdog we run it in the background
mkdir -p /var/run/xen/ /var/run/xenstored
XENCONSOLED_ARGS='--log=all --log-dir=/var/log/xen' /etc/init.d/xencommons start

# We have the following filesystem logs from Xen to care about under /var/log/xen
#   hypervisor.log
#   xen-hotplug.log
#   guest-DOMAIN_NAME.log
#   qemu-dm-DOMAIN_NAME.log
#   xl-DOMAIN_NAME.log
# For now we will only take care of the two that don't change its name

while true; do
  echo "$(date -Is -u) Starting hypervisor.log"
  tail -c +0 -F /var/log/xen/hypervisor.log /var/log/xen/xen-hotplug.log |\
    while IFS= read -r line; do printf "%s %s\n" "$(date -Is -u)" "$line"; done
done
