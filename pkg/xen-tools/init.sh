#!/bin/sh

# FIXME: this will need to be absorbed by containerd/shim
keyctl link @u @s

if [ -d /proc/xen/ ]; then
   echo "Xen hypervisor support detected"

   # set things up for log collection
   cp -r /var.template/* /var
   mkdir -p /var/log/xen
   mkfifo /var/log/xen/xen-hotplug.log

   # start collecting logs (make sure that FIFO remains always open for
   # writing - so readers don't get EOF, but rather block)
   tail -f /var/log/xen/xen-hotplug.log &
   sh -c 'kill -STOP $$' 3>>/var/log/xen/xen-hotplug.log &

   # Finally, we need to start Xen
   # In case it hangs and we have no hardware watchdog we run it in the background
   mkdir -p /var/run/xen/ /var/run/xenstored

   XENCONSOLED_ARGS='--log=all --log-dir=/var/log/xen' /etc/init.d/xencommons start

   # Now start the watchdog
   mkdir -p /run/watchdog/pid/xen
   (cd /run/watchdog/pid/xen && touch qemu-dom0.pid xenconsoled.pid xenstored.pid)

   # spin for now, but later we can add Xen checks here
   while true ; do sleep 60 ; done

elif [ -e /dev/kvm ]; then
   echo "KVM hypervisor support detected"

   # set things up for R/O FS qemu task execution
   ln -s . /run/run || :

   while true ; do sleep 60 ; done

else
   echo "No hypervisor support detected, feel free to run bare-metal containers"

fi
