#!/bin/sh

# FIXME: this will need to be absorbed by containerd/shim
keyctl link @u @s

if [ -d /proc/xen/ ]; then
   echo "Xen hypervisor support detected"

   # set things up for log collection
   mkdir -p /var/log/xen
   mkfifo /var/log/xen/xen-hotplug.log

   # start collecting logs (make sure that FIFO remains alway open for
   # writing - so readers don't get EOF, but rather block)
   tail -f /var/log/xen/xen-hotplug.log &
   sh -c 'kill -STOP $$' 3>>/var/log/xen/xen-hotplug.log &

   # Finally, we need to start Xen
   # In case it hangs and we have no hardware watchdog we run it in the background
   mkdir -p /var/run/xen/ /var/run/xenstored
   # FIXME: this is a workaround for Xen on ARM still requiring qemu-system-i386
   #   https://wiki.xenproject.org/wiki/Xen_ARM_with_Virtualization_Extensions#Use_of_qemu-system-i386_on_ARM
   if [ "$(uname -m)" = aarch64 ]; then
      export QEMU_XEN=/bin/true
      echo 1 > /var/run/xen/qemu-dom0.pid
   fi
   XENCONSOLED_ARGS='--log=all --log-dir=/var/log/xen' /etc/init.d/xencommons start

   # Now start the watchdog
   mkdir -p /run/watchdog/pid/xen
   (cd /run/watchdog/pid/xen && touch qemu-dom0.pid xenconsoled.pid xenstored.pid)

   # spin for now, but later we can add Xen checks here
   while true ; do sleep 60 ; done

elif [ -e /dev/kvm ]; then
   echo "KVM hypervisor support detected"
   while true ; do sleep 60 ; done

else
   echo "No hypervisor support detected, feel free to run bare-metail containers"

fi
