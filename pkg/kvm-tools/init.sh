#!/bin/sh

# FIXME: this will need to be absorbed by containerd/shim
keyctl link @u @s

if [ -e /dev/kvm ]; then
   echo "KVM hypervisor support detected"

   # set things up for R/O FS task execution
   ln -s . /run/run || :

   while true ; do sleep 60 ; done

else
   echo "No hypervisor support detected, feel free to run bare-metal containers"

fi
