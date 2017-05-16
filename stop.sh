#!/bin/bash
# Remove anything which has an impact on the system.
# Does not affect the registration etc

cd /usr/local/bin/lisp
./STOP-LISP

eid=`grep "eid-prefix = fd" lisp.config | awk '{print $3}' | awk -F/ '{print $1}'`
# Mostly gets the right interface
intf=`ip addr show scope global up | grep BROADCAST | grep -v docker0 | awk -F : '{print $2}'`
# Take first from list
first=`echo $intf | awk '{print $1}'`
intf=$first
echo "EID: $eid"
echo "INTF: $intf"

sudo /sbin/ifconfig lo inet6 del $eid
sudo ip route del 0::/0 via fe80::1 dev $intf
sudo ip nei del fe80::1 lladdr 0:0:0:0:0:1 dev $intf
