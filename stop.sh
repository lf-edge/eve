#!/bin/bash
# Remove anything which has an impact on the system.
# Does not affect the registration etc

LISPDIR=/usr/local/bin/lisp

cd $LISPDIR
./STOP-LISP

#Pick first eid-prefix; others are for applications
eid=`grep "eid-prefix = fd" lisp.config | awk '{print $3}' | awk -F/ '{print $1}' | head -1`

intf=`$BINDIR/find-uplink.sh $LISPDIR/lisp.config`
echo "Removing config for EID $eid on $intf"

sudo /sbin/ifconfig lo inet6 del $eid
sudo ip route del fd00::/8 via fe80::1 src $eid dev $intf
sudo ip nei del fe80::1 lladdr 0:0:0:0:0:1 dev $intf
