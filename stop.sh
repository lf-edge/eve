#!/bin/bash
# Remove anything which has an impact on the system.
# Does not affect the registration etc

LISPDIR=/usr/local/bin/lisp

cd $LISPDIR
./STOP-LISP

eid=`grep "eid-prefix = fd" lisp.config | awk '{print $3}' | awk -F/ '{print $1}'`

# Find the interface based on the routes to the map servers
# Take the first one for now
ms=`grep dns-name $LISPDIR/lisp.config | awk '{print $3}' | sort -u`
for m in $ms; do
    echo ms $ms
    ips=`getent hosts $m | awk '{print $1}' | sort -u`
    # Could get multiple ips
    for ip in $ips; do
	echo ip $ip
	rt=`ip route get $ip`
	echo rt $rt
	intf=`echo $rt | sed 's/.* dev \([^ ]*\) .*/\1/'`
	if [ "$intf" != "" ]; then
	    break
	fi
    done
    if [ "$intf" != "" ]; then
	break
    fi
done
echo "EID: $eid"
echo "INTF: $intf"

sudo /sbin/ifconfig lo inet6 del $eid
sudo ip route del fd00::/8 via fe80::1 src $eid dev $intf
sudo ip nei del fe80::1 lladdr 0:0:0:0:0:1 dev $intf
