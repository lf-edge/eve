#!/bin/bash
# Find the interface based on the routes to the map servers
# For now we take the first one IP for the first map server which has a route 

if [ $# != 1 ]; then
    echo "Usage: find-uplink.sh <lisp.config>"
    exit 1
fi
LISP_CONFIG=$1

ms=`grep dns-name $LISP_CONFIG | awk '{print $3}' | sort -u`
for m in $ms; do
    # echo ms $ms
    ips=`getent hosts $m | awk '{print $1}' | sort -u`
    # Could get multiple ips
    for ip in $ips; do
	# echo ip $ip
	rt=`ip route get $ip`
	# echo rt $rt
	intf=`echo $rt | sed 's/.* dev \([^ ]*\) .*/\1/'`
	if [ "$intf" != "" ]; then
	    break
	fi
    done
done
echo $intf
