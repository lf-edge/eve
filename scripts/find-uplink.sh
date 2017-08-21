#!/bin/bash
# Find the interface based on the routes to the map servers
# For now we take the first one IP for the first map server which has a route 
if [ "$1" == -d ]; then
    DEBUG=1
    shift
fi
if [ $# != 1 ]; then
    echo "Usage: find-uplink.sh <lisp.config>"
    exit 1
fi
LISP_CONFIG=$1

intf=""
ms=`grep dns-name $LISP_CONFIG | awk '{print $3}' | sort -u`
for m in $ms; do
    if [ $DEBUG ]; then
	echo ms $ms
    fi
    ips=`getent hosts $m | awk '{print $1}' | sort -u`
    # Could get multiple ips
    for ip in $ips; do
	if [ $DEBUG ]; then
	    echo ip $ip
	fi
	rt=`ip route get $ip`
	if [ $DEBUG ]; then
	    echo rt $rt
	fi
	intf=`echo $rt | sed 's/.* dev \([^ ]*\) .*/\1/'`
	if [ $DEBUG ]; then
	    echo intf $intf
	fi
	if [ "$intf" != "" ]; then
	    break
	fi
    done
    if [ "$intf" != "" ]; then
	break
    fi
done
echo $intf
