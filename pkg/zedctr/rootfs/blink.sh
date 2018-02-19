#!/bin/sh
# 200ms on, 200ms off, repeat pattern time
# then off for 1200ms
pattern=3
repeat=-1

if [ $# != 0 ]; then
    if [ $# == 1 ]; then
	pattern=$1
    elif [ $# == 2 ]; then
	pattern=$1
	repeat=$2
    else
	echo "Usage: $0 [ pattern [ repeat ] ]"
    fi
fi

while [ $repeat != 0 ] ; do
    for i in `seq 1 $pattern`; do
	dd if=/dev/sda of=/dev/null bs=4M count=22 2>1 >/dev/null
	usleep 200000
    done
    usleep 1200000
    repeat=`expr $repeat - 1`
done
