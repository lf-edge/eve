#!/bin/sh
# SOS pattern ...
# then off for 800ms
repeat=-1

if [ $# != 0 ]; then
    if [ $# == 1 ]; then
	repeat=$1
    else
	echo "Usage: $0 [ repeat ]"
    fi
fi

while [ $repeat != 0 ] ; do
    # SOS pattern?
    for i in `seq 1 3`; do
	dd if=/dev/sda of=/dev/null bs=4M count=11 2>1 >/dev/null
	usleep 100000
    done
    usleep 200000
    for i in `seq 1 3`; do
	dd if=/dev/sda of=/dev/null bs=4M count=33 2>1 >/dev/null
	usleep 100000
    done
    usleep 200000
    for i in `seq 1 3`; do
	dd if=/dev/sda of=/dev/null bs=4M count=11 2>1 >/dev/null
	usleep 100000
    done
    usleep 800000
    repeat=`expr $repeat - 1`
done
