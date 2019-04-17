#!/bin/sh
# SOS pattern with 100 ms as basic time; 3X for dash and character spacing,
# and 7X for word spacing.
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
    usleep 300000
    for i in `seq 1 3`; do
	dd if=/dev/sda of=/dev/null bs=4M count=33 2>1 >/dev/null
	usleep 100000
    done
    usleep 300000
    for i in `seq 1 3`; do
	dd if=/dev/sda of=/dev/null bs=4M count=11 2>1 >/dev/null
	usleep 100000
    done
    usleep 700000
    repeat=`expr $repeat - 1`
done
