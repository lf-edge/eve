#!/bin/sh
# creating additional entropy for containerd to be happy
while ! (ip link show wlan0 > /dev/null 2>&1) ; do sleep 5; done
