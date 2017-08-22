#!/bin/bash
# Run this after reboot of host to prepare to run Xen domUs
# XXX should we pick a directory?
XENDIR=`pwd`
# XXX also add a IMGDIR for the losetup??

# XXX should extract vif info from /var/run/zedrouter/status/*.json

# We assume ${XENDIR}/xen${APPNUM}.template exists with the blk and name etc
# We will append the vif and uuid config to those templates

# This belongs in ZedManager
echo "Setup disk loopback"
if [ ! -f ubuntu-cloudimg.img ]; then
    echo "Missing ubuntu-cloudimg.img"
    exit 1
fi
losetup /dev/loop3 ubuntu-cloudimg.img
if [ ! -f xxx-test.img ]; then
    echo "Missing xxx-test.img"
    exit 1
fi
losetup /dev/loop4 xxx-test.img 
if [ ! -f two-cloudimg.img ]; then
    echo "Missing two-cloudimg.img"
    exit 1
fi
losetup /dev/loop5 two-cloudimg.img
