#!/bin/sh

# Plugged in as a watchdog repair script just so that we can record the
# watchdog reason
# Does NOT attempt any repair

# First log to /persist in case zboot/kernel is hung on disk

DATE=`date -Ins`
echo "Watchdog repair at $DATE: $@" >>/persist/reboot-reason
sync
CURPART=`zboot curpart`
echo "Watchdog repair at $DATE: $@" >>/persist/$CURPART/reboot-reason
sync
sleep 10
exit 254
