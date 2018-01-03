#!/bin/sh
set -x
# uqmi -d /dev/cdc-wdm0 --start-network vzwinternet --autoconnect
# uqmi -d /dev/cdc-wdm0 --get-data-status
# udhcpc -i wwan0
modprobe ppp_async
modprobe qcserial
modprobe qmi_wwan
pppd call vzwinternet
