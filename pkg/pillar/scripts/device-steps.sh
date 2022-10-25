#!/bin/sh
#
# Copyright (c) 2018 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

WATCHDOG_PID=/run/watchdog/pid
CONFIGDIR=/config
PERSISTDIR=/persist
DEVICE_CERT_NAME="${CONFIGDIR}/device.cert.pem"
DEVICE_KEY_NAME="${CONFIGDIR}/device.key.pem"
BINDIR=/opt/zededa/bin
TMPDIR="$PERSISTDIR/tmp"
ZTMPDIR=/run/global
FIRSTBOOTFILE=$ZTMPDIR/first-boot
FIRSTBOOT=
TPM_DEVICE_PATH="/dev/tpmrm0"
PATH=$BINDIR:$PATH

# shellcheck source=pkg/pillar/scripts/common.sh
. /opt/zededa/bin/common.sh

if [ -f "$FIRSTBOOTFILE" ]; then
  FIRSTBOOT=1
fi

echo "$(date -Ins -u) Starting device-steps.sh"
echo "$(date -Ins -u) EVE version: $(cat /run/eve-release)"

MEASURE=0
while [ $# != 0 ]; do
    if [ "$1" = -m ]; then
        MEASURE=1
    elif [ "$1" = -w ]; then
        echo "$(date -Ins -u) Got old -w"
    else
        echo "Usage: device-steps.sh [-h] [-m]"
        exit 1
    fi
    shift
done

INPUTFILE=/run/nim/DeviceNetworkStatus/global.json
DEFAULT_NTPSERVER=pool.ntp.org
# Return one line with all the NTP servers for all the ports
get_ntp_servers() {
    if [ ! -f "$INPUTFILE" ];  then
        return
    fi
    res=
    i=0
    while true; do
        portInfo=$(jq -c .Ports[$i] < $INPUTFILE)
        if [ "$portInfo" = "null" ] || [ -z "$portInfo" ]; then
            break
        fi
        list=$(echo "$portInfo" | jq .NtpServers)
        ns=$(echo "$list" | awk -F\" '{ if (NF > 2) { print $2}}')
        res="$res $ns"
        i=$((i + 1))
    done
    out=
    # Make uniform whitespace separator
    for r in $res; do
        if [ -z "$out" ]; then
            out="$r"
        else
            out="$out $r"
        fi
    done
    echo "$out"
}

# Return one (the first) ntp server with default if none
get_ntp_server() {
    res=$(get_ntp_servers)
    one="$DEFAULT_NTPSERVER"
    for first in $res; do
        one=$first
        break
    done
    echo "$one"
}


CONFIGDEV=$(zboot partdev CONFIG)

# Need a special check (and slower booting) if the device has no hardware clock
if [ -c /dev/rtc ] || [ -c /dev/rtc0 ]; then
    RTC=1
else
    RTC=0
fi
if [ $RTC = 0 ]; then
    echo "$(date -Ins -u) No real-time clock"
fi
# On first boot (of boxes which have been powered off for a while) force
# ntp setting of clock
if [ ! -s "$DEVICE_CERT_NAME" ] || [ $RTC = 0 ] || [ -n "$FIRSTBOOT" ]; then
    # Wait for having IP addresses for a few minutes
    # so that we are likely to have an address when we run ntp then create cert
    echo "$(date -Ins -u) Starting waitforaddr"
    $BINDIR/waitforaddr

    # Deposit any diag information from nim
    access_usb

    # We need to try our best to setup time *before* we generate the certifiacte.
    # Otherwise the cert may have start date in the future or in 1970
    # Did NIM get some NTP servers from DHCP? Pick the first one we find.
    # Otherwise we use the default
    NTPSERVER=$(get_ntp_server)
    echo "$(date -Ins -u) Check for NTP config"
    if [ -f /usr/sbin/ntpd ]; then
        # Wait until synchronized and force the clock to be set from ntp
        echo "$(date -Ins -u) ntpd -q -n -g -p $NTPSERVER"
        /usr/sbin/ntpd -q -n -g -p "$NTPSERVER"
        ret_code=$?
        echo "$(date -Ins -u) ntpd: $ret_code"
        # Run ntpd to keep it in sync.
        echo "$(date -Ins -u) ntpd -p $NTPSERVER"
        /usr/sbin/ntpd -p "$NTPSERVER"
        ret_code=$?
        echo "$(date -Ins -u) ntpd: $ret_code"
        # Add ndpd to watchdog
        touch "$WATCHDOG_PID/ntpd.pid"
    else
        echo "$(date -Ins -u) No ntpd"
    fi

    # The device cert generation needs the current time. Some hardware
    # doesn't have a battery-backed clock
    YEAR=$(date +%Y)
    while [ "$YEAR" = "1970" ]; do
        echo "$(date -Ins -u) It's still 1970; waiting for ntp to advance"
        sleep 10
        YEAR=$(date +%Y)
    done
    if [ $RTC = 1 ]; then
        # Update RTC based on time from ntpd so that after a reboot we have a
        # sane starting time. This fixes issues when the RTC was not in UTC
        hwclock -u -v --systohc
    fi
else
    # Start ntpd before network is up. Assumes it will synchronize later.
    # Did NIM get some NTP servers from DHCP? Otherwise use default.
    # If DHCP isn't done we don't get a server here. So we recheck
    # at the end of device-steps.sh
    NTPSERVER=$(get_ntp_server)
    if [ -f /usr/sbin/ntpd ]; then
        # Run ntpd to keep it in sync. Allow a large initial jump in case clock
        # had drifted more than 1000 seconds while the device was powered off
        echo "$(date -Ins -u) ntpd -g -p $NTPSERVER"
        /usr/sbin/ntpd -g -p "$NTPSERVER"
        ret_code=$?
        echo "$(date -Ins -u) ntpd: $ret_code"
        # Add ndpd to watchdog
        touch "$WATCHDOG_PID/ntpd.pid"
    else
        echo "$(date -Ins -u) No ntpd"
    fi
fi
if [ ! -s "$DEVICE_CERT_NAME" ]; then
    echo "$(date -Ins -u) Generating a device key pair and self-signed cert (using TPM if available)"
    mount -o remount,flush,dirsync,noatime,rw /config
    if [ -c $TPM_DEVICE_PATH ] && ! [ -f $DEVICE_KEY_NAME ]; then
        echo "$(date -Ins -u) TPM device is present and allowed, creating TPM based device key"
        if ! $BINDIR/tpmmgr createDeviceCert; then
            echo "$(date -Ins -u) TPM is malfunctioning, falling back to software certs; disabling tpm"
            $BINDIR/tpmmgr createSoftDeviceCert
        fi
    else
        $BINDIR/tpmmgr createSoftDeviceCert
    fi
    # Reduce chance that we register with controller and crash before
    # the filesystem has persisted /config/device.*.pem
    # If we have a TPM we can we can recover the certificate from NVRAM
    # but without it we are lost.
    sync
    blockdev --flushbufs "$CONFIGDEV"
    sleep 10
    sync
    blockdev --flushbufs "$CONFIGDEV"
    echo "$(date -Ins -u) Making /config read-only again"
    mount -o remount,flush,ro /config
    # Did we fail to generate a certificate?
    if [ ! -s "$DEVICE_CERT_NAME" ]; then
        echo "$(date -Ins -u) Failed to generate a device certificate. Done" | tee /dev/console
        exit 0
    fi
else
    echo "$(date -Ins -u) Using existing device key pair"
fi
if [ ! -s $CONFIGDIR/server ] || [ ! -s $CONFIGDIR/root-certificate.pem ]; then
    echo "$(date -Ins -u) No server or root-certificate to connect to. Done" | tee /dev/console
    exit 0
fi

if [ -c $TPM_DEVICE_PATH ] && ! [ -f $DEVICE_KEY_NAME ]; then
    echo "$(date -Ins -u) device-steps: TPM device, creating additional security certificates"
    if ! $BINDIR/tpmmgr createCerts; then
        echo "$(date -Ins -u) device-steps: createCerts failed"
    fi
else
    echo "$(date -Ins -u) device-steps: NOT TPM device, creating additional security certificates"
    if ! $BINDIR/tpmmgr createSoftCerts; then
        echo "$(date -Ins -u) device-steps: createSoftCerts failed"
    fi
fi

# Deposit any diag information from nim and onboarding
access_usb

# Add zedclient to watchdog; it runs as a separate process
touch "$WATCHDOG_PID/zedclient.pid"

rm -f $ZTMPDIR/zedrouterconfig.json

CLIENT_COMMANDS="getUuid"
echo "$(date -Ins -u) Get UUID of device registered in controller"
if [ -f $CONFIGDIR/onboard.cert.pem ] && [ -f $CONFIGDIR/onboard.key.pem ]; then
   echo "$(date -Ins -u) Self-registering our device certificate"
   CLIENT_COMMANDS="selfRegister $CLIENT_COMMANDS"
fi
echo "$(date -Ins -u) Starting client $CLIENT_COMMANDS"
# shellcheck disable=SC2086
if ! $BINDIR/client $CLIENT_COMMANDS; then
   echo "$(date -Ins -u) client $CLIENT_COMMANDS failed"
   exit 1
fi

# Remove zedclient.pid from watchdog
rm "$WATCHDOG_PID/zedclient.pid"

uuid=$(cat $PERSISTDIR/status/uuid)
/bin/hostname >/etc/hostname

if ! grep -q "$uuid" /etc/hosts; then
    # put the uuid in /etc/hosts to avoid complaints
    echo "$(date -Ins -u) Adding $uuid to /etc/hosts"
    echo "127.0.0.1 $uuid" >>/etc/hosts
else
    echo "$(date -Ins -u) Found $uuid in /etc/hosts"
fi

echo "$(date -Ins -u) Initial setup done"

if [ $MEASURE = 1 ]; then
    ping6 -c 3 -w 1000 zedcontrol
    echo "$(date -Ins -u) Measurement done"
fi

echo "$(date -Ins -u) Done starting EVE version: $(cat /run/eve-release)"

# If there is a USB stick inserted and debug.enable.usb is set, we periodically
# check for any usb.json with DevicePortConfig, deposit our identity,
# and dump any diag information
while true; do
    access_usb
    # Check if NTP server changed
    # Note that this really belongs in a separate ntpd container
    ns=$(get_ntp_server)
    if [ -n "$ns" ] && [ "$ns" != "$NTPSERVER" ] && [ -f /run/ntpd.pid ]; then
        echo "$(date -Ins -u) NTP server changed from $NTPSERVER to $ns"
        NTPSERVER="$ns"
        ntpd_pid="$(cat /run/ntpd.pid)"
        kill "$ntpd_pid"
        # Wait for it to go away before restarting
        while kill -0 "$ntpd_pid"; do
            echo "$(date -Ins -u) NTP server $ntpd_pid still running"
            sleep 3
        done
        echo "$(date -Ins -u) ntpd -g -p $NTPSERVER"
        /usr/sbin/ntpd -g -p "$NTPSERVER"
        ret_code=$?
        echo "$(date -Ins -u) ntpd: $ret_code"
    fi
    sleep 300
done
