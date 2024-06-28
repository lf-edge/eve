#!/bin/sh
#
# Copyright (c) 2018 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

WATCHDOG_PID=/run/watchdog/pid
WATCHDOG_FILE=/run/watchdog/file
CONFIGDIR=/config
CONFIGDIR_PERSIST=/tmp/config_persist
PERSISTDIR=/persist
DEVICE_CERT_NAME="/config/device.cert.pem"
DEVICE_KEY_NAME="/config/device.key.pem"
TPM_CREDENTIAL="/config/tpm_credential"
BOOTSTRAP_CONFIG="${CONFIGDIR}/bootstrap-config.pb"
BINDIR=/opt/zededa/bin
TMPDIR=$PERSISTDIR/tmp
ZTMPDIR=/run/global
DPCDIR=$ZTMPDIR/DevicePortConfig
FIRSTBOOTFILE=$ZTMPDIR/first-boot
FIRSTBOOT=
AGENTS="diag zedagent ledmanager nim nodeagent domainmgr loguploader tpmmgr vaultmgr zedmanager zedrouter downloader verifier baseosmgr wstunnelclient volumemgr watcher zfsmanager usbmanager zedkube"
TPM_DEVICE_PATH="/dev/tpmrm0"
PATH=$BINDIR:$PATH
TPMINFOTEMPFILE=/var/tmp/tpminfo.txt

echo "$(date -Ins -u) Starting device-steps.sh"
echo "$(date -Ins -u) EVE version: $(cat /run/eve-release)"

if [ -f "$FIRSTBOOTFILE" ]; then
  FIRSTBOOT=1
fi

# For checking whether we have a Keyboard etc at startup
in=$(cat /sys/class/input/input*/name)
echo "$(date -Ins -u) input devices: $in"

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

# Sleep for a bit until /run/$1.touch exists
wait_for_touch() {
    f=/run/"$1".touch
    waited=0
    while [ ! -f "$f" ] && [ "$waited" -lt 60 ]; do
            echo "$(date -Ins -u) waiting for $f"
            sleep 3
            waited=$((waited + 3))
    done
    if [ ! -f "$f" ]; then
        echo "$(date -Ins -u) gave up waiting for $f"
    else
        echo "$(date -Ins -u) waited $waited for $f"
    fi
}

INPUTFILE=/run/nim/DeviceNetworkStatus/global.json
# This one is actually a pool, not a single server.
# So if going to change this, please don't forget
# to change DEFAULT_NTPMODE below.
DEFAULT_NTPSERVER=pool.ntp.org
DEFAULT_NTPMODE=pool
# Current NTP servers
NTPSERVERS=

# Return one line with all the NTP servers for all the ports
get_ntp_servers() {
    if [ ! -f "$INPUTFILE" ];  then
        return
    fi

    # Select static NTP sources
    ntp_static=$(jq -r  -c  \
                '.Ports[] |
                 select(.NtpServer != null and .NtpServer != "") |
                 .NtpServer' $INPUTFILE)

    # Select dynamic (from DHCP) NTP sources
    ntp_dynamic=$(jq -r  -c  \
                '.Ports[] |
                 select(.NtpServers != null) |
                 .NtpServers | .[]' $INPUTFILE)

    # Concat all in one string
    ntp_all="$ntp_static $ntp_dynamic"

    # Make the following: "$mode $ntp" and separate
    # each with \n for further processing in a caller
    list=
    for ntp in $ntp_all; do
        list="$list server\n$ntp\n"
    done
    ntp_all="$list"

    # Fallback to default if nothing is configured
    if [ -z "$ntp_all" ]; then
        ntp_all="$DEFAULT_NTPMODE\n$DEFAULT_NTPSERVER\n"
    fi

    # shellcheck disable=SC3037
    echo -n "$ntp_all"
}

# Formats argument line for chrony prepending and appending
# strings to each NTP server
format_chrony_args() {
    ntp_servers="$1"
    prepend="$2"
    append="$3"

    # '-e' for echo to enable interpretation of \n
    # shellcheck disable=SC3037
    list=$(echo -e "$ntp_servers" | while read -r mode && read -r server; do
        # shellcheck disable=SC3037
        echo -n "\"$prepend $mode $server $append\" "
    done)

    # shellcheck disable=SC3037
    echo -n "$list"
}

# Wait until NTP synchronised
wait_ntp_sync() {
    echo "$(date -Ins -u) Wait NTP sync for 1 min"
    /usr/bin/chronyc waitsync 6
    ret_code=$?
    echo "$(date -Ins -u) chronyc: $ret_code"
}

# Populate NTP sources from the string argument, which represents
# \n separated list of servers
populate_ntp_sources() {
    servers="$1"
    echo "$(date -Ins -u) Populate NTP with new sources"
    # Creates string of servers in "add $mode $server iburst" format
    args=$(format_chrony_args "$servers" "add" "iburst")
    echo "$(date -Ins -u) chronyc -m $args"
    echo "$args" | xargs /usr/bin/chronyc -m
    ret_code=$?
    echo "$(date -Ins -u) chronyc: $ret_code"
}

# Start NTP daemon
start_ntp_daemon() {
    NTPSERVERS=$(get_ntp_servers)
    echo "$(date -Ins -u) Check for NTP config"
    if [ -f /usr/sbin/chronyd ]; then
        # Run chronyd to keep it in sync.
        echo "$(date -Ins -u) chronyd -u root -f /etc/chrony/chrony.conf"
        /usr/sbin/chronyd -u root -f /etc/chrony/chrony.conf
        ret_code=$?
        echo "$(date -Ins -u) chronyd: $ret_code"
        # Add chronyd to watchdog
        touch "$WATCHDOG_PID/chronyd.pid"

        # Pass NTP server through the chronyc, unfortunately can't pass as
        # an argument to the daemon itself.
        if [ "$ret_code" = "0" ]; then
            # Give some time for chronyd to start
            sleep 1
            populate_ntp_sources "$NTPSERVERS"
        fi
    else
        echo "$(date -Ins -u) ERROR: no NTP (chrony) on EVE"
    fi
}

# Reload NTP sources
reload_ntp_sources() {
    echo "$(date -Ins -u) Remove all NTP sources from chronyd"
    while true; do
        # Get all sources, skip 2 lines header, take first line
        ip=$(/usr/bin/chronyc -n sources | tail +3 | head -1 | awk '{print $2}')
        if [ -z "$ip" ]; then
            break
        fi
        # Delete IP
        echo "$(date -Ins -u) chronyc delete \"$ip\""
        /usr/bin/chronyc delete "$ip"
        ret_code=$?
        echo "$(date -Ins -u) chronyc: $ret_code"
        if [ "$ret_code" != "0" ]; then
            break
        fi
    done
    populate_ntp_sources "$NTPSERVERS"
}

# If zedbox is already running we don't have to start it.
if ! pgrep zedbox >/dev/null; then
    echo "$(date -Ins -u) Starting zedbox"
    $BINDIR/zedbox &
    wait_for_touch zedbox
fi

# Look for a USB stick with a usb.json file
# XXX note that gpt on the USB stick needs to be labeled with DevicePortConfig
# If there is a dump directory on the stick we put log and debug info
# in there.
# If there is an identity directory on the stick we put identifying
# information in a subdir there.
access_usb() {
    # echo "$(date -Ins -u) XXX Looking for USB stick with DevicePortConfig"
    SPECIAL=$(lsblk -l -o name,label,partlabel | awk '/DevicePortConfig|QEMU VVFAT/ {print "/dev/"$1;}')
    if [ -n "$SPECIAL" ] && [ -b "$SPECIAL" ]; then
        echo "$(date -Ins -u) Found USB with DevicePortConfig: $SPECIAL"
        mount -t vfat "$SPECIAL" /mnt
        ret_code=$?
        if [ "$ret_code" != 0 ]; then
            echo "$(date -Ins -u) mount $SPECIAL failed: $ret_code"
            return
        fi
        # Apply legacy usb.json only if bootstrap-config.pb is not present.
        if [ ! -f "$BOOTSTRAP_CONFIG" ]; then
            # shellcheck disable=SC2066
            for fd in "usb.json:$DPCDIR" ; do
                file=/mnt/$(echo "$fd" | cut -f1 -d:)
                dst=$(echo "$fd" | cut -f2 -d:)
                if [ -f "$file" ]; then
                    echo "$(date -Ins -u) Found $file on $SPECIAL"
                    echo "$(date -Ins -u) Copying from $file to $dst"
                    cp -p "$file" "$dst"
                else
                    echo "$(date -Ins -u) $file not found on $SPECIAL"
                fi
            done
        fi
        if [ -d /mnt/identity ] && [ -f "$DEVICE_CERT_NAME" ]; then
            echo "$(date -Ins -u) Saving identity to USB stick"
            IDENTITYHASH=$(cat $CONFIGDIR/soft_serial)
            IDENTITYDIR="/mnt/identity/$IDENTITYHASH"
            [ -d "$IDENTITYDIR" ] || mkdir -p "$IDENTITYDIR"
            cp -p "$DEVICE_CERT_NAME" "$IDENTITYDIR"
            [ ! -f $CONFIGDIR/onboard.cert.pem ] || cp -p $CONFIGDIR/onboard.cert.pem "$IDENTITYDIR"
            [ ! -f $PERSISTDIR/status/uuid ] || cp -p $PERSISTDIR/status/uuid "$IDENTITYDIR"
            cp -p $CONFIGDIR/root-certificate.pem "$IDENTITYDIR"
            [ ! -f $CONFIGDIR/v2tlsbaseroot-certificates.pem ] || cp -p $CONFIGDIR/v2tlsbaseroot-certificates.pem "$IDENTITYDIR"
            [ ! -f $CONFIGDIR/soft_serial ] || cp -p $CONFIGDIR/soft_serial "$IDENTITYDIR"
            $BINDIR/hardwaremodel -c -o "$IDENTITYDIR/hardwaremodel.dmi"
            sync
        fi
        if [ -d /mnt/dump ]; then
            echo "$(date -Ins -u) Dumping diagnostics to USB stick"
            # Check if it fits without clobbering an existing tar file
            if ! $BINDIR/tpmmgr saveTpmInfo $TPMINFOTEMPFILE; then
                echo "$(date -Ins -u) saveTpmInfo failed" > $TPMINFOTEMPFILE
            fi
            NETDUMPDIR="/persist/netdump"
            [ -d "$NETDUMPDIR" ] || NETDUMPDIR=""
            if tar cf /mnt/dump/diag1.tar /persist/status/ /var/run/ /persist/log /persist/newlog "$NETDUMPDIR" $TPMINFOTEMPFILE; then
                mv /mnt/dump/diag1.tar /mnt/dump/diag.tar
            else
                rm -f /mnt/dump/diag1.tar
            fi
            sync
        fi
        umount -f /mnt
        blockdev --flushbufs "$SPECIAL"
    fi
}

# Read any usb.json with DevicePortConfig, and deposit our identity
access_usb

# Update our local /etc/hosts with entries coming from /config
# We append on every boot since /etc/hosts starts from read-only rootfs
[ -f /config/hosts ] && cat /config/hosts >> /etc/hosts

# If there are any device-specific startup scripts, execute them
echo "$(date -Ins -u) Starting device-specific startup scripts"

for f in /opt/vendor/*/init.d/*; do
    [ -x "$f" ] || continue
    echo "$(date -Ins -u) Running $f"
    "$f"
done

echo "$(date -Ins -u) Done starting device-specific startup scripts"

echo "$(date -Ins -u) Starting services"

for AGENT in $AGENTS; do
    echo "$(date -Ins -u) Starting $AGENT"
    if [ "$AGENT" = "diag" ]; then
      # Print diag output forever on changes
      # NOTE: it is safe to do either kill -STOP or an outright
      # kill -9 on the following cat process if you want to stop
      # receiving those messages on the console.
      size="$(stty -F /dev/console size)"
      rows=$(echo "$size" | awk '{print $1}')
      columns=$(echo "$size" | awk '{print $2}')
      [ "$rows" != 0 ] || rows=""
      [ -z "$rows" ] || rows="-r $rows"
      [ "$columns" != 0 ] || columns=""
      [ -z "$columns" ] || columns="-c $columns"
      mkfifo /run/diag.pipe
      (while true; do cat; done) < /run/diag.pipe >/dev/console 2>&1 &
      # shellcheck disable=SC2086
      $BINDIR/diag -f -o /run/diag.pipe -s /run/diag.out $rows $columns &
    else
      $BINDIR/"$AGENT" &
    fi
done

# Now run watchdog for agents
for AGENT in $AGENTS; do
    if [ "$AGENT" = "diag" ]; then
      # we do not use touch for diag
      continue
    fi
    wait_for_touch "$AGENT"
    touch "$WATCHDOG_FILE/$AGENT.touch"
done

echo "$(date -Ins -u) Starting services done"

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

    # Start NTP daemon
    start_ntp_daemon

    # We need to try our best to setup time *before* we generate the certifiacte.
    # Otherwise the cert may have start date in the future or in 1970
    # Did NIM get some NTP servers from DHCP? Pick the first one we find.
    # Otherwise we use the default
    wait_ntp_sync

    # The device cert generation needs the current time. Some hardware
    # doesn't have a battery-backed clock
    YEAR=$(date +%Y)
    while [ "$YEAR" = "1970" ]; do
        echo "$(date -Ins -u) It's still 1970; waiting for ntp to advance"
        sleep 10
        YEAR=$(date +%Y)
    done
    if [ $RTC = 1 ]; then
        # Update RTC based on time from ntp so that after a reboot we have a
        # sane starting time. This fixes issues when the RTC was not in UTC
        hwclock -u -v --systohc
    fi
else
    # Start NTP before network is up. Assumes it will synchronize later.
    # Did NIM get some NTP servers from DHCP? Otherwise use default.
    # If DHCP isn't done we don't get a server here. So we recheck
    # at the end of device-steps.sh
    start_ntp_daemon
fi
if [ ! -s "$DEVICE_CERT_NAME" ]; then
    echo "$(date -Ins -u) Generating a device key pair and self-signed cert (using TPM if available)"
    CONFIGDEV=$(zboot partdev CONFIG)
    mount -o remount,rw $CONFIGDIR
    mkdir -p $CONFIGDIR_PERSIST
    mount -t vfat -o flush,dirsync,noatime,rw "$CONFIGDEV" $CONFIGDIR_PERSIST
    if [ -c $TPM_DEVICE_PATH ] && ! [ -f $DEVICE_KEY_NAME ]; then
        echo "$(date -Ins -u) TPM device is present and allowed, creating TPM based device key"
        if ! $BINDIR/tpmmgr createDeviceCert; then
            echo "$(date -Ins -u) TPM is malfunctioning, falling back to software certs; disabling tpm"
            $BINDIR/tpmmgr createSoftDeviceCert
        fi
    else
        $BINDIR/tpmmgr createSoftDeviceCert
    fi

    # copy certificates, device key and generated TPM credentials from /config to persist config
    if [ -f $DEVICE_CERT_NAME ]; then
        cp $DEVICE_CERT_NAME $CONFIGDIR_PERSIST
    fi
    if [ -f $TPM_CREDENTIAL ]; then
        cp $TPM_CREDENTIAL $CONFIGDIR_PERSIST
    fi
    if [ -f $DEVICE_KEY_NAME ]; then
        cp $DEVICE_KEY_NAME $CONFIGDIR_PERSIST
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
    echo "$(date -Ins -u) Unmount persist config and make in-memory config read-only again"
    mount -o remount,ro $CONFIGDIR
    umount $CONFIGDIR_PERSIST
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
    # Check if NTP servers changed
    # Note that this really belongs in a separate ntpd container
    ns=$(get_ntp_servers)
    if [ -n "$ns" ] && [ "$ns" != "$NTPSERVERS" ]; then
        echo "$(date -Ins -u) NTP server changed from \"$NTPSERVERS\" to \"$ns\", reload NTP sources"
        # Reload NTP sources
        reload_ntp_sources
    fi
    sleep 300
done
