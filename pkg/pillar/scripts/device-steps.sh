#!/bin/sh
#
# Copyright (c) 2018 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

WATCHDOG_PID=/run/watchdog/pid
WATCHDOG_FILE=/run/watchdog/file
CONFIGDIR=/config
PERSISTDIR=/persist
PERSIST_CERTS=$PERSISTDIR/certs
DEVICE_CERT_NAME="/config/device.cert.pem"
DEVICE_KEY_NAME="/config/device.key.pem"
BOOTSTRAP_CONFIG="${CONFIGDIR}/bootstrap-config.pb"
PERSIST_AGENT_DEBUG=$PERSISTDIR/agentdebug
BINDIR=/opt/zededa/bin
TMPDIR=/persist/tmp
ZTMPDIR=/run/global
DPCDIR=$ZTMPDIR/DevicePortConfig
FIRSTBOOTFILE=$ZTMPDIR/first-boot
FIRSTBOOT=
AGENTS0="zedagent ledmanager nim nodeagent domainmgr loguploader"
AGENTS1="zedmanager zedrouter downloader verifier baseosmgr wstunnelclient volumemgr watcher zfsmanager"
AGENTS="$AGENTS0 $AGENTS1"
TPM_DEVICE_PATH="/dev/tpmrm0"
SECURITYFSPATH=/sys/kernel/security
PATH=$BINDIR:$PATH
TPMINFOTEMPFILE=/var/tmp/tpminfo.txt
DISKSPACE_RECOVERY_LIMIT=70

echo "$(date -Ins -u) Starting device-steps.sh"
echo "$(date -Ins -u) EVE version: $(cat /run/eve-release)"

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
        # Add statically configured NTP server.
        ns="$(echo "$portInfo" | jq -r .NtpServer)"
        res="$res $ns"
        if [ -z "$ns" ]; then
            # If NTP server is not statically configured, add the first NTP server
            # advertised by DHCP server.
            list=$(echo "$portInfo" | jq .NtpServers)
            ns=$(echo "$list" | awk -F\" '{ if (NF > 2) { print $2}}')
            res="$res $ns"
        fi
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

mkdir -p $ZTMPDIR
if [ -d $TMPDIR ]; then
    echo "$(date -Ins -u) Old TMPDIR files:"
    ls -lt $TMPDIR
    rm -rf $TMPDIR
fi
mkdir -p $TMPDIR
export TMPDIR

if ! mount -t securityfs securityfs "$SECURITYFSPATH"; then
    echo "$(date -Ins -u) mounting securityfs failed"
fi

DIRS="$PERSIST_CERTS $PERSIST_AGENT_DEBUG /persist/status/zedclient/OnboardingStatus"

# If /persist/installer/first-boot exists treat this as a first boot
# we rename file to not assume that it is the first boot if we reboot occasionally
if [ -f "$PERSISTDIR/installer/first-boot" ]; then
    mv "$PERSISTDIR/installer/first-boot" "$PERSISTDIR/installer/send-require"
    touch $FIRSTBOOTFILE # For nodeagent
    FIRSTBOOT=1
fi

# If /persist didn't exist or was removed treat this as a first boot
if [ ! -d $PERSIST_CERTS ]; then
    touch $FIRSTBOOTFILE # For nodeagent
    FIRSTBOOT=1
fi

for d in $DIRS; do
    d1=$(dirname "$d")
    if [ ! -d "$d1" ]; then
        echo "$(date -Ins -u) Create $d1"
        mkdir -p "$d1"
        chmod 700 "$d1"
    fi
    if [ ! -d "$d" ]; then
        echo "$(date -Ins -u) Create $d"
        mkdir -p "$d"
        chmod 700 "$d"
    fi
done

# Save any existing checkpoint directory for debugging
rm -rf $PERSIST_AGENT_DEBUG/checkpoint
if [ -d /persist/checkpoint ]; then
    echo "$(date -Ins -u) Saving copy of /persist/checkpoint in /persist/agentdebug"
    cp -rp /persist/checkpoint $PERSIST_AGENT_DEBUG/
fi

# Save any existing /persist/status directory for debugging
rm -rf $PERSIST_AGENT_DEBUG/status
if [ -d /persist/status ]; then
    echo "$(date -Ins -u) Saving copy of /persist/status in /persist/agentdebug"
    cp -rp /persist/status $PERSIST_AGENT_DEBUG/
fi

echo "$(date -Ins -u) Configuration from factory/install:"
(cd $CONFIGDIR || return; ls -l)
echo

CONFIGDEV=$(zboot partdev CONFIG)

# If zedbox is already running we don't have to start it.
if ! pgrep zedbox >/dev/null; then
    echo "$(date -Ins -u) Starting zedbox"
    $BINDIR/zedbox &
    wait_for_touch zedbox
fi

mkdir -p "$WATCHDOG_PID" "$WATCHDOG_FILE"
touch "$WATCHDOG_PID/zedbox.pid" "$WATCHDOG_FILE/zedbox.touch"

if [ -c $TPM_DEVICE_PATH ] && ! [ -f $DEVICE_KEY_NAME ]; then
    # It is a device with TPM, enable disk encryption
    if ! $BINDIR/vaultmgr setupDeprecatedVaults; then
        echo "$(date -Ins -u) device-steps: vaultmgr setupDeprecatedVaults failed"
    fi
fi

if [ -f $PERSISTDIR/reboot-reason ]; then
    echo "Reboot reason: $(cat $PERSISTDIR/reboot-reason)" > /dev/console
elif [ -n "$FIRSTBOOT" ]; then
    echo "Reboot reason: NORMAL: First boot of device - at $(date -Ins -u)" > /dev/console
else
    echo "Reboot reason: UNKNOWN: reboot reason - power failure or crash - at $(date -Ins -u)" > /dev/console
fi

if [ ! -d $PERSISTDIR/log ]; then
    echo "$(date -Ins -u) Creating $PERSISTDIR/log"
    mkdir $PERSISTDIR/log
fi

if [ ! -d $PERSISTDIR/status ]; then
    echo "$(date -Ins -u) Creating $PERSISTDIR/status"
    mkdir $PERSISTDIR/status
fi

if [ -f $CONFIGDIR/restartcounter ]; then
    echo "$(date -Ins -u) move $CONFIGDIR/restartcounter $PERSISTDIR/status"
    mv $CONFIGDIR/restartcounter $PERSISTDIR/status
fi
if [ -f $CONFIGDIR/rebootConfig ]; then
    echo "$(date -Ins -u) move $CONFIGDIR/rebootConfig $PERSISTDIR/status"
    mv $CONFIGDIR/rebootConfig $PERSISTDIR/status
fi
if [ -f $CONFIGDIR/hardwaremodel ]; then
    echo "$(date -Ins -u) move $CONFIGDIR/hardwaremodel $PERSISTDIR/status"
    mv $CONFIGDIR/hardwaremodel $PERSISTDIR/status
fi

# Checking for low diskspace at bootup. If used percentage of
# /persist directory is more than 70% then we will remove the
# following sub directories:
# /persist/log/*
# /persist/newlog/appUpload/*
# /persist/newlog/devUpload/*
# /persist/newlog/keepSentQueue/*
# /persist/newlog/failedUpload/*
diskspace_used=$(df /persist |awk '/\/dev\//{printf("%d",$5);}')
echo "Used percentage of /persist: $diskspace_used"
if [ "$diskspace_used" -ge "$DISKSPACE_RECOVERY_LIMIT" ]
then
    echo "Used percentage of /persist is $diskspace_used more than the limit $DISKSPACE_RECOVERY_LIMIT"
    for DIR in log newlog/keepSentQueue newlog/failedUpload newlog/appUpload newlog/devUpload
    do
        dir_del=$PERSISTDIR/$DIR
        rm -rf "${dir_del:?}/"*
        diskspace_used=$(df /persist |awk '/\/dev\//{printf("%d",$5);}')
        echo "Used percentage of /persist is $diskspace_used after clearing $dir_del"
        if [ "$diskspace_used" -le "$DISKSPACE_RECOVERY_LIMIT" ]
        then
            break
        fi
    done
    diskspace_used=$(df /persist |awk '/\/dev\//{printf("%d",$5);}')
    echo "Used percentage of /persist after recovery: $diskspace_used"
fi

# Run upgradeconverter
mkdir -p /persist/ingested/
echo "$(date -Ins -u) device-steps: Starting upgradeconverter (pre-vault)"
$BINDIR/upgradeconverter pre-vault
echo "$(date -Ins -u) device-steps: upgradeconverter (pre-vault) Completed"

# Start zedagent to make sure we have a ConfigItemValueMap publisher
echo "$(date -Ins -u) Starting zedagent"
$BINDIR/zedagent &
wait_for_touch zedagent

touch "$WATCHDOG_FILE/zedagent.touch"

# BlinkCounter 1 means we have started; might not yet have IP addresses
# client/selfRegister and zedagent update this when the found at least
# one free uplink with IP address(s)
mkdir -p "$ZTMPDIR/LedBlinkCounter"
echo '{"BlinkCounter": 1}' > "$ZTMPDIR/LedBlinkCounter/ledconfig.json"

# If ledmanager is already running we don't have to start it.
# TBD: Should we start it earlier before wwan and wlan services?
if ! pgrep ledmanager >/dev/null; then
    echo "$(date -Ins -u) Starting ledmanager"
    $BINDIR/ledmanager &
    wait_for_touch ledmanager
fi

# Start domainmgr to setup USB hid/storage based on onboarding status
# and config item
echo "$(date -Ins -u) Starting domainmgr"
$BINDIR/domainmgr &
wait_for_touch domainmgr

echo "$(date -Ins -u) Starting nodeagent"
$BINDIR/nodeagent &
wait_for_touch nodeagent

touch "$WATCHDOG_FILE/nodeagent.touch" \
      "$WATCHDOG_FILE/ledmanager.touch" \
      "$WATCHDOG_FILE/domainmgr.touch"

mkdir -p $DPCDIR

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
            $BINDIR/hardwaremodel -f -o "$IDENTITYDIR/hardwaremodel.txt"
            sync
        fi
        if [ -d /mnt/dump ]; then
            echo "$(date -Ins -u) Dumping diagnostics to USB stick"
            # Check if it fits without clobbering an existing tar file
            if ! $BINDIR/tpmmgr saveTpmInfo $TPMINFOTEMPFILE; then
                echo "$(date -Ins -u) saveTpmInfo failed" > $TPMINFOTEMPFILE
            fi
            if tar cf /mnt/dump/diag1.tar /persist/status/ /var/run/ /persist/log "/persist/newlog" $TPMINFOTEMPFILE; then
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

# Get IP addresses
echo "$(date -Ins -u) Starting nim"
$BINDIR/nim &
wait_for_touch nim

# Add nim to watchdog
touch "$WATCHDOG_FILE/nim.touch"

# Print diag output forever on changes
# NOTE: it is safe to do either kill -STOP or an outright
# kill -9 on the following cat process if you want to stop
# receiving those messages on the console.
mkfifo /run/diag.pipe
(while true; do cat; done) < /run/diag.pipe >/dev/console 2>&1 &
$BINDIR/diag -f -o /run/diag.pipe runAsService &

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

echo "$(date -Ins -u) Starting tpmmgr as a service agent"
$BINDIR/tpmmgr runAsService &
wait_for_touch tpmmgr
touch "$WATCHDOG_FILE/tpmmgr.touch"

if ! pgrep loguploader >/dev/null; then
    echo "$(date -Ins -u) Starting loguploader"
    $BINDIR/loguploader &
    wait_for_touch loguploader
    touch "$WATCHDOG_FILE/loguploader.touch"
fi

for AGENT in $AGENTS1; do
    echo "$(date -Ins -u) Starting $AGENT"
    $BINDIR/"$AGENT" &
    wait_for_touch "$AGENT"
done

# Start vaultmgr as a service
$BINDIR/vaultmgr runAsService &
wait_for_touch vaultmgr
touch "$WATCHDOG_FILE/vaultmgr.touch"

# Now run watchdog for all agents
for AGENT in $AGENTS; do
    touch "$WATCHDOG_FILE/$AGENT.touch"
done

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
