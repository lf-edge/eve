#!/bin/sh
#
# Copyright (c) 2018 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

USE_HW_WATCHDOG=1
CONFIGDIR=/config
PERSISTDIR=/persist
BINDIR=/opt/zededa/bin
TMPDIR=/var/tmp/zededa
DPCDIR=$TMPDIR/DevicePortConfig
GCDIR=$PERSISTDIR/config/GlobalConfig
LISPDIR=/opt/zededa/lisp
LOGDIRA=$PERSISTDIR/IMGA/log
LOGDIRB=$PERSISTDIR/IMGB/log
AGENTS0="logmanager ledmanager nim"
AGENTS1="zedmanager zedrouter domainmgr downloader verifier identitymgr zedagent lisp-ztr baseosmgr wstunnelclient"
AGENTS="$AGENTS0 $AGENTS1"

PATH=$BINDIR:$PATH

echo "$(date -Ins -u) Starting device-steps.sh"
echo "$(date -Ins -u) go-provision version: $(cat $BINDIR/versioninfo)"

MEASURE=0
while [ $# != 0 ]; do
    if [ "$1" = -h ]; then
        USE_HW_WATCHDOG=0
    elif [ "$1" = -m ]; then
        MEASURE=1
    elif [ "$1" = -w ]; then
        echo "$(date -Ins -u) Got old -w"
    else
        echo "Usage: device-steps.sh [-h] [-m]"
        exit 1
    fi
    shift
done

mkdir -p $TMPDIR

if [ -c /dev/watchdog ]; then
    if [ $USE_HW_WATCHDOG = 0 ]; then
        echo "$(date -Ins -u) Disabling use of /dev/watchdog"
        wdctl /dev/watchdog
    fi
else
    echo "$(date -Ins -u) Platform has no /dev/watchdog"
    USE_HW_WATCHDOG=0
fi

# Create the watchdog(8) config files we will use
# XXX should we enable realtime in the kernel?
if [ $USE_HW_WATCHDOG = 1 ]; then
    cat >$TMPDIR/watchdogbase.conf <<EOF
watchdog-device = /dev/watchdog
EOF
else
    cat >$TMPDIR/watchdogbase.conf <<EOF
EOF
fi
cat >>$TMPDIR/watchdogbase.conf <<EOF
admin =
#realtime = yes
#priority = 1
interval = 10
logtick  = 60
repair-binary=/opt/zededa/bin/watchdog-report.sh
pidfile = /var/run/xen/qemu-dom0.pid
pidfile = /var/run/xen/xenconsoled.pid
pidfile = /var/run/xen/xenstored.pid
pidfile = /var/run/crond.pid
EOF
# XXX Other processes we should potentially watch but they run outside
# of this container:
# sshd.pid
# services.linuxkit/zededa-tools/init.pid
# services.linuxkit/wwan/init.pid
# services.linuxkit/wlan/init.pid
# services.linuxkit/ntpd/init.pid
# services.linuxkit/guacd/init.pid

cp $TMPDIR/watchdogbase.conf $TMPDIR/watchdogled.conf
cat >>$TMPDIR/watchdogled.conf <<EOF
pidfile = /var/run/ledmanager.pid
file = /var/run/ledmanager.touch
change = 300
EOF
cp $TMPDIR/watchdogled.conf $TMPDIR/watchdognim.conf
cat >> $TMPDIR/watchdognim.conf <<EOF
pidfile = /var/run/nim.pid
file = /var/run/nim.touch
change = 300
EOF
cp $TMPDIR/watchdogled.conf $TMPDIR/watchdogclient.conf
cat >>$TMPDIR/watchdogclient.conf <<EOF
pidfile = /var/run/zedclient.pid
pidfile = /var/run/nim.pid
pidfile = /var/run/ntpd.pid
file = /var/run/nim.touch
change = 300
EOF

cp $TMPDIR/watchdogled.conf $TMPDIR/watchdogall.conf
echo "pidfile = /var/run/ntpd.pid" >>$TMPDIR/watchdogall.conf
for AGENT in $AGENTS; do
    echo "pidfile = /var/run/$AGENT.pid" >>$TMPDIR/watchdogall.conf
    if [ "$AGENT" = "lisp-ztr" ]; then
        continue
    fi
    echo "file = /var/run/$AGENT.touch" >>$TMPDIR/watchdogall.conf
    echo "change = 300" >>$TMPDIR/watchdogall.conf
    if [ "$AGENT" = "zedagent" ]; then
        cat >>$TMPDIR/watchdogall.conf <<EOF
file = /var/run/${AGENT}config.touch
change = 300
file = /var/run/${AGENT}metrics.touch
change = 300
EOF
    fi
done

# In case watchdog is running we restart it with the base file
if [ -f /var/run/watchdog.pid ]; then
    # XXX define killwait function?
    kill "$(cat /var/run/watchdog.pid)"
    sleep 5 # Wait for it to exit so it can be restarted
fi
# Always run watchdog(8) in case we have a hardware watchdog timer to advance
/usr/sbin/watchdog -c $TMPDIR/watchdogbase.conf -F -s &

if ! mount -o remount,flush,dirsync,noatime $CONFIGDIR; then
    echo "$(date -Ins -u) Remount $CONFIGDIR failed"
fi

DIRS="$CONFIGDIR $PERSISTDIR $TMPDIR $CONFIGDIR/DevicePortConfig $TMPDIR/DeviceNetworkConfig/ $TMPDIR/AssignableAdapters"

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

echo "$(date -Ins -u) Configuration from factory/install:"
(cd $CONFIGDIR || return; ls -l)
echo

if P3=$(zboot partdev P3) && [ -n "$P3" ]; then
    echo "$(date -Ins -u) Using $P3 for $PERSISTDIR"
    if ! fsck.ext3 -y "$P3"; then
        echo "$(date -Ins -u) mkfs on $P3 for $PERSISTDIR"
        # XXX note that if we have a bad ext3 partition this will ask questions
        # Need to either dd zeros over the partition of feed "yes" into mkfs.
        if ! mkfs -t ext3 -v "$P3"; then
            echo "$(date -Ins -u) mkfs $P3 failed: $?"
            # Try mounting below
        fi
    fi
    if ! mount -t ext3 -o dirsync,noatime "$P3" $PERSISTDIR; then
        echo "$(date -Ins -u) mount $P3 failed: $?"
    fi
else
    echo "$(date -Ins -u) No separate $PERSISTDIR partition"
fi

echo "$(date -Ins -u) Current downloaded files:"
ls -lt $PERSISTDIR/downloads/*/*
echo

# Copy any GlobalConfig from /config
dir=$CONFIGDIR/GlobalConfig
for f in "$dir"/*.json; do
    if [ "$f" = "$dir/*.json" ]; then
        break
    fi
    if [ ! -d $GCDIR ]; then
        mkdir -p $GCDIR
    fi
    echo "$(date -Ins -u) Copying from $f to $GCDIR"
    cp -p "$f" $GCDIR
done

if ! CURPART=$(zboot curpart); then
    CURPART="IMGA"
fi

if [ ! -d $LOGDIRA ]; then
    echo "$(date -Ins -u) Creating $LOGDIRA"
    mkdir -p $LOGDIRA
fi
if [ ! -d $LOGDIRB ]; then
    echo "$(date -Ins -u) Creating $LOGDIRB"
    mkdir -p $LOGDIRB
fi

if [ ! -d $PERSISTDIR/log ]; then
    echo "$(date -Ins -u) Creating $PERSISTDIR/log"
    mkdir $PERSISTDIR/log
fi

echo "$(date -Ins -u) Set up log capture"
DOM0LOGFILES="ntpd.err.log wlan.err.log wwan.err.log ntpd.out.log wlan.out.log wwan.out.log pillar.out.log pillar.err.log"
for f in $DOM0LOGFILES; do
    echo "$(date -Ins -u) Starting $f" >$PERSISTDIR/$CURPART/log/"$f"
    tail -c +0 -F /var/log/dom0/"$f" >>$PERSISTDIR/$CURPART/log/"$f" &
done
tail -c +0 -F /var/log/device-steps.log >>$PERSISTDIR/$CURPART/log/device-steps.log &
echo "$(date -Ins -u) Starting hypervisor.log" >>$PERSISTDIR/$CURPART/log/hypervisor.log
tail -c +0 -F /var/log/xen/hypervisor.log >>$PERSISTDIR/$CURPART/log/hypervisor.log &
echo "$(date -Ins -u) Starting dmesg" >>$PERSISTDIR/$CURPART/log/dmesg.log
dmesg -T -w -l 1,2,3 --time-format iso >>$PERSISTDIR/$CURPART/log/dmesg.log &

if [ -d $LISPDIR/logs ]; then
    echo "$(date -Ins -u) Saving old lisp logs in $LISPDIR/logs.old"
    mv $LISPDIR/logs $LISPDIR/logs.old
fi

# Save any device-steps.log's to /persist/log/ so we can look for watchdog's
# in there. Also save dmesg in case it tells something about reboots.
tail -c +0 -F /var/log/device-steps.log >>$PERSISTDIR/log/device-steps.log &
echo "$(date -Ins -u) Starting pillar" >>$PERSISTDIR/log/pillar.out.log
tail -c +0 -F /var/log/dom0/pillar.out.log >>$PERSISTDIR/log/pillar.out.log &
echo "$(date -Ins -u) Starting dmesg" >>$PERSISTDIR/log/dmesg.log
dmesg -T -w -l 1,2,3 --time-format iso >>$PERSISTDIR/log/dmesg.log &

#
# Remove any old symlink to different IMG directory
rm -f $LISPDIR/logs
if [ ! -d $PERSISTDIR/$CURPART/log/lisp ]; then
    mkdir -p $PERSISTDIR/$CURPART/log/lisp
fi
ln -s $PERSISTDIR/$CURPART/log/lisp $LISPDIR/logs

# BlinkCounter 1 means we have started; might not yet have IP addresses
# client/selfRegister and zedagent update this when the found at least
# one free uplink with IP address(s)
mkdir -p /var/tmp/zededa/LedBlinkCounter/
echo '{"BlinkCounter": 1}' > '/var/tmp/zededa/LedBlinkCounter/ledconfig.json'

# If ledmanager is already running we don't have to start it.
# TBD: Should we start it earlier before wwan and wlan services?
if ! pgrep ledmanager >/dev/null; then
    echo "$(date -Ins -u) Starting ledmanager"
    ledmanager &
fi

# Restart watchdog - just for ledmanager so far
if [ -f /var/run/watchdog.pid ]; then
    kill "$(cat /var/run/watchdog.pid)"
    sleep 5 # Wait for it to exit so it can be restarted
fi
/usr/sbin/watchdog -c $TMPDIR/watchdogled.conf -F -s &

mkdir -p $DPCDIR

# Look for a USB stick with a usb.json file
# If found it replaces any build override file in /config
# XXX note that filesystem on USB stick needs to be labeled with DevicePortConfig
SPECIAL=$(cgpt find -l DevicePortConfig)
if [ -n "$SPECIAL" ] && [ -b "$SPECIAL" ]; then
    echo "$(date -Ins -u) Found USB with DevicePortConfig: $SPECIAL"
    if ! mount -t vfat "$SPECIAL" /mnt; then
        echo "$(date -Ins -u) mount $SPECIAL failed: $?"
    else
        keyfile=/mnt/usb.json
        if [ -f $keyfile ]; then
            echo "$(date -Ins -u) Found $keyfile on $SPECIAL"
            echo "$(date -Ins -u) Copying from $keyfile to $CONFIGDIR/DevicePortConfig/"
            cp $keyfile $CONFIGDIR/DevicePortConfig/
        else
            echo "$(date -Ins -u) $keyfile not found on $SPECIAL"
        fi
    fi
fi

# Copy any DevicePortConfig from /config
dir=$CONFIGDIR/DevicePortConfig
for f in "$dir"/*.json; do
    if [ "$f" = "$dir/*.json" ]; then
        break
    fi
    echo "$(date -Ins -u) Copying from $f to $DPCDIR"
    cp -p "$f" $DPCDIR
done

# Get IP addresses
echo "$(date -Ins -u) Starting nim"
$BINDIR/nim -c $CURPART &

# Restart watchdog ledmanager and nim
if [ -f /var/run/watchdog.pid ]; then
    kill "$(cat /var/run/watchdog.pid)"
    sleep 5 # Wait for it to exit so it can be restarted
fi
/usr/sbin/watchdog -c $TMPDIR/watchdognim.conf -F -s &

# Wait for having IP addresses for a few minutes
# so that we are likely to have an address when we run ntp
echo "$(date -Ins -u) Starting waitforaddr"
$BINDIR/waitforaddr -c $CURPART

# We need to try our best to setup time *before* we generate the certifiacte.
# Otherwise the cert may have start date in the future or in 1970
echo "$(date -Ins -u) Check for NTP config"
if [ -f /usr/sbin/ntpd ]; then
    # '-p' means peer in some distros; pidfile in others
    /usr/sbin/ntpd -q -n -p pool.ntp.org
    # Run ntpd to keep it in sync.
    /usr/sbin/ntpd -g -p pool.ntp.org
else
    echo "$(date -Ins -u) No ntpd"
fi

# Print the initial diag output
# If we don't have a network this takes many minutes. Backgrounded
$BINDIR/diag -c $CURPART >/dev/console 2>&1 &

# The device cert generation needs the current time. Some hardware
# doesn't have a battery-backed clock
YEAR=$(date +%Y)
while [ "$YEAR" = "1970" ]; do
    echo "$(date -Ins -u) It's still 1970; waiting for ntp to advance"
    sleep 10
    YEAR=$(date +%Y)
done

# Restart watchdog ledmanager, client, and nim
if [ -f /var/run/watchdog.pid ]; then
    kill "$(cat /var/run/watchdog.pid)"
    sleep 5 # Wait for it to exit so it can be restarted
fi
/usr/sbin/watchdog -c $TMPDIR/watchdogclient.conf -F -s &

if ! [ -f $CONFIGDIR/device.cert.pem ] || ! [ -f $CONFIGDIR/device.key.pem ]; then
    echo "$(date -Ins -u) Generating a device key pair and self-signed cert (using TPM/TEE if available)"
    touch $CONFIGDIR/self-register-pending
    sync
    $BINDIR/generate-device.sh $CONFIGDIR/device
    # Reduce chance that we register with controller and crash before
    # the filesystem has persisted /config/device.cert.* and
    # self-register-pending
    sync
    sleep 10
    sync
    SELF_REGISTER=1
elif [ -f $CONFIGDIR/self-register-pending ]; then
    echo "$(date -Ins -u) self-register failed/killed/rebooted"
    if ! $BINDIR/client -c $CURPART -r 5 getUuid; then
        echo "$(date -Ins -u) self-register failed/killed/rebooted; getUuid fail; redoing self-register"
        SELF_REGISTER=1
    else
        echo "$(date -Ins -u) self-register failed/killed/rebooted; getUuid pass hence already registered"
        rm -f $CONFIGDIR/self-register-pending
        sync
    fi
else
    echo "$(date -Ins -u) Using existing device key pair and self-signed cert"
    SELF_REGISTER=0
fi
if [ ! -f $CONFIGDIR/server ] || [ ! -f $CONFIGDIR/root-certificate.pem ]; then
    echo "$(date -Ins -u) No server or root-certificate to connect to. Done"
    exit 0
fi

if [ $SELF_REGISTER = 1 ]; then
    rm -f $TMPDIR/zedrouterconfig.json

    # Persistently remember we haven't finished selfRegister in case the device
    # is powered off
    echo "$(date -Ins -u) Self-registering our device certificate"
    if ! [ -f $CONFIGDIR/onboard.cert.pem ] || ! [ -f $CONFIGDIR/onboard.key.pem ]; then
        echo "$(date -Ins -u) Missing onboarding certificate. Giving up"
        exit 1
    fi
    echo "$(date -Ins -u) Starting client selfRegister"
    if ! $BINDIR/client -c $CURPART selfRegister; then
        echo "$(date -Ins -u) client selfRegister failed with $?"
        exit 1
    fi
    rm -f $CONFIGDIR/self-register-pending
    sync
    echo "$(date -Ins -u) Starting client getUuid"
    $BINDIR/client -c $CURPART getUuid
    if [ ! -f $CONFIGDIR/hardwaremodel ]; then
        /opt/zededa/bin/hardwaremodel -c >$CONFIGDIR/hardwaremodel
        echo "$(date -Ins -u) Created default hardwaremodel $(/opt/zededa/bin/hardwaremodel -c)"
    fi
    # Make sure we set the dom0 hostname, used by LISP nat traversal, to
    # a unique string. Using the uuid
    uuid=$(cat $CONFIGDIR/uuid)
    /bin/hostname "$uuid"
    /bin/hostname >/etc/hostname
    if ! grep -q "$uuid" /etc/hosts; then
        # put the uuid in /etc/hosts to avoid complaints
        echo "$(date -Ins -u) Adding $uuid to /etc/hosts"
        echo "127.0.0.1 $uuid" >>/etc/hosts
    else
        echo "$(date -Ins -u) Found $uuid in /etc/hosts"
    fi
else
    echo "$(date -Ins -u) Get UUID in in case device was deleted and recreated with same device cert"
    echo "$(date -Ins -u) Starting client getUuid"
    $BINDIR/client -c $CURPART getUuid
    if [ ! -f $CONFIGDIR/hardwaremodel ]; then
        echo "$(date -Ins -u) XXX /config/hardwaremodel missing; creating"
        /opt/zededa/bin/hardwaremodel -c >$CONFIGDIR/hardwaremodel
        echo "$(date -Ins -u) Created hardwaremodel $(/opt/zededa/bin/hardwaremodel -c)"
    fi

    uuid=$(cat $CONFIGDIR/uuid)
    /bin/hostname "$uuid"
    /bin/hostname >/etc/hostname

    if ! grep -q "$uuid" /etc/hosts; then
        # put the uuid in /etc/hosts to avoid complaints
        echo "$(date -Ins -u) Adding $uuid to /etc/hosts"
        echo "127.0.0.1 $uuid" >>/etc/hosts
    else
        echo "$(date -Ins -u) Found $uuid in /etc/hosts"
    fi
fi

if [ ! -d $LISPDIR ]; then
    echo "$(date -Ins -u) Missing $LISPDIR directory. Giving up"
    exit 1
fi

# Need a key for device-to-device map-requests
cp -p $CONFIGDIR/device.key.pem $LISPDIR/lisp-sig.pem

# Setup default amount of space for images
# Half of /persist by default! Convert to kbytes
size=$(df -B1 --output=size $PERSISTDIR | tail -1)
space=$((size / 2048))
mkdir -p /var/tmp/zededa/GlobalDownloadConfig/
echo \{\"MaxSpace\":"$space"\} >/var/tmp/zededa/GlobalDownloadConfig/global.json

# Restart watchdog ledmanager and nim
if [ -f /var/run/watchdog.pid ]; then
    kill "$(cat /var/run/watchdog.pid)"
    sleep 5 # Wait for it to exit so it can be restarted
fi
/usr/sbin/watchdog -c $TMPDIR/watchdognim.conf -F -s &

for AGENT in $AGENTS1; do
    echo "$(date -Ins -u) Starting $AGENT"
    $BINDIR/"$AGENT" -c $CURPART &
done

#If logmanager is already running we don't have to strt it.
if ! pgrep logmanager >/dev/null; then
    echo "$(date -Ins -u) Starting logmanager"
    $BINDIR/logmanager -c $CURPART &
fi

# Now run watchdog for all agents
if [ -f /var/run/watchdog.pid ]; then
    kill "$(cat /var/run/watchdog.pid)"
    sleep 5 # Wait for it to exit so it can be restarted
fi
/usr/sbin/watchdog -c $TMPDIR/watchdogall.conf -F -s &

echo "$(date -Ins -u) Initial setup done"

# Print diag output forever on changes
$BINDIR/diag -c $CURPART -f >/dev/console 2>&1 &

if [ $MEASURE = 1 ]; then
    ping6 -c 3 -w 1000 zedcontrol
    echo "$(date -Ins -u) Measurement done"
fi
