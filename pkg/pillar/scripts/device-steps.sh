#!/bin/sh
#
# Copyright (c) 2018 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

USE_HW_WATCHDOG=1
CONFIGDIR=/config
PERSISTDIR=/persist
PERSISTCONFIGDIR=/persist/config
PERSIST_RKT_DATA_DIR=$PERSISTDIR/rkt
BINDIR=/opt/zededa/bin
TMPDIR=/var/tmp/zededa
DPCDIR=$TMPDIR/DevicePortConfig
FIRSTBOOTFILE=$TMPDIR/first-boot
GCDIR=$PERSISTDIR/config/GlobalConfig
LISPDIR=/opt/zededa/lisp
LOGDIRA=$PERSISTDIR/IMGA/log
LOGDIRB=$PERSISTDIR/IMGB/log
AGENTS0="logmanager ledmanager nim nodeagent"
AGENTS1="zedmanager zedrouter domainmgr downloader verifier identitymgr zedagent lisp-ztr baseosmgr wstunnelclient"
AGENTS="$AGENTS0 $AGENTS1"
TPM_DEVICE_PATH="/dev/tpmrm0"

PATH=$BINDIR:$PATH

echo "$(date -Ins -u) Starting device-steps.sh"
echo "$(date -Ins -u) EVE version: $(cat $BINDIR/versioninfo)"

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
interval = 1
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
pidfile = /var/run/nodeagent.pid
file = /var/run/nodeagent.touch
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
file = /var/run/${AGENT}devinfo.touch
change = 300
EOF
    fi
done

killwait_watchdog() {
    if [ -f /var/run/watchdog.pid ]; then
        wp=$(cat /var/run/watchdog.pid)
        echo "$(date -Ins -u) Killing watchdog $wp"
        kill "$wp"
        # Wait for it to exit so it can be restarted
        while kill -0 "$wp"; do
            echo "$(date -Ins -u) Waiting for watchdog to exit"
            if [ $USE_HW_WATCHDOG = 1 ]; then
                wdctl
            fi
            sleep 1
        done
        echo "$(date -Ins -u) Killed watchdog"
        sync
    fi
}

killwait_watchdog

# In case watchdog is running we restart it with the base file
# Always run watchdog(8) in case we have a hardware watchdog timer to advance
/usr/sbin/watchdog -c $TMPDIR/watchdogbase.conf -F -s &

if ! mount -o remount,flush,dirsync,noatime $CONFIGDIR; then
    echo "$(date -Ins -u) Remount $CONFIGDIR failed"
fi

# XXX Remove DNC and AA directories?
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

CONFIGDEV=$(zboot partdev CONFIG)

P3_FS_TYPE="ext3"
FSCK_FAILED=0
#For systems with ext3 filesystem, try not to change to ext4, since it will brick
#the device when falling back to old images expecting P3 to be ext3. Migrate to ext4
#when we do usb install, this way the transition is more controlled.
if P3=$(zboot partdev P3) && [ -n "$P3" ]; then
    P3_FS_TYPE=$(blkid "$P3"| awk '{print $3}' | sed 's/TYPE=//' | sed 's/"//g')
    echo "$(date -Ins -u) Using $P3 (formatted with $P3_FS_TYPE), for $PERSISTDIR"

    if [ "$P3_FS_TYPE" = "ext3" ]; then
        if ! fsck.ext3 -y "$P3"; then
            FSCK_FAILED=1
        fi
    else
        P3_FS_TYPE="ext4"
        if ! fsck.ext4 -y "$P3"; then
            FSCK_FAILED=1
        fi
    fi

    #Any fsck error (ext3 or ext4), will lead to formatting P3 with ext4
    if [ $FSCK_FAILED = 1 ]; then
        echo "$(date -Ins -u) mkfs.ext4 on $P3 for $PERSISTDIR"
        #Use -F option twice, to avoid any user confirmation in mkfs
        if ! mkfs -t ext4 -v -F -F -O encrypt "$P3"; then
            echo "$(date -Ins -u) mkfs.ext4 $P3 failed"
        else
            echo "$(date -Ins -u) mkfs.ext4 $P3 successful"
            P3_FS_TYPE="ext4"
        fi
    fi

    if [ "$P3_FS_TYPE" = "ext3" ]; then
        if ! mount -t ext3 -o dirsync,noatime "$P3" $PERSISTDIR; then
            echo "$(date -Ins -u) mount $P3 failed"
        fi
    fi
    #On ext4, enable encryption support before mounting.
    if [ "$P3_FS_TYPE" = "ext4" ]; then
        tune2fs -O encrypt "$P3"
        if ! mount -t ext4 -o dirsync,noatime "$P3" $PERSISTDIR; then
            echo "$(date -Ins -u) mount $P3 failed"
        fi
    fi
else
    echo "$(date -Ins -u) No separate $PERSISTDIR partition"
fi

if [ ! -d $LOGDIRA ]; then
    echo "$(date -Ins -u) Creating $LOGDIRA"
    mkdir -p $LOGDIRA
fi
if [ ! -d $LOGDIRB ]; then
    echo "$(date -Ins -u) Creating $LOGDIRB"
    mkdir -p $LOGDIRB
fi

if [ -c $TPM_DEVICE_PATH ] && ! [ -f $CONFIGDIR/disable-tpm ] && [ "$P3_FS_TYPE" = "ext4" ]; then
    #Initialize fscrypt algorithm, hash length etc.
    $BINDIR/vaultmgr -c "$CURPART" setupVaults

    #tpm_in_use might have been wiped out during mkfs above.
    touch $PERSISTCONFIGDIR/tpm_in_use
    sync
fi

if [ ! -d "$PERSIST_RKT_DATA_DIR" ]; then
    echo "$(date -Ins -u) Create $PERSIST_RKT_DATA_DIR"
    mkdir -p "$PERSIST_RKT_DATA_DIR"
    chmod 700 "$PERSIST_RKT_DATA_DIR"
fi

if [ -f $PERSISTDIR/IMGA/reboot-reason ]; then
    echo "IMGA reboot-reason: $(cat $PERSISTDIR/IMGA/reboot-reason)"
fi
if [ -f $PERSISTDIR/IMGB/reboot-reason ]; then
    echo "IMGB reboot-reason: $(cat $PERSISTDIR/IMGB/reboot-reason)"
fi
if [ -f $PERSISTDIR/reboot-reason ]; then
    echo "Common reboot-reason: $(cat $PERSISTDIR/reboot-reason)"
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
echo "$(date -Ins -u) Starting nodeagent"
$BINDIR/nodeagent -c $CURPART &

# Restart watchdog - just for ledmanager so far
killwait_watchdog
/usr/sbin/watchdog -c $TMPDIR/watchdogled.conf -F -s &

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
        if ! mount -t vfat "$SPECIAL" /mnt; then
            # XXX !? will be zero
            echo "$(date -Ins -u) mount $SPECIAL failed: $?"
            return
        fi
        for fd in "usb.json:$DPCDIR" hosts:/config server:/config ; do
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
        if [ -d /mnt/identity ] && [ -f $CONFIGDIR/device.cert.pem ]; then
            echo "$(date -Ins -u) Saving identity to USB stick"
            IDENTITYHASH=$(openssl sha256 $CONFIGDIR/device.cert.pem |awk '{print $2}')
            IDENTITYDIR="/mnt/identity/$IDENTITYHASH"
            [ -d "$IDENTITYDIR" ] || mkdir -p "$IDENTITYDIR"
            cp -p $CONFIGDIR/device.cert.pem "$IDENTITYDIR"
            [ ! -f $CONFIGDIR/onboard.cert.pem ] || cp -p $CONFIGDIR/onboard.cert.pem "$IDENTITYDIR"
            [ ! -f $CONFIGDIR/uuid ] || cp -p $CONFIGDIR/uuid "$IDENTITYDIR"
            cp -p $CONFIGDIR/root-certificate.pem "$IDENTITYDIR"
            [ ! -f $CONFIGDIR/hardwaremodel ] || cp -p $CONFIGDIR/hardwaremodel "$IDENTITYDIR"
            [ ! -f $CONFIGDIR/soft_serial ] || cp -p $CONFIGDIR/soft_serial "$IDENTITYDIR"
            /opt/zededa/bin/hardwaremodel -c >"$IDENTITYDIR/hardwaremodel.dmi"
            /opt/zededa/bin/hardwaremodel -f >"$IDENTITYDIR/hardwaremodel.txt"
            sync
        fi
        if [ -d /mnt/dump ]; then
            echo "$(date -Ins -u) Dumping diagnostics to USB stick"
            # Check if it fits without clobbering an existing tar file
            if tar cf /mnt/dump/diag1.tar /persist/status/ /persist/config /var/run/ /persist/log "/persist/$CURPART/log"; then
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

# Update our local /etc/hosts with entries comming from /config
[ -f /config/hosts ] && cat /config/hosts >> /etc/hosts

# Need to clear old usb files from /config/DevicePortConfig
if [ -f $CONFIGDIR/DevicePortConfig/usb.json ]; then
    echo "$(date -Ins -u) Removing old $CONFIGDIR/DevicePortConfig/usb.json"
    rm -f $CONFIGDIR/DevicePortConfig/usb.json
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
killwait_watchdog
/usr/sbin/watchdog -c $TMPDIR/watchdognim.conf -F -s &

# Print diag output forever on changes
$BINDIR/diag -c $CURPART -f >/dev/console 2>&1 &

# Wait for having IP addresses for a few minutes
# so that we are likely to have an address when we run ntp
echo "$(date -Ins -u) Starting waitforaddr"
$BINDIR/waitforaddr -c $CURPART

# Deposit any diag information from nim
access_usb

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

# The device cert generation needs the current time. Some hardware
# doesn't have a battery-backed clock
YEAR=$(date +%Y)
while [ "$YEAR" = "1970" ]; do
    echo "$(date -Ins -u) It's still 1970; waiting for ntp to advance"
    sleep 10
    YEAR=$(date +%Y)
done

# Restart watchdog ledmanager, client, and nim
killwait_watchdog
/usr/sbin/watchdog -c $TMPDIR/watchdogclient.conf -F -s &

if [ ! -f $CONFIGDIR/device.cert.pem ]; then
    echo "$(date -Ins -u) Generating a device key pair and self-signed cert (using TPM/TEE if available)"
    touch $FIRSTBOOTFILE # For zedagent
    touch $CONFIGDIR/self-register-pending
    sync
    blockdev --flushbufs "$CONFIGDEV"
    if [ -c $TPM_DEVICE_PATH ] && ! [ -f $CONFIGDIR/disable-tpm ]; then
        echo "TPM device is present and allowed, marking mode as tpm-enabled"
        touch $PERSISTCONFIGDIR/tpm_in_use
        sync
        blockdev --flushbufs "$CONFIGDEV"
        $BINDIR/generate-device.sh -b $CONFIGDIR/device -t
    else
        #Just in case, it got disabled in BIOS later on.
        rm -f $PERSISTCONFIGDIR/tpm_in_use
        sync
        blockdev --flushbufs "$CONFIGDEV"
        $BINDIR/generate-device.sh -b $CONFIGDIR/device
    fi
    # Reduce chance that we register with controller and crash before
    # the filesystem has persisted /config/device.cert.* and
    # self-register-pending
    sync
    blockdev --flushbufs "$CONFIGDEV"
    sleep 10
    sync
    blockdev --flushbufs "$CONFIGDEV"
    SELF_REGISTER=1
elif [ -f $CONFIGDIR/self-register-pending ]; then
    echo "$(date -Ins -u) previous self-register failed/killed/rebooted"
    SELF_REGISTER=1
else
    echo "$(date -Ins -u) Using existing device key pair and self-signed cert"
    SELF_REGISTER=0
fi
if [ ! -f $CONFIGDIR/server ] || [ ! -f $CONFIGDIR/root-certificate.pem ]; then
    echo "$(date -Ins -u) No server or root-certificate to connect to. Done"
    exit 0
fi

# Deposit any diag information from nim and onboarding
access_usb

if [ $SELF_REGISTER = 1 ]; then
    rm -f $TMPDIR/zedrouterconfig.json

    # Persistently remember we haven't finished selfRegister in case the device
    # is powered off
    echo "$(date -Ins -u) Self-registering our device certificate"
    if ! [ -f $CONFIGDIR/onboard.cert.pem ] || ! [ -f $CONFIGDIR/onboard.key.pem ]; then
        echo "$(date -Ins -u) Missing onboarding certificate. Giving up"
        exit 1
    fi
    echo "$(date -Ins -u) Starting client selfRegister getUuid"
    if ! $BINDIR/client -c $CURPART selfRegister getUuid; then
        # XXX $? is always zero
        echo "$(date -Ins -u) client selfRegister failed with $?"
        exit 1
    fi
    rm -f $CONFIGDIR/self-register-pending
    sync
    blockdev --flushbufs "$CONFIGDEV"
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

if ! [ -f $PERSISTCONFIGDIR/tpm_in_use ]; then
    # Need a key for device-to-device map-requests
    cp -p $CONFIGDIR/device.key.pem $LISPDIR/lisp-sig.pem
fi

# Setup default amount of space for images
# Half of /persist by default! Convert to kbytes
size=$(df -B1 --output=size $PERSISTDIR | tail -1)
space=$((size / 2048))
mkdir -p /var/tmp/zededa/GlobalDownloadConfig/
echo \{\"MaxSpace\":"$space"\} >/var/tmp/zededa/GlobalDownloadConfig/global.json

# Restart watchdog ledmanager and nim
killwait_watchdog
/usr/sbin/watchdog -c $TMPDIR/watchdognim.conf -F -s &

for AGENT in $AGENTS1; do
    echo "$(date -Ins -u) Starting $AGENT"
    $BINDIR/"$AGENT" -c $CURPART &
done

# Start vaultmgr as a service
$BINDIR/vaultmgr -c "$CURPART" runAsService &

#If logmanager is already running we don't have to strt it.
if ! pgrep logmanager >/dev/null; then
    echo "$(date -Ins -u) Starting logmanager"
    $BINDIR/logmanager -c $CURPART &
fi

# Now run watchdog for all agents
killwait_watchdog
/usr/sbin/watchdog -c $TMPDIR/watchdogall.conf -F -s &

blockdev --flushbufs "$CONFIGDEV"

echo "$(date -Ins -u) Initial setup done"

if [ $MEASURE = 1 ]; then
    ping6 -c 3 -w 1000 zedcontrol
    echo "$(date -Ins -u) Measurement done"
fi

# XXX remove? Looking for watchdog
sleep 5
ps -ef
# XXX redundant but doesn't always start
/usr/sbin/watchdog -c $TMPDIR/watchdogall.conf -F -s &

echo "$(date -Ins -u) Done starting EVE version: $(cat $BINDIR/versioninfo)"

# If there is a USB stick inserted and debug.enable.usb is set, we periodically
# check for any usb.json with DevicePortConfig, deposit our identity,
# and dump any diag information
while true; do
    access_usb
    sleep 300
done
