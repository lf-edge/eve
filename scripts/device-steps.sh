#!/bin/sh

STARTTIME=`date`
echo "Starting device-steps.sh at" $STARTTIME

CONFIGDIR=/config
PERSISTDIR=/persist
BINDIR=/opt/zededa/bin
TMPDIR=/var/tmp/zededa
DNCDIR=$TMPDIR/DeviceNetworkConfig
DPCDIR=$TMPDIR/DevicePortConfig
LISPDIR=/opt/zededa/lisp
LOGDIRA=$PERSISTDIR/IMGA/log
LOGDIRB=$PERSISTDIR/IMGB/log
AGENTS="zedmanager logmanager ledmanager zedrouter domainmgr downloader verifier identitymgr zedagent lisp-ztr nim"

PATH=$BINDIR:$PATH

WAIT=1
EID_IN_DOMU=0
MEASURE=0
CLEANUP=0
while [ $# != 0 ]; do
    if [ "$1" = -w ]; then
	WAIT=0
    elif [ "$1" = -x ]; then
	EID_IN_DOMU=1
    elif [ "$1" = -m ]; then
	MEASURE=1
    elif [ "$1" = -c ]; then
	CLEANUP=1
    else
	CONFIGDIR=$1
    fi
    shift
done

mkdir -p $TMPDIR

if [ $CLEANUP = 1 -a -d $PERSISTDIR/downloads ]; then
    echo "Cleaning up download dir $PERSISTDIR/downloads"
    rm -rf $PERSISTDIR/downloads
fi
    
echo "Handling restart case at" `date`

# Create the watchdog(8) config files we will use
# XXX should we enable realtime in the kernel?
cat >$TMPDIR/watchdogbase.conf <<EOF
watchdog-device = /dev/watchdog
admin =
#realtime = yes
#priority = 1
interval = 10
logtick  = 60
EOF
cp $TMPDIR/watchdogbase.conf $TMPDIR/watchdogled.conf
echo "pidfile = /var/run/ledmanager.pid" >>$TMPDIR/watchdogled.conf
cp $TMPDIR/watchdogled.conf $TMPDIR/watchdognim.conf
echo "pidfile = /var/run/nim.pid" >>$TMPDIR/watchdognim.conf
cp $TMPDIR/watchdogled.conf $TMPDIR/watchdogclient.conf
echo "pidfile = /var/run/nim.pid" >>$TMPDIR/watchdogclient.conf
echo "pidfile = /var/run/zedclient.pid" >>$TMPDIR/watchdogclient.conf

cp $TMPDIR/watchdogled.conf $TMPDIR/watchdogall.conf
for AGENT in $AGENTS; do
    echo "pidfile = /var/run/$AGENT.pid" >>$TMPDIR/watchdogall.conf
done
# XXX Apply for all agents?
echo "file = /var/run/zedagent.touch" >>$TMPDIR/watchdogall.conf
echo "change = 600" >>$TMPDIR/watchdogall.conf

# If watchdog was running we restart it in a way where it will
# no fail due to killing the agents below.
if [ -f /var/run/watchdog.pid ]; then
    kill `cat /var/run/watchdog.pid`
fi
# Always run watchdog(8) since we have a hardware timer to advance
/usr/sbin/watchdog -c $TMPDIR/watchdogbase.conf -F -s &

# If we are re-running this script, clean up from last run
pgrep zedmanager >/dev/null
if [ $? = 0 ]; then
    killall tail
    killall dmesg
fi

DIRS="$CONFIGDIR $PERSISTDIR $TMPDIR $CONFIGDIR/DevicePortConfig $TMPDIR/DeviceNetworkConfig/ $TMPDIR/AssignableAdapters"

for d in $DIRS; do
    d1=`dirname $d`
    if [ ! -d $d1 ]; then
	# XXX echo "Create $d1"
	mkdir -p $d1
	chmod 700 $d1
    fi
    if [ ! -d $d ]; then
	# XXX echo "Create $d"
	mkdir -p $d
	chmod 700 $d
    fi
done

if [ $CLEANUP = 0 ]; then
    # Add a tag to preserve any downloaded and verified files
    touch /var/tmp/zededa/preserve
fi

# XXX Untested support for re-running all the agents:
# Even with IPC the checkpoint files will be there
pkill zedagent
dir=/var/run/zedagent
if [ -d $dir ]; then
    echo "XXX Removing $dir"
    rm -rf $dir
    AGENT=zedmanager
    dir=/var/run/zedmanager/AppInstanceStatus
    if [ -d $dir ]; then
	while /bin/true; do
	    wait=0
	    for f in $dir/*; do
		# echo "XXX: f is $f"
		if [ "$f" = "$dir/*" ]; then
		    # echo "XXX: skipping $dir"
		    break
		fi
		if [ "$f" = "$dir/global" ]; then
		    echo "Ignoring $f"
		elif [ "$f" = "$dir/restarted" ]; then
		    echo "Ignoring $f"
		else
		    echo "Waiting due to $f"
		    wait=1
		fi
	    done
	    if [ $wait = 1 ]; then
		echo "Waiting for $AGENT to clean up"
		sleep 3
	    else
		break
	    fi
	done
    fi
fi

for AGENT in $AGENTS; do
    pkill $AGENT
done

if [ $CLEANUP = 0 ]; then
    # Remove the preserve tag
    rm /var/tmp/zededa/preserve
fi

echo "Handling restart done at" `date`

echo "Starting" `date`
echo "go-provison version:" `cat $BINDIR/versioninfo`

echo "Configuration from factory/install:"
(cd $CONFIGDIR; ls -l)
echo

P3=`zboot partdev P3`
if [ $? = 0 -a x$P3 != x ]; then
    echo "Using $P3 for $PERSISTDIR"
    fsck.ext3 -y $P3
    if [ $? != 0 ]; then
	echo "mkfs on $P3 for $PERSISTDIR"
	mkfs -t ext3 -v $P3
        if [ $? != 0 ]; then
            echo "mkfs $P3 failed: $?"
	    # Try mounting below
        fi
    fi
    mount -t ext3 $P3 $PERSISTDIR
    if [ $? != 0 ]; then
	echo "mount $P3 failed: $?"
    fi
else
    echo "No separate $PERSISTDIR partition"
fi

echo "Current downloaded files:"
ls -lt $PERSISTDIR/downloads/*/*
echo

# Places for surviving global config and status
if [ ! -d $PERSISTDIR/config/GlobalConfig ]; then
    mkdir -p $PERSISTDIR/config/GlobalConfig
fi
if [ -f $PERSISTDIR/config/GlobalConfig ]; then
    rm -f /var/tmp/zededa/GlobalConfig
fi
ln -s $PERSISTDIR/config/GlobalConfig /var/tmp/zededa/GlobalConfig

if [ ! -d $PERSISTDIR/status ]; then
    mkdir -p $PERSISTDIR/status
fi

CURPART=`zboot curpart`
if [ $? != 0 ]; then
    CURPART="IMGA"
fi

if [ ! -d $LOGDIRA ]; then
    echo "Creating $LOGDIRA"
    mkdir -p $LOGDIRA
fi
if [ ! -d $LOGDIRB ]; then
    echo "Creating $LOGDIRB"
    mkdir -p $LOGDIRB
fi

if [ ! -d $PERSISTDIR/log ]; then
    echo "Creating $PERSISTDIR/log"
    mkdir $PERSISTDIR/log
fi

echo "Set up log capture"
DOM0LOGFILES="ntpd.err.log wlan.err.log wwan.err.log ntpd.out.log wlan.out.log wwan.out.log zededa-tools.out.log zededa-tools.err.log"
for f in $DOM0LOGFILES; do
    tail -c +0 -F /var/log/dom0/$f >$PERSISTDIR/$CURPART/log/$f &
done
tail -c +0 -F /var/log/xen/hypervisor.log >$PERSISTDIR/$CURPART/log/hypervisor.log &
dmesg -T -w -l 1,2,3 --time-format iso >$PERSISTDIR/$CURPART/log/dmesg.log &

if [ -d $LISPDIR/logs ]; then
    echo "Saving old lisp logs in $LISPDIR/logs.old"
    mv $LISPDIR/logs $LISPDIR/logs.old
fi

# Save any device-steps.log's to /persist/log/ so we can look for watchdog's
# in there. Also save dmesg in case it tells something about reboots.
# XXX redundant files to try to capture any info about reboots
tail -c +0 -F /var/log/device-steps.log >$PERSISTDIR/log/device-steps.log."$STARTTIME" &
tail -c +0 -F /var/log/dom0/zededa-tools.out.log >$PERSISTDIR/log/zededa-tools.out.log."$STARTTIME" &
dmesg -T -w -l 1,2,3 --time-format iso >$PERSISTDIR/log/dmesg.log."$STARTTIME" &

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
pgrep ledmanager >/dev/null
if [ $? != 0 ]; then
    echo "Starting ledmanager at" `date`
    ledmanager &
    if [ $WAIT = 1 ]; then
	echo -n "Press any key to continue "; read dummy; echo; echo
    fi
fi

# Restart watchdog - just for ledmanager so far
if [ -f /var/run/watchdog.pid ]; then
    kill `cat /var/run/watchdog.pid`
fi
/usr/sbin/watchdog -c $TMPDIR/watchdogled.conf -F -s &

mkdir -p $DPCDIR
if [ -f $CONFIGDIR/allow-usb-override ]; then
    # Look for a USB stick with a key'ed file
    # If found it replaces any build override file in /config
    # XXX alternative is to use a designated UUID and -t.
    # cgpt find -t ebd0a0a2-b9e5-4433-87c0-68b6b72699c7
    # XXX invent a unique uuid for the above?
    SPECIAL=`cgpt find -l DevicePortConfig`
    echo "Found SPECIAL: $SPECIAL"
    if [ -z $SPECIAL ]; then
	SPECIAL=/dev/sdb1
    fi
    if [ -b $SPECIAL ]; then
	key=`cat /config/root-certificate.pem /config/server /config/device.cert.pem | openssl sha256 | awk '{print $2}'`
	mount -t vfat $SPECIAL /mnt
	if [ $? != 0 ]; then
	    echo "mount $SPECIAL failed: $?"
	else
	    # XXX Remove this code? nim will do testing...
	    echo "Mounted $SPECIAL"
	    keyfile=/mnt/$key.json
	    if [ -f $keyfile ]; then
		echo "Found $keyfile on $SPECIAL"
		echo "Copying from $keyfile to $CONFIGDIR/DevicePortConfig/override.json"
		cp -p $keyfile $CONFIGDIR/DevicePortConfig/override.json
		# No more override allowed
		rm $CONFIGDIR/allow-usb-override
	    else
		echo "$keyfile not found on $SPECIAL"
	    fi
	fi
    fi
fi
if [ -f $CONFIGDIR/DevicePortConfig/override.json ]; then
    echo "Copying from $CONFIGDIR/DevicePortConfig/override.json"
    cp -p $CONFIGDIR/DevicePortConfig/override.json $DPCDIR
fi

# Get IP addresses
echo $BINDIR/nim
$BINDIR/nim &

# Restart watchdog ledmanager and nim
if [ -f /var/run/watchdog.pid ]; then
    kill `cat /var/run/watchdog.pid`
fi
/usr/sbin/watchdog -c $TMPDIR/watchdognim.conf -F -s &

# Wait for having IP addresses for a few minutes
# so that we are likely to have an address when we run ntp
echo $BINDIR/waitforaddr
$BINDIR/waitforaddr

# We need to try our best to setup time *before* we generate the certifiacte.
# Otherwise it may have start date in the future
echo "Check for NTP config"
if [ -f $CONFIGDIR/ntp-server ]; then
    echo -n "Using "
    cat $CONFIGDIR/ntp-server
    # Ubuntu has /usr/bin/timedatectl; ditto Debian
    # ntpdate pool.ntp.org
    # Not installed on Ubuntu
    #
    if [ -f /usr/bin/ntpdate ]; then
	/usr/bin/ntpdate `cat $CONFIGDIR/ntp-server`
    elif [ -f /usr/bin/timedatectl ]; then
	echo "NTP might already be running. Check"
	/usr/bin/timedatectl status
    else
	echo "NTP not installed. Giving up"
	exit 1
    fi
elif [ -f /usr/bin/ntpdate ]; then
    /usr/bin/ntpdate pool.ntp.org
elif [ -f /usr/sbin/ntpd ]; then
    # last ditch attemp to sync up our clock
    # '-p' means peer in some distros; pidfile in others
    /usr/sbin/ntpd -q -n -p pool.ntp.org
    # Run ntpd to keep it in sync.
    /usr/sbin/ntpd -g -p pool.ntp.org
else
    echo "No ntpd"
fi
if [ $WAIT = 1 ]; then
    echo -n "Press any key to continue "; read dummy; echo; echo
fi

# Restart watchdog ledmanager, client, and nim
if [ -f /var/run/watchdog.pid ]; then
    kill `cat /var/run/watchdog.pid`
fi
/usr/sbin/watchdog -c $TMPDIR/watchdogclient.conf -F -s &

if [ ! \( -f $CONFIGDIR/device.cert.pem -a -f $CONFIGDIR/device.key.pem \) ]; then
    echo "Generating a device key pair and self-signed cert (using TPM/TEE if available) at" `date`
    $BINDIR/generate-device.sh $CONFIGDIR/device
    SELF_REGISTER=1
elif [ -f $CONFIGDIR/self-register-failed ]; then
    echo "self-register failed/killed/rebooted"
    $BINDIR/client -r 5 getUuid
    if [ $? != 0 ]; then 
	echo "self-register failed/killed/rebooted; getUuid fail; redoing self-register"
	SELF_REGISTER=1
    else
	echo "self-register failed/killed/rebooted; getUuid pass"
    fi
else
    echo "Using existing device key pair and self-signed cert"
    SELF_REGISTER=0
fi
if [ ! -f $CONFIGDIR/server -o ! -f $CONFIGDIR/root-certificate.pem ]; then
    echo "No server or root-certificate to connect to. Done"
    exit 0
fi

if [ $WAIT = 1 ]; then
    echo -n "Press any key to continue "; read dummy; echo; echo
fi

# XXX should we harden/remove any Linux network services at this point?
echo "Check for WiFi config"
if [ -f $CONFIGDIR/wifi_ssid ]; then
    echo -n "SSID: "
    cat $CONFIGDIR/wifi_ssid
    if [ -f $CONFIGDIR/wifi_credentials ]; then
	echo -n "Wifi credentials: "
	cat $CONFIGDIR/wifi_credentials
    fi
    # XXX actually configure wifi
    # Requires a /etc/network/interfaces.d/wlan0.cfg
    # and /etc/wpa_supplicant/wpa_supplicant.conf
    # Assumes wpa packages are included. Would be in our image?
fi
if [ $WAIT = 1 ]; then
    echo -n "Press any key to continue "; read dummy; echo; echo
fi

if [ $SELF_REGISTER = 1 ]; then
    rm -f $TMPDIR/zedrouterconfig.json
    
    touch $CONFIGDIR/self-register-failed
    echo "Self-registering our device certificate at " `date`
    if [ ! \( -f $CONFIGDIR/onboard.cert.pem -a -f $CONFIGDIR/onboard.key.pem \) ]; then
	echo "Missing onboarding certificate. Giving up"
	exit 1
    fi
    echo $BINDIR/client selfRegister
    $BINDIR/client selfRegister
    if [ $? != 0 ]; then
	echo "client selfRegister failed with $?"
	exit 1
    fi
    rm -f $CONFIGDIR/self-register-failed
    if [ $WAIT = 1 ]; then
	echo -n "Press any key to continue "; read dummy; echo; echo
    fi
    echo $BINDIR/client getUuid 
    $BINDIR/client getUuid
    if [ ! -f $CONFIGDIR/hardwaremodel ]; then
	/opt/zededa/bin/hardwaremodel -c >$CONFIGDIR/hardwaremodel
	echo "Created default hardwaremodel" `/opt/zededa/bin/hardwaremodel -c`
    fi
    # Make sure we set the dom0 hostname, used by LISP nat traversal, to
    # a unique string. Using the uuid
    uuid=`cat $CONFIGDIR/uuid`
    /bin/hostname $uuid
    /bin/hostname >/etc/hostname
    grep -q $uuid /etc/hosts
    if [ $? = 1 ]; then
	# put the uuid in /etc/hosts to avoid complaints
	echo "Adding $uuid to /etc/hosts"
	echo "127.0.0.1 $uuid" >>/etc/hosts
    else
	echo "Found $uuid in /etc/hosts"
    fi
    if [ $WAIT = 1 ]; then
	echo -n "Press any key to continue "; read dummy; echo; echo
    fi
else
    echo "XXX until cloud keeps state across upgrades redo getUuid"
    echo $BINDIR/client getUuid 
    $BINDIR/client getUuid
    if [ ! -f $CONFIGDIR/hardwaremodel ]; then
	# XXX for upgrade path
	# XXX do we need a way to override?
	/opt/zededa/bin/hardwaremodel -c >$CONFIGDIR/hardwaremodel
	echo "Created hardwaremodel" `/opt/zededa/bin/hardwaremodel -c`
    fi

    uuid=`cat $CONFIGDIR/uuid`
    /bin/hostname $uuid
    /bin/hostname >/etc/hostname
    grep -q $uuid /etc/hosts
    if [ $? = 1 ]; then
	# put the uuid in /etc/hosts to avoid complaints
	echo "Adding $uuid to /etc/hosts"
	echo "127.0.0.1 $uuid" >>/etc/hosts
    else
	echo "Found $uuid in /etc/hosts"
    fi
    if [ $WAIT = 1 ]; then
	echo -n "Press any key to continue "; read dummy; echo; echo
    fi
fi

if [ ! -d $LISPDIR ]; then
    echo "Missing $LISPDIR directory. Giving up"
    exit 1
fi

echo "Removing old iptables/ip6tables rules"
# Cleanup any remaining iptables rules from a failed run
iptables -F
ip6tables -F
ip6tables -t raw -F

if [ $SELF_REGISTER = 1 ]; then
    # Do we have a file from the build?
    # For now we do not exit if it is missing, but instead we determine
    # a minimal one on the fly
    model=`$BINDIR/hardwaremodel`
    MODELFILE=${model}.json
    if [ ! -f "$DNCDIR/$MODELFILE" ] ; then
	echo "XXX Missing $DNCDIR/$MODELFILE - generate on the fly"
	echo "Determining uplink interface"
	intf=`$BINDIR/find-uplink.sh $TMPDIR/lisp.config.base`
	if [ "$intf" != "" ]; then
		echo "Found interface $intf based on route to map servers"
	else
		echo "NOT Found interface based on route to map servers. Giving up"
		exit 1    
	fi
	cat <<EOF >"$DNCDIR/$MODELFILE"
{"Uplink":["$intf"], "FreeUplinks":["$intf"]}
EOF
    fi
fi

# Need a key for device-to-device map-requests
cp -p $CONFIGDIR/device.key.pem $LISPDIR/lisp-sig.pem

# Setup default amount of space for images
# Half of /persist by default! Convert to kbytes
size=`df -B1 --output=size $PERSISTDIR | tail -1`
space=`expr $size / 2048`
mkdir -p /var/tmp/zededa/GlobalDownloadConfig/
echo {\"MaxSpace\":$space} >/var/tmp/zededa/GlobalDownloadConfig/global.json

# Now run watchdog for all agents
if [ -f /var/run/watchdog.pid ]; then
    kill `cat /var/run/watchdog.pid`
fi
/usr/sbin/watchdog -c $TMPDIR/watchdogall.conf -F -s &

echo "Starting verifier at" `date`
verifier &
if [ $WAIT = 1 ]; then
    echo -n "Press any key to continue "; read dummy; echo; echo
fi

echo "Starting ZedManager at" `date`
zedmanager &
if [ $WAIT = 1 ]; then
    echo -n "Press any key to continue "; read dummy; echo; echo
fi

echo "Starting downloader at" `date`
downloader &
if [ $WAIT = 1 ]; then
    echo -n "Press any key to continue "; read dummy; echo; echo
fi

echo "Starting identitymgr at" `date`
identitymgr &
if [ $WAIT = 1 ]; then
    echo -n "Press any key to continue "; read dummy; echo; echo
fi

echo "Starting ZedRouter at" `date`
zedrouter &
if [ $WAIT = 1 ]; then
    echo -n "Press any key to continue "; read dummy; echo; echo
fi

echo "Starting DomainMgr at" `date`
domainmgr &
# Do something
if [ $WAIT = 1 ]; then
    echo -n "Press any key to continue "; read dummy; echo; echo
fi

echo "Starting zedagent at" `date`
zedagent &
if [ $WAIT = 1 ]; then
    echo -n "Press any key to continue "; read dummy; echo; echo
fi

echo "Starting lisp-ztr at" `date`
lisp-ztr &
if [ $WAIT = 1 ]; then
    echo -n "Press any key to continue "; read dummy; echo; echo
fi

#If logmanager is already running we don't have to start it.
pgrep logmanager >/dev/null
if [ $? != 0 ]; then
    echo "Starting logmanager at" `date`
    logmanager &
    if [ $WAIT = 1 ]; then
	echo -n "Press any key to continue "; read dummy; echo; echo
    fi
fi

echo "Initial setup done at" `date`

# Print the initial diag output
/opt/zededa/bin/diag

if [ $MEASURE = 1 ]; then
    ping6 -c 3 -w 1000 zedcontrol
    echo "Measurement done at" `date`
fi
