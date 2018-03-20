#!/bin/sh

echo "Starting device-steps.sh at" `date`

CONFIGDIR=/config
PERSISTDIR=/persist
BINDIR=/opt/zededa/bin
PROVDIR=$BINDIR
TMPDIR=/var/tmp/zededa
DNCDIR=/var/tmp/zededa/DeviceNetworkConfig
LISPDIR=/opt/zededa/lisp
LOGDIRA=$PERSISTDIR/IMGA/log
LOGDIRB=$PERSISTDIR/IMGB/log
AGENTS="logmanager ledmanager zedrouter domainmgr downloader verifier identitymgr eidregister zedagent"
ALLAGENTS="zedmanager $AGENTS"

PATH=$BINDIR:$PATH

OLDFLAG=
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
    elif [ "$1" = -o ]; then
	OLDFLAG=$1
    elif [ "$1" = -c ]; then
	CLEANUP=1
    else
	CONFIGDIR=$1
    fi
    shift
done

mkdir -p $TMPDIR

if [ -d /var/tmp/zedmanager/downloads ]; then
    echo "Cleaning up old download dir: /var/tmp/zedmanager/downloads"
    rm -rf /var/tmp/zedmanager/downloads
fi
if [ -d /var/tmp/domainmgr/img ]; then
    echo "Removing old domU img dir: /var/tmp/domainmgr/img"
    rm -rf /var/tmp/domainmgr/img
fi

if [ $CLEANUP = 1 -a -d $PERSISTDIR/downloads ]; then
    echo "Cleaning up download dir $PERSISTDIR/downloads"
    rm -rf $PERSISTDIR/downloads
fi
    
# Move any uuid file to /config
if [ -f $TMPDIR/uuid ]; then
    if [ -f $CONFIGDIR/uuid ]; then
	echo "Removing old $TMPDIR/uuid"
	rm -f $TMPDIR/uuid
    else
	echo "Moving old $TMPDIR/uuid to $CONFIGDIR/uuid"
	mv $TMPDIR/uuid $CONFIGDIR/uuid
    fi
fi

echo "Configuration from factory/install:"
(cd $CONFIGDIR; ls -l)
echo

echo "Handling restart case at" `date`
# XXX should we check if zedmanager is running?

echo "Removing old stale files"
# Remove internal config files
pkill zedmanager
if [ x$OLDFLAG = x ]; then
	echo "Removing old zedmanager config files"
	rm -rf /var/tmp/zedmanager/config/*.json
fi

echo "Removing old zedmanager status files"
rm -rf /var/run/zedmanager/status/*.json

# The following is a workaround for a racecondition between different agents
# Make sure we have the required directories in place
DIRS="$CONFIGDIR $PERSISTDIR $TMPDIR /var/tmp/ledmanager/config/ /var/tmp/domainmgr/config/ /var/tmp/verifier/config/ /var/tmp/downloader/config/ /var/tmp/zedmanager/config/ /var/tmp/identitymgr/config/ /var/tmp/zedrouter/config/ /var/run/domainmgr/status/ /var/run/downloader/status/ /var/run/zedmanager/status/ /var/run/eidregister/status/ /var/run/zedrouter/status/ /var/run/identitymgr/status/ /var/tmp/zededa/DeviceNetworkConfig/ /var/run/zedrouter/DeviceNetworkStatus/ /var/tmp/zededa/AssignableAdapters"
for d in $DIRS; do
    d1=`dirname $d`
    if [ ! -d $d1 ]; then
	mkdir -p $d1
	chmod 700 $d1
    fi
    if [ ! -d $d ]; then
	mkdir -p $d
	chmod 700 $d
    fi
done

# Some agents have multiple config and status files
AGENTDIRS="$AGENTS verifier/appImg.obj verifier/baseOs.obj downloader/appImg.obj downloader/baseOs.obj downloader/cert.obj"
for AGENTDIR in $AGENTDIRS; do
    d=`dirname $AGENTDIR`
    if [ $d != '.' ]; then
	AGENT=$d
    else
	AGENT=$AGENTDIR
    fi
    # echo "XXX Looking in config $AGENTDIR for $AGENT"
    if [ ! -d /var/tmp/$AGENTDIR ]; then
	continue
    fi
    dir=/var/tmp/$AGENTDIR/config
    if [ ! -d $dir ]; then
	continue
    fi
    # echo "XXX Looking in config $dir"
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
	    # Note that this deletes domainmgr config which, unlike a reboot,
	    # will remove the rootfs copy in /persist/img/
	    echo "Deleting config file: $f"
	    rm -f "$f"
	fi
    done
done

# Try to cleanup in case the agents are running or /var/run files are left over
# If agents are running then the deletion of the /var/tmp/ files should
# cleaned up all but /var/run/zedmanager/*.json

if [ $CLEANUP = 0 ]; then
    # Add a tag to preserve any downloaded and verified files
    touch /var/tmp/verifier/config/preserve
fi

# If agents are running wait for the status files to disappear
for AGENTDIR in $AGENTDIRS; do
    d=`dirname $AGENTDIR`
    if [ $d != '.' ]; then
	AGENT=$d
    else
	AGENT=$AGENTDIR
    fi
    # echo "XXX Looking in status $AGENTDIR for $AGENT"
    if [ ! -d /var/run/$AGENT ]; then
	# Needed for zedagent
	pkill $AGENT
	continue
    fi
    if [ $AGENT = "verifier" ]; then
	echo "Skipping check for /var/run/$AGENTDIR/status"
	pkill $AGENT
	continue
    fi
    dir=/var/run/$AGENTDIR/status
    if [ ! -d $dir ]; then
	continue
    fi
    # echo "XXX Looking in status $dir"
    pid=`pgrep $AGENT`
    if [ "$pid" != "" ]; then
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
    else
	for f in $dir/*; do
	    # echo "XXX: f is $f"
	    if [ "$f" = "$dir/*" ]; then
		# echo "XXX: skipping $dir"
		break
	    fi
	    echo "Deleting status file: $f"
	    rm -f "$f"
	done
    fi
done
for AGENT in $AGENTS; do
    pkill $AGENT
done

if [ $CLEANUP = 0 ]; then
    # Remove the preserve tag
    rm /var/tmp/verifier/config/preserve
fi

echo "Handling restart done at" `date`

if [ ! -d $LOGDIRA ]; then
    echo "Creating $LOGDIRA"
    mkdir -p $LOGDIRA
fi
if [ ! -d $LOGDIRB ]; then
    echo "Creating $LOGDIRB"
    mkdir -p $LOGDIRB
fi

echo "Set up log capture"
CURPART=`zboot curpart`
if [ $? != 0 ]; then
    CURPART="IMGA"
fi
DOM0LOGFILES="dhcpcd.err.log ntpd.err.log wlan.err.log wwan.err.log zededa-tools.err.log dhcpcd.out.log ntpd.out.log wlan.out.log wwan.out.log zededa-tools.out.log"
for f in $DOM0LOGFILES; do
    tail -c +0 -F /var/log/dom0/$f >/persist/$CURPART/log/$f &
done
tail -c +0 -F /var/log/xen/hypervisor.log >/persist/$CURPART/log/hypervisor.log &
dmesg -T -w --time-format iso >/persist/$CURPART/log/dmesg.log &

if [ -d $LISPDIR/logs ]; then
    echo "Saving old lisp logs in $LISPDIR/logs.old"
    mv $LISPDIR/logs $LISPDIR/logs.old
fi
# Remove any old symlink to different IMG directory
rm -f $LISPDIR/logs
if [ ! -d /persist/$CURPART/log/lisp ]; then
    mkdir -p /persist/$CURPART/log/lisp
fi
ln -s /persist/$CURPART/log/lisp $LISPDIR/logs

# BlinkCounter 1 means we have started; might not yet have IP addresses
# client/selfRegister and zedagent update this when the found at least
# one free uplink with IP address(s)
echo '{"BlinkCounter": 1}' > '/var/tmp/ledmanager/config/ledconfig.json'

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

# We need to try our best to setup time *before* we generate the certifiacte.
# Otherwise it may have start date in the future
echo "Check for NTP config"
if [ -f $CONFIGDIR/ntp-server ]; then
    echo -n "Using "
    cat $CONFIGDIR/ntp-server
    # XXX is ntp service running/installed?
    # XXX actually configure ntp
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
else
    echo "No ntpd"
fi
if [ $WAIT = 1 ]; then
    echo -n "Press any key to continue "; read dummy; echo; echo
fi


if [ ! \( -f $CONFIGDIR/device.cert.pem -a -f $CONFIGDIR/device.key.pem \) ]; then
    echo "Generating a device key pair and self-signed cert (using TPM/TEE if available) at" `date`
    $PROVDIR/generate-device.sh $CONFIGDIR/device
    SELF_REGISTER=1
elif [ -f $TMPDIR/self-register-failed ]; then
    echo "self-register failed/killed/rebooted; redoing self-register"
    SELF_REGISTER=1
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
    
    touch $TMPDIR/self-register-failed
    echo "Self-registering our device certificate at " `date`
    if [ ! \( -f $CONFIGDIR/onboard.cert.pem -a -f $CONFIGDIR/onboard.key.pem \) ]; then
	echo "Missing onboarding certificate. Giving up"
	exit 1
    fi
    echo $BINDIR/client $OLDFLAG -d $CONFIGDIR selfRegister
    $BINDIR/client $OLDFLAG -d $CONFIGDIR selfRegister
    rm -f $TMPDIR/self-register-failed
    if [ $WAIT = 1 ]; then
	echo -n "Press any key to continue "; read dummy; echo; echo
    fi
    echo $BINDIR/client $OLDFLAG -d $CONFIGDIR getUuid 
    $BINDIR/client $OLDFLAG -d $CONFIGDIR getUuid

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
elif [ x$OLDFLAG = x ]; then
    echo "XXX until cloud keeps state across upgrades redo getUuid"
    echo $BINDIR/client $OLDFLAG -d $CONFIGDIR getUuid 
    $BINDIR/client $OLDFLAG -d $CONFIGDIR getUuid

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

# XXX remove once OLDFLAG goes away
# We always redo this to get an updated zedserverconfig
rm -f $TMPDIR/zedserverconfig
if [ x$OLDFLAG != x ]; then
    echo "Retrieving device and overlay network config at" `date`
    echo $BINDIR/client $OLDFLAG -d $CONFIGDIR lookupParam
    $BINDIR/client $OLDFLAG -d $CONFIGDIR lookupParam
    if [ -f $TMPDIR/zedserverconfig ]; then
	echo "Retrieved overlay /etc/hosts with:"
	cat $TMPDIR/zedserverconfig
	# edit zedserverconfig into /etc/hosts
	match=`awk '{print $2}' $TMPDIR/zedserverconfig| sort -u | awk 'BEGIN {m=""} { m = sprintf("%s|%s", m, $1) } END { m = substr(m, 2, length(m)); printf ".*:.*(%s)\n", m}'`
	egrep -v $match /etc/hosts >/tmp/hosts.$$
	cat $TMPDIR/zedserverconfig >>/tmp/hosts.$$
	echo "New /etc/hosts:"
	cat /tmp/hosts.$$
	cp /tmp/hosts.$$ /etc/hosts
	rm -f /tmp/hosts.$$
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
	intf=`$BINDIR/find-uplink.sh $CONFIGDIR/lisp.config.base`
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
else
    model=`$BINDIR/hardwaremodel`
    MODELFILE=${model}.json
    if [ ! -f "$DNCDIR/$MODELFILE" ] ; then
	echo "Missing $DNCDIR/$MODELFILE - giving up"
	exit 1
    fi
fi

# Need a key for device-to-device map-requests
cp -p $CONFIGDIR/device.key.pem $LISPDIR/lisp-sig.pem

# Pick up the device EID zedrouter config file from $TMPDIR and put
# it in /var/tmp/zedrouter/config/
# This will result in starting lispers.net when zedrouter starts
if [ -f $TMPDIR/zedrouterconfig.json ]; then
    uuid=`cat $CONFIGDIR/uuid`
    cp $TMPDIR/zedrouterconfig.json /var/tmp/zedrouter/config/${uuid}.json
fi

# Setup default amount of space for images
echo '{"MaxSpace":2000000}' >/var/tmp/downloader/config/global 

rm -f /var/run/verifier/*/status/restarted
rm -f /var/tmp/zedrouter/config/restart

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

echo "Starting eidregister at" `date`
eidregister $OLDFLAG -d $CONFIGDIR &
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

#If logmanager is already running we don't have to start it.
pgrep logmanager >/dev/null
if [ $? != 0 ]; then
    echo "Starting logmanager at" `date`
    logmanager >/var/run/logmanager.log 2>&1 &
    if [ $WAIT = 1 ]; then
	echo -n "Press any key to continue "; read dummy; echo; echo
    fi
fi

echo "Initial setup done at" `date`
if [ $MEASURE = 1 ]; then
    ping6 -c 3 -w 1000 zedcontrol
    echo "Measurement done at" `date`
fi
