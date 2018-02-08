#!/bin/sh

echo "Starting device-steps.sh at" `date`

# This is really CONFIGDIR; ETCDIR across reboots is TMPDIR
ETCDIR=/config
PERSISTDIR=/persist
BINDIR=/opt/zededa/bin
PROVDIR=$BINDIR
TMPDIR=/var/tmp/zededa
LISPDIR=/opt/zededa/lisp
AGENTS="ledmanager zedrouter domainmgr downloader verifier identitymgr eidregister zedagent"
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
	ETCDIR=$1
    fi
    shift
done

mkdir -p $TMPDIR

# The docker build moves this to /config
if [ ! -d $ETCDIR -a -d /opt/zededa/etc ]; then
    echo "Moving from /opt/zededa/etc to $ETCDIR"
    mv /opt/zededa/etc $ETCDIR
elif [ -d /opt/zededa/etc ]; then
    echo "Updating from /opt/zededa/etc to $ETCDIR:"
    (cd /opt/zededa/etc/; tar cf - . ) | (cd $ETCDIR; tar xfv -)
    rm -rf /opt/zededa/etc
fi
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
    
echo "Configuration from factory/install:"
(cd $ETCDIR; ls -l)
echo

echo "Update version info in $TMPDIR/version"
if [ -f $TMPDIR/version_tag ]; then
    cat $TMPDIR/version_tag >$TMPDIR/version
else
    rm -f $TMPDIR/version
fi
for AGENT in $ALLAGENTS; do
    $BINDIR/$AGENT -v >>$TMPDIR/version
done

echo "Combined version:"
cat $TMPDIR/version

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
DIRS="$ETCDIR $PERSISTDIR $TMPDIR /var/tmp/ledmanager/config/ /var/tmp/domainmgr/config/ /var/tmp/verifier/config/ /var/tmp/downloader/config/ /var/tmp/zedmanager/config/ /var/tmp/identitymgr/config/ /var/tmp/zedrouter/config/ /var/run/domainmgr/status/ /var/run/downloader/status/ /var/run/zedmanager/status/ /var/run/eidregister/status/ /var/run/zedrouter/status/ /var/run/identitymgr/status/ /var/tmp/zededa/DeviceNetworkConfig/ /var/run/zedrouter/DeviceNetworkStatus/ /var/tmp/zededa/DeviceNetworkConfig/AssignableAdapters"
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

echo "Saving any old log files"
LOGGERS=$ALLAGENTS
for l in $LOGGERS; do
    f=/var/log/$l.log
    if [ -f $f ]; then
	datetime=`stat -c %y $f | awk '{printf "%s-%s", $1, $2}'`
	echo "Saving $f.$datetime"
	mv $f $f.$datetime
    fi
done

# BlinkCounter 1 means we have started; might not yet have IP addresses
# client/selfRegister and zedagent update this when the found at least
# one free uplink with IP address(s)
echo '{"BlinkCounter": 1}' > '/var/tmp/ledmanager/config/ledconfig.json'

# If ledmanager is already running we don't have to start it.
# TBD: Should we start it earlier before wwan and wlan services?
pgrep ledmanager >/dev/null
if [ $? != 0 ]; then
    echo "Starting ledmanager at" `date`
    ledmanager >/var/log/ledmanager.log 2>&1 &
    if [ $WAIT = 1 ]; then
	echo -n "Press any key to continue "; read dummy; echo; echo
    fi
fi

# We need to try our best to setup time *before* we generate the certifiacte.
# Otherwise it may have start date in the future
echo "Check for NTP config"
if [ -f $ETCDIR/ntp-server ]; then
    echo -n "Using "
    cat $ETCDIR/ntp-server
    # XXX is ntp service running/installed?
    # XXX actually configure ntp
    # Ubuntu has /usr/bin/timedatectl; ditto Debian
    # ntpdate pool.ntp.org
    # Not installed on Ubuntu
    #
    if [ -f /usr/bin/ntpdate ]; then
	/usr/bin/ntpdate `cat $ETCDIR/ntp-server`
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


if [ ! \( -f $ETCDIR/device.cert.pem -a -f $ETCDIR/device.key.pem \) ]; then
    echo "Generating a device key pair and self-signed cert (using TPM/TEE if available) at" `date`
    $PROVDIR/generate-device.sh $ETCDIR/device
    SELF_REGISTER=1
elif [ -f $TMPDIR/self-register-failed ]; then
    echo "self-register failed/killed/rebooted; redoing self-register"
    SELF_REGISTER=1
else
    echo "Using existing device key pair and self-signed cert"
    SELF_REGISTER=0
fi
if [ ! -f $ETCDIR/server -o ! -f $ETCDIR/root-certificate.pem ]; then
    echo "No server or root-certificate to connect to. Done"
    exit 0
fi

if [ $WAIT = 1 ]; then
    echo -n "Press any key to continue "; read dummy; echo; echo
fi

# XXX should we harden/remove any Linux network services at this point?
echo "Check for WiFi config"
if [ -f $ETCDIR/wifi_ssid ]; then
    echo -n "SSID: "
    cat $ETCDIR/wifi_ssid
    if [ -f $ETCDIR/wifi_credentials ]; then
	echo -n "Wifi credentials: "
	cat $ETCDIR/wifi_credentials
    fi
    # XXX actually configure wifi
    # Requires a /etc/network/interfaces.d/wlan0.cfg
    # and /etc/wpa_supplicant/wpa_supplicant.conf
    # Assumes wpa packages are included. Would be in our image?
fi
if [ $WAIT = 1 ]; then
    echo -n "Press any key to continue "; read dummy; echo; echo
fi

# We use the factory network.config.static if we have one, otherwise
# we reuse the DeviceNetworkConfig from a previous run
mkdir -p $TMPDIR/DeviceNetworkConfig/
if [ -f $ETCDIR/network.config.static ] ; then
    echo "Using $ETCDIR/network.config.static"
    cp -p $ETCDIR/network.config.static $TMPDIR/DeviceNetworkConfig/global.json 
fi

if [ ! -f $TMPDIR/uuid -a -f $ETCDIR/uuid ]; then
    cp -p $ETCDIR/uuid $TMPDIR/uuid
fi

if [ $SELF_REGISTER = 1 ]; then
    rm -f $TMPDIR/zedrouterconfig.json
    
    touch $TMPDIR/self-register-failed
    echo "Self-registering our device certificate at " `date`
    if [ ! \( -f $ETCDIR/onboard.cert.pem -a -f $ETCDIR/onboard.key.pem \) ]; then
	echo "Missing onboarding certificate. Giving up"
	exit 1
    fi
    echo $BINDIR/client $OLDFLAG -d $ETCDIR selfRegister
    $BINDIR/client $OLDFLAG -d $ETCDIR selfRegister
    rm -f $TMPDIR/self-register-failed
    if [ $WAIT = 1 ]; then
	echo -n "Press any key to continue "; read dummy; echo; echo
    fi
fi
# We always redo this to get an updated zedserverconfig
rm -f $TMPDIR/zedserverconfig
if [ /bin/true -o ! -f $ETCDIR/lisp.config ]; then
    echo "Retrieving device and overlay network config at" `date`
    echo $BINDIR/client $OLDFLAG -d $ETCDIR lookupParam
    $BINDIR/client $OLDFLAG -d $ETCDIR lookupParam
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
    if [ ! -f $ETCDIR/network.config.static ] ; then
	echo "Determining uplink interface"
	intf=`$BINDIR/find-uplink.sh $ETCDIR/lisp.config.base`
	if [ "$intf" != "" ]; then
		echo "Found interface $intf based on route to map servers"
	else
		echo "NOT Found interface based on route to map servers. Giving up"
		exit 1    
	fi
	cat <<EOF >$TMPDIR/DeviceNetworkConfig/global.json
{"Uplink":["$intf"], "FreeUplinks":["$intf"]}
EOF
    fi
    # Make sure we set the dom0 hostname, used by LISP nat traversal, to
    # a unique string. Using the uuid
    if [ -f $TMPDIR/uuid ]; then
	uuid=`cat $TMPDIR/uuid`
    else
	uuid=`cat $ETCDIR/uuid`
    fi
    echo "Setting hostname to $uuid"
    /bin/hostname $uuid
    /bin/hostname >/etc/hostname
    # put the uuid in /etc/hosts to avoid complaints
    echo "Adding $uuid to /etc/hosts"
    echo "127.0.0.1 $uuid" >>/etc/hosts
else
    if [ -f $TMPDIR/uuid ]; then
	uuid=`cat $TMPDIR/uuid`
    else
	uuid=`cat $ETCDIR/uuid`
    fi
    # For safety in case the rootfs was duplicated and /etc/hostame wasn't
    # updated
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
    # Handle old file format
    grep -q FreeUplinks $TMPDIR/DeviceNetworkConfig/global.json
    if [ $? = 0 ]; then
	echo "Found FreeUplinks in $TMPDIR/DeviceNetworkConfig/global.json"
    else
	echo "Determining uplink interface"
	intf=`$BINDIR/find-uplink.sh $ETCDIR/lisp.config.base`
	if [ "$intf" != "" ]; then
		echo "Found interface $intf based on route to map servers"
	else
		echo "NOT Found interface based on route to map servers. Giving up"
		exit 1    
	fi
	cat <<EOF >$TMPDIR/DeviceNetworkConfig/global.json
{"Uplink":["$intf"], "FreeUplinks":["$intf"]}
EOF
    fi
fi

# Need a key for device-to-device map-requests
cp -p $ETCDIR/device.key.pem $LISPDIR/lisp-sig.pem   

# Pick up the device EID zedrouter config file from $ETCDIR and put
# it in /var/tmp/zedrouter/config/
# This will result in starting lispers.net when zedrouter starts
if [ -f $TMPDIR/zedrouterconfig.json ]; then
	cp $TMPDIR/zedrouterconfig.json /var/tmp/zedrouter/config/${uuid}.json
fi

# Setup default amount of space for images
echo '{"MaxSpace":2000000}' >/var/tmp/downloader/config/global 

rm -f /var/run/verifier/*/status/restarted
rm -f /var/tmp/zedrouter/config/restart

echo "Starting verifier at" `date`
verifier >/var/log/verifier.log 2>&1 &
if [ $WAIT = 1 ]; then
    echo -n "Press any key to continue "; read dummy; echo; echo
fi

echo "Starting ZedManager at" `date`
zedmanager >/var/log/zedmanager.log 2>&1 &
if [ $WAIT = 1 ]; then
    echo -n "Press any key to continue "; read dummy; echo; echo
fi

echo "Starting downloader at" `date`
downloader >/var/log/downloader.log 2>&1 &
if [ $WAIT = 1 ]; then
    echo -n "Press any key to continue "; read dummy; echo; echo
fi

echo "Starting eidregister at" `date`
eidregister >/var/log/eidregister.log 2>&1 &
if [ $WAIT = 1 ]; then
    echo -n "Press any key to continue "; read dummy; echo; echo
fi

echo "Starting identitymgr at" `date`
identitymgr >/var/log/identitymgr.log 2>&1 &
if [ $WAIT = 1 ]; then
    echo -n "Press any key to continue "; read dummy; echo; echo
fi

echo "Starting ZedRouter at" `date`
zedrouter >/var/log/zedrouter.log 2>&1 &
if [ $WAIT = 1 ]; then
    echo -n "Press any key to continue "; read dummy; echo; echo
fi

echo "Starting DomainMgr at" `date`
domainmgr >/var/log/domainmgr.log 2>&1 &
# Do something
if [ $WAIT = 1 ]; then
    echo -n "Press any key to continue "; read dummy; echo; echo
fi

echo "Starting zedagent at" `date`
zedagent >/var/log/zedagent.log 2>&1 &
if [ $WAIT = 1 ]; then
    echo -n "Press any key to continue "; read dummy; echo; echo
fi

echo "Initial setup done at" `date`
if [ $MEASURE = 1 ]; then
    ping6 -c 3 -w 1000 zedcontrol
    echo "Measurement done at" `date`
fi
