#!/bin/sh

echo "Starting device-steps.sh at" `date`

ETCDIR=/opt/zededa/etc
BINDIR=/opt/zededa/bin
PROVDIR=$BINDIR
LISPDIR=/opt/zededa/lisp
AGENTS="zedrouter domainmgr downloader verifier identitymgr eidregister zedagent"
ALLAGENTS="zedmanager $AGENTS"

PATH=$BINDIR:$PATH

OLDFLAG=
WAIT=1
EID_IN_DOMU=0
MEASURE=0
while [ $# != 0 ]; do
    if [ "$1" = -w ]; then
	WAIT=0
    elif [ "$1" = -x ]; then
	EID_IN_DOMU=1
    elif [ "$1" = -m ]; then
	MEASURE=1
    elif [ "$1" = -o ]; then
	OLDFLAG=$1
    else
	ETCDIR=$1
    fi
    shift
done

echo "Configuration from factory/install:"
(cd $ETCDIR; ls -l)
echo

echo "Update version info in $ETCDIR/version"
cat $ETCDIR/version_tag >$ETCDIR/version
for AGENT in $ALLAGENTS; do
    $BINDIR/$AGENT -v >>$ETCDIR/version
done

echo "Combined version:"
cat $ETCDIR/version

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
    /usr/sbin/ntpd -d -q -n -p pool.ntp.org
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
elif [ -f $ETCDIR/self-register-failed ]; then
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

# XXX this should run in domZ aka ZedRouter on init.
# Ideally just to WiFi setup in dom0 and do DHCP in domZ

if [ $SELF_REGISTER = 1 ]; then
    touch $ETCDIR/self-register-failed
    echo "Self-registering our device certificate at " `date`
    if [ ! \( -f $ETCDIR/onboard.cert.pem -a -f $ETCDIR/onboard.key.pem \) ]; then
	echo "Missing onboarding certificate. Giving up"
	exit 1
    fi
    echo $BINDIR/client $OLDFLAG -d $ETCDIR selfRegister
    $BINDIR/client $OLDFLAG -d $ETCDIR selfRegister
    rm -f $ETCDIR/self-register-failed
    if [ $WAIT = 1 ]; then
	echo -n "Press any key to continue "; read dummy; echo; echo
    fi
fi

# XXX We always redo this to get an updated zedserverconfig
rm -f $ETCDIR/zedserverconfig
if [ /bin/true -o ! -f $ETCDIR/lisp.config ]; then
    echo "Retrieving device and overlay network config at" `date`
    echo $BINDIR/client $OLDFLAG -d $ETCDIR lookupParam
    $BINDIR/client $OLDFLAG -d $ETCDIR lookupParam
    if [ -f $ETCDIR/zedserverconfig ]; then
	echo "Retrieved overlay /etc/hosts with:"
	cat $ETCDIR/zedserverconfig
	# edit zedserverconfig into /etc/hosts
	match=`awk '{print $2}' $ETCDIR/zedserverconfig| sort -u | awk 'BEGIN {m=""} { m = sprintf("%s|%s", m, $1) } END { m = substr(m, 2, length(m)); printf ".*:.*(%s)\n", m}'`
	egrep -v $match /etc/hosts >/tmp/hosts.$$
	cat $ETCDIR/zedserverconfig >>/tmp/hosts.$$
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

if [ -f /var/tmp/zedrouter/config/global ]; then
   cp -p /var/tmp/zedrouter/config/global $ETCDIR/network.config.global
fi

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
DIRS="/var/tmp/domainmgr/config/ /var/tmp/verifier/config/ /var/tmp/downloader/config/ /var/tmp/zedmanager/config/ /var/tmp/identitymgr/config/ /var/tmp/zedrouter/config/ /var/run/domainmgr/status/ /var/run/verifier/status/ /var/run/downloader/status/ /var/run/zedmanager/status/ /var/run/eidregister/status/ /var/run/zedrouter/status/ /var/run/identitymgr/status/"
for d in $DIRS; do
    mkdir -p $d
    chmod 700 $d `dirname $d`
done

for AGENT in $AGENTS; do
    if [ ! -d /var/tmp/$AGENT ]; then
	continue
    fi
    dir=/var/tmp/$AGENT/config
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
	    # will remove the rootfs copy in /var/tmp/domainmgr/img/
	    echo "Deleting config file: $f"
	    rm -f "$f"
	fi
    done
done

# Try to cleanup in case the agents are running or /var/run files are left over
# If agents are running then the deletion of the /var/tmp/ files should
# cleaned up all but /var/run/zedmanager/*.json

# Add a tag to preserve any downloaded and verified files
touch /var/tmp/verifier/config/preserve

# If agents are running wait for the status files to disappear
for AGENT in $AGENTS; do
    if [ ! -d /var/run/$AGENT ]; then
	# Needed for zedagent
	pkill $AGENT
	continue
    fi
    if [ $AGENT = "verifier" ]; then
	echo "Skipping check for /var/run/$AGENT/status"
	pkill $AGENT
	continue
    fi
    dir=/var/run/$AGENT/status
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
    pkill $AGENT
done

# Remove the preserve tag
rm /var/tmp/verifier/config/preserve

echo "Removing old iptables/ip6tables rules"
# Cleanup any remaining iptables rules from a failed run
iptables -F
ip6tables -F
ip6tables -t raw -F

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

if [ $SELF_REGISTER = 1 ]; then
	rm -f $ETCDIR/zedrouterconfig.json
    
	intf=`$BINDIR/find-uplink.sh $ETCDIR/lisp.config.base`
	if [ "$intf" != "" ]; then
		echo "Found interface $intf based on route to map servers"
	else
		echo "NOT Found interface based on route to map servers. Giving up"
		exit 1    
	fi
	echo "Determining uplink interface"
# XXX this doesn't run on update; handle both formats in json?
	cat <<EOF >$ETCDIR/network.config.global
{"Uplink":["$intf"]}
EOF

	# Make sure we set the dom0 hostname, used by LISP nat traversal, to
	# a unique string. Using the uuid
	uuid=`cat $ETCDIR/uuid`
	echo "Setting hostname to $uuid"
	/bin/hostname $uuid
	/bin/hostname >/etc/hostname
	# put the uuid in /etc/hosts to avoid complaints
	echo "Adding $uuid to /etc/hosts"
	echo "127.0.0.1 $uuid" >>/etc/hosts
else
	uuid=`cat $ETCDIR/uuid`
	# For safety in case the rootfs was duplicated and /etc/hostame wasn't
	# updated
	/bin/hostname $uuid
	/bin/hostname >/etc/hostname
	grep -s $uuid /etc/hosts >/dev/null
	if [ !? = 1 ]; then
		# put the uuid in /etc/hosts to avoid complaints
		echo "Adding $uuid to /etc/hosts"
		echo "127.0.0.1 $uuid" >>/etc/hosts
	else
		echo "Found $uuid in /etc/hosts"
	fi
fi

# Need a key for device-to-device map-requests
cp -p $ETCDIR/device.key.pem $LISPDIR/lisp-sig.pem   

# Pick up the device EID zedrouter config file from $ETCDIR and put
# it in /var/tmp/zedrouter/config/
# This will result in starting lispers.net when zedrouter starts
if [ -f $ETCDIR/zedrouterconfig.json ]; then
	cp $ETCDIR/zedrouterconfig.json /var/tmp/zedrouter/config/${uuid}.json
fi

cp $ETCDIR/network.config.global /var/tmp/zedrouter/config/global

# Setup default amount of space for images
echo '{"MaxSpace":2000000}' >/var/tmp/downloader/config/global 

rm -f /var/run/verifier/status/restarted
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

echo "Starting dataplane at" `date`
dataplane >/var/log/dataplane.log 2>&1 &
if [ $WAIT = 1 ]; then
    echo; read -n 1 -s -p "Press any key to continue"; echo; echo
fi

echo "Uploading device (hardware) status at" `date`
machine=`uname -m`
processor=`uname -p`
platform=`uname -i`
if [ -f /proc/device-tree/compatible ]; then
    compatible=`cat /proc/device-tree/compatible`
else
    compatible=""
fi
memory=`awk '/MemTotal/ {print $2}' /proc/meminfo`
storage=`df -kl --output=size / | tail -n +2| awk '{print $1}'`
cpus=`nproc --all`
# Try dmidecode which should work on Intel
# XXX or look for /sys/firmware/dmi
manufacturer=`dmidecode -s system-manufacturer`
if [ "$manufacturer" != "" ]; then
    productName=`dmidecode -s system-product-name`
    version=`dmidecode -s system-version`
    serialNumber=`dmidecode -s system-serial-number`
    uuid=`dmidecode -s system-uuid`
else
    productName=""
    version=""
    serialNumber=""
    uuid="00000000-0000-0000-0000-000000000000"
fi
# Add AdditionalInfoDevice to this
if [ -f $ETCDIR/clientIP ]; then
    publicIP=`cat $ETCDIR/clientIP`
else
    publicIP="0.0.0.0"
fi
cat >$ETCDIR/hwstatus.json <<EOF
{
	"Machine": "$machine",
	"Processor": "$processor",
	"Platform": "$platform",
	"Compatible": "$compatible",
	"Cpus": $cpus,
	"Memory": $memory,
	"Storage": $storage,
	"SystemManufacturer": "$manufacturer",
	"SystemProductName": "$productName",
	"SystemVersion": "$version",
	"SystemSerialNumber": "$serialNumber",
	"SystemUUID": "$uuid",
	"PublicIP": "$publicIP"
}
EOF
echo $BINDIR/client $OLDFLAG -d $ETCDIR updateHwStatus
$BINDIR/client $OLDFLAG -d $ETCDIR updateHwStatus

if [ $WAIT = 1 ]; then
    echo -n "Press any key to continue "; read dummy; echo; echo
fi

echo "Uploading software status at" `date`
# Only report the Linux info for now
name=`uname -o`
version=`uname -r`
description=`uname -v`
cat >$ETCDIR/swstatus.json <<EOF
{
	"ApplicationStatus": [
		{
			"Infra": true,
			"EID": "::",
			"DisplayName": "$name",
			"Version": "$version",
			"Description": "$description",
			"State": 5,
			"Activated": true
		}
	]
}
EOF
echo $BINDIR/client $OLDFLAG -d $ETCDIR updateSwStatus
$BINDIR/client $OLDFLAG -d $ETCDIR updateSwStatus

echo "Initial setup done at" `date`
if [ $MEASURE = 1 ]; then
    ping6 -c 3 -w 1000 zedcontrol
    echo "Measurement done at" `date`
fi
