#!/bin/bash

ETCDIR=/usr/local/etc/zededa
BINDIR=/usr/local/bin/zededa
PROVDIR=$BINDIR
LISPDIR=/usr/local/bin/lisp
WAIT=1
EID_IN_DOMU=0
while [ $# != 0 ]; do
    if [ "$1" == -w ]; then
	WAIT=0
    elif [ "$1" == -x ]; then
	EID_IN_DOMU=1
    else
	ETCDIR=$1
    fi
    shift
done

echo "Configuration from factory/install:"
(cd $ETCDIR; ls -l)
echo

if [ ! \( -f $ETCDIR/device.cert.pem -a -f $ETCDIR/device.key.pem \) ]; then
    echo "Generating a device key pair and self-signed cert (using TPM/TEE if available)"
    $PROVDIR/generate-device.sh $ETCDIR/device
    SELF_REGISTER=1
else
    echo "Using existing device key pair and self-signed cert"
    SELF_REGISTER=0
fi
if [ ! -f $ETCDIR/server -o ! -f $ETCDIR/root-certificate.pem ]; then
    echo "No server or root-certificate to connect to. Done"
    exit 0
fi

if [ $WAIT == 1 ]; then
    echo; read -n 1 -s -p "Press any key to continue"; echo; echo
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
if [ $WAIT == 1 ]; then
    echo; read -n 1 -s -p "Press any key to continue"; echo; echo
fi

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
fi
if [ $WAIT == 1 ]; then
    echo; read -n 1 -s -p "Press any key to continue"; echo; echo
fi

# XXX this should run in domZ aka ZedRouter on init.
# Ideally just to WiFi setup in dom0 and do DHCP in domZ

if [ $SELF_REGISTER = 1 ]; then
    echo "Self-registering our device certificate"
    if [ ! \( -f $ETCDIR/onboard.cert.pem -a -f $ETCDIR/onboard.key.pem \) ]; then
	echo "Missing onboarding certificate. Giving up"
	exit 1
    fi
    $BINDIR/client $ETCDIR selfRegister
    if [ $WAIT == 1 ]; then
	echo; read -n 1 -s -p "Press any key to continue"; echo; echo
    fi
fi

# XXX We always redo this to get an updated zedserverconfig
if [ /bin/true -o ! -f $ETCDIR/lisp.config ]; then
    echo "Retrieving device and overlay network config"
    $BINDIR/client $ETCDIR lookupParam
    echo "Retrieved overlay /etc/hosts with:"
    cat $ETCDIR/zedserverconfig
    # edit zedserverconfig into /etc/hosts
    match=`awk '{print $2}' $ETCDIR/zedserverconfig| sort -u | awk 'BEGIN {m=""} { m = sprintf("%s|%s", m, $1) } END { m = substr(m, 2, length(m)); printf ".*:.*(%s)\n", m}'`
    egrep -v $match /etc/hosts >/tmp/hosts.$$
    cat $ETCDIR/zedserverconfig >>/tmp/hosts.$$
    echo "New /etc/hosts:"
    cat /tmp/hosts.$$
    sudo cp /tmp/hosts.$$ /etc/hosts
    rm -f /tmp/hosts.$$
    if [ $WAIT == 1 ]; then
	echo; read -n 1 -s -p "Press any key to continue"; echo; echo
    fi
fi

echo "Determining uplink interface"
if [ ! -d $LISPDIR ]; then
    echo "Missing $LISPDIR directory. Giving up"
    exit 1
fi

# Remove internal config files
if [ -f /var/tmp/zedrouter/config/global ]; then
   cp -p /var/tmp/zedrouter/config/global $ETCDIR/network.config.global
fi
rm -rf /var/tmp/{zedrouter,xenmgr,downloader,verifier,identitymgr}/config/*

# XXX allow restart? pkill? Clean up status?
files=/var/run/{zedrouter,xenmgr,downloader,verifier,identitymgr}/status/*.json
found=0
for f in $files; do
    if [ -f $f ]; then
	echo "Found file: $f"
	rm -f $f
	found=1
    fi
done
sleep 5
pkill zedrouter
pkill xenmgr
pkill downloader
pkill verifier
pkill identitymgr
pkill eidregister

rm -rf /var/run/{zedrouter,xenmgr,downloader,verifier,identitymgr}/status/*.json

if [ $SELF_REGISTER = 1 ]; then
	intf=`$BINDIR/find-uplink.sh $ETCDIR/lisp.config.base`
	if [ "$intf" != "" ]; then
		echo "Found interface $intf based on route to map servers"
	else
		echo "NOT Found interface based on route to map servers. Giving up"
		exit 1    
	fi
	# XXX put in $ETCDIR first
	cat <<EOF >$ETCDIR/network.config.global
{"Uplink":"$intf"}
EOF

	# Make sure we set the dom0 hostname, used by LISP nat traversal, to
	# a unique string. Using the uuid
	echo "Setting hostname to $uuid"
	/bin/hostname $uuid
	/bin/hostname >/etc/hostname
fi

mkdir -p /var/tmp/zedrouter/config/
# Pick up the device EID zedrouter config file from $ETCDIR and put
# it in /var/tmp/zedrouter/config/
# This will result in starting lispers.net when zedrouter starts
uuid=`cat $ETCDIR/uuid`
cp $ETCDIR/zedrouterconfig.json /var/tmp/zedrouter/config/${uuid}.json

cp $ETCDIR/network.config.global /var/tmp/zedrouter/config/global

# Setup default amount of space for images
mkdir -p /var/tmp/downloader/config/
echo '{"MaxSpace":1000000}' >/var/tmp/downloader/config/global 

echo "Starting downloader"
/usr/local/bin/zededa/downloader >&/var/log/downloader.log&
if [ $WAIT == 1 ]; then
    echo; read -n 1 -s -p "Press any key to continue"; echo; echo
fi

echo "Starting verifier"
/usr/local/bin/zededa/verifier >&/var/log/verifier.log&
if [ $WAIT == 1 ]; then
    echo; read -n 1 -s -p "Press any key to continue"; echo; echo
fi

echo "Starting eidregister"
/usr/local/bin/zededa/eidregister >&/var/log/eidregister.log&
if [ $WAIT == 1 ]; then
    echo; read -n 1 -s -p "Press any key to continue"; echo; echo
fi

echo "Starting identitymgr"
/usr/local/bin/zededa/identitymgr >&/var/log/identitymgr.log&
if [ $WAIT == 1 ]; then
    echo; read -n 1 -s -p "Press any key to continue"; echo; echo
fi

echo "Starting ZedRouter"
/usr/local/bin/zededa/zedrouter >&/var/log/zedrouter.log&
if [ $WAIT == 1 ]; then
    echo; read -n 1 -s -p "Press any key to continue"; echo; echo
fi

echo "Starting XenMgr"
/usr/local/bin/zededa/xenmgr >&/var/log/xenmgr.log&
# Do something
if [ $WAIT == 1 ]; then
    echo; read -n 1 -s -p "Press any key to continue"; echo; echo
fi

echo "Starting ZedManager"
/usr/local/bin/zededa/zedmanager >&/var/log/zedmanager.log&
# Do something
if [ $WAIT == 1 ]; then
    echo; read -n 1 -s -p "Press any key to continue"; echo; echo
fi

echo "Uploading device (hardware) status"
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
cat >$ETCDIR/hwstatus.json <<EOF
{
	"Machine": "$machine",
	"Processor": "$processor",
	"Platform": "$platform",
	"Compatible": "$compatible",
	"Cpus": $cpus,
	"Memory": $memory,
	"Storage": $storage
}
EOF
$BINDIR/client $ETCDIR updateHwStatus

if [ $WAIT == 1 ]; then
    echo; read -n 1 -s -p "Press any key to continue"; echo; echo
fi

echo "Uploading software status"
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
$BINDIR/client $ETCDIR updateSwStatus

echo "Initial setup done!"


