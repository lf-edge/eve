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
    echo "Generating a device key pair and self-signed cert (using TPM/TEE if available) plus device uuid"
    $PROVDIR/generate-device.sh $ETCDIR/device
    uuidgen >$ETCDIR/uuid
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
	echo "Missing provisioning certificate. Giving up"
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
    
if [ $SELF_REGISTER = 1 ]; then
	# XXX do this in zedmanager?
	mkdir -p /var/tmp/zedmamager/config/
	mkdir -p /var/tmp/zedrouter/config/
	mkdir -p /var/tmp/xenmgr/config/
	mkdir -p /var/tmp/identitymgr/config/
	intf=`$BINDIR/find-uplink.sh $ETCDIR/lisp.config`

	if [ "$intf" != "" ]; then
		echo "Found interface $intf based on route to map servers"
	else
		echo "NOT Found interface based on route to map servers. Giving up"
		exit 1    
	fi
	cat <<EOF >/var/tmp/zedrouter/config/global
{"Uplink":"$intf"}
EOF

	# Create the device EID file in /var/tmp/zedrouter/config/
	# Kicks off lispers.net when zedrouter starts
	uuid=`uuidgen`
	name="zed"`uname -n`
	#Pick first eid-prefix; any others are for applications
	eid=`grep "eid-prefix = fd" lisp.config | awk '{print $3}' | awk -F/ '{print $1}' | head -1`
	iid=`grep "instance-id = " /usr/local/etc/zededa/lisp.config | awk '{print $3}' | awk -F/ '{print $1}' | head -1`
	sig=`grep "json-string = { \"signature\""  /usr/local/etc/zededa/lisp.config | awk '{print $6}' | awk -F/ '{print $1}' | head -1`
	cat <<EOF 
{"UUIDandVersion":{"UUID":"$uuid","Version":"0"},"DisplayName":"$name", "IsZedmanager":true,"OverlayNetworkList":[{"IID":$iid, "EID":"$eid","Signature":"$sig","ACLs":[{"Matches":[{"Type":"eidset"}]}],"NameToEidList":[{"HostName":"zedhikey","EIDs":["fd07:cfa2:2b35:b8f6:d6f6:e9be:7d2a:fc93"]},{"HostName":"zedbobo","EIDs":["fdd5:79bf:7261:d9df:aea1:c8d2:842d:b99b"]},{"HostName":"zedcontrol","EIDs":["fd45:efca:3607:4c1d:eace:a947:3464:d21e"]},{"HostName":"zedlake","EIDs":["fd45:efca:3607:4c1d:eace:a947:3464:d21e"]}]}],"UnderlayNetworkList":null}
EOF
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
/usr/local/bin/zededa/zedrouter >&/var/log/zedrouter.log&
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


